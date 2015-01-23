/*
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   Author: Richard Withnell
   github.com/richardwithnell
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "debug.h"
#include "link_monitor.h"
#include "lmnl_interface.h"
#include "util.h"

int route_cb(const struct nlmsghdr* nlh, struct update_obj** update)
{
    struct update_obj* u;
    struct rtmsg* rm = mnl_nlmsg_get_payload(nlh);
    struct mnl_route* route = 0;

    route = mnl_route_from_msg(rm, nlh);
    if (!route) {
        print_error("Failed to parse route\ns");
        return -1;
    }

    if (route->destination) {
        print_verb("Not default: %s\n", ip_to_str(htonl(route->gateway)));
        free(route);
        return 0;
    } else {
        print_verb("Default: %s\n", ip_to_str(htonl(route->gateway)));
    }

    if (!route->gateway) {
        print_verb("Route doesn't have a gateway\n");
        free(route);
        return 0;
    }

    if (route->table != RT_TABLE_MAIN) {
        print_verb("Route not from main table: %d (%d)\n", route->table, RT_TABLE_MAIN);
        free(route);
        return 0;
    } else {
        print_verb("Route for main table: %d\n", route->table);
    }

    if (!(u = malloc(sizeof(struct update_obj)))) {
        print_error("ENOMOM\n");
        errno = ENOMEM;
        free(route);
        return errno;
    }

    switch (nlh->nlmsg_type) {
    case RTM_NEWROUTE:
        print_debug("New Route - %s\n", ip_to_str(htonl(route->gateway)));
        u->action = ADD_RT;
        break;
    case RTM_DELROUTE:
        print_debug("Delete route - %s\n", ip_to_str(htonl(route->gateway)));
        u->action = DEL_RT;
        break;
    }

    u->update = mnl_to_rtnl_route(route);
    u->type = UPDATE_ROUTE;
    *update = u;

    return 0;
}

int address_cb(const struct nlmsghdr* nlh, struct update_obj** update)
{
    struct update_obj* u;
    struct ifaddrmsg* ifa = mnl_nlmsg_get_payload(nlh);
    struct mnl_addr* addr = mnl_addr_from_msg(ifa, nlh);

    if (!(u = malloc(sizeof(struct update_obj)))) {
        print_debug("ENOMOM\n");
        errno = ENOMEM;
        return errno;
    }

    switch (nlh->nlmsg_type) {
    case RTM_NEWADDR:
        print_debug("Add IP\n");
        u->action = ADD_IP;
        break;
    case RTM_DELADDR:
        print_debug("Delete IP\n");
        u->action = DEL_IP;
        break;
    }

    u->update = mnl_to_rtnl_addr(addr);
    u->type = UPDATE_ADDR;
    *update = u;

    return 0;
}

int link_cb(const struct nlmsghdr* nlh, struct update_obj** update)
{
    struct update_obj* u;
    struct ifinfomsg* ifm = mnl_nlmsg_get_payload(nlh);
    struct mnl_link* link = mnl_link_from_msg(ifm, nlh);

    if (!(u = malloc(sizeof(struct update_obj)))) {
        print_debug("ENOMOM\n");
        errno = ENOMEM;
        return errno;
    }
    print_debug("Link Update\n");
    if (ifm->ifi_flags & IFF_UP) {
        u->action = ADD_IFF;
    } else {
        u->action = DEL_IFF;
    }

    u->update = mnl_to_rtnl_link(link);
    u->type = UPDATE_LINK;
    *update = u;

    return 0;
}

int data_cb(const struct nlmsghdr* nlh, void* data)
{
    struct cache_monitor* mon = (struct cache_monitor*)data;
    Qitem* item;
    struct update_obj* update = (struct update_obj*)0;

    if (nlh->nlmsg_type == RTM_NEWROUTE || nlh->nlmsg_type == RTM_DELROUTE) {
        if (route_cb(nlh, &update)) {
            return MNL_CB_OK;
        }
        if (!update) {
            print_debug("Failed to create route update\n");
            return MNL_CB_OK;
        }
    } else if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
        print_debug("GOT ADDRESS UPDATE\n");
        address_cb(nlh, &update);
        if (!update) {
            print_debug("Failed to create address update\n");
            return MNL_CB_OK;
        }
    } else if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
        link_cb(nlh, &update);
        if (!update) {
            print_debug("Failed to create link update\n");
            return MNL_CB_OK;
        }
    } else {
        print_debug("Unknown nlmsg type in callback\n");
        return MNL_CB_OK;
    }

    if (!(item = malloc(sizeof(Qitem)))) {
        print_debug("ENOMOM\n");
        errno = ENOMEM;
        return errno;
    }

    item->next = 0;
    item->data = update;

    print_debug("UPDATE: %p\n", update);

    mon = (struct cache_monitor*)data;
    print_debug("add to queue\n");
    pthread_mutex_lock(mon->lock);
    queue_put(mon->queue, item);
    pthread_mutex_unlock(mon->lock);
    print_debug("sem_post\n");
    sem_post(mon->barrier);

    return MNL_CB_OK;
}

int boot(struct mnl_socket* nl, struct nlmsghdr* nlh, unsigned int seq, void* data)
{
    int ret = 0;
    unsigned int portid = 0;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    portid = mnl_socket_get_portid(nl);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        return -1;
    }

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, seq, portid, data_cb, data);
        if (ret == MNL_CB_STOP) {
            print_debug("MNL_CB_STOP\n");
            break;
        } else if (ret < MNL_CB_STOP) {
            print_debug("MNL_CB_ERROR\n");
            break;
        }
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }

    if (ret == -1) {
        print_debug("");
        perror("error");
        return -1;
    }

    return 0;
}

int boot_links(struct mnl_socket* nl, void* data)
{
    struct nlmsghdr* nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct rtgenmsg* rtl;
    unsigned int seq = 0;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type       = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);
    rtl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    rtl->rtgen_family = AF_PACKET;

    return boot(nl, nlh, seq, data);
}

int boot_addresses(struct mnl_socket* nl, void* data)
{
    struct nlmsghdr* nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct rtgenmsg* rta;
    int seq = 0;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type       = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);
    rta = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    rta->rtgen_family = AF_INET;

    return boot(nl, nlh, seq, data);
}

int boot_routes(struct mnl_socket* nl, void* data)
{
    struct nlmsghdr* nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct rtmsg* rtm;
    int seq = 0;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);
    rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;

    return boot(nl, nlh, seq, data);
}

int initalise_nl(void* data)
{
    struct mnl_socket* nl;

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        perror("mnl_socket_open");
        return -1;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        return -1;
    }

    boot_links(nl, data);
    boot_addresses(nl, data);
    boot_routes(nl, data);

    mnl_socket_close(nl);

    return 0;
}

void init_monitor(void* data)
{
    int ret = 0;

    print_debug("Initalise netlink caches\n");

    struct mnl_socket* nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        perror("mnl_socket_open");
    }

    /*Need to bind before boot,
       or there may be a race condition leading to missed address updates*/
    if (mnl_socket_bind(nl, RTMGRP_IPV4_ROUTE | RTMGRP_LINK | RTMGRP_IPV4_IFADDR,
                        MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }

    /*Boot the link/address/route information,
       grab everything that already exists*/
    if ((ret = initalise_nl(data))) {
        print_error("Failed to initalise netlink information");
        pthread_exit(&ret);
    }

    print_debug("Monitor updates from netlink\n");

    /*Get future updates*/
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, 0, 0, data_cb, data);
        if (ret <= MNL_CB_STOP) {
            break;
        }
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }

    if (ret == -1) {
        perror("error");
    }

    mnl_socket_close(nl);

    pthread_exit(&ret);
}

/* end file: link_monitor_lmnl.c */
