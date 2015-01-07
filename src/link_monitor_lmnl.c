/* This example is placed in the public domain. */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "link_monitor_lmnl.h"
#include "lmnl_interface.h"

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
  struct update_obj *update;
  Qitem *item;
  struct cache_monitor *mon = (struct cache_monitor*) data;


  if(nlh->nlmsg_type == RTM_NEWROUTE || nlh->nlmsg_type == RTM_DELROUTE) {
    struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
    struct mnl_route *route = mnl_route_from_msg(rm, nlh);

    if(!route->gateway || route->table != RT_TABLE_MAIN){
      print_debug("Non matching route");
      free(route);
      free(rm);
    }


    if(!(update = malloc(sizeof(struct update_obj)))){
      print_debug("ENOMOM\n");
      errno = ENOMEM;
      return;
    }
    update->update = mnl_to_rtnl_route(route);
    update->type = UPDATE_ROUTE;

    switch(nlh->nlmsg_type) {
      case RTM_NEWROUTE:
        print_debug("[NEW RT] ");
        update->action = ADD_RT;
        break;
      case RTM_DELROUTE:
        print_debug("[DEL RT] ");
        update->action = DEL_RT;
        break;
    }

  } else if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
    struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
    struct mnl_addr *addr = mnl_route_from_msg(ifa, nlh);



    if(!(update = malloc(sizeof(struct update_obj)))){
      print_debug("ENOMOM\n");
      errno = ENOMEM;
      return;
    }
    update->update = mnl_to_rtnl_addr(addr);
    update->type = UPDATE_ADDR;

    switch(nlh->nlmsg_type) {
      case RTM_NEWADDR:
        print_debug("Add IP\n");
        update->action = ADD_IP;
        break;
      case RTM_DELADDR:
        print_debug("Delete IP\n");
        update->action = DEL_IP;
        break;
    }

  } else if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
    struct mnl_link *link = mnl_route_from_msg(ifm, nlh);


    if(!(update = malloc(sizeof(struct update_obj)))){
      print_debug("ENOMOM\n");
      errno = ENOMEM;
      return;
    }
    update->update = mnl_to_rtnl_link(link);
    update->type = UPDATE_LINK;

    if (ifm->ifi_flags & IFF_UP){
      update->action = ADD_IFF;
    } else {
      update->action = DEL_IFF;
    }
  }

  if(!(item = malloc(sizeof(Qitem)))){
    print_debug("ENOMOM\n");
    errno = ENOMEM;
    return;
  }

  item->next = 0;
  item->data = update;

  print_debug("add to queue\n");
  pthread_mutex_lock(mon->lock);
  queue_put(mon->queue, item);
  pthread_mutex_unlock(mon->lock);
  print_debug("sem_post\n");
  sem_post(mon->barrier);

  printf("\n");
  return MNL_CB_OK;
}

void init_monitor(void *data)
{
  int ret = 0;
  struct mnl_socket *nl;
  char buf[MNL_SOCKET_BUFFER_SIZE];

  struct cache_monitor *mon = (struct cache_monitor*)data;

  nl = mnl_socket_open(NETLINK_ROUTE);
  if (nl == NULL) {
    perror("mnl_socket_open");
    exit(EXIT_FAILURE);
  }

  if (mnl_socket_bind(nl, RTMGRP_IPV4_ROUTE | RTMGRP_LINK | RTMGRP_IPV4_IFADDR ,
    MNL_SOCKET_AUTOPID) < 0) {
      perror("mnl_socket_bind");
      exit(EXIT_FAILURE);
  }

  ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, 0, 0, data_cb, mon);
    if (ret <= MNL_CB_STOP){
      break;
    }
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }

  if (ret == -1) {
    perror("error");
    pthread_exit(&ret);
  }

  mnl_socket_close(nl);
  pthread_exit(&ret);
}
