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

#include <errno.h>

#include "link_monitor.h"
#include "debug.h"

#define DEBUG_VERB 0

void cache_update(struct nl_cache *cache, struct nl_object *obj, int action, void *arg);


/*
*
*/
void change_route_cb(void *arg, struct nl_object *obj, int action)
{
    struct update_obj *update;
    Qitem *item;
    struct rtnl_route *route = (struct rtnl_route *)obj;
    struct cache_monitor *mon = (struct cache_monitor*) arg;
    struct nl_addr *dst = 0;

    char n = '0';
    dst = nl_addr_build(AF_INET, &n, 0);

    if(rtnl_route_get_family(route) != AF_INET){
		print_debug("Not IPv4 Route\n");
        return;
    }

    if(rtnl_route_get_table(route) != RT_TABLE_MAIN){
		print_debug(" Not main table route\n");
        return;
    }

    #ifdef DEBUG_VERB
    char addr_buff[32];
    struct rtnl_nexthop *nexthop = rtnl_route_nexthop_n (route, 0);
    struct nl_addr *gw = rtnl_route_nh_get_gateway (nexthop);
    print_debug("GW Address (%s)\n", nl_addr2str(gw, addr_buff, 32));
    #endif

    dst = rtnl_route_get_dst(route);

    if(!dst){
		print_debug("No destination\n");
        return;
    }

    if(!nl_addr_iszero(dst)){
		print_debug("Desination is zero\n");
        return;
    }

    if(!(update = malloc(sizeof(struct update_obj)))){
		print_debug("ENOMOM\n");
		errno = ENOMEM;
        return;
    }

    if(!(item = malloc(sizeof(Qitem)))){
		print_debug("ENOMOM\n");
		errno = ENOMEM;
        return;
    }

    update->update = (struct rtnl_route*)nl_object_clone((struct nl_object*)route);
    update->type = UPDATE_ROUTE;

    if(action == NL_ACT_NEW){
        update->action = ADD_RT;
		print_debug("route add: %d\n", action);
    } else if(action == NL_ACT_DEL){
        update->action = DEL_RT;
		print_debug("Route delete: %d\n", action);
    } else if(action == NL_ACT_GET){
		print_debug("Route get: %lu\n", (unsigned long)action);
    } else if(action == NL_ACT_SET){
		print_debug("Route set: %lu\n", (unsigned long)action);
    } else if(action == NL_ACT_CHANGE){
		update->action = CHANGE_RT;
		print_debug("Route change: %lu\n", (unsigned long)action);
    } else if(action == NL_ACT_UNSPEC){
		print_debug("Route unspec: %lu\n", (unsigned long)action);
    }

    item->next = 0;
    item->data = update;

    print_debug("add to queue\n");
    pthread_mutex_lock(mon->lock);
    queue_put(mon->queue, item);
    pthread_mutex_unlock(mon->lock);
	print_debug("sem_post\n");
    sem_post(mon->barrier);
}


/*
*
*/
void change_addr_cb(void *arg, struct nl_object *obj, int action)
{
    struct update_obj *update;
    Qitem *item;
    struct rtnl_addr *addr = (struct rtnl_addr *)obj;
    struct cache_monitor *mon = (struct cache_monitor*) arg;

    struct nl_addr *local = rtnl_addr_get_local(addr);

    if(nl_addr_get_family(local) != AF_INET){
		print_debug("Not IPv4\n");
        return;
    }

    if(!(update = malloc(sizeof(struct update_obj)))){
		print_debug("ENOMOM\n");
		errno = ENOMEM;
        return;
    }

    if(!(item = malloc(sizeof(Qitem)))){
		print_debug("ENOMOM\n");
		errno = ENOMEM;
        return;
    }

    update->update = (struct rtnl_addr*)nl_object_clone((struct nl_object*)addr);
    update->type = UPDATE_ADDR;

    if(action == NL_ACT_NEW){
		print_debug("Add IP\n");
        update->action = ADD_IP;
    } else if(action == NL_ACT_DEL){
		print_debug("Delete IP\n");
        update->action = DEL_IP;
    } else if(action == NL_ACT_CHANGE){
		print_debug("Change IP\n");
        update->action = CHANGE_IP;
    } else {
		print_debug("Unknown IP Action\n");
    }

    item->next = 0;
    item->data = update;
    print_debug("add to queue \n");

    pthread_mutex_lock(mon->lock);
    queue_put(mon->queue, item);
    pthread_mutex_unlock(mon->lock);

	print_debug("\n");

    sem_post(mon->barrier);
}


/*
*
*/
void change_link_cb(void *arg, struct nl_object *obj, int action)
{
    struct update_obj *update;
    Qitem *item;
    struct cache_monitor *mon = (struct cache_monitor*) arg;
    struct rtnl_link *link = (struct rtnl_link *)obj;

    if(!(update = malloc(sizeof(struct update_obj)))){
		print_debug("ENOMEM\n");
		errno = ENOMEM;
        return;
    }

    if(!(item = malloc(sizeof(Qitem)))){
		print_debug("ENOMEM\n");
		errno = ENOMEM;
        return;
    }

    update->update = (struct rtnl_link*)nl_object_clone((struct nl_object*)link);
    update->type = UPDATE_LINK;

    if(action == NL_ACT_NEW){
		print_debug("New Link\n");
        update->action = ADD_IFF;
    } else if(action == NL_ACT_DEL){
		print_debug("Delete Link\n");
        update->action = DEL_IFF;
    } else {
		print_debug("Update Link\n");
        if((rtnl_link_get_flags(update->update) & IFF_UP)){
            update->action = ADD_IFF;
        } else {
            update->action = DEL_IFF;
        }
    }

    item->next = 0;
    item->data = update;
    print_debug("add to queue\n");
    pthread_mutex_lock(mon->lock);
    queue_put(mon->queue, item);
    pthread_mutex_unlock(mon->lock);
    print_debug("sem_post\n");
    sem_post(mon->barrier);
}


/*
*
*/
void cache_update(struct nl_cache *cache, struct nl_object *obj, int action, void *arg)
{
    struct cache_monitor *mon = (struct cache_monitor*) arg;
	print_debug("\n");

    if(mon){
        if(cache == mon->addr_cache){
            change_addr_cb(arg, obj, action);
        } else if(cache == mon->link_cache){
            change_link_cb(arg, obj, action);
        } else if(cache == mon->route_cache){
            change_route_cb(arg, obj, action);
        }
    }
}


/*
*
*/
static void boot_addr_cache(struct nl_object *obj, void *arg)
{
	struct nl_ctx *pl = arg;
	print_debug("\n");
	change_addr_cb(pl, obj, NL_ACT_NEW);
}


/*
*
*/
static void boot_link_cache(struct nl_object *obj, void *arg)
{
	struct nl_ctx *pl = arg;
	print_debug("\n");
	change_link_cb(pl, obj, NL_ACT_NEW);
}


/*
*
*/
static void boot_route_cache(struct nl_object *obj, void *arg)
{
	struct nl_ctx *pl = arg;
	print_debug("\n");
	change_route_cb(pl, obj, NL_ACT_NEW);
}


/*
*
*/
void init_monitor(void *data)
{
	fd_set fds;
	int link_running = 1;
	int sk = 0;
    struct nl_sock *sock = nl_socket_alloc();
    int ret = 0;
    struct nl_cache_mngr *mngr = 0;
    struct cache_monitor *mon = (struct cache_monitor*)data;

    print_debug("\n");

    if((ret = nl_cache_mngr_alloc (sock, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr))){
        nl_perror(ret, 0);
        pthread_exit(&ret);
    }

	print_debug("add addr\n");
    if((ret = nl_cache_mngr_add(mngr, "route/addr", (change_func_t)&cache_update, mon, &(mon->addr_cache)))){
        nl_perror(ret, 0);
        pthread_exit(&ret);
    }

	print_debug("add link\n");
    if((ret = nl_cache_mngr_add(mngr, "route/link", (change_func_t)&cache_update, mon, &(mon->link_cache)))){
        nl_perror(ret, 0);
        pthread_exit(&ret);
    }

	print_debug("add route\n");
    if((ret = nl_cache_mngr_add(mngr, "route/route", (change_func_t)&cache_update, mon, &( mon->route_cache)))){
        nl_perror(ret, 0);
        pthread_exit(&ret);
    }

	print_debug("Boot cache\n");

    nl_cache_foreach(mon->link_cache, boot_link_cache, mon);
	nl_cache_foreach(mon->addr_cache, boot_addr_cache, mon);
	nl_cache_foreach(mon->route_cache, boot_route_cache, mon);
	print_debug("Setup FDS\n");


    sk = nl_socket_get_fd(sock);
    print_debug("Socket: %d\n", sk);
	while(link_running) {

		FD_ZERO(&fds);
        FD_SET(sk, &fds);
		if( select(sk+1, &fds, NULL, NULL, NULL) < 0 ) {
            ret = -1;
			perror("select");
			break;
		}
        ret = nl_cache_mngr_data_ready(mngr);
    }
    pthread_exit(&ret);
}

/* end file: link_monitor.c */
