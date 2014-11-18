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

#ifndef MPD_LINK_MONITOR
#define MPD_LINK_MONITOR

#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/addr.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/rule.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/data.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/addr.h>
#include <netlink/object.h>
#include <semaphore.h>
#include <pthread.h>

#include "queue.h"


struct cache_monitor {
    Queue *queue;
    pthread_mutex_t *lock;
    sem_t *barrier;
    struct nl_cache *addr_cache;
    struct nl_cache *link_cache;
    struct nl_cache *route_cache;
};

struct update_obj {
    int action;
    int type;
    void *update;
};

#define UPDATE_LINK 1
#define UPDATE_ADDR 2
#define UPDATE_ROUTE 3
#define UPDATE_GATEWAY 4

#define ADD_IFF 0x01
#define DEL_IFF 0x02
#define ADD_IP 0x03
#define DEL_IP 0x04
#define CHANGE_IP 0x07
#define CHANGE_RT 0x08
#define ADD_RT 0x05
#define DEL_RT 0x06

void init_monitor(void *data);
int destroy_monitor(void);

#endif

/* end file: link_monitor.h */
