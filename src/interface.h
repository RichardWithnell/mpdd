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

#ifndef MPD_INTERFACE
#define MPD_INTERFACE

#include <errno.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/data.h>
#include <netlink/netlink.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/route.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/rule.h>
#include <netlink/utils.h>

#include "list.h"
#include "queue.h"
#include "util.h"

enum {
    EXTERNAL_ID_MODE_IP = 0x01,
    EXTERNAL_ID_MODE_MAC = 0x02
};

struct virtual_interface;
struct physical_interface;
struct interface;

enum {
    LB_DELETE_NEXTHOP = 0x01,
    LB_ADD_NEXTHOP = 0x02
};

enum {
    PHYSICAL_TYPE = 0x01,
    VIRTUAL_TYPE = 0x02
};

struct interface
{
    int type;
    uint8_t ifidx;
    char ifname[IFNAMSIZ];                 //iff name
};

struct metrics
{
    uint32_t bandwidth;
    uint16_t latency;
    uint8_t loss;
    uint8_t type;
};

struct physical_interface
{
    struct interface super;
    uint32_t address;
    uint32_t netmask;
    uint32_t gateway;
    uint32_t broadcast;
    uint32_t external_ip;
    uint32_t metric;
    uint8_t mac_address[6];
    uint8_t diss;
    uint8_t request;
    uint8_t timed_out;
    uint8_t depth;
    uint8_t flags;
    uint8_t table;
    uint8_t request_received;
    uint8_t packet_received;
    int last_update;
    int socket;
    struct sockaddr_in saddr;
    List* virt_list;
};

struct virtual_interface
{
    struct interface super;
    uint32_t address;
    uint32_t netmask;
    uint32_t gateway;
    uint32_t external_ip;
    uint32_t metric;
    uint32_t sender;
    uint8_t depth;
    uint8_t flags;
    uint8_t table;
    uint8_t type_gateway;
    uint8_t type_subnet;
    char label[IFNAMSIZ];
    int last_update;
    struct physical_interface* attach;
    struct physical_interface* out;
    struct virtual_interface* linked;
    List *backup_list;
};

struct physical_interface*
get_iff_network_update(uint32_t sender_ip, List* iff_list);

uint32_t get_host_id(struct physical_interface* phy);

int in_list(char* name, List* diss_list);
int mark_diss_iff(char* name, List* diss_list);

struct physical_interface* init_phys(void);
struct virtual_interface* init_virt(void);

void destroy_interface(struct interface* iff);
void destroy_phys_interface(struct physical_interface* phys);
void destroy_virt_interface(struct virtual_interface* virt);

struct interface* get_interface_by_idx(int ifidx, List* l);

struct interface*
add_link(struct rtnl_link* link,
         List* iff_list,
         List* ignore_list,
         List* diss_list,
         int type);

uint32_t
find_free_default_route_metric(struct nl_sock* sock,
                               uint32_t metric,
                               uint32_t inc);

struct virtual_interface* add_virtual(char* name, uint32_t idx, uint32_t flags, List* iff_list);

int delete_link(struct rtnl_link* link, List* iff, List* virt, List* ignore_list);
struct interface* add_addr(struct nl_sock* sock,
                           struct rtnl_addr* addr,
                           List* iff,
                           List* virt,
                           List* ignore_list,
                           List* diss_list);
int delete_address_rtnl(struct nl_sock* sock, struct rtnl_addr* addr, List* iff, List* virt);
struct physical_interface* add_route(struct nl_sock* sock,
                                     struct rtnl_route* route,
                                     List* iff,
                                     List* virt);
int delete_route(struct nl_sock* sock, struct rtnl_route* route, List* iff_list, List* virt_list);

int delete_default_route(struct nl_sock *sock, struct virtual_interface *virt);

int delete_address(struct nl_sock* sock, uint32_t ip, uint32_t netmask, uint8_t ifidx);

int16_t find_free_routing_table(struct nl_sock* sock);

int flush_table(struct nl_sock* sock, int table);
void flush_table_cb(struct nl_object* cb, void* arg);

int delete_virtual_by_gw(List* list, uint32_t gw);

int delete_rule(struct nl_sock* sock, uint32_t ip, uint32_t mask, uint32_t table);

void delete_rule_cb(struct nl_object* cb, void* arg);

int delete_route_from_physical(List* l, uint32_t route);

int add_address(struct nl_sock* sock, unsigned int ip, int ifidx, int label);
int create_aliases_for_gw(struct nl_sock* sock,
                          List* phys_list,
                          List* virt_list,
                          struct interface* p);
int create_rules_for_gw(struct nl_sock* sock, List* list, struct interface* gw);
int create_rule_for_gw(struct nl_sock* sock, struct interface* iff, int ifidx);
int create_routing_table(struct nl_sock* sock, struct interface* iff, List *virt_list);
int create_routing_table_subnet_route(struct nl_sock* sock, struct interface* iff, uint32_t idx, uint32_t table);
int create_routing_table_default_route(struct nl_sock* sock, struct interface* iff, uint32_t idx, uint32_t table);


int add_default_route(struct nl_sock* sock, unsigned int ip, int table, int ifidx, int metric);

int clean_up_interfaces(struct nl_sock* sock, List* virt_list, List* phys_list);

void print_interface(struct interface* iff);
void print_interface_list(List* l);

void free_subnet_cb(struct nl_object* cb, void* arg);
uint32_t find_free_subnet(struct nl_sock* sock);

int add_virt_for_diss(struct nl_sock* sock,
                      struct physical_interface* phy,
                      List* iff_list,
                      List* virt_list);

int add_load_balance_route_from_rtnl(struct nl_sock *sock, struct rtnl_route *route);
int delete_load_balance_route_from_rtnl(struct nl_sock *sock, struct rtnl_route *route);

#endif

/* end file: config.h */
