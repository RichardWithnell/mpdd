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

#ifndef LMNL_INTERFACE
#define LMNL_INTERFACE

#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/data.h>
#include <netlink/netlink.h>
#include <netlink/netlink.h>
#include <netlink/object.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/route.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/rule.h>
#include <netlink/utils.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

struct mnl_addr
{
    uint32_t address;
    uint32_t local;
    uint32_t broadcast;
    uint32_t prefix;
    uint32_t prefixlen;
    int idx;
    uint32_t flags;
    char label[16];
    int family;
};

struct mnl_link
{
    int idx;
    unsigned int flags;
    uint8_t type;
    uint32_t family;
    char name[16];
};

struct mnl_route
{
    uint8_t table;
    int idx;
    uint32_t destination;
    uint32_t gateway;
    uint32_t prio;
    uint32_t family;
};

struct mnl_route* mnl_route_from_msg(struct rtmsg* rm, const struct nlmsghdr* nlh);
struct mnl_addr* mnl_addr_from_msg(struct ifaddrmsg* ifa, const struct nlmsghdr* nlh);
struct mnl_link* mnl_link_from_msg(struct ifinfomsg* ifm, const struct nlmsghdr* nlh);

struct rtnl_addr* mnl_to_rtnl_addr(struct mnl_addr* addr);
struct rtnl_link* mnl_to_rtnl_link(struct mnl_link* link);
struct rtnl_route* mnl_to_rtnl_route(struct mnl_route* route);
struct mnl_addr* rtnl_to_mnl_addr(struct rtnl_addr* addr);
struct mnl_link* rtnl_to_mnl_link(struct rtnl_link* link);
struct mnl_route* rtnl_to_mnl_route(struct rtnl_route* route);

#endif
