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

#include "lmnl_interface.h"
#include "debug.h"

int validate_link_attr_cb(const struct nlattr *attr, void *data)
{
  const struct nlattr **tb = data;
  int type = mnl_attr_get_type(attr);

  /* skip unsupported attribute in user-space */
  if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
  return MNL_CB_OK;

  switch(type) {
    case IFLA_IFNAME:
      if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
        perror("mnl_attr_validate2");
        return MNL_CB_ERROR;
      }
      break;
  }
  tb[type] = attr;
  return MNL_CB_OK;
}

int validate_addr_attr_cb(const struct nlattr *attr, void *data)
{
  const struct nlattr **tb = data;
  int type = mnl_attr_get_type(attr);

  /* skip unsupported attribute in user-space */
  if (mnl_attr_type_valid(attr, IFA_MAX) < 0)
  return MNL_CB_OK;

  switch(type) {
    case IFA_LABEL:
      if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
        perror("mnl_attr_validate");
        return MNL_CB_ERROR;
      }
      break;
      case IFA_ADDRESS:
      case IFA_LOCAL:
      case IFA_BROADCAST:
        if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
          perror("mnl_attr_validate");
          return MNL_CB_ERROR;
        }
    break;
  }
  tb[type] = attr;
  return MNL_CB_OK;
}

int validate_rt_attr_cb(const struct nlattr *attr, void *data)
{
  const struct nlattr **tb = data;
  int type = mnl_attr_get_type(attr);

  /* skip unsupported attribute in user-space */
  if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
  return MNL_CB_OK;

  switch(type) {
    case RTA_TABLE:
    case RTA_OIF:
    case RTA_GATEWAY:
    case RTA_PRIORITY:
    if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
      perror("mnl_attr_validate");
      return MNL_CB_ERROR;
    }
    break;
  }

  tb[type] = attr;
  return MNL_CB_OK;
}

struct mnl_link * mnl_link_from_msg(struct ifinfomsg *ifm, const struct nlmsghdr *nlh)
{
  struct mnl_link *link = (struct mnl_link*)0;
  struct nlattr *tb[RTA_MAX+1] = {};

  link = malloc(sizeof(struct mnl_link));
  //mnl_attr_parse(nlh, sizeof(*ifm), validate_link_attr_cb, tb);



  link->idx = ifm->ifi_index;
  link->type = ifm->ifi_type;
  link->flags = ifm->ifi_flags;
  link->family = ifm->ifi_family;


  if (tb[IFLA_IFNAME]) {
    strcpy(link->name, mnl_attr_get_str(tb[IFLA_IFNAME]));
  }

  return link;
}

struct mnl_addr * mnl_addr_from_msg(struct ifaddrmsg *ifa, const struct nlmsghdr *nlh)
{
  struct mnl_addr *addr = (struct mnl_addr*)0;
  struct nlattr *tb[RTA_MAX+1] = {};

  addr = malloc(sizeof(struct mnl_addr));

  mnl_attr_parse(nlh, sizeof(*ifa), validate_addr_attr_cb, tb);

  addr->idx = ifa->ifa_index;
  addr->family = ifa->ifa_family;
  addr->prefixlen =  ifa->ifa_prefixlen;
  addr->flags = ifa->ifa_flags;

  /*TODO FILL IN PREFIX*/
  addr->prefix = 0;

  if (tb[IFA_ADDRESS]) {
    void *a = mnl_attr_get_payload(tb[IFA_ADDRESS]);
    addr->address = *(uint32_t*)a;
  }

  if (tb[IFA_LOCAL]){
    void *local = mnl_attr_get_payload(tb[IFA_LOCAL]);
    addr->local = *(uint32_t*)local;
  }

  if (tb[IFA_BROADCAST]){
    void *bc = mnl_attr_get_payload(tb[IFA_BROADCAST]);
    addr->broadcast = *(uint32_t*)bc;
  }

  if (tb[IFA_LABEL]){
    void * label = mnl_attr_get_payload(tb[IFA_LABEL]);
    strcpy(addr->label, label);
  }

  return addr;
}

struct mnl_route * mnl_route_from_msg(struct rtmsg *rm, const struct nlmsghdr *nlh)
{
  struct mnl_route *rt = (struct mnl_route*)0;
  struct nlattr *tb[RTA_MAX+1] = {};

  rt = malloc(sizeof(struct mnl_route));

  mnl_attr_parse(nlh, sizeof(*rm), validate_rt_attr_cb, tb);

  rt->family = rm->rtm_family;

  switch(rm->rtm_family) {
    case AF_INET:
      if (tb[RTA_TABLE]) {
        rt->table = mnl_attr_get_u32(tb[RTA_TABLE]);
      }

      if (tb[RTA_OIF]) {
        rt->idx = mnl_attr_get_u32(tb[RTA_OIF]);
      }

      if (tb[RTA_GATEWAY]) {
        struct in_addr *addr = mnl_attr_get_payload(tb[RTA_GATEWAY]);
        rt->gateway = *(uint32_t*)addr;
      }

      if (tb[RTA_PRIORITY]) {
        rt->prio = mnl_attr_get_u32(tb[RTA_PRIORITY]);
      }

    break;
  }
  return rt;
}

struct rtnl_addr * mnl_to_rtnl_addr(struct mnl_addr *a)
{
  struct rtnl_addr *addr;

  addr = rtnl_addr_alloc();
  rtnl_addr_set_ifindex(addr, a->idx);
  rtnl_addr_set_prefixlen(addr, a->prefixlen);
  print_debug("PrefixLength: %d\n", a->prefixlen);
  rtnl_addr_set_flags(addr, a->flags);
  rtnl_addr_set_label(addr, a->label);
  rtnl_addr_set_family(addr, a->family);

  struct nl_addr *mb = nl_addr_build(a->family, (void *)&(a->broadcast), sizeof(a->broadcast));
  struct nl_addr *ml = nl_addr_build(a->family, (void *)&(a->local), sizeof(a->local));

  rtnl_addr_set_local(addr, ml);
  rtnl_addr_set_broadcast(addr, mb);

  return addr;
}

struct rtnl_link * mnl_to_rtnl_link(struct mnl_link *l)
{
  struct rtnl_link *link;

  link = rtnl_link_alloc();
  rtnl_link_set_name(link, l->name);
  rtnl_link_set_ifindex(link, l->idx);
//  rtnl_link_set_type(link, l->type);
  rtnl_link_set_flags(link, l->flags);

  return link;
}

struct rtnl_route * mnl_to_rtnl_route(struct mnl_route *r)
{
  struct rtnl_route *route;
  struct rtnl_nexthop *route_nh;
  struct nl_addr *gw;

  route = rtnl_route_alloc();
  route_nh = 	rtnl_route_nh_alloc();

  gw = nl_addr_build(r->family, (void *)&(r->gateway), sizeof(r->gateway));
  rtnl_route_nh_set_gateway(route_nh, gw);
  rtnl_route_nh_set_ifindex(route_nh, r->idx);

  rtnl_route_add_nexthop(route, route_nh);
  rtnl_route_set_table(route, r->table);
  rtnl_route_set_iif(route, r->idx);
  rtnl_route_set_priority(route, r->prio);

  return route;
}

struct mnl_addr * rtnl_to_mnl_addr(struct rtnl_addr *addr)
{
  return (struct mnl_addr*)0;
}

struct mnl_link * rtnl_to_mnl_link(struct rtnl_link *link)
{
  return (struct mnl_link*)0;
}

struct mnl_route * rtnl_to_mnl_route(struct rtnl_route *route)
{
  return (struct mnl_route*)0;
}
