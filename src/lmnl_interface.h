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

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "link_monitor_lmnl.h"

struct rtnl_addr * mnl_to_rtnl_addr(struct mnl_addr *addr);
struct rtnl_link * mnl_to_rtnl_link(struct mnl_link *link);
struct rtnl_route * mnl_to_rtnl_route(struct mnl_route *route);
struct mnl_addr * rtnl_to_mnl_addr(struct rtnl_addr *addr);
struct mnl_link * rtnl_to_mnl_link(struct rtnl_link *link);
struct mnl_route * rtnl_to_mnl_route(struct rtnl_route *route);
