#include <errno.h>

#include "../src/link_monitor.h"
	
struct nl_cache *lc, *nc, *ac, *rc;
	
void print_route_cb(void *arg, struct nl_object *obj, int action){
    char addr_buff[32];
    struct rtnl_route *route = (struct rtnl_route *)obj;
    struct rtnl_nexthop *nexthop = rtnl_route_nexthop_n (route, 0);
    struct nl_addr *gw = rtnl_route_nh_get_gateway (nexthop);    
    if(action == 1) printf("\tAdd ");
    else if(action == 2) printf("\tDel ");
    else printf("\tChange ");
    printf("Default Route - %s\n", nl_addr2str(gw, addr_buff, 32));
}
	
void change_cb(struct nl_cache *cache, struct nl_object *obj, int action, void *arg)
{
	if (cache == rc){
        printf("Route Update\n");
        print_route_cb(arg, obj, action);
    }
}

static void boot_route_cache(struct nl_object *obj, void *arg)
{
	struct nl_ctx *pl = arg;
	printf("boot_route_cache()\n");
	print_route_cb(pl, obj, NL_ACT_NEW);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    
	struct nl_cache_mngr *mngr;
	struct nl_sock *handle;

	handle = nl_socket_alloc();

	ret = nl_cache_mngr_alloc(handle, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
	if (ret) {
		nl_perror(ret, 0);
		return -1;
	}

	ret = nl_cache_mngr_add(mngr, "route/route",  (change_func_t)&change_cb, 0, &rc);
	if (ret) {
		nl_perror(ret, 0);
		return -1;
	}
	
    nl_cache_foreach(rc, boot_route_cache, NULL);
	
	while( 1 ) {
		int err = nl_cache_mngr_poll(mngr, 5000);
		if (err < 0) {
		    nl_perror(ret, 0);
			return -1;
		}
	}

	nl_cache_mngr_free(mngr);

	return 0;
}
