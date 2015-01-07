/*
	gcc -fPIC -U_FORTIFY_SOURCE -o simple_link_monitor simple_link_monitor.c -pie -rdynamic -I/usr/include/libnl3 -lnl-3 -lnl-route-3
*/


#include <netlink/cache.h>
#include <unistd.h>
#include <sys/select.h>

static void go()
{
	struct timeval tv;
	struct nl_cache *rc;
	struct nl_cache_mngr *mngr = (struct nl_cache_mngr*)0;
	struct nl_sock *handle = nl_socket_alloc();
	int ret = 0;
	fd_set fds;

	if(!handle){
		printf("Handle is null\n");
	}

	printf("Manager Pointer: %p\n", mngr);

	ret = nl_cache_mngr_alloc(handle, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
	if (ret) {
		printf("Alloc Failed\n");
		return;
	}

	printf("Manager Alloc Ret Val: %d\n", ret);
	printf("Manager Pointer: %p\n", mngr);

	ret = nl_cache_mngr_add(mngr, "route/route",  (change_func_t)0, 0, &rc);
	if (ret) {
		printf("Add route failed %d\n", ret); /* -24 - "Unknown or invalid cache type"*/
		return;
	} else {
		printf("Added Route Manager\n");
	}

	while(ret >= 0){
		int sk = nl_cache_mngr_get_fd(mngr);
		FD_ZERO(&fds);
		FD_SET(sk, &fds);
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		ret = select(sk+1, &fds, 0, 0, &tv);
		if (ret > 0) {
			nl_cache_mngr_data_ready(mngr);
			printf("Do something...\n");
		} else if (!ret) printf("Timeout...\n");
		else printf("Error...\n");
	}
}

int main(int argc, char *argv[])
{
	go();

	return 0;
}
