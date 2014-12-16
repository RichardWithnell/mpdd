#include <netlink/cache.h>
#include <unistd.h>
#include <sys/select.h>

int main(int argc, char *argv[])
{
	struct timeval tv;
	struct nl_cache *rc;
	struct nl_cache_mngr *mngr;
	struct nl_sock *handle = nl_socket_alloc();
	int ret = 0;
	fd_set fds;

	ret = nl_cache_mngr_alloc(handle, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
	if (ret) {
		printf("Alloc Failed\n");
		return -1;
	}

	ret = nl_cache_mngr_add(mngr, "route/route",  (change_func_t)0, 0, &rc);
	if (ret) {
		printf("Add route failed\n");
		return -1;
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

	return 0;
}
