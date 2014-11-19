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
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <unistd.h>
#include <signal.h>

#include "debug.h"
#include "queue.h"
#include "list.h"
#include "util.h"
#include "interface.h"
#include "link_monitor.h"
#include "network.h"
#include "config.h"



#define MAX_DEPTH 255

#define CONFIG_FILE "/etc/mpd/mpdd.conf"

static int running = 1;

sem_t update_barrier;

int
handle_gateway_update(
	struct network_update *nupdate,
	List *iff_list,
	List *virt_list,
	struct nl_sock *sock,
	struct send_queue squeue);

void sig_handler(int signum);
int cleanup();


/*
*
*/
void sig_handler(int signum){
	if (signum == SIGINT){
		running = 0;
	}
	sem_post(&update_barrier);
}


/*
*
*/
int
main(int argc, char *argv[])
{

	struct nl_sock *sock = (struct nl_sock*)0;

	struct mpd_config *config = (struct mpd_config*)0;

	List *iff_list = 0;
	List *virt_list = 0;
	List *diss_list = 0;
	List *ignore_list = 0;

	/*Define variables for libnl updates*/
	struct cache_monitor mon_data;
	pthread_t monitor_thread;
	pthread_t network_thread;
	pthread_mutex_t update_lock;
	Queue update_queue;
	struct send_queue squeue;

	/*Setup libnl socket*/
	if(!(sock = nl_socket_alloc())){
		fprintf(stderr, "Alloc nl sock failed\n");
		return -1;
	}
	/*Connect to the link module*/
	if(nl_connect(sock, NETLINK_ROUTE)){
		fprintf(stderr, "Connect nl sock failed\n");
		nl_socket_free(sock);
		return -1;
	}

	/*Register signal handler*/
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Failed to register signal handler\n");
		return FAILURE;
	}

	if(!(iff_list = malloc(sizeof(List)))) {
		fprintf(stderr, "Failed to allocate memory for phys interface list\n");
		errno = ENOMEM;
		return FAILURE;
	}

	if(!(virt_list = malloc(sizeof(List)))) {
		fprintf(stderr, "Failed to allocate memory for virt interface list\n");
		errno = ENOMEM;
		return FAILURE;
	}

	list_init(iff_list);
	list_init(virt_list);

	if (pthread_mutex_init(&(squeue.flag_lock), NULL) != 0) {
		fprintf(stderr, "Update mutex init failed\n");
		return FAILURE;
	}

	if (pthread_mutex_init(&(squeue.request_flag_lock), NULL) != 0) {
		fprintf(stderr, "Update mutex init failed\n");
		return FAILURE;
	}

	if (pthread_mutex_init(&(squeue.iff_list_lock), NULL) != 0) {
		fprintf(stderr, "Update mutex init failed\n");
		return FAILURE;
	}

	if (pthread_mutex_init(&(squeue.virt_list_lock), NULL) != 0) {
		fprintf(stderr, "Update mutex init failed\n");
		return FAILURE;
	}

	if (pthread_mutex_init(&update_lock, NULL) != 0) {
		fprintf(stderr, "Update mutex init failed\n");
		return FAILURE;
	}

	if (sem_init(&update_barrier, 0, 0) != 0) {
		fprintf(stderr, "Update barrier init failed\n");
		return FAILURE;
	}

	if(queue_init(&update_queue)) {
		printf("Queue init failed\n");
		return FAILURE;
	}
	print_debug("Loading Config\n");
	config = load_config(CONFIG_FILE);
	if(!config){
		print_debug("Loading the configuration file failed\n");
		return FAILURE;
	}
	diss_list = config->diss;
	ignore_list = config->ignore;

	mon_data.queue = &update_queue;
	mon_data.lock = &update_lock;
	mon_data.barrier = &update_barrier;
	mon_data.addr_cache = 0;
	mon_data.link_cache = 0;

	pthread_create(&monitor_thread, NULL, (void *)&init_monitor, (void *)&mon_data);

	queue_init(&(squeue.receive_queue));
	queue_init(&(squeue.request_queue));
	squeue.flag = 0;
	squeue.request_flag = 0;
	squeue.iff_list = iff_list;
	squeue.virt_list = virt_list;
	squeue.old_virt_list = virt_list;
	squeue.running = 1;
	squeue.mon_data = &mon_data;

	pthread_create(&network_thread, NULL, (void *)&recv_broadcast, (void *)&squeue);

	while(running) {
		sem_wait(&update_barrier);
		if(!running) break;
			print_debug("Recieved update\n");
			pthread_mutex_lock(&update_lock);
			Qitem *qitem = queue_get(&update_queue);
			pthread_mutex_unlock(&update_lock);

			if(qitem) {
				struct update_obj *u = qitem->data;
				print_debug("Recieved qitem %d\n", u->type);
				if(u->type == UPDATE_LINK){
					struct rtnl_link *link = u->update;
					if(u->action == ADD_IFF) {
						print_debug("Update Link - Add Link\n");
						/*Make sure we are interested in this interface*/
						pthread_mutex_lock(&(squeue.iff_list_lock));
						if(!add_link(link, iff_list, ignore_list, diss_list, PHYSICAL_TYPE)){
							pthread_mutex_unlock(&(squeue.iff_list_lock));
							goto LOOP_END;
						}
						pthread_mutex_unlock(&(squeue.iff_list_lock));

					} else if(u->action == DEL_IFF) {
						print_debug("Update Link - Del Link\n");
						pthread_mutex_lock(&(squeue.iff_list_lock));
						if(!delete_link(link, iff_list, virt_list, ignore_list)){
							pthread_mutex_unlock(&(squeue.iff_list_lock));
							goto LOOP_END;
						}
						pthread_mutex_unlock(&(squeue.iff_list_lock));
					} else {
						print_debug("Update Link - Unknown\n");
					}
				} else if(u->type == UPDATE_ADDR){
					struct rtnl_addr *addr = (struct rtnl_addr*)u->update;
					if(u->action == ADD_IP) {
						struct interface *iff = 0;
						print_debug("Update Address - Add IP\n");
						pthread_mutex_lock(&(squeue.iff_list_lock));
						iff = add_addr(sock, addr, iff_list,
								virt_list, ignore_list, diss_list);
						pthread_mutex_unlock(&(squeue.iff_list_lock));

						if(!iff){
							print_debug("Add address failed...\n");
							goto LOOP_END;
						}
						/*Tell the network thread there was an update*/
						if(iff->type == VIRTUAL_TYPE ){
							struct virtual_interface *virt;

							print_debug("Virtual address added\n");

							virt = (struct virtual_interface*)iff;
							/*Check we actually have connectivity
							TODO make the external IP check continuous*/
							if(virt->out->external_ip != 0){
								pthread_mutex_lock(&(squeue.flag_lock));
								squeue.flag = 1;
								pthread_mutex_unlock(&(squeue.flag_lock));
							}
						} else if(iff->type == PHYSICAL_TYPE ) {
							struct physical_interface *phys;
							Qitem *qi;

							print_debug("Physical address added\n");

							qi = malloc(sizeof(qi));
							phys = (struct physical_interface *)iff;
							qi->data = phys;

							/*Found a new interface, request MPDD updates*/
							pthread_mutex_lock(&(squeue.flag_lock));
							squeue.request_flag = 1;
							queue_put(&(squeue.request_queue), qi);
							pthread_mutex_unlock(&(squeue.flag_lock));
						}
					} else if(u->action == DEL_IP) {
						print_debug("Update Address - Del IP\n");
						pthread_mutex_lock(&(squeue.iff_list_lock));
						delete_addr(addr, iff_list, virt_list);
						pthread_mutex_unlock(&(squeue.iff_list_lock));
					} else {
						print_debug("Update Address - Unknown\n");
					}
				} else if(u->type == UPDATE_ROUTE){
					struct rtnl_route *route = u->update;
					print_debug("Recieved update route type: %d\n", u->action);
					if(u->action == ADD_RT) {
						print_debug("Update Route - Add RT\n");
						pthread_mutex_lock(&(squeue.iff_list_lock));
						add_route(sock, route, iff_list, virt_list);
						pthread_mutex_unlock(&(squeue.iff_list_lock));

						print_debug("Update Route - Completed\n");
					} else if(u->action == DEL_RT) {
						print_debug("Update Route - Del RT\n");
						pthread_mutex_lock(&(squeue.iff_list_lock));
						delete_route(sock, route, iff_list, virt_list);
						pthread_mutex_unlock(&(squeue.iff_list_lock));

						/*
						* Tell the network thread
						* there was an update to the list
						*/
						pthread_mutex_lock(&(squeue.flag_lock));
						squeue.flag = 1;
						pthread_mutex_unlock(&(squeue.flag_lock));
					} else if(u->action == CHANGE_RT){
						print_debug("Update Route - Change RT %d\n", u->action);
						pthread_mutex_lock(&(squeue.iff_list_lock));
						add_route(sock, route, iff_list, virt_list);
						pthread_mutex_unlock(&(squeue.iff_list_lock));
					} else {
						print_debug("Update Route - Unknown %d\n", u->action);
					}
				} else if(u->type == UPDATE_GATEWAY){

					struct network_update *nupdate = 0;

					nupdate = (struct network_update*)u->update;

					if(!nupdate){
						goto LOOP_END;
					}

					if(handle_gateway_update(nupdate,
							iff_list, virt_list, sock, squeue))
					{
						print_debug("Network Update exited\n");
						goto LOOP_END;
					}

				}
LOOP_END:
				printf("#######################\n");
				printf("-----------------------\n");
				printf("- Physical Interfaces -\n");
				printf("-----------------------\n");
				pthread_mutex_lock(&(squeue.iff_list_lock));
				print_interface_list(iff_list);
				pthread_mutex_unlock(&(squeue.iff_list_lock));
				printf("-----------------------\n");
				printf("- Virtual Interfaces  -\n");
				printf("-----------------------\n");
				print_interface_list(virt_list);
				printf("#######################\n");
			}
			free(qitem);
		}
		printf("\n#######################\n");
		print_debug("Cleaning up...\n");
		clean_up_interfaces(sock, virt_list);
		print_debug("Done\n");
		return SUCCESS;
	}


/*
*
*/
int
handle_gateway_update(
	struct network_update *nupdate,
	List *iff_list,
	List *virt_list,
	struct nl_sock *sock,
	struct send_queue squeue)
{
	struct physical_interface * temp_phys;
	struct virtual_interface * temp_virt;
	struct mpdpacket *pkt;
	struct sockaddr_in *addr;
	struct physical_interface *phy;
	uint32_t host_id = 0;
	int idx = 0;
	int i = 0;
	int exists = 0;

	print_debug("Update gateway\n");
	pkt = &(nupdate->pkt);
	addr = &(nupdate->addr);

	pthread_mutex_lock(&(squeue.iff_list_lock));
	phy = get_iff_network_update(addr->sin_addr.s_addr,
								iff_list);
	pthread_mutex_unlock(&(squeue.iff_list_lock));

	host_id = get_host_id(phy);
	for(idx = 0; idx < pkt->header->num; idx++){
		struct mpdentry *entry = (pkt->entry)+idx;
		Litem *item;
		struct virtual_interface * v;
		uint32_t host_ip = 0;

		if (entry->depth >= MAX_DEPTH){
			return FAILURE;
		}

		//check IP doesnt already exist;
		host_ip = htonl((entry->netmask & entry->address) | htonl(host_id));

		print_debug("Lock ifflist\n");
		pthread_mutex_lock(&(squeue.iff_list_lock));
		for(i = 0; i < list_size(iff_list); i++){
			temp_phys = (struct physical_interface*)
							(list_get(iff_list, i))->data;
			if(temp_phys){
				if(temp_phys->address == host_ip){
					print_debug("Address already exists, skipping\n");
					exists = 1;
					break;
				}
			}
		}
		pthread_mutex_unlock(&(squeue.iff_list_lock));
		print_debug("Unlock ifflist\n");

		if(exists){
			return FAILURE;
		}

		print_debug("Virt List: %p\n", virt_list);
		print_debug("Virt List: %p\n", virt_list->front);

		if(virt_list->front){
			for(i = 0; i < list_size(virt_list); i++){
				temp_virt = (struct virtual_interface*)
					(list_get(virt_list, i))->data;
				if(temp_virt){
					if(temp_virt->address == host_ip){
						print_debug("Address already exists\n");
						exists = 1;
						break;
					}
				}
			}
		}

		if(exists){
			return FAILURE;
		}

		print_debug("Lock ifflist\n");

		pthread_mutex_lock(&(squeue.iff_list_lock));
		v = add_virtual(phy->super.ifname,
						phy->super.ifidx,
						0,
						virt_list);
		pthread_mutex_unlock(&(squeue.iff_list_lock));
		print_debug("Unlock ifflist\n");

		print_debug("Added virtual interface %p\n", v);

		if(!v){
			print_debug("Failed to add virtual interface\n");
			return FAILURE;
		}

		print_debug("External IP: %s\n", ip_to_str(htonl(entry->ext_ip)));

		v->gateway = htonl(entry->address);
		v->out = phy;
		v->attach = phy;
		v->address = host_ip;
		v->netmask = htonl(entry->netmask);
		v->depth = entry->depth + 1;
		v->external_ip = htonl(entry->ext_ip);
		print_debug("Find a free routing table\n");
		v->table = find_free_routing_table(sock);
		print_debug("\tAssigned - %u\n", v->table);
		item = (Litem*)malloc(sizeof(Litem));
		if(!item){
			errno = ENOMEM;
			destroy_virt_interface(v);
			fprintf(stderr, "Failed to malloc a new list item\n");
		}
		print_debug("Add the new virtual interface to the phy list\n");
		item->data = (void*)v;
		print_debug("Add address to the interface\n");
		print_debug("Virt IP: %s\n", ip_to_str(v->address));
		print_debug("Physical Virt List: %p\n", phy->virt_list);
		if(!phy->virt_list){
			phy->virt_list = malloc(sizeof(List));
			list_init(phy->virt_list);
			print_debug("Init Physical Virt List: %p\n", phy->virt_list);

		}
		list_put(phy->virt_list, item);
		print_debug("Added item, interfacse (%d)\n", list_size(phy->virt_list));


		print_debug("Lock ifflist\n");
		pthread_mutex_lock(&(squeue.iff_list_lock));
		if(add_address(sock,
						v->address,
						phy->super.ifidx,
						list_size(phy->virt_list)))
		{
			pthread_mutex_unlock(&(squeue.iff_list_lock));

			/*
			This could be because the address already exists
			in which case, we should try and add the default
			route anyway.
			*/
			fprintf(stderr, "Failed to add address, for network update\n");
			//continue;
		}
		pthread_mutex_unlock(&(squeue.iff_list_lock));
		print_debug("Unlock ifflist\n");


		print_debug("Create the default route\n");

		pthread_mutex_lock(&(squeue.iff_list_lock));

		if(add_default_route(sock, entry->address, v->table, phy->super.ifidx))
		{
			pthread_mutex_unlock(&(squeue.iff_list_lock));

			fprintf(stderr, "Failed to add route, for network update\n");
			return FAILURE;
		}
		pthread_mutex_unlock(&(squeue.iff_list_lock));

	}

	return SUCCESS;
}

/* end file: mpdd.c */
