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

#include "../src/queue.h"
#include "../src/list.h"
#include "../src/util.h"
#include "../src/interface.h"
#include "../src/link_monitor.h"
#include "../src/network.h"

int main(void)
{    
    sem_t update_barrier; 
	struct cache_monitor mon_data;
    pthread_t monitor_thread;
	pthread_mutex_t update_lock;
	Queue update_queue;
    	
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
    
	mon_data.queue = &update_queue;
    mon_data.lock = &update_lock;
    mon_data.barrier = &update_barrier;
    mon_data.addr_cache = 0;
    mon_data.link_cache = 0;
	
	printf("Create monitor thread\n");
	pthread_create(&monitor_thread,
	               NULL,
	               (void *)&init_monitor,
	               (void *)&mon_data);
	
	
    while(1) {
        sem_wait(&update_barrier);

        pthread_mutex_lock(&update_lock);
        Qitem *qitem = queue_get(&update_queue);
        pthread_mutex_unlock(&update_lock);            

        if(qitem) {
            struct update_obj *u = qitem->data;
            if(u->type == UPDATE_LINK){
                struct rtnl_link *link = u->update;
                if(u->action == ADD_IFF) {
        			printf("Update Link - Add Link (%s)\n", 
        			    rtnl_link_get_name(link));
				} else if(u->action == DEL_IFF) {
        			printf("Update Link - Del Link (%s)\n", 
        			    rtnl_link_get_name(link));
				} else {
        			printf("Update Link - Unknown (%s)\n", 
        			    rtnl_link_get_name(link));
                }
            } else if(u->type == UPDATE_ADDR){
                struct rtnl_addr *addr = u->update;
                char addr_buff[32];
        		if(u->action == ADD_IP) {
					printf("Update Address - Add IP (%s - %s)\n", 
					    rtnl_addr_get_label(addr), 
					    nl_addr2str(rtnl_addr_get_local(addr), addr_buff, 32));
				} else if(u->action == DEL_IP) {
					printf("Update Address - Del IP (%s - %s)\n", 
					    rtnl_addr_get_label(addr),
					    nl_addr2str(rtnl_addr_get_local(addr), addr_buff, 32));
				} else {
					printf("Update Address - Unknown (%s - %s)\n", 
					    rtnl_addr_get_label(addr),
					    nl_addr2str(rtnl_addr_get_local(addr), addr_buff, 32));
				}        
            } else if(u->type == UPDATE_ROUTE){		
            	struct rtnl_route *route = u->update;
                struct rtnl_nexthop *nexthop = rtnl_route_nexthop_n (route, 0);
                struct nl_addr *gw = rtnl_route_nh_get_gateway (nexthop);
                char addr_buff[32];

        		if(u->action == ADD_RT) {
		    		printf("Update Route - Add RT (%s)\n",
		    		    nl_addr2str(gw, addr_buff, 32));    
        		} else if(u->action == DEL_RT) {
		    		printf("Update Route - Del RT (%s)\n",
		    		    nl_addr2str(gw, addr_buff, 32));    
        		} else if(u->action == CHANGE_RT){
		    		printf("Update Route - Change RT %d (%s)\n", 
		    		    u->action,
		    		    nl_addr2str(gw, addr_buff, 32));  
        		} else {
		    		printf("Update Route - Unknown %d (%s)\n", 
		    		    u->action,
		    		    nl_addr2str(gw, addr_buff, 32));
        		}	         
            } else if(u->type == UPDATE_GATEWAY){
                printf("Gateway Update (From remote host)\n");           
            }
        } else {
            printf("Not qitem\n");
        }
    }
	
	printf("Exiting monitor thread\n");
	pthread_join(monitor_thread, 0);
    return 0;
}
