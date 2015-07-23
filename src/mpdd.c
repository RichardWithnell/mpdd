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

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "debug.h"
#include "interface.h"
#include "link_monitor.h"
#include "list.h"
#include "network.h"
#include "queue.h"
#include "util.h"
#include "resource_interface.h"

#define ENABLE_HEARTBEAT 1
#define ENABLE_LINK_TIMEOUT 1
#define BACKUP_LINK_SUPPORT 1
#define ENABLE_LOAD_BALANCE 0

static const int MAX_DEPTH = 255;
static const int HEART_BEAT_TIME = 10;
static const int LINK_CHECK_TIME = 2;
static const int LINK_TIMEOUT = 60;

static const char DEF_CONFIG_FILE[32] = "/etc/mpd/mpdd_simple.conf";

static const char LOAD_BALANCING = ENABLE_LOAD_BALANCE;


static int running = 1;

sem_t update_barrier;
char host_name[32];

int
handle_gateway_update(
    struct network_update* nupdate,
    List* iff_list,
    List* virt_list,
    struct nl_sock* sock,
    struct send_queue squeue);

void sig_handler(int signum);
int cleanup();

static void* flag_heartbeat(void* data);
static void* check_timeout(void* data);
int delete_old_route(
  struct nl_sock *sock,
  struct physical_interface *phy,
  struct virtual_interface* virt,
  List *iff_list,
  List *virt_list,
  int i);


struct send_queue squeue;
List* iff_list = 0;
List* virt_list = 0;

static int lookup_weight(uint32_t ip)
{
    return 1;
}


/*
 *
 */
static void* check_timeout(void* data)
{
    int i = 0;
    Litem *item;
    struct send_queue* squeue = (struct send_queue*)data;

    List *phys_list = squeue->iff_list;
    List* virt_list = squeue->virt_list;
    struct nl_sock *sock = squeue->sock;
    if(!squeue) {
        print_error("struct send_queue is null");
        return (void*)-1;
    }

    while(running) {
        pthread_mutex_lock(&squeue->iff_list_lock);
        /*Check links*/
        list_for_each(item, virt_list){
            struct virtual_interface* virt =
                (struct virtual_interface*)item->data;
            if(virt && (virt->attach == virt->out)) {
                virt->last_update -= LINK_CHECK_TIME;
                print_debug("Virt Last Update: %d\n", virt->last_update);
                if(virt->last_update <= 0) {
                    delete_old_route(sock, virt->out, virt, phys_list, virt_list, i);
                    /*Add to event list*/
                    print_debug("Virt %s: timed out\n",
                        ip_to_str(ntohl(virt->address)));
                }
            }
            i++;
        }
        pthread_mutex_unlock(&squeue->iff_list_lock);

        sleep(LINK_CHECK_TIME);
    }

    return (void*)0;
}


/*
 *
 */
static void* flag_heartbeat(void* data)
{
    struct send_queue* squeue = (struct send_queue*)data;

    if(!squeue) {
        print_error("struct send_queue is null");
        return (void*)-1;
    }

    while(running) {
        /* Take appropriate actions for signal delivery */
        pthread_mutex_lock(&squeue->flag_lock);
        squeue->flag = 1;
        print_verb("Send Heartbeat\n");
        pthread_mutex_unlock(&squeue->flag_lock);

        sleep(HEART_BEAT_TIME);
    }

    return (void*)0;
}


/*
 *
 */
void sig_handler(int signum)
{
    if (signum == SIGINT) {
        running = 0;
    }
    sem_post(&update_barrier);
}


/*
*
*/
int is_virtual_route(struct rtnl_route *route, List * virt_list)
{
    struct rtnl_nexthop *nexthop = (struct rtnl_nexthop*)0;
    struct nl_addr* gw = (struct nl_addr*)0;
    uint32_t binary_gw = 0;
    Litem *vitem;

    if (route) {
        nexthop = rtnl_route_nexthop_n(route, 0);
    } else {
        print_debug("route is NULL\n");
        return 0;
    }

    if (nexthop) {
        gw = rtnl_route_nh_get_gateway(nexthop);
    } else {
        print_debug("nexthop is NULL\n");
        return 0;
    }

    if (gw) {
        binary_gw = *(uint32_t*)nl_addr_get_binary_addr(gw);
    } else {
        print_debug("gw is NULL\n");
        return 0;
    }

    list_for_each(vitem, virt_list){
        struct virtual_interface *virt = (struct virtual_interface*)vitem->data;
        if(virt->gateway == binary_gw){
            return 1;
        }
    }

    return 0;
}


/*
 *
 */
void print_nexthop_cb(struct rtnl_nexthop* nh, void* args)
{
    struct timespec monotime;
    char buff[32];
    struct nl_addr* gw = rtnl_route_nh_get_gateway(nh);
    clock_gettime(CLOCK_REALTIME, &monotime);
    print_eval("NR:%s:%s:%lld.%.9ld\n",
               host_name,
               nl_addr2str(gw, buff, (size_t)32),
               (long long)monotime.tv_sec,
               (long)monotime.tv_nsec);
}


/*
*
*/
void print_help_message(void)
{
    printf("Usage: mpdd [-cC] configfile.");
    printf("\t -c\t Minimal Config file");
    printf("\t -C\t libconfig file");
}


/*
 *
 */
int
main(int argc, char* argv[])
{
    struct nl_sock* sock = (struct nl_sock*)0;
    struct mpd_config* config = (struct mpd_config*)0;

    List* diss_list = 0;
    List* ignore_list = 0;

    /*Define variables for libnl updates*/
    struct cache_monitor mon_data;
    pthread_t monitor_thread;
    pthread_t network_thread;
    pthread_t timeout_thread;
    pthread_t heartbeat_thread;

    pthread_mutex_t update_lock;
    Queue update_queue;

    /*Define options for command line args*/
    struct stat fileStat;
    int c = 0;
    char* config_path = (char*)0;
    int minimal_config = 0;

    static struct option long_options[] = {
        {"conf", required_argument, 0, 'c'},
        {"minimal-conf", required_argument, 0, 'C'},
        {0, 0, 0, 0}
    };

    print_debug("TEST HTONL: %lu %lu\n", 0x00000001, htonl(0x00000001));
    print_debug("TEST NTOHL: %lu %lu\n", 0x00000001, htonl(0x00000001));


    srand(time(0));

    while(1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "c:C:", long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch(c) {
            case 'c':
                if(optarg) {
                    int pathlength = strlen(optarg);
                    config_path = malloc(pathlength + 1);
                    strcpy(config_path, optarg);
                }
                break;
            case 'C':
                if(optarg) {
                    minimal_config = 1;
                    int pathlength = strlen(optarg);
                    config_path = malloc(pathlength + 1);
                    strcpy(config_path, optarg);
                }
                break;
            case 'h':
                print_help_message();
                return 0;
            case '?':
                break;
            default:
                return -1;
        }
    }

    if(!config_path) {
        config_path = malloc(strlen(DEF_CONFIG_FILE));
        strcpy(config_path, DEF_CONFIG_FILE);
    }

    if(stat(config_path, &fileStat)) {
        print_error("Config file not found: %s\n", config_path);
        return -1;
    } else {
        print_debug("Found config file: %s\n", config_path);
    }

    /*Write PID file*/
    remove("/var/run/mpdd.pid");
    int pid_fd = open("/var/run/mpdd.pid", O_RDWR | O_CREAT | O_TRUNC, 666);
    if(!pid_fd) {
        print_error("Could not open pid file.\n");
        return -1;
    } else {
        char pid_buff[128];
        snprintf(pid_buff, 128, "%ld\n", (long)getpid());

        if (write(pid_fd, pid_buff, strlen(pid_buff)) != strlen(pid_buff)) {
            print_error("Could not write to pid file.\n");
            return -1;
        }
        close(pid_fd);
    }

    print_debug("LIBNL: %d.%d.%d\n",
                LIBNL_VER_MAJ,
                LIBNL_VER_MIN,
                LIBNL_VER_MIC);

    memset(host_name, 0, 32);

    /*Setup libnl socket*/
    if(!(sock = nl_socket_alloc())) {
        print_error("Alloc nl sock failed\n");
        return -1;
    }
    /*Connect to the link module*/
    if(nl_connect(sock, NETLINK_ROUTE)) {
        print_error("Connect nl sock failed\n");
        nl_socket_free(sock);
        return -1;
    }

    /*Register signal handler*/
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        print_error("Failed to register signal handler\n");
        return FAILURE;
    }

    if(!(iff_list = malloc(sizeof(List)))) {
        print_error("Failed to allocate memory for phys interface list\n");
        errno = ENOMEM;
        return FAILURE;
    }

    if(!(virt_list = malloc(sizeof(List)))) {
        print_error("Failed to allocate memory for virt interface list\n");
        errno = ENOMEM;
        return FAILURE;
    }

    list_init(iff_list);
    list_init(virt_list);

    if (pthread_mutex_init(&(squeue.flag_lock), NULL) != 0) {
        print_error("Update mutex init failed\n");
        return FAILURE;
    }

    if (pthread_mutex_init(&(squeue.request_flag_lock), NULL) != 0) {
        print_error("Update mutex init failed\n");
        return FAILURE;
    }

    if (pthread_mutex_init(&(squeue.iff_list_lock), NULL) != 0) {
        print_error("Update mutex init failed\n");
        return FAILURE;
    }

    if (pthread_mutex_init(&(squeue.virt_list_lock), NULL) != 0) {
        print_error("Update mutex init failed\n");
        return FAILURE;
    }

    if (pthread_mutex_init(&update_lock, NULL) != 0) {
        print_error("Update mutex init failed\n");
        return FAILURE;
    }

    if (sem_init(&update_barrier, 0, 0) != 0) {
        print_error("Update barrier init failed\n");
        return FAILURE;
    }

    if(queue_init(&update_queue)) {
        printf("Queue init failed\n");
        return FAILURE;
    }

    if(minimal_config) {
        print_debug("Loading Minimal Config\n");
        config = load_min_config(config_path);
    } else {
        print_debug("Loading Full Config\n");
        config = load_config(config_path);
    }
    if(!config) {
        print_debug("Loading the configuration file failed\n");
        return FAILURE;
    }
    free(config_path);
    diss_list = config->diss;
    ignore_list = config->ignore;
    strcpy(host_name, config->host_id);

    print_debug("Host Name: %s config->host_id: %s\n", host_name, config->host_id);

    mon_data.queue = &update_queue;
    mon_data.lock = &update_lock;
    mon_data.barrier = &update_barrier;
    //mon_data.addr_cache = 0;
    //mon_data.link_cache = 0;
    //mon_data.route_cache = 0;

    pthread_create(&monitor_thread, NULL,
                   (void*)&init_monitor, (void*)&mon_data);

    queue_init(&(squeue.receive_queue));
    queue_init(&(squeue.request_queue));
    squeue.flag = 0;
    squeue.request_flag = 0;
    squeue.iff_list = iff_list;
    squeue.virt_list = virt_list;
    squeue.old_virt_list = virt_list;
    squeue.running = 1;
    squeue.mon_data = &mon_data;
    squeue.sock = sock;

    pthread_create(&network_thread, NULL,
                   (void*)&recv_broadcast, (void*)&squeue);

    if(ENABLE_HEARTBEAT) {
        pthread_create(&heartbeat_thread, NULL,
                       (void*)&flag_heartbeat, (void*)&squeue);
    }

    if(ENABLE_LINK_TIMEOUT) {
        pthread_create(&timeout_thread, NULL,
                       (void*)&check_timeout, (void*)&squeue);
    }

    while(running) {
        print_debug("Waiting on barrier\n");
        sem_wait(&update_barrier);
        if(!running) {
            break;
        }
        print_debug("Recieved update\n");
        pthread_mutex_lock(&update_lock);
        Qitem* qitem = queue_get(&update_queue);
        pthread_mutex_unlock(&update_lock);

        if(qitem) {
            struct update_obj* u = qitem->data;
            print_debug("Recieved qitem %d\n", u->type);
            if(u->type == UPDATE_LINK) {
                struct rtnl_link* link = u->update;
                if(u->action == ADD_IFF) {
                    print_debug("Update Link - Add Link\n");
                    /*Make sure we are interested in this interface*/
                    pthread_mutex_lock(&(squeue.iff_list_lock));
                    if(!add_link(link, iff_list, ignore_list,
                                 diss_list, PHYSICAL_TYPE)) {
                        pthread_mutex_unlock(&(squeue.iff_list_lock));
                        goto LOOP_END;
                    }
                    pthread_mutex_unlock(&(squeue.iff_list_lock));
                } else if(u->action == DEL_IFF) {
                    print_debug("Update Link - Del Link\n");
                    pthread_mutex_lock(&(squeue.iff_list_lock));
                    if(!delete_link(link, iff_list, virt_list, ignore_list)) {
                        pthread_mutex_unlock(&(squeue.iff_list_lock));
                        goto LOOP_END;
                    }
                    pthread_mutex_unlock(&(squeue.iff_list_lock));
                } else {
                    print_debug("Update Link - Unknown\n");
                }
            } else if(u->type == UPDATE_ADDR) {
                struct rtnl_addr* addr = (struct rtnl_addr*)u->update;
                if(u->action == ADD_IP) {
                    struct interface* iff = 0;
                    print_debug("Update Address - Add IP\n");
                    pthread_mutex_lock(&(squeue.iff_list_lock));

                    iff = add_addr(sock, addr, iff_list,
                                   virt_list, ignore_list, diss_list);
                    pthread_mutex_unlock(&(squeue.iff_list_lock));

                    if(!iff) {
                        print_debug("Add address failed...\n");
                        goto LOOP_END;
                    }
                    /*Tell the network thread there was an update*/
                    if(iff->type == VIRTUAL_TYPE ) {
                        struct virtual_interface* virt;

                        print_debug("Virtual address added\n");

                        virt = (struct virtual_interface*)iff;
                        /*Check we actually have connectivity
                           TODO make the external IP check continuous*/
                        if(virt->external_ip != 0) {
                            char* external_ip =
                                ip_to_str(ntohl(virt->external_ip));
                            print_debug(
                                "Virtual Interface has Internet "
                                "connection %s\n",
                                external_ip);
                            pthread_mutex_lock(&(squeue.flag_lock));
                            squeue.flag = 1;
                            pthread_mutex_unlock(&(squeue.flag_lock));
                        }
                    } else if(iff->type == PHYSICAL_TYPE ) {
                        struct physical_interface* phys =
                            (struct physical_interface*)0;
                        Qitem* qi = (Qitem*)0;

                        print_debug("Physical address added\n");

                        if(!(qi = malloc(sizeof(Qitem)))) {
                            print_debug("Malloc failed\n");
                            continue;
                        }
                        phys = (struct physical_interface*)iff;
                        qi->data = phys;

                        if(phys->diss) {
                            pthread_mutex_lock(&(squeue.iff_list_lock));
                            add_virt_for_diss(sock,
                                              phys,
                                              iff_list,
                                              virt_list);
                            pthread_mutex_unlock(&(squeue.iff_list_lock));
                        }

                        /*Found a new interface, request MPDD updates*/
                        pthread_mutex_lock(&(squeue.flag_lock));
                        squeue.request_flag = 1;
                        queue_put(&(squeue.request_queue), qi);
                        pthread_mutex_unlock(&(squeue.flag_lock));
                    }
                } else if(u->action == DEL_IP) {
                    int ret_val = 0;
                    print_debug("Update Address - Del IP\n");
                    pthread_mutex_lock(&(squeue.iff_list_lock));
                    ret_val = delete_address_rtnl(
                                sock, addr, iff_list, virt_list);
                    pthread_mutex_unlock(&(squeue.iff_list_lock));

                    if(ret_val > 0) {
                        print_debug(
                            "Address, belonged to gateway, send update\n");
                        pthread_mutex_lock(&(squeue.flag_lock));
                        squeue.flag = 1;
                        pthread_mutex_unlock(&(squeue.flag_lock));
                    }
                } else {
                    print_debug("Update Address - Unknown\n");
                }
            } else if(u->type == UPDATE_ROUTE) {
                struct rtnl_route* route = u->update;
                print_debug("Recieved update route type: %d\n", u->action);
                if(u->action == ADD_RT) {
                    pthread_mutex_lock(&(squeue.iff_list_lock));
                    if(LOAD_BALANCING){
                        if(rtnl_route_get_priority(route) != 0){
                            print_debug("Update Route - Add loadbalance\n");
                            add_load_balance_route_from_rtnl(sock, route);
                        } else {
                            print_debug("Update Route - Priority not 0\n");
                        }
                    } else {
                        print_debug("Update Route - Add loadbalance\n");
                    }
                    if(is_virtual_route(route, virt_list)){
                        pthread_mutex_unlock(&(squeue.iff_list_lock));

                        print_debug("Update Route -\
                            Add RT (Not physical, move on)\n");
                        goto LOOP_END;
                    } else {
                        pthread_mutex_unlock(&(squeue.iff_list_lock));
                        print_debug("Update Route - Add RT\n");
                    }

                    pthread_mutex_lock(&(squeue.iff_list_lock));
                    add_route(sock, route, iff_list, virt_list);
                    pthread_mutex_unlock(&(squeue.iff_list_lock));

                    print_debug("Update Route - Completed\n");
                } else if(u->action == DEL_RT) {
                    pthread_mutex_lock(&(squeue.iff_list_lock));
                    if(LOAD_BALANCING){
                        if(rtnl_route_get_priority(route) != 0){
                            print_debug("Update Route - Delete loadbalance\n");
                            delete_load_balance_route_from_rtnl(sock, route);
                        } else {
                            print_debug("Update Route - Priority not 0\n");
                        }
                    } else {
                        print_debug("Update Route - Add loadbalance\n");
                    }
                    if(is_virtual_route(route, virt_list)){
                        pthread_mutex_unlock(&(squeue.iff_list_lock));
                        print_debug("Update Route -\
                             Del RT (Not physical, move on)\n");
                        goto LOOP_END;
                    } else {
                        pthread_mutex_unlock(&(squeue.iff_list_lock));
                        print_debug("Update Route - Del RT\n");
                    }
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
                } else {
                    print_debug("Update Route - Unknown %d\n", u->action);
                }

#ifdef EVAL
//                rtnl_route_foreach_nexthop (route, print_nexthop_cb, 0);
#endif
            } else if(u->type == UPDATE_GATEWAY) {
                struct network_update* nupdate = 0;

                nupdate = (struct network_update*)u->update;

                if(!nupdate) {
                    goto LOOP_END;
                }

                if(handle_gateway_update(nupdate, iff_list,
                                         virt_list, sock, squeue)) {
                    print_debug("Network Update exited\n");
                    goto LOOP_END;
                }
            }
        }
LOOP_END:

#ifdef PRINT_LIST
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
#endif
        free(qitem);
    }

    //printf("\n#######################\n");
    printf("Cleaning up...\n");

    clean_up_interfaces(sock, virt_list, iff_list);
    printf("Done.\n");
    return SUCCESS;
}


/*
*
*/
int
delete_old_route(
  struct nl_sock *sock,
  struct physical_interface *phy,
  struct virtual_interface* virt,
  List *ifflist,
  List *virtlist,
  int i)
{
    /*Remove associated subnets*/
    Litem *item;
    Litem *pitem;
    print_debug("Loop through the physical interfaces\n");
    list_for_each(pitem, ifflist){
        struct physical_interface* phys = (struct physical_interface*)pitem->data;
        print_debug("Interface Type: %u\n", phys->super.type);
        if(phys->super.type != PHYSICAL_TYPE){
            print_error("Virtual Interface in phys list?! %p\n", phys);
            print_error("\tAddress: %s\n", ip_to_str(ntohl(phys->address)));
            print_error("\tIff list: %p Iff List Ref: %p \nVirt List: %p Virt List Ref: %p\n", iff_list, ifflist, virt_list, virtlist);
            continue;
        }
        if(phys->diss) {
            int j = 0;
            Litem *pvitem = (Litem*)0;
            print_debug(
                "Loop through the virtual interfaces for phy\n");
            if(!phys->virt_list){
                print_error("Virt list not created\n");
                continue;
            } else {
                print_verb("Phys virt_list created: %p\n", phys->virt_list);
            }
            print_verb("Loop through virt list\n");

            list_for_each(pvitem, phys->virt_list){
                if(virt->table == ((struct virtual_interface*)
                                   pvitem->data)->table) {
                    print_debug("Loop thorugh the virtual interfaces for phy\n");

                    item = list_remove(phys->virt_list, j);
                    if(!item) {
                        print_error("Remove Index out of bounds\n");
                        break;
                    }
                    struct virtual_interface* pvirt =
                      (struct virtual_interface*)
                        item->data;
                    if(!pvirt) {
                        print_error("Interface to remove is null\n");
                        break;
                    }
                    print_debug("Deleting associated subnet\n");

                    delete_address(
                        sock,
                        pvirt->address,
                        pvirt->netmask,
                        pvirt->attach->super.ifidx);
                    break;
                }
                j++;
            }
            j = 0;
            /*TODO: Unbodge this. It's getting ridiculous.*/
            list_for_each(pvitem, virtlist){
                if(virt->table == ((struct virtual_interface*)
                                   pvitem->data)->table) {
                    print_debug("Loop thorugh the virtual \
                         interface list\n");

                    item = list_remove(virtlist, j);
                    break;
                }
                j++;
            }
        } else {
            print_debug("Skipping interface, not diss enabled\n");
        }
    }


    /*Remove virtual address exit*/
    print_debug("Calling delete address\n");
    delete_address(sock,
        virt->address,
        virt->netmask,
        virt->out->super.ifidx);
    delete_default_route(sock, virt);
    delete_rule(sock, virt->address, virt->netmask, virt->table);
    list_remove(phy->virt_list, i);

#ifndef DCE_NS3_FIX
    delete_table_file(ntohl(virt->address), INDIRECT_RESOURCE);
#endif

#ifdef EVAL
    struct timespec monotime;
    clock_gettime(CLOCK_REALTIME, &monotime);
    print_eval("DR:%s:%s:%lld.%.9ld\n",
               host_name,
               ip_to_str(ntohl(virt->external_ip)),
               (long long)monotime.tv_sec,
               (long)monotime.tv_nsec);
#endif

    flush_table(sock, virt->table);

    pthread_mutex_lock(&squeue.flag_lock);
    squeue.flag = 1;
    pthread_mutex_unlock(&squeue.flag_lock);

    return 0;
}


/*
* TODO let the main loop handle link deletion from the data structures
*/
int
delete_old_routes(
    struct network_update* nupdate,
    List* virt_list,
    List* iff_list,
    struct nl_sock* sock,
    int host_id,
    struct send_queue squeue)
{
    int idx = 0;
    int exists = 0;
    struct virtual_interface* virt = (struct virtual_interface*)0;
    struct mpdpacket* pkt = (struct mpdpacket*)0;
    struct physical_interface* phy = (struct physical_interface*)0;
    struct sockaddr_in* addr = (struct sockaddr_in*)0;
    int i = 0;
    Litem *vitem;

    pkt = &(nupdate->pkt);

    print_debug("\n");

    addr = &(nupdate->addr);

    pthread_mutex_lock(&(squeue.iff_list_lock));

    print_debug("Get Interface For Update From: %s\n", ip_to_str(ntohl(addr->sin_addr.s_addr)));

    phy = get_iff_network_update(addr->sin_addr.s_addr,
                                 iff_list);
    if(!phy){
        print_error("Didn't find phy for address: %s\n", ip_to_str(ntohl(addr->sin_addr.s_addr)));
        pthread_mutex_unlock(&(squeue.iff_list_lock));
        return FAILURE;
    }

    phy->packet_received = 1;
    pthread_mutex_unlock(&(squeue.iff_list_lock));

    if(!phy->virt_list) {
        print_error("Virt List is null\n");
        return SUCCESS;
    }

    list_for_each(vitem, phy->virt_list){
        virt = vitem->data;

        if(!virt) {
            i++;
            print_error("Virt Data Is null\n");
            continue;
        }

        if(!virt->type_gateway) {
            print_debug("This is a subnet, don't delete it... yet\n");
            i++;
            continue;
        }

        if(virt->out->super.ifidx != virt->attach->super.ifidx) {
            print_debug("This is a subnet, don't delete it... yet, missed gateway type check\n");
            i++;
            continue;
        }

        print_verb("Loop Through Packet\n");
        exists = 1;
        for(idx = 0; idx < pkt->header->num; idx++) {
            struct mpdentry* entry = (pkt->entry) + idx;
            int host_ip = 0;

            host_ip = (entry->netmask & entry->address) | host_id;

            print_verb("Checking that address check came from correct sender\n");
            print_verb("\tSender: %s\n", ip_to_str(ntohl(virt->sender)));
            print_verb("\tGateway: %s\n", ip_to_str(ntohl(entry->gateway)));
            if(virt && virt->sender == entry->gateway && virt->address != host_ip) {
                print_debug("Gateway for packet doesn't match virtual interface\n");
                exists = 0;
            }

            if(virt && virt->address == host_ip) {
                print_debug("Address already exists\n");
                exists = 1;
                break;
            }
        }

        if(!exists) {
            print_debug("Delete old route\n");
            delete_old_route(sock, phy, virt, iff_list, virt_list, i);
        }
        i++;
    }

    return SUCCESS;
}


/*
 *
 */
int
handle_gateway_update(
    struct network_update* nupdate,
    List* iff_list,
    List* virt_list,
    struct nl_sock* sock,
    struct send_queue squeue)
{
    struct physical_interface* temp_phys;
    struct virtual_interface* temp_virt;
    struct mpdpacket* pkt;
    struct sockaddr_in* addr;
    struct physical_interface* phy;
    uint32_t host_id = 0;
    int idx = 0;
    int exists = 0;

    print_debug("Update gateway\n");
    pkt = &(nupdate->pkt);
    addr = &(nupdate->addr);

    pthread_mutex_lock(&(squeue.iff_list_lock));
    phy = get_iff_network_update(addr->sin_addr.s_addr,
                                 iff_list);
    if(!phy){
        print_error("Didn't find phy for address: %s\n", ip_to_str(ntohl(addr->sin_addr.s_addr)));
        pthread_mutex_unlock(&(squeue.iff_list_lock));
        return FAILURE;
    }
    pthread_mutex_unlock(&(squeue.iff_list_lock));

    host_id = get_host_id(phy);

    delete_old_routes(nupdate, virt_list, iff_list, sock, host_id, squeue);

    for(idx = 0; idx < pkt->header->num; idx++) {
        struct mpdentry* entry = (pkt->entry) + idx;
        Litem *item;
        Litem *pitem;
        Litem *vitem;
        struct virtual_interface* v;
        uint32_t host_ip = 0;
        int16_t free_table = -1;
        exists = 0;

        if (entry->depth >= MAX_DEPTH) {
            return FAILURE;
        }

        /*check IP doesnt already exist;*/
        host_ip = (entry->netmask & entry->address) | host_id;

        print_debug("\tHost ID: %s\n", ip_to_str(ntohl(host_id)));
        print_debug("\tEntry Netmask: %s\n", ip_to_str(ntohl(entry->netmask)));
        print_debug("\tEntry Address: %s\n", ip_to_str(ntohl(entry->address)));
        print_debug("Checking Host IP Doesnt Exist: %s\n", ip_to_str(ntohl(host_ip)));

        pthread_mutex_lock(&(squeue.iff_list_lock));
        list_for_each(pitem, iff_list){
            temp_phys = (struct physical_interface*)pitem->data;
            if(temp_phys && temp_phys->address == host_ip) {
                print_debug("Physical address aldready exists, skipping\n");
                exists = 1;
                break;
            }
        }

        if(exists) {
            print_debug("Skipping entry, already seen\n");
            continue;
        }

        pthread_mutex_unlock(&(squeue.iff_list_lock));

        if(virt_list) {
            list_for_each(vitem, virt_list){
                temp_virt = (struct virtual_interface*)vitem->data;
                if(temp_virt && temp_virt->address == host_ip) {
                    print_debug(
                        "Virtual address already exists, resetting timout\n");
                    if(temp_virt->external_ip == entry->ext_ip
                       && phy == temp_virt->attach
                       && phy == temp_virt->out)
                    {
                        /*Don't reset the timeout if it was a bogus IP update
                        from a different host*/
                        temp_virt->last_update = 0;
                        temp_virt->last_update = LINK_TIMEOUT;
                    }
                    exists = 1;
                    break;
                }
                if(temp_virt->external_ip == entry->ext_ip){
                    //Add link as backup
                }
            }
        }

        if(exists) {
            print_debug("Skipping entry, already seen\n");
            continue;
        }

        free_table = find_free_routing_table(sock);
        if(free_table < 0 ) {
            print_debug("No more free routing tables\n");
            continue;
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

        if(!v) {
            print_debug("Failed to add virtual interface\n");
            return FAILURE;
        }

        print_debug("External IP: %s\n", ip_to_str(entry->ext_ip));

        v->gateway = entry->address;
        v->sender = addr->sin_addr.s_addr;
        v->out = phy;
        v->attach = phy;
        v->address = host_ip;
        v->netmask = entry->netmask;
        v->depth = entry->depth + 1;
        v->metric = ntohl(entry->metric);

        print_debug("ENTRY METRIC: %zu\n", ntohl(entry->metric));

        v->external_ip = entry->ext_ip;
        v->last_update = LINK_TIMEOUT;
        v->type_gateway = 1;
        print_debug("Find a free routing table\n");
        v->table = free_table;
        print_debug("\tAssigned - %u\n", v->table);
        create_rule_for_gw(sock, (struct interface*)v, v->table);
        item = (Litem*)malloc(sizeof(Litem));
        if (!item) {
            errno = ENOMEM;
            destroy_virt_interface(v);
            fprintf(stderr, "Failed to malloc a new list item\n");
        }
        print_verb("Add the new virtual interface to the phy list\n");
        item->data = (void*)v;
        print_verb("Add address to the interface\n");
        print_verb("Virt IP: %s\n", ip_to_str(ntohl(v->address)));
        print_debug("Physical Virt List: %p\n", phy->virt_list);

        pthread_mutex_lock(&(squeue.iff_list_lock));
        if (!phy->virt_list) {
            phy->virt_list = malloc(sizeof(List));
            list_init(phy->virt_list);
            print_debug("Init Physical Virt List: %p\n", phy->virt_list);
        }
        print_debug("add_address: List Size Pre Put %d for %s\n", list_size(
                        phy->virt_list), phy->super.ifname);
        list_put(phy->virt_list, item);
        print_debug("Added item, interfacse (%d)\n", list_size(phy->virt_list));
        print_debug("add_address: List Size Post Put %d for %s\n", list_size(
                        phy->virt_list), phy->super.ifname);
        pthread_mutex_unlock(&(squeue.iff_list_lock));

        pthread_mutex_lock(&(squeue.iff_list_lock));

        print_debug("Adding Interface with Label: %d\n",
                        list_size(phy->virt_list));
        print_debug("calling add_address()\n");
        if(add_address(sock,
                       v->address,
                       phy->super.ifidx,
                       list_size(phy->virt_list))) {
            pthread_mutex_unlock(&(squeue.iff_list_lock));

            /*
               This could be because the address already exists
               in which case, we should try and add the default
               route anyway.
             */
            fprintf(stderr, "Failed to add address, for network update\n");
        }

        pthread_mutex_unlock(&(squeue.iff_list_lock));
        print_debug("Unlock ifflist\n");

        print_debug("Create the default route\n");

        pthread_mutex_lock(&(squeue.iff_list_lock));

        /*
        This step is currently redundant
        if(add_default_route(sock, entry->address,
          v->table, phy->super.ifidx, entry->metric))
        {
            pthread_mutex_unlock(&(squeue.iff_list_lock));

            fprintf(stderr, "Failed to add route, for network update\n");
            return FAILURE;
        }
        */

        create_aliases_for_gw(sock, iff_list, virt_list, (struct interface*)v);
        create_rules_for_gw(sock, virt_list, (struct interface*)v);
        print_debug("Create the routing table for virtual gateway\n");
        //create_routing_table(sock, (struct interface*)v);
        create_routing_table_default_route(sock,
            (struct interface*)v,
            v->attach->super.ifidx,
            v->table);

        create_routing_table_subnet_route(sock,
            (struct interface*)v,
            v->attach->super.ifidx,
            v->table);

        {
            int res = 0;
            uint32_t find_metric = find_free_default_route_metric(
                                    sock,
                                    v->metric,
                                    phy->super.ifidx);
            print_verb("Found free metric: %d\n", find_metric);

            res = add_default_route(sock,
                                    entry->address,
                                    RT_TABLE_MAIN,
                                    phy->super.ifidx,
                                    find_metric);
            if(res < 0){
                print_error("Failed to add default route: %d\n", res);
                pthread_mutex_unlock(&(squeue.iff_list_lock));
                return FAILURE;
            }
        }
        pthread_mutex_unlock(&(squeue.iff_list_lock));

#ifndef DCE_NS3_FIX
        create_table_file(ntohl(v->address), v->table, INDIRECT_RESOURCE);
#endif


#ifdef EVAL
        struct timespec monotime;
        clock_gettime(CLOCK_REALTIME, &monotime);
        print_eval("NR:%s:%s:%s:%lld.%.9ld\n",
                   host_name,
                   ip_to_str(ntohl(v->external_ip)),
                   v->out->super.ifname,
                   (long long)monotime.tv_sec,
                   (long)monotime.tv_nsec);
#endif
    }

    /*Flag the udpate*/
    print_debug("Flagging to update hosts\n");
    pthread_mutex_lock(&squeue.flag_lock);
    squeue.flag = 1;
    pthread_mutex_unlock(&squeue.flag_lock);


    return SUCCESS;
}

/* end file: mpdd.c */
