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

#define UPDATE_FREQUENCY 1000

int send_clear(char* dev_address, char *broadcast_address, char *broadcast_dev_name)
{
    struct sockaddr_in saddr;
    struct sockaddr_in in_addr;
    struct physical_interface *bc_dev = (struct physical_interface*)0;
    int do_broadcast = 1;

    int sock = 0;
    List *ifflist = (List*)0;
    Litem *item = (Litem*)0;

    item = malloc(sizeof(Litem));

    bc_dev = init_phys();

    bc_dev->virt_list = malloc(sizeof(List));
    list_init(bc_dev->virt_list);

    ifflist = malloc(sizeof(List));

    list_init(ifflist);

    bc_dev->diss = 1;

    inet_pton(AF_INET, broadcast_address, &(in_addr.sin_addr));
    bc_dev->broadcast = in_addr.sin_addr.s_addr;

    inet_pton(AF_INET, dev_address, &(in_addr.sin_addr));
    bc_dev->address = in_addr.sin_addr.s_addr;

    strcpy(bc_dev->super.ifname, broadcast_dev_name);

    item->data = bc_dev;

    list_put(ifflist, item);


    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        /*Cleanup*/
        perror("create_socket() - socket()");
        return -1;
    }

    print_debug("Set socket option\n");

    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_BROADCAST,
                   (void*)&do_broadcast,
                   sizeof(do_broadcast)) < 0) {
        /*Cleanup*/
        perror("create_socket() - setsockopt(BROADCAST)");
        return -1;
    }

    memset(&(saddr), '0', sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = (in_port_t)htons(MPD_BROADCAST_PORT);
    saddr.sin_addr.s_addr = INADDR_ANY;

    print_debug("Try and bind\n");
    if (bind(sock,
             (struct sockaddr*)&(saddr),
             (socklen_t )sizeof(struct sockaddr_in))) {
        perror("create_socket() - bind()");
        return -1;
    }

    send_update_broadcast(ifflist, sock);

    sleep(1);

    shutdown(sock, 2);
    close(sock);
    return 0;
}

int send_update(char* dev_address, char *broadcast_address, char *broadcast_dev_name, int resources)
{
    struct sockaddr_in saddr;
    struct sockaddr_in in_addr;
    struct sockaddr_in in_addr_2;
    struct physical_interface *bc_dev = (struct physical_interface*)0;
    int resources_to_announce = resources;
    int iterations = 1;
    int idx = 0;
    char* base_gateway = "10.1.1.1";
    char* base_subnet = "172.16.1.1";
    uint32_t gw_dec = 0;
    uint32_t subnet_dec = 0;
    uint32_t subnet_mask = 0;
    int do_broadcast = 1;

    int sock = 0;
    List *ifflist = (List*)0;
    Litem *item = (Litem*)0;

    bc_dev = init_phys();

    bc_dev->virt_list = malloc(sizeof(List));
    item = malloc(sizeof(Litem));

    ifflist = malloc(sizeof(List));

    inet_pton(AF_INET, broadcast_address, &(in_addr.sin_addr));
    bc_dev->broadcast = in_addr.sin_addr.s_addr;

    inet_pton(AF_INET, dev_address, &(in_addr.sin_addr));
    bc_dev->address = in_addr.sin_addr.s_addr;


    list_init(bc_dev->virt_list);
    list_init(ifflist);

    bc_dev->diss = 1;

    strcpy(bc_dev->super.ifname, broadcast_dev_name);

    item->data = bc_dev;

    list_put(ifflist, item);

    inet_pton(AF_INET, base_gateway, &(in_addr_2.sin_addr));
    gw_dec = in_addr_2.sin_addr.s_addr;

    inet_pton(AF_INET, base_subnet, &(in_addr_2.sin_addr));
    subnet_dec = in_addr_2.sin_addr.s_addr;

    for(idx = 0; idx < resources_to_announce; idx++) {
        Litem *item = (Litem*)0;
        struct virtual_interface *virt = (struct virtual_interface*)0;
        virt = malloc(sizeof(struct virtual_interface));
        item = malloc(sizeof(Litem));


        gw_dec += htonl(0x00000400);
        subnet_dec += htonl(0x00000400);
        subnet_mask = subnet_dec & htonl(0xFFFFFF00);

        virt->address = subnet_dec;
        virt->netmask = subnet_mask;
        virt->gateway = gw_dec;
        virt->metric = idx+1;
        virt->external_ip = gw_dec;
        virt->depth = 1;
        virt->attach = bc_dev;
        virt->out = 0;

        item->data = virt;

        list_put(bc_dev->virt_list, item);

        gw_dec += htonl(0x00000100);
        subnet_dec += htonl(0x00000100);
    }


    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        /*Cleanup*/
        perror("create_socket() - socket()");
        return -1;
    }

    print_debug("Set socket option\n");

    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_BROADCAST,
                   (void*)&do_broadcast,
                   sizeof(do_broadcast)) < 0) {
        /*Cleanup*/
        perror("create_socket() - setsockopt(BROADCAST)");
        return -1;
    }

    memset(&(saddr), '0', sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = (in_port_t)htons(MPD_BROADCAST_PORT);
    saddr.sin_addr.s_addr = INADDR_ANY;

    print_debug("Try and bind\n");
    if (bind(sock,
             (struct sockaddr*)&(saddr),
             (socklen_t )sizeof(struct sockaddr_in))) {
        perror("create_socket() - bind()");
        return -1;
    }

    for(idx = 0; idx < iterations; idx++) {
        send_update_broadcast(ifflist, sock);

        sleep(1);
    }


    shutdown(sock, 2);
    close(sock);
    return 0;
}

int send_periodic(char* dev_address, char *broadcast_address, char *broadcast_dev_name)
{
    struct sockaddr_in saddr;
    struct sockaddr_in in_addr;
    struct sockaddr_in in_addr_2;
    struct physical_interface *bc_dev = (struct physical_interface*)0;
    int resources_to_announce = 1;
    int iterations = 1;
    int idx = 0;
    char* base_gateway = "10.1.1.1";
    char* base_subnet = "172.16.1.1";
    uint32_t gw_dec = 0;
    uint32_t subnet_dec = 0;
    uint32_t subnet_mask = 0;
    int do_broadcast = 1;

    int sock = 0;
    List *ifflist = (List*)0;
    Litem *item = (Litem*)0;



    inet_pton(AF_INET, base_gateway, &(in_addr_2.sin_addr));
    gw_dec = in_addr_2.sin_addr.s_addr;

    inet_pton(AF_INET, base_subnet, &(in_addr_2.sin_addr));
    subnet_dec = in_addr_2.sin_addr.s_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        /*Cleanup*/
        perror("create_socket() - socket()");
        return -1;
    }

    print_debug("Set socket option\n");

    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_BROADCAST,
                   (void*)&do_broadcast,
                   sizeof(do_broadcast)) < 0) {
        /*Cleanup*/
        perror("create_socket() - setsockopt(BROADCAST)");
        return -1;
    }

    memset(&(saddr), '0', sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = (in_port_t)htons(MPD_BROADCAST_PORT);
    saddr.sin_addr.s_addr = INADDR_ANY;

    print_debug("Try and bind\n");
    if (bind(sock,
             (struct sockaddr*)&(saddr),
             (socklen_t )sizeof(struct sockaddr_in))) {
        perror("create_socket() - bind()");
        return -1;
    }

    while(1){

        bc_dev = init_phys();

        bc_dev->virt_list = malloc(sizeof(List));
        item = malloc(sizeof(Litem));

        ifflist = malloc(sizeof(List));

        inet_pton(AF_INET, broadcast_address, &(in_addr.sin_addr));
        bc_dev->broadcast = in_addr.sin_addr.s_addr;

        inet_pton(AF_INET, dev_address, &(in_addr.sin_addr));
        bc_dev->address = in_addr.sin_addr.s_addr;


        list_init(bc_dev->virt_list);
        list_init(ifflist);

        bc_dev->diss = 1;

        strcpy(bc_dev->super.ifname, broadcast_dev_name);

        item->data = bc_dev;

        list_put(ifflist, item);

        Litem *item = (Litem*)0;
        struct virtual_interface *virt = (struct virtual_interface*)0;
        virt = malloc(sizeof(struct virtual_interface));
        item = malloc(sizeof(Litem));
        subnet_mask = subnet_dec & htonl(0xFFFFFF00);

        virt->address = subnet_dec;
        virt->netmask = subnet_mask;
        virt->gateway = gw_dec;
        virt->metric = idx+1;
        virt->external_ip = gw_dec;
        virt->depth = 1;
        virt->attach = bc_dev;
        virt->out = 0;

        item->data = virt;

        list_put(bc_dev->virt_list, item);

        gw_dec += htonl(0x00000100);
        subnet_dec += htonl(0x00000100);

        send_update_broadcast(ifflist, sock);

        usleep(UPDATE_FREQUENCY);
    }

    shutdown(sock, 2);
    close(sock);
    return 0;
}


void print_usage(void)
{
    printf("packet_tester {0 clear, < update} [dev_addr] [broadcast_addr] [dev_name] \n");
}

int main(int argc, char *argv[])
{
    if (argc != 5){
        print_usage();
        return 0;
    }
    if(!strcmp(argv[1], "p")){
        printf("send_periodic\n");
        send_periodic(argv[2], argv[3], argv[4]);
    } else if(atoi(argv[1])){
        printf("Send Update\n");
        send_update(argv[2], argv[3], argv[4], atoi(argv[1]));
    } else {
        printf("Send Clear\n");
        send_clear(argv[2], argv[3], argv[4]);
    }
    return 0;
}
