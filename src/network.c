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

#include "debug.h"
#include "network.h"
#include <unistd.h>

/*
 * TODO: Speed this up with libev.
 */

char host_name[32];

void *
send_request_thread(struct physical_interface *phy, int sock)
{
    if(1){
        send_request_broadcast(phy, sock, MPD_HDR_REQUEST);
    }
    return 0;
}

/*
 *
 */
int
create_socket(struct physical_interface* i)
{
    int do_broadcast = 1;
    int sock = 0;

    print_debug("\n");

    if ((i->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        /*Cleanup*/
        perror("create_socket() - socket()");
        return FAILURE;
    }

    if (setsockopt(i->socket,
                   SOL_SOCKET,
                   SO_BROADCAST,
                   (void*)&do_broadcast,
                   sizeof(do_broadcast)) < 0) {
        /*Cleanup*/
        perror("create_socket() - setsockopt(BROADCAST)");
        return FAILURE;
    }

    if (setsockopt(i->socket,
                   SOL_SOCKET,
                   SO_BINDTODEVICE,
                   i->super.ifname,
                   strlen(i->super.ifname)) < 0) {
        /*Cleanup*/
        perror("create_socket() - setsockopt(BIND)");
        return FAILURE;
    }

    memset(&(i->saddr), '0', sizeof(struct sockaddr_in));
    i->saddr.sin_family = AF_INET;
    i->saddr.sin_port = (in_port_t)htons(MPD_BROADCAST_PORT);
    i->saddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(i->socket,
             (struct sockaddr*)&(i->saddr),
             (socklen_t )sizeof(struct sockaddr_in))) {
        perror("create_socket() - bind() ");
        return FAILURE;
    }

    return sock;
}

/*
 *
 */
void* recv_broadcast(struct send_queue* squeue)
{
    struct sockaddr_in saddr;
    struct cache_monitor* mon;

    int do_broadcast = 1;
    int sock = 0;
    int maxfd = 0;
    int ret = 0;
    int exists = 0;
    int i = 0;
    struct timeval tv;
    unsigned char* buff = 0;
    socklen_t fromlen;

    fd_set wfds;
    fd_set rfds;
    fd_set efds;

    print_debug("Thread started\n");

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        /*Cleanup*/
        perror("create_socket() - socket()");
        return (void*)FAILURE;
    }

    print_debug("Set socket option\n");

    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_BROADCAST,
                   (void*)&do_broadcast,
                   sizeof(do_broadcast)) < 0) {
        /*Cleanup*/
        perror("create_socket() - setsockopt(BROADCAST)");
        return (void*)FAILURE;
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
        return (void*)FAILURE;
    }

    fromlen = (socklen_t)sizeof(saddr);

    maxfd = sock + 1;

    buff = malloc(2048);

    mon = squeue->mon_data;
    print_debug("Entering main loop\n");

    while (squeue->running) {
        struct mpdpacket* pkt = 0;

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);

        FD_SET(sock, &rfds);
        FD_SET(sock, &wfds);
        FD_SET(sock, &efds);

        //ret = select(maxfd, &rfds, &wfds, &efds, &tv);
        ret = select(maxfd, &rfds, &wfds, &efds, &tv);

        if (ret > 0) {
            exists = 0;
            if (FD_ISSET(sock, &rfds)) {
                print_debug("Read FDS Set\n");
                memset(buff, 0, 2048);
                if ((ret = recvfrom(sock, buff, (size_t)2048, 0,
                                    (struct sockaddr*)&(saddr), &fromlen)) == 0) {
                    perror("recv_broadcast() - recvfrom()");
                    continue;
                }

                /*Ignore broadcasts from localhost*/
                if(IS_LOCAL_HOST(saddr.sin_addr.s_addr) ||
                        IS_LOCAL_HOST(htonl(saddr.sin_addr.s_addr)))
                {
                    print_debug("Broadcast came from localhost, ignore\n");
                    continue;
                }

                pthread_mutex_lock(&(squeue->flag_lock));
                struct physical_interface* temp_phys =
                    (struct physical_interface*)0;
                for (i = 0; i < list_size(squeue->iff_list); i++) {
                    temp_phys = (struct physical_interface*)
                                (list_get(squeue->iff_list, i))->data;
                    if (temp_phys) {
                        if (temp_phys->address == saddr.sin_addr.s_addr) {
                            print_debug(
                                "Broadcast came from this host, "
                                "ignore\n");
                            exists = 1;
                            break;
                        }
                    }
                }
                pthread_mutex_unlock(&(squeue->flag_lock));

                if (exists) {
                    continue;
                }

                #ifdef EVAL
                struct timespec monotime;
                clock_gettime(CLOCK_REALTIME, &monotime);
                print_eval("RP:%s:%s:%lld.%.9ld\n",
                    host_name,
                    ip_to_str(htonl(saddr.sin_addr.s_addr)),
                    (long long)monotime.tv_sec,
                    (long)monotime.tv_nsec);
                #endif

                deserialize_packet(buff, &pkt);

                print_packet(pkt);

                if (!pkt) {
                    print_debug("Failed to deserialize packet\n");
                    continue;
                }

                if (pkt->header->type == MPD_HDR_UPDATE) {
                    Qitem* item = 0;
                    struct network_update* nupdate = 0;
                    struct update_obj* u;

                    print_debug("Found update packet\n");

                    #ifdef EVAL
                    struct timespec monotime;
                    clock_gettime(CLOCK_REALTIME, &monotime);
                    print_eval("RU:%s:%s:%lld.%.9ld\n",
                        host_name,
                        ip_to_str(htonl(saddr.sin_addr.s_addr)),
                        (long long)monotime.tv_sec,
                        (long)monotime.tv_nsec);
                    #endif

                    if (!(nupdate = malloc(sizeof(struct network_update)))) {
                        errno = ENOMEM;
                        print_debug("malloc failed()\n");
                        continue;
                    }

                    memcpy(&(nupdate->addr), &saddr, sizeof(struct sockaddr));
                    memcpy(&(nupdate->pkt), pkt, sizeof(struct mpdpacket));

                    if (!(item = malloc(sizeof(Qitem)))) {
                        print_debug("item ENOMEM\n");
                        errno = ENOMEM;
                        continue;
                    }

                    if (!(u = malloc(sizeof(struct update_obj)))) {
                        print_debug("item ENOMEM\n");
                        errno = ENOMEM;
                        continue;
                    }

                    print_debug("Setting the update information\n");

                    u->update = nupdate;
                    u->type = UPDATE_GATEWAY;
                    u->action = ADD_IP;
                    print_debug("Adding to the update queue\n");
                    item->data = u;

                    print_debug("Lock monitor mutex\n");
                    pthread_mutex_lock(mon->lock);
                    queue_put(mon->queue, item);
                    print_debug("Unlock monitor mutex\n");
                    pthread_mutex_unlock(mon->lock);
                    print_debug("sem_post\n");
                    sem_post(mon->barrier);
                } else if (pkt->header->type == MPD_HDR_REQUEST) {
                    print_debug("Found request packet\n");
                    #ifdef EVAL
                    struct timespec monotime;
                    clock_gettime(CLOCK_REALTIME, &monotime);
                    print_eval("RR:%s:%s:%lld.%.9ld\n",
                        host_name,
                        ip_to_str(htonl(saddr.sin_addr.s_addr)),
                        (long long)monotime.tv_sec,
                        (long)monotime.tv_nsec);
                    #endif
                    pthread_mutex_lock(&(squeue->flag_lock));
                    print_debug("Sending update packet onto link\n");
                    //send_update_broadcast(squeue->iff_list, sock);
                    squeue->flag = 1;
                    pthread_mutex_unlock(&(squeue->flag_lock));
                } else if (pkt->header->type == MPD_HDR_HEARTBEAT) {
                    print_debug("Found heartbeat packet\n");

                    pthread_mutex_lock(&(squeue->flag_lock));
                    //print_debug("Sending update packet onto link\n");
                    /*Mark to send, if we fall into the receive loop multiple
                    times only send one response*/
                    //squeue->flag = 1;
                    //send_update_broadcast(squeue->iff_list, sock);
                    pthread_mutex_unlock(&(squeue->flag_lock));
                } else {
                    print_debug("Unknown packet header type\n");
                }
            } else if (FD_ISSET(sock, &wfds)) {
                pthread_mutex_lock(&(squeue->flag_lock));
                if (squeue->flag) {
                    #ifdef EVAL
                    struct timespec monotime;
                    clock_gettime(CLOCK_REALTIME, &monotime);
                    print_eval("READYTOSEND:%s:%lld.%.9ld\n",
                        host_name,
                        (long long)monotime.tv_sec,
                        (long)monotime.tv_nsec);
                    #endif
                    send_update_broadcast(squeue->iff_list, sock);
                    squeue->flag = 0;
                }
                pthread_mutex_unlock(&(squeue->flag_lock));

                /*Send requests for updates*/
                pthread_mutex_lock(&(squeue->flag_lock));
                if (squeue->request_flag) {
                    Qitem* qitem;
                    while ((qitem = queue_get(&(squeue->request_queue)))) {
                        print_debug("Request flag set\n");
                        struct physical_interface * phy = qitem->data;

                        if(!phy) {
                            continue;
                        }

                        /*We don't need to send a request, already received packet*/
                        if(phy->packet_received) {
                            continue;
                        } else {
                            #ifdef EVAL
                            struct timespec monotime;
                            clock_gettime(CLOCK_REALTIME, &monotime);
                            print_eval("SR:%s:%s:%lld.%.9ld\n",
                                host_name,
                                ip_to_str(htonl(phy->address)),
                                (long long)monotime.tv_sec,
                                (long)monotime.tv_nsec);
                            #endif
                            //usleep((double)(rand() / ((double)RAND_MAX + 1.00) * (1000000 + 1)));
                            send_request_broadcast(phy, sock, MPD_HDR_REQUEST);
                            //phy->packet_received = 1;
                        }

                        free(qitem);
                    }
                }
                squeue->request_flag = 0;
                pthread_mutex_unlock(&(squeue->flag_lock));

                pthread_mutex_lock(&(squeue->flag_lock));

                /*Send out heartbeat, interfaces are still here.*/
                if (squeue->heartbeat_flag) {
                    Qitem* qitem;
                    while ((qitem = queue_get(&(squeue->request_queue)))) {
                        print_debug("Request flag set\n");

                        send_request_broadcast(
                            (struct physical_interface*)qitem->data,
                            sock, MPD_HDR_HEARTBEAT);

                        free(qitem);
                    }
                    squeue->heartbeat_flag = 0;
                }

                pthread_mutex_unlock(&(squeue->flag_lock));
#ifdef DCE_NS3_FIX
                print_verb("NS3FixSleep(1)\n");
                usleep(1000);
#else
                select(0, 0, 0, 0, &tv);
#endif
            } else if (FD_ISSET(sock, &efds)) {
                print_debug("Error FDS Set\n");
            }
            free(pkt);
        } else if (!ret) {
            print_debug("Selected timed out\n");
        } else if (ret < 0) {
            print_debug("Select failed");
        }
    }
    shutdown(sock, 2);
    close(sock);
    free(buff);
    return (void*)0;
}



/*
 *
 */
int
do_broadcast(struct physical_interface* i,
             int sock,
             unsigned char* buffer,
             int len)
{
    int sent = 0;

    if (sock < 0) {
        /*cleanup*/
        print_debug("bad socket < 0");
        return FAILURE;
    }

    if (!buffer) {
        return 0;
    }

    sent = sendto(sock,
                  buffer,
                  len,
                  0,
                  (struct sockaddr*)&(i->saddr),
                  sizeof(struct sockaddr_in));

    if ((sent) < 0) {
        perror("do_broadcast() - sendto()");
        return FAILURE;
    } else {
        print_debug("Sent %d bytes to %s \n", sent,
                    ip_to_str(ntohl((unsigned int)i->saddr.sin_addr.s_addr)));
    }

    return sent;
}

/*
 *
 */
int
send_request_broadcast(struct physical_interface* iff, int sock, int hflag)
{
    int len = 0;
    struct mpdpacket* packet;
    unsigned char* data = 0;

    if (create_request_packet(&packet, hflag) < 0) {
        print_debug("Create Request Packet Failed\n");
        return FAILURE;
    }

    if ((len = serialize_packet(packet, &data)) <= 0) {
        print_debug("Serialize Packet Failed\n");
        return FAILURE;
    }

    print_debug("Sending request on interface - %s\n", iff->super.ifname);

/*
#ifdef DEBUG
    struct mpdpacket* test_packet;
    printf("Deserialize Packet\n.....");
    deserialize_packet(data, &test_packet);
    print_packet(test_packet);
    free(test_packet);
#endif
*/
    free(packet);

    memset(&(iff->saddr), '0', sizeof(struct sockaddr_in));
    iff->saddr.sin_family = AF_INET;
    iff->saddr.sin_port = (in_port_t)htons(MPD_BROADCAST_PORT);
    iff->saddr.sin_addr.s_addr = iff->broadcast;

    do_broadcast(iff, sock, data, len);
    free(data);

    return SUCCESS;
}

/*
 *
 */
int
send_update_broadcast(List* iff_list, int sock)
{
    int i = 0;
    int size = 0;
    int ret = 0;

    size = list_size(iff_list);
    print_debug("Sending broadcast of new virtual interface\n");
    for (i = 0; i < size; i++) {
        struct physical_interface* iff =
            (struct physical_interface*)(list_get(iff_list, i))->data;
        if (iff->diss) {
            struct mpdpacket* packet;
            unsigned char* data = 0;
            unsigned int len = 0;
            int gws = 0;

            print_debug("Create Packet for %s\n", iff->super.ifname);

            #ifdef EVAL
            struct timespec monotime;
            clock_gettime(CLOCK_REALTIME, &monotime);
            print_eval("SU:%s:%s:%lld.%.9ld\n",
                host_name,
                ip_to_str(ntohl(iff->address)),
                (long long)monotime.tv_sec,
                (long)monotime.tv_nsec);
            #endif

            if ((gws = create_update_packet(iff, &packet)) < 0) {
                print_error("Create Packet Failed: %d\n", gws);
                continue;
            }

            len = serialize_packet(packet, &data);
            print_debug("Created serialized packet: length %d bytes\n", len);

            struct mpdpacket* test_packet;
            deserialize_packet(data, &test_packet);
            print_packet(test_packet);
            free(test_packet);

            free(packet);

            memset(&(iff->saddr), '0', sizeof(struct sockaddr_in));
            iff->saddr.sin_family = AF_INET;
            iff->saddr.sin_port = (in_port_t)htons(MPD_BROADCAST_PORT);
            iff->saddr.sin_addr.s_addr = iff->broadcast;

            do_broadcast(iff, sock, data, len);
            if(ret < 0) {
                print_error("Broadcast failed\n");
            }
            free(data);
        }
    }

    return SUCCESS;
}

/*
 *
 */
void print_packet(struct mpdpacket* pkt)
{
    if (!pkt) {
        printf("Null packet\n");
    } else {
        int i = 0;
        int size = pkt->header->num;
        printf("Header:\n");
        printf("\t Type: %d\n", pkt->header->type);
        printf("\t Num: %d\n", pkt->header->num);
        for (i = 0; i < size; i++) {
            struct mpdentry* e;
            e = (pkt->entry) + i;
            printf("Entry:\n");
            printf("\tAddress: %s\n", ip_to_str(e->address));
            printf("\tNetmask: %s\n", ip_to_str(e->netmask));
            printf("\tGateway: %s\n", ip_to_str(e->gateway));
            printf("\tExternal: %s\n", ip_to_str(e->ext_ip));
            printf("\tDepth: %d\n", e->depth);
            printf("\tMetric: %d\n", e->metric);
            printf("\tType: %d\n", e->type);
        }
        printf("\n");
    }
}

/*
 *
 */
int serialize_packet(struct mpdpacket* pkt, unsigned char** buffer)
{
    int entry_size = 0;
    int header_size = 0;
    unsigned char* b = 0;
    unsigned char* entries = 0;
    int count = 0;
    int i = 0;
    int size = 0;

    if (!pkt || !buffer) {
        errno = ENOMEM;
        print_debug("NULL Parameters passed\n");
        return FAILURE;
    }

    count = pkt->header->num;

    entry_size = sizeof(struct mpdentry);
    header_size = sizeof(struct mpdhdr);
    size = header_size + (entry_size * count);
    b = malloc(size);
    if (!b) {
        /*cleanup*/
        errno = ENOMEM;
        print_debug("malloc failed\n");
        return FAILURE;
    }
    memcpy(b, pkt->header, header_size);
    entries = (unsigned char*)(b + header_size);
    for (i = 0; i < count; i++) {
        memcpy(entries, &(pkt->entry[i]), entry_size);
        entries += entry_size;
    }
    *buffer = b;
    return size;
}

/**
 *
 */
int
deserialize_packet(unsigned char* buffer, struct mpdpacket** pkt)
{
    int entry_size = 0;
    int header_size = 0;
    int i = 0;
    struct mpdpacket* packet;
    struct mpdhdr* hdr;
    struct mpdentry* entries;

    entry_size = sizeof(struct mpdentry);
    header_size = sizeof(struct mpdhdr);
    packet = malloc(sizeof(struct mpdpacket));
    if (!packet) {
        /*Cleanup*/
        return -1;
    }
    hdr = malloc(header_size);
    if (!hdr) {
        /*Cleanup*/
        return -1;
    }
    memcpy(hdr, buffer, header_size);
    packet->header = hdr;
    entries = malloc(entry_size * hdr->num);
    if (!entries) {
        /*Cleanup*/
        return -1;
    }
    buffer += header_size;
    packet->entry = entries;
    for (i = 0; i < hdr->num; i++) {
        memcpy(entries + i, buffer + (i * entry_size), entry_size);
    }
    *pkt = packet;
    return 0;
}

/**
 *
 */
int
create_request_packet(struct mpdpacket** packet, int hflag)
{
    struct mpdpacket* pkt;

    pkt = malloc(sizeof(struct mpdpacket));

    pkt->header = 0;
    pkt->entry = 0;

    if (!pkt) {
        /*cleanup*/
        print_debug("Packet is null\n");
        return FAILURE;
    }

    pkt->header = malloc(sizeof(struct mpdhdr));

    if (!(pkt->header)) {
        /*cleanup*/
        print_debug("Header is null\n");
        return FAILURE;
    }

    pkt->header->type = hflag;
    pkt->header->num = 0;
    *packet = (void*)pkt;

    return SUCCESS;
}

/**
 *
 */
int
create_update_packet(struct physical_interface* iff, struct mpdpacket** packet)
{
    int i = 0;
    int j = 0;
    int buffer_size = 0;
    int size = 0;
    struct mpdpacket* pkt;

    if (!iff->virt_list) {
        /*
           This can be normal behaviour if there are no other interfaces with
           available gateways
         */
        print_error("Virtual interface list has not been created\n");
        return FAILURE;
    }

    size = list_size(iff->virt_list);

    if (!size) {
        print_error("Interface has no virtual addresses\n");
        print_debug("No more exits available?");
        //return FAILURE;
    }

    pkt = malloc(sizeof(struct mpdpacket));

    pkt->header = 0;
    pkt->entry = 0;

    if (!pkt) {
        /*cleanup*/
        print_error("Packet is null\n");
        return FAILURE;
    }

    pkt->header = malloc(sizeof(struct mpdhdr));

    if (!(pkt->header)) {
        /*cleanup*/
        print_error("Header is null\n");
        return FAILURE;
    }

    buffer_size = sizeof(struct mpdentry);

    print_debug("Processing virtual interface list (size: %d)\n", size);
    for (i = 0; i < size; i++) {
        struct virtual_interface* virt = (list_get(iff->virt_list, i))->data;
        print_debug("Adding virtual interface %d to packet\n", i);
        if(virt->attach == iff && virt->out == iff){
            printf("This link originated from this host, don't send back\n");
            continue;
        }
        if (virt->gateway && virt->address && virt->netmask) {
            struct mpdentry* e = 0;
            print_debug("Entry Buffer Size: %d\n", buffer_size);
            pkt->entry = realloc(pkt->entry, buffer_size);

            if (!pkt->entry) {
                print_error("Realloc failed\n");
                break;
            }

            buffer_size += sizeof(struct mpdentry);
            e = (pkt->entry) + j;
            print_debug("Entry (%p) - j(%d) pkt(%p)\n", e, j, pkt->entry);
            e->address = (virt->address);
            e->netmask = htonl(virt->netmask);
            e->gateway = htonl(virt->attach->address);
            e->metric = htonl(virt->metric);
            e->ext_ip = htonl(virt->external_ip);
            //e->mp_mode = get_net_mp_const(iff->ifflags);
            //e->mp_mode= 0;
            e->depth = virt->depth;
            e->type = ENTRY_TYPE_ADD;
            print_debug("Entry Address: %s\n", ip_to_str(ntohl(e->address)));
            j++;
        } else {
            print_error("found null gateway\n");
        }
    }

    pkt->header->type = MPD_HDR_UPDATE;
    pkt->header->num = j;

    *packet = (void*)pkt;

    return j;
}

/* end file: network.c */
