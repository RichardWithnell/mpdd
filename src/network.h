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

#ifndef MPD_NETWORK
#define MPD_NETWORK

#include "interface.h"
#include "link_monitor.h"
#include "list.h"
#include "queue.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/socket.h>

#define DISS_MODE_MESH 0x00
#define DISS_MODE_TREE 0x01

enum {
    MPD_BROADCAST_PORT = 12344,
    MPD_MULTICAST_PORT = 12346,
    MPD_UNICAST_PORT = 12347
};

enum {
    MPD_HDR_REQUEST  = 0x00,
    MPD_HDR_UPDATE = 0x01,
    MPD_HDR_HEARTBEAT = 0x02
};

//#define NET_MP_MODE_BACKUP 0x03
//#define NET_MP_MODE_HANDOVER 0x02
//#define NET_MP_MODE_OFF 0x00
//#define NET_MP_MODE_ON 0x01

enum {
    SUCCESS = 0x00,
    FAILURE = -0x01
};



enum {
    ENTRY_TYPE_DEL = 0x00,
    ENTRY_TYPE_ADD = 0x01
};

struct mpdentry
{
    uint32_t address;
    uint32_t netmask;
    uint32_t gateway;
    uint32_t ext_ip;
    uint32_t metric;
    uint8_t depth;
    uint8_t type;
} __attribute__((__packed__));

struct mpdhdr
{
    uint8_t type;
    uint8_t num;
} __attribute__((__packed__));

struct mpdpacket
{
    struct mpdhdr* header;
    struct mpdentry* entry;
} __attribute__((__packed__));

struct send_queue
{
    struct queue receive_queue;
    int flag;
    int request_flag;
    int heartbeat_flag;
    struct queue request_queue;
    List* iff_list;
    List* virt_list;
    List* old_virt_list;
    struct cache_monitor* mon_data;
    pthread_mutex_t flag_lock;
    pthread_mutex_t request_flag_lock;
    pthread_mutex_t iff_list_lock;
    pthread_mutex_t virt_list_lock;
    struct nl_sock *sock;
    int socket_fd;
    fd_set wfds;
    int running;
};

struct network_update
{
    struct sockaddr_in addr;
    struct mpdpacket pkt;
};

void* recv_broadcast(struct send_queue* squeue);

int serialize_packet(struct mpdpacket* pkt, unsigned char** buffer);
int deserialize_packet(unsigned char* buffer, struct mpdpacket** pkt);

int create_update_packet(struct physical_interface* iff, struct mpdpacket** packet);
int create_request_packet(struct mpdpacket** packet, int hflag);

void print_packet(struct mpdpacket* pkt);
int do_broadcast(struct physical_interface* i,
                 int sock,
                 unsigned char* buffer,
                 int len);
int send_update_broadcast(List* iff_list, int sock);
int send_request_broadcast(struct physical_interface* iff, int sock, int hflag);

int create_socket(struct physical_interface* i);

#define IS_LOCAL_HOST(host) (2130706433 == host ? 1 : 0)

#endif

/* end file: network.h */
