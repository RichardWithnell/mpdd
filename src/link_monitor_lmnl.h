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

#ifndef MPD_LINK_MONITOR
#define MPD_LINK_MONITOR

#include <semaphore.h>
#include <pthread.h>
#include <stdint.h>

#include "queue.h"

struct mnl_addr {
  uint32_t address;
  uint32_t local;
  uint32_t broadcast;
  uint32_t prefix;
  uint32_t prefixlen;
  int idx;
  uint32_t flags;
  char label[16];
  int family;
};

struct mnl_link {
  int idx;
  unsigned int flags;
  uint8_t type;
  uint32_t family;
  char name[16];
};

struct mnl_route {
  uint8_t table;
  int idx;
  uint32_t gateway;
  uint32_t prio;
};

struct cache_monitor {
    Queue *queue;
    pthread_mutex_t *lock;
    sem_t *barrier;
};

struct update_obj {
    int action;
    int type;
    void *update;
};

#define UPDATE_LINK 1
#define UPDATE_ADDR 2
#define UPDATE_ROUTE 3
#define UPDATE_GATEWAY 4

#define ADD_IFF 0x01
#define DEL_IFF 0x02
#define ADD_IP 0x03
#define DEL_IP 0x04
#define CHANGE_IP 0x07
#define CHANGE_RT 0x08
#define ADD_RT 0x05
#define DEL_RT 0x06

void init_monitor(void *data);

#endif

/* end file: link_monitor.h */
