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

#ifndef MPD_UTIL
#define MPD_UTIL

#include "list.h"

enum {
    IFF_NOMULTIPATH = 0x80000,       /*Disable for MPTCP        */
    IFF_MPBACKUP = 0x100000,  /*Use as back up path for MPTCP*/
    IFF_MPHANDOVER = 0x200000
};

#define CONFIG "/etc/mpd/mpd.conf"
#define IGNORE_CONFIG "/etc/mpd/ignore.conf"

enum {
    NET_MP_MODE_OFF = 0x02,
    NET_MP_MODE_BACKUP = 0x03,
    NET_MP_MODE_HANDOVER = 0x04,
    NET_MP_MODE_ON = 0x01
};

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t lookup_cidr(uint32_t netmask);
uint32_t get_ext_ip(uint32_t ip);
char* trimwhitespace(char* str);
List* read_config(char* path);
char* ip_to_str(int ip);
void print_ip(int ip);
int multipath_enabled(void);
uint8_t get_net_mp_const(int flags);
char* get_mp_mode(int flags);

#endif

/* end file: util.h */
