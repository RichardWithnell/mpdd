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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>

#include "util.h"
#include "debug.h"


static const uint32_t CIDR[33] =
{0x0,
    0x80000000,
    0xC0000000,
    0xE0000000,
    0xF0000000,
    0xF8000000,
    0xFC000000,
    0xFE000000,
    0xFF000000,
    0xFF800000,
    0xFFC00000,
    0xFFE00000,
    0xFFF00000,
    0xFFF80000,
    0xFFFC0000,
    0xFFFE0000,
    0xFFFF0000,
    0xFFFF0000,
    0xFFFF0000,
    0xFFFFE000,
    0xFFFFE000,
    0xFFFFF800,
    0xFFFFFC00,
    0xFFFFFE00,
    0xFFFFFF00,
    0xFFFFFF80,
    0xFFFFFFC0,
    0xFFFFFFE0,
    0xFFFFFFF0,
    0xFFFFFFF8,
    0xFFFFFFFC,
    0xFFFFFFFE,
    0xFFFFFFFF
};

/**
*
*/
uint32_t lookup_cidr(uint32_t netmask)
{
    int i = 0;
    for(i = 0; i <= 32; i++) {
        if(CIDR[i] == netmask) break;
    }

    return i;
}


/********
*
* TODO this blocks the thread if there is no IP address... probably the same
* for DNS issues.
*/
uint32_t get_ext_ip(uint32_t ip)
{
    char *cmd = malloc(256);
    char *buffer = malloc(128);
    struct in_addr addr;

    memset(cmd, 0 , 256);
    memset(buffer, 0, 128);

    sprintf(cmd,
        "wget http://icanhazip.com --tries=1 \
             --timeout=5 \
             --bind-address=%s \
             -O - -o /dev/null",
         ip_to_str(ntohl(ip)));

    FILE *f = popen(cmd, "r");
    fscanf(f, "%s", buffer);

    /*Retrieved the external IP succes
    sfully*/
    if(inet_pton(AF_INET, buffer, &addr) == 1){
        free(buffer);
        free(cmd);
        return (uint32_t)addr.s_addr;
    } else {
        free(buffer);
        free(cmd);
        return (uint32_t)0;
    }
}


/**
*
*/
char *trimwhitespace(char *str)
{
  char *end;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}


/**
*
*/
char *ip_to_str(int ip)
{
    static char ipstr[32] = "";

	memset(ipstr, 0, 32);
    sprintf(ipstr, "%d.%d.%d.%d", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return ipstr;
}


/**
*
*/
void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("\t%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}


/**
*
*/
int multipath_enabled(void)
{
    size_t size = 0;
    int enabled;
    char *line, *endptr = 0;

    FILE *file = fopen("/proc/sys/net/mptcp/mptcp_enabled", "r");
    while (!feof(file)) getline(&line, &size, file);
    fclose (file);
    enabled = strtol(line, &endptr, 10);
    return (endptr != line) ? enabled : 0;
}


/**
*
*/
uint8_t get_net_mp_const(int flags){
    uint8_t mode = 0;
    int mp = flags & IFF_NOMULTIPATH;
    int bu = flags & IFF_MPBACKUP;
    int ho = flags & IFF_MPHANDOVER;
    if(mp){
        mode = NET_MP_MODE_OFF;
    } else if(bu){
        mode = NET_MP_MODE_BACKUP;
    } else if(ho){
        mode = NET_MP_MODE_HANDOVER;
    } else {
        mode = NET_MP_MODE_ON;
    }
    return mode;
}


/**
*
*/
char* get_mp_mode(int flags){
    static char *mode = "";
    int mp = flags & IFF_NOMULTIPATH;
    int bu = flags & IFF_MPBACKUP;
    int ho = flags & IFF_MPHANDOVER;
    if(mp){
        mode = "NOMULTIPATH";
    } else if(bu){
        mode = "MPBACKUP";
    } else if(ho){
        mode = "MPHANDOVER";
    } else {
        mode = "MULTIPATH";
    }
    return mode;
}

/* end file: util.c */
