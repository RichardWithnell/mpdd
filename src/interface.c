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

/*
 * TODO split this into two files,
 */

#include "debug.h"
#include "interface.h"
#include "resource_interface.h"

#define SUCCESS 0x00
#define FAILURE -0x01

#define LOOPBACK "lo"

int delete_rules_by_gw(struct nl_sock* sock, List* list, uint32_t gw);
int delete_virtual_by_phy_addr(List* list, uint32_t gw);
struct virtual_interface* create_alias(struct nl_sock* sock,
                                       struct physical_interface* iff,
                                       struct interface* p,
                                       List* virt_list);

char host_name[32];
const int PREFER_OWN_LINKS = 1;


/*
 *
 */
struct physical_interface*
get_iff_network_update(uint32_t sender_ip, List* iff_list)
{
    if (!sender_ip) {
        print_debug("sender IP NULL\n");
        return (struct physical_interface*)FAILURE;
    }
    Litem *item;
    list_for_each(item, iff_list){
        struct physical_interface* iff = item->data;

        if (iff->address) {
            if ((sender_ip & iff->netmask) == (iff->address & iff->netmask)) {
                return iff;
            }
        }
    }

    return (struct physical_interface*)0;
}


/*
 *
 */
uint32_t get_host_id(struct physical_interface* phy)
{
    if (phy) {
        return phy->address & (~(phy->netmask));
    } else {
        return 0;
    }
}


/*
 *
 */
int in_list(char* name, List* diss_list)
{
    Litem *item;
    list_for_each(item, diss_list){
        char* data = item->data;

        if (!strcmp(data, name)) {
            return 1;
        }
    }
    return 0;
}


/*
 *
 */
int mark_diss_iff(char* name, List* diss_list)
{
    if (!name) {
        print_debug("Name is NULL");
        return 0;
    }

    if (!diss_list) {
        print_debug("Diss_list is null");
        return 0;
    }
    Litem *item;
    list_for_each(item, diss_list){
        char* data = item->data;

        if (!data) {
            continue;
        }
        print_debug("Compare: %s : %s \n", data, name);
        if (!strcmp(data, name)) {
#ifdef DEBUG
            print_debug("Marking %s for dissemination\n", name);
#endif
            return 1;
        }
    }
#ifdef DEBUG
    print_debug("No dissemination on %s\n", name);
#endif
    return 0;
}


/*
 *
 */
struct interface* get_interface_by_idx(int ifidx, List* l)
{
    Litem *item;
    list_for_each(item, l){
        struct interface* iff = item->data;

        if (iff->ifidx == ifidx) {
            return (struct interface*)iff;
        }
    }
    return (struct interface*)0;
}


/*
 *
 */
struct virtual_interface*
add_virtual(char* name, uint32_t idx, uint32_t flags, List* iff_list)
{
    Litem* item = 0;
    struct virtual_interface* virt = 0;

    /*Create the interface*/
    virt = init_virt();
    if (!virt) {
        errno = ENOMEM;
        return (struct virtual_interface*)0;
    }

    /*Create the list item*/
    item = (Litem*)malloc(sizeof(Litem));
    if (!item) {
        errno = ENOMEM;
        return (struct virtual_interface*)0;
    }

    /*Copy the properties across*/
    strcpy(virt->super.ifname, name);
    virt->super.ifidx = idx;
    virt->flags = flags;
    virt->gateway = 0;

    item = (Litem*)malloc(sizeof(Litem));
    if (!item) {
        errno = ENOMEM;
        destroy_virt_interface(virt);
        return (struct virtual_interface*)0;
    }
    item->data = (void*)virt;
    list_put(iff_list, item);
    return virt;
}


/*
 *
 */
struct physical_interface*
add_physical(
  char* name,
  uint32_t idx,
  uint32_t flags,
  int diss,
  uint8_t *mac_address,
  List* iff_list)
{
    Litem* item = 0;
    struct physical_interface* phys = 0;

    print_debug("\n");
    /*Create the interface*/
    phys = init_phys();
    if (!phys) {
        errno = ENOMEM;
        return (struct physical_interface*)0;
    }

    /*Create the list item*/
    item = (Litem*)malloc(sizeof(Litem));
    if (!item) {
        errno = ENOMEM;
        return (struct physical_interface*)0;
    }

    /*Copy the properties across*/
    strcpy(phys->super.ifname, name);
    phys->super.ifidx = idx;
    phys->flags = flags;
    phys->diss = diss;
    memcpy(phys->mac_address, mac_address, 6);

    item = (Litem*)malloc(sizeof(Litem));
    if (!item) {
        errno = ENOMEM;
        destroy_phys_interface(phys);
        return (struct physical_interface*)0;
    }
    item->data = (void*)phys;
    list_put(iff_list, item);
    return phys;
}


/*
 *
 */
struct interface*
add_link(
    struct rtnl_link* link,
    List* iff_list,
    List* ignore_list,
    List* diss_list,
    int type)
{
    int ifidx = -1;
    char* ifname = 0;
    int flags = 0;
    struct nl_addr *mac;
    uint8_t mac_address[6];
    void *macaddr;

    ifname = rtnl_link_get_name(link);

    print_debug("ifname: %s\n", ifname);

    /*We don't care about the loopback interface*/
    if (!strcmp(LOOPBACK, ifname)) {
        print_debug("Found Loop Back\n");
        return (struct interface*)0;
    } else {
        if (ignore_list) {
            if (in_list(ifname, ignore_list)) {
                print_debug("Interface in ignore list.\n");
                return (struct interface*)0;
            }
        }
    }

    /*Check if we already have this interface*/
    ifidx = rtnl_link_get_ifindex(link);
    flags = rtnl_link_get_flags(link);
    mac = rtnl_link_get_addr(link);
    if(!mac){
        return (struct interface*)0;
    }
    macaddr = nl_addr_get_binary_addr (mac);
    if(!macaddr){
        return (struct interface*)0;
    }

    memcpy(mac_address, (int*)macaddr, 6);

    if (type == PHYSICAL_TYPE) {
        int diss = 0;
        struct physical_interface* phys =
            (struct physical_interface*)get_interface_by_idx(ifidx, iff_list);
        print_debug("Creating physical interface\n");
        if (phys) {
            /*Interface already exists*/

            phys->flags = flags;
            return (struct interface*)phys;
        } else {
            /*New Interface*/
            phys = 0;
        }
        if (diss_list) {
            diss = mark_diss_iff(ifname, diss_list);
        }
        return (struct interface*)add_physical(ifname, ifidx, flags, diss,
                                                mac_address, iff_list);
    } else if (type == VIRTUAL_TYPE) {
        struct virtual_interface* virt =
            (struct virtual_interface*)get_interface_by_idx(ifidx, iff_list);
        print_debug("Creating virtual interface\n");
        if (virt) {
            /*Interface already exists*/
            virt->flags = flags;
            return (struct interface*)virt;
        } else {
            /*New Interface*/
            virt = 0;
        }
        return (struct interface*)add_virtual(ifname, ifidx, flags, iff_list);
    } else {
        print_debug("bad type\n");
        return (struct interface*)0;
    }
}


/*
 *
 */
int
delete_link(struct rtnl_link* link, List* iff, List* virt, List* ignore_list)
{
    int j = 0;

    int idx = rtnl_link_get_ifindex(link);

    for (j = list_size(iff); j--; ) {
        struct physical_interface* p = (struct physical_interface*)list_get(iff, j)->data;
        if( p && (idx == p->super.ifidx)) {
            list_remove(iff, j);
            free(p);
        }
    }
    return SUCCESS;
}


/*
 *
 */
struct interface*
add_addr(
    struct nl_sock* sock,
    struct rtnl_addr* addr,
    List* iff, List* virt,
    List* ignore_list,
    List* diss_list )
{
    char* label = 0;
    uint32_t* broadcast = 0;
    uint32_t prefix = 0;
    int ifidx = -1;
    struct physical_interface* temp_phys;
    struct virtual_interface* temp_virt;

    struct nl_addr* local = 0;

    if (!addr) {
        print_debug("Addr param == null\n");
        return (struct interface*)0;
    }

    local = rtnl_addr_get_local(addr);

    if (nl_addr_iszero(local)) {
        print_debug("Address invalid\n");
        return (struct interface*)0;
    }

    /*get the index*/
    ifidx = rtnl_addr_get_ifindex(addr);
    print_debug("Address Index: %d\n",  ifidx);

    if (local) {
        Litem *pitem;
        list_for_each(pitem, iff){
            temp_phys = (struct physical_interface*)pitem->data;
            print_debug("\tComparing %s and ",
                        ip_to_str(htonl(temp_phys->address)));
            print_debug("%s\n",
                        ip_to_str(htonl(*(uint32_t*) nl_addr_get_binary_addr(
                                            (struct nl_addr*)local))));

            if (temp_phys->address ==
                *(uint32_t*)nl_addr_get_binary_addr((struct nl_addr*)local)
                ) {
                print_debug("Address already exists\n");
                return (struct interface*)0;
            }
        }
        Litem *vitem;
        list_for_each(vitem, virt) {
            temp_virt = (struct virtual_interface*)vitem->data;

            print_debug("\tComparing %s and ", ip_to_str(htonl(temp_virt->address)));
            print_debug("%s\n",
                        ip_to_str(htonl(*(uint32_t*)nl_addr_get_binary_addr(
                                            (struct nl_addr*)local))));

            if (temp_virt->address ==
                *(uint32_t*)nl_addr_get_binary_addr((struct nl_addr*)local)
                ) {
                print_debug("Address already exists\n");
                return (struct interface*)0;
            }
        }
    }

    /*Get address attributes*/
    prefix = rtnl_addr_get_prefixlen(addr);
    broadcast = (uint32_t*)rtnl_addr_get_broadcast(addr);
    label = rtnl_addr_get_label(addr);

    if (strstr(label, ":") != NULL) {
        struct physical_interface* p = (struct physical_interface*)0;
        struct virtual_interface* v = (struct virtual_interface*)0;
        print_debug(" Handling add alias address\n");
        //Add to the virtual list

        /*We should have setup the interface already*/
        //v = (struct virtual_interface*) get_interface_by_address(ifidx, virt);
        p = (struct physical_interface*)get_interface_by_idx(ifidx, iff);

        if (!p) {
            print_debug("Physical Interface doesn't exist\n");
            struct rtnl_link* link = rtnl_addr_get_link(addr);
            if (!link) {
                print_debug("No link for addr\n");
                return (struct interface*)0;
            }
            p = (struct physical_interface*)add_link(link,
                                                     iff,
                                                     ignore_list,
                                                     diss_list,
                                                     PHYSICAL_TYPE);

            if (!p) {
                print_debug("Failed to add link\n");
                return (struct interface*)0;
            }
        } else {
            print_debug("Found physical interface\n");
        }

        if (p->virt_list) {
            Litem *item;

            print_debug("Virtual List: %d\n", list_size(p->virt_list));

            list_for_each(item, p->virt_list){
                struct virtual_interface* iff = item->data;

                if (!iff->address) {
                    v = (struct virtual_interface*)iff;
                }
            }
        } else {
            print_debug(
                "The physical interface, virtual address list is not instantiated\n");
        }

        /*Interface not created*/

        if (!v) {
            print_debug("Didn't find virtual interface\n");
            struct rtnl_link* link = rtnl_addr_get_link(addr);

            if (!link) {
                print_debug("Bad link\n");
                return (struct interface*)0;
            }

            v = (struct virtual_interface*)add_virtual(p->super.ifname,
                                                       ifidx, p->flags, virt);
            if (!v) {
                print_debug("Failed to create virtual interface\n");
                return (struct interface*)0;
            }
        } else {
            print_debug(" Found virtual interface\n");
        }

        print_debug("Setting interface that the virtual IP address is attached to\n");

        if (local) {
            v->address =
                *(uint32_t*)nl_addr_get_binary_addr((struct nl_addr*)local);
        }

        if (prefix) {
            v->netmask = ntohl((0xffffffff >> (32 - prefix)) << (32 - prefix));
        }

        if (p->diss) {
            print_debug("Added address to virtual list, find gateway\n");
            create_rule_for_gw(sock, (struct interface*)v, v->out->super.ifidx);
        }

        create_routing_table_subnet_route(sock,
            (struct interface*)v, v->attach->super.ifidx, v->out->super.ifidx);

        if(!v->external_ip) {
            v->external_ip = v->out->external_ip;
        }

        return (struct interface*)v;
    } else {
        /*Add to the physical list*/
        struct physical_interface* p = (struct physical_interface*)0;

        print_debug("Add physical interface\n");

        /*We should have setup the interface already*/
        p = (struct physical_interface*)get_interface_by_idx(ifidx, iff);

        /*Interface not created*/
        if (!p) {
            struct nl_cache* lcache;
            int idx = rtnl_addr_get_ifindex(addr);
            int ret = rtnl_link_alloc_cache (sock, AF_INET, &lcache);

            if(ret) {
                print_debug("Failed to get link %d (%s)\n",
                            rtnl_addr_get_ifindex(addr),
                            rtnl_addr_get_label(addr));

                return (struct interface*)0;
            }

            struct rtnl_link* link = rtnl_link_get(lcache, idx);

            nl_cache_free(lcache);

            if (!link) {
                print_debug("Failed to get link %d (%s)\n",
                            rtnl_addr_get_ifindex(addr),
                            rtnl_addr_get_label(addr));

                return (struct interface*)0;
            }

            p = (struct physical_interface*)add_link(
                link, iff, ignore_list, diss_list, PHYSICAL_TYPE);

            if (!p) {
                print_debug("Failed to add link\n");
                return (struct interface*)0;
            }
        }

        if (local) {
            p->address = *(uint32_t*)nl_addr_get_binary_addr(
                (struct nl_addr*)local);
        }
        if (broadcast) {
            p->broadcast = *(uint32_t*)nl_addr_get_binary_addr(
                (struct nl_addr*)broadcast);
        }
        if (prefix) {
            p->netmask = ntohl((0xffffffff >> (32 - prefix)) << (32 - prefix));
        }
        /*Assume broadcast address, if not explicitly set*/
        if (!p->broadcast || p->broadcast == p->address) {
            p->broadcast = (p->netmask & p->address) | (~p->netmask);
        }
        return (struct interface*)p;
    }
}


/*
 * The address has been deleted by the system, delete from the appropriate data structures
 */
int
delete_address_rtnl(
    struct nl_sock* sock,
    struct rtnl_addr* addr,
    List* iff_list,
    List* virt_list)
{
    uint32_t vaddr = (uint32_t)0;
    struct nl_addr* local = (struct nl_addr*)0;
    char* label = (char*)0;
    int ret_val = 0;

    if (!addr) {
        print_debug("Addr struct is null\n");
    }

    local = rtnl_addr_get_local(addr);

    if (nl_addr_iszero(local)) {
        print_debug("Address invalid\n");
        return FAILURE;
    }

    vaddr = *(uint32_t*)nl_addr_get_binary_addr((struct nl_addr*)local);

    label = rtnl_addr_get_label(addr);

    print_debug("Deleting: %s from %s\n", ip_to_str(htonl(vaddr)), label);

    if (strstr(label, ":") != NULL) {
        Litem *vitem;
        Litem *temp_item = (Litem*)0;
        print_debug("Deleting virtual address\n");
        int i = 0;

        ret_val = 1;

        list_for_each(vitem, virt_list){
            struct virtual_interface* virt =
                (struct virtual_interface*)vitem->data;

            if (virt && (vaddr == virt->address)) {
                Litem *pvitem;
                int j = 0;
                list_for_each(pvitem, virt->attach->virt_list){
                    struct virtual_interface* phys_virt =
                        (struct virtual_interface*)pvitem->data;

                    if (phys_virt && vaddr == phys_virt->address) {
                        temp_item = list_remove(virt->attach->virt_list, j);
                        free(temp_item);
                        break;
                    }
                    j++;
                }

                temp_item = list_remove(virt_list, i);
                free(temp_item);
                free(virt);
                break;
            }
            i++;
        }
    } else {
        Litem *pitem;
        print_debug("Deleting physical address\n");
        list_for_each(pitem, iff_list){
            struct physical_interface* phys =
                (struct physical_interface*)pitem->data;

            if (phys && (vaddr == phys->address)) {
                /*Delete all virtual interfaces interfaces*/
                if(phys->gateway) {
                    uint32_t gw = phys->gateway;
                    delete_route_from_physical(iff_list, gw);
                    delete_rules_by_gw(sock, virt_list, gw);
                    delete_virtual_by_gw(virt_list, gw);
                    flush_table(sock, phys->super.ifidx);
                    ret_val = 1;
                }
                Litem * item;
                if(phys->virt_list) {
                    list_for_each(item, phys->virt_list){
                        int j = 0;
                        struct virtual_interface* iff =
                            (struct virtual_interface*)item->data;
                        for (j = list_size(virt_list); j--; ) {
                            if(iff ==
                               (struct virtual_interface*)list_get(
                                   virt_list, j)->data) {
                                Litem* tmpitem = list_remove(
                                    virt_list,
                                    j);
                                free(tmpitem->data);
                                free(tmpitem);
                                break;
                            }
                        }
                    }
                    free(phys->virt_list);
                    phys->virt_list = 0;
                }

                phys->address = 0;
                phys->netmask = 0;
                phys->gateway = 0;
                phys->broadcast = 0;
                phys->external_ip = 0;

                break;
            }
        }
    }

    return ret_val;
}

/*
*
*/
int
delete_address(
    struct nl_sock* sock,
    uint32_t ip,
    uint32_t netmask,
    uint8_t ifidx)
{
    int ret = 0;
    struct rtnl_addr* addr = (struct rtnl_addr*)0;
    struct nl_addr* local = (struct nl_addr*)0;
    uint32_t plen = 0;

    addr = rtnl_addr_alloc();

    if (!addr) {
        print_debug("Failed to allocate address\n");
        return FAILURE;
    }

    local = nl_addr_build(AF_INET, &ip, sizeof(uint32_t));

    if (!local) {
        print_debug("Failed to build address\n");
        rtnl_addr_put(addr);
        return FAILURE;
    }

    print_debug("Netmask: %s IDX: %d\n",
                ip_to_str(htonl(netmask)), ifidx);

    plen = lookup_cidr(htonl(netmask));

    print_debug("Built address: %s/%d\n",
                ip_to_str(htonl(*(uint32_t*)
                                nl_addr_get_binary_addr((struct nl_addr*)local))),
                plen);

    rtnl_addr_set_local(addr, local);
    rtnl_addr_set_prefixlen(addr, plen);
    rtnl_addr_set_family(addr, AF_INET);
    rtnl_addr_set_ifindex(addr, ifidx);

    ret = rtnl_addr_delete(sock, addr, 0);
    if (ret) {
        print_error("Delete address failed: %s - %s\n",
                    nl_geterror(ret),
                    ip_to_str(htonl(*(uint32_t*)
                                    nl_addr_get_binary_addr((struct nl_addr*)local))));
        nl_addr_put(local);
        rtnl_addr_put(addr);
        return FAILURE;
    }
    print_debug("Delete address succeeded\n");
    nl_addr_put(local);
    rtnl_addr_put(addr);
    return SUCCESS;
}


/*
*
*/
int
add_virt_for_diss(struct nl_sock* sock,
                  struct physical_interface* phy,
                  List* iff_list,
                  List* virt_list)
{
    if(!phy->diss) {
        return 0;
    }

    Litem *item;

    list_for_each(item, iff_list){
        struct physical_interface* p = (struct physical_interface*)item->data;

        if(p->gateway) {
            struct virtual_interface* v = create_alias(sock,
                                                       phy,
                                                       (struct interface*)p,
                                                       virt_list);

            create_rule_for_gw(sock, (struct interface*)v, v->table);
        }
    }

    return 0;
}


/*
 *
 */
struct physical_interface*
add_route(struct nl_sock* sock,
          struct rtnl_route* route,
          List* iff_list,
          List* virt_list)
{
    struct nl_addr* gw = 0;
    uint32_t binary_gw = 0;
    struct rtnl_nexthop* nexthop;
    int ifidx = 0;
    struct physical_interface* p = (struct physical_interface*)0;

    if (route) {
        nexthop = rtnl_route_nexthop_n(route, 0);
    } else {
        print_debug("route is NULL\n");
        return (struct physical_interface*)0;
    }

    if (nexthop) {
        gw = rtnl_route_nh_get_gateway(nexthop);
    } else {
        print_debug("nexthop is NULL\n");
        return (struct physical_interface*)0;
    }

    if (gw) {
        binary_gw = *(uint32_t*)nl_addr_get_binary_addr(gw);
    } else {
        print_debug("gw is NULL\n");
        return (struct physical_interface*)0;
    }

    /*Add the default gateway to the list*/
    ifidx = rtnl_route_nh_get_ifindex(nexthop);
    p = (struct physical_interface*)get_interface_by_idx(ifidx, iff_list);
    if (!p) {
        print_debug("Didn't find physical interface\n");
        return (struct physical_interface*)0;
    }
    p->gateway = binary_gw;

    p->metric = rtnl_route_get_priority(route);
    printf("Set link metric to: %u\n", p->metric);

    print_debug("Set Physical Gateway (%s) to %s\n",
                p->super.ifname,
                ip_to_str(htonl(p->gateway)));

    /*create virtual interfaces*/
    print_debug("create aliases for gw\n");
    create_aliases_for_gw(sock, iff_list, virt_list, (struct interface*)p);
    /*create ip rules to tunnel traffic*/
    print_debug("create rules for gw\n");
    create_rule_for_gw(sock, (struct interface*)p, p->super.ifidx);
    create_rules_for_gw(sock, virt_list, (struct interface*)p);
    /*create routing table*/
    print_debug("create routing table\n");
    create_routing_table(sock, (struct interface*)p, virt_list);
    print_debug("get_external_ip\n");
    p->external_ip = get_ext_ip(p->address);

    if(p->external_ip) {
        print_debug("External IP: %s\n", ip_to_str(htonl(p->external_ip)));
#ifdef EVAL
        struct timespec monotime;
        clock_gettime(CLOCK_REALTIME, &monotime);
        print_eval("NR:%s:%s:%s:%lld.%.9ld\n",
                   host_name,
                   ip_to_str(htonl(p->external_ip)),
                   p->super.ifname,
                   (long long)monotime.tv_sec,
                   (long)monotime.tv_nsec);
#endif
    } else {
        print_debug("Failed to get external IP address\n");
    }
#ifndef DEBUG
    create_table_file(p->address, p->super.ifidx, DIRECT_RESOURCE);
#endif
    print_debug(" Done\n");
    return p;
}


/*
 *
 */
int delete_route_from_physical(List* l, uint32_t route)
{
    Litem *item;

    list_for_each(item, l){
        struct physical_interface* iff = (struct physical_interface*)item->data;

        if (iff->gateway == route) {
            iff->gateway = 0;

#ifdef EVAL
            struct timespec monotime;
            clock_gettime(CLOCK_REALTIME, &monotime);
            print_eval("DR:%s:%s:%lld.%.9ld\n",
                       host_name,
                       ip_to_str(htonl(iff->external_ip)),
                       (long long)monotime.tv_sec,
                       (long)monotime.tv_nsec);
#endif
#ifndef DEBUG
            delete_table_file(iff->address, DIRECT_RESOURCE);
#endif
        }
    }
    return 0;
}


/*
 *
 */
void delete_rule_cb(struct nl_object* cb, void* arg)
{
    print_debug("Delete rule callback\n");
    struct nl_sock* sock;
    struct rtnl_rule* rule;
    int ret = 0;

    sock = (struct nl_sock*)arg;
    rule = (struct rtnl_rule*)cb;
    ret = rtnl_rule_delete(sock, rule, 0);

    if (ret) {
        print_debug("Error deleting rule: %d\n", ret);
    }
}


/*
 *
 */
int
delete_rule(struct nl_sock* sock, uint32_t ip, uint32_t mask, uint32_t table)
{
    struct rtnl_rule* filter = 0;
    struct nl_cache* rule_cache = 0;

    filter = rtnl_rule_alloc();
    rtnl_rule_alloc_cache(sock, AF_INET, &rule_cache);
    int sip = ip & mask;
    print_debug("RULE IPS\n");
    //print_ip(ip);
    //print_ip(mask);
    struct nl_addr* src = nl_addr_build(AF_INET, &sip, sizeof(uint32_t));
    nl_addr_set_prefixlen(src, 24);
    char buff[64];
    nl_addr2str(src, buff, 64);
    print_debug("Rule Src: %s\n", buff);
    rtnl_rule_set_src(filter, src);
    rtnl_rule_set_family(filter, AF_INET);
    rtnl_rule_set_table(filter, table);
    print_debug("Lookup CIDR: %d\n", lookup_cidr(htonl(mask)));
    //rtnl_rule_set_mask(filter, lookup_cidr(htonl(mask)));
    nl_cache_foreach_filter(
        rule_cache, (struct nl_object*)filter, delete_rule_cb, sock);
    return 0;
}


/*
 *
 */
int
delete_rules_by_gw(struct nl_sock* sock, List* list, uint32_t gw)
{
    Litem *item;

    list_for_each(item, list){
        struct virtual_interface* iff = item->data;

        if (iff->gateway == gw) {
            print_debug("delete rules with address: ");
            //print_ip(iff->address);
            delete_rule(sock, iff->address, iff->netmask, iff->table);
        }
    }

    return 0;
}


/*
 *
 */
int delete_virtual_by_gw(List* list, uint32_t gw)
{
    int i = 0;
    int j = 0;

    print_debug("\n");
    print_debug("List Size: %d\n", list_size(list));

    for (i = list_size(list); i--; ) {
        print_debug("IDX: %d\n", i);
        struct virtual_interface* iff = (list_get(list, i))->data;

        print_debug("Virtual Gateway: %s\n", ip_to_str(iff->gateway));
        print_debug("Actual Gateway: %s\n", ip_to_str(gw));
        if (iff->gateway == gw) {
            Litem* tmpitem = list_remove(list, i);

            if(iff->attach) {
                List* l = iff->attach->virt_list;
                if(!l) {
                    break;
                }
                for (j = list_size(l); j--; ) {
                    struct virtual_interface* v = (list_get(l, j))->data;
                    if(v == iff) {
                        list_remove(l, j);
                        break;
                    }
                }
            }

            if(iff->out) {
                List* l = iff->out->virt_list;
                if(!l) {
                    break;
                }
                for (j = list_size(l); j--; ) {
                    struct virtual_interface* v = (list_get(l, j))->data;
                    if(v == iff) {
                        list_remove(l, j);
                        break;
                    }
                }
            }

            free(tmpitem->data);
            free(tmpitem);
        }
    }
    return 0;
}


/*
 *
 */
int delete_virtual_by_phy_addr(List* list, uint32_t addr)
{
    int i = 0;

    print_debug("\n");
    print_debug("List Size: %d\n", list_size(list));

    for (i = list_size(list); i--; ) {
        print_debug("IDX: %d\n", i);
        struct virtual_interface* iff = (list_get(list, i))->data;

        print_debug("Actual Gateway: %s\n", ip_to_str(addr));
        if (iff->attach->address == addr) {
            print_debug("Removing Attached Virt: %s\n",
                        ip_to_str(iff->attach->address));
            list_remove(list, i);
        } else if (iff->out->address == addr) {
            print_debug("Removing Outgoing Virt: %s\n",
                        ip_to_str(iff->out->address));
            list_remove(list, i);
        }
        free(iff);
    }
    return 0;
}


/*
 *
 */
void flush_table_cb(struct nl_object* cb, void* arg)
{
    struct nl_sock* sock;
    struct rtnl_route* route;

    sock = (struct nl_sock*)arg;
    route = (struct rtnl_route*)cb;

    print_debug("Deleting route\n");
    if (rtnl_route_delete(sock, route, 0)) {
        print_debug("Delte route failed\n");
    }
}


/*
 *
 */
int flush_table(struct nl_sock* sock, int table)
{
    struct nl_cache* route_cache = 0;
    struct rtnl_route* filter = 0;

    print_debug("Flush table (%d)\n", table);

    if (table <= 0) {
        printf("Bad table number: %d\n", table);
        return -1;
    }

    if ((rtnl_route_alloc_cache(sock, AF_UNSPEC, 0, &route_cache)) < 0) {
        print_debug("Alloc cache failed\n");
        return -1;
    }

    if (nl_cache_is_empty(route_cache)) {
        /*Cleanup*/
        print_debug("Route cache is empty\n");
        return -1;
    }

    filter = rtnl_route_alloc();
    rtnl_route_set_table(filter, table);

    nl_cache_foreach_filter(
        route_cache, (struct nl_object*)filter, flush_table_cb, sock);

    rtnl_route_put(filter);
    nl_cache_free(route_cache);

    return 0;
}


/*
 *
 */
int
delete_route(
    struct nl_sock* sock,
    struct rtnl_route* route,
    List* iff_list,
    List* virt_list)
{
    int ifidx = 0;
    struct rtnl_nexthop* nexthop = 0;
    struct nl_addr* gw = 0;
    uint32_t binary_gw = 0;

    nexthop = rtnl_route_nexthop_n(route, 0);
    ifidx = rtnl_route_nh_get_ifindex(nexthop);
    gw = rtnl_route_nh_get_gateway(nexthop);
    binary_gw = *(uint32_t*)nl_addr_get_binary_addr(gw);

    print_debug("Delete Route: %s\n", ip_to_str(binary_gw));

    delete_route_from_physical(iff_list, binary_gw);
    delete_rules_by_gw(sock, virt_list, binary_gw);
    delete_virtual_by_gw(virt_list, binary_gw);
    flush_table(sock, ifidx);

    return SUCCESS;
}


/*
 *
 */
int
delete_virtual_address(struct nl_sock* sock, unsigned int ip, int ifidx)
{
    struct rtnl_addr* addr = rtnl_addr_alloc();
    struct nl_addr* local = nl_addr_build(AF_INET, &ip, 4);

    rtnl_addr_set_prefixlen(addr, 24);
    rtnl_addr_set_ifindex(addr, ifidx);
    rtnl_addr_set_family(addr, AF_INET);
    rtnl_addr_set_local(addr, local);
    rtnl_addr_set_prefixlen(addr, 24);

#ifdef DEBUG
    {
        char buff[64];
        nl_addr2str(local, buff, 64);
        print_debug("Local: %s\n", buff);
    }
#endif

    rtnl_addr_delete(sock, addr, 0);

    print_debug("Delete Address: %d\nIP: ", 0);
    //print_ip(ip);
    //printf("Index: %d\n", ifidx);
    //printf("Ret: %d\n", ret);
    rtnl_addr_put(addr);
    nl_addr_put(local);
    return 0;
}

struct NexthopMatch {
    struct nl_sock *sock;
    List *list;
    struct virtual_interface *virt;
    char flag;
};


/*
*
*/
void delete_nexthop_virt_cb(struct rtnl_nexthop* nh, void* args)
{
    struct NexthopMatch *nhm = (struct NexthopMatch*)args;
    struct virtual_interface* iff = (struct virtual_interface*)nhm->virt;
    if(iff && (iff->out == iff->attach)){
        struct nl_addr* gw = rtnl_route_nh_get_gateway(nh);
        uint32_t bgw = *(uint32_t*)nl_addr_get_binary_addr(gw);
        if(bgw == iff->gateway){
            nhm->flag = 1;
        }
    }
}


/*
*
*/
void delete_nexthop_list_cb(struct rtnl_nexthop* nh, void* args)
{
    struct NexthopMatch *nhm = (struct NexthopMatch*)args;
    List *list = nhm->list;
    Litem *item;
    list_for_each(item, list) {
        struct virtual_interface* iff = (struct virtual_interface*)item->data;
        if(iff && (iff->out == iff->attach)){
            struct nl_addr* gw = rtnl_route_nh_get_gateway(nh);
            uint32_t bgw = *(uint32_t*)nl_addr_get_binary_addr(gw);
            if(bgw == iff->gateway){
                nhm->flag = 1;
            }
        }
    }
}

/*
* TODO change this to use a function pointer to reduce duplication
*/
void
delete_virtual_rt_virt_cb(struct nl_object* cb, void* arg)
{
    if (cb) {
        printf("Delete Virtual RT CB\n");
        struct NexthopMatch *nhm = (struct NexthopMatch *)arg;
        struct rtnl_route* rt = (struct rtnl_route*)cb;
        nhm->flag = 0;
        rtnl_route_foreach_nexthop (rt, delete_nexthop_virt_cb, nhm);
        if(nhm->flag){
            rtnl_route_delete(nhm->sock, rt, 0);
        }
    }
}


/*
*
*/
void
delete_virtual_rt_list_cb(struct nl_object* cb, void* arg)
{
    if (cb) {
        printf("Delete Virtual RT CB\n");
        struct NexthopMatch *nhm = (struct NexthopMatch *)arg;
        struct rtnl_route* rt = (struct rtnl_route*)cb;
        nhm->flag = 0;
        rtnl_route_foreach_nexthop (rt, delete_nexthop_list_cb, nhm);
        if(nhm->flag){
            rtnl_route_delete(nhm->sock, rt, 0);
        }
    }
}


/*
*
*/
struct rtnl_route *
create_load_balance_route(struct nl_sock *sock)
{
    struct nl_addr* dst = 0;
    struct rtnl_route* route = 0;
    struct rtnl_nexthop* nexthop = 0;
    char n = '0';

    if (!(route = rtnl_route_alloc())) {
        perror("add_default_route() - route alloc failed");
        return (struct rtnl_route *)0;
    }

    if (!(nexthop = rtnl_route_nh_alloc())) {
        perror("add_default_route() - nexthop alloc failed");
        return (struct rtnl_route *)0;
    }

    dst = nl_addr_build(AF_INET, &n, 0);

    print_debug("Build address - dst\n");

    if (!dst) {
        print_debug("dst null");
        return (struct rtnl_route *)0;
    }

    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    rtnl_route_set_table(route, RT_TABLE_MAIN);
    rtnl_route_set_priority(route, 0);

    if (rtnl_route_set_family(route, AF_INET)) {
        print_debug("failed to set family\n");
    }

    if (rtnl_route_set_dst(route, dst)) {
        print_debug("Failed to set destination\n");
    }

    return route;

}

struct find_lb_route_data {
    struct rtnl_route *lb_route;
    char found;
};

/*
*
*/
void
__get_load_balance_route_cb(struct nl_object *obj, void * args)
{
    struct rtnl_route *route;
    struct rtnl_route *rt;
    struct find_lb_route_data *lbd;

    rt = (struct rtnl_route*)obj;
    lbd = (struct find_lb_route_data*)args;

    print_debug("Load Balance: Check route: %d\n", rtnl_route_get_priority(rt));
    if(rtnl_route_get_priority(rt) == 0){
        print_debug("Found Load Balance Route\n");
        route = (struct rtnl_route*)nl_object_clone(obj);
        lbd->lb_route = route;
        lbd->found = 1;
    }
}


/*
*
*/
int
__modify_load_balance_route(struct nl_sock *sock, struct rtnl_nexthop *nexthop, int flag)
{
    struct nl_cache *route_cache = (struct nl_cache*)0;
    struct rtnl_route *lb_route = (struct rtnl_route *)0;
    struct rtnl_route *filter = (struct rtnl_route *)0;
    struct nl_addr *dst;
    char n = '0';
    struct find_lb_route_data find_lb;

    find_lb.found = 0;
    find_lb.lb_route = (struct rtnl_route *)0;

    filter = rtnl_route_alloc();
    dst = nl_addr_build(AF_INET, &n, 0);
    rtnl_route_set_dst(filter, dst);
    rtnl_route_set_family(filter, AF_INET);
    rtnl_route_set_table(filter, RT_TABLE_MAIN);

    if(rtnl_route_alloc_cache(sock, AF_INET, 0, &route_cache)){
        print_debug("Adding cache failed\n");
        return FAILURE;
    }

    print_debug("Finding load balance route\n");
    nl_cache_foreach_filter(route_cache, (struct nl_object*)filter, __get_load_balance_route_cb, &find_lb);

    if(!find_lb.found){
        print_debug("Load balance route not found...create it\n");
        lb_route = create_load_balance_route(sock);
    } else {
        lb_route = find_lb.lb_route;
        print_debug("Load balance route found...delete it\n");
        rtnl_route_delete(sock, lb_route, 0);
    }

    if(flag == LB_ADD_NEXTHOP){
        print_debug("Adding nexthop to load balance route\n");
        rtnl_route_add_nexthop(lb_route, nexthop);
    } else if(flag == LB_DELETE_NEXTHOP) {
        print_debug("Deleting nexthop from load balance route\n");
        rtnl_route_remove_nexthop(lb_route, nexthop);
    } else {
        return FAILURE;
    }
    print_debug("Adding loadbalance route\n");
    int ret = rtnl_route_add(sock, lb_route, 0);
    if(!ret){
        print_debug("Sucess adding loadbalance route: %d\n", ret);
        return SUCCESS;
    } else {
        print_debug("Failed adding loadbalance route: %d\n", ret);
        return FAILURE;
    }
}


/*
*
*/
struct rtnl_nexthop *
__load_balance_create_nexthop(uint32_t gateway, uint32_t ifidx, uint32_t weight)
{
    struct rtnl_nexthop *nh;
    struct nl_addr *gw;

    nh = rtnl_route_nh_alloc();

    gw = nl_addr_build(AF_INET, &gateway, sizeof(uint32_t));

    if (!gw) {
        print_debug("gw null");
        return (struct rtnl_nexthop *)0;
    }

    rtnl_route_nh_set_ifindex(nh, ifidx);
    rtnl_route_nh_set_gateway(nh, gw);
    rtnl_route_nh_set_weight(nh, 0);
    return nh;
}


/*
*
*/
int
add_load_balance_route(struct nl_sock *sock, uint32_t gateway, uint32_t ifidx, uint32_t weight)
{
    struct rtnl_nexthop *nh;
    nh = __load_balance_create_nexthop(gateway, ifidx, weight);
    if(nh){
        print_debug("Created nexthop\n");
        return __modify_load_balance_route(sock, nh, LB_ADD_NEXTHOP);
    } else {
        print_error("Failed to create nexthop\n");
        return FAILURE;
    }
}


/*
*
*/
int
delete_load_balance_route(struct nl_sock *sock, uint32_t gateway, uint32_t ifidx, uint32_t weight)
{
    struct rtnl_nexthop *nh;
    nh = __load_balance_create_nexthop(gateway, ifidx, weight);
    if(nh){
        print_debug("Created nexthop\n");
        return __modify_load_balance_route(sock, nh, LB_DELETE_NEXTHOP);
    } else {
        print_error("Failed to create nexthop\n");
        return FAILURE;
    }
}


/*
*
*/
int
add_load_balance_route_from_rtnl(struct nl_sock *sock, struct rtnl_route *route)
{
    if(!route){
        print_error("Route is null\n");
        return FAILURE;
    }

    if(rtnl_route_get_nnexthops(route) == 1){
        struct rtnl_nexthop *nh = rtnl_route_nexthop_n (route, 0);
        struct nl_addr *gw = rtnl_route_nh_get_gateway(nh);
        uint32_t ifidx = rtnl_route_nh_get_ifindex(nh);
        uint32_t gateway = *(uint32_t*)nl_addr_get_binary_addr(gw);
        #ifdef POLICY_MODULE
        uint32_t weight = lookup_weight(gateway, ifidx);
        #else
        uint32_t weight = 1;
        #endif
        return add_load_balance_route(sock, gateway, ifidx, 1);
    } else {
        print_error("Route didn't have a single nexthop\n");
        return FAILURE;
    }
}


/*
*
*/
int
delete_load_balance_route_from_rtnl(struct nl_sock *sock, struct rtnl_route *route)
{
    if(!route){
        return FAILURE;
    }

    if(rtnl_route_get_nnexthops(route) == 1){
        struct rtnl_nexthop *nh = rtnl_route_nexthop_n (route,  0);
        struct nl_addr *gw = rtnl_route_nh_get_gateway(nh);
        uint32_t ifidx = rtnl_route_nh_get_ifindex(nh);
        uint32_t gateway = *(uint32_t*)nl_addr_get_binary_addr(gw);
        #ifdef POLICY_MODULE
        uint32_t weight = lookup_weight(gateway, ifidx);
        #else
        uint32_t weight = 1;
        #endif
        return delete_load_balance_route(sock, gateway, ifidx, 1);
    } else {
        print_error("Route didn't have a single nexthop\n");
        return FAILURE;
    }
}


/*
*
*/
int
delete_default_route(struct nl_sock *sock, struct virtual_interface *virt)
{
    /*Delete Default routes*/
    struct rtnl_route* filter = 0;
    struct nl_cache* cache = 0;
    struct nl_addr *dst;
    char n = '0';
    struct NexthopMatch nhm;

    rtnl_route_alloc_cache(sock, AF_INET, 0, &cache);
    filter = rtnl_route_alloc();
    dst = nl_addr_build(AF_INET, &n, 0);
    rtnl_route_set_dst(filter, dst);
    rtnl_route_set_family(filter, AF_INET);
    rtnl_route_set_table(filter, RT_TABLE_MAIN);
    nhm.sock = sock;
    nhm.virt = virt;
    nhm.flag = 0;
    nl_cache_foreach_filter(cache, (struct nl_object*)filter, delete_virtual_rt_virt_cb, &nhm);
    return 0;
}


/*
*
*/
int
delete_default_routes(struct nl_sock *sock, List* list)
{
    /*Delete Default routes*/
    struct rtnl_route* filter = 0;
    struct nl_cache* cache = 0;
    struct nl_addr *dst;
    char n = '0';
    struct NexthopMatch nhm;

    rtnl_route_alloc_cache(sock, AF_INET, 0, &cache);
    filter = rtnl_route_alloc();
    dst = nl_addr_build(AF_INET, &n, 0);
    rtnl_route_set_dst(filter, dst);
    rtnl_route_set_family(filter, AF_INET);
    rtnl_route_set_table(filter, RT_TABLE_MAIN);
    nhm.sock = sock;
    nhm.list = list;
    nhm.flag = 0;
    nl_cache_foreach_filter(cache, (struct nl_object*)filter, delete_virtual_rt_list_cb, &nhm);
    return 0;
}


/*
 *
 */
int
clean_up_interfaces(struct nl_sock* sock, List* virt_list, List* phys_list)
{
    Litem *item;

    print_debug("Cleaning up created interfaces...\n");

    delete_default_routes(sock, virt_list);

    print_debug("Cleaning up created rules\n");
    list_for_each(item, virt_list) {
        struct virtual_interface* iff = (struct virtual_interface*)item->data;

        print_debug("delete rules with address: \n");
        //print_ip(iff->address);
        flush_table(sock, iff->out->super.ifidx);
        flush_table(sock, iff->table);
        delete_rule(sock, iff->address, iff->netmask, iff->table);
        delete_rule(sock, iff->address, iff->netmask, iff->out->super.ifidx);
        delete_virtual_address(sock, iff->address, iff->attach->super.ifidx);
    }

    list_for_each(item, phys_list) {
        struct physical_interface* iff = (struct physical_interface*)item->data;

        print_debug("delete rules with address: \n");
        //print_ip(iff->address);
        flush_table(sock, iff->super.ifidx);
        flush_table(sock, iff->table);
        delete_rule(sock, iff->address, iff->netmask, iff->super.ifidx);
    }


    print_debug("Done.\n");

    return 0;
}


/*
*
*/
struct virtual_interface*
create_alias(struct nl_sock* sock,
             struct physical_interface* iff,
             struct interface* p,
             List* virt_list)
{
    Litem* item = 0;
    uint32_t alias_subnet = 0;
    uint32_t addr = 0;
    uint32_t host_id = 0;
    uint32_t ip = 0;
    struct virtual_interface* v = (struct virtual_interface*)0;

    print_debug("Found a dissemination interface\n");

    addr = find_free_subnet(sock);
    if (!addr) {
        return (struct virtual_interface*)0;
    }
    alias_subnet = addr;

    print_debug("Free Subnet: %s\n", ip_to_str(htonl(addr)));

    host_id = iff->address & (~iff->netmask);

    print_debug("Host ID: %d\n", htonl(host_id));

    ip = alias_subnet | host_id;

    print_debug("Adding address\n");

    if (!iff->virt_list) {
        iff->virt_list = malloc(sizeof(List));
        list_init(iff->virt_list);
    }

    v = add_virtual(iff->super.ifname, iff->super.ifidx, 0, virt_list);
    if (p->type == VIRTUAL_TYPE) {
        v->gateway = ((struct virtual_interface*)p)->gateway;
        v->out = ((struct virtual_interface*)p)->out;
        v->table = ((struct virtual_interface*)p)->table;
        v->external_ip = ((struct virtual_interface*)p)->external_ip;
        v->metric = ((struct virtual_interface*)p)->metric;
        print_debug("Assigning Ext IP: %s from virt\n",
                    ip_to_str(((struct virtual_interface*)p)->external_ip));
    } else {
        v->gateway = ((struct physical_interface*)p)->gateway;
        v->out = (struct physical_interface*)p;
        v->external_ip = ((struct physical_interface*)p)->external_ip;
        v->metric = ((struct physical_interface*)p)->metric;
        print_debug("Assigning Ext IP: %s from phys\n",
                    ip_to_str(((struct physical_interface*)p)->external_ip));
    }
    v->attach = iff;

    item = (Litem*)malloc(sizeof(Litem));
    if (!item) {
        errno = ENOMEM;
        return (struct virtual_interface*)0;
    }

    item = (Litem*)malloc(sizeof(Litem));
    if (!item) {
        errno = ENOMEM;
        destroy_virt_interface(v);
        return (struct virtual_interface*)0;
    }

    item->data = (void*)v;

    print_debug("add_address prelist put to %s (%d)\n", iff->super.ifname,
                list_size(iff->virt_list));
    list_put(iff->virt_list, item);
    print_debug("add_address ppostlist put to %s (%d)\n", iff->super.ifname,
                list_size(iff->virt_list));

    print_debug("calling add_address() to %s\n", iff->super.ifname);
    add_address(sock, ip, iff->super.ifidx, list_size(iff->virt_list));

    return v;
}


/*
 *
 */
int
create_aliases_for_gw(
    struct nl_sock* sock,
    List* phys_list,
    List* virt_list,
    struct interface* p)
{
    Litem *item;
    print_debug("\n");
    list_for_each(item, phys_list){
        struct physical_interface* iff =
            (struct physical_interface*)item->data;

        if ((struct interface*)iff == (struct interface*)p) {
            continue;
        }

        if (iff->diss) {
            create_alias(sock, iff, p, virt_list);
        }
    }
    return 0;
}


/*
*
*/
int create_routing_table_default_route(
  struct nl_sock* sock,
  struct interface* iff,
  uint32_t ifidx,
  uint32_t table)
{
    struct nl_addr* dst = 0;
    struct nl_addr* gw = 0;
    struct rtnl_route* route = 0;
    struct rtnl_nexthop* nexthop = 0;
    char n = '0';
    int ret = 0;

    if (!(route = rtnl_route_alloc())) {
        perror("route alloc failed");
        return FAILURE;
    }

    if (!(nexthop = rtnl_route_nh_alloc())) {
        perror("nexthop alloc failed");
        return FAILURE;
    }

    print_debug("Creating routing table for iff: %d\n", iff->ifidx);

    dst = nl_addr_build(AF_INET, &n, 0);
    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    rtnl_route_set_table(route, table);
    rtnl_route_set_family(route, AF_INET);
    rtnl_route_set_dst(route, dst);

    if (iff->type == PHYSICAL_TYPE) {
        struct physical_interface* p;
        p = (struct physical_interface*)iff;
        gw = nl_addr_build(AF_INET, &(p->gateway), 4);
    } else if (iff->type == VIRTUAL_TYPE) {
        struct virtual_interface* v;
        v = (struct virtual_interface*)iff;
        gw = nl_addr_build(AF_INET, &(v->gateway), 4);
    }
    rtnl_route_nh_set_ifindex(nexthop, ifidx);

    rtnl_route_nh_set_gateway(nexthop, gw);

    rtnl_route_add_nexthop(route, nexthop);
    ret = rtnl_route_add(sock, route, 0);
    if (ret < 0) {
        nl_perror(ret, 0);
        return FAILURE;
    }
    print_debug("created: %d (%d)\n", iff->ifidx, ret);

    return SUCCESS;
}


/*
*
*/
int create_routing_table_subnet_route(
  struct nl_sock* sock,
  struct interface* iff,
  uint32_t ifidx,
  uint32_t table)
{
    struct nl_addr* dst = 0;
    struct rtnl_route* route = 0;
    struct rtnl_nexthop* nexthop = 0;
    int ret = 0;

    print_debug("\n");

    if (!(route = rtnl_route_alloc())) {
        perror("route alloc failed");
        return FAILURE;
    }

    if (!(nexthop = rtnl_route_nh_alloc())) {
        perror("nexthop alloc failed");
        return FAILURE;
    }

    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    rtnl_route_set_family(route, AF_INET);

    if (iff->type == PHYSICAL_TYPE) {
        uint32_t ip = ((struct physical_interface*)iff)->address
            & ((struct physical_interface*)iff)->netmask;
        dst = nl_addr_build(AF_INET, &ip, sizeof(ip));
        nl_addr_set_prefixlen(dst, 24);
    } else if (iff->type == VIRTUAL_TYPE) {
        uint32_t ip = ((struct virtual_interface*)iff)->address
            & ((struct virtual_interface*)iff)->netmask;
        dst = nl_addr_build(AF_INET, &ip, sizeof(ip));
        nl_addr_set_prefixlen(dst, 24);
    }

    rtnl_route_nh_set_ifindex(nexthop, ifidx);
    rtnl_route_set_table(route, table);
    rtnl_route_set_dst(route, dst);

    rtnl_route_add_nexthop(route, nexthop);

    ret = rtnl_route_add (sock, route, 0);
    if (ret < 0) {
        print_debug("rtnl_route_add failed: %d\n", ret);
        return FAILURE;
    }

    print_debug("Route Successful\n");
    return SUCCESS;
}


/*
 *
 */
int create_routing_table(struct nl_sock* sock, struct interface* iff, List *virt_list)
{
    print_debug("Flushing old routing table: %d\n",
                iff->ifidx);
    flush_table(sock, iff->ifidx);

    if (iff->type == PHYSICAL_TYPE) {
        if(create_routing_table_default_route(sock, iff, iff->ifidx, iff->ifidx)){
            print_debug("Failed adding default route to table: %d\n", iff->ifidx);
            return FAILURE;
        }
        if(create_routing_table_subnet_route(sock, iff, iff->ifidx, iff->ifidx)){
            print_debug("Failed adding subnet route to table: %d\n", iff->ifidx);
            return FAILURE;
        }
    } else {
        if(create_routing_table_default_route(sock, iff, iff->ifidx, iff->ifidx)){
            print_debug("Failed adding default route to table: %d\n", iff->ifidx);
            return FAILURE;
        }
        if(create_routing_table_subnet_route(sock, iff, ((struct virtual_interface*)iff)->attach->super.ifidx, iff->ifidx)){
            print_debug("Failed adding subnet route to table: %d\n", iff->ifidx);
            return FAILURE;
        }
    }


    return SUCCESS;
}


/*
 *
 */
int
create_rule_for_gw(
    struct nl_sock* sock,
    struct interface* iff,
    int ifidx)
{

    uint32_t ip = 0;
    struct nl_addr* src = 0;
    struct rtnl_rule* rule = 0;


    if(iff->type == PHYSICAL_TYPE){
        print_debug("Creating a rule for a physical interface\n");
        ip = ((struct physical_interface*)iff)->address
            & ((struct physical_interface*)iff)->netmask;
    } else {
        print_debug("Creating a rule for a virtual interface\n");
        ip = ((struct virtual_interface*)iff)->address
            & ((struct virtual_interface*)iff)->netmask;
    }

    if (ip) {
        if (!(src = nl_addr_build(AF_INET, &ip, sizeof(ip)))) {
            perror(
                "create_rules_for_gw() - \
                Failed building nl address for routing rule");
            return FAILURE;
        }

        nl_addr_set_prefixlen(src, 24);

        if (!(rule = rtnl_rule_alloc())) {
            perror("create_rules_for_gw() - Failed allocating routing rule");
            return FAILURE;
        }
        rtnl_rule_set_family(rule, AF_INET);
        if (rtnl_rule_set_src(rule, src)) {
            perror(
                "create_rules_for_gw() - \
                Failed setting src address for rule");
            return FAILURE;
        }

        //rtnl_rule_set_mask(rule, 24);
        rtnl_rule_set_table(rule, ifidx);
        rtnl_rule_set_action(rule, FR_ACT_TO_TBL);

        if (rtnl_rule_add(sock, rule, 0)) {
            perror("create_rules_for_gw() - Failed to add rule");
            return FAILURE;
        }

        if(iff->type == PHYSICAL_TYPE){
            print_debug("Created Rule for physical interface %s\n",
                        ip_to_str(htonl(((struct physical_interface*)iff)->address)));
        } else {
            print_debug("Created Rule for virtual interface %s\n",
                        ip_to_str(htonl(((struct virtual_interface*)iff)->address)));
        }

        return SUCCESS;
    } else {
        print_debug("Interface doesn't have an IP\n");

        return FAILURE;
    }
}


/*
 *
 */
int
create_rules_for_gw(struct nl_sock* sock, List* list, struct interface* gw)
{
    Litem *item;
    print_debug("\n");
    list_for_each(item, list){
        struct virtual_interface* iff = (struct virtual_interface*)item->data;

        if (gw->type == PHYSICAL_TYPE) {
            if (iff->attach->diss && gw->ifidx == iff->out->super.ifidx) {
                print_debug("Phys Name: %s\n", iff->super.ifname);
                create_rule_for_gw(sock, (struct interface*)iff, gw->ifidx);
            }
        } else {
            struct virtual_interface* p = (struct virtual_interface*)gw;

            if (iff->attach->diss) {
                print_debug("Virt Name: %s\n", iff->super.ifname);
                create_rule_for_gw(sock, (struct interface*)iff, p->table);
            }
        }
    }
    return SUCCESS;
}


/*
 *
 */
int
add_default_route(
  struct nl_sock* sock,
  unsigned int ip,
  int table,
  int ifidx,
  int metric)
{
    struct nl_addr* dst = 0;
    struct nl_addr* gw = 0;
    struct rtnl_route* route = 0;
    struct rtnl_nexthop* nexthop = 0;
    char n = '0';
    int ret = 0;
    uint32_t gateway = htonl(ip);

    print_debug("Add default route - gateway: %s\n", ip_to_str(gateway));

    if (!(route = rtnl_route_alloc())) {
        perror("add_default_route() - route alloc failed");
        return FAILURE;
    }

    if (!(nexthop = rtnl_route_nh_alloc())) {
        perror("add_default_route() - nexthop alloc failed");
        return FAILURE;
    }

    print_debug("Creating routing table for iff: %d\n", table);

    dst = nl_addr_build(AF_INET, &n, 0);

    print_debug("Build address - dst\n");

    if (!dst) {
        print_debug("dst null");
        return FAILURE;
    }

    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    rtnl_route_set_table(route, table);
    rtnl_route_set_priority(route, metric);

    if (rtnl_route_set_family(route, AF_INET)) {
        print_debug("failed to set family\n");
    }

    if (rtnl_route_set_dst(route, dst)) {
        print_debug("Failed to set destination\n");
    }

    print_debug("Building gateway: %s\n", ip_to_str(gateway));
    gw = nl_addr_build(AF_INET, &gateway, 4);
    print_debug("Build address - gw\n");

    if (!gw) {
        print_debug("gw null");
        return FAILURE;
    }

    rtnl_route_nh_set_ifindex(nexthop, ifidx);
    print_debug("Ifidx set\n");
    rtnl_route_nh_set_gateway(nexthop, gw);
    print_debug("Gateway set\n");
    rtnl_route_add_nexthop(route, nexthop);
    print_debug("nexthop added\n");
    ret = rtnl_route_add(sock, route, 0);
    if (ret < 0) {
        nl_perror(ret, 0);
    }

    if (ret == NLE_EXIST) {
        return -2;
    } else if (ret < 0) {
        return -1;
    } else {
        print_debug("Create Routing Table: %d (%d)\n", table, ret);

        return 0;
    }
}


/*
 *
 */
int
add_address(struct nl_sock* sock, unsigned int ip, int ifidx, int label)
{
    print_debug("Start: %d\n", label);
    struct rtnl_addr* addr = 0;
    struct nl_addr* local = 0;
    struct nl_cache* cache = 0;
    struct rtnl_link* link = 0;
    char* ifname;
    char* alias;
    char name[16];
    int ret = 0;

    addr = rtnl_addr_alloc();

    if (!addr) {
        return 0;
    }

    local = nl_addr_build(AF_INET, &ip, 4);

    if (!local) {
        print_debug("Didn't build addr\n");
        return 0;
    }
    nl_addr2str(local, name, 16);

    rtnl_addr_set_ifindex(addr, ifidx);

    rtnl_addr_set_local(addr, local);

    if (rtnl_link_alloc_cache(sock, AF_INET, &cache) != 0) {
        perror("alloc cache");
        return FAILURE;
    }

    link = rtnl_link_get(cache, ifidx);
    ifname = rtnl_link_get_name(link);

    alias = malloc(IFNAMSIZ);

    sprintf(alias, "%s:%d", ifname, label);
    print_debug("Alias: %s\n", alias);
    if (rtnl_addr_set_label(addr, alias)) {
        perror("Failed to set label\n");
        return FAILURE;
    }

    rtnl_addr_set_prefixlen(addr, 24);

    if ((ret = rtnl_addr_add(sock, addr, 0))) {
        print_error("Failed to add address: %s\n", nl_geterror(ret));
        return FAILURE;
    }

    free(alias);

    rtnl_addr_put(addr);
    print_debug("Add Addr successful\n");
    print_debug("End\n");
    return 0;
}


/*
 *
 */
void
print_interface_list(List* l)
{
    Litem *item;
    print_debug("Print Interface List\n");
    list_for_each(item, l){
        struct interface* iff = item->data;

        if (iff) {
            print_interface(iff);
        }
        printf("\n");
    }
}


/*
 *
 */
void
print_interface(struct interface* i)
{
    if (i->type == VIRTUAL_TYPE) {
        struct virtual_interface* iff = (struct virtual_interface*)i;
        printf("Virtual Interface (%p)\n", iff);
        if (iff->attach) {
            printf("  Ingress Interface %d: %s\n",
                   iff->attach->super.ifidx,
                   iff->attach->super.ifname);
        }
        if (iff->out) {
            printf("  Egress  Interface %d: %s\n",
                   iff->out->super.ifidx,
                   iff->out->super.ifname);
        }
        printf("\tAddress: %s\n", ip_to_str(htonl(iff->address)));
        printf("\tMask: %s\n", ip_to_str(htonl(iff->netmask)));
        printf("\tGateway: %s\n", ip_to_str(htonl(iff->gateway)));
        printf("\tExternal IP: %s\n", ip_to_str(htonl(iff->external_ip)));
        printf("\tRT Table: %d\n", iff->table);
        printf("\tDepth: %d\n", iff->depth);
    } else if (i->type == PHYSICAL_TYPE) {
        struct physical_interface* iff = (struct physical_interface*)i;
        printf("Physical Interface %d: %s Pointer(%p)\n",
               iff->super.ifidx,
               iff->super.ifname,
               iff);
        printf("\tAddress: %s\n", ip_to_str(htonl(iff->address)));
        printf("\tBroadcast: %s\n", ip_to_str(htonl(iff->broadcast)));
        printf("\tGateway: %s\n", ip_to_str(htonl(iff->gateway)));
        printf("\tMask: %s\n", ip_to_str(htonl(iff->netmask)));
        printf("\tExternal IP: %s\n", ip_to_str(htonl(iff->external_ip)));
        printf("\tMAC Address: %s\n", mac_to_str(iff->mac_address));
        printf("\tMP Mode: %s\n", get_mp_mode(iff->flags));
        printf("\tDissem: %d\n", iff->diss);
        if (iff->virt_list && iff->virt_list->size > 0) {
            printf("\tVirtual Interfaces: (%d)\n", iff->virt_list->size);
            Litem *item;
            list_for_each(item, iff->virt_list){
                struct virtual_interface* virt =
                    (struct virtual_interface*)item->data;

                printf("\t  - Virt (%p)\n", virt);
                printf("\t  - Address: %s\n",
                       ip_to_str(htonl(virt->address)));
                printf("\t  - Subnet: %s\n",
                       ip_to_str(htonl(virt->netmask)));
                printf("\t  - Gateway: %s\n",
                       ip_to_str(htonl(virt->gateway)));
                printf("\t  - External: %s\n",
                       ip_to_str(virt->external_ip));
                printf("\n");
            }
        }
    }
}


/*
 *
 */
struct find_subnet
{
    uint32_t address;
    int flag;
};


/*
 *
 */
void
free_subnet_cb(struct nl_object* cb, void* arg)
{
    if (cb) {
        struct find_subnet* fs = (struct find_subnet*)arg;
        struct rtnl_addr* filter = (struct rtnl_addr*)cb;
        struct nl_addr* local = rtnl_addr_get_local(filter);
        uint32_t ip = *(uint32_t*)nl_addr_get_binary_addr(local);
        /*Drop host id*/
        ip = (ip << 8) >> 8;
        if (fs->address == ip) {
            fs->flag = 1;
        }
    }
}


/*
*
*/
uint32_t rand_interval(unsigned int min, unsigned int max)
{
    long int r;
    const unsigned int range = 1 + max - min;
    const unsigned int buckets = RAND_MAX / range;
    const unsigned int limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do {
        r = random();
    } while (r >= limit);

    return (uint32_t)(min + (r / buckets));
}


/**
*   If there are no free subnets this is screwed
*   Fine for nested gateways but will cause trouble with some topologies
*/
uint32_t
find_free_subnet(struct nl_sock* sock)
{
    int i = 0;
    uint32_t ip = 0;
    struct rtnl_addr* filter = 0;
    struct nl_cache* cache = 0;
    struct find_subnet fs;

    rtnl_addr_alloc_cache(sock, &cache);

    filter = rtnl_addr_alloc();
    srand(time(0));

    rtnl_addr_set_family(filter, AF_INET);

    while (i < 512) {
        inet_pton(AF_INET, "172.16.0.0", &ip);
        unsigned int inc = rand_interval(0, 4095);
        ip = ip | htonl(inc << 8);

        fs.address = ip;
        fs.flag = 0;

        nl_cache_foreach_filter(
            cache,
            (struct nl_object*)filter,
            free_subnet_cb, &fs);

        if (!fs.flag) {
            return ip;
        }

        i++;
    }
    return 0;
}


/*
 *
 */
struct find_rt
{
    uint32_t table;
    int flag;
};


/*
 *
 */
void
free_rt_metric_cb(struct nl_object* cb, void* arg)
{
    if (cb) {
        struct rtnl_route* filter = (struct rtnl_route*) cb;
        struct find_rt* frt = (struct find_rt*) arg;
        uint32_t prio = rtnl_route_get_priority(filter);
        print_verb("Priority: %u Desired: %u\n", prio, frt->table);
        if(PREFER_OWN_LINKS){
            if (frt->table <= prio) {
                frt->flag = 1;
            }
        } else {
            if (frt->table == prio) {
                frt->flag = 1;
            }
        }
    }
}


/*
*
*/
uint32_t
find_free_default_route_metric(
  struct nl_sock* sock,
  uint32_t metric,
  uint32_t inc)
{
    int i = 0;
    struct rtnl_route* filter = 0;
    struct nl_cache* cache = 0;
    struct nl_addr *dst;
    struct find_rt frt;
    char n = '0';

    rtnl_route_alloc_cache(sock, AF_INET, 0, &cache);
    filter = rtnl_route_alloc();
    dst = nl_addr_build(AF_INET, &n, 0);
    rtnl_route_set_dst(filter, dst);
    rtnl_route_set_family(filter, AF_INET);
    rtnl_route_set_table(filter, RT_TABLE_MAIN);

    while (i < 512) {
        frt.table = metric;
        frt.flag = 0;
        nl_cache_foreach_filter(
            cache,
            (struct nl_object*)filter,
            free_rt_metric_cb, &frt);

        if (!frt.flag) {
            return metric;
        }

        metric += inc;
        i++;
    }
    return 0;
}


/*
 *
 */
void
free_rt_cb(struct nl_object* cb, void* arg)
{
    if (cb) {
        struct find_rt* frt = (struct find_rt*)arg;
        frt->flag = 1;
    }
}


/*
 *
 */
int16_t find_free_routing_table(struct nl_sock* sock)
{
    struct rtnl_route* filter = 0;
    struct nl_cache* cache = 0;
    struct find_rt frt;

    rtnl_route_alloc_cache(sock, AF_INET, 0, &cache);

    filter = rtnl_route_alloc();

    //main routing tables start at 253
    for (frt.table = 252; frt.table >= 1; frt.table--) {
        frt.flag = 0;

        rtnl_route_set_table(filter, frt.table);

        nl_cache_foreach_filter(
            cache,
            (struct nl_object*)filter,
            free_rt_cb,
            &frt);

        if (!frt.flag) {
            return frt.table;
        }
    }
    return FAILURE;
}


/*
 *
 */
void destroy_interface(struct interface* iff)
{
    free(iff);
}


/*
 *
 */
void destroy_virt_interface(struct virtual_interface* virt)
{
    free(virt);
}


/*
 *
 */
void destroy_phys_interface(struct physical_interface* phys)
{
    free(phys);
}


/*
 *
 */
struct physical_interface* init_phys(void)
{
    struct physical_interface* p;

    if (!(p = malloc(sizeof(struct physical_interface)))) {
        errno = ENOMEM;
        return (struct physical_interface*)FAILURE;
    }
    p->super.type = PHYSICAL_TYPE;
    p->virt_list = 0;
    p->address = 0;
    p->netmask = 0;
    p->broadcast = 0;
    p->gateway = 0;
    p->external_ip = 0;
    p->super.ifidx = 0;
    memset(p->super.ifname, 0, IFNAMSIZ);
    memset(p->mac_address, 0, 6);
    p->diss = 0;
    p->metric = 0;
    p->depth = 0;
    p->request = 0;
    p->flags = 0;
    p->socket = 0;
    p->table = 0;
    p->request_received = 0;
    p->packet_received = 0;

    return p;
}


/*
 *
 */
struct virtual_interface* init_virt(void)
{
    struct virtual_interface* v;

    v = malloc(sizeof(struct virtual_interface));
    if (!v) {
        errno = ENOMEM;
        return (struct virtual_interface*)FAILURE;
    }
    v->super.type = VIRTUAL_TYPE;
    v->attach = (struct physical_interface*)0;
    v->out = (struct physical_interface*)0;
    v->external_ip = 0;
    v->address = 0;
    v->netmask = 0;
    v->gateway = 0;
    v->super.ifidx = 0;
    memset(v->super.ifname, 0, IFNAMSIZ);
    v->metric = 0;
    v->depth = 0;
    v->table = 0;
    v->type_gateway = 0;
    return v;
}

/* end file: interface.c */
