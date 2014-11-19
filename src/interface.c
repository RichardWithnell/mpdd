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

#include "interface.h"
#include "debug.h"

#define SUCCESS 0x00
#define FAILURE -0x01

#define LOOPBACK "lo"

/*
*
*/
struct physical_interface *
get_iff_network_update(uint32_t sender_ip, List *iff_list)
{
    if(!sender_ip){
        print_debug("sender IP NULL\n");
        return (struct physical_interface *)FAILURE;
    }

    list_for_each(item, iff_list){
        struct physical_interface *iff = item->data;
        printf("Sender IP: %s\n", ip_to_str(sender_ip));
        printf("Iff Address: %s\n", ip_to_str(iff->address));
        printf("Sender Mask: %s\n", ip_to_str(iff->netmask));
        if(iff->address){
            if((sender_ip & iff->netmask) == (iff->address & iff->netmask)){
                return iff;
            }
        }
    }

    return (struct physical_interface*)0;
}


/*
*
*/
uint32_t get_host_id(struct physical_interface *phy)
{
    if(phy)
        return phy->address & (~(phy->netmask));
    else{
        return 0;
    }
}


/*
*
*/
int in_list(char *name, List *diss_list){
    list_for_each(item, diss_list){
        char *data = item->data;
        if(!strcmp(data, name)){
            return 1;
        }
    }
    return 0;
}


/*
*
*/
int mark_diss_iff(char *name, List *diss_list)
{
    if(!name){
        print_debug("Name is NULL");
        return 0;
    }

    if(!diss_list){
        print_debug("Diss_list is null");
        return 0;
    }

    list_for_each(item, diss_list){
        char *data = item->data;

        if(!data){
            continue;
        }
        print_debug("Compare: %s : %s \n", data, name);
        if(!strcmp(data, name)){
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
struct interface * get_interface_by_idx(int ifidx, List *l)
{
    list_for_each(item, l){
        struct interface *iff = item->data;
        if(iff->ifidx == ifidx){
            return (struct interface*)iff;
        }
    }
    return (struct interface*)0;
}


/*
*
*/
struct virtual_interface *
add_virtual(char* name, uint32_t idx, uint32_t flags, List *iff_list)
{
    Litem *item = 0;
    struct virtual_interface *virt = 0;

    /*Create the interface*/
    virt = init_virt();
    if(!virt){
        errno = ENOMEM;
        return (struct virtual_interface *)0;
    }

    /*Create the list item*/
    item = (Litem*)malloc(sizeof(Litem));
    if(!item){
        errno = ENOMEM;
        return (struct virtual_interface *)0;
    }

    /*Copy the properties across*/
    strcpy(virt->super.ifname, name);
    virt->super.ifidx = idx;
    virt->flags = flags;

    item = (Litem*)malloc(sizeof(Litem));
    if(!item){
        errno = ENOMEM;
        destroy_virt_interface(virt);
        return (struct virtual_interface *)0;
    }
    item->data = (void*)virt;
    list_put(iff_list, item);
    return virt;
}


/*
*
*/
struct physical_interface *
add_physical(char* name, uint32_t idx, uint32_t flags, int diss, List *iff_list)
{
    Litem *item = 0;
    struct physical_interface *phys = 0;

    print_debug("\n");
    /*Create the interface*/
    phys = init_phys();
    if(!phys){
        errno = ENOMEM;
        return (struct physical_interface *)0;
    }

    /*Create the list item*/
    item = (Litem*)malloc(sizeof(Litem));
    if(!item){
        errno = ENOMEM;
        return (struct physical_interface *)0;
    }

    /*Copy the properties across*/
    strcpy(phys->super.ifname, name);
    phys->super.ifidx = idx;
    phys->flags = flags;
    phys->diss = diss;

    item = (Litem*)malloc(sizeof(Litem));
    if(!item){
        errno = ENOMEM;
        destroy_phys_interface(phys);
        return (struct physical_interface *)0;
    }
    item->data = (void*)phys;
    list_put(iff_list, item);
    return phys;
}


/*
*
*/
struct interface *
add_link(
    struct rtnl_link *link,
    List *iff_list,
    List *ignore_list,
    List *diss_list,
    int type)
{
    int ifidx = -1;
    char *ifname = 0;
    int flags = 0;

    ifname = rtnl_link_get_name(link);

    print_debug("ifname: %s\n", ifname);

    /*We don't care about the loopback interface*/
    if(!strcmp(LOOPBACK, ifname)){
        print_debug("Found Loop Back\n");
        return (struct interface *)0;
    } else {
        if(ignore_list){
            if(in_list(ifname, ignore_list)) {
                print_debug("Interface in ignore list.\n");
                return (struct interface *)0;
            }
        }
    }

    /*Check if we already have this interface*/
    ifidx = rtnl_link_get_ifindex(link);
    flags = rtnl_link_get_flags (link);

    if(type == PHYSICAL_TYPE){
        int diss = 0;
        struct physical_interface *phys =
            (struct physical_interface *)get_interface_by_idx(ifidx, iff_list);
        print_debug("Creating physical interface\n");
        if(phys){
            /*Interface already exists*/
            phys->flags = flags;
            return (struct interface *)phys;
        } else {
            /*New Interface*/
            phys = 0;
        }
        if(diss_list){
            diss = mark_diss_iff(ifname, diss_list);
        }
        return (struct interface*)add_physical(ifname, ifidx, flags, diss, iff_list);
    } else if (type == VIRTUAL_TYPE){
        struct virtual_interface *virt =
            (struct virtual_interface *)get_interface_by_idx(ifidx, iff_list);
        print_debug("Creating virtual interface\n");
        if(virt){
            /*Interface already exists*/
            virt->flags = flags;
            return (struct interface *)virt;
        } else {
            /*New Interface*/
            virt = 0;
        }
        return  (struct interface*)add_virtual(ifname, ifidx, flags, iff_list);
    } else {
        print_debug("bad type\n");
        return (struct interface *)0;
    }
}


/*
*
*/
int
delete_link(struct rtnl_link *link, List *iff, List *virt, List *ignore_list)
{
    return SUCCESS;
}


/*
*
*/
struct interface*
add_addr (
  struct nl_sock *sock,
  struct rtnl_addr *addr,
  List *iff, List *virt,
  List * ignore_list,
  List * diss_list )
{
    char *label = 0;
    uint32_t *broadcast = 0;
    uint32_t prefix = 0;
    int ifidx = -1;
    struct physical_interface * temp_phys;
    struct virtual_interface * temp_virt;

    struct nl_addr *local = 0;

    if(!addr){
        print_debug("Addr param == null\n");
        return (struct interface*)0;
    }

    local = rtnl_addr_get_local(addr);

    if(nl_addr_iszero(local)){
        print_debug("Address invalid\n");
        return (struct interface*)0;
    }

    /*get the index*/
    ifidx = rtnl_addr_get_ifindex(addr);
    print_debug("Address Index: %d\n",  ifidx);

    if(local){
        list_for_each(pitem, iff){
            temp_phys = (struct physical_interface*)pitem->data;
            print_debug("\tComparing %s and ",
                ip_to_str(temp_phys->address));
            print_debug("%s\n",
                ip_to_str(*(uint32_t*)
                    nl_addr_get_binary_addr((struct nl_addr *)local)));

            if(temp_phys->address ==
                *(uint32_t*)nl_addr_get_binary_addr((struct nl_addr *)local)
            ) {
                print_debug("Address already exists\n");
                return (struct interface*)0;
            }
        }
        list_for_each(vitem, virt){
            temp_virt = (struct virtual_interface*)vitem->data;

            print_debug("\tComparing %s and ", ip_to_str(temp_virt->address));
            print_debug("%s\n",
                    ip_to_str(*
                        (uint32_t*)nl_addr_get_binary_addr(
                            (struct nl_addr *)local)));

            if(temp_virt->address ==
                *(uint32_t*)nl_addr_get_binary_addr((struct nl_addr *)local)
            ) {
                print_debug("Address already exists\n");
                return (struct interface*)0;
            }
        }
    }

    /*Get address attributes*/
    prefix = (uint32_t)rtnl_addr_get_prefixlen(addr);
    broadcast = (uint32_t*)rtnl_addr_get_broadcast(addr);
    label = rtnl_addr_get_label (addr);

    if (strstr(label, ":") != NULL) {
        struct physical_interface *p = (struct physical_interface*)0;
        struct virtual_interface *v = (struct virtual_interface*)0;
        print_debug(" Handling add alias address\n");
        //Add to the virtual list

        /*We should have setup the interface already*/
        //v = (struct virtual_interface*) get_interface_by_address(ifidx, virt);
        p = (struct physical_interface*) get_interface_by_idx(ifidx, iff);

        if(!p) {
            print_debug("Physical Interface doesn't exist\n");
            struct rtnl_link *link = rtnl_addr_get_link(addr);
            if(!link){
                print_debug("No link for addr\n");
                return (struct interface*)0;
            }
            p = (struct physical_interface*)add_link(link,
            iff, ignore_list, diss_list, PHYSICAL_TYPE);

            if(!p){
                print_debug("Failed to add link\n");
                return (struct interface*)0;
            }

        } else {
            print_debug("Found physical interface\n");
        }

        if(p->virt_list){
            print_debug("Virtual List: %d\n", list_size(p->virt_list));
            list_for_each(item, p->virt_list){
                struct virtual_interface *iff = item->data;
                if(!iff->address){
                    v = (struct virtual_interface*)iff;
                }
            }
        } else {
            print_debug("The physical interface, virtual address list is not instantiated\n");
        }

        /*Interface not created*/

        if(!v){
            print_debug("Didn't find virtual interface\n");
            struct rtnl_link *link = rtnl_addr_get_link(addr);

            if(!link){
                print_debug("Bad link\n");
                return (struct interface*)0;
            }

            v = (struct virtual_interface*)add_virtual(p->super.ifname,
                                            ifidx, p->flags, virt);
            if(!v){
                print_debug("Failed to create virtual interface\n");
                return (struct interface*)0;
            }
        } else {
                print_debug(" Found virtual interface\n");
        };

        print_debug("Setting interface that the virtual IP address is attached to\n");

        if(local){
            v->address =
                *(uint32_t*)nl_addr_get_binary_addr((struct nl_addr *)local);
        }

        if(prefix){
            v->netmask = ntohl((0xffffffff >> (32 - prefix)) << (32 - prefix));
        }

        if(p->diss){
            print_debug("Added address to virtual list, find gateway\n");
            create_rule_for_gw(sock, v, v->out->super.ifidx);
        }

        return (struct interface*)v;

    } else {
        /*Add to the physical list*/
        struct physical_interface *p = (struct physical_interface*)0;

        print_debug("Add physical interface\n");

        /*We should have setup the interface already*/
        p = (struct physical_interface*)get_interface_by_idx(ifidx, iff);

        /*Interface not created*/
        if(!p){
            struct rtnl_link *link = rtnl_addr_get_link(addr);
            if(!link){
                print_debug("Failed to get link %d (%s)\n",
                rtnl_addr_get_ifindex (addr),
                rtnl_addr_get_label(addr));

                return (struct interface*)0;
            }
            p = (struct physical_interface*)add_link(
            link, iff, ignore_list, diss_list, PHYSICAL_TYPE);
            if(!p){
                print_debug("Failed to add link\n");
                return (struct interface*)0;
            }
        }

        if(local){
            p->address = *(uint32_t*)nl_addr_get_binary_addr(
            (struct nl_addr *)local);
        }
        if(broadcast){
            p->broadcast = *(uint32_t*)nl_addr_get_binary_addr(
            (struct nl_addr *)broadcast);
        }
        if(prefix){
            p->netmask = ntohl((0xffffffff >> (32 - prefix)) << (32 - prefix));
        }
        return (struct interface*)p;
    }
}


/*
*
*/
int
delete_addr(struct rtnl_addr *addr, List *iff, List *virt)
{
    return SUCCESS;
}


/*
*
*/
struct physical_interface*
add_route(struct nl_sock *sock,
          struct rtnl_route *route,
          List *iff_list,
          List *virt_list)
{
    struct nl_addr *gw = 0;
    uint32_t binary_gw = 0;
    struct rtnl_nexthop *nexthop;
    int ifidx = 0;
    struct physical_interface *p = (struct physical_interface*)0;

    if(route){
        nexthop = rtnl_route_nexthop_n (route, 0);
    } else {
        print_debug("route is NULL\n");
        return (struct physical_interface*)0;
    }

    if(nexthop){
        gw = rtnl_route_nh_get_gateway(nexthop);
    } else {
        print_debug("nexthop is NULL\n");
        return (struct physical_interface*)0;
    }

    if(gw){
        binary_gw = *(uint32_t*)nl_addr_get_binary_addr(gw);
    } else {
        print_debug("gw is NULL\n");
        return (struct physical_interface*)0;
    }

    /*Add the default gateway to the list*/

    ifidx = rtnl_route_nh_get_ifindex (nexthop);
    p = (struct physical_interface*)get_interface_by_idx(ifidx, iff_list);
    p->gateway = binary_gw;

    /*create virtual interfaces*/
    print_debug("create aliases for gw\n");
    create_aliases_for_gw(sock, iff_list, virt_list, (struct interface*)p);
    /*create ip rules to tunnel traffic*/
    print_debug("create rules for gw\n");
    create_rules_for_gw(sock, virt_list, (struct interface*)p);
    /*create routing table*/
    print_debug("create routing table\n");
    create_routing_table(sock, (struct interface*)p);
    print_debug("get_external_ip\n");
    p->external_ip = get_ext_ip(p->address);
    print_debug(" Done\n");
    return p;
}


/*
*
*/
int delete_route_from_physical(List *l, uint32_t route)
{
    list_for_each(item, l){
        struct physical_interface *iff = (struct physical_interface*)item->data;
        if(iff->gateway == route){
            iff->gateway = 0;
        }
    }
    return 0;
}


/*
*
*/
void delete_rule_cb(struct nl_object *cb, void *arg)
{
    print_debug("Delete rule callback\n");
    struct nl_sock *sock;
    struct rtnl_rule *rule;
    int ret = 0;

    sock = (struct nl_sock *)arg;
    rule = (struct rtnl_rule *)cb;
    ret = rtnl_rule_delete(sock, rule, 0);

    if(ret){
        print_debug("Error deleting rule: %d\n", ret);
    }
}


/*
*
*/
int
delete_rule(struct nl_sock *sock, uint32_t ip, uint32_t mask)
{
    struct rtnl_rule *filter = 0;
    struct nl_cache *rule_cache = 0;
    filter = rtnl_rule_alloc ();
    rtnl_rule_alloc_cache(sock, AF_INET, &rule_cache);
    int sip = ip & mask;
    print_debug("RULE IPS\n");
    //print_ip(ip);
    //print_ip(mask);
    struct nl_addr *src = nl_addr_build(AF_INET, &sip, 4);
    char buff[64];
    nl_addr2str(src, buff, 64);
    print_debug("Rule Src: %s\n", buff);
    rtnl_rule_set_src(filter, src);
    print_debug("Lookup CIDR: %d\n", lookup_cidr(htonl(mask)));
    //rtnl_rule_set_mask(filter, lookup_cidr(htonl(mask)));
    nl_cache_foreach_filter(
        rule_cache, (struct nl_object*) filter, delete_rule_cb, sock);
    return 0;
}


/*
*
*/
int
delete_rules_by_gw(struct nl_sock *sock, List *list, uint32_t gw)
{
    list_for_each(item, list){
        struct virtual_interface *iff = item->data;

        if(iff->gateway == gw){
            print_debug("delete rules with address: ");
            //print_ip(iff->address);
            delete_rule(sock, iff->address, iff->netmask);
        }
    }

    return 0;
}


/*
*
*/
int delete_virtual_by_gw(List *list, uint32_t gw)
{
    int i = 0;

    print_debug("\n");
    print_debug("List Size: %d\n", list_size(list));

    for(i = list_size(list) ; i--; ) {
        print_debug("IDX: %d\n", i);
        struct virtual_interface *iff = (list_get(list, i))->data;

        print_debug("Virtual Gateway: %s\n",ip_to_str(iff->gateway));
        print_debug("Actual Gateway: %s\n",ip_to_str(gw));
        if(iff->gateway == gw){
            list_remove(list, i);
        }
    }
    return 0;
}


/*
*
*/
void flush_table_cb(struct nl_object *cb, void *arg)
{
    struct nl_sock *sock;
    struct rtnl_route *route;

    sock = (struct nl_sock *)arg;
    route = (struct rtnl_route *)cb;

    print_debug("Deleting route\n");
    if(rtnl_route_delete(sock, route, 0)){
        print_debug("Delte route failed\n");
    }

}


/*
*
*/
int flush_table(struct nl_sock *sock, int table)
{
    struct nl_cache *route_cache = 0;
    struct rtnl_route *filter = 0;

    print_debug("Flush table (%d)\n", table);

    if(table < 0) {
        printf("Bad table number\nn");
        return -1;
    }

    if((rtnl_route_alloc_cache(sock, AF_UNSPEC, 0, &route_cache)) < 0){
        print_debug("Alloc cache failed\n");
        return -1;
    }

    if (nl_cache_is_empty(route_cache)){
        /*Cleanup*/
        print_debug("Route cache is empty\n");
        return -1;
    }

    filter = rtnl_route_alloc();
    rtnl_route_set_table(filter, table);

    nl_cache_foreach_filter(
    route_cache, (struct nl_object*) filter, flush_table_cb, sock);

    rtnl_route_put(filter);
    nl_cache_free(route_cache);

    return 0;
}


/*
*
*/
int
delete_route(
    struct nl_sock *sock,
    struct rtnl_route *route,
    List *iff_list,
    List *virt_list)
{
    int ifidx = 0;
    struct rtnl_nexthop *nexthop = 0;
    struct nl_addr *gw = 0;
    uint32_t binary_gw = 0;

    nexthop = rtnl_route_nexthop_n (route, 0);
    ifidx = rtnl_route_nh_get_ifindex (nexthop);
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
delete_virtual_address(struct nl_sock *sock, unsigned int ip, int ifidx)
{
    struct rtnl_addr *addr = rtnl_addr_alloc();
    struct nl_addr *local = nl_addr_build(AF_INET, &ip, 4);

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


/*
*
*/
int
clean_up_interfaces(struct nl_sock *sock, List *list)
{
    print_debug("Cleaning up created rules\n");
    list_for_each(item, list){
        struct virtual_interface *iff = item->data;
        print_debug("delete rules with address: \n");
        //print_ip(iff->address);
        flush_table(sock, iff->out->super.ifidx);
        flush_table(sock, iff->table);
        delete_rule(sock, iff->address, iff->netmask);
        delete_virtual_address(sock, iff->address, iff->attach->super.ifidx);
    }
    return 0;
}


/*
*
*/
int
create_aliases_for_gw(
    struct nl_sock *sock,
    List *phys_list,
    List *virt_list,
    struct interface *p)
{
    print_debug("\n");
    list_for_each(item, phys_list){
        struct physical_interface *iff =
        (struct physical_interface*)item->data;

        if((struct interface*)iff == (struct interface*)p){
            continue;
        }

        if(iff->diss){
            Litem *item = 0;
            uint32_t alias_subnet = 0;
            uint32_t addr = 0;
            uint32_t host_id = 0;
            uint32_t ip = 0;
            struct virtual_interface * v = (struct virtual_interface*)0;

            print_debug("Found a dissemination interface\n");

            addr = find_free_subnet(sock);
            if(!addr){
                continue;
            }
            alias_subnet = addr;
            host_id = iff->address & (~iff->netmask);

            print_debug("Host ID: %d\n", host_id);

            ip = alias_subnet | host_id;

            print_debug("Adding address\n");

            if(!iff->virt_list){
                iff->virt_list = malloc(sizeof(List));
                list_init(iff->virt_list);
            }

            v = add_virtual(iff->super.ifname, iff->super.ifidx, 0, virt_list);
            if(p->type == VIRTUAL_TYPE){
                v->gateway = ((struct virtual_interface*)p)->gateway;

                v->out = ((struct virtual_interface*)p)->out;
            } else {
                v->gateway = ((struct physical_interface*)p)->gateway;
                v->out = (struct physical_interface*)p;
            }
            v->attach = iff;

            item = (Litem*)malloc(sizeof(Litem));
            if(!item){
                errno = ENOMEM;
                return FAILURE;
            }

            item = (Litem*)malloc(sizeof(Litem));
            if(!item){
                errno = ENOMEM;
                destroy_virt_interface(v);
                return FAILURE;
            }
            item->data = (void*)v;
            list_put(iff->virt_list, item);

            add_address(sock, ip, iff->super.ifidx, list_size(iff->virt_list));
        }
    }
    return 0;
}


/*
*
*/
int create_routing_table(struct nl_sock *sock, struct interface *iff)
{
    struct nl_addr *dst = 0;
    struct nl_addr *gw = 0;
    struct rtnl_route *route = 0;
    struct rtnl_nexthop *nexthop = 0;
    char n = '0';
    int ret = 0;

    print_debug("Flushing old routing table: %d\n",
        iff->ifidx);
    flush_table(sock, iff->ifidx);

    if(!(route = rtnl_route_alloc())){
        perror("create_routing_table() - route alloc failed");
        return FAILURE;
    }

    if(!(nexthop = rtnl_route_nh_alloc())){
        perror("create_routing_table() - nexthop alloc failed");
        return FAILURE;
    }

    print_debug("Creating routing table for iff: %d\n", iff->ifidx);

    dst = nl_addr_build(AF_INET, &n, 0);
    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    rtnl_route_set_table(route, iff->ifidx);
    rtnl_route_set_family (route, AF_INET);
    rtnl_route_set_dst(route, dst);

    if(iff->type == PHYSICAL_TYPE) {
        struct physical_interface *p;
        p = (struct physical_interface*) iff;
        //print_ip(p->gateway);
        gw = nl_addr_build(AF_INET, &(p->gateway), 4);
        rtnl_route_nh_set_ifindex(nexthop, iff->ifidx);
    } else if (iff->type == VIRTUAL_TYPE){
        struct virtual_interface *v;
        v = (struct virtual_interface*) iff;
        //print_ip(v->gateway);
        gw = nl_addr_build(AF_INET, &(v->gateway), 4);
        rtnl_route_nh_set_ifindex(nexthop, iff->ifidx);
    }

    rtnl_route_nh_set_gateway(nexthop, gw);

    rtnl_route_add_nexthop(route, nexthop);
    ret = rtnl_route_add(sock, route, 0);
    if(ret < 0){
        nl_perror(ret, 0);
    }
    print_debug("created: %d (%d)\n", iff->ifidx, ret);

    return 0;
}


/*
*
*/
int
create_rule_for_gw(
    struct nl_sock *sock,
    struct virtual_interface *iff,
    int ifidx)
{
    print_debug("Creating a rule for a virtual interface\n");

    uint32_t ip = 0;
    struct nl_addr *src = 0;
    struct rtnl_rule *rule = 0;

    ip = iff->address & iff->netmask;

    if(ip){
        if(!(src = nl_addr_build(AF_INET, &ip, 4))){
            perror("create_rules_for_gw() - \
                Failed building nl address for routing rule");
            return FAILURE;
        }
        if(!(rule = rtnl_rule_alloc())){
            perror("create_rules_for_gw() - Failed allocating routing rule");
            return FAILURE;
        }
        rtnl_rule_set_family (rule, AF_INET);
        if(rtnl_rule_set_src(rule, src)){
            perror("create_rules_for_gw() - \
                Failed setting src address for rule");
            return FAILURE;
        }
        rtnl_rule_set_mask(rule, 24);

        rtnl_rule_set_table (rule, ifidx);

        if(rtnl_rule_add(sock, rule, 0)){
            perror("create_rules_for_gw() - Failed to add rule");
            return FAILURE;
        }
        print_debug("Created Rule for virtual interface %s\n",
             ip_to_str(iff->address));
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
create_rules_for_gw(struct nl_sock *sock, List *list, struct interface *gw)
{
    print_debug("\n");
    list_for_each(item, list){
        struct virtual_interface *iff = (struct virtual_interface*)item->data;

        if(gw->type == PHYSICAL_TYPE){
            if(iff->attach->diss && gw->ifidx == iff->out->super.ifidx){
                print_debug("Name: %s\n", iff->super.ifname);
                create_rule_for_gw(sock, iff, gw->ifidx);
            }
        } else {
            struct virtual_interface *p = (struct virtual_interface*)gw;

            if(iff->attach->diss){
                print_debug("Name: %s\n", iff->super.ifname);
                create_rule_for_gw(sock, iff, p->table);
            }
        }
    }
    return SUCCESS;
}


/*
*
*/
int
add_default_route(struct nl_sock *sock, unsigned int ip, int table, int ifidx)
{
    struct nl_addr *dst = 0;
    struct nl_addr *gw = 0;
    struct rtnl_route *route = 0;
    struct rtnl_nexthop *nexthop = 0;
    char n = '0';
    int ret = 0;
    uint32_t gateway = htonl(ip);

    print_debug("\n");

    if(!(route = rtnl_route_alloc())){
        perror("add_default_route() - route alloc failed");
        return FAILURE;
    }

    if(!(nexthop = rtnl_route_nh_alloc())){
        perror("add_default_route() - nexthop alloc failed");
        return FAILURE;
    }

    print_debug("Creating routing table for iff: %d\n", table);


    dst = nl_addr_build(AF_INET, &n, 0);

    print_debug("Build address - dst\n");

    if(!dst){
        print_debug("dst null");
        return FAILURE;
    }

    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    rtnl_route_set_table(route, table);

    if(rtnl_route_set_family (route, AF_INET)){
        print_debug("failed to set family\n");
    }

    if(rtnl_route_set_dst(route, dst)){
        print_debug("Failed to set destination\n");
    }

    print_debug("Building gateway: %s\n", ip_to_str(gateway));
    gw = nl_addr_build(AF_INET, &gateway, 4);
    print_debug("Build address - gw\n");

    if(!gw){
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
    if(ret < 0){
        nl_perror(ret, 0);
    }

    print_debug("Create Routing Table: %d (%d)\n", table, ret);

    return 0;
}


/*
*
*/
int
add_address(struct nl_sock *sock, unsigned int ip, int ifidx, int label)
{
    struct rtnl_addr *addr = 0;
    struct nl_addr *local = 0;
    struct nl_cache *cache = 0;
    struct rtnl_link *link = 0;
    char* ifname;
    char* alias;
    char name[16];
    int ret = 0;
    addr = rtnl_addr_alloc();

    if (!addr){
        return 0;
    }

    local = nl_addr_build(AF_INET, &ip, 4);

    if(!local){
        print_debug("Didn't build addr");
        return 0;
    }
    nl_addr2str (local, name, 16);

    rtnl_addr_set_ifindex(addr, ifidx);

    rtnl_addr_set_local(addr, local);

    if(rtnl_link_alloc_cache(sock, AF_INET, &cache) != 0){
        perror("alloc cache");
        return FAILURE;
    }

    link = rtnl_link_get(cache, ifidx);
    ifname = rtnl_link_get_name(link);

    alias = malloc(IFNAMSIZ);

    sprintf(alias, "%s:%d", ifname, label);
    print_debug("Alias: %s\n", alias);
    if(rtnl_addr_set_label(addr, alias)){
        perror("Failed to set label\n");
        return FAILURE;
    }

    rtnl_addr_set_prefixlen(addr, 24);

    if((ret = rtnl_addr_add(sock, addr, 0))){
        nl_perror(ret, 0);
        perror("Failed to add address");
        return FAILURE;
    }

    free(alias);

    rtnl_addr_put(addr);
    print_debug("Add Addr successful\n");
    return 0;
}


/*
*
*/
void
print_interface_list(List *l)
{
    print_debug("Print Interface List\n");
    list_for_each(item, l){
        struct interface *iff = item->data;
        if(iff){
            print_interface(iff);
        }
        printf("\n");
    }
}


/*
*
*/
void
print_interface(struct interface *i)
{
    if(i->type == VIRTUAL_TYPE){
        struct virtual_interface * iff = (struct virtual_interface*)i;
        printf("Virtual Interface (%p)\n", iff);
        if(iff->attach){
            printf("  Ingress Interface %d: %s\n",
            iff->attach->super.ifidx,
            iff->attach->super.ifname);
        }
        if(iff->out){
            printf("  Egress  Interface %d: %s\n",
            iff->out->super.ifidx,
            iff->out->super.ifname);
        }
        printf("\tAddress: %s\n", ip_to_str(htonl(iff->address)));
        printf("\tMask: %s\n", ip_to_str(htonl(iff->netmask)));
        printf("\tGateway: %s\n", ip_to_str(htonl(iff->gateway)));
        printf("\tExternal IP: %s\n", ip_to_str(htonl(iff->external_ip)));
    } else if(i->type == PHYSICAL_TYPE) {
        struct physical_interface * iff = (struct physical_interface*)i;
        printf("Physical Interface %d: %s Pointer(%p)\n",
            iff->super.ifidx,
            iff->super.ifname,
            iff);
        printf("\tAddress: %s\n", ip_to_str(htonl(iff->address)));
        printf("\tBroadcast: %s\n", ip_to_str(htonl(iff->broadcast)));
        printf("\tGateway: %s\n", ip_to_str(htonl(iff->gateway)));
        printf("\tMask: %s\n", ip_to_str(htonl(iff->netmask)));
        printf("\tExternal IP: %s\n", ip_to_str(htonl(iff->external_ip)));
        printf("\tMP Mode: %s\n", get_mp_mode(iff->flags));
        printf("\tDissem: %d\n", iff->diss);
        if(iff->virt_list && iff->virt_list->size > 0){
            printf("\tVirtual Interfaces: (%d)\n", iff->virt_list->size);
            list_for_each(item, iff->virt_list){
                struct virtual_interface *virt =
                    (struct virtual_interface *) item->data;
                printf("\t  - Virt (%p)\n", virt);
                printf("\t  - Address: %s\n",
                    ip_to_str(htonl(virt->address)));
                printf("\t  - Subnet: %s\n",
                    ip_to_str(htonl(virt->netmask)));
                printf("\t  - Gateway: %s\n",
                    ip_to_str(htonl(virt->gateway)));
                printf("\t  - External: %s\n",
                    ip_to_str(htonl(virt->external_ip)));
                printf("\n");
            }
        }
    }
}


/*
*
*/
struct find_subnet {
    uint32_t address;
    int flag;
};


/*
*
*/
void
free_subnet_cb(struct nl_object *cb, void *arg)
{
    if(cb) {
        struct find_subnet *fs = (struct find_subnet*)arg;
        struct rtnl_addr *filter = (struct rtnl_addr *)cb;
        struct nl_addr *local = rtnl_addr_get_local(filter);
        uint32_t ip = *(uint32_t*)nl_addr_get_binary_addr(local);
        /*Drop host id*/
        ip = (ip << 8) >> 8;
        if(fs->address == ip) fs->flag = 1;
    }
}

/*
If there are no free subnets this is screwed
TODO Make this random as opposed to iterative.
Fine for nested gateways but will cause trouble with some topologies
*/
uint32_t
find_free_subnet(struct nl_sock *sock)
{
    int i = 0;
    uint32_t ip = 0;
    uint32_t inc = 1;
    struct rtnl_addr *filter = 0;
    struct nl_cache *cache = 0;
    struct find_subnet fs;

    rtnl_addr_alloc_cache(sock, &cache);

    filter = rtnl_addr_alloc();

    i = rand() % 255;
    rtnl_addr_set_family(filter, AF_INET);

    inet_pton(AF_INET, "192.168.11.0", &ip);

    inc = ((uint32_t)inc)<<16;

    while(i < 254){
        fs.address = ip;
        fs.flag = 0;

        nl_cache_foreach_filter(
            cache,
            (struct nl_object *)filter,
            free_subnet_cb, &fs);

        if(!fs.flag){
            return ip;
        }
        ip += inc;
        i++;
    }
    return 0;
}


/*
*
*/
struct find_rt {
    uint32_t table;
    int flag;
};


/*
*
*/
void
free_rt_cb(struct nl_object *cb, void *arg)
{
    if(cb) {
        struct find_rt *frt = (struct find_rt*)arg;
        frt->flag = 1;
    }
}


/*
*
*/
int16_t find_free_routing_table(struct nl_sock *sock)
{
    struct rtnl_route *filter = 0;
    struct nl_cache *cache = 0;
    struct find_rt frt;

    rtnl_route_alloc_cache(sock, AF_INET, 0, &cache);

    filter = rtnl_route_alloc();

    //main routing tables start at 253
    for(frt.table = 252; frt.table >= 1; frt.table--) {
        frt.flag = 0;

        rtnl_route_set_table(filter, frt.table);

        nl_cache_foreach_filter(
            cache,
            (struct nl_object *)filter,
            free_rt_cb,
            &frt);

        if(!frt.flag){
            return frt.table;
        }
    }
    return FAILURE;
}


/*
*
*/
void destroy_interface(struct interface *iff)
{
    free(iff);
}


/*
*
*/
void destroy_virt_interface(struct virtual_interface *virt)
{
    free(virt);
}


/*
*
*/
void destroy_phys_interface(struct physical_interface *phys)
{
    free(phys);
}


/*
*
*/
struct physical_interface *init_phys(void)
{
    struct physical_interface *p;
    if(!(p = malloc(sizeof(struct physical_interface)))) {
        errno = ENOMEM;
        return (struct physical_interface *)FAILURE;
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
    p->diss = 0;
    p->metric = 0;
    p->depth = 0;
    p->request = 0;
    p->flags = 0;
    p->socket = 0;
    p->table = 0;

    return p;
}


/*
*
*/
struct virtual_interface *init_virt(void)
{
    struct virtual_interface *v;

    v = malloc(sizeof(struct virtual_interface));
    if(!v){
        errno = ENOMEM;
        return (struct virtual_interface *)FAILURE;
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
