/*
 *  mul_nbapi_path.c: Mul Northbound Path Application for Mul Controller
 *  Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "mul_common.h"
#include "mul_nbapi_common.h"
#include "mul_nbapi_fabric.h"
#include "mul_nbapi_endian.h"

int add_del_fabric_port_tnid(uint64_t datapath_id,
                    char *str_tenant_id,
                    char *str_network_id,
                    char *in_port,
		    bool add)
{

    uuid_t tenant_id;
    uuid_t network_id;
    int ret = 0;
    uint32_t port;

    ret = uuid_parse(str_tenant_id, tenant_id);
    if (ret != 0){
        return -2;
    }
    ret = uuid_parse(str_network_id, network_id);
    if (ret != 0){
        return -3;
    }

   port = atoi(in_port);

    if(mul_fabric_port_tnid_mod(nbapi_app_data->fab_service, datapath_id, port, tenant_id, network_id, add)){
	return -5;
    }
    return 1;
}


static void
nbapi_fabric_port_tnid_dump(void *arg, void *buf){

    nbapi_fabric_port_tnid_list_t *list = (nbapi_fabric_port_tnid_list_t *)arg;
    c_ofp_port_tnid_mod_t *cofp_host = (c_ofp_port_tnid_mod_t *)buf;

    c_ofp_port_tnid_mod_t *cofp_arg;
    cofp_arg = calloc(1, sizeof(*cofp_host));
    memcpy(cofp_arg, cofp_host, sizeof(c_ofp_port_tnid_mod_t));
    cofp_arg->datapath_id = ntohll(cofp_arg->datapath_id);
    cofp_arg->port = ntohl(cofp_arg->port); 
    list->array = g_slist_prepend(list->array, cofp_arg);
}


static void
nbapi_fabric_host_dump(void *arg, void *buf){

    nbapi_fabric_host_list_t *list = (nbapi_fabric_host_list_t *)arg;
    c_ofp_host_mod_t *cofp_host = (c_ofp_host_mod_t *)buf;

    c_ofp_host_mod_t *cofp_arg;
    cofp_arg = calloc(1, sizeof(*cofp_host));
    memcpy(cofp_arg, cofp_host, sizeof(*cofp_host));
    ntoh_c_ofp_fabric_host(cofp_arg);
    cofp_arg->host_flow.in_port = ntohs(htonl(cofp_arg->host_flow.in_port));
    list->array = g_slist_prepend(list->array, cofp_arg);
}
static void 
nbapi_fabric_tenant_nw_dump(void *arg, void *buf){
    nbapi_fabric_tenant_nw_list_t *list = (nbapi_fabric_tenant_nw_list_t *)arg;
    c_ofp_tenant_nw_mod_t *cofp_tn = (c_ofp_tenant_nw_mod_t *)buf;

    c_ofp_port_tnid_mod_t *cofp_arg;
    cofp_arg = calloc(1, sizeof(*cofp_tn));
    memcpy(cofp_arg, cofp_tn, sizeof(c_ofp_tenant_nw_mod_t));
    list->array = g_slist_prepend(list->array, cofp_arg);
}
nbapi_fabric_tenant_nw_list_t get_fabric_tenant_net_all(void){
    nbapi_fabric_tenant_nw_list_t list;
    int n_tenant = 0;

    list.array = NULL;
    list.length = 0;

    c_rd_lock(&nbapi_app_data->lock);
    if(!nbapi_app_data->fab_service){
        c_rd_unlock(&nbapi_app_data->lock);
        return list;
    }
    n_tenant = mul_fabric_show_tenant_nw(nbapi_app_data->fab_service, &list, 
					(void *)nbapi_fabric_tenant_nw_dump);
    c_rd_unlock(&nbapi_app_data->lock);

    list.length = n_tenant;
    list.array = g_slist_reverse(list.array);
    return list;
}
nbapi_fabric_port_tnid_list_t get_fabric_port_tnid_all(void)
{
        nbapi_fabric_port_tnid_list_t list;
        int n_hosts = 0;

        list.array = NULL;
        list.length = 0;

        c_rd_lock(&nbapi_app_data->lock);
        if (!nbapi_app_data->fab_service) {
                c_rd_unlock(&nbapi_app_data->lock);
                return list;
        }
        if (nbapi_app_data->fab_service) {
            n_hosts = mul_fabric_port_tnid_show(nbapi_app_data->fab_service, false,
                                                (void *)&list, nbapi_fabric_port_tnid_dump);
        }
    c_rd_unlock(&nbapi_app_data->lock);
        list.length = n_hosts;
        list.array = g_slist_reverse(list.array);
        return list;
}

nbapi_fabric_host_list_t get_fabric_host_all(int active)
{
	nbapi_fabric_host_list_t list;
        int n_hosts = 0;

	list.array = NULL;
	list.length = 0;

	c_rd_lock(&nbapi_app_data->lock);
	if (!nbapi_app_data->fab_service) {
		c_rd_unlock(&nbapi_app_data->lock);
	 	return list;
	}
 	if (nbapi_app_data->fab_service) {
  	    if (active > 0){
 		n_hosts = mul_fabric_show_hosts
				  (nbapi_app_data->fab_service, true, false, true,
 	                          (void *)&list, /*true,*/ nbapi_fabric_host_dump);
	    }
 	    else {
 	    	n_hosts = mul_fabric_show_hosts(nbapi_app_data->fab_service, false, false, true,
 					  (void *)&list, /*true,*/ nbapi_fabric_host_dump);
	    }
 	}
        c_rd_unlock(&nbapi_app_data->lock);
 	list.length = n_hosts;
 	list.array = g_slist_reverse(list.array);
 	return list;
}
char * nbapi_uuid_to_str(uuid_t uuid){
    char * pbuf;
    int len = 0;
    uint8_t id[FAB_UUID_STR_SZ];

    pbuf = calloc(1, HOST_PBUF_SZ);
    uuid_unparse((const uint8_t *) uuid, (char * ) id);
    len += snprintf(pbuf+len, HOST_PBUF_SZ-len-1,
 		    "%s",
		    id);
    return pbuf; 
}

int add_fabric_host(uint64_t datapath_id,
		    char *str_tenant_id,
		    char *str_network_id,
		    char *nw_src,
		    char *dl_src,
		    char *in_port,
                    char *is_gw)
{

    uuid_t tenant_id;
    uuid_t network_id;
    int ret = 0, i = 0;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char * mac_str = NULL, *next = NULL;
    

    ret = uuid_parse(str_tenant_id, tenant_id);
    if (ret != 0){
	return -2;
    } 
    ret = uuid_parse(str_network_id, network_id);
    if (ret != 0){
	return -3;
    }

    fl.in_port = htonl(atoi(in_port));
    ret = str2prefix(nw_src, (void *)&host_ip);
    if (ret <= 0) {
	return -4;
    }
    fl.ip.nw_src = host_ip.prefix.s_addr;
    if (!strncmp(is_gw, "no", strlen(is_gw))){
	fl.FL_DFL_GW = false;
    } else {
	fl.FL_DFL_GW = true;
    }
    mac_str = (void *)dl_src;
    for ( i = 0; i< 6 ; i++) {
	fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
 	if(mac_str == next)
	    break;
	mac_str = next + 1;
    }

    if (i != 6 ) {
	return -5;
    }

    if (mul_fabric_host_mod(nbapi_app_data->fab_service, datapath_id, &fl, tenant_id, network_id, true)){
	return -6;
    }
    return 1;
}

int delete_fabric_host( char *str_tenant_id, 
			char *str_network_id, 
			char *str_host_ip, 
			char *str_host_mac)
{
    uuid_t tenant_id;
    uuid_t network_id;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int i = 0, ret = 0;

    memset(&fl, 0, sizeof(fl));
    ret = uuid_parse(str_tenant_id, tenant_id);
    if (ret == -1){
	return -1;
    }

    ret = uuid_parse(str_network_id, network_id);
    if (ret == -1) {
	return -2;
    }

    ret = str2prefix(str_host_ip, (void *)&host_ip);
    if (ret <= 0) {
	return -3;
    }

    fl.ip.nw_src = host_ip.prefix.s_addr;
    mac_str = (void *)str_host_mac;

    for(i = 0; i < 6 ; i++) {
	fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
	if(mac_str == next)
	    break;
	mac_str = next + 1;
    }

    if (i != 6) {
	return -4;
    }

    if (mul_fabric_host_mod(nbapi_app_data->fab_service, 0, &fl, tenant_id, network_id, false)) {
	return -5;
    }

    return 1;
}
static void
nbapi_fabric_route_dump(void *arg, char *buf){

    nbapi_fabric_route_list_t *list = (nbapi_fabric_route_list_t *)arg;
    struct c_ofp_auxapp_cmd *cofp_auc = (struct c_ofp_auxapp_cmd *)buf;
    struct nbapi_fabric_route *nf_r;
    struct c_ofp_route *cofp_route;
    struct c_ofp_route_link *cofp_rl;
    int n_links = 0, i = 0, len = 0;
    n_links = (ntohs(cofp_auc->header.length) -
                      (sizeof(*cofp_auc) + sizeof(struct c_ofp_route)))/sizeof(struct c_ofp_route_link);
    cofp_route = (void *)(cofp_auc->data);
    cofp_rl = (struct c_ofp_route_link *)cofp_route->route_links;
    nf_r = calloc(1, sizeof(*nf_r));
    nf_r->str_route = calloc(1, FAB_DFL_PBUF_SZ);
    len += snprintf(nf_r->str_route+len, FAB_DFL_PBUF_SZ-len-1,"[");
    for (; i<n_links; i++){
	len += snprintf(nf_r->str_route+len, FAB_DFL_PBUF_SZ-len-1,
                        "{ 'hop' : '%d', 'to_switch' : '0x%llx', 'to_sw_port' : '%d' },",
			i+1,
                        (unsigned long long)(ntohll(cofp_rl->datapath_id)),
                        ntohs(cofp_rl->src_link));
	cofp_rl++;
    }
    len--;
    len += snprintf(nf_r->str_route+len, FAB_DFL_PBUF_SZ-len-1,"]");
    memcpy(&nf_r->src_host, &cofp_route->src_host, sizeof(cofp_route->src_host));
    memcpy(&nf_r->dst_host, &cofp_route->dst_host, sizeof(cofp_route->dst_host));
    ntoh_c_ofp_fabric_host(&nf_r->src_host);
    ntoh_c_ofp_fabric_host(&nf_r->dst_host);
    nf_r->src_host.host_flow.in_port = ntohs(htonl(nf_r->src_host.host_flow.in_port));
    nf_r->dst_host.host_flow.in_port = ntohs(htonl(nf_r->dst_host.host_flow.in_port));
    c_log_err("src dpid0x%llx ip%08x to dst dpid0x%llx ip%08x",
                U642ULL(nf_r->src_host.switch_id.datapath_id),
                nf_r->src_host.host_flow.ip.nw_src,
                U642ULL(nf_r->dst_host.switch_id.datapath_id),
                nf_r->dst_host.host_flow.ip.nw_src);
    list->array = g_slist_prepend(list->array, nf_r);
}

nbapi_fabric_route_list_t nbapi_get_fabric_route_all(void){
    nbapi_fabric_route_list_t list;
    int n_routes = 0;
    list.array=NULL;
    list.length=0;

    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->fab_service){
	c_rd_unlock(&nbapi_app_data->lock);
	return list;	
    }
    if (nbapi_app_data->fab_service){
	n_routes = mul_fabric_show_routes(nbapi_app_data->fab_service, (void *)&list, true, 
				nbapi_fabric_route_dump, NULL, NULL);
    }
    c_rd_unlock(&nbapi_app_data->lock);
    list.length = n_routes;
    list.array = g_slist_reverse(list.array);
    return list;
}

nbapi_fabric_route_list_t nbapi_get_host_route(	char *str_tenant_id,
                        			char *str_network_id,
                        			char *str_host_ip,
                        			char *str_host_mac)
{
    nbapi_fabric_route_list_t list;
    int n_routes = 0;
    uuid_t tenant_id;
    uuid_t network_id;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int i = 0, ret = 0;
    list.array=NULL;
    list.length=0;
    memset(&fl, 0, sizeof(fl));
    ret = uuid_parse(str_tenant_id, tenant_id);
    if (ret == -1){
        return list;
    }

    ret = uuid_parse(str_network_id, network_id);
    if (ret == -1) {
        return list;
    }

    ret = str2prefix(str_host_ip, (void *)&host_ip);
    if (ret <= 0) {
        return list;
    }

    fl.ip.nw_src = host_ip.prefix.s_addr;
    mac_str = (void *)str_host_mac;

    for(i = 0; i < 6 ; i++) {
        fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        return list;
    }

    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->fab_service){
        c_rd_unlock(&nbapi_app_data->lock);
        return list;
    }
    if (nbapi_app_data->fab_service){
        n_routes = mul_fabric_show_host_routes(nbapi_app_data->fab_service, (void *)&list, 
				&fl, tenant_id, network_id, nbapi_fabric_route_dump);
    }
    c_rd_unlock(&nbapi_app_data->lock);
    list.length = n_routes;
    list.array = g_slist_reverse(list.array);
    return list;
}

int nbapi_compare_src_host(struct flow flow, char *str_host_mac, char *str_host_ip)
{
    uint8_t mac[6];
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int i = 0, ret = 0;

    ret = str2prefix(str_host_ip, (void *)&host_ip);
    if (ret <= 0) {
        return -1;
    }

    mac_str = (void *)str_host_mac;

    for(i = 0; i < 6 ; i++) {
        mac[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        return -1;
    }

    if(flow.ip.nw_src == host_ip.prefix.s_addr && 
	!memcmp(mac, flow.dl_src, 6)){
	return 1;
    }
    return 0;
}
