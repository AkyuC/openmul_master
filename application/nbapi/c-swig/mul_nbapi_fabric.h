/*
 *  mul_nbapi_fabric.h: Mul Northbound Fabric Manager API application headers
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
#ifndef __MUL_NBAPI_FABRIC_H__
#define __MUL_NBAPI_FABRIC_H__

#include "mul_app_interface.h"
#include "glib.h"
#include "mul_nbapi_swig_helper.h"
#include "mul_vty.h"
#include "uuid.h"

#ifdef SWIG
    %newobject get_fabric_tenant_net_all;
    %newobject get_fabric_port_tnid_all;
    %newobject get_fabric_host_all;
    %newobject nbapi_uuid_to_str;
    %newobject nbapi_get_fabric_route_all;
    %newobject nbapi_get_host_route;
#endif

MUL_NBAPI_PYLIST_RETURN( c_ofp_host_mod , nbapi_fabric_host_list_t )
MUL_NBAPI_PYLIST_RETURN( c_ofp_port_tnid_mod , nbapi_fabric_port_tnid_list_t )
MUL_NBAPI_PYLIST_RETURN( c_ofp_tenant_nw_mod , nbapi_fabric_tenant_nw_list_t )

struct nbapi_fabric_route{
    struct c_ofp_host_mod src_host;
    struct c_ofp_host_mod dst_host;
    char * str_route;
};

MUL_NBAPI_PYLIST_RETURN( nbapi_fabric_route , nbapi_fabric_route_list_t )

int add_del_fabric_port_tnid(uint64_t datapath_id, char *str_tenant_id, char *str_network_id, 
                             char *in_port, bool add);
nbapi_fabric_tenant_nw_list_t get_fabric_tenant_net_all(void);
nbapi_fabric_port_tnid_list_t get_fabric_port_tnid_all(void);
nbapi_fabric_host_list_t get_fabric_host_all(int active);
char *nbapi_uuid_to_str(uuid_t uuid);
int add_fabric_host(uint64_t datapath_id, char *str_tenant_id, char *str_network_id,
                    char *nw_src, char *dl_src, char *in_port, char *is_gw);
int delete_fabric_host(char *str_tenant_id, char *str_network_id, 
                        char *str_host_ip, char *str_host_mac);
nbapi_fabric_route_list_t nbapi_get_fabric_route_all(void);
nbapi_fabric_route_list_t nbapi_get_host_route(char *str_tenant_id, char *str_network_id,
                                                char *str_host_ip, char *str_host_mac);
int nbapi_compare_src_host(struct flow flow, char *str_host_mac, char *str_host_ip);
#endif
