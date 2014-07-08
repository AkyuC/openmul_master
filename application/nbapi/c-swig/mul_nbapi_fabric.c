/*
 * mul_nbapi_path.c: Mul Northbound Path Application for Mul Controller
 * Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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

#include "mul_nbapi_common.h"
#include "mul_nbapi_fabric.h"
#include "mul_nbapi_endian.h"


static void
nbapi_fabric_host_dump(nbapi_fabric_host_list_t *list, c_ofp_host_mod_t *cofp_host)
{
	c_ofp_host_mod_t *cofp_arg = calloc(sizeof(*cofp_host), 1);
    *cofp_arg = *cofp_host;
    ntoh_c_ofp_fabric_host(cofp_arg);
    list->array = g_slist_prepend(list->array, cofp_arg);
}

nbapi_fabric_host_list_t get_fabric_host_all(int active)
{
	nbapi_fabric_host_list_t list;
	list.array = NULL;
	list.length = 0;
	int n_hosts = 0;

	c_rd_lock(&nbapi_app_data->lock);
	if (!nbapi_app_data->fab_service) {
		c_rd_unlock(&nbapi_app_data->lock);
	 	return list;
	}

 	if (nbapi_app_data->fab_service) {
 		if (active > 0)
 			n_hosts = mul_fabric_show_hosts(nbapi_app_data->fab_service, true, false,
 		                          &list, true, nbapi_fabric_host_dump);
 	    else
 	    	mul_fabric_show_hosts(nbapi_app_data->fab_service, false, false,
 				 		                          &list, true, nbapi_fabric_host_dump);
 	}
 	list.length = n_hosts;
 	list.array = g_slist_reverse(list.array);
 	return list;
 }

static inline void
add_tenant_id(struct flow *fl, uint32_t *wildcards, uint16_t tenant_id)
{

    if (wildcards)
        *wildcards &= ~(OFPFW_DL_VLAN);

    fl->dl_vlan = htons(tenant_id);
}

static inline void
add_network_id(struct flow *fl, uint16_t network_id)
{
    *(uint16_t *)&fl->pad[1] = htons(network_id);
}

int add_fabric_host(uint64_t datapath_id,
				uint16_t tenant_id,
				uint16_t network_id,
                struct flow *fl,
                int is_gw)
{
	add_tenant_id(fl, NULL, tenant_id);
	add_network_id(fl, network_id);

	if (is_gw > 0)
		fl->FL_DFL_GW = false;
	else
		fl->FL_DFL_GW = true;

	//hton_flow(fl);

	if (mul_fabric_host_mod(nbapi_app_data->fab_service, datapath_id, fl, true)) {
	        return -1;
	}
	return 1;
}

int delete_fabric_host(uint64_t datapath_id,
		        uint16_t tenant_id,
				uint16_t network_id,
                struct flow *fl)
{
	add_tenant_id(fl, NULL, tenant_id);
	add_network_id(fl, network_id);

	//hton_flow(fl);

	if (mul_fabric_host_mod(nbapi_app_data->fab_service, 0, fl, false)) {
		return -1;
	}
	return 1;
}
