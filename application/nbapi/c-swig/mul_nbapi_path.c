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

#include "mul_common.h"
#include "mul_nbapi_common.h"
#include "mul_nbapi_path.h"
#include "mul_nbapi_endian.h"

static void
nbapi_route_path_dump(rt_path_elem_t* rt_elem, nbapi_path_elem_list_t *list)
{
    rt_path_elem_t* rt_arg;
    rt_arg = calloc(1, sizeof(*rt_elem));
    memcpy(rt_arg, rt_elem, sizeof(*rt_elem));
    //rt_arg->sw_dpid = ntohll(rt_arg->sw_dpid);
    rt_arg->in_port = rt_arg->link.la;
    list->length++;
    list->array = g_slist_prepend(list->array, rt_arg);
}

nbapi_path_elem_list_t get_simple_path( int src_sw_alias, int dest_sw_alias){
    nbapi_path_elem_list_t list;
    int i = 0;
    GSList * route = NULL;
    list.length = 0;
    list.array = NULL;

    c_rd_lock(&nbapi_app_data->lock);
    if( !nbapi_app_data->route_service) {
	c_rd_unlock(&nbapi_app_data->lock);
	return list;
    }

    route = mul_route_get(nbapi_app_data->route_service, src_sw_alias, dest_sw_alias);
    c_rd_unlock(&nbapi_app_data->lock);

    if (!route){
	return list;
    }

    for (; route ; i++){
	rt_path_elem_t * rt_elem = route->data;
	nbapi_route_path_dump(rt_elem, &list);
	route = route->next;
    }

    list.length = i;
    list.array = g_slist_reverse(list.array);
    mul_destroy_route(route);

    return list;
}

nbapi_port_neigh_list_t get_switch_neighbor_all(uint64_t datapath_id) {
    nbapi_port_neigh_list_t list;
    struct cbuf *b;

    list.array = NULL;
    list.length = 0;

    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->tr_service) {
        c_rd_unlock(&nbapi_app_data->lock);
        return list;
    }
    b = mul_neigh_get(nbapi_app_data->tr_service, datapath_id);

    c_rd_unlock(&nbapi_app_data->lock);

    if (b) {
        c_ofp_auxapp_cmd_t *cofp_auc = (void *)(b->data);
        c_ofp_switch_neigh_t *neigh = (void *)(cofp_auc->data);
        int i, num_ports = (ntohs(cofp_auc->header.length) - (sizeof(c_ofp_switch_neigh_t)
                + sizeof(c_ofp_auxapp_cmd_t)))/ sizeof(struct c_ofp_port_neigh);

        struct c_ofp_port_neigh *port = (void *) (neigh->data);
        for (i = 0; i < num_ports; i++, port++) {
            struct c_ofp_port_neigh *copy = calloc(1, sizeof(*port));
            if (!copy) {
                g_slist_free_full(list.array, free);
                list.array = NULL;
                list.length = 0;
                return list;
            }

            memcpy(copy, port, sizeof(*port));
            ntoh_c_ofp_port_neigh(copy);
            list.array = g_slist_prepend(list.array, copy);
        }
        free_cbuf(b);
        list.array = g_slist_reverse(list.array);
        list.length = num_ports;
    }
    return list;

}


