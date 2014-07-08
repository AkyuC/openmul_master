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

 nbapi_path_elem_list_t get_simple_path(int src_sw_alias, 
									uint16_t src_port_no, 
									int dest_sw_alias, 
									uint16_t dest_port_no) {
 	nbapi_path_elem_list_t ret_list;
 	ret_list.array = NULL;
 	ret_list.length = 0;

 	c_rd_lock(&nbapi_app_data->lock);
 	if (!nbapi_app_data->route_service) {
 		c_rd_unlock(&nbapi_app_data->lock);
 		return ret_list;
 	}

 	if (nbapi_app_data->route_service) {
 		GSList *route = mul_route_get(nbapi_app_data->route_service, src_sw_alias, dest_sw_alias);

 		c_rd_unlock(&nbapi_app_data->lock);
 		if (route) {
 			GSList *index = route;
 			uint16_t ingress_port_no = src_port_no;
			ret_list.length = g_slist_length(route);

 			while (index) {
 				rt_path_elem_t *route_entry = index->data;
 				nbapi_path_elem_t *path_entry = calloc(sizeof(*path_entry),1);
 				if ( !path_entry ) {
 					c_log_err("%s: failed to alloc nbapi_path_elem", FN);
 					g_slist_free_full(ret_list.array, free);
 					mul_destroy_route(route);
 					ret_list.array = NULL;
 					ret_list.length = 0;
 					return ret_list;
 				}
 				c_log_debug("%s: switch %u la %hu lb %hu", 
 								FN, route_entry->sw_alias, 
 								route_entry->link.la, route_entry->link.lb);

				path_entry->switch_alias = route_entry->sw_alias;
				path_entry->ingress_port_no = ingress_port_no;

 				if (route_entry->flags == RT_PELEM_LAST_HOP) {
 					path_entry->egress_port_no = dest_port_no;
 				}
 				else {
 					path_entry->egress_port_no = route_entry->link.la;
 					ingress_port_no = route_entry->link.lb;
 				}
 				ret_list.array = g_slist_prepend(ret_list.array, path_entry);

 				index = index->next;
 			}
 			ret_list.length = g_slist_length(ret_list.array);
 			ret_list.array = g_slist_reverse(ret_list.array);
 			mul_destroy_route(route);
 		}
 	}
 	return ret_list;
 }
