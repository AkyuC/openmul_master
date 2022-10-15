/*
 *  prism_app_route.h: PRISM application for MUL Controller 
 *  Copyright (C) 2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#ifndef __PRISM_APP_ROUTE_H__
#define __PRISM_APP_ROUTE_H__
#include "prism_app.h"
#include "prism_common.h"

#define ROUTE_PBUF_SZ 512

extern prism_app_struct_t *prism_ctx;

unsigned int prism_route_hash_func(const void *key);

int prism_compare_rt_key(void *h_arg, void *v_arg UNUSED, void *u_arg);

int prism_route_equal_func(const void *key1, const void *key2);

void prism_add_route_via_conx(void *elem, void *key_arg UNUSED, void
        *u_arg UNUSED);
void prism_delete_route_via_conx(void *elem, void *key_arg UNUSED, void
        *u_arg UNUSED);

void __prism_loop_all_routes_per_nh(prism_nh_elem_t *nh_elem, GHFunc iter_fn,
                           void *u_data UNUSED);

void prism_loop_all_routes(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
                           void *u_data);

void __prism_loop_all_routes(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
                           void *u_data);

unsigned int __prism_route_add(prism_app_struct_t *prism_ctx, uint32_t dst_nw, 
        uint32_t dst_nm, uint32_t nh, uint64_t dpid, uint32_t oif);

unsigned int prism_route_add(prism_app_struct_t *prism_ctx, uint32_t dst_nw, 
        uint32_t dst_nm, uint32_t nh, uint64_t dpid, uint32_t oif);

 unsigned int
__prism_route_delete(prism_app_struct_t *prism_ctx, uint32_t dst_nw,
                     uint32_t dst_nm, bool free_nh);

unsigned int
prism_route_delete(prism_app_struct_t *prism_ctx, uint32_t dst_nw, 
                   uint32_t dst_nm, bool free_nh);

int
prism_route_mod_self(prism_app_struct_t *prism_ctx, uint32_t dst_nw,
                     uint64_t dpid, bool add);
char *
prism_dump_single_route(prism_rt_elem_t *route);

#endif
