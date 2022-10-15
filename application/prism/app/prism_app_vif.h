/*
 *  prism_app_vif.h: PRISM application for MUL Controller 
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
#ifndef __PRISM_APP_VIF_H__
#define __PRISM_APP_VIF_H__
#include "prism_app.h"
#include "prism_common.h"

#define VIF_PBUF_SZ 512

char * prism_dump_single_vif(prism_vif_elem_t *vif);

unsigned int prism_vif_hash_func(const void *key);

int prism_vif_equal_func(const void *key1, const void *key2);

int prism_compare_vif_key(void *h_arg, void *v_arg UNUSED, void *u_arg);

unsigned int __prism_vif_add(prism_app_struct_t *prism_ctx,
                                  uint64_t dpid, uint32_t oif, 
                                  uint32_t vif_flags, uint8_t *mac_addr);

unsigned int prism_vif_add(prism_app_struct_t *prism_ctx, 
                                  uint64_t dpid, uint32_t oif,
                                  uint32_t vif_flags, uint8_t *mac_addr);

unsigned int __prism_vif_del(prism_app_struct_t *prism_ctx,
                                  uint64_t dpid, uint32_t oif);

unsigned int prism_vif_del(prism_app_struct_t *prism_ctx,
                                  uint64_t dpid, uint32_t oif);

unsigned int __prism_vif_modify(prism_app_struct_t *prism_ctx,
                                  uint64_t dpid, uint32_t oif, 
                                  uint32_t vif_flags, uint8_t *mac_addr,
                                  bool update_ip, uint32_t intf_ip);

unsigned int prism_vif_modify(prism_app_struct_t *prism_ctx, 
                                  uint64_t dpid, uint32_t oif,
                                  uint32_t vif_flags, uint8_t *mac_addr,
                                  bool update_ip, uint32_t intf_ip);

void __prism_loop_all_vif(prism_app_struct_t *prism_ctx, GHFunc iter_fn, 
                            void *u_data);

void prism_loop_all_vif(prism_app_struct_t *prism_ctx, GHFunc iter_fn, 
                            void *u_data);

unsigned int prism_vif_hash_func(const void *key);

int prism_vif_equal_func(const void *key1, const void *key2);

int prism_compare_vif_key(void *h_arg, void *v_arg UNUSED, void *u_arg);

void prism_app_vif_init(prism_app_struct_t *prism_ctx);

#endif
