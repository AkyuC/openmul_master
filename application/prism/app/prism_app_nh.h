/*
 *  prism_app_nh.h: PRISM application for MUL Controller 
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
#ifndef __PRISM_APP_NH_H__
#define __PRISM_APP_NH_H__
#include "prism_app.h"
#include "prism_common.h"
#include "prism_app_route.h"

#define NH_PBUF_SZ 512
#define PRISM_NEXT_HOP_TABLE_ID     0x2

char * prism_dump_single_nh(prism_nh_elem_t *nh);

unsigned int prism_next_hop_hash_func(const void *key);

int prism_next_hop_equal_func(const void *key1, const void *key2);

int prism_compare_nh_key(void *h_arg, void *v_arg UNUSED, void *u_arg);

unsigned int __prism_next_hop_add(prism_app_struct_t *prism_ctx, uint32_t nh, 
                                  uint64_t dpid, uint32_t oif, 
                                  uint32_t nh_flags, uint8_t *mac_addr);

unsigned int prism_next_hop_add(prism_app_struct_t *prism_ctx, uint32_t nh, 
                                  uint64_t dpid, uint32_t oif,
                                  uint32_t nh_flags, uint8_t *mac_addr);

unsigned int __prism_next_hop_del(prism_app_struct_t *prism_ctx, uint32_t nh, 
                                  uint64_t dpid, uint32_t oif);

unsigned int prism_next_hop_del(prism_app_struct_t *prism_ctx, uint32_t nh, 
                                  uint64_t dpid, uint32_t oif);

void __prism_loop_all_nh(prism_app_struct_t *prism_ctx, GHFunc iter_fn, 
                            void *u_data);

void prism_loop_all_nh(prism_app_struct_t *prism_ctx, GHFunc iter_fn, 
                            void *u_data);

void __prism_loop_all_nh_remove(prism_app_struct_t *prism_ctx, GHRFunc iter_fn, 
                            void *u_data);

void prism_loop_all_nh_remove(prism_app_struct_t *prism_ctx, GHRFunc iter_fn, 
                            void *u_data);

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
int prism_next_hop_flow_install(uint32_t next_hop, uint32_t oif, uint64_t dpid,
        uint8_t *nh_mac, uint8_t *hw_addr);

void prism_next_hop_flow_uninstall(uint32_t next_hop, uint64_t dpid);

#else

int prism_next_hop_group_install(prism_nh_elem_t *nh, uint8_t *hw_addr);

void prism_next_hop_group_uninstall(prism_nh_elem_t *nh);

#endif


void prism_replay_all_nh(prism_app_struct_t *prism_ctx, prism_vif_hash_key_t *key);

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
void prism_nh_get_flow_stats(void *elem, void *v_arg UNUSED, 
                        void *u_arg UNUSED);
#else
void prism_nh_get_group_stats(void *elem, void *v_arg UNUSED, 
                        void *u_arg UNUSED);
#endif

void __prism_nh_make_entry_stale_single(void *nh_arg, void *arg UNUSED, 
                                   void *u_arg UNUSED);

int __prism_nh_clear_stale_entry_single(void *nh_arg, void *arg UNUSED, 
                                   void *u_arg UNUSED);

unsigned int __prism_next_hop_del_entry(prism_nh_elem_t* nh_elem);

#endif
