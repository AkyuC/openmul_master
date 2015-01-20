/*
 *  makdi.h: MAKDI MUL application headers
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>,
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
#ifndef __MAKDI_H__
#define __MAKDI_H__

#include <curl/curl.h>

#define SERV_FDB_DEBUG 1
#define MAKDI_STANDALONE 1
#define MAKDI_METER_TYPE 0

#define MAKDI_APP_NAME "mul-makdi"
#define MAKDI_UNK_BUFFER_ID (0xffffffff)

struct makdi_iter_arg
{
 	mul_service_t *serv;
    void (*send_cb)(mul_service_t *s, struct cbuf *b);
    void *vty;
};

struct dp_nh_key
{
    int64_t dst_dpid;
    int64_t src_dpid;
};
typedef struct dp_nh_key dp_nh_key_t;

struct dp_nh_ent
{
    dp_nh_key_t key;
    uint64_t nh_dpid; 
    uint32_t nh_port; 
    uint32_t nh_nport; 
};
typedef struct dp_nh_ent dp_nh_ent_t;

struct dp_fl_ent
{
    uint64_t dpid;
    struct flow fl;
    struct flow mask;
    uint8_t *actions;
    size_t act_len;
    uint32_t oport;
};
typedef struct dp_fl_ent dp_fl_ent_t;

struct dp_reg_ent
{
    uint64_t dpid; 
    uint32_t port; 
    uint8_t  type;
    GSList *s_fdb_list;
};
typedef struct dp_reg_ent dp_reg_ent_t;

struct sw_key
{
    uint64_t      dpid;
};
typedef struct sw_key sw_key_t;

struct sw_ent
{
	sw_key_t key;
	c_atomic_t	  ref;
    mul_switch_t  *sw; 
};
typedef struct sw_ent sw_ent_t;

struct g_slist_find_service_t 
{ 
    GSList *list;
    uint16_t vlan;
};

struct g_slist_find_user_t 
{ 
    GSList *list;
    uint32_t  ip;
};

struct flow_match_iter_arg
{
    struct makdi_iter_arg *iter_arg;
    GSList *iter;
};

struct makdi_hdl_ {
    c_rw_lock_t   lock;
    void          *base;
    GHashTable    *dp_rhtbl;
    GHashTable    *s_user_htbl;
    GHashTable    *nfv_group_htbl;
    GHashTable    *dp_nhtbl;
    GHashTable	  *service_htbl;
    GHashTable    *sw_htbl;
    GHashTable    *s_user_level_htbl;
    GSList        *chain_list;
    mul_service_t *cfg_service;
    mul_service_t *route_service; /* Route Service Instance */
    mul_service_t *mul_service;   
    struct event  *timer_event;
#define RT_STATE_WAIT_FOR_CONVERGENCE       (0)
#define RT_STATE_CONVERGED                  (1)
    uint64_t       rt_conv_state;
};
typedef struct makdi_hdl_ makdi_hdl_t;

/* Initialization Functions */
void makdi_module_init(void *ctx);
void makdi_module_vty_init(void *arg);

void __default_rule_service_traverse_all(void *group, void *uarg);
void dp_nh_dump_all(makdi_hdl_t *hdl);
dp_nh_ent_t *__dp_nh_find(makdi_hdl_t *hdl, uint64_t src_dpid, uint64_t dst_dpid);
void dp_nh_tbl_init(makdi_hdl_t *hdl);
int register_serv_flow(uint64_t dpid, uint32_t nw_src, uint16_t iif);
int unregister_serv_flow(uint64_t dpid, uint32_t nw_src, uint16_t iif);
int makdi_reg_allowed_dpid(makdi_hdl_t *hdl, uint64_t dpid,
                           uint16_t port, uint8_t type);
bool run_makdi_on_dpid(uint64_t dpid, uint16_t port);

/* Init functions */
void makdi_module_init(void *base_arg);
void makdi_module_vty_init(void *arg UNUSED);

#endif
