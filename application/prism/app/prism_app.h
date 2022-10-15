/*
 *  prism_app.h: prism application headers
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
#ifndef __PRISM_APP_H__
#define __PRISM_APP_H__

#include "config.h"
#include "mul_common.h"
#include "mul_vty.h"
#include "mul_conx_servlet.h"
#include "prism_common.h"

#define PRISM_NETMASK_32_BIT (0xFFFFFFFF)
#define PRISM_UNK_BUFFER_ID  (0xFFFFFFFF)
#define PRISM_NEXT_HOP_MAX_GROUP_ENTRIES (4096)
struct prism_switch
{
    uint64_t    dpid;
    int         alias;
    bool        valid;
    c_atomic_t  ref;
    c_rw_lock_t lock;
    GHashTable *port_htbl;
    ipool_hdl_t  *group_ipool;          /* Pool for maintaining Group IDs*/
};
typedef struct prism_switch prism_switch_t;

typedef void (*send_cb_t)(mul_service_t *s, struct cbuf *b);

enum rt_flag_val
{
    RT_DIRECT, /* Direct Route */
    RT_INDIRECT /* Indirect Route */
};

struct pat_rt_elem_data
{
    uint32_t rt_flags;
}; 

struct prism_rt_hash_key
{
    uint32_t dst_nw;     /* Destination Network */
    uint32_t dst_nm;     /* Netmask */
};
typedef struct prism_rt_hash_key prism_rt_hash_key_t;

struct prism_rt_elem
{
    prism_rt_hash_key_t hkey; /* This field should not be moved */
    uint64_t dpid;       /* Switch identifier */    
    uint32_t rt_flags;   /* Route specific flags */
    void *nh_ptr;        /* Pointer to next-hop element */   
};
typedef struct prism_rt_elem prism_rt_elem_t;

struct prism_nh_hash_key
{
    uint32_t next_hop;          /* Next-hop IP */
};
typedef struct prism_nh_hash_key prism_nh_hash_key_t;

struct prism_nh_elem
{
    prism_nh_hash_key_t hkey; /*This field should not be moved */
    uint32_t oif;               /* Interface number */
    uint64_t dpid;              /* Switch identifier */
    uint32_t nh_flags;          /* Next-hop specific flags */
    uint8_t nh_mac[ETH_ADDR_LEN];   /* Resolved Next-hop mac address */
    GSList *route_list;
    uint64_t packet_count;
    uint32_t group_id;
    time_t last_known_active_time;
    struct of_group_mod_params g_parms;
};
typedef struct prism_nh_elem prism_nh_elem_t;

enum nf_flag_val
{
    NH_REACHABLE,   /* a confirmed working cache entry */
    NH_STALE,      /* used if the NH entry is STALE */
    NH_INCOMPLETE,  /* a currently resolving cache entry */
};

struct prism_vif_hash_key
{
    uint32_t port;               /* Interface number */
    uint64_t dpid;              /* Switch identifier */
};
typedef struct prism_vif_hash_key prism_vif_hash_key_t;

struct prism_vif_elem
{
    prism_vif_hash_key_t hkey; /*This field should not be moved */
    uint32_t vif_flags;          /* Next-hop specific flags */
    uint32_t intf_ip_addr;
    uint8_t vif_mac[ETH_ADDR_LEN];   /* Resolved Next-hop mac address */
};
typedef struct prism_vif_elem prism_vif_elem_t;


struct prism_path_elem
{
    uint64_t dst_dpid;                      /* Switch identifier */
    uint32_t out_port;                      /* Interface number*/
    struct flow flow;                   /* Openflow match tuple */
    struct flow mask;                /* Openflow mask tuple */
    uint32_t action_len;            /* Openflow action list len */
    void   *action_list;                 /* Openflow action list */ 
    size_t   n_src_dpid;
    uint64_t *src_dpid;
};
typedef struct prism_path_elem prism_path_elem_t;

struct prism_sdn_path
{
    uint32_t dst_nw;                  /* Destination Network */
    uint32_t dst_nm;                  /* Destination route netmask */
    uint32_t src_nw;                  /* Source Network */
    uint32_t src_nm;                  /* Source route netmask */
    prism_path_elem_t *path_list;           /* Pointer to path list for each SDN node flow info */
    void *nh_ptr;                        /* Pointer to the egress next-hop table entry */    
    void * rt_src_ptr;                  /* Pointer to the source route */  
    void *rt_dst_ptr;                   /* Pointer to the destination route */
}; 
typedef struct prism_sdn_path prism_sdn_path_t;


/* Main prism context struct holding all info */
struct prism_app_struct {
    c_rw_lock_t   lock;
    void          *base;
    GHashTable    *route_hasher_db;     /* Route hash table*/
    GHashTable    *nh_hasher_db;        /* Next hop hash table*/
    GHashTable    *vif_hasher_db;       /* Virtual I/F hash table*/
    GHashTable    *switch_htbl;         /* Switch hash table*/
    void          *ptree;               /* Pointer to Patricia Tree*/

    mul_service_t *prism_cli_service; /* Fabric cli Service */
    mul_service_t *prism_conx_service;   /* Service to communcate with FABRIC
                                           application */
    mul_service_t *prism_app_service;  /* PRISM service to receive
                                            messages from PRISM agent */
    mul_service_t *prism_agent_service;  /* PRISM service to send
                                            messages to PRISM agent */
    mul_service_t *prism_mul_service;  /* PRISM service to send
                                            messages to MUL Core */
    void          *serv_base;
    pthread_t     serv_thread;
    c_rw_lock_t   serv_lock;
    struct event  *serv_timer_event;
    struct event *sync_timer_event;
    struct event *nh_sync_timer_event;
    struct event *nh_stale_timer_event;
};
typedef struct prism_app_struct prism_app_struct_t;

int prism_service_send(void *service, struct cbuf *b,
                       bool wait, uint8_t resp);
int  prism_port_add(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no,
                  uint32_t config, uint32_t state, uint8_t *hw_addr);
int  prism_port_delete(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw,
        uint16_t port_no, uint32_t config, uint32_t state);
void prism_port_update(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no,
                     uint32_t config, uint32_t state, uint8_t *hw_addr);
bool prism_port_valid(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no);
bool prism_port_up(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no);
prism_port_t *__prism_port_find(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw,
                            uint16_t port_no);
void prism_switch_put(void *sw_arg);
void prism_switch_put_locked(void *sw_arg);
prism_switch_t *prism_switch_get(prism_app_struct_t *prism_ctx, uint64_t dpid);
prism_switch_t *prism_switch_get_with_alias(prism_app_struct_t *prism_ctx, int alias);
prism_switch_t *__prism_switch_get_with_alias(prism_app_struct_t *prism_ctx, int alias);
prism_switch_t *__prism_switch_get(prism_app_struct_t *prism_ctx, uint64_t dpid);
int prism_switch_del(prism_app_struct_t *ctx, uint64_t dpid);
int prism_switch_add(prism_app_struct_t *ctx, uint64_t dpid, int alias);
int prism_switches_init(prism_app_struct_t *prism_ctx);
void prism_switches_reset(prism_app_struct_t *ctx);

void prism_traverse_all_switch(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
        void *arg);

int prism_app_service_send(void *service, struct cbuf *b,
                   bool wait, uint8_t resp);

void prism_send_edge_node_msg(void *key UNUSED, 
                                 struct prism_switch *prism_sw, 
                                 void *arg UNUSED);
void prism_send_port_info(void *key UNUSED, void *port_arg, void *u_arg);
void prism_vty_init(void *arg);

void prism_switch_delete_notifier(prism_app_struct_t *prism_ctx, int sw_alias, 
                                bool locked);
void prism_module_init(void *ctx);
void prism_module_vty_init(void *arg);

#endif
