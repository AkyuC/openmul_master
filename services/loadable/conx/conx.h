/*
 *  conx.h: Connector module header file
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#ifndef __CONX_H__
#define __CONX_H__

#define CONX_FLOW_DEBUG 1
#define CONX_MAX_GROUPS (2048)

#define CONX_FL_PRIO_HI (C_FL_PRIO_FWD+202)
#define CONX_FL_PRIO_LO (C_FL_PRIO_FWD+200) 

extern struct c_rlim_dat crl;
struct conx_ent;

typedef struct conx_op_res {
    void *arg;
    int pos;
    int res;
}conx_op_res_t;

struct conx_ent_key {
    uint64_t src_dpid;
    uint64_t dst_dpid;
};
typedef struct conx_ent_key conx_ent_key_t;

typedef struct conx_tunnel_desc {
    union {
        struct conx_overlay_id {
            uint64_t tunnel_id;
            uint32_t tunnel_key;
        }o;
        struct conx_underlay_id {
            uint8_t tun_dmac[ETH_ADDR_LEN];
            uint8_t tun_smac[ETH_ADDR_LEN];
        }u;
    };
}conx_tunnel_desc_t;

struct conx_route
{
    bool valid_rt;
    GSList *conx_route;
};

struct conx_ent_grp {
    uint32_t group_id;
    struct of_group_mod_params g_parms;
};

struct conx_ent {
    conx_ent_key_t key;
    int src_alias;
    int dst_alias;
    conx_tunnel_desc_t tun_desc;
    conx_tunnel_t type;
    struct conx_ent_grp ecmp_grp;
#define CONX_ENT_LOOPBACK (0x1)
    uint32_t flags;
#define CONX_MAX_ROUTES 2
    struct conx_route routes[CONX_MAX_ROUTES];
};
typedef struct conx_ent conx_ent_t;

struct conx_sw_priv {
    void *app_sw;
    GHashTable  *sw_conx_htbl;
};
typedef struct conx_sw_priv conx_sw_priv_t;

struct conx_ufl_hent {
    conx_ent_key_t key;
    GSList *user_fl_list;
};
typedef struct conx_ufl_hent conx_ufl_hent_t; 

struct conx_struct {
    c_rw_lock_t lock;
    void *base;
    bool use_groups;
    ipool_hdl_t *g_ipool;
    mul_service_t *route_service;
    mul_service_t *mul_service;
    mul_service_t *config_service;
    struct event *per_sec_tim_event;
    GSList *conx_sw_list;
    GHashTable *uflow_htbl;
    GHashTable *ucookie_htbl;
};
typedef struct conx_struct conx_struct_t;

struct user_fl_ent {
    conx_ent_key_t key;
    conx_tunnel_desc_t tun_desc;
    bool valid;
#define CONX_UENT_LOOPBACK CONX_ENT_LOOPBACK
#define CONX_UENT_SRC_FLOW (0x2)
#define CONX_UENT_STALE (0x4)
    uint32_t flags;

    struct flow flow;
    struct flow mask;
    uint32_t tenant;
    uint32_t app_cookie;
    time_t refresh_time;
    uint16_t prio;
    void *egress_actions;
    size_t act_len;
    conx_ent_t *conx;
};
typedef struct user_fl_ent user_fl_ent_t;

void conx_retry_all(void);
void conx_nh_tbl_init(void);
conx_ent_t *conx_ent_alloc(uint64_t s_dpid, uint64_t d_dpid,
               int s_alias, int d_alias,
               uint64_t tunnel_id, uint32_t tunnel_key,
               conx_tunnel_t tun_type);

void conx_ent_free(void *arg);
int conx_route_uninstall(conx_ent_t *ent, bool destroy, int pos);
int conx_route_uninstall_all(conx_ent_t *ent, bool destroy);
void conx_per_dp_nh_destroy(void *k, void *v, void *u);
char *conx_dump_route(GSList *route_path);

#endif
