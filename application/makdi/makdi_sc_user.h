/*
 *  makdi_sc_user.h: makdi service-chain user management headers
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
#ifndef __MAKDI_SC_USER_H__
#define __MAKDI_SC_USER_H__

#define MAKDI_MAX_IROUTES 100
#define MAKDI_CHAIN_INIT_VID (100)

#define MAKDI_MIN_NFVS_IN_SC 2

#define MAKDI_ENTRY_NFV_GRP "USER"
#define MAKDI_EXIT_NFV_GRP "EXIT"

struct s_user_key_
{
    uint64_t dpid;
#define SERV_ID vlan
    uint16_t vlan;
    uint16_t res;
    uint32_t src_nw_addr;
};
typedef struct s_user_key_ s_user_key_t;

struct s_user_ent_
{
    s_user_key_t key;
    void *s_ent;
    uint64_t e_dpid;
    uint16_t e_iif;
    uint64_t s_dpid;
    uint16_t s_iif;
    GHashTable *s_fdb_htbl;
    GSList *nfv_groups;
    GSList *nfv_list;
    GSList *r_nfv_list;
    bool reg;               /* active or not */ 
    bool retry_reg;
    bool use_default;
#define S_SERV_TIMEO 5
    time_t create_ts;
};
typedef struct s_user_ent_ s_user_ent_t;

struct s_user_level_key_
{
    uint32_t nw_src;
};
typedef struct s_user_level_key_ s_user_level_key_t;

struct s_user_level_ent_
{
    s_user_level_key_t key;
    uint8_t user_level;
};
typedef struct s_user_level_ent_ s_user_level_ent_t;

struct chain_fl_ent
{
    uint64_t dpid;
    struct flow fl;
    struct flow mask;
    uint8_t *actions;
    size_t act_len;
    uint32_t oport;
    s_user_ent_t *u_ent;
};
typedef struct chain_fl_ent chain_fl_ent_t;

#define GET_SERV_ID_FROM_FDB(fdb) (ntohs((fdb)->key.fdb_fl.dl_vlan))
#define GET_USER_IP_FROM_FDB(fdb) (ntohl((fdb)->key.fdb_fl.ip.nw_src))

struct s_fdb_key_
{
    struct flow fdb_fl;
};
typedef struct s_fdb_key_ s_fdb_key_t;

struct s_fdb_ent_
{
    s_fdb_key_t key;
    bool reg;
    uint64_t dpid;
    struct flow r_fl;
    s_user_ent_t *u_ent;
    GSList *chain_fl;
    GSList *r_chain_fl;
#define S_FDB_TIMEO 20
    time_t create_ts;
};
typedef struct s_fdb_ent_ s_fdb_ent_t;

struct s_fdb_iter_arg
{
    GHFunc iter_fn;
    void *arg;
};

void __s_per_user_timer(void *key, void *user, void *uarg);
void __s_user_nfv_list_traverse_elem(void *ent, void *uarg);
void __sc_reset_all_users_with_nfv(void *nfv_key, bool dp_event);
void s_user_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg);
void s_user_traverse_all_writer(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg);
int s_user_add(makdi_hdl_t *hdl, s_user_ent_t *u_ent);
int s_user_del(makdi_hdl_t *hdl, s_user_key_t *key);

void sc_modify_on_port_up(uint64_t dpid, uint16_t port);
void sc_modify_on_port_down(uint64_t dpid, uint16_t port);
void sc_modify_on_dp_down(uint64_t dpid);
int sc_remove(makdi_hdl_t *hdl, char *service_name,
          uint32_t src_nw_addr, uint64_t dpid);
int sc_insert(makdi_hdl_t *hdl, char *service_name,
              uint32_t src_nw_addr, uint64_t dpid,
              int nfvc, char **nfvv, bool use_default);

GSList *__s_user_level_find(void *service_ent,
                            uint32_t nw_src);
int __s_user_ent_reset_nfv_list(s_user_ent_t *u_ent, int nfvc, char **nfvv);
void s_user_key_init(s_user_ent_t *u_ent, uint32_t src_nw_addr,
                     uint64_t dpid, uint16_t serv_id);
int s_user_level_add(makdi_hdl_t *hdl, s_user_level_ent_t *u_ent);
int s_user_level_del(makdi_hdl_t *hdl, s_user_level_key_t *key);
int __s_user_level_del(makdi_hdl_t *hdl, s_user_level_key_t *key);
s_user_ent_t *__s_user_find(makdi_hdl_t *hdl, s_user_ent_t *u_lkup);
int makdi_sc_default_insert(makdi_hdl_t *hdl, char *service_name,
                            int nfvc, char **nfvv, uint16_t type);
int makdi_sc_default_remove(makdi_hdl_t *hdl, char *service_name, uint16_t level);

void show_s_fdb_info(void *key UNUSED, void *fdb_arg, void *uarg);
void send_s_fdb_info(void *key UNUSED, void *fdb_arg, void *uarg);
void __s_fdb_traverse_per_user(void *key, void *user, void *uarg);
void s_fdb_ent_init(s_fdb_ent_t *fdb, struct flow *flow, uint64_t dpid);
void s_fdb_r_flow_init(s_fdb_ent_t *fdb, uint16_t port);
void s_fdb_dump(s_fdb_ent_t *fdb, char *msg);
int s_fdb_expired(void *key_arg, void *val_arg, void *uarg);
int __s_fdb_install_serv(s_fdb_ent_t *fdb, bool dir, s_user_ent_t *u_ent);
int __s_fdb_add(makdi_hdl_t *hdl UNUSED, s_user_ent_t *u_ent, s_fdb_ent_t *fdb,
            uint32_t in_port, uint32_t buffer_id, uint8_t *raw,
            size_t pkt_len);
int __s_fdb_del(s_user_ent_t *u_ent, s_fdb_ent_t *fdb);
int s_fdb_lrn(makdi_hdl_t *hdl, s_fdb_ent_t *lrn_fdb,
          uint32_t in_port, uint32_t buffer_id,
          uint8_t *raw, size_t pkt_len);

int makdi_users_init(makdi_hdl_t *hdl);
s_user_level_ent_t *s_user_level_ent_alloc(uint32_t nw_src, uint8_t level);

#endif
