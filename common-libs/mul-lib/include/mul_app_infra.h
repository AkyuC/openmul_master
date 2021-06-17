/*
 * mul_app_infra.h - MUL application infrastructre headers
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
#ifndef __MUL_APP_INFRA_H__
#define __MUL_APP_INFRA_H__ 1

struct mul_switch
{
    void        *hdl;
    c_rw_lock_t lock;
    c_atomic_t  ref;
    uint64_t    dpid;
    int         alias_id;
    GSList      *port_list;
    uint8_t     n_stale;
#define MUL_PRIV_SWITCH(X) (X->priv)
    void        *priv;

    uint32_t    n_buffers;
    uint8_t     n_tables;
    uint8_t     ofp_ver;
};
typedef struct mul_switch mul_switch_t;

struct mul_port
{
    mul_switch_t *owner;
    uint16_t     port_no;
    uint32_t     config;
    uint32_t     state;
    uint8_t      hw_addr[6];
    uint8_t      n_stale;
#define MUL_PRIV_PORT(X) (x->priv)
    void         *priv;
};
typedef struct mul_port mul_port_t;

struct mul_app_client_cb
{
    int  (*switch_priv_alloc)(void **switch_ptr);
    void (*switch_priv_free)(void *switch_ptr);
    void (*switch_add_cb)(mul_switch_t *sw); 
    void (*switch_del_cb)(mul_switch_t *sw); 
    int  (*switch_priv_port_alloc)(void **port_ptr);
    void (*switch_priv_port_free)(void **port_ptr);
    void (*switch_port_add_cb)(mul_switch_t *sw, mul_port_t *port); 
    void (*switch_port_del_cb)(mul_switch_t *sw, mul_port_t *port); 
    void (*switch_port_chg)(mul_switch_t *sw, mul_port_t *port, bool adm, 
                            bool link); 
    void (*switch_port_link_chg)(mul_switch_t *sw, mul_port_t *port, bool link); 
    void (*switch_port_adm_chg)(mul_switch_t *sw, mul_port_t *port, bool adm); 
    void (*switch_packet_in)(mul_switch_t *sw, struct flow *fl, uint32_t port,
                            uint32_t buffer_id,  uint8_t *raw, size_t pkt_len);
    void (*switch_error)(mul_switch_t *sw, uint16_t type, uint16_t code,
                         uint8_t *raw, size_t raw_len);
    void (*switch_fl_mod_err)(mul_switch_t *sw, uint16_t type, uint16_t code,
                              c_ofp_flow_mod_t *fm);
    void (*switch_group_mod_err)(mul_switch_t *sw, uint16_t type, uint16_t code,
                                 c_ofp_group_mod_t *gm);
    void (*switch_meter_mod_err)(mul_switch_t *sw, uint16_t type, uint16_t code,
                                 c_ofp_meter_mod_t *fm);
    void (*core_conn_closed)(void);
    void (*core_conn_reconn)(void);
    void (*app_ha_state)(uint32_t sysid, uint32_t ha_state);
    void (*process_vendor_msg_cb)(mul_switch_t *sw,uint8_t *msg, size_t pkt_len);
    void (*topo_route_status_cb)(uint64_t status);
};
typedef struct mul_app_client_cb mul_app_client_cb_t;

void mul_app_free_buf(void *b);
int mul_register_app(void *app, char *app_name, uint32_t app_flags,
                     uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                     void  (*ev_cb)(void *app_arg, void *pkt_arg));
int mul_register_app_cb(void *app_arg, char *app_name, uint32_t app_flags,
                    uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                    struct mul_app_client_cb *app_cbs);
int mul_unregister_app(char *app_name);
int mul_app_command_handler(void *app_name,void *b);

int mul_app_send_flow_add(void *app_name, void *sw_arg,
                      uint64_t dpid, struct flow *fl, struct flow *mask,
                      uint32_t buffer_id, void *actions, size_t action_len,
                      uint16_t itimeo, uint16_t htimeo, uint16_t prio,
                      uint64_t flags);
int mul_service_send_flow_add(void *service,
                          uint64_t dpid, struct flow *fl, struct flow *mask,
                          uint32_t buffer_id, void *actions, size_t action_len,
                          uint16_t itimeo, uint16_t htimeo, uint16_t prio,
                          uint64_t flags);
int mul_app_send_flow_del(void *app_name, void *sw_arg, uint64_t dpid,
                          struct flow *fl, struct flow *mask,
                          uint32_t port, uint16_t prio, uint64_t flag,
                          uint32_t group);
int mul_service_send_flow_del(void *service,
                      uint64_t dpid, struct flow *fl,
                      struct flow *mask, uint32_t oport,
                      uint16_t prio, uint64_t flags,
                      uint32_t group);
uint32_t mul_app_group_id_alloc(uint32_t id);
uint32_t mul_app_group_id_dealloc(uint32_t id);
int mul_service_send_group_add(void *service,
                           uint64_t dpid,
                           struct of_group_mod_params *g_parms);
int mul_service_send_group_del(void *service,
                           uint64_t dpid, struct of_group_mod_params *g_parms);
void mul_app_send_pkt_out(void *sw_arg, uint64_t dpid, void *parms);
void *mul_app_create_service(char *name,
                             void (*service_handler)(void *service,
                                                     struct cbuf *msg));
void *mul_app_get_service(char *name, const char *server);
void *mul_app_get_service_notify(char *name,
                          void (*conn_update)(void *service,
                                              unsigned char conn_event),
                          bool retry_conn, const char *server);
void *
mul_app_get_service_notify_ka(char *name,
                              void (*conn_update)(void *service,
                                              unsigned char conn_event),
                              bool (*keepalive)(void *service),
                              bool retry_conn,
                              const char *server);
void mul_app_destroy_service(void *service);
bool mul_app_is_master(void);

mul_switch_t *c_app_switch_get_with_id(uint64_t dpid);
void c_app_traverse_all_switches(GHFunc iter_fn, void *arg);
void __c_app_traverse_all_switches(GHFunc iter_fn, void *arg);
uint8_t c_app_switch_get_version_with_id(uint64_t dpid);
uint64_t c_app_switch_get_dpid_with_alias(int alias);
void c_app_switch_put(mul_switch_t *sw);

void mul_app_act_alloc(mul_act_mdata_t *mdata);
void mul_app_act_free(mul_act_mdata_t *mdata);
size_t mul_app_act_len(mul_act_mdata_t *mdata);
size_t mul_app_act_buf_room(mul_act_mdata_t *mdata);
int mul_app_act_set_ctors(mul_act_mdata_t *mdata, uint64_t dpid);
int mul_app_inst_goto(mul_act_mdata_t *mdata, uint8_t table);
int mul_app_inst_meter(mul_act_mdata_t *mdata, uint32_t meter);
int mul_app_inst_wr_meta(mul_act_mdata_t *mdata, uint64_t metadata,
                     uint64_t metadata_mask);
int mul_app_set_inst_write(mul_act_mdata_t *mdata);
int mul_app_set_inst_apply(mul_act_mdata_t *mdata);
int mul_app_action_output(mul_act_mdata_t *mdata, uint32_t oport);
int mul_app_action_set_queue(mul_act_mdata_t *mdata, uint32_t queue);
int mul_app_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid);
int mul_app_action_strip_vlan(mul_act_mdata_t *mdata);
int mul_app_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac);
int mul_app_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac);
int mul_app_action_set_eth_type(mul_act_mdata_t *mdata, uint16_t eth_type);
int mul_app_action_push_hdr(mul_act_mdata_t *mdata, uint16_t eth_type);
int mul_app_action_strip_mpls(mul_act_mdata_t *mdata, uint16_t eth_type);
int mul_app_action_set_mpls_ttl(mul_act_mdata_t *mdata, uint8_t ttl);
int mul_app_action_set_mpls_label(mul_act_mdata_t *mdata, uint32_t label);
int mul_app_action_set_mpls_tc(mul_act_mdata_t *mdata, uint8_t tc);
int mul_app_action_set_mpls_bos(mul_act_mdata_t *mdata, uint8_t bos);
int mul_app_action_dec_mpls_ttl(mul_act_mdata_t *mdata);
int mul_app_action_set_nw_ttl(mul_act_mdata_t *mdata, uint8_t ttl);
int mul_app_action_dec_nw_ttl(mul_act_mdata_t *mdata);
int mul_app_action_cp_ttl(mul_act_mdata_t *mdata, bool in);
int mul_app_action_strip_pbb(mul_act_mdata_t *mdata);
int mul_app_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp);
int mul_app_action_set_nw_saddr(mul_act_mdata_t *mdata, uint32_t nw_saddr); 
int mul_app_action_set_nw_daddr(mul_act_mdata_t *mdata, uint32_t nw_daddr);
int mul_app_action_set_nw_saddr6(mul_act_mdata_t *mdata, uint8_t *nw_saddr); 
int mul_app_action_set_nw_daddr6(mul_act_mdata_t *mdata, uint8_t *nw_daddr);
int mul_app_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos);
int mul_app_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port);
int mul_app_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port);
int mul_app_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port);
int mul_app_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port);
int mul_app_action_set_group(mul_act_mdata_t *mdata, uint32_t group);
int mul_app_action_set_tunnel_id(mul_act_mdata_t *mdata, uint64_t tunnel);
int mul_app_set_band_drop(mul_act_mdata_t *mdata, struct of_meter_band_parms *parms);
int mul_app_set_band_dscp(mul_act_mdata_t *mdata, struct of_meter_band_parms *parms);
int mul_service_send_meter_add(void *service,uint64_t dpid, 
                               struct of_meter_mod_params *m_parms);
int mul_service_send_meter_del(void *service, uint64_t dpid,
                               struct of_meter_mod_params *m_parms);
int mul_service_send_port_mod(void *service, uint64_t dpid,
                              struct of_port_mod_params *pm_parms);
int mul_app_send_port_mod(uint64_t dpid,
                          struct of_port_mod_params *pm_parms);
int mul_service_send_async_config(void *service, uint64_t dpid,
                                  struct of_async_config_params *ac_parms);
int mul_app_send_loop_status(uint64_t status);
int mul_send_vendor_msg(uint64_t dpid, uint32_t vendor_id, void *arg, uint16_t arg_len);
bool mul_app_core_conn_available(void);
int mul_app_send_tr_status(uint64_t status);

#endif
