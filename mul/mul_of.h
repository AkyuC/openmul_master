/*
 *  mul_of.h: MUL openflow abstractions 
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
#ifndef __MUL_OF_H__
#define __MUL_OF_H__
    
#define OF_MAX_ACTION_LEN   1024

#define OF_PKT_NEXT_HDR(h_, tot, rem) ((void *)((uint8_t *)h_ + tot - rem))

#define OFP_HDR_SZ          sizeof(struct ofp_header)
#define NULL_OF_HANDLER     {NULL, sizeof(struct ofp_header), NULL}

#define FL_NEED_HW_SYNC(parms) (((parms)->flags & C_FL_ENT_NOSYNC) || \
                                (parms)->flags & C_FL_ENT_CLONE) ||   \
                                (parms)->flags & C_FL_ENT_RESIDUAL ||   \
                                ((parms)->flags & C_FL_ENT_LOCAL) ? false : true;

#define FL_EXM_NEED_HW_SYNC(parms) ((parms)->flags & C_FL_ENT_NOSYNC || \
                                    (parms)->flags & C_FL_ENT_LOCAL) ? false : true;

void            c_per_sw_topo_change_notify(void *k, void *v UNUSED, void *arg);
void            c_topo_loop_change_notify(bool loop_chg, uint64_t new_state,
                                          bool root_locked, bool clr_fdb);
void            c_set_tr_status(uint64_t new_status, bool root_locked);
bool            of_switch_port_validate_cb(void *sw, uint32_t port);
bool            of_switch_port_valid(c_switch_t *sw, struct flow *fl,
                                     struct flow *mask);
bool            of_switch_table_valid(c_switch_t *sw, uint8_t table);
void            c_sw_port_hton(struct c_sw_port *dst, struct c_sw_port *src);
int             of_validate_actions_strict(c_switch_t *sw, void *actions,
                                           size_t action_len);
void            of_send_features_request(c_switch_t *sw);
void            of_send_set_config(c_switch_t *sw, uint16_t flags, uint16_t miss_len);
void            of_send_echo_request(c_switch_t *sw);
void            of_send_hello(c_switch_t *sw);
void            of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms);
void            of_send_pkt_out_inline(void *sw, struct of_pkt_out_params *parms);
void            of_send_echo_reply(c_switch_t *sw, uint32_t xid);
void            __of_send_features_request(c_switch_t *sw);
void            __of_send_set_config(c_switch_t *sw, uint16_t flags, uint16_t miss_len);
void            __of_send_echo_request(c_switch_t *sw);
void            __of_send_hello(c_switch_t *sw);
void            __of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms);
void            __of_send_echo_reply(c_switch_t *sw, uint32_t xid);
void            c_switch_recv_msg(void *sw_arg, struct cbuf *b);
void            c_switch_add(c_switch_t *sw);
void            c_switch_del(c_switch_t *sw);
void            c_switch_mark_sticky_del(c_switch_t *sw);
void            c_switch_flow_tbl_delete(c_switch_t *sw);
void            c_switch_flow_tbl_reset(c_switch_t *sw);
int             of_flow_extract(uint8_t *pkt, struct flow *flow,
                                uint32_t in_port, size_t pkt_len, bool only_l2);
void            c_flow_entry_put(c_fl_entry_t *ent);
int             c_switch_flow_add(c_switch_t *sw,
                                  struct of_flow_mod_params *parms); 
int             c_switch_flow_del(c_switch_t *sw,
                                  struct of_flow_mod_params *parms);
void            c_per_switch_flow_resync_hw(void *k, void *v, void *arg);
void            c_flow_resync_hw_all(ctrl_hdl_t *c_hdl);
int             c_switch_group_add(c_switch_t *sw, struct of_group_mod_params *gp_parms);
int             c_switch_group_del(c_switch_t *sw, struct of_group_mod_params *gp_parms);
void            __c_per_switch_del_group_with_owner(c_switch_t *sw, void *app);
int             c_switch_meter_add(c_switch_t *sw, struct of_meter_mod_params *m_parms);
int             c_switch_meter_del(c_switch_t *sw, struct of_meter_mod_params *m_parms);
void            __c_per_switch_del_meter_with_owner(c_switch_t *sw, void *app);
typedef         void (*group_parser_fn)(void *arg, c_switch_group_t *ent); 
void            c_switch_group_traverse_all(c_switch_t *sw, void *u_arg, group_parser_fn fn);
typedef         void (*meter_parser_fn)(void *arg, c_switch_meter_t *ent); 
void            c_switch_meter_traverse_all(c_switch_t *sw, void *u_arg, meter_parser_fn fn);
int             of_send_flow_add_direct(c_switch_t *sw, struct flow *fl,
                            struct flow *mask, uint32_t buffer_id, void *actions,  
                            size_t action_len, uint16_t itimeo, 
                            uint16_t htimeo, uint16_t prio);
int             of_send_flow_del_direct(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t oport, bool strict, 
                             uint16_t prio, uint32_t group);
int             __of_send_flow_add_direct(c_switch_t *sw, struct flow *fl,
                            struct flow *mask, uint32_t buffer_id, void *actions,  
                            size_t action_len, uint16_t itimeo, 
                            uint16_t htimeo, uint16_t prio);
int             __of_send_flow_del_direct(c_switch_t *sw, struct flow *fl,
                         struct flow *mask, uint16_t oport, bool strict,
                         uint16_t prio, uint32_t group);
int             of_send_flow_stat_req(c_switch_t *sw, const struct flow *flow,
                             const struct flow *mask, uint32_t oport,
                             uint32_t grp);
int             __of_send_flow_stat_req(c_switch_t *sw, const struct flow *flow,
                             const struct flow *mask, uint32_t oport,
                             uint32_t grp);
void            __of_send_mpart_msg(c_switch_t *sw, uint16_t type, uint16_t flags,
                                    size_t body_len);
void            __of_send_q_stat_req(c_switch_t *sw, uint32_t port, uint32_t queue);
void            __of_send_barrier_request(c_switch_t *sw);
int             of_send_group_stat_req(c_switch_t *sw, uint32_t group_id);
int             __of_send_group_stat_req(c_switch_t *sw, uint32_t group_id);
int             of_send_meter_stat_req(c_switch_t *sw, uint32_t meter_id);
int             __of_send_meter_stat_req(c_switch_t *sw, uint32_t meter_id);
int             of_send_meter_config_stat_req(c_switch_t *sw,
                                              uint32_t meter_id);
int             __of_send_meter_config_stat_req(c_switch_t *sw,
                                                uint32_t meter_id);
int             of_send_port_stat_req(c_switch_t *sw, uint32_t port_no);
int             __of_send_port_stat_req(c_switch_t *sw, uint32_t port_no);
int             of_send_port_q_get_conf(c_switch_t *sw, uint32_t port_no);
int             __of_send_port_q_get_conf(c_switch_t *sw, uint32_t port_no);
void            __of_send_clear_all_groups(c_switch_t *sw);
void            __of_send_clear_all_meters(c_switch_t *sw);
void            __of_send_role_request(c_switch_t *sw);
int             __of_send_vendor_msg(c_switch_t *sw,
                                     struct of_vendor_params *vp);
void            c_per_switch_stats_scan(c_switch_t *sw, time_t curr_time);
bool            of_switch_table_supported(c_switch_t *sw, uint8_t table);
char            *of_dump_fl_app(c_fl_entry_t *ent);
typedef         void (*flow_parser_fn)(void *arg, c_fl_entry_t *ent); 
void            c_flow_traverse_tbl_all(c_switch_t *sw, void *u_arg, flow_parser_fn fn);
void            __c_per_switch_del_app_flow_owner(c_switch_t *sw, void *app);
int             __c_flow_find_app_owner(void *key_arg UNUSED, void *ent_arg, void *app);
void            *c_switch_alloc(void *ctx);
c_switch_t      *c_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid);
c_switch_t      *c_switch_alias_get(ctrl_hdl_t *ctrl, int alias);
c_switch_t      *__c_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid);
void            c_switch_put(c_switch_t *sw);
void            c_switch_try_publish(c_switch_t *sw, bool need_ha_sync_req);
void            of_switch_brief_info(c_switch_t *sw,
                                     struct c_ofp_switch_brief *cofp_sb);
void            of_switch_detail_info(c_switch_t *sw,
                                      struct ofp_switch_features *osf);
void            c_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc dump_fn, void *arg);
void            __c_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc dump_fn, void *arg);
void            __c_switch_port_traverse_all(c_switch_t *sw, GHFunc iter_fn, void *arg);
void            __c_port_q_traverse_all(c_port_t *port, GHFunc iter_fn, void *arg);
void            c_switch_port_q_traverse_all(c_switch_t *sw, uint32_t port_no,
                                             GHFunc iter_fn, void *arg);
int             of_dfl_fwd(struct c_switch *sw, struct cbuf *b, void *data,
                           size_t pkt_len, struct c_pkt_in_mdata *mdata,
                           uint32_t in_port);
int             of_dfl_port_status(c_switch_t *sw, uint32_t port,
                                   uint32_t cfg, uint32_t state,
                                   struct c_port_cfg_state_mask *mask);
void            of131_send_pkt_out_inline(void *arg, struct of_pkt_out_params *parms);

bool            c_of_fl_group_check_add(void *sw_arg, uint32_t group_id, void *arg);
struct cbuf *   c_of_prep_group_mod_msg(c_switch_group_t *grp, bool add);
bool            c_of_fl_meter_check_add(void *sw_arg, uint32_t group_id, void *arg);
struct cbuf *   c_of_prep_meter_mod_msg(c_switch_meter_t *meter, bool add);
struct cbuf *   c_of_prep_group_feature_msg(c_switch_t *sw);
struct cbuf *   c_of_prep_meter_feature_msg(c_switch_t *sw);
struct cbuf *   c_of_prep_table_feature_msg(c_switch_t *sw, uint8_t table_id);
struct cbuf *   c_ofp_prep_flow_mod(c_switch_t *sw, c_fl_entry_t *ent,
                                    bool add);
void            c_switch_async_config(c_switch_t *sw,
                        struct of_async_config_params *ac_params);
struct cbuf *   c_of_prep_switch_rlims(c_switch_t *sw, bool rx, bool get);
void            c_switch_rlim_sync(c_switch_t *sw);
struct cbuf *   c_of_prep_switch_stats_strategy(c_switch_t *sw);
void            c_switch_stats_strategy_sync(c_switch_t *sw);
void            c_switch_stats_mode_sync(c_switch_t *sw);
void            c_switch_async_config(c_switch_t *sw,
                            struct of_async_config_params *ac_params);
struct cbuf *   c_of_prep_switch_table_stats(c_switch_t *sw, uint8_t table_id);
struct cbuf *   c_of_prep_port_stats(c_switch_t *sw, uint32_t port_no);
int c_switch_port_mod(c_switch_t *sw, struct of_port_mod_params *pm_parms);
#endif
