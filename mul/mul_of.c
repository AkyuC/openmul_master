/*
 *  mul_of.c: MUL openflow abstractions 
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

#include "mul.h"

extern ctrl_hdl_t ctrl_hdl;
extern struct c_rlim_dat crl; 

static void of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, 
                             uint32_t buffer_id, bool ha_sync, bool mod);
static void of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent,
                             uint16_t oport, bool strict, uint32_t group);
static void of_send_flow_del_strict(c_switch_t *sw, c_fl_entry_t *ent,
                                    uint16_t oport, uint32_t group);
static void c_switch_flow_table_enable(c_switch_t *sw, uint8_t table_id);
static c_fl_entry_t *__c_flow_get_exm(c_switch_t *sw, struct flow *fl);
static void c_flow_rule_free(void *arg, void *u_arg);
static void port_config_to_ofxlate(uint32_t *of_port_config, uint32_t config);
static void port_status_to_ofxlate(uint32_t *of_port_config, uint32_t status);
static void c_switch_group_ent_free(void *arg);
static void c_switch_meter_ent_free(void *arg);
static uint32_t c_fl_cookie_hash(const void *key);
static int c_fl_cookie_match(const void *v1, const void *v2);
static int c_switch_bulk_flow_scan(c_switch_t *sw, bool force);

struct c_ofp_rx_handler of_boot_handlers[];
struct c_ofp_rx_handler of_init_handlers[];
struct c_ofp_rx_handler of131_init_handlers[];
struct c_ofp_rx_handler of140_init_handlers[];
struct c_ofp_rx_handler of_handlers[];
struct c_ofp_rx_handler of131_handlers[];
struct c_ofp_rx_handler of140_handlers[];
struct c_ofp_proc_helpers ofp_priv_procs;
struct c_ofp_proc_helpers ofp131_priv_procs;
struct c_ofp_proc_helpers ofp140_priv_procs;

static struct c_ofp_ctors of10_ctors = {
    .hello = of_prep_hello,
    .echo_req = of_prep_echo,
    .echo_rsp = of_prep_echo_reply,
    .set_config = of_prep_set_config,
    .features = of_prep_features_request,
    .pkt_out = of_prep_pkt_out_msg,
    .pkt_out_fast = of_send_pkt_out_inline,
    .flow_add = of_prep_flow_add_msg,
    .flow_del = of_prep_flow_del_msg,
    .flow_stat_req = of_prep_flow_stat_msg,
    .port_stat_req = of_prep_port_stat_msg,
    .port_mod = of_prep_port_mod_msg,
    .prep_vendor_msg = of_prep_vendor_msg,
    .normalize_flow = of10_flow_correction,
    .validate_acts = of_validate_actions,
    .act_output = of_make_action_output,
    .act_set_vid = of_make_action_set_vid,
    .act_strip_vid = of_make_action_strip_vlan,
    .act_set_dmac = of_make_action_set_dmac,
    .act_set_smac = of_make_action_set_smac,
    .act_set_nw_saddr = of_make_action_set_nw_saddr,
    .act_set_nw_daddr = of_make_action_set_nw_daddr,
    .act_set_vlan_pcp = of_make_action_set_vlan_pcp,
    .act_set_nw_tos = of_make_action_set_nw_tos,
    .act_set_tp_udp_dport = of_make_action_set_tp_udp_dport,
    .act_set_tp_udp_sport = of_make_action_set_tp_udp_sport,
    .act_set_tp_tcp_dport = of_make_action_set_tp_tcp_dport,
    .act_set_tp_tcp_sport = of_make_action_set_tp_tcp_sport,
    .dump_flow = of10_dump_flow,
    .dump_acts = of10_dump_actions,
    .flow_stats_support = of_switch_supports_flow_stats,
};

static struct c_ofp_ctors of131_ctors = {
    .hello = of131_prep_hello_msg, 
    .echo_req = of131_prep_echo_msg,
    .echo_rsp = of131_prep_echo_reply_msg,
    .set_config = of131_prep_set_config_msg,
    .role_request = of131_prep_role_request_msg,
    .features = of131_prep_features_request_msg,
    .pkt_out = of131_prep_pkt_out_msg,
    .pkt_out_fast = of131_send_pkt_out_inline,
    .flow_add = of131_prep_flow_add_msg,
    .flow_del = of131_prep_flow_del_msg,
    .flow_stat_req = of131_prep_flow_stat_msg,
    .group_stat_req = of131_prep_group_stat_req,
    .meter_stat_req = of131_prep_meter_stat_req,
    .meter_stat_cfg_req = of131_prep_meter_config_req,
    .port_stat_req = of131_prep_port_stat_req,
    .port_q_get_conf = of131_prep_q_get_config,
    .port_q_stat_req = of131_prep_queue_stat_msg,
    .group_validate = of131_group_validate_parms,
    .validate_acts = of131_validate_actions,
    .normalize_flow = of131_flow_normalize,
    .group_validate_feat = of131_group_validate_feat,
    .meter_validate_feat = of131_meter_validate_feat,
    .group_add = of131_prep_group_add_msg,
    .group_del = of131_prep_group_del_msg,
    .meter_add = of131_prep_meter_add_msg,
    .meter_del = of131_prep_meter_del_msg,
    .port_mod = of131_prep_port_mod_msg,
    .prep_mpart_msg = of131_prep_mpart_msg,
    .prep_barrier_req = of131_prep_barrier_req,
    .async_config = of131_prep_async_config,
    .inst_goto = of131_make_inst_goto,
    .inst_meter = of131_make_inst_meter,
    .act_output = of131_make_action_output,
    .act_set_vid = of131_make_action_set_vid,
    .act_strip_vid = of131_make_action_strip_vlan,
    .act_push = of131_make_action_push,
    .act_strip_mpls = of131_make_action_strip_mpls,
    .act_strip_pbb = of131_make_action_strip_pbb,
    .act_set_mpls_ttl = of131_make_action_set_mpls_ttl,
    .act_dec_mpls_ttl = of131_make_action_dec_mpls_ttl,
    .act_set_ip_ttl = of131_make_action_set_ip_ttl,
    .act_dec_ip_ttl = of131_make_action_dec_ip_ttl,
    .act_cp_ttl = of131_make_action_cp_ttl,
    .act_set_dmac = of131_make_action_set_dmac,
    .act_set_smac = of131_make_action_set_smac,
    .act_set_eth_type = of131_make_action_set_eth_type,
    .act_set_mpls_label = of131_make_action_set_mpls_label,
    .act_set_mpls_tc = of131_make_action_set_mpls_tc,
    .act_set_mpls_bos = of131_make_action_set_mpls_bos,
    .act_set_nw_saddr = of131_make_action_set_ipv4_src,
    .act_set_nw_daddr = of131_make_action_set_ipv4_dst, 
    .act_set_vlan_pcp = of131_make_action_set_vlan_pcp,
    .act_set_nw_tos = of131_make_action_set_nw_tos,
    .act_set_tp_udp_dport = of131_make_action_set_tp_udp_dport,
    .act_set_tp_udp_sport = of131_make_action_set_tp_udp_sport,
    .act_set_tp_tcp_dport = of131_make_action_set_tp_tcp_dport,
    .act_set_tp_tcp_sport = of131_make_action_set_tp_tcp_sport,
    .act_set_group = of131_make_action_group,
    .act_set_queue = of131_make_action_set_queue,
    .act_set_tunnel = of131_make_action_set_tunnel_id,
    .meter_drop = of131_make_meter_band_drop,
    .meter_mark_dscp = of131_make_meter_band_mark_dscp, 
    .dump_flow = of_dump_flow_generic,
    .dump_acts = of131_dump_actions,    
    .dump_of_msg = of131_dump_msg, 
    .multi_table_support = of131_supports_multi_tables,
    .flow_stats_support = of131_switch_supports_flow_stats,
    .group_stats_support = of131_switch_supports_group_stats,
    .table_stats_support = of131_switch_supports_table_stats
};

static struct c_ofp_ctors of140_ctors = {
    .hello = of140_prep_hello_msg, 
    .echo_req = of140_prep_echo_msg,
    .echo_rsp = of140_prep_echo_reply_msg,
    .set_config = of131_prep_set_config_msg,
    .role_request = of131_prep_role_request_msg,
    .features = of140_prep_features_request_msg,
    .pkt_out = of131_prep_pkt_out_msg,
    .pkt_out_fast = of131_send_pkt_out_inline,
    .flow_add = of140_prep_flow_add_msg,
    .flow_del = of140_prep_flow_del_msg,
    .flow_stat_req = of140_prep_flow_stat_msg,
    .group_stat_req = of140_prep_group_stat_req,
    .meter_stat_req = of140_prep_meter_stat_req,
    .meter_stat_cfg_req = of140_prep_meter_config_req,
    .port_stat_req = of140_prep_port_stat_req,
    .port_q_get_conf = of131_prep_q_get_config,
    .port_q_stat_req = of140_prep_queue_stat_msg,
    .group_validate = of131_group_validate_parms,
    .validate_acts = of131_validate_actions,
    .normalize_flow = of131_flow_normalize,
    .group_validate_feat = of131_group_validate_feat,
    .meter_validate_feat = of131_meter_validate_feat,
    .group_add = of140_prep_group_add_msg,
    .group_del = of140_prep_group_del_msg,
    .meter_add = of140_prep_meter_add_msg,
    .meter_del = of140_prep_meter_del_msg,
    .port_mod = of140_prep_port_mod_msg,
    .prep_mpart_msg = of140_prep_mpart_msg,
    .prep_barrier_req = of131_prep_barrier_req,
    .async_config = of131_prep_async_config,
    .inst_goto = of131_make_inst_goto,
    .inst_meter = of131_make_inst_meter,
    .act_output = of131_make_action_output,
    .act_set_vid = of131_make_action_set_vid,
    .act_strip_vid = of131_make_action_strip_vlan,
    .act_push = of131_make_action_push,
    .act_strip_mpls = of131_make_action_strip_mpls,
    .act_strip_pbb = of131_make_action_strip_pbb,
    .act_set_mpls_ttl = of131_make_action_set_mpls_ttl,
    .act_dec_mpls_ttl = of131_make_action_dec_mpls_ttl,
    .act_set_ip_ttl = of131_make_action_set_ip_ttl,
    .act_dec_ip_ttl = of131_make_action_dec_ip_ttl,
    .act_cp_ttl = of131_make_action_cp_ttl,
    .act_set_dmac = of131_make_action_set_dmac,
    .act_set_smac = of131_make_action_set_smac,
    .act_set_eth_type = of131_make_action_set_eth_type,
    .act_set_mpls_label = of131_make_action_set_mpls_label,
    .act_set_mpls_tc = of131_make_action_set_mpls_tc,
    .act_set_mpls_bos = of131_make_action_set_mpls_bos,
    .act_set_nw_saddr = of131_make_action_set_ipv4_src,
    .act_set_nw_daddr = of131_make_action_set_ipv4_dst, 
    .act_set_vlan_pcp = of131_make_action_set_vlan_pcp,
    .act_set_nw_tos = of131_make_action_set_nw_tos,
    .act_set_tp_udp_dport = of131_make_action_set_tp_udp_dport,
    .act_set_tp_udp_sport = of131_make_action_set_tp_udp_sport,
    .act_set_tp_tcp_dport = of131_make_action_set_tp_tcp_dport,
    .act_set_tp_tcp_sport = of131_make_action_set_tp_tcp_sport,
    .act_set_group = of131_make_action_group,
    .act_set_queue = of131_make_action_set_queue,
    .act_set_tunnel = of131_make_action_set_tunnel_id,
    .meter_drop = of131_make_meter_band_drop,
    .meter_mark_dscp = of131_make_meter_band_mark_dscp, 
    .dump_flow = of_dump_flow_generic,
    .dump_acts = of131_dump_actions,    
    .dump_of_msg = of131_dump_msg, 
    .multi_table_support = of131_supports_multi_tables,
    .flow_stats_support = of131_switch_supports_flow_stats,
    .group_stats_support = of131_switch_supports_group_stats,
    .table_stats_support = of131_switch_supports_table_stats
};

static struct c_ofp_ctors of_unk_ctors = {
     .hello = of140_prep_hello_msg, 
    .echo_req = of140_prep_echo_msg,
    .echo_rsp = of140_prep_echo_reply_msg,
};

static void
c_ha_get_of_state(uint32_t *role, uint64_t *gen_id)
{
    switch(ctrl_hdl.ha_state) {
    case C_HA_STATE_NONE:
    case C_HA_STATE_CONNECTED:
    case C_HA_STATE_NOHA:
    case C_HA_STATE_CONFLICT:
        *role = OFPCR_ROLE_EQUAL;
        break;
    case C_HA_STATE_MASTER:
        *role = OFPCR_ROLE_MASTER;
        break;
    case C_HA_STATE_SLAVE:
        *role = OFPCR_ROLE_SLAVE;
        break;
    }

    *gen_id = ctrl_hdl.gen_id;
}

void
c_per_sw_topo_change_notify(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    uint64_t status = *(uint64_t *)arg;

    c_wr_lock(&sw->lock);

    if (sw->fp_ops.fp_topo_change)
        sw->fp_ops.fp_topo_change(sw, status, true);

    c_wr_unlock(&sw->lock);
}

void
c_topo_loop_change_notify(bool loop_chg, uint64_t new_state,
                          bool root_locked, bool clr_fdb)
{
    if (!root_locked) c_wr_lock(&ctrl_hdl.lock);

    if (loop_chg) {
        if (ctrl_hdl.loop_status != new_state) {
            c_log_debug("|TOPO| State change %llu to %llu",
                        U642ULL(ctrl_hdl.loop_status), U642ULL(new_state));
            if (clr_fdb && ctrl_hdl.loop_en) {
                __c_switch_traverse_all(&ctrl_hdl,
                                        c_per_sw_topo_change_notify,
                                        &new_state);
            }
            ctrl_hdl.loop_status = new_state;
            mb();
        }
    } else {
        if (clr_fdb && !ctrl_hdl.loop_en)
            __c_switch_traverse_all(&ctrl_hdl,
                                    c_per_sw_topo_change_notify,
                                    &new_state);
        if(ctrl_hdl.tr_status != new_state) {
            ctrl_hdl.tr_status = new_state;
            mb();
            c_log_debug("|TOPO| RT Conv Status change %llu to %llu",
                         U642ULL(ctrl_hdl.tr_status), U642ULL(new_state));
        }
    }
    if (!root_locked) c_wr_unlock(&ctrl_hdl.lock);
}

static inline int
c_flow_mod_validate_parms(c_switch_t *sw,
                          struct of_flow_mod_params *fl_parms)
{
    if (!of_switch_table_supported(sw, fl_parms->flow->table_id) || 
        (!fl_parms->app_owner) ||
        (fl_parms->flags & C_FL_ENT_CLONE && fl_parms->flags & C_FL_ENT_LOCAL) ||
        (fl_parms->flags & C_FL_ENT_NOCACHE)) { 
        c_log_err("[FLOW] Invalid flow mod flags %d %d %d %d",
                  !of_switch_table_supported(sw, fl_parms->flow->table_id),
                  (!fl_parms->app_owner), 
                  (fl_parms->flags & C_FL_ENT_CLONE && 
                   fl_parms->flags & C_FL_ENT_LOCAL),
                  (int)(fl_parms->flags & C_FL_ENT_NOCACHE));
        return -1;
    }

    return 0;
}

static inline int
of_exm_flow_mod_validate_parms(c_switch_t *sw,
                               struct of_flow_mod_params *fl_parms)
{
    if (!of_switch_table_supported(sw, fl_parms->flow->table_id) ||
        fl_parms->flags & C_FL_ENT_CLONE || fl_parms->flags & C_FL_ENT_NOCACHE || 
        !fl_parms->app_owner) { 
        c_log_err("[FLOW] Invalid exm-flow mod flags");
        return -1;
    }

    return 0;
}

static inline void
c_switch_tx(c_switch_t *sw, struct cbuf *b, bool only_q)
{
    if (sw->tx_dump_en && sw->ofp_ctors->dump_of_msg) {
        sw->ofp_ctors->dump_of_msg(b, true, sw->DPID);
    }

    c_thread_tx(&sw->conn, b, only_q);
}

static inline void
c_switch_chain_tx(c_switch_t *sw, struct cbuf **b, size_t nbufs)
{
    c_thread_chain_tx(&sw->conn, b, nbufs);
}

static void
c_sw_exp_ent_free(void *ent_arg)
{
    struct c_sw_expired_ent *ent = ent_arg;
    if (ent_arg) {
        if (ent->app) {
            c_app_unref(ent->app);
        }
        if (ent->b) {
            free_cbuf(ent->b);
        }
    }
    free(ent_arg);
    return;
}

static void
c_flow_app_ref_free(void *arg UNUSED)
{
    /* Nothing to do */
    return;
}

char *
of_dump_fl_app(c_fl_entry_t *ent)  
{
    c_app_info_t *app;
    GSList *iterator; 
#define FL_APP_BUF_SZ 1024
    char *pbuf = calloc(1, FL_APP_BUF_SZ);
    int len = 0;
    
    len += snprintf(pbuf+len, FL_APP_BUF_SZ-len-1, "Owner: ");
    assert(len < FL_APP_BUF_SZ-1);

    c_rd_lock(&ent->FL_LOCK);
    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        len += snprintf(pbuf+len, FL_APP_BUF_SZ-len-1, "%s ", app->app_name);
        assert(len < FL_APP_BUF_SZ-1);
    }
    c_rd_unlock(&ent->FL_LOCK);

    return pbuf;
}

/* 
 * of_switch_port_valid - 
 *
 */
bool
of_switch_port_valid(c_switch_t *sw, struct flow *fl, struct flow *mask)
{
    bool valid = true;
    if (mask->in_port) {
        c_rd_lock(&sw->lock);
        valid = __c_switch_port_valid(sw, ntohl(fl->in_port));
        c_rd_unlock(&sw->lock);
    }

    return valid;
}

/* 
 * of_switch_port_validate_cb - 
 *
 */
bool
of_switch_port_validate_cb(void *sw_arg, uint32_t port)
{
    c_switch_t *sw = sw_arg;
    bool valid = true;
    c_rd_lock(&sw->lock);
    valid = __c_switch_port_valid(sw, port);
    c_rd_unlock(&sw->lock);

    return valid;
}

/* 
 * of_switch_table_valid - 
 *
 */
bool
of_switch_table_valid(c_switch_t *sw, uint8_t table)
{
    bool valid = true;
    c_flow_tbl_t *tbl;

    /* We allow table 0 always */
    c_rd_lock(&sw->lock);
    if (table && sw->ofp_ctors && sw->ofp_ctors->multi_table_support) {
        tbl = &sw->rule_flow_tbls[table];
        valid = tbl->hw_tbl_active ? true: false; 
    }
    c_rd_unlock(&sw->lock);

    return valid;
}

/* 
 * of_switch_get_next_valid_table - 
 *
 */
static int
of_switch_get_next_valid_table(c_switch_t *sw, uint8_t table)
{
    c_flow_tbl_t *tbl;
    int i = 0;

    if (!sw->ofp_ctors ||
        !sw->ofp_ctors->multi_table_support)
        return -1;

    c_rd_lock(&sw->lock);
    for (i = table+1; i < C_MAX_RULE_FLOW_TBLS; i++) {
        tbl = &sw->rule_flow_tbls[i];
        if (tbl->hw_tbl_active) {
            c_rd_unlock(&sw->lock);
            return i;
        }
    }
    c_rd_unlock(&sw->lock);

    return -1;
}


void
c_sw_port_hton(struct c_sw_port *dst, struct c_sw_port *src)
{
    dst->port_no = htonl(src->port_no);
    memcpy(dst->name, src->name, OFP_MAX_PORT_NAME_LEN);
    memcpy(dst->hw_addr, src->hw_addr, OFP_ETH_ALEN);
    dst->config = htonl(src->config);
    dst->state = htonl(src->state);
    dst->of_config = htonl(src->of_config);
    dst->of_state = htonl(src->of_state);

    dst->curr = htonl(src->curr);
    dst->advertised = htonl(src->advertised);
    dst->supported = htonl(src->supported);
    dst->peer = htonl(src->peer);
}

static unsigned int
of_switch_hash_key (const void *p)
{
    c_switch_t *sw = (c_switch_t *) p;

    return (unsigned int)(sw->DPID);
}

static int 
of_switch_hash_cmp (const void *p1, const void *p2)
{
    const c_switch_t *sw1 = (c_switch_t *) p1;
    const c_switch_t *sw2 = (c_switch_t *) p2;

    if (sw1->DPID == sw2->DPID) {
        return 1; /* TRUE */
    } else {
        return 0; /* FALSE */
    }
}

void
c_switch_add(c_switch_t *sw)
{
    struct c_cmn_ctx *cmn_ctx = sw->ctx;
    ctrl_hdl_t *ctrl          = cmn_ctx->c_hdl; 
    c_switch_t *old_sw;

    c_wr_lock(&ctrl->lock);
    if (!ctrl->sw_hash_tbl) {
        ctrl->sw_hash_tbl = g_hash_table_new(of_switch_hash_key, 
                                             of_switch_hash_cmp);
    } else {
        if ((old_sw =__c_switch_get(ctrl, sw->DPID))) {
            c_log_err("[SWITCH] switch |0x%llx| exists", sw->DPID);
            c_switch_put(old_sw);
            c_wr_unlock(&ctrl->lock);
            return;
        }
    }

    g_hash_table_insert(ctrl->sw_hash_tbl, sw, sw);
    if ((sw->alias_id = ipool_get(ctrl->sw_ipool, sw)) < 0) {
        /* Throw a log and continue as we still can continue */
        c_log_err("[SWITCH} |0x%llx\n| alias error", sw->DPID);
    }

    c_wr_unlock(&ctrl->lock);

}

static int 
c_switch_clone_on_conn(c_switch_t *sw, c_switch_t *old_sw)
{
    if (old_sw == sw) {
        return SW_CLONE_USE;
    }

    if (!(old_sw->switch_state & SW_DEAD)) {
        return SW_CLONE_DENY;
    }

    return SW_CLONE_OLD;
}

void
c_switch_del(c_switch_t *sw)
{
    struct c_cmn_ctx *cmn_ctx = sw->ctx;
    ctrl_hdl_t *ctrl          = cmn_ctx->c_hdl;

    c_conn_destroy(&sw->conn);
    c_conn_destroy(&sw->ha_conn);

    c_wr_lock(&ctrl->lock);
    if (ctrl->sw_hash_tbl) {
       g_hash_table_remove(ctrl->sw_hash_tbl, sw);
    }

    if (ctrl->sw_ipool) {
        if (sw->switch_state & SW_REGISTERED)
            ipool_put(ctrl->sw_ipool, sw->alias_id);
    }
    c_wr_unlock(&ctrl->lock);

    if (sw->switch_state & SW_REGISTERED)
        c_signal_app_event(sw, NULL, C_DP_UNREG, NULL, NULL, false);

    sw->switch_state |= SW_DEAD;
}

void
c_switch_mark_sticky_del(c_switch_t *sw)
{
    sw->last_refresh_time = time(NULL);
    sw->switch_state |= SW_DEAD;
}

static void
c_switch_port_free(void *arg)
{
    c_port_t *port = arg;
    if (port->port_stats)
        free(port->port_stats);
    port->port_stats = NULL;
    if (port->pkt_qs)
        g_hash_table_destroy(port->pkt_qs);
    port->pkt_qs = NULL;
    free(arg);
}

static void
c_switch_q_free(void *arg)
{
    c_pkt_q_t *q = arg;
    if (q->q_prop)
        free(q->q_prop);
    if (q->q_stats)
        free(q->q_stats);
    free(arg);
}

void *
c_switch_alloc(void *ctx)
{
    c_switch_t *new_switch;

    new_switch = calloc(1, sizeof(c_switch_t));
    assert(new_switch);

    new_switch->switch_state = SW_INIT;
    new_switch->version = OFP_MUL_SB_VERSION;
    new_switch->ctx = ctx;
    new_switch->last_refresh_time = time(NULL);
    c_rw_lock_init(&new_switch->lock);
    c_rw_lock_init(&new_switch->conn.conn_lock);
    cbuf_list_head_init(&new_switch->conn.tx_q);
    new_switch->ofp_rx_handler_sz = OFPT_BARRIER_REPLY;
    new_switch->ofp_rx_handlers = of_boot_handlers;
    new_switch->ofp_ctors = &of_unk_ctors;
    new_switch->rx_lim_on = false;
    c_rlim_dat_init(&new_switch->rx_rlim, 1000, C_PER_SW_DFL_PPS);
    c_rlim_dat_init(&new_switch->tx_rlim, 1000, C_PER_SW_DFL_PPS);
    new_switch->sw_ports =  g_hash_table_new_full(g_int_hash,
                                                  g_int_equal,
                                                  NULL,
                                                  c_switch_port_free);

    assert(new_switch->sw_ports);
    new_switch->groups =  g_hash_table_new_full(g_int_hash,
                                                g_int_equal,
                                                NULL,
                                                c_switch_group_ent_free);
    assert(new_switch->groups);
    new_switch->meters =  g_hash_table_new_full(g_int_hash,
                                                g_int_equal,
                                                NULL,
                                                c_switch_meter_ent_free);
    assert(new_switch->meters);

    if (ctrl_hdl.dfl_dump_pkts) {
        new_switch->rx_dump_en = true;
        new_switch->tx_dump_en = true;
    }

    return new_switch;
}

c_switch_t *
c_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid)
{
    c_switch_t       key, *sw = NULL; 
    unsigned int     found;

    if (!ctrl->sw_hash_tbl) {
        return NULL;
    }

    key.datapath_id = dpid;

    c_rd_lock(&ctrl->lock);

    found = g_hash_table_lookup_extended(ctrl->sw_hash_tbl, &key, 
                                         NULL, (gpointer*)&sw);
    if (found) {
        atomic_inc(&sw->ref, 1);
    }

    c_rd_unlock(&ctrl->lock);

    return sw;
}

c_switch_t *
c_switch_alias_get(ctrl_hdl_t *ctrl, int alias)
{
    c_switch_t       *sw; 

    c_rd_lock(&ctrl->lock);

    sw = ipool_idx_priv(ctrl->sw_ipool, alias);
    if (sw) {
        atomic_inc(&sw->ref, 1);
    }

    c_rd_unlock(&ctrl->lock);

    return sw;
}

c_switch_t *
__c_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid)
{
    c_switch_t       key, *sw = NULL; 
    unsigned int     found;

    key.datapath_id = dpid;

    if (ctrl->sw_hash_tbl) {
        found = g_hash_table_lookup_extended(ctrl->sw_hash_tbl, &key, 
                                             NULL, (gpointer*)&sw);
        if (found) {
            atomic_inc(&sw->ref, 1);
        }

    }

    return sw;
}

void
c_switch_put(c_switch_t *sw)
{
    if (atomic_read(&sw->ref) == 0){
        c_log_debug("[Switch] |0x:%llx| FREED", sw->DPID);

        c_switch_flow_tbl_delete(sw);

        if (sw->fp_ops.fp_db_dtor) {
            sw->fp_ops.fp_db_dtor(sw, true);
        }
        if (sw->exp_list) g_slist_free_full(sw->exp_list, 
                                            c_sw_exp_ent_free);
        if (sw->meter_features) free(sw->meter_features);
        if (sw->group_features) free(sw->group_features);
        if (sw->sw_ports) g_hash_table_destroy(sw->sw_ports);
        if (sw->groups) g_hash_table_destroy(sw->groups);
        if (sw->meters) g_hash_table_destroy(sw->meters);
        if (sw->sav_b) free(sw->sav_b);
        c_rw_lock_destroy(&sw->lock);
        free(sw);
    } else {
        atomic_dec(&sw->ref, 1);
    }
}

static void
__c_switch_update_probe_state(c_switch_t *sw, uint64_t next_state)
{
     sw->start_probe = 0;
     sw->last_probed = 0;
     sw->switch_state |= next_state; 
}

void
c_switch_try_publish(c_switch_t *sw, bool need_ha_sync_req UNUSED)
{
    struct flow  flow;
    struct flow  mask;
    time_t ctime = time(NULL);

    memset(&flow, 0, sizeof(flow));
    of_mask_set_dc_all(&mask);

    if (sw->switch_state & SW_PUBLISHED)
        return;

    /* SW_OFP_TBL/GRP/MET_FEAT -
         is not checked to allow OVS to work for Of1.3+ */
    if (sw->switch_state & SW_REGISTERED) {
        if ((sw->switch_state &
             SW_OFP_PORT_FEAT) == SW_OFP_PORT_FEAT) {
             __c_switch_update_probe_state(sw,
                                    SW_FLOW_PROBED | SW_FLOW_PROBE_DONE |
                                    SW_METER_PROBED | SW_METER_PROBE_DONE |
                                    SW_GROUP_PROBED | SW_GROUP_PROBE_DONE);
            if (!(sw->switch_state & SW_PUBLISHED)) {
                if (!(sw->switch_state & SW_OFP_TBL_FEAT)) {
                    /* OVS1.3+ does not support Table features so we enable our
                     * minimal required tables 
                     */
                    if (sw->n_tables >= C_OPT_NO_TABLES) {
                        c_switch_flow_table_enable(sw, 2);
                        c_switch_flow_table_enable(sw, 1);
                        c_switch_flow_table_enable(sw, 0);
                    }
                    sw->switch_state |= SW_OFP_TBL_FEAT;
                }
 
                c_log_debug("|SWITCH| Publishing 0x%llx", U642ULL(sw->DPID));
                c_signal_app_event(sw, sw->sav_b, C_DP_REG, NULL, NULL, false);
                if (sw->sav_b) free (sw->sav_b);
                sw->sav_b = NULL;
                sw->switch_state |= SW_PUBLISHED;
            }
        } else {
            if (sw->last_feat_probed &&
                ctime - sw->last_feat_probed > C_SWITCH_FEAT_PROBE_TIMEO) {
                /* Get all the table features */
                __of_send_mpart_msg(sw, OFPMP_TABLE_FEATURES, 0, 0);
                /* Get all the group features */
                 __of_send_mpart_msg(sw, OFPMP_GROUP_FEATURES, 0, 0);
                /* Get all the meter features */
                __of_send_mpart_msg(sw, OFPMP_METER_FEATURES, 0, 0);
                /* There is no port info in features reply. Get it! */
                __of_send_mpart_msg(sw, OFPMP_PORT_DESC, 0, 0);
                sw->last_feat_probed = ctime;
                c_log_debug("|SWITCH| Port Probe for |0x%llx|",
                        U642ULL(sw->DPID));
            }
        }
    }
}

static int 
__c_switch_port_add(c_switch_t *sw, c_port_t *port_desc)
{
    c_port_t *new_port_desc = NULL;
    assert(port_desc);
    if (port_desc->sw_port.port_no &&
        !(new_port_desc =
            __c_switch_port_find(sw, port_desc->sw_port.port_no))) {
        new_port_desc = calloc(1, sizeof(*new_port_desc));
        if (new_port_desc) {
            new_port_desc->pkt_qs =  g_hash_table_new_full(g_int_hash,
                                                g_int_equal,
                                                NULL,
                                                c_switch_q_free);
            memcpy(&new_port_desc->sw_port,
                   &port_desc->sw_port, sizeof(c_sw_port_t));
            g_hash_table_insert(sw->sw_ports, &new_port_desc->sw_port.port_no,
                                new_port_desc);
            sw->n_ports++;
            return 0;
        }
    } else if (new_port_desc) {
        memcpy(&new_port_desc->sw_port,
               &port_desc->sw_port, sizeof(c_sw_port_t));
    }

    return -1;
}

static void
__c_switch_port_delete(c_switch_t *sw, c_port_t *port_desc)
{
    assert(port_desc);
    if (g_hash_table_remove(sw->sw_ports, &port_desc->sw_port.port_no)) {
        sw->n_ports--;
    }
}

void
__c_switch_port_traverse_all(c_switch_t *sw, GHFunc iter_fn, void *arg)
{
    if (sw->sw_ports) {
        g_hash_table_foreach(sw->sw_ports,
                             (GHFunc)iter_fn, arg);
    }
}

static struct c_pkt_q * 
__c_port_q_find(c_port_t *port, uint32_t qid)
{
    if (port->pkt_qs) {
        return g_hash_table_lookup(port->pkt_qs, &qid);
    } else {
        return NULL;
    }
}

static int
__c_port_q_add(c_port_t *port, uint32_t qid,
               void *q_prop, size_t q_prop_len)
{
    c_pkt_q_t *q;

    if (q_prop_len > C_MAX_Q_PROP_LEN) {
        c_log_err("|OF-Q| too many props");
        return -1;
    }

    if ((q = __c_port_q_find(port, qid))) {
        q->last_seen = time(NULL);
        return -1;
    }

    q = calloc(1, sizeof(*q));    
    if (!q) return -1;
    
    if (q_prop && q_prop_len) {
        q->q_prop = calloc(1, q_prop_len);
        if (!q->q_prop) goto free_q_out;
        memcpy(q->q_prop, q_prop, q_prop_len);
        q->q_prop_len = q_prop_len;
    }
    q->qid = qid;
    q->port_no = port->sw_port.port_no;
    q->last_seen = time(NULL);
    g_hash_table_insert(port->pkt_qs, &q->qid, q);

    return 0;

free_q_out:
    free(q);
    return -1; 
}

static int
__c_port_q_del(c_port_t *port, uint32_t qid)
{
    if (__c_port_q_find(port, qid))
        return g_hash_table_remove(port->pkt_qs, &qid);
    else
        return -1;
}

static int UNUSED
c_switch_port_q_add(c_switch_t *sw, uint32_t port_no, uint32_t qid,
                    void *q_prop, size_t q_prop_len)
{
    c_port_t *port;
    int ret = 0;

    c_wr_lock(&sw->lock);
    port = __c_switch_port_find(sw, port_no);
    if (!port) {
        ret = -1;
        goto unlock_out;
    }
    ret = __c_port_q_add(port, qid, q_prop, q_prop_len); 
    
unlock_out:
    c_wr_unlock(&sw->lock);
    return ret;
}

static int UNUSED
c_switch_port_q_del(c_switch_t *sw, uint32_t port_no, uint32_t qid)
{
    c_port_t *port;
    int ret = 0;

    c_wr_lock(&sw->lock);
    port = __c_switch_port_find(sw, port_no);
    if (!port) {
        ret = -1;
        c_log_err("|%s| No such port |%lu|", FN, U322UL(port_no));
        goto unlock_out;
    }
    ret = __c_port_q_del(port, qid); 
    if (ret) { 
        c_log_err("|%s| No such queue |%lu|", FN, U322UL(qid));
    }
    
unlock_out:
    c_wr_unlock(&sw->lock);
    return ret;
}

void
__c_port_q_traverse_all(c_port_t *port, GHFunc iter_fn, void *arg)
{
    if (port->pkt_qs) {
        g_hash_table_foreach(port->pkt_qs,
                             (GHFunc)iter_fn, arg);
    }
}

void
c_switch_port_q_traverse_all(c_switch_t *sw, uint32_t port_no,
                             GHFunc iter_fn, void *arg)
{
    c_port_t *port = NULL;

    c_rd_lock(&sw->lock);
    port = __c_switch_port_find(sw, port_no);
    if (port && port->pkt_qs) {
        __c_port_q_traverse_all(port,
                                (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&sw->lock);
}

static void
c_switch_mk_ofp1_0_port_info(void *k UNUSED, void *v, void *arg)
{
    struct ofp_phy_port *port_msg = *(struct ofp_phy_port **)(arg);
    c_port_t *port = v;

    port_msg->port_no = htons(port->sw_port.port_no);
    port_config_to_ofxlate(&port_msg->config, port->sw_port.config);
    port_status_to_ofxlate(&port_msg->state, port->sw_port.state);
    port_msg->curr = htonl(port->sw_port.curr);
    port_msg->advertised = htonl(port->sw_port.advertised);
    port_msg->supported = htonl(port->sw_port.supported);
    port_msg->peer = htonl(port->sw_port.peer);

    memcpy(port_msg->name, port->sw_port.name, OFP_MAX_PORT_NAME_LEN);
    memcpy(port_msg->hw_addr, port->sw_port.hw_addr, OFP_ETH_ALEN);
    port_msg++;

    *(struct ofp_phy_port **)(arg) = port_msg;
}


static struct cbuf *
c_switch_mk_ofp1_0_features(c_switch_t *sw)
{
    struct cbuf *b;
    struct ofp_switch_features *osf;
    struct ofp_phy_port *port_msg;

    c_rd_lock(&sw->lock);
    b = of_prep_msg(sizeof(*osf) + (sw->n_ports * sizeof(struct ofp_phy_port)),
                    OFPT_FEATURES_REPLY, 0);

    osf = (void *)(b->data);
    C_ADD_ALIAS_IN_SWADD(osf, sw->alias_id);
    osf->datapath_id = htonll(sw->DPID);
    osf->n_buffers = htonl(sw->n_buffers);
    osf->n_tables = sw->n_tables;
    osf->capabilities = htonl(sw->capabilities);
    osf->actions = htonl(sw->actions);
    port_msg = osf->ports;
    __c_switch_port_traverse_all(sw, c_switch_mk_ofp1_0_port_info, &port_msg);

    c_rd_unlock(&sw->lock);

    return b;
}

void
of_switch_brief_info(c_switch_t *sw,
                     struct c_ofp_switch_brief *cofp_sb) 
{
    cofp_sb->switch_id.datapath_id = htonll(sw->DPID);
    cofp_sb->n_ports = ntohl(sw->n_ports);
    cofp_sb->state = ntohll(sw->switch_state); 
    strncpy(cofp_sb->conn_str, sw->conn.conn_str, OFP_CONN_DESC_SZ);
    cofp_sb->conn_str[OFP_CONN_DESC_SZ-1] = '\0';
}

void
c_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&hdl->lock);
    if (hdl->sw_hash_tbl) {
        g_hash_table_foreach(hdl->sw_hash_tbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&hdl->lock);
}

void
__c_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    if (hdl->sw_hash_tbl) {
        g_hash_table_foreach(hdl->sw_hash_tbl,
                             (GHFunc)iter_fn, arg);
    }
}

static unsigned int
c_flow_exm_key(const void *p)
{
    const struct flow *fl = p;

    return hash_words((const uint32_t *) fl,
                      sizeof *fl/sizeof(uint32_t), 1);
}

static int 
c_flow_exm_key_cmp (const void *p1, const void *p2)
{
    struct flow *fl1 = (struct flow *) p1;
    struct flow *fl2 = (struct flow *) p2;

    return !memcmp(fl1, fl2, sizeof(*fl1));
}

static void
c_flow_exm_key_free(void *arg UNUSED)
{
    return;
}

static void
__c_flow_exm_release(void *arg)
{
    c_fl_entry_t *ent = arg;
    c_fl_entry_t *parent = ent->parent;

    if (parent) {
        parent->cloned_list = g_slist_remove(parent->cloned_list, ent);
        c_flow_entry_put(parent);
    }
    c_flow_entry_put(ent);
}

static void
c_flow_exm_release(void *arg, void *u_arg)
{
    c_flow_tbl_t *tbl;
    c_switch_t  *sw = u_arg;
    c_fl_entry_t *ent = arg;

    tbl = &sw->exm_flow_tbl;

    if (tbl->exm_fl_hash_tbl) {
        /* This will lead a call to __c_flow_exm_release() */
        g_hash_table_remove(tbl->exm_fl_hash_tbl, &ent->fl);
    }

    return;
}

static int
__c_flow_add_app_owner(c_fl_entry_t *ent, void *new_app)
{
    GSList       *iterator = NULL;
    void         *app;

    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        if (app == new_app) {
            c_wr_unlock(&ent->FL_LOCK);
            return -EEXIST;
        }
    }

    c_app_ref(new_app); 
    atomic_inc(&ent->app_ref, 1);
    ent->app_owner_list = g_slist_append(ent->app_owner_list, new_app);    
 
    return 0;
}


static int
c_flow_add_app_owner(c_fl_entry_t *ent, void *new_app)
{
    c_wr_lock(&ent->FL_LOCK);
    __c_flow_add_app_owner(ent, new_app);
    c_wr_unlock(&ent->FL_LOCK);
    return 0;
}

int
__c_flow_find_app_owner(void *key_arg UNUSED, void *ent_arg, void *app)
{
    GSList       *iterator = NULL;
    void         *app_owner;
    c_fl_entry_t *ent = ent_arg;

    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app_owner = iterator->data;
        if (app_owner == app) {
            return 1;
        }
    }

    return 0;
}

/* Ownership needs to be verified before calling */
static int
__c_flow_del_app_owner(c_fl_entry_t *ent, void *app)
{
    ent->app_owner_list = g_slist_remove(ent->app_owner_list, app);    
    atomic_dec(&ent->app_ref, 1);
    c_app_unref(app); 
 
    return 0;
}

static int
__c_flow_find_del_all_app_owner(void *key_arg UNUSED, void *ent_arg, void *arg UNUSED)
{
    GSList       *iterator = NULL;
    void         *app_owner;
    c_fl_entry_t *ent = ent_arg;

    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app_owner = iterator->data;
        atomic_dec(&ent->app_ref, 1);
        c_app_unref(app_owner);
    }

    g_slist_free(ent->app_owner_list);
    ent->app_owner_list = NULL;
    return 0;
}

static int
c_flow_find_del_app_owner(void *key_arg UNUSED, void *ent_arg, void *app)
{
    c_fl_entry_t *ent = ent_arg;

    c_wr_lock(&ent->FL_LOCK);

    if (__c_flow_find_app_owner(NULL, ent, app) ) {
        __c_flow_del_app_owner(ent, app);

        if (!atomic_read(&ent->app_ref)) {
            c_wr_unlock(&ent->FL_LOCK);
            return 1;
        }

        if (!(ent->FL_FLAGS & C_FL_ENT_LOCAL)) { 
            of_send_flow_del(ent->sw, ent, 0, false, OFPG_ANY);
        }
    }

    c_wr_unlock(&ent->FL_LOCK);

    return 0;
}

static void 
__c_per_switch_del_app_flow_rule(c_switch_t *sw, GSList **list, void *app) 
{
    GSList *tmp, *tmp1, *prev = NULL;
    c_fl_entry_t *ent;
    
    tmp = *list;
    while (tmp) {
        ent = tmp->data;     
        c_wr_lock(&ent->FL_LOCK);
        if (__c_flow_find_app_owner(NULL, ent, app)) { 
            __c_flow_del_app_owner(ent, app);
            tmp1 = tmp;

            if (!atomic_read(&ent->app_ref)) {
                if (prev) {
                    prev->next = tmp->next;
                    tmp = tmp->next;
                } else {
                    *list = tmp->next;
                    tmp = *list;
                }

                if (!ent->parent && !(ent->FL_FLAGS & C_FL_ENT_LOCAL)) { 
                    of_send_flow_del(sw, ent, 0, false, OFPG_ANY);
                }

                c_wr_unlock(&ent->FL_LOCK);
                g_slist_free_1(tmp1);
                c_flow_rule_free(ent, sw);
                continue;
            }
        }

        c_wr_unlock(&ent->FL_LOCK);
        prev = tmp;
        tmp = prev->next;
    }

    return;
}

static void 
__c_per_switch_del_app_flow_exm(c_switch_t *sw, void *app) 
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;

    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_foreach_remove(tbl->exm_fl_hash_tbl,
                                    c_flow_find_del_app_owner, app);
    }
}

void
__c_per_switch_del_app_flow_owner(c_switch_t *sw, void *app)
{
    int idx = 0;    
    c_flow_tbl_t *tbl;

    for (idx = 0; idx < C_MAX_RULE_FLOW_TBLS; idx++) {
        tbl = &sw->rule_flow_tbls[idx];
        __c_per_switch_del_app_flow_rule(sw, &tbl->rule_fl_tbl, app);
    }

    __c_per_switch_del_app_flow_exm(sw, app);

}

static int  UNUSED
c_flow_exm_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    c_fl_entry_t *new_ent, *ent;
    c_flow_tbl_t  *tbl;
    int ret = 0;
    bool need_hw_sync = FL_EXM_NEED_HW_SYNC(fl_parms);

    if (of_exm_flow_mod_validate_parms(sw, fl_parms)) {
        return -EINVAL;
    }

    new_ent = calloc(1, sizeof(*new_ent));
    assert(new_ent);

    c_rw_lock_init(&new_ent->FL_LOCK);
    new_ent->sw = sw;
    new_ent->FL_ENT_TYPE = C_TBL_EXM;
    new_ent->FL_FLAGS = fl_parms->flags;
    
    new_ent->FL_PRIO = C_FL_PRIO_EXM;
    memcpy(&new_ent->fl, fl_parms->flow, sizeof(struct flow));
    new_ent->action_len = fl_parms->action_len;
    new_ent->actions    = fl_parms->actions;
    atomic_inc(&new_ent->FL_REF, 1);

    tbl = &sw->exm_flow_tbl;

    c_wr_lock(&sw->lock);

    if ((ent = __c_flow_get_exm(sw, fl_parms->flow))) {
        ret = -EEXIST;
        if ((fl_parms->flags & C_FL_ENT_LOCAL) &&
            (ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
           ret = c_flow_add_app_owner(ent, fl_parms->app_owner);
        }

        c_wr_unlock(&sw->lock);
        c_flow_entry_put((void *)ent);
        free(new_ent);
        return ret;
    }

    c_flow_add_app_owner(new_ent, fl_parms->app_owner);

    g_hash_table_insert(tbl->exm_fl_hash_tbl, &new_ent->fl, new_ent);

    c_wr_unlock(&sw->lock);

    if (need_hw_sync) {
        of_send_flow_add(sw, new_ent, fl_parms->buffer_id, true, false);
    }

    c_flow_entry_put(new_ent);

    return ret;
}

/*
 * Parent should be held before hand 
 */
static c_fl_entry_t * 
c_flow_clone_exm(c_switch_t *sw, struct flow *flow, c_fl_entry_t *parent)
{
    c_fl_entry_t *ent;
    c_flow_tbl_t  *tbl;

    ent = calloc(1, sizeof(*ent));
    assert(ent);

    ent->FL_ENT_TYPE = C_TBL_EXM;
    ent->FL_FLAGS = 0;
    
    ent->FL_ITIMEO = C_FL_IDLE_DFL_TIMEO;
    ent->FL_HTIMEO = C_FL_HARD_DFL_TIMEO;
    ent->FL_PRIO = C_FL_PRIO_EXM;
    memcpy(&ent->fl, flow, sizeof(*flow));
    ent->action_len = parent->action_len;
    ent->actions    = parent->actions;
    ent->parent     = parent;
    atomic_inc(&ent->FL_REF, 1);

    c_wr_lock(&sw->lock);

    tbl = &sw->exm_flow_tbl;

    parent->cloned_list = g_slist_append(parent->cloned_list, ent);
    g_hash_table_insert(tbl->exm_fl_hash_tbl, &ent->fl, ent);

    c_wr_unlock(&sw->lock);

    return ent;
}

static int  UNUSED
c_flow_exm_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    c_flow_tbl_t        *tbl;
    static c_fl_entry_t *fl_ent;

    if (of_exm_flow_mod_validate_parms(sw, fl_parms)) {
        return -EINVAL;   
    }

    tbl = &sw->exm_flow_tbl;

    c_wr_lock(&sw->lock);

    fl_ent = __c_flow_get_exm(sw, fl_parms->flow);
    if (!fl_ent) {
        c_wr_unlock(&sw->lock);
        return -EINVAL;
    }


    c_wr_lock(&fl_ent->FL_LOCK);
    if (__c_flow_find_app_owner(NULL, fl_ent, fl_parms->app_owner)) {
        __c_flow_del_app_owner(fl_ent, fl_parms->app_owner);
        c_wr_unlock(&fl_ent->FL_LOCK);
    } else {
        c_log_err("[FLOW] Del Failed - Owner mismatch");
        c_wr_unlock(&fl_ent->FL_LOCK);
        c_wr_unlock(&sw->lock);
        return -EINVAL;
    }

    if (!atomic_read(&fl_ent->app_ref)) {
        g_hash_table_remove(tbl->exm_fl_hash_tbl, fl_parms->flow);
    }

    if (!(fl_ent->FL_FLAGS & C_FL_ENT_LOCAL)) 
        of_send_flow_del(sw, fl_ent, 0, true, OFPG_ANY);


    c_wr_unlock(&sw->lock);

    c_flow_entry_put(fl_ent);

    return 0;
}

static void
c_flow_exm_iter(void *k UNUSED, void *v, void *args)
{
    struct c_iter_args *u_parms = args;
    c_fl_entry_t       *ent = v;
    flow_parser_fn     fn;

    fn = (flow_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, ent); 
}


static void
c_flow_rule_free(void *arg, void *u_arg)
{
    c_fl_entry_t *ent = arg;

    if (ent->cloned_list) {
        g_slist_foreach(ent->cloned_list, (GFunc)c_flow_exm_release, u_arg);
        g_slist_free(ent->cloned_list); 
    }

    if (ent->sw->fl_cookies)
        g_hash_table_remove(ent->sw->fl_cookies, ent);

    c_flow_entry_put(ent);
}

static void
c_flow_rule_iter(void *k, void *args)
{
    struct c_iter_args *u_parms = args;
    c_fl_entry_t       *ent = k;
    flow_parser_fn     fn;

    fn = (flow_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, ent); 
}


static bool
c_match_flow_ip_addr_generic(struct flow *fl1, struct flow *fl2,
                             struct flow *mask)
{
    /* Assumes fl1 and fl2's mask are equal */
    if (!mask->dl_type)  return true;

    if (fl1->dl_type != fl2->dl_type) return false;

    if (fl1->dl_type == htons(ETH_TYPE_IPV6)) {
        if (ipv6_addr_mask_equal(&fl1->ipv6.nw_src,
                                 &mask->ipv6.nw_src,
                                &fl1->ipv6.nw_src) &&
           ipv6_addr_mask_equal(&fl1->ipv6.nw_dst,
                                &mask->ipv6.nw_dst,
                                &fl1->ipv6.nw_dst)) {
            return true;
        }
        return false;                        
    } else if (fl1->dl_type == htons(ETH_TYPE_IP) ||
               fl1->dl_type == htons(ETH_TYPE_ARP)) {
        if ((fl1->ip.nw_dst & mask->ip.nw_dst) == fl2->ip.nw_dst &&
            (fl1->ip.nw_src & mask->ip.nw_src) == fl2->ip.nw_src) {
            return true;
        }
        return false;
    }

    return true;
}

static c_fl_entry_t * 
__c_flow_lookup_rule_strict_prio_hint_detail(c_switch_t *sw UNUSED, 
                                             GSList **list,
                                             struct flow *fl,
                                             struct flow *mask, 
                                             uint16_t prio)
{
    GSList *iterator = NULL, *hint = NULL;
    c_fl_entry_t *ent;
    struct flow *ent_fl;
    uint8_t zero_mac[] = { 0, 0, 0, 0, 0, 0};

    for (iterator = *list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if ((hint && ((c_fl_entry_t *)(hint->data))->FL_PRIO > ent->FL_PRIO) ||
            (prio >= ent->FL_PRIO)) {
            hint = iterator;
        }

        if (memcmp(&ent->fl_mask, mask, sizeof(*mask)-sizeof(mask->pad))) {
            continue;
        }

        ent_fl = &ent->fl;

        if (c_match_flow_ip_addr_generic(fl, ent_fl, mask) &&
            (!mask->nw_proto || fl->nw_proto == ent_fl->nw_proto) &&
            (!mask->nw_tos || fl->nw_tos == ent_fl->nw_tos) &&
            (!mask->tp_dst || fl->tp_dst == ent_fl->tp_dst) &&
            (!mask->tp_src || fl->tp_src == ent_fl->tp_src) &&
            (!memcmp(mask->dl_src, zero_mac, 6) || 
             !memcmp(fl->dl_src, ent_fl->dl_src, 6)) &&
            (!memcmp(mask->dl_dst, zero_mac, 6) || 
             !memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) &&
            (!mask->dl_type || fl->dl_type == ent_fl->dl_type) &&
            (!mask->dl_vlan || fl->dl_vlan == ent_fl->dl_vlan) &&
            (!mask->dl_vlan_pcp || fl->dl_vlan_pcp == ent_fl->dl_vlan_pcp) &&
            (!mask->mpls_label || fl->mpls_label == ent_fl->mpls_label) &&
            (!mask->mpls_tc || fl->mpls_tc == ent_fl->mpls_tc) &&
            (!mask->mpls_bos || fl->mpls_bos == ent_fl->mpls_bos) &&
            (!mask->in_port || fl->in_port == ent_fl->in_port) && 
            (!mask->metadata || fl->metadata == ent_fl->metadata) && 
            (!mask->tunnel_id || fl->tunnel_id == ent_fl->tunnel_id) && 
            ent->FL_PRIO == prio)  {
            *list = hint;
            return ent;
        }
    }

    *list = hint;
    return NULL;
}

#if 0
static c_fl_entry_t *
__c_flow_lookup_rule_strict_prio_hint(GSList **list, struct flow *fl, uint32_t wildcards,
                                       uint16_t prio)
{
    GSList *iterator = NULL, *hint = NULL;
    c_fl_entry_t *ent;

    for (iterator = *list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if ((hint && ((c_fl_entry_t *)(hint->data))->FL_PRIO > ent->FL_PRIO) || 
            (prio >= ent->FL_PRIO)) {
            hint = iterator;
        } 
        if (!memcmp(&ent->fl, fl, sizeof(*fl)) 
            && ent->FL_WILDCARDS == wildcards &&
            ent->FL_PRIO == prio) {
            *list = hint;
            return ent;
        }
    }

    *list = hint;
    return NULL;
}
#else
static c_fl_entry_t *
__c_flow_lookup_rule_strict_prio_hint(GSList **list, struct flow *fl,
                                      struct flow *fl_mask, uint16_t prio)
{
    GSList *iterator = NULL, *hint = NULL;
    c_fl_entry_t *ent;

    for (iterator = *list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if ((hint && ((c_fl_entry_t *)(hint->data))->FL_PRIO > ent->FL_PRIO) || 
            (prio >= ent->FL_PRIO)) {
            hint = iterator;
        } 
        if (!memcmp(&ent->fl, fl, sizeof(*fl))  &&
            !memcmp(&ent->fl_mask, fl_mask,
                    sizeof(*fl_mask) - sizeof(fl_mask->pad)) &&
            ent->FL_PRIO == prio) {
            *list = hint;
            return ent;
        }
    }

    *list = hint;
    return NULL;
}
#endif

struct cbuf *
c_of_prep_table_feature_msg(c_switch_t *sw, uint8_t table_id)
{
    struct cbuf *b;
    size_t tot_len = 0;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_switch_feature_common *cofp_sfc;
    size_t table_feat_len = 0;
    void *table_features = NULL;

    c_rd_lock(&sw->lock);
    
    if (table_id < C_MAX_RULE_FLOW_TBLS &&
        sw->rule_flow_tbls[table_id].props) {
        table_feat_len = sizeof(struct of_flow_tbl_props);
        table_features = sw->rule_flow_tbls[table_id].props;
    } 

    tot_len = sizeof(*cofp_sfc) + sizeof(*cofp_aac) + table_feat_len;
    b = of_prep_msg(tot_len, C_OFPT_AUX_CMD, 0);

    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code =  htonl(C_AUX_CMD_MUL_SWITCH_TABLE_FEAT);

    cofp_sfc = ASSIGN_PTR(cofp_aac->data);
    cofp_sfc->datapath_id = htonll(sw->DPID);
    cofp_sfc->table_id = table_id;
    if (table_features) {
        memcpy(cofp_sfc->data, table_features,
               sizeof(struct of_flow_tbl_props));
    }

    c_rd_unlock(&sw->lock);

    return b;
}

static c_fl_entry_t *
__c_flow_lookup_rule(c_switch_t *sw UNUSED, struct flow *fl, c_flow_tbl_t *tbl)
{
    GSList *list, *iterator = NULL;
    c_fl_entry_t  *ent;
    struct flow   *ent_fl, *mask;
    uint8_t       zero_mac[] = { 0, 0, 0, 0, 0, 0};  

    list = tbl->rule_fl_tbl;

    for (iterator = list; iterator; iterator = iterator->next) {
        
        ent = iterator->data;
        ent_fl = &ent->fl;
        mask = &ent->fl_mask;

        if (ent->FL_FLAGS & C_FL_ENT_RESIDUAL) continue;

        if (c_match_flow_ip_addr_generic(fl, ent_fl, mask)  &&
            (!mask->nw_proto || fl->nw_proto == ent_fl->nw_proto) &&
            (!mask->nw_tos || fl->nw_tos == ent_fl->nw_tos) &&
            (!mask->tp_dst || fl->tp_dst == ent_fl->tp_dst) &&
            (!mask->tp_src || fl->tp_src == ent_fl->tp_src) &&
            (!memcmp(mask->dl_src, zero_mac, 6) || 
             !memcmp(fl->dl_src, ent_fl->dl_src, 6)) &&
            (!memcmp(mask->dl_dst, zero_mac, 6) 
             || !memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) &&
            (!mask->dl_type || fl->dl_type == ent_fl->dl_type) && 
            (!mask->dl_vlan || fl->dl_vlan == ent_fl->dl_vlan) &&
            (!mask->dl_vlan_pcp || fl->dl_vlan_pcp == ent_fl->dl_vlan_pcp) &&
            (!mask->in_port || fl->in_port == ent_fl->in_port) &&
            (!mask->mpls_label || fl->mpls_label == ent_fl->mpls_label) &&
            (!mask->mpls_tc || fl->mpls_tc == ent_fl->mpls_tc) && 
            (!mask->mpls_bos || fl->mpls_bos == ent_fl->mpls_bos))  {
            return ent;
        }
    }

    return NULL;
}

static void 
__c_flow_rule_disassociate_meters_only(GSList *list)
{
    GSList *iter;
    c_switch_meter_t *meter;

    for (iter = list; iter; iter = iter->next) {
        meter = iter->data;
        atomic_dec(&meter->ref, 1);
    }
    return;
}

static void 
__c_flow_rule_disassociate_meters(c_switch_t *sw UNUSED, c_fl_entry_t *ent)
{
    if (!ent->meters) return;
    __c_flow_rule_disassociate_meters_only(ent->meters);
    g_slist_free(ent->meters);
    ent->meters = NULL;
    return;
}

static int
__c_flow_rule_associate_meters(c_switch_t *sw, c_fl_entry_t *ent,
                               GSList *meter_list)
{
    GSList *iter;
    int ret = 0;
    c_switch_meter_t *meter;

    if (!meter_list) return 0;

    for (iter = meter_list; iter; iter = iter->next) {
        uint32_t *meter_id = iter->data;

        if (!(meter = g_hash_table_lookup(sw->meters, meter_id))) {
            ret = -1;
            goto err;
        }

        atomic_inc(&meter->ref, 1);
        ent->meters = g_slist_append(ent->meters, meter); 
    }

    return 0;

err:
    __c_flow_rule_disassociate_meters(sw, ent);
    return ret;
}

static void 
__c_flow_rule_disassociate_grps_only(GSList *list)
{
    GSList *iter;
    c_switch_group_t *group;

    for (iter = list; iter; iter = iter->next) {
        group = iter->data;
        atomic_dec(&group->ref, 1);
    }
    return;
}

static void 
__c_flow_rule_disassociate_grps(c_switch_t *sw UNUSED, c_fl_entry_t *ent)
{
    if (!ent->groups) return;
    __c_flow_rule_disassociate_grps_only(ent->groups);
    g_slist_free(ent->groups);
    ent->groups = NULL;
    return;
}

static int
__c_flow_rule_associate_grps(c_switch_t *sw, c_fl_entry_t *ent,
                             GSList *grp_list)
{
    GSList *iter;
    int ret = 0;
    c_switch_group_t *group;

    if (!grp_list) return 0;

    for (iter = grp_list; iter; iter = iter->next) {
        uint32_t *grp_id = iter->data;

        if (!(group = g_hash_table_lookup(sw->groups, grp_id))) {
            ret = -1;
            goto err;
        }

        atomic_inc(&group->ref, 1);
        ent->groups = g_slist_append(ent->groups, group); 
    }

    return 0;

err:
    __c_flow_rule_disassociate_grps(sw, ent);
    return ret;
}

static int
c_flow_rule_mod(c_switch_t *sw, c_fl_entry_t *ent,
                struct of_flow_mod_params *fl_parms,
                bool *hw_install)
{
    GSList  *old_meters = NULL, *old_groups = NULL;

    c_wr_lock(&ent->FL_LOCK);

    /* Previous group and meter dependencies */
    old_meters = ent->meters;
    old_groups = ent->groups;

    ent->meters = NULL;
    ent->groups = NULL;

    if (ent->FL_FLAGS & C_FL_ENT_RESIDUAL) {
        if (!(fl_parms->flags & C_FL_ENT_RESIDUAL)) {
            __c_flow_find_del_all_app_owner(NULL, ent, NULL);
            __c_flow_add_app_owner(ent, fl_parms->app_owner); 
            if (ent->action_len != fl_parms->action_len || 
                memcmp(ent->actions,  fl_parms->actions, ent->action_len)) {
                ent->FL_INSTALLED = false;
                *hw_install = true;
            } else
                *hw_install = false;
        } else {
            if (!c_rlim(&crl))
                c_log_err("|FLOW| Tried to change residual flow. Ignored");
            return -1;
        }
    } 

    if (__c_flow_rule_associate_grps(sw, ent, fl_parms->grp_dep)) {
        c_log_debug("%s:rule grp associate fail", FN);
        goto out_mod_err_ga;
    }

    if (__c_flow_rule_associate_meters(sw, ent, fl_parms->meter_dep)) {
        c_log_debug("%s:rule meter associate fail", FN);
        goto out_mod_err_ma;
    }

    __c_flow_rule_disassociate_grps_only(old_groups);
    __c_flow_rule_disassociate_meters_only(old_meters);

    free(ent->actions);
    ent->actions = fl_parms->actions;
    ent->action_len = fl_parms->action_len;
    memset(&ent->fl_stats, 0, sizeof(ent->fl_stats));
    ent->fl_stats.last_refresh = time(NULL);

    if (ent->FL_FLAGS & C_FL_ENT_RESIDUAL &&
        !(fl_parms->flags & C_FL_ENT_RESIDUAL)) {
        ent->FL_FLAGS = fl_parms->flags;
    } 

    c_wr_unlock(&ent->FL_LOCK);
    return 0;

out_mod_err_ma:
    __c_flow_rule_disassociate_grps(sw, ent);
out_mod_err_ga:
    ent->meters = old_meters;
    ent->groups = old_groups; 

    c_wr_unlock(&ent->FL_LOCK);
    return -1;
} 

static int
c_flow_rule_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    GSList       *list;
    c_fl_entry_t *new_ent, *ent;
    c_flow_tbl_t *tbl;
    int          ret = 0;
    char         *err_str = NULL;
    bool         modify = false;
    uint8_t      table_id = fl_parms->flow->table_id;
    bool         hw_sync = FL_NEED_HW_SYNC(fl_parms); 

    new_ent = calloc(1, sizeof(*new_ent));
    assert(new_ent);

    if (c_flow_mod_validate_parms(sw, fl_parms)) {
        return -EINVAL;
    }

    /* FIXME Move allocation and init to common function */
    c_rw_lock_init(&new_ent->FL_LOCK);
    new_ent->sw = sw;
    new_ent->FL_ENT_TYPE = C_TBL_RULE;
    new_ent->FL_FLAGS = fl_parms->flags;

    new_ent->FL_PRIO = fl_parms->prio;
    memcpy(&new_ent->fl, fl_parms->flow, sizeof(struct flow));
    memcpy(&new_ent->fl_mask, fl_parms->mask, sizeof(struct flow));
    new_ent->action_len = fl_parms->action_len;
    new_ent->actions    = fl_parms->actions;
    new_ent->cloned_list = NULL;
    new_ent->fl_stats.last_refresh = time(NULL);

    if (hw_sync) {
        atomic_inc(&new_ent->FL_REF, 1); 
    }

    tbl = &sw->rule_flow_tbls[table_id];
    list = tbl->rule_fl_tbl;

    c_wr_lock(&sw->lock);

    /* FIXME : Combine lookup and insert for perf */   
    if ((ent = __c_flow_lookup_rule_strict_prio_hint(&list, fl_parms->flow, 
                                                     fl_parms->mask, 
                                                     fl_parms->prio))) {
        if ((fl_parms->flags & C_FL_ENT_LOCAL) && 
            (ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
           ret = c_flow_add_app_owner(ent, fl_parms->app_owner);
           goto out_err_free; 
        }

        if (!(ent->FL_FLAGS & C_FL_ENT_RESIDUAL)) {
            if (!__c_flow_find_app_owner(NULL, ent, fl_parms->app_owner)) {
            /* FIXME : Race condition above */
                ret = -EPERM;
                err_str = "owner mismatch";
                goto out_err_free;
            } 
            if ((new_ent->action_len == ent->action_len &&
                !memcmp(new_ent->actions ,ent->actions, ent->action_len))) {
                ent->FL_FLAGS &= ~C_FL_ENT_STALE;
                ret = -EEXIST;
                err_str = "existing entry";
                goto out_err_free;
            }
        }

        if (c_flow_rule_mod(sw, ent, fl_parms, &hw_sync)) {
            ret = -EINVAL;
            err_str = "modify err";
            goto out_err_free;
        }

        ent->FL_FLAGS &= ~C_FL_ENT_STALE;

        modify = true;
        if (hw_sync) {
            atomic_inc(&ent->FL_REF, 1);
        }
        free(new_ent);
        new_ent = ent;
        c_wr_unlock(&sw->lock);
        goto hw_install;
    }

    if (__c_flow_rule_associate_grps(sw, new_ent, fl_parms->grp_dep)) {
        err_str = "group associate err";
        ret = -EINVAL;
        goto out_err_free;
    }

    if (__c_flow_rule_associate_meters(sw, new_ent, fl_parms->meter_dep)) {
        err_str = "meter associate err";
        ret = -EINVAL;
        goto out_err_free_groups;
    }

    c_flow_add_app_owner(new_ent, fl_parms->app_owner);

    tbl->rule_fl_tbl = g_slist_insert_before(tbl->rule_fl_tbl, list, new_ent);
    tbl->sw_active_entries++;
    sw->fl_idx_cookie++;
    new_ent->FL_COOKIE = fl_parms->cookie ? : sw->fl_idx_cookie;
    new_ent->FL_INSTALLED = true;
    if (new_ent->FL_FLAGS & C_FL_ENT_RESIDUAL)
        new_ent->FL_INSTALLED = true;
    g_hash_table_insert(sw->fl_cookies, new_ent, new_ent);
    c_wr_unlock(&sw->lock);

hw_install:
    if (hw_sync) {
        /* HA sync will be done at app interface layer itself */
        of_send_flow_add(sw, new_ent, fl_parms->buffer_id, false, modify);
        c_flow_entry_put(new_ent);
    }

    return ret;

out_err_free_groups:
    __c_flow_rule_disassociate_grps(sw, new_ent); 
out_err_free:
    c_wr_unlock(&sw->lock);
    if (!c_rlim(&crl)) {
        char *act_str = NULL;
        char *fl_str = of_dump_flow_generic(fl_parms->flow, fl_parms->mask);
        if (sw->ofp_ctors && sw->ofp_ctors->dump_acts) 
            act_str = sw->ofp_ctors->dump_acts(new_ent->actions,
                                               new_ent->action_len, false);
        c_log_err("[FLOW] Mod fail (%s) 0x%llx t%d (FL-%s) (Act-%s)",
                  err_str?:"Unknown", U642ULL(sw->DPID), 
                  fl_parms->flow->table_id,
                  fl_str?:"", act_str?:"");
        if (fl_str) free(fl_str);
        if (act_str) free(act_str);
    }
    if (new_ent->actions) free(new_ent->actions);
    free(new_ent);
    return ret;
}

#if 0
static bool
__c_flow_rule_del_strict(GSList **list, struct flow **flow, 
                          uint32_t wildcards, uint16_t prio, 
                          void *app)
{
    GSList *tmp, *prev = NULL;
    c_fl_entry_t *ent;
    bool found = false;
    
    tmp = *list;
    while (tmp) {
        ent = tmp->data;     

        c_wr_lock(&ent->FL_LOCK);
        if (!memcmp(&ent->fl, *flow, sizeof(struct flow)) &&
            ent->FL_WILDCARDS == wildcards && 
            ent->FL_PRIO == prio &&
            __c_flow_find_app_owner(NULL, ent, app)) { 
            __c_flow_del_app_owner(ent, app);
            c_wr_unlock(&ent->FL_LOCK);
            *flow = &ent->fl;
            found = TRUE;

            if (atomic_read(&ent->app_ref)) {
                break;
            }

            if (prev)
                prev->next = tmp->next;
            else
                *list = tmp->next;
            g_slist_free_1 (tmp);
            break;
        }
        prev = tmp;
        tmp = prev->next;
        c_wr_unlock(&ent->FL_LOCK);
    }       

    return found;
}
#else
static bool
__c_flow_rule_del_strict(GSList **list, struct flow **flow, 
                         struct flow *mask, uint16_t prio,
                         void *app)
{
    GSList *tmp, *prev = NULL;
    c_fl_entry_t *ent;
    bool found = false;
    
    tmp = *list;
    while (tmp) {
        ent = tmp->data;     

        c_wr_lock(&ent->FL_LOCK);
        if (!memcmp(&ent->fl, *flow, sizeof(struct flow)) &&
            !memcmp(&ent->fl_mask, mask, sizeof(struct flow)) &&
            ent->FL_PRIO == prio &&
            __c_flow_find_app_owner(NULL, ent, app)) { 
            __c_flow_del_app_owner(ent, app);
            c_wr_unlock(&ent->FL_LOCK);
            *flow = &ent->fl;
            found = TRUE;

            if (atomic_read(&ent->app_ref)) {
                break;
            }

            if (prev)
                prev->next = tmp->next;
            else
                *list = tmp->next;
            g_slist_free_1 (tmp);
            break;
        }
        prev = tmp;
        tmp = prev->next;
        c_wr_unlock(&ent->FL_LOCK);
    }       

    return found;
}

#endif

static int
c_flow_rule_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms)
{
    c_fl_entry_t *ent;
    c_flow_tbl_t  *tbl;
    struct flow *flow = fl_parms->flow;

    if (c_flow_mod_validate_parms(sw, fl_parms)) {
        return -1;
    }

    c_wr_lock(&sw->lock);
    tbl = &sw->rule_flow_tbls[flow->table_id];

    if (!__c_flow_rule_del_strict(&tbl->rule_fl_tbl, &flow, 
                                  fl_parms->mask, fl_parms->prio, 
                                  fl_parms->app_owner)) {
        c_wr_unlock(&sw->lock);
        if (!c_rlim(&crl)) {
            char *fl_str = of_dump_flow_generic(fl_parms->flow, fl_parms->mask);
            c_log_err("[FLOW] Flow Del fail- 0x%llx t%d No such %s",
                       sw->DPID, fl_parms->flow->table_id, fl_str);
            if (fl_str) free(fl_str);
        }
        return -1;
    }

    /* FIXME : Take this ent and add to a tentative list 
     * If we get negative ack from switch add it back to flow
     * table else free it. 
     */
    ent = container_of(flow, c_fl_entry_t, fl);

    if (!(ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
        of_send_flow_del_strict(sw, ent, 0, OFPG_ANY);
    }

    if (!atomic_read(&ent->app_ref)) {
        c_flow_rule_free(ent, sw);
        tbl->sw_active_entries--;
    }

    c_wr_unlock(&sw->lock);

    return 0;
}

int
c_switch_flow_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms)
{
#ifdef CONFIG_FLOW_EXM
    if (fl_parms->wildcards) {
        return c_flow_rule_add(sw, fl_parms);
    } else {
        return c_flow_exm_add(sw, fl_parms);
    }

    return 0;
#else
    return c_flow_rule_add(sw, fl_parms);
#endif
}

int
c_switch_flow_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
#ifdef CONFIG_FLOW_EXM
    if (fl_parms->wildcards) {
        return c_flow_rule_del(sw, fl_parms);
    } else {
        return c_flow_exm_del(sw, fl_parms);
    }

    return 0;
#else
    return c_flow_rule_del(sw, fl_parms);
#endif
}

static void
c_per_flow_resync_hw(void *arg UNUSED, c_fl_entry_t *ent)
{
    if (ent->FL_FLAGS & C_FL_ENT_NOSYNC ||  ent->FL_FLAGS & C_FL_ENT_CLONE ||
        ent->FL_FLAGS & C_FL_ENT_LOCAL ) {
        return;
    }

    of_send_flow_add(ent->sw, ent, 0xffffffff, false, false);
}

void
c_per_switch_flow_resync_hw(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;

    c_log_info("[HA] Resync switch |0x%llx|-FLOWS", sw->DPID);
    c_rd_lock(&sw->lock);
    c_flow_traverse_tbl_all(sw, arg, c_per_flow_resync_hw);
    c_rd_unlock(&sw->lock);
}

void
c_flow_resync_hw_all(ctrl_hdl_t *c_hdl)
{
    c_switch_traverse_all(c_hdl, c_per_switch_flow_resync_hw,
                          NULL);
}

static void
c_flow_traverse_tbl(c_switch_t *sw, uint8_t tbl_type, uint8_t tbl_idx, 
                    void *u_arg, flow_parser_fn fn)
{
    struct c_iter_args  args;
    c_flow_tbl_t        *tbl;

    if (tbl_type && tbl_idx >= C_MAX_RULE_FLOW_TBLS) {
        c_log_err("[FLOW] unknown tbl type");
        return;
    }

    args.u_arg = u_arg;
    args.u_fn  = (void *)fn;

    c_rd_lock(&sw->lock);

    if (!tbl_type) {
        tbl = &sw->exm_flow_tbl;
    } else {
        tbl = &sw->rule_flow_tbls[tbl_idx];
    }

    if (tbl->c_fl_tbl_type == C_TBL_EXM &&
        tbl->exm_fl_hash_tbl) {
        g_hash_table_foreach(tbl->exm_fl_hash_tbl,
                             (GHFunc)c_flow_exm_iter, &args);
    } else if (tbl->c_fl_tbl_type == C_TBL_RULE &&
               tbl->rule_fl_tbl){
        g_slist_foreach(tbl->rule_fl_tbl, 
                        (GFunc)c_flow_rule_iter, &args);
    }

    c_rd_unlock(&sw->lock);
}

void 
c_flow_traverse_tbl_all(c_switch_t *sw, void *u_arg, flow_parser_fn fn)
{
    uint8_t       tbl_idx = 0;

#ifdef CONFIG_FLOW_EXM
    c_flow_traverse_tbl(sw, C_TBL_EXM, tbl_idx, u_arg, fn);
#endif

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        c_flow_traverse_tbl(sw, C_TBL_RULE, tbl_idx, u_arg, fn);
    }
 
}

static void
c_switch_flow_tbl_create(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;
    
    c_wr_lock(&sw->lock);

    sw->fl_cookies =  g_hash_table_new_full(c_fl_cookie_hash,
                                            c_fl_cookie_match,
                                            NULL,
                                            NULL);
    assert(sw->fl_cookies);

    tbl = &sw->exm_flow_tbl;
    if (!tbl->exm_fl_hash_tbl) {
        tbl->exm_fl_hash_tbl =
                    g_hash_table_new_full(c_flow_exm_key,
                                          c_flow_exm_key_cmp,
                                          c_flow_exm_key_free,
                                          __c_flow_exm_release);
        assert(tbl->exm_fl_hash_tbl);
        tbl->c_fl_tbl_type = C_TBL_EXM;
    }

    for (tbl_idx = 0; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        tbl->c_fl_tbl_type = C_TBL_RULE; 
    }
    c_wr_unlock(&sw->lock);
}

void
c_switch_flow_tbl_delete(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;

    c_wr_lock(&sw->lock);

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        if (tbl->rule_fl_tbl) {
            g_slist_foreach(tbl->rule_fl_tbl, (GFunc)c_flow_rule_free, sw);
            g_slist_free(tbl->rule_fl_tbl);
            tbl->rule_fl_tbl = NULL;
        }
        if (tbl->props) free(tbl->props);
    }

    tbl = &sw->exm_flow_tbl;
    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_destroy(tbl->exm_fl_hash_tbl);
        tbl->exm_fl_hash_tbl = NULL;
    }
    if (tbl->props) free(tbl->props);

    if (sw->fl_cookies) g_hash_table_destroy(sw->fl_cookies);
    sw->fl_cookies = NULL;

    c_wr_unlock(&sw->lock);
}

void
c_switch_flow_tbl_reset(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;

    c_wr_lock(&sw->lock);

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        if (tbl->rule_fl_tbl) {
            g_slist_foreach(tbl->rule_fl_tbl, (GFunc)c_flow_rule_free, sw);
            g_slist_free(tbl->rule_fl_tbl);
            tbl->rule_fl_tbl = NULL;
        }
    }

    tbl = &sw->exm_flow_tbl;
    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_remove_all(tbl->exm_fl_hash_tbl);
    }

    c_wr_unlock(&sw->lock);
}

static int
c_of_grp_cmp_list(const void *list_arg, const void *uarg)
{
    uint32_t grp1 = *(uint32_t *)list_arg;
    uint32_t grp2 = *(uint32_t *)uarg;

    if (grp1 == grp2) return 0;
    return -1;
}

bool
c_of_fl_group_check_add(void *sw_arg, uint32_t group_id, void *arg)
{
    c_switch_t *sw = sw_arg;
    struct ofp_inst_check_args *u_arg = arg;
    uint32_t *new_group;
    c_switch_group_t *grp;

    c_rd_lock(&sw->lock);
    if (!(grp = g_hash_table_lookup(sw->groups, &group_id))) {
        c_log_err("[GROUP] No |%u| on switch |0x%llx| exists",
                  group_id, sw->DPID);
        c_rd_unlock(&sw->lock);
        return false;
    }
    if (grp->flags & C_GRP_EXPIRED) {
        c_log_err("[GROUP] |%u| on switch |0x%llx| is expired/dead",
                  group_id, sw->DPID);
        c_rd_unlock(&sw->lock);
        return false;
    }
    c_rd_unlock(&sw->lock);

    if (u_arg->grp_list &&
        g_slist_find_custom(u_arg->grp_list, &group_id,
                            (GCompareFunc)c_of_grp_cmp_list)) {
        return true;
    }

    new_group = malloc(sizeof(uint32_t));
    if (!new_group) return false;

    *new_group = group_id;

    u_arg->grp_list = g_slist_append(u_arg->grp_list, new_group);
    return true;
}

struct cbuf *
c_of_prep_group_feature_msg(c_switch_t *sw)
{
    struct cbuf *b;
    size_t tot_len = 0;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_switch_feature_common *cofp_sfc;

    c_rd_lock(&sw->lock); 
    tot_len = sizeof(*cofp_sfc) + sizeof(*cofp_aac) +
              ((sw->group_features) ? sw->group_feat_len : 0);

    b = of_prep_msg(tot_len, C_OFPT_AUX_CMD, 0);

    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code =  htonl(C_AUX_CMD_MUL_SWITCH_GROUP_FEAT);
     
    cofp_sfc = ASSIGN_PTR(cofp_aac->data);
    cofp_sfc->datapath_id = htonll(sw->DPID);
    if (sw->group_features) {
        memcpy(cofp_sfc->data, sw->group_features, sw->group_feat_len);
    }
    
    c_rd_unlock(&sw->lock); 

    return b;
}

static struct cbuf *
c_of_prep_group_mod_msg_with_parms(c_switch_t *sw,
                                   struct of_group_mod_params *g_parms,
                                   bool add)
{
    struct cbuf *b;
    size_t tot_len = 0;
    int act = 0;
    struct c_ofp_group_mod *cofp_gm;
    struct of_act_vec_elem *act_elem;
    struct c_ofp_bkt *bkt;

    for (;add && act < g_parms->act_vec_len; act++) {
        act_elem = g_parms->act_vectors[act];
        if (act_elem)
            tot_len += act_elem->action_len + sizeof(*bkt);
    }

    tot_len += sizeof(*cofp_gm);

    b = of_prep_msg(tot_len, C_OFPT_GROUP_MOD, 0);

    cofp_gm = (void *)(b->data);
    cofp_gm->datapath_id = htonll(sw->DPID);
    cofp_gm->command = add ? C_OFPG_ADD: C_OFPG_DEL;
    cofp_gm->group_id = htonl(g_parms->group);
    cofp_gm->type = g_parms->type;
    cofp_gm->flags = g_parms->flags;

    tot_len = sizeof(*cofp_gm);
    for (act = 0; add && act < g_parms->act_vec_len; act++) {
        bkt = INC_PTR8(cofp_gm, tot_len); 
        act_elem = g_parms->act_vectors[act];

        assert(act_elem);

        tot_len +=  sizeof(*bkt) + act_elem->action_len;
        bkt->weight = htons(act_elem->weight);
        bkt->ff_port = htonl(act_elem->ff_port);
        bkt->ff_group = htonl(act_elem->ff_group);
        bkt->act_len = htons(act_elem->action_len);
        memcpy(bkt->actions, act_elem->actions, act_elem->action_len);
    }

    return b;
}

struct cbuf *
c_of_prep_group_mod_msg(c_switch_group_t *grp, bool add)
{
    struct cbuf *b;
    size_t tot_len = 0;
    int act = 0;
    struct c_ofp_group_mod *cofp_gm;
    struct of_act_vec_elem *act_elem;
    struct c_ofp_bkt *bkt;

    for (;add && act < grp->act_vec_len; act++) {
        act_elem = grp->act_vectors[act];
        if (act_elem)
            tot_len += act_elem->action_len + sizeof(*bkt);
    }

    tot_len += sizeof(*cofp_gm);

    b = of_prep_msg(tot_len, C_OFPT_GROUP_MOD, 0);

    cofp_gm = (void *)(b->data);
    cofp_gm->datapath_id = htonll(grp->sw->DPID);
    cofp_gm->command = add ? C_OFPG_ADD: C_OFPG_DEL;
    cofp_gm->group_id = htonl(grp->group);
    cofp_gm->type = grp->type;
    cofp_gm->flags = grp->flags;
    if (!grp->installed) {
        cofp_gm->flags |= C_GRP_NOT_INSTALLED; 
    }
    cofp_gm->byte_count = ntohll(grp->byte_count);
    cofp_gm->packet_count = ntohll(grp->packet_count);
    cofp_gm->duration_sec = ntohl(grp->duration_sec);
    cofp_gm->duration_nsec = ntohl(grp->duration_nsec);

    tot_len = sizeof(*cofp_gm);
    for (act = 0; add && act < grp->act_vec_len; act++) {
        bkt = INC_PTR8(cofp_gm, tot_len); 
        act_elem = grp->act_vectors[act];

        assert(act_elem);

        tot_len +=  sizeof(*bkt) + act_elem->action_len;
        bkt->weight = htons(act_elem->weight);
        bkt->ff_port = htonl(act_elem->ff_port);
        bkt->ff_group = htonl(act_elem->ff_group);
        bkt->act_len = htons(act_elem->action_len);
        memcpy(bkt->actions, act_elem->actions, act_elem->action_len);
    }

    return b;
}

static void
c_per_group_iter(void *k UNUSED, void *v, void *args)
{
    struct c_iter_args *u_parms = args;
    c_switch_group_t *grp = v;
    group_parser_fn fn;

    fn = (group_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, grp);
}

void
c_switch_group_traverse_all(c_switch_t *sw, void *u_arg, group_parser_fn fn)
{
    struct c_iter_args args;

    args.u_arg = u_arg;
    args.u_fn = fn;

    c_rd_lock(&sw->lock);
    if (sw->groups) {
        g_hash_table_foreach(sw->groups,
                             (GHFunc)c_per_group_iter, &args);
    }
    c_rd_unlock(&sw->lock);
}

static void
c_group_act_bucket_free(void *arg)
{
    struct of_act_vec_elem *elem = arg;

    if (elem) {
        if (elem->actions) free(elem->actions);
        free(elem);
    }
}

static int 
__c_switch_group_modify(c_switch_t *sw UNUSED, c_switch_group_t *old,
                        struct of_group_mod_params *gp_parms,
                        bool *install)
{
    int bkt = 0;
    bool bkt_diff = 1;

    if (!(old->flags & C_GRP_RESIDUAL) &&
        old->app_owner != gp_parms->app_owner) {
        c_log_err("|GROUP| Mod failed. Not owner");
        return -1; 
    }

    if (old->act_vec_len == gp_parms->act_vec_len) {
        bkt_diff = 0;
        for (bkt = 0; bkt < old->act_vec_len; bkt++) {
            if (old->act_vectors[bkt]->weight != 
                gp_parms->act_vectors[bkt]->weight ||
                old->act_vectors[bkt]->ff_port !=
                gp_parms->act_vectors[bkt]->ff_port ||
                old->act_vectors[bkt]->ff_group !=
                gp_parms->act_vectors[bkt]->ff_group ||
                ((old->act_vectors[bkt]->action_len !=
                gp_parms->act_vectors[bkt]->action_len) ||
                memcmp(old->act_vectors[bkt]->actions,
                       gp_parms->act_vectors[bkt]->actions,
                       old->act_vectors[bkt]->action_len))) {
                bkt_diff = 1;
                break;
            } 
        }
    }

    if (old->flags & C_GRP_EXPIRED) {
        /* If it has expired allow modification */
        bkt_diff = 1;
    }

    if (old->flags & C_GRP_RESIDUAL && 
        !(gp_parms->flags & C_GRP_RESIDUAL)) {
        if (bkt_diff) *install = true;
        else *install = false;
        bkt_diff = 1;
        c_app_put(old->app_owner);
        old->app_owner = gp_parms->app_owner;
        c_app_ref(old->app_owner);
    }
        
    if (!bkt_diff) {
        c_log_err("|GROUP| Mod failed. Same group");
        return -1;
    }

    for (bkt = 0; bkt < old->act_vec_len; bkt++) {
        c_group_act_bucket_free(old->act_vectors[bkt]);
        old->act_vectors[bkt] = NULL;
    }

    old->type = gp_parms->type;
    old->flags = gp_parms->flags;
    for (bkt = 0; bkt < gp_parms->act_vec_len; bkt++) {
        old->act_vectors[bkt] = gp_parms->act_vectors[bkt];
    }
    old->act_vec_len = gp_parms->act_vec_len;

    old->installed = 0;
    old->last_scan = 0;

    old->last_seen = time(NULL);

    return 0;
}

static c_switch_group_t *
c_switch_group_init(c_switch_t *sw, struct of_group_mod_params *gp_parms)
{
    c_switch_group_t *new;
    int act = 0;

    new = calloc(1, sizeof(*new));
    assert(new);

    new->group = gp_parms->group;
    new->type = gp_parms->type;
    new->flags = gp_parms->flags;
    new->app_owner = gp_parms->app_owner;
    for (act = 0; act < gp_parms->act_vec_len; act++) {
        new->act_vectors[act] = gp_parms->act_vectors[act];
    }
    new->act_vec_len = gp_parms->act_vec_len;
    c_app_ref(new->app_owner);
    new->sw = sw;
    new->last_seen = time(NULL);
    new->installed = true;

    return new;
}

static void
c_switch_group_ent_free(void *arg) 
{
    c_switch_group_t *group = arg;
    int acts = 0;

    c_app_put(group->app_owner);
    for(; acts < group->act_vec_len; acts++) {
        c_group_act_bucket_free(group->act_vectors[acts]);
    }
    free(group);
}

static int
c_group_owner_match(void *k_arg UNUSED, void *v_arg, void *u_arg)
{
    c_switch_group_t *group = v_arg;

    if (group->app_owner == u_arg) {
        return 1;
    }
    
    return 0;
}

void
__c_per_switch_del_group_with_owner(c_switch_t *sw, void *app)
{
    g_hash_table_foreach_remove(sw->groups, c_group_owner_match, app);
}

int
c_switch_group_add(c_switch_t *sw, struct of_group_mod_params *gp_parms) 
{
    c_switch_group_t *group;
    struct cbuf *b;
    bool modify = false;
    bool install = true;

    if (!C_SWITCH_SUPPORTS_GROUP(sw)) {
        return -1;
    }

    if (!sw->ofp_ctors->group_validate(true, gp_parms->group, gp_parms->type,
                                       gp_parms->act_vectors,
                                       gp_parms->act_vec_len)) {
        c_log_err("[GROUP] add failed:invalid-args");
        return -1;
    }

    c_wr_lock(&sw->lock);
    if ((group = g_hash_table_lookup(sw->groups, &gp_parms->group))) {
        if (__c_switch_group_modify(sw, group, gp_parms, &install)) {
            c_log_err("[GROUP] |%u| on switch |0x%llx| exists",
                      gp_parms->group, sw->DPID); 
            c_wr_unlock(&sw->lock);
            return -1;
        } 
        c_wr_unlock(&sw->lock);
        modify = true;
        goto hw_install;
    } else {
        if (gp_parms->flags & C_GRP_RESIDUAL)
            install = false;
    }

    group = c_switch_group_init(sw, gp_parms);
    g_hash_table_insert(sw->groups, &group->group, group);
    c_wr_unlock(&sw->lock);

hw_install:
    b = sw->ofp_ctors->group_add(gp_parms->group,
                                 gp_parms->type,
                                 gp_parms->act_vectors,
                                 gp_parms->act_vec_len, modify);
    c_switch_tx(sw, b, false);
    if (gp_parms->flags & C_GRP_BARRIER_EN)
        __of_send_barrier_request(sw);

    return 0;
}

int
c_switch_group_del(c_switch_t *sw, struct of_group_mod_params *gp_parms) 
{
    c_switch_group_t *group;
    struct cbuf *b;

    if (!C_SWITCH_SUPPORTS_GROUP(sw)) {
        return -1;
    }

    if (!sw->ofp_ctors->group_validate(false, gp_parms->group,
                                       gp_parms->type,
                                       gp_parms->act_vectors,
                                       gp_parms->act_vec_len)) {
        c_log_err("[GROUP] del failed:invalid args");
        return -1;
    }

    c_wr_lock(&sw->lock);
    if (!(group = g_hash_table_lookup(sw->groups, &gp_parms->group))) {
        c_log_err("[GROUP] del fail:switch 0x%llx:No such grp |%u|",
                  sw->DPID, gp_parms->group); 
        c_wr_unlock(&sw->lock);
        return -1;
    }

    if (atomic_read(&group->ref)) {
        c_log_err("[GROUP] del fail:switch 0x%llx:grp |%u| has ref left",
                  sw->DPID, gp_parms->group);
        c_wr_unlock(&sw->lock);
        return -1;
    }

    if (group->app_owner == gp_parms->app_owner) {
        g_hash_table_remove(sw->groups, &gp_parms->group);

        if (sw->ofp_ctors && sw->ofp_ctors->group_del) {
            b = sw->ofp_ctors->group_del(gp_parms->group);
            c_switch_tx(sw, b, false);
        }
    }

    c_wr_unlock(&sw->lock);
    return 0;
}

static int
c_of_meter_cmp_list(const void *list_arg, const void *uarg)
{
    uint32_t m1 = *(uint32_t *)list_arg;
    uint32_t m2 = *(uint32_t *)uarg;

    if (m1 == m2) return 0;
    return -1;
}

bool
c_of_fl_meter_check_add(void *sw_arg, uint32_t meter_id, void *arg)
{
    c_switch_t *sw = sw_arg;
    struct ofp_inst_check_args *u_arg = arg;
    uint32_t *new_meter;
    c_switch_meter_t *meter;

    c_rd_lock(&sw->lock);
    if (!(meter = g_hash_table_lookup(sw->meters, &meter_id))) {
        c_log_err("[METER] No |%u| on switch |0x%llx| exists",
                  meter_id, sw->DPID);
        c_rd_unlock(&sw->lock);
        return false;
    } else {
        if (meter->cflags & C_METER_EXPIRED) {
            c_log_err("[METER] |%u| on switch |0x%llx| expired/dead",
                      meter_id, sw->DPID);
            c_rd_unlock(&sw->lock);
            return false;
        }
    }
    c_rd_unlock(&sw->lock);

    if (u_arg->meter_list &&
        g_slist_find_custom(u_arg->meter_list, &meter_id,
                            (GCompareFunc)c_of_meter_cmp_list)) {
        return true;
    }

    new_meter = malloc(sizeof(uint32_t));
    if (!new_meter) return false;

    *new_meter = meter_id;

    u_arg->meter_list = g_slist_append(u_arg->meter_list, new_meter);
    return true;
}

struct cbuf *
c_of_prep_meter_feature_msg(c_switch_t *sw)
{
    struct cbuf *b;
    size_t tot_len = 0;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_switch_feature_common *cofp_sfc;

    c_rd_lock(&sw->lock);
    tot_len = sizeof(*cofp_sfc) + sizeof(*cofp_aac) +
              ((sw->meter_features) ? sw->meter_feat_len : 0);

    b = of_prep_msg(tot_len, C_OFPT_AUX_CMD, 0);

    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code =  htonl(C_AUX_CMD_MUL_SWITCH_METER_FEAT);

    cofp_sfc = ASSIGN_PTR(cofp_aac->data);
    cofp_sfc->datapath_id = htonll(sw->DPID);
    if (sw->group_features) {
        memcpy(cofp_sfc->data, sw->meter_features, sw->meter_feat_len);
    }

    c_rd_unlock(&sw->lock);

    return b;
}

struct cbuf *
c_of_prep_meter_mod_msg(c_switch_meter_t *meter, bool add)
{
    struct cbuf *b;
    size_t tot_len = 0;
    int nband = 0;
    struct c_ofp_meter_mod *cofp_mm;
    struct of_meter_band_elem *band_elem;
    struct ofp_meter_band_header *band_bkt;

    for (;add &&  nband < meter->meter_nbands; nband++) {
        band_elem = meter->meter_bands[nband];
        if (band_elem)
            tot_len += band_elem->band_len;
    }

    tot_len += sizeof(*cofp_mm);

    b = of_prep_msg(tot_len, C_OFPT_METER_MOD, 0);

    cofp_mm = CBUF_DATA(b);
    cofp_mm->datapath_id = htonll(meter->sw->DPID);
    cofp_mm->command = add ? C_OFPMC_ADD : C_OFPMC_DEL;
    cofp_mm->meter_id = htonl(meter->meter);
    cofp_mm->flags = htons(meter->flags);
    cofp_mm->c_flags = meter->cflags;
    if (!meter->installed) {
        cofp_mm->c_flags |= C_METER_NOT_INSTALLED;
    }
    cofp_mm->byte_count = htonll(meter->byte_count);
    cofp_mm->packet_count = htonll(meter->packet_count);
    cofp_mm->flow_count = htonl(meter->flow_count);
    cofp_mm->duration_sec = htonl(meter->duration_sec);
    cofp_mm->duration_nsec = htonl(meter->duration_nsec);

    tot_len = sizeof(*cofp_mm);
    for (nband = 0; add && nband < meter->meter_nbands; nband++) {
        band_bkt = INC_PTR8(cofp_mm, tot_len); 
        band_elem = meter->meter_bands[nband];

        assert(band_elem);

        tot_len +=  band_elem->band_len;
        memcpy(band_bkt, band_elem->band, band_elem->band_len);
    }

    return b;
}

static struct cbuf *
c_of_prep_meter_mod_msg_with_parms(c_switch_t *sw,
                                   struct of_meter_mod_params *m_parms,
                                   bool add)
{
    struct cbuf *b;
    size_t tot_len = 0;
    int nband = 0;
    struct c_ofp_meter_mod *cofp_mm;
    struct of_meter_band_elem *band_elem;
    struct ofp_meter_band_header *band_bkt;

    for (;add &&  nband < m_parms->meter_nbands; nband++) {
        band_elem = m_parms->meter_bands[nband];
        if (band_elem)
            tot_len += band_elem->band_len;
    }

    tot_len += sizeof(*cofp_mm);

    b = of_prep_msg(tot_len, C_OFPT_METER_MOD, 0);

    cofp_mm = CBUF_DATA(b);
    cofp_mm->datapath_id = htonll(sw->DPID);
    cofp_mm->command = add ? C_OFPMC_ADD : C_OFPMC_DEL;
    cofp_mm->meter_id = htonl(m_parms->meter);
    cofp_mm->flags = htons(m_parms->flags);
    cofp_mm->c_flags = m_parms->cflags;

    tot_len = sizeof(*cofp_mm);
    for (nband = 0; add && nband < m_parms->meter_nbands; nband++) {
        band_bkt = INC_PTR8(cofp_mm, tot_len); 
        band_elem = m_parms->meter_bands[nband];

        assert(band_elem);

        tot_len +=  band_elem->band_len;
        memcpy(band_bkt, band_elem->band, band_elem->band_len);
    }

    return b;
}

static void
c_per_meter_iter(void *k UNUSED, void *v, void *args)
{
    struct c_iter_args *u_parms = args;
    c_switch_meter_t *meter = v;
    meter_parser_fn fn;

    fn = (meter_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, meter);
}

void
c_switch_meter_traverse_all(c_switch_t *sw, void *u_arg, meter_parser_fn fn)
{
    struct c_iter_args args;

    args.u_arg = u_arg;
    args.u_fn = fn;

    c_rd_lock(&sw->lock);
    if (sw->meters) {
        g_hash_table_foreach(sw->meters,
                             (GHFunc)c_per_meter_iter, &args);
    }
    c_rd_unlock(&sw->lock);
}

static void
c_meter_band_free(void *arg)
{
    struct of_meter_band_elem *elem = arg;

    if (elem) {
        if (elem->band) free(elem->band);
        free(elem);
    }
}

static int 
__c_switch_meter_modify(c_switch_t *sw UNUSED, c_switch_meter_t *old,
                        struct of_meter_mod_params *m_parms,
                        bool *install)
{
    int met = 0;
    bool bands_diff = 1;


    if (!(old->cflags & C_METER_RESIDUAL) &&
        (old->app_owner != m_parms->app_owner)) {
        c_log_err("|METER| Mod failed. Not owner");
        return -1; 
    }

    if (old->meter_nbands == m_parms->meter_nbands) {
        bands_diff = 0;
        for (met = 0; met < old->meter_nbands; met++) {
            if ((old->meter_bands[met]->band_len !=
                m_parms->meter_bands[met]->band_len) ||
                memcmp(old->meter_bands[met]->band,
                       m_parms->meter_bands[met]->band,
                       m_parms->meter_bands[met]->band_len)) {
                bands_diff = 1;
                break;
            } 
        }
    }

    if (old->cflags & C_METER_EXPIRED) {
        /* If it has expired allow modification */
        bands_diff = 1;
    }

    if (old->cflags & C_METER_RESIDUAL &&
        !(m_parms->cflags & C_METER_RESIDUAL)) {
        if (bands_diff) *install = true;
        else *install = false; 
        bands_diff = 1; 
        c_app_put(old->app_owner);
        old->app_owner = m_parms->app_owner;
        c_app_ref(old->app_owner);
    }
    if (!bands_diff) {
        c_log_err("|METER| Mod failed. Same meter");
        return -1;
    }

    for (met = 0; met < old->meter_nbands; met++) {
        c_meter_band_free(old->meter_bands[met]);
        old->meter_bands[met] = NULL; 
    }

    old->flags = m_parms->flags;
    old->cflags = m_parms->cflags;
    for (met = 0; met < m_parms->meter_nbands; met++) {
        old->meter_bands[met] = m_parms->meter_bands[met];
    }
    old->meter_nbands = m_parms->meter_nbands;
    old->installed = 0;
    old->last_scan = 0;

    old->last_seen = time(NULL);

    return 0;
}

static c_switch_meter_t *
c_switch_meter_init(c_switch_t *sw, struct of_meter_mod_params *m_parms)
{
    c_switch_meter_t *new;
    int met = 0;

    new = calloc(1, sizeof(*new));
    assert(new);

    new->meter = m_parms->meter;
    new->flags = m_parms->flags;
    new->cflags = m_parms->cflags;
    new->app_owner = m_parms->app_owner;
    for (met = 0; met < m_parms->meter_nbands; met++) {
        new->meter_bands[met] = m_parms->meter_bands[met];
    }
    new->meter_nbands = m_parms->meter_nbands;
    c_app_ref(new->app_owner);
    new->sw = sw;
    new->last_seen = time(NULL);
    new->installed = true;

    return new;
}

static void
c_switch_meter_ent_free(void *arg) 
{
    c_switch_meter_t *meter = arg;
    int acts = 0;

    c_app_put(meter->app_owner);
    for(; acts < meter->meter_nbands; acts++) {
        c_meter_band_free(meter->meter_bands[acts]);
        meter->meter_bands[acts] = NULL;
    }
    free(meter);
}

static int
c_meter_owner_match(void *k_arg UNUSED, void *v_arg, void *u_arg)
{
    c_switch_meter_t *meter = v_arg;

    if (meter->app_owner == u_arg) {
        return 1;
    }
    
    return 0;
}

void
__c_per_switch_del_meter_with_owner(c_switch_t *sw, void *app)
{
    g_hash_table_foreach_remove(sw->meters, c_meter_owner_match, app);
}

int
c_switch_meter_add(c_switch_t *sw, struct of_meter_mod_params *m_parms)
{
    c_switch_meter_t *meter;
    struct cbuf *b;
    bool modify = false;
    bool install = true;

    if (!C_SWITCH_SUPPORTS_METER(sw)) {
        return -1;
    }

    c_wr_lock(&sw->lock);
    if ((meter = g_hash_table_lookup(sw->meters, &m_parms->meter))) {
        if (__c_switch_meter_modify(sw, meter, m_parms, &install)) {
            c_log_err("[METER] add fail:switch 0x%llx:|%u| exists",
                      sw->DPID, m_parms->meter);
            c_wr_unlock(&sw->lock);
            return -1;
        }
        c_wr_unlock(&sw->lock);
        modify = true;
        goto hw_install; 
    } else {
        if (m_parms->cflags & C_METER_RESIDUAL) 
            install = false;
    }

    meter = c_switch_meter_init(sw, m_parms);
    g_hash_table_insert(sw->meters, &meter->meter, meter);
    c_wr_unlock(&sw->lock);

hw_install:
    b = sw->ofp_ctors->meter_add(m_parms->meter, m_parms->flags,
                                 m_parms->meter_bands,
                                 m_parms->meter_nbands, modify);

    c_switch_tx(sw, b, false);
    if (m_parms->cflags & C_METER_BARRIER_EN)
        __of_send_barrier_request(sw);

    return 0;
}

int
c_switch_meter_del(c_switch_t *sw, struct of_meter_mod_params *m_parms)
{
    c_switch_meter_t *meter;
    struct cbuf *b;

    if (!C_SWITCH_SUPPORTS_METER(sw)) {
        return -1;
    }

    c_wr_lock(&sw->lock);
    if (!(meter = g_hash_table_lookup(sw->meters, &m_parms->meter))) {
        c_log_err("[METER] del fail:switch 0x%llx:no meter %u",
                  sw->DPID, m_parms->meter);
        c_wr_unlock(&sw->lock);
        return -1;
    }

    if (atomic_read(&meter->ref)) {
        c_log_err("[GROUP] del fail:switch 0x%llx:meter |%u| has ref left",
                  sw->DPID, m_parms->meter);
        c_wr_unlock(&sw->lock);
        return -1;
    }

    if (meter->app_owner == m_parms->app_owner) {
        g_hash_table_remove(sw->meters, &m_parms->meter);

        if (sw->ofp_ctors && sw->ofp_ctors->meter_del) {
            b = sw->ofp_ctors->meter_del(m_parms->meter);
            c_switch_tx(sw, b, false);
        }
    }

    c_wr_unlock(&sw->lock);

    return 0;
}

int
c_switch_port_mod(c_switch_t *sw, struct of_port_mod_params *pm_parms)
{
    c_port_t *port = NULL;
    struct cbuf *b;

    c_rd_lock(&sw->lock);
    if (!(port = g_hash_table_lookup(sw->sw_ports, &pm_parms->port_no))) {
        c_rd_unlock(&sw->lock);
        c_log_err("%s: Port no %d is not valid.",FN, pm_parms->port_no);
        return -1;
    }

    c_rd_unlock(&sw->lock);
    
    pm_parms->type = ntohs(port->sw_port.type);

    b = sw->ofp_ctors->port_mod(pm_parms->port_no, pm_parms,
                                port->sw_port.hw_addr);
    c_switch_tx(sw, b, false);

    return 0;
}

void
c_switch_async_config(c_switch_t *sw, struct of_async_config_params *ac_params)
{
    struct cbuf *b;

    b = sw->ofp_ctors->async_config(ac_params);
    c_switch_tx(sw, b, false);
    
    return;
}

struct cbuf *
c_of_prep_switch_rlims(c_switch_t *sw, bool rx, bool get)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_rlim *cofp_rl;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rl),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = get ? htonl(C_AUX_CMD_MUL_SWITCH_GET_RLIM) :
                               htonl(C_AUX_CMD_MUL_SWITCH_RLIM);
    cofp_rl = ASSIGN_PTR(cofp_auc->data);
    cofp_rl->datapath_id = htonll(sw->DPID);

    c_rd_lock(&sw->lock);
    if (rx) {
        cofp_rl->is_rx = htonl(1);
        cofp_rl->pps = sw->rx_lim_on ? htonl(sw->rx_rlim.max) : 0;
    } else {
        cofp_rl->pps = sw->tx_lim_on ? htonl(sw->tx_rlim.max) : 0;
    }

    c_rd_unlock(&sw->lock);

    return b;
}

/*
 * c_switch_rlim_sync - 
 *
 * Sync up switch's rate-limit info 
 */
void
c_switch_rlim_sync(c_switch_t *sw UNUSED)
{
    /* TODO */
} 

struct cbuf *
c_of_prep_switch_stats_strategy(c_switch_t *sw)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_stats_strategy *cofp_ss;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_ss),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_SET_STATS_STRAT); 
    cofp_ss = ASSIGN_PTR(cofp_auc->data);
    cofp_ss->datapath_id = htonll(sw->DPID);

    c_rd_lock(&sw->lock);
    cofp_ss->fl_bulk_enable = sw->switch_state & SW_BULK_FLOW_STATS ?
                                        htonl(1) : 0;
    cofp_ss->grp_bulk_enable = sw->switch_state & SW_BULK_GRP_STATS ?
                                        htonl(1) : 0;
    cofp_ss->meter_bulk_config_enable =
        sw->switch_state & SW_BULK_METER_CONF_STATS? htonl(1) : 0;

    c_rd_unlock(&sw->lock);

    return b;
}

/*
 * c_switch_stats_strategy_sync - 
 *
 * Sync up switch's stats strategy 
 */
void
c_switch_stats_strategy_sync(c_switch_t *sw UNUSED)
{
    /* TODO */
}

struct cbuf *
c_of_prep_switch_table_stats(c_switch_t *sw, uint8_t table_id)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_table_stats *cofp_ts;
    c_flow_tbl_t *tbl = NULL;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_ts),
                    C_OFPT_AUX_CMD, 0);
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_GET_TBL_STATS);
    cofp_ts = ASSIGN_PTR(cofp_auc->data);
    cofp_ts->datapath_id = htonll(sw->DPID);
    cofp_ts->table_id = table_id;

    c_rd_lock(&sw->lock);

    tbl = &sw->rule_flow_tbls[table_id];
    if (tbl && tbl->hw_tbl_active) {
        cofp_ts->active_count = htonl(tbl->hw_active_count);
        cofp_ts->lookup_count = htonll(tbl->hw_lookup_count);
        cofp_ts->matched_count = htonll(tbl->hw_matched_count);
    }
    c_rd_unlock(&sw->lock);

    return b;
}

struct cbuf *
c_of_prep_port_stats(c_switch_t *sw, uint32_t port_no)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_port_query *cofp_pq;
    c_port_t *port = NULL;
    size_t port_stat_len = 0;
    
    c_rd_lock(&sw->lock);
    
    port = __c_switch_port_find(sw, ntohl(port_no));

    if(!port) {
        c_log_warn("%s: Port stats query for Invalid port(%u) ", FN,
                   ntohl(port_no));
    }
    
    if (port && port->port_stats) {
        port_stat_len = port->port_stat_len;
    }

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_pq) + port_stat_len,
                    C_OFPT_AUX_CMD, 0);
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_PORT_QUERY);
    cofp_pq = ASSIGN_PTR(cofp_auc->data);
    cofp_pq->datapath_id = htonll(sw->DPID);
    cofp_pq->port_no = htonl(port_no);

    if (port && port->port_stats) {
        memcpy(cofp_pq->data,port->port_stats, port->port_stat_len);
    }
    c_rd_unlock(&sw->lock);

    return b;
}

static inline void
of_prep_msg_on_stack(struct cbuf *b, size_t len, uint8_t type,
                     uint32_t xid, uint8_t version)
{
    struct ofp_header *h;

    h = (void *)(b->data);

    h->version = version;
    h->type = type;
    h->length = htons(len);
    h->xid = xid;

    /* NOTE - No memset of extra data for performance */
    return;
}

void
of_send_features_request(c_switch_t *sw)
{
    if (!sw->ofp_ctors->features) {
        return;
    }
    c_switch_tx(sw, sw->ofp_ctors->features(), true);
}

void
__of_send_features_request(c_switch_t *sw)
{
    of_send_features_request(sw);
    c_thread_sg_tx_sync(&sw->conn);
}

void
of_send_set_config(c_switch_t *sw, uint16_t flags, uint16_t miss_len)
{
    struct cbuf *b;
    
    b = sw->ofp_ctors->set_config(flags, miss_len);
    c_switch_tx(sw, b, false);
}

void
__of_send_set_config(c_switch_t *sw, uint16_t flags, uint16_t miss_len)
{
    of_send_set_config(sw, flags, miss_len);
}

void
of_send_echo_request(c_switch_t *sw)
{
    struct cbuf *b = sw->ofp_ctors->echo_req();
    c_switch_tx(sw, b, false);
}

void
__of_send_echo_request(c_switch_t *sw)
{
    of_send_echo_request(sw);
}

void
of_send_echo_reply(c_switch_t *sw, uint32_t xid)
{
    struct cbuf *b = sw->ofp_ctors->echo_rsp(xid);
    c_switch_tx(sw, b, false);
}

void
__of_send_echo_reply(c_switch_t *sw, uint32_t xid)
{
    of_send_echo_reply(sw, xid);
}

void
of_send_hello(c_switch_t *sw)
{
    struct cbuf *b = sw->ofp_ctors->hello();
    c_switch_tx(sw, b, false);
}

void __fastpath
of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    struct cbuf *b;

    b = sw->ofp_ctors->pkt_out(parms);
    c_switch_tx(sw, b, true);
} 

void __fastpath
of_send_pkt_out_inline(void *arg, struct of_pkt_out_params *parms)
{
    struct cbuf b;
    size_t tot_len;
    uint8_t data[C_INLINE_BUF_SZ];
    struct ofp_packet_out *out;
    c_switch_t *sw = arg;

    if (sw->tx_lim_on && c_rlim(&sw->tx_rlim)) {
        sw->tx_pkt_out_dropped++;
        return;
    }

    tot_len = sizeof(struct ofp_packet_out) + parms->action_len + parms->data_len;
    if (unlikely(tot_len > C_INLINE_BUF_SZ)) return of_send_pkt_out(sw, parms);

    cbuf_init_on_stack(&b, data, tot_len);
    of_prep_msg_on_stack(&b, tot_len, OFPT_PACKET_OUT, 
                         (unsigned long)parms->data, sw->version);

    out = (void *)b.data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htons(parms->in_port);
    out->actions_len = htons(parms->action_len);
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy((uint8_t *)out->actions + parms->action_len, 
            parms->data, parms->data_len);

    c_switch_tx(sw, &b, false);
} 

void __fastpath
__of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    of_send_pkt_out(sw, parms);
    c_thread_sg_tx_sync(&sw->conn);
}

#if 0
struct cbuf *
c_ofp_prep_flow_mod(c_switch_t *sw, c_fl_entry_t *ent,
                    bool add)
{
    struct cbuf *b;
    c_ofp_flow_mod_t *cofp_fm;
    void *act;
    size_t tot_len = 0;
    size_t action_len = add ? ent->action_len : 0;

    tot_len = sizeof(*cofp_fm) + action_len;
    b = of_prep_msg(tot_len, C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    cofp_fm->sw_alias = htonl((uint32_t)(sw->alias_id));
    cofp_fm->datapath_id = htonll(sw->DPID);
    cofp_fm->command = add ? C_OFPC_ADD : C_OFPC_DEL;
    cofp_fm->flags = htonll(ent->FL_FLAGS);
    memcpy(&cofp_fm->flow, &ent->fl, sizeof(struct flow));
    memcpy(&cofp_fm->mask, &ent->fl_mask, sizeof(struct flow));
    cofp_fm->wildcards = 0;
    cofp_fm->priority = ntohs(ent->FL_PRIO);
    cofp_fm->itimeo = ntohs(ent->FL_ITIMEO);
    cofp_fm->htimeo = htons(ent->FL_HTIMEO);
    cofp_fm->buffer_id = 0xffffffff;
    cofp_fm->oport = OF_NO_PORT;
    cofp_fm->cookie = htonl(ent->FL_COOKIE);

    if (add) {
        act = ASSIGN_PTR(cofp_fm->actions);
        memcpy(act, ent->actions, action_len);
    }

    return b;
}
#endif

static struct cbuf *
c_ofp_prep_flow_mod_with_parms(c_switch_t *sw,
                               struct flow *flow,
                               struct flow *mask,
                               uint16_t itimeo,
                               uint16_t htimeo, 
                               uint64_t flags,
                               uint16_t prio,
                               uint32_t buffer_id,
                               uint32_t cookie_id,
                               void *actions,
                               size_t action_len,
                               bool add)
{
    struct cbuf *b;
    c_ofp_flow_mod_t *cofp_fm;
    void *act;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_fm) + action_len;
    b = of_prep_msg(tot_len, C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    cofp_fm->sw_alias = htonl((uint32_t)(sw->alias_id));
    cofp_fm->datapath_id = htonll(sw->DPID);
    cofp_fm->command = add ? C_OFPC_ADD : C_OFPC_DEL;
    cofp_fm->flags = htonll(flags);
    memcpy(&cofp_fm->flow, flow, sizeof(struct flow));
    memcpy(&cofp_fm->mask, mask, sizeof(struct flow));
    cofp_fm->wildcards = 0;
    cofp_fm->priority = ntohs(prio);
    cofp_fm->itimeo = ntohs(itimeo);
    cofp_fm->htimeo = htons(htimeo);
    cofp_fm->buffer_id = htonl(buffer_id);
    cofp_fm->oport = OF_NO_PORT;
    cofp_fm->cookie = htonl(cookie_id);

    if (add && actions && action_len) {
        act = ASSIGN_PTR(cofp_fm->actions);
        memcpy(act, actions, action_len);
    }

    return b;
}

struct cbuf *
c_ofp_prep_flow_mod(c_switch_t *sw, c_fl_entry_t *ent,
                    bool add)
{
    return c_ofp_prep_flow_mod_with_parms(sw, &ent->fl, &ent->fl_mask,
                                          ent->FL_ITIMEO, ent->FL_HTIMEO,   
                                          ent->FL_FLAGS, ent->FL_PRIO,
                                          (uint32_t)(-1), ent->FL_COOKIE,
                                          add ? ent->actions : NULL, 
                                          add ? ent->action_len : 0, add);
}

static void
of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id,
                 bool ha_sync UNUSED, bool modify)
{
    struct cbuf *b;

    b = sw->ofp_ctors->flow_add(&ent->fl, &ent->fl_mask, 
                                buffer_id, ent->actions, 
                                ent->action_len, ent->FL_ITIMEO,
                                ent->FL_HTIMEO, ent->FL_PRIO,
                                ent->FL_COOKIE, modify); 
    c_switch_tx(sw, b, true);

    if (ent->FL_FLAGS & C_FL_ENT_BARRIER)
        __of_send_barrier_request(sw);
} 

static void UNUSED
__of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id,
                   bool ha_sync, bool modify)
{
    of_send_flow_add(sw, ent, buffer_id, ha_sync, modify);
    c_thread_sg_tx_sync(&sw->conn);
}

int __fastpath
of_send_flow_add_direct(c_switch_t *sw, struct flow *fl, struct flow *mask, 
                        uint32_t buffer_id, void *actions, size_t action_len,
                        uint16_t itimeo, uint16_t htimeo, uint16_t prio)
{
    struct cbuf *b;

    b = sw->ofp_ctors->flow_add(fl, mask,
                                buffer_id, actions, 
                                action_len, itimeo, htimeo,
                                prio, 0, false); /* dont care about cookie */
    c_switch_tx(sw, b, true);
    return 0;
} 

int __fastpath
__of_send_flow_add_direct(c_switch_t *sw, struct flow *fl, struct flow *mask, 
                          uint32_t buffer_id, void *actions, size_t action_len,
                          uint16_t itimeo, uint16_t htimeo, uint16_t prio)
{
    int ret;
    ret = of_send_flow_add_direct(sw, fl, mask, buffer_id,
                                  actions, action_len,
                                  itimeo, htimeo, prio);
    c_thread_sg_tx_sync(&sw->conn);
    return ret;
}

static void
of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport,
                 bool strict, uint32_t group)
{
    struct cbuf *b;

    b = sw->ofp_ctors->flow_del(&ent->fl, &ent->fl_mask,
                                oport, strict,
                                ent->FL_PRIO, group);
    c_switch_tx(sw, b, true);
}

static void
of_send_flow_del_strict(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport, 
                        uint32_t group)
{
    struct cbuf *b;

    b = sw->ofp_ctors->flow_del(&ent->fl, &ent->fl_mask,
                                oport, true, ent->FL_PRIO,
                                group);
    c_switch_tx(sw, b, true);
}

static void UNUSED
__of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport,
                   bool strict, uint32_t group)
{
    of_send_flow_del(sw, ent, oport, strict, group);
    c_thread_sg_tx_sync(&sw->conn);
}

int
of_send_flow_del_direct(c_switch_t *sw, struct flow *fl, struct flow *mask,
                         uint16_t oport, bool strict, uint16_t prio, 
                         uint32_t group)
{
    struct cbuf *b;
    b = sw->ofp_ctors->flow_del(fl, mask, 
                                oport, strict,
                                prio, group);
    c_switch_tx(sw, b, true);
    return 0;
}

int
__of_send_flow_del_direct(c_switch_t *sw, struct flow *fl, struct flow *mask,
                         uint16_t oport, bool strict, uint16_t prio,
                         uint32_t group)
{
    of_send_flow_del_direct(sw, fl, mask, oport, strict, prio, group);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

int
of_send_flow_stat_req(c_switch_t *sw, const struct flow *flow, 
                      const struct flow *mask, uint32_t oport,
                      uint32_t group)
{
    struct cbuf *b;

    if (sw->ofp_ctors->flow_stat_req) {
        b = sw->ofp_ctors->flow_stat_req(flow, mask, oport, group);
        c_switch_tx(sw, b, true);
    } else {
        return -1;
    } 

    return 0;
}

int
__of_send_flow_stat_req(c_switch_t *sw, const struct flow *flow, 
                        const struct flow *mask, uint32_t oport,
                        uint32_t group)
{
    of_send_flow_stat_req(sw, flow, mask, oport, group);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

int
of_send_group_stat_req(c_switch_t *sw, uint32_t group_id) 
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->group_stat_req) {
        b = sw->ofp_ctors->group_stat_req(group_id);
        c_switch_tx(sw, b, true);
    } else {
        return -1;
    }

    return 0;
}

int
__of_send_group_stat_req(c_switch_t *sw, uint32_t group_id)
{
    of_send_group_stat_req(sw, group_id);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

int
of_send_meter_stat_req(c_switch_t *sw, uint32_t meter_id) 
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->meter_stat_req) {
        b = sw->ofp_ctors->meter_stat_req(meter_id);
        c_switch_tx(sw, b, true);
    } else {
        return -1;
    }

    return 0;
}

int
__of_send_meter_stat_req(c_switch_t *sw, uint32_t meter_id)
{
    of_send_meter_stat_req(sw, meter_id);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

int
of_send_meter_config_stat_req(c_switch_t *sw, uint32_t meter_id) 
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->meter_stat_cfg_req) {
        b = sw->ofp_ctors->meter_stat_cfg_req(meter_id);
        c_switch_tx(sw, b, true);
    } else {
        return -1;
    }

    return 0;
}

int
__of_send_meter_config_stat_req(c_switch_t *sw, uint32_t meter_id)
{
    of_send_meter_config_stat_req(sw, meter_id);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

int
of_send_port_stat_req(c_switch_t *sw, uint32_t port_no) 
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->port_stat_req) {
        b = sw->ofp_ctors->port_stat_req(port_no);
        c_switch_tx(sw, b, true);
    } else {
        return -1;
    }

    return 0;
}

int
__of_send_port_stat_req(c_switch_t *sw, uint32_t port_no)
{
    of_send_port_stat_req(sw, port_no);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

int
of_send_port_q_get_conf(c_switch_t *sw, uint32_t port_no) 
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->port_q_get_conf) {
        b = sw->ofp_ctors->port_q_get_conf(port_no);
        c_switch_tx(sw, b, true);
    } else {
        return -1;
    }

    return 0;
}

int
__of_send_port_q_get_conf(c_switch_t *sw, uint32_t port_no)
{
    of_send_port_q_get_conf(sw, port_no);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

void
__of_send_clear_all_groups(c_switch_t *sw)
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->group_del) {
        b = sw->ofp_ctors->group_del(OFPG_ALL);
        c_switch_tx(sw, b, false);
    }
}

void
__of_send_clear_all_meters(c_switch_t *sw)
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->meter_del) {
        b = sw->ofp_ctors->meter_del(OFPM_ALL);
        c_switch_tx(sw, b, false);
    }
}

void
__of_send_role_request(c_switch_t *sw)
{
    struct cbuf *b;
    uint32_t role = 0;
    uint64_t gen_id;

    c_ha_get_of_state(&role, &gen_id);

    if (sw->ofp_ctors && sw->ofp_ctors->role_request) {
        b = sw->ofp_ctors->role_request(role, gen_id);
        c_switch_tx(sw, b, false);
    }
}

bool
of_switch_table_supported(c_switch_t *sw, uint8_t table)
{
    
    if (table < C_MAX_RULE_FLOW_TBLS && 
        sw->ofp_ctors && sw->ofp_ctors->multi_table_support &&
        sw->ofp_ctors->multi_table_support(sw->n_tables, table)) {
        return true;
    } else {
        if (table == C_TBL_HW_IDX_DFL) return true;
        return false;
    }
}

void
__of_send_mpart_msg(c_switch_t *sw, uint16_t type,
                    uint16_t flags, size_t body_len)
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->prep_mpart_msg) {
        b = sw->ofp_ctors->prep_mpart_msg(type, flags, body_len);
        c_switch_tx(sw, b, false);
    }
}

void
__of_send_q_stat_req(c_switch_t *sw, uint32_t port, uint32_t queue)
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->port_q_stat_req) {
        b = sw->ofp_ctors->port_q_stat_req(port, queue);
        c_switch_tx(sw, b, false);
    }
}

void
__of_send_barrier_request(c_switch_t *sw)
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->prep_barrier_req) {
        b = sw->ofp_ctors->prep_barrier_req();
        c_switch_tx(sw, b, false);
    }
}

int
__of_send_vendor_msg(c_switch_t *sw,
                     struct of_vendor_params *vp)
{
    struct cbuf *b;;
    if (sw->ofp_ctors && sw->ofp_ctors->prep_vendor_msg) {
        b = sw->ofp_ctors->prep_vendor_msg(vp);
        c_switch_tx(sw, b, false);
    }
    return 0;
}

/* 
 * __c_switch_port_update -
 * 
 * Update a switch port attributes
 */ 
static void 
__c_switch_port_update(c_switch_t *sw, c_port_t *port_desc, 
                       uint8_t  chg_reason,
                       struct c_port_cfg_state_mask *chg_mask)
{
    c_port_t    *port = NULL;
    uint32_t        port_no;

    port_no = port_desc->sw_port.port_no;

    switch (chg_reason) {
    case OFPPR_DELETE:
        //c_log_err("%s: %llx port(%u) delete", FN, sw->DPID, port_no);
        __c_switch_port_delete(sw, port_desc);
        break;
    case OFPPR_ADD:
        //c_log_err("%s: %llx port(%u) add", FN, sw->DPID, port_no);
        if (!__c_switch_port_add(sw, port_desc) && chg_mask) {
            chg_mask->config_mask = port_desc->sw_port.config;
            chg_mask->state_mask = port_desc->sw_port.state;
        }
        break;
    case OFPPR_MODIFY:
        //c_log_err("%s: %llx port(%u) mod", FN, sw->DPID, port_no);
        if ((port = __c_switch_port_find(sw, port_desc->sw_port.port_no))) {
            if (chg_mask) {
                chg_mask->config_mask = port->sw_port.config ^
                    port_desc->sw_port.config;
                chg_mask->state_mask = port->sw_port.state ^
                    port_desc->sw_port.state;
            }
            memcpy(&port->sw_port, &port_desc->sw_port, sizeof(c_sw_port_t));
        }
        break;
    default:
        c_log_err("[PORT] unknown |%u| change reason|%u|", port_no, chg_reason);
        return;
    }

    return;
}

static void
port_status_to_cxlate(uint32_t *status, uint32_t of_port_status)
{
    *status = 0;
    if (of_port_status & OFPPS_LINK_DOWN) {
        *status |= C_MLPS_DOWN;
    }
}

static void
port_config_to_cxlate(uint32_t *config, uint32_t of_port_config)
{
    *config= 0;
    if (of_port_config & OFPPC_PORT_DOWN) {
        *config |= C_MLPC_DOWN;
    }
}

static void
port_status_to_ofxlate(uint32_t *of_port_status, uint32_t status)
{
    *of_port_status = 0;
    if (status & C_MLPS_DOWN) {
        *of_port_status |= OFPPS_LINK_DOWN;   
    }

    *of_port_status = htonl(*of_port_status);
}

static void
port_config_to_ofxlate(uint32_t *of_port_config, uint32_t config)
{
    *of_port_config= 0;
    if (config & C_MLPC_DOWN) {
        *of_port_config |= OFPPC_PORT_DOWN;
    }
    
    *of_port_config = htonl(*of_port_config);
}

static c_port_t * 
of10_process_phy_port(c_switch_t *sw UNUSED, void *opp_)
{
    const struct ofp_phy_port   *opp;
    c_port_t                    *port_desc;

    opp     = opp_;
    port_desc = calloc(sizeof(c_port_t), 1);
    assert(port_desc);

    port_desc->sw_port.port_no = ntohs(opp->port_no);
    port_config_to_cxlate(&port_desc->sw_port.config, ntohl(opp->config));
    port_status_to_cxlate(&port_desc->sw_port.state, ntohl(opp->state));
    port_desc->sw_port.curr = ntohl(opp->curr);
    port_desc->sw_port.advertised = ntohl(opp->advertised);
    port_desc->sw_port.supported = ntohl(opp->supported);
    port_desc->sw_port.peer      = ntohl(opp->peer);
    port_desc->sw_port.of_config = ntohl(opp->config);
    port_desc->sw_port.of_state  = ntohl(opp->state);

    memcpy(port_desc->sw_port.name, opp->name, OFP_MAX_PORT_NAME_LEN);
    port_desc->sw_port.name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
    memcpy(port_desc->sw_port.hw_addr, opp->hw_addr, OFP_ETH_ALEN);

    return port_desc;
}

static void
of10_recv_port_status(c_switch_t *sw, struct cbuf *b)
{
    struct c_port_chg_mdata mdata;
    struct c_port_cfg_state_mask chg_mask = { 0, 0 };
    struct ofp_port_status *ops = (void *)(b->data);
    c_port_t *phy_port_desc = NULL;
       
    phy_port_desc = sw->ofp_priv_procs->xlate_port_desc(sw, &ops->desc);
    assert(phy_port_desc);

    c_wr_lock(&sw->lock);
    __c_switch_port_update(sw, phy_port_desc, ops->reason, &chg_mask);
    c_wr_unlock(&sw->lock);

    mdata.reason = ops->reason;
    mdata.chg_mask = &chg_mask;
    mdata.port_desc = &phy_port_desc->sw_port;
    c_signal_app_event(sw, b, C_PORT_CHANGE, NULL, &mdata, false);

    if (sw->fp_ops.fp_port_status)
        sw->fp_ops.fp_port_status(sw,
                                  phy_port_desc->sw_port.port_no,
                                  phy_port_desc->sw_port.config, 
                                  phy_port_desc->sw_port.state,
                                  &chg_mask);
    free(phy_port_desc);
}

static bool 
c_switch_features_check(c_switch_t *sw, uint64_t dpid)
{
    c_switch_t *old_sw = NULL;

    old_sw = c_switch_get(sw->c_hdl, dpid);
    if (old_sw) {
        switch (c_switch_clone_on_conn(sw, old_sw)) {
        case SW_CLONE_USE: 
            /* c_log_debug("[SWITCH] |0x%llx| use new conn", U642ULL(dpid)); */
            c_switch_put(old_sw);
            return true;
        case SW_CLONE_DENY:
            c_log_debug("[SWITCH] |0x%llx| Deny new conn", U642ULL(dpid));
            sw->conn.dead = true; /* Indication to close the conn on switch delete */
            c_switch_mark_sticky_del(sw); /* eventually switch should go */
            c_switch_put(old_sw);
            return false;
        case SW_CLONE_OLD:
            c_log_debug("%s: Clone old switch conn", FN);
            c_conn_events_del(&sw->conn);
            c_switch_mark_sticky_del(sw);
            old_sw->reinit_fd = sw->conn.fd;
            old_sw->switch_state |= SW_REINIT;
            old_sw->switch_state &= ~SW_DEAD;
            c_switch_put(old_sw);
            return false;
        default:
            c_log_err("[SWITCH] |0x%llx| Unknown clone state", U642ULL(dpid));
            c_switch_put(old_sw);
            return false;
        }
    }
    return true;
}

static void
c_init_switch_features(c_switch_t *sw, uint64_t datapath_id, uint8_t ofp_version,
                       uint8_t n_tables, uint32_t n_bufs, uint32_t ofp_acts,
                       uint32_t cap)
{
    sw->datapath_id = datapath_id;
    sw->version     = ofp_version;
    sw->n_buffers   = n_bufs;
    sw->n_tables    = n_tables;
    sw->actions     = ofp_acts;
    sw->capabilities = cap;
}

static void
c_register_switch(c_switch_t *sw, struct cbuf *reg_pkt, bool trig_event)
{
    struct flow  flow;
    struct flow  mask;

    memset(&flow, 0, sizeof(flow));
    of_mask_set_dc_all(&mask);
    if (!(sw->switch_state & SW_REGISTERED)) {
        c_switch_flow_tbl_create(sw);
        c_switch_add(sw);
        sw->switch_state |= SW_REGISTERED;
        sw->last_sample_time = time(NULL);
        sw->last_fp_aging_time = time(NULL);
        if (sw->version == OFP_VERSION) {
            sw->ofp_rx_handler_sz = OFPT_BARRIER_REPLY; 
            sw->ofp_rx_handlers = of_handlers;
        } else if (sw->version == OFP_VERSION_131) {
            sw->ofp_rx_handler_sz = OFPT131_METER_MOD; 
            sw->ofp_rx_handlers = of131_handlers;
        }else if (sw->version == OFP_VERSION_140) {
            sw->ofp_rx_handler_sz = OFPT140_BUNDLE_ADD_MESSAGE; 
            sw->ofp_rx_handlers = of140_handlers;
        } 
        else {
            NOT_REACHED();
        }
        sw->fp_ops.fp_fwd = of_dfl_fwd;
        sw->fp_ops.fp_port_status = of_dfl_port_status;

        __of_send_role_request(sw);
        __of_send_set_config(sw, 0, OF_MAX_MISS_SEND_LEN);
        if (trig_event) {
            int i = 0;
            for (; i < sw->n_tables; i++) {
                flow.table_id = i;
                __of_send_flow_del_direct(sw, &flow, &mask, 0, 
                                          false, C_FL_PRIO_DFL, OFPG_ANY);
            }
            __of_send_clear_all_groups(sw);
            __of_send_clear_all_meters(sw);

            c_signal_app_event(sw, reg_pkt, C_DP_REG, NULL, NULL, false);
            sw->switch_state |= (SW_PUBLISHED | SW_OFP_PORT_FEAT |
                                 SW_OFP_TBL_FEAT| SW_OFP_GRP_FEAT |
                                 SW_FLOW_PROBED | SW_FLOW_PROBE_DONE |
                                 SW_METER_PROBED | SW_METER_PROBE_DONE |
                                 SW_GROUP_PROBED | SW_GROUP_PROBE_DONE);
        } else {
            sw->sav_b = cbuf_realloc_headroom(reg_pkt, 0, false);
            if (!sw->sav_b) {
                c_log_err("[SWITCH] Cant save reg state 0x%llx", sw->DPID);
            }
        }
    }
}

static void
of10_recv_features_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_switch_features  *osf = (void *)(b->data);
    size_t                       n_ports, i;
    c_flow_tbl_t                *tbl;

    if (!c_switch_features_check(sw, ntohll(osf->datapath_id))) {
        return;
    }

    n_ports = ((ntohs(osf->header.length)
                - offsetof(struct ofp_switch_features, ports))
            / sizeof *osf->ports);

    c_init_switch_features(sw, ntohll(osf->datapath_id), osf->header.version,
                           osf->n_tables, ntohl(osf->n_buffers), ntohl(osf->actions),
                           ntohl(osf->capabilities));                           

    for (i = 0; i < n_ports; i++) {
        c_port_t *port_info = NULL;
        assert(sw->ofp_priv_procs->xlate_port_desc);
        port_info = sw->ofp_priv_procs->xlate_port_desc(sw, &osf->ports[i]);
        c_wr_lock(&sw->lock);
        __c_switch_port_update(sw, port_info, OFPPR_ADD, NULL);
        c_wr_unlock(&sw->lock);
        free(port_info);
    }

    /* there is no separate table feature msg in 1.0 */
    tbl = &sw->rule_flow_tbls[0];
    tbl->hw_tbl_active = true;

    c_register_switch(sw, b, true);
    c_switch_try_publish(sw, false); 
    mb();
}

int __fastpath
of_flow_extract(uint8_t *pkt, struct flow *flow, 
                uint32_t in_port, size_t pkt_len,
                bool only_l2)
{
    struct eth_header *eth;
    int    retval = 0;
    size_t rem_len = pkt_len;

    memset(flow, 0, sizeof *flow);
    flow->dl_vlan = 0;  //htons(OFP_VLAN_NONE);
    flow->in_port = htonl(in_port);

    if (unlikely(rem_len < sizeof(*eth))) {
        return -1;
    }

    eth = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
    rem_len -= sizeof(*eth);
    if (likely(ntohs(eth->eth_type) >= OFP_DL_TYPE_ETH2_CUTOFF)) {
        /* This is an Ethernet II frame */
        flow->dl_type = eth->eth_type;
    } else {
        /* This is an 802.2 frame */
        if (!c_rlim(&crl))
            c_log_err("802.2 recvd. Not handled");
        return -1;
    }

    /* Check for a VLAN tag */
    if (unlikely(flow->dl_type == htons(ETH_TYPE_VLAN))) {
        struct vlan_header *vh;
        if (rem_len < sizeof(*vh)) {
            return -1;
        }
        vh =  OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*vh);
        flow->dl_type = vh->vlan_next_type;
        flow->dl_vlan = vh->vlan_tci & htons(VLAN_VID_MASK);
        flow->dl_vlan_pcp = (uint8_t)((ntohs(vh->vlan_tci)  >>  
                                        VLAN_PCP_SHIFT) & VLAN_PCP_BITMASK);
    }

    memcpy(flow->dl_dst, eth->eth_dst, 2*ETH_ADDR_LEN);

    if (likely(only_l2)) {
        return 0;
    }

    if (likely(flow->dl_type == htons(ETH_TYPE_IP))) {
        const struct ip_header *nh;

        if (rem_len < sizeof(*nh)) {
            return -1;
        }
        nh = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*nh);

        flow->nw_tos = nh->ip_tos & 0xfc;
        flow->nw_proto = nh->ip_proto;
        flow->ip.nw_src = nh->ip_src;
        flow->ip.nw_dst = nh->ip_dst;
        if (likely(!IP_IS_FRAGMENT(nh->ip_frag_off))) {
            if (flow->nw_proto == IP_TYPE_TCP) {
                const struct tcp_header *tcp;
                if (rem_len < sizeof(*tcp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                tcp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);;
                rem_len -= sizeof(*tcp);

                flow->tp_src = tcp->tcp_src;
                flow->tp_dst = tcp->tcp_dst;
            } else if (flow->nw_proto == IP_TYPE_UDP) {
                const struct udp_header *udp;
                if (rem_len < sizeof(*udp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                udp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
                rem_len -= sizeof(*udp);

                flow->tp_src = udp->udp_src;
                flow->tp_dst = udp->udp_dst;
            } else if (flow->nw_proto == IP_TYPE_ICMP) {
                const struct icmp_header *icmp;
                if (rem_len < sizeof(*icmp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                icmp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
                rem_len -= sizeof(*icmp);

                // flow->tp_src = htons(icmp->icmp_type);
                // flow->tp_dst = htons(icmp->icmp_code);
            }
       } else {
                retval = 1;
       }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
        const struct arp_eth_header *arp;
        if (rem_len < sizeof(*arp)) {
            return -1;
        }
        arp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len); 
        rem_len -= sizeof(*arp);

        if (arp->ar_pro == htons(ARP_PRO_IP) && 
            arp->ar_pln == IP_ADDR_LEN) {
            flow->ip.nw_src = arp->ar_spa;
            flow->ip.nw_dst = arp->ar_tpa;
        }
        flow->nw_proto = ntohs(arp->ar_op) && 0xff;
    } else if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
               flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
        const struct mpls_header *mpls;
        if (rem_len < sizeof(*mpls)) {
            return -1;
        }
        mpls = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*mpls);
        flow->mpls_label = htonl(MPLS_HDR_GET_LABEL(mpls->mpls_tag));
        flow->mpls_tc = MPLS_HDR_GET_TC(mpls->mpls_tag);
        flow->mpls_bos = MPLS_HDR_GET_BOS(mpls->mpls_tag);

    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        const struct ipv6_header *ip6;

        if (rem_len < sizeof(*ip6)) {
            return -1;
        }
        ip6 = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*ip6);

        flow->nw_tos = (ip6->ver_tc_label >> 20) & 0xfc;
        flow->nw_proto = ip6->next_header;
        memcpy(&flow->ipv6.nw_src, &ip6->src, sizeof(ip6->src));
        memcpy(&flow->ipv6.nw_dst, &ip6->dest, sizeof(ip6->dest));

        if (flow->nw_proto == NEXTHDR_TCP) {
            const struct tcp_header *tcp;
            if (rem_len < sizeof(*tcp)) {
                flow->nw_proto = 0;
                return 0;
            }
            tcp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);;
            rem_len -= sizeof(*tcp);

            flow->tp_src = tcp->tcp_src;
            flow->tp_dst = tcp->tcp_dst;
        } else if (flow->nw_proto == NEXTHDR_UDP) {
            const struct udp_header *udp;
            if (rem_len < sizeof(*udp)) {
                flow->nw_proto = 0;
                return 0;
            }
            udp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
            rem_len -= sizeof(*udp);

            flow->tp_src = udp->udp_src;
            flow->tp_dst = udp->udp_dst;
        } /* else if (flow->nw_proto == NEXTHDR_ICMP) {
            struct icmp6_header *icmp6;
            if (rem_len < sizeof(*icmp6)) {
                flow->nw_proto = 0;
                return 0;
            }
            icmp6 = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
            rem_len -= sizeof(*icmp6);
        } */
    }

    return retval;
}

#ifdef CONFIG_FLOW_EXM
static c_fl_entry_t * UNUSED 
c_flow_get_exm(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;
    c_fl_entry_t     *ent = NULL;
    unsigned int     found;

    c_rd_lock(&sw->lock);

    found = g_hash_table_lookup_extended(tbl->exm_fl_hash_tbl, fl,
                                         NULL, (gpointer*)&ent);
    if (found) {
        atomic_inc(&ent->FL_REF, 1);
    }

    c_rd_unlock(&sw->lock);

    return ent;

}
#endif

static c_fl_entry_t *
__c_flow_get_exm(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;
    c_fl_entry_t     *ent = NULL;
    unsigned int     found;

    found = g_hash_table_lookup_extended(tbl->exm_fl_hash_tbl, fl,
                                         NULL, (gpointer*)&ent);
    if (found) {
        atomic_inc(&ent->FL_REF, 1);
    }

    return ent;
}

static uint32_t 
c_fl_cookie_hash(const void *key)
{
    c_fl_entry_t *fl_ent = ASSIGN_PTR(key);

    return fl_ent->FL_COOKIE; 
}

static int
c_fl_cookie_match(const void *v1,
                  const void *v2)
{
    c_fl_entry_t *ent1 = ASSIGN_PTR(v1);
    c_fl_entry_t *ent2 = ASSIGN_PTR(v2);
    struct flow *ent_fl = &ent1->fl;
    struct flow *fl = &ent2->fl;
    struct flow *mask = &ent1->fl_mask;
    uint8_t zero_mac[] = { 0, 0, 0, 0, 0, 0};

    /* c_log_err("%s:%d %d", FN, !memcmp(&ent1->fl_mask, &ent2->fl_mask,
                   sizeof(*mask)-sizeof(mask->pad)),
             c_match_flow_ip_addr_generic(fl, ent_fl, mask)); */

    return (ent1->FL_COOKIE == ent2->FL_COOKIE &&
            !memcmp(&ent1->fl_mask, &ent2->fl_mask, 
                   sizeof(*mask)-sizeof(mask->pad)) &&
            c_match_flow_ip_addr_generic(fl, ent_fl, mask) &&
            (!mask->nw_proto || fl->nw_proto == ent_fl->nw_proto) &&
            (!mask->nw_tos || fl->nw_tos == ent_fl->nw_tos) &&
            (!mask->tp_dst || fl->tp_dst == ent_fl->tp_dst) &&
            (!mask->tp_src || fl->tp_src == ent_fl->tp_src) &&
            (!memcmp(mask->dl_src, zero_mac, 6) ||
             !memcmp(fl->dl_src, ent_fl->dl_src, 6)) &&
            (!memcmp(mask->dl_dst, zero_mac, 6) ||
             !memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) &&
            (!mask->dl_type || fl->dl_type == ent_fl->dl_type) &&
            (!mask->dl_vlan || fl->dl_vlan == ent_fl->dl_vlan) &&
            (!mask->dl_vlan_pcp || fl->dl_vlan_pcp == ent_fl->dl_vlan_pcp) &&
            (!mask->mpls_label || fl->mpls_label == ent_fl->mpls_label) &&
            (!mask->mpls_tc || fl->mpls_tc == ent_fl->mpls_tc) &&
            (!mask->mpls_bos || fl->mpls_bos == ent_fl->mpls_bos) &&
            (!mask->in_port || fl->in_port == ent_fl->in_port) &&
            ent1->FL_PRIO == ent2->FL_PRIO);
}

static inline c_fl_entry_t *
c_do_flow_lookup_slow(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl;
    c_fl_entry_t     *ent = NULL;
    
    c_rd_lock(&sw->lock);
    tbl = &sw->rule_flow_tbls[fl->table_id];
    if (tbl && (ent = __c_flow_lookup_rule(sw, fl, tbl))) {
        atomic_inc(&ent->FL_REF, 1);
        c_rd_unlock(&sw->lock);
        return ent;
    }
    c_rd_unlock(&sw->lock);

    return NULL;
}

static c_fl_entry_t *
__c_do_rule_lookup_with_detail(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio)
{
    c_flow_tbl_t     *tbl;
    c_fl_entry_t     *ent = NULL;
    GSList           *list = NULL;

    tbl = &sw->rule_flow_tbls[fl->table_id];
    list = tbl->rule_fl_tbl;
    if (tbl &&
        (ent = __c_flow_lookup_rule_strict_prio_hint_detail
                       (sw, &list, fl, mask, prio))) {
       atomic_inc(&ent->FL_REF, 1);
       return ent;
    }

    return NULL;
}

static c_fl_entry_t *
c_do_rule_lookup_with_detail(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio)
{
    c_fl_entry_t *ent = NULL;

    c_rd_lock(&sw->lock);
    ent = __c_do_rule_lookup_with_detail(sw, fl, mask, prio);
    c_rd_unlock(&sw->lock);

    return ent;
}


static c_fl_entry_t *
__c_do_flow_lookup_with_cookie(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio, 
                             uint32_t cookie)
{
    c_fl_entry_t ent;
    c_fl_entry_t *sw_fl_ent = NULL;

    memset(&ent, 0, sizeof(ent));
    memcpy(&ent.fl, fl, sizeof(*fl));
    memcpy(&ent.fl_mask, mask, sizeof(*mask)); 
    ent.FL_PRIO = prio;
    ent.FL_COOKIE = cookie;
    ent.sw = sw;
    
    if (sw->fl_cookies &&
        (sw_fl_ent = g_hash_table_lookup(sw->fl_cookies, &ent))) {
        atomic_inc(&sw_fl_ent->FL_REF, 1);
        return sw_fl_ent;
    }

    return NULL;
}

static c_fl_entry_t *
c_do_flow_lookup_with_cookie(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio, 
                             uint32_t cookie)
{
    c_fl_entry_t *ent = NULL;
    c_rd_lock(&sw->lock);
    ent = __c_do_flow_lookup_with_cookie(sw, fl, mask, prio, cookie);
    c_rd_unlock(&sw->lock);

    return ent;
}

static inline c_fl_entry_t *
c_do_flow_lookup(c_switch_t *sw, struct flow *fl)
{

#ifdef CONFIG_FLOW_EXM
    c_fl_entry_t *ent = NULL;

    if ((ent = c_flow_get_exm(sw, fl))) {
        return ent;
    }
#endif
    return c_do_flow_lookup_slow(sw, fl);
}

static inline c_fl_entry_t *
__c_do_flow_lookup_with_detail(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio)
{
#ifdef CONFIG_FLOW_EXM
    c_fl_entry_t *ent = NULL;

    if ((ent = __c_flow_get_exm(sw, fl))) {
        return ent;
    }
#endif
    return __c_do_rule_lookup_with_detail(sw, fl, mask, prio);
}

static inline c_fl_entry_t *
c_do_flow_lookup_with_detail(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio)
{
#ifdef CONFIG_FLOW_EXM
    c_fl_entry_t *ent = NULL;

    if ((ent = c_flow_get_exm(sw, fl))) {
        return ent;
    }
#endif
    return c_do_rule_lookup_with_detail(sw, fl, mask, prio);
}


void
c_flow_entry_put(c_fl_entry_t *ent)
{
    if (atomic_read(&ent->FL_REF) == 0) {
        __c_flow_rule_disassociate_meters(ent->sw, ent);
        __c_flow_rule_disassociate_grps(ent->sw, ent);
        if (ent->actions &&
            !(ent->FL_FLAGS & C_FL_ENT_CLONE))  {
            /* Cloned entry refs parent action list */
            free(ent->actions);
        }

        if (ent->app_owner_list) {
            g_slist_free_full(ent->app_owner_list, c_flow_app_ref_free);
            ent->app_owner_list = NULL;
        }

        c_rw_lock_destroy(&ent->FL_LOCK);
        free(ent);
    } else {
        atomic_dec(&ent->FL_REF, 1);
    }
}


static inline void
c_mcast_app_packet_in(c_switch_t *sw, struct cbuf *b,
                      c_fl_entry_t *fl_ent,
                      struct c_pkt_in_mdata *mdata)
{
    void    *app;
    GSList  *iterator;

    c_sw_hier_rdlock(sw);

    c_rd_lock(&fl_ent->FL_LOCK);
    for (iterator = fl_ent->app_owner_list;
         iterator;
         iterator = iterator->next) {
        app = iterator->data;
        c_signal_app_event(sw, b, C_PACKET_IN, app, mdata, true);
    }

    c_rd_unlock(&fl_ent->FL_LOCK);

    c_sw_hier_unlock(sw);
}

int 
of_dfl_fwd(struct c_switch *sw, struct cbuf *b, void *data, size_t pkt_len,
           struct c_pkt_in_mdata *mdata, uint32_t in_port)
{
    struct of_pkt_out_params parms;
    c_fl_entry_t  *fl_ent;
    struct ofp_packet_in *opi = (void *)(b->data);
    struct flow *fl = mdata->fl; 

    if(!(fl_ent = c_do_flow_lookup(sw, fl))) {
        //c_log_debug("Flow lookup fail");
        return 0;
    }

    if (fl_ent->FL_FLAGS & C_FL_ENT_RESIDUAL) {
        c_flow_entry_put(fl_ent);
        return 0;
    }

    if (fl_ent->FL_ENT_TYPE != C_TBL_EXM &&
        fl_ent->FL_FLAGS & C_FL_ENT_CLONE) {
        fl_ent = c_flow_clone_exm(sw, fl, fl_ent);
    }

    if (fl_ent->FL_FLAGS & C_FL_ENT_LOCAL) {
        c_mcast_app_packet_in(sw, b, fl_ent, mdata);

        c_flow_entry_put(fl_ent);
        return 0;
    }

    of_send_flow_add(sw, fl_ent, ntohl(opi->buffer_id), false, false);

    if (ntohl(opi->buffer_id) != (uint32_t)(-1)) {
        goto out;
    }

    parms.data       = 0;
    parms.data_len   = 0;
    parms.buffer_id  = ntohl(opi->buffer_id);
    parms.in_port    = in_port;
    parms.action_len = fl_ent->action_len;
    parms.action_list = fl_ent->actions;
    parms.data_len = (parms.buffer_id == (uint32_t)(-1))? pkt_len : 0;
    parms.data = data;

    of_send_pkt_out(sw, &parms);
out:
    c_flow_entry_put(fl_ent);

    return 0;
}

int
of_dfl_port_status(c_switch_t *sw UNUSED, uint32_t port UNUSED,
                   uint32_t cfg UNUSED, uint32_t state UNUSED,
                   struct c_port_cfg_state_mask *mask UNUSED)
{
    /* Nothing to do for now */
    return 0;
}

static void __fastpath
of10_recv_packet_in(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_packet_in *opi __aligned = (void *)(b->data);
    struct c_pkt_in_mdata mdata;
    size_t pkt_ofs, pkt_len;
    struct flow fl;
    uint16_t in_port = ntohs(opi->in_port);
    bool only_l2 = sw->fp_ops.fp_fwd == c_l2_lrn_fwd ? true : false;

    if (sw->rx_lim_on && c_rlim(&sw->rx_rlim)) {
        sw->rx_pkt_in_dropped++;
        return;
    }

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;

    if(!sw->fp_ops.fp_fwd ||
        of_flow_extract(opi->data, &fl, in_port, pkt_len, only_l2) < 0) {
        return;
    }

    mdata.fl = &fl;
    mdata.pkt_ofs = pkt_ofs;
    mdata.pkt_len = pkt_len;
    mdata.buffer_id = ntohl(opi->buffer_id);

    sw->fp_ops.fp_fwd(sw, b, opi->data, pkt_len, &mdata, in_port);

    return;
}

static void
of_recv_hello(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_header *h = (void *)(b->data);

    if (sw->switch_state & SW_OFP_NEGOTIATED)
        return;

    if (h->version == OFP_VERSION) {
        sw->ofp_rx_handler_sz = OFPT_BARRIER_REPLY; 
        sw->ofp_rx_handlers = of_init_handlers;
        sw->ofp_ctors = &of10_ctors;
        sw->ofp_priv_procs = &ofp_priv_procs;
        sw->switch_state |= SW_OFP_NEGOTIATED;
        of_send_hello(sw);
        of_send_features_request(sw);
    } else if (h->version == OFP_VERSION_131) {
        sw->ofp_rx_handler_sz = OFPT131_METER_MOD;
        sw->ofp_rx_handlers = of131_init_handlers; 
        sw->ofp_ctors = &of131_ctors;
        sw->ofp_priv_procs = &ofp131_priv_procs;
        sw->switch_state |= SW_OFP_NEGOTIATED;
        of_send_hello(sw);
        of_send_features_request(sw);
    } else if (h->version == OFP_VERSION_140) {
        sw->ofp_rx_handler_sz = OFPT140_BUNDLE_ADD_MESSAGE;
        sw->ofp_rx_handlers = of140_init_handlers; 
        sw->ofp_ctors = &of140_ctors;
        sw->ofp_priv_procs = &ofp140_priv_procs;
        sw->switch_state |= SW_OFP_NEGOTIATED;
        of_send_hello(sw);
        of_send_features_request(sw);
    } else {
        c_log_err("[OF] |%u| ver unsupported", h->version);
        of_send_hello(sw);
    }
}

static void
of10_recv_echo_request(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_header *h = (void *)(b->data);

    return of_send_echo_reply(sw, h->xid);
}

static void
of10_recv_echo_reply(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    /* Nothing to do as timestamp is already updated */
}

static void
of10_recv_vendor_msg(c_switch_t *sw UNUSED, struct cbuf *b)
{
    struct c_vendor_mdata mdata;
    struct ofp_header *h = (void *)(b->data);

    mdata.data_len = ntohs(h->length) - sizeof(struct ofp_vendor_header);
    mdata.data_ofs = sizeof(struct ofp_vendor_header);

    c_signal_app_event(sw, b, C_VENDOR_MSG, NULL, &mdata, false);
}

static void
of_recv_init_echo_request(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_header *h = (void *)(b->data);
    of_send_echo_reply(sw, h->xid);
    __of_send_features_request(sw);
}

static void
of_recv_init_echo_reply(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    __of_send_features_request(sw);
    /* Nothing else to-do as timestamp is already updated */
}

static void
of10_flow_removed(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow, mask;
    struct ofp_flow_removed     *ofm = (void *)(b->data);
    struct of_flow_mod_params   fl_parms;

    memset(&fl_parms, 0, sizeof(fl_parms));
    memset(&flow, 0, sizeof(flow));
    memset(&mask, 0, sizeof(flow));

    of10_wc_to_mask(ofm->match.wildcards, &mask);
    fl_parms.prio = ntohs(ofm->priority);

    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.ip.nw_src = ofm->match.nw_src;
    flow.ip.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.flow = &flow;
    fl_parms.mask = &mask;
    fl_parms.flow->table_id = C_TBL_HW_IDX_DFL; 
    fl_parms.reason = ofm->reason;
    
    /*
     * It is upto the application to check what flows are removed
     * by the switch and inform the controller so the controller 
     * itself does not take any action 
     */
    c_signal_app_event(sw, b, C_FLOW_REMOVED, NULL, &fl_parms, false);
}

static void
of10_recv_flow_mod_failed(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow;
    struct flow                 mask;
    struct ofp_error_msg        *ofp_err = (void *)(b->data);
    struct ofp_flow_mod         *ofm = (void *)(ofp_err->data);
    struct of_flow_mod_params   fl_parms;
    void                        *app;
    char                        *print_str;

    memset(&flow, 0, sizeof(flow));
    memset(&mask, 0, sizeof(flow));

    of10_wc_to_mask(ofm->match.wildcards, &mask);
    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.ip.nw_src = ofm->match.nw_src;
    flow.ip.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.mask = &mask;
    fl_parms.flow = &flow;
    fl_parms.prio = ntohs(ofm->priority);
    fl_parms.flow->table_id = C_TBL_HW_IDX_DFL;
    fl_parms.command = ntohs(ofm->command);

    /* Controller owns only vty intalled static flows */
    if (!(app = c_app_get(sw->c_hdl, C_VTY_NAME))) {
        goto app_signal_out;
    }

    fl_parms.app_owner = app;
    c_switch_flow_del(sw, &fl_parms);
    c_app_put(app);
    fl_parms.app_owner = NULL;

app_signal_out:
    /* We take a very conservative approach here and multicast
     * flow mod failed to all apps irrespective of whether they are owners
     * of this flow or not, to maintain sanity because some apps
     * may implicitly use this flow for some operation
     */
    c_signal_app_event(sw, b, C_FLOW_MOD_FAILED, NULL, &fl_parms, false);

    if (sw->ofp_ctors->dump_flow) {
        print_str=  sw->ofp_ctors->dump_flow(&flow, &mask); 
        c_log_info("[OFP10] flow-mod fail notification");
        c_log_info("%s", print_str);
        free(print_str);
    }

    return;
} 

static void
of10_recv_err_msg(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_error_msg *ofp_err = (void *)(b->data);

    c_log_warn("[OFP10] error from switch |0x%llx| type|%hu|code|%hu|",
               U642ULL(sw->DPID), ntohs(ofp_err->type), ntohs(ofp_err->code));

    switch(ntohs(ofp_err->type)) {
    case OFPET_FLOW_MOD_FAILED:
        return of10_recv_flow_mod_failed(sw, b);
    default:
        break;
    }
}

static void
c_sw_trigger_expiry(c_switch_t *sw)
{
    struct c_sw_expired_ent *ent;
    GSList *iterator;

    for (iterator = sw->exp_list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        __mul_app_command_handler(ent->app, ent->b);
    }

    g_slist_free_full(sw->exp_list, c_sw_exp_ent_free);
    sw->exp_list = NULL;
}

static void 
c_flow_stats_update(c_switch_t *sw, struct flow *flow, struct flow *mask,
                    void *flow_acts, size_t act_len, uint16_t prio,
                    uint64_t pkt_count, uint64_t byte_count,
                    uint32_t dur_sec, uint32_t dur_nsec,
                    uint32_t cookie, uint16_t itimeo, uint16_t htimeo)
{
    c_fl_entry_t    *ent;
    time_t          curr_time, time_diff;

    ent = cookie ? c_do_flow_lookup_with_cookie(sw, flow, mask, prio, cookie) :
                   c_do_flow_lookup_with_detail(sw, flow, mask, prio);
    if (!ent ||
        act_len != ent->action_len ||
        (act_len && memcmp(flow_acts, ent->actions, ent->action_len))) {
#ifdef MUL_FLOW_DEBUG
        if (sw->ofp_ctors->dump_flow) {
            char *fl_str;
            fl_str = sw->ofp_ctors->dump_flow(flow, mask);
            if (!c_rlim(&crl)) {
                c_log_warn("[FLOW] switch |0x%llx| C-%lu stats:No such flow|%s",
                           sw->DPID, U322UL(cookie), fl_str);
            }
            free(fl_str);
        }
#endif
        if (ent) c_flow_entry_put(ent);

        if (sw->switch_state & SW_FLOW_PROBED &&
            !(sw->switch_state & SW_FLOW_PROBE_DONE) &&
            !htimeo) {
            struct cbuf *b = c_ofp_prep_flow_mod_with_parms(sw, flow, mask,
                                                        itimeo, htimeo,
                                                        C_FL_ENT_RESIDUAL,
                                                        prio, (uint32_t)(-1),
                                                        cookie,
                                                        flow_acts, act_len,
                                                        true);

            if (b) {
                void *app;
                app = c_app_get(&ctrl_hdl, C_VTY_NAME);
                if (app) {
                    __mul_app_command_handler(app, b);
                    c_app_put(app);
                }
                free_cbuf(b);
            }
         
        }
        return;
    }

    curr_time = time(NULL);
    time_diff = curr_time - ent->fl_stats.last_refresh; 

    if (ent->fl_stats.last_refresh && time_diff) {
        if (byte_count >= ent->fl_stats.byte_count) {
            ent->fl_stats.bps = (double)(byte_count
                                 - ent->fl_stats.byte_count)/time_diff;
        } else {
            c_log_warn("%s: Byte count wrap around", FN);
        }
        if (pkt_count >= ent->fl_stats.pkt_count) {
            ent->fl_stats.pps = (double)(pkt_count
                                 - ent->fl_stats.pkt_count)/time_diff;
        } else {
            c_log_warn("%s: Pkt count wrap around", FN);
        }
    }

    if (ent->FL_FLAGS & C_FL_ENT_GSTATS) {
        ent->fl_stats.byte_count = byte_count;
        ent->fl_stats.pkt_count = pkt_count;
        ent->fl_stats.duration_sec = dur_sec;
        ent->fl_stats.duration_nsec = dur_nsec;
    }
    ent->fl_stats.last_refresh = curr_time;
    ent->FL_INSTALLED = true;
    c_flow_entry_put(ent);
}

static int
of10_proc_one_flow_stats(c_switch_t *sw, void *ofps)
{
    struct flow             flow, mask;
    struct ofp_flow_stats   *ofp_stats = ofps;
    uint16_t                port;
    uint64_t                cookie;
    int                     act_len = ntohs(ofp_stats->length) - sizeof(*ofp_stats);

    cookie = ntohll(ofp_stats->cookie);
    port = ntohs(ofp_stats->match.in_port);
    memset(&flow, 0, sizeof(flow));

    /* Table-id is 0 */
    flow.in_port = htonl((uint32_t)(port));
    memcpy(flow.dl_src, ofp_stats->match.dl_src, sizeof ofp_stats->match.dl_src);
    memcpy(flow.dl_dst, ofp_stats->match.dl_dst, sizeof ofp_stats->match.dl_dst);
    flow.dl_vlan = ofp_stats->match.dl_vlan;
    flow.dl_type = ofp_stats->match.dl_type;
    flow.dl_vlan_pcp = ofp_stats->match.dl_vlan_pcp;
    flow.ip.nw_src = ofp_stats->match.nw_src;
    flow.ip.nw_dst = ofp_stats->match.nw_dst;
    flow.nw_proto = ofp_stats->match.nw_proto;
    flow.tp_src = ofp_stats->match.tp_src;
    flow.tp_dst = ofp_stats->match.tp_dst;
    of10_wc_to_mask(ofp_stats->match.wildcards, &mask);

    c_flow_stats_update(sw, &flow, &mask,
                        ofp_stats->actions,
                        act_len,
                        htons(ofp_stats->priority), 
                        ntohll(ofp_stats->packet_count),
                        ntohll(ofp_stats->byte_count),
                        ntohl(ofp_stats->duration_sec),
                        ntohl(ofp_stats->duration_nsec),
                        (uint32_t)(cookie),
                        ntohs(ofp_stats->idle_timeout),
                        ntohs(ofp_stats->hard_timeout));
    return act_len;
}

static void
of10_proc_one_port_stats(c_switch_t *sw, void *ofps)
{
    struct ofp_port_stats   *ofp_stats = ofps;
    struct c_port           *port = NULL;
    uint32_t                 port_no;
    
    port_no = ntohs(ofp_stats->port_no);
    c_wr_lock(&sw->lock);
    if ((port = g_hash_table_lookup(sw->sw_ports,
				    &port_no))) {
        if(!port->port_stats) {
            port->port_stats = calloc(1,sizeof(*ofp_stats));
	    port->port_stat_len = sizeof(*ofp_stats);
        }
        if (port->port_stat_len == sizeof(*ofp_stats)) {
            memcpy(port->port_stats, ofp_stats, port->port_stat_len);
        }
    }
    else {
        if (!c_rlim(&crl)) {
            c_log_err("[OF10] port-stats-rx:|0x%llx| no port %u",
                      sw->DPID, ntohl(ofp_stats->port_no));
        }
    }
    c_wr_unlock(&sw->lock);
}

static int
of10_refresh_ports(c_switch_t *sw)
{
    __of_send_features_request(sw);
    return 0;
}

static void
c_per_flow_stats_scan(void *time_arg UNUSED, c_fl_entry_t *ent)
{
    time_t ctime;

    ctime = time(NULL);
    c_wr_lock(&ent->FL_LOCK);
    if ((ent->FL_ENT_TYPE != C_TBL_EXM &&
        ent->FL_FLAGS & C_FL_ENT_CLONE) || 
        ent->FL_FLAGS & C_FL_ENT_LOCAL) {
        c_wr_unlock(&ent->FL_LOCK);
        return;
    }

    if (ent->sw->switch_state & SW_BULK_FLOW_STATS) {
        if (!ent->fl_stats.last_scan) {
            ent->fl_stats.last_refresh = ctime;
        }
        ent->fl_stats.last_scan = ctime;
    }

    if (ent->FL_FLAGS & C_FL_ENT_GSTATS) { 
        if (!ent->fl_stats.last_scan || 
            ((ent->FL_FLAGS & C_FL_ENT_GSTATS) &&
            (ctime - ent->fl_stats.last_scan) > C_FL_STAT_TIMEO)) {
            __of_send_flow_stat_req(ent->sw, &ent->fl, &ent->fl_mask, 
                                    0, OFPG_ANY);
            if (!ent->fl_stats.last_scan) {
                ent->fl_stats.last_refresh = ctime;
            }
            ent->fl_stats.last_scan = ctime;
        }
    } 
    c_wr_unlock(&ent->FL_LOCK);
}

static void
c_per_group_stats_scan(void *time_arg UNUSED,
                       c_switch_group_t *grp UNUSED)
{
    /* TODO */
    return;
}

static void
c_per_meter_verify_stats_scan(void *time_arg UNUSED,
                              c_switch_meter_t *meter UNUSED)
{
    /* TODO */
    return;
}

static inline bool
c_switch_supports_flow_stats(c_switch_t *sw)
{
    if (sw->ofp_ctors && sw->ofp_ctors->flow_stats_support)
        return sw->ofp_ctors->flow_stats_support(sw->capabilities);

    return  false;
}

static inline bool
c_switch_supports_group_stats(c_switch_t *sw)
{
    if (sw->ofp_ctors && sw->ofp_ctors->group_stats_support)
        return sw->ofp_ctors->group_stats_support(sw->capabilities);

    return  false;
}

static inline bool
c_switch_supports_table_stats(c_switch_t *sw)
{
    if (sw->ofp_ctors && sw->ofp_ctors->table_stats_support)
        return sw->ofp_ctors->table_stats_support(sw->capabilities);

    return  false;
}

static int 
c_switch_bulk_flow_scan(c_switch_t *sw, bool force)
{
    c_flow_tbl_t     *tbl;
    int              i = 0;
    int              n_active = 0;
    struct flow      fl, mask;

    memset(&fl, 0, sizeof(fl));
    memset(&mask, 0, sizeof(mask));

    mask.table_id = 0xff;
    c_rd_lock(&sw->lock);
    for (i = 0; i < C_MAX_RULE_FLOW_TBLS; i++) {
        tbl = &sw->rule_flow_tbls[i];
        if (tbl && tbl->hw_tbl_active &&
           (force || tbl->sw_active_entries)) {
            fl.table_id = i;
            __of_send_flow_stat_req(sw, &fl, &mask, 0, OFPG_ANY);
            n_active++;
        }
    }
    c_rd_unlock(&sw->lock);
    return n_active;
}

static void
c_switch_port_stats_scan(c_switch_t *sw)
{
    size_t num_ports = 0;

    c_rd_lock(&sw->lock);
    num_ports = g_hash_table_size(sw->sw_ports);

    if (num_ports) {
        __of_send_port_stat_req(sw, OF_ANY_PORT);
    }
    c_rd_unlock(&sw->lock);
}

void
c_per_switch_stats_scan(c_switch_t *sw, time_t curr_time)
{
    if (c_switch_supports_flow_stats(sw)) {
        if (sw->switch_state & SW_BULK_FLOW_STATS)
            c_switch_bulk_flow_scan(sw, false);
        c_flow_traverse_tbl_all(sw, (void *)&curr_time, 
                                c_per_flow_stats_scan);
    }

    if (c_switch_supports_group_stats(sw)) {
         c_switch_group_traverse_all(sw, (void *)&curr_time,
                                     c_per_group_stats_scan);
    }

    c_switch_meter_traverse_all(sw, (void *)&curr_time,
                                c_per_meter_verify_stats_scan);

    if (sw->switch_state & SW_PORT_STATS_ENABLE)
        c_switch_port_stats_scan(sw);

    if (c_switch_supports_table_stats(sw)) {
        /* Get all the table features */
        __of_send_mpart_msg(sw, OFPMP_TABLE, 0, 0);
    }
}

static void 
c_switch_tbl_prop_update(c_switch_t *sw, uint8_t tbl_id, 
                         uint32_t *bmask, uint16_t type) 
{
    c_flow_tbl_t  *tbl;

    c_rd_lock(&sw->lock);
    tbl = &sw->rule_flow_tbls[tbl_id];

    if (!tbl->props) {
        tbl->props = calloc(1, sizeof(of_flow_tbl_props_t));
    }
    assert(tbl->props);

    switch (type) {
    case OF_FL_TBL_FEAT_INSTRUCTIONS:
        tbl->props->bm_inst = *bmask;
        break;
    case OF_FL_TBL_FEAT_INSTRUCTIONS_MISS:
        tbl->props->bm_inst_miss = *bmask;
        break;
    case OF_FL_TBL_FEAT_NTABLE:
        memcpy(tbl->props->bm_next_tables, bmask,
               sizeof(tbl->props->bm_next_tables));
        break;
    case OF_FL_TBL_FEAT_NTABLE_MISS:
         memcpy(tbl->props->bm_next_tables_miss, bmask,
               sizeof(tbl->props->bm_next_tables_miss));
        break;
    case OF_FL_TBL_FEAT_WR_ACT:
        tbl->props->bm_wr_actions = *bmask;
        break;
    case OF_FL_TBL_FEAT_WR_ACT_MISS:
        tbl->props->bm_wr_actions_miss = *bmask;
        break;
    case OF_FL_TBL_FEAT_APP_ACT:
        tbl->props->bm_app_actions = *bmask;
        break;
    case OF_FL_TBL_FEAT_APP_ACT_MISS:
        tbl->props->bm_app_actions_miss = *bmask;
        break;
    case OF_FL_TBL_FEAT_WR_SETF:
        memcpy(tbl->props->bm_wr_set_field, bmask,
               sizeof(tbl->props->bm_wr_set_field));
        break;
    case OF_FL_TBL_FEAT_WR_SETF_MISS:
        memcpy(tbl->props->bm_wr_set_field_miss, bmask,
               sizeof(tbl->props->bm_wr_set_field_miss));
        break;
    case OF_FL_TBL_FEAT_APP_SETF:
        memcpy(tbl->props->bm_app_set_field, bmask,
               sizeof(tbl->props->bm_app_set_field));
        break;
    case OF_FL_TBL_FEAT_APP_SETF_MISS:
        memcpy(tbl->props->bm_app_set_field_miss, bmask,
               sizeof(tbl->props->bm_app_set_field_miss));
        break;
    default:
        break;
    }
    
    c_rd_unlock(&sw->lock);
}
 
static void
c_switch_flow_table_enable(c_switch_t *sw, uint8_t table_id)
{
    struct flow flow, mask;
    c_flow_tbl_t  *tbl;
    bool en = false;
    mul_act_mdata_t mdata;
    int next_valid_tbl = -1;

    memset(&flow, 0, sizeof(flow));
    of_mask_set_dc_all(&mask);

    c_rd_lock(&sw->lock);
    tbl = &sw->rule_flow_tbls[table_id];

    if (!tbl->hw_tbl_active) {
        tbl->hw_tbl_active = 1;
        en = true; 
    }
    c_rd_unlock(&sw->lock);

    if (!en ||
        ctrl_hdl.no_dfl_flows) {
        return;
    }

    flow.table_id = table_id;
    mask.table_id = 0xff;

    if (table_id == 0) {
        next_valid_tbl = of_switch_get_next_valid_table(sw, table_id);
    }

    if (next_valid_tbl >= 0 &&
        sw->ofp_ctors->inst_goto) { 

        of_mact_alloc(&mdata);
        sw->ofp_ctors->inst_goto(&mdata, table_id+1);
        __of_send_flow_add_direct(sw, &flow, &mask, OFP_NO_BUFFER,
                              mdata.act_base, of_mact_len(&mdata),
                              0, 0, C_FL_PRIO_DFL); 
        of_mact_free(&mdata);

    } else {    
        assert(sw->ofp_ctors->act_output);
        of_mact_alloc(&mdata);
        if (sw->ofp_ctors->act_output) {
            sw->ofp_ctors->act_output(&mdata, 0); /* 0 -> Send to controller */
        }

        __of_send_flow_add_direct(sw, &flow, &mask, OFP_NO_BUFFER,
                              mdata.act_base, of_mact_len(&mdata),
                              0, 0, C_FL_PRIO_DFL); 
        of_mact_free(&mdata);
    }
}

static void
of10_recv_flow_mod(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow;
    struct ofp_flow_mod         *ofm = (void *)(b->data);
    struct of_flow_mod_params   fl_parms;
    void                        *app;
    uint16_t                    command = ntohs(ofm->command);
    bool                        flow_add;

    c_log_err("[OFP10] unexpected flow-mod");

    switch (command) {
    case OFPFC_MODIFY_STRICT:
        flow_add = true;
        break;
    case OFPFC_DELETE:
    case OFPFC_DELETE_STRICT: 
        flow_add = false;
        break;
    default:
        c_log_err("[OF10] unexpected flow-mod command");
        return;
    }

    memset(&flow, 0, sizeof(flow));
    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.ip.nw_src = ofm->match.nw_src;
    flow.ip.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.wildcards = ofm->match.wildcards;
    fl_parms.flow = &flow;
    fl_parms.flags = (uint8_t)ntohl(ofm->buffer_id);
    fl_parms.prio = ntohs(ofm->priority);

    if (flow_add) {
        fl_parms.action_len = ntohs(ofm->header.length) - sizeof(*ofm); 
        fl_parms.actions = calloc(1, fl_parms.action_len);
        memcpy(fl_parms.actions, ofm->actions, fl_parms.action_len);
    }

    /* Controller owns only vty intalled static flows */
    if (!(app = c_app_get(sw->c_hdl, C_VTY_NAME))) {
        c_log_err("[APP] |PANIC| Native app not found");
        return;
    }

    fl_parms.app_owner = app;
    if (flow_add) {
        c_switch_flow_add(sw, &fl_parms);
    } else {
        c_switch_flow_del(sw, &fl_parms);
    }
    c_app_put(app);
}
 
static void
of10_recv_stats_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_stats_reply *ofp_sr = (void *)(b->data);
    int act_len = 0;
    bool last = false;

    if (ntohs(ofp_sr->header.length) < sizeof(*ofp_sr)) {
        return;    
    }

    last = ntohs(ofp_sr->flags)? false: true;

    switch(ntohs(ofp_sr->type)) {
    case OFPST_FLOW:
        {
            struct ofp_flow_stats *ofp_fstats = (void *)(ofp_sr->body);
            ssize_t stat_length = ntohs(ofp_sr->header.length) - sizeof(*ofp_sr);

            while (stat_length > 0) {
                assert(sw->ofp_priv_procs->proc_one_flow_stats);
                act_len = sw->ofp_priv_procs->proc_one_flow_stats(sw,
                                                        (void *)(ofp_fstats));
                if (!act_len) break;
                ofp_fstats = INC_PTR8(ofp_fstats, sizeof(*ofp_fstats) + act_len);
                stat_length -= (sizeof(*ofp_fstats) + act_len);

            }
            if (last) { 
                if (!(sw->switch_state & SW_FLOW_PROBE_DONE) &&
                    sw->switch_state & SW_FLOW_PROBED) {
                    if (sw->n_tbl_probed)
                        sw->n_tbl_probed--;

                    if (sw->n_tbl_probed <= 0) {
                        c_log_debug("[SWITCH] |0x%llx| Flow probed",
                                    U642ULL(sw->DPID));
                        __c_switch_update_probe_state(sw, SW_FLOW_PROBE_DONE);
                    }
                }
            }

            break;
        }
    case OFPST_PORT:
        {
            struct ofp_port_stats *ofp_pstats = (void *)(ofp_sr->body);
            ssize_t stat_length = ntohs(ofp_sr->header.length) - sizeof(*ofp_sr);

            while (stat_length > 0) {
                assert(sw->ofp_priv_procs->proc_one_port_stats);
                sw->ofp_priv_procs->proc_one_port_stats(sw,
                                                        (void *)(ofp_pstats));
                ofp_pstats = INC_PTR8(ofp_pstats, sizeof(*ofp_pstats));
                stat_length -= sizeof(*ofp_pstats);
            }
            break;
        }
    default:
        c_log_err("[OF10] unhandled stats reply |0x%x|", ntohs(ofp_sr->type));
        break;
    }

    c_switch_try_publish(sw, false);
    return;
}

void __fastpath
of131_send_pkt_out_inline(void *arg, struct of_pkt_out_params *parms)
{
    struct cbuf     b;
    size_t          tot_len;
    uint8_t         data[C_INLINE_BUF_SZ];
    struct ofp131_packet_out *out;
    c_switch_t *sw = arg;

    if (sw->tx_lim_on && c_rlim(&sw->tx_rlim)) {
        sw->tx_pkt_out_dropped++;
        return;
    }

    tot_len = sizeof(struct ofp131_packet_out) +
                parms->action_len + parms->data_len;
    if (unlikely(tot_len > C_INLINE_BUF_SZ)) return of_send_pkt_out(sw, parms);

    cbuf_init_on_stack(&b, data, tot_len);
    of_prep_msg_on_stack(&b, tot_len, OFPT131_PACKET_OUT, 
                         (unsigned long)parms->data, sw->version);

    out = (void *)b.data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htonl(parms->in_port);
    out->actions_len = htons(parms->action_len);
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy((uint8_t *)out->actions + parms->action_len, 
            parms->data, parms->data_len);

    c_switch_tx(sw, &b, false);
} 

static c_port_t * 
of131_process_port(c_switch_t *sw UNUSED, void *opp_)
{
    const struct ofp131_port *opp;
    c_port_t *port_desc;

    opp = opp_;
    port_desc = calloc(sizeof(c_port_t), 1);
    assert(port_desc);

    port_desc->sw_port.port_no = ntohl(opp->port_no);
    port_config_to_cxlate(&port_desc->sw_port.config, ntohl(opp->config));
    port_status_to_cxlate(&port_desc->sw_port.state, ntohl(opp->state));
    port_desc->sw_port.curr = ntohl(opp->curr);
    port_desc->sw_port.advertised = ntohl(opp->advertised);
    port_desc->sw_port.supported = ntohl(opp->supported);
    port_desc->sw_port.peer      = ntohl(opp->peer);
    port_desc->sw_port.of_config = ntohl(opp->config);
    port_desc->sw_port.of_state  = ntohl(opp->state);

    memcpy(port_desc->sw_port.name, opp->name, OFP_MAX_PORT_NAME_LEN);
    port_desc->sw_port.name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
    memcpy(port_desc->sw_port.hw_addr, opp->hw_addr, OFP_ETH_ALEN);

    return port_desc;
}

static void UNUSED
of131_recv_err_flow_mod(c_switch_t *sw, struct cbuf *buf UNUSED,
                        struct ofp131_flow_mod *ofp_mod,
                        size_t msg_len, uint32_t cookie)
{
    struct flow flow, mask;
    struct ofpx_match *match;
    void *app_owner;
    uint16_t prio;
    ssize_t match_len;
    c_fl_entry_t *ent = NULL;
    struct c_sw_expired_ent *exp_ent = NULL;
    GSList *iterator = NULL;

    if (!cookie) {

        if (msg_len < sizeof(*ofp_mod)) return;

        match = &ofp_mod->match;
        match_len = C_ALIGN_8B_LEN(htons(match->length)); /* Aligned match-length */
        if (msg_len < sizeof(*ofp_mod) + match_len - OFPX_MATCH_HDR_SZ) {
            if (!c_rlim(&crl)) {
                c_log_err("[OF13] err msg too short to parse");
            }
            return;
        } 

        prio = ntohs(ofp_mod->priority);
        match = &ofp_mod->match;
        cookie = (uint32_t)ntohll(ofp_mod->cookie);
        if (of131_ofpx_match_to_flow(match, &flow, &mask)) {
            if (!c_rlim(&crl))
                c_log_err("[OF13] err msg:OXM TLV parse-err");
            return;
        }
        flow.table_id = ofp_mod->table_id;
        mask.table_id = 0xff;  /* Inconsequential */
    } else {
        memset(&flow, 0, sizeof(flow)); 
        memset(&mask, 0, sizeof(flow)); 
        prio = 0;
    }

    ent = cookie ? c_do_flow_lookup_with_cookie(sw, &flow, &mask, prio,
                                                (uint32_t)cookie) :
                   c_do_flow_lookup_with_detail(sw, &flow, &mask, prio);
    if (!ent) {
        if (!c_rlim(&crl))
            c_log_err("[FLOW] %s: No such flow", FN);
        return;    
    }

    c_rd_lock(&ent->FL_LOCK);
    for (iterator = ent->app_owner_list; iterator;
         iterator = iterator->next) {
        app_owner = iterator->data;
        c_app_ref(app_owner);
        exp_ent = calloc(1, sizeof(*exp_ent));
        exp_ent->app = app_owner;
        exp_ent->b = c_ofp_prep_flow_mod(ent->sw, ent, false);
        ent->sw->exp_list = g_slist_append(ent->sw->exp_list,
                                           exp_ent);
    }
    c_rd_unlock(&ent->FL_LOCK);

    c_sw_trigger_expiry(sw);
}

static void
of131_recv_err_msg(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_error_msg *ofp_err = (void *)(b->data);
    struct ofp_header *ofp = ASSIGN_PTR(ofp_err->data);
    bool parse_body = false;
    ssize_t orig_len = ntohs(ofp_err->header.length) - sizeof(*ofp_err);

    if (!c_rlim(&crl))
        c_log_err("[OF13] error from switch |0x%llx| type|%hu|code|%hu|", 
                   U642ULL(sw->DPID), ntohs(ofp_err->type),
                   ntohs(ofp_err->code));

    switch(ntohs(ofp_err->type)) {
    case OFPET131_FLOW_MOD_FAILED:
    case OFPET131_BAD_REQUEST:
    case OFPET131_BAD_ACTION: 
    case OFPET131_BAD_INSTRUCTION: 
    case OFPET131_BAD_MATCH: 
        parse_body = true;
        break;
    default:
        break;
    }

    if (!parse_body && orig_len >= sizeof(*ofp)) return;

    switch (ofp->type) {
    case OFPT131_FLOW_MOD:
        //return of131_recv_err_flow_mod(sw, b, (void *)ofp, orig_len, 0);
    default:
        break;
    }
}
 
static void
of131_recv_features_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp131_switch_features  *osf = CBUF_DATA(b);
    int tbl = 0;
    struct flow  flow;
    struct flow  mask;

    memset(&flow, 0, sizeof(flow));
    of_mask_set_dc_all(&mask);

    if (!c_switch_features_check(sw, ntohll(osf->datapath_id))) {
        return;
    }

    c_init_switch_features(sw, ntohll(osf->datapath_id), osf->header.version,
                           osf->n_tables, ntohl(osf->n_buffers), 0,
                           ntohl(osf->capabilities));                           

    c_register_switch(sw, b, false);

    for (tbl = 0; tbl < sw->n_tables; tbl++) {
         flow.table_id = tbl;
         __of_send_flow_del_direct(sw, &flow, &mask, 0,
                                    false, C_FL_PRIO_DFL, OFPG_ANY);
     }
     __of_send_clear_all_groups(sw);
     __of_send_clear_all_meters(sw);

    /* Get all the table features */
    c_switch_tx(sw, of131_prep_mpart_msg(OFPMP_TABLE_FEATURES, 0, 0), false);

    /* Get all the group features */
    c_switch_tx(sw, of131_prep_mpart_msg(OFPMP_GROUP_FEATURES, 0, 0), false);

    /* Get all the meter features */
    c_switch_tx(sw, of131_prep_mpart_msg(OFPMP_METER_FEATURES, 0, 0), false);

    /* There is no port info in features reply. Get it! */
    c_switch_tx(sw, of131_prep_mpart_msg(OFPMP_PORT_DESC, 0, 0), false);

    /* Update gen-id if stale */
    c_switch_tx(sw, of131_prep_role_request_msg(OFPCR_ROLE_NOCHANGE, 0), false); 

    sw->last_feat_probed = time(NULL);
}

static void
of131_recv_barrier_reply(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    /* Nothing to do */
}

static void of131_process_port_stats(c_switch_t *sw, struct ofp_multipart_reply *ofp_mr)
{
    struct ofp131_port_stats *ofp_ps = (void *)(ofp_mr->body);
    ssize_t stat_length = ntohs(ofp_mr->header.length) -
        sizeof(*ofp_mr);
    c_port_t *port = NULL;
    uint32_t port_no;

    int loops = OFSW_MAX_PORT_STATS_COLL;
    while (loops-- > 0 &&
            stat_length >= (int)(sizeof(*ofp_ps))) {

        c_wr_lock(&sw->lock);
        port_no = ntohl(ofp_ps->port_no);
        if ((port = g_hash_table_lookup(sw->sw_ports,
                        &port_no))) {
            if(!port->port_stats) {
                port->port_stats = calloc(1,sizeof(*ofp_ps));
                port->port_stat_len = sizeof(*ofp_ps);
            }
            if (port->port_stat_len == sizeof(*ofp_ps))
                memcpy(port->port_stats,ofp_ps,port->port_stat_len);
        }
        else {
            if (!c_rlim(&crl)) {
                c_log_err("[OF13] mpart-rx:|0x%llx| no port %u",
                        sw->DPID, ntohl(ofp_ps->port_no));
            }
        }
        c_wr_unlock(&sw->lock);

        stat_length -= sizeof(*ofp_ps);
        ofp_ps = INC_PTR8(ofp_ps, sizeof(*ofp_ps));
    }
}

static void of140_process_port_stats(c_switch_t *sw, struct ofp_multipart_reply *ofp_mr)
{
    struct ofp140_port_stats *ofp_ps = (void *)(ofp_mr->body);
    ssize_t stat_length = ntohs(ofp_mr->header.length) -
        sizeof(*ofp_mr);
    c_port_t *port = NULL;
    uint32_t port_no;
    size_t port_stat_length = 0;

    int loops = OFSW_MAX_PORT_STATS_COLL;
    while (loops-- > 0 &&
            stat_length >= (int)(sizeof(*ofp_ps))) {

        c_wr_lock(&sw->lock);
        port_no = ntohl(ofp_ps->port_no);
        port_stat_length = ntohs(ofp_ps->length);
        if ((port = g_hash_table_lookup(sw->sw_ports,
                        &port_no))) {
            if(!port->port_stats) {
                port->port_stats = calloc(1, port_stat_length);
                port->port_stat_len =  port_stat_length;
            }
            if (port->port_stat_len ==  port_stat_length)
                memcpy(port->port_stats,ofp_ps,port->port_stat_len);
            else {
                c_log_err("[OF14] port-stats-rx:|0x%llx| port %u Len err:"
                        "|%d:%d|",
                        sw->DPID, ntohl(ofp_ps->port_no),(int)port_stat_length,
                        (int)port->port_stat_len);
            }

        }
        else {
            if (!c_rlim(&crl)) {
                c_log_err("[OF14] mpart-rx:|0x%llx| no port %u",
                        sw->DPID, ntohl(ofp_ps->port_no));
            }
        }
        c_wr_unlock(&sw->lock);

        stat_length -= (port_stat_length);
        ofp_ps = INC_PTR8(ofp_ps, port_stat_length);
    }
}

static void
of13_14_mpart_process(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_multipart_reply *ofp_mr = CBUF_DATA(b);
    ssize_t body_len = ntohs(ofp_mr->header.length) - sizeof(*ofp_mr);
    int loops; /* Will not support more than this */
    int ret = -1;
    bool last = !(ntohs(ofp_mr->flags) & OFPMPF_REPLY_MORE);

    if (ntohs(ofp_mr->header.length) < sizeof(*ofp_mr)) {
        return;
    }

    switch (htons(ofp_mr->type)) {
    case OFPMP_PORT_DESC:
        {
            struct ofp131_port *port = (void *)(ofp_mr->body);
            struct c_port_chg_mdata mdata;
            c_port_t *port_desc = NULL;
            struct c_port_cfg_state_mask chg_mask = { 0, 0 };
            uint16_t port_length = 0;
            loops = OFSW_MAX_REAL_PORTS; /* Will not support more than this */

            while (body_len >= (int)(sizeof(*port)) && (loops-- > 0)) {
                port_desc = sw->ofp_priv_procs->xlate_port_desc(sw, port);
                if(sw->version == OFP_VERSION_131) {
                    assert(port_desc);
                    port_length = sizeof(*port);
                }
                else {
                    /* length parameter has been introduced in OF1.4 and it
                     * has been taken from the padded bytes, so typecasting
                     * port to ofp140_port will suffice the situation*/
                    port_length = ntohs(((struct ofp140_port *)port)->length);
                    if(!port_desc){
                        c_log_err("[OF14] Incorrect Port Desc recvd");
                        body_len -= port_length;
                        port = INC_PTR8(port, port_length);
                        continue;
                    }
                }

                c_wr_lock(&sw->lock);
                __c_switch_port_update(sw, port_desc, OFPPR_ADD, &chg_mask);
                c_wr_unlock(&sw->lock);

                mdata.reason = OFPPR_ADD;
                mdata.chg_mask = &chg_mask;
                mdata.port_desc = &port_desc->sw_port;
                c_signal_app_event(sw, b, C_PORT_CHANGE, NULL, &mdata, false);

                free(port_desc);
                body_len -= port_length;
                port = INC_PTR8(port, port_length);
                if (last) sw->switch_state |= SW_OFP_PORT_FEAT;
            } 
            break;
        }
    case OFPMP_FLOW:
        {
            struct ofp131_flow_stats *ofp_stats = (void *)(ofp_mr->body);
            ssize_t stat_length = ntohs(ofp_mr->header.length) -
                                    sizeof(*ofp_mr);
            loops = OFSW_MAX_FLOW_STATS_COLL;

            while (loops-- > 0 &&
                   stat_length >= (int)(sizeof(*ofp_stats))) {

                if (stat_length < (int)ntohs(ofp_stats->length)) {
                    c_log_err("[OF13] mpart-rx:flow stats len err %d of %d",
                              (int)stat_length, (int)ntohs(ofp_stats->length));
                    break;
                }
                assert(sw->ofp_priv_procs->proc_one_flow_stats);
                ret = sw->ofp_priv_procs->proc_one_flow_stats(sw,
                                                        (void *)(ofp_stats));
                if (ret < 0) break;
                stat_length -= ntohs(ofp_stats->length);
                ofp_stats = INC_PTR8(ofp_stats, ntohs(ofp_stats->length));
            }
            if (last) { 
                if (!(sw->switch_state & SW_FLOW_PROBE_DONE) &&
                    sw->switch_state & SW_FLOW_PROBED) {
                    if (sw->n_tbl_probed)
                        sw->n_tbl_probed--;

                    if (sw->n_tbl_probed <= 0) {
                        c_log_debug("[SWITCH] |0x%llx| Flow probed",
                                    U642ULL(sw->DPID));
                        __c_switch_update_probe_state(sw, SW_FLOW_PROBE_DONE);
                    }
                }
            }
            break;
        }
    case OFPMP_TABLE_FEATURES: 
        {
            struct ofp_table_features *ofp_tf = (void *)(ofp_mr->body);
            ssize_t table_feat_len = ntohs(ofp_mr->header.length) -
                                        sizeof(*ofp_mr);
            loops = C_MAX_RULE_FLOW_TBLS;

            while (table_feat_len >= sizeof(*ofp_tf) && loops-- > 0) {
                if (sw->ofp_priv_procs->proc_one_tbl_feature) {
                    sw->ofp_priv_procs->proc_one_tbl_feature(sw, (void *)ofp_tf);
                }
                c_switch_flow_table_enable(sw, ofp_tf->table_id);
                table_feat_len -= ntohs(ofp_tf->length);
                ofp_tf = INC_PTR8(ofp_tf, ntohs(ofp_tf->length));
            }
            if (last) sw->switch_state |= SW_OFP_TBL_FEAT; 
            break;
        }
    case OFPMP_GROUP_FEATURES: 
        {
            struct ofp_group_features *ofp_gf = (void *)(ofp_mr->body);

            if (body_len < sizeof(*ofp_gf)) break;

            if (!sw->group_features || 
                sw->group_feat_len != sizeof(*ofp_gf)) { 
                if (sw->group_features) free(sw->group_features);
                sw->group_features = calloc(1, sizeof(*ofp_gf));
                if (!sw->group_features) break;
            }
            c_wr_lock(&sw->lock);
            memcpy(sw->group_features, ofp_gf, sizeof(*ofp_gf)); 
            sw->group_feat_len = sizeof(*ofp_gf);
            c_wr_unlock(&sw->lock);
            if (last) sw->switch_state |= SW_OFP_GRP_FEAT; 
            break;
        }
    case OFPMP_METER_FEATURES: 
        {
            struct ofp_meter_features *ofp_mf = (void *)(ofp_mr->body);

            if (body_len < sizeof(*ofp_mf)) break;

            if (!sw->meter_features || 
                sw->meter_feat_len != sizeof(*ofp_mf)) { 
                if (sw->meter_features) free(sw->meter_features);
                sw->meter_features = calloc(1, sizeof(*ofp_mf));
                if (!sw->meter_features) break;
            }
            c_wr_lock(&sw->lock);
            memcpy(sw->meter_features, ofp_mf, sizeof(*ofp_mf)); 
            sw->meter_feat_len = sizeof(*ofp_mf);
            c_wr_unlock(&sw->lock);
            if (last) sw->switch_state |= SW_OFP_MET_FEAT; 
            break;
        }
    case OFPMP_METER:
        {
            struct ofp_meter_stats *ofp_ms = (void *)(ofp_mr->body);
            c_switch_meter_t *meter = NULL;
            ssize_t stat_length = ntohs(ofp_mr->header.length) -
                                        sizeof(*ofp_mr);
            uint32_t id;

            loops = OFSW_MAX_GROUP_STATS_COLL;
            while (loops-- > 0 &&
                   stat_length >= (int)(sizeof(*ofp_ms))) {

                if (stat_length < (int)ntohs(ofp_ms->len)) {
                    c_log_err("[OF13] mpart-rx:meter stats len err %d of %d",
                              (int)stat_length, (int)ntohs(ofp_ms->len));
                    break;
                }

                id = ntohl(ofp_ms->meter_id);
                c_wr_lock(&sw->lock);
                if ((meter = g_hash_table_lookup(sw->meters, 
                                                 &id))) {
                    meter->last_seen = time(NULL);
                    meter->flow_count = ntohl(ofp_ms->flow_count);
                    meter->byte_count = ntohll(ofp_ms->byte_in_count);
                    meter->packet_count = ntohll(ofp_ms->packet_in_count);
                    meter->duration_sec = ntohl(ofp_ms->duration_sec);
                    meter->duration_nsec = ntohl(ofp_ms->duration_nsec);
                    meter->installed = true;
                } else {
                    if (!c_rlim(&crl)) {
                        c_log_err("[OF13] mpart-rx:|0x%llx| no meter %u",
                                  sw->DPID, ntohl(ofp_ms->meter_id));
                    }
                }
                c_wr_unlock(&sw->lock); 
                stat_length -= ntohs(ofp_ms->len);
                ofp_ms = INC_PTR8(ofp_ms, ntohs(ofp_ms->len));
            }
            break;
        }
    case OFPMP_METER_CONFIG:
        {
            uint32_t id;
            void *app;
            int nbands = 0, i = 0;
            struct of_meter_mod_params m_parms;
            ssize_t band_len, tot_len;
            struct of_meter_band_elem *band_elem;
            struct ofp_meter_band_header *band_pelem;
            struct ofp_meter_config *ofp_mc = (void *)(ofp_mr->body);
            ssize_t stat_length = ntohs(ofp_mr->header.length) -
                                    sizeof(*ofp_mr);
            bool free_mparms = false;
            c_switch_meter_t *meter;

            memset(&m_parms, 0, sizeof(m_parms));
            loops = OFSW_MAX_METER_STATS_COLL;
            while (loops-- > 0 &&
                   stat_length >= (int)(sizeof(*ofp_mc))) {

                if (stat_length < (int)ntohs(ofp_mc->length)) {
                    c_log_err("[OF13] mpart-rx:meter stats len err %d of %d",
                              (int)stat_length, (int)ntohs(ofp_mc->length));
                    break;
                }

                id = ntohl(ofp_mc->meter_id);
                c_wr_lock(&sw->lock);
                if ((meter = g_hash_table_lookup(sw->meters, 
                                                 &id))) {
                    meter->last_seen = time(NULL);
                    meter->installed = true;
                } else {
                    if (!c_rlim(&crl)) {
                        c_log_err("[OF13] mpart-rx:|0x%llx| no meter %u",
                                  sw->DPID, ntohl(ofp_mc->meter_id));
                    }
                    if (sw->switch_state & SW_METER_PROBED &&
                        !(sw->switch_state & SW_METER_PROBE_DONE)) {

                        memset(&m_parms, 0, sizeof(m_parms));
                        nbands = 0;
                        free_mparms = true;

                        band_pelem = ASSIGN_PTR(ofp_mc->bands);
                        tot_len = ntohs(ofp_mc->length) - sizeof(*ofp_mc);
                        if (tot_len <= 0) goto next_meter;
                        while (tot_len >= 
                               (int)sizeof(struct ofp_meter_band_header) &&
                               nbands < OF_MAX_METER_VECTORS) {
                            band_elem = calloc(1, sizeof(*band_elem));
                            band_len = ntohs(band_pelem->len);
                            if (band_len > tot_len) goto next_meter;
                            if (!band_elem) goto next_meter;
                            if (!(band_elem->band = calloc(1, band_len)))
                                goto next_meter;
                            memcpy(band_elem->band, band_pelem, band_len);
                            m_parms.meter_bands[nbands] = band_elem;
                            band_elem->band_len = band_len;
                            band_pelem = INC_PTR8(band_pelem, band_len);
                            nbands++;
                            tot_len -= band_len;
                        }
                        /* Dont try to add if we cant support */
                        if (nbands >= OF_MAX_METER_VECTORS)
                            goto next_meter;
                        m_parms.meter = id;
                        m_parms.flags = ntohs(ofp_mc->flags);
                        m_parms.meter_nbands = nbands;
                        m_parms.cflags = C_METER_RESIDUAL;
                        if (m_parms.flags & OFPMF_STATS)
                            m_parms.cflags |= C_METER_GSTATS;
                        b = c_of_prep_meter_mod_msg_with_parms(sw, &m_parms, true);
                        if (!b) goto next_meter;
                        app = c_app_get(&ctrl_hdl, C_VTY_NAME);
                        if (app) {
                            c_wr_unlock(&sw->lock);
                            __mul_app_command_handler(app, b);
                            c_wr_lock(&sw->lock);
                            c_app_put(app);
                        }
                        free_cbuf(b);
                    }
                }
next_meter:
                if (free_mparms) {
                    for (i = 0; i < OF_MAX_METER_VECTORS; i++) {
                        band_elem = m_parms.meter_bands[i];
                        if (band_elem) {
                            if (band_elem->band) free(band_elem->band);
                            band_elem->band = NULL;
                            free(band_elem);
                        }
                        m_parms.meter_bands[i] = NULL;
                    }
                }
                c_wr_unlock(&sw->lock); 

                stat_length -= ntohs(ofp_mc->length);
                ofp_mc = INC_PTR8(ofp_mc, ntohs(ofp_mc->length));
            }
            if (last) { 
                if (!(sw->switch_state & SW_METER_PROBE_DONE) &&
                    sw->switch_state & SW_METER_PROBED) {
                    c_log_debug("[SWITCH] |0x%llx| Meter probed", U642ULL(sw->DPID));
                    __c_switch_update_probe_state(sw, SW_METER_PROBE_DONE);
                }
            }
            break;
        }
    case OFPMP_GROUP_DESC:
        {
            uint32_t id;
            void *app;
            int i = 0, nbkts = 0;
            struct of_group_mod_params g_parms;
            struct of_act_vec_elem *act_elem;
            bool free_gparms = false;
            ssize_t bkt_len, tot_len, act_len;
            struct ofp_group_desc *ofp_gs = (void *)(ofp_mr->body);
            ssize_t stat_length = ntohs(ofp_mr->header.length) -
                                    sizeof(*ofp_mr);
            c_switch_group_t *group = NULL;
            struct ofp_bucket *of_bkt_elem;

            memset(&g_parms, 0, sizeof(g_parms));
            loops = OFSW_MAX_GROUP_STATS_COLL;
            while (loops-- > 0 &&
                   stat_length >= (int)(sizeof(*ofp_gs))) {

                if (stat_length < (int)ntohs(ofp_gs->length)) {
                    c_log_err("[OF13] mpart-rx:group desc len err %d of %d",
                              (int)stat_length, (int)ntohs(ofp_gs->length));
                    break;
                }

                c_wr_lock(&sw->lock);
                id = ntohl(ofp_gs->group_id);
                if ((group = g_hash_table_lookup(sw->groups,
                                                 &id))) {
                    group->last_seen = time(NULL);
                    group->installed = true;
                } else {
                    if (!c_rlim(&crl)) {
                        c_log_err("[OF13] mpart-rx:|0x%llx| no grp desc %u",
                                  sw->DPID, ntohl(ofp_gs->group_id));
                    } 
                    if (sw->switch_state & SW_GROUP_PROBED &&
                        !(sw->switch_state & SW_GROUP_PROBE_DONE)) {

                        memset(&g_parms, 0, sizeof(g_parms));
                        free_gparms = true;

                        g_parms.group = id;
                        g_parms.type = ofp_gs->type; 
                        g_parms.flags = C_GRP_RESIDUAL;
                        of_bkt_elem = ASSIGN_PTR(ofp_gs->buckets);
                        tot_len = ntohs(ofp_gs->length) - sizeof(*ofp_gs);
                        if (tot_len <= 0) goto next_group_desc;
                        while (tot_len >=
                               (int)sizeof(struct ofp_bucket) &&
                               nbkts < OF_MAX_ACT_VECTORS) {
                            act_elem = calloc(1, sizeof(*act_elem));
                            bkt_len = ntohs(of_bkt_elem->len);
                            act_len = bkt_len - sizeof(*of_bkt_elem);
                            if (act_len > bkt_len || bkt_len > tot_len ||
                                !act_elem)
                                goto next_group_desc;
                            if (!(act_elem->actions = calloc(1, act_len)))
                                goto next_group_desc;
                            memcpy(act_elem->actions, of_bkt_elem->actions, act_len);
                            act_elem->action_len = act_len;
                            act_elem->weight = ntohs(of_bkt_elem->weight);
                            act_elem->ff_port = ntohl(of_bkt_elem->watch_port);
                            act_elem->ff_group = ntohl(of_bkt_elem->watch_group);
                            g_parms.act_vectors[nbkts] = act_elem;
                            of_bkt_elem = INC_PTR8(of_bkt_elem, bkt_len);
                            nbkts++;
                            tot_len -= bkt_len;
                        }
                        g_parms.act_vec_len = nbkts;
                        b = c_of_prep_group_mod_msg_with_parms(sw, &g_parms, true);
                        if (!b) goto next_group_desc;
                        app = c_app_get(&ctrl_hdl, C_VTY_NAME);
                        if (app) {
                            c_wr_unlock(&sw->lock);
                            __mul_app_command_handler(app, b);
                            c_wr_lock(&sw->lock);
                            c_app_put(app);
                        }
                        free_cbuf(b);
                    }
                }
next_group_desc:
                if (free_gparms) {
                    for (i = 0; i < OF_MAX_ACT_VECTORS; i++) {
                        act_elem = g_parms.act_vectors[i];
                        if (act_elem) {
                            if (act_elem->actions) free(act_elem->actions);
                            act_elem->actions = NULL;
                            free(act_elem);
                        }
                        g_parms.act_vectors[i] = NULL;
                    }
                }
                c_wr_unlock(&sw->lock);

                stat_length -= ntohs(ofp_gs->length);
                ofp_gs = INC_PTR8(ofp_gs, ntohs(ofp_gs->length));
            }
            if (last) { 
                if (!(sw->switch_state & SW_GROUP_PROBE_DONE) &&
                    sw->switch_state & SW_GROUP_PROBED) {
                    c_log_debug("[SWITCH] |0x%llx| Groups probed", U642ULL(sw->DPID));
                    __c_switch_update_probe_state(sw, SW_GROUP_PROBE_DONE);
                }
            }
            break;
        }

    case OFPMP_GROUP:
        {
            uint32_t id;
            void *app;
            int i = 0;
            struct of_group_mod_params g_parms;
            struct of_act_vec_elem *act_elem;
            bool free_gparms = false;
            struct ofp_group_stats *ofp_gs = (void *)(ofp_mr->body);
            ssize_t stat_length = ntohs(ofp_mr->header.length) -
                                    sizeof(*ofp_mr);
            c_switch_group_t *group = NULL;

            memset(&g_parms, 0, sizeof(g_parms));
            loops = OFSW_MAX_GROUP_STATS_COLL;
            while (loops-- > 0 &&
                   stat_length >= (int)(sizeof(*ofp_gs))) {

                if (stat_length < (int)ntohs(ofp_gs->length)) {
                    c_log_err("[OF13] mpart-rx:group stats len err %d of %d",
                              (int)stat_length, (int)ntohs(ofp_gs->length));
                    break;
                }

                c_wr_lock(&sw->lock);
                id = ntohl(ofp_gs->group_id);
                if ((group = g_hash_table_lookup(sw->groups,
                                                 &id))) {
                    group->last_seen = time(NULL);
                    group->installed = true;
                    if (group->flags & C_GRP_GSTATS) {
                        group->byte_count = ntohll(ofp_gs->byte_count);
                        group->packet_count = ntohll(ofp_gs->packet_count);
                        group->duration_sec = ntohl(ofp_gs->duration_sec);
                        group->duration_nsec = ntohl(ofp_gs->duration_nsec);
                    }
                } else {
                    if (!c_rlim(&crl)) {
                        c_log_err("[OF13] mpart-rx:|0x%llx| no grp %u",
                                  sw->DPID, ntohl(ofp_gs->group_id));
                    } 
                    if (sw->switch_state & SW_GROUP_PROBED &&
                        !(sw->switch_state & SW_GROUP_PROBE_DONE)) {

                        memset(&g_parms, 0, sizeof(g_parms));
                        free_gparms = true;

                        g_parms.group = id;
                        g_parms.flags = C_GRP_RESIDUAL;
                        /* No group type in stats */
                        b = c_of_prep_group_mod_msg_with_parms(sw, &g_parms, true);
                        if (!b) goto next_group;
                        app = c_app_get(&ctrl_hdl, C_VTY_NAME);
                        if (app) {
                            c_wr_unlock(&sw->lock);
                            __mul_app_command_handler(app, b);
                            c_wr_lock(&sw->lock);
                            c_app_put(app);
                        }
                        free_cbuf(b);
                    }
                }
next_group:
                if (free_gparms) {
                    for (i = 0; i < OF_MAX_ACT_VECTORS; i++) {
                        act_elem = g_parms.act_vectors[i];
                        if (act_elem) {
                            if (act_elem->actions) free(act_elem->actions);
                            act_elem->actions = NULL;
                            free(act_elem);
                        }
                        g_parms.act_vectors[i] = NULL;
                    }
                }
                c_wr_unlock(&sw->lock);

                stat_length -= ntohs(ofp_gs->length);
                ofp_gs = INC_PTR8(ofp_gs, ntohs(ofp_gs->length));
            }
            if (last) { 
                if (!(sw->switch_state & SW_GROUP_PROBE_DONE) &&
                    sw->switch_state & SW_GROUP_PROBED) {
                    c_log_debug("[SWITCH] |0x%llx| Groups probed", U642ULL(sw->DPID));
                    __c_switch_update_probe_state(sw, SW_GROUP_PROBE_DONE);
                }
            }
            break;
        }
    case OFPMP_PORT_STATS:
        {
            if(sw->version == OFP_VERSION_131) {
                of131_process_port_stats(sw, ofp_mr);
            }
            else {
                of140_process_port_stats(sw, ofp_mr);
            }
                        break;
        }
 
    case OFPMP_TABLE:
        {
            struct ofp131_table_stats *ofp_ts = (void *)(ofp_mr->body);
            ssize_t stat_length = ntohs(ofp_mr->header.length) -
                                    sizeof(*ofp_mr);
            c_flow_tbl_t *tbl = NULL;

            loops = 255;
            while (loops-- >= 0 &&
                   stat_length >= (int)(sizeof(*ofp_ts))) {

                c_wr_lock(&sw->lock);
                tbl = &sw->rule_flow_tbls[ofp_ts->table_id];
                if (tbl && tbl->hw_tbl_active) {
                    tbl->hw_active_count = ntohl(ofp_ts->active_count);
                    tbl->hw_lookup_count = ntohll(ofp_ts->lookup_count);
                    tbl->hw_matched_count = ntohll(ofp_ts->matched_count);
                }
                c_wr_unlock(&sw->lock);

                stat_length -= sizeof(*ofp_ts);
                ofp_ts = INC_PTR8(ofp_ts, sizeof(*ofp_ts));
            }
            break;
        }
    case OFPMP_QUEUE:
        {
            c_pkt_q_t *q = NULL;
            c_port_t *port = NULL;
            struct ofp131_queue_stats *ofp_q_stat = (void *)(ofp_mr->body);
            ssize_t stat_length = ntohs(ofp_mr->header.length) -
                                    sizeof(*ofp_mr);
            loops = 65535;
            while (loops-- >= 0 &&
                   stat_length >= (int)(sizeof(*ofp_q_stat))) {

                c_wr_lock(&sw->lock);
                port = __c_switch_port_find(sw, ntohl(ofp_q_stat->port_no));
                if (port &&
                    (q = __c_port_q_find(port, 
                                         ntohl(ofp_q_stat->queue_id)))) {
                    q->last_seen = time(NULL);
                    if (!q->q_stats) {
                        q->q_stats = calloc(1, sizeof(*ofp_q_stat));
                    }
                    if (q->q_stats) {
                        memcpy(q->q_stats, ofp_q_stat, sizeof(*ofp_q_stat));
                        q->q_stats_len = sizeof(*ofp_q_stat);
                    } 
                }    
                c_wr_unlock(&sw->lock);
                stat_length -= sizeof(*ofp_q_stat);
                ofp_q_stat = INC_PTR8(ofp_q_stat, sizeof(*ofp_q_stat));
            }
            break;
        }
    default:
        if (!c_rlim(&crl))
            c_log_err("[OF13] mpart-rx: |%u| not handled", htons(ofp_mr->type));
        break; 
    } 

    c_switch_try_publish(sw, true);
}

static void
of131_recv_mpart_reply(c_switch_t *sw, struct cbuf *b)
{
    // struct ofp_multipart_reply *ofp_mr = CBUF_DATA(b);

    if (1/*!(ntohs(ofp_mr->flags) & OFPMPF_REPLY_MORE)*/) {
        return of13_14_mpart_process(sw, b);
    } else {
        /* FIXME : Buffering logic required ?? */
        return;
    }
}

static void
of131_recv_q_config_reply(c_switch_t *sw, struct cbuf *b)
{
    ssize_t tot_len;
    struct ofp131_queue_get_config_reply *ofp_qc = CBUF_DATA(b);
    struct ofp131_packet_queue *ofp_q;
    c_port_t *port;
    size_t q_len = 0;

    tot_len = htons(ofp_qc->header.length); 
    if (tot_len < sizeof(*ofp_qc)) return;
    tot_len -= sizeof(*ofp_qc);

    c_wr_lock(&sw->lock);
    port = __c_switch_port_find(sw, ntohl(ofp_qc->port));
    if (!port) goto unlock_out;

    ofp_q = ASSIGN_PTR(&ofp_qc->queues[0]);
    while (tot_len >= sizeof(*ofp_q)) {
        q_len = ntohs(ofp_q->len); 
        if (q_len >= sizeof(*ofp_q) &&
            tot_len >= q_len) {
            __c_port_q_add(port, ntohl(ofp_q->queue_id),
                           ofp_q->properties,
                           q_len - sizeof(*ofp_q));
        } else {
            break;
        }

        ofp_q = INC_PTR8(ofp_q, q_len);
        tot_len -= q_len;
    }

#ifdef C_OF_QUEUE_TEST_STUB
    static uint32_t qid = 1;
    if (qid < 5) {
        __c_port_q_add(port, qid++, NULL, 0); 
        __c_port_q_add(port, qid++, NULL, 0);
    }
#endif
unlock_out:
    c_wr_unlock(&sw->lock);
    return;
}

static void
of131_recv_role_reply(c_switch_t *sw, struct cbuf *b UNUSED)
{
    uint32_t curr_role = 0;
    uint64_t gen_id;

    c_ha_get_of_state(&curr_role, &gen_id);
    c_log_info("[HA] |Switch-0x%llx| New role confirmed |%s|",
               U642ULL(sw->DPID), of_role_to_str(curr_role)); 
}

static void __fastpath
of131_recv_packet_in(c_switch_t *sw, struct cbuf *b)
{
    struct ofp131_packet_in *opi __aligned = CBUF_DATA(b);
    size_t pkt_len, pkt_ofs;
    struct flow fl[2]; /*Flow and mask pair */
    bool only_l2 = sw->fp_ops.fp_fwd == c_l2_lrn_fwd ? true : false;
    uint8_t *data;
    ssize_t match_len;
    struct c_pkt_in_mdata mdata; 

    if (sw->rx_lim_on && c_rlim(&sw->rx_rlim)) {
        sw->rx_pkt_in_dropped++;
        return;
    }

    match_len = C_ALIGN_8B_LEN(htons(opi->match.length)); /* Aligned match-length */
    match_len -= sizeof(opi->match);

    if (ntohs(opi->header.length) < sizeof(*opi) + match_len ||
        of131_ofpx_match_to_flow(&opi->match, &fl[0], &fl[1])) {
        return;
    }

    pkt_ofs = (sizeof(*opi) + match_len + 2);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    data = INC_PTR8(opi, pkt_ofs);

    if(!sw->fp_ops.fp_fwd ||
        (pkt_len && 
         of_flow_extract(data, &fl[0], ntohl(fl[0].in_port), 
                        pkt_len, only_l2) < 0)) {
        return;
    }

    fl[0].table_id = opi->table_id;

    mdata.fl = &fl[0];
    mdata.pkt_ofs = pkt_ofs;
    mdata.pkt_len = pkt_len;

    /* If its because of flow miss or controller action,
     * we already make sure we get the whole packet. Some
     * switches can still send buffer-id along with whole
     * packet causing confusion in our apps
     */
    mdata.buffer_id = opi->reason != OFPR_INVALID_TTL ? 
                        0xffffffff : ntohl(opi->buffer_id);

    sw->fp_ops.fp_fwd(sw, b, data, pkt_len, &mdata, ntohl(fl[0].in_port));
    return;
}

static void
of131_recv_flow_mod(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    /* TODO */
}

static void
of131_flow_removed(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    /* TODO */
} 

static void
of131_recv_port_status(c_switch_t *sw, struct cbuf *b)
{
    struct c_port_chg_mdata mdata;
    struct c_port_cfg_state_mask chg_mask = { 0, 0 };
    struct ofp131_port_status *ops = CBUF_DATA(b);
    c_port_t *port_desc = NULL;

    port_desc = sw->ofp_priv_procs->xlate_port_desc(sw, &ops->desc);
    assert(port_desc);

    c_wr_lock(&sw->lock);
    __c_switch_port_update(sw, port_desc, ops->reason, &chg_mask);
    c_wr_unlock(&sw->lock);

    mdata.reason = ops->reason;
    mdata.chg_mask = &chg_mask; 
    mdata.port_desc = &port_desc->sw_port;
    c_signal_app_event(sw, b, C_PORT_CHANGE, NULL, &mdata, false);

    if (sw->fp_ops.fp_port_status)
        sw->fp_ops.fp_port_status(sw,
                                  port_desc->sw_port.port_no,
                                  port_desc->sw_port.config,
                                  port_desc->sw_port.state,
                                  &chg_mask);
    free(port_desc);
}

static void
of131_proc_tbl_feat_instructions(c_switch_t *sw, void *prop,
                                    uint8_t table_id,
                                    bool miss, size_t buf_len)
{
    struct ofp_table_feature_prop_instructions *ofp_tfi = prop;
    struct ofp_instruction *ofp_i;
    uint32_t inst_supp_bmask = 0;
    size_t len = ntohs(ofp_tfi->length); 
    size_t ilen;
    int loops = 0xffff;

    if (len > buf_len || buf_len < sizeof(*ofp_tfi)) {
        c_log_err("[OF13] table-feat len-err");
        return;
    }

    len -= sizeof(struct ofp_table_feature_prop_header);
    ofp_i = ofp_tfi->instruction_ids;
    while (loops-- > 0 &&
           len > sizeof(*ofp_i)) {

        ilen = ntohs(ofp_i->len);
        if (len < ilen  || ilen < sizeof(*ofp_i)) {
            c_log_err("[OF13] table-feat parse-err|%llx|",U642ULL(sw->DPID));
            break;
        }

        if (ntohs(ofp_i->type) <= OFPIT_METER) {
            inst_supp_bmask |= (1 << ntohs(ofp_i->type));
        }

        len -= ilen;
        ofp_i = INC_PTR8(ofp_i, ilen); 
    }

    c_switch_tbl_prop_update(sw, table_id, &inst_supp_bmask,
                             miss ? OF_FL_TBL_FEAT_INSTRUCTIONS_MISS :
                             OF_FL_TBL_FEAT_INSTRUCTIONS);
}

static void
of131_proc_tbl_feat_next_tables(c_switch_t *sw, void *prop,
                                uint8_t table_id,
                                bool miss, size_t buf_len)
{
    struct ofp_table_feature_prop_next_tables *ofp_tfn = prop;
    uint8_t *n_tbl;
    uint32_t tbl_supp_bmask[OF_MAX_TABLE_BMASK_SZ];
    size_t len = ntohs(ofp_tfn->length); 
    int loops = 0xff;

    if (len > buf_len || buf_len < sizeof(*ofp_tfn)) {
        c_log_err("[OF13] table-feat next-table len-err");
        return;
    }

    memset(tbl_supp_bmask, 0, sizeof(tbl_supp_bmask));

    len -= sizeof(struct ofp_table_feature_prop_header);
    n_tbl = ofp_tfn->next_table_ids;
    while (loops-- > 0 &&
           len > sizeof(*n_tbl)) {
        SET_BIT_IN_32MASK(tbl_supp_bmask, *n_tbl);
        len -= sizeof(*n_tbl);
        n_tbl = INC_PTR8(n_tbl, sizeof(*n_tbl)); 
    }

    c_switch_tbl_prop_update(sw, table_id, tbl_supp_bmask,
                             miss ? OF_FL_TBL_FEAT_NTABLE_MISS:
                             OF_FL_TBL_FEAT_NTABLE);
}

static void
of131_proc_tbl_feat_actions(c_switch_t *sw, void *prop,
                            uint8_t table_id,
                            bool write, bool miss, size_t buf_len)
{
    struct ofp_table_feature_prop_actions *ofp_tfa = prop;
    struct ofp_action_header *ofp_a = ofp_tfa->action_ids; 
    uint32_t act_supp_bmask = 0;
    size_t len = ntohs(ofp_tfa->length); 
    size_t alen;
    int loops = 32;

    if (len > buf_len || buf_len < sizeof(*ofp_tfa)) {
        c_log_err("[OF13] table-feat actions len-err");
        return;
    }

    len -= sizeof(struct ofp_table_feature_prop_header);
    while (loops-- > 0 && len > OFP_ACT_HDR_SZ) {

        alen = ntohs(ofp_a->len);
        if (alen > len || alen < OFP_ACT_HDR_SZ) {
            c_log_err("[OF13] table feat action error");
            break;
        }

        if (ntohs(ofp_a->type) <= OFPAT131_POP_PBB) {
            act_supp_bmask |= (1 << htons(ofp_a->type));
        }

        len -= alen;
        ofp_a = INC_PTR8(ofp_a, alen); 
    }

    c_switch_tbl_prop_update(sw, table_id, &act_supp_bmask,
                             miss ? (write ? 
                                     OF_FL_TBL_FEAT_WR_ACT_MISS: 
                                     OF_FL_TBL_FEAT_APP_ACT_MISS):
                             (write ?
                              OF_FL_TBL_FEAT_WR_ACT:
                              OF_FL_TBL_FEAT_APP_ACT));
}

static void
of131_proc_tbl_feat_set_field(c_switch_t *sw, void *prop,
                              uint8_t table_id,
                              bool write, bool miss, size_t buf_len)
{
    struct ofp_table_feature_prop_oxm *ofp_tfx = prop;
    struct ofp_oxm_header *ofp_oxm = ASSIGN_PTR(ofp_tfx->oxm_ids); 
    struct ofp_oxm_header oxm;
    uint32_t set_field_bmask[OF_MAX_SET_FIELD_BMASK_SZ];
    size_t len = ntohs(ofp_tfx->length); 
    int loops = 32;
    size_t xlen;

    if (len > buf_len || buf_len < sizeof(*ofp_tfx)) {
        c_log_err("[OF13] table-feat set-field len-err");
        return;
    }

    memset(set_field_bmask, 0, sizeof(set_field_bmask));
    len -= sizeof(struct ofp_table_feature_prop_header);
    while (loops-- > 0  && len > sizeof(oxm)) {

        ASSIGN_OXM_HDR(&oxm, ofp_oxm);
        NTOH_OXM_HDR(&oxm);

        xlen = oxm.length; 
        if (xlen > len || xlen < sizeof(oxm)) {
            c_log_err("[OF13] table feat set-field error");
            break;
        }

        if (OFP_OXM_GHDR_FIELD(&oxm) <= OFPXMT_OFB_IPV6_EXTHDR) {
            SET_BIT_IN_32MASK(set_field_bmask, OFP_OXM_GHDR_FIELD(&oxm));
        }
        len -= xlen;
        ofp_oxm = INC_PTR8(ofp_oxm, xlen); 
    }

    c_switch_tbl_prop_update(sw, table_id, set_field_bmask,
                             miss ? (write ? 
                                     OF_FL_TBL_FEAT_WR_SETF_MISS: 
                                     OF_FL_TBL_FEAT_APP_SETF_MISS):
                             (write ?
                              OF_FL_TBL_FEAT_WR_SETF:
                              OF_FL_TBL_FEAT_APP_SETF));
}

static int
of131_proc_one_tbl_feature(c_switch_t *sw, void *tbf)
{
    struct ofp_table_features *ofp_tbf = tbf;
    struct ofp_table_feature_prop_header *prop = ofp_tbf->properties;
    ssize_t tot_len = ntohs(ofp_tbf->length);
    ssize_t prop_len;
    uint8_t table = ofp_tbf->table_id;
    int loops = OFP_MAX_TABLE_PROPS; 

    while (loops-- > 0 && tot_len >= C_ALIGN_8B_LEN(sizeof(*prop))) {

        prop_len = C_ALIGN_8B_LEN(ntohs(prop->length));
        if (prop_len > tot_len || prop_len < C_ALIGN_8B_LEN(sizeof(*prop))) {
            c_log_err("[OF13] %s:table-feat len error", FN);
            break;
        }

        switch(htons(prop->type)) {
        case OFPTFPT_INSTRUCTIONS:
            of131_proc_tbl_feat_instructions(sw, prop, table, false, tot_len);
            break;
        case OFPTFPT_INSTRUCTIONS_MISS:
            of131_proc_tbl_feat_instructions(sw, prop, table, true, tot_len);
            break;
        case OFPTFPT_NEXT_TABLES:
            of131_proc_tbl_feat_next_tables(sw, prop, table, false, tot_len);
            break; 
        case OFPTFPT_NEXT_TABLES_MISS:
            of131_proc_tbl_feat_next_tables(sw, prop, table, true, tot_len);
            break;
        case OFPTFPT_WRITE_ACTIONS:
            of131_proc_tbl_feat_actions(sw, prop, table, true, false, tot_len);
            break;
        case OFPTFPT_WRITE_ACTIONS_MISS:
            of131_proc_tbl_feat_actions(sw, prop, table, true, true, tot_len);
            break;
        case OFPTFPT_APPLY_ACTIONS:
            of131_proc_tbl_feat_actions(sw, prop, table, false, false, tot_len);
            break;
        case OFPTFPT_APPLY_ACTIONS_MISS:
            of131_proc_tbl_feat_actions(sw, prop, table, false, true, tot_len);
            break;
        case OFPTFPT_WRITE_SETFIELD:
            of131_proc_tbl_feat_set_field(sw, prop, table, true, false, tot_len);
            break;
        case OFPTFPT_WRITE_SETFIELD_MISS:
            of131_proc_tbl_feat_set_field(sw, prop, table, true, true, tot_len);
            break;
        case OFPTFPT_APPLY_SETFIELD:
            of131_proc_tbl_feat_set_field(sw, prop, table, false, false, tot_len);
            break;
        case OFPTFPT_APPLY_SETFIELD_MISS:
            of131_proc_tbl_feat_set_field(sw, prop, table, false, true, tot_len);
            break;
        case OFPTFPT_EXPERIMENTER:
        case OFPTFPT_EXPERIMENTER_MISS:
            break;
        default:
            goto out;
        }

        tot_len -= prop_len;
        prop = INC_PTR8(prop, prop_len);
    }

out:  
    
    return 0;
}

static int
of131_proc_one_flow_stats(c_switch_t *sw, void *ofps)
{
    struct flow flow, mask;
    struct ofp131_flow_stats *ofp_stats = ofps;
    struct ofpx_match *match = &ofp_stats->match;
    uint8_t *inst_list = NULL;
    ssize_t inst_len, match_len;
    uint64_t cookie = ntohll(ofp_stats->cookie);

    match_len = C_ALIGN_8B_LEN(htons(match->length)); /* Aligned match-length */

    inst_list = INC_PTR8(match, match_len);
    inst_len = ntohs(ofp_stats->length) - DIFF_PTR8(inst_list, ofp_stats);

    if (inst_len < 0) {
        if (!c_rlim(&crl))
            c_log_err("[OF13] flow-stats parse-err");
        return -1;
    }

    if (of131_ofpx_match_to_flow(&ofp_stats->match, &flow, &mask)) {
        if (!c_rlim(&crl))
            c_log_err("[OF13] switch|0x%llx|:OXM TLV parse err",
                      U642ULL(sw->DPID));
        return -1;
    }
    flow.table_id = ofp_stats->table_id;
    mask.table_id = 0xff;  /* Inconsequential */

    c_flow_stats_update(sw, &flow, &mask,
                        inst_list, inst_len,
                        htons(ofp_stats->priority), 
                        ntohll(ofp_stats->packet_count),
                        ntohll(ofp_stats->byte_count),
                        ntohl(ofp_stats->duration_sec),
                        ntohl(ofp_stats->duration_nsec),
                        (uint32_t)(cookie),
                        ntohs(ofp_stats->idle_timeout),
                        ntohs(ofp_stats->hard_timeout));
    return inst_len;
}

static int
of131_refresh_ports(c_switch_t *sw)
{
    __of_send_mpart_msg(sw, OFPMP_PORT_DESC, 0, 0);
    return 0;
}

static c_port_t * 
of140_process_port(c_switch_t *sw UNUSED, void *opp_)
{
    const struct ofp140_port *opp;
    c_port_t *port_desc;
    struct ofp_port_desc_prop_ethernet *properties;
    uint16_t rem_len = 0;

    opp = opp_;
    port_desc = calloc(sizeof(c_port_t), 1);
    assert(port_desc);

    port_desc->sw_port.port_no = ntohl(opp->port_no);
    port_config_to_cxlate(&port_desc->sw_port.config, ntohl(opp->config));
    port_status_to_cxlate(&port_desc->sw_port.state, ntohl(opp->state));

    rem_len = opp->length - sizeof(struct ofp140_port);

    if(rem_len <= sizeof(struct ofp_port_desc_prop_ethernet)) {
        c_log_err("[of14] port desc len err");
        free(port_desc);
        return NULL;
    }


    properties = (struct ofp_port_desc_prop_ethernet* )&opp->properties[0];

    port_desc->sw_port.curr = ntohl(properties->curr);
    port_desc->sw_port.advertised = ntohl(properties->advertised);
    port_desc->sw_port.supported = ntohl(properties->supported);
    port_desc->sw_port.peer      = ntohl(properties->peer);
    port_desc->sw_port.of_config = ntohl(opp->config);
    port_desc->sw_port.of_state  = ntohl(opp->state);

    memcpy(port_desc->sw_port.name, opp->name, OFP_MAX_PORT_NAME_LEN);
    port_desc->sw_port.name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
    memcpy(port_desc->sw_port.hw_addr, opp->hw_addr, OFP_ETH_ALEN);

    return port_desc;
}

static void
of140_recv_features_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp140_switch_features  *osf = CBUF_DATA(b);
    struct flow  flow;
    struct flow  mask;
    int tbl = 0;

    memset(&flow, 0, sizeof(flow));
    of_mask_set_dc_all(&mask);

    if (!c_switch_features_check(sw, ntohll(osf->datapath_id))) {
        return;
    }

    c_init_switch_features(sw, ntohll(osf->datapath_id), osf->header.version,
                           osf->n_tables, ntohl(osf->n_buffers), 0,
                           ntohl(osf->capabilities));                           

    c_register_switch(sw, b, false);

    for (tbl = 0; tbl < sw->n_tables; tbl++) {
         flow.table_id = tbl;
         __of_send_flow_del_direct(sw, &flow, &mask, 0,
                                    false, C_FL_PRIO_DFL, OFPG_ANY);
     }

    /* Get all the table features */
    c_switch_tx(sw, of140_prep_mpart_msg(OFPMP_TABLE_FEATURES, 0, 0), false);

    /* Get all the group features */
    c_switch_tx(sw, of140_prep_mpart_msg(OFPMP_GROUP_FEATURES, 0, 0), false);

    /* Get all the meter features */
    c_switch_tx(sw, of140_prep_mpart_msg(OFPMP_METER_FEATURES, 0, 0), false);

    /* There is no port info in features reply. Get it! */
    c_switch_tx(sw, of140_prep_mpart_msg(OFPMP_PORT_DESC, 0, 0), false);

    /* Update gen-id if stale */
    c_switch_tx(sw, of140_prep_role_request_msg(OFPCR_ROLE_NOCHANGE, 0), false); 

    sw->last_feat_probed = time(NULL);
}

struct c_ofp_rx_handler of_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT_HELLO */
    { of10_recv_err_msg, sizeof(struct ofp_error_msg), NULL }, /* OFPT_ERROR */
    { of10_recv_echo_request, OFP_HDR_SZ, NULL }, /* OFPT_ECHO_REQUEST */
    { of10_recv_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT_ECHO_REPLY */
    { of10_recv_vendor_msg, sizeof(struct ofp_vendor_header), NULL}, /* OFPT_VENDOR */
    NULL_OF_HANDLER, /* OFPT_FEATURES_REQUEST */
    { of10_recv_features_reply, OFP_HDR_SZ, NULL },
                     /* OFPT_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT_SET_CONFIG */
    { of10_recv_packet_in, sizeof(struct ofp_packet_in), NULL},
                     /* OFPT_PACKET_IN */
    { of10_flow_removed, sizeof(struct ofp_flow_removed), NULL}, 
                     /* OFPT_FLOW_REMOVED */
    { of10_recv_port_status, sizeof(struct ofp_port_status), NULL },
                     /* OFPT_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT_PACKET_OUT */
    { of10_recv_flow_mod, sizeof(struct ofp_flow_mod), NULL }, /* OFPT_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT_STATS_REQUEST */
    { of10_recv_stats_reply, sizeof(struct ofp_stats_reply), NULL },
                     /* OFPT_STATS_REPLY */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REPLY */
};

struct c_ofp_rx_handler of_boot_handlers[] __aligned = {
    { of_recv_hello, OFP_HDR_SZ, NULL }, /* OFPT_HELLO */
    { of_recv_hello, OFP_HDR_SZ, NULL }, /* OFPT_ERROR */
    NULL_OF_HANDLER, /* OFPT_ECHO_REQUEST */
    { of_recv_hello, OFP_HDR_SZ, NULL }, /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER, /* OFPT_VENDOR */
    NULL_OF_HANDLER, /* OFPT_FEATURES_REQUEST */
    NULL_OF_HANDLER, /* OFPT_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT_SET_CONFIG */
    NULL_OF_HANDLER, /* OFPT_PACKET_IN */
    NULL_OF_HANDLER, /* OFPT_FLOW_REMOVED */
    NULL_OF_HANDLER, /* OFPT_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT_PACKET_OUT */
    NULL_OF_HANDLER, /* OFPT_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT_STATS_REQUEST */
    NULL_OF_HANDLER, /* OFPT_STATS_REPLY */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REPLY */
};

struct c_ofp_rx_handler of_init_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT_HELLO */
    NULL_OF_HANDLER, /* OFPT_ERROR */
    { of_recv_init_echo_request, OFP_HDR_SZ, NULL }, /* OFPT_ECHO_REQUEST */
    { of_recv_init_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER, /* OFPT_VENDOR */
    NULL_OF_HANDLER, /* OFPT_FEATURES_REQUEST */
    { of10_recv_features_reply, OFP_HDR_SZ, NULL },
                     /* OFPT_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT_SET_CONFIG */
    NULL_OF_HANDLER, /* OFPT_PACKET_IN */
    NULL_OF_HANDLER, /* OFPT_FLOW_REMOVED */
    NULL_OF_HANDLER, /* OFPT_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT_PACKET_OUT */
    NULL_OF_HANDLER, /* OFPT_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT_STATS_REQUEST */
    NULL_OF_HANDLER, /* OFPT_STATS_REPLY */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REPLY */
};

struct c_ofp_rx_handler of131_init_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT131_HELLO */
    NULL_OF_HANDLER, /* OFPT131_ERROR */
    { of_recv_init_echo_request, OFP_HDR_SZ, NULL }, /* OFPT_ECHO_REQUEST */
    { of_recv_init_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER, /* OFPT131_EXPERIMENTER */
    NULL_OF_HANDLER, /* OFPT131_FEATURES_REQUEST */
    { of131_recv_features_reply, OFP_HDR_SZ, NULL },
                     /* OFPT131_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT131_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT131_SET_CONFIG */
    NULL_OF_HANDLER, /* OFPT131_PACKET_IN */
    NULL_OF_HANDLER, /* OFPT131_FLOW_REMOVED */
    NULL_OF_HANDLER, /* OFPT131_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT131_PACKET_OUT */
    NULL_OF_HANDLER, /* OFPT131_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT131_GROUP_MOD */
    NULL_OF_HANDLER, /* OFPT131_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT131_TABLE_MOD */
    NULL_OF_HANDLER, /* OFPT131_MULTIPART_REQUEST */
    { of131_recv_mpart_reply, sizeof(struct ofp_multipart_reply), NULL },
                     /* OFPT131_MULTIPART_REPLY */
    NULL_OF_HANDLER, /* OFPT131_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_BARRIER_REPLY */
    NULL_OF_HANDLER, /* OFPT131_QUEUE_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_QUEUE_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT131_ROLE_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_ROLE_REPLY */
    NULL_OF_HANDLER, /* OFPT131_GET_ASYNC_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_GET_ASYNC_REPLY */
    NULL_OF_HANDLER, /* OFPT131_SET_ASYNC */
    NULL_OF_HANDLER, /* OFPT131_METER_MOD */
};

struct c_ofp_rx_handler of131_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT131_HELLO */
    { of131_recv_err_msg, sizeof(struct ofp_error_msg), NULL },
                      /* OFPT131_ERROR */
    { of10_recv_echo_request, OFP_HDR_SZ, NULL },  /* OFPT131_ECHO_REQUEST */
    { of10_recv_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT131_ECHO_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_EXPERIMENTER */
    NULL_OF_HANDLER,  /* OFPT131_FEATURES_REQUEST */
    { of131_recv_features_reply, OFP_HDR_SZ, NULL },
                      /* OFPT131_FEATURES_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_GET_CONFIG_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_SET_CONFIG */
    { of131_recv_packet_in, sizeof(struct ofp131_packet_in), NULL},
                      /* OFPT131_PACKET_IN */
    { of131_flow_removed, sizeof(struct ofp131_flow_removed), NULL},
                      /* OFPT131_FLOW_REMOVED */
    { of131_recv_port_status, sizeof(struct ofp131_port_status), NULL },
                      /* OFPT131_PORT_STATUS */
    NULL_OF_HANDLER,  /* OFPT131_PACKET_OUT */
    { of131_recv_flow_mod, sizeof(struct ofp131_flow_mod), NULL },
                      /* OFPT131_FLOW_MOD */
    NULL_OF_HANDLER,  /* OFPT131_GROUP_MOD */
    NULL_OF_HANDLER,  /* OFPT131_PORT_MOD */
    NULL_OF_HANDLER,  /* OFPT131_TABLE_MOD */
    NULL_OF_HANDLER,  /* OFPT131_MULTIPART_REQUEST */
    { of131_recv_mpart_reply, sizeof(struct ofp_multipart_reply), NULL },
                      /* OFPT131_MULTIPART_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_BARRIER_REQUEST */
    { of131_recv_barrier_reply, OFP_HDR_SZ, NULL }, /* OFPT131_BARRIER_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_QUEUE_GET_CONFIG_REQUEST */
    { of131_recv_q_config_reply, sizeof(struct ofp_queue_get_config_reply) , NULL },  /* OFPT131_QUEUE_GET_CONFIG_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_ROLE_REQUEST */
    { of131_recv_role_reply, sizeof(struct ofp_role_request), NULL },  /* OFPT131_ROLE_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_GET_ASYNC_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_GET_ASYNC_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_SET_ASYNC */
    NULL_OF_HANDLER,  /* OFPT131_METER_MOD */    
};

struct c_ofp_rx_handler of140_init_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT140_HELLO */
    { of131_recv_err_msg, OFP_HDR_SZ, NULL}, /* OFPT140_ERROR */
    { of_recv_init_echo_request, OFP_HDR_SZ, NULL }, /* OFPT_ECHO_REQUEST */
    { of_recv_init_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER, /* OFPT140_EXPERIMENTER */
    NULL_OF_HANDLER, /* OFPT140_FEATURES_REQUEST */
    { of140_recv_features_reply, OFP_HDR_SZ, NULL },
                     /* OFPT140_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT140_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT140_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT140_SET_CONFIG */
    NULL_OF_HANDLER, /* OFPT140_PACKET_IN */
    NULL_OF_HANDLER, /* OFPT140_FLOW_REMOVED */
    NULL_OF_HANDLER, /* OFPT140_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT140_PACKET_OUT */
    NULL_OF_HANDLER, /* OFPT140_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT140_GROUP_MOD */
    NULL_OF_HANDLER, /* OFPT140_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT140_TABLE_MOD */
    NULL_OF_HANDLER, /* OFPT140_MULTIPART_REQUEST */
    { of131_recv_mpart_reply, sizeof(struct ofp_multipart_reply), NULL },
                     /* OFPT140_MULTIPART_REPLY */
    NULL_OF_HANDLER, /* OFPT140_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT140_BARRIER_REPLY */
    NULL_OF_HANDLER, /* OFPT140_QUEUE_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT140_QUEUE_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT140_ROLE_REQUEST */
    NULL_OF_HANDLER, /* OFPT140_ROLE_REPLY */
    NULL_OF_HANDLER, /* OFPT140_GET_ASYNC_REQUEST */
    NULL_OF_HANDLER, /* OFPT140_GET_ASYNC_REPLY */
    NULL_OF_HANDLER, /* OFPT140_SET_ASYNC */
    NULL_OF_HANDLER, /* OFPT140_METER_MOD */
};

struct c_ofp_rx_handler of140_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT131_HELLO */
    { of131_recv_err_msg, sizeof(struct ofp_error_msg), NULL },
                      /* OFPT131_ERROR */
    { of10_recv_echo_request, OFP_HDR_SZ, NULL },  /* OFPT140_ECHO_REQUEST */
    { of10_recv_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT140_ECHO_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_EXPERIMENTER */
    NULL_OF_HANDLER,  /* OFPT131_FEATURES_REQUEST */
    { of140_recv_features_reply, OFP_HDR_SZ, NULL },
                      /* OFPT131_FEATURES_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_GET_CONFIG_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_SET_CONFIG */
    { of131_recv_packet_in, sizeof(struct ofp131_packet_in), NULL},
                      /* OFPT131_PACKET_IN */
    { of131_flow_removed, sizeof(struct ofp131_flow_removed), NULL},
                      /* OFPT131_FLOW_REMOVED */
    { of131_recv_port_status, sizeof(struct ofp131_port_status), NULL },
                      /* OFPT131_PORT_STATUS */
    NULL_OF_HANDLER,  /* OFPT131_PACKET_OUT */
    { of131_recv_flow_mod, sizeof(struct ofp131_flow_mod), NULL },
                      /* OFPT131_FLOW_MOD */
    NULL_OF_HANDLER,  /* OFPT131_GROUP_MOD */
    NULL_OF_HANDLER,  /* OFPT131_PORT_MOD */
    NULL_OF_HANDLER,  /* OFPT131_TABLE_MOD */
    NULL_OF_HANDLER,  /* OFPT131_MULTIPART_REQUEST */
    { of131_recv_mpart_reply, sizeof(struct ofp_multipart_reply), NULL },
                      /* OFPT131_MULTIPART_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_BARRIER_REQUEST */
    { of131_recv_barrier_reply, OFP_HDR_SZ, NULL }, /* OFPT131_BARRIER_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_QUEUE_GET_CONFIG_REQUEST */
    { of131_recv_q_config_reply, sizeof(struct ofp_queue_get_config_reply) , NULL },  /* OFPT131_QUEUE_GET_CONFIG_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_ROLE_REQUEST */
    { of131_recv_role_reply, sizeof(struct ofp_role_request), NULL },  /* OFPT131_ROLE_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_GET_ASYNC_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_GET_ASYNC_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_SET_ASYNC */
    NULL_OF_HANDLER,  /* OFPT131_METER_MOD */    
};

struct c_ofp_proc_helpers ofp_priv_procs __aligned = {
    .xlate_port_desc = of10_process_phy_port,
    .mk_ofp_features = c_switch_mk_ofp1_0_features,
    .proc_one_flow_stats = of10_proc_one_flow_stats,
    .proc_one_port_stats = of10_proc_one_port_stats,
    .refresh_ports = of10_refresh_ports
};

struct c_ofp_proc_helpers ofp131_priv_procs __aligned = {
    .xlate_port_desc = of131_process_port,
    .mk_ofp_features =  NULL, /* TODO */
    .proc_one_flow_stats = of131_proc_one_flow_stats, 
    .proc_one_tbl_feature = of131_proc_one_tbl_feature,
    .refresh_ports = of131_refresh_ports
};

struct c_ofp_proc_helpers ofp140_priv_procs __aligned = {
    .xlate_port_desc = of140_process_port,
    .mk_ofp_features =  NULL, /* TODO */
    .proc_one_flow_stats = of131_proc_one_flow_stats, 
    .proc_one_tbl_feature = of131_proc_one_tbl_feature,
    .refresh_ports = of131_refresh_ports
};

void __fastpath
c_switch_recv_msg(void *sw_arg, struct cbuf *b)
{
    c_switch_t *sw = sw_arg;
    struct ofp_header *oh;
    c_ofp_rx_handler_t *rx_handlers;
    uint8_t of_type;

    prefetch(&of_handlers[OFPT_PACKET_IN]);

    oh = (void *)b->data;
    of_type = oh->type;

    if (sw->rx_dump_en && sw->ofp_ctors->dump_of_msg) {
        sw->ofp_ctors->dump_of_msg(b, false, sw->DPID);
    }

    sw->last_refresh_time = time(NULL);
    sw->conn.rx_pkts++;

    rx_handlers = sw->ofp_rx_handlers;
    if (unlikely(of_type > sw->ofp_rx_handler_sz ||
                 !rx_handlers[of_type].handler) ||
                 b->len < rx_handlers[of_type].min_size ||
                 ((sw->switch_state & SW_REGISTERED) &&
                 (oh->version != sw->version))) {
        if (!c_rlim(&crl)) {
            c_log_err("[I/O] Bad OF message |%d| Len|%d:%d|",
                      of_type, (int)(b->len),
                      (int)(rx_handlers[of_type].min_size));
        }
        return;
    }

    rx_handlers[of_type].handler(sw, (void *)b);

#ifdef C_VIRT_CON_HA
    if (rx_handlers[of_type].ha_handler) {
        rx_handlers[of_type].ha_handler(sw, (void *)b); 
    }
#endif
}
