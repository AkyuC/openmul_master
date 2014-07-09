/*
 *  mul_app_infra.c: MUL application infrastructre 
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
#include "mul_common.h"
#include "mul_app_main.h"
#include "mul_app_infra.h"
#include "mul_services.h"

static c_app_hdl_t *hdl = NULL;
extern struct mul_app_client_cb *app_cbs;
extern struct c_app_service c_app_service_tbl[MUL_MAX_SERVICE_NUM];

int c_app_switch_add(c_app_hdl_t *hdl, c_ofp_switch_add_t *cofp_sa);
void c_app_switch_del(c_app_hdl_t *hdl, c_ofp_switch_delete_t *cofp_sa);
void c_switch_port_status(c_app_hdl_t *hdl, c_ofp_port_status_t *ofp_psts);
void c_app_packet_in(c_app_hdl_t *hdl, c_ofp_packet_in_t *ofp_pin);
void c_controller_reconn(c_app_hdl_t *hdl);
void c_app_notify_ha_event(c_app_hdl_t *hdl, uint32_t ha_sysid, uint32_t ha_state);
void c_controller_disconn(c_app_hdl_t *hdl);
void c_app_vendor_msg(c_app_hdl_t *hdl UNUSED, c_ofp_vendor_msg_t *ofp_vm);
int c_app_infra_init(c_app_hdl_t *hdl);
void c_app_infra_vty_init(void *hdl);
static void __c_app_traverse_all_switches(GHFunc iter_fn, void *arg);
static void c_app_traverse_switch_ports(mul_switch_t *sw,
                                        GFunc iter_fn, void *arg);

static struct c_ofp_ctors of10_ctors = {
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
};

static struct c_ofp_ctors of131_ctors = {
    .group_validate = of131_group_validate_parms,
    .group_add = of131_prep_group_add_msg,
    .group_del = of131_prep_group_del_msg,
    .set_act_inst = of131_set_inst_action_type,
    .inst_goto = of131_make_inst_goto,
    .inst_meter = of131_make_inst_meter,
    .act_output = of131_make_action_output,
    .act_set_vid = of131_make_action_set_vid,
    .act_strip_vid = of131_make_action_strip_vlan,
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
    .act_set_nw_saddr6 = of131_make_action_set_ipv6_src,
    .act_set_nw_daddr6 = of131_make_action_set_ipv6_dst,
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
    .multi_table_support = of131_supports_multi_tables
};

static struct c_ofp_ctors of140_ctors = {
    .group_validate = of131_group_validate_parms,
    .group_add = of131_prep_group_add_msg,
    .group_del = of131_prep_group_del_msg,
    .set_act_inst = of131_set_inst_action_type,
    .inst_goto = of131_make_inst_goto,
    .inst_meter = of131_make_inst_meter,
    .act_output = of131_make_action_output,
    .act_set_vid = of131_make_action_set_vid,
    .act_strip_vid = of131_make_action_strip_vlan,
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
    .act_set_nw_saddr6 = of131_make_action_set_ipv6_src,
    .act_set_nw_daddr6 = of131_make_action_set_ipv6_dst,
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
    .multi_table_support = of131_supports_multi_tables
};

static void
c_app_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

int
mul_app_command_handler(void *app_name UNUSED, void *b)
{
    c_conn_tx(&hdl->conn, (struct cbuf *)(b),
              c_app_write_event_sched);
    return 0;
}

static void
c_app_port_slist_ent_free(void *arg)
{
    mul_port_t *port = arg;

    if (app_cbs && app_cbs->switch_priv_port_free &&
        port->priv) {
        app_cbs->switch_priv_port_free(port->priv);
    }

    free(arg);
}

static inline void
c_app_switch_get(mul_switch_t *sw)
{
    atomic_inc(&sw->ref, 1);
}

mul_switch_t * 
c_app_switch_get_with_id(uint64_t dpid)
{
    mul_switch_t *sw = NULL;

    c_rd_lock(&hdl->infra_lock);
    if (!(sw = g_hash_table_lookup(hdl->switches, &dpid))) {
        c_rd_unlock(&hdl->infra_lock);
        c_log_err("[infra] unknown switch (0x%llx)",
                  (unsigned long long)dpid);
        return NULL;
    }

    atomic_inc(&sw->ref, 1);
    c_rd_unlock(&hdl->infra_lock);
    return sw;
}

static mul_switch_t * 
__c_app_switch_get_with_id(uint64_t dpid)
{
    mul_switch_t *sw = NULL;

    if (!(sw = g_hash_table_lookup(hdl->switches, &dpid))) {
        c_log_err("[infra] sw(0x%llx) doesnt exist", (unsigned long long)dpid);
        return NULL;
    }

    atomic_inc(&sw->ref, 1);
    return sw;
}

static void
c_switch_free(mul_switch_t *sw)
{
    if (app_cbs && app_cbs->switch_priv_free &&
        sw->priv) {
        app_cbs->switch_priv_free(sw->priv);
    }
    c_rw_lock_destroy(&sw->lock);
    free(sw);
}

void
c_app_switch_put(mul_switch_t *sw)
{
    if (atomic_read(&sw->ref) == 0){
        if (sw->port_list) g_slist_free_full(sw->port_list, 
                                             c_app_port_slist_ent_free);
        sw->port_list = NULL;
        c_switch_free(sw);
    } else {
        atomic_dec(&sw->ref, 1);
    }
}

static void
c_app_sw_free(void *arg)
{
    c_app_switch_put((mul_switch_t *)arg);
}

uint8_t
c_app_switch_get_version_with_id(uint64_t dpid)
{
    mul_switch_t *sw = NULL;
    uint8_t ver;

    c_rd_lock(&hdl->infra_lock);
    if (!(sw = g_hash_table_lookup(hdl->switches, &dpid))) {
        c_rd_unlock(&hdl->infra_lock);
        c_log_err("[infra] Unknown switch-id (0x%llx)",
                  (unsigned long long)dpid);
        return 0;
    }

    ver = sw->ofp_ver;
    c_rd_unlock(&hdl->infra_lock);
    return ver;
}

void
c_app_traverse_all_switches(GHFunc iter_fn, void *arg)
{
    c_rd_lock(&hdl->infra_lock);
    if (hdl->switches) {
        g_hash_table_foreach(hdl->switches,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&hdl->infra_lock);

    return;
}

static void UNUSED
__c_app_traverse_all_switches(GHFunc iter_fn, void *arg)
{
    if (hdl->switches) {
        g_hash_table_foreach(hdl->switches, (GHFunc)iter_fn, arg);
    }

    return;
}

static void
c_app_traverse_switch_ports(mul_switch_t *sw, 
                            GFunc iter_fn, void *arg)
{
    c_rd_lock(&sw->lock);
    if (sw->port_list) {
        g_slist_foreach(sw->port_list,
                        (GFunc)iter_fn, arg);
    }
    c_rd_unlock(&sw->lock);

    return;
}

static mul_switch_t *
mul_switch_alloc(void)
{
    mul_switch_t *sw = calloc(sizeof(*sw), 1);

    c_rw_lock_init(&sw->lock);
    if (app_cbs && app_cbs->switch_priv_alloc) {
        app_cbs->switch_priv_alloc(&sw->priv);
    }
    return sw;
}

static int
mul_app_port_equal(const void *p1, const void *p2)
{
    return !(((mul_port_t *)p1)->port_no == *(uint16_t *)(p2));
}

static mul_port_t *
__mul_app_switch_port_find(mul_switch_t *sw, uint16_t port_no)
{
    GSList *iterator;
    mul_port_t *port = NULL;

    iterator = g_slist_find_custom(sw->port_list, &port_no, mul_app_port_equal);
    if (iterator) {
        port = iterator->data;
    }

    return port;
}

static int
__mul_app_switch_port_add(mul_switch_t *sw, mul_port_t *port)
{
    if (!__mul_app_switch_port_find(sw, port->port_no)) {
        sw->port_list = g_slist_append(sw->port_list, port);
    } else {
        c_log_err("[infra] port_no (%u) exists", port->port_no);
        return -1;
    }
    return 0;
}

static void
__mul_app_switch_port_del(mul_switch_t *sw, mul_port_t *port)
{
    sw->port_list = g_slist_remove(sw->port_list, port);
}

int
c_app_switch_add(c_app_hdl_t *hdl, c_ofp_switch_add_t *cofp_sa)
{
    uint64_t dpid = ntohll(cofp_sa->datapath_id);
    uint32_t n_ports, idx = 0;
    mul_switch_t *sw = mul_switch_alloc();

    c_log_debug("[infra] switch 0x%llx add", U642ULL(dpid));
    n_ports =  ((ntohs(cofp_sa->header.length)
                - offsetof(c_ofp_switch_add_t, ports))
               / sizeof *cofp_sa->ports);

    c_rw_lock_init(&sw->lock);
    sw->dpid = dpid;
    sw->alias_id = (int)(ntohl(cofp_sa->sw_alias));
    sw->hdl = hdl;
    sw->ofp_ver = cofp_sa->header.version;

    c_wr_lock(&hdl->infra_lock);
    if (g_hash_table_lookup(hdl->switches, &dpid)) {
        c_wr_unlock(&hdl->infra_lock);
        c_switch_free(sw);
        c_log_err("[infra] switch 0x%llx exists", (unsigned long long)dpid);
        return -1;
    } 

    c_app_switch_get(sw);
    g_hash_table_insert(hdl->switches, &sw->dpid, sw);
    c_wr_unlock(&hdl->infra_lock);

    if (app_cbs && app_cbs->switch_add_cb) {
        app_cbs->switch_add_cb(sw);
    }

    c_wr_lock(&sw->lock);
    for (; idx < n_ports; idx++) {
        struct c_sw_port *opp = (void *)(&cofp_sa->ports[idx]);
        mul_port_t *port = calloc(1, sizeof(mul_port_t));

        port->port_no = ntohl(opp->port_no);
        port->state = ntohl(opp->state);
        port->config = ntohl(opp->config);
        port->owner = sw;
        memcpy(port->hw_addr, opp->hw_addr, OFP_ETH_ALEN);
        // c_app_switch_get(sw);
        __mul_app_switch_port_add(sw, port);
        if (app_cbs && app_cbs->switch_port_add_cb) {
            app_cbs->switch_port_add_cb(sw, port);
        }
    }
    c_wr_unlock(&sw->lock);
    c_app_switch_put(sw);

    return 0;
}

static void 
mul_app_swports_del_notify(void *port_arg, void *uarg UNUSED)
{
    mul_port_t *port = port_arg;

    if (app_cbs && app_cbs->switch_port_del_cb) {
        app_cbs->switch_port_del_cb(port->owner, port);
    }
}

void
c_app_switch_del(c_app_hdl_t *hdl, c_ofp_switch_delete_t *cofp_sa)
{
    mul_switch_t *sw;
    uint64_t dpid = ntohll(cofp_sa->datapath_id);

    c_log_err("[infra] switch 0x%llx del", U642ULL(dpid));
    c_wr_lock(&hdl->infra_lock);
    sw = __c_app_switch_get_with_id(dpid);
    if (!sw) {
        c_log_err("[infra] switch 0x%llx not found", (unsigned long long)dpid);
        c_wr_unlock(&hdl->infra_lock);
        return;
    }
    c_app_traverse_switch_ports(sw, mul_app_swports_del_notify, NULL);
    if (app_cbs && app_cbs->switch_del_cb) {
        app_cbs->switch_del_cb(sw);
    }
    c_app_switch_put(sw);
    g_hash_table_remove(hdl->switches, &dpid); /* c_app_sw_free() */
    c_wr_unlock(&hdl->infra_lock);
}

void
c_switch_port_status(c_app_hdl_t *hdl UNUSED,
                     c_ofp_port_status_t *ofp_psts)
{
    uint32_t in_port = 0;
    uint32_t config_mask, state_mask;
    struct c_sw_port *ofpp = &ofp_psts->desc;
    mul_switch_t *sw = NULL;   
    mul_port_t *port = NULL;
    bool port_exists = false;

    config_mask = ntohl(ofp_psts->config_mask);
    state_mask  = ntohl(ofp_psts->state_mask);
    in_port     = ntohl(ofp_psts->desc.port_no);

    if (!(sw = c_app_switch_get_with_id(ntohll(ofp_psts->datapath_id)))) {
        c_log_err("[infra] switch 0x%llx not found", 
                  (unsigned long long)ntohll(ofp_psts->datapath_id));
        return;
    }

    c_wr_lock(&sw->lock);
    
    port = __mul_app_switch_port_find(sw, in_port); 
    switch(ofp_psts->reason) {
    case OFPPR_ADD:
        if (!port) {
            port = calloc(1, sizeof(*port));
            port->port_no = in_port;
            port->owner = sw;
            __mul_app_switch_port_add(sw, port);
        } else {
            port->port_no = in_port;
            port_exists = true;
        }
        /* Fall through */
    case OFPPR_MODIFY:
        if (port) {
            port->state = ntohl(ofpp->state);
            port->config = ntohl(ofpp->config);
            memcpy(port->hw_addr, ofpp->hw_addr, OFP_ETH_ALEN);
        }

        if (ofp_psts->reason == OFPPR_ADD) { 
            if (!port_exists && 
                app_cbs && app_cbs->switch_port_add_cb) {
                app_cbs->switch_port_add_cb(sw, port);
            }
        } else { /* OFPPR_MODIFY */
            if (app_cbs && app_cbs->switch_port_chg) {
                app_cbs->switch_port_chg(sw, port,
                           port->config & OFPPC_PORT_DOWN ? false : true,
                           port->state & OFPPS_LINK_DOWN ? false : true); 
                break;
            }
            if (config_mask & OFPPC_PORT_DOWN && app_cbs &&
                app_cbs->switch_port_adm_chg) {
                app_cbs->switch_port_adm_chg(sw, port, 
                                port->config & OFPPC_PORT_DOWN ? false : true);
            } else if (state_mask & OFPPS_LINK_DOWN && app_cbs && 
                       app_cbs->switch_port_link_chg) {
                app_cbs->switch_port_link_chg(sw, port,
                                port->state & OFPPS_LINK_DOWN ? false : true);
            } 
        }
        break;
    case OFPPR_DELETE:
        if (port) {
            if (app_cbs && app_cbs->switch_port_del_cb) {
                app_cbs->switch_port_del_cb(sw, port);    
            }
            __mul_app_switch_port_del(sw, port);
        }
        break;
    default:
        c_log_err("[infra] unknown port change code");
        return;
    }

    c_wr_unlock(&sw->lock);

    c_app_switch_put(sw);
}

void
c_app_packet_in(c_app_hdl_t *hdl UNUSED, c_ofp_packet_in_t *ofp_pin)
{
    mul_switch_t *sw;
    size_t pkt_len, pkt_ofs;


    if (!(sw = c_app_switch_get_with_id(ntohll(ofp_pin->datapath_id)))) {
        /* FIXME : Ratelimit this */
        c_log_err("[infra] |pkt-in| switch not found");
        return;
    }

    pkt_ofs = offsetof(struct c_ofp_packet_in, data);
    pkt_len = ntohs(ofp_pin->header.length) - pkt_ofs;

    if (app_cbs && app_cbs->switch_packet_in) {
        app_cbs->switch_packet_in(sw, &ofp_pin->fl, ntohl(ofp_pin->fl.in_port),
                                  ntohl(ofp_pin->buffer_id), ofp_pin->data,
                                  pkt_len);
    }

    c_app_switch_put(sw);
}

void
c_app_vendor_msg(c_app_hdl_t *hdl UNUSED, c_ofp_vendor_msg_t *ofp_vm)
{
    mul_switch_t *sw; 
    size_t pkt_ofs, pkt_len;

    if (!(sw = c_app_switch_get_with_id(ntohll(ofp_vm->datapath_id)))) {
        /* FIXME : Ratelimit this */
        c_log_err("[infra] |vendor-msg| switch not found");
        return;
    }

    pkt_ofs = sizeof(struct ofp_vendor_header);
    pkt_len = ntohs(ofp_vm->header.length) - pkt_ofs;

    if (app_cbs && app_cbs->process_vendor_msg_cb) {
        app_cbs->process_vendor_msg_cb(sw,ofp_vm->data,pkt_len);
    }
}

static void
c_app_switch_del_notify(void *key UNUSED, void *sw_arg, void *uarg UNUSED)
{
    mul_switch_t *sw = sw_arg;
    c_app_traverse_switch_ports(sw, mul_app_swports_del_notify, NULL);
    if (app_cbs && app_cbs->switch_del_cb) {
        app_cbs->switch_del_cb(sw);
    }
}

void
c_controller_disconn(c_app_hdl_t *hdl)
{
    c_app_traverse_all_switches(c_app_switch_del_notify, NULL);
    g_hash_table_remove_all(hdl->switches);
    if (app_cbs && app_cbs->core_conn_closed) {
        app_cbs->core_conn_closed();
    }
}

void
c_controller_reconn(c_app_hdl_t *hdl UNUSED)
{
    if (app_cbs && app_cbs->core_conn_reconn) {
        app_cbs->core_conn_reconn();
    }
}

void
c_app_notify_ha_event(c_app_hdl_t *hdl UNUSED, uint32_t ha_sysid, uint32_t ha_state)
{
    if (app_cbs && app_cbs->app_ha_state) {
        app_cbs->app_ha_state(ha_sysid, ha_state);
    }
}

int
c_app_infra_init(c_app_hdl_t *app_hdl)
{
    hdl = app_hdl;
    c_rw_lock_init(&hdl->infra_lock);
    hdl->switches = g_hash_table_new_full(g_int64_hash,
                                           g_int64_equal,
                                           NULL, c_app_sw_free);
    return 0;
}

void
mul_app_free_buf(void *b UNUSED)
{
    /* Nothing to do */
    return;
}

static int
_commom_reg_app(void *app_arg UNUSED, char *app_name, uint32_t app_flags,
                uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                void  (*ev_cb)(void *app_arg, void *pkt_arg),
                struct mul_app_client_cb *client_app_cbs)
{
    uint64_t *p_dpid = NULL;
    struct cbuf *b;
    c_ofp_register_app_t *reg_app;
    int idx = 0;

#ifdef APP_HA
    struct c_app_service *serv;
    size_t serv_sz = sizeof(c_app_service_tbl)/sizeof(c_app_service_tbl[0]);
    for (; idx < serv_sz; idx++) {
        serv = &c_app_service_tbl[idx];
        if (!strncmp(serv->app_name, app_name, MAX_SERV_NAME_LEN-1)) {
            if (hdl->ha_server) {
                if (hdl->ha_service) {
                    mul_service_destroy(hdl->ha_service);
                }

                hdl->ha_service = mul_app_get_service_notify(
                                                serv->service_name,
                                                c_service_conn_update,
                                                true, hdl->ha_server);
                assert(hdl->ha_service);
                hdl->peer_mini_state = C_HA_STATE_CONNECTED;
            }
        }
    }
#endif

    b = of_prep_msg(sizeof(struct c_ofp_register_app) +
                    (n_dpid * sizeof(uint64_t)), C_OFPT_REG_APP, 0);

    reg_app = (void *)(b->data);
    strncpy(reg_app->app_name, app_name, C_MAX_APP_STRLEN-1);
    reg_app->app_flags = htonl(app_flags);
    reg_app->ev_mask = htonl(ev_mask);
    reg_app->dpid = htonl(n_dpid);

    p_dpid = (void *)(reg_app+1);
    for (idx = 0; idx < n_dpid; idx++) {
        *p_dpid++ = *dpid_list++;
    }

    if (client_app_cbs) {
        if (!app_cbs) {
            app_cbs = client_app_cbs;
        }
    } else {
        hdl->ev_cb = ev_cb;
        app_cbs = NULL;
    }

    c_conn_tx(&hdl->conn, b, c_app_write_event_sched);

    return 0;
}

int
mul_register_app(void *app_arg, char *app_name, uint32_t app_flags,
                 uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                 void  (*ev_cb)(void *app_arg, void *pkt_arg))
{
    return _commom_reg_app(app_arg, app_name, app_flags, ev_mask, n_dpid, 
                           dpid_list, ev_cb, NULL);
}

#ifdef MUL_APP_V2_MLAPI
int
mul_register_app_cb(void *app_arg, char *app_name, uint32_t app_flags,
        uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
        struct mul_app_client_cb *app_cbs)
{
    FILE *fp;
    char dpid_str[DPID_CHAR_SZ];
    uint64_t dpid = 0;
    char c;
    uint64_t new_dpid_list[MAX_NUMBER_DPID];
    uint8_t num_dpid = 0;
    assert(app_cbs);

    if(strcmp(hdl->dpid_file,"\0")) {
        fp = fopen(hdl->dpid_file,"r");
        c_log_debug("Reading DPIDs from %s",hdl->dpid_file);
        if( fp == NULL) {
            perror("Error while opening the file");
        }
        else {

            do {
                c = fscanf(fp,"%s",dpid_str); /* got one dpid from the file */
                if(c != EOF) {
                    dpid = strtoull(dpid_str, NULL, 16);
                    if (dpid == ULONG_MAX && errno == ERANGE) {
                        c_log_err("%s: Incorrect DPID format - %s", FN,
                                dpid_str);
                        continue;
                    }

                    new_dpid_list[num_dpid] = dpid;
                    num_dpid++;
                }
                /* Repeat until EOF character or maximum limit of DPIDs is
                 * achieved */
            } while (c != EOF && num_dpid < MAX_NUMBER_DPID); 
            dpid_list = new_dpid_list;
            n_dpid = num_dpid;
            app_flags = 0;
        }
    }
    return _commom_reg_app(app_arg, app_name, app_flags, ev_mask, n_dpid,
                           dpid_list, NULL, app_cbs);
}
#endif

int
mul_unregister_app(char *app_name)
{
    struct cbuf *b;
    c_ofp_unregister_app_t *unreg_app;

    b = of_prep_msg(sizeof(*unreg_app), C_OFPT_UNREG_APP, 0);
    unreg_app = (void *)(b->data);
    strncpy(unreg_app->app_name, app_name, C_MAX_APP_STRLEN-1);
    c_conn_tx(&hdl->conn, b, c_app_write_event_sched);

    return 0;
}

void
mul_app_send_pkt_out(void *arg UNUSED, uint64_t dpid, void *parms_arg)
{
    struct of_pkt_out_params *parms = parms_arg;
    void *out_data;
    struct cbuf *b;
    uint8_t *act;
    struct c_ofp_packet_out *cofp_po;

    b = of_prep_msg(sizeof(*cofp_po) + parms->action_len + parms->data_len,
                    OFPT_PACKET_OUT, 0);

    cofp_po = (void *)(b->data);
    cofp_po->datapath_id = htonll(dpid);
    cofp_po->in_port = htonl(parms->in_port);
    cofp_po->buffer_id = htonl(parms->buffer_id);
    cofp_po->actions_len = htons(parms->action_len);

    act = (void *)(cofp_po+1);
    memcpy(act, parms->action_list, parms->action_len);

    if (parms->data_len) {
        out_data = (void *)(act + parms->action_len);
        memcpy(out_data, parms->data, parms->data_len);
    }

    mul_app_command_handler(NULL, b);

    return;
}

static struct cbuf *
mul_app_prep_flow_add(uint64_t dpid, struct flow *fl, struct flow *mask,
                      uint32_t buffer_id, void *actions, size_t action_len,
                      uint16_t itimeo, uint16_t htimeo, uint16_t prio,
                      uint64_t flags)
{
    c_ofp_flow_mod_t *cofp_fm;
    void *act;
    struct cbuf *b;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_fm) + action_len;

    b = of_prep_msg(tot_len, C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    if (flags & C_FL_ENT_SWALIAS) {
        cofp_fm->sw_alias = htonl((uint32_t)dpid);
    } else {
        cofp_fm->datapath_id = htonll(dpid);
    }
    cofp_fm->command = C_OFPC_ADD;
    cofp_fm->flags = htonll(flags);
    memcpy(&cofp_fm->flow, fl, sizeof(*fl));
    memcpy(&cofp_fm->mask, mask, sizeof(*mask));
    cofp_fm->wildcards = 0;
    cofp_fm->priority = htons(prio);
    cofp_fm->itimeo = htons(itimeo);
    cofp_fm->htimeo = htons(htimeo);
    cofp_fm->buffer_id = htonl(buffer_id);
    cofp_fm->oport = OF_NO_PORT;

    act = ASSIGN_PTR(cofp_fm->actions);
    memcpy(act, actions, action_len);

    return b;
}

int
mul_app_send_flow_add(void *app_name UNUSED, void *sw_arg UNUSED,
                      uint64_t dpid, struct flow *fl, struct flow *mask,
                      uint32_t buffer_id, void *actions, size_t action_len,
                      uint16_t itimeo, uint16_t htimeo, uint16_t prio,
                      uint64_t flags)
{
    struct cbuf *b;

    b = mul_app_prep_flow_add(dpid, fl, mask, buffer_id, actions, action_len,
                              itimeo, htimeo, prio, flags);
    mul_app_command_handler(NULL, b);

    return 0;
}

int
mul_service_send_flow_add(void *service,
                          uint64_t dpid, struct flow *fl, struct flow *mask,
                          uint32_t buffer_id, void *actions, size_t action_len,
                          uint16_t itimeo,  uint16_t htimeo, uint16_t prio,
                          uint64_t flags)
{
    struct cbuf *b;

    b = mul_app_prep_flow_add(dpid, fl, mask, buffer_id, actions, action_len,
                              itimeo, htimeo, prio, flags);
    c_service_send(service, b);

    return 0;
}

static struct cbuf *
mul_app_prep_flow_del(uint64_t dpid, struct flow *fl,
                      struct flow *mask, uint32_t oport,
                      uint16_t prio, uint64_t flags,
                      uint32_t ogroup)
{
    c_ofp_flow_mod_t *cofp_fm;
    struct cbuf *b;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_fm);

    b = of_prep_msg(tot_len, C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    if (flags & C_FL_ENT_SWALIAS) {
        cofp_fm->sw_alias = htonl((uint32_t)dpid);
    } else {
        cofp_fm->datapath_id = htonll(dpid);
    }
    cofp_fm->command = C_OFPC_DEL;
    cofp_fm->priority = htons(prio);
    cofp_fm->flags = htonll(flags);
    memcpy(&cofp_fm->flow, fl, sizeof(*fl));
    memcpy(&cofp_fm->mask, mask, sizeof(*fl));

    cofp_fm->oport = htonl(oport);
    cofp_fm->ogroup = htonl(ogroup);

    return b;
}

int
mul_app_send_flow_del(void *app_name UNUSED, void *sw_arg UNUSED,
                      uint64_t dpid, struct flow *fl,
                      struct flow *mask, uint32_t oport,
                      uint16_t prio, uint64_t flags, uint32_t ogroup)
{
    struct cbuf *b;

    b = mul_app_prep_flow_del(dpid, fl, mask, oport, prio, flags, 
                              ogroup);
    mul_app_command_handler(NULL, b);
    return 0;
}

int
mul_service_send_flow_del(void *service,
                      uint64_t dpid, struct flow *fl,
                      struct flow *mask, uint32_t oport,
                      uint16_t prio, uint64_t flags,
                      uint32_t ogroup)
{
    struct cbuf *b;

    b = mul_app_prep_flow_del(dpid, fl, mask, oport, prio, flags, ogroup);
    c_service_send(service, b);
    return 0;
}

static struct cbuf *
mul_app_prep_meter_add(uint64_t dpid, struct of_meter_mod_params *m_parms)
{
    struct cbuf *b;
    struct c_ofp_meter_mod *cofp_mm;
    int act = 0;
    size_t tot_len = 0;
    struct of_meter_band_elem *band_elem;
    struct ofp_meter_band_header *band;

    for (; act < m_parms->meter_nbands; act++) {
        band_elem = m_parms->meter_bands[act];
        if (band_elem)
            tot_len += band_elem->band_len;
    }
    tot_len += sizeof(*cofp_mm);
    
	b = of_prep_msg(tot_len, C_OFPT_METER_MOD, 0);
    cofp_mm = CBUF_DATA(b);

    cofp_mm->datapath_id = htonll(dpid);
    cofp_mm->command = C_OFPMC_ADD;
    cofp_mm->meter_id = htonl(m_parms->meter);
    cofp_mm->flags = htons(m_parms->flags);
    cofp_mm->c_flags = m_parms->cflags;
    
	tot_len = sizeof(*cofp_mm);
    for (act = 0; act < m_parms->meter_nbands; act++) {
        band = INC_PTR8(cofp_mm, tot_len);
        band_elem = m_parms->meter_bands[act];

        if (band_elem) {
            memcpy(band, band_elem->band, band_elem->band_len);
            band->len = htons(band_elem->band_len);
            tot_len += band_elem->band_len;
        }
    }
    return b;
}

static struct cbuf *
mul_app_prep_meter_del(uint64_t dpid, struct of_meter_mod_params *m_parms)
{
    struct cbuf *b;
    struct c_ofp_meter_mod *cofp_mm;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_mm);

    b = of_prep_msg(tot_len, C_OFPT_METER_MOD, 0);
    cofp_mm = CBUF_DATA(b);

    cofp_mm->datapath_id = htonll(dpid);
    cofp_mm->command = C_OFPMC_DEL;
    cofp_mm->meter_id = htonl(m_parms->meter);
    cofp_mm->c_flags = m_parms->cflags;

    return b;
}

static struct cbuf *
mul_app_prep_port_mod(uint64_t dpid, struct of_port_mod_params *pm_parms)
{
    struct cbuf *b;
    struct c_ofp_port_mod *cofp_pm;

    b = of_prep_msg(sizeof(struct c_ofp_port_mod), C_OFPT_PORT_MOD, 0);
    cofp_pm = CBUF_DATA(b);

    cofp_pm->datapath_id = htonll(dpid);
    cofp_pm->port_no = htonl(pm_parms->port_no);
    cofp_pm->config = htonl(pm_parms->config);
    cofp_pm->mask = htonl(pm_parms->mask);
    return b;
}

static struct cbuf *
mul_app_prep_async_config(uint64_t dpid, 
                       struct of_async_config_params *async_config_params)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_async_config *cofp_ac;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_ac) + sizeof(*cofp_aac);

    b = of_prep_msg(tot_len, C_OFPT_AUX_CMD, 0);

    
    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code =  htonl(C_AUX_CMD_ASYNC_CONFIG);

    cofp_ac = ASSIGN_PTR(cofp_aac->data);

    cofp_ac->datapath_id = htonll(dpid);
    
    cofp_ac->packet_in_mask[0] =
        htonl(async_config_params->packet_in_mask[0]);
    cofp_ac->packet_in_mask[1] =
        htonl(async_config_params->packet_in_mask[1]);

    cofp_ac->port_status_mask[0] =
        htonl(async_config_params->port_status_mask[0]);
    cofp_ac->port_status_mask[1] =
        htonl(async_config_params->port_status_mask[1]);
    
    cofp_ac->flow_removed_mask[0] =
        htonl(async_config_params->flow_removed_mask[0]);
    cofp_ac->flow_removed_mask[1] =
        htonl(async_config_params->flow_removed_mask[1]);
    return b;
}

static struct cbuf *
mul_app_prep_loop_status(uint64_t status) 
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_loop_status_mod *cofp_sm;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_sm) + sizeof(*cofp_aac);

    b = of_prep_msg(tot_len, C_OFPT_AUX_CMD, 0);

    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code =  htonl(C_AUX_CMD_MUL_LOOP_STATUS);

    cofp_sm = ASSIGN_PTR(cofp_aac->data);

    cofp_sm->loop_status = htonll(status);
    
    return b;
}

static struct cbuf *
mul_app_prep_tr_status(uint64_t status) 
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_tr_status_mod *cofp_trsm;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_trsm) + sizeof(*cofp_aac);

    b = of_prep_msg(tot_len, C_OFPT_AUX_CMD, 0);

    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code =  htonl(C_AUX_CMD_MUL_TR_STATUS);

    cofp_trsm = ASSIGN_PTR(cofp_aac->data);

    cofp_trsm->tr_status = htonll(status);
    
    return b;
}
static struct cbuf *
mul_app_prep_group_add(uint64_t dpid, struct of_group_mod_params *g_parms)
{
    struct cbuf *b;
    struct c_ofp_group_mod *cofp_gm;
    int act = 0;
    size_t tot_len = 0;
    struct of_act_vec_elem *act_elem;
    struct c_ofp_bkt *bkt;

    for (; act < g_parms->act_vec_len; act++) {
        act_elem = g_parms->act_vectors[act];
        if (act_elem)
            tot_len += act_elem->action_len + sizeof(*bkt);
    }
    tot_len += sizeof(*cofp_gm);

    b = of_prep_msg(tot_len, C_OFPT_GROUP_MOD, 0);
    cofp_gm = CBUF_DATA(b);

    cofp_gm->datapath_id = htonll(dpid);
    cofp_gm->command = C_OFPG_ADD;
    cofp_gm->group_id = htonl(g_parms->group);
    cofp_gm->type = g_parms->type;
    cofp_gm->flags = g_parms->flags;

    tot_len = sizeof(*cofp_gm);
    for (act = 0; act < g_parms->act_vec_len; act++) {
        bkt = INC_PTR8(cofp_gm, tot_len);
        act_elem = g_parms->act_vectors[act];

        if (act_elem) {
            bkt->weight = htons(act_elem->weight);
            bkt->ff_port = htonl(act_elem->ff_port);
            bkt->ff_group = htonl(act_elem->ff_group);
            bkt->act_len = htons(act_elem->action_len);
            memcpy(bkt->actions, act_elem->actions, act_elem->action_len);
            tot_len += sizeof(*bkt) + act_elem->action_len;
        }
    }

    return b;
}

static struct cbuf *
mul_app_prep_group_del(uint64_t dpid, struct of_group_mod_params *g_parms)
{
    struct cbuf *b;
    struct c_ofp_group_mod *cofp_gm;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_gm);

    b = of_prep_msg(tot_len, C_OFPT_GROUP_MOD, 0);
    cofp_gm = CBUF_DATA(b);

    cofp_gm->datapath_id = htonll(dpid);
    cofp_gm->command = C_OFPG_DEL;
    cofp_gm->group_id = htonl(g_parms->group);
    cofp_gm->type = g_parms->type;
    cofp_gm->flags = g_parms->flags;

    return b;
}

int
mul_service_send_group_add(void *service,
                           uint64_t dpid, struct of_group_mod_params *g_parms)
{
    struct cbuf *b;

    b = mul_app_prep_group_add(dpid, g_parms);
    c_service_send(service, b);

    return 0;
}

int
mul_service_send_group_del(void *service,
                           uint64_t dpid, struct of_group_mod_params *g_parms)
{
    struct cbuf *b;

    b = mul_app_prep_group_del(dpid, g_parms);
    c_service_send(service, b);

    return 0;
}

int
mul_service_send_meter_add(void *service,
                           uint64_t dpid, struct of_meter_mod_params *m_parms)
{
    struct cbuf *b;

    b = mul_app_prep_meter_add(dpid, m_parms);
    c_service_send(service, b);

    return 0;
}

int
mul_service_send_meter_del(void *service,
                           uint64_t dpid, struct of_meter_mod_params *m_parms)
{
    struct cbuf *b;

    b = mul_app_prep_meter_del(dpid, m_parms);
    c_service_send(service, b);

    return 0;
}

int
mul_service_send_port_mod(void *service,
                           uint64_t dpid, struct of_port_mod_params *pm_parms)
{
    struct cbuf *b;

    b = mul_app_prep_port_mod(dpid, pm_parms);
    c_service_send(service, b);

    return 0;
}

int
mul_app_send_port_mod(uint64_t dpid, struct of_port_mod_params *pm_parms)
{
    struct cbuf *b;
    b = mul_app_prep_port_mod(dpid, pm_parms);
    return mul_app_command_handler(NULL, b);
}

int
mul_service_send_async_config(void *service, uint64_t dpid,
                              struct of_async_config_params *ac_parms)
{
    struct cbuf *b;

    b = mul_app_prep_async_config(dpid, ac_parms);
    c_service_send(service, b);

    return 0;
}

int
mul_app_send_loop_status(uint64_t status)
{
    struct cbuf *b;

    b = mul_app_prep_loop_status(status);
    return mul_app_command_handler(NULL, b);
}

int
mul_app_send_tr_status(uint64_t status)
{
    struct cbuf *b;

    b = mul_app_prep_tr_status(status);
    return mul_app_command_handler(NULL, b);
}

static struct cbuf *
mul_prep_send_vendor_msg(uint64_t dpid, uint32_t vendor_id, void *arg, uint16_t len)
{
    struct cbuf *b;
    c_ofp_send_vendor_message_t *vm;
    void *ptr = NULL;

    b = of_prep_msg(sizeof(*vm) +len, C_OFPT_VENDOR_MSG, 0);
    vm = CBUF_DATA(b);
    vm->datapath_id = htonll(dpid);
    vm->vendor_id = htonl(vendor_id);

    ptr = ASSIGN_PTR(vm->data);
    memcpy(ptr, arg, len);

    return b;

}

int
mul_send_vendor_msg(uint64_t dpid, uint32_t vendor_id, void *arg, uint16_t arg_len)
{
    struct cbuf *b;

    b = mul_prep_send_vendor_msg(dpid, vendor_id, arg, arg_len);
    mul_app_command_handler(NULL, b);
    return 0;
}

void
mul_app_act_alloc(mul_act_mdata_t *mdata)
{
    return of_mact_alloc(mdata);
}

int
mul_app_act_set_ctors(mul_act_mdata_t *mdata, uint64_t dpid)
{
    uint8_t ver = c_app_switch_get_version_with_id(dpid);

    switch (ver) {
    case OFP_VERSION:
        mdata->ofp_ctors = &of10_ctors;
        break;
    case OFP_VERSION_131:
        mdata->ofp_ctors = &of131_ctors;
        break;
    case OFP_VERSION_140:
        mdata->ofp_ctors = &of140_ctors;
        break;
    default:
        return -1;
    }

    return 0;
}

void
mul_app_act_free(mul_act_mdata_t *mdata)
{
    return of_mact_free(mdata);
}

size_t
mul_app_act_buf_room(mul_act_mdata_t *mdata)
{
    return of_mact_buf_room(mdata);
}

size_t
mul_app_act_len(mul_act_mdata_t *mdata)
{
    return of_mact_len(mdata);
}

int
mul_app_set_inst_write(mul_act_mdata_t *mdata)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->set_act_inst) {
        return ctors->set_act_inst(mdata, OFPIT_WRITE_ACTIONS);
    } else {
        c_log_err("%s: inst write not supported", FN);
        return -1;
    }
}

int
mul_app_set_inst_apply(mul_act_mdata_t *mdata)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->set_act_inst) {
        return ctors->set_act_inst(mdata, OFPIT_APPLY_ACTIONS);
    } else {
        c_log_err("%s: inst apply not supported", FN);
        return -1;
    }
}

int
mul_app_inst_goto(mul_act_mdata_t *mdata, uint8_t table)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->inst_goto) {
        if (!ctors->inst_goto(mdata, table)) {
            return -1;
        }
    } else {
        c_log_err("%s: goto not supported", FN);
        return -1;
    }

    return 0;
}

int
mul_app_inst_meter(mul_act_mdata_t *mdata, uint32_t meter)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->inst_meter) {
        if (!ctors->inst_meter(mdata, meter)) {
            return -1;
        }
    } else {
        c_log_err("%s: meter not supported", FN);
        return -1;
    }

    return 0;
}

int
mul_app_action_output(mul_act_mdata_t *mdata, uint32_t oport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_output) {
        return ctors->act_output(mdata, oport);
    }

    return -1;
}

int
mul_app_action_set_queue(mul_act_mdata_t *mdata, uint32_t queue)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_queue) {
       return  ctors->act_set_queue(mdata, queue);
    } else {
        c_log_err("%s: set queue action not supported", FN);
    }

    return -1;
}

int
mul_app_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_vid) {
        return ctors->act_set_vid(mdata, vid);
    }
    return -1;
}

int
mul_app_action_strip_vlan(mul_act_mdata_t *mdata)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_strip_vid) {
        return ctors->act_strip_vid(mdata);
    }
    return -1; 
}

int
mul_app_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_dmac) {
        return ctors->act_set_dmac(mdata, dmac);
    }
    return -1;
}

int
mul_app_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_smac) {
        return ctors->act_set_smac(mdata, smac);
    }
    return -1;
}

int
mul_app_action_set_eth_type(mul_act_mdata_t *mdata, uint16_t eth_type)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_eth_type) {
        return ctors->act_set_eth_type(mdata, eth_type);
    } else {
        c_log_err("%s: Set eth type action not supported", FN);
    }
    return -1;
}

int
mul_app_action_push_hdr(mul_act_mdata_t *mdata, uint16_t eth_type)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_push) {
        return ctors->act_push(mdata, eth_type);
    } else {
        c_log_err("%s: push hdr action not supported", FN);
    }
    return -1;
}

int
mul_app_action_strip_mpls(mul_act_mdata_t *mdata, uint16_t eth_type)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_strip_mpls) {
        return ctors->act_strip_mpls(mdata, eth_type);
    } else {
        c_log_err("%s: pop mpls action not supported", FN);
    }
    return -1;
}

int
mul_app_action_set_mpls_ttl(mul_act_mdata_t *mdata, uint8_t ttl)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_mpls_ttl) {
        return ctors->act_set_mpls_ttl(mdata, ttl);
    } else {
        c_log_err("%s: set mpls ttl action not supported", FN);
    }
    return -1;
}

int
mul_app_action_set_mpls_label(mul_act_mdata_t *mdata, uint32_t label)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_mpls_label) {
        return ctors->act_set_mpls_label(mdata, label);
    } else {
        c_log_err("%s: set mpls label action not supported", FN);
    }
    return -1;
}

int
mul_app_action_set_mpls_tc(mul_act_mdata_t *mdata, uint8_t tc)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_mpls_tc) {
        return ctors->act_set_mpls_tc(mdata, tc);
    } else {
        c_log_err("%s: set mpls TC action not supported", FN);
    }
    return -1;
}

int
mul_app_action_set_mpls_bos(mul_act_mdata_t *mdata, uint8_t bos)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_mpls_bos) {
        return ctors->act_set_mpls_bos(mdata, bos);
    } else {
        c_log_err("%s: set mpls BOS action not supported", FN);
    }
    return -1;
}

int
mul_app_action_dec_mpls_ttl(mul_act_mdata_t *mdata)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_dec_mpls_ttl) {
        return ctors->act_dec_mpls_ttl(mdata);
    } else {
        c_log_err("%s: dec mpls ttl action not supported", FN);
    }
    return -1;
}

int
mul_app_action_set_nw_ttl(mul_act_mdata_t *mdata, uint8_t ttl)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_ip_ttl) {
        return ctors->act_set_ip_ttl(mdata, ttl);
    } else {
        c_log_err("%s: set nw ttl action not supported", FN);
    }
    return -1;
}

int
mul_app_action_dec_nw_ttl(mul_act_mdata_t *mdata)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_dec_ip_ttl) {
        return ctors->act_dec_ip_ttl(mdata);
    } else {
        c_log_err("%s: dec nw ttl action not supported", FN);
    }
    return -1;
}

int
mul_app_action_cp_ttl(mul_act_mdata_t *mdata, bool in)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_cp_ttl) {
        return ctors->act_cp_ttl(mdata, in);
    } else {
        c_log_err("%s: cp ttl action not supported", FN);
    }

    return -1;
}

int
mul_app_action_strip_pbb(mul_act_mdata_t *mdata)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_strip_pbb) {
        return ctors->act_strip_pbb(mdata);
    } else {
        c_log_err("%s: pop PBB action not supported", FN);
    }
    return -1;
}

int
mul_app_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_vlan_pcp) {
        return ctors->act_set_vlan_pcp(mdata, vlan_pcp);
    }
    return -1;
}

int
mul_app_action_set_nw_saddr(mul_act_mdata_t *mdata, uint32_t nw_saddr) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_saddr) {
       return  ctors->act_set_nw_saddr(mdata, nw_saddr);
    }
    return -1;
}

int
mul_app_action_set_nw_daddr(mul_act_mdata_t *mdata, uint32_t nw_daddr) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_daddr) {
        return ctors->act_set_nw_daddr(mdata, nw_daddr);
    }
    return -1;
}

int
mul_app_action_set_nw_saddr6(mul_act_mdata_t *mdata, uint8_t *nw_saddr) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_saddr6) {
       return  ctors->act_set_nw_saddr6(mdata, nw_saddr);
    }
    return -1;
}

int
mul_app_action_set_nw_daddr6(mul_act_mdata_t *mdata, uint8_t *nw_daddr) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_daddr6) {
        return ctors->act_set_nw_daddr6(mdata, nw_daddr);
    }
    return -1;
}

int
mul_app_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_tos) {
        return ctors->act_set_nw_tos(mdata, tos);
    }
    return -1;
}

int
mul_app_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t sport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tp_udp_sport) {
        return ctors->act_set_tp_udp_sport(mdata, sport);
    }
    return -1;
}

int
mul_app_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t dport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tp_udp_dport) {
        return ctors->act_set_tp_udp_dport(mdata, dport);
    }
    return -1;
}

int
mul_app_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t sport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tp_tcp_sport) {
        return ctors->act_set_tp_tcp_sport(mdata, sport);
    }
    return -1;
}

int
mul_app_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t dport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tp_tcp_dport) {
        return ctors->act_set_tp_tcp_dport(mdata, dport);
    }
    return -1;
}

int
mul_app_action_set_group(mul_act_mdata_t *mdata, uint16_t group)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_group) {
        return ctors->act_set_group(mdata, group);
    }
    return -1;
}

int
mul_app_action_set_tunnel_id(mul_act_mdata_t *mdata, uint64_t tunnel)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tunnel) {
        return ctors->act_set_tunnel(mdata, tunnel);
    }
    return -1;
}

int
mul_app_set_band_drop(mul_act_mdata_t *mdata, struct of_meter_band_parms *parms)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->meter_drop) {
        ctors->meter_drop(mdata, parms);
    } else {
        c_log_err("%s: drop band not supported", FN);
        return -1;
    }
    return 0;
}

int
mul_app_set_band_dscp(mul_act_mdata_t *mdata, struct of_meter_band_parms *parms)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->meter_mark_dscp) {
        ctors->meter_mark_dscp(mdata, parms);
    } else {
        c_log_err("%s: mark dscp not supported", FN);
        return -1;
    }

    return 0;
}

bool
mul_app_core_conn_available(void)
{
    return !hdl->conn.dead;
}

#ifdef MUL_APP_VTY
#include "mul_vty.h"

#ifndef SWIG_INFRA
static void
vty_show_port_info(void *port_arg, void *uarg)
{
    mul_port_t *port = port_arg;
    struct vty *vty = uarg;

    vty_out(vty, "%hu(%x:%x) ", port->port_no,
            !(port->config & OFPPC_PORT_DOWN),
            !(port->state & OFPPS_LINK_DOWN));
}

static void
vty_show_switch_info(void *key UNUSED, void *sw_arg, void *uarg)
{
    mul_switch_t *sw = sw_arg;
    struct vty  *vty = uarg;

    vty_out(vty, "0x%-16llx ", (unsigned long long)sw->dpid);
    c_app_traverse_switch_ports(sw, vty_show_port_info, vty);
    vty_out(vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
}

DEFUN_HIDDEN (show_switches,
       show_switches_cmd,
       "show app-switch all",
       SHOW_STR
       "app switches\n"
       "Summary information for all")
{

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    vty_out(vty, "%10s %18s %s%s", "DP-id",
            "Port-list","<port-num>(admin:link)", VTY_NEWLINE);
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_app_traverse_all_switches(vty_show_switch_info, vty);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

void
c_app_infra_vty_init(void *hdl UNUSED)
{
    install_element(ENABLE_NODE, &show_switches_cmd);
}
module_vty_init(c_app_infra_vty_init);
#endif
#endif
