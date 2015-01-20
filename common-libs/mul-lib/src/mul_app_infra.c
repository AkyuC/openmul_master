/**
 *  @file mul_app_infra.c
 *  @brief Mul application infrastructure
 *  @author Dipjyoti Saikia  <dipjyoti.saikia@gmail.com>
 *  @copyright Copyright (C) 2013, Dipjyoti Saikia
 *
 * @license This program is free software; you can redistribute it and/or
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
 *
 *
 * @see www.openmul.org
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
void c_switch_err_msg(c_app_hdl_t *hdl UNUSED, c_ofp_error_msg_t *ofp_err);
void c_app_packet_in(c_app_hdl_t *hdl, c_ofp_packet_in_t *ofp_pin);
void c_controller_reconn(c_app_hdl_t *hdl);
void c_app_notify_ha_event(c_app_hdl_t *hdl, uint32_t ha_sysid, uint32_t ha_state);
void c_controller_disconn(c_app_hdl_t *hdl);
void c_app_vendor_msg(c_app_hdl_t *hdl UNUSED, c_ofp_vendor_msg_t *ofp_vm);
void c_app_tr_status(c_app_hdl_t *hdl UNUSED, c_ofp_tr_status_mod_t *ofp_trsm);
int c_app_infra_init(c_app_hdl_t *hdl);
void c_app_infra_vty_init(void *hdl);
static void c_app_traverse_switch_ports(mul_switch_t *sw,
                                        GFunc iter_fn, void *arg);

/* Openflow 1.0 Constructors */
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

/* Openflow 1.3.1 Constructors */
static struct c_ofp_ctors of131_ctors = {
    .group_validate = of131_group_validate_parms,
    .group_add = of131_prep_group_add_msg,
    .group_del = of131_prep_group_del_msg,
    .set_act_inst = of131_set_inst_action_type,
    .inst_goto = of131_make_inst_goto,
    .inst_meter = of131_make_inst_meter,
    .inst_wr_meta = of131_make_inst_wr_meta,
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

/* Openflow 1.4 Constructors */
static struct c_ofp_ctors of140_ctors = {
    .group_validate = of131_group_validate_parms,
    .group_add = of131_prep_group_add_msg,
    .group_del = of131_prep_group_del_msg,
    .set_act_inst = of131_set_inst_action_type,
    .inst_goto = of131_make_inst_goto,
    .inst_meter = of131_make_inst_meter,
    .inst_wr_meta = of131_make_inst_wr_meta,
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


/**
 * @name c_app_write_event_sched 
 * @brief Schedule a write event
 */
static void
c_app_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

/**
 * @name mul_app_command_handler 
 * @brief Sends a command containing cbuf to mul-core
 */
int
mul_app_command_handler(void *app_name UNUSED, void *b)
{
    c_conn_tx(&hdl->conn, (struct cbuf *)(b),
              c_app_write_event_sched);
    return 0;
}

/**
 * @name c_app_port_slist_ent_free 
 * @brief Free the port list and call
 *        the switch_priv_port_free if necessary  
 */
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

/**
 * @name c_app_switch_get
 * @brief Increment the app switch's reference count 
 */
static inline void
c_app_switch_get(mul_switch_t *sw)
{
    atomic_inc(&sw->ref, 1);
}

/**
 * @name c_app_switch_get_with_id 
 * @brief Given a datapath-id, find the switch
 * @param [in] dpid the datapath-id
 * 
 * @retval mul_switch_t * the pointer to app switch struct 
 *
 * The switch if found has its reference count incremented
 */
mul_switch_t * 
c_app_switch_get_with_id(uint64_t dpid)
{
    mul_switch_t *sw = NULL;
    int lock = 0;

    lock = c_rd_trylock(&hdl->infra_lock);
    if (!(sw = g_hash_table_lookup(hdl->switches, &dpid))) {
        if (!lock) c_rd_unlock(&hdl->infra_lock);
        c_log_err("[infra] unknown switch (0x%llx)",
                  (unsigned long long)dpid);
        return NULL;
    }

    atomic_inc(&sw->ref, 1);
    if (!lock)  c_rd_unlock(&hdl->infra_lock);
    return sw;
}

/**
 * @name __c_app_switch_get_with_id
 * @brief No lock version of c_app_switch_get_with_id
 */
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

/**
 * @name c_switch_free
 * @brief Free the app infra switch and call switch_priv_free if needed`;
 */
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

/**
 * @name c_app_switch_put
 * @brief Deref a switch's reference 
 * @param [in] sw Pointer to mul_switch_t 
 *
 * @retval void Nothing
 * 
 * If ref count drops  to 0, free all memory used by the switch
 */
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

/**
 * @name c_app_sw_free
 * @brief Wrapper over c_app_switch_put
 */
static void
c_app_sw_free(void *arg)
{
    c_app_switch_put((mul_switch_t *)arg);
}

/**
 * @name c_app_switch_get_version_with_id 
 * @brief Given a datapath-id returns OF version  
 * @param [in] dpid datapath-id of the switch
 *
 * @retval uint8_t Openflow version, 0 if no such switch
 */
uint8_t
c_app_switch_get_version_with_id(uint64_t dpid)
{
    mul_switch_t *sw = NULL;
    uint8_t ver;
    int lock = 0;

    lock = c_rd_trylock(&hdl->infra_lock);
    if (!(sw = g_hash_table_lookup(hdl->switches, &dpid))) {
        if (!lock) c_rd_unlock(&hdl->infra_lock);
        c_log_err("[infra] Unknown switch-id (0x%llx)",
                  (unsigned long long)dpid);
        return 0;
    }

    ver = sw->ofp_ver;
    if (!lock) c_rd_unlock(&hdl->infra_lock);
    return ver;
}

/**
 * @name c_app_alias_finder 
 * @brief Finds a alias-id match in the switch list 
 */
static bool
c_app_alias_finder(void *key UNUSED,
                   void *value,
                   void *u_arg)
{
    mul_switch_t *sw = value;
    int alias = *(int *)u_arg;

    if (sw->alias_id == alias) return true;

    return false;
}

/**
 * @name c_app_switch_get_dpid_with_alias
 * @brief Given a switch alias-id, find the datapath-id 
 * @param [in] alias the alias-id
 * 
 * @retval uint64_t the switch dpid, 0 if no such switch 
 */
uint64_t
c_app_switch_get_dpid_with_alias(int alias)
{
    mul_switch_t *sw = NULL;
    uint64_t dpid;
    int lock = 0;

    lock = c_rd_trylock(&hdl->infra_lock);
    if (!(sw = g_hash_table_find(hdl->switches, 
                                 (GHRFunc)c_app_alias_finder,
                                 &alias))) {
        if (!lock) c_rd_unlock(&hdl->infra_lock);
        return 0;
    }

    dpid = sw->dpid;
    if (!lock) c_rd_unlock(&hdl->infra_lock);

    return dpid;
}

/**
 * @name c_app_traverse_all_switches
 * @brief Traverse through the switch list  
 * @param iter_fn Function to be invoked for each switch
 * @param arg Argument to be passed to iter_fn
 * 
 * @retval void Nothing 
 * 
 * Holds appropriate locks before traversal
 */
void
c_app_traverse_all_switches(GHFunc iter_fn, void *arg)
{
    int lock = 0;
    lock = c_rd_trylock(&hdl->infra_lock);
    if (hdl->switches) {
        g_hash_table_foreach(hdl->switches,
                             (GHFunc)iter_fn, arg);
    }
    if (!lock) c_rd_unlock(&hdl->infra_lock);

    return;
}

/**
 * @name __c_app_traverse_all_switches
 * @brief Traverse through the switch list  
 * @param iter_fn Function to be invoked for each switch
 * @param arg Argument to be passed to iter_fn
 * 
 * @retval void Nothing 
 * 
 * Does not hold appropriate locks before traversal. User needs
 * to hold locks necessary
 */
void
__c_app_traverse_all_switches(GHFunc iter_fn, void *arg)
{
    if (hdl->switches) {
        g_hash_table_foreach(hdl->switches, (GHFunc)iter_fn, arg);
    }

    return;
}

/** 
 * @name c_app_traverse_switch_ports
 * @brief Traverse all ports of a switch
 */
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

/** 
 * @name  c_app_switch_add
 * @brief Adds a switch to the app infrastructure
 */
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

/** 
 * @name mul_app_swports_del_notify 
 * @brief Send notification for switch port delete to app 
 */
static void 
mul_app_swports_del_notify(void *port_arg, void *uarg UNUSED)
{
    mul_port_t *port = port_arg;

    if (app_cbs && app_cbs->switch_port_del_cb) {
        app_cbs->switch_port_del_cb(port->owner, port);
    }
}

/** 
 * @name c_app_switch_del 
 * @brief Delete a switch from app infra 
 */
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
    c_wr_unlock(&hdl->infra_lock);

    if (app_cbs && app_cbs->switch_del_cb) {
        app_cbs->switch_del_cb(sw);
    }

    c_wr_lock(&hdl->infra_lock);
    c_app_switch_put(sw);
    g_hash_table_remove(hdl->switches, &dpid); /* c_app_sw_free() */
    c_wr_unlock(&hdl->infra_lock);
}

/** 
 * @name c_switch_port_status 
 * @brief Port status updatation 
 */
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

/** 
 * @name c_switch_port_status 
 * @brief Packet-in handler and notification generation for app
 */
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

/** 
 * @name c_switch_err_msg
 * @brief Error message handler and notification generation for app
 */
void
c_switch_err_msg(c_app_hdl_t *hdl UNUSED, c_ofp_error_msg_t *ofp_err)
{
    mul_switch_t *sw;
    struct ofp_header *hdr;
    uint16_t len = ntohs(ofp_err->header.length);

    if (len < sizeof(*ofp_err))
        return;

    if (len < sizeof(*ofp_err)+sizeof(ofp_err->header))
        return; 

    hdr = ASSIGN_PTR(ofp_err->data);

    switch (hdr->type) {
    case C_OFPT_FLOW_MOD: {
        c_ofp_flow_mod_t *cofp_fm;
        char *str;

        if (len < sizeof(*ofp_err)+sizeof(*cofp_fm)) 
            return;

        cofp_fm = ASSIGN_PTR(ofp_err->data);

        if (!(sw = c_app_switch_get_with_id(ntohll(cofp_fm->datapath_id)))) {
            /* FIXME : Ratelimit this */
            c_log_err("[infra] |switch-err| switch not found");
            return;
        }

        str = of_dump_flow_generic(&cofp_fm->flow, &cofp_fm->mask);
        if (str) {
            c_log_err("%s: flow mod fail %s", FN, str);
            free(str);
        }

        if (app_cbs && app_cbs->switch_fl_mod_err)
            app_cbs->switch_fl_mod_err(sw,
                                       ntohs(ofp_err->type),
                                       ntohs(ofp_err->code),
                                       cofp_fm);
        break;

    }
    case C_OFPT_GROUP_MOD: {
        c_ofp_group_mod_t *cofp_gm;

        if (len < sizeof(*ofp_err)+sizeof(*cofp_gm)) 
            return;

        cofp_gm = ASSIGN_PTR(ofp_err->data);

        if (!(sw = c_app_switch_get_with_id(ntohll(cofp_gm->datapath_id)))) {
            /* FIXME : Ratelimit this */
            c_log_err("[infra] |switch-err| switch not found");
            return;
        }

        c_log_err("%s: group |%lu| mod fail",
                  FN, U322UL(ntohl(cofp_gm->group_id)));

        if (app_cbs && app_cbs->switch_group_mod_err)
            app_cbs->switch_group_mod_err(sw,
                                       ntohs(ofp_err->type),
                                       ntohs(ofp_err->code),
                                       cofp_gm);
        
        break;

    }
    case C_OFPT_METER_MOD: {
        c_ofp_meter_mod_t *cofp_mm;

        if (len < sizeof(*ofp_err)+sizeof(*cofp_mm)) 
            return;

        cofp_mm = ASSIGN_PTR(ofp_err->data);

        if (!(sw = c_app_switch_get_with_id(ntohll(cofp_mm->datapath_id)))) {
            /* FIXME : Ratelimit this */
            c_log_err("[infra] |switch-err| switch not found");
            return;
        }

        c_log_err("%s: meter |%lu| mod fail",
                  FN, U322UL(ntohl(cofp_mm->meter_id)));

        if (app_cbs && app_cbs->switch_meter_mod_err)
            app_cbs->switch_meter_mod_err(sw,
                                       ntohs(ofp_err->type),
                                       ntohs(ofp_err->code),
                                       cofp_mm);
        
        break;

    }
    default:
        break; 
    }

}

/** 
 * @name c_app_vendor_msg
 * @brief Vendor message handler and notification generation for app
 */
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

/** 
 * @name c_app_tr_status
 * @brief Topology status update and notification generation for app
 */
void
c_app_tr_status(c_app_hdl_t *hdl UNUSED, c_ofp_tr_status_mod_t *ofp_trsm)
{
    if (app_cbs && app_cbs->topo_route_status_cb) {
        app_cbs->topo_route_status_cb(ntohll(ofp_trsm->tr_status));
    }
}

/** 
 * @name c_app_switch_del_notify
 * @brief Switch delete notification generation for app
 *
 * It also triggers deletion of switch ports 
 */
static void
c_app_switch_del_notify(void *key UNUSED, void *sw_arg, void *uarg UNUSED)
{
    mul_switch_t *sw = sw_arg;
    c_app_traverse_switch_ports(sw, mul_app_swports_del_notify, NULL);
    if (app_cbs && app_cbs->switch_del_cb) {
        app_cbs->switch_del_cb(sw);
    }
}

/** 
 * @name c_controller_disconn
 * @brief Controller connection disconnect notification generation for app
 */
void
c_controller_disconn(c_app_hdl_t *hdl)
{
    c_app_traverse_all_switches(c_app_switch_del_notify, NULL);
    g_hash_table_remove_all(hdl->switches);
    if (app_cbs && app_cbs->core_conn_closed) {
        app_cbs->core_conn_closed();
    }
}

/** 
 * @name c_controller_reconn
 * @brief Controller connection re-connect notification generation for app
 */
void
c_controller_reconn(c_app_hdl_t *hdl UNUSED)
{
    if (app_cbs && app_cbs->core_conn_reconn) {
        app_cbs->core_conn_reconn();
    }
}

/** 
 * @name c_app_notify_ha_event
 * @brief Notify HA events to app
 */
void
c_app_notify_ha_event(c_app_hdl_t *hdl UNUSED, uint32_t ha_sysid, uint32_t ha_state)
{
    if (app_cbs && app_cbs->app_ha_state) {
        app_cbs->app_ha_state(ha_sysid, ha_state);
    }
}

/** 
 * @name c_app_infra_init
 * @brief Notify HA events to app
 */
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

/** 
 * @name _common_reg_app
 * @brief Register a app to controller core 
 * @param  [in] app_arg Application context (unused)
 * @param [in] app_name Application name
 * @app_flags [in] Flags for registration
 * @ev_mask [in] Events required
 * @n_dpid [in] No. of dpids for filtering (if any) 
 * @dpid_list [in] List of dpids for filtering (if any) 
 * @ev_cb [in] Event callback for processing raw controller generated events 
 * @client_app_cbs [in] Set of Callback functions to be called per event.
 *                      This prevents each app to parse messages by its own
 *
 * @retval int 0 for sucess and non-0  for failure
 */
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
    uint32_t app_cookie = 0;
    struct c_app_service *serv;
    size_t serv_sz = sizeof(c_app_service_tbl)/sizeof(c_app_service_tbl[0]);

    for (; idx < serv_sz; idx++) {
        serv = &c_app_service_tbl[idx];
        if (!strncmp(serv->app_name, app_name, MAX_SERV_NAME_LEN-1)) {
            app_cookie = serv->app_cookie;
#ifdef APP_HA
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
#endif
        }
    }

    b = of_prep_msg(sizeof(struct c_ofp_register_app) +
                    (n_dpid * sizeof(uint64_t)), C_OFPT_REG_APP, 0);

    reg_app = (void *)(b->data);
    strncpy(reg_app->app_name, app_name, C_MAX_APP_STRLEN-1);
    reg_app->app_flags = htonl(app_flags);
    reg_app->ev_mask = htonl(ev_mask);
    reg_app->dpid = htonl(n_dpid);
    reg_app->app_cookie = htonl(app_cookie);
    hdl->app_cookie = app_cookie;

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

/** 
 * @name mul_register_app 
 * @brief Register a app to controller core (Front end api)
 * @param  [in] app_arg Application context
 * @param [in] app_name Application name
 * @app_flags [in] Flags for registration
 * @ev_mask [in] Events required
 * @n_dpid [in] No. of dpids for filtering (if any) 
 * @dpid_list [in] List of dpids for filtering (if any) 
 * @ev_cb [in] Event callback for processing raw controller generated events 
 *
 * @retval int 0 for sucess and non-0  for failure
 */ 
int
mul_register_app(void *app_arg, char *app_name, uint32_t app_flags,
                 uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                 void  (*ev_cb)(void *app_arg, void *pkt_arg))
{
    return _commom_reg_app(app_arg, app_name, app_flags, ev_mask, n_dpid, 
                           dpid_list, ev_cb, NULL);
}

#ifdef MUL_APP_V2_MLAPI
/** 
 * @name mul_register_app_cb 
 * @brief Register a app to controller core 
 * @param  [in] app_arg Application context (unused)
 * @param [in] app_name Application name
 * @app_flags [in] Flags for registration
 * @ev_mask [in] Events required
 * @n_dpid [in] No. of dpids for filtering (if any) 
 * @dpid_list [in] List of dpids for filtering (if any) 
 * @ev_cb [in] Event callback for processing raw controller generated events 
 * @client_app_cbs [in] Set of Callback functions to be called per event.
 *                      This prevents each app to parse messages by its own
 *
 * @retval int 0 for sucess and non-0  for failure
 */
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

    if(!n_dpid) {
        if(strcmp(hdl->dpid_file,"\0")) {
            fp = fopen(hdl->dpid_file,"r");
            c_log_debug("Reading DPIDs from %s",hdl->dpid_file);
            if( fp == NULL) {
                perror("Error while opening the file");
            }
            else {

                do {
                    c = fscanf(fp,"%s",dpid_str); /* scan dpid from the file */
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
    }
    return _commom_reg_app(app_arg, app_name, app_flags, ev_mask, n_dpid,
                           dpid_list, NULL, app_cbs);
}
#endif


/** 
 * @name mul_unregister_app
 * @brief Un-register a app to controller core 
 * @param [in] app_name Application name
 *
 * @retval int 0 for sucess and non-0  for failure
 */
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

/** 
 * @name mul_app_send_pkt_out
 * @brief Send packet out message via controller core 
 * @param [in] arg Application argument (unused) 
 * @param [in] dpid Datapath-id from where packet needs to be sent 
 * @param [in] parms_arg Packet-out arguments in struct of_pkt_out_params *
 *                       Caller to free the arguments
 *
 * @retval void Nothing 
 */
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

/** 
 * @name mul_app_prep_flow_add 
 * @brief Prepare a flow add message
 */
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
    cofp_fm->cookie = htonl(hdl->app_cookie);

    act = ASSIGN_PTR(cofp_fm->actions);
    memcpy(act, actions, action_len);

    return b;
}


/** 
 * @name mul_app_send_flow_add
 * @brief Send a flow add message to controller 
 * @param [in] app_name Application name (unused) 
 * @param [in] sw_arg Switch argument (unused) 
 * @param [in] dpid Datapath-id of the concerned switch
 * @param [in] fl Flow match in struct flow *
 * @param [in] mask Flow mask in struct flow *
 * @param [in] buffer_id Buffer-id associated with this flow (as per OF spec) 
 * @param [in] actions Pointer to the buffer containing actions 
 * @param [in] action_len Action length 
 * @param [in] itimeo Idle timeout (as per OF Spec)
 * @param [in] htimeo Hard timeout (as per OF Spec) 
 * @param [in] prio Flow priority 
 * @param [in] flags Internal controller flow flags
 *
 * @retval int 0 for success non 0 for failure 
 *
 * This instructs the controller core to install a flow via main controller connection.
 * This flow will be deleted whenver application dies or unregisters itself 
 */
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

/** 
 * @name mul_app_send_flow_add
 * @brief Send a flow add message to controller 
 * @param [in] service Pointer to the client service created beforehand 
 * @param [in] dpid Datapath-id of the concerned switch
 * @param [in] fl Flow match in struct flow *
 * @param [in] mask Flow mask in struct flow *
 * @param [in] buffer_id Buffer-id associated with this flow (as per OF spec) 
 * @param [in] actions Pointer to the buffer containing actions 
 * @param [in] action_len Action length 
 * @param [in] itimeo Idle timeout (as per OF Spec)
 * @param [in] htimeo Hard timeout (as per OF Spec) 
 * @param [in] prio Flow priority 
 * @param [in] flags Internal controller flow flags.Can be a mask of the following:
 *             C_FL_ENT_STATIC A static flow  
 *             C_FL_ENT_CLONE  A cloned flow 
 *             C_FL_ENT_LOCAL  A Local flow for app delivery not installed in switch
 *             C_FL_ENT_NOCACHE Push the flow to the switch without keeping in local DB
 *             C_FL_ENT_NOT_INST Flow was not installed
 *             C_FL_ENT_NOSYNC Whether flow needs resyncing after HA event
 *             C_FL_ENT_GSTATS Gather stats flor this flow 
 *             C_FL_ENT_SWALIAS Flow add to happen via switch alias-id than dpid 
 *             C_FL_ENT_BARRIER Send accompanying barrier message with flow mod 
 *             C_FL_ENT_RESIDUAL Flow is residual flow read from switch (no app owner)
 *             C_FL_ENT_STALE Flow is stale 
 *             C_FL_NO_ACK Dont wait for ACK after flow add
 *             C_FL_ENT_CTRL_LOCAL Flow is meant for local controller delivery
 *             C_FL_ENT_TBL_PHYS Table-id in flow should not be translated
 *
 * @retval int 0 for success non 0 for failure 
 *
 * This instructs the controller core to install a flow via service connection.
 * This flow will not be deleted whenever application dies or unregisters itself 
 */
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

/**
 * @name mul_app_prep_flow_del
 * @brief Prepare a flow delete mlapi message 
 */
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

/** 
 * @name mul_app_send_flow_del
 * @brief Send a flow del message to controller 
 * @param [in] app_name Name of application (unused) 
 * @param [in] sw_arg Switch argument (Unused)
 * @param [in] dpid Datapath-id of the concerned switch
 * @param [in] fl Flow match in struct flow *
 * @param [in] mask Flow mask in struct flow *
 * @param [in] oport Match a Output port for flow del (as per OF Spec)
 * @param [in] prio Flow priority 
 * @param [in] flags Internal controller flow flags.Can be a mask of the following:
 *             C_FL_ENT_STATIC A static flow  
 *             C_FL_ENT_CLONE  A cloned flow 
 *             C_FL_ENT_LOCAL  A Local flow for app delivery not installed in switch
 *             C_FL_ENT_NOCACHE Push the flow to the switch without keeping in local DB
 *             C_FL_ENT_NOT_INST Flow was not installed
 *             C_FL_ENT_NOSYNC Whether flow needs resyncing after HA event
 *             C_FL_ENT_GSTATS Gather stats flor this flow 
 *             C_FL_ENT_SWALIAS Flow add to happen via switch alias-id than dpid 
 *             C_FL_ENT_BARRIER Send accompanying barrier message with flow mod 
 *             C_FL_ENT_RESIDUAL Flow is residual flow read from switch (no app owner)
 *             C_FL_ENT_STALE Flow is stale 
 *             C_FL_NO_ACK Dont wait for ACK after flow add
 *             C_FL_ENT_CTRL_LOCAL Flow is meant for local controller delivery
 *             C_FL_ENT_TBL_PHYS Table-id in flow should not be translated
 * @param [in] ogroup Match a Output group for flow del (as per OF Spec)
 *
 * @retval int 0 for success non 0 for failure 
 *
 * This instructs the controller core to delete a flow via main core connection.
 */
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

/** 
 * @name mul_service_send_flow_del
 * @brief Send a flow del message to controller 
 * @param [in] service Pointer to the client service handle
 * @param [in] dpid Datapath-id of the concerned switch
 * @param [in] fl Flow match in struct flow *
 * @param [in] mask Flow mask in struct flow *
 * @param [in] oport Match a Output port for flow del (as per OF Spec)
 * @param [in] prio Flow priority 
 * @param [in] flags Internal controller flow flags.Can be a mask of the following:
 *             C_FL_ENT_STATIC A static flow  
 *             C_FL_ENT_CLONE  A cloned flow 
 *             C_FL_ENT_LOCAL  A Local flow for app delivery not installed in switch
 *             C_FL_ENT_NOCACHE Push the flow to the switch without keeping in local DB
 *             C_FL_ENT_NOT_INST Flow was not installed
 *             C_FL_ENT_NOSYNC Whether flow needs resyncing after HA event
 *             C_FL_ENT_GSTATS Gather stats flor this flow 
 *             C_FL_ENT_SWALIAS Flow add to happen via switch alias-id than dpid 
 *             C_FL_ENT_BARRIER Send accompanying barrier message with flow mod 
 *             C_FL_ENT_RESIDUAL Flow is residual flow read from switch (no app owner)
 *             C_FL_ENT_STALE Flow is stale 
 *             C_FL_NO_ACK Dont wait for ACK after flow add
 *             C_FL_ENT_CTRL_LOCAL Flow is meant for local controller delivery
 *             C_FL_ENT_TBL_PHYS Table-id in flow should not be translated
 * @param [in] ogroup Match a Output group for flow del (as per OF Spec)
 *
 * @retval int 0 for success non 0 for failure 
 *
 * This instructs the controller core to delete a flow via controller service connection
 */
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

/**
 * @name mul_app_prep_meter_add
 * @brief Prepare a meter add mlapi message 
 */
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

/**
 * @name mul_app_prep_meter_del
 * @brief Prepare a meter delete mlapi message 
 */
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

/**
 * @name mul_app_prep_port_mod
 * @brief Prepare a port mod mlapi message
 */
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

/**
 * @name mul_app_prep_async_config
 * @brief Prepare a async config mlapi message
 */
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

/**
 * @name mul_app_prep_loop_status
 * @brief Prepare a loop convergence mlapi status message
 */
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

/**
 * @name mul_app_prep_tr_status
 * @brief Prepare a Topology status mlapi message 
 */
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

/**
 * @name mul_app_group_id_alloc
 * @brief Make a app specific group-id 
 * @param [in] id Plain group-id 
 *
 * @retval uint32_t translated app group-id
 * The input id's initial 16-bit is valid
 */
uint32_t
mul_app_group_id_alloc(uint32_t id)
{
    return (((hdl->app_cookie & 0xffff) << 16) |
            (id & 0xffff));
}

/**
 * @name mul_app_group_id_dealloc
 * @brief Return a plain group-id from app group-id
 * @param [in] id App group-id 
 *
 * @retval uint32_t translated plain group-id
 */
uint32_t
mul_app_group_id_dealloc(uint32_t id)
{
    return (id & 0xffff);
}

/**
 * @name mul_app_prep_group_add
 * @brief Prepares a group add mlapi message
 */
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

/**
 * @name mul_app_prep_group_del
 * @brief Prepares a group delete mlapi message
 */
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

/**
 * @name mul_service_send_group_add
 * @brief Send a group add mlapi to controller service
 * @param [in] service Pointer to the controller client service handle
 * @param [in] dpid Datapath-id of the switch
 * @param [in] g_parms Group modification parameters 
 * 
 * @retval int 0 for success and non 0 for failure
 * 
 * This instructs the controller to add a group via a service connection
 */
int
mul_service_send_group_add(void *service,
                           uint64_t dpid, struct of_group_mod_params *g_parms)
{
    struct cbuf *b;

    b = mul_app_prep_group_add(dpid, g_parms);
    c_service_send(service, b);

    return 0;
}

/**
 * @name mul_service_send_group_del
 * @brief Send a group del mlapi to controller service
 * @param [in] service Pointer to the controller client service handle
 * @param [in] dpid Datapath-id of the switch
 * @param [in] g_parms Group modification parameters 
 * 
 * @retval int 0 for success and non 0 for failure
 * 
 * This instructs the controller to delete a group via a service connection
 */
int
mul_service_send_group_del(void *service,
                           uint64_t dpid, struct of_group_mod_params *g_parms)
{
    struct cbuf *b;

    b = mul_app_prep_group_del(dpid, g_parms);
    c_service_send(service, b);

    return 0;
}

/**
 * @name mul_service_send_meter_add
 * @brief Send a meter add mlapi to controller service
 * @param [in] service Pointer to the controller client service handle
 * @param [in] dpid Datapath-id of the switch
 * @param [in] m_parms Meter modification parameters 
 * 
 * @retval int 0 for success and non 0 for failure
 * 
 * This instructs the controller to add a meter via a service connection
 */
int
mul_service_send_meter_add(void *service,
                           uint64_t dpid, struct of_meter_mod_params *m_parms)
{
    struct cbuf *b;

    b = mul_app_prep_meter_add(dpid, m_parms);
    c_service_send(service, b);

    return 0;
}

/**
 * @name mul_service_send_meter_del
 * @brief Send a meter del mlapi to controller service
 * @param [in] service Pointer to the controller client service handle
 * @param [in] dpid Datapath-id of the switch
 * @param [in] m_parms Meter modification parameters 
 * 
 * @retval int 0 for success and non 0 for failure
 * 
 * This instructs the controller to delete a meter via a service connection
 */
int
mul_service_send_meter_del(void *service,
                           uint64_t dpid, struct of_meter_mod_params *m_parms)
{
    struct cbuf *b;

    b = mul_app_prep_meter_del(dpid, m_parms);
    c_service_send(service, b);

    return 0;
}

/**
 * @name mul_service_send_port_mod
 * @brief Send a port prop mod mlapi message 
 * @param [in] service Pointer to the controller client service handle
 * @param [in] dpid Datapath-id of the switch
 * @param [in] pm_parms Port modification parameters 
 * 
 * @retval int 0 for success and non 0 for failure
 * 
 * This instructs the controller to modify a port via service connection
 */
int
mul_service_send_port_mod(void *service,
                           uint64_t dpid, struct of_port_mod_params *pm_parms)
{
    struct cbuf *b;

    b = mul_app_prep_port_mod(dpid, pm_parms);
    c_service_send(service, b);

    return 0;
}

/**
 * @name mul_app_send_port_mod
 * @brief Send a port prop mod mlapi message 
 * @param [in] dpid Datapath-id of the switch
 * @param [in] pm_parms Port modification parameters 
 * 
 * @retval int 0 for success and non 0 for failure
 * 
 * This instructs the controller to modify a port via default controller channel 
 */
int
mul_app_send_port_mod(uint64_t dpid, struct of_port_mod_params *pm_parms)
{
    struct cbuf *b;
    b = mul_app_prep_port_mod(dpid, pm_parms);
    return mul_app_command_handler(NULL, b);
}

/**
 * @name mul_service_send_async_config
 * @brief Send async config mlapi message to controller
 * @param [in] service Pointer to the controller client service handle
 * @param [in] dpid Datapath-id of the switch
 * @param [in] ac_parms Async config modification parameters 
 * 
 * @retval int 0 for success and non 0 for failure
 */
int
mul_service_send_async_config(void *service, uint64_t dpid,
                              struct of_async_config_params *ac_parms)
{
    struct cbuf *b;

    b = mul_app_prep_async_config(dpid, ac_parms);
    c_service_send(service, b);

    return 0;
}

/**
 * @name mul_app_send_loop_status 
 * @brief Send loop detection status to controller 
 * @param [in] status Status of the loop detection
 * 
 * @retval int 0 for success and non 0 for failure
 */
int
mul_app_send_loop_status(uint64_t status)
{
    struct cbuf *b;

    b = mul_app_prep_loop_status(status);
    return mul_app_command_handler(NULL, b);
}

/**
 * @name mul_app_send_tr_status 
 * @brief Send topo convergence status to controller 
 * @param [in] status Status of the loop detection
 * 
 * @retval int 0 for success and non 0 for failure
 */
int
mul_app_send_tr_status(uint64_t status)
{
    struct cbuf *b;

    b = mul_app_prep_tr_status(status);
    return mul_app_command_handler(NULL, b);
}

/**
 * @name mul_prep_send_vendor_msg 
 * @brief  Prepare a vendor message send mlapi message
 */
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

/**
 * @name mul_send_vendor_msg 
 * @brief  Send a vendor message mlapi message
 * @param [in] dpid Datapath-id of the switch
 * @param [in] vendor_id Vendor specific-id 
 * @param [in] arg  Argument pointing to vendor message buffer
 * @param [in] arg_len  Length of vendor message buffer
 * 
 * @retval int 0 for success and non 0 for failure
 */
int
mul_send_vendor_msg(uint64_t dpid, uint32_t vendor_id, void *arg, uint16_t arg_len)
{
    struct cbuf *b;

    b = mul_prep_send_vendor_msg(dpid, vendor_id, arg, arg_len);
    mul_app_command_handler(NULL, b);
    return 0;
}

/**
 * @name mul_app_act_alloc
 * @brief Allocate a action metadata strcture 
 * @param [in] mdata Main meta-data structure 
 *
 * @retval void Nothing
 */
void
mul_app_act_alloc(mul_act_mdata_t *mdata)
{
    return of_mact_alloc(mdata);
}

/**
 * @name mul_app_act_set_ctors 
 * @brief Associate a switch with action metadata for constructor init 
 * @param [in] mdata Pointer to action meta-data structure 
 * @param [in] dpid  Datapath-id
 *
 * @retval int 0 for success and no 0 for failure
 */
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

/**
 * @name mul_app_act_free
 * @brief Deallocate an action metadata structure 
 * @param [in] mdata Main meta-data structure 
 *
 * @retval void Nothing
 */
void
mul_app_act_free(mul_act_mdata_t *mdata)
{
    return of_mact_free(mdata);
}

/**
 * @name mul_app_act_buf_room
 * @brief Query the size remaining in action meta data buffer 
 * @param [in] mdata Main meta-data structure 
 *
 * @retval size_t Size of remaining buffer length
 */
size_t
mul_app_act_buf_room(mul_act_mdata_t *mdata)
{
    return of_mact_buf_room(mdata);
}

/**
 * @name mul_app_act_len
 * @brief Query the size used in action meta data buffer 
 * @param [in] mdata Main meta-data structure 
 *
 * @retval size_t Size of used buffer length
 */
size_t
mul_app_act_len(mul_act_mdata_t *mdata)
{
    return of_mact_len(mdata);
}

/**
 * @name mul_app_set_inst_write 
 * @brief Mark beginning of instruction write actions 
 * @param [in] mdata Pointer to meta-data structure 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_set_inst_apply
 * @brief Mark beginning of instruction apply actions 
 * @param [in] mdata Pointer to meta-data structure 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_inst_goto
 * @brief Constructor for instruction goto
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] table Table-id for goto
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_inst_meter
 * @brief Constructor for instruction meter
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] meter meter-id for meter instruction 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_inst_wr_meta
 * @brief Constructor for instruction metadat 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] metadata metadata for metadata instruction 
 * @param [in] metadata_mask metadata mask for metadata instruction 
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_inst_wr_meta(mul_act_mdata_t *mdata, uint64_t metadata,
                     uint64_t metadata_mask)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->inst_wr_meta) {
        if (!ctors->inst_wr_meta(mdata, metadata, metadata_mask)) {
            return -1;
        }
    } else {
        c_log_err("%s: Write Metadata not supported", FN);
        return -1;
    }

    return 0;
}

/**
 * @name mul_app_action_output 
 * @brief Constructor for action output 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] oport Output port
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_output(mul_act_mdata_t *mdata, uint32_t oport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_output) {
        return ctors->act_output(mdata, oport);
    }

    return -1;
}

/**
 * @name mul_app_action_set_queue
 * @brief Constructor for action set queue
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] queue Set queue-id
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_set_vid
 * @brief Constructor for action set vlan-id 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] vid Set vlan-id
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_vid) {
        return ctors->act_set_vid(mdata, vid);
    }
    return -1;
}

/**
 * @name mul_app_action_strip_vlan
 * @brief Constructor for action strip vlan-id 
 * @param [in] mdata Pointer to meta-data structure 
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_strip_vlan(mul_act_mdata_t *mdata)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_strip_vid) {
        return ctors->act_strip_vid(mdata);
    }
    return -1; 
}

/**
 * @name mul_app_action_set_dmac
 * @brief Constructor for action set destination mac 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] dmac Destination mac array 
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_dmac) {
        return ctors->act_set_dmac(mdata, dmac);
    }
    return -1;
}

/**
 * @name mul_app_action_set_smac
 * @brief Constructor for action set source mac 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] dmac source mac array 
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_smac) {
        return ctors->act_set_smac(mdata, smac);
    }
    return -1;
}

/**
 * @name mul_app_action_set_eth_type
 * @brief Constructor for action set ether-type
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] eth_type Ethernet type
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_push_hdr
 * @brief Constructor for action push header
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] eth_type Ethernet type for push-header
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_push_hdr(mul_act_mdata_t *mdata, uint16_t eth_type)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_push) {
        return ctors->act_push(mdata, eth_type);
    }
    return -1;
}

/**
 * @name mul_app_action_strip_mpls
 * @brief Constructor for action strip mpls
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] eth_type Inner Ethernet type 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_set_mpls_ttl
 * @brief Constructor for action set mpls ttl
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] ttl time to live value 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_set_mpls_label
 * @brief Constructor for action set mpls label
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] label label value
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_set_mpls_tc
 * @brief Constructor for action set mpls tc
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] tc tc value
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_set_mpls_bos
 * @brief Constructor for action set mpls bos 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] bos bos value ( 0 or 1)
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_dec_mpls_ttl
 * @brief Constructor for action decrement mpls ttl 
 * @param [in] mdata Pointer to meta-data structure 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_set_nw_ttl
 * @brief Constructor for action set network ttl 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] ttl  ttl value
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_dec_nw_ttl
 * @brief Constructor for action decrement network ttl 
 * @param [in] mdata Pointer to meta-data structure 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_cp_ttl
 * @brief Constructor for action decrement network ttl 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] in Bool (true if copy ttl in, false for copy ttl out)
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_strip_pbb
 * @brief Constructor for action  strip PBB header
 * @param [in] mdata Pointer to meta-data structure 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_action_set_vlan_pcp
 * @brief Constructor for action set vlan pcp
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] vlan_pcp vlan pcp value
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_vlan_pcp) {
        return ctors->act_set_vlan_pcp(mdata, vlan_pcp);
    }
    return -1;
}

/**
 * @name mul_app_action_set_nw_saddr
 * @brief Constructor for action set IP source address
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] nw_saddr Source IP address 
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_nw_saddr(mul_act_mdata_t *mdata, uint32_t nw_saddr) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_saddr) {
       return  ctors->act_set_nw_saddr(mdata, nw_saddr);
    }
    return -1;
}

/**
 * @name mul_app_action_set_nw_daddr
 * @brief Constructor for action set IP destination address
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] nw_daddr Destination IP address 
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_nw_daddr(mul_act_mdata_t *mdata, uint32_t nw_daddr) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_daddr) {
        return ctors->act_set_nw_daddr(mdata, nw_daddr);
    }
    return -1;
}

/**
 * @name mul_app_action_set_nw_saddr6
 * @brief Constructor for action set IPv6 source address
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] nw_saddr Source IPv6 address 
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_nw_saddr6(mul_act_mdata_t *mdata, uint8_t *nw_saddr) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_saddr6) {
       return  ctors->act_set_nw_saddr6(mdata, nw_saddr);
    }
    return -1;
}

/**
 * @name mul_app_action_set_nw_daddr6
 * @brief Constructor for action set IPv6 destination address
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] nw_daddr Destination IPv6 address 
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_nw_daddr6(mul_act_mdata_t *mdata, uint8_t *nw_daddr) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_daddr6) {
        return ctors->act_set_nw_daddr6(mdata, nw_daddr);
    }
    return -1;
}

/**
 * @name mul_app_action_set_nw_tos
 * @brief Constructor for action set network ToS
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] tos Set network TOS
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos) 
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_nw_tos) {
        return ctors->act_set_nw_tos(mdata, tos);
    }
    return -1;
}

/**
 * @name mul_app_action_set_tp_udp_sport
 * @brief Constructor for action set udp L4 source port 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] sport source port
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t sport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tp_udp_sport) {
        return ctors->act_set_tp_udp_sport(mdata, sport);
    }
    return -1;
}

/**
 * @name mul_app_action_set_tp_udp_dport
 * @brief Constructor for action set udp L4 destination port 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] dport destination port
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t dport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tp_udp_dport) {
        return ctors->act_set_tp_udp_dport(mdata, dport);
    }
    return -1;
}

/**
 * @name mul_app_action_set_tp_tcp_sport
 * @brief Constructor for action set tcp L4 source port 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] sport source port
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t sport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tp_tcp_sport) {
        return ctors->act_set_tp_tcp_sport(mdata, sport);
    }
    return -1;
}

/**
 * @name mul_app_action_set_tp_tcp_dport
 * @brief Constructor for action set tcp L4 destination port 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] dport destination port
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t dport)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tp_tcp_dport) {
        return ctors->act_set_tp_tcp_dport(mdata, dport);
    }
    return -1;
}

/**
 * @name mul_app_action_set_group
 * @brief Constructor for action set group 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] group group-id
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_group(mul_act_mdata_t *mdata, uint32_t group)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_group) {
        return ctors->act_set_group(mdata, group);
    }
    return -1;
}

/**
 * @name mul_app_action_set_tunnel_id
 * @brief Constructor for action set tunnel-id
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] tunnel tunnel-id
 *
 * @retval int 0 for success and non 0 for error 
 */
int
mul_app_action_set_tunnel_id(mul_act_mdata_t *mdata, uint64_t tunnel)
{
    struct c_ofp_ctors *ctors = mdata->ofp_ctors;

    if (ctors && ctors->act_set_tunnel) {
        return ctors->act_set_tunnel(mdata, tunnel);
    }
    return -1;
}

/**
 * @name mul_app_set_band_drop
 * @brief Constructor for preparing a drop meter band 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] parms Pointer to meter band parms 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_set_band_dscp
 * @brief Constructor for preparing a dscp meter band 
 * @param [in] mdata Pointer to meta-data structure 
 * @param [in] parms Pointer to meter band parms 
 *
 * @retval int 0 for success and non 0 for error 
 */
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

/**
 * @name mul_app_core_conn_available
 * @brief Checks if default core controller connection is available
 */
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

    vty_out(vty, "0x%16llx ", (unsigned long long)sw->dpid);
    vty_out(vty, "0x%-5d ", sw->ofp_ver);
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

    vty_out(vty, "%16s %5s %18s %s%s", "DP-id", "ver",
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
