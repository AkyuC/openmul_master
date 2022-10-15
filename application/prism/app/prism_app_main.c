/*
 *  prism_app_main.c: PRISM application for MUL Controller 
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "prism_app.h"
#include "prism_common.h"
#include "prism_app_route.h"
#include "prism_app_nh.h"
#include "prism_app_vif.h"
#include "mul_patricia.h"

prism_app_struct_t *prism_ctx;

extern struct mul_app_client_cb prism_app_cbs;

void prism_add_route_via_conx(void *elem, void *key_arg UNUSED, void
        *u_arg UNUSED);
void prism_delete_route_via_conx(void *elem, void *key_arg UNUSED, void
        *u_arg UNUSED);
static void prism_nh_mark_entry_stale_all(bool* need_replay);

static void prism_sync_wait_timer(void);

static void
prism_service_handler(void *prism_service, struct cbuf *b);

/** 
 * prism_pkt_rcv -
 *
 * Handler for packet receive events 
 */
static void
prism_pkt_rcv(mul_switch_t *sw, struct flow *fl UNUSED, uint32_t inport,
            uint32_t buffer_id UNUSED, uint8_t *pkt, size_t pkt_len)
{
    /* TODO: Filtering required */
    /* Packets only from edge ports must be passed to Agent*/

    struct prism_packet_in *pkt_in;
    struct cbuf       *new_b = NULL;
    void              *data = NULL;
    struct eth_header *eth = NULL;
    size_t rem_len = pkt_len;
    size_t len = 0;

    eth = PRISM_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
    rem_len -= sizeof(*eth);

    if((eth->eth_type != htons(ETH_TYPE_ARP)) &&
            eth->eth_type != htons(ETH_TYPE_IP)) {
        app_log_err("DPID: %llx Port %d : Unwanted pkt recvd, Dropped!",
                U642ULL(sw->dpid), inport);
        return;
    }
#if 0
    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        /* Extract the dst ip from packet */
        ip = PRISM_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*ip);
        nw_dst = ntohl(ip->ip_dst);

        /* Route Look up in Patrcia Tree */
        pfind = mul_pat_search(nw_dst, prism_ctx->ptree);

        /* Check whether it is present in the tree or not */
        if(pfind->pat_key == (nw_dst & pfind->pat_mask->pm_mask)) {
            app_log_info("%s: Route Entry Present %08lx: ", FN, pfind->pat_key);
        }
        else {
            /* Route lookup is failed, Drop the packet! */
            app_log_err("%s: Route Lookup(%08lx) failed, Packet Dropped!!!",
                    FN, htonl(nw_dst));
            return;
        }

        rt_flags = *(uint32_t *)pfind->pat_mask->pm_data;

        /* Check the dst IP in NH Hash table */
        nh_key.next_hop = nw_dst;
        nh_key.dpid = sw->dpid;
        nh_key.oif = inport;
        /* Check if the entry is present in the NH Hash Table */
        if((nh_elem = g_hash_table_find(prism_ctx->nh_hasher_db,
                        prism_compare_nh_key,
                        &nh_key))) {

            /* Check if Next Hop is resolved */
            if(nh_elem->nh_flags == NH_REACHABLE ||
                    nh_elem->nh_flags == NH_PERMANENT) {
                rt_elem = calloc(1, sizeof(prism_rt_elem_t));
                rt_elem->hkey.dst_nw = nw_dst;
                rt_elem->hkey.dst_nm = 0xffffffff;
                rt_elem->rt_flags = RT_DIRECT;
                rt_elem->nh_ptr = nh_elem;

                /* Install the flows through Fabric App */
                prism_add_route_via_conx(rt_elem, NULL, NULL);

                free(rt_elem);
                app_log_err("Unexpected case: L3 pkt recvd and NH is"\
                        " already resolved, Dropped!");
                return;
            }
            else {
                /* If Next Hop is unresolved then forward the packet 
                 * to Prism Agent */
                app_log_debug("Pkt recvd from Indirect Host, Next Hop is not resolved");
                goto fwd_pkt;
            }
        }
        else {
            /* If Next Hop is not present in NH Hash table then 
             * forward the packet to Prism Agent */
            app_log_debug("Pkt recvd from Direct Host, Next Hop entry is not present");
            goto fwd_pkt;
        }
    }
    else {
        app_log_err("Unwanted pkt recvd, Dropped!");
        return;
    }

#endif

    /* Forward the packet to Prism Agent */
    len = sizeof(struct prism_packet_in) + pkt_len;

    new_b = alloc_cbuf(len);

    pkt_in = cbuf_put(new_b, len);

    pkt_in->hdr.cmd = PRISM_LEGACY_PACKET_IN;
    pkt_in->hdr.len = htons(sizeof(struct prism_packet_in) + pkt_len);
    pkt_in->hdr.version = OFP_VERSION;
    pkt_in->dpid = htonll(sw->dpid);
    pkt_in->iif = htonl(inport);
    pkt_in->pkt_len = htonl(pkt_len);

    data = (void *)(pkt_in->pkt_data);
    memcpy(data, pkt, pkt_len);

    if(prism_app_service_send(prism_ctx->prism_agent_service, new_b,
                false, PRISM_SERVICE_SUCCESS)) {
        app_log_err("%s: Packet-In is not recvd properly at agent", FN);
    }
    else {
        app_log_debug("DPID: %llx Port %d : Packet forwarded to Agent",
                U642ULL(sw->dpid), inport);
    }
}

/** 
 * prism_switch_add_notifier -
 *
 * Handler for switch add/join event
 */
static void
prism_switch_add_notifier(mul_switch_t *sw)
{
    if (prism_switch_add(prism_ctx, sw->dpid, sw->alias_id)) {
        app_log_err("%s: Failed to add switch", FN);
        return;
    }
}

/** 
 * prism_switch_del_notifier -
 *
 * Handler for switch delete event
 */
static void
prism_switch_del_notifier(mul_switch_t *sw)
{
    prism_switch_del(prism_ctx, sw->dpid);
}

/**
 * prism_port_add_cb -
 *
 * Application port add callback 
 */
static void
prism_port_add_cb(mul_switch_t *sw,  mul_port_t *port)
{
    prism_switch_t *prism_sw;
    prism_vif_elem_t *vif_elem;
    struct prism_vif_hash_key vif_hkey;

    memset(&vif_hkey, 0, sizeof(struct prism_vif_hash_key));

    prism_sw = prism_switch_get(prism_ctx, sw->dpid);
    if (!prism_sw) {
        app_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(sw->dpid));
        return;
    }

    vif_hkey.port = port->port_no;
    vif_hkey.dpid = sw->dpid;

    c_rd_lock(&prism_ctx->lock);
    if((vif_elem = g_hash_table_lookup(prism_ctx->vif_hasher_db, 
                    &vif_hkey))) {
        prism_port_add(prism_ctx, prism_sw, port->port_no, port->config,
                port->state, port->hw_addr); 
    } 
    c_rd_unlock(&prism_ctx->lock);
    prism_switch_put(prism_sw);

    prism_replay_all_nh(prism_ctx, &vif_hkey);
}

 
/**
 * prism_port_del_cb -
 *
 * Application port del callback 
 */
static void
prism_port_del_cb(mul_switch_t *sw,  mul_port_t *port)
{
    prism_switch_t *prism_sw;
    prism_vif_elem_t *vif_elem;
    struct prism_vif_hash_key vif_hkey;
    memset(&vif_hkey, 0, sizeof(struct prism_vif_hash_key));

    prism_sw = prism_switch_get(prism_ctx, sw->dpid);
    if (!prism_sw) {
        app_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(sw->dpid));
        return;
    }
    
    vif_hkey.port = port->port_no;
    vif_hkey.dpid = sw->dpid;

    c_rd_lock(&prism_ctx->lock);
    if((vif_elem = g_hash_table_lookup(prism_ctx->vif_hasher_db, 
                    &vif_hkey))) {

        prism_port_delete(prism_ctx, prism_sw, port->port_no, PPCR_PORT_DOWN,
                          PPCR_LINK_DOWN); 
        
    } else {
        app_log_warn("%s: DPID %llx Port %u not an edge port", FN,
                U642ULL(sw->dpid), port->port_no);
    }
    c_rd_unlock(&prism_ctx->lock);
    prism_switch_put(prism_sw);
}


/**
 * prism_port_chg -
 *
 * Application port change callback 
 */
static void
prism_port_chg(mul_switch_t *sw,  mul_port_t *port , bool adm UNUSED,
        bool link UNUSED)
{
    prism_switch_t *prism_sw;
    prism_vif_elem_t *vif_elem;
    struct prism_vif_hash_key vif_hkey;
    memset(&vif_hkey, 0, sizeof(struct prism_vif_hash_key));

    prism_sw = prism_switch_get(prism_ctx, sw->dpid);
    if (!prism_sw) {
        app_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(sw->dpid));
        return;
    }
    
    vif_hkey.port = port->port_no;
    vif_hkey.dpid = sw->dpid;

    c_rd_lock(&prism_ctx->lock);
    if((vif_elem = g_hash_table_lookup(prism_ctx->vif_hasher_db, 
                    &vif_hkey))) {

        prism_port_update(prism_ctx, prism_sw, port->port_no, port->config,
                port->state, port->hw_addr);

    } else {
        app_log_warn("%s: DPID %llx Port %u not an edge port", FN,
                U642ULL(sw->dpid), port->port_no);
    }
    c_rd_unlock(&prism_ctx->lock);

    prism_switch_put(prism_sw);
}


/** 
 * prism_recv_err_msg -
 *
 * Handler for error notifications from controller/switch 
 */
static void
prism_recv_err_msg(mul_switch_t *sw UNUSED, uint16_t type, uint16_t code,
                 uint8_t *raw UNUSED, size_t raw_len UNUSED)
{
    app_log_err("%s: Controller sent error type %hu code %hu",
              FN, type, code);

    /* FIXME : Handle errors */
}

/**
 * prism_core_closed -
 */
static void
prism_core_closed(void)
{
    app_log_info("%s: ", FN);
    return;
}

/**
 * prism_core_reconn -
 */
static void
prism_core_reconn(void)
{
    app_log_info("%s:Core rejoin  ", FN);
    mul_register_app_cb(NULL, PRISM_APP_NAME,
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, &prism_app_cbs);
}

struct mul_app_client_cb prism_app_cbs = {
    .switch_priv_alloc = NULL,
    .switch_priv_free = NULL,
    .switch_add_cb =  prism_switch_add_notifier,
    .switch_del_cb = prism_switch_del_notifier,
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = prism_port_add_cb,
    .switch_port_del_cb = prism_port_del_cb,
    .switch_port_chg = prism_port_chg,
    .switch_packet_in = prism_pkt_rcv,
    .switch_error = prism_recv_err_msg,
    .core_conn_closed = prism_core_closed,
    .core_conn_reconn = prism_core_reconn,
    //.app_ha_state = prism_ha_status_recv
};

/**
 * prism_service_error -
 *
 * Sends error message to service requester in case of error 
 */
static void
prism_service_error(void *prism_service, uint32_t type, uint32_t code)
{
    struct cbuf       *new_b;
    size_t len;
    struct prism_error_msg *err_msg;

    len = sizeof(struct prism_error_msg);

    new_b = alloc_cbuf(len);

    err_msg = cbuf_put(new_b, len);

    err_msg->hdr.cmd = PRISM_SERVICE_ERROR;
    err_msg->hdr.len = htons(sizeof(struct prism_error_msg));
    err_msg->hdr.version = OFP_VERSION;
    err_msg->type = htonl(type);
    err_msg->code = htonl(code);

    c_service_send(prism_service, new_b);
}


/**
 * prism_service_success -
 *
 * Sends success message to service requester
 */
static void
prism_service_success(void *prism_service)
{
    struct cbuf       *new_b;
    struct prism_success_msg *success_msg;
    size_t len;

    len = sizeof(struct prism_success_msg);

    new_b = alloc_cbuf(len);

    success_msg = cbuf_put(new_b, len);

    success_msg->hdr.cmd = PRISM_SERVICE_SUCCESS;
    success_msg->hdr.len = htons(sizeof(struct prism_success_msg));

    success_msg->hdr.version = OFP_VERSION;

    c_service_send(prism_service, new_b);
}

/**
 * prism_legacy_route_mod-
 *
 * Service handler for legacy route add/del
 */
static void
prism_legacy_route_mod(void *prism_service UNUSED,
                        struct prism_ipv4_rt_cmd *rt_cmd,
                        bool add)
{
    uint32_t code = 0;
    uint32_t dst_nw;
    uint32_t dst_nm;
    uint32_t nh;
    uint64_t dpid;
    uint32_t oif;
    uint32_t rt_flags;

    if (ntohs(rt_cmd->hdr.len) < 
              sizeof(struct prism_ipv4_rt_cmd)) {
        app_log_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(rt_cmd->hdr.len),
                  (unsigned long)(sizeof(struct prism_ipv4_rt_cmd)));
        code = PRTM_LENGTH_ERROR;
        return;
    }
    app_log_debug("%s: %s", FN, add ? "add": "del");

    dst_nw = ntohl(rt_cmd->dst_nw);
    dst_nm = ntohl(rt_cmd->dst_nm);
    nh = ntohl(rt_cmd->nh);
    dpid = ntohll(rt_cmd->dpid);
    oif = ntohl(rt_cmd->oif);
    rt_flags = ntohl(rt_cmd->rt_flags);

    if(rt_flags == RTN_LOCAL) {
        app_log_info("%s: Local Route Add with interface IP 0x%x Port %u",
                FN, dst_nw, oif);
        code = prism_vif_modify(prism_ctx, dpid, oif, 0, NULL, true,
                                add ? dst_nw : 0);
        prism_route_mod_self(prism_ctx, dst_nw, dpid, add);
        return;
    }

    if (add) {
        code = prism_route_add(prism_ctx, dst_nw, dst_nm, nh, dpid, oif);
    } else {
        code = prism_route_delete(prism_ctx, dst_nw, dst_nm, true);
    }
    if (code) {
        app_log_err("%s: Failed", FN);
    }
}

/**
 * prism_next_hop_state_mod-
 *
 * Service handler for next hop ARP state resolved/unresolved
 */
static void
prism_next_hop_state_mod(void *prism_service UNUSED, 
                        struct prism_ipv4_nh_cmd *nh_cmd,
                        bool add)
{
    uint32_t code = 0;
    uint32_t nh;
    uint32_t oif;
    uint64_t dpid;
    uint32_t nh_flags;

    if (ntohl(nh_cmd->hdr.len) < 
              sizeof(struct prism_ipv4_nh_cmd)) {
        app_log_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohl(nh_cmd->hdr.len),
                  (unsigned long)(sizeof(struct prism_ipv4_nh_cmd)));
        code = PNHM_LENGTH_ERROR;       
        return;
    }
    
    nh = ntohl(nh_cmd->nh);
    oif = ntohl(nh_cmd->oif);
    dpid = ntohll(nh_cmd->dpid);
    nh_flags = ntohl(nh_cmd->nh_flags);

    app_log_debug("%s: %s", FN, add ? "add": "del");

    if (add) {
       code = prism_next_hop_add(prism_ctx, nh, dpid, oif, nh_flags,
               nh_cmd->mac_addr);
    } else {
       code = prism_next_hop_del(prism_ctx, nh, dpid, oif);
    }
    if (code) {
        app_log_err("%s: Failed", FN);
    }
}

/**
 * prism_sdn_vif_mod
 *
 * Service handler for SDN Virtual Interface ADD/DEL/MODIFY
 */
static void
prism_sdn_vif_mod(void *prism_service UNUSED, 
                  struct prism_vif_cmd *vif_cmd,
                  uint8_t cmd)
{
    uint32_t code = 0;
    uint32_t port;
    uint64_t dpid;
    uint32_t if_flags;

    if (ntohl(vif_cmd->hdr.len) < 
              sizeof(struct prism_vif_cmd)) {
        app_log_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohl(vif_cmd->hdr.len),
                  (unsigned long)(sizeof(struct prism_vif_cmd)));
        code = PNHM_LENGTH_ERROR;       
        return;
    }
    
    port = ntohl(vif_cmd->port);
    dpid = ntohll(vif_cmd->dpid);
    if_flags = ntohl(vif_cmd->if_flags);

    switch(cmd) {
        case PRISM_VIF_ADD:
            code = prism_vif_add(prism_ctx, dpid, port, if_flags,
                    vif_cmd->mac_addr);
            break;
        case PRISM_VIF_DEL:
            code = prism_vif_del(prism_ctx, dpid, port);
            break;
        case PRISM_VIF_UPDATE:
            code = prism_vif_modify(prism_ctx, dpid, port, if_flags,
                    vif_cmd->mac_addr, false, 0);
            break;
    }
    if (code) {
        app_log_err("%s: Failed", FN);
    }
}

/**
 * prism_process_packet_out-
 *
 * Service handler for packet out
 */
static void
prism_process_packet_out(void *prism_service , struct prism_packet_out *pkt_out)
{
    struct of_pkt_out_params parms;
    struct mul_act_mdata mdata;
    uint64_t dpid;
    uint32_t port;
    uint32_t pkt_len = 0;
    int ret = 0;

    if (ntohs(pkt_out->hdr.len) < 
              sizeof(struct prism_packet_out) + ntohl(pkt_out->pkt_len)) {
        app_log_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(pkt_out->hdr.len),
                  (unsigned long)(sizeof(struct prism_packet_out) +
                      ntohl(pkt_out->pkt_len)));
        return prism_service_error(prism_service,
                PRISM_LEGACY_PKT_OUT_FAILED,
                PLPO_LENGTH_ERROR);
    }

    dpid = ntohll(pkt_out->dpid);
    port = ntohl(pkt_out->oif);
    pkt_len = ntohl(pkt_out->pkt_len);

    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    if((ret = mul_app_act_set_ctors(&mdata, dpid))) {
        app_log_err("%s: cant assign ctors for DPID %llx", FN, U642ULL(dpid));
        mul_app_act_free(&mdata);
        return;
    }
    if((ret = mul_app_action_output(&mdata, port)) < 0) {
        app_log_err("%s: cant set act_output for DPID %llx port %u", FN,
                U642ULL(dpid), port);
        mul_app_act_free(&mdata);
        return;
    }
    parms.buffer_id = 0xFFFFFFFF;
    parms.in_port = OF_NO_PORT;
    parms.action_list = mdata.act_base;
    parms.action_len = mul_app_act_len(&mdata);
    parms.data_len = pkt_len;
    parms.data = pkt_out->pkt_data;
    mul_app_send_pkt_out(NULL, dpid, &parms);
    mul_app_act_free(&mdata);
    app_log_debug("%s: PKT_OUT DPID %llx port %u", FN,
                U642ULL(dpid), port);
}

/**
 * prism_service_handler -
 *
 * Handler service requests 
 */
static void
prism_service_handler(void *prism_service, struct cbuf *b)
{
    struct prism_idl_hdr *idl_hdr = (void *)(b->data);
    if (ntohs(idl_hdr->len) < sizeof(struct prism_idl_hdr)) {
        app_log_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(idl_hdr->len),
                  (unsigned long)(sizeof(struct prism_idl_hdr)));
         prism_service_error(prism_service, PRISM_IDL_LENGTH_ERROR, 0);
        return;
    }

    switch(idl_hdr->cmd) {
    case PRISM_LEGACY_RT_ADD:
         prism_legacy_route_mod(prism_service, 
                 (struct prism_ipv4_rt_cmd*) (b->data),
                                       true);
         break;
    case PRISM_LEGACY_RT_DEL:
         prism_legacy_route_mod(prism_service,
                 (struct prism_ipv4_rt_cmd*) (b->data),
                                       false);
         break;
    case PRISM_LEGACY_NH_ADD:
         prism_next_hop_state_mod(prism_service,
                 (struct prism_ipv4_nh_cmd*) (b->data),
                                       true);
         break;
    case PRISM_LEGACY_NH_DEL:
         prism_next_hop_state_mod(prism_service,
                 (struct prism_ipv4_nh_cmd*)(b->data),
                                       false);
         break;
    case PRISM_LEGACY_PACKET_OUT:
         prism_process_packet_out(prism_service,(struct prism_packet_out*)(b->data));
         break;

    case PRISM_SDN_VIRT_IF_ADD:
         prism_sdn_vif_mod(prism_service,
                 (struct prism_vif_cmd*) (b->data),
                 PRISM_VIF_ADD);
         break;

    case PRISM_SDN_VIRT_IF_DEL:
         prism_sdn_vif_mod(prism_service,
                 (struct prism_vif_cmd*) (b->data),
                 PRISM_VIF_DEL);
         break;

    case PRISM_SDN_VIRT_IF_UPDATE:
         prism_sdn_vif_mod(prism_service,
                 (struct prism_vif_cmd*) (b->data),
                 PRISM_VIF_UPDATE);
         break;

    case PRISM_SERVICE_ECHO:
         prism_service_success(prism_service);
         break;

    default:
         app_log_err("%s: Unsupported message(%u) recvd at PRISM APP", FN,
                 idl_hdr->cmd);
    }
}

/**
 * __prism_delete- 
 * @buf: buffer to be freed 
 *
 * Frees the allocated buffer
 */
static void 
__prism_delete(void *buf)
{
    free(buf);
}

static void 
prism_app_sw_info_replay(void)
{
    prism_traverse_all_switch(prism_ctx, (GHFunc)prism_send_edge_node_msg,
            NULL);
}

static void
prism_app_send_legacy_config_msg(void *prism_service)
{
    struct prism_legacy_config_replay *lcr = NULL;
    size_t len = 0;
    struct cbuf *b = NULL;

    len = sizeof(sizeof(struct prism_legacy_config_replay));
    b = alloc_cbuf(len);

    lcr = cbuf_put(b , len);
    lcr->hdr.version = OFP_VERSION;
    lcr->hdr.cmd = PRISM_LEGACY_CONFIG_REPLAY;
    lcr->hdr.len = htons(len);
    if(prism_app_service_send(prism_service, b, false, PRISM_SERVICE_SUCCESS)) {
        app_log_err("%s: Failed to send LEGACY_CONFIG_REPLAY request to "\
                "Prism Agent", FN);
    } else {
        app_log_info("%s: LEGACY_CONFIG_REPLAY request sent to Prism Agent",
                FN);
    }
}

static void
prism_agent_service_conn_event(void *serv_arg UNUSED, unsigned char conn_event)
{
    bool *need_replay = calloc(1, sizeof(bool));

    *need_replay = false;

    app_log_err("%s: %d", FN, conn_event);

    if (conn_event == MUL_SERVICE_UP) {

        /* Marking all the Next Hop entries as STALE*/
        prism_nh_mark_entry_stale_all(need_replay);

        /* When agent reconnects, it might have lost all the information
         * and will go out of sync. Send the latest info again*/
        prism_app_sw_info_replay();
        
        /* Asking the agent to send all the routes and Next Hop info again*/
        prism_app_send_legacy_config_msg(prism_ctx->prism_agent_service);
    }
}

static void
prism_conx_service_conn_event(void *serv_arg UNUSED, unsigned char
        conn_event)
{
    app_log_err("%s: %d", FN, conn_event);
    if (conn_event == MUL_SERVICE_UP) {

        /* When ConX reconnects, it might have lost some of the information
         * and can go out of sync. Make all the info STALE at ConX and send
         * the latest info again*/
        mul_conx_stale(prism_ctx->prism_conx_service, PRISM_APP_COOKIE);
        prism_replay_all_nh(prism_ctx, NULL);
    }
}

static void
prism_mul_service_conn_event(void *serv_arg UNUSED, unsigned char
        conn_event)
{
    bool *need_replay = calloc(1, sizeof(bool));
    struct timeval tv = { 3, 0 };

    /* Need to free this variable in the call back function for timer expiry*/
    *need_replay = true;

    app_log_err("%s: %d", FN, conn_event);

    if (conn_event == MUL_SERVICE_UP) {

        /* Marking all the Next Hop entries as STALE*/
        prism_nh_mark_entry_stale_all(need_replay);

        /* Running timer for Syncing with agent tp get all the routes 
           and Next Hop info again*/
        evtimer_add(prism_ctx->sync_timer_event, &tv);
    } else {
        
        /* Deleting timer for Syncing with agent tp get all the routes 
           and Next Hop info again*/
        evtimer_del(prism_ctx->sync_timer_event);
    }
    
}

static bool 
prism_app_service_ka(void *prism_service UNUSED)
{
    return true;
}

static void
prism_service_validity_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                             void *arg UNUSED)
{
    struct prism_service_echo_msg *prism_echo_msg;
    struct cbuf *new_b;
    size_t len;
    struct timeval tv = { 10, 0 };
    uint32_t tx_pkts;
    mul_service_t *service = prism_ctx->prism_agent_service;

    if (service->conn.dead || service->ext_ka_flag) {
        app_log_err("%s: Conn Dead!", FN);
        goto done;
    }
    
    tx_pkts = service->last_tx_pkts;
    service->last_tx_pkts = service->conn.tx_pkts;

    if (tx_pkts != service->conn.tx_pkts)
        goto done;

    len = sizeof(struct prism_service_echo_msg);
    new_b = alloc_cbuf(len);
    prism_echo_msg = cbuf_put(new_b, len);
    prism_echo_msg->hdr.version = OFP_VERSION;
    prism_echo_msg->hdr.cmd = PRISM_SERVICE_ECHO;
    prism_echo_msg->hdr.len = htons(sizeof(struct prism_service_echo_msg));
    c_wr_lock(&prism_ctx->serv_lock);
    c_service_send(service, new_b);
    new_b = c_service_wait_response(service);
    c_wr_unlock(&prism_ctx->serv_lock);
    if (new_b) {
        free_cbuf(new_b);
        service->ext_ka_flag = 0;
    } else {
        service->ext_ka_flag = 1;
    }
done:
    mb();
    evtimer_add(prism_ctx->serv_timer_event, &tv);
}

static void *
serv_monitor_main(void *arg UNUSED)
{
    struct timeval tv = { 1, 0 };

    prism_ctx->serv_base = event_base_new();
    assert(prism_ctx->serv_base);

    prism_ctx->serv_timer_event = evtimer_new(prism_ctx->serv_base,
                                        prism_service_validity_timer,
                                        prism_ctx);
    evtimer_add(prism_ctx->serv_timer_event, &tv);

    event_base_dispatch(prism_ctx->serv_base);
    return NULL;
}

static void
prism_sync_timer_expiry(evutil_socket_t fd UNUSED, short event UNUSED,
                             void *arg UNUSED)
{
    app_log_info("%s: Sync Wait Timer expires", FN);
    prism_app_send_legacy_config_msg(prism_ctx->prism_agent_service);
}

static void 
prism_sync_wait_timer(void)
{
    struct timeval tv = { 3, 0 };

    prism_ctx->sync_timer_event = evtimer_new(prism_ctx->base,
                                        prism_sync_timer_expiry,
                                        prism_ctx);
    evtimer_add(prism_ctx->sync_timer_event, &tv);
}

static void
prism_nh_clear_stale_entry_all(evutil_socket_t fd UNUSED, short event UNUSED,
                          void *arg)
{

    app_log_info("%s: Next Hop clean STALE entry timer expires..", FN);

    prism_loop_all_nh_remove(prism_ctx, __prism_nh_clear_stale_entry_single, arg);
    
    free(arg);
}

static void 
prism_nh_mark_entry_stale_all(bool* need_replay)
{
    struct timeval tv = { 10, 0 };


    prism_loop_all_nh(prism_ctx, __prism_nh_make_entry_stale_single, NULL);

    prism_ctx->nh_stale_timer_event = evtimer_new(prism_ctx->base,
                                        prism_nh_clear_stale_entry_all,
                                        need_replay);
    evtimer_add(prism_ctx->nh_stale_timer_event, &tv);
}

static void
prism_prepare_dpid_list(void *key UNUSED, void *elem, void *u_arg)
{
    prism_vif_elem_t *vif_elem = (prism_vif_elem_t *) elem;
    uint64_t *dpid_list = *(uint64_t **) u_arg;

    *dpid_list = vif_elem->hkey.dpid;
    *(uint64_t **) u_arg = (dpid_list + 1);
}

/**
 * prism_module_init -
 *
 * PRISM application entry point 
 */
static void
prism_app_init(void *base_arg)
{
    struct pat_tree *phead;
    struct pat_tree_mask *pm;
    struct event_base *base = base_arg;
    size_t num_dpid = 0;
    uint64_t *dpid_list = NULL;
    uint64_t *p_dpid_list = NULL;
    app_log_debug("%s", FN);

    prism_ctx = calloc(1, sizeof(prism_app_struct_t));

    assert(prism_ctx);

    prism_ctx->base = base;
    c_rw_lock_init(&prism_ctx->lock);
    c_rw_lock_init(&prism_ctx->serv_lock);

    prism_ctx->route_hasher_db = g_hash_table_new_full(prism_route_hash_func,
                                               prism_route_equal_func,
                                               NULL, __prism_delete);
    assert(prism_ctx->route_hasher_db);

    prism_ctx->nh_hasher_db = g_hash_table_new_full(g_int_hash,
                                               g_int_equal,
                                               NULL, __prism_delete);
    assert(prism_ctx->nh_hasher_db);
    
    prism_ctx->vif_hasher_db = g_hash_table_new_full(prism_vif_hash_func,
                                               prism_vif_equal_func,
                                               NULL, __prism_delete);
    assert(prism_ctx->vif_hasher_db);

    prism_switches_init(prism_ctx);

    prism_ctx->prism_cli_service = mul_app_create_service(MUL_PRISM_CLI_SERVICE_NAME,
                                                          prism_service_handler);
    assert(prism_ctx->prism_cli_service);

    prism_ctx->prism_app_service =
        mul_app_create_service(MUL_PRISM_APP_SERVICE_NAME,
                               prism_service_handler);
    assert(prism_ctx->prism_app_service);
   
    prism_ctx->prism_agent_service =
        mul_app_get_service_notify_ka(MUL_PRISM_AGENT_SERVICE_NAME,
                prism_agent_service_conn_event, prism_app_service_ka, true,
                NULL);

    if(!prism_ctx->prism_agent_service)
        app_log_err("Agent service is not alive!");

    prism_ctx->prism_conx_service =
        mul_app_get_service_notify(MUL_CONX_CONF_SERVICE_NAME,
                prism_conx_service_conn_event, true,
                NULL);

    if(!prism_ctx->prism_conx_service)
        app_log_err("ConX service is not alive!");

    mul_conx_stale(prism_ctx->prism_conx_service, PRISM_APP_COOKIE);

    prism_ctx->prism_mul_service =
        mul_app_get_service_notify(MUL_CORE_SERVICE_NAME,
                prism_mul_service_conn_event, true,
                NULL);
    if(!prism_ctx->prism_mul_service)
        app_log_err("MUL Core is not alive!");

    /* 
     * Initialize the Patricia trie by doing the following:
     *   1. Assign the head pointer a default route/default node
     *   2. Give it an address of 0.0.0.0 and a mask of 0x00000000
     *      (matches everything)
     *   3. Set the bit position (pat_bit) to 0.
     *   4. Set the number of masks to 1 (the default one).
     *   5. Point the head's 'left' and 'right' pointers to itself.
     */

    phead = (struct pat_tree *)calloc(1, sizeof(struct pat_tree));
    
    phead->pat_mask = (struct pat_tree_mask *)calloc( 1,
            sizeof(struct pat_tree_mask));
    
    pm = phead->pat_mask;
    pm->pm_data = (struct pat_rt_elem_data *)malloc(sizeof(struct
                pat_rt_elem_data));

    /* Fill in default route/default node data here */
    phead->pat_mask_len = 1;
    phead->pat_left = phead->pat_right = phead;

    prism_ctx->ptree = phead;

    /* Get virtual Interfaces Info*/
    prism_app_vif_init(prism_ctx);

    num_dpid = g_hash_table_size(prism_ctx->vif_hasher_db);

    dpid_list = calloc(num_dpid, sizeof(uint64_t));

    p_dpid_list = dpid_list;

    prism_loop_all_vif(prism_ctx, prism_prepare_dpid_list, (void*)&p_dpid_list);
    
    /* Running the timer for syncing with Prism agent*/
    prism_sync_wait_timer();

    pthread_create(&prism_ctx->serv_thread, NULL, serv_monitor_main, prism_ctx);

    mul_register_app_cb(NULL, PRISM_APP_NAME, 
                     0, C_APP_ALL_EVENTS,
                     num_dpid, dpid_list, &prism_app_cbs);

    free(dpid_list);
    
    return;
}

/**
 * prism_module_vty_init -
 *
 * PRISM application's vty entry point 
 */
void
prism_module_vty_init(void *arg)
{
    app_log_debug("%s:", FN);

    prism_vty_init(arg);
}

module_init(prism_app_init);
module_vty_init(prism_module_vty_init);
