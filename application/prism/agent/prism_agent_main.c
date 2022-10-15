/*
 *  prism_agent_main.c: PRISM agent application for MUL Controller 
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
#include "config.h"
#include "mul_common.h"
#include <linux/if_tun.h>
#include "mul_vty.h"
#include "prism_agent.h"
#include "prism_common.h"

struct prism_agent_ctx *CTX;

static void prism_agent_service_handler(void *prism_service, struct cbuf *b);

/**
 * prism_agent_service_success
 *
 * Sends success message to service requester
 */
static void
prism_agent_service_success(void *prism_service)
{
    struct cbuf *new_b;
    struct prism_success_msg *success_msg;
    size_t len;

    len = sizeof(struct prism_success_msg);
    new_b = alloc_cbuf(len);

    success_msg = cbuf_put(new_b, len);

    success_msg->hdr.version = OFP_VERSION;
    success_msg->hdr.cmd = PRISM_SERVICE_SUCCESS;
    success_msg->hdr.len = htons(sizeof(struct prism_success_msg));

    c_service_send(prism_service, new_b);
}

/**
 * prism_agent_service_error
 *
 * Sends error message to service requester in case of error 
 */
static void UNUSED
prism_agent_service_error(void *prism_service, uint32_t type, uint32_t code)
{
    struct cbuf *new_b;
    struct prism_error_msg *err_msg;
    size_t len;

    len = sizeof(struct prism_error_msg);
    new_b = alloc_cbuf(len);

    err_msg = cbuf_put(new_b, len);

    err_msg->hdr.version = OFP_VERSION;
    err_msg->hdr.cmd = PRISM_SERVICE_ERROR;
    err_msg->hdr.len = htons(sizeof(struct prism_error_msg));
    err_msg->type = htonl(type);
    err_msg->code = htonl(code);

    c_service_send(prism_service, new_b);
}

static void
prism_vif_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

/**
 * prism_process_packet_in -
 *
 * Process packet-in events
 * Does not send back any notification
 */
static void
prism_process_packet_in(void *prism_service UNUSED,
                        struct prism_packet_in *pkt_in)
{
    struct cbuf *new_b;
    size_t len;
    struct prism_vif *vif;
    uint8_t exp_mac[ETH_ADDR_LEN] = PRISM_EXP_VIF_MAC_ADDR;

    app_log_debug("%s -", FN);
    
    if (ntohs(pkt_in->hdr.len) < sizeof(struct prism_packet_in)) {
        app_log_err("%s: Size err (%hu) of (%lu)", FN,
                     (unsigned short)ntohs(pkt_in->hdr.len),
                     U322UL(sizeof(struct prism_packet_in)));
        return;
    }
    
    len = ntohs(pkt_in->hdr.len) - sizeof(struct prism_packet_in) ;
    if (!len || len > 1518) {
        app_log_err("%s: Packet-data len err", FN);
        return;
    }

    new_b = alloc_cbuf(len);
    cbuf_put(new_b, len);
    memcpy(new_b->data, pkt_in->pkt_data, len);
    
    c_rd_lock(&CTX->lock);
    vif = __prism_dp_port_to_vif(pkt_in->dpid, pkt_in->iif);
    if (!vif) {
        vif = __prism_dp_port_to_vif(PRISM_EXP_VIF_DPID, PRISM_EXP_VIF_PORT);
        if (!vif) {
            c_rd_unlock(&CTX->lock);
            app_log_err("%s: vif not found (0x%llx:%lu)", FN,
                     U642ULL(ntohll(pkt_in->dpid)),
                     U322UL(htonl(pkt_in->iif)));
            return;
        }
        if (is_unicast_ether_addr(new_b->data)) {
            memcpy(new_b->data, exp_mac, ETH_ADDR_LEN);
        }
    }

    c_conn_tx(&vif->conn, new_b, prism_vif_write_event_sched);
    c_rd_unlock(&CTX->lock);
}

static void
prism_agent_vif_mod(void *prism_service UNUSED,
                    struct prism_vif_cmd *vif_cmd,
                    bool add)
{
    struct prism_vif *vif;

    if (ntohs(vif_cmd->hdr.len) < sizeof(struct prism_vif_cmd)) {
        app_log_err("%s: Size err (%hu) of (%lu)", FN,
                  (unsigned short)ntohs(vif_cmd->hdr.len),
                  (unsigned long)(sizeof(struct prism_vif_cmd)));
        return;
    }
    
    app_log_debug("%s: vif %s for (0x%llx:%lu)", FN, add ? "add" : "del",
                   U642ULL(htonll(vif_cmd->dpid)),
                   U322UL(htonl(vif_cmd->port)));

    c_rd_lock(&CTX->lock);
    vif = __prism_dp_port_to_vif(vif_cmd->dpid, vif_cmd->port);
    if (!vif) {
        app_log_debug("%s: vif not found (0x%llx:%lu)", FN,
                       U642ULL(htonll(vif_cmd->dpid)),
                       U322UL(htonl(vif_cmd->port)));
        c_rd_unlock(&CTX->lock);
        return;
    }
    prism_vif_link_mod(CTX, vif, add);
    c_rd_unlock(&CTX->lock);
    return;
}

static void
prism_agent_vif_update(void *prism_service UNUSED, struct prism_vif_cmd *vif_cmd)
{
    struct prism_vif *vif;
    
    if (ntohs(vif_cmd->hdr.len) < sizeof(struct prism_vif_cmd)) {
        c_log_err("%s: Size err (%hu) of (%lu)", FN, 
                  (unsigned short)ntohs(vif_cmd->hdr.len),
                  (unsigned long)(sizeof(struct prism_vif_cmd)));
    
        return; 
    }
    
    c_rd_lock(&CTX->lock);
    vif = __prism_dp_port_to_vif(vif_cmd->dpid, vif_cmd->port);
    if (!vif) {
        c_rd_unlock(&CTX->lock);
        app_log_debug("%s: vif not found (0x%llx:%lu)", FN,
                       U642ULL(htonll(vif_cmd->dpid)),
                       U322UL(htonl(vif_cmd->port)));
        return; 
    }

    prism_vif_update_mac_addr(CTX, vif, vif_cmd->mac_addr); 
    c_rd_unlock(&CTX->lock);

    return;
}

static void
prism_agent_replay(void *prism_service UNUSED)
{
    if (!mul_service_available(CTX->prism_app_service)) {
        app_rlog_err("%s: %s is dead", FN,
                     CTX->prism_app_service->service_name); 
        app_log_info("%s: Replay will be done when %s is restored", FN,
                     CTX->prism_app_service->service_name); 
        CTX->need_replay = true;
        return;
    }
    prism_nl_replay_routes();
    prism_nl_replay_nh();
}

static void
prism_agent_process_port_config_replay(void *prism_service UNUSED, 
                               struct prism_edge_port_info* edge_port_info)
{
    struct prism_vif *vif;
    uint64_t dpid ;
    uint32_t port ;
    uint32_t config ;
    uint32_t state ;

    if (ntohs(edge_port_info->hdr.len) < sizeof(struct prism_edge_port_info)) {
        c_log_err("%s: Size err (%hu) of (%lu)", FN, 
                  (unsigned short)ntohs(edge_port_info->hdr.len),
                  (unsigned long)(sizeof(struct prism_edge_port_info)));
        return;
    }

    c_rd_lock(&CTX->lock);

    dpid = (edge_port_info->dpid);
    port =(uint32_t)ntohs((edge_port_info->port.port_no));
    config = ntohl(edge_port_info->port.config);
    state = ntohl(edge_port_info->port.state);

    app_log_debug("%s: (0x%llx:%u)",
                       FN, U642ULL(ntohll(dpid)), port);
    vif = __prism_dp_port_to_vif(dpid, htonl(port));
    if (!vif) {
        c_rd_unlock(&CTX->lock);
        app_log_debug("%s: vif not found (0x%llx:%u)",
                       FN, U642ULL(ntohll(dpid)), port);
        return;
    }

    if (!(vif->flags & PRISM_VIF_LIVE) && 
        !((config & PPCR_PORT_DOWN) &&
         (state & PPCR_LINK_DOWN))) {
        prism_vif_link_mod(CTX, vif, true);
        vif->flags |= PRISM_VIF_LIVE;
        app_log_debug("%s: (0x%llx:%u) Status: UP!",
                       FN, U642ULL(ntohll(dpid)), port);
    }

    if ((vif->flags & PRISM_VIF_LIVE) && 
        ((config & PPCR_PORT_DOWN) &&
          (state & PPCR_LINK_DOWN)))    {

        prism_vif_link_mod(CTX, vif, false);
        vif->flags &= ~PRISM_VIF_LIVE;
        app_log_debug("%s: (0x%llx:%u) Status: DOWN!",
                       FN, U642ULL(ntohll(dpid)), port);
    }

    if ((vif->flags & PRISM_VIF_LIVE) && 
        !((config & PPCR_PORT_DOWN) &&
         (state & PPCR_LINK_DOWN)))    {

        if (memcmp(vif->hw_addr, edge_port_info->port.hw_addr, ETH_ADDR_LEN)) {

           memcpy(vif->hw_addr, edge_port_info->port.hw_addr, ETH_ADDR_LEN);
           prism_vif_update_mac_addr(CTX, vif, edge_port_info->port.hw_addr);
            app_log_debug("%s: MAC Address updated"
                    " (0x%llx:%u:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x)",
                       FN, U642ULL(ntohll(dpid)), port,
                       vif->hw_addr[0], vif->hw_addr[1], vif->hw_addr[2],
                       vif->hw_addr[3], vif->hw_addr[4], vif->hw_addr[5]);
        }
    }

    c_rd_unlock(&CTX->lock);
    return;
}

/**
 * prism_agent_service_handler
 * 
 * Handler service requests
 */
static void
prism_agent_service_handler(void *prism_service, struct cbuf *b)
{
    struct prism_idl_hdr *idl_hdr = (void *)(b->data);

    if (ntohs(idl_hdr->len) < sizeof(struct prism_idl_hdr)) {
        c_log_err("%s: Size err (%hu) of (%lu)", FN, 
                    (unsigned short)ntohs(idl_hdr->len),
                    (unsigned long)(sizeof(struct prism_idl_hdr)));
        return; 
    }
    
    switch (idl_hdr->cmd) {
        
        case PRISM_LEGACY_PACKET_IN:
            prism_process_packet_in(prism_service, (struct prism_packet_in*)(b->data));
            break;
        case PRISM_SDN_VIRT_IF_ADD:
            prism_agent_vif_mod(prism_service, (struct prism_vif_cmd*)(b->data), true);
            break;
        
        case PRISM_SDN_VIRT_IF_DEL:
            prism_agent_vif_mod(prism_service, (struct prism_vif_cmd*)(b->data), false);
            break;
        case PRISM_SDN_VIRT_IF_UPDATE:
            prism_agent_vif_update(prism_service, (struct prism_vif_cmd*)(b->data));
            break;
        case PRISM_SERVICE_ECHO:
            prism_agent_service_success(prism_service);
            break;
        case PRISM_LEGACY_CONFIG_REPLAY:
            prism_agent_replay(prism_service);
            break;
        case PRISM_PORT_CONFIG_REPLAY:
            prism_agent_process_port_config_replay(prism_service, (struct prism_edge_port_info*)(b->data));
            break;
        default:
            break;
    }

    /* NOT REACHED */
    return;
}

static void
prism_app_service_conn_event(void *serv_arg UNUSED, unsigned char conn_event)
{
    c_log_err("%s: %d", FN, conn_event);
    if(CTX->need_replay) {
        CTX->need_replay = false;
        app_log_info("Prism APP is UP, replaying pending information");
        prism_agent_replay(serv_arg);
    }
}

static bool
prism_agent_service_ka(void *prism_service UNUSED)
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
    mul_service_t *service = CTX->prism_app_service;

    if (service->conn.dead || service->ext_ka_flag) {
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
    c_wr_lock(&CTX->serv_lock);
    c_service_send(service, new_b);
    new_b = c_service_wait_response(service);
    c_wr_unlock(&CTX->serv_lock);
    if (new_b) {
        free_cbuf(new_b);
        service->ext_ka_flag = 0;
    } else {
        service->ext_ka_flag = 1;
    }
done:
    mb();
    evtimer_add(CTX->serv_timer_event, &tv);
}


static void *
serv_monitor_main(void *arg UNUSED)
{
    struct timeval tv = { 2, 0 };

    CTX->serv_base = event_base_new(); 
    assert(CTX->serv_base);

    CTX->serv_timer_event = evtimer_new(CTX->serv_base,
                                        prism_service_validity_timer,
                                        CTX);
    evtimer_add(CTX->serv_timer_event, &tv);

    event_base_dispatch(CTX->serv_base);
    return NULL;
}

/**
 * prism_agent_init
 *
 * PRISM agent entry point
 */
void
prism_agent_init(void *base_arg)
{
    struct event_base *base = base_arg;

    c_log_debug("[%s]", FN);

    CTX = calloc(1, sizeof(struct prism_agent_ctx));
    assert(CTX);
    
    CTX->base = base;
    c_rw_lock_init(&CTX->lock);
    c_rw_lock_init(&CTX->serv_lock);

    CTX->prism_agent_service = mul_app_create_service(MUL_PRISM_AGENT_SERVICE_NAME, 
                                                      prism_agent_service_handler);
    assert(CTX->prism_agent_service);
        
    CTX->prism_app_service = mul_app_get_service_notify_ka(
                                        MUL_PRISM_APP_SERVICE_NAME, 
                                        prism_app_service_conn_event,
                                        prism_agent_service_ka, 
                                        true, NULL);
    assert(CTX->prism_app_service);
 
    if (prism_netlink_init(CTX) < 0)
        assert(0);

    prism_vif_init();

    pthread_create(&CTX->serv_thread, NULL, serv_monitor_main, CTX);

    return;
}

/**
 * prism_agent_vty_init
 *
 * PRISM agent's vty entry point
 */
void
prism_agent_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
}

module_init(prism_agent_init);
module_vty_init(prism_agent_vty_init);
