/**
 *  @file mul_fabric.c
 *  @brief Mul fabric application main   
 *  @author Dipjyoti Saikia  <dipjyoti.saikia@gmail.com> 
    @copyright Copyright (C) 2012, Dipjyoti Saikia 
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

#include "mul_fabric_common.h"

/* Fabric application context */
fab_struct_t *fab_ctx;

extern struct mul_app_client_cb fab_app_cbs;

static void
fabric_service_handler(void *fab_service, struct cbuf *b);

/** 
 * fab_timer_event -
 *
 * timer for handling fabric events 
 */
static void
fab_timer_event(evutil_socket_t fd UNUSED, short event UNUSED,
                void *arg)
{
    fab_struct_t    *fab_ctx  = arg;
    struct timeval  tv    = { FAB_TIMER_SEC_INT, FAB_TIMER_USEC_INT};

    fab_route_per_sec_timer(fab_ctx);

    evtimer_add(fab_ctx->fab_timer_event, &tv);
}

/**
 * @name    fab_pkt_rcv 
 * @brief   Handler for packet receive events 
 * @ingroup Fabric Application 
 *
 * @param [in] sw Pointer to infra switch pointer
 * @param [in] fl Pointer to flow structure 
 * @param [in] inport The inport of the received packet 
 * @param [in] buffer_id Buffer id of the received packet 
 * @param [in] raw Pointer to the raw packet 
 * @param [in] pkt_len Packet length 
 *
 * @retval void Nothing
 *
 */
static void
fab_pkt_rcv(mul_switch_t *sw, struct flow *fl, uint32_t inport,
            uint32_t buffer_id, uint8_t *raw, size_t pkt_len)
{
    if (fab_ctx->fab_learning == FAB_PROXY_ARP_ENABLED) {
        if (fl->dl_type == htons(ETH_TYPE_ARP)) {
            return fab_arp_rcv(NULL, fab_ctx, fl, inport, raw, sw->dpid);
        } else {
            fab_dhcp_rcv(NULL, fab_ctx,  fl, inport, raw, pkt_len, sw->dpid);
        }
    } else {
	    if (fl->dl_type != htons(ETH_TYPE_ARP)) {
	        fab_dhcp_rcv(NULL, fab_ctx, fl, inport, raw, pkt_len, sw->dpid);
	    }
        return fab_host_tracker(NULL, fab_ctx, fl, inport, raw, sw->dpid,
                                pkt_len, buffer_id);
    }
}


/**
 * @name    fab_switch_add_notifier 
 * @brief   switch add notifier handler 
 * @ingroup Fabric Application 
 *
 * @param [in] sw Pointer to infra switch pointer
 *
 * @retval void Nothing
 *
 */
static void
fab_switch_add_notifier(mul_switch_t *sw)
{
    if (fab_switch_add(fab_ctx, sw->dpid, sw->alias_id)) {
        c_log_err("%s: Failed", FN);
        return;
    }

    fab_add_dhcp_tap_per_switch(NULL, sw->dpid);

    if(fab_ctx->fab_learning == FAB_PROXY_ARP_ENABLED) {
        fab_add_arp_tap_per_switch(NULL, sw->dpid);
    }
    else {
        fab_add_all_flows_per_switch(sw->dpid);
    }
}


/**
 * @name    fab_switch_del_notifier 
 * @brief   switch del notifier handler 
 * @ingroup Fabric Application 
 *
 * @param [in] sw Pointer to infra switch pointer
 *
 * @retval void Nothing
 *
 */
static void
fab_switch_del_notifier(mul_switch_t *sw)
{
    fab_switch_del(fab_ctx, sw->dpid);
    fab_reset_all_routes(fab_ctx);
}

/**
 * @name    fab_port_add_cb
 * @brief   switch port add notifier handler 
 * @ingroup Fabric Application 
 *
 * @param [in] sw Pointer to infra switch pointer
 * @param [in] port Pointer to infra port pointer
 *
 * @retval void Nothing
 *
 */
static void
fab_port_add_cb(mul_switch_t *sw,  mul_port_t *port)
{
    fab_switch_t *fab_sw;

    fab_sw = fab_switch_get(fab_ctx, sw->dpid);
    if (!fab_sw) {
        c_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(sw->dpid));
        return;
    }

    fab_port_add(fab_ctx, fab_sw, port->port_no, port->config, port->state); 
    fab_activate_all_hosts_on_switch_port(fab_ctx, sw->dpid, port->port_no);
    fab_switch_put(fab_sw);
}

 
/**
 * @name    fab_port_del_cb
 * @brief   switch port del notifier handler 
 * @ingroup Fabric Application 
 *
 * @param [in] sw Pointer to infra switch pointer
 * @param [in] port Pointer to infra port pointer
 *
 * @retval void Nothing
 *
 */
static void
fab_port_del_cb(mul_switch_t *sw,  mul_port_t *port)
{
    fab_switch_t *fab_sw;

    fab_sw = fab_switch_get(fab_ctx, sw->dpid);
    if (!fab_sw) {
        c_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(sw->dpid));
        return;
    }

    fab_port_delete(fab_ctx, fab_sw, port->port_no);
    fab_delete_routes_with_port(fab_ctx, sw->alias_id, port->port_no);
    fab_switch_put(fab_sw);
}


/**
 * @name fab_port_chg
 * @brief Application port change callback 
 */
static void
fab_port_chg(mul_switch_t *sw,  mul_port_t *port, bool adm, bool link)
{
    fab_switch_t *fab_sw;

    fab_sw = fab_switch_get(fab_ctx, sw->dpid);
    if (!fab_sw) {
        c_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(sw->dpid));
        return;
    }

    fab_port_update(fab_ctx, fab_sw, port->port_no, port->config, port->state);
    if (adm && link) {
        fab_ctx->rt_scan_all_pending = true;
    } else if (!adm || !link) {
        fab_delete_routes_with_port(fab_ctx, sw->alias_id, port->port_no);
    }
    fab_switch_put(fab_sw);
}


/** 
 * @name fab_recv_err_msg -
 * @brief Handler for error notifications from controller/switch 
 */
static void
fab_recv_err_msg(mul_switch_t *sw UNUSED, uint16_t type, uint16_t code,
                 uint8_t *raw UNUSED, size_t raw_len UNUSED)
{
    c_log_err("%s: Controller sent error type %hu code %hu",
              FN, type, code);

    /* FIXME : Handle errors */
}

/**
 * @name fab_ha_sync_slave
 * @brief Sync all hosts info to peer app
 */
static void
fab_ha_sync_slave(fab_struct_t *fab_ctx)
{
    struct fab_host_service_arg iter_arg = { true, NULL,
                                            (send_cb_t)mul_app_ha_proc };

    c_log_debug("%s", FN);
	c_rd_lock(&fab_ctx->lock);
    __fab_loop_all_hosts(fab_ctx, fabric_service_send_host_info, &iter_arg);
    __fab_loop_all_inactive_hosts(fab_ctx, fabric_service_send_host_info, &iter_arg);
	c_rd_unlock(&fab_ctx->lock);
}


/**
 * @name fab_ha_state_transition
 * @brief Handler for ha state notifications from controller/switch
 * @param [in] ha_new New HA state
 *             HA_STATE_NONE (0)
 *             HA_STATE_CONNECTED (1)
 *             HA_STATE_MASTER (2)
 *             HA_STATE_SLAVE (3)
 *
 */
static void
fab_ha_state_transition(fab_struct_t *fab_ctx UNUSED, uint32_t ha_old UNUSED,
                        uint32_t ha_new)
{
    if (ha_new == C_HA_STATE_MASTER) {
        fab_ha_sync_slave(fab_ctx);
	}
}

/**
 * @name fab_ha_status_recv -
 * @brief Receive the HA status from peer
 */
static void
fab_ha_status_recv(uint32_t ha_sysid UNUSED, uint32_t ha_new_state)
{
    uint32_t ha_old_state;

    ha_old_state = fab_ctx->ha_state;
    c_log_err("%s: C_OFPT_HA old state : %d current state : %d", FN, 
			  ha_old_state, ha_new_state);

    fab_ha_state_transition(fab_ctx, ha_old_state, ha_new_state);
    fab_ctx->ha_state = ha_new_state;
}

/**
 * @name fab_core_closed
 * @brief Core connection closed notification
 */
static void
fab_core_closed(void)
{
    c_log_info("%s: ", FN);
    return;
}

/**
 * @name fab_core_reconn
 * @brief Core connection re-established notification
 */
static void
fab_core_reconn(void)
{
    c_log_info("%s:Core rejoin  ", FN);
    mul_register_app_cb(NULL, FAB_APP_NAME,
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, &fab_app_cbs);
}

/**
 * @name fab_app_cbs
 * @brief Fabric app notifier callbacks
 */
struct mul_app_client_cb fab_app_cbs = {
    .switch_priv_alloc = NULL,
    .switch_priv_free = NULL,
    .switch_add_cb =  fab_switch_add_notifier,
    .switch_del_cb = fab_switch_del_notifier,
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = fab_port_add_cb,
    .switch_port_del_cb = fab_port_del_cb,
    .switch_port_chg = fab_port_chg,
    .switch_packet_in = fab_pkt_rcv,
    .switch_error = fab_recv_err_msg,
    .core_conn_closed = fab_core_closed,
    .core_conn_reconn = fab_core_reconn,
    .app_ha_state = fab_ha_status_recv
};

/**
 * @name fabric_service_success
 * @brief sends success message to service requester
 */
static void
fabric_service_success(void *fab_service)
{
    struct cbuf             *new_b;
    struct c_ofp_auxapp_cmd *cofp_aac;

    new_b = of_prep_msg(sizeof(*cofp_aac), C_OFPT_AUX_CMD, 0);

    cofp_aac = (void *)(new_b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_SUCCESS);

    c_service_send(fab_service, new_b);
}

/**
 * @name fabric_put_route_elem
 */
static void
fabric_put_route_elem(void *rt_arg, void *u_arg)
{
    struct c_ofp_route_link *cofp_rl = *(struct c_ofp_route_link **)(u_arg);
    rt_path_elem_t *rt_elem = rt_arg;
    fab_switch_t *fab_sw = NULL;

    fab_sw = fab_switch_get_with_alias(fab_ctx, rt_elem->sw_alias);
    if (!fab_sw) {
        /* We cant fail here so pretend */
        cofp_rl->datapath_id = 0;
    } else {
        cofp_rl->datapath_id = htonll(fab_sw->dpid);
    }

    if (fab_sw) fab_switch_put(fab_sw);

    cofp_rl->src_link = htons(rt_elem->link.la);
    cofp_rl->dst_link = htons(rt_elem->link.lb);
    
    *(struct c_ofp_route_link **)(u_arg) = cofp_rl + 1;
}


/**
 * @name fab_service_send_single_route
 */
static void
fab_service_send_single_route(void *route, void *fab_service)
{
    fab_route_t *froute = route;
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_route *cofp_r;
    struct c_ofp_route_link *cofp_rl;
    size_t n_links = g_slist_length(froute->iroute);
    uint64_t dpid = 0;
    
    b = of_prep_msg(sizeof(*cofp_aac) +
                    sizeof(*cofp_r) + (n_links * sizeof(*cofp_rl)),
                    C_OFPT_AUX_CMD, 0);
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_FAB_ROUTE);
    cofp_r = (void *)(cofp_aac->data);
    cofp_rl = (void *)(cofp_r->route_links);

    fab_dump_single_host_to_flow(froute->src, &cofp_r->src_host.host_flow, &dpid);
    cofp_r->src_host.switch_id.datapath_id = htonll(dpid);
    memcpy(cofp_r->src_host.tenant_id, froute->src->tenant_id, sizeof(uuid_t));
    memcpy(cofp_r->src_host.network_id, froute->src->network_id, sizeof(uuid_t));

    fab_dump_single_host_to_flow(froute->dst, &cofp_r->dst_host.host_flow, &dpid);
    cofp_r->dst_host.switch_id.datapath_id = htonll(dpid);
    memcpy(cofp_r->dst_host.tenant_id, froute->dst->tenant_id, sizeof(uuid_t));
    memcpy(cofp_r->dst_host.network_id, froute->dst->network_id, sizeof(uuid_t));

    mul_route_path_traverse(froute->iroute, fabric_put_route_elem,
                            (void *)(&cofp_rl));

    c_service_send(fab_service, b);
}

/**
 * @name __fabric_service_show_host_route
 */
static void
__fabric_service_show_host_route(void *host_arg, void *value UNUSED,
                                 void *fab_service)
{
    fab_loop_all_host_routes(host_arg, fab_service_send_single_route,
                             fab_service);
}

/**
 * @name fabric_service_show_route
 * @brief service handler for route show 
 */
static void
fabric_service_show_routes(void *fab_service)
{
    fab_loop_all_hosts(fab_ctx, (GHFunc)__fabric_service_show_host_route, fab_service);

    return fabric_service_success(fab_service); 
}

/**
 * @name fabric_service_show_host_route 
 */
static void
fabric_service_show_host_route(void *fab_service, struct cbuf *b, 
				               struct c_ofp_auxapp_cmd *cofp_aac)
{
    struct c_ofp_host_mod *cofp_hm;

    if (ntohs(cofp_aac->header.length) <
              sizeof(*cofp_aac) + sizeof(*cofp_hm)) {
        c_log_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(cofp_aac->header.length),
                  (unsigned long)(sizeof(*cofp_aac) + sizeof(*cofp_hm)));
        goto err;
    }

    cofp_hm = (void *)(cofp_aac->data);
    fab_find_host_route(fab_ctx, &cofp_hm->host_flow, cofp_hm->tenant_id, 
                        cofp_hm->network_id,
			            fab_service_send_single_route, fab_service);
   
    return fabric_service_success(fab_service);

err:
    return c_service_send_error(fab_service, b, OFPET_BAD_REQUEST,
                                OFPBRC_BAD_GENERIC);
}
/**
 * @name fabric_service_send_host_info
 */
void
fabric_service_send_host_info(void *host, void *v_arg UNUSED,
                              void *iter_arg)
{
    struct c_ofp_host_mod *cofp_hm;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct cbuf *b;
    uint64_t dpid = 0;
	struct fab_host_service_arg *serv_send_arg = iter_arg;

    b = of_prep_msg(sizeof(*cofp_aac) + sizeof(*cofp_hm), C_OFPT_AUX_CMD, 0);
    cofp_aac = (void *)(b->data);
	if (serv_send_arg->add) { 
    	cofp_aac->cmd_code = htonl(C_AUX_CMD_FAB_HOST_ADD);
	} else {
    	cofp_aac->cmd_code = htonl(C_AUX_CMD_FAB_HOST_DEL);
	}
    cofp_hm = (void *)(cofp_aac->data);

    fab_dump_single_host_to_flow(host, &cofp_hm->host_flow, &dpid);
    cofp_hm->switch_id.datapath_id = htonll(dpid);

    memcpy(cofp_hm->tenant_id, ((fab_host_t*) host)->tenant_id, sizeof(uuid_t));
    memcpy(cofp_hm->network_id, ((fab_host_t*) host)->network_id, sizeof(uuid_t));

	assert(serv_send_arg->send_cb);
	serv_send_arg->send_cb(serv_send_arg->serv, b);
}

/**
 * @name fabric_service_show_hosts
 * @brief Service handler for host show 
 */
static void
fabric_service_show_hosts(void *fab_service, bool active)
{
	struct fab_host_service_arg iter_arg = { true, fab_service, c_service_send };
    if (active) {
        fab_loop_all_hosts(fab_ctx, fabric_service_send_host_info, &iter_arg); 
    } else {
        fab_loop_all_inactive_hosts(fab_ctx, fabric_service_send_host_info,
                                    &iter_arg);
    }

    return fabric_service_success(fab_service); 
}

/**
 * @name fabric_service_host_mod
 * @brief service handler for host add/del
 */
static void
fabric_service_host_mod(void *fab_service, struct cbuf *b,
                        struct c_ofp_auxapp_cmd *cofp_aac,
                        bool add)
{
    int ret = -1;
    struct c_ofp_host_mod *cofp_hm;
    
    c_log_debug("%s: %s", FN, add ? "add": "del");

    if (ntohs(cofp_aac->header.length) < 
              sizeof(*cofp_aac) + sizeof(*cofp_hm)) {
        c_log_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(cofp_aac->header.length),
                  (unsigned long)(sizeof(*cofp_aac) + sizeof(*cofp_hm)));
        goto err;
    }

    cofp_hm = (void *)(cofp_aac->data);

    if (add) {
        ret = fab_host_add(fab_ctx, ntohll(cofp_hm->switch_id.datapath_id),
                           &cofp_hm->host_flow, cofp_hm->tenant_id,
                           cofp_hm->network_id, true);
    } else {
        ret = fab_host_delete(fab_ctx, &cofp_hm->host_flow, 
                cofp_hm->tenant_id, cofp_hm->network_id, 
                false, false, true);
                           
    }

    if (!ret) {
        return fabric_service_success(fab_service); 
    }

err:
    return c_service_send_error(fab_service, b, OFPET_BAD_REQUEST,
                                OFPBRC_BAD_GENERIC);
}

/**
 * @name fabric_service_send_tenant_id
 * @brief Sends tenant network info to client
 */
void
fabric_service_send_tenant_nw(void *tenant, void *v_arg UNUSED, void *fab_service)
{
    struct c_ofp_tenant_nw_mod * cofp_tnm;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct cbuf *b;
 
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
                    sizeof(struct c_ofp_tenant_nw_mod),
                    C_OFPT_AUX_CMD, 0);
   
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_FAB_SHOW_TENANT_NW);
    cofp_tnm = (void *)(cofp_aac->data);

    memcpy(cofp_tnm->tenant_id, ((fab_tenant_net_t*) tenant)->tenant_id, sizeof(uuid_t));
    memcpy(cofp_tnm->network_id, ((fab_tenant_net_t*) tenant)->network_id, sizeof(uuid_t));
    c_service_send(fab_service, b);

}

/**
 * @name fabric_service_show_tenant_nw
 * @brief service handler for tenant list show
 */
static void
fabric_service_show_tenant_nw(void *fab_service)
{
    fab_loop_all_tenant_nw(fab_ctx, (GHFunc)fabric_service_send_tenant_nw, fab_service );

    return fabric_service_success(fab_service);
}

/**
 * @name fabric_service_port_tnid_mod
 * @brief Service handler for add/del port_tnid
 */
static void
fabric_service_port_tnid_mod(void *fab_service, struct cbuf *b,
			   struct c_ofp_auxapp_cmd *cofp_aac,
			   bool add)
{
    int ret = -1;
    struct c_ofp_port_tnid_mod *cofp_ptm;

    c_log_debug("%s: %s", FN, add ? "add" : "del");
    if (ntohs(cofp_aac->header.length) <
	sizeof(*cofp_aac) + sizeof(*cofp_ptm)){
	c_log_err("%s : Size err(%lu) of (%lu)", FN,
		  (unsigned long)ntohs(cofp_aac->header.length),
		  (unsigned long)(sizeof(*cofp_aac) + sizeof(*cofp_ptm)));
	goto err;
    }

    cofp_ptm = (void *)(cofp_aac->data);
    if(add) {
	ret = fab_port_tnid_add(fab_ctx, cofp_ptm->tenant_id, cofp_ptm->network_id,
				       ntohll(cofp_ptm->datapath_id),
				       ntohl(cofp_ptm->port));
    } else {
	ret = fab_port_tnid_delete(fab_ctx, cofp_ptm->tenant_id, cofp_ptm->network_id,
				       ntohll(cofp_ptm->datapath_id),
				       ntohl(cofp_ptm->port));
    }

    if (!ret) {
	return fabric_service_success(fab_service);
    }

err:
    return c_service_send_error(fab_service, b, OFPET_BAD_REQUEST,
                                OFPBRC_BAD_GENERIC);
}

/**
 * @name fabric_service_send_port_tnid
 * @brief service handler for port_tnid list show
 */
void
fabric_service_send_port_tnid(void *port_tnid, void *v_arg UNUSED, void *fab_service)
{
    struct c_ofp_port_tnid_mod * cofp_ptm;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct cbuf *b;
    uint64_t datapath_id;
    uint32_t port;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
                    sizeof(struct c_ofp_port_tnid_mod),
                    C_OFPT_AUX_CMD, 0);
    
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_FAB_PORT_TNID_ADD);
    cofp_ptm = (void *)(cofp_aac->data);

    datapath_id = ((fab_port_tnid_t *)port_tnid)->pt_hkey.datapath_id;
    port = ((fab_port_tnid_t *)port_tnid)->pt_hkey.port;

    cofp_ptm->datapath_id = htonll(datapath_id);
    cofp_ptm->port = htonl(port);
    memcpy(cofp_ptm->tenant_id, ((fab_port_tnid_t*) port_tnid)->tenant_id, sizeof(uuid_t));
    memcpy(cofp_ptm->network_id, ((fab_port_tnid_t*) port_tnid)->network_id, sizeof(uuid_t));
    c_service_send(fab_service, b);

}

/**
 * @name fabric_service_send_port_tnid
 * @brief Service handler for port_tnid list show
 */
static void
fabric_service_port_tnid_show(void *fab_service)
{
    fab_loop_all_port_tnids(fab_ctx, fabric_service_send_port_tnid,fab_service );
    return fabric_service_success(fab_service);
}

/**
 * @name fabric_service_handler
 * @brief mlapi service requests handler
 */
static void
fabric_service_handler(void *fab_service, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        app_rlog_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(cofp_aac->header.length),
                  (unsigned long)(sizeof(struct c_ofp_auxapp_cmd)));
        return c_service_send_error(fab_service, b, OFPET_BAD_REQUEST,
                                    OFPBRC_BAD_LEN);
    }
    switch(ntohl(cofp_aac->cmd_code)) {
    case C_AUX_CMD_FAB_HOST_ADD:
        return fabric_service_host_mod(fab_service, b, cofp_aac,
                                       true);
    case C_AUX_CMD_FAB_HOST_DEL:
        return fabric_service_host_mod(fab_service, b, cofp_aac,
                                       false);
    case C_AUX_CMD_FAB_SHOW_ACTIVE_HOSTS:
        return fabric_service_show_hosts(fab_service, true);
    case C_AUX_CMD_FAB_SHOW_INACTIVE_HOSTS:
        return fabric_service_show_hosts(fab_service, false);
    case C_AUX_CMD_FAB_SHOW_ROUTES:
        return fabric_service_show_routes(fab_service);
    case C_AUX_CMD_FAB_SHOW_TENANT_NW:
	return fabric_service_show_tenant_nw(fab_service);
    case C_AUX_CMD_FAB_PORT_TNID_ADD:
	return fabric_service_port_tnid_mod(fab_service, b, cofp_aac, true);
    case C_AUX_CMD_FAB_PORT_TNID_DEL:
	return fabric_service_port_tnid_mod(fab_service, b, cofp_aac, false);
    case C_AUX_CMD_FAB_PORT_TNID_SHOW:
	return fabric_service_port_tnid_show(fab_service);
    case C_AUX_CMD_FAB_SHOW_HOST_ROUTE:
	return fabric_service_show_host_route(fab_service, b, cofp_aac);
    default:
        c_service_send_error(fab_service, b, OFPET_BAD_REQUEST,
                             OFPBRC_BAD_GENERIC);
    }

}

#ifdef FAB_USE_CONX
static void
fab_conx_service_conn_event(void *serv_arg UNUSED, unsigned char
        conn_event)
{
    app_log_err("%s: %d", FN, conn_event);
    if (conn_event == MUL_SERVICE_UP) {

        /* When ConX reconnects, it might have lost some of the information
         * and can go out of sync. Make all the info STALE at ConX and send
         * the latest info again*/
        mul_conx_stale(fab_ctx->fab_conx_service, FAB_APP_COOKIE);
        fab_add_all_routes(fab_ctx);
    }
}
#endif

/**
 * @name fabric_module_init
 * @brief Fabric application main entry point 
 */
void
fabric_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval    tv = { FAB_TIMER_SEC_INT, FAB_TIMER_USEC_INT };
    char fab_learn_str[FAB_STR_SZ], *str;
    
    FILE *fp = NULL;
    char c ;

    c_log_debug("%s", FN);

    fab_ctx = fab_zalloc(sizeof(fab_struct_t));

    fab_ctx->base = base;
    c_rw_lock_init(&fab_ctx->lock);

    fab_ctx->host_htbl = g_hash_table_new_full(fab_host_hash_func,
                                               fab_host_equal_func,
                                               NULL, __fab_host_delete);
    assert(fab_ctx->host_htbl);

    fab_ctx->inact_host_htbl = g_hash_table_new_full(fab_host_hash_func,
                                               fab_host_equal_func,
                                               NULL, __fab_host_delete);
    assert(fab_ctx->inact_host_htbl);

    fab_ctx->tenant_net_htbl = g_hash_table_new_full(fab_tenant_nw_hash_func,
                                                 fab_tenant_nw_equal_func,
                                                 NULL, NULL);
    assert(fab_ctx->tenant_net_htbl);

    fab_ctx->port_tnid_htbl = g_hash_table_new_full(fab_port_tnid_hash_func,
						fab_port_tnid_equal_func,
						NULL, NULL);
    assert(fab_ctx->port_tnid_htbl);

    fab_switches_init(fab_ctx);

    fab_ctx->fab_timer_event = evtimer_new(base,
                                           fab_timer_event,
                                           (void *)fab_ctx);

    fab_ctx->fab_cli_service = mul_app_create_service(MUL_FAB_CLI_SERVICE_NAME,
                                                      fabric_service_handler);
    assert(fab_ctx->fab_cli_service);

#ifndef FAB_USE_CONX
    fab_ctx->route_service = mul_app_get_service(MUL_ROUTE_SERVICE_NAME, NULL);
    assert(fab_ctx->route_service);

#else
    fab_ctx->fab_conx_service =
        mul_app_get_service_notify(MUL_CONX_CONF_SERVICE_NAME,
                fab_conx_service_conn_event, true,
                NULL);

    if(!fab_ctx->fab_conx_service)
        app_log_err("ConX service is not alive!");
#endif

    evtimer_add(fab_ctx->fab_timer_event, &tv);

    mul_register_app_cb(NULL, FAB_APP_NAME, 
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, &fab_app_cbs);

    /* By default Host tracker feature will be disabled */
    fab_ctx->fab_learning = FAB_PROXY_ARP_ENABLED;
    fp = fopen("/etc/mul/fabric.cfg","r");
    if( fp != NULL) {
        c = fscanf(fp,"%s",fab_learn_str); 
        if(c != EOF) {
            str = strtok(fab_learn_str, "=");
            if(!strcmp(str,"HOST_TRACKER")) {
                str = strtok(NULL, "=");

                if(!strcmp(str,"ON")) { 
                    fab_ctx->fab_learning = FAB_HOST_TRACKER_ENABLED;
                }
            }

        }
    }

    if (fab_ctx->fab_learning == FAB_HOST_TRACKER_ENABLED)
        app_log_info("Fabric mode is reactive");
    else
        app_log_info("Fabric mode is proactve");
    
   
    return;
}

/**
 * @name fabric_module_vty_init
 * @brief Fabric application's vty entry point 
 */
void
fabric_module_vty_init(void *arg)
{
    c_log_debug("%s:", FN);

    fabric_vty_init(arg);
}

module_init(fabric_module_init);
module_vty_init(fabric_module_vty_init);
