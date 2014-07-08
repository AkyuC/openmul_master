/*
 *  mul_fabric.c: Fabric application for MUL Controller 
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
#include "mul_fabric_common.h"

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
 * fab_pkt_rcv -
 *
 * Handler for packet receive events 
 */
static void
fab_pkt_rcv(mul_switch_t *sw, struct flow *fl, uint32_t inport,
            uint32_t buffer_id UNUSED, uint8_t *raw, size_t pkt_len)
{
    // fab_learn_host(opq, fab_ctx, pin);

    if (fl->dl_type == htons(ETH_TYPE_ARP)) {
        return fab_arp_rcv(NULL, fab_ctx, fl, inport, raw, sw->dpid);
    } else {
        fab_dhcp_rcv(NULL, fab_ctx,  fl, inport, raw, pkt_len, sw->dpid);
    }
}

/** 
 * fab_switch_add_notifier -
 *
 * Handler for switch add/join event
 */
static void
fab_switch_add_notifier(mul_switch_t *sw)
{
    if (fab_switch_add(fab_ctx, sw->dpid, sw->alias_id)) {
        c_log_err("%s: Failed", FN);
        return;
    }

    fab_add_arp_tap_per_switch(NULL, sw->dpid);
    fab_add_dhcp_tap_per_switch(NULL, sw->dpid);
}

/** 
 * fab_switch_del_notifier -
 *
 * Handler for switch delete event
 */
static void
fab_switch_del_notifier(mul_switch_t *sw)
{
    fab_switch_del(fab_ctx, sw->dpid);
    fab_reset_all_routes(fab_ctx);
}

/**
 * fab_port_add_cb -
 *
 * Application port add callback 
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
 * fab_port_del_cb -
 *
 * Application port del callback 
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
 * fab_port_chg -
 *
 * Application port change callback 
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
 * fab_recv_err_msg -
 *
 * Handler for error notifications from controller/switch 
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
 * fab_core_closed -
 */
static void
fab_core_closed(void)
{
    c_log_info("%s: ", FN);
    return;
}

/**
 * fab_core_reconn -
 */
static void
fab_core_reconn(void)
{
    c_log_info("%s:Core rejoin  ", FN);
    mul_register_app_cb(NULL, FAB_APP_NAME,
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, &fab_app_cbs);
}

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
};

/**
 * fabric_service_error -
 *
 * Sends error message to service requester in case of error 
 */
static void
fabric_service_error(void *tr_service, struct cbuf *b,
                     uint16_t type, uint16_t code)
{
    struct cbuf       *new_b;
    c_ofp_error_msg_t *cofp_em;
    void              *data;
    size_t            data_len;

    data_len = b->len > C_OFP_MAX_ERR_LEN?
                    C_OFP_MAX_ERR_LEN : b->len;

    new_b = of_prep_msg(sizeof(*cofp_em) + data_len, C_OFPT_ERR_MSG, 0);

    cofp_em = (void *)(new_b->data);
    cofp_em->type = htons(type);
    cofp_em->code = htonl(code);

    data = (void *)(cofp_em + 1);
    memcpy(data, b->data, data_len);

    c_service_send(tr_service, new_b);
}


/**
 * fabric_service_success -
 *
 * Sends success message to service requester
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
 * fabric_put_route_elem -
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
 * fab_service_send_single_route -
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

    fab_dump_single_host_to_flow(froute->dst, &cofp_r->dst_host.host_flow, &dpid);
    cofp_r->dst_host.switch_id.datapath_id = htonll(dpid);

    mul_route_path_traverse(froute->iroute, fabric_put_route_elem,
                            (void *)(&cofp_rl));

    c_service_send(fab_service, b);
}

/**
 * __fabric_service_show_host_route -
 */
static void
__fabric_service_show_host_route(void *host_arg, void *value UNUSED,
                                 void *fab_service)
{
    fab_loop_all_host_routes(host_arg, fab_service_send_single_route,
                             fab_service);
}

/**
 * fabric_service_show_route -
 *
 * Service handler for route show 
 */
static void
fabric_service_show_routes(void *fab_service)
{
    fab_loop_all_hosts(fab_ctx, (GHFunc)__fabric_service_show_host_route, fab_service);

    return fabric_service_success(fab_service); 
}


/**
 * fabric_service_send_host_info -
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

	assert(serv_send_arg->send_cb);
	serv_send_arg->send_cb(serv_send_arg->serv, b);
}

/**
 * fabric_service_show_hosts -
 *
 * Service handler for host show 
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
 * fabric_service_host_mod -
 *
 * Service handler for host add/del
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
                           &cofp_hm->host_flow, true);
    } else {
        ret = fab_host_delete(fab_ctx, &cofp_hm->host_flow, false, false, true);
                           
    }

    if (!ret) {
        return fabric_service_success(fab_service); 
    }

err:
    return fabric_service_error(fab_service, b, OFPET_BAD_REQUEST,
                                OFPBRC_BAD_GENERIC);
}

/**
 * fabric_service_handler -
 *
 * Handler service requests 
 */
static void
fabric_service_handler(void *fab_service, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        c_log_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(cofp_aac->header.length),
                  (unsigned long)(sizeof(struct c_ofp_auxapp_cmd)));
        return fabric_service_error(fab_service, b, OFPET_BAD_REQUEST,
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
    default:
        fabric_service_error(fab_service, b, OFPET_BAD_REQUEST,
                             OFPBRC_BAD_GENERIC);
    }

}

/**
 * fabric_module_init -
 *
 * Fabric application entry point 
 */
void
fabric_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval    tv = { FAB_TIMER_SEC_INT, FAB_TIMER_USEC_INT };
    
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

    fab_switches_init(fab_ctx);

    fab_ctx->fab_timer_event = evtimer_new(base,
                                           fab_timer_event,
                                           (void *)fab_ctx);

    fab_ctx->fab_cli_service = mul_app_create_service(MUL_FAB_CLI_SERVICE_NAME,
                                                      fabric_service_handler);
    assert(fab_ctx->fab_cli_service);

    fab_ctx->route_service = mul_app_get_service(MUL_ROUTE_SERVICE_NAME, NULL);
    assert(fab_ctx->route_service);

    evtimer_add(fab_ctx->fab_timer_event, &tv);

    mul_register_app_cb(NULL, FAB_APP_NAME, 
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, &fab_app_cbs);

    return;
}

/**
 * fabric_module_vty_init -
 *
 * Fabric application's vty entry point 
 */
void
fabric_module_vty_init(void *arg)
{
    c_log_debug("%s:", FN);

    fabric_vty_init(arg);
}

module_init(fabric_module_init);
module_vty_init(fabric_module_vty_init);
