/*  mul_tr.c: MUL topology and routing application module  
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

#include "mul_tr.h"

tr_struct_t *tr_hdl;
extern struct mul_app_client_cb lldp_app_cbs;

/**
 * __tr_get_max_switch_alias -
 */
int
__tr_get_max_switch_alias(tr_struct_t *tr)
{
    return __lldp_get_max_switch_alias(tr->topo_hdl);
}

/**
 * __tr_get_num_switches -
 */
int
__tr_get_num_switches(tr_struct_t *tr)
{
    return __lldp_get_num_switches(tr->topo_hdl);
}

/**
 * __tr_init_neigh_pair_adjacencies -
 */
void
__tr_init_neigh_pair_adjacencies(tr_neigh_query_arg_t *arg)
{
    return __lldp_init_neigh_pair_adjacencies(arg);
}

/**
 * tr_show_route_adj_matrix -
 */
char *
tr_show_route_adj_matrix(tr_struct_t *tr)
{
    char *pbuf = NULL;

    lldp_sw_rd_lock(tr->topo_hdl);

    if(tr->rt.rt_dump_adj_matrix) {
        pbuf = tr->rt.rt_dump_adj_matrix(tr);
    }

    lldp_sw_rd_unlock(tr_hdl->topo_hdl);

    return pbuf;
}

/**
 * __tr_get_route -
 *
 * Get a route
 */
GSList *
__tr_get_route(tr_struct_t *tr, int src_node, int dst_node)
{
    GSList *route = NULL;
    int num_nodes = 0;

    num_nodes = __tr_get_max_switch_alias(tr);

    if (!(num_nodes) || 
        src_node < 0 || dst_node < 0 ||
        src_node > num_nodes || dst_node > num_nodes) {
        return NULL;        
    }

    if(tr->rt.rt_get_sp) {
        route = tr->rt.rt_get_sp(tr, src_node, dst_node);
    }

    return route;
}

/**
 * tr_get_route -
 *
 * Get a route
 */
GSList *
tr_get_route(tr_struct_t *tr, int src_node, int dst_node)
{
    GSList *route = NULL;
    lldp_sw_rd_lock(tr->topo_hdl);
    route = __tr_get_route(tr, src_node, dst_node);
    lldp_sw_rd_unlock(tr_hdl->topo_hdl);

    return route;
}


/**
 * tr_dump_route -
 *
 * Dump a route for printing
 */
char *
tr_dump_route(GSList *route_path)
{
    char *pbuf = calloc(1, TR_ROUTE_PBUF_SZ);
    int len = 0;
    GSList *iterator = NULL;
    rt_path_elem_t *rt_elem = NULL;

    len += snprintf(pbuf+len, TR_ROUTE_PBUF_SZ-len-1, "iROUTE:\r\n");
    assert(len < TR_ROUTE_PBUF_SZ-1);

    for (iterator = route_path; iterator; iterator = iterator->next) {
        rt_elem = iterator->data;

        len += snprintf(pbuf+len, TR_ROUTE_PBUF_SZ-len-1,
                        "Node(%d):Link(%hu)->", 
                        rt_elem->sw_alias, rt_elem->link.la);
        assert(len < TR_ROUTE_PBUF_SZ-1);
    }


    len += snprintf(pbuf+len, TR_ROUTE_PBUF_SZ-len-1, "||\r\n");
    assert(len < TR_ROUTE_PBUF_SZ-1);

    return pbuf;
}

/**
 * tr_destroy_route -
 *
 * Destroy route. Utility wrapper over mul_destroy_route() 
 */
void
tr_destroy_route(GSList *route)
{
    return mul_destroy_route(route);
}

void
__tr_route_recalc(tr_struct_t *tr)
{
    if (tr->rt.rt_recalc) {
        tr->rt.rt_recalc(tr);
    }
}

/**
 * __tr_invoke_routing -
 *
 * Invoke routing subsystem to recalcuate all routes
 */
void
__tr_invoke_routing(tr_struct_t *tr)
{
    if (tr->rt.rt_clean_state) {
        tr->rt.rt_clean_state(tr);
    }
    if (tr->rt.rt_init_state) {
        tr->rt.rt_init_state(tr, false);
    }

    if (tr->rt.rt_calc) {
        tr->rt.rt_calc(tr);
    }

    if (!tr->rt.rt_init_trigger) {
        tr->rt.rt_init_trigger = true;
    }

    tr->loop_trigger = true;
}


/**
 * tr_invoke_routing -
 *
 * Invoke routing subsystem to recalculate all routes
 * Reclaim global lock if it is not yet held
 */
void
tr_invoke_routing(tr_struct_t *tr)
{
    int lock;

    if (!tr->rt.rt_init_trigger) {
        return;
    }

    lock = !lldp_sw_wr_trylock(tr->topo_hdl);
    __tr_invoke_routing(tr);
    if (lock) {
        lldp_sw_wr_unlock(tr->topo_hdl);
    }
}

/**
 * tr_service_error -
 *
 * Sends error message to service requester in case of error 
 */
static void 
tr_service_error(void *tr_service, struct cbuf *b,
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
 * tr_service_success -
 *
 * Sends success message to service requester
 */
static void 
tr_service_success(void *tr_service)
{
    struct cbuf             *new_b;
    struct c_ofp_auxapp_cmd *cofp_aac;

    new_b = of_prep_msg(sizeof(*cofp_aac), C_OFPT_AUX_CMD, 0);

    cofp_aac = CBUF_DATA(new_b);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_SUCCESS);

    c_service_send(tr_service, new_b);
}

/**
 * tr_service_request_neigh -
 *
 * Handle neigh request 
 */
static void
tr_service_request_neigh(void *tr_service,
                         struct cbuf *req_b,
                         struct c_ofp_auxapp_cmd *cofp_aac)
{
    struct cbuf *b;
    c_ofp_req_dpid_attr_t *req_dpid = (void *)(cofp_aac->data);

    if (ntohs(cofp_aac->header.length) < sizeof(*req_dpid)) {
        c_log_err("%s: Size err (%u) of (%lu)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*req_dpid)));
        return;
    }

    b = lldp_service_neigh_request(ntohll(req_dpid->datapath_id),
                                   cofp_aac->header.xid); 
    if (b) {
        c_service_send(tr_service, b);
    } else {
        tr_service_error(tr_service, req_b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
    }
}

/**
 * tr_service_set_loop_detect -
 *
 * Enable or disable loop detection on-demand 
 */
static void
tr_service_set_loop_detect(void *tr_service,
                           struct cbuf *req_b UNUSED,
                           struct c_ofp_auxapp_cmd *cofp_aac,
                           bool enable)
{
    if (ntohs(cofp_aac->header.length) < sizeof(*cofp_aac)) {
        c_log_err("%s: Size err (%u) of (%lu)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac)));
        return;
    }

    lldp_service_set_loop_detect(enable);
    tr_service_success(tr_service);
    c_log_debug("[loop-tr] %s", enable ? "enabled" : "disabled");
}

/**
 * tr_service_handler -
 *
 * Handler service requests 
 */
static void
tr_service_handler(void *tr_service, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        c_log_err("%s: Size err (%u) of (%lu)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(struct c_ofp_auxapp_cmd)));
        return tr_service_error(tr_service, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch(ntohl(cofp_aac->cmd_code)) {
    case C_AUX_CMD_TR_GET_NEIGH:
        return tr_service_request_neigh(tr_service, b, cofp_aac);
    default:
        tr_service_error(tr_service, b, OFPET_BAD_REQUEST, OFPBRC_BAD_GENERIC);
    }
}

/**
 * tr_create_service -
 *
 * Create a new controller service 
 */
static void * 
tr_create_service(tr_struct_t *tr_hdl UNUSED)
{
    return mul_app_create_service(MUL_TR_SERVICE_NAME, tr_service_handler);        
}

/**
 * tr_cleanall -
 *
 * Clean all info TR module is holding
 */
static void
tr_cleanall(tr_struct_t *tr)
{
    lldp_cleanall_switches(tr);
    if(tr->rt.rt_clean_state) {
        tr->rt.rt_clean_state(tr);
    }
}

/**
 * tr_core_closed - 
 */
static void
tr_core_closed(void)
{
    c_log_info("%s: ", FN);
    tr_cleanall(tr_hdl);
    return;
}

/**
 * tr_core_reconn -
 */
static void
tr_core_reconn(void)
{
    c_log_info("%s:Core rejoin  ", FN);
    mul_register_app_cb(NULL, TR_APP_NAME, C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &lldp_app_cbs);
}

/**
 * tr_module_init -
 */
void
tr_module_init(void *ctx)
{
	tr_struct_t *tr = NULL;

	c_log_debug("%s", FN);

	tr = calloc(1, sizeof(tr_struct_t));
	if (!tr) {
		c_log_err("%s: alloc failed", FN);
		return;
	}

    tr->app_ctx = ctx;
	tr_hdl = tr;

#ifdef CONFIG_MUL_RT
    mul_route_init(tr);
#endif

    tr->rt.rt_next_trigger_ts = time(NULL) + RT_INIT_TRIGGER_TS;

    mul_lldp_init(tr);
    
    tr->tr_service = tr_create_service(tr);
    if (!tr->tr_service) {
        c_log_err("%s: TR service could not be created", FN);
        /* We can still continue albeit with some limited ability */
    }

    lldp_app_cbs.core_conn_closed = tr_core_closed;
    lldp_app_cbs.core_conn_reconn = tr_core_reconn;
    
    mul_register_app_cb(NULL, TR_APP_NAME, C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &lldp_app_cbs);
}

/**
 * tr_vty_init -
 */
void
tr_vty_init(void *arg UNUSED)
{
    lldp_vty_init(tr_hdl);
    route_vty_init(tr_hdl);
}

module_init(tr_module_init);
module_vty_init(tr_vty_init);
