/*  mul_loop.c: MUL loop detection framework
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 *
 */

#include "mul_tr.h"

extern topo_hdl_t *topo_hdl;


/**
 * mul_loop_detect_reset -
 *
 * Reset internal state of Loop detection state machine
 */ 
void
mul_loop_detect_reset(bool lock)
{
    topo_hdl->loop_info.loop_reset_only = true;
    topo_hdl->loop_info.next_loop_state = LOOP_STATE_RESET;
    topo_hdl->tr->loop_trigger = true;
    mul_loop_detect(topo_hdl, lock);
}

/**
 * mul_dp_port_update -
 *
 * Apply port flags
 */
static void
mul_dp_port_update(uint64_t dpid, uint16_t port_no,
                   uint32_t config, uint32_t mask)
{
    struct of_port_mod_params pm_params;

    memset(&pm_params,0,sizeof(pm_params));
    pm_params.port_no = (uint32_t)port_no;
    pm_params.config = config;
    pm_params.mask = mask;

    mul_app_send_port_mod(dpid, &pm_params);
}


/**
 * mul_loop_port_mod -
 *
 * Get port flags corresponding to loop state 
 * and apply them
 */
void
mul_loop_port_mod(uint64_t dpid, uint32_t port_no,
                  int loop_state)
{
    uint32_t config = 0;
    uint32_t mask = 0;

    switch (loop_state) {
    case LOOP_PORT_STATUS_INIT:
        config |= OFPPC_NO_RECV| OFPPC_NO_FLOOD;
        mask |= (OFPPC_NO_RECV|OFPPC_NO_FWD|OFPPC_NO_FLOOD);
        //c_log_debug("|Loop| Init link %d on 0x%llx", port_no, dpid);
        mul_dp_port_update(dpid, port_no, config, mask);
        break;
    case LOOP_PORT_STATUS_NONE:
        mask |= (OFPPC_NO_RECV|OFPPC_NO_FWD|OFPPC_NO_FLOOD);
        //c_log_debug("|Loop| link %d on 0x%llx None ", port_no, dpid);
        mul_dp_port_update(dpid, port_no, config, mask);
        break;
    case LOOP_PORT_STATUS_DP:
    case LOOP_PORT_STATUS_RP:
        mask |= (OFPPC_NO_RECV|OFPPC_NO_FWD|OFPPC_NO_FLOOD);
        //c_log_debug("|Loop| Turning on link %d on 0x%llx", port_no, dpid);
        mul_dp_port_update(dpid, port_no, config, mask);
        break;
    case LOOP_PORT_STATUS_DP_N:
        config |= (OFPPC_NO_RECV|OFPPC_NO_FLOOD);
        mask |= (OFPPC_NO_RECV|OFPPC_NO_FLOOD);
        //c_log_debug("|Loop| Turning on link %d on 0x%llx", port_no, dpid);
        mul_dp_port_update(dpid, port_no, config, mask);
        break;
    case LOOP_PORT_STATUS_NDP:
        config |= (OFPPC_NO_RECV|OFPPC_NO_FLOOD);
        mask |= (OFPPC_NO_RECV|OFPPC_NO_FLOOD);
        mul_dp_port_update(dpid, port_no, config, mask);
        c_log_debug("|Loop| Turning off link %d on 0x%llx", port_no, U642ULL(dpid));
        break;
    default:
        break;
    }      
}

/*
 * mul_loop_rt_neigh_conn_update -
 *
 * Update the rt neigh connection to indicate block state
 */
static void
mul_loop_rt_neigh_conn_update(lldp_port_t *port, lldp_port_t *neigh_port,
                              bool block_rt)
{
    lldp_switch_t *sw = port->lldp_sw;
    lldp_switch_t *neigh_sw = neigh_port->lldp_sw;
    lweight_pair_t lw_pair;

    memset(&lw_pair, 0, sizeof(lw_pair));
    lw_pair.la = port->port_no;
    lw_pair.lb = port->neighbor_port;
    lw_pair.weight = NEIGH_NO_PATH;
    lw_pair.flags = NEIGH_FL_ONLINK;
    if (block_rt) 
        lw_pair.flags |= NEIGH_FL_BLOCK;

    if (topo_hdl->tr->rt.rt_add_neigh_conn) {
        topo_hdl->tr->rt.rt_add_neigh_conn(topo_hdl->tr,
                                           sw->alias_id,
                                           neigh_sw->alias_id,
                                           sw->dpid,
                                           neigh_sw->dpid,
                                           &lw_pair, true);
    }

    return;
}

/**
 * __mul_loop_port_update -
 *
 * Apply a loop state to a port
 */
void
__mul_loop_port_update(lldp_switch_t *sw, lldp_port_t *port,
                       int new_state)
{
    time_t ctime;

    if (new_state == LOOP_PORT_STATUS_NONE) {

        ctime = time(NULL);

        port->commit_loop_status = new_state;

        if (!port->hold_time ||
            port->hold_time + LOOP_PORT_HOLD_TIMEO >= ctime) {
            //c_log_debug("|Loop| Port %d on 0x%llx hold-timer %lu",
            //            port->port_no, sw->dpid,
            //            (unsigned long)port->hold_time);
            if (!port->hold_time)
                port->hold_time = ctime;
            return;
        }

        port->hold_time = 0;
    }

    mul_loop_port_mod(sw->dpid, port->port_no, new_state);
    port->loop_status = new_state;
}

/** 
 * mul_per_switch_port_loop_reset -
 *
 * Reset switch port's loop status
 */
static void
mul_per_switch_port_loop_reset(void *key UNUSED, void *p_arg, void *uarg)
{
    lldp_port_t *port = (lldp_port_t *)p_arg;
    enum loop_port_status status = LOOP_PORT_STATUS_INIT;

    if (uarg) {
        mul_loop_port_mod(port->lldp_sw->dpid, port->port_no, status);
    }

    port->loop_status = status; 
}

/**
 * mul_per_switch_loop_reset -
 *
 * Reset loop flags across domain
 */
static void
mul_per_switch_loop_reset(void *key UNUSED, void *sw_arg, void *uarg UNUSED)
{
    lldp_switch_t *sw = (lldp_switch_t *)sw_arg;

    c_wr_lock(&sw->lock);
    sw->root_switch = 0;
    sw->root_path_cost = 0;
    __lldp_port_traverse_all(sw, mul_per_switch_port_loop_reset, NULL);
    c_wr_unlock(&sw->lock);
}

/**
 * mul_root_per_switch_elect -
 *
 * Decide whether current switch is root or not 
 */
static void
mul_root_per_switch_elect(void *key UNUSED, void *sw_arg, void *uarg)
{
    lldp_switch_t *sw = (lldp_switch_t *)sw_arg;
    uint64_t *least_dpid = ASSIGN_PTR(uarg);

    c_wr_lock(&sw->lock);
    if (sw->dpid < *least_dpid &&
        __lldp_num_ports_in_switch(sw)) {
        *least_dpid = sw->dpid;
    }
    c_wr_unlock(&sw->lock);
}

/**
 * mul_mark_ports_per_switch -
 *
 * Mark each port in the root switch as indicated 
 */
static void
mul_mark_ports_per_switch(void *key UNUSED, void *p_arg, void *uarg)
{
    lldp_port_t *port = (lldp_port_t *)p_arg;
    enum loop_port_status status = *(int *)uarg;

    __mul_loop_port_update(port->lldp_sw, port, status);
}

/**
 * mul_per_switch_port_dp_calc -
 *
 * Determine desginated port status  for each switch port 
 */
static void
mul_per_switch_port_dp_calc(void *key UNUSED, void *p_arg, void *uarg UNUSED)
{
    lldp_port_t *port = (lldp_port_t *)p_arg;
    enum loop_port_status status;
    lldp_switch_t *sw = port->lldp_sw;
    lldp_switch_t *neigh_sw = NULL;
    lldp_port_t *neigh_port = NULL;
    bool need_lock = true; 

    if (port->status == LLDP_PORT_STATUS_NEIGHBOR &&
        port->loop_status != LOOP_PORT_STATUS_RP) {
        neigh_sw  = __fetch_and_retain_switch(port->neighbor_dpid);
        if (!neigh_sw) {
            c_log_err("%s: Port(%d) DPID (0x%llx) neigh-dpid (0x%llx) "
                      "not found", FN, port->port_no,
                       U642ULL(port->lldp_sw->dpid),
                       U642ULL(port->neighbor_dpid));
            return;
        }
        if (neigh_sw == sw) need_lock = false;

        if (need_lock) c_wr_lock(&neigh_sw->lock);
        neigh_port = __lldp_port_find(neigh_sw, port->neighbor_port);
        if (neigh_port) {
            if (neigh_port->loop_status == LOOP_PORT_STATUS_RP) {
                status = LOOP_PORT_STATUS_DP;
                mul_mark_ports_per_switch(NULL, port, &status);
            } else if (neigh_port->loop_status == LOOP_PORT_STATUS_DP) {
                status = LOOP_PORT_STATUS_NDP;
                mul_mark_ports_per_switch(NULL, port, &status);
                mul_loop_rt_neigh_conn_update(port, neigh_port, true);
                status = LOOP_PORT_STATUS_DP_N;
                mul_mark_ports_per_switch(NULL, neigh_port, &status);
                mul_loop_rt_neigh_conn_update(neigh_port, port, true);
            } else if (neigh_port->loop_status == LOOP_PORT_STATUS_NDP) {
                status = LOOP_PORT_STATUS_DP_N;
                mul_mark_ports_per_switch(NULL, port, &status);
                mul_loop_rt_neigh_conn_update(port, neigh_port, true);
            } else if (neigh_port->loop_status == LOOP_PORT_STATUS_DP_N) {
                status = LOOP_PORT_STATUS_NDP;
                mul_mark_ports_per_switch(NULL, port, &status);
                mul_loop_rt_neigh_conn_update(port, neigh_port, true);
            } else {
                if (neigh_sw->root_path_cost > port->lldp_sw->root_path_cost) {
                    status = LOOP_PORT_STATUS_DP_N;
                    mul_mark_ports_per_switch(NULL, port, &status); 
                    mul_loop_rt_neigh_conn_update(port, neigh_port, true);
                } else if (neigh_sw->root_path_cost <
                           port->lldp_sw->root_path_cost) {
                    status = LOOP_PORT_STATUS_NDP;
                    mul_mark_ports_per_switch(NULL, port, &status);
                    mul_loop_rt_neigh_conn_update(port, neigh_port, true);
                    status = LOOP_PORT_STATUS_DP_N;
                    mul_mark_ports_per_switch(NULL, neigh_port, &status);
                    mul_loop_rt_neigh_conn_update(neigh_port, port, true);
                } else {
                    /* Use DPID to resolve */
                    if (neigh_sw->dpid >= port->lldp_sw->dpid) {
                        status = LOOP_PORT_STATUS_DP_N;
                        mul_mark_ports_per_switch(NULL, port, &status);
                        mul_loop_rt_neigh_conn_update(port, neigh_port, true);
                    } else {
                        status = LOOP_PORT_STATUS_NDP;
                        mul_mark_ports_per_switch(NULL, port, &status);
                        mul_loop_rt_neigh_conn_update(port, neigh_port, true);
                        status = LOOP_PORT_STATUS_DP_N;
                        mul_mark_ports_per_switch(NULL, neigh_port, &status);
                        mul_loop_rt_neigh_conn_update(neigh_port, port, true); 
                    }
                }
            }
        } else {
            c_log_err("%s: Port(%d) DPID (0x%llx) neigh-dpid (0x%llx)(%d) "
                      "not found", FN, port->port_no, U642ULL(port->lldp_sw->dpid),
                       U642ULL(port->neighbor_dpid), port->neighbor_port);
        }

        if (need_lock) c_wr_unlock(&neigh_sw->lock);
        lldp_switch_unref(neigh_sw);
    }
}

/**
 * mul_per_switch_port_mark_none -
 *
 * If port's loop-status was init, then move it to none after 
 * completion of loop detection process 
 */
static void
mul_per_switch_port_mark_none(void *key UNUSED, void *p_arg, void *uarg UNUSED)
{
    lldp_port_t *port = (lldp_port_t *)p_arg;
    enum loop_port_status status = LOOP_PORT_STATUS_NONE;

    if (port->loop_status == LOOP_PORT_STATUS_NONE || 
        port->loop_status == LOOP_PORT_STATUS_INIT) {
        if (port->hold_time)
            topo_hdl->loop_info.held_ports++;
        mul_mark_ports_per_switch(NULL, port, &status);
        if (!port->hold_time) {
            topo_hdl->loop_info.clr_ports++;
        }
    }
}

/**
 * mul_route_cost_calc -
 *
 * Calculate route's total cost 
 */
static int
mul_route_cost_calc(GSList *iroute, uint16_t *rport)
{
    GSList *iterator = NULL;
    rt_path_elem_t *rt_elem = NULL;
    int cost = 0;

    *rport = 0;

    for (iterator = iroute; iterator; iterator = iterator->next) {
        rt_elem = iterator->data;
        /* FIXME : Get port speed */
        cost += 10;
        if (!*rport) {
            *rport = rt_elem->link.la;
        }
    }

    return cost;
}

/**
 * mul_per_switch_rp_calc -
 *
 * Calculate Root path cost 
 */
static void
mul_per_switch_rp_calc(void *key UNUSED, void *sw_arg, void *uarg)
{
    lldp_switch_t *sw = (lldp_switch_t *)sw_arg;
    lldp_switch_t *r_sw = ASSIGN_PTR(uarg);
    GSList *iroute = NULL;
    enum loop_port_status pstatus = LOOP_PORT_STATUS_NONE;
    uint16_t rport_no = 0;
    lldp_port_t *sw_rport = NULL;

    if (sw->dpid == r_sw->dpid) return; 

    iroute = __tr_get_route(topo_hdl->tr, sw->alias_id, r_sw->alias_id);
    if (!iroute) {
        sw->root_path_cost = -1;
        lldp_port_traverse_all(sw, mul_mark_ports_per_switch, &pstatus);
        return;
    }

    sw->root_path_cost = mul_route_cost_calc(iroute, &rport_no);

    c_wr_lock(&sw->lock);

    pstatus = LOOP_PORT_STATUS_RP;
    sw_rport = __lldp_port_find(sw, rport_no);
    if (sw_rport) {
        mul_mark_ports_per_switch(NULL, sw_rport, &pstatus);
    } else {
        c_log_err("%s: Cant find rport %d for switch 0x%llx",
                  FN, rport_no, U642ULL(sw->dpid));
    }

    c_wr_unlock(&sw->lock);

    tr_destroy_route(iroute);
}

/**
 * mul_per_switch_dp_calc -
 *
 * Calculate designated/non-designated port 
 */
static void
mul_per_switch_dp_calc(void *key UNUSED, void *sw_arg, void *uarg)
{
    lldp_switch_t *sw = (lldp_switch_t *)sw_arg;
    lldp_switch_t *r_sw = ASSIGN_PTR(uarg);

    if (sw->dpid == r_sw->dpid) return; 

    c_wr_lock(&sw->lock);
    __lldp_port_traverse_all(sw, mul_per_switch_port_dp_calc, NULL);
    c_wr_unlock(&sw->lock);
}

/**
 * mul_per_switch_none_select -
 *
 * Calculate none connected ports 
 */
static void
mul_per_switch_none_select(void *key UNUSED, void *sw_arg, void *uarg)
{
    lldp_switch_t *sw = (lldp_switch_t *)sw_arg;
    lldp_switch_t *r_sw = ASSIGN_PTR(uarg);

    if (sw->dpid == r_sw->dpid) return;

    c_wr_lock(&sw->lock);
    __lldp_port_traverse_all(sw, mul_per_switch_port_mark_none, NULL);
    c_wr_unlock(&sw->lock);
}

/**
 * mul_per_switch_port_mark_none_lazy -
 *
 * If port's loop-status was init, then move it to none after 
 * completion of loop detection process (Lazy version)
 */
static void
mul_per_switch_port_mark_none_lazy(void *key UNUSED, void *p_arg, void *uarg UNUSED)
{
    lldp_port_t *port = (lldp_port_t *)p_arg;
    enum loop_port_status status = LOOP_PORT_STATUS_NONE;

    if ((port->loop_status == LOOP_PORT_STATUS_NONE || 
        port->loop_status == LOOP_PORT_STATUS_INIT) &&
        port->hold_time) {
        if (port->hold_time)
            topo_hdl->loop_info.held_ports++;
        mul_mark_ports_per_switch(NULL, port, &status);
        if (!port->hold_time) {
            topo_hdl->loop_info.clr_ports++;
        }
    }
}

/**
 * mul_per_switch_none_select_lazy -
 *
 * Calculate none connected ports in delayed fashion
 */
static void
mul_per_switch_none_select_lazy(void *key UNUSED, void *sw_arg, void *uarg UNUSED)
{
    lldp_switch_t *sw = (lldp_switch_t *)sw_arg;

    c_wr_lock(&sw->lock);
    __lldp_port_traverse_all(sw, mul_per_switch_port_mark_none_lazy, NULL);
    c_wr_unlock(&sw->lock);
}

/**
 * __mul_loop_detect_state_reset -
 *
 * Reset loop detection state
 */
static void
__mul_loop_detect_state_reset(topo_hdl_t *topo)
{
    topo->loop_info.root_dpid = MUL_LLDP_INV_DPID;
    __lldp_switch_traverse_all(topo, mul_per_switch_loop_reset,
                               topo->loop_info.loop_reset_only ? topo:NULL);
    if (topo->loop_info.loop_reset_only) {
        TR_LOOP_TRIGGER_ON(topo->tr);
        topo->loop_info.loop_blocked = true;
    } 
    topo->loop_info.next_loop_state = LOOP_STATE_ROOT_ELECT;
}


/**
 * __mul_loop_detect_root_select -
 *
 * Selects a root switch and marks all its ports as designated
 */
static void
__mul_loop_detect_root_select(topo_hdl_t *topo)
{
    uint64_t least_dpid = MUL_LLDP_INV_DPID;
    enum loop_port_status pstatus = LOOP_PORT_STATUS_DP;

    topo->loop_info.root_sw =  NULL;
    __lldp_switch_traverse_all(topo, mul_root_per_switch_elect,
                               &least_dpid);

    topo->loop_info.root_dpid = least_dpid;
    if (topo->loop_info.root_dpid  == MUL_LLDP_INV_DPID) {
        topo->loop_info.next_loop_state = LOOP_STATE_NONE_SELECT;
    } else {
        if (!(topo->loop_info.root_sw = 
            __fetch_and_retain_switch(topo->loop_info.root_dpid))) {
            topo->loop_info.root_dpid = MUL_LLDP_INV_DPID;
            topo->loop_info.next_loop_state = LOOP_STATE_NONE_SELECT;
        } else {
            lldp_port_traverse_all(topo->loop_info.root_sw,
                                   mul_mark_ports_per_switch, &pstatus);
            topo->loop_info.next_loop_state = LOOP_STATE_ROOT_COST_CALC;
        }
    }
}

static void
__mul_loop_detect_root_cost_calc(topo_hdl_t *topo)
{
    if (topo->loop_info.root_sw) {
        __lldp_switch_traverse_all(topo, mul_per_switch_rp_calc,
                                   topo->loop_info.root_sw);
        topo->loop_info.next_loop_state = LOOP_STATE_DP_SELECT;
    } else {
        topo->loop_info.root_dpid = MUL_LLDP_INV_DPID;
        topo->loop_info.next_loop_state = LOOP_STATE_NONE_SELECT;
    }
}

/**
 * __mul_loop_detect_dp_select -
 *
 * Select designated ports
 */
static void
__mul_loop_detect_dp_select(topo_hdl_t *topo)
{
    if (topo->loop_info.root_sw) {
         /* Now calculate desginated ports in each non-root switch */
        __lldp_switch_traverse_all(topo, mul_per_switch_dp_calc,
                                   topo->loop_info.root_sw);
        topo->loop_info.next_loop_state = LOOP_STATE_NONE_SELECT;
    } else {
        topo->loop_info.root_dpid = MUL_LLDP_INV_DPID;
        topo->loop_info.next_loop_state = LOOP_STATE_NONE_SELECT;
    }
}

/**
 * __mul_loop_detect_none_select -
 *
 * Select ports to marked as None 
 */
static void
__mul_loop_detect_none_select(topo_hdl_t *topo)
{
    if (topo->loop_info.root_sw) {
         /* Now calculate non connected ports in each non-root switch */
        __lldp_switch_traverse_all(topo, mul_per_switch_none_select,
                                   topo->loop_info.root_sw);
        lldp_switch_unref(topo->loop_info.root_sw);
        topo->loop_info.root_sw = NULL;
    } else {
        topo->loop_info.root_dpid = MUL_LLDP_INV_DPID;
    }

    topo->loop_info.loop_blocked = true;
    topo->loop_info.next_loop_state = LOOP_STATE_RESET;
}


/**
 * mul_loop_convergence_state -
 *
 * Get loop convergence state
 */
static int 
mul_loop_convergence_state(topo_hdl_t *topo, bool run)
{
    int state = C_LOOP_STATE_NONE;
    if (run) {
        state = C_LOOP_STATE_LD;
    }

    /* We calculate how many ports were clear and held and beginning
     * of loop and increment the number of cleared and held ports
     * If there were x ports in held state and after loop there are 
     * x ports in clear state then we cna safely deduce that loop state 
     * is converged 
     */
    if (topo->loop_info.held_ports == topo->loop_info.clr_ports) {
        state = C_LOOP_STATE_CONV;
    }

    return state;
}

/**
 * mul_loop_detect -
 *
 * Detects loop in the current OF domain 
 */
void
mul_loop_detect(topo_hdl_t *topo, bool need_lock)
{
    bool loop_run = false;
    int conv_state = C_LOOP_STATE_NONE;

    if (need_lock) c_wr_lock(&topo->switch_lock);
    
    /* Reset per-loop state variables */
    topo->loop_info.held_ports = 0;
    topo->loop_info.clr_ports = 0;

    __lldp_switch_traverse_all(topo, mul_per_switch_none_select_lazy,
                               NULL);

    if (!TR_LOOP_TRIGGER_IS_ON(topo->tr)) {
        goto loop_detect_done;
    }

    if (!topo->loop_info.loop_reset_only)
        loop_run = true;    
    topo->loop_info.loop_blocked = false;

    TR_LOOP_TRIGGER_OFF(topo->tr);

    while (!topo->loop_info.loop_blocked) {
        switch (topo->loop_info.next_loop_state) {
        case LOOP_STATE_RESET:
            __mul_loop_detect_state_reset(topo);
            break;
        case LOOP_STATE_ROOT_ELECT:
            __mul_loop_detect_root_select(topo);        
            break;
        case LOOP_STATE_ROOT_COST_CALC:
            __mul_loop_detect_root_cost_calc(topo);
            break;
        case LOOP_STATE_DP_SELECT:
            __mul_loop_detect_dp_select(topo);
            __tr_route_recalc(topo->tr);
            break;
        case LOOP_STATE_NONE_SELECT:
            __mul_loop_detect_none_select(topo);
            break;
        }
    }

loop_detect_done:
    topo->loop_info.loop_reset_only = false;
    conv_state = mul_loop_convergence_state(topo, loop_run);

    if (conv_state != C_LOOP_STATE_NONE &&
        topo->loop_info.loop_conv_state != conv_state) {
        //c_log_debug("%s: Loop converged state %d @ |%lu|s", 
        //            FN, conv_state, time(NULL));
        mul_app_send_loop_status(conv_state);
    }
    topo->loop_info.loop_conv_state = conv_state;

    if (need_lock) c_wr_unlock(&topo->switch_lock);
}
