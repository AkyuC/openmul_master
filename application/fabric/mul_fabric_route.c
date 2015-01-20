/**
 *  @file mul_fabric_route.c
 *  @brief Mul fabric route manager 
 *  @author Dipjyoti Saikia  <dipjyoti.saikia@gmail.com> 
 *  @copyright Copyright (C) 2012, Dipjyoti Saikia 
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

extern fab_struct_t *fab_ctx;

/**
 * @name fab_route_elem_valid
 * @brief Check if a fabric route elem is valid
 */
static int 
fab_route_elem_valid(void *rt_path_arg, void *route_arg)
{
    rt_path_elem_t *rt_elem = rt_path_arg;
    fab_switch_t *sw;
    fab_route_t *froute = route_arg;

    sw = __fab_switch_get_with_alias(fab_ctx, rt_elem->sw_alias);
    if (!sw) {
        goto route_inv_switch;
    }

    if ((rt_elem->flags & RT_PELEM_LAST_HOP)) {
        if (!fab_port_valid(fab_ctx, sw, froute->dst->sw.port)) {
            goto route_inv_port;
        }
    } else {
        if (!fab_port_up(fab_ctx, sw, rt_elem->link.la)) {
            goto route_inv_port;
        }
    }

    fab_switch_put_locked(sw);

    return 0;

route_inv_port:
    fab_switch_put_locked(sw);
route_inv_switch:
    c_log_err("%s: Route elem err", FN);
    return -1;
}

/**
 * @name fab_mp_select
 *
 * @brief Select a path from multi-path set
 */
static size_t
fab_mp_select(void *u_arg, size_t max_routes)
{
    fab_route_t *froute = u_arg;
    unsigned int mp_key;

    assert(froute);

#ifdef NOTDEMO
    mp_key = hash_bytes(&froute->rt_flow.nw_src, 8, 1);
    mp_key %= max_routes;
#else
    mp_key = ntohl(froute->rt_flow.ip.nw_dst) & 0xff;
    mp_key %= max_routes;
#endif

    return mp_key;
}

/**
 * @name fab_route_get
 *
 * @brief Get a fabric route
 */
GSList *
fab_route_get(void *rt_service, int src_sw, int dst_sw,
              fab_route_t *froute)
{
    GSList *route = NULL;

    if (!fab_ctx->use_ecmp || !froute) {
        if (!(route = mul_route_get(rt_service, src_sw, dst_sw))) {
            return NULL;
        }
    } else {
        if (!(route = mul_route_get_mp(rt_service, src_sw, dst_sw,
                                       froute, fab_mp_select))) {
            return NULL;
        }
    }

    if (!g_slist_find_custom(route, froute, (GCompareFunc)fab_route_elem_valid)) {
        mul_destroy_route(route);
        return NULL;
    }
    
    return route;
}

/**
 * @name fab_route_from_host_cmp 
 *
 * @brief Check whether route originates from a host 
 */
static int
fab_route_from_host_cmp(void *route_elem, void *h_arg)
{
    fab_route_t *froute = route_elem;
    fab_host_t *host = h_arg;

    if (host == froute->src) {
        return 0; 
    }

    return 1;
} 

/**
 * @name fab_route_to_host_cmp
 * @brief Check whether a route terminates at given host 
 *
 * @retval int 0 if it terminates else 1
 */
static int
fab_route_to_host_cmp(void *route_elem, void *h_arg)
{
    fab_route_t *froute = route_elem;
    fab_host_t *host = h_arg;

    if (host == froute->dst) return 0; 

    return 1;
} 

/**
 * @name fab_dump_single_pending_route -
 *
 * @brief Dump a single pending route
 */
void
fab_dump_single_pending_route(void *route, void *arg UNUSED)
{
    fab_route_t *froute = route;

    c_log_debug("%s: Pending route between (0x%llx:%d -Port(%u)) -> (0x%llx:%d - Port (%u))",
                FN, (unsigned long long)(froute->src->sw.swid),
                froute->src->sw.alias , froute->src->sw.port,
                (unsigned long long)(froute->dst->sw.swid),
                froute->dst->sw.alias, froute->dst->sw.port);
}

/**
 * @name __fab_loop_all_pending_routes
 * @brief Loop over all pending routes
 * @param fab_ctx : Fabric ctx pointer
 * @param iter_fn : Iteration callback for each route of host
 * @param u_data  : User arg to be passed to iter_fn
 *
 * @retval void Nothing
 */
void
__fab_loop_all_pending_routes(fab_struct_t *fab_ctx, GFunc iter_fn, void *u_data)
{
    if (fab_ctx->rt_pending_list) {
        g_slist_foreach(fab_ctx->rt_pending_list,
                        (GFunc)iter_fn, u_data);
    }
}

/**
 * @name fab_route_elem_oport_cmp
 *
 * @brief Check whether fabric route element has port as out_port for this node
 */
static int
fab_route_elem_oport_cmp(void *rt_path_arg, void *sw_arg)
{
    rt_path_elem_t *rt_elem = rt_path_arg;
    fab_host_sw_t  *sw = sw_arg;

    if (!(rt_elem->flags & RT_PELEM_LAST_HOP) &&
        rt_elem->sw_alias == sw->alias &&
        rt_elem->link.la == sw->port) {
        c_log_err("%s: Match", FN);
        return 0;
    }

    return 1;
}


/**
 * @name fab_per_switch_route_install
 * @brief Install a fabric route element to a switch node
 * @param rt : a route element  
 * @param u_arg : fabric route pointer  
 *
 */
static void
fab_per_switch_route_install(void *rt, void *u_arg)
{
    rt_path_elem_t              *rt_elem = rt;
    fab_route_t                 *froute = u_arg;
    struct mul_act_mdata        mdata;
    uint16_t                    out_port, in_port;
    uint16_t                    tenant_id = 0;
    bool                        fhop, lhop; 
    bool                        add_pkt_tenant = false, strip_pkt_tenant = false;
    bool                        set_dmac_lhop = false;
    char                        *fl_str;
    fab_switch_t                *sw; 

    sw = __fab_switch_get_with_alias(fab_ctx, rt_elem->sw_alias);
    if (!sw) {
        app_rlog_err("%s: switch cant be found", FN);
        return;
    }
    app_log_debug("%s: 0x%x -> 0x%x:(Switch 0x%llx)", FN, froute->src->hkey.host_ip, 
                froute->dst->hkey.host_ip, (unsigned long long)sw->dpid);
    fab_switch_put_locked(sw);

    lhop = rt_elem->flags & RT_PELEM_LAST_HOP ? true: false;
    fhop = rt_elem->flags & RT_PELEM_FIRST_HOP ? true: false;
    /*TODO: FIXME
            Masking is not the permanent solution for keeping tenant id
            within the range of VLAN ID*/
    tenant_id = fab_tnid_to_tid(froute->src->hkey.tn_id) & 0x0fff;
    out_port = lhop ? froute->dst->sw.port : rt_elem->link.la;
    in_port = fhop ? froute->src->sw.port : rt_elem->in_port;

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, sw->dpid);

    /* 
     * Update the last hop oport and first hop iport in the route
     * This is not accomplshed by route-service 
     */
    rt_elem->link.la = out_port;
    rt_elem->in_port = in_port;

    if (tenant_id) {
        if (lhop && fhop) { 
            if(fab_ctx->fab_learning != FAB_HOST_TRACKER_ENABLED) {
                set_dmac_lhop = true;
            }
            goto apply_route;
        } else if (fhop) {
            add_pkt_tenant = true;
            goto apply_route;
        } else if (lhop) {
            /* Last hop */
            strip_pkt_tenant = true;
        } 
        fab_add_tenant_id(&froute->rt_flow, &froute->rt_mask, tenant_id);

    } else {
        if(fab_ctx->fab_learning != FAB_HOST_TRACKER_ENABLED) {
            if (lhop) {
                set_dmac_lhop = true;
            }
        }
    }

apply_route:

    if (add_pkt_tenant) {
        mul_app_action_push_hdr(&mdata, ETH_TYPE_VLAN);
        mul_app_action_set_vid(&mdata, tenant_id);
    } else if (strip_pkt_tenant) {
        mul_app_action_strip_vlan(&mdata);
        if(fab_ctx->fab_learning != FAB_HOST_TRACKER_ENABLED) {
            mul_app_action_set_dmac(&mdata, froute->dst->hkey.host_mac);
        }
    } else if (set_dmac_lhop) {
        if(fab_ctx->fab_learning != FAB_HOST_TRACKER_ENABLED) {
            mul_app_action_set_dmac(&mdata, froute->dst->hkey.host_mac);
        }
    }

    mul_app_action_output(&mdata, in_port == out_port ? OFPP_IN_PORT : out_port);

    froute->rt_flow.in_port = htonl((uint32_t)in_port);
    of_mask_set_in_port(&froute->rt_mask);

    fl_str = of_dump_flow_generic(&froute->rt_flow, &froute->rt_mask);
    app_log_debug("%s", fl_str);
    free(fl_str);

    mul_app_send_flow_add(FAB_APP_NAME, NULL, (uint64_t)(rt_elem->sw_alias), 
                          &froute->rt_flow, 
                          &froute->rt_mask, 
                          FAB_UNK_BUFFER_ID,
                          mdata.act_base, mul_app_act_len(&mdata), 
                          0, 0, froute->prio,
                          C_FL_ENT_SWALIAS  | C_FL_ENT_GSTATS);

    if(fab_ctx->fab_learning == FAB_HOST_TRACKER_ENABLED) {
        froute->rt_flow.dl_type = ntohs(ETH_TYPE_ARP);
        mul_app_send_flow_add(FAB_APP_NAME, NULL, (uint64_t)(rt_elem->sw_alias), 
                &froute->rt_flow, &froute->rt_mask, FAB_UNK_BUFFER_ID,
                mdata.act_base, mul_app_act_len(&mdata), 0, 0,
                froute->prio, C_FL_ENT_SWALIAS | C_FL_ENT_GSTATS);
    }

    /* Reset flow modifications if any */
    froute->rt_flow.dl_type = htons(ETH_TYPE_IP);
    if (tenant_id) {
        fab_reset_tenant_id(&froute->rt_flow, &froute->rt_mask);
    }

    froute->rt_flow.in_port = 0;
    of_mask_clr_in_port(&froute->rt_mask);
    mul_app_act_free(&mdata);
}

#ifndef FAB_USE_CONX
/**
 * @name fab_per_switch_route_uninstall- 
 * @brief Uninstall a fabric route element from a switch node
 * @param rt : a route element  
 * @param u_arg : fabric route pointer  
 *
 */
static void
fab_per_switch_route_uninstall(void *rt, void *u_arg)
{
    rt_path_elem_t   *rt_elem = rt;
    fab_route_t      *froute = u_arg;
    uint16_t         tenant_id = fab_tnid_to_tid(froute->src->hkey.tn_id);       
    bool             fhop;
    char             *fl_str;
    fab_switch_t     *sw;

    sw = __fab_switch_get_with_alias(fab_ctx, rt_elem->sw_alias);
    if (!sw) {
        app_rlog_err("%s: switch cant be found", FN);
        return;
    }
    app_log_debug("%s: 0x%x -> 0x%x:(Switch 0x%llx)", FN, froute->src->hkey.host_ip,
                froute->dst->hkey.host_ip, (unsigned long long)sw->dpid);
    fab_switch_put_locked(sw);

    fhop = rt_elem->flags & RT_PELEM_FIRST_HOP ? true: false;
    if (tenant_id && !fhop) {
         fab_add_tenant_id(&froute->rt_flow, &froute->rt_mask, tenant_id);
    }

    froute->rt_flow.in_port = htonl(rt_elem->in_port);
    of_mask_set_in_port(&froute->rt_mask);

    fl_str = of_dump_flow_generic(&froute->rt_flow, &froute->rt_mask);
    app_log_debug("%s", fl_str);
    free(fl_str);

    mul_app_send_flow_del(FAB_APP_NAME, NULL, (uint64_t)(rt_elem->sw_alias),
                          &froute->rt_flow, &froute->rt_mask, OFPP_NONE, 
                          froute->prio, C_FL_ENT_SWALIAS, OFPG_ANY);

    if(fab_ctx->fab_learning == FAB_HOST_TRACKER_ENABLED) {
        froute->rt_flow.dl_type = ntohs(ETH_TYPE_ARP);
        mul_app_send_flow_del(FAB_APP_NAME, NULL, (uint64_t)(rt_elem->sw_alias),
                &froute->rt_flow, &froute->rt_mask, OF_NO_PORT, 
                froute->prio, C_FL_ENT_SWALIAS, OFPG_ANY);
    }

    froute->rt_flow.dl_type = ntohs(ETH_TYPE_IP);
    if (tenant_id && !fhop) {
        fab_reset_tenant_id(&froute->rt_flow, &froute->rt_mask);
    }

    froute->rt_flow.in_port = 0;
    of_mask_clr_in_port(&froute->rt_mask);
}
#endif

/**
 * @name fab_route_install - 
 * @brief Install a fabric route to hardware
 * @param froute : Fabric route to install  
 *
 */
static void
fab_route_install(fab_route_t *froute)
{
    froute->flags &= ~FAB_ROUTE_DIRTY;
    mul_route_path_traverse(froute->iroute, fab_per_switch_route_install,
                            froute);
}

/**
 * @name fab_route_uninstall 
 * @brief Uninstall a fabric route from hardware
 * @param froute : Fabric route to uninstall  
 *
 */
static void
fab_route_uninstall(fab_route_t *froute)
{
#ifndef FAB_USE_CONX
    mul_route_path_traverse(froute->iroute, fab_per_switch_route_uninstall, 
                            froute); 
#else
    int ret = 0;
    froute->rt_flow.in_port = htonl(froute->src->sw.port);
    of_mask_set_in_port(&froute->rt_mask);
    ret = mul_conx_mod_uflow(fab_ctx->fab_conx_service,
                             false, 1, &froute->src->sw.swid,
                             (uint64_t)(froute->dst->sw.swid),
                             &froute->rt_flow, /* Ingress Flow*/
                             &froute->rt_mask,
                             0, 0,
                             NULL, 0,
                             0, CONX_UFLOW_FORCE);
    if(ret != 0 ) {
        app_log_err("Failed to del flows through ConX");
    }
    if(fab_ctx->fab_learning == FAB_HOST_TRACKER_ENABLED) {
        froute->rt_flow.dl_type = ntohs(ETH_TYPE_ARP);
        ret = mul_conx_mod_uflow(fab_ctx->fab_conx_service,
                                 false, 1, &froute->src->sw.swid,
                                 (uint64_t)(froute->dst->sw.swid),
                                 &froute->rt_flow, /* Ingress Flow*/
                                 &froute->rt_mask,
                                 0, 0,
                                 NULL, 0,
                                 0, CONX_UFLOW_FORCE);
        if(ret != 0 ) {
            app_log_err("Failed to del flows through ConX");
        }
    }

    froute->rt_flow.dl_type = ntohs(ETH_TYPE_IP);
    froute->rt_flow.in_port = 0;
    of_mask_clr_in_port(&froute->rt_mask);

#endif
    froute->flags |= FAB_ROUTE_DEAD;
}

/**
 * @name fab_zaproute
 * @brief Destructor for a fabric route
 * @param route : Fabric route to destroy  
 *
 * Frees a route's memory and decrements ref count of route's end points
 */
static void
fab_zaproute(void *route)
{
    fab_route_t *froute = route;

    if (froute->iroute) {
        mul_destroy_route(froute->iroute);
    }

    fab_host_put(froute->src);
    fab_host_put(froute->dst);

    fab_free(froute);
}


/**
 * @name __fab_del_pending_route
 * @brief Delete route from pending list
 * @param fab_ctx : Fabric context pointer
 * @param route : Fabric route
 *
 * If route between two hosts can't be established it is added to the pending list
 * This function deletes the route from this list
 */
static void
__fab_del_pending_route(fab_struct_t *fab_ctx, fab_route_t *froute)
{
    fab_ctx->rt_pending_list = g_slist_remove(fab_ctx->rt_pending_list, froute);
}


/**
 * @name __fab_del_pending_routes_tofro_host
 * @brief Delete pending routes to and from a host
 * @param fab_ctx : Fabric context pointer
 * @param host : Fabric host 
 *
 */
void
__fab_del_pending_routes_tofro_host(fab_struct_t *fab_ctx, fab_host_t *host)
{
    GSList *iterator;

    iterator = g_slist_find_custom(fab_ctx->rt_pending_list,
                                   host,
                                   (GCompareFunc)fab_route_from_host_cmp);

    if (iterator) {
        __fab_del_pending_route(fab_ctx, iterator->data);
    }

    iterator = g_slist_find_custom(fab_ctx->rt_pending_list,
                                   host,
                                   (GCompareFunc)fab_route_to_host_cmp);

    if (iterator) {
        __fab_del_pending_route(fab_ctx, iterator->data);
    }
}


/**
 * @name __fab_add_to_pending_routes
 * @brief Add a host-pair route as pending
 * @param fab_ctx : Fabric context pointer  
 * @param route : Fabric route  
 *
 */
static void
__fab_add_to_pending_routes(fab_struct_t *fab_ctx, fab_route_t *froute)
{
    froute->expiry_ts = time(NULL) + FAB_ROUTE_RETRY_INIT_TS;
    fab_ctx->rt_pending_list = g_slist_append(fab_ctx->rt_pending_list, froute);
}

/**
 * @name fab_flush_pending_routes - 
 * @brief Flush all pending host-pair routes 
 * @param fab_ctx : Fabric context pointer
 *
 */
void
fab_flush_pending_routes(fab_struct_t *fab_ctx)
{
    c_wr_lock(&fab_ctx->lock);
    g_slist_free_full(fab_ctx->rt_pending_list, (GDestroyNotify)fab_zaproute);
    fab_ctx->rt_pending_list = NULL;
    c_wr_unlock(&fab_ctx->lock);
}

/**
 * @name fab_retry_pending_routes -
 * @brief Retry establishing all pending host-pair routes 
 * @param fab_ctx : Fabric context pointer  
 * @param curr_ts : Current timestamp
 *
 */
static void
fab_retry_pending_routes(fab_struct_t *fab_ctx, time_t curr_ts)
{
    GSList *iterator, *prev = NULL;
    fab_route_t *froute;
    bool scan_all_pending;
    int num_runs = 0;

start:
    scan_all_pending = fab_ctx->rt_scan_all_pending;
    fab_ctx->rt_scan_all_pending ^= fab_ctx->rt_scan_all_pending;

    c_wr_lock(&fab_ctx->lock);

restart:
    prev = NULL;
    iterator = fab_ctx->rt_pending_list; 
    while (iterator) {
        froute = iterator->data;
        if(scan_all_pending ||
           curr_ts > froute->expiry_ts) {
            app_log_debug("%s: Pending route between (0x%x) -> (0x%x)",
                  FN, froute->src->hkey.host_ip, froute->dst->hkey.host_ip);


           if ((froute->iroute = fab_route_get(fab_ctx->route_service,
                                           froute->src->sw.alias, 
                                           froute->dst->sw.alias,
                                           froute)) ||
                froute->src->dead || froute->dst->dead) {

                if (!froute->src->dead && !froute->dst->dead) {

                    /* Routes are now reachable. Install it */
                    c_wr_lock(&froute->dst->lock);
                    froute->dst->host_routes = 
                            g_slist_append(froute->dst->host_routes, froute);
                    fab_route_install(froute);
                    c_wr_unlock(&froute->dst->lock);
                } else {
                    app_log_debug("%s: Zapped route(%d)->(%d)", FN,
                                froute->src->sw.alias, froute->dst->sw.alias);
                    fab_zaproute(froute);
                }

                /* Delete it from the pending list */
                if (prev) {
                    prev->next = iterator->next;
                } else {
                    fab_ctx->rt_pending_list = iterator->next;
                }   
                g_slist_free_1(iterator);
                goto restart;
            }
            froute->expiry_ts = curr_ts + FAB_ROUTE_RETRY_TS;
        }
        
        prev = iterator;
        iterator = iterator->next;
    }

    c_wr_unlock(&fab_ctx->lock);

    if (fab_ctx->rt_scan_all_pending && ++num_runs > FAB_MAX_PENDING_LOOPS) {
        goto start;
    }

    if (num_runs > FAB_MAX_PENDING_LOOPS) {
        c_log_err("%s: Ran too many times", FN);
    }
}

/**
 * @name fab_mkroute - 
 * @brief Make a route from a source to a destination host 
 * @param src : Source host 
 * @param dst : Destination host
 *
 * @retval fab_route_t * Pointer to new route or NULL
 */
static fab_route_t * 
fab_mkroute(fab_host_t *src, fab_host_t *dst)
{
    fab_route_t *froute;

    froute = fab_zalloc(sizeof(fab_route_t));

    fab_host_get(src);
    fab_host_get(dst);
    froute->src = src;
    froute->dst = dst;
    froute->flags = FAB_ROUTE_DIRTY;
    if (froute->src->sw.alias == froute->dst->sw.alias) {
         froute->flags |= FAB_ROUTE_SAME_SWITCH;
    }

    of_mask_set_dc_all(&froute->rt_mask);

#if 0
    fab_add_tenant_id(&froute->rt_flow, &froute->rt_mask, 
                      fab_tnid_to_tid(src->hkey.tn_id));
#endif

    if (src->dfl_gw || dst->dfl_gw) {
        froute->prio = C_FL_PRIO_FWD+1;
    } else {
        froute->prio = C_FL_PRIO_FWD+2;
    }

    if (!src->dfl_gw) {
        froute->rt_flow.ip.nw_src = htonl(src->hkey.host_ip);
        of_mask_set_nw_src(&froute->rt_mask, 32);
    }

    if (!dst->dfl_gw) {
        froute->rt_flow.ip.nw_dst = htonl(dst->hkey.host_ip);
        of_mask_set_nw_dst(&froute->rt_mask, 32);
    }

    froute->rt_flow.dl_type = htons(ETH_TYPE_IP);
    of_mask_set_dl_type(&froute->rt_mask);

#ifndef FAB_USE_CONX
    froute->iroute = fab_route_get(fab_ctx->route_service,
                                   src->sw.alias, dst->sw.alias,
                                   froute);
    if (!froute->iroute) {
        app_rlog_err("%s: No host route src(0x%x)[0x%llx:%d]->dst(0x%x)[0x%llx:%d]",
                     FN, src->hkey.host_ip, (unsigned long long)(src->sw.swid),
                     src->sw.alias, dst->hkey.host_ip, 
                  (unsigned long long)(dst->sw.swid),
                  dst->sw.alias);
        __fab_add_to_pending_routes(fab_ctx, froute);
        return NULL;
    }
#endif

    return froute;
}

/**
 * @name __fab_loop_all_host_routes - 
 * @brief Loop over all routes of a host and invoke callback for each
 *
 * @param host : Fabric host pointer 
 * @param iter_fn : Iteration callback for each route of host 
 * @param u_data : User arg to be passed to iter_fn 
 *
 */
static void
__fab_loop_all_host_routes(fab_host_t *host, GFunc iter_fn, void *u_data)
{                               
    if (host->host_routes) {
        g_slist_foreach(host->host_routes,
                        (GFunc)iter_fn, u_data);
    }
}

/**
 * @name fab_loop_all_host_routes - 
 * @brief Loop over all routes of a host and invoke callback for each
 *        with explicit locking
 *
 * @param host : Fabric host pointer 
 * @param iter_fn : Iteration callback for each route of host 
 * @param u_data : User arg to be passed to iter_fn 
 *
 */
void
fab_loop_all_host_routes(fab_host_t *host, GFunc iter_fn, void *u_data)
{                               
    c_rd_lock(&host->lock);
    if (host->host_routes) {
        g_slist_foreach(host->host_routes,
                        (GFunc)iter_fn, u_data);
    }
    c_rd_unlock(&host->lock);
}

/**
 * @name fab_host_route_delete_1 - 
 * @brief Uninstall and destroy a single fabric route
 * @param iroute: Fabric route to destroy 
 * @param u_arg : User arg (unused) 
 *
 */
static void 
fab_host_route_delete_1(void *iroute, void *u_arg UNUSED)
{
    fab_route_uninstall(iroute);
    fab_zaproute(iroute);
}

#ifdef FAB_USE_CONX
/**
 * @name fab_conx_route_install
 * @brief Install a fabric route using Conx route
 *
 */
static void
fab_conx_route_install(fab_route_t *froute)
{
    struct mul_act_mdata        mdata;
    uint16_t                    out_port, in_port;
    uint16_t                    tenant_id = 0;
    int                         ret = 0;

    tenant_id = 0;
    out_port = froute->dst->sw.port;
    in_port = froute->src->sw.port;

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, (uint64_t)(froute->src->sw.swid));


    if(fab_ctx->fab_learning != FAB_HOST_TRACKER_ENABLED) {
        mul_app_action_set_dmac(&mdata, froute->dst->hkey.host_mac);
    }

    mul_app_action_set_smac(&mdata, froute->src->hkey.host_mac);
    mul_app_action_set_dmac(&mdata, froute->dst->hkey.host_mac);
    mul_app_action_output(&mdata, out_port);

    froute->rt_flow.in_port = htonl((uint32_t)in_port);
    of_mask_set_in_port(&froute->rt_mask);

    ret = mul_conx_mod_uflow(fab_ctx->fab_conx_service,
                             true, 1, &froute->src->sw.swid,
                             (uint64_t)(froute->dst->sw.swid),
                             &froute->rt_flow, /* Ingress Flow*/
                             &froute->rt_mask,
                             0, 0,
                             mdata.act_base,
                             mul_app_act_len(&mdata),
                             0, CONX_UFLOW_FORCE);
    if(ret != 0 ) {
        app_log_err("Failed to add flows through ConX");
    }

    if(fab_ctx->fab_learning == FAB_HOST_TRACKER_ENABLED) {
        froute->rt_flow.dl_type = ntohs(ETH_TYPE_ARP);
        ret = mul_conx_mod_uflow(fab_ctx->fab_conx_service,
                                 true, 1, &froute->src->sw.swid,
                                 (uint64_t)(froute->dst->sw.swid),
                                 &froute->rt_flow, /* Ingress Flow*/
                                 &froute->rt_mask,
                                 0, 0,
                                 mdata.act_base,
                                 mul_app_act_len(&mdata),
                                 0, CONX_UFLOW_FORCE);
        if(ret != 0 ) {
            app_log_err("Failed to add ARP flows through ConX");
        }
    }

    /* Reset flow modifications if any */
    froute->rt_flow.dl_type = htons(ETH_TYPE_IP);
    if (tenant_id) {
        fab_reset_tenant_id(&froute->rt_flow, &froute->rt_mask);
    }

    froute->rt_flow.in_port = 0;
    of_mask_clr_in_port(&froute->rt_mask);
    mul_app_act_free(&mdata);

}
#endif

/**
 * @name fab_host_route_add -
 * @brief Find route from src to dst and install the route
 */
static int
fab_host_route_add(fab_host_t *src, fab_host_t *dst)
{
    fab_route_t *froute;

    if (src == dst ||
        src->dead ||
        dst->dead) {
        return -1;
    }

    app_log_debug("%s: Adding route betweem 0x%x -> 0x%x",
                  FN, src->hkey.host_ip, dst->hkey.host_ip);
    
    froute = fab_mkroute(src, dst);
    if (froute) {
        /* FIXME - Check for duplicates */
        c_wr_lock(&dst->lock);
        dst->host_routes = g_slist_append(dst->host_routes, froute);
#ifndef FAB_USE_CONX
        fab_route_install(froute);
#else
        fab_conx_route_install(froute);
#endif
        c_wr_unlock(&dst->lock);

        return 0;
    }

    return -1;
}

/**
 * @name fab_host_per_tenant_nw_add_route_pair - 
 * @Add host routes for a given src<->dst host pairs 
 * @param shost : Source host 
 * @param dhost : Destination host
 *
 * Add host routes for a given src<->dst host pairs 
 */
static void 
fab_host_per_tenant_nw_add_route_pair(void *shost, void *dhost)
{
    fab_host_route_add(shost, dhost);
    fab_host_route_add(dhost, shost);
}

/**
 * @name fab_host_per_tenant_nw_add_route - 
 * @brief Add host routes for a given src->dst host 
 * @param shost : Source host 
 * @param dhost : Destination host
 *
 */
static void 
fab_host_per_tenant_nw_add_route(void *shost, void *dhost)
{
    fab_host_route_add(shost, dhost);
}

/**
 * @name fab_route_port_cmp -
 * @brief Check whether fabric route has port as out_port for any path
 */
static int
fab_route_port_cmp(void *route_elem, void *sw_arg)
{
    fab_route_t *froute = route_elem;
    GSList *iterator;

    if (!froute->iroute) return 1;

    iterator = g_slist_find_custom(froute->iroute,
                                   sw_arg,
                                   (GCompareFunc)fab_route_elem_oport_cmp);
    if (iterator) return 0;

    return 1;
}

/**
 * @name fab_host_per_tenant_nw_delete_route - 
 * @brief Delete host routes for a given host for a network
 * @param elem_host : host of a tenant network
 * @param arg_host : host getting deleted 
 *
 */
static void 
fab_host_per_tenant_nw_delete_route(void *elem_host, void *arg_host)
{
    fab_host_t *host = elem_host;
    fab_host_t *del_host = arg_host;
    GSList *iterator;

    if (host == del_host) {
        return;
    }

    c_wr_lock(&host->lock);
    iterator = g_slist_find_custom(host->host_routes,
                                   del_host,
                                   (GCompareFunc)fab_route_from_host_cmp);
    if (!iterator) {
        app_rlog_err("%s: No host route between (0x%llx:%d) -> (0x%llx:%d)",
                  FN, (unsigned long long)(del_host->sw.swid),
                  del_host->sw.alias,
                  (unsigned long long)(host->sw.swid), host->sw.alias);
        c_wr_unlock(&host->lock);
        return;
    }

    fab_host_route_delete_1(iterator->data, NULL);

    host->host_routes = g_slist_remove(host->host_routes, iterator->data);
    c_wr_unlock(&host->lock);  

    return;
}

/**
 * @name __fab_routes_tofro_host_add - 
 * @brief Add host routes from all other hosts of same tenant network
 * @param host_arg : Fabric host pointer
 * @param key_arg : Unused arg
 * @param u_arg : User arg whether to install pair routes or not 
 *
 * NOTE - It is assumed that fab_ctx main lock is held prior
 * to invocation 
 */
void
__fab_routes_tofro_host_add(void *host_arg, void *key_arg UNUSED, void *u_arg)
{
    fab_host_t *host = host_arg;
    bool install_pair = *(bool *)u_arg;

    /* Do not continue if there is pending recalc all */
    if (fab_ctx->rt_recalc_pending) {
        app_rlog_err("%s: Cant add host route - Pending recal event", FN);
        return;
    }

    __fab_tenant_nw_loop_all_hosts(host->tenant_nw,
                                   install_pair ? 
                                   fab_host_per_tenant_nw_add_route_pair :
                                   fab_host_per_tenant_nw_add_route,
                                   host);
}

/**
 * @name __fab_host_route_del_with_port -
 * @brief  Delete all routes for a host which matches oport for a switch node 
 */
static void
__fab_host_route_del_with_port(void *host_arg, void *key_arg UNUSED,
                               void *sw_arg)
{
    fab_host_t *host = host_arg;
    GSList *iterator;
    fab_route_t *froute;

find_route:
    c_wr_lock(&host->lock);
    iterator = g_slist_find_custom(host->host_routes,
                                   sw_arg,
                                   (GCompareFunc)fab_route_port_cmp);
    if (!iterator) {
        c_wr_unlock(&host->lock);
        return;
    }

    froute = iterator->data;
    fab_route_uninstall(froute);

    host->host_routes = g_slist_remove(host->host_routes, iterator->data);
    c_wr_unlock(&host->lock);

    mul_destroy_route(froute->iroute);
    froute->iroute = NULL;

    if (froute->src->sw.swid != froute->dst->sw.swid) { 
        fab_host_per_tenant_nw_add_route(froute->src, froute->dst);
        fab_zaproute(froute);
    } else {
        __fab_add_to_pending_routes(fab_ctx, froute);
    }
    /*
     * Place a call to __fab_add_to_pending_routes(fab_ctx, froute);
     * instead of above 2 lines if there is no hurry to recalc new route
     */
    goto find_route;
}


/**
 * @name __fab_host_route_delete - 
 * @brief Delete host routes from all other hosts of same tenant network
 * @param host_arg : Fabric host pointer 
 * @param ctx_arg : Fabric context pointer 
 *
 * NOTE - It is assumed that fab_ctx main lock is held prior
 * to invocation 
 */
void
__fab_host_route_delete(void *host_arg, void *v_arg UNUSED, void *ctx_arg UNUSED)
{
    fab_host_t *host = host_arg;

    c_wr_lock(&host->lock);

    __fab_loop_all_host_routes(host, fab_host_route_delete_1, fab_ctx); 
    g_slist_free(host->host_routes);
    host->host_routes = NULL;

    c_wr_unlock(&host->lock);

    if (host->tenant_nw) {
        __fab_tenant_nw_loop_all_hosts(host->tenant_nw, 
                                   fab_host_per_tenant_nw_delete_route,
                                   host);
    }
}

/**
 * @name fab_reset_all_routes - 
 * @brief Reset all routes for all hosts
 * @param fab_ctx : Fabric context pointer 
 *
 */
void
fab_reset_all_routes(fab_struct_t *fab_ctx)
{
    fab_ctx->rt_recalc_pending = true;
    fab_ctx->rt_recalc_ts = time(NULL) + FAB_RT_RECALC_TS;

    fab_loop_all_hosts(fab_ctx, (GHFunc)__fab_host_route_delete, fab_ctx); 
    //fab_flush_pending_routes(fab_ctx);
}

/**
 * @name fab_add_all_routes - 
 * @brief Recalculate and add all routes for all hosts
 * @param fab_ctx : Fabric context pointer 
 *
 */
void
fab_add_all_routes(fab_struct_t *fab_ctx)
{
    bool add_pair = false;
    fab_loop_all_hosts(fab_ctx, (GHFunc)__fab_routes_tofro_host_add, &add_pair);
}

/**
 * @name fab_delete_routes_with_port -
 * @brief Delete all routes matching switch id and port number
 * @param fab_ctx :  Fabric context pointer
 * @param sw_alias : switch alias id
 * @param port_no : port number
 *
 */
void
fab_delete_routes_with_port(fab_struct_t *fab_ctx, int sw_alias, uint16_t port_no)
{
    fab_host_sw_t sw = { 0, 0, 0};
    sw.alias = sw_alias;
    sw.port  = port_no;

    usleep(200000); /* 200ms breather to routing */
    fab_loop_all_hosts_wr(fab_ctx, (GHFunc)__fab_host_route_del_with_port, &sw);
}

/**
 * @name fab_route_per_sec_timer - 
 * @brief Per second timer for fabric route management  
 * @param fab_ctx : Fabric context pointer 
 *
 */
void
fab_route_per_sec_timer(fab_struct_t *fab_ctx)
{
    time_t curr_ts = time(NULL);

    if (fab_ctx->rt_recalc_pending && 
        curr_ts > fab_ctx->rt_recalc_ts) {
        app_log_debug("%s: Recalc all host routes", FN);
        fab_ctx->rt_recalc_pending = false;
        fab_add_all_routes(fab_ctx);
    } 

    /* If there is a recalc event then there can be no pending routes */
    if (!fab_ctx->rt_recalc_pending) {
        fab_retry_pending_routes(fab_ctx, curr_ts);
    }

}
