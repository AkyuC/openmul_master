/**
 *  @file mul_route_servlet.c
 *  @brief Mul routing service APIs 
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

#include "mul_common.h"
#include "mul_route.h"
#include "mul_route_apsp.h"

GSList *mul_route_apsp_get_sp(void *rt_service, int src_sw, int dest_sw);

/**
 * @name mul_route_path_traverse -
 * @brief Traverse through all path elements of a route
 * @param [in] iroute List of route elements
 * @param [in] iter_fn Iteration callback per element
 * @param [in] arg Argument to be passed with iter_fn callback 
 *
 * @retval void Nothing
 */
void
mul_route_path_traverse(GSList *iroute, GFunc iter_fn, void *arg)
{
    if (iroute) {
        g_slist_foreach(iroute, (GFunc)iter_fn, arg);
    }

}

/**
 * @name mul_free_rt_links -
 * @brief Free all path elements of a route
 */
static void
mul_free_rt_links(void *ptr)
{
    free(ptr);
}

/**
 * @name mul_destroy_route -
 * @brief Free memory taken up by a topo route 
 * @param [in] route List of route elements
 * 
 * @retval void Nothing
 */ 
void
mul_destroy_route(GSList *route)
{
    if (route) {
        g_slist_free_full(route, mul_free_rt_links);
    }
}

/**
 * @name mul_route_init_block_meta -
 * @brief Initialize shared memory meta data for routing subsystem 
 * @param [in] rt_info Pointer to the metadata area for storing info
 * @param [in] blk The state info block which is locally allocated 
 * 
 * @retval void Nothing
 */
void
mul_route_init_block_meta(void *rt_info, void *blk)
{
    rt_apsp_t *rt_apsp_info = rt_info;

    rt_apsp_info->state_info = blk;
    rt_apsp_info->adj_matrix = (void *)(((uint8_t *)(blk))+sizeof(rt_apsp_state_t));
    rt_apsp_info->paths = (void *)((uint8_t *)(rt_apsp_info->adj_matrix) + 
                                        RT_APSP_MAX_MATRIX_SZ(sizeof(rt_adj_elem_t)));
}

/**
 * @name mul_route_service_get -
 * @brief Get a service handle to the routing service 
 * 
 * @retval void * Pointer to the client service handle
 */
void *
mul_route_service_get(void)
{
    void *ptr = NULL;
    rt_apsp_t *rt_apsp_info;
    int serv_fd;

    c_log_debug("%s: ", FN);

    if ((serv_fd = shm_open(MUL_TR_SERVICE_NAME, O_RDONLY, 0)) < 0) {
        c_log_err("%s: Cant get service (unavailable)", FN);
        return NULL;
    }

    perror("shm_open");

    ptr = mmap(0, RT_APSP_BLOCK_SIZE, PROT_READ, MAP_SHARED, serv_fd, 0);
    if (ptr == MAP_FAILED) {
        c_log_err("%s: Cant get service (failed to map)", FN);
        return NULL;
    }

    rt_apsp_info = calloc(1, sizeof(*rt_apsp_info));
    if (!rt_apsp_info) {
        c_log_err("%s: RT apsp info allocation fail", FN);
        return NULL;
    }

    mul_route_init_block_meta(rt_apsp_info, ptr);

    close(serv_fd);

    return (void *)rt_apsp_info;
}

/**
 * @name mul_route_service_destroy -
 * @brief Derefer service handle of the routing service
 * @param [in] rt_service pointer to the client service handle
 */
void
mul_route_service_destroy(void *rt_service)
{
    munmap((void *)rt_service, RT_APSP_BLOCK_SIZE);
    
    shm_unlink(MUL_TR_SERVICE_NAME);
}

/**
 * @name add_route_path_elem -
 * @brief Adds a path element to a route given adjacency info 
 * @param [in] route Double pointer to the route list
 * @param [in] node alias-id of the current node
 * @param [in] adj Adjacency information in struct lweight_pair_t *
 * @param [in] dpid datapath-id of the current node
 * @param [in] last_hop Bool:flag denoting if this is the last hop
 *
 * @retval void Nothing
 */
static inline void
add_route_path_elem(GSList **route, int node, lweight_pair_t *adj,
                    uint64_t dpid, bool last_hop)
{
    rt_path_elem_t *path_elem;

    path_elem = calloc(1, sizeof(*path_elem));
    path_elem->sw_alias = node;
    path_elem->sw_dpid = dpid;
    path_elem->flags = last_hop ? RT_PELEM_LAST_HOP :0;
    path_elem->in_port = NEIGH_NO_LINK; 
    
    memcpy(&path_elem->link, adj, sizeof(lweight_pair_t));

    if (!(*route)) {
        path_elem->flags |= RT_PELEM_FIRST_HOP;
    }

    *route = g_slist_append((*route), path_elem);
}

/**
 * @name mul_route_list_free -
 * @brief Free a route list
 * @param [in] path_head The head of the route list
 * @param [in] free_route Bool:true if individual routes need to be freed
 *
 * @retval void Nothing
 *
 * Route-list are used for holding multiple routes from point A to B
 * especially in 
 */
void
mul_route_list_free(rt_list_t *path_head, bool free_route)
{
    rt_list_t *cur_path = path_head, *prev_path = NULL;

    while (cur_path) {
        prev_path = cur_path;
        cur_path = cur_path->next;
        if (free_route && !prev_path->skip) {
            mul_destroy_route(prev_path->route);
        }
        free(prev_path);
    }
}

/**
 * @name mul_route_list_size -
 * @brief Return the number of routes in a route-list 
 * @param [in] rt_list Route list of routes
 *
 * @retval size_t number of individual routes in route list
 */
static size_t
mul_route_list_size(rt_list_t *rt_list)
{
    size_t n_routes = 0;

    while(rt_list) {
        rt_list = rt_list->next;
        n_routes++;
    }

    return n_routes;
}

/**
 * @name mul_print_route -
 * @brief Dump a route for printing
 */
static void  UNUSED
mul_print_route(GSList *route_path)
{
#define TR_ROUTE_PBUF_SZ 4096
    char *pbuf = calloc(1, TR_ROUTE_PBUF_SZ);
    int len = 0;
    GSList *iterator = NULL;
    rt_path_elem_t *rt_elem = NULL;

    len += snprintf(pbuf+len, TR_ROUTE_PBUF_SZ-len-1, "iROUTE: ");
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

    c_log_debug("%s", pbuf);
    free(pbuf);
}


/**
 * @name mul_routes_concat -
 * @brief Concat two routes to one 
 */
static  GSList *
mul_routes_concat(GSList *route1, GSList *route2)
{
    GSList *new_route = NULL;
    GSList *iterator = NULL;
    rt_path_elem_t *rt_elem_new = NULL;
    rt_path_elem_t *rt_elem = NULL;

    for (iterator = route1; iterator; iterator = iterator->next) {
        rt_elem = iterator->data;

        /* if (!iterator->next && route2) break;  */

        rt_elem_new = calloc(1, sizeof(*rt_elem_new));
        assert(rt_elem_new);
        memcpy(rt_elem_new, rt_elem, sizeof(*rt_elem_new));
        new_route = g_slist_append(new_route, rt_elem_new);
    }

    for (iterator = route2; iterator; iterator = iterator->next) {
        rt_elem = iterator->data;

        rt_elem_new = calloc(1, sizeof(*rt_elem_new));
        assert(rt_elem_new);
        memcpy(rt_elem_new, rt_elem, sizeof(*rt_elem_new));
        new_route = g_slist_append(new_route, rt_elem_new);
    }

    return new_route;
}

/**
 * @name mul_route_list_merge -
 * @brief Merge two route-lists into a single route-list 
 */
static void
mul_route_list_merge(rt_list_t **path, rt_list_t *path_ik,
                     rt_list_t *path_kj)
{
    rt_list_t *elem_path_ik = path_ik;
    rt_list_t *elem_path_kj = path_kj;
    rt_list_t *cur_path;

    while (elem_path_ik) {
        while (elem_path_kj) {
            cur_path = calloc(1, sizeof(*cur_path));
            cur_path->next = *path;
            *path = cur_path;

            cur_path->route = mul_routes_concat(elem_path_ik->route, elem_path_kj->route);

            elem_path_kj = elem_path_kj->next;
        }
        elem_path_ik = elem_path_ik->next;
    }

    /* Free ik and kj paths */
    mul_route_list_free(path_ik, true);
    mul_route_list_free(path_kj, true);
}

/**
 * @name mul_dump_route -
 *
 */
static char *
mul_dump_route(GSList *route_path)
{
#define _ROUTE_PBUF_SZ 4096
    char *pbuf = calloc(1, _ROUTE_PBUF_SZ);
    int len = 0;
    GSList *iterator = NULL;
    rt_path_elem_t *rt_elem = NULL;

    len += snprintf(pbuf+len, _ROUTE_PBUF_SZ-len-1, "iROUTE: ");
    assert(len < _ROUTE_PBUF_SZ-1);

    for (iterator = route_path; iterator; iterator = iterator->next) {
        rt_elem = iterator->data;

        len += snprintf(pbuf+len, _ROUTE_PBUF_SZ-len-1,
                        "Node(%d):Link(%hu)->",
                        rt_elem->sw_alias, rt_elem->link.la);
        assert(len < _ROUTE_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, _ROUTE_PBUF_SZ-len-1, "||\r\n");
    assert(len < _ROUTE_PBUF_SZ-1);

    return pbuf;
}

/**
 * @name mul_route_list_dump -
 *
 */
static void UNUSED
mul_route_list_dump(rt_list_t *path_head)
{
    rt_list_t *cur_path = path_head;
    int i = 0;
    char *dump_route;

    while (cur_path) {
        c_log_debug("List # %d", i++);
        dump_route = mul_dump_route(cur_path->route);
        c_log_err(" %s", dump_route);
        if (dump_route) free(dump_route);
        cur_path = cur_path->next;
    }
}


/**
 * @name mul_route_apsp_get_subp -
 * @brief Get a list of shortest paths between src and dest 
 *        int form of rt_list_t
 */
static rt_list_t *
mul_route_apsp_get_subp(rt_apsp_t *rt_apsp_info, int src, int dest, int *max_hops)
{
    int transit_sw = NEIGH_NO_PATH;
    rt_list_t *path = NULL;
    rt_list_t *path_ik;
    rt_list_t *path_jk;
    int n = 0;

    if (*max_hops <= 0) {
        c_log_debug("%s: max-hops exceeded", FN);
        return path;
    }
    --*max_hops;

    for (; n < RT_MAX_EQ_PATHS; n++) {

        if (((transit_sw = RT_APSP_PATH_ELEM(rt_apsp_info, src, dest)->sw_alias[n])
                                == NEIGH_NO_PATH)) {
            if (rt_apsp_onlink_neigh(rt_apsp_info, src, dest)) {

                path = calloc(1, sizeof(*path));
                add_route_path_elem(&path->route, src,
                                    rt_apsp_get_pair(rt_apsp_info, src, dest),
                                    rt_apsp_get_src_dp(rt_apsp_info, src, dest),
                                    false);
                /* c_log_err("%s: onlink route between %d to %d", FN, src, dest); */
            } else {
                /* c_log_err("%s: No route between %d to %d", FN, src, dest); */
            }

            return path;
        }

        if (src == transit_sw || dest == transit_sw) {
            return path;
        }

        path_ik = mul_route_apsp_get_subp(rt_apsp_info, src, transit_sw, max_hops);
        path_jk = mul_route_apsp_get_subp(rt_apsp_info, transit_sw, dest, max_hops);

        mul_route_list_merge(&path, path_ik, path_jk);

    }

    return path;
}


/**
 * @name mul_route_select_single_and_purge_list -
 * @brief Grabs a route from route list as denoted by rt_select_hint 
 *        and return to caller
 * @route_list : A route list
 * @rt_select_hint : a hint in form of integer to aid selection among multiple routes 
 *
 * @retval GSList * Pointer to the selected route
 *
 * If rt_select_hint > number of routes in route list it will return NULL    
 */
static GSList *
mul_route_select_single_and_purge_list(rt_list_t *route_list, size_t rt_select_hint)
{
    GSList *route = NULL;
    rt_list_t *tmp;
    size_t rt_count = 0;

    if (!route_list) {
        return route;
    }

    while (route_list) {
        tmp = route_list;
        route_list = route_list->next;

        if (rt_count++ == rt_select_hint) {
            route = tmp->route;
        } else {
            mul_destroy_route(tmp->route);
        }

        free(tmp);
    }

    return route;
}

/**
 * @name mul_route_prep_out -
 * @brief Adds inport and flags info for each element or node 
 * @param [in] route : A route 
 *
 * @retval int zero for success or non-zero for failure
 */
static int 
mul_route_prep_out(GSList *route)
{
    GSList *prev = NULL, *curr;
    rt_path_elem_t *rt_prev_elem, *rt_elem;
    int ret = 0;

    for (curr = route; curr; curr = curr->next) {
        rt_elem = curr->data;

        rt_elem->flags = 0;
        if (prev) {
            rt_prev_elem = prev->data;
            rt_elem->in_port = rt_prev_elem->link.lb;
        } else {
            rt_elem->flags |= RT_PELEM_FIRST_HOP;
        }

        /* Safety check */
        if (curr->next && rt_elem->link.la == NEIGH_NO_LINK) {
            ret = -1;
        }

        prev = curr;
    }

    if (prev) {
        rt_prev_elem = prev->data;
        rt_prev_elem->flags |= RT_PELEM_LAST_HOP;
    }

    return ret;
}

/**
 * @mul_route_apsp_get_mp_sp -
 * @brief Get shortest path between src_sw and dest_sw. 
 * @param [in] rt_service Pointer to the rt_service client 
 * @param [in] src_sw Source switch alias-id
 * @param [in] dest_sw Destination switch alias-id
 * @param [in] u_arg User argument to be passed when mp_select callback is invoked
 * @param [in] mp_select Callback to selects a single route in case of multiple ecmp 
 *                       routes 
 * @param [in] bpairs Bool:true to specify whether all route pairs are required 
 *                         else false
 * @retval void * Pointer to a route_list
 *
 * If multiple paths exists it will select a path based of user provided 
 * mp_select function or the first availabe route if mp_select is not provided
 */ 
static void *
mul_route_apsp_get_mp_sp(void *rt_service, int src_sw, int dest_sw, void *u_arg,
                         size_t (*mp_select)(void *u_arg, size_t max_routes),
                         bool bpairs)
{
    uint64_t dest_sw_dpid = 0;
    unsigned int lock, max_retries = 0;
    int max_hops; 
    rt_apsp_t *rt_apsp_info = rt_service;
    GSList *route = NULL;
    rt_list_t *route_list = NULL, *tmp = NULL;
    size_t mp_rt_hint = 0, num_mp_routes = 0; 
    lweight_pair_t last_hop = { NEIGH_NO_LINK, NEIGH_NO_LINK, 
                                NEIGH_NO_PATH, 0 };

    if (src_sw == dest_sw) {
        route_list = calloc(1, sizeof(*route_list));
        if (!route_list) return NULL;
        goto route_same_node;
    }

    if (!(dest_sw_dpid = c_app_switch_get_dpid_with_alias(dest_sw))) {
        c_log_err("%s: No such  last hop %d", FN, dest_sw);
        return NULL;
    }

retry:
    max_hops = MAX_SWITCHES_PER_CLUSTER*RT_MAX_EQ_PATHS;
    if (max_retries++ >= RT_MAX_GET_RETRIES) {
        c_log_err("Too much writer contention or service died");
        return NULL;
    }

    lock = c_seq_rd_lock(&rt_apsp_info->state_info->lock);
    if (!rt_apsp_converged(rt_apsp_info)) {
        if (c_seq_rd_unlock(&rt_apsp_info->state_info->lock,
                            lock))  {
            goto retry;
        }
        c_log_err("%s: Routes not yet converged", FN);
        return NULL;
    }

    if (rt_apsp_get_weight(rt_apsp_info, src_sw, dest_sw) == NEIGH_NO_PATH) {
        if (c_seq_rd_unlock(&rt_apsp_info->state_info->lock,
                            lock))  {
            goto retry;
        }
        c_log_err("%s: Not a neigbour (%d:%d) %d", FN, src_sw, dest_sw, 
                  rt_apsp_get_weight(rt_apsp_info, src_sw, dest_sw));
        return NULL;
    }

    route_list = mul_route_apsp_get_subp(rt_apsp_info, src_sw, dest_sw, &max_hops); 
    if (mp_select) {
        num_mp_routes = mul_route_list_size(route_list);
        mp_rt_hint = mp_select(u_arg, num_mp_routes); 
        if (mp_rt_hint >= num_mp_routes) {
            /* Silently ignore any user advice on multi-path selection */
            mp_rt_hint = 0;
        }
    }

    if (!bpairs) {
        route = mul_route_select_single_and_purge_list(route_list, mp_rt_hint);
        route_list = calloc(1, sizeof(*route_list));
        if (!route_list) {
            mul_destroy_route(route);
            route = NULL;
        } else {
            route_list->route = route;
        }
    }

    if (c_seq_rd_unlock(&rt_apsp_info->state_info->lock, lock)) {
        mul_route_list_free(route_list, true);
        goto retry;
    }

    if (max_hops <= 0) {
        mul_route_list_free(route_list, true);
        return NULL;
    }

route_same_node:
    
    for (tmp = route_list; tmp; tmp = tmp->next) {
        route = tmp->route;
        add_route_path_elem(&route, dest_sw, &last_hop, dest_sw_dpid, true);
        if (mul_route_prep_out(route)) {
            mul_destroy_route(route);
            route = NULL; 
            route_list->route = NULL;
        }
    }

    return route_list;
}

/**
 * @name mul_route_apsp_get_sp -
 * @brief Wrapper api on top of mul_route_apsp_get_mp_sp()
 * @param [in] route_service : Handle to the route service 
 * @param [in] src_sw : Source node  
 * @param [in] dest_sw : Destination node 
 *
 * Wrapper api on top of mul_route_apsp_get_mp_sp(). It does not take 
 * into account multi-pathing routes 
 */
GSList *
mul_route_apsp_get_sp(void *rt_service, int src_sw, int dest_sw)
{
    GSList *route = NULL;
    rt_list_t *route_list = NULL;

    route_list = mul_route_apsp_get_mp_sp(rt_service, src_sw, dest_sw, 
                                          NULL, NULL, false);
    if (route_list) {
        route = route_list->route;
        free(route_list);
        return route;
    }
    return NULL;
}

/**
 * @name mul_route_service_alive -
 * @brief Checks status of routing service 
 * @param [in] service : Handle to the route service 
 *
 * @retval bool true if service is alive
 */
static bool
mul_route_service_alive(void *service)
{
    rt_apsp_t *rt_apsp_info = service;
    time_t curr_ts = time(NULL);

    if (curr_ts >
        (rt_apsp_info->state_info->serv_ts + (2*RT_HB_INTVL_SEC))) {
        c_log_err("%s: %s not available", FN, MUL_TR_SERVICE_NAME);
        return false;
    }

    return true;
}

/**
 * @name mul_route_get_nodes -
 * @brief Get number of nodes in routing matrix 
 * @param [in] rt_service : Handle to the route service 
 *
 * @retval size_t number of active nodes in topology
 */
size_t
mul_route_get_nodes(void *rt_service)
{
    rt_apsp_t *rt_apsp_info = rt_service;

    if (!mul_route_service_alive(rt_service)) {
        return 0;
    }

    return rt_apsp_info->state_info->nodes;
} 

/**
 * @name mul_route_get -
 * @brief Front-end api of routing service to get route from source to dest 
 * @param [in] rt_service : Handle to the route service 
 * @param [in] src_sw : Source node  
 * @param [in] dest_sw : Destination node 
 *
 * Applicable when users dont want multi-pathing support
 */
GSList *
mul_route_get(void *rt_service, int src_sw, int dest_sw)
{
    rt_apsp_t *rt_apsp_info = rt_service;

    if (!mul_route_service_alive(rt_service)) {
        return 0;
    }

    if (src_sw < 0 || dest_sw < 0 ||
        ((src_sw != dest_sw) && (src_sw >= rt_apsp_info->state_info->nodes ||
        dest_sw >= rt_apsp_info->state_info->nodes))) {
        c_log_err("%s: src(%d) or dst(%d) out of range(%d)",
                  FN, src_sw, dest_sw, (int)rt_apsp_info->state_info->nodes);
        return NULL;
    }

    return mul_route_apsp_get_sp(rt_service, src_sw, dest_sw);
}

/**
 * @name mul_route_get_mp -
 * @brief Front-end api of routing service to get route from source to dest 
 * @param [in] rt_service : Handle to the route service 
 * @paam [in] src_sw : Source node  
 * @param [in] dest_sw : Destination node 
 * @param [in] u_arg : User argument to be passed to mp_select  
 * @param [in] mp_select : Callback for aiding multi-pathing selection
 *
 * Applicable when users want multi-pathing support
 */
GSList *
mul_route_get_mp(void *rt_service, int src_sw, int dest_sw,  void *u_arg,
                 size_t (*mp_select)(void *u_arg, size_t max_routes))
{
    rt_apsp_t *rt_apsp_info = rt_service;
    GSList *route = NULL;
    rt_list_t *route_list = NULL;

    if (!mul_route_service_alive(rt_service)) {
        return 0;
    }

    if (src_sw < 0 || dest_sw < 0 ||
        ((src_sw != dest_sw) && (src_sw >= rt_apsp_info->state_info->nodes ||
        dest_sw >= rt_apsp_info->state_info->nodes))) {
        c_log_err("%s: src(%d) or dst(%d) out of range(%d)",
                  FN, src_sw, dest_sw, (int)rt_apsp_info->state_info->nodes);
        return NULL;
    }

    route_list = mul_route_apsp_get_mp_sp(rt_service, src_sw, dest_sw,
                                          u_arg, mp_select, false);

    if (route_list) {
        route = route_list->route;
        free(route_list);
        return route;
    }
    return NULL;

}

/**
 * @name mul_route_get_all -
 * @brief Front-end api of routing service to get all ecmp routes 
 *        from source to dest 
 * @brief rt_service : Handle to the route service 
 * @param [in] src_sw : Source node  
 * @param [in] dest_sw : Destination node 
 * @param [in] u_arg : User argument to be passed to mp_select  
 * @param [in] mp_select : Callback for multi-pathing selection
 *
 */
rt_list_t *
mul_route_get_all(void *rt_service, int src_sw, int dest_sw)
{
    rt_apsp_t *rt_apsp_info = rt_service;
    rt_list_t *route_list = NULL;

    if (!mul_route_service_alive(rt_service)) {
        return 0;
    }

    if (src_sw < 0 || dest_sw < 0 ||
        ((src_sw != dest_sw) && (src_sw >= rt_apsp_info->state_info->nodes ||
        dest_sw >= rt_apsp_info->state_info->nodes))) {
        c_log_err("%s: src(%d) or dst(%d) out of range(%d)",
                  FN, src_sw, dest_sw, (int)rt_apsp_info->state_info->nodes);
        return NULL;
    }

    route_list = mul_route_apsp_get_mp_sp(rt_service, src_sw, dest_sw,
                                          NULL, NULL, true);
    return route_list;
}
