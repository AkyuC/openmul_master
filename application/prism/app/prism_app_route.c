/*
 *  prism_app_route.c: PRISM application for MUL Controller 
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
#include "prism_app_route.h"
#include "prism_app_nh.h"
#include "prism_app_vif.h"
#include "mul_patricia.h"

char *
prism_dump_single_route(prism_rt_elem_t *route)
{
    char nh_ip_str[32];
    prism_nh_elem_t *nh_ptr = route->nh_ptr;
    char     *pbuf = calloc(1, ROUTE_PBUF_SZ);
    struct in_addr in_addr, in_mask, nh_addr;
    int len = 0;
    in_addr.s_addr = htonl(route->hkey.dst_nw);
    in_mask.s_addr = htonl(route->hkey.dst_nm);
    
    if(nh_ptr) {
        nh_addr.s_addr = htonl(nh_ptr->hkey.next_hop);
        len += snprintf(pbuf+len, ROUTE_PBUF_SZ - len - 1,
                "Host-IP %s/%d next-hop-ip %s conn-dpid 0x%lx Outport %u Flags"
                " RT_INDIRECT\n",
                inet_ntoa(in_addr),(int)c_count_one_bits(ntohl(in_mask.s_addr)),
                inet_ntop(AF_INET,(struct sockaddr_in*)&nh_addr, nh_ip_str,
                    INET_ADDRSTRLEN), route->dpid, nh_ptr->oif);
    }
    else {
        len += snprintf(pbuf+len, ROUTE_PBUF_SZ - len - 1,
                "Host-IP %s/%d Flags RT_DIRECT\n",
                inet_ntoa(in_addr),(int)c_count_one_bits(ntohl(in_mask.s_addr)));
    }

    assert(len < ROUTE_PBUF_SZ);

    return pbuf;

}

/**
 * prism_route_hash_func- 
 * @key: Prism route hash key 
 *
 * Derive a hash val froma route key 
 */
unsigned int                     
prism_route_hash_func(const void *key)
{
    const prism_rt_elem_t *rt_elem = key;

    return hash_bytes(rt_elem, sizeof(prism_rt_hash_key_t), 1);
} 

/**
 * prism_route_equal_func - 
 * @key1: prism route1 hash key 
 * @key2: prism route2 hash key 
 *
 * Deduce if two routes are equal
 */
int 
prism_route_equal_func(const void *key1, const void *key2)
{       
    return !memcmp(key1, key2, sizeof(prism_rt_hash_key_t));
} 

/**
 * prism_compare_rt_key-
 *
 * Key comparison function for Next Hop
 */
int
prism_compare_rt_key(void *h_arg, void *v_arg UNUSED, void *u_arg)
{
    prism_rt_hash_key_t *key = u_arg;
    prism_rt_elem_t *rt_elem = h_arg;

    if(rt_elem->hkey.dst_nw == key->dst_nw &&
       rt_elem->hkey.dst_nm == key->dst_nm)
        return true;

    return false;
}

/**
 * prism_del_flow_via_conx -
 *
 * Calls ConX API to uninstall flows in edge nodes
 */

static void
prism_prep_src_dpid_list(void *vif_elem, void *v_arg UNUSED, void *path)
{
    prism_vif_elem_t *src_elem = vif_elem;
    prism_path_elem_t *path_elem = path;
    
    if(!(src_elem->hkey.dpid == path_elem->dst_dpid &&
            src_elem->hkey.port == path_elem->out_port)) {
        app_log_debug("%s: S.DPID %llx,oif %u, D.DPID:%llx, oif %u",
                FN, U642ULL(src_elem->hkey.dpid), src_elem->hkey.port,
                U642ULL(path_elem->dst_dpid),
                path_elem->out_port);
    
        path_elem->src_dpid[path_elem->n_src_dpid] =
            src_elem->hkey.dpid;
        path_elem->n_src_dpid++;
    }
}

/**
 * prism_add_route_via_conx -
 *
 * Iterates all the edge nodes to install flows for a route
 */
void 
prism_add_route_via_conx(void *elem, void *key_arg UNUSED, void
        *u_arg UNUSED)
{
    prism_rt_elem_t *rt_elem = (prism_rt_elem_t *) elem;
    prism_nh_elem_t *nh_elem = rt_elem->nh_ptr;
    prism_path_elem_t path_node;
    struct mul_act_mdata mdata;
    struct in_addr in_mask;
    int ret = 0;
    uint32_t flags = CONX_UFLOW_FORCE;
    //size_t n_src_dpid = 0;
     
    memset(&path_node, 0 , sizeof(prism_path_elem_t));

    /*Dest edge node DPID*/
    path_node.dst_dpid = nh_elem->dpid;
    path_node.out_port = nh_elem->oif;

    /* Set dl_type as IPv4*/
    path_node.flow.dl_type = htons(ETH_TYPE_IP);
    of_mask_set_dl_type(&path_node.mask);
    
    /* Dest egde node ip address (Resolved Next Hop)*/
    path_node.flow.ip.nw_dst = htonl(rt_elem->hkey.dst_nw);
    in_mask.s_addr = htonl(rt_elem->hkey.dst_nm);
    of_mask_set_nw_dst(&path_node.mask,
            (int)c_count_one_bits(ntohl(in_mask.s_addr)) );

    /* Default route */
    if (!path_node.flow.ip.nw_dst)
        flags |= CONX_UFLOW_DFL;

    mul_app_act_alloc(&mdata);
    mdata.only_acts = false;
    mul_app_act_set_ctors(&mdata, path_node.dst_dpid);

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
    /* Next Hop IP will used as metadata*/
    mul_app_inst_wr_meta(&mdata, nh_elem->hkey.next_hop, 0xFFFFFFFF);
    
    /* Set instruction goto as to direct the flow to Next Hop table*/
    mul_app_inst_goto(&mdata, PRISM_NEXT_HOP_TABLE_ID);
#else

    /* Associate group ID for next hop with edge flow */
    mul_app_action_set_group(&mdata, nh_elem->g_parms.group);

#endif
    path_node.action_list = mdata.act_base;
    path_node.action_len = mul_app_act_len(&mdata);

    /* Dest Node(port+dpid) will not be counted as src node*/
    //n_src_dpid = g_hash_table_size(prism_ctx->vif_hasher_db) - 1;

    path_node.src_dpid = calloc(path_node.n_src_dpid, sizeof(uint64_t));

    app_log_debug("%s: Install Route 0x%x Next Hop 0x%x", FN,
            rt_elem->hkey.dst_nw, nh_elem->hkey.next_hop);

    __prism_loop_all_vif(prism_ctx, prism_prep_src_dpid_list, &path_node); 

    ret = mul_conx_mod_uflow(prism_ctx->prism_conx_service,
                true, path_node.n_src_dpid, path_node.src_dpid,
                path_node.dst_dpid,
                &path_node.flow, /* Ingress Flow*/
                &path_node.mask,
                0, 0,
                path_node.action_list,
                path_node.action_len,
                C_FL_NO_ACK, flags);
    if(ret != 0 ) {
        app_log_err("Failed to add flows through ConX");
    }

    free(path_node.src_dpid);

    mul_app_act_free(&mdata);
}

/**
 * prism_delete_route_via_conx -
 */
void 
prism_delete_route_via_conx(void *elem, void *key_arg UNUSED, void
        *u_arg UNUSED)
{
    prism_rt_elem_t *rt_elem = (prism_rt_elem_t *) elem;
    prism_nh_elem_t *nh_elem = rt_elem->nh_ptr;
    prism_path_elem_t path_node;
    struct in_addr in_mask;
    int ret = 0;
    uint32_t flags = CONX_UFLOW_FORCE;
    //size_t n_src_dpid = 0;
    
    memset(&path_node, 0 , sizeof(prism_path_elem_t));

    /*Dest edge node DPID*/
    path_node.dst_dpid = nh_elem->dpid;
    path_node.out_port = nh_elem->oif;

    /* Set dl_type as IPv4*/
    path_node.flow.dl_type = htons(ETH_TYPE_IP);
    of_mask_set_dl_type(&path_node.mask);
    
    /* Dest egde node ip address (Resolved Next Hop)*/
    path_node.flow.ip.nw_dst = htonl(rt_elem->hkey.dst_nw);
    in_mask.s_addr = rt_elem->hkey.dst_nm;
    of_mask_set_nw_dst(&path_node.mask,
            (int)c_count_one_bits(ntohl(in_mask.s_addr)) );

    /* Default route */
    if (!path_node.flow.ip.nw_dst)
        flags |= CONX_UFLOW_DFL;
    
    app_log_debug("%s: Uninstall Route 0x%x Next Hop 0x%x", FN,
            rt_elem->hkey.dst_nw, nh_elem->hkey.next_hop);

    /* Dest Node(port+dpid) will not be counted as src node*/
    //n_src_dpid = g_hash_table_size(prism_ctx->vif_hasher_db) - 1;

    path_node.src_dpid = calloc(path_node.n_src_dpid, sizeof(uint64_t));
    __prism_loop_all_vif(prism_ctx, prism_prep_src_dpid_list, &path_node); 

    ret = mul_conx_mod_uflow(prism_ctx->prism_conx_service,
                false, path_node.n_src_dpid, path_node.src_dpid,
                path_node.dst_dpid,
                &path_node.flow, /* Ingress Flow*/
                &path_node.mask,
                0, 0,
                path_node.action_list,
                path_node.action_len,
                0, flags);
    if(ret != 0 ) {
        app_log_err("Failed to del flows through ConX");
    }

    free(path_node.src_dpid);
}
/**
 * __prism_loop_all_routes -
 * @prism_ctx  : Pointer to Prism APP context
 * @iter_fn    : Iteration callback for each route of next hop
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all routes of a tenant and invoke callback for each
 * NOTE - lockless version and assumes fab_ctx lock as held
 */
void
__prism_loop_all_routes(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
                               void *u_data)
{
    if (prism_ctx->route_hasher_db) {
        g_hash_table_foreach(prism_ctx->route_hasher_db,
                        (GHFunc)iter_fn, u_data);
    }
}

/**
 * prism_loop_all_routes -
 * @prism_ctx  : Pointer to Prism APP context
 * @iter_fn    : Iteration callback for each route of next hop
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all routes of a tenant and invoke callback for each
 * NOTE - lockless version and assumes fab_ctx lock as held
 */
void
prism_loop_all_routes(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
                               void *u_data)
{
    c_wr_lock(&prism_ctx->lock);
    __prism_loop_all_routes(prism_ctx, iter_fn, u_data);
    c_wr_unlock(&prism_ctx->lock);
}

/**
 * __prism_loop_all_routes_per_nh -
 * @nh_elem    : Next Hop pointer
 * @iter_fn    : Iteration callback for each route of next hop
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all routes of a tenant and invoke callback for each
 * NOTE - lockless version and assumes fab_ctx lock as held
 */
void
__prism_loop_all_routes_per_nh(prism_nh_elem_t *nh_elem, GHFunc iter_fn,
                               void *u_data UNUSED)
{
    if (nh_elem->route_list) {
        g_slist_foreach(nh_elem->route_list,
                        (GFunc)iter_fn, u_data);
    }
    assert(nh_elem->route_list);
}

static unsigned int UNUSED
add_route_pat_tree(prism_app_struct_t *prism_ctx, prism_rt_hash_key_t *rt_key, uint32_t rt_flags)
{

    struct pat_tree *phead = prism_ctx->ptree;
    struct pat_tree *pnode ,*pfind;
    struct pat_tree_mask *pmask;

    pnode = (struct pat_tree *)calloc(1, sizeof(struct pat_tree));

    /* Allocate the mask data */
    pnode->pat_mask = (struct pat_tree_mask *)calloc( 1,
            sizeof(struct pat_tree_mask));
    /*
     * Allocate the data for this node.
     * Replace 'struct MyNode' with whatever you'd like.
     */
    pmask = pnode->pat_mask;
    pmask->pm_data = (struct pat_rt_elem_data *)calloc(1, 
            sizeof(struct pat_rt_elem_data));

    /* Assign a value to the IP address and mask field for this
     * node */

    pnode->pat_key = rt_key->dst_nw;     
    
    pnode->pat_mask->pm_mask = rt_key->dst_nm;

    memcpy(pmask->pm_data, &rt_flags, sizeof(struct pat_rt_elem_data));

    /* Finds the closest match */
    pfind = mul_pat_search(pnode->pat_key, phead);
    
    if(pfind->pat_key == (pnode->pat_key & pnode->pat_mask->pm_mask)) {
        app_log_info("Route Entry already Present %08lx: ", pfind->pat_key);
        return PRTM_DUP_ROUTE;
    }
    else {
        app_log_debug("Route Entry Inserted Route: %08lx Mask: %08lx",
                pnode->pat_key, pnode->pat_mask->pm_mask);
        /* Insert the node */
        if(!mul_pat_insert(pnode, phead)) {
            app_log_err("%s: Insertion in Patricia Trie failed", FN);
            free(pnode->pat_mask->pm_data);
            free(pnode->pat_mask);
            free(pnode);
            return PRTM_INTERNAL_ERROR;
        }
    }
    return 0;
}

/**
 * __prism_route_add-
 *
 * Service handler for legacy route add
 */
unsigned int
__prism_route_add(prism_app_struct_t *prism_ctx, uint32_t dst_nw, 
                  uint32_t dst_nm, uint32_t nh, uint64_t dpid, uint32_t oif)
{
    prism_rt_elem_t *rt_elem = NULL;
    prism_nh_elem_t *nh_elem = NULL;
    prism_rt_hash_key_t rt_key;
    prism_nh_hash_key_t nh_key;
    uint32_t rt_flags = RT_INDIRECT;
    uint32_t code = 0;

    /* Prepare Next Hop Key*/
    memset(&nh_key, 0, sizeof(nh_key));
    nh_key.next_hop = nh;

    /*Key for route elem*/
    memset(&rt_key, 0, sizeof(rt_key));
    rt_key.dst_nw = dst_nw; 
    rt_key.dst_nm = dst_nm; 

    /* Check if this is a direct route*/
    if(!nh) {
		app_log_debug("direct");
        rt_flags = RT_DIRECT;
        /*FIXME: In future we may not store direct routes in Hash Table as
         * we are not doing anything by keeping these entries*/
	}
#if 0
    /* Stote the route info in patricia tree */
    code = add_route_pat_tree(prism_ctx, &rt_key, rt_flags);
#endif
    if((rt_elem = g_hash_table_lookup(prism_ctx->route_hasher_db,
                                     &rt_key))) {
        app_log_err("%s:Ignored Duplicate Route Add", FN);
        code = PRTM_DUP_ROUTE;
    }
    if(code)
        goto rt_add_end;

    if((rt_flags == RT_INDIRECT) && 
            !(nh_elem = g_hash_table_lookup(prism_ctx->nh_hasher_db,
                                   &nh_key))) {
        /*No Next hop entry present*/
        nh_elem = calloc(1, sizeof(prism_nh_elem_t));
        assert(nh_elem);

        nh_elem->hkey = nh_key;
        nh_elem->dpid = dpid;
        nh_elem->oif = oif;
        nh_elem->nh_flags = NH_INCOMPLETE;

        rt_flags = RT_INDIRECT;

        /* Store a new entry for Next Hop*/
        g_hash_table_insert(prism_ctx->nh_hasher_db, nh_elem, nh_elem);
		app_log_debug("Indirect, dpid 0x%llx oif %u", U642ULL(dpid),
                oif);
    }

    /*Prepare new route element to insert*/
    rt_elem = calloc(1, sizeof(prism_rt_elem_t));
    assert(rt_elem);

    rt_elem->hkey = rt_key;
    rt_elem->dpid = dpid;
    rt_elem->rt_flags = rt_flags;

    rt_elem->nh_ptr = nh_elem;
    /* Store route entry in route hash table */
    g_hash_table_insert(prism_ctx->route_hasher_db, rt_elem, rt_elem);
    
    app_log_debug("%s: Route (0x%x) mask (0x%x) nh (0x%x)",
                FN, (unsigned)(rt_key.dst_nw),
                (unsigned)(rt_key.dst_nm),
                (unsigned)(nh));

    
    /*Check if this is indirect route*/
    if(nh_elem) {
        /* Add one more route to this next hop route list*/
        nh_elem->route_list = g_slist_append(nh_elem->route_list, rt_elem);

        if((nh_elem->nh_flags == NH_REACHABLE) || 
           (nh_elem->nh_flags == NH_STALE)) {
            /* Pass the info to ConX Service*/
            prism_add_route_via_conx(rt_elem, NULL, NULL);
        }
    }

rt_add_end:
    return code;
}

/**
 * prism_route_add-
 *
 * Service handler for legacy route add
 */
unsigned int
prism_route_add(prism_app_struct_t *prism_ctx, uint32_t dst_nw, uint32_t dst_nm,
                            uint32_t nh, uint64_t dpid, uint32_t oif)
{
    uint32_t code = 0;
    c_wr_lock(&prism_ctx->lock);
    code = __prism_route_add(prism_ctx, dst_nw, dst_nm, nh, dpid, oif);
    c_wr_unlock(&prism_ctx->lock);
    return code;
}



/**
 * __prism_route_delete-
 *
 * Service handler for legacy route del
 */
unsigned int
__prism_route_delete(prism_app_struct_t *prism_ctx, uint32_t dst_nw,
                     uint32_t dst_nm, bool free_nh)
{
    prism_rt_elem_t *rt_elem = NULL;
    prism_nh_elem_t *nh_elem = NULL;
//    struct pat_tree *pnode = NULL;
    prism_rt_hash_key_t rt_key;
    uint32_t code = 0;
    struct flow fl, mask;
    prism_switch_t *prism_sw = NULL;
    
    memset(&fl, 0, sizeof(fl));
    memset(&mask, 0, sizeof(mask));
    of_mask_set_dc_all(&mask);

    /*Key for route elem*/
    memset(&rt_key, 0, sizeof(rt_key));
    rt_key.dst_nw = dst_nw; 
    rt_key.dst_nm = dst_nm; 

    /*Check if Route is present or not */
    if((rt_elem = g_hash_table_lookup(prism_ctx->route_hasher_db,
                    &rt_key))) {

        nh_elem = rt_elem->nh_ptr;

        if(nh_elem) {
            /* Delete this route from next hop route list*/
            nh_elem->route_list = g_slist_remove(nh_elem->route_list, rt_elem);

            /* If Next Hop is resolved then 
               Delete route from edge nodes Via Conx Service */
            if(nh_elem->nh_flags != NH_INCOMPLETE)
                prism_delete_route_via_conx(rt_elem, NULL, NULL);
            
            /* If next hop is not associated with any other route 
               then destroy next hop entry from NH hasher DB */
            if(!nh_elem->route_list && free_nh) {

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
                /* Uninstall flow from Next Hop table*/
                prism_next_hop_flow_uninstall(nh_elem->hkey.next_hop, nh_elem->dpid);
#else
                prism_next_hop_group_uninstall(nh_elem);

                /* Get the switch and hold it, this might be needed while
                 * returning group ID for next Hop.*/
                prism_sw = __prism_switch_get(prism_ctx, nh_elem->dpid);
                if (!prism_sw) {
                    app_log_err("%s: Unknown switch (0x%llx)", FN,
                            U642ULL(nh_elem->dpid));
                    code = PNHM_DPID_NOT_EXIST;
                    goto prism_nh_remove;
                }

                c_wr_lock(&prism_sw->lock);
                /* Free group ID and return it to the pool*/
                if (prism_sw->group_ipool) {
                    ipool_put(prism_sw->group_ipool, nh_elem->group_id);
                }

                c_wr_unlock(&prism_sw->lock);

                /* Group ID have been returned to the pool, 
                   No need to hold the switch any more*/
                prism_switch_put(prism_sw);

prism_nh_remove:
                if(nh_elem->g_parms.act_vectors[0]->actions)
                    free(nh_elem->g_parms.act_vectors[0]->actions);
                if(nh_elem->g_parms.act_vectors[0])
                    free(nh_elem->g_parms.act_vectors[0]);
#endif
                /* Clean the entry from Next Hop Hash Table*/
                g_hash_table_remove(prism_ctx->nh_hasher_db, nh_elem);
            }
        }

        /* Delete route entry in route hash table */
        g_hash_table_remove(prism_ctx->route_hasher_db, rt_elem);
        app_log_debug("%s: Removed Route (0x%x) mask (0x%x)",
                FN, (unsigned)( rt_key.dst_nw), rt_key.dst_nm);
#if 0
        pnode = calloc(1, sizeof(struct pat_tree));
        pnode->pat_key = dst_nw;
        pnode->pat_mask = calloc(1, sizeof(struct pat_tree_mask));
        pnode->pat_mask->pm_mask = dst_nm;

        if(!mul_pat_remove(pnode, prism_ctx->ptree)) {
            app_log_err("%s: Error in removing Route (0x%x) mask (%lx) from"\
                    " Patricia Tree",
                FN, (unsigned)( rt_key.dst_nw), U322UL(rt_key.dst_nm));
            code = PRTM_INTERNAL_ERROR;
        }
        else {
            app_log_debug("%s: Removed Route (0x%x) mask (%u) from"\
                    " Patricia Tree",
                FN, (unsigned)( rt_key.dst_nw), rt_key.dst_nm);
        }

        free(pnode->pat_mask);
        free(pnode);
#endif
    }
    else {
        app_log_err("%s: Route (0x%x) mask (0x%x) not present",
                FN, (rt_key.dst_nw),
                rt_key.dst_nm);
        code = PRTM_ROUTE_NOT_EXIST;
    }

    return code;
}
/**
 * prism_route_delete-
 *
 * Service handler for legacy route delete
 */
unsigned int
prism_route_delete(prism_app_struct_t *prism_ctx, uint32_t dst_nw, 
                   uint32_t dst_nm, bool free_nh)
{
    uint32_t code = 0;
    c_wr_lock(&prism_ctx->lock);
    code = __prism_route_delete(prism_ctx, dst_nw, dst_nm, free_nh);
    c_wr_unlock(&prism_ctx->lock);
    return code;
}

int
prism_route_mod_self(prism_app_struct_t *prism_ctx UNUSED,
                     uint32_t dst_nw, uint64_t dpid, bool add)
{
    struct flow fl, mask;
    struct mul_act_mdata mdata;
    int ret = 0;

    memset(&fl, 0, sizeof(fl));
    memset(&mask, 0, sizeof(mask));
    of_mask_set_dc_all(&mask);

    fl.dl_type = htons(ETH_TYPE_IP);
    of_mask_set_dl_type(&mask);

    fl.ip.nw_dst = htonl(dst_nw);
    of_mask_set_nw_dst(&mask, 32);

    fl.table_id = 1;
    
    if (add) {
        mul_app_act_alloc(&mdata);
        mdata.only_acts = false;

        if (mul_app_act_set_ctors(&mdata, dpid)) {
            ret = -1;
            mul_app_act_free(&mdata);
            goto out;
        }
        mul_app_action_output(&mdata, 0); /* Send to controller */

        /* Send flow to MUL Core*/
        mul_app_send_flow_add(NULL, NULL,
                              dpid, &fl, &mask,
                              PRISM_UNK_BUFFER_ID, mdata.act_base,
                              mul_app_act_len(&mdata),
                              0, 0, C_FL_PRIO_EXM,
                              /* C_FL_ENT_GSTATS |*/ C_FL_ENT_CTRL_LOCAL);
        mul_app_act_free(&mdata);

#if 0
        if (c_service_timed_wait_response(prism_ctx->prism_mul_service) > 0) {
            app_log_err("%s: Failed to add a flow. Check log messages", FN);
            ret = -1;
        }
#endif
    } else {
        mul_app_send_flow_del(NULL, NULL,
                              dpid, &fl, &mask,
                              0, C_FL_PRIO_EXM,
                              /* C_FL_ENT_GSTATS | */ C_FL_ENT_CTRL_LOCAL,
                              OFPG_ANY);
#if 0
        if (c_service_timed_wait_response(prism_ctx->prism_mul_service) > 0) {
            app_log_err("%s: Failed to del a flow. Check log messages", FN);
            ret = -1;
        }
#endif
    }
out:
    return ret;
} 
