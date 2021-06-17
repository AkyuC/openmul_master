/*
 *  prism_app_nh.c: PRISM application for MUL Controller 
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
#include "prism_app_nh.h"
#include <linux/neighbour.h>

/**
 * prism_dump_single_nh- 
 * @nh: Pointer to next hop element 
 *
 * Dumps the information of Next Hop
 */

char *
prism_dump_single_nh(prism_nh_elem_t *nh)
{
    char nh_ip_str[32];
    char     *pbuf = calloc(1, NH_PBUF_SZ);
    struct in_addr nh_addr;
    int len = 0;
    nh_addr.s_addr = htonl(nh->hkey.next_hop);
#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
    len += snprintf(pbuf+len, ROUTE_PBUF_SZ - len - 1,
        "Next-hop-ip %s next-hop-mac 0x%02x:%02x:%02x:%02x:%02x:%02x"
        " conn-dpid 0x%lx Outport %u Flags %u\n",
        inet_ntop(AF_INET,(struct sockaddr_in*)&nh_addr, nh_ip_str,
            INET_ADDRSTRLEN), nh->nh_mac[0], nh->nh_mac[1], nh->nh_mac[2],
        nh->nh_mac[3], nh->nh_mac[4], nh->nh_mac[5],nh->dpid,
        nh->oif, nh->nh_flags);
#else
    len += snprintf(pbuf+len, ROUTE_PBUF_SZ - len - 1,
        "Next-hop-ip %s next-hop-mac 0x%02x:%02x:%02x:%02x:%02x:%02x"
        " conn-dpid 0x%lx Outport %u Flags %u GroupID %u\n",
        inet_ntop(AF_INET,(struct sockaddr_in*)&nh_addr, nh_ip_str,
            INET_ADDRSTRLEN), nh->nh_mac[0], nh->nh_mac[1], nh->nh_mac[2],
        nh->nh_mac[3], nh->nh_mac[4], nh->nh_mac[5],nh->dpid,
        nh->oif, nh->nh_flags, nh->group_id);
#endif
    assert(len < ROUTE_PBUF_SZ);

    return pbuf;

}

/**
 * prism_next_hop_hash_func- 
 * @key: Prism next hop hash key 
 *
 * Derive a hash val froma next hop key 
 */
unsigned int                     
prism_next_hop_hash_func(const void *key)
{
    const prism_nh_elem_t *nh_elem = key;

    return hash_bytes(nh_elem, sizeof(prism_nh_hash_key_t), 1);
}
#if 0
/**
 * prism_next_hop_equal_func - 
 * @key1: prism next hop1 hash key 
 * @key2: prism next hop2 hash key 
 *
 * Deduce if two next hop are equal
 */
int 
prism_next_hop_equal_func(const void *key1, const void *key2)
{       
    return !memcmp(key1, key2, sizeof(prism_nh_hash_key_t));
} 

/**
 * prism_compare_nh_key-
 *
 * Key comparison function for Next Hop
 */
int
prism_compare_nh_key(void *h_arg, void *v_arg UNUSED, void *u_arg)
{
    prism_nh_hash_key_t *key = u_arg;
    prism_nh_elem_t *next_hop_elem = h_arg;

    if(next_hop_elem->hkey.next_hop == key->next_hop)
        return true;

    return false;
}
#endif
/**
 * __prism_next_hop_add-
 *
 * Service handler for next hop resolved state
 */
unsigned int
__prism_next_hop_add(prism_app_struct_t *prism_ctx, uint32_t nh, uint64_t dpid,
                   uint32_t oif, uint32_t nh_flags, uint8_t *mac_addr)
{
    prism_rt_elem_t *rt_elem = NULL;
    prism_nh_elem_t *nh_elem = NULL;
    prism_rt_hash_key_t rt_key;
    prism_nh_hash_key_t nh_key;
    uint32_t rt_flags = RT_DIRECT;
    struct flow fl, mask;
    uint32_t code = 0;
    prism_port_t lkup_port, *port;
    prism_switch_t *prism_sw;
    uint8_t hw_addr[ETH_ADDR_LEN];
    bool install_flows = true;
    bool staling_case = false;
    int ret = 0;
    struct of_group_mod_params *g_parms;

    memset(&fl, 0, sizeof(fl));
    memset(&mask, 0, sizeof(mask));
    of_mask_set_dc_all(&mask);

    /* Prepare Next Hop Key*/
    memset(&nh_key, 0, sizeof(nh_key));
    nh_key.next_hop = nh;    

    app_log_info("%s: Next hop add: NH(0x%x) dpid (%llx) OIF (%u)",
            FN, (unsigned)nh, 
            (unsigned long long)dpid,
            oif);

    /* Get the switch and hold it, this might be needed while allocating
     * group ID for next Hop.*/
    prism_sw = __prism_switch_get(prism_ctx, dpid);
    if (!prism_sw) {
        app_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(dpid));
        code = PNHM_DPID_NOT_EXIST;
        goto nh_add_end;
    }

    memset(&lkup_port, 0, sizeof(lkup_port));
    lkup_port.port_no = oif;

    c_rd_lock(&prism_sw->lock);
    if ((port = g_hash_table_lookup(prism_sw->port_htbl, &lkup_port))) {
        memcpy(hw_addr, port->hw_addr, ETH_ADDR_LEN);
    } else {
        app_log_err("%s: Edge port (%d) not found", FN, lkup_port.port_no);
        c_wr_unlock(&prism_sw->lock);
        code = PNHM_PORT_NOT_EXIST;
        /* No need to hold the switch any more*/
        prism_switch_put(prism_sw);
        goto nh_add_end;
    }
    c_rd_unlock(&prism_sw->lock);

    if((nh_elem = g_hash_table_lookup(prism_ctx->nh_hasher_db,
                    &nh_key))) {
        
        if(nh_elem->nh_flags == NH_INCOMPLETE) {
            
            /* Next Hop state changes from INCOMPLETE to REACHABLE*/
            nh_elem->nh_flags = NH_REACHABLE;
            memcpy(nh_elem->nh_mac, mac_addr, ETH_ADDR_LEN);
            nh_elem->last_known_active_time = time(NULL);
            app_log_debug("%s: NH Flag updated", FN);
            goto nh_update;

        } else if(nh_elem->nh_flags == NH_STALE){

            /* Next Hop state changes from STALE to REACHABLE*/
            /* Turn the entry to Reachable state*/
            app_log_debug("%s: NH %x STALE -> REACHABLE", FN,
                    nh_elem->hkey.next_hop);

            nh_elem->nh_flags = NH_REACHABLE;
 
            /* No need to hold the switch any more*/
            prism_switch_put(prism_sw);

            install_flows = false;

            staling_case = true;

            goto prism_install_nh_flow_group;

        } else if(memcmp(nh_elem->nh_mac, mac_addr, ETH_ADDR_LEN)) {
            
            /* Update the MAC address of the Next Hop*/
            memcpy(nh_elem->nh_mac, mac_addr, ETH_ADDR_LEN);
            nh_elem->last_known_active_time = time(NULL);

            app_log_debug("%s: NH MAC updated", FN);
            app_log_info("%s: Updated Next hop (0x%x) dpid (%llx) Flags (%u)"
                    " MAC %x:%x:%x:%x:%x:%x",
                    FN, (unsigned)nh, 
                    (unsigned long long)dpid,
                    nh_elem->nh_flags,
                    nh_elem->nh_mac[0],nh_elem->nh_mac[1],nh_elem->nh_mac[2],
                    nh_elem->nh_mac[3],nh_elem->nh_mac[4],nh_elem->nh_mac[5]);

            /* Only MAC has been updated, just update the MAC in group/flow
             * table. No need to update routes in edge switches via ConX*/
            install_flows = false;
 
            /* No need to hold the switch any more*/
            prism_switch_put(prism_sw);

            goto prism_install_nh_flow_group;
        } else {
            nh_elem->last_known_active_time = time(NULL);
            app_log_err("%s: Ignored NH_ADD: Next hop (0x%x) NH_FLAGS %u",
                    FN, (unsigned)nh, nh_flags);
            code = PNHM_DUP_NEXT_HOP;
 
            /* No need to hold the switch any more*/
            prism_switch_put(prism_sw);

            goto nh_check_probe_trigger;
        }
    } else {
        app_log_info("%s: New Next hop (0x%x) dpid (%llx)",
                FN, (unsigned)nh, 
                (unsigned long long)dpid);
        /*No Next hop entry present*/
        nh_elem = calloc(1, sizeof(prism_nh_elem_t));
        assert(nh_elem);

        nh_elem->hkey = nh_key;
        nh_elem->nh_flags = NH_REACHABLE;
        nh_elem->dpid = dpid;
        nh_elem->oif = oif;
        
        memcpy(nh_elem->nh_mac, mac_addr, ETH_ADDR_LEN);

        nh_elem->packet_count = 0;
        nh_elem->last_known_active_time = time(NULL);

        /* Store a new entry for Next Hop*/
        g_hash_table_insert(prism_ctx->nh_hasher_db, nh_elem, nh_elem);
        goto nh_update;
    }

nh_update :
   
    /*Key for route elem*/
    memset(&rt_key, 0, sizeof(rt_key));
    rt_key.dst_nw = nh; 
    rt_key.dst_nm = PRISM_NETMASK_32_BIT; 

    /*Prepare new route element to insert*/
    rt_elem = calloc(1, sizeof(prism_rt_elem_t));
    assert(rt_elem);

    rt_elem->hkey = rt_key;
    rt_elem->dpid = dpid;
    rt_elem->rt_flags = rt_flags;

    rt_elem->nh_ptr = nh_elem;

    /* Add route to this next hop route list*/
    nh_elem->route_list = g_slist_append(nh_elem->route_list,
            rt_elem);
    
    /* Store route entry in route hash table */
    g_hash_table_insert(prism_ctx->route_hasher_db, rt_elem, rt_elem);

#ifndef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
    c_wr_lock(&prism_sw->lock);

    /* Allocate the group ID from Switch Group ID pool for Next Hop*/
    if ((nh_elem->group_id = ipool_get(prism_sw->group_ipool, nh_elem)) < 0) {

        /* Unable to allocate group ID, we cannot proceed further with
         * this Next Hop. Exit with Internal error as Code*/
        app_log_err("%s: Unable to allocate Group ID for NH 0x%x", FN, nh);

        c_wr_unlock(&prism_sw->lock);

        /* Group ID cannot be allocated, No need to hold the switch any more*/
        prism_switch_put(prism_sw);
        /* Set ret as -1 to indicate error*/
        ret = -1;
        goto prism_group_error_check;
    }
    c_wr_unlock(&prism_sw->lock);

    /* Group ID have been allocated from the pool, 
       No need to hold the switch any more*/
    prism_switch_put(prism_sw);
 
    g_parms = &nh_elem->g_parms;

    memset(g_parms, 0, sizeof(*g_parms));
    g_parms->group =  mul_app_group_id_alloc(nh_elem->group_id);
    g_parms->type = OFPGT_ALL;
    g_parms->flags = C_GRP_STATIC | C_GRP_BARRIER_EN | C_GRP_GSTATS;

    app_log_debug("%s: Allocated Group ID %d", FN, g_parms->group);
#endif

prism_install_nh_flow_group:

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
    /*Install flow match for Next Hop in PRISM_NEXT_HOP_TABLE_ID */
    ret = prism_next_hop_flow_install( nh_elem->hkey.next_hop, oif, dpid, 
            nh_elem->nh_mac, hw_addr);
#else
    /*Install group for Next Hop in Group table in edge switch through
     * which next hop is associated (Packet exit point) */
    ret = prism_next_hop_group_install( nh_elem, hw_addr);

prism_group_error_check:
#endif

    if(ret) {
        /* Unable to install group for Next Hop*/
        code = PNHM_INTERNAL_ERROR;

        if(staling_case) {
            /* Iterate all routes associated with this next hop and \
               Unistall flows to all Switched using ConX service*/
            __prism_loop_all_routes_per_nh(nh_elem,
                    (GHFunc)prism_delete_route_via_conx, NULL);
        }

        /* Clean the entry from Route Hash Table*/
        g_hash_table_remove(prism_ctx->route_hasher_db, rt_elem);
        
        /* Clean the entry from Next Hop Hash Table*/
        g_hash_table_remove(prism_ctx->nh_hasher_db, nh_elem);

        goto nh_add_end;
    }

    if(install_flows) {
        /* Iterate all routes associated with this next hop and \
           Install flows to all Switched using ConX service*/
        __prism_loop_all_routes_per_nh(nh_elem,
                (GHFunc)prism_add_route_via_conx, NULL);
    }

nh_check_probe_trigger:
    
    if(nh_flags == NUD_STALE) {
        /* Trigger Probing */
#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
        prism_nh_get_flow_stats(nh_elem, NULL, NULL);
#else
        prism_nh_get_group_stats(nh_elem, NULL, NULL);
#endif
    }
nh_add_end:
    return code;
}

/**
 * prism_next_hop_add-
 *
 * Service handler for next hop resolved state
 */

unsigned int
prism_next_hop_add(prism_app_struct_t *prism_ctx, uint32_t nh, uint64_t dpid,
                   uint32_t oif, uint32_t nh_flags, uint8_t *mac_addr)
{
    uint32_t code = 0;
    c_wr_lock(&prism_ctx->lock);
    code = __prism_next_hop_add(prism_ctx, nh, dpid, oif, nh_flags, mac_addr);
    c_wr_unlock(&prism_ctx->lock);

    return code;
}

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
/**
 * prism_next_hop_flow_install-
 *
 * Installs flow entry for next hop match
 */

int
prism_next_hop_flow_install(uint32_t next_hop, uint32_t oif, uint64_t dpid,
        uint8_t *nh_mac, uint8_t *hw_addr)
{
    struct flow fl, mask;
    struct mul_act_mdata mdata;

    memset(&fl, 0, sizeof(fl));
    memset(&mask, 0, sizeof(mask));
    of_mask_set_dc_all(&mask);

    fl.dl_type = htons(ETH_TYPE_IP);
    of_mask_set_dl_type(&mask);
    mul_app_act_alloc(&mdata);
    mdata.only_acts = false;
    mul_app_act_set_ctors(&mdata, dpid);

    /* Source Mac must be changed to edge Node port's MAC address before
     * exiting the SDN island*/
    mul_app_action_set_smac(&mdata, hw_addr);

    /* Dest mac must also be set as Next Hop MAC address*/
    mul_app_action_set_dmac(&mdata, nh_mac);

#ifndef PRISM_INTEROP_WITH_HP_SWITCH
    /* Decrementing Network TTL*/
    mul_app_action_dec_nw_ttl(&mdata);
#endif

    /* Set the output port to which Next Hop is connected*/
    mul_app_action_output(&mdata, oif);
    fl.metadata = htonll(next_hop);
    of_mask_set_metadata(&mask);
    fl.table_id = PRISM_NEXT_HOP_TABLE_ID;

    /* Send flow to MUL Core*/
    mul_service_send_flow_add(prism_ctx->prism_mul_service,
            dpid, &fl, &mask,
            PRISM_UNK_BUFFER_ID, mdata.act_base,
            mul_app_act_len(&mdata),
            0, 0, C_FL_PRIO_FWD, 0/*C_FL_ENT_GSTATS*/);
    mul_app_act_free(&mdata);
    
    if (c_service_timed_wait_response(prism_ctx->prism_mul_service) > 0) {
        app_log_err("%s: Failed to add a flow. Check log messages", FN);
        return -1;
    }
    return 0;
}

/**
 * prism_next_hop_flow_uninstall-
 *
 * Uninstalls flow entry for next hop match
 */

void
prism_next_hop_flow_uninstall(uint32_t next_hop, uint64_t dpid)
{
    struct flow fl, mask;
    memset(&fl, 0, sizeof(fl));
    memset(&mask, 0, sizeof(mask));
    of_mask_set_dc_all(&mask);
    /* Uninstall flow match for Next Hop in PRISM_NEXT_HOP_TABLE_ID */
    fl.dl_type = htons(ETH_TYPE_IP);
    of_mask_set_dl_type(&mask);
    fl.metadata = htonll(next_hop);
    of_mask_set_metadata(&mask);
    fl.table_id = PRISM_NEXT_HOP_TABLE_ID;

    /* Send flow to MUL Core*/
    mul_service_send_flow_del(prism_ctx->prism_mul_service,
            dpid, &fl, &mask,
            0,C_FL_PRIO_FWD,0/*C_FL_ENT_GSTATS*/, OFPG_ANY);
    if (c_service_timed_wait_response(prism_ctx->prism_mul_service) > 0) {
        app_log_err("%s: Failed to delete a flow. Check log messages", FN);
    } 

}
#else
/**
 * prism_next_hop_group_install-
 *
 * Installs group entry for next hop match
 */

int
prism_next_hop_group_install(prism_nh_elem_t *nh_elem , uint8_t *hw_addr)
{
    struct mul_act_mdata mdata;
    struct of_act_vec_elem *act_elem = NULL;

    struct of_group_mod_params *g_parms;
 
    g_parms = &nh_elem->g_parms;
    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    mul_app_act_set_ctors(&mdata, nh_elem->dpid);

    /* Source Mac must be changed to edge Node port's MAC address before
     * exiting the SDN island*/
    mul_app_action_set_smac(&mdata, hw_addr);

    /* Dest mac must also be set as Next Hop MAC address*/
    mul_app_action_set_dmac(&mdata, nh_elem->nh_mac);

#ifndef PRISM_INTEROP_WITH_HP_SWITCH
    /* Decrementing Network TTL*/
    mul_app_action_dec_nw_ttl(&mdata);
#endif

    /* Set the output port to which Next Hop is connected*/
    mul_app_action_output(&mdata, nh_elem->oif);

    act_elem = calloc(1, sizeof(*act_elem));

    act_elem->actions = mdata.act_base;
    act_elem->action_len = of_mact_len(&mdata);
    g_parms->act_vectors[0] = act_elem;
    g_parms->act_vec_len = 1;

    /* Send group add to MUL Core*/
    mul_service_send_group_add(prism_ctx->prism_mul_service, nh_elem->dpid, g_parms);

    if (c_service_timed_wait_response(prism_ctx->prism_mul_service) > 0) {
        app_log_err("%s: Failed to add a group %u for Next hop 0x%x. " 
                "Check log messages", FN, g_parms->group, nh_elem->hkey.next_hop);
        return -1;
    }
    return 0;
}

/**
 * prism_next_hop_group_uninstall-
 *
 * Uninstalls group entry for next hop match
 */

void
prism_next_hop_group_uninstall(prism_nh_elem_t* nh_elem)
{
    struct of_group_mod_params *gp_parms;

    gp_parms = &nh_elem->g_parms;

    /* Send flow to MUL Core*/
    mul_service_send_group_del(prism_ctx->prism_mul_service, nh_elem->dpid, gp_parms);
    if (c_service_timed_wait_response(prism_ctx->prism_mul_service) > 0) {
        app_log_err("%s: Failed to delete a group %u. Check log messages",
                FN, gp_parms->group);
    }

}
#endif
unsigned int
__prism_next_hop_del_entry(prism_nh_elem_t* nh_elem)
{
    uint32_t code = 0;

    app_log_info("%s: Next hop del: NH(0x%x) dpid (%llx) OIF (%u)",
            FN, (unsigned)nh_elem->hkey.next_hop, 
            (unsigned long long)nh_elem->dpid,
            nh_elem->oif);

    /*Delete direct route(self route only) */
    code = __prism_route_delete(prism_ctx, nh_elem->hkey.next_hop, 
            PRISM_NETMASK_32_BIT,
            false);

    /* Check if any route list is empty*/
    if(nh_elem->route_list) {

        /* Iterate all routes associated with this next hop and \
           delete flows from all Switched using Fabric service */
        __prism_loop_all_routes_per_nh(nh_elem,(GHFunc)prism_delete_route_via_conx, NULL);

        /* Mark this next Hop as Unresolved*/
        nh_elem->nh_flags = NH_INCOMPLETE;

        /* Reset counters for Probing when Next Hop is not active*/
        nh_elem->packet_count = 0;
        nh_elem->last_known_active_time = 0;
    }

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
    /* Uninstall flow from Next Hop table*/
    prism_next_hop_flow_uninstall(nh_elem->hkey.next_hop, 
            nh_elem->dpid);
#else
    /* Uninstall group from Next Hop table*/
    prism_next_hop_group_uninstall(nh_elem);
#endif

    /* Note: We have not returned Group ID to the pool as we assume that its
     * next hop entry is going to be accessed by the caller function. 
     * If not, Caller function must take the responsibility and return the
     * group ID back to the group ID pool */

    return code;
}

/**
 * prism_next_hop_del-
 *
 * Service handler for next hop unresolved state
 */
unsigned int
__prism_next_hop_del(prism_app_struct_t *prism_ctx, uint32_t nh, 
                     uint64_t dpid UNUSED, uint32_t oif UNUSED)
{
    prism_nh_hash_key_t nh_key;
    prism_nh_elem_t *nh_elem = NULL;
    uint32_t code = 0;
#ifndef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
    prism_switch_t *prism_sw;
#endif

    /* Prepare Next Hop Key*/
    nh_key.next_hop = nh;    

    /*FIXME: When will the entries for Direct next hops will be deleted???*/

    if((nh_elem = g_hash_table_lookup(prism_ctx->nh_hasher_db,
                    &nh_key))) {

        if(nh_elem->nh_flags!= NH_INCOMPLETE) {

            /* Delete the entry from Hash Table and delete all the route
             * flows associated with it*/
            __prism_next_hop_del_entry(nh_elem);

            /* Check if any route list is empty*/
            if(!nh_elem->route_list) {
#ifndef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
                /* Get the switch and hold it, this might be needed while
                 * returning group ID for next Hop.*/
                prism_sw = __prism_switch_get(prism_ctx, nh_elem->dpid);
                if (!prism_sw) {
                    app_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(dpid));
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
#endif
                /* Clean the entry from Next Hop Hash Table*/
                g_hash_table_remove(prism_ctx->nh_hasher_db, nh_elem);

            }
        } else {
            app_log_err("%s: Ignored, Next hop (0x%x) already unresolved",
                    FN, (unsigned) nh);
            code = PNHM_NEXT_HOP_NOT_EXIST;
        }
    } else {
        app_log_err("%s: Next hop (0x%x) not present",
                FN, (unsigned) nh);
        code = PNHM_NEXT_HOP_NOT_EXIST;
    }
    
    return code;
}
/**
 * prism_next_hop_del-
 *
 * Service handler for next hop resolved state
 */

unsigned int
prism_next_hop_del(prism_app_struct_t *prism_ctx, uint32_t nh, uint64_t dpid,
                   uint32_t oif)
{
    uint32_t code = 0;
    c_wr_lock(&prism_ctx->lock);
    code = __prism_next_hop_del(prism_ctx, nh, dpid, oif);
    c_wr_unlock(&prism_ctx->lock);

    return code;
}

/**
 * __prism_loop_all_nh_remove -
 * @prism_ctx  : Pointer to Prism APP context
 * @iter_fn    : Iteration callback 
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all Next Hop and invoke callback for each
 * NOTE - lockless version and assumes fab_ctx lock as held
 */
void
__prism_loop_all_nh_remove(prism_app_struct_t *prism_ctx, GHRFunc iter_fn,
                               void *u_data)
{
    if (prism_ctx->nh_hasher_db) {
        g_hash_table_foreach_remove(prism_ctx->nh_hasher_db,
                        (GHRFunc)iter_fn, u_data);
    }
}

/**
 * prism_loop_all_nh_remove-
 * @prism_ctx  : Pointer to Prism APP context
 * @iter_fn    : Iteration callback 
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all Next Hop and invoke callback for each
 */
void
prism_loop_all_nh_remove(prism_app_struct_t *prism_ctx, GHRFunc iter_fn,
                               void *u_data)
{
    c_wr_lock(&prism_ctx->lock);
    __prism_loop_all_nh_remove(prism_ctx, iter_fn, u_data);
    c_wr_unlock(&prism_ctx->lock);
}


/**
 * __prism_loop_all_nh -
 * @prism_ctx  : Pointer to Prism APP context
 * @iter_fn    : Iteration callback 
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all Next Hop and invoke callback for each
 * NOTE - lockless version and assumes fab_ctx lock as held
 */
void
__prism_loop_all_nh(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
                               void *u_data)
{
    if (prism_ctx->nh_hasher_db) {
        g_hash_table_foreach(prism_ctx->nh_hasher_db,
                        (GHFunc)iter_fn, u_data);
    }
}

/**
 * prism_loop_all_nh-
 * @prism_ctx  : Pointer to Prism APP context
 * @iter_fn    : Iteration callback 
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all Next Hop and invoke callback for each
 */
void
prism_loop_all_nh(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
                               void *u_data)
{
    c_wr_lock(&prism_ctx->lock);
    __prism_loop_all_nh(prism_ctx, iter_fn, u_data);
    c_wr_unlock(&prism_ctx->lock);
}


/**
 * __prism_per_nh_replay -
 * @nh_arg   : nh elem pointer
 * @v_arg    : Unused param
 * @vif_karg : Pointer to VIF key
 * @return   : Void
 *
 * Replays per NH info to conx and core
 */
static void
__prism_per_nh_replay(void *nh_arg, void *v_arg UNUSED, void *vif_karg)
{
    prism_nh_elem_t *nh_elem = nh_arg;
    prism_port_t lkup_port, *port;
    prism_switch_t *prism_sw;
    uint8_t hw_addr[ETH_ADDR_LEN];
    prism_vif_hash_key_t *vif = vif_karg;

    if (nh_elem->nh_flags == NH_INCOMPLETE)
        return;

    if (vif) {
        if (vif->dpid != nh_elem->dpid || 
            vif->port != nh_elem->oif)
            return;
    }

    prism_sw = __prism_switch_get(prism_ctx, nh_elem->dpid);
    if (!prism_sw) {
        app_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(nh_elem->dpid));
        return;
    }
    memset(&lkup_port, 0, sizeof(lkup_port));
    lkup_port.port_no = nh_elem->oif;

    c_rd_lock(&prism_sw->lock);
    if ((port = g_hash_table_lookup(prism_sw->port_htbl, &lkup_port))) {
        memcpy(hw_addr, port->hw_addr, ETH_ADDR_LEN);
    } else {
        app_log_err("%s: Edge port (%d) not found", FN, lkup_port.port_no);
        c_wr_unlock(&prism_sw->lock);
        return;
    }
    c_rd_unlock(&prism_sw->lock);

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
    prism_next_hop_flow_install(nh_elem->hkey.next_hop,
                                nh_elem->oif,
                                nh_elem->dpid,
                                nh_elem->nh_mac, hw_addr);
#else
    prism_next_hop_group_install(nh_elem,
                                hw_addr);
#endif
    __prism_loop_all_routes_per_nh(nh_elem,
            (GHFunc)prism_add_route_via_conx, NULL);

}

/**
 * prism_replay_all_nh -
 * @prism_ctx : Pointer to Prism APP context
 * @key       : Pointer to VIF key
 * @return : void
 */
void
prism_replay_all_nh(prism_app_struct_t *prism_ctx, prism_vif_hash_key_t *key)
{
    prism_loop_all_nh(prism_ctx, __prism_per_nh_replay, key);
}

static void *
prism_nh_proxy_arp_request(prism_nh_elem_t *nh_elem)
{
    uint8_t               *out_pkt;
    struct eth_header     *eth;
    struct arp_eth_header *arp_req;
    prism_port_t lkup_port, *port;
    prism_switch_t *prism_sw;
    uint8_t hw_addr[ETH_ADDR_LEN];
    prism_vif_hash_key_t vif_hkey;
    prism_vif_elem_t *vif_elem;

    memset(&vif_hkey, 0, sizeof(prism_vif_hash_key_t));
    vif_hkey.dpid = nh_elem->dpid;
    vif_hkey.port = nh_elem->oif;

    lkup_port.port_no = nh_elem->oif;

    prism_sw = __prism_switch_get(prism_ctx, nh_elem->dpid);
    if (!prism_sw) {
        app_log_err("%s: Unknown switch (0x%llx)", FN, U642ULL(nh_elem->dpid));
        return NULL;
    }

    c_rd_lock(&prism_sw->lock);
    if ((port = g_hash_table_lookup(prism_sw->port_htbl, &lkup_port))) {
        memcpy(hw_addr, port->hw_addr, ETH_ADDR_LEN);
    } else {
        app_log_err("%s: Edge port (%d) not found", FN, lkup_port.port_no);
        c_wr_unlock(&prism_sw->lock);
        return NULL;
    }
    c_rd_unlock(&prism_sw->lock);

    vif_elem = g_hash_table_lookup(prism_ctx->vif_hasher_db, &vif_hkey);

    out_pkt = calloc(1, sizeof(struct arp_eth_header) +
                         sizeof(struct eth_header));

    eth = (struct eth_header *)out_pkt;
    arp_req = (struct arp_eth_header *)(eth + 1);
    
    memset(eth->eth_dst, 0xFF, ETH_ADDR_LEN);
    memcpy(eth->eth_src, hw_addr, ETH_ADDR_LEN);
    eth->eth_type = htons(ETH_TYPE_ARP);

    arp_req->ar_hrd = htons(ARP_HRD_ETHERNET);
    arp_req->ar_pro = htons(ARP_PRO_IP); 
    arp_req->ar_pln = IP_ADDR_LEN;
    arp_req->ar_hln = ETH_ADDR_LEN;
    arp_req->ar_op = htons(ARP_OP_REQUEST);

    /*Interface MAC address*/
    memcpy(arp_req->ar_sha, hw_addr, ETH_ADDR_LEN);
    
    /* Interface IP address*/
    arp_req->ar_spa = htonl(vif_elem->intf_ip_addr);

    /* Target MAC address */
    memset(arp_req->ar_tha, 0xFF, ETH_ADDR_LEN);

    /* Target IP address*/
    arp_req->ar_tpa = htonl(nh_elem->hkey.next_hop);

    return out_pkt;
}

static void
prism_nh_probe_arp(prism_nh_elem_t *nh_elem)
{
    struct of_pkt_out_params  parms;
    struct mul_act_mdata      mdata;
 
    app_log_info("%s: Probing for NH %x", FN, nh_elem->hkey.next_hop);
    memset(&parms, 0, sizeof(parms));

    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    mul_app_act_set_ctors(&mdata, nh_elem->dpid);
    mul_app_action_output(&mdata, nh_elem->oif);
    parms.buffer_id = PRISM_UNK_BUFFER_ID;
    parms.in_port = OF_NO_PORT;
    parms.action_list = mdata.act_base;
    parms.action_len = mul_app_act_len(&mdata);
    parms.data_len = sizeof(struct eth_header) + sizeof(struct arp_eth_header);
    parms.data = prism_nh_proxy_arp_request(nh_elem);
    mul_app_send_pkt_out(NULL, nh_elem->dpid, &parms);
    mul_app_act_free(&mdata);
    free(parms.data);
}

#ifdef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
static void
prism_nh_verify_flow_stats(void *elem, void *data) 
{
    prism_nh_elem_t *nh_elem = (prism_nh_elem_t *)elem;
    struct c_ofp_flow_info *flow_info = (struct c_ofp_flow_info *) data;
    uint64_t packet_count = ntohll(flow_info->packet_count);
    app_log_info("%s: NH %x PC %lu SC %lu", FN, nh_elem->hkey.next_hop,
            nh_elem->packet_count, packet_count );
    if(packet_count != nh_elem->packet_count) {
        app_log_info("%s: NH %x is active", FN, nh_elem->hkey.next_hop);
        prism_nh_probe_arp(nh_elem);
        nh_elem->packet_count = packet_count;
    }
}

void
prism_nh_get_flow_stats(void *elem, void *v_arg UNUSED, 
                        void *vif_karg UNUSED)
{ 
    prism_nh_elem_t *nh_elem = (prism_nh_elem_t *) elem;
    int ret = 0;
    struct flow fl, mask;

    memset(&fl, 0, sizeof(fl));
    memset(&mask, 0, sizeof(mask));
    of_mask_set_dc_all(&mask);

    if(nh_elem->nh_flags == NH_REACHABLE ) {
        app_log_info("%s: Probing time for NH %x", FN,
                nh_elem->hkey.next_hop);

        fl.dl_type = htons(ETH_TYPE_IP);
        of_mask_set_dl_type(&mask);
        fl.metadata = htonll(nh_elem->hkey.next_hop);
        of_mask_set_metadata(&mask);
        fl.table_id = PRISM_NEXT_HOP_TABLE_ID;
        of_mask_set_table_id(&mask);

        ret = mul_get_matched_flow_info(prism_ctx->prism_mul_service, nh_elem->dpid,
                false, true, nh_elem, &fl, &mask, C_FL_PRIO_FWD,
                prism_nh_verify_flow_stats);
        if(ret <= 0) {
            app_log_err("%s: NH get flow stats failed for NH %x", FN,
                    nh_elem->hkey.next_hop);
        }
    }
}
#else
static void
prism_nh_verify_group_stats(void *elem, void *data) 
{
    prism_nh_elem_t *nh_elem = (prism_nh_elem_t *)elem;
    struct c_ofp_group_mod *group_info = (struct c_ofp_group_mod *) data;
    uint64_t packet_count = ntohll(group_info->packet_count);
    app_log_info("%s: NH %x PC %lu SC %lu", FN, nh_elem->hkey.next_hop,
            nh_elem->packet_count, packet_count );
    if(packet_count != nh_elem->packet_count) {
        app_log_info("%s: NH %x is active", FN, nh_elem->hkey.next_hop);
        prism_nh_probe_arp(nh_elem);
        nh_elem->packet_count = packet_count;
    }
}

void
prism_nh_get_group_stats(void *elem, void *v_arg UNUSED, 
                        void *vif_karg UNUSED)
{ 
    prism_nh_elem_t *nh_elem = (prism_nh_elem_t *) elem;
    int ret = 0;

    if(nh_elem->nh_flags == NH_REACHABLE ) {
        app_log_info("%s: Probing time for NH %x", FN,
                nh_elem->hkey.next_hop);

        ret = mul_get_matched_group_info(prism_ctx->prism_mul_service, 
                nh_elem->dpid, nh_elem->g_parms.group, false, true, nh_elem,
                prism_nh_verify_group_stats);
        if(ret <= 0) {
            app_log_err("%s: NH get group stats failed for NH 0x%x"\
                    " Group ID %u", FN, nh_elem->hkey.next_hop,
                    nh_elem->g_parms.group);
        }
    }
}

#endif

/**
 * __prism_nh_make_entry_stale_single-
 * @nh_arg   : nh elem pointer
 * @arg      : Unused param
 * @u_arg    : Unused param
 * @return   : Void
 *
 * Make NH entries stale
 */
void
__prism_nh_make_entry_stale_single(void *nh_arg, void *arg UNUSED, 
                                   void *u_arg UNUSED)
{
    prism_nh_elem_t *nh_elem = nh_arg;
    nh_elem->nh_flags = NH_STALE;
    app_log_info("%s: NH %x : STALE", FN, nh_elem->hkey.next_hop);
}

/**
 * __prism_nh_clear_stale_entry_single-
 * @nh_arg   : nh elem pointer
 * @arg      : Unused param
 * @u_arg    : Unused param
 * @return   : Void
 *
 * Clear the state entry from NH hash DB and delete all the flows via ConX
 */
int
__prism_nh_clear_stale_entry_single(void *nh_arg, void *arg UNUSED, 
                                   void *u_arg)
{
    prism_nh_elem_t *nh_elem = nh_arg;
    bool need_replay = *(bool*)u_arg;
    uint32_t code = 0;
#ifndef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
    prism_switch_t *prism_sw;
#endif

    if(nh_elem->nh_flags == NH_STALE) {
        app_log_info("%s: NH %x : STALE - Clearing", FN, nh_elem->hkey.next_hop);
        code = __prism_next_hop_del_entry(nh_elem);
        /* Check if any route list is empty*/
        if(!nh_elem->route_list) {

#ifndef PRISM_NEXT_HOP_FLOW_TABLE_SUPPORT
            /* Return group ID allocated to the Pool*/
            /* Get the switch and hold it, this might be needed while
             * returning group ID for next Hop.*/
            prism_sw = __prism_switch_get(prism_ctx, nh_elem->dpid);
            if (!prism_sw) {
                app_log_err("%s: Unknown switch (0x%llx)", FN,
                        U642ULL(nh_elem->dpid));
                return true;
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

            /* Returning true suggests that caller function is going to free
             * nh_elem by itself from nh_hasher_db. So, we have returned
             * group ID to the pool here*/
#endif
            return true;
        }
    } else if(need_replay) {
        app_log_info("%s: NH %x : Replaying the info", FN, nh_elem->hkey.next_hop);
        __prism_per_nh_replay(nh_elem, NULL, NULL);
    }

    if(code) {
        app_log_info("%s: NH %x : STALE - Clearing failed, Code: %u", 
                FN, nh_elem->hkey.next_hop, code);
    }
    return false;
}


