/*
 *  conx_p.c: Connector P module 
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
#include "conx_common.h"

struct conx_struct *conx;

/**
 * conx_dump_route -
 *
 * Dump a route for printing
 */
char *
conx_dump_route(GSList *route_path)
{
#define CONX_ROUTE_PBUF_SZ 4096
    char *pbuf = calloc(1, CONX_ROUTE_PBUF_SZ);
    int len = 0;
    GSList *iterator = NULL;
    rt_path_elem_t *rt_elem = NULL;

    len += snprintf(pbuf+len, CONX_ROUTE_PBUF_SZ-len-1, "iROUTE:\r\n");
    assert(len < CONX_ROUTE_PBUF_SZ-1);

    for (iterator = route_path; iterator; iterator = iterator->next) {
        rt_elem = iterator->data;

        len += snprintf(pbuf+len, CONX_ROUTE_PBUF_SZ-len-1,
                        "Node(%d):Link(%hu)->",
                        rt_elem->sw_alias, rt_elem->link.la);
        assert(len < CONX_ROUTE_PBUF_SZ-1);
    }


    len += snprintf(pbuf+len, CONX_ROUTE_PBUF_SZ-len-1, "||\r\n");
    assert(len < CONX_ROUTE_PBUF_SZ-1);

    return pbuf;
}

static bool
conx_route_eq(GSList *r1, GSList *r2)
{
    rt_path_elem_t *pe1;
    rt_path_elem_t *pe2;

    if (!r1 && !r2) return true;
    if ((!r1 && r2) || (!r2 && r1)) return false;

    if (g_slist_length(r1) != g_slist_length(r2))
        return false;
    
    for (pe1 = r1->data, pe2 = r2->data;
         r1 && r2;
         r1= r1->next, r2 = r2->next) {
        if (!pe1 || !pe2) assert(0);

        if (memcmp(pe1, pe2, sizeof(rt_path_elem_t))) {
            return false;
        }
    }

    return true;
}

static void
conx_fhop_grp_uninstall(void *rt, conx_op_res_t *res)
{
    rt_path_elem_t *rt_elem = rt;
    conx_ent_t *ent = res->arg;
    struct of_group_mod_params *g_parms;
    int gp = 0;

    g_parms = &ent->ecmp_grp.g_parms;

    if (ent->ecmp_grp.group_id) {
        ipool_put(conx->g_ipool, mul_app_group_id_dealloc(g_parms->group));
        mul_service_send_group_del(conx->mul_service,
                                   rt_elem->sw_dpid, g_parms);
        if (c_service_timed_wait_response(conx->mul_service)) {
            app_log_err("%s: Failed to delete a group %lu in 0x%llx",
                        FN, U322UL(g_parms->group), U642ULL(rt_elem->sw_dpid));
        }
        for (gp = 0; gp < g_parms->act_vec_len; gp++) {
            if (g_parms->act_vectors[gp]) {
                if (g_parms->act_vectors[gp]->actions)
                    free(g_parms->act_vectors[gp]->actions);
                free(g_parms->act_vectors[gp]);
                g_parms->act_vectors[gp] = NULL;
            }
        }
        memset(g_parms, 0, sizeof(*g_parms));
        ent->ecmp_grp.group_id = 0;
    }

    return;
}

static void
conx_phop_route_flow_uninstall(void *rt, void *u_arg)
{
    struct flow fl;
    struct flow mask;
    rt_path_elem_t *rt_elem = rt;
    conx_op_res_t *res = u_arg;
    conx_ent_t *ent = res->arg;
    uint16_t prio;
    bool lhop;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);

    prio = res->pos ? CONX_FL_PRIO_LO : CONX_FL_PRIO_HI;
    lhop = rt_elem->flags & RT_PELEM_LAST_HOP ? true: false;

    if (!lhop) {
        fl.table_id = CONX_L2_TABLE_ID;
    } else {
        fl.table_id = CONX_L1_TABLE_ID;
    }

    memcpy(fl.dl_dst, ent->tun_desc.u.tun_dmac, ETH_ADDR_LEN);
    memcpy(fl.dl_src, ent->tun_desc.u.tun_smac, ETH_ADDR_LEN);

    of_mask_set_dl_dst(&mask);
    of_mask_set_dl_src(&mask);

    mul_service_send_flow_del(conx->mul_service,
                          rt_elem->sw_dpid,
                          &fl, &mask, 0, prio,
                          C_FL_ENT_GSTATS, OFPG_ANY);
    if (c_service_timed_wait_response(conx->mul_service) != 0) {
        app_rlog_err("%s: [WARNING] flow del failed in %llx",
                     FN, U642ULL(rt_elem->sw_dpid));
    }

    return;
}

static void
conx_per_switch_route_uninstall(void *rt, void *u_arg)
{
    rt_path_elem_t *rt_elem = rt;
    conx_op_res_t *res = u_arg;
    conx_ent_t *ent = res->arg;
    bool fhop;

    if (ent->type != CONX_TUNNEL_OF) return;

    fhop = rt_elem->flags & RT_PELEM_FIRST_HOP ? true: false;

    if (fhop && conx->use_groups) {
        return conx_fhop_grp_uninstall(rt, res);
    }

    return conx_phop_route_flow_uninstall(rt, res);
}

int
conx_route_uninstall(conx_ent_t *ent, bool destroy, int pos)
{
    conx_op_res_t res;
    struct conx_route *cr;

    if (pos >= CONX_MAX_ROUTES ||
        (pos > 0 && !conx->use_groups))
        return -1;

    cr = &ent->routes[pos];

    res.pos = pos;
    res.arg = ent;
    res.res = 0;

    if (cr->conx_route) {
        mul_route_path_traverse(cr->conx_route,
                                conx_per_switch_route_uninstall,
                                &res);
        /* FIXME - It may fail */
        cr->valid_rt = false;
        if (destroy)  {
            mul_destroy_route(cr->conx_route);
            cr->conx_route = NULL;
        }
    }
    return 0;
}

int
conx_route_uninstall_all(conx_ent_t *ent, bool destroy)
{
    int nrt = 0;
    for (; nrt < CONX_MAX_ROUTES; nrt++) {
        conx_route_uninstall(ent, destroy, nrt);
    }
    return 0;
}

static void
conx_fhop_grp_install(void *rt, conx_op_res_t *res)
{
    rt_path_elem_t *rt_elem = rt;
    conx_ent_t *ent = res->arg;
    struct of_group_mod_params *g_parms;
    struct mul_act_mdata mdata;
    struct of_act_vec_elem *act_elem;
    int id = 0, rcode = 0;

    g_parms = &ent->ecmp_grp.g_parms;

    if (!ent->ecmp_grp.group_id) {
        memset(g_parms, 0, sizeof(*g_parms));
        id = ipool_get(conx->g_ipool, ent);
        if (id < 0) goto err;
        g_parms->group = mul_app_group_id_alloc(id);
        ent->ecmp_grp.group_id = g_parms->group;
        g_parms->type = OFPGT_SELECT;
        g_parms->flags = C_GRP_STATIC | C_GRP_BARRIER_EN | C_GRP_GSTATS;
    }

    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    if (mul_app_act_set_ctors(&mdata, rt_elem->sw_dpid)) {
        mul_app_act_free(&mdata);
        goto err_mdata_free;
    }

    if (mul_app_action_set_dmac(&mdata,
                                ent->tun_desc.u.tun_dmac) <= 0) {
        app_rlog_err("%s: act dmac failed", FN);
        goto err_mdata_free;
    }
    
    if (mul_app_action_set_smac(&mdata,
                                ent->tun_desc.u.tun_smac) <= 0) {
        app_rlog_err("%s: act smac failed", FN);
        goto err_mdata_free;
    }

    if (mul_app_action_output(&mdata, rt_elem->link.la) <= 0) {
        app_rlog_err("%s: act output failed", FN);
        goto err_mdata_free;
    }

    act_elem = calloc(1, sizeof(*act_elem));
    if (!act_elem) goto err_mdata_free;

    act_elem->actions = mdata.act_base;
    act_elem->action_len = of_mact_len(&mdata);
    g_parms->act_vectors[g_parms->act_vec_len] = act_elem;
    g_parms->act_vec_len++;

    /* Send group add to MUL Core */
    mul_service_send_group_add(conx->mul_service, rt_elem->sw_dpid, g_parms);
    if ((rcode = c_service_timed_wait_response(conx->mul_service))) {
        if (rcode != OFPGMFC131_GROUP_EXISTS) {
            app_log_err("%s: Failed to add a group %lu in 0x%llx",
                        FN, U322UL(g_parms->group),
                        U642ULL(rt_elem->sw_dpid));
            goto err;
        }
    }
    return;

err_mdata_free:
    mul_app_act_free(&mdata);
err:
    res->res = -1;
    return;
}

static void
conx_phop_route_flow_install(void *rt, conx_op_res_t *res)
{
    rt_path_elem_t *rt_elem = rt;
    struct flow fl;
    struct flow mask;
    bool lhop;
    conx_ent_t *ent = res->arg;
    struct mul_act_mdata mdata;
    int rcode = 0;
    uint16_t prio;

    prio = res->pos ? CONX_FL_PRIO_LO : CONX_FL_PRIO_HI;
    lhop = rt_elem->flags & RT_PELEM_LAST_HOP ? true: false;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);

    mul_app_act_alloc(&mdata);
    if (mul_app_act_set_ctors(&mdata, rt_elem->sw_dpid)) {
        app_rlog_err("%s: rt-elem dp 0x%llx not found", FN,
                     U642ULL(rt_elem->sw_dpid));
        goto err;
    }

    if (!lhop) {
        if (mul_app_action_output(&mdata, rt_elem->link.la) <= 0) {
            app_rlog_err("%s: rt-elem act output failed", FN);
            goto err;
        }
        fl.table_id = CONX_L2_TABLE_ID;
    } else {
        if (mul_app_inst_goto(&mdata, CONX_L2_TABLE_ID)) {
            app_rlog_err("%s: Can't add goto instruction", FN);
            goto err;
        } 
        fl.table_id = CONX_L1_TABLE_ID;
    }

    memcpy(fl.dl_dst, ent->tun_desc.u.tun_dmac, ETH_ADDR_LEN);
    memcpy(fl.dl_src, ent->tun_desc.u.tun_smac, ETH_ADDR_LEN);

    of_mask_set_dl_dst(&mask);
    of_mask_set_dl_src(&mask);

    mul_service_send_flow_add(conx->mul_service,
                          rt_elem->sw_dpid,
                          &fl, &mask, OFP_NO_BUFFER,
                          mdata.act_base, mul_app_act_len(&mdata),
                          0, 0,
                          prio,
                          C_FL_ENT_GSTATS);
    mul_app_act_free(&mdata);

    if ((rcode = c_service_timed_wait_response(conx->mul_service))) {
        char *fl_str = of_dump_flow_generic(&fl, &mask);
        app_rlog_err("%s: flow add failed %d in 0x%llx %s",
                      FN, rcode, U642ULL(rt_elem->sw_dpid), fl_str);
        free(fl_str);
        if (rcode != OFPFMFC_FLOW_EXIST)
            goto err;
    }

    return; 
err:
    res->res = -1;
    return;
}

static void
conx_per_switch_route_install(void *rt, void *u_arg)
{
    rt_path_elem_t *rt_elem = rt;
    conx_op_res_t *res = u_arg;
    conx_ent_t *ent = res->arg;
    bool fhop;

    if (res->res) return;

    fhop = rt_elem->flags & RT_PELEM_FIRST_HOP ? true: false;

    if (ent->type != CONX_TUNNEL_OF) return;

    if (fhop && conx->use_groups) {
        return conx_fhop_grp_install(rt, res);
    }

    return conx_phop_route_flow_install(rt, res);

}

static int
conx_route_install(conx_ent_t *ent, GSList *route, int pos)
{
    conx_op_res_t res;
    struct conx_route *cr;

    if (pos >= CONX_MAX_ROUTES ||
        (pos > 0 && !conx->use_groups)) {
        app_log_debug("%s: Cant route-install 0x%llx->0x%llx",
                    FN, U642ULL(ent->key.src_dpid),
                    U642ULL(ent->key.dst_dpid));
        mul_destroy_route(route);
        return -1;
    }
 
    cr = &ent->routes[pos];

    if (ent->flags & CONX_ENT_LOOPBACK) {
        cr->valid_rt = true;
        return 0;
    }

    cr->conx_route = route;

    res.arg = ent;
    res.pos = pos;
    res.res = 0;

    mul_route_path_traverse(route,
                            conx_per_switch_route_install,
                            &res);
    if (res.res) {
        cr->valid_rt = false;
        conx_route_uninstall(ent, true, pos);
        app_log_err("%s: route-install err 0x%llx->0x%llx",
                    FN, U642ULL(ent->key.src_dpid),
                    U642ULL(ent->key.dst_dpid));
        return -1;
    } 

    cr->valid_rt = true;
    return 0;
}

static void 
conx_routes_mk_valid(struct conx_ent *ent)
{
    int i = 0;

    for (; i < CONX_MAX_ROUTES; i++) {
        ent->routes[i].valid_rt = true;
    }
}

static bool 
conx_any_valid_route(struct conx_ent *ent)
{
    int i = 0;

    for (; i < CONX_MAX_ROUTES; i++) {
        if (ent->routes[i].valid_rt)
            return true;
    }
    return false;
}
 
static void 
conx_routes_neq_install(struct conx_ent *ent, rt_list_t *new_list)
{
    int i = 0, j = 0;
    struct conx_route *r1;
    rt_list_t *elem = NULL;
    bool rt_match;

    for (i = 0; i < CONX_MAX_ROUTES; i++) {
        elem = new_list;
        r1 = &ent->routes[i];
        for (j = 0; elem && j < CONX_MAX_ROUTES; j++) {
            if (!elem->skip) {
                rt_match = conx_route_eq(r1->conx_route, elem->route);
                if ((!r1->valid_rt && elem->route) ||
                    !rt_match) {
                    conx_route_uninstall(ent, true, i);
                    conx_route_install(ent, elem->route, i);
                    elem->skip = true;
                    break;
                }
                if (rt_match) { 
                    elem->skip = true;
                    break;
                }
            }
            elem = elem->next;        
        }
    }

    mul_route_list_free(new_list, true);
}

static void
conx_per_dp_nh_init(void *key UNUSED, void *sw_arg, void *uarg)
{
    conx_ent_key_t conx_finder;
    conx_ent_t *conx_ent = NULL;
    mul_switch_t *neigh_sw = sw_arg;
    mul_switch_t *sw = uarg;
    conx_ufl_hent_t *hent;
    rt_list_t *rt_list;

    /* Only works with 1.3 or more */
    if (neigh_sw->ofp_ver == OFP_VERSION) return;

    if (sw && neigh_sw)
        app_log_debug("conx-nh-init: 0x%llx -> 0x%llx",
                      U642ULL(sw->dpid), U642ULL(neigh_sw->dpid));

    if (!uarg) {
        __c_app_traverse_all_switches(conx_per_dp_nh_init, sw_arg);
    } else {
        conx_sw_priv_t *psw = MUL_PRIV_SWITCH(sw);

        if (!psw) return;
        conx_finder.src_dpid = sw->dpid;
        conx_finder.dst_dpid = neigh_sw->dpid;

        if (!(conx_ent = g_hash_table_lookup(psw->sw_conx_htbl, &conx_finder))) {
            conx_ent = conx_ent_alloc(sw->dpid, neigh_sw->dpid,
                                      sw->alias_id, neigh_sw->alias_id,
                                      0, 0,
                                      CONX_TUNNEL_OF);
            if (!conx_ent) return; 
            g_hash_table_insert(psw->sw_conx_htbl, conx_ent, conx_ent);
        }

        if (conx_ent->flags & CONX_ENT_LOOPBACK) {
            conx_routes_mk_valid(conx_ent);
            return; 
        }

        rt_list = mul_route_get_all(conx->route_service,
                                    sw->alias_id,
                                    neigh_sw->alias_id);

        conx_routes_neq_install(conx_ent, rt_list);
        /* Scanning for uflows installation must be done after creating the
         * internal routes*/
        if ((hent = g_hash_table_lookup(conx->uflow_htbl, &conx_finder))) {
            conx_uflow_scan(conx_ent, hent, true);
        }
    }
}

void
conx_per_dp_nh_destroy(void *key UNUSED, void *sw_arg, void *uarg)
{
    conx_ent_key_t conx_finder;
    conx_ent_t *conx_ent = NULL;
    mul_switch_t *neigh_sw = uarg;
    mul_switch_t *sw = sw_arg;
    conx_ufl_hent_t *hent;
    conx_sw_priv_t *psw = MUL_PRIV_SWITCH(sw);

     /* Only works with 1.3 or more */
    if (neigh_sw->ofp_ver == OFP_VERSION ||
        sw->ofp_ver == OFP_VERSION) return;

    app_log_debug("%s: 0x%llx -> 0x%llx", FN,
                  U642ULL(sw->dpid), U642ULL(neigh_sw->dpid));

    conx_finder.src_dpid = sw->dpid;
    conx_finder.dst_dpid = neigh_sw->dpid;

    if ((hent = g_hash_table_lookup(conx->uflow_htbl, &conx_finder))) {
        conx_uflow_scan(NULL, hent, false);
    }

    if (!psw || 
        !psw->sw_conx_htbl) return;

    if (!(conx_ent = g_hash_table_lookup(psw->sw_conx_htbl, &conx_finder))) {
        return; 
    }

    g_hash_table_remove(psw->sw_conx_htbl, conx_ent);
    //conx_route_uninstall(conx_ent, true);
}

void
conx_nh_tbl_init(void)
{
    if (!mul_service_available(conx->mul_service)) 
        return;

    app_log_debug("[NH TBL INIT]");
    c_wr_lock(&conx->lock);
    c_app_traverse_all_switches(conx_per_dp_nh_init, NULL);
    c_wr_unlock(&conx->lock);
} 

static void
conx_per_conn_retry(void *k, void *v UNUSED, void *arg UNUSED)
{
    conx_ent_t *conx_ent = k;
    rt_list_t *rt_list;

    if (conx_any_valid_route(conx_ent)) return;

    rt_list = mul_route_get_all(conx->route_service,
                                conx_ent->src_alias,
                              conx_ent->dst_alias);

    conx_routes_neq_install(conx_ent, rt_list);
}

static void
conx_per_dp_retry(void *key UNUSED, void *sw_arg, void *uarg UNUSED)
{
    mul_switch_t *sw = sw_arg;
    conx_sw_priv_t *psw = MUL_PRIV_SWITCH(sw);

    /* Only works with 1.3 or more */
    if (sw->ofp_ver == OFP_VERSION || !psw) return;

    g_hash_table_foreach(psw->sw_conx_htbl,
                         (GHFunc)conx_per_conn_retry,
                         NULL);
}

void
conx_retry_all(void)
{
    c_wr_lock(&conx->lock);
    c_app_traverse_all_switches(conx_per_dp_retry, NULL);
    c_wr_unlock(&conx->lock);
}
