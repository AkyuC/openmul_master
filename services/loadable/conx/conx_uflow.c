/*
 *  conx_uflow.c: Connector user flow module 
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

static int conx_uflow_install(user_fl_ent_t *uflow,
                              uint64_t flags);
static int conx_uflow_uninstall(user_fl_ent_t *uflow,
                                uint64_t flags);

void
conx_ucookie_hent_destroy(void *arg)
{
    free(arg);
}

static void
ufl_hent_list_elem_activate(void *e_arg, void *arg)
{
    user_fl_ent_t *u_flow = e_arg;
    int err = 0;

    if (u_flow->valid) return;

    u_flow->conx = arg;
    err = conx_uflow_install(u_flow, 0);
    if (!err)
        u_flow->valid = true;
    else 
        u_flow->conx = NULL;
  
    return;
}

static void
ufl_hent_list_elem_deactivate(void *e_arg, void *arg UNUSED)
{
    user_fl_ent_t *u_flow = e_arg;

    if (!u_flow->valid) return;

    conx_uflow_uninstall(u_flow, 0);
    u_flow->valid = false;
    u_flow->conx = NULL;
  
    return;
}

static void
ufl_hent_list_elem_destroy(void *e_arg, void *arg)
{
    user_fl_ent_t *u_flow = e_arg;

    ufl_hent_list_elem_deactivate(u_flow, arg);
    free(u_flow);
}

void
conx_ufl_hent_destroy(void *e_arg)
{
    conx_ufl_hent_t *ent = e_arg;
    if (ent->user_fl_list)
        g_slist_foreach(ent->user_fl_list, ufl_hent_list_elem_destroy,  
                        ent);
    free(ent);
}

void
conx_uflow_scan(conx_ent_t *conx_ent, conx_ufl_hent_t *hent,
                bool active)
{
    if (active)
        g_slist_foreach(hent->user_fl_list, ufl_hent_list_elem_activate,
                        conx_ent);
    else
        g_slist_foreach(hent->user_fl_list, ufl_hent_list_elem_deactivate,
                        NULL);
}

static int
conx_uflow_uninstall(user_fl_ent_t *uflow, uint64_t flags)
{
    int err = 0;
    bool reset = false;

    if (uflow->flags & CONX_ENT_LOOPBACK) {
        /* FIXME start: Realized while doing interop with HP that
         * installing/uninstalling a flow in L2 table for single 
         * node case is appropriate for maintaining the genarality */
        uflow->flow.table_id = CONX_L2_TABLE_ID;
        /* FIXME end: */
    }else {
        /* Uninstall at source */
        uflow->flow.table_id = CONX_L1_TABLE_ID;
    }

#ifdef CONX_FLOW_DEBUG
    if (1) {
        char * str = of_dump_flow_generic(&uflow->flow, &uflow->mask);
        app_log_debug("%s: Del Flow SRC 0x%llx t%d %s",
                      FN, U642ULL(uflow->conx->key.src_dpid),
                      uflow->flow.table_id, str);
        if (str) free(str);
    }
#endif

    mul_service_send_flow_del(conx->mul_service,
            uflow->conx->key.src_dpid,
            &uflow->flow, &uflow->mask,
            0, uflow->prio,
            flags, OFPG_ANY);
    if(!(flags & C_FL_NO_ACK)) {
        if (c_service_timed_wait_response(conx->mul_service)) {
            err = -EFAULT;
        }
    }

    if (uflow->flags & CONX_ENT_LOOPBACK ||
        uflow->flags & CONX_UENT_SRC_FLOW) {
        goto done;
    }

    /* Uninstall at dest */
    if (of_mask_has_in_port(&uflow->mask)) {
        of_mask_clr_in_port(&uflow->mask);
        reset = true;
    }
    uflow->flow.table_id = CONX_L2_TABLE_ID;

#ifdef CONX_FLOW_DEBUG
    if (1) {
        char * str = of_dump_flow_generic(&uflow->flow, &uflow->mask);
        app_log_debug("%s: Del Flow DST 0x%llx t%d %s",
                      FN, U642ULL(uflow->conx->key.dst_dpid),
                      uflow->flow.table_id, str);
        if (str) free(str);
    }
#endif

    mul_service_send_flow_del(conx->mul_service,
            uflow->conx->key.dst_dpid,
            &uflow->flow, &uflow->mask,
            0, uflow->prio,
            flags, OFPG_ANY);
    if (reset) of_mask_set_in_port(&uflow->mask);
    if(!(flags & C_FL_NO_ACK)) {
        uflow->flow.table_id = CONX_L1_TABLE_ID;
        if (c_service_timed_wait_response(conx->mul_service)) {
            err = -EFAULT;
        }
    }
done:
    return err;
}

static int
conx_uflow_install(user_fl_ent_t *uflow, uint64_t flags)
{
    struct mul_act_mdata mdata;
    int err = 0;
    bool reset = false;

    if (uflow->conx->type != CONX_TUNNEL_OF) {
        return -EINVAL;
    }

    /* Install at source */
    uflow->flow.table_id = CONX_L1_TABLE_ID;
    mul_app_act_alloc(&mdata);
    if (mul_app_act_set_ctors(&mdata, uflow->conx->key.src_dpid)) {
        app_rlog_err("%s: dp 0x%llx not found", FN,
                U642ULL(uflow->conx->key.src_dpid));
        err = -EFAULT;
        goto err;
    }

    if (uflow->conx->flags & CONX_ENT_LOOPBACK) {
        /* FIXME start: Realized while doing interop with HP that
         * installing/uninstalling a flow in L2 table for single 
         * node case is appropriate for maintaining the genarality */
        uflow->flow.table_id = CONX_L2_TABLE_ID;
        /* FIXME end: */
        mul_service_send_flow_add(conx->mul_service,
                uflow->key.src_dpid,
                &uflow->flow, &uflow->mask,
                OFP_NO_BUFFER,
                uflow->egress_actions,
                uflow->act_len,
                0, 0, uflow->prio,
                flags);
        uflow->flow.table_id = CONX_L1_TABLE_ID;
        if(!(flags & C_FL_NO_ACK)) {
            if (c_service_timed_wait_response(conx->mul_service)) {
                char *fl_str = of_dump_flow_generic(&uflow->flow, &uflow->mask);
                app_rlog_err("Failed to LB add in DP 0x%llx flow %s",
                        U642ULL(uflow->conx->key.src_dpid), fl_str);
                if (fl_str) free(fl_str);
                err = -EFAULT;
                goto err;
            }
        }
        goto done;
    }

    if (conx->use_groups && uflow->conx->ecmp_grp.group_id) {
        if (mul_app_action_set_group(&mdata,
                    uflow->conx->ecmp_grp.group_id) <= 0) {
            app_rlog_err("%s: Can't add group action", FN);
            err = -EINVAL;
            goto err;
        }
    } else {
        if (mul_app_action_set_dmac(&mdata,
                    uflow->tun_desc.u.tun_dmac) <= 0) {
            app_rlog_err("%s: act dmac failed", FN);
            err = -EINVAL;
            goto err;
        }

        if (mul_app_action_set_smac(&mdata,
                    uflow->tun_desc.u.tun_smac) <= 0) {
            app_rlog_err("%s: act smac failed", FN);
            err = -EINVAL;
            goto err;
        }

        if (mul_app_inst_goto(&mdata, CONX_L2_TABLE_ID)) {
            app_rlog_err("%s: Can't add goto instruction", FN);
            err = -EINVAL;
            goto err;
        }
    }

    mul_service_send_flow_add(conx->mul_service,
            uflow->key.src_dpid,
            &uflow->flow, &uflow->mask,
            OFP_NO_BUFFER,
            mdata.act_base, mul_app_act_len(&mdata),
            0, 0, uflow->prio, flags);
    if(!(flags & C_FL_NO_ACK)) {
        if ((err = c_service_timed_wait_response(conx->mul_service))) {
            char *fl_str;
            if (err == OFPFMFC_FLOW_EXIST) {
                err = 0;
                goto install_dst;
            }
            fl_str = of_dump_flow_generic(&uflow->flow, &uflow->mask);
            app_rlog_err("Failed to add in DP 0x%llx flow %s",
                    U642ULL(uflow->conx->key.src_dpid), fl_str);
            free(fl_str);
            err = -EFAULT;
            goto err;
        }
    }

    if (uflow->flags & CONX_UENT_SRC_FLOW) goto done; 

install_dst:
    /* Install at dest */
    uflow->flow.table_id = CONX_L2_TABLE_ID;
    if (of_mask_has_in_port(&uflow->mask)) {
        of_mask_clr_in_port(&uflow->mask);
        reset = true;
    }
    mul_service_send_flow_add(conx->mul_service,
            uflow->key.dst_dpid,
            &uflow->flow, &uflow->mask,
            OFP_NO_BUFFER,
            uflow->egress_actions,
            uflow->act_len,
            0, 0, uflow->prio, flags);
    if (reset) of_mask_set_in_port(&uflow->mask);
    uflow->flow.table_id = CONX_L1_TABLE_ID;
    if(!(flags & C_FL_NO_ACK)) {
        if ((err = c_service_timed_wait_response(conx->mul_service))) {
            char *fl_str;
            if (err == OFPFMFC_FLOW_EXIST) {
                err = 0;
                goto done;
            }
            fl_str = of_dump_flow_generic(&uflow->flow, &uflow->mask);
            app_rlog_err("Failed to add in DP 0x%llx flow %s",
                    U642ULL(uflow->conx->key.dst_dpid), fl_str);
            free(fl_str);
            err = -EFAULT;
            goto err_uinstall_src;
        }
    }

done:
    mul_app_act_free(&mdata);
    return 0;

err_uinstall_src:
    uflow->flow.table_id = CONX_L1_TABLE_ID;
    mul_service_send_flow_del(conx->mul_service,
            uflow->conx->key.src_dpid,
            &uflow->flow, &uflow->mask,
            0, uflow->prio,
            flags, OFPG_ANY);
    if(!(flags & C_FL_NO_ACK)) {
        if (c_service_timed_wait_response(conx->mul_service)) {
            err = -EFAULT;
        }
    }
err:
    mul_app_act_free(&mdata);
    return err;
}

static user_fl_ent_t *
conx_uflow_ent_alloc(struct flow *in_fl,
                     struct flow *in_mask,
                     uint32_t tenant,
                     uint32_t app_cookie,
                     void *actions,
                     size_t action_len,
                     conx_ent_t *ent,
                     uint16_t prio)
{
    user_fl_ent_t *u_ent = conx_safe_calloc(sizeof(*u_ent));
    if (!u_ent) return NULL;

    if (actions) {
        u_ent->egress_actions = conx_safe_calloc(action_len);
        if (!u_ent->egress_actions) {
            conx_free(u_ent);
            return NULL;
        }
        memcpy(u_ent->egress_actions, actions, action_len);
        u_ent->act_len = action_len;
    }

    memcpy(&u_ent->tun_desc, &ent->tun_desc, 
           sizeof(conx_tunnel_desc_t));
    memcpy(&u_ent->flow, in_fl, sizeof(struct flow));
    memcpy(&u_ent->mask, in_mask, sizeof(struct flow));
    memcpy(&u_ent->key, &ent->key, sizeof(conx_ent_key_t));
    if (u_ent->key.src_dpid == u_ent->key.dst_dpid)
        u_ent->flags |= CONX_ENT_LOOPBACK;
    u_ent->flow.table_id = CONX_L1_TABLE_ID;
    u_ent->tenant = tenant;
    u_ent->app_cookie = app_cookie;
    u_ent->prio = prio;
    u_ent->conx = ent;

    return u_ent;
}

static int
conx_uflow_dup_finder(const void *ent, const void *uarg)
{
    const user_fl_ent_t *fl_ent = ent;
    const user_fl_ent_t *uflow = uarg;

    if (!memcmp(&fl_ent->key,  &uflow->key, sizeof(conx_ent_key_t)) &&
        !memcmp(&fl_ent->flow, &uflow->flow, sizeof(struct flow)) &&
        !memcmp(&fl_ent->mask, &uflow->mask, sizeof(struct flow))) {
        return 0;
    }

    return 1;
}

static void UNUSED
conx_uflow_dumper(const void *ent, const void *uarg UNUSED)
{
    user_fl_ent_t *fl_ent = (user_fl_ent_t *)ent;
    char *str;

    str = of_dump_flow_generic(&fl_ent->flow, &fl_ent->mask);
    app_rlog_debug("Table ent flow %s", str);
    return;
}

int
conx_uflow_add(uint64_t src_dp,
               uint64_t dst_dp,
               struct flow *in_fl,
               struct flow *in_mask,
               uint32_t tunnel_key,
               uint32_t tunnel_type,
               uint32_t app_cookie,
               void *actions,
               size_t action_len,
               uint64_t flags,
               bool src_flow,
               uint16_t uflow_prio)
{
    conx_ent_key_t conx_finder;
    mul_switch_t *sw;
    conx_sw_priv_t *psw;
    conx_ent_t *conx_ent;
    conx_ent_t fake_conx_ent;
    int err = 0;
    user_fl_ent_t *uflow;
    GSList *ufl_item = NULL;
    conx_ufl_hent_t *hent;
    char *str;
    bool inactive = false;

    conx_finder.src_dpid = src_dp;
    conx_finder.dst_dpid = dst_dp;

    if (!uflow_prio)
        uflow_prio = CONX_UFLOW_PRIO;

#ifdef CONX_FLOW_DEBUG
    str = of_dump_flow_generic(in_fl, in_mask);
    app_log_debug("%s: src 0x%llx->0x%llx %s",
                  FN, U642ULL(src_dp), U642ULL(dst_dp), str);
    if (str) free(str);
#endif

    memset(&fake_conx_ent, 0, sizeof(fake_conx_ent));

    c_wr_lock(&conx->lock);
    sw = c_app_switch_get_with_id(src_dp);
    if (!sw) {
        err = -EINVAL;
        app_rlog_err("%s: No such DP 0x%llx", FN, U642ULL(src_dp));
        goto out;
    }
    psw = MUL_PRIV_SWITCH(sw);
    if (!psw) {
        err = -EFAULT; 
        goto out;
    }

    if (!(conx_ent = g_hash_table_lookup(psw->sw_conx_htbl, &conx_finder))) {
        err = -EINVAL;
        app_rlog_err("%s: No active end-points 0x%llx->0x%llx",
                  FN, U642ULL(src_dp), U642ULL(dst_dp));
        conx_ent = &fake_conx_ent; 
        memcpy(&conx_ent->key, &conx_finder, sizeof(conx_ent_key_t));
        conx_ent->type = tunnel_type;
        inactive = true;
    }

    if (conx_ent->type != tunnel_type) {
        app_rlog_err("%s: Tunnel type mismatch", FN);
        goto out;
    }

    if (!(hent = g_hash_table_lookup(conx->uflow_htbl, &conx_finder))) {
        hent = conx_safe_calloc(sizeof(*hent));
        if (!hent) {
            err = -ENOMEM;
            goto out;
        }
        memcpy(&hent->key, &conx_finder, sizeof(conx_ent_key_t));
        g_hash_table_insert(conx->uflow_htbl, hent, hent);
    }

    uflow = conx_uflow_ent_alloc(in_fl, in_mask,
                                 tunnel_key,
                                 app_cookie,
                                 actions, action_len,
                                 conx_ent, uflow_prio);
    if (!uflow) {
        err = -ENOMEM;
        goto out;
    }

    if (src_flow) uflow->flags |= CONX_UENT_SRC_FLOW;

    if (hent->user_fl_list &&
        (ufl_item = g_slist_find_custom(hent->user_fl_list,
                            uflow,
                            conx_uflow_dup_finder))) {
        user_fl_ent_t *ent = ufl_item->data;     
        ent->refresh_time = time(NULL);
        ent->flags &= ~CONX_UENT_STALE;
        str = of_dump_flow_generic(in_fl, in_mask);
        app_rlog_err("%s: uFlow %s already present", FN, str);
        free(str);
        err = -EEXIST;
        conx_free(uflow);
        goto out;
    }

    if (!inactive) {
        err = conx_uflow_install(uflow, flags);
        if (err) goto out;

        uflow->valid = true;
    } else {
        uflow->valid = false;
        uflow->conx = NULL;
    }

    hent->user_fl_list = g_slist_append(hent->user_fl_list, uflow);

out:
    c_wr_unlock(&conx->lock);
    return err;
}

static int
__conx_uflow_del(uint64_t src_dp,
               uint64_t dst_dp,
               struct flow *in_fl,
               struct flow *in_mask,
               bool need_lock,
               uint64_t flags)
{
    conx_ent_key_t conx_finder;
    mul_switch_t *sw;
    conx_sw_priv_t *psw = NULL;
    conx_ent_t *conx_ent;
    conx_ent_t fake_conx_ent;
    conx_ufl_hent_t *hent;
    int err = 0;
    GSList *lent = NULL;
    user_fl_ent_t *uflow = NULL, *uflow_ent = NULL;
    bool inactive = false;
    char *str;
    
    memset(&fake_conx_ent, 0, sizeof(fake_conx_ent));
    conx_finder.src_dpid = src_dp;
    conx_finder.dst_dpid = dst_dp;

#ifdef CONX_FLOW_DEBUG
    str = of_dump_flow_generic(in_fl, in_mask);
    app_log_debug("%s: src 0x%llx->0x%llx %s",
                  FN, U642ULL(src_dp), U642ULL(dst_dp), str);
    if (str) free(str);
#endif

    if (need_lock) c_wr_lock(&conx->lock);
    sw = c_app_switch_get_with_id(src_dp);
    if (!sw) {
        err = -EINVAL;
        app_rlog_err("%s: No such DP 0x%llx", FN, U642ULL(src_dp));
    } else {
        psw = MUL_PRIV_SWITCH(sw);
        if (!psw) {
            err = -EFAULT; 
            goto out;
        }
    }

    if (!psw ||
        !(conx_ent = g_hash_table_lookup(psw->sw_conx_htbl, &conx_finder))) {
        err = -EINVAL;
        app_rlog_err("%s: No end-points 0x%llx->0x%llx - faking",
                     FN, U642ULL(src_dp), U642ULL(dst_dp));
        conx_ent = &fake_conx_ent;
        memcpy(&conx_ent->key, &conx_finder, sizeof(conx_ent_key_t));
        inactive = true;
    }

    if (!(hent = g_hash_table_lookup(conx->uflow_htbl, &conx_finder))) {
        app_rlog_err("%s: No uflow thbl ent 0x%llx->0x%llx",
                     FN, U642ULL(src_dp), U642ULL(dst_dp));
        err = -EINVAL;
        goto out;
    }

    uflow = conx_uflow_ent_alloc(in_fl, in_mask,
                                 0, 0, NULL, 0,
                                 conx_ent, 0);
    if (!uflow) {
        err = -ENOMEM;
        goto out;
    }

    uflow->flow.table_id = CONX_L1_TABLE_ID;

    if (!hent->user_fl_list || 
        !(lent = g_slist_find_custom(hent->user_fl_list,
                             uflow,
                             conx_uflow_dup_finder)) ||
        !lent->data) {
        str = of_dump_flow_generic(in_fl, in_mask);
        app_rlog_err("%s: uFlow %s not present", FN, str);
        free(str);
        err = -EINVAL;
        goto out;
    }
    

    uflow_ent = lent->data;
    if (inactive || !uflow_ent->valid) uflow_ent->conx = &fake_conx_ent;
    err = conx_uflow_uninstall(uflow_ent, flags);
    hent->user_fl_list = g_slist_remove(hent->user_fl_list, uflow_ent);
    if (!hent->user_fl_list) g_hash_table_remove(conx->uflow_htbl, hent);

out:
    if (need_lock) c_wr_unlock(&conx->lock);
    if (uflow) conx_free(uflow);
    if (uflow_ent) conx_free(uflow_ent);
    return err;
}

int
conx_uflow_del(uint64_t src_dp,
               uint64_t dst_dp,
               struct flow *in_fl,
               struct flow *in_mask,
               uint64_t flags)
{
    return __conx_uflow_del(src_dp, dst_dp, in_fl, in_mask,
                            true, flags);
}

static void
conx_uflow_traverse_all_for_stale(void *ent, void *uarg)
{
    user_fl_ent_t *uflow = ent;
    struct uflow_iter_arg *arg = uarg;
    uint32_t app_cookie;

    if (!arg) return;
    
    if (arg->stale) {
        if (uflow->flags & CONX_UENT_STALE) {
            char *str = of_dump_flow_generic(&uflow->flow, &uflow->mask);
            arg->ucookie->stale_list =
                g_slist_append(arg->ucookie->stale_list, uflow);
            arg->ctr++;
            app_rlog_info("Stale flow src 0x%llx->dst 0x%llx %s", 
                          U642ULL(uflow->key.src_dpid),
                          U642ULL(uflow->key.dst_dpid), str);
            if (str) free(str);
        }
    } else {
        if (!arg->uarg) return;
        app_cookie = *(uint32_t *)arg->uarg;
        if (app_cookie == uflow->app_cookie) {
            uflow->refresh_time = time(NULL);
            uflow->flags |= CONX_UENT_STALE;
            arg->ctr++;
        }
    }
}

static void
conx_uflow_hent_traverse(void *key UNUSED, void *h_arg, void *uarg)
{
    conx_ufl_hent_t *hent = h_arg;
    struct uflow_iter_arg *iter_arg = uarg;
    
    if (hent &&
        hent->user_fl_list &&
        iter_arg->uflow_iter_fn) {
        g_slist_foreach(hent->user_fl_list, iter_arg->uflow_iter_fn, 
                        uarg);
    }
}

static void
conx_uflow_stale_del(void *ent_arg, void *uarg UNUSED)
{
    user_fl_ent_t *uflow = ent_arg;    

    __conx_uflow_del(uflow->key.src_dpid,
                     uflow->key.dst_dpid,
                     &uflow->flow,
                     &uflow->mask,
                     false,
                     C_FL_NO_ACK);
}

static void
conx_uflow_stale_end(evutil_socket_t fd UNUSED, short event UNUSED,
                     void *uarg)
{
    struct conx_ucookie_ent *hent = uarg; 
    struct uflow_iter_arg arg = { 
                .uflow_iter_fn = conx_uflow_traverse_all_for_stale,
                .uarg = &hent->u_app_cookie,
                .stale = 1,
                .ctr = 0,
                .ucookie = hent};

    c_wr_lock(&conx->lock);
    if (conx->uflow_htbl) {
        arg.ucookie = hent;    
        g_hash_table_foreach(conx->uflow_htbl,
                             conx_uflow_hent_traverse,
                             &arg);
        if (hent->stale_list) {
            g_slist_foreach(hent->stale_list, conx_uflow_stale_del,
                            &hent);
            g_slist_free(hent->stale_list);
            hent->stale_list = NULL;
        }        
    }
    g_hash_table_remove(conx->ucookie_htbl, hent);
    c_wr_unlock(&conx->lock);

    evtimer_del(hent->stale_timer_event);
    event_free(hent->stale_timer_event);
}

void
conx_uflow_stale_begin(uint32_t cookie)
{
    struct conx_ucookie_ent *hent; 
    struct timeval tv = { CONX_UFLOW_STALE_TGR_TIME, 0 };
    struct uflow_iter_arg arg = { 
                .uflow_iter_fn = conx_uflow_traverse_all_for_stale,
                .uarg = &cookie,
                .stale = 0,
                .ctr = 0,
                .ucookie = NULL };

    c_wr_lock(&conx->lock);
    if (conx->uflow_htbl) {
        if (!(hent = g_hash_table_lookup(conx->ucookie_htbl, &cookie))) {
            hent = conx_safe_calloc(sizeof(*hent));
            if (!hent) {
                app_rlog_err("%s: Mem exhausted", FN);
                c_wr_unlock(&conx->lock);
                return;
            }
            hent->u_app_cookie = cookie;
            g_hash_table_insert(conx->ucookie_htbl, hent, hent);
        } else {
            app_rlog_info("app-cookie %lu staling is in queue", U322UL(cookie));
            c_wr_unlock(&conx->lock);
            return;
        }

        app_rlog_info("app-cookie %lu staling start", U322UL(cookie));
        arg.ucookie = hent;    
        g_hash_table_foreach(conx->uflow_htbl,
                             conx_uflow_hent_traverse,
                             &arg);
        if (!arg.ctr) {
            if (hent->stale_timer_event) {
                evtimer_del(hent->stale_timer_event);
                event_free(hent->stale_timer_event);
            }
            app_rlog_debug("%s: No flows for %lu cookie", FN, U322UL(cookie));
            g_hash_table_remove(conx->ucookie_htbl, hent);
        } else {
            hent->stale_timer_event = evtimer_new(conx->base,
                                        conx_uflow_stale_end,
                                        hent);    
            evtimer_add(hent->stale_timer_event, &tv);
        }        
    }
    c_wr_unlock(&conx->lock);
}
