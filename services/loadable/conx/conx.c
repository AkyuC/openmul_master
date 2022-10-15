/*
 *  conx.c: Connector module 
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
extern struct mul_app_client_cb conx_app_cbs;

static unsigned int
conx_ent_key_calc(const void *p)
{
    return hash_bytes((uint8_t *)p, sizeof(conx_ent_key_t), 1);
}

static int
conx_ent_key_eq(const void *p1, const void *p2)
{
    return !memcmp(p1, p2, sizeof(conx_ent_key_t));
}

void
conx_ent_free(void *arg)
{
    free(arg);
}

static void
conx_dp_alias_to_oftun_mac(uint64_t ddpid,
                           int dalias UNUSED,
                           uint64_t sdpid,
                           int salias UNUSED,
                           uint8_t *dmac_key,
                           uint8_t *smac_key)
{
    memcpy(dmac_key, &ddpid, 6);
    memcpy(&smac_key[2], &sdpid, 4);
    memcpy(smac_key, INC_PTR8(&ddpid, 6), 2);
}

conx_ent_t *
conx_ent_alloc(uint64_t s_dpid, uint64_t d_dpid,
               int s_alias, int d_alias,
               uint64_t tunnel_id, uint32_t tunnel_key,
               conx_tunnel_t tun_type)
{
    conx_ent_t *ent = conx_safe_calloc(sizeof(*ent)); 

    if (!ent) return NULL;

    ent->key.src_dpid = s_dpid;
    ent->key.dst_dpid = d_dpid;
    ent->src_alias = s_alias;
    ent->dst_alias = d_alias;

    switch (tun_type) {
    case CONX_TUNNEL_OF:
        conx_dp_alias_to_oftun_mac(d_dpid, d_alias,
                                   s_dpid, s_alias,
                                   ent->tun_desc.u.tun_dmac,
                                   ent->tun_desc.u.tun_smac);
        //c_hex_dump(ent->tun_desc.u.tun_smac, 6);
        //c_hex_dump(ent->tun_desc.u.tun_dmac, 6);
        break;
    case CONX_TUNNEL_VXLAN:
    case CONX_TUNBEL_GRE:
        ent->tun_desc.o.tunnel_id = tunnel_id;
        ent->tun_desc.o.tunnel_key = tunnel_key;
        break;
    default:
        app_rlog_err("Unknown conx type");
        free(ent);
        return NULL; 
    }

    ent->type = tun_type;
    if (s_dpid == d_dpid)
        ent->flags |= CONX_ENT_LOOPBACK;

    return ent;
}

static int
conx_sw_priv_alloc(void **priv)
{
    conx_sw_priv_t **sw_pptr = (conx_sw_priv_t **)priv;

    *sw_pptr = conx_calloc(sizeof(conx_sw_priv_t));
    return 0;
}

static void 
conx_sw_priv_free(void *priv)
{
    free(priv);
    return;
}

static void
conx_ent_destroy(void *e_arg)
{
    conx_ent_t *ent = e_arg;
    conx_route_uninstall_all(ent, true);
    free(ent);
}

static void
conx_sw_add(mul_switch_t *sw)
{
    conx_sw_priv_t *sw_priv = MUL_PRIV_SWITCH(sw);

    /* Only works with 1.3 or more */
    if (sw->ofp_ver == OFP_VERSION) return;

    c_wr_lock(&conx->lock);
    sw_priv->app_sw = sw;
    sw_priv->sw_conx_htbl = g_hash_table_new_full(conx_ent_key_calc,
                                             conx_ent_key_eq,
                                             NULL,
                                             conx_ent_destroy);
    c_wr_unlock(&conx->lock);
}

static void
conx_sw_del(mul_switch_t *sw)
{
    conx_sw_priv_t *sw_priv = MUL_PRIV_SWITCH(sw);

    /* Only works with 1.3 or more */
    if (sw->ofp_ver == OFP_VERSION) return;

    c_wr_lock(&conx->lock);
    if (sw_priv) {
        c_app_traverse_all_switches(conx_per_dp_nh_destroy, sw);
        sw_priv->app_sw = NULL;
        if (sw_priv->sw_conx_htbl) g_hash_table_destroy(sw_priv->sw_conx_htbl);
        sw_priv->sw_conx_htbl = NULL;
    }
    c_wr_unlock(&conx->lock);
}

static void
conx_tr_update(uint64_t status)
{
    app_log_debug("[tr-status] [%llu]", U642ULL(status));

    if(status == C_RT_APSP_CONVERGED) {
        /* Update the next hop table*/
        conx_nh_tbl_init();
    }
}

static void
conx_core_closed(void)
{
    app_log_debug("%s: ", FN);
    return;
}

static void
conx_core_reconn(void)
{
    app_log_debug("%s: ", FN);
    mul_register_app_cb(NULL, CONX_APP_NAME,
                        C_APP_ALL_SW,
                        C_APP_ALL_EVENTS,
                        0,
                        NULL,
                        &conx_app_cbs);
}

struct mul_app_client_cb conx_app_cbs = {
    .switch_priv_alloc = conx_sw_priv_alloc,
    .switch_priv_free = conx_sw_priv_free,
    .switch_add_cb =  conx_sw_add,
    .switch_del_cb = conx_sw_del,
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = NULL,
    .switch_port_del_cb = NULL,
    .switch_port_link_chg = NULL,
    .switch_port_adm_chg = NULL,
    .core_conn_closed = conx_core_closed,
    .core_conn_reconn = conx_core_reconn,
    .topo_route_status_cb = conx_tr_update
};

static void
conx_route_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    app_log_debug("[tr-service] %d", conn_event);
}

static void
conx_mul_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    app_log_debug("[mul-service] %d", conn_event);

    if (conn_event == MUL_SERVICE_UP) {
        conx_nh_tbl_init();
    }
}

//#define CONX_STATIC_INIT 1

#ifdef CONX_STATIC_INIT
static void conx_service_mod_uflow(void *conx_service, struct cbuf *b,
                       struct c_ofp_auxapp_cmd *cofp_aac,
                       bool add);

static int
__mul_conx_mod_uflow(
                   uint32_t cookie,
                   bool add,
                   size_t n_dpid,
                   uint64_t *src_dps,
                   uint64_t dst_dp,
                   struct flow *in_fl,
                   struct flow *in_mask,
                   uint32_t tunnel_key,
                   uint32_t tunnel_type,
                   void *actions,
                   size_t action_len,
                   uint64_t fl_flags,
                   uint32_t conx_flags)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_conx_user_flow *conx_fl;
    int i = 0;
    uint8_t zero_mac[6] = { 0, 0, 0, 0, 0, 0};
    size_t ext_len = 0;
    uint8_t *act_ptr = NULL;
    uint64_t *src_dpid;

    if (n_dpid < 1 || n_dpid > 1024) return -1;

    if (tunnel_type == CONX_TUNNEL_OF &&
        (memcmp(in_mask->dl_dst, zero_mac, 6) ||
        memcmp(in_mask->dl_src, zero_mac, 6))) {
        c_log_err("uFlow can't use src-dst Mac match");
        return -1;
    }

    if (of_check_flow_wildcard_generic(in_fl, in_mask)) {
        c_log_debug("Conx add-uflow all-wc not allowed");
        return -1;
    }

    ext_len = action_len + (sizeof(uint64_t)*n_dpid);

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*conx_fl) + ext_len,
                    C_OFPT_AUX_CMD, 0);
    if (!b) return -1;
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = add ? htonl(C_AUX_CMD_CONX_ADD_UFLOW):
                               htonl(C_AUX_CMD_CONX_DEL_UFLOW);

    conx_fl = ASSIGN_PTR(cofp_auc->data);
    conx_fl->dst_dpid = htonll(dst_dp);
    conx_fl->tunnel_key = htonl(tunnel_key); /* Overridden as tenant-id */
    conx_fl->tunnel_type = htonl(tunnel_type);
    conx_fl->app_cookie = htonl(cookie);
    conx_fl->fl_flags = htonll(fl_flags);
    conx_fl->conx_flags = htonl(conx_flags);
    conx_fl->n_src = htonll(n_dpid);

    memcpy(&conx_fl->flow, in_fl, sizeof(struct flow));
    memcpy(&conx_fl->mask, in_mask, sizeof(struct flow));

    src_dpid = ASSIGN_PTR(conx_fl->src_dpid_list);
    for (i = 0; i < n_dpid; i++) {
        src_dpid[i] = htonll(src_dps[i]);
    }

    if (add && action_len) {
        act_ptr = INC_PTR8(conx_fl->src_dpid_list, sizeof(uint64_t)*n_dpid);
        memcpy(act_ptr, actions, action_len);
    }

    conx_service_mod_uflow(NULL, b, cofp_auc, add);
    free_cbuf(b);

    return 0;
}

#endif

static void
conx_per_5sec_timer(evutil_socket_t fd UNUSED,
                    short event UNUSED,
                    void *arg UNUSED)
{
    struct timeval tv = CONX_5SEC_TV;

#ifdef CONX_STATIC_INIT
    static int i = 1;
    struct flow flow;
    struct flow mask;
    struct mul_act_mdata mdata;

    if (i > 0) {
        uint8_t dmac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };
        uint64_t s_dps[2];
        mul_app_act_alloc(&mdata);
        if (mul_app_act_set_ctors(&mdata, 0x3)) {
            assert(0);
        }
        mul_app_action_set_dmac(&mdata, dmac);
        mul_app_action_output(&mdata, 0x0);

        memset(&flow, 0, sizeof(flow));
        of_mask_set_dc_all(&mask);
        flow.ip.nw_dst = htonl(0x0c0c0c00);
        flow.dl_type = htons(ETH_TYPE_IP);
        of_mask_set_dl_type(&mask);
        of_mask_set_nw_dst(&mask, 24);
        s_dps[0] = 0x1;
        //s_dps[1] = 0x2;
        __mul_conx_mod_uflow(44, true,1, s_dps, 0x3ULL,
                             &flow, &mask,
                             0, CONX_TUNNEL_OF,
                             mdata.act_base,  mul_app_act_len(&mdata),
                             C_FL_NO_ACK, CONX_UFLOW_FORCE);
        mul_app_act_free(&mdata);

        mul_app_act_alloc(&mdata);
        if (mul_app_act_set_ctors(&mdata, 0x1)) {
            assert(0);
        }
        mul_app_action_set_dmac(&mdata, dmac);
        mul_app_action_output(&mdata, 0x0);

        memset(&flow, 0, sizeof(flow));
        of_mask_set_dc_all(&mask);
        flow.ip.nw_dst = htonl(0x0b0b0b00);
        flow.dl_type = htons(ETH_TYPE_IP);
        of_mask_set_dl_type(&mask);
        of_mask_set_nw_dst(&mask, 24);
        //s_dps[0] = 0x2;
        s_dps[1] = 0x3;
        __mul_conx_mod_uflow(44, true, 1, s_dps, 0x1ULL,
                             &flow, &mask,
                             0, CONX_TUNNEL_OF,
                             mdata.act_base,  mul_app_act_len(&mdata),
                             C_FL_NO_ACK, CONX_UFLOW_FORCE);
        mul_app_act_free(&mdata);
        i--;
    }
    if (i == 0) {
        conx_uflow_stale_begin(45);
        conx_uflow_stale_begin(55);
        i--;
    }
#endif
    
    evtimer_add(conx->per_sec_tim_event, &tv);
}

static uint64_t *
conx_mk_valid_dpid_list(uint64_t *orig, size_t *n_dps)
{
    int i = 0, j = 0;
    bool found = false;
    size_t valid_dps = 0;
    uint64_t *srcs = NULL;

    srcs = calloc(1, sizeof(uint64_t)*(*n_dps));
    if (!srcs)
        return NULL; 

    for (i = 0; i < *n_dps; i++) {
        found = false;
        for (j = 0; j < valid_dps; j++) {
            if (srcs[j] == orig[i]) {
                found = true;
                break;
            }
        }

        if (!found) {
            srcs[valid_dps++] = orig[i];
        }
    }
    *n_dps = valid_dps;
    return srcs;
}

static void
conx_service_mod_uflow(void *conx_service, struct cbuf *b,
                       struct c_ofp_auxapp_cmd *cofp_aac,
                       bool add)
{
    struct c_conx_user_flow *conx_uflow;
    size_t action_len;
    void *actions = NULL;
    int ret = 0;
    int i = 0; 
    size_t n_dps = 0;
    size_t dp_list_len = 0;
    uint16_t prio = CONX_UFLOW_PRIO;
    uint32_t conx_flags;
    uint64_t *psrc_dpid, *srcs = NULL;

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd) + 
        sizeof(struct c_conx_user_flow)) {
        app_rlog_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(cofp_aac->header.length),
                  (unsigned long)(sizeof(struct c_ofp_auxapp_cmd) +
                                  sizeof(struct c_conx_user_flow)));
        return c_service_send_error(conx_service, b, OFPET_BAD_REQUEST,
                                    OFPBRC_BAD_LEN);
    }


    conx_uflow = ASSIGN_PTR(cofp_aac->data);
    n_dps = ntohll(conx_uflow->n_src);
    if (!n_dps || n_dps >= 1024) return; 

    dp_list_len = sizeof(uint64_t)*n_dps;
    conx_flags = ntohl(conx_uflow->conx_flags);

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd) +
        sizeof(struct c_conx_user_flow) + dp_list_len) {
        app_rlog_err("%s: Size err 1 (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(cofp_aac->header.length),
                  (unsigned long)(sizeof(struct c_ofp_auxapp_cmd) +
                                  sizeof(struct c_conx_user_flow)) +
                                  dp_list_len);
        return c_service_send_error(conx_service, b, OFPET_BAD_REQUEST,
                                    OFPBRC_BAD_LEN);
    }

    action_len = ntohs(cofp_aac->header.length) - 
                    (sizeof(struct c_ofp_auxapp_cmd) +
                     sizeof(struct c_conx_user_flow) +
                     dp_list_len);

    if (of_check_flow_wildcard_generic(&conx_uflow->flow,
                                       &conx_uflow->mask)) {
        return c_service_send_error(conx_service, b, OFPET_BAD_REQUEST,
                                    OFPBRC_BAD_LEN);
    }

    psrc_dpid = ASSIGN_PTR(&conx_uflow->src_dpid_list);
    actions = INC_PTR8(conx_uflow->src_dpid_list, dp_list_len);

    if (conx_flags & CONX_UFLOW_DFL)
        prio = CONX_UFLOW_PRIO_LO;

    srcs = conx_mk_valid_dpid_list(psrc_dpid, &n_dps);
    if (!srcs) {
        return c_service_send_error(conx_service, b, OFPET_BAD_REQUEST,
                                    OFPBRC_BUFFER_EMPTY);
    }

    for (i = 0; i < n_dps; i++) {
        if (add) {
            ret = conx_uflow_add(ntohll(srcs[i]),
                             ntohll(conx_uflow->dst_dpid),
                             &conx_uflow->flow,
                             &conx_uflow->mask,
                             ntohl(conx_uflow->tunnel_key),
                             ntohl(conx_uflow->tunnel_type),
                             ntohl(conx_uflow->app_cookie),
                             actions,
                             action_len,
                             ntohll(conx_uflow->fl_flags),
                             i != (n_dps - 1), prio);
            if (ret && 
                !(conx_flags & CONX_UFLOW_FORCE))
                goto err;
        } else {
            ret = conx_uflow_del(ntohll(srcs[i]),
                             ntohll(conx_uflow->dst_dpid),
                             &conx_uflow->flow,
                             &conx_uflow->mask,
                             ntohll(conx_uflow->fl_flags));
        }
    }


out:
    if (srcs) free(srcs);
    /* Check if client needs ACK for service taken or not */
    if(!(ntohll(conx_uflow->fl_flags) & C_FL_NO_ACK)) { 
        if (!ret)
            c_service_send_success(conx_service);
        else
            c_service_send_error(conx_service, b, OFPET_FLOW_MOD_FAILED,
                             OFPFMFC_BAD_COMMAND);
    }
    return;
err:
    for (i = 0; i < n_dps; i++) {
        conx_uflow_del(ntohll(srcs[i]),
                       ntohll(conx_uflow->dst_dpid),
                       &conx_uflow->flow,
                       &conx_uflow->mask,
                       0);
    }
    goto out;
}

static void 
conx_service_stale_req(void *conx_service, struct cbuf *b, 
                       struct c_ofp_auxapp_cmd *cofp_aac)
{
    struct c_conx_user_flow *conx_uflow;

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd) +
        sizeof(struct c_conx_user_flow)) {
        app_rlog_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(cofp_aac->header.length),
                  (unsigned long)(sizeof(struct c_ofp_auxapp_cmd) +
                                  sizeof(struct c_conx_user_flow)));
        c_service_send_error(conx_service, b, OFPET_BAD_REQUEST,
                             OFPBRC_BAD_LEN);
        return;
    }

    conx_uflow = ASSIGN_PTR(cofp_aac->data);
    conx_uflow_stale_begin(ntohl(conx_uflow->app_cookie));
    c_service_send_success(conx_service);
    return;
}

/**
 * conx_service_handler -
 * @conx_service : service metadata
 * @b : cbuf pointer
 * @return : void
 *
 * Conx Handler service requests
 */
static void
conx_service_handler(void *conx_service, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        app_rlog_err("%s: Size err (%lu) of (%lu)", FN,
                  (unsigned long)ntohs(cofp_aac->header.length),
                  (unsigned long)(sizeof(struct c_ofp_auxapp_cmd)));
        return c_service_send_error(conx_service, b, OFPET_BAD_REQUEST,
                                    OFPBRC_BAD_LEN);
    }

    switch(ntohl(cofp_aac->cmd_code)) {
    case C_AUX_CMD_CONX_ADD_UFLOW:
        return conx_service_mod_uflow(conx_service, b, cofp_aac,
                                      true);
    case C_AUX_CMD_CONX_DEL_UFLOW:
        return conx_service_mod_uflow(conx_service, b, cofp_aac,
                                      false);
    case C_AUX_CMD_CONX_STALE:
        return conx_service_stale_req(conx_service, b, cofp_aac);
    default:
        return c_service_send_error(conx_service, b, OFPET_BAD_REQUEST,
                             OFPBRC_BAD_GENERIC);
    }
}

static void
conx_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval tv = CONX_5SEC_TV;

    c_log_info("C O N X  -- I N I T");

    conx = conx_calloc(sizeof(struct conx_struct));

    c_rw_lock_init(&conx->lock);
    conx->base = base;
    conx->g_ipool = ipool_create(CONX_MAX_GROUPS, 1);
    assert(conx->g_ipool);

    conx->use_groups = 1;
    conx->uflow_htbl = g_hash_table_new_full(conx_ent_key_calc,
                                             conx_ent_key_eq,
                                             NULL,
                                             conx_ufl_hent_destroy);
    assert(conx->uflow_htbl);
    conx->ucookie_htbl = g_hash_table_new_full(g_int_hash,
                                             g_int_equal,
                                             NULL,
                                             conx_ucookie_hent_destroy);
    assert(conx->ucookie_htbl);

    conx->per_sec_tim_event  = evtimer_new(base, conx_per_5sec_timer, NULL);
    evtimer_add(conx->per_sec_tim_event, &tv);

    conx->config_service = mul_app_create_service(MUL_CONX_CONF_SERVICE_NAME,
                                                  conx_service_handler);
    assert(conx->config_service);

    conx->route_service = mul_app_get_service_notify(MUL_ROUTE_SERVICE_NAME,
                                   conx_route_service_conn_event,
                                   true, NULL);
    assert(conx->route_service);

    conx->mul_service =
            mul_app_get_service_notify(MUL_CORE_SERVICE_NAME,
                                       conx_mul_service_conn_event,
                                       true, NULL);
    assert(conx->mul_service);

    mul_register_app_cb(NULL, CONX_APP_NAME,
                        C_APP_ALL_SW, 
                        C_APP_ALL_EVENTS,
                        0, NULL, &conx_app_cbs);
    return;
}

#ifdef MUL_APP_VTY

static void
ufl_hent_list_dump(void *e_arg, void *arg)
{
    user_fl_ent_t *u_flow = e_arg;
    struct vty *vty = arg;
    char *str;

    str = of_dump_flow_generic(&u_flow->flow, &u_flow->mask); 
    vty_out(vty, "[%s] %s %s C%lu %s", u_flow->valid ? "Valid": "Invalid",
            u_flow->flags & CONX_ENT_LOOPBACK ? "LB":"",
            u_flow->flags & CONX_UENT_STALE ? "Stale":"",
            U322UL(u_flow->app_cookie), str);
  
    if (str) free(str);
}

static void
conx_hent_dump(void *key UNUSED,
               void *value,
               void *arg)
{
    conx_ufl_hent_t *hent = value;
    struct vty *vty = arg;

    vty_out(vty, "-----------------------------------------"
            "----------------------------------------------\r\n");
    vty_out(vty, " SRC 0x%llx --> DST 0x%llx\r\n",
            U642ULL(hent->key.src_dpid),
            U642ULL(hent->key.dst_dpid));
    if (hent->user_fl_list)
        g_slist_foreach(hent->user_fl_list, ufl_hent_list_dump,
                        vty);
    vty_out(vty, "-----------------------------------------"
            "----------------------------------------------\r\n");
}

DEFUN (show_uflow_all,
       show_uflow_all_cmd,
        "show conx uflow-all",
        SHOW_STR
        "Conx\n"
        "User app flows\n"
        "Summary information for all switches\n"
)
{
    g_hash_table_foreach(conx->uflow_htbl, conx_hent_dump, vty);
    return 0;
}

static void
conx_vty_init(void *arg UNUSED)
{
    install_element(ENABLE_NODE, &show_uflow_all_cmd);    
}

#else

static void
conx_vty_init(void *arg UNUSED)
{
    
}

#endif

module_init(conx_init);
module_vty_init(conx_vty_init);
