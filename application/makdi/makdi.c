/*
 *  makdi.c: makdi application for MUL Controller 
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>,
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
#include "makdi_common.h"

C_RL_DEFINE(crl, 1000, 100);

makdi_hdl_t *makdi_hdl;
uint64_t ingress_dpid;
uint64_t current_count = 0;

extern struct mul_app_client_cb makdi_app_cbs;

static void makdi_reg_arp(s_fdb_ent_t *fdb, uint32_t in_port);

static void show_dp_nh_info(void *key UNUSED, void *nh, void *uarg UNUSED);

/* Callback functions */
static void makdi_switch_add_cb(mul_switch_t *sw);
static void makdi_switch_del_cb(mul_switch_t *sw);
static void makdi_core_closed_cb(void);
static void makdi_port_add_cb(mul_switch_t *sw,  mul_port_t *port);
static void makdi_port_del_cb(mul_switch_t *sw,  mul_port_t *port);
static void makdi_core_reconn_cb(void);
static void makdi_learn_serv_flow_cb(mul_switch_t *sw, struct flow *fl, uint32_t in_port,
                   uint32_t buffer_id, uint8_t *raw, size_t pkt_len);
static void makdi_user_stats_cb(void *arg, void *pbuf);
static void makdi_service_stats_cb(void *arg, void *pbuf);

/* Traverse functions */
static void s_dp_reg_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg);
static void dp_nh_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg); 

static void __makdi_app_per_user_chain(void *k, void *user, void *arg);

/* Entry initialization functions */
static void dp_nh_key_init(dp_nh_ent_t *dp_nh_ent, uint64_t dst_dpid,
                           uint64_t src_dpid);
static dp_nh_ent_t *dp_nh_ent_alloc(uint64_t dst_dpid, uint64_t src_dpid, 
                                    uint64_t nh_dpid, uint64_t nh_port,
                                    uint16_t nh_nport);

/* Entry reg/unreg functions */
static int dp_nh_add(makdi_hdl_t *hdl, uint64_t src_dpid, uint64_t dst_dpid,
                     uint64_t nh_dpid, uint16_t nh_port, uint16_t nh_nport);

/* OF 1.3 functions */
struct of_meter_band_elem *makdi_meter_default(void);
struct mul_act_mdata *makdi_make_service_mdata(service_ent_t *service);

/* Entry memory mgmt functions */
static void dp_fdb_ent_free(void *arg);
static void dp_reg_ent_free(void *arg);
static void dp_nh_ent_free(void *ent);

/* Utility functions */
void makdi_db_sync(void);
static void __s_dp_reg_per_port(void *key UNUSED, void *dp, void *uarg);

/* HASH Table functions */
static unsigned int dp_nh_hash(const void *p);
static int dp_nh_equal(const void *p1, const void *p2);

/* Init functions */
static void makdi_static_init(makdi_hdl_t *hdl);

bool 
run_makdi_on_dpid(uint64_t dpid, uint16_t port)
{
    dp_reg_ent_t l_ent;
    dp_reg_ent_t *ent = NULL;

    memset(&l_ent, 0, sizeof(l_ent));
    l_ent.dpid = dpid;
    l_ent.port = port;
    
    c_rd_lock(&makdi_hdl->lock);
    
    ent = (dp_reg_ent_t *)g_hash_table_lookup(makdi_hdl->dp_rhtbl, &l_ent);
    
    if (ent && ent->type == 0) {
        c_rd_unlock(&makdi_hdl->lock);
        return true;
    }
    c_rd_unlock(&makdi_hdl->lock);
    
    return false;
}

static void
makdi_install_dfl_flows(uint64_t dpid)
{
    struct flow  fl;
    struct flow                 mask;

    memset(&fl, 0, sizeof(fl));

    of_mask_set_dc_all(&mask);

    mul_app_send_flow_add(MAKDI_APP_NAME, NULL, dpid, &fl, &mask, MAKDI_UNK_BUFFER_ID,
                          NULL, 0, 0, 0, C_FL_PRIO_DFL, 
                          C_FL_ENT_LOCAL);
}

static void
makdi_switch_add_cb(mul_switch_t *sw)
{
    if (!sw) {
        c_log_debug("Switch is not valid");
        return;
    }
    makdi_install_dfl_flows(sw->dpid);

    /* set route convergence flag to waiting state*/
    makdi_hdl->rt_conv_state = RT_STATE_WAIT_FOR_CONVERGENCE;
}

static void
makdi_switch_del_cb(mul_switch_t *sw UNUSED)
{

    sc_modify_on_dp_down(sw->dpid);

    /* set route convergence flag to waiting state*/
    makdi_hdl->rt_conv_state = RT_STATE_WAIT_FOR_CONVERGENCE;
}

static void
makdi_core_closed_cb(void)
{
    c_log_info("[core-conn] ||closed||");
}

static void
makdi_port_add_cb(mul_switch_t *sw,  mul_port_t *port)
{
    /* c_log_debug("[switch-port] add: 0x%llx port 0x%hu",
                U642ULL(sw->dpid), port->port_no); */

    sc_modify_on_port_up(sw->dpid, port->port_no);

    /* set route convergence flag to waiting state*/
    makdi_hdl->rt_conv_state = RT_STATE_WAIT_FOR_CONVERGENCE;
}

static void 
s_dp_reg_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg) 
{
    c_rd_lock(&hdl->lock);
    if (hdl->dp_rhtbl) {
        g_hash_table_foreach(hdl->dp_rhtbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&hdl->lock);

    return;
}

static void
makdi_port_chg_cb(mul_switch_t *sw,  mul_port_t *port, bool adm, bool link)
{
    /* Port is administratively down*/
    if(!adm || !link) {
        sc_modify_on_port_down(sw->dpid, port->port_no);
        /* set route convergence flag to waiting state*/
        makdi_hdl->rt_conv_state = RT_STATE_WAIT_FOR_CONVERGENCE;
    }
}

static void
makdi_port_del_cb(mul_switch_t *sw,  mul_port_t *port)
{
    /* c_log_debug("[switch-port] del: 0x%llx port 0x%hu",
                U642ULL(sw->dpid), port->port_no); */

    sc_modify_on_port_down(sw->dpid, port->port_no);
    /* set route convergence flag to waiting state*/
    makdi_hdl->rt_conv_state = RT_STATE_WAIT_FOR_CONVERGENCE;
}

static void
makdi_core_reconn_cb(void)
{
    c_log_info("[core-conn] ||reconnected||");

    makdi_db_sync();

    mul_register_app_cb(NULL, MAKDI_APP_NAME, 
                        C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &makdi_app_cbs);
    /* set route convergence flag to waiting state*/
    makdi_hdl->rt_conv_state = RT_STATE_WAIT_FOR_CONVERGENCE;
}

static void
makdi_get_tr_status(uint64_t status)
{
    c_log_info("[tr-status] [%llu]", U642ULL(status));

    if(status == C_RT_APSP_CONVERGED) {
        /* Update the next hop table*/
        dp_nh_tbl_init(makdi_hdl);
        makdi_hdl->rt_conv_state = RT_STATE_CONVERGED;
    }
}

struct mul_app_client_cb makdi_app_cbs = {
    .switch_priv_alloc = NULL,
    .switch_priv_free = NULL,
    .switch_add_cb =  makdi_switch_add_cb,
    .switch_del_cb = makdi_switch_del_cb,
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = makdi_port_add_cb,
    .switch_port_del_cb = makdi_port_del_cb,
    .switch_port_chg = makdi_port_chg_cb,
    .switch_port_link_chg = NULL,
    .switch_port_adm_chg = NULL,
    .switch_packet_in = makdi_learn_serv_flow_cb,
    .switch_error = NULL,
    .core_conn_closed = makdi_core_closed_cb,
    .core_conn_reconn = makdi_core_reconn_cb,
    .topo_route_status_cb = makdi_get_tr_status
};

static unsigned int 
dp_reg_hash(const void *p)
{   
    const uint8_t *key = p;
    return hash_bytes(key, sizeof(dp_reg_ent_t), 1);
}

static int
dp_reg_equal(const void *p1, const void *p2)
{
    const dp_reg_ent_t *arg_1 = p1;
    const dp_reg_ent_t *arg_2 = p2;
    int result;

    if ((arg_1->dpid == arg_2->dpid) &&
        (arg_1->port == arg_2->port))
        result = 1;
    else
        result = 0;
    
    return result; 
}

static void
dp_fdb_ent_free(void *arg)
{
    dp_fl_ent_t *ent = arg;
    /* TODO : Remove each flow entry */

    if (!c_rlim(&crl))
        c_log_debug("[dp-fdb] Flow delete");

    mul_app_send_flow_del(MAKDI_APP_NAME, NULL,
                          ent->dpid,
                          &ent->fl, &ent->mask, 
                          OFPP_NONE, C_FL_PRIO_DFL, C_FL_ENT_LOCAL, OFPG_ANY);
    free(ent);
}

static void
dp_reg_ent_free(void *arg)
{
    dp_reg_ent_t *dp_ent = arg;
    
    if (dp_ent->s_fdb_list)
        g_slist_free_full(dp_ent->s_fdb_list, dp_fdb_ent_free);

    free(dp_ent);
}

static void
makdi_bcast_arp(mul_switch_t *sw, struct flow *fl UNUSED,
                uint32_t in_port, uint32_t buffer_id,
                uint8_t *raw, size_t pkt_len)
{
    uint32_t oport = OF_ALL_PORTS;
    struct of_pkt_out_params parms;
    struct mul_act_mdata mdata;

    memset(&parms, 0, sizeof(parms));

    if (buffer_id != (uint32_t)(-1)) {
        pkt_len = 0;
    }

    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    if (mul_app_act_set_ctors(&mdata, sw->dpid))
        goto free_out;
    mul_app_action_output(&mdata, oport);
    parms.buffer_id = buffer_id;
    parms.in_port = in_port;
    parms.action_list = mdata.act_base;
    parms.action_len = mul_app_act_len(&mdata);
    parms.data_len = pkt_len;
    parms.data = raw;
    mul_app_send_pkt_out(NULL, sw->dpid, &parms);
free_out:
    mul_app_act_free(&mdata);
}

static void
makdi_learn_serv_flow_cb(mul_switch_t *sw, struct flow *fl, uint32_t in_port,
                   uint32_t buffer_id, uint8_t *raw, size_t pkt_len)
{
    s_fdb_ent_t  *fdb;
    char *str = NULL;

    if (fl->dl_type != htons(ETH_TYPE_IP) &&
        fl->dl_type != htons(ETH_TYPE_ARP)) {
        return;
    }

    /* Check validity of core service */
    if (!mul_service_available(makdi_hdl->mul_service))
        return;

    str = of_dump_flow(fl, 0);
    if (!c_rlim(&crl))
        c_log_err("[sc-fl-learn] Flow %s", str);
    free(str);

    fdb = calloc(1, sizeof(*fdb));
    if (!fdb) return;

    s_fdb_ent_init(fdb, fl, sw->dpid);

    if (fl->dl_type == htons(ETH_TYPE_ARP)) {
        if (!c_rlim(&crl))
            c_log_debug("[sc-fl-learn] ARP Learning ");  
#ifdef MAKDI_ARP_LEARNING
        makdi_reg_arp(fdb, in_port);
#else
        makdi_bcast_arp(sw, fl, in_port, buffer_id, raw, pkt_len);                
#endif
        free(fdb);
        return;
    } else {
#ifdef MAKDI_NEED_DPID_REG
        if (!run_makdi_on_dpid(sw->dpid, ntohl(fl->in_port))) {
            if (!c_rlim(&crl))
                c_log_err("[sc-fl-learn] Blocked");
            free(fdb);
            return;
        }
#endif
    }

    if (s_fdb_lrn(makdi_hdl, fdb, in_port, buffer_id, raw, pkt_len)) {
        free(fdb);
    }

    return;
}

static void  UNUSED
makdi_reg_arp(s_fdb_ent_t *fdb, uint32_t in_port UNUSED)
{
    s_dp_reg_traverse_all(makdi_hdl, __s_dp_reg_per_port, fdb);
}

static void
__s_dp_reg_per_port(void *key UNUSED, void *dp, void *uarg)
{
    struct flow mask;
    struct flow fl;
    uint64_t dpid;
    struct mul_act_mdata        mdata;
    dp_reg_ent_t *dp_reg;
    s_fdb_ent_t *fdb;
    uint8_t *actions;
    size_t act_len; 
    char *flow_str;
    dp_fl_ent_t *fl_ent;
     
    dp_reg = dp;
    fdb = uarg; 
    dpid = fdb->dpid;
    fl = fdb->key.fdb_fl;

    flow_str = of_dump_flow(&fdb->key.fdb_fl, 0);

    if (!c_rlim(&crl))
        c_log_debug("%s : fdb dpid %llx, port %lx, dp_reg dpid %llx, port %lx",
                FN, U642ULL(fdb->dpid), U322UL(fl.in_port), 
                U642ULL(dp_reg->dpid), U322UL(dp_reg->port));   
 
    if((fdb->dpid == dp_reg->dpid) && (ntohl(fl.in_port) == dp_reg->port))
        return;
    
    of_mask_set_dc_all(&mask);    
    of_mask_set_dl_type(&mask);
    of_mask_set_in_port(&mask);
            
    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, dpid);
    mul_app_action_output(&mdata, dp_reg->port);

    actions = mdata.act_base;
    act_len = of_mact_len(&mdata);    
    
    if (!c_rlim(&crl))
        c_log_debug("%s : Flow info(%s) out_port %lx", FN, flow_str, 
                U322UL(dp_reg->port));

    mul_service_send_flow_add(makdi_hdl->mul_service, 
                          (uint64_t)dpid,
                          &fl, &mask, MAKDI_UNK_BUFFER_ID,
                          actions, act_len,
                          0, 0,
                          C_FL_PRIO_DFL, 
                          C_FL_ENT_STATIC|C_FL_ENT_GSTATS);

    fl_ent = calloc(1, sizeof(*fl_ent));
    fl_ent->dpid = fdb->dpid;
    fl_ent->fl = fdb->key.fdb_fl;
    fl_ent->mask = mask;
    fl_ent->actions = actions;
    fl_ent->act_len = act_len;
    fl_ent->oport = dp_reg->port;

    //c_wr_lock(&makdi_hdl->lock);
    dp_reg->s_fdb_list = g_slist_append(dp_reg->s_fdb_list, fl_ent);
    //c_wr_unlock(&makdi_hdl->lock);
}

static unsigned int 
dp_nh_hash(const void *p)
{   
    const uint8_t *key = p;
    return hash_bytes(key, sizeof(dp_nh_key_t), 1);
}

static int
dp_nh_equal(const void *p1, const void *p2)
{
    return !memcmp(p1, p2, sizeof(dp_nh_key_t));
}

static void
dp_nh_key_init(dp_nh_ent_t *dp_nh_ent, uint64_t dst_dpid,
               uint64_t src_dpid)
{
    dp_nh_ent->key.src_dpid = src_dpid;
    dp_nh_ent->key.dst_dpid = dst_dpid;
}

static dp_nh_ent_t *
dp_nh_ent_alloc(uint64_t dst_dpid, uint64_t src_dpid, 
                uint64_t nh_dpid, uint64_t nh_port,
                uint16_t nh_nport)
{
    dp_nh_ent_t *ent;

    ent = calloc(1, sizeof(*ent));
    assert(ent);

    dp_nh_key_init(ent, dst_dpid, src_dpid);
    ent->nh_dpid = nh_dpid;
    ent->nh_port = nh_port;
    ent->nh_nport = nh_nport;

    return ent;
}

static void
dp_nh_ent_free(void *ent)
{
    free(ent);
}

static int 
dp_nh_add(makdi_hdl_t *hdl, uint64_t src_dpid, uint64_t dst_dpid,
          uint64_t nh_dpid, uint16_t nh_port, uint16_t nh_nport)
{
    dp_nh_ent_t *ent;

    ent = dp_nh_ent_alloc(dst_dpid, src_dpid, nh_dpid, nh_port,
                          nh_nport);
    assert(ent);

    c_wr_lock(&hdl->lock);
    if (g_hash_table_lookup(hdl->dp_nhtbl, &ent->key)) {
        c_wr_unlock(&hdl->lock);
        c_log_err("%s: dp-nh 0x%llx -> 0x%llx exists", FN, 
                  U642ULL(src_dpid), U642ULL(dst_dpid));
        dp_nh_ent_free(ent);
        return -1;
    }

    g_hash_table_insert(hdl->dp_nhtbl, &ent->key, ent);
    c_wr_unlock(&hdl->lock);

    return 0;
}

dp_nh_ent_t *
__dp_nh_find(makdi_hdl_t *hdl, uint64_t src_dpid, uint64_t dst_dpid)
{
    dp_nh_ent_t l_ent, *ent;
    dp_nh_key_init(&l_ent, dst_dpid, src_dpid);

    ent = g_hash_table_lookup(hdl->dp_nhtbl, &l_ent.key);
    return ent;
}

static void 
dp_nh_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg) 
{
    c_rd_lock(&hdl->lock);
    if (hdl->dp_nhtbl) {
        g_hash_table_foreach(hdl->dp_nhtbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&hdl->lock);
    return;
}

static void
show_dp_nh_info(void *key UNUSED, void *nh, void *uarg UNUSED)
{
    dp_nh_ent_t *nh_ent = nh;

    c_log_info("%s: src-dp(0x%llx) --> dst-dp(0x%llx) "
               "nh-dp (0x%llx) nh-port (0x%lu)", FN,
                U642ULL(nh_ent->key.src_dpid), 
                U642ULL(nh_ent->key.dst_dpid),
                U642ULL(nh_ent->nh_dpid), 
                U322UL(nh_ent->nh_port));
}

void
dp_nh_dump_all(makdi_hdl_t *hdl)
{
    dp_nh_traverse_all(hdl, show_dp_nh_info, NULL); 
}

static void UNUSED
makdi_user_stats_cb(void *arg, void *pbuf)
{
    struct makdi_iter_arg *iter_arg = arg;
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc = NULL;
    struct c_ofp_user_stats_show *user_stats_info;
    struct c_ofp_flow_info *cofp_fi = pbuf;
    
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*user_stats_info),
                C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_USER_STATS_ALL);
    user_stats_info = (void *)(cofp_auc->data);

    memcpy(&user_stats_info->stats, cofp_fi, sizeof(*cofp_fi));
    iter_arg->send_cb((iter_arg)->serv, b); 
}

static void UNUSED
makdi_service_stats_cb(void *arg, void *pbuf)
{
    struct makdi_iter_arg *iter_arg = arg;
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc = NULL;
    struct c_ofp_service_stats_show *service_stats_info;

    struct c_ofp_flow_info *cofp_fi = pbuf;
    service_ent_t *service_ent = NULL;
    
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*service_stats_info),
                C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SERVICE_STATS_ALL);
    service_stats_info = (void *)(cofp_auc->data);

    service_ent = __service_ent_get_by_id(makdi_hdl, cofp_fi->flow.dl_vlan);

    memcpy(&service_stats_info->stats, cofp_fi, sizeof(*cofp_fi));
    strcpy(service_stats_info->service_name, service_ent->key.name);
    iter_arg->send_cb((iter_arg)->serv, b); 
}

static void UNUSED
makdi_app_send_user_stats_cb(void *arg, void *pbuf)
{
    struct c_ofp_user_stats_show *cofp_user_stats = NULL;
    struct c_ofp_auxapp_cmd *cofp_aac = NULL;
    struct c_ofp_flow_info *cofp_fi = pbuf;
    struct makdi_iter_arg *iter_arg = arg;
    struct cbuf                 *b;

    b = of_prep_msg(sizeof(*cofp_aac) + sizeof(*cofp_user_stats),
                    C_OFPT_AUX_CMD, 0);
    cofp_aac = (void *) (b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_MAKDI_USER_STATS);
    cofp_user_stats = (void *) (cofp_aac->data);
    cofp_user_stats->stats = *cofp_fi;    
    
    iter_arg->send_cb((iter_arg)->serv, b);
}

static void
__makdi_app_send_user_chain_all(s_user_ent_t *u_ent, void *arg)
{
    struct makdi_iter_arg *iter_arg = arg;
    struct c_ofp_s_chain_show *user_chain_info;
    struct c_ofp_auxapp_cmd *cofp_auc = NULL;
    struct cbuf                 *b;
    struct in_addr addr = { .s_addr = htonl(u_ent->key.src_nw_addr) };
    service_ent_t *s_ent;

    s_ent = __service_ent_get_by_id(makdi_hdl, u_ent->key.SERV_ID);
    if (!s_ent) {
        c_log_err("%s: failed to get service", FN);
        return;
    }
    
	b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*user_chain_info),
				C_OFPT_AUX_CMD, 0);
    
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SHOW_SERVICE_CHAIN_ALL);
    user_chain_info = ASSIGN_PTR(cofp_auc->data);

    user_chain_info->dpid = htonll(u_ent->key.dpid);
    user_chain_info->nw_src = htonl(u_ent->key.src_nw_addr);
    strncpy(user_chain_info->service, s_ent->key.name, MAX_SERVICE_NAME -1);
    user_chain_info->service[MAX_SERVICE_NAME -1] = '\0'; 
    user_chain_info->nfv_list.num_nfvs = 0;

    if (!iter_arg) {
        if (!c_rlim(&crl))
            c_log_info("[USER] %s: DP:0x%llx serv-id %d", inet_ntoa(addr),
                    U642ULL(u_ent->key.dpid), u_ent->key.SERV_ID);
    }

    g_slist_foreach(u_ent->nfv_list,
                    __s_user_nfv_list_traverse_elem,
                    &user_chain_info->nfv_list);

    if (iter_arg)
        iter_arg->send_cb((iter_arg)->serv, b);
    else
        free_cbuf(b);
}

static void
__makdi_app_per_user_chain(void *k UNUSED, void *user, void *arg)
{
    struct makdi_iter_arg *iter_arg = arg;
    s_user_ent_t *u_ent = user;

    __makdi_app_send_user_chain_all(u_ent, iter_arg);
}

int
makdi_reg_allowed_dpid(makdi_hdl_t *hdl, uint64_t dpid,
                       uint16_t port, uint8_t type)
{
    struct dp_reg_ent *ent = NULL;
    
    ent = calloc(1, sizeof(*ent));
    ent->dpid = dpid;
    ent->port = port;
    ent->type = type;

    c_wr_lock(&hdl->lock);
    if (g_hash_table_lookup(hdl->dp_rhtbl, ent)) {
        c_rd_unlock(&hdl->lock);
        free(ent);
        c_log_debug("%s: DPID (0x%llx) port %x already allowed", 
                    FN, U642ULL(dpid), port);
        c_wr_unlock(&hdl->lock);
        return -1;
    }
    ent->s_fdb_list = NULL;
    
    g_hash_table_insert(hdl->dp_rhtbl, ent, ent);
    c_wr_unlock(&hdl->lock);

    return 0;
}

/* Housekeep Timer for app monitoring */
static void
makdi_main_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                void *arg)
{
    makdi_hdl_t     *hdl  = arg;
    struct timeval tv    = { 1 , 0 };

    /* FIXME : Delete */
    /*
    if ( current_count % 5 == 0 )
       sc_modify_on_port_down(0x0000001c732fee20, 0x3);
    if ( current_count % 6 == 0 )
       sc_modify_on_port_up(0x0000001c732fee20, 0x3);
    current_count++;
    */
    /* FIXME : Delete */
    
    s_user_traverse_all_writer(hdl, __s_per_user_timer, NULL);
    evtimer_add(hdl->timer_event, &tv);
}  

/**
 * makdi_service_success -
 *
 * Sends success message to service requester
 */
static void
makdi_service_success(void *m_service)
{
    struct cbuf             *new_b;
    struct c_ofp_auxapp_cmd *cofp_aac;

    new_b = of_prep_msg(sizeof(*cofp_aac), C_OFPT_AUX_CMD, 0);

    cofp_aac = (void *)(new_b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_SUCCESS);

    c_service_send(m_service, new_b);
}


/**
 * makdi_service_error -
 *
 * Sends error message to service requester in case of error
 */
static void
makdi_service_error(void *tr_service, struct cbuf *b,
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
 * makdi_service_handler -
 *
 * Handler service requests
 */
static void makdi_service_handler(void *m_serv, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *) (b->data);
    int i = 0, ret = -1;

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        c_log_err("%s: Size err (%lu) of (%lu)", FN,
                (unsigned long) ntohs(cofp_aac->header.length),
                (unsigned long) (sizeof(struct c_ofp_auxapp_cmd)));
        return makdi_service_error(m_serv, b, OFPET_BAD_REQUEST,
                                   OFPBRC_BAD_LEN);
    }

    switch (ntohl(cofp_aac->cmd_code)) {
    case C_AUX_CMD_MAKDI_SHOW_USER: {
        struct makdi_iter_arg iter_arg = { m_serv, c_service_send, NULL };
        struct s_fdb_iter_arg arg = { send_s_fdb_info, &iter_arg };

        /*Traversing all the user flows*/
        s_user_traverse_all(makdi_hdl, __s_fdb_traverse_per_user, &arg);
        break;
    }

    case C_AUX_CMD_MAKDI_SERVICE_ADD: {
        struct c_ofp_service_info *cofp_seri;

        if (ntohs(cofp_aac->header.length)
                < sizeof(*cofp_aac) + sizeof(*cofp_seri)) {
            c_log_err("%s: Size err (%lu) of (%lu)", FN,
                    (unsigned long) ntohs(cofp_aac->header.length),
                    (unsigned long) (sizeof(*cofp_aac) + sizeof(*cofp_seri)));
            goto err;
        }

        cofp_seri = (void *) (cofp_aac->data);

        ret = service_add(makdi_hdl, cofp_seri->service, ntohs(cofp_seri->vlan));
        if (ret) goto err; 
        break;
    }
    case C_AUX_CMD_MAKDI_SERVICE_DEL: {
        struct c_ofp_service_info *cofp_seri;

        if (ntohs(cofp_aac->header.length)
                < sizeof(*cofp_aac) + sizeof(*cofp_seri)) {
            c_log_err("%s: Size err (%lu) of (%lu)", FN,
                    (unsigned long) ntohs(cofp_aac->header.length),
                    (unsigned long) (sizeof(*cofp_aac) + sizeof(*cofp_seri)));
            goto err;
        }

        cofp_seri = (void *) (cofp_aac->data);

        ret = service_del(makdi_hdl, cofp_seri->service);
        if (ret) goto err;
        break;
    }
    case C_AUX_CMD_MAKDI_SHOW_SERVICE: {
        struct makdi_iter_arg iter_arg = { m_serv, c_service_send, NULL };
        service_traverse_all(makdi_hdl, __makdi_app_per_service_info, &iter_arg);
        break;
    }
    case C_AUX_CMD_MAKDI_NFV_GROUP_ADD: {
        struct c_ofp_s_chain_nfv_group_info *cofp_nfv_group_info;
        if (ntohs(cofp_aac->header.length)
                < sizeof(*cofp_aac) + sizeof(*cofp_nfv_group_info)) {
            c_log_err("%s: Size err (%lu) of (%lu)", FN,
                    (unsigned long) ntohs(cofp_aac->header.length),
                    (unsigned long) (sizeof(*cofp_aac)
                            + sizeof(*cofp_nfv_group_info)));
            goto err;
        }

        cofp_nfv_group_info = (void *) (cofp_aac->data);
        ret = nfv_group_add(makdi_hdl, cofp_nfv_group_info->nfv_group);
        if (ret) goto err;
        break;
    }
    case C_AUX_CMD_MAKDI_NFV_GROUP_DEL: {
        struct c_ofp_s_chain_nfv_group_info *cofp_nfv_group_info;
        if (ntohs(cofp_aac->header.length)
                < sizeof(*cofp_aac) + sizeof(*cofp_nfv_group_info)) {
            c_log_err("%s: Size err (%lu) of (%lu)", FN,
                    (unsigned long) ntohs(cofp_aac->header.length),
                    (unsigned long) (sizeof(*cofp_aac)
                            + sizeof(*cofp_nfv_group_info)));
            goto err;
        }

        cofp_nfv_group_info = (void *)(cofp_aac->data);
        ret = nfv_group_del(makdi_hdl, cofp_nfv_group_info->nfv_group);
        if (ret) goto err;
        break;
    }
    case C_AUX_CMD_MAKDI_SHOW_NFV:
    case C_AUX_CMD_MAKDI_SHOW_NFV_GROUP: {
        struct makdi_iter_arg iter_arg = { m_serv, c_service_send, NULL };
        nfv_group_traverse_all(makdi_hdl,
                               __makdi_app_per_group_info,
                               &iter_arg);
        break;
    }
    case C_AUX_CMD_MAKDI_NFV_ADD: {
        struct c_ofp_s_chain_nfv_info *cofp_nfv_info;
        if (ntohs(cofp_aac->header.length) <
                sizeof(*cofp_aac) + sizeof(*cofp_nfv_info)) {
            c_log_err("%s: Size err (%lu) of (%lu)", FN,
                    (unsigned long) ntohs(cofp_aac->header.length),
                    (unsigned long) (sizeof(*cofp_aac) + sizeof(*cofp_nfv_info)));
            goto err;
        }

        cofp_nfv_info = (void *) (cofp_aac->data);
        ret = nfv_add(makdi_hdl, cofp_nfv_info->nfv_group, cofp_nfv_info->nfv,
                ntohll(cofp_nfv_info->dpid), ntohs(cofp_nfv_info->iif),
                ntohs(cofp_nfv_info->oif));

        if (ret) goto err;
        break;
    }
    case C_AUX_CMD_MAKDI_NFV_DEL: {
        struct c_ofp_s_chain_nfv_info *cofp_nfv_info;

        if (ntohs(cofp_aac->header.length) <
            sizeof(*cofp_aac) + sizeof(*cofp_nfv_info)) {
            c_log_err("%s: Size err (%lu) of (%lu)", FN,
                    (unsigned long) ntohs(cofp_aac->header.length),
                    (unsigned long) (sizeof(*cofp_aac) + sizeof(*cofp_nfv_info)));
            goto err;
        }

        cofp_nfv_info = (void *) (cofp_aac->data);
        ret = nfv_del(makdi_hdl, cofp_nfv_info->nfv_group, cofp_nfv_info->nfv,
                      ntohll(cofp_nfv_info->dpid), ntohs(cofp_nfv_info->oif),
                      ntohs(cofp_nfv_info->iif));
        if (ret) goto err;
        break;
    }
    case C_AUX_CMD_MAKDI_SERVICE_CHAIN_ADD: {
        struct c_ofp_s_chain_mod *cofp_scm;
        int num_nfv;
        char **nfv_list;

        if (ntohs(cofp_aac->header.length) <
            sizeof(*cofp_aac) + sizeof(*cofp_scm)) {
            c_log_err("%s: Size err (%lu) of (%lu)", FN,
                    (unsigned long) ntohs(cofp_aac->header.length),
                    (unsigned long)(sizeof(*cofp_aac) + sizeof(*cofp_scm)));
            goto err;
        }

        cofp_scm = (void *) (cofp_aac->data);
        num_nfv = (int) ntohll(cofp_scm->num_nfvs);

        if (num_nfv > MAX_NFV && num_nfv < MAKDI_MIN_NFVS_IN_SC) {
            goto err;
        }

        nfv_list = (char **) calloc(ntohll(cofp_scm->num_nfvs), sizeof(char *));
        if (!nfv_list) goto err;

        for (i = 0; i < num_nfv; i++) {
            nfv_list[i] = cofp_scm->nfv_list[i];
        }

        ret = sc_insert(makdi_hdl, cofp_scm->service,
                ntohl(cofp_scm->user_info.host_flow.ip.nw_src),
                ntohll(cofp_scm->user_info.switch_id.datapath_id), 
                num_nfv,
                nfv_list, false);

        free(nfv_list);
        if (ret) goto err;
        break;
    }
    case C_AUX_CMD_MAKDI_SERVICE_CHAIN_DEL: {
        struct c_ofp_s_chain_mod *cofp_scm;

        if (ntohs(cofp_aac->header.length) <
            sizeof(*cofp_aac) + sizeof(*cofp_scm)) {
            c_log_err("%s: Size err (%lu) of (%lu)", FN,
                    (unsigned long) ntohs(cofp_aac->header.length),
                    (unsigned long) (sizeof(*cofp_aac) + sizeof(*cofp_scm)));
            goto err;
        }

        cofp_scm = ASSIGN_PTR(cofp_aac->data);
        ret = sc_remove(makdi_hdl, cofp_scm->service,
                        ntohl(cofp_scm->user_info.host_flow.ip.nw_src),
                        ntohll(cofp_scm->user_info.switch_id.datapath_id));
        if (ret) goto err; 
        break;
    }
    case C_AUX_CMD_MAKDI_SHOW_SERVICE_CHAIN: 
	case C_AUX_CMD_MAKDI_SHOW_SERVICE_CHAIN_ALL: {
        struct makdi_iter_arg iter_arg = { m_serv, c_service_send, NULL };
        s_user_traverse_all(makdi_hdl, __makdi_app_per_user_chain, &iter_arg);
        break;
    }
    case C_AUX_CMD_MAKDI_NFV_STATS_ALL:
    case C_AUX_CMD_MAKDI_NFV_STATS: {
        struct makdi_iter_arg iter_arg = { m_serv, c_service_send, NULL };
        nfv_group_traverse_all(makdi_hdl, __makdi_app_per_group_stats_info,
                               &iter_arg);
        break;
    }
    default:
        break;
    }

    return makdi_service_success(m_serv);

err:
    return makdi_service_error(m_serv, b, OFPET_BAD_REQUEST,
                               OFPBRC_BAD_GENERIC);
}

void
makdi_db_sync(void)
{
}

static void
print_dp_nh_tbl(void *k UNUSED, void *ent, void *arg UNUSED)
{
    dp_nh_ent_t *nh_ent = ent;
    c_log_debug("%s : src_dpid(0x%llx) dst_dpid(0x%llx) next dpid(0x%llx) "
                "oif(%lu) iif(%lu)", FN, U642ULL(nh_ent->key.src_dpid),
                U642ULL(nh_ent->key.dst_dpid), U642ULL(nh_ent->nh_dpid),
                U322UL(nh_ent->nh_port), U322UL(nh_ent->nh_nport));
}

static void UNUSED
dp_nh_dump(makdi_hdl_t *hdl)
{
    c_rd_lock(&hdl->lock);        
    if (hdl->dp_nhtbl) {
        g_hash_table_foreach(hdl->dp_nhtbl, (GHFunc)print_dp_nh_tbl, NULL);
    }
    c_rd_unlock(&hdl->lock);
}

struct switch_attr
{
    uint64_t dpid;
    int alias_id;
};

static void
swid_elem_free(void *elem)
{
    free(elem);
}

static void
c_app_per_switch_dpid_fetch(void *key UNUSED, void *sw_arg, void *uarg)
{
    GSList **list = uarg;
    mul_switch_t *sw = sw_arg;
    struct switch_attr *swid;

    swid = calloc(1, sizeof(*swid));
    if (!swid) return;

    swid->dpid = sw->dpid;
    swid->alias_id = sw->alias_id;

    *list = g_slist_append(*list, swid);
}

static int 
c_fetch_dpid_from_alias_id(void *swid_arg, void *swid_m_arg)
{
    struct switch_attr *swid = swid_arg;
    struct switch_attr *swid_m = swid_m_arg;

    if (swid->alias_id == swid_m->alias_id) {
        swid_m->dpid = swid->dpid;
        return 0;
    }
    return -1;
}

void
dp_nh_tbl_init(makdi_hdl_t *hdl)
{
    GSList *route = NULL;
    GSList *list = NULL;
    GSList *iterator = NULL;
    GSList *iterator1 = NULL;
    struct switch_attr *swid = NULL;
    struct switch_attr *dest_swid = NULL;
    int alias_src = -1;
    int alias_dst = -1; 
    struct switch_attr next_swid;
    rt_path_elem_t *route_entry_dst;

    if (!makdi_hdl->route_service)
        return; 

    c_wr_lock(&hdl->lock);
    g_hash_table_remove_all(hdl->dp_nhtbl);
    c_wr_unlock(&hdl->lock);

    c_app_traverse_all_switches(c_app_per_switch_dpid_fetch, &list);
    if (!list) {
        c_log_debug("%s: No switches", FN);
        return;
    }

    for (iterator = list; iterator; iterator = iterator->next) {
        swid = iterator->data;
        alias_src = swid->alias_id;

        for (iterator1 = list; iterator1; iterator1 = iterator1->next) {
            dest_swid = iterator1->data;
            if (dest_swid == swid) continue;

            alias_dst = dest_swid->alias_id;
            if(alias_src < 0 || alias_dst < 0) {
                break;
            }

            route = mul_route_get(makdi_hdl->route_service,
                                  alias_src,
                                  alias_dst);
            if (route) {
                GSList *index = route;
                rt_path_elem_t *route_entry_src = index->data;
                int egress_port = route_entry_src->link.la;
                int ingress_port = route_entry_src->link.lb;

                index = index->next;
                if (!index) continue;

                route_entry_dst = index->data;
                next_swid.alias_id = route_entry_dst->sw_alias;

                if (!g_slist_find_custom(list, &next_swid, 
                    (GCompareFunc)c_fetch_dpid_from_alias_id))
                    continue;

                /* Modify sw_key_t to compare dpid or alias_id */
                c_log_debug("%s: src_sw : %d dst_sw : %d next switch(0x%llx):%d egress "
                            "%lu ingress %lu", FN, alias_src, alias_dst,
                            U642ULL(next_swid.dpid), next_swid.alias_id, U322UL(egress_port),
                            U322UL(ingress_port));

                /* Add the dp_nh_entr */
                dp_nh_add(makdi_hdl, swid->dpid, dest_swid->dpid,
                          next_swid.dpid, egress_port, ingress_port);
                mul_destroy_route(route);
            } else {
                c_log_debug("There is no route between %s: src_sw(0x%llx):%u "
                            "dst_sw(0x%llx):%u", FN,
                            U642ULL(swid->dpid), alias_src,
                            U642ULL(dest_swid->dpid), dest_swid->alias_id);
            } 
        }
    }

    g_slist_free_full(list, swid_elem_free);
    dp_nh_dump_all(hdl);
}

static void
makdi_static_init(makdi_hdl_t *hdl UNUSED)
{
#if 0
    char **nfv_list;
    char **nfv_list_def;

    nfv_list = (char **)malloc(2 * sizeof(char *));
    nfv_list_def = (char **)malloc(1 * sizeof(char *));
    nfv_list[0] = "USER";
    nfv_list[1] = "EXIT";
    
    nfv_list_def[0] = "E";

    ingress_dpid = 0x4;

    nfv_group_add(hdl, "A");
    nfv_group_add(hdl, "C");
    nfv_group_add(hdl, "D");
    nfv_group_add(hdl, "EXIT");
    nfv_group_add(hdl, "USER");

    service_add(hdl, "NAVER", 0);

    //nfv_add(hdl, "A", "nfv1", 0x4, 0x3, 0x3);
    //nfv_add(hdl, "B", "nfv2", 0x5, 0x2, 0x2);
    //nfv_add(hdl, "C", "hfv3", 0x5, 0x1, 0x1);
    nfv_add(hdl, "EXIT", "internet", 0x1, 0x2, 0x2);
    nfv_add(hdl, "USER", "user", 0x1, 0x1, 0x1);
    nfv_group_all_dump_nfvs(hdl);

    /* UE1 : 192.168.1.15 */
    sc_insert(hdl, "NAVER", 0x0a000001,
              0x1, 0x0, 2, nfv_list, false);

    s_user_traverse_all(makdi_hdl, __makdi_app_per_user_chain, NULL);

    //sc_modify_on_port_down(arista_sw, 0x3);
    /*c_log_err("After insert nfv-groups");
    nfv_group_all_dump_nfvs(hdl); */
    
#if 0
    if (sc_remove(hdl, "NAVER", 0xc0a8010f, arista_sw)) {
        c_log_err("WARNING : Remove failed");
    }

    /* c_log_err("After del nfv-groups");
     nfv_group_all_dump_nfvs(hdl); */

    /* UE1 : 192.168.1.16 */
    sc_insert(hdl, "NAVER", 0xc0a80110,
                    arista_sw, 0x2, 2, nfv_list);
    
    sc_insert(hdl, "NAVER", 0xc0a80104,
                    arista_sw, 0x2, 2, nfv_list);
    
#endif
    /*
    nfv_group_dump_all(hdl);
    service_dump_all(hdl, NULL);
    default_rule_dump_all(hdl);
    nfv_dump_all(hdl);
    */
#endif
}

static void
makdi_route_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_err("[tr-service] %d", conn_event);
}

static void
makdi_mul_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_err("[mul-service] %d", conn_event);
}

void
makdi_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval    tv = { 1, 0 };
    makdi_hdl_t       *hdl = NULL;

    c_log_debug("%s", FN);

    hdl = calloc(1, sizeof(makdi_hdl_t));
    if (!hdl) {
        c_log_err("%s: alloc failed", FN);
        return;
    }

    makdi_hdl = hdl;
    hdl->base = base;
    c_rw_lock_init(&hdl->lock);

    hdl->dp_rhtbl = g_hash_table_new_full(dp_reg_hash,
                                          dp_reg_equal,
                                          NULL, dp_reg_ent_free);

    hdl->dp_nhtbl = g_hash_table_new_full(dp_nh_hash,
                                          dp_nh_equal,
                                          NULL, dp_nh_ent_free);

    makdi_users_init(hdl);
    makdi_nfv_group_init(hdl);
    makdi_nfv_service_init(hdl);

    hdl->cfg_service = mul_app_create_service(MUL_MAKDI_SERVICE_NAME,
                                              makdi_service_handler);
    assert(hdl->cfg_service);

    hdl->route_service = mul_app_get_service_notify(MUL_ROUTE_SERVICE_NAME,
                                   makdi_route_service_conn_event,
                                   true, NULL);
    assert(hdl->route_service);

    hdl->mul_service =
            mul_app_get_service_notify(MUL_CORE_SERVICE_NAME,
                                       makdi_mul_service_conn_event,
                                       true, NULL);
    assert(hdl->mul_service);

    hdl->timer_event = evtimer_new(base,
                                   makdi_main_timer,
                                   (void *)hdl);
    evtimer_add(hdl->timer_event, &tv);
    makdi_static_init(hdl);

    /* set route convergence flag to waiting state*/
    hdl->rt_conv_state = RT_STATE_WAIT_FOR_CONVERGENCE;

    mul_register_app_cb(NULL, MAKDI_APP_NAME, 
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, &makdi_app_cbs);
    return;
}

DEFUN (show_s_fdb,
       show_s_fdb_cmd,
       "show service-fdb all",
       SHOW_STR
       "Service FDBs\n"
       "Summary information for all")
{
    struct s_fdb_iter_arg arg = { show_s_fdb_info, vty };
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    s_user_traverse_all(makdi_hdl, __s_fdb_traverse_per_user, &arg);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_s_user,
       show_s_user_cmd,
       "show user-sc-chain all",
       SHOW_STR
       "User Service Chain\n"
       "Summary information for all")
{

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    s_user_traverse_all(makdi_hdl, __makdi_app_per_user_chain, NULL);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    return CMD_SUCCESS;
}

void
makdi_module_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
    install_element(ENABLE_NODE, &show_s_fdb_cmd);
    install_element(ENABLE_NODE, &show_s_user_cmd);
}

module_init(makdi_module_init);
module_vty_init(makdi_module_vty_init);
