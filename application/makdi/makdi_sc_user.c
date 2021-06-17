/*
 *  makdi_sc_user.c: makdi service-chain user management for MUL Controller 
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

extern makdi_hdl_t *makdi_hdl;
extern struct c_rlim_dat crl;

static void
serv_ent_free(void *ent)
{
    chain_fl_ent_t *chain_ent = ent;

    if (chain_ent->actions) free(chain_ent->actions);
    chain_ent->actions = NULL;
    free(ent);
}

static int UNUSED
serv_chain_ent_comp(void *chain_ent, void *u_arg)
{
    chain_fl_ent_t *ent_arg = u_arg;
    chain_fl_ent_t *ent = chain_ent;

    return ent_arg->dpid != ent->dpid ||
            memcmp(&ent_arg->fl, &ent->fl, sizeof(struct flow) ||
            memcmp(&ent_arg->mask, &ent->mask, sizeof(struct flow)));
}

static void
serv_chain_ent_install(void *ent, void *uarg)
{
    struct chain_fl_ent *chain_ent = ent;
    int *ret = uarg;

#ifdef SERV_FDB_DEBUG
    char *str;

    str = of_dump_flow_generic(&chain_ent->fl, &chain_ent->mask);
    
    if (!c_rlim(&crl))
        c_log_err("[hop-fl-install] DPID:(0x%llx) Flow %s",
                  U642ULL(chain_ent->dpid), str);
    free(str);
#endif

    mul_service_send_flow_add(makdi_hdl->mul_service,
                          (uint64_t)(chain_ent->dpid),
                          &chain_ent->fl, &chain_ent->mask, MAKDI_UNK_BUFFER_ID,
                          chain_ent->actions, chain_ent->act_len,
                          0, 0,
                          C_FL_PRIO_FWD,
                          C_FL_ENT_GSTATS);

    if (c_service_timed_wait_response(makdi_hdl->mul_service) > 0) {
        c_log_err("[hop-fl-install] WARNING flow add failed");
        *ret = 1;
    }

    return;
}

int
__s_fdb_install_serv(s_fdb_ent_t *fdb, bool dir, s_user_ent_t *u_ent)
{
    GSList *iterator;
    nfv_ent_t *nfv;
    struct mul_act_mdata mdata;
    uint64_t s_dpid = 0;
    uint64_t e_dpid = 0;
    uint64_t n_dpid = 0;
    dp_nh_ent_t *nh = NULL;
    uint16_t vlan_id = MAKDI_CHAIN_INIT_VID;
    uint16_t ivid = 0;
    uint16_t in_port = OFPP_NONE;
    bool nfv_src = false;
    GSList *nfv_list = NULL;
    struct flow *base_flow = NULL;
    struct flow mask;
    GSList *serv_chain = NULL;
    uint8_t nfv_idx = 0;
    int num_iroutes = 0;
    uint16_t oif = 0;
    int ret = 0;

    of_mask_set_dc_all(&mask);

    if (fdb->key.fdb_fl.dl_type == htons(ETH_TYPE_IP)) {
        if (!c_rlim(&crl))
            c_log_debug("[fdb-install] ethernet pkt");
        of_mask_set_dl_type(&mask);
        of_mask_set_in_port(&mask);
        of_mask_set_nw_src(&mask,32);
        of_mask_set_nw_dst(&mask,32);
    } else {
        if (!c_rlim(&crl))
            c_log_debug("[fdb-install] non-ethernet pkt");
        of_mask_set_in_port(&mask);
        of_mask_set_nw_dst(&mask,32);
        of_mask_set_nw_src(&mask,32);
        of_mask_set_nw_proto(&mask);
        of_mask_set_dl_vlan_pcp(&mask);
        of_mask_set_tp_src(&mask);
        of_mask_set_tp_dst(&mask);
        if(dir)
            of_mask_set_dl_dst(&mask);
        else
            of_mask_set_dl_src(&mask);
    }

    s_dpid = fdb->dpid;

    nfv_list = fdb->u_ent->nfv_list;
    base_flow = &fdb->key.fdb_fl;

    if (!dir) {
        ivid = 0;
#ifdef SERV_FDB_DEBUG
        if (!c_rlim(&crl))
            c_log_debug("[fdb-install] Reverse Chain");
#endif
        nfv_list = fdb->u_ent->r_nfv_list;
        s_dpid = fdb->u_ent->e_dpid;
        base_flow = &fdb->r_fl;
    } else {
        ivid = GET_SERV_ID_FROM_FDB(fdb);
#ifdef SERV_FDB_DEBUG
    if (!c_rlim(&crl))
        c_log_debug("[fdb-install] Forward Chain");
#endif
    }

    if (!nfv_list) {
        if (!c_rlim(&crl))
            c_log_err("[fdb-install] No NFV list");
        return -1;
    }

    in_port = ntohl(base_flow->in_port);

    g_slist_foreach(nfv_list, (GFunc)__s_user_nfv_list_traverse_elem, NULL);

    for (iterator = nfv_list;
         iterator;
         iterator = iterator->next) {
        struct chain_fl_ent *chain_ent;

        /* We dont use first entry of the NFV List in any direction */
        if (iterator == nfv_list) continue;

        nfv = iterator->data;
        assert(nfv);
        e_dpid  = nfv->key.dpid;
        n_dpid = s_dpid;

#ifdef SERV_FDB_DEBUG
        if (!c_rlim(&crl))
            c_log_debug("[fdb-install] (new) ns (%u) e_dpid 0x%llx 0xn_dpid %llx "
                    "s_dpid 0x%llx", nfv_src, U642ULL(e_dpid),
                    U642ULL(n_dpid), U642ULL(s_dpid));
#endif
        /* find the path to end dpid*/

        num_iroutes = 0;
        while (n_dpid != e_dpid) {
            /* find the datapath next hop to end dpid*/
            if (num_iroutes++ >= MAKDI_MAX_IROUTES) {
                if (!c_rlim(&crl))
                    c_log_err("routes exceeded"); 
                goto out_err;
            }

            nh = __dp_nh_find(makdi_hdl, n_dpid, e_dpid);
            if (!nh) goto out_err;

            chain_ent = calloc(1, sizeof(*chain_ent));
            if (!chain_ent) goto out_err;

            memcpy(&chain_ent->fl, base_flow, sizeof(struct flow));

            chain_ent->dpid = n_dpid;
            chain_ent->u_ent = u_ent;
            chain_ent->fl.in_port = htonl(in_port);
            memcpy(&chain_ent->mask, &mask, sizeof(struct flow));

            if (!nfv_src) {
                if (!nfv_idx) {
                    if (ivid)
                        of_mask_set_dl_vlan(&chain_ent->mask);
                } else {
                    chain_ent->fl.dl_vlan = htons(vlan_id);
                    of_mask_set_dl_vlan(&chain_ent->mask);
                }
            } else {
                chain_ent->fl.dl_vlan = htons(vlan_id);
                of_mask_set_dl_vlan(&chain_ent->mask);
            }
            mul_app_act_alloc(&mdata);
            if (mul_app_act_set_ctors(&mdata, chain_ent->dpid)) {
                mul_app_act_free(&mdata);
                goto out_err; 
            }

            mul_app_action_output(&mdata, in_port == nh->nh_port ? 
                                          OF_SEND_IN_PORT : nh->nh_port);
            chain_ent->oport = (in_port == nh->nh_port) ? 
                                OF_SEND_IN_PORT : nh->nh_port;

            chain_ent->actions = mdata.act_base;
            chain_ent->act_len = of_mact_len(&mdata);
            /* Add all the intermediate dpid as chain entities in chaining
             * list*/
            serv_chain = g_slist_append(serv_chain, chain_ent);

            nfv_src = false;
            in_port = nh->nh_nport;
            n_dpid = nh->nh_dpid;
#ifdef SERV_FDB_DEBUG
            if (!c_rlim(&crl))
                c_log_debug("[fdb-install] ns(%u) e_dpid %llx n_dpid %llx s_dpid %llx",
                   nfv_src, U642ULL(e_dpid), U642ULL(n_dpid), U642ULL(s_dpid));
#endif
        }
        /* Preparing service chain element for end DPID*/
        if (n_dpid == e_dpid) {
#ifdef SERV_FDB_DEBUG
            if (!c_rlim(&crl))
                c_log_debug("[fdb-install] ns(%u) e_dpid %llx n_dpid %llx s_dpid %llx",
                   nfv_src, U642ULL(e_dpid), U642ULL(n_dpid), U642ULL(s_dpid));
#endif

            chain_ent = calloc(1, sizeof(*chain_ent));
            if (!chain_ent) goto out_err;

            chain_ent->u_ent = u_ent;
            memcpy(&chain_ent->fl, base_flow, sizeof(struct flow));

            chain_ent->dpid = n_dpid;
            memcpy(&chain_ent->mask, &mask, sizeof(struct flow));
            chain_ent->fl.in_port = htonl(in_port);

            mul_app_act_alloc(&mdata);
            if (mul_app_act_set_ctors(&mdata, chain_ent->dpid)){
                mul_app_act_free(&mdata);
                goto out_err;
            }

            if (!nfv_idx) {
                if (ivid)
                   of_mask_set_dl_vlan(&chain_ent->mask);
            } else {
                chain_ent->fl.dl_vlan = htons(vlan_id);
                of_mask_set_dl_vlan(&chain_ent->mask);
            }
            vlan_id++;
            /* If it is the last nfv */
            if (nfv_idx == g_slist_length(nfv_list) - 2) {
                if  (ivid || nfv_idx)
                    mul_app_action_strip_vlan(&mdata);
            } else
                mul_app_action_set_vid(&mdata, vlan_id);

            oif = dir ? nfv->key.oif : nfv->key.iif;
            mul_app_action_output(&mdata, in_port == oif ? OFPP_IN_PORT : oif);
            chain_ent->oport = (in_port == oif) ? OFPP_IN_PORT : oif;
            chain_ent->actions = mdata.act_base;
            chain_ent->act_len = of_mact_len(&mdata);

            serv_chain = g_slist_append(serv_chain, chain_ent);

            nfv_src = true;
            in_port = dir ? nfv->key.iif : nfv->key.oif;
            s_dpid = e_dpid;
        }
        nfv_idx++;
    }

    /* Installing flows for service chain per chain element*/
    g_slist_foreach(serv_chain, serv_chain_ent_install, &ret);
    if (ret) goto out_err;

    if (dir) {
        /* Prepare reverse service chain for reverse direction*/
        if (__s_fdb_install_serv(fdb, false, u_ent)) {
            c_log_err("[fdb-install] reverse chain failed");
            goto out_err;
        }
        fdb->chain_fl = serv_chain;
    } else {
        fdb->r_chain_fl = serv_chain;
        fdb->reg = true;
    }

    return 0;

out_err:
    if (serv_chain)
        g_slist_free_full(serv_chain, serv_ent_free);
    fdb->chain_fl = NULL;
    fdb->r_chain_fl = NULL;
 
    return -1;
}


static void
__serv_chain_ent_uninstall(void *ent, void *uarg UNUSED)
{
    struct chain_fl_ent *chain_ent = ent;

#ifdef SERV_FDB_DEBUG
    char *str = NULL;
    str = of_dump_flow_generic(&chain_ent->fl, &chain_ent->mask);
    c_log_err("[hop-fl-uninstall] DPID:(0x%llx) Flow %s",
              U642ULL(chain_ent->dpid), str);
    free(str);
#endif

    mul_service_send_flow_del(makdi_hdl->mul_service, chain_ent->dpid,
                          &chain_ent->fl, &chain_ent->mask,
                          0, C_FL_PRIO_FWD, 
                          C_FL_ENT_GSTATS, OFPG_ANY);
    if (c_service_timed_wait_response(makdi_hdl->mul_service) > 0) {
        c_log_err("[hop-fl-uninstall] WARNING flow del failed");
    }

    return;
}

static int
__s_fdb_uninstall_serv(s_fdb_ent_t *fdb)
{
    if (fdb->chain_fl) {
#ifdef SERV_FDB_DEBUG
        c_log_debug("[fdb-uninstall] Forward chain");
#endif
        g_slist_foreach(fdb->chain_fl, __serv_chain_ent_uninstall, NULL);
        g_slist_free_full(fdb->chain_fl, serv_ent_free);
    }

    if (fdb->r_chain_fl) {
#ifdef SERV_FDB_DEBUG
        c_log_debug("[fdb-uninstall] Reverse chain");
#endif
        g_slist_foreach(fdb->r_chain_fl, __serv_chain_ent_uninstall, NULL);
        g_slist_free_full(fdb->r_chain_fl, serv_ent_free);
    }

    fdb->chain_fl = NULL;
    fdb->r_chain_fl = NULL;
    fdb->reg = false;
    return 0;
}

void
s_fdb_dump(s_fdb_ent_t *fdb, char *msg)
{
    char *flow_str= NULL;
    flow_str = of_dump_flow(&fdb->key.fdb_fl, 0);
    c_log_info("|fdb-info| (%s) %s", msg, flow_str);
    free(flow_str);
}

static void
__s_fdb_ent_free(void *arg)
{
    s_fdb_ent_t *fdb = arg;

    if (!c_rlim(&crl))
        c_log_debug("[fdb-free] %s",
                    fdb->reg ? "registered" : "unregistered");

    if(fdb->reg)
        __s_fdb_uninstall_serv(fdb);

    free(arg);
}

static unsigned int
s_fdb_hash(const void *p)
{
    const uint8_t *key = p;
    return hash_bytes(key, sizeof(s_fdb_key_t), 1);
}

static int
s_fdb_equal(const void *p1, const void *p2)
{
    return !memcmp(p1, p2, sizeof(s_fdb_key_t));
}

int
__s_fdb_add(makdi_hdl_t *hdl UNUSED, s_user_ent_t *u_ent,
            s_fdb_ent_t *fdb, uint32_t in_port,
            uint32_t buffer_id, uint8_t *raw,
            size_t pkt_len)
{
    struct of_pkt_out_params parms;
    chain_fl_ent_t *c_ent;
    s_fdb_ent_t *fdb_ent;

    fdb->u_ent = u_ent;

    if(!u_ent->reg)
        goto pkt_out;

    assert(fdb->u_ent->nfv_list);
    s_fdb_r_flow_init(fdb, u_ent->e_iif);

    if ((fdb_ent = g_hash_table_lookup(u_ent->s_fdb_htbl, &fdb->key))) {
        s_fdb_dump(fdb, "exists");
        __s_fdb_ent_free(fdb);
        fdb = fdb_ent;
    } else {
        g_hash_table_insert(u_ent->s_fdb_htbl, &fdb->key, fdb);
        s_fdb_dump(fdb, "newly added");
    }

    if(makdi_hdl->rt_conv_state == RT_STATE_CONVERGED) {
        /* Install the service chain if routes are converged*/
        __s_fdb_install_serv(fdb, true, u_ent);
    }
    else{
        /* We cannot install service chain as it may be in a Stale state*/
        if (!c_rlim(&crl))
            c_log_err("[fdb-install] Route not yet converged");
    }

pkt_out:
    if (buffer_id != MAKDI_UNK_BUFFER_ID) {
        pkt_len = 0;
    }

    c_ent = fdb->chain_fl->data;
    if (!c_ent) goto out;

    if (buffer_id != MAKDI_UNK_BUFFER_ID) {
        pkt_len = 0;
    }

    parms.buffer_id = buffer_id;
    parms.in_port = ntohl(in_port);
    parms.action_list = c_ent->actions;
    parms.action_len = c_ent->act_len;
    parms.data_len = pkt_len;
    parms.data = raw;
    mul_app_send_pkt_out(NULL, c_ent->dpid, &parms);

out:
    return 0;
}

int
__s_fdb_del(s_user_ent_t *u_ent, s_fdb_ent_t *fdb)
{
    s_fdb_dump(fdb, "Delete");
    c_wr_lock(&makdi_hdl->lock);
    g_hash_table_remove(u_ent->s_fdb_htbl, &fdb->key);
    c_wr_unlock(&makdi_hdl->lock);

    return 0;
}

int
s_fdb_lrn(makdi_hdl_t *hdl, s_fdb_ent_t *lrn_fdb,
          uint32_t in_port, uint32_t buffer_id,
          uint8_t *raw, size_t pkt_len)
{
    s_user_ent_t u_lkup, *u_ent = NULL;
    int ret = -1;

    s_user_key_init(&u_lkup, GET_USER_IP_FROM_FDB(lrn_fdb),
                    lrn_fdb->dpid, GET_SERV_ID_FROM_FDB(lrn_fdb));

    c_wr_lock(&hdl->lock);
    u_ent = __s_user_find(hdl, &u_lkup);
    if (!u_ent) {
        if (!c_rlim(&crl))
            c_log_debug("user not found 0x%llx", U642ULL(u_lkup.key.dpid));
        goto out_unlock; 
    }
    if (!c_rlim(&crl))
        c_log_debug("user found SIP[%x] VLAN[%d] "
            "DPID[%llx]",u_ent->key.src_nw_addr, u_ent->key.vlan,
            U642ULL(u_ent->key.dpid));

    /* s_fdb_dump(lrn_fdb, "user found"); */
    g_slist_foreach(u_ent->nfv_list,
                    (GFunc)__s_user_nfv_list_traverse_elem, NULL);

    ret = __s_fdb_add(hdl, u_ent, lrn_fdb, in_port, buffer_id, raw, pkt_len);

out_unlock:
    c_wr_unlock(&hdl->lock);

    return ret;
}

int
s_fdb_expired(void *key_arg, void *val_arg UNUSED, void *uarg)
{
    time_t curr = *(time_t *)uarg;
    s_fdb_ent_t *fdb = key_arg;

    if (!fdb) return false;

    if (curr > fdb->create_ts + S_FDB_TIMEO) {
        s_fdb_dump(fdb, "Expired");
        return true;
    }

    return false;
}

void
s_fdb_ent_init(s_fdb_ent_t *fdb, struct flow *flow, uint64_t dpid)
{
    memset(fdb, 0, sizeof(*fdb));

    memcpy(&fdb->key.fdb_fl, flow, sizeof(*flow));
    fdb->create_ts = time(NULL);
    fdb->dpid = dpid;

    if (fdb->key.fdb_fl.dl_type == htons(ETH_TYPE_ARP)) {
        fdb->key.fdb_fl.ip.nw_src = 0;
        fdb->key.fdb_fl.ip.nw_dst = 0;
        fdb->key.fdb_fl.tp_src = 0;
        fdb->key.fdb_fl.tp_dst = 0;
        fdb->key.fdb_fl.nw_proto = 0;
        fdb->key.fdb_fl.nw_tos = 0;
        fdb->key.fdb_fl.dl_vlan_pcp = 0;
    }

    if (fdb->key.fdb_fl.dl_type == htons(ETH_TYPE_IP) &&
        fdb->key.fdb_fl.nw_proto == IP_TYPE_ICMP) {
        fdb->key.fdb_fl.tp_src = 0;
        fdb->key.fdb_fl.tp_dst = 0;
    }
}

void
s_fdb_r_flow_init(s_fdb_ent_t *fdb, uint16_t port)
{
    struct flow *r_fl = &fdb->r_fl;
    struct flow *fl = &fdb->key.fdb_fl;

    r_fl->in_port = htonl(port);
    r_fl->ip.nw_src = fl->ip.nw_dst;
    r_fl->ip.nw_dst = fl->ip.nw_src;
    r_fl->dl_vlan = fl->dl_vlan;
    r_fl->dl_type = fl->dl_type;
    r_fl->tp_src = fl->tp_dst;
    r_fl->tp_dst = fl->tp_src;
    memcpy(r_fl->dl_src, fl->dl_dst, 6);
    memcpy(r_fl->dl_dst, fl->dl_src, 6);
    r_fl->dl_vlan_pcp = fl->dl_vlan_pcp;
    r_fl->nw_tos = fl->nw_tos;
    r_fl->nw_proto = fl->nw_proto;
}

static void
show_s_fdb_nfv_list(void *ent, void *uarg)
{
    nfv_dump_print(ent, ent, uarg);
}

void
show_s_fdb_info(void *key UNUSED, void *fdb_arg, void *uarg)
{
    s_fdb_ent_t *fdb = fdb_arg;
    struct vty  *vty = uarg;
    char *flow_str;

    flow_str = of_dump_flow(&fdb->key.fdb_fl, 0);

    vty_out (vty, " %s\r\n", flow_str);
    free(flow_str);

    if (fdb->u_ent->nfv_list) {
        g_slist_foreach(fdb->u_ent->nfv_list,
                        show_s_fdb_nfv_list, NULL);
    }
}

/**
 * s_fdb_to_flow-
 *
 * Copy a single flow
 */
static void
s_fdb_to_flow(s_fdb_ent_t *fdb, struct c_ofp_host_mod *user_info)
{
    user_info->switch_id.datapath_id = htonll(fdb->dpid);
    user_info->host_flow = fdb->key.fdb_fl;
}

/*
 * send_s_fdb_info -
 *
 * Functions prepare Flow Info and sends to the service
 */
void
send_s_fdb_info(void *key UNUSED, void *fdb_arg, void *uarg)
{
    s_fdb_ent_t *fdb = fdb_arg;
    struct makdi_iter_arg *makdi_iter_arg = uarg;

    struct c_ofp_s_chain_info *cofp_serv_chain = NULL;
    struct c_ofp_auxapp_cmd *cofp_aac = NULL;
    struct cbuf *b = NULL;

    b = of_prep_msg(sizeof(*cofp_aac) + sizeof(*cofp_serv_chain),
                    C_OFPT_AUX_CMD, 0);
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_MAKDI_USER);
    cofp_serv_chain = (void *)(cofp_aac->data);

    s_fdb_to_flow(fdb, &cofp_serv_chain->user_info);
    if (fdb->u_ent->nfv_list) {
        g_slist_foreach(fdb->u_ent->nfv_list,
                        (GFunc)__s_user_nfv_list_traverse_elem,
                        &cofp_serv_chain->nfv_list);
    }

    assert(makdi_iter_arg->send_cb);
    makdi_iter_arg->send_cb(makdi_iter_arg->serv, b);
}

void
__s_fdb_traverse_per_user(void *key UNUSED, void *user, void *uarg)
{
    s_user_ent_t *u_ent = user;
    struct s_fdb_iter_arg *iter_arg = uarg;

    if (u_ent->s_fdb_htbl) {
        g_hash_table_foreach(u_ent->s_fdb_htbl,
                             (GHFunc)iter_arg->iter_fn, iter_arg->arg);
    }
}

static void
s_user_dump(s_user_ent_t *u_ent, char *msg)
{
    struct in_addr addr;

    addr.s_addr = htonl(u_ent->key.src_nw_addr);
    c_log_info("[user] (%s) (0x%llx:%s:%u) %s",
                u_ent->reg ? "Registered" : "Unregistered",
                U642ULL(u_ent->key.dpid),
                inet_ntoa(addr),
                u_ent->key.SERV_ID, msg);
}

void
__s_per_user_timer(void *key UNUSED, void *user, void *uarg UNUSED)
{
    s_user_ent_t *u_ent = user;
    time_t curr_ts = time(NULL);
    char *nfv_list[MAX_NFV];
    GSList *siter = NULL;
    nfv_group_ent_t *nfv_group;
    int i = 0;

    if (!u_ent->reg) {
        if (u_ent->nfv_groups) {
            for (siter = u_ent->nfv_groups; siter; siter = siter->next) {
                nfv_group = siter->data;
                nfv_list[i++] = nfv_group->key.name;
                assert(i < MAX_NFV);
            }
            if (i)
                __s_user_ent_reset_nfv_list(u_ent, i, nfv_list);
        }
        return;
    }
    if (u_ent->s_fdb_htbl) {
        g_hash_table_foreach_remove(u_ent->s_fdb_htbl,
                                    s_fdb_expired,
                                    &curr_ts);
    }
}

static void
s_user_ent_purge_nfv_list(s_user_ent_t *u_ent)
{
    if (u_ent->nfv_list)
        g_slist_free(u_ent->nfv_list);
    u_ent->nfv_list = NULL;
    if (u_ent->r_nfv_list)
        g_slist_free(u_ent->r_nfv_list);
    u_ent->r_nfv_list = NULL;
}

static void
s_user_ent_free(void *arg)
{
    s_user_ent_t *u_ent = arg;
    service_ent_t *s_ent_arg = NULL;

    s_user_ent_purge_nfv_list(u_ent);
    if (u_ent->nfv_groups) {
        g_slist_free_full(u_ent->nfv_groups, nfv_group_ent_put);
        u_ent->nfv_groups = NULL;
    }
    if (u_ent->s_fdb_htbl)
        g_hash_table_destroy(u_ent->s_fdb_htbl);
    u_ent->s_fdb_htbl = NULL;

    assert(u_ent->s_ent);

    if (u_ent->s_ent) {
        s_ent_arg = u_ent->s_ent;
        if (s_ent_arg->usr_list) {
            s_ent_arg->usr_list = g_slist_remove(s_ent_arg->usr_list,
                                                 u_ent);
        }
        service_ent_put(u_ent->s_ent);
    }
    u_ent->s_ent = NULL;

    free(arg);
}

static unsigned int
s_user_hash(const void *p)
{
    const uint8_t *key = p;
    return hash_bytes(key, sizeof(s_user_key_t), 1);
}

static int
s_user_equal(const void *p1, const void *p2)
{
    const s_user_key_t *user_ent = p1;
    const s_user_key_t *user_ent_arg = p2;

    if ((user_ent->src_nw_addr == user_ent_arg->src_nw_addr) &&
        (user_ent->vlan == user_ent_arg->vlan) &&
        (user_ent->dpid == user_ent_arg->dpid)) {
        return true;
    }
    return false;
}

void
__s_user_nfv_list_traverse_elem(void *ent, void *uarg)
{
    if (uarg) {
        nfv_dump_msg(ent, ent, uarg);
    } else {
        nfv_dump_print(ent, ent, uarg);
    }
}

void
s_user_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&hdl->lock);
    if (hdl->s_user_htbl) {
        g_hash_table_foreach(hdl->s_user_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&hdl->lock);

    return;
}

void
s_user_traverse_all_writer(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    c_wr_lock(&hdl->lock);
    if (hdl->s_user_htbl) {
        g_hash_table_foreach(hdl->s_user_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_wr_unlock(&hdl->lock);

    return;
}

void
s_user_key_init(s_user_ent_t *u_ent, uint32_t src_nw_addr,
                uint64_t dpid, uint16_t serv_id)
{
    u_ent->key.SERV_ID = serv_id;
    u_ent->key.res = 0;
    u_ent->key.src_nw_addr = src_nw_addr;
    u_ent->key.dpid = dpid;
}

static int
__s_user_add(makdi_hdl_t *hdl, s_user_ent_t *u_ent)
{
    if (g_hash_table_lookup(hdl->s_user_htbl, &u_ent->key)) {
        s_user_dump(u_ent, "exists");
        return -1;
    }

    u_ent->reg = true;
    g_hash_table_insert(hdl->s_user_htbl, &u_ent->key, u_ent);
    s_user_dump(u_ent, "newly added");

    return 0;
}

int
s_user_add(makdi_hdl_t *hdl, s_user_ent_t *u_ent)
{
    c_wr_lock(&hdl->lock);
    __s_user_add(hdl, u_ent);
    g_hash_table_insert(hdl->s_user_htbl, &u_ent->key, u_ent);
    c_wr_unlock(&hdl->lock);

    return 0;
}

s_user_ent_t *
__s_user_find(makdi_hdl_t *hdl, s_user_ent_t *u_lkup)
{
    return (s_user_ent_t *)g_hash_table_lookup(hdl->s_user_htbl, &u_lkup->key);
}

static int
__s_user_del(makdi_hdl_t *hdl, s_user_key_t *key)
{
    int ret;
    struct in_addr addr = { .s_addr = htonl(key->src_nw_addr) };

    ret =  g_hash_table_remove(hdl->s_user_htbl, key);
    if (ret) {
        c_log_debug("[user] %s DP:0x%llx serv-id(%u) deleted",
                inet_ntoa(addr), U642ULL(key->dpid), key->SERV_ID);
    }
    return !ret;
}

int
s_user_del(makdi_hdl_t *hdl, s_user_key_t *key)
{
    c_wr_lock(&hdl->lock);
    __s_user_del(hdl, key);
    c_wr_unlock(&hdl->lock);
    return 0;
}

int
__s_user_ent_reset_nfv_list(s_user_ent_t *u_ent, int nfvc, char **nfvv)
{
    int i = 0;
    nfv_ent_t *nfv = NULL;
    nfv_ent_t *nfv_list[nfvc];

    if (nfvc < MAKDI_MIN_NFVS_IN_SC ||
        !nfvv[0] ||
        strncmp(nfvv[0], MAKDI_ENTRY_NFV_GRP, strlen(MAKDI_ENTRY_NFV_GRP)) ||
        !nfvv[nfvc-1] ||
        strncmp(nfvv[nfvc-1], MAKDI_EXIT_NFV_GRP,
                strlen(MAKDI_EXIT_NFV_GRP))) {
        c_log_err("[sc-nfv-reset] Invalid nfvs %d", nfvc);
        return -1;
    }

    s_user_ent_purge_nfv_list(u_ent);
    if (u_ent->s_fdb_htbl)
        g_hash_table_destroy(u_ent->s_fdb_htbl);

    u_ent->s_fdb_htbl = NULL;
    u_ent->reg = true;
    u_ent->s_dpid = 0;
    u_ent->s_iif = (uint16_t)(-1);

    u_ent->create_ts = time(NULL);
    u_ent->s_fdb_htbl = g_hash_table_new_full(s_fdb_hash,
                                              s_fdb_equal,
                                              NULL,
                                              __s_fdb_ent_free);
    assert(u_ent->nfv_groups);
    for (i = 0; i < nfvc; i++) {
        nfv = __nfv_ent_get_from_group(makdi_hdl, nfvv[i], true);
        if (!nfv) {
            if (!c_rlim(&crl))
                c_log_err("[sc-path] No nfv list in group %s", nfvv[i]);
            goto free_err;
        }
        u_ent->nfv_list = g_slist_append(u_ent->nfv_list, nfv);
        nfv_list[i] = nfv;
        if (!c_rlim(&crl))
            c_log_debug("[sc-path] nfv(%s:%s) dpid(0x%llx)(%hu:%hu)-->",
                    nfv->name, NFV_ENT_GROUP_NAME(nfv),
                    U642ULL(nfv->key.dpid), nfv->key.iif, nfv->key.oif);
    }

    assert(nfv); /* Cant happen if everything is in sane state */

    u_ent->e_dpid = nfv->key.dpid;
    u_ent->e_iif = nfv->key.iif;
    u_ent->r_nfv_list = NULL;

    for (i = nfvc-1; i >= 0; i--) { 
        u_ent->r_nfv_list = g_slist_append(u_ent->r_nfv_list, nfv_list[i]);
        if (!c_rlim(&crl))
            c_log_debug("[sc-path] (R) nfv(%s:%s) dpid(0x%llx)(%hu:%hu)-->",
                    nfv_list[i]->name, NFV_ENT_GROUP_NAME(nfv_list[i]),
                    U642ULL(nfv_list[i]->key.dpid), nfv_list[i]->key.oif, 
                    nfv_list[i]->key.iif); 
    }

#ifdef MAKDI_NFV_DEBUG
    c_log_debug("UL NFVs:");
    g_slist_foreach(u_ent->nfv_list,
                    (GFunc)__s_user_nfv_list_traverse_elem, NULL);

    c_log_debug("DL NFVs:");
    g_slist_foreach(u_ent->r_nfv_list,
                    (GFunc)__s_user_nfv_list_traverse_elem, NULL);
#endif

    return 0;
free_err:
    if (!c_rlim(&crl))
        c_log_err("[sc-nfv-reset] NFV List error");
    s_user_ent_purge_nfv_list(u_ent);
    if (u_ent->s_fdb_htbl)
        g_hash_table_destroy(u_ent->s_fdb_htbl);
    u_ent->s_fdb_htbl = NULL;
    u_ent->reg = false;
    return -1;
}

/*
 * __s_user_ent_mod_nfv_list -
 *
 * Note - To be called under main lock
 */
static int
__s_user_ent_mod_nfv_list(s_user_ent_t *u_ent, int nfvc, char **nfvv)
{
    int i = 0;
    nfv_group_ent_t *grp = NULL;
    nfv_ent_t *nfv = NULL;
    GSList *iter = NULL;
    bool modify = false;
    GSList *old_groups = NULL;
    bool need_log = !c_rlim(&crl);

    if (nfvc < MAKDI_MIN_NFVS_IN_SC ||
        !nfvv[0] ||
        strncmp(nfvv[0], MAKDI_ENTRY_NFV_GRP, strlen(MAKDI_ENTRY_NFV_GRP)) ||
        !nfvv[nfvc-1] ||
        strncmp(nfvv[nfvc-1], MAKDI_EXIT_NFV_GRP,
                strlen(MAKDI_EXIT_NFV_GRP))) {
        if (need_log)
            c_log_err("[sc-nfv-mod] Invalid nfv num");
        return -1;
    }

    if (u_ent->nfv_groups) {
        if (g_slist_length(u_ent->nfv_groups) == nfvc) {
            for (iter = u_ent->nfv_groups; iter; iter = iter->next, i++) {
                grp = iter->data;
                if (!strncmp(grp->key.name, nfvv[i], MAX_NFV_NAME)) {
                    continue;
                } else {
                    modify = true;
                    break;
                }
            }
            if (!modify) {
                if (need_log)
                    c_log_debug("[sc-nfv-mod] User for same service exists");
                return -1;
            }
        }
    }

    old_groups = u_ent->nfv_groups;
    u_ent->nfv_groups = NULL;

    for ( i = 0; i < nfvc; i++) {
        grp = __nfv_group_get(makdi_hdl, nfvv[i]);
        if (grp) {
            u_ent->nfv_groups = g_slist_append(u_ent->nfv_groups, grp);
        } else {
            if (u_ent->nfv_groups)
                g_slist_free_full(u_ent->nfv_groups, nfv_group_ent_put);
            u_ent->nfv_groups = old_groups;
            s_user_dump(u_ent, "configuration failed");
        }
    }
    
    if (old_groups) {
        g_slist_free_full(old_groups, nfv_group_ent_put);
    }

    /* Confirm NFV groups and list are present */
    for (i = 0; i < nfvc; i++) {
        if (!nfvv[i]) return -1;
        nfv = __nfv_ent_get_from_group(makdi_hdl, nfvv[i], false);
        if (!nfv) {
            if (need_log)
                c_log_err("[nfv-select] group(%s) has no nfv", nfvv[i]);
            return -1;
        } else {
            if (need_log)
                c_log_info("[nfv-select] %s in grp %s", nfv->name, nfvv[i]);
        }
    }

    __s_user_ent_reset_nfv_list(u_ent, nfvc, nfvv);

    return 0;
}

void
sc_modify_on_port_up(uint64_t dpid, uint16_t port)
{
    nfv_key_t nfv_key;

    nfv_key.dpid = dpid;
    nfv_key.iif = port;
    nfv_key.oif = port;

    __nfv_group_traverse_all(makdi_hdl, mark_nfv_active_in_group_port_ev,
                             &nfv_key);
}

void
sc_modify_on_port_down(uint64_t dpid, uint16_t port)
{
    nfv_key_t nfv_key;

    nfv_key.dpid = dpid;
    nfv_key.iif = port;
    nfv_key.oif = port;

    c_wr_lock(&makdi_hdl->lock);
    __sc_reset_all_users_with_nfv(&nfv_key, false);
    c_wr_unlock(&makdi_hdl->lock);
}

void
sc_modify_on_dp_down(uint64_t dpid)
{
    nfv_key_t nfv_key;

    nfv_key.dpid = dpid;
    nfv_key.iif = 0;
    nfv_key.oif = 0;

    c_wr_lock(&makdi_hdl->lock);
    __sc_reset_all_users_with_nfv(&nfv_key, false);
    c_wr_unlock(&makdi_hdl->lock);
}

void
__sc_reset_all_users_with_nfv(void *nfv_key_arg, bool dp_event)
{
    nfv_key_t *nfv_key = nfv_key_arg;
    s_user_ent_t *u_ent = NULL;
    nfv_ent_t *nfv_ent;
    int i = 0;
    GHashTableIter iter;
    gpointer u_key, u_value;
    GSList *siter;
    char *nfv_list[MAX_NFV];
    bool need_reset;

    /* For every nfv_ent re mark the flag */
    __nfv_group_traverse_all(makdi_hdl,
                             dp_event ?
                                mark_nfv_inactive_in_group_dpid_ev:
                                mark_nfv_inactive_in_group_port_ev,
                             nfv_key);

    g_hash_table_iter_init(&iter, makdi_hdl->s_user_htbl);
    while (g_hash_table_iter_next(&iter, &u_key, &u_value)) {
        u_ent = u_value;
        need_reset = false;
        i = 0;
        for (siter = u_ent->nfv_list; siter; siter = siter->next) {
            nfv_ent = siter->data;
            nfv_list[i++] = NFV_ENT_GROUP_NAME(nfv_ent);
            c_log_debug("[sc-update] #%d nfv %s %s", i, nfv_list[i-1],
                      nfv_ent->inactive ? "inactive":"active");
            assert(i < MAX_NFV);
            if (!nfv_ent->inactive) continue;
            need_reset = true;
        }

        if (need_reset) {
            __s_user_ent_reset_nfv_list(u_ent, i, nfv_list);
        }

    }
}

int
sc_insert(makdi_hdl_t *hdl, char *service_name, uint32_t src_nw_addr,
          uint64_t dpid, int nfvc, char **nfvv,
          bool use_default)
{
    s_user_ent_t *u_lkup, *u_ent = NULL;
    service_ent_t *service_ent = NULL;
    bool modify = true;

    u_lkup = calloc(1, sizeof(*u_lkup));
    if (!u_lkup) {
        return -1;
    }
    c_wr_lock(&hdl->lock);
    if (service_name) {
        service_ent = __service_ent_get(hdl, service_name);
        if (!service_ent) {
            c_log_err("[sc-insert] No such service[%s]", service_name);
            goto err_out;
        }
    }
    else {
        c_log_err("[sc-insert] Empty service name");
        goto err_out;
    }

    s_user_key_init(u_lkup, src_nw_addr, dpid, service_ent->SERV_ID);

    u_ent = __s_user_find(hdl, u_lkup);
    if (!u_ent) {
        u_ent = u_lkup;
        modify = false;
    } else {
        assert(u_ent->s_ent == service_ent);
        free(u_lkup);
    }

    if (!modify) {
        u_ent->s_ent = service_ent;
        service_ent->usr_list = g_slist_append(service_ent->usr_list,
                                               u_ent);
    }

    if (use_default)
        u_ent->use_default = TRUE;
    else
        u_ent->use_default = FALSE;
    
    if (!modify && __s_user_add(hdl, u_ent)) {
        goto err_out1;
    }

    if (__s_user_ent_mod_nfv_list(u_ent, nfvc, nfvv)) {
        u_ent->reg = false;
        goto err_out1;
    }

    c_wr_unlock(&hdl->lock);

    return 0;

err_out:
    free(u_ent);
    if (service_ent) service_ent_put(service_ent);
err_out1:
    c_wr_unlock(&hdl->lock);
    return -1;
}

int
sc_remove(makdi_hdl_t *hdl, char *service_name,
          uint32_t src_nw_addr, uint64_t dpid)
{
    s_user_ent_t u_ent;
    service_ent_t *service_ent = NULL;
    int ret = 0;

    if (!service_name) return -1;

    c_wr_lock(&hdl->lock);
    service_ent = __service_ent_get(hdl, service_name);
    if(!service_ent) goto err_out;

    s_user_key_init(&u_ent, src_nw_addr, dpid, service_ent->SERV_ID);
    ret = __s_user_del(hdl, &u_ent.key);

    c_wr_unlock(&hdl->lock);
    return ret;

err_out:
    c_wr_unlock(&hdl->lock);
    return -1;
}

int
makdi_users_init(makdi_hdl_t *hdl)
{
    hdl->s_user_htbl = g_hash_table_new_full(s_user_hash, s_user_equal,
                                             NULL, s_user_ent_free);
    assert(hdl->s_user_htbl);
    return 0;
}
