/*
 *  l2switch.c: L2switch application for MUL Controller 
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
#include "config.h"
#include "mul_common.h"
#include "mul_vty.h"
#include "l2switch.h"

extern struct mul_app_client_cb l2sw_app_cbs;
int l2sw_mod_flow(l2sw_t *l2sw, l2fdb_ent_t *fdb, 
                  bool add_del, uint32_t buffer_id);
static void l2sw_install_dfl_flows(uint64_t dpid);
static void l2_fdb_ent_free(void *arg);

c_rw_lock_t app_lock;
struct event *l2sw_timer_event;

#ifndef CONFIG_L2SW_FDB_CACHE
static int
l2sw_set_fp_ops(l2sw_t *l2sw)
{
    c_ofp_set_fp_ops_t  *cofp_fp;
    struct cbuf         *b;

    b = of_prep_msg(sizeof(*cofp_fp), C_OFPT_SET_FPOPS, 0);

    cofp_fp = (void *)(b->data);
    cofp_fp->datapath_id = htonll(l2sw->swid); 
    cofp_fp->fp_type = htonl(C_FP_TYPE_L2);

    return mul_app_command_handler(L2SW_APP_NAME, b);
}
#endif

static void
l2_fdb_ent_free(void *arg)
{
    free(arg);
}

static unsigned int 
l2fdb_key(const void *p)
{   
    const uint8_t *mac_da = p;
    
    return hash_bytes(mac_da, OFP_ETH_ALEN, 1);
}

static int
l2fdb_equal(const void *p1, const void *p2)
{
    return !memcmp(p1, p2, OFP_ETH_ALEN);
}

#ifdef CONFIG_L2SW_FDB_CACHE
static int
check_l2port_down_l2sw_fdb(void *key UNUSED, void *ent, void *u_arg)
{
    l2fdb_ent_t                 *fdb = ent;
    struct l2sw_fdb_port_args   *args = u_arg;
    l2sw_t                      *l2sw = args->sw;

    if (fdb->lrn_port != args->port) {
        return 0;
    }

    l2sw_mod_flow(l2sw, fdb, false, L2SW_UNK_BUFFER_ID);
    return 1;
}
#endif

static int
l2sw_alloc(void **priv)
{
    l2sw_t **l2sw = (l2sw_t **)priv;

    *l2sw = calloc(1, sizeof(l2sw_t)); 
    assert(*l2sw);
    return 0;
}

static void 
l2sw_free(void *priv)
{
    free(priv);
}

static void 
l2sw_add(mul_switch_t *sw)
{
    l2sw_t      *l2sw = MUL_PRIV_SWITCH(sw);

    c_rw_lock_init(&l2sw->lock);
    l2sw->swid = sw->dpid;
    l2sw->l2fdb_htbl = g_hash_table_new_full(l2fdb_key,
                                             l2fdb_equal,
                                             NULL,
                                             l2_fdb_ent_free);
    assert(l2sw->l2fdb_htbl);

#ifndef CONFIG_L2SW_FDB_CACHE
    /* Let controller handle exception forwarding */
    l2sw_set_fp_ops(l2sw);
#endif

    /* Add flood flows for this switch eg Brdcast, mcast etc */
    l2sw_install_dfl_flows(sw->dpid);

    c_log_debug("L2 Switch 0x%llx added", (unsigned long long)(sw->dpid));
}

static void
l2sw_install_dfl_flows(uint64_t dpid)
{
    struct flow                 fl;
    struct flow                 mask;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);

    /* Clear all entries for this switch */
    mul_app_send_flow_del(L2SW_APP_NAME, NULL, dpid, &fl,
                          &mask, OFPP_NONE, 0, C_FL_ENT_NOCACHE, OFPG_ANY);

    /* Zero DST MAC Drop */
    of_mask_set_dl_dst(&mask); 
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, &mask,
                          L2SW_UNK_BUFFER_ID, NULL, 0, 0, 0, 
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Zero SRC MAC Drop */
    of_mask_set_dc_all(&mask);
    of_mask_set_dl_src(&mask); 
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, &mask, 
                          L2SW_UNK_BUFFER_ID, NULL, 0, 0, 0,  
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Broadcast SRC MAC Drop */
    memset(&fl.dl_src, 0xff, OFP_ETH_ALEN);
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, &mask,
                          L2SW_UNK_BUFFER_ID, NULL, 0, 0, 0,
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

#ifdef CONFIG_L2SW_FDB_CACHE
    /* Send any unknown flow to app */
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, &mask,
                          L2SW_UNK_BUFFER_ID, NULL, 0, 0, 0, C_FL_PRIO_DFL, 
                          C_FL_ENT_LOCAL);
#endif
}


static void
l2sw_del(mul_switch_t *sw)
{
    l2sw_t *l2sw = MUL_PRIV_SWITCH(sw);
 
    c_wr_lock(&l2sw->lock);
    if (l2sw->l2fdb_htbl) g_hash_table_destroy(l2sw->l2fdb_htbl);
    l2sw->l2fdb_htbl = NULL;
    c_wr_unlock(&l2sw->lock);
    c_log_debug("L2 Switch 0x%llx removed", (unsigned long long)(sw->dpid));
}


int 
l2sw_mod_flow(l2sw_t *l2sw, l2fdb_ent_t *fdb, 
              bool add, uint32_t buffer_id)
{
    struct mul_act_mdata mdata;  
    struct flow          fl; 
    struct flow          mask;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    of_mask_set_dl_dst(&mask);
    memcpy(&fl.dl_dst, fdb->mac_da, OFP_ETH_ALEN);

    if (add) { 
        mul_app_act_alloc(&mdata);
        mul_app_act_set_ctors(&mdata, l2sw->swid);
        mul_app_action_output(&mdata, fdb->lrn_port) ;
        mul_app_send_flow_add(L2SW_APP_NAME, NULL, l2sw->swid, &fl, 
                              &mask, buffer_id,
                              mdata.act_base, mul_app_act_len(&mdata),
                              L2FDB_ITIMEO_DFL, L2FDB_HTIMEO_DFL,
                              C_FL_PRIO_DFL, C_FL_ENT_NOCACHE);
        mul_app_act_free(&mdata);
    } else {
        mul_app_send_flow_del(L2SW_APP_NAME, NULL, l2sw->swid, &fl,
                              &mask, OFPP_NONE, C_FL_PRIO_DFL,
                              C_FL_ENT_NOCACHE, OFPG_ANY);
    }

    return 0;
}

static void 
l2sw_learn_and_fwd(mul_switch_t *sw, struct flow *fl, uint32_t inport,
                   uint32_t buffer_id, uint8_t *raw, size_t pkt_len)
{
    l2sw_t                      *l2sw = MUL_PRIV_SWITCH(sw);
#ifdef CONFIG_L2SW_FDB_CACHE
    l2fdb_ent_t                 *fdb;
#endif
    uint32_t                    oport = OF_ALL_PORTS;
    struct of_pkt_out_params    parms;
    struct mul_act_mdata mdata;  

    memset(&parms, 0, sizeof(parms));

    /* Check packet validity */
    if (is_zero_ether_addr(fl->dl_src) || 
        is_zero_ether_addr(fl->dl_dst) ||
        is_multicast_ether_addr(fl->dl_src) || 
        is_broadcast_ether_addr(fl->dl_src)) {
        c_log_debug("%s: Invalid src/dst mac addr", FN);
        return;
    }

#ifdef CONFIG_L2SW_FDB_CACHE
    c_wr_lock(&l2sw->lock);
    fdb = g_hash_table_lookup(l2sw->l2fdb_htbl, fl->dl_src);
    if (fdb) { 
        /* Station moved ? */
        if (ntohl(fl->in_port) != fdb->lrn_port) {
            l2sw_mod_flow(l2sw, fdb, false, (uint32_t)(-1));
            fdb->lrn_port = ntohs(fl->in_port); 
            l2sw_mod_flow(l2sw, fdb, true, (uint32_t)(-1));
        }  

        goto l2_fwd;
    }
    fdb = malloc(sizeof(*fdb));
    memcpy(fdb->mac_da, fl->dl_src, OFP_ETH_ALEN);
    fdb->lrn_port = ntohl(fl->in_port);
    g_hash_table_insert(l2sw->l2fdb_htbl, fdb->mac_da, fdb);

l2_fwd:

    fdb = g_hash_table_lookup(l2sw->l2fdb_htbl, fl->dl_dst);
    if (fdb) { 
        oport = fdb->lrn_port;
        l2sw_mod_flow(l2sw, fdb, true, L2SW_UNK_BUFFER_ID);
    } 
    c_wr_unlock(&l2sw->lock);
#endif

    if (buffer_id != L2SW_UNK_BUFFER_ID) {
        pkt_len = 0;
    }


    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    mul_app_act_set_ctors(&mdata, l2sw->swid);
    mul_app_action_output(&mdata, oport);
    parms.buffer_id = buffer_id;
    parms.in_port = inport;
    parms.action_list = mdata.act_base;
    parms.action_len = mul_app_act_len(&mdata);
    parms.data_len = pkt_len;
    parms.data = raw;
    mul_app_send_pkt_out(NULL, l2sw->swid, &parms);
    mul_app_act_free(&mdata);

    return;
}

#ifdef CONFIG_L2SW_FDB_CACHE
static int
__l2sw_fdb_traverse_all(l2sw_t *l2sw, GHFunc iter_fn, void *arg) 
{
    if (l2sw->l2fdb_htbl) {
        g_hash_table_foreach(l2sw->l2fdb_htbl,
                             (GHFunc)iter_fn, arg);
    }

    return 0;
}

static int 
__l2sw_fdb_del_all_with_inport(l2sw_t *l2sw, uint16_t in_port) 
{
    c_ofp_flow_mod_t            *cofp_fm;
    uint32_t                    wildcards = OFPFW_ALL;
    struct cbuf                 *b;

    b = of_prep_msg(sizeof(*cofp_fm), C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    cofp_fm->datapath_id = htonll(l2sw->swid);
    cofp_fm->command = C_OFPC_DEL;
    cofp_fm->flags = C_FL_ENT_NOCACHE;
    cofp_fm->wildcards = htonl(wildcards);
    cofp_fm->itimeo = htons(L2FDB_ITIMEO_DFL);
    cofp_fm->htimeo = htons(L2FDB_HTIMEO_DFL);
    cofp_fm->buffer_id = (uint32_t)(-1);
    cofp_fm->oport = htons(in_port);

    return mul_app_command_handler(L2SW_APP_NAME, b);
}
#endif

static void
l2sw_core_closed(void)
{
    c_log_info("%s: ", FN);
    return;
}

static void
l2sw_core_reconn(void)
{
    c_log_info("%s: ", FN);
    mul_register_app_cb(NULL, L2SW_APP_NAME,
                        C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &l2sw_app_cbs);
}

struct mul_app_client_cb l2sw_app_cbs = {
    .switch_priv_alloc = l2sw_alloc,
    .switch_priv_free = l2sw_free,
    .switch_add_cb =  l2sw_add,
    .switch_del_cb = l2sw_del,
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = NULL,
    .switch_port_del_cb = NULL,
    .switch_port_link_chg = NULL,
    .switch_port_adm_chg = NULL,
    .switch_packet_in = l2sw_learn_and_fwd,
    .core_conn_closed = l2sw_core_closed,
    .core_conn_reconn = l2sw_core_reconn 
};  

/* Housekeep Timer for app monitoring */
static void
l2sw_main_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                void *arg UNUSED)
{
    struct timeval tv    = { 1 , 0 };
    evtimer_add(l2sw_timer_event, &tv);
}  

void
l2sw_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval    tv = { 1, 0 };

    c_log_debug("%s", FN);

    l2sw_timer_event = evtimer_new(base, l2sw_main_timer, NULL); 
    evtimer_add(l2sw_timer_event, &tv);

    mul_register_app_cb(NULL, L2SW_APP_NAME, 
                        C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &l2sw_app_cbs);

    return;
}


#ifdef CONFIG_L2SW_FDB_CACHE
static void
show_l2sw_fdb_info(void *key UNUSED, void *fdb_arg, void *uarg)
{
    l2fdb_ent_t *fdb = fdb_arg;
    struct vty  *vty = uarg;

    vty_out(vty, "%02x:%02x:%02x:%02x:%02x:%02x %5hu%s", 
            fdb->mac_da[0], fdb->mac_da[1], fdb->mac_da[2],
            fdb->mac_da[3], fdb->mac_da[4], fdb->mac_da[5],
            fdb->lrn_port, VTY_NEWLINE);
}

DEFUN (show_l2sw_fdb,
       show_l2sw_fdb_cmd,
       "show l2-switch X fdb",
       SHOW_STR
       "L2 switches\n"
       "Datapath-id in 0xXXX format\n"
       "Learned Forwarding database\n")
{
    uint64_t        swid;
    mul_switch_t    *sw;
    l2sw_t          *l2sw;

    swid = strtoull(argv[0], NULL, 16);

    sw = c_app_switch_get_with_id(swid);
    if (!sw) {
        vty_out(vty, "No such switch 0x%llx\r\n", U642ULL(swid));
        return CMD_SUCCESS;
    }

    l2sw = MUL_PRIV_SWITCH(sw);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    vty_out (vty, "%8s %18s%s", "mac", "lrn_port", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_rd_lock(&l2sw->lock);
    __l2sw_fdb_traverse_all(l2sw, show_l2sw_fdb_info, vty);
    c_rd_unlock(&l2sw->lock);

    c_app_switch_put(sw);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}
#endif

void
l2sw_module_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
#ifdef CONFIG_L2SW_FDB_CACHE
    install_element(ENABLE_NODE, &show_l2sw_fdb_cmd);
#endif
}

module_init(l2sw_module_init);
module_vty_init(l2sw_module_vty_init);
