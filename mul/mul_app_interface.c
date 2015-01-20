/*
 *  mul_app_interface.c: MUL application interface 
 *  Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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

#include "mul.h"

extern struct c_rlim_dat crl;

#define RETURN_APP_ERR(A, B, R, T, C)  \
do {                                                     \
     c_app_info_t *_app = (void *)A;                     \
     if (_app && (_app->app_flags & C_APP_REMOTE ||      \
         _app->app_flags & C_APP_AUX_REMOTE)) {          \
        if (!R) {                                        \
            c_remote_app_notify_success(A);              \
            return 0;                                    \
        }                                                \
        return c_remote_app_error(A, B, T, C);           \
     } else {                                            \
        return R;                                        \
     }                                                   \
}while(0)

#define RETURN_APP_FL_ERR(A, B, R, T, C, S)  \
do {                                                     \
     c_app_info_t *_app = (void *)A;                     \
    if(S) {                                              \
     if (_app && (_app->app_flags & C_APP_REMOTE ||      \
         _app->app_flags & C_APP_AUX_REMOTE)) {          \
        if (!R) {                                        \
            c_remote_app_notify_success(A);              \
            return 0;                                    \
        }                                                \
        return c_remote_app_error(A, B, T, C);           \
     }                                                   \
    }                                                    \
    return R;                                            \
}while(0)

static void c_switch_app_list_exp(c_switch_t *sw);
static void c_switch_app_list_de_exp(c_switch_t *sw);
static struct cbuf *c_app_dpreg_event_prep(c_switch_t *sw,
                                           void *orig_b UNUSED);
static void c_app_dpreg_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_dpunreg_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_packet_in_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_port_change_event(c_switch_t *sw, void *buf, 
                              c_app_info_t *app, void *priv);
static void c_app_flow_removed_event(c_switch_t *sw, void *buf, 
                              c_app_info_t *app, void *priv);
static void c_app_flow_mod_failed_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_group_mod_failed_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_meter_mod_failed_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_ha_event(c_switch_t *sw, void *buf,
                           c_app_info_t *app, void *priv);
static void c_app_event_blackhole(void *app_arg, void *pkt_arg);
static void __c_sw_fpops_set(c_app_info_t *app, c_switch_t *sw,
                             uint32_t fp_type);
static void c_app_vendor_msg_event(c_switch_t *sw, void *buf, 
                        c_app_info_t *app, void *priv);
static void
c_app_tr_status_event(c_switch_t *sw , void *buf,
               c_app_info_t *app , void *priv);
static int
c_app_worq_tx(void *app_arg, uint64_t dpid, struct cbuf *b);


extern ctrl_hdl_t ctrl_hdl;

struct c_app_handler_op
{
    void (*pre_proc)(c_switch_t *sw);
    void (*app_handler)(c_switch_t *sw, void *buf, 
                        c_app_info_t *app, void *priv);
    void (*post_proc)(c_switch_t *sw);
} c_app_handler_ops[] = {
    { c_switch_app_list_exp, c_app_dpreg_event, NULL }, 
    { NULL, c_app_dpunreg_event, c_switch_app_list_de_exp },
    { NULL, c_app_packet_in_event, NULL },
    { NULL, c_app_port_change_event, NULL },
    { NULL, c_app_flow_removed_event, NULL },
    { NULL, c_app_flow_mod_failed_event, NULL },
    { NULL, c_app_ha_event, NULL },
    { NULL, c_app_vendor_msg_event, NULL },
    { NULL, c_app_tr_status_event, NULL },
    { NULL, c_app_group_mod_failed_event, NULL },
    { NULL, c_app_meter_mod_failed_event, NULL }
};

#define C_APP_OPS_SZ (sizeof(c_app_handler_ops)/sizeof(struct c_app_handler_op))

void
mul_app_free_buf(void *b)
{
    free_cbuf((struct cbuf *)b);
}

static inline c_app_info_t *
__c_app_lookup(ctrl_hdl_t *c_hdl, char *app_name)
{
    c_app_info_t *app;  
    GSList       *iterator = NULL;

    for (iterator = c_hdl->app_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        if (!strncmp(app->app_name, app_name, C_MAX_APP_STRLEN)) { 
            return app;
        }
    }

    return NULL;
}

c_app_info_t *
c_app_get(ctrl_hdl_t *c_hdl, char *app_name)
{
    c_app_info_t *app = NULL;  

    c_rd_lock(&c_hdl->lock);

    if ((app = __c_app_lookup(c_hdl, app_name))) {
        atomic_inc(&app->ref, 1);
    }

    c_rd_unlock(&c_hdl->lock);

    return app;
}

static inline c_app_info_t *
__c_app_get(ctrl_hdl_t *c_hdl, char *app_name)
{
    c_app_info_t *app = NULL;  

    if ((app = __c_app_lookup(c_hdl, app_name))) {
        atomic_inc(&app->ref, 1);
    }

    return app;
}

void
c_app_put(c_app_info_t *app)
{
    if (atomic_read(&app->ref) == 0){
        c_log_err("[APP] |%s| freed", app->app_name);
        free(app);
    } else {
        atomic_dec(&app->ref, 1);
    }

}

c_app_info_t *
c_app_alloc(void *ctx)
{
    c_app_info_t *app = NULL;
    
    app = calloc(1, sizeof(c_app_info_t));
    if (!app) {
        c_log_err("[APP] alloc failed");
        return NULL;
    }

    c_rw_lock_init(&app->app_conn.conn_lock);
    app->ctx = ctx;
    strcpy(app->app_name, "unreg");

    return app;
}

static void
c_per_switch_app_register(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    c_app_info_t *app = arg;

    c_wr_lock(&sw->lock);

    if (g_slist_find(sw->app_list, app)) {
        c_wr_unlock(&sw->lock);
        return;
    }

    atomic_inc(&app->ref, 1);
    sw->app_list = g_slist_append(sw->app_list, app);    
    c_wr_unlock(&sw->lock);
}

static void
__c_per_switch_app_register(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    c_app_info_t *app = arg;

    if (g_slist_find(sw->app_list, app)) {
        return;
    }

    atomic_inc(&app->ref, 1);
    sw->app_list = g_slist_append(sw->app_list, app);    
}

static void
c_per_switch_app_unregister(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    c_app_info_t *app = arg;

    c_wr_lock(&sw->lock);

     __c_per_switch_del_app_flow_owner(sw, app);
    __c_per_switch_del_group_with_owner(sw, app);
    __c_per_switch_del_meter_with_owner(sw, app);


    if (!sw->app_list || !g_slist_find(sw->app_list, app)) {
        c_wr_unlock(&sw->lock);
        return;
    }

    sw->app_list = g_slist_remove(sw->app_list, app);    

    if (app->priv_flags & C_APP_FP_L2 &&
        app == sw->fp_owner) {
        __c_sw_fpops_set(app, sw, C_FP_TYPE_DFL);
    }

    c_wr_unlock(&sw->lock);
    c_app_put(app);
}

static void UNUSED
__c_per_switch_app_unregister(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    c_app_info_t *app = arg;

    sw->app_list = g_slist_remove(sw->app_list, app);    
    c_app_put(app);
}

static void
c_per_app_switch_register(void *arg, void *sw_arg)
{
    c_app_info_t *app = arg;
    c_switch_t   *sw = sw_arg;

    if (!(app->app_flags & C_APP_AUX_REMOTE) &&
        (app->app_flags & C_APP_ALL_SW ||
        g_hash_table_lookup(app->dpid_hlist, &sw->DPID)))  {

       /* TODO - Double check locking */
        __c_per_switch_app_register(sw, NULL, app);
    }
}

static void
c_per_app_switch_unregister(void *arg, void *sw_arg)
{
    c_app_info_t *app = arg;
    c_switch_t   *sw = sw_arg;

    if(!(app->app_flags & C_APP_AUX_REMOTE) &&
       (app->app_flags & C_APP_ALL_SW ||
       g_hash_table_lookup(app->dpid_hlist, &sw->DPID)))  {
        __c_per_switch_app_unregister(sw, NULL, app);
    }
}

static void
c_app_event_q_ent_free(void *ent)
{
    free(ent);
}

static void
c_per_switch_app_replay(void *k, void *v UNUSED, void *arg)
{

    struct c_sw_replay_q_ent *q_ent;
    GSList **app_replay_q =(GSList **)arg;
    struct cbuf *b;
    c_switch_t *sw = k;

    if (!(sw->switch_state & SW_PUBLISHED))
        return;

    b = c_app_dpreg_event_prep(sw, NULL);

    if (!(q_ent = calloc(1, sizeof(struct c_sw_replay_q_ent)))) {
        c_log_err("[APP] q_ent alloc failed");
        return;
    } 
    
    atomic_inc(&sw->ref, 1);
    q_ent->sw = sw;
    q_ent->b = b;
        
    *app_replay_q = g_slist_append(*app_replay_q, q_ent);
}


static void
c_switch_replay_all(ctrl_hdl_t *hdl, void *app_arg)
{                                  
    GSList *iterator;            
    struct c_sw_replay_q_ent *q_ent;
    GSList *app_replay_q = NULL;
    c_app_info_t *app = app_arg;

    c_rd_lock(&hdl->lock);
    
    if (hdl->sw_hash_tbl) {
        g_hash_table_foreach(hdl->sw_hash_tbl,
                             (GHFunc)c_per_switch_app_replay, 
                             (void *)&app_replay_q);
    }       
    c_rd_unlock(&hdl->lock);
                          
    for (iterator = app_replay_q; iterator; iterator = iterator->next) {
        q_ent = iterator->data;
        if ((app->app_flags & C_APP_ALL_SW) || 
            g_hash_table_lookup(app->dpid_hlist, &(q_ent->sw->DPID))) {
            c_signal_app_event(q_ent->sw, q_ent->b, C_DP_REG, app_arg,
                               NULL, false);
            free_cbuf(q_ent->b); /* NOTE */
        }
        c_switch_put(q_ent->sw);
    }

    if (app_replay_q) {
        g_slist_free_full(app_replay_q, c_app_event_q_ent_free);
    }
} 

int
mul_register_app(void *app_arg, char *app_name, uint32_t app_flags, 
                 uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list, 
                 void  (*ev_cb)(void *app_arg, void *pkt_arg))
{
    c_app_info_t *app = app_arg;
    bool         is_remote = app? true:false;
    uint64_t     *dpid;
    c_switch_t   *sw;
    uint32_t     n;
    bool         app_alloc = false;

    if (!app_name) {
        c_log_err("[APP] register fail");
        return -1;
    }

    if (!app) {
        app = calloc(1, sizeof(c_app_info_t));
        if (!app) {
            c_log_err("%s: App alloc failed", FN);
            return -1;
        }
        app_alloc = true;
    }

    c_wr_lock(&ctrl_hdl.lock);
 
    if (__c_app_get(&ctrl_hdl, app_name)) {
        c_wr_unlock(&ctrl_hdl.lock);
        c_log_err("[APP] |%s| exists", app_name);
        if (app_alloc) free(app);
        return -1;
    }

    strncpy(app->app_name, app_name, C_MAX_APP_STRLEN);
    app->app_name[C_MAX_APP_STRLEN-1] = '\0';
    app->app_flags = app_flags;
    if (is_remote) app->app_flags |= C_APP_REMOTE;
    app->ev_mask = ev_mask;
    app->ev_cb = ev_cb?:c_app_event_blackhole;
        
    if (!(app->app_flags & C_APP_ALL_SW)) {

        if (!n_dpid) {
            c_wr_unlock(&ctrl_hdl.lock);
            c_log_err("[APP] %s:%s No dpids given", FN, app->app_name);
            if (app_alloc) free(app);
            return -1;
        }

        /* Registered switch list can be expanded on-demand */
        app->dpid_hlist = g_hash_table_new_full(g_int64_hash,
                                                g_int64_equal, 
                                                NULL,
                                                g_slist_cmn_ent_free); 
        app->n_dpid = n_dpid; 
        for (n = 0; n < n_dpid; n++) {
            dpid = calloc(1, sizeof(uint64_t)); // Optimize ??   
            assert(dpid);

            *dpid = ntohll(dpid_list[n]);
            g_hash_table_insert(app->dpid_hlist, dpid, dpid);

            if ((sw = __c_switch_get(&ctrl_hdl, *dpid))) {
                c_per_switch_app_register(sw, NULL, app);
                c_switch_put(sw);
            }
        }
    } else {
        __c_switch_traverse_all(&ctrl_hdl, c_per_switch_app_register,
                                 app);
    }

    ctrl_hdl.app_list = g_slist_append(ctrl_hdl.app_list, app);
    c_wr_unlock(&ctrl_hdl.lock);

    c_log_debug("[APP] %s registered", app_name);

    return 0;
}

int
mul_unregister_app(char *app_name) 
{
    c_app_info_t *app;

    c_wr_lock(&ctrl_hdl.lock);
 
    if (!(app = __c_app_get(&ctrl_hdl, app_name))) {
        c_wr_unlock(&ctrl_hdl.lock);
        c_log_err("[APP] unreg fail:|%s| unknown app", app_name);
        return -1;
    }

    ctrl_hdl.app_list = g_slist_remove(ctrl_hdl.app_list, app);

    __c_switch_traverse_all(&ctrl_hdl, c_per_switch_app_unregister,
                            app);

    app->priv_flags &= ~C_APP_FP_L2;
    if (app->dpid_hlist) {
        g_hash_table_destroy(app->dpid_hlist);
        app->dpid_hlist = NULL;
        app->n_dpid = 0;
    }
    app->ev_cb = c_app_event_blackhole;

    c_wr_unlock(&ctrl_hdl.lock);

    c_log_debug("[APP] |%s| unregistered", app_name);

    c_app_put(app);

    return 0;
}

static void
c_switch_app_list_exp(c_switch_t *sw)
{
    g_slist_foreach(ctrl_hdl.app_list, 
                    (GFunc)c_per_app_switch_register, sw);
}

static void
c_switch_app_list_de_exp(c_switch_t *sw)
{
    if (sw->app_list) {
        g_slist_foreach(ctrl_hdl.app_list, 
                        (GFunc)c_per_app_switch_unregister, sw);
        g_slist_free(sw->app_list);
    }
}

static void
c_remote_app_event(void *app_arg, void *pkt_arg)
{
    c_app_info_t *app = app_arg;
    return c_thread_tx(&app->app_conn, pkt_arg, false);
}

static int 
c_remote_app_error(void *app_arg, struct cbuf *b,
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
    cofp_em->code = htons(code);

    data = ASSIGN_PTR(cofp_em->data);
    memcpy(data, b->data, data_len);

    c_remote_app_event(app_arg, new_b);

    return 0;
}

static void
c_remote_app_notify_success(void *app_arg)
{
    struct cbuf             *new_b;
    struct c_ofp_auxapp_cmd *cofp_aac;

    new_b = of_prep_msg(sizeof(*cofp_aac), C_OFPT_AUX_CMD, 0);

    cofp_aac = (void *)(new_b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_SUCCESS);

    c_remote_app_event(app_arg, new_b);
    return;
}


static void
c_app_event_blackhole(void *app_arg UNUSED, void *pkt_arg)
{
   free_cbuf(pkt_arg);
}

static inline void
c_app_event_finish(c_switch_t *sw, c_app_info_t *app, void *pkt_arg)
{
    struct c_sw_event_q_ent *ev_q_ent;

    if (app->app_flags & C_APP_REMOTE)  {
        app->ev_cb(app, pkt_arg);
    } else if (sw) {
        ev_q_ent = malloc(sizeof(*ev_q_ent));
        if (unlikely(!ev_q_ent)) return;
        atomic_inc(&app->ref, 1);
        ev_q_ent->app = app;
        ev_q_ent->b = pkt_arg; 
        sw->app_eventq = g_slist_append(sw->app_eventq, ev_q_ent);       
    }
}

static void
c_app_event_send(void *arg, void *u_arg)
{
    struct c_sw_event_q_ent *ev_q_ent = arg;

    if (ev_q_ent->app->app_flags & C_APP_REMOTE) {
        c_log_err("%s: Unknown remote app event queued", FN);
        c_app_put(ev_q_ent->app);
        return;
    }

    ev_q_ent->app->ev_cb(u_arg, ev_q_ent->b);
    c_app_put(ev_q_ent->app);
    free_cbuf(ev_q_ent->b);
}

static inline void
c_switch_app_eventq_send(c_switch_t *sw)
{
    if (!sw) {
        return;
    }

    /* Strategically dont care about locking */
    if (sw->app_eventq) {
        g_slist_foreach(sw->app_eventq,
                        (GFunc)c_app_event_send, sw);
        g_slist_free_full(sw->app_eventq, c_app_event_q_ent_free);
        sw->app_eventq = NULL;
    }
}

static void
c_app_dp_port_reg_prep(void *k UNUSED, void *v, void *arg)
{
    struct c_port *port_info = v;
    struct c_buf_iter_arg *iter_arg = arg;
    struct c_sw_port *port_msg = ASSIGN_PTR(iter_arg->wr_ptr);

    if ((struct c_sw_port *)(iter_arg->wr_ptr) - 
        (struct c_sw_port *)(iter_arg->data) >= iter_arg->max_blocks) {
        c_log_err("%s: [WARN] buf overrun protect", FN);
        return;
    }
    c_sw_port_hton(port_msg, &port_info->sw_port);
    iter_arg->wr_ptr += sizeof(*port_msg);
}

static struct cbuf * 
c_app_dpreg_event_prep(c_switch_t *sw, void *orig_b)
{
    struct cbuf *b;
    struct c_ofp_switch_add *cofp_sa;
    size_t len = sizeof(struct c_ofp_switch_add); 
    uint32_t n_ports;
    struct c_buf_iter_arg iter_arg = { NULL, NULL, 0, 0};

    c_rd_lock(&sw->lock);
    n_ports = g_hash_table_size(sw->sw_ports);
    len += n_ports * sizeof(struct c_sw_port);
    b = of_prep_msg_common(sw->version, len, 
                           C_OFPT_SWITCH_ADD, c_buf_ofp_xid(orig_b));
    cofp_sa = CBUF_DATA(b);

    cofp_sa->datapath_id = htonll(sw->DPID);
    cofp_sa->sw_alias = htonl(sw->alias_id);
    cofp_sa->ver = sw->version;
    cofp_sa->n_buffers = htonl(sw->n_buffers);
    cofp_sa->n_tables = sw->n_tables;
    cofp_sa->capabilities = htonl(sw->capabilities);

    cofp_sa->state = htonll(sw->switch_state);
    cofp_sa->rx_rlim_pps = htonl((uint32_t)(sw->rx_rlim.max));
    cofp_sa->tx_rlim_pps = htonl((uint32_t)(sw->tx_rlim.max));
    cofp_sa->rx_dump_en = sw->rx_dump_en ? 1:0;
    cofp_sa->tx_dump_en = sw->tx_dump_en ? 1:0;
    iter_arg.wr_ptr = ASSIGN_PTR(cofp_sa->ports);
    iter_arg.data = iter_arg.wr_ptr;
    iter_arg.max_blocks = n_ports;
    __c_switch_port_traverse_all(sw, c_app_dp_port_reg_prep, &iter_arg);
    c_rd_unlock(&sw->lock);

    return b;
}

static void
c_app_dpreg_event(c_switch_t *sw, void *b,
                  c_app_info_t *app, void *priv UNUSED)
{
    struct cbuf *new_b;
    uint8_t ver = sw->version;

    switch (ver) {
    case OFP_VERSION:
    case OFP_VERSION_131:
    case OFP_VERSION_140:
        new_b = c_app_dpreg_event_prep(sw, b);
        break;
    default:
        c_log_err("%s: Unsupported Version", FN);
        return;
    }

    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_dpunreg_event(c_switch_t *sw, void *buf UNUSED, 
                    c_app_info_t *app, void *priv UNUSED)
{
    struct cbuf                 *b;
    struct c_ofp_switch_delete  *ofp_sd;  

    b = of_prep_msg_common(sw->version, sizeof(struct c_ofp_switch_delete), 
                           C_OFPT_SWITCH_DELETE, 0);

    ofp_sd = CBUF_DATA(b);
    ofp_sd->datapath_id = htonll(sw->DPID);
    ofp_sd->sw_alias = htonl(sw->alias_id);

    return c_app_event_finish(sw, app, b);
}

static void __fastpath
c_app_packet_in_event(c_switch_t *sw, void *buf,
                      c_app_info_t *app, void *priv)
{
    struct c_pkt_in_mdata *mdata = priv;
    struct cbuf *b = buf, *new_b;
    struct c_ofp_packet_in  *cofp_pin; 
    uint8_t ver;

    assert(b);

    ver = c_buf_ofp_ver(b);
    switch (ver) {
    case OFP_VERSION:
    case OFP_VERSION_131:
    case OFP_VERSION_140:
        break;
    default:
        return;
    }

    new_b = of_prep_msg_common(ver, sizeof(*cofp_pin)+ mdata->pkt_len,
                               C_OFPT_PACKET_IN, c_buf_ofp_xid(b));
    cofp_pin = CBUF_DATA(new_b); 
    cofp_pin->datapath_id = htonll(sw->DPID); 
    cofp_pin->sw_alias = htonl(sw->alias_id);
    cofp_pin->buffer_id = htonl(mdata->buffer_id);
    memcpy(&cofp_pin->fl, mdata->fl, sizeof(struct flow));
    memcpy(cofp_pin->data, INC_PTR8(CBUF_DATA(b), mdata->pkt_ofs),
           mdata->pkt_len);

    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_port_change_event(c_switch_t *sw, void *buf, 
                        c_app_info_t *app, void *priv)
{
    struct c_port_chg_mdata *mdata = priv;
    struct cbuf *b = buf, *new_b;
    struct c_ofp_port_status *cofp_psts; 
    struct c_port_cfg_state_mask *chg_mask = ASSIGN_PTR(mdata->chg_mask);
    uint32_t config_mask = chg_mask ? chg_mask->config_mask : 0;
    uint32_t state_mask = chg_mask ? chg_mask->state_mask : 0;
    uint8_t ver;

    assert(b);

    ver = c_buf_ofp_ver(b);
    switch (ver) {
    case OFP_VERSION:
    case OFP_VERSION_131:
    case OFP_VERSION_140:
        break;
    default:
        return;
    }

    new_b = of_prep_msg_common(ver, sizeof(*cofp_psts), C_OFPT_PORT_STATUS,
                               c_buf_ofp_xid(b));

    cofp_psts = CBUF_DATA(new_b); 
    cofp_psts->datapath_id = htonll(sw->DPID);
    cofp_psts->sw_alias = htonl(sw->alias_id);
    cofp_psts->reason = mdata->reason; 
    cofp_psts->config_mask = htonl(config_mask); 
    cofp_psts->state_mask = htonl(state_mask); 
    c_sw_port_hton(&cofp_psts->desc, mdata->port_desc);

    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_vendor_msg_event(c_switch_t *sw, void *buf, 
                        c_app_info_t *app, void *priv)
{
    struct cbuf *b = buf, *new_b;
    struct c_ofp_vendor_message *cofp_vm; 
    uint8_t ver;
    size_t length = 0;
    struct c_vendor_mdata *mdata = priv;

    assert(b);

    ver = c_buf_ofp_ver(b);
    switch (ver) {
    case OFP_VERSION:
    case OFP_VERSION_131:
    case OFP_VERSION_140:
        break;
    default:
        return;
    }

    length = ntohs(((struct ofp_header *)(b->data))->length);

    if (length < sizeof(struct ofp_vendor_header))
        return;

    new_b = of_prep_msg_common(ver, sizeof(struct c_ofp_vendor_message) +
	    length - sizeof(struct ofp_vendor_header) , C_OFPT_VENDOR_MSG,
                               c_buf_ofp_xid(b));

    cofp_vm = CBUF_DATA(new_b); 
    cofp_vm->datapath_id = htonll(sw->DPID);
    cofp_vm->sw_alias = htonl(sw->alias_id);

    memcpy(cofp_vm->data, INC_PTR8(((struct cbuf*)b->data), mdata->data_ofs),
            mdata->data_len);

    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_flow_removed_event(c_switch_t *sw, void *buf, 
                         c_app_info_t *app, void *priv)
{
    struct cbuf *b = buf, *new_b;
    struct of_flow_mod_params *fl_parms = priv;
    struct ofp_flow_removed *ofm;
    struct c_ofp_flow_removed *cofm;
    uint8_t ver;

    assert(b && priv);

    ver = c_buf_ofp_ver(b);
    switch (ver) {
    case OFP_VERSION:
    case OFP_VERSION_131:
    case OFP_VERSION_140:
        break;
    default:
        return;
    }

    ofm = (void *)(b->data);

    new_b = of_prep_msg_common(ver, sizeof(*cofm), C_OFPT_FLOW_REMOVED, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    cofm = (void *)(new_b->data);
    cofm->datapath_id = htonll(sw->DPID); 
    memcpy(&cofm->flow, &fl_parms->flow, sizeof(struct flow));
    memcpy(&cofm->mask, &fl_parms->mask, sizeof(struct flow));
    cofm->cookie = ofm->cookie;
    cofm->priority = ofm->priority;
    cofm->reason = fl_parms->reason;
    
    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_flow_mod_failed_event(c_switch_t *sw, void *buf,
                            c_app_info_t *app, void *priv)
{
    struct cbuf *b = buf, *new_b;
    struct of_flow_mod_params *fl_parms = priv;
    struct ofp_error_msg *ofp_err;
    c_ofp_error_msg_t *cofp_em;
    c_ofp_flow_mod_t *cofp_fm;
    uint8_t ver;

    assert(b && priv);

    ver = c_buf_ofp_ver(b);
    switch (ver) {
    case OFP_VERSION:
    case OFP_VERSION_131:
    case OFP_VERSION_140:
        break;
    default:
        return;
    }

    ofp_err = (void *)(b->data);
    new_b = of_prep_msg_common(ver, sizeof(*cofp_em) + 
                               sizeof(*cofp_fm),
                               C_OFPT_ERR_MSG, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    cofp_em = CBUF_DATA(new_b);
    cofp_em->type = ofp_err->type;
    cofp_em->code = ofp_err->code;

    cofp_fm = ASSIGN_PTR(cofp_em->data);
    cofp_fm->header.version = ver;
    cofp_fm->header.type = C_OFPT_FLOW_MOD;
    cofp_fm->header.length = htons(sizeof(*cofp_fm));

    cofp_fm->datapath_id = htonll(sw->DPID);
    cofp_fm->sw_alias = htonl(sw->alias_id);
    memcpy(&cofp_fm->flow, fl_parms->flow, sizeof(struct flow));
    memcpy(&cofp_fm->mask, fl_parms->mask, sizeof(struct flow));
    cofp_fm->priority = htons(fl_parms->prio);
    cofp_fm->command = htons(fl_parms->command);
    cofp_fm->cookie = htonl(fl_parms->cookie);
    cofp_fm->seq_cookie = htonl(fl_parms->seq_cookie);

    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_group_mod_failed_event(c_switch_t *sw, void *buf,
                             c_app_info_t *app, void *priv)
{
    struct cbuf *b = buf, *new_b;
    struct of_group_mod_params *g_parms = priv;
    struct ofp_error_msg *ofp_err;
    c_ofp_error_msg_t *cofp_em;
    struct c_ofp_group_mod *cofp_gm;
    uint8_t ver;

    assert(b && priv);

    ver = c_buf_ofp_ver(b);
    switch (ver) {
    case OFP_VERSION:
    case OFP_VERSION_131:
    case OFP_VERSION_140:
        break;
    default:
        return;
    }

    ofp_err = (void *)(b->data);
    new_b = of_prep_msg_common(ver, sizeof(*cofp_em) +
                               sizeof(*cofp_gm),
                               C_OFPT_ERR_MSG, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    cofp_em = CBUF_DATA(new_b);
    cofp_em->type = ofp_err->type;
    cofp_em->code = ofp_err->code;

    cofp_gm = ASSIGN_PTR(cofp_em->data);
    cofp_gm->header.version = ver;
    cofp_gm->header.type = C_OFPT_METER_MOD;
    cofp_gm->header.length = htons(sizeof(*cofp_gm));

    cofp_gm->datapath_id = htonll(sw->DPID);
    cofp_gm->group_id = htonl(g_parms->group);
    cofp_gm->command = g_parms->command;

    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_meter_mod_failed_event(c_switch_t *sw, void *buf,
                             c_app_info_t *app, void *priv)
{
    struct cbuf *b = buf, *new_b;
    struct of_meter_mod_params *m_parms = priv;
    struct ofp_error_msg *ofp_err;
    c_ofp_error_msg_t *cofp_em;
    struct c_ofp_meter_mod *cofp_mm;
    uint8_t ver;

    assert(b && priv);

    ver = c_buf_ofp_ver(b);
    switch (ver) {
    case OFP_VERSION:
    case OFP_VERSION_131:
    case OFP_VERSION_140:
        break;
    default:
        return;
    }

    ofp_err = (void *)(b->data);
    new_b = of_prep_msg_common(ver, sizeof(*cofp_em) + 
                               sizeof(*cofp_mm),
                               C_OFPT_ERR_MSG, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    cofp_em = CBUF_DATA(new_b);
    cofp_em->type = ofp_err->type;
    cofp_em->code = ofp_err->code;

    cofp_mm = ASSIGN_PTR(cofp_em->data);
    cofp_mm->header.version = ver;
    cofp_mm->header.type = C_OFPT_METER_MOD;
    cofp_mm->header.length = htons(sizeof(*cofp_mm));

    cofp_mm->datapath_id = htonll(sw->DPID);
    cofp_mm->meter_id = htonl(m_parms->meter);
    cofp_mm->command = m_parms->command;

    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_ha_event(c_switch_t *sw UNUSED, void *buf,
               c_app_info_t *app UNUSED, void *priv UNUSED)
{
    struct cbuf *b = buf;
    struct cbuf *new_b = buf;

    new_b = cbuf_realloc_headroom(b, 0, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    if (app->app_flags & C_APP_REMOTE)  {
        return c_app_event_finish(NULL, app, new_b);
    }
}

static void
c_app_tr_status_event(c_switch_t *sw UNUSED, void *buf,
               c_app_info_t *app UNUSED, void *priv UNUSED)
{
    struct cbuf *b = buf;
    struct cbuf *new_b = buf;

    new_b = cbuf_realloc_headroom(b, 0, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    if (app->app_flags & C_APP_REMOTE)  {
        return c_app_event_finish(NULL, app, new_b);
    }
}

static inline void
c_process_app_event_loop(c_switch_t *sw, void *b, c_app_event_t event,
                         struct c_app_handler_op *app_op, void *app,
                         void *priv)
{
    c_app_info_t *__app = app;
    GSList *iter = NULL;

    if (__app) {
        if (((1 << event) & __app->ev_mask)) {
            app_op->app_handler(sw, b, __app, priv);
        }
        return;
    } 

    for (iter = sw ? sw->app_list:ctrl_hdl.app_list; iter; iter = iter->next) {
        __app = iter->data;
        if (!((1 << event) & __app->ev_mask)) {
            continue;
        }
        app_op->app_handler(sw, b, __app, priv); 
    }

    return;
}

void __fastpath
c_signal_app_event(c_switch_t *sw, void *b, c_app_event_t event, 
                   void *app_arg, void *priv, bool locked)
{
    struct c_app_handler_op *app_op;

    app_op = &event[c_app_handler_ops];
    prefetch(app_op);

    if (unlikely(event >= C_APP_OPS_SZ)) {
        c_log_err("[APP] |%u| unhandled event", event);
        return;
    }

    switch(event) {
    /*case C_DP_REG:*/
    case C_DP_UNREG:
    case C_PORT_CHANGE:
        /* 
         * NOTE: make sure all these events are called without locks
         * else it will lead to strange deadlocks
         */ 
        assert(!locked);
        c_topo_loop_change_notify(true, C_LOOP_STATE_NONE, false, false);
    default:
        break;
    }
    
    if (!locked) {
        c_sw_hier_rdlock(sw);
    }

    if (app_op->pre_proc) app_op->pre_proc(sw);
    c_process_app_event_loop(sw, b, event, app_op, app_arg, priv);
    if (app_op->post_proc) app_op->post_proc(sw);

    if (!locked) {
        c_sw_hier_unlock(sw);
    }

    c_switch_app_eventq_send(sw); 

    return;
}

static int  __fastpath
c_app_flow_mod_wrk_command(void *app_arg, struct cbuf *b, void *data)
{
    c_switch_t *sw;
    c_app_info_t *app = app_arg;
    struct c_ofp_flow_mod *cofp_fm = data;
    struct ofp_inst_check_args inst_args;
    struct of_flow_mod_params fl_parms;
    uint64_t flags = 0;
    int ret = -1;
    uint32_t code = OFPFMFC_GENERIC;
    size_t action_len = ntohs(cofp_fm->header.length) -
                        sizeof(*cofp_fm);
    int table_id;
    bool send_app_ack = true;

#if 0
    if (ntohs(cofp_fm->header.length) < sizeof(c_ofp_flow_mod_t)) {
        if (!c_rlim(&crl))
            c_log_err("%s:cmd(%u) err %u of %lu", FN, C_OFPT_FLOW_MOD,
                      ntohs(cofp_fm->header.length),
                      (unsigned long)sizeof(c_ofp_flow_mod_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED, OFPBRC_BAD_LEN);
    }
#endif

    memset(&fl_parms, 0, sizeof(fl_parms));
    flags = ntohll(cofp_fm->flags);

    if (flags & C_FL_NO_ACK) {
        send_app_ack = false;
    }

    if (!(flags & C_FL_ENT_LOCAL) &&
        !(flags & C_FL_ENT_RESIDUAL) &&
        of_check_flow_wildcard_generic(&cofp_fm->flow, &cofp_fm->mask)) {
        /* Don't allow all wildcards */
        if (!c_rlim(&crl))
            c_log_err("%s: All wildcard flow-mod not allowed", FN);
        RETURN_APP_FL_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED,
                OFPFMFC_BAD_FLAG, send_app_ack);
    }


    if (flags & C_FL_ENT_SWALIAS) {
        sw = c_switch_alias_get(&ctrl_hdl, (int)(ntohl(cofp_fm->sw_alias)));
    } else {
        sw = c_switch_get(&ctrl_hdl, ntohll(cofp_fm->DPID));
    }

    if (!sw) {
        if (!c_rlim(&crl))
            c_log_err("%s: invalid switch:dpid(0x%llx) alias(%d)", FN,
                  (unsigned long long)ntohll(cofp_fm->DPID),
                  (int)(ntohl(cofp_fm->sw_alias)));
        RETURN_APP_FL_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED,
                OFPBRC_BAD_DPID, send_app_ack);
    }

    if (!app ||
        app->app_flags & C_APP_AUX_REMOTE) {
        app = c_app_get(&ctrl_hdl, C_VTY_NAME);
        if (!app) {
            /* This condition should never occur */
            c_log_err("%s: %s app not found", FN, C_VTY_NAME);
            app = app_arg;
        }
    }

    if (flags & C_FL_ENT_NOCACHE && 
        flags & (C_FL_ENT_LOCAL | C_FL_ENT_CLONE)) {
        if (!c_rlim(&crl))
            c_log_err("[FLOW] %s: Invalid flags", FN);
        RETURN_APP_FL_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED, 
                       OFPFMFC_BAD_FLAG, send_app_ack); 
    }

    if (sw->ofp_ctors->normalize_flow) {
        ret = sw->ofp_ctors->normalize_flow(&cofp_fm->flow, &cofp_fm->mask);
        if (ret < 0) {
            if (!c_rlim(&crl))
                c_log_err("[FLOW] %s:normalize err", FN);
            RETURN_APP_FL_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED, 
                           OFPFMFC_BAD_COMMAND, send_app_ack); 
        }
    }

    table_id = cofp_fm->flow.table_id;
    if (!(flags & C_FL_ENT_TBL_PHYS))  {
        table_id = of_switch_get_v2p_tbl(sw, table_id);
        cofp_fm->flow.table_id = table_id;
    }
    memset(&inst_args, 0, sizeof(inst_args));
    inst_args.tbl_prop = sw->rule_flow_tbls[table_id].props;
    inst_args.check_setf_supp = false;
    inst_args.sw_ctx = sw;
    inst_args.check_port = of_switch_port_validate_cb;
    inst_args.check_add_group = c_of_fl_group_check_add;
    inst_args.check_add_meter = c_of_fl_meter_check_add;
    inst_args.get_v2p_tbl = of_switch_get_v2p_tbl;

#ifdef MUL_FLOW_DEBUG
    if (1) {
        char *str = of_dump_flow_generic(&cofp_fm->flow, &cofp_fm->mask);
        c_log_err("[FLOW] switch |0x%llx|:Flow-%s |%s|",
              U642ULL(sw->DPID),
              cofp_fm->command == C_OFPC_ADD ? "Add" :"Del",
              str); 
        free(str);
    }
#endif

loop_mtable:
    if (!sw->debug_flag &&
        (!of_switch_port_valid(sw, &cofp_fm->flow, &cofp_fm->mask) ||
        !of_switch_table_valid(sw, table_id) ||
        (cofp_fm->command == C_OFPC_ADD && 
         sw->ofp_ctors && sw->ofp_ctors->validate_acts &&
         sw->ofp_ctors->validate_acts(&cofp_fm->flow, &cofp_fm->mask,
                                      cofp_fm->actions, action_len,
                                      false, &inst_args)))) {
        ret = -1;
        c_switch_put(sw);
        if (!c_rlim(&crl)) {
            char *str; 
            str = of_dump_flow_generic(&cofp_fm->flow, &cofp_fm->mask);
            c_log_err("[FLOW] %s:Invalid actions/in-port/table|0x%llx|%s",
                      FN, U642ULL(sw->DPID), str?:"");
            if (str) free(str);
            if (sw->ofp_ctors && sw->ofp_ctors->dump_acts) {
                str = sw->ofp_ctors->dump_acts(cofp_fm->actions,
                                               action_len, false); 
                if (str) {
                    c_log_err("Actions: %s", str);
                    free(str);
                }
            }
                
        }
        RETURN_APP_FL_ERR(app_arg, b, ret,
                       OFPET_FLOW_MOD_FAILED, OFPBAC_BAD_GENERIC,
                       send_app_ack); 
    }

    fl_parms.app_owner = app;
    fl_parms.flow = &cofp_fm->flow;
    fl_parms.mask = &cofp_fm->mask;
    fl_parms.action_len = action_len;
    fl_parms.wildcards = cofp_fm->wildcards;
    fl_parms.buffer_id = ntohl(cofp_fm->buffer_id);
    fl_parms.flags = flags | C_FL_ENT_TBL_PHYS;
    fl_parms.prio = ntohs(cofp_fm->priority);
    fl_parms.itimeo = ntohs(cofp_fm->itimeo); 
    fl_parms.htimeo = ntohs(cofp_fm->htimeo); 
    fl_parms.oport = ntohl(cofp_fm->oport);
    fl_parms.ogroup = ntohl(cofp_fm->ogroup);
    fl_parms.cookie = ntohl(cofp_fm->cookie);
    fl_parms.seq_cookie = ntohl(cofp_fm->seq_cookie);
    fl_parms.grp_dep = inst_args.grp_list;
    fl_parms.meter_dep = inst_args.meter_list;
    
    if (action_len) {
        fl_parms.actions = malloc(action_len);
        if (!fl_parms.actions) {
            RETURN_APP_FL_ERR(app_arg, b, -1, OFPET_FLOW_MOD_FAILED,
                           code, send_app_ack);
        }
    }

    memcpy(fl_parms.actions, cofp_fm->actions, action_len);

    if (cofp_fm->command == C_OFPC_ADD) {
        ret = flags & C_FL_ENT_NOCACHE ? 
            of_send_flow_add_direct(sw, fl_parms.flow, fl_parms.mask,
                                     fl_parms.buffer_id,
                                     fl_parms.actions, fl_parms.action_len,
                                     fl_parms.itimeo, fl_parms.htimeo, 
                                     fl_parms.prio) : 
            c_switch_flow_add(sw, &fl_parms);
        if (ret == -EEXIST) code = OFPFMFC_FLOW_EXIST;
    } else /* if (cofp_fm->command == C_OFPC_DEL)*/ { 
        ret = flags & C_FL_ENT_NOCACHE ? 
            of_send_flow_del_direct(sw, fl_parms.flow, fl_parms.mask,
                                    fl_parms.oport, false, 
                                    fl_parms.prio, fl_parms.ogroup) :  
            c_switch_flow_del(sw, &fl_parms);
    } 

    if ((flags & C_FL_ENT_STATIC ||
        flags & C_FL_ENT_RESIDUAL) &&
        !(flags & C_FL_ENT_NOCACHE) && !ret) {
        c_ha_proc(b);
    }

    c_thread_sg_tx_sync(&sw->conn);

    if (inst_args.grp_list) 
        g_slist_free_full(inst_args.grp_list, g_slist_cmn_ent_free);

    if (inst_args.meter_list) 
        g_slist_free_full(inst_args.meter_list, g_slist_cmn_ent_free);

    if (flags & C_FL_ENT_NOCACHE && fl_parms.actions)
       free(fl_parms.actions); 

    if (!ret &&
        flags & C_FL_ENT_LOCAL &&
        sw->ofp_ctors && sw->ofp_ctors->multi_table_support) {
        while(++table_id < C_MAX_RULE_FLOW_TBLS) {
            if (of_switch_table_valid(sw, table_id)) {
                cofp_fm->flow.table_id = table_id;
                goto loop_mtable;
            }
        }
    }

    c_switch_put(sw);
    if (app != app_arg) {
        c_app_put(app);
    } 
    RETURN_APP_FL_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED, code, send_app_ack); 
}

static int  __fastpath
c_app_flow_mod_command(void *app_arg, struct cbuf *b, void *data)
{
    c_app_info_t *app = app_arg;
    struct c_ofp_flow_mod *cofp_fm = data;
    struct of_flow_mod_params fl_parms;
    uint64_t flags = 0;
    int ret = -1;
    assert(app);

    if (ntohs(cofp_fm->header.length) < sizeof(c_ofp_flow_mod_t)) {
        if (!c_rlim(&crl))
            c_log_err("%s:cmd(%u) err %u of %lu", FN, C_OFPT_FLOW_MOD,
                      ntohs(cofp_fm->header.length),
                      (unsigned long)sizeof(c_ofp_flow_mod_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED, OFPBRC_BAD_LEN);
    }

    memset(&fl_parms, 0, sizeof(fl_parms));
    flags = ntohll(cofp_fm->flags);

    if (flags & C_FL_NO_ACK) {
        if ((ret = c_app_worq_tx(app_arg,
                                 ntohll(cofp_fm->datapath_id), b) <= 0)) {
            RETURN_APP_FL_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED,
                           OFPFMFC_BAD_FLAG, false);
        }
    }

    return c_app_flow_mod_wrk_command(app_arg, b, data);
} 

static int
c_app_group_mod_command(void *app_arg, struct cbuf *b, void *data)
{
    c_switch_t *sw = NULL;
    c_app_info_t *app = app_arg;
    struct c_ofp_group_mod *cofp_gm = data;
    struct of_group_mod_params g_parms;
    struct of_act_vec_elem *act_elem;
    uint16_t rcode = OFPGMFC131_INVALID_GROUP;
    int ret = -1, act = 0;
    ssize_t tot_len = ntohs(cofp_gm->header.length);
    size_t act_len = 0, bkt_dist = 0;
    struct c_ofp_bkt *bkt;
    bool add;
    struct ofp_inst_check_args inst_args;

    assert(app);

    if (tot_len < sizeof(*cofp_gm)) {
        c_log_err("%s:cmd(%u) size err %u of %lu", FN, C_OFPT_GROUP_MOD,
                   ntohs(cofp_gm->header.length),
                   (unsigned long)sizeof(*cofp_gm));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);  
    }

    memset(&g_parms, 0, sizeof(g_parms));

    if (cofp_gm->command == C_OFPG_ADD) {
        add = true;
    } else if (cofp_gm->command == C_OFPG_DEL) {
        add = false;
    } else {
        goto err_out;
    }

    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_gm->DPID));
    if (!sw) {
        if (!c_rlim(&crl))
            c_log_err("%s: Invalid switch:dpid(0x%llx)", FN,
                  U642ULL(ntohll(cofp_gm->DPID)));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);  
    }

    if (app->app_flags & C_APP_AUX_REMOTE) {
        app = c_app_get(&ctrl_hdl, C_VTY_NAME);
        if (!app) {
            /* This condition should never occur */
            c_log_err("%s: %s app not found", FN, C_VTY_NAME);
            app = app_arg;
        }
    }

    g_parms.app_owner = app;
    g_parms.group = ntohl(cofp_gm->group_id);
    g_parms.type = cofp_gm->type;
    g_parms.flags = cofp_gm->flags;

    tot_len -= sizeof(*cofp_gm);
    bkt_dist = sizeof(*cofp_gm);

    while(tot_len >= (int)sizeof(*bkt) && act < OF_MAX_ACT_VECTORS) {
        bkt = INC_PTR8(cofp_gm, bkt_dist);
        act_len = ntohs(bkt->act_len);
        bkt_dist += sizeof(*bkt) + act_len;

        if (act_len > (tot_len - sizeof(*bkt))) {
            ret = -1;
            goto err_out;
        }

        act_elem = calloc(1, sizeof(*act_elem));
        if (!act_elem) goto err_out;
        act_elem->actions = calloc(1, act_len);
        if (!act_elem->actions) goto err_out;
        memcpy(act_elem->actions, bkt->actions, act_len);
        act_elem->action_len = act_len;
        act_elem->weight = ntohs(bkt->weight);
        act_elem->ff_port = ntohl(bkt->ff_port);
        act_elem->ff_group = ntohl(bkt->ff_group);
        g_parms.act_vectors[act] = act_elem;
        g_parms.act_vec_len++;

        tot_len -= act_len + sizeof(*bkt);
        act++;

        memset(&inst_args, 0, sizeof(inst_args));
        inst_args.check_setf_supp = false;
        inst_args.sw_ctx = sw;
        inst_args.check_port = of_switch_port_validate_cb;
        if (sw->ofp_ctors && sw->ofp_ctors->validate_acts &&
            sw->ofp_ctors->validate_acts(NULL, NULL,
                                      act_elem->actions, act_elem->action_len,
                                      true, &inst_args)) {
            ret = -1;
            goto err_out;
        }
        if (inst_args.inst_local) {
            g_parms.flags |= C_GRP_LOCAL;    
        }

    }

    if (add) {
        if (!sw->debug_flag && sw->ofp_ctors &&
            sw->ofp_ctors->group_validate_feat &&
            (ret = sw->ofp_ctors->group_validate_feat(&g_parms,
                                                      sw->group_features))) {
            goto err_out;
        }

        ret = c_switch_group_add(sw, &g_parms);
        if (ret) {
            if (ret == -EEXIST) rcode = OFPGMFC131_GROUP_EXISTS;
            goto err_out;
        }
    } else {
        ret = c_switch_group_del(sw, &g_parms);
    }

    if ((cofp_gm->flags & C_GRP_STATIC ||
        cofp_gm->flags & C_GRP_RESIDUAL) && !ret) {
        c_ha_proc(b);
    }

    c_thread_sg_tx_sync(&sw->conn);

out:
    if (sw) c_switch_put(sw);
    if (app != app_arg) {
        c_app_put(app);
    }

    RETURN_APP_ERR(app_arg, b, ret, OFPET131_GROUP_MOD_FAILED, rcode); 

err_out:
    for (act = 0; act < g_parms.act_vec_len; act++) {
        act_elem = g_parms.act_vectors[act];
        if (act_elem) {
            if (act_elem->actions) {
                free(act_elem->actions);
            }
            free(act_elem);
        }
    }
    goto out;
}

static int
c_app_meter_mod_command(void *app_arg, struct cbuf *b, void *data)
{
    c_switch_t *sw = NULL;
    c_app_info_t *app = app_arg;
    struct c_ofp_meter_mod *cofp_mm = data;
    struct of_meter_mod_params m_parms;
    struct of_meter_band_elem *band_elem;
    uint16_t rcode = OFPMMFC_INVALID_METER;
    int ret = -1, nband = 0;
    ssize_t tot_len = ntohs(cofp_mm->header.length);
    struct ofp_meter_band_header *band_hdr;
    size_t band_len = 0, bkt_dist = 0;
    bool add;

    assert(app);

    if (tot_len < sizeof(*cofp_mm)) {
        c_log_err("%s:cmd(%u) size err %u of %lu", FN, C_OFPT_GROUP_MOD,
                   ntohs(cofp_mm->header.length),
                   (unsigned long)sizeof(*cofp_mm));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);  
    }

    memset(&m_parms, 0, sizeof(m_parms));

    if (cofp_mm->command == C_OFPMC_ADD) {
        add = true;
    } else if (cofp_mm->command == C_OFPMC_DEL) {
        add = false;
    } else {
        goto err_out;
    }

    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_mm->DPID));
    if (!sw) {
        if (!c_rlim(&crl))
            c_log_err("%s: Invalid switch:dpid(0x%llx)", FN,
                  U642ULL(ntohll(cofp_mm->DPID)));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);  
    }

    if (app->app_flags & C_APP_AUX_REMOTE) {
        app = c_app_get(&ctrl_hdl, C_VTY_NAME);
        if (!app) {
            /* This condition should never occur */
            c_log_err("%s: %s app not found", FN, C_VTY_NAME);
            app = app_arg;
        }
    }

    m_parms.app_owner = app;
    m_parms.meter = ntohl(cofp_mm->meter_id);
    m_parms.flags = ntohs(cofp_mm->flags);
    m_parms.cflags = cofp_mm->c_flags;

    tot_len -= sizeof(*cofp_mm);
    bkt_dist = sizeof(*cofp_mm);

    while(tot_len >= (int)sizeof(struct ofp_meter_band_header) &&
          nband < OF_MAX_METER_VECTORS) {
        band_hdr = INC_PTR8(cofp_mm, bkt_dist);
        band_len = ntohs(band_hdr->len);
        bkt_dist += band_len;

        if (band_len > tot_len) {
            ret = -1;
            goto err_out;
        }

        band_elem = calloc(1, sizeof(*band_elem));
        if (!band_elem) {
            ret = -1;
            goto err_out;
        }
        band_elem->band = calloc(1, band_len);
        if (!band_elem->band) {
             ret = -1;
            goto err_out;
        }
        assert(band_elem->band);
        memcpy(band_elem->band, band_hdr, band_len);
        band_elem->band_len = band_len;
        m_parms.meter_bands[nband] = band_elem;
        m_parms.meter_nbands++;

        tot_len -= band_len;
        nband++;
    }

    if (add) {
        if (!sw->debug_flag && sw->ofp_ctors &&
            sw->ofp_ctors->meter_validate_feat &&
            (ret = sw->ofp_ctors->meter_validate_feat(&m_parms,
                                                      sw->meter_features))) {
            goto err_out;
        }

        ret = c_switch_meter_add(sw, &m_parms);
        if (ret) {
            if (ret == -EEXIST) rcode = OFPMMFC_METER_EXISTS;
            goto err_out;
        }
    } else {
        ret = c_switch_meter_del(sw, &m_parms);
    }

    if ((cofp_mm->c_flags & C_METER_STATIC ||
        cofp_mm->c_flags & C_METER_RESIDUAL) && !ret) {
        c_ha_proc(b);
    }

    c_thread_sg_tx_sync(&sw->conn);

out:
    if (sw) c_switch_put(sw);
    if (app != app_arg) {
        c_app_put(app);
    }

    RETURN_APP_ERR(app_arg, b, ret, OFPET131_METER_MOD_FAILED, rcode); 

err_out:
    for (nband = 0; nband < m_parms.meter_nbands; nband++) {
        band_elem = m_parms.meter_bands[nband];
        if (band_elem) {
            if (band_elem->band) {
                free(band_elem->band);
            }
            free(band_elem);
        }
    }
    goto out;
}
 
 
int __fastpath
mul_app_send_flow_add(void *app_name, void *sw_arg, uint64_t dpid, 
                      struct flow *fl, struct flow *fl_mask,
                      uint32_t buffer_id, void *actions,
                      size_t action_len, uint16_t itimeo,
                      uint16_t htimeo, uint16_t prio, uint64_t flags)  
{
    c_switch_t *sw = sw_arg;
    struct of_flow_mod_params fl_parms;
    c_app_info_t *app;
    int ret = 0;

    if (sw == NULL) {
        if (!( sw = c_switch_get(&ctrl_hdl, dpid))) {
            return -EINVAL;
        }
    } else {
        atomic_inc(&sw->ref, 1);
    }

    if (flags & C_FL_ENT_NOCACHE) {
        ret = of_send_flow_add_direct(sw, fl, fl_mask, buffer_id, actions,
                                      action_len, itimeo, htimeo, prio);
        c_switch_put(sw);
        return ret;
    }

    app = c_app_get(&ctrl_hdl, (char *)app_name);
    if (!app) {
        c_switch_put(sw);
        return -EINVAL;
    }

    memset(&fl_parms, 0, sizeof(fl_parms));
    fl_parms.app_owner = app;
    fl_parms.flow = fl;
    fl_parms.mask = fl_mask;
    fl_parms.wildcards = 0;
    fl_parms.buffer_id = buffer_id;
    fl_parms.flags = flags;
    fl_parms.prio = prio;
    fl_parms.itimeo = itimeo;
    fl_parms.htimeo = htimeo;
    fl_parms.actions = actions;
    fl_parms.action_len = action_len;

    ret = c_switch_flow_add(sw, &fl_parms);

    c_app_put(app);
    c_switch_put(sw);

    return ret;
}

int __fastpath
mul_app_send_flow_del(void *app_name, void *sw_arg, uint64_t dpid, 
                      struct flow *fl,  struct flow *mask, uint32_t oport,
                      uint16_t prio, uint64_t flags, uint32_t ogroup)
{
    c_switch_t *sw = sw_arg;
    struct of_flow_mod_params fl_parms;
    c_app_info_t *app;
    int ret = 0;

    if (sw == NULL) {
        if (!( sw = c_switch_get(&ctrl_hdl, dpid))) {
            return -EINVAL;
        }
    } else {
        atomic_inc(&sw->ref, 1);
    }

    if (flags & C_FL_ENT_NOCACHE) {
        ret = of_send_flow_del_direct(sw, fl, mask, oport, false, prio, ogroup);
        c_switch_put(sw);
        return ret;    
    }

    app = c_app_get(&ctrl_hdl, (char *)app_name);
    if (!app) {
        c_switch_put(sw);
        return -EINVAL;
    }

    memset(&fl_parms, 0, sizeof(fl_parms));
    fl_parms.app_owner = app;
    fl_parms.flow = fl;
    fl_parms.mask = mask;
    fl_parms.wildcards = 0;
    fl_parms.flags = flags;
    fl_parms.oport = oport;
    fl_parms.ogroup = ogroup;
    fl_parms.prio = htons(prio);;

    ret = c_switch_flow_del(sw, &fl_parms);

    c_app_put(app);
    c_switch_put(sw);

    return ret;
}

static int  __fastpath
c_app_packet_out_command(void *app_arg, struct cbuf *b, void *data)
{
    c_switch_t  *sw;
    struct of_pkt_out_params parms;
    struct c_ofp_packet_out *cofp_po = data;
    uint16_t pkt_len = ntohs(cofp_po->header.length);
    int ret = -1;

    if (unlikely(pkt_len < sizeof(c_ofp_packet_out_t))) {
        c_log_err("%s:Cmd(%u) Size err %hu of %lu", FN, C_OFPT_PACKET_OUT,
                  pkt_len, (unsigned long)sizeof(c_ofp_packet_out_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);  
    }

    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_po->DPID));
    if (unlikely(!sw)) {
        //c_log_err("%s: Invalid switch-dpid(0x%llx)", FN,
        //          (unsigned long long)ntohll(cofp_po->DPID));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);  
    }

    /* FIXME : Allow lldp */
    if (sw->tx_lim_on && c_rlim(&sw->tx_rlim)) {
        sw->tx_pkt_out_dropped++;
        c_switch_put(sw);
        return 0;
    }

    parms.action_len = ntohs(cofp_po->actions_len);
    if (unlikely(pkt_len < (sizeof(*cofp_po)+parms.action_len))) {
        c_log_err("%s:Cmd(%u) Data sz err (%hu:%lu)", FN,
                  C_OFPT_PACKET_OUT, pkt_len,
                  (unsigned long)sizeof(*cofp_po) + parms.action_len);
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_ACTION, OFPBAC_BAD_LEN);  
    }

    parms.buffer_id = ntohl(cofp_po->buffer_id);
    parms.in_port = ntohl(cofp_po->in_port);
    parms.action_list = cofp_po->actions;

    parms.data_len = pkt_len - (sizeof(*cofp_po)+parms.action_len);
    parms.data = (void *)((uint8_t *)(cofp_po + 1) +
                                      parms.action_len);

    of_send_pkt_out(sw, &parms);
    c_thread_sg_tx_sync(&sw->conn);

    c_switch_put(sw);

    return 0;
}

void __fastpath
mul_app_send_pkt_out(void *sw_arg, uint64_t dpid, void *parms_arg)
{
    c_switch_t *sw = sw_arg;
    struct of_pkt_out_params *parms = parms_arg;
    
    if (sw == NULL) {
        if (!(sw = c_switch_get(&ctrl_hdl, dpid))) {
            return;
        }
    } else {
        atomic_inc(&sw->ref, 1);
    }

    of_send_pkt_out(sw, parms);

    c_switch_put(sw);

    return;

}

static int
c_app_port_mod_command(void *app_arg, struct cbuf *b, void *data)
{
    c_switch_t *sw = NULL;
    struct of_port_mod_params pm_parms;
    struct c_ofp_port_mod *cofp_pm = data;
    ssize_t tot_len = ntohs(cofp_pm->header.length);
    int ret = -1;
    c_port_t *port UNUSED;
    uint32_t new_config = 0;
    
    if (tot_len < sizeof(*cofp_pm)) {
        c_log_err("%s:cmd(%u) size err %u of %lu", FN, C_OFPT_PORT_MOD,
                   ntohs(cofp_pm->header.length),
                   (unsigned long)sizeof(*cofp_pm));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);  
    }

    memset(&pm_parms, 0, sizeof(pm_parms));

    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_pm->DPID));
    if (!sw) {
        if (!c_rlim(&crl))
            c_log_err("%s: Invalid switch:dpid(0x%llx)", FN,
                  U642ULL(ntohll(cofp_pm->DPID)));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);  
    }

    pm_parms.port_no = ntohl(cofp_pm->port_no);
    pm_parms.config = ntohl(cofp_pm->config);
    pm_parms.mask = ntohl(cofp_pm->mask);

    ret = c_switch_port_mod(sw, &pm_parms);
    c_thread_sg_tx_sync(&sw->conn);

    if (ret || !ctrl_hdl.loop_en) goto out;

    c_wr_lock(&sw->lock);
    port = __c_switch_port_find(sw, pm_parms.port_no);
    if(!port) {
        if (!c_rlim(&crl)) {
            c_log_err("%s: No such port %lu on |0x%llx|", FN,
                      U322UL(pm_parms.port_no), U642ULL(sw->DPID));
        }
        c_wr_unlock(&sw->lock);
        ret = -1;
        goto out;
    }

    new_config = port->sw_port.of_config & ~pm_parms.mask;
    new_config |= pm_parms.config;

    if (new_config == port->sw_port.of_config) {
        c_wr_unlock(&sw->lock);
        goto  out;
    }

    port->sw_port.of_config = new_config;
    /* if (sw->fp_ops.fp_topo_change) {
        c_log_err("%s: DPID 0x%llx L2 fdb refreshed", FN, sw->DPID);
        sw->fp_ops.fp_topo_change(sw, status, true);
    } */

    c_wr_unlock(&sw->lock);

    /* Get updated port flags from switch */
    if (sw->ofp_priv_procs && sw->ofp_priv_procs->refresh_ports) {
        sw->ofp_priv_procs->refresh_ports(sw);
    }

out:
    if (sw) c_switch_put(sw);

    RETURN_APP_ERR(app_arg, b, ret, OFPET131_METER_MOD_FAILED, OFPFMFC_GENERIC); 
}

static struct cbuf *
c_prep_tr_status(uint64_t status) 
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_tr_status_mod *cofp_trsm;
    size_t tot_len = 0;

    tot_len = sizeof(*cofp_trsm) + sizeof(*cofp_aac);

    b = of_prep_msg(tot_len, C_OFPT_AUX_CMD, 0);

    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code =  htonl(C_AUX_CMD_MUL_TR_STATUS);

    cofp_trsm = ASSIGN_PTR(cofp_aac->data);

    cofp_trsm->tr_status = htonll(status);
    
    return b;
}

static void
c_tr_notify(ctrl_hdl_t *c_hdl, void *app)
{
    struct cbuf *b = c_prep_tr_status(c_hdl->tr_status);

    c_signal_app_event(NULL, b, C_TR_STATUS, app, NULL, false);
    free_cbuf(b);
}

static void
c_app_per_flow_stale(void *arg, c_fl_entry_t *ent)
{
    uint32_t app_cookie = *(uint32_t *)arg;

    c_wr_lock(&ent->FL_LOCK);
    if (ent->FL_FLAGS & C_FL_ENT_STATIC ||
        ent->FL_FLAGS & C_FL_ENT_LOCAL) {
        c_wr_unlock(&ent->FL_LOCK);
        return;
    }

    if ((uint32_t)(ent->FL_COOKIE >> 32) == app_cookie) { 
        ent->stale_time = time(NULL);
        ent->FL_FLAGS |= C_FL_ENT_STALE;
        ent->fl_stats.last_scan = 0; 
#ifdef MUL_FLOW_DEBUG
        if (1) {
            char *str = of_dump_flow_generic(&ent->fl, &ent->fl_mask);
            c_log_err("[FLOW] switch |0x%llx|:marked stale %lus %s |%s|",
                  U642ULL(ent->sw->DPID),
                  ent->stale_time,
                  ent->FL_FLAGS & C_FL_ENT_STALE ? "stale":"",
                  str);
            free(str);
        }
#endif
    }

    c_wr_unlock(&ent->FL_LOCK);
}

static void
c_app_per_group_stale(void *arg, c_switch_group_t *grp)
{
    uint32_t app_cookie = *(uint32_t *)arg;

    if ((uint32_t)((grp->group >> 16) & 0xffff) == app_cookie) { 
        if (!(grp->flags & C_GRP_STALE)) {
            grp->stale_time = time(NULL);
            grp->flags |= C_GRP_STALE;
            grp->last_scan = 0; 
#ifdef MUL_FLOW_DEBUG
            c_log_err("[GROUP] switch |0x%llx|:|%lu| %s %lu stale marked",
                      U642ULL(grp->sw->DPID), U322UL(grp->group),
                      grp->flags & C_GRP_STALE ? "stale":"",
                      grp->stale_time);
#endif

        }
    }
}

static void
c_app_per_meter_stale(void *arg, c_switch_meter_t *m)
{
    uint32_t app_cookie = *(uint32_t *)arg;

    if ((uint32_t)((m->meter >> 16) & 0xffff) == app_cookie) { 
        if (!(m->flags & C_METER_STALE)) {
            m->stale_time = time(NULL);
            m->flags |= C_METER_STALE;
            m->last_scan = 0;
        }
    }
}

static void
c_app_per_switch_elem_stale(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;

    c_flow_traverse_tbl_all(sw, arg, c_app_per_flow_stale);
    c_switch_group_traverse_all(sw, arg, c_app_per_group_stale);
    c_switch_meter_traverse_all(sw, arg, c_app_per_meter_stale);
}

static int 
c_app_register_app_command(void *app_arg, struct cbuf *b, void *data)
{
    int  i;
    uint32_t app_cookie;
    struct c_ofp_register_app *cofp_ra = data;
    c_app_info_t *app = app_arg;
    int ret = -1;

    if (ntohs(cofp_ra->header.length) < sizeof(c_ofp_register_app_t)) {
        c_log_err("%s:Cmd(%u) Size err %u of %lu", FN, C_OFPT_REG_APP,
                   ntohs(cofp_ra->header.length),
                   (unsigned long)sizeof(c_ofp_register_app_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    } 

    cofp_ra->app_flags = ntohl(cofp_ra->app_flags);
    cofp_ra->ev_mask = ntohl(cofp_ra->ev_mask);
    cofp_ra->dpid = ntohl(cofp_ra->dpid);

    app_cookie = ntohl(cofp_ra->app_cookie);

    if (ntohs(cofp_ra->header.length) <
            sizeof(c_ofp_register_app_t) +
            (cofp_ra->dpid * sizeof(cofp_ra->dpid))) {
        c_log_err("%s:Cmd(%u) Size err %u of %lu", FN, C_OFPT_REG_APP,
                   ntohs(cofp_ra->header.length),
                   (unsigned long)sizeof(c_ofp_register_app_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    } 
    

    for (i = 0; i < cofp_ra->dpid; i++) {
        cofp_ra->dpid_list[i] = ntohll(cofp_ra->dpid_list[i]);
    } 

    ret = mul_register_app(app, cofp_ra->app_name, cofp_ra->app_flags,
                           cofp_ra->ev_mask, cofp_ra->dpid,
                           cofp_ra->dpid_list, c_remote_app_event);
    if (ret) {
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, 
                       OFPBRC_BAD_APP_REG);
    }
    c_switch_replay_all(&ctrl_hdl, app);
    c_ha_notify(&ctrl_hdl, app);
    c_tr_notify(&ctrl_hdl, app);

    if (app_cookie) {
        c_log_debug("[APP] %s cookie 0x%lx", cofp_ra->app_name, U322UL(app_cookie));
        app->app_cookie = app_cookie; // FIXME: No locking 
        mb(); 
        c_switch_traverse_all(&ctrl_hdl, c_app_per_switch_elem_stale,
                              &app_cookie);
    }
    return 0;
}

static int 
c_app_unregister_app_command(void *app_arg, struct cbuf *b, void *data)
{
    struct c_ofp_unregister_app *cofp_ura = data;
    int ret = -1;

    if (ntohs(cofp_ura->header.length) < sizeof(c_ofp_unregister_app_t)) { 
        c_log_err("%s:Cmd(%u) Size err %u of %lu", 
                  FN, C_OFPT_UNREG_APP, ntohs(cofp_ura->header.length),
                  (unsigned long)sizeof(c_ofp_unregister_app_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }   

    ret = mul_unregister_app(cofp_ura->app_name);
    RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, 
                   OFPBRC_BAD_APP_UREG);
}

static void 
__c_sw_fpops_set(c_app_info_t *app, c_switch_t *sw, uint32_t fp_type)
{
    if (sw->fp_type == fp_type) {
        c_log_err("[SWITCH] |0x%llx| %s: switch in FP |mode %lu| "
                   "OR app mismatch", U642ULL(sw->DPID),
                    FN, U322UL(sw->fp_type));
        return;
    }
    switch (fp_type) {
    case C_FP_TYPE_DFL:
        if (sw->fp_owner != app) {
            c_log_err("[SWITCH] FP owner mismatch");
            break;
        }

        sw->fp_ops.fp_fwd = of_dfl_fwd;
        sw->fp_ops.fp_port_status = of_dfl_port_status;
        sw->fp_ops.fp_db_dump = NULL;
        sw->fp_ops.fp_topo_change = NULL;

        if (sw->fp_ops.fp_db_dtor) {
            sw->fp_ops.fp_db_dtor(sw, true);
        }
        sw->fp_ops.fp_db_dtor = NULL;
        sw->fp_ops.fp_db_ctor = NULL;

        c_log_info("[SWITCH] |%llx| FP clear", U642ULL(sw->DPID));
        sw->fp_type = fp_type;
        sw->fp_owner  = NULL;
        c_app_put(app);
        break;
    case C_FP_TYPE_L2:
        if (sw->fp_ops.fp_db_dtor) {
            sw->fp_ops.fp_db_dtor(sw, true);
        }

        sw->fp_ops.fp_db_dtor = c_l2fdb_destroy;
        sw->fp_ops.fp_db_ctor = c_l2fdb_init;

        sw->fp_ops.fp_db_ctor(sw, true);

        sw->fp_ops.fp_fwd = c_l2_lrn_fwd;
        sw->fp_ops.fp_port_status = c_l2_port_status;
        sw->fp_ops.fp_db_dump = c_l2fdb_show;
        sw->fp_ops.fp_aging = c_l2fdb_aging;
        sw->fp_ops.fp_topo_change = c_l2_topo_change;

        c_log_info("[SWITCH] |%llx| FP: l2-fwd", U642ULL(sw->DPID));
        
        sw->fp_type = fp_type;
        app->priv_flags |= C_APP_FP_L2;
        c_app_ref(app);
        sw->fp_owner = app;
        break;
    default:
        break;
    }
}

static int
c_app_set_fpops_command(void *app_arg, struct cbuf *b, void *data)
{
    struct c_ofp_set_fp_ops *cofp_sfp = data;
    int ret = -1;
    c_switch_t *sw;
    c_app_info_t *app = app_arg;

    if (app->app_flags & C_APP_AUX_REMOTE) {
        c_log_err("[APP] %s: Not allowed", FN);
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_EPERM);
    }

    if (ntohs(cofp_sfp->header.length) < sizeof(c_ofp_set_fp_ops_t)) {
        c_log_err("%s:Cmd(%u) Size err %u of %lu",
                  FN, C_OFPT_SET_FPOPS, ntohs(cofp_sfp->header.length),
                  (unsigned long)sizeof(c_ofp_set_fp_ops_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_sfp->DPID));
    if (unlikely(!sw)) {
        c_log_err("%s: Invalid switch-dpid(0x%llx)", FN,
                  (unsigned long long)ntohll(cofp_sfp->DPID));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
    }

    c_wr_lock(&sw->lock);
    __c_sw_fpops_set(app, sw, ntohl(cofp_sfp->fp_type));
    c_wr_unlock(&sw->lock);

    c_switch_put(sw);

    return 0;
}

static void
c_app_send_per_flow_info(void *arg, c_fl_entry_t *ent)
{
    struct c_buf_iter_arg *iter_arg = arg;
    c_ofp_flow_info_t           *cofp_fm;
    void                        *act;
    struct cbuf                 *b;
    size_t                      tot_len = 0;

    c_rd_lock(&ent->FL_LOCK);
    if (iter_arg->wr_ptr &&  /* wr_ptr field is overridden */
        !(ent->FL_FLAGS & C_FL_ENT_STATIC)) {
        c_rd_unlock(&ent->FL_LOCK);
        return;
    }

    tot_len = sizeof(*cofp_fm) + ent->action_len;

    b = of_prep_msg(tot_len, C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    cofp_fm->sw_alias = htonl((uint32_t)ent->sw->alias_id);
    cofp_fm->datapath_id = htonll(ent->sw->DPID);
    cofp_fm->command = C_OFPC_ADD;
    cofp_fm->flags = ent->FL_FLAGS;
    if (!ent->FL_INSTALLED) {
        cofp_fm->flags |= C_FL_ENT_NOT_INST; 
    }
    cofp_fm->flags = htonll(cofp_fm->flags);
    memcpy(&cofp_fm->flow, &ent->fl, sizeof(struct flow));
    memcpy(&cofp_fm->mask, &ent->fl_mask, sizeof(struct flow));
    cofp_fm->priority = htons(ent->FL_PRIO);
    cofp_fm->itimeo = htons(ent->FL_ITIMEO);
    cofp_fm->htimeo = htons(ent->FL_HTIMEO);
    cofp_fm->buffer_id = 0xffffffff;
    cofp_fm->oport = OFPP_NONE;

    cofp_fm->byte_count = htonll(ent->fl_stats.byte_count);
    cofp_fm->packet_count = htonll(ent->fl_stats.pkt_count);
    cofp_fm->duration_sec = htonl(ent->fl_stats.duration_sec);
    cofp_fm->duration_nsec = htonl(ent->fl_stats.duration_nsec);
    snprintf((char *)cofp_fm->bps, C_FL_XPS_SZ-1, "%lf", ent->fl_stats.bps);
    snprintf((char *)cofp_fm->pps, C_FL_XPS_SZ-1, "%lf", ent->fl_stats.pps);

    act = (void *)(cofp_fm+1);
    memcpy(act, ent->actions, ent->action_len);

    c_rd_unlock(&ent->FL_LOCK);

    c_remote_app_event(iter_arg->data, b);
}

static void
c_app_per_switch_flow_info(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;
    struct c_buf_iter_arg *iter_arg = arg;

    if (!(sw->switch_state & SW_PUBLISHED))
        return;

    if (sw->fp_ops.fp_db_dump) {
        /* FIXME : Chances of race condition */
        sw->fp_ops.fp_db_dump(sw, iter_arg, c_app_send_per_flow_info);
    }
    c_flow_traverse_tbl_all(sw, iter_arg, c_app_send_per_flow_info);
}

static void 
c_app_send_flow_info(void *app_arg, struct cbuf *b, bool dump_all)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL, 0, 0 };
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_rda)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_rda)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    iter_arg.data = app_arg;
    if (!dump_all) {
        iter_arg.wr_ptr = app_arg;
    }

    cofp_rda = (void *)(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_rda->datapath_id));
    if (!sw) {
        if (!cofp_rda->datapath_id) {
            c_switch_traverse_all(&ctrl_hdl, c_app_per_switch_flow_info,
                                  &iter_arg);
            goto done;
        }
        c_log_err("%s: Switch(0x%llx) not found", FN,
                  U642ULL(ntohll(cofp_rda->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }
    c_app_per_switch_flow_info(sw, NULL, &iter_arg);
    c_switch_put(sw);

done:
    c_remote_app_notify_success(app_arg);

    return;
}

static void 
c_app_send_matched_flow_info(void *app_arg, struct cbuf *b, bool dump_all UNUSED)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL, 0, 0 };
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_flow_info *cofp_fi;
    c_switch_t *sw = NULL;
    c_fl_entry_t *fl_entry = NULL;
    char *str = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_fi)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_fi)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    iter_arg.data = app_arg;
    cofp_fi = (void *)(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_fi->datapath_id));
    if (!sw) {
        if (!cofp_fi->datapath_id) {
            c_switch_traverse_all(&ctrl_hdl, c_app_per_switch_flow_info,
                                   &iter_arg);
            goto done;
        }
        c_log_err("%s: Switch(0x%llx) not found", FN,
                  U642ULL(ntohll(cofp_fi->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }
    
    if ((fl_entry = c_do_rule_lookup_with_detail(sw, &cofp_fi->flow,
                                               &cofp_fi->mask,
                                               ntohs(cofp_fi->priority)))) {
        c_app_send_per_flow_info(&iter_arg, fl_entry);
    } else {
        str = of_dump_flow_generic(&cofp_fi->flow, &cofp_fi->mask);
        c_log_err("%s: Flow not found : %s", FN, str);
        free(str);
    }
    c_switch_put(sw);

done:
    c_remote_app_notify_success(app_arg);

    return;
}

static void 
c_app_loop_detect_command(void *app_arg, struct cbuf *b, bool enable)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);

    if (ntohs(cofp_aac->header.length) <
            sizeof(*cofp_aac)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    ctrl_hdl.loop_en = enable;
    c_log_debug("|LOOP| %s", enable ? "Enabled" : "Disabled");
    c_remote_app_notify_success(app_arg);

    return;
}

static void
c_app_send_per_meter_info(void *arg, c_switch_meter_t *meter)
{
    struct c_buf_iter_arg *iter_arg = arg;
    struct cbuf *b;

    b = c_of_prep_meter_mod_msg(meter, true);
    c_remote_app_event(iter_arg->data, b);
}

static void
c_app_per_switch_meter_info(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;
    struct c_buf_iter_arg *iter_arg = arg;

    c_switch_meter_traverse_all(sw, iter_arg, c_app_send_per_meter_info);
}

static void 
c_app_send_meter_info(void *app_arg, struct cbuf *b, bool dump_all)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL, 0, 0};
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_rda)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_rda)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    iter_arg.data = app_arg;
    if (!dump_all) {
        iter_arg.wr_ptr = app_arg;
    }

    cofp_rda = (void *)(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_rda->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, U642ULL(ntohll(cofp_rda->datapath_id)));
        if (!cofp_rda->datapath_id) {
            c_switch_traverse_all(&ctrl_hdl, c_app_per_switch_meter_info,
                                   &iter_arg);
            goto done;
        }
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }
    c_app_per_switch_meter_info(sw, NULL, &iter_arg);
    c_switch_put(sw);

done:
    c_remote_app_notify_success(app_arg);

    return;
}

static void
c_app_send_per_group_info(void *arg, c_switch_group_t *grp)
{
    struct c_buf_iter_arg *iter_arg = arg;
    struct cbuf *b;

    b = c_of_prep_group_mod_msg(grp, true);
    c_remote_app_event(iter_arg->data, b);
}

static void
c_app_per_switch_group_info(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;
    struct c_buf_iter_arg *iter_arg = arg;

    c_switch_group_traverse_all(sw, iter_arg, c_app_send_per_group_info);
}

static void 
c_app_send_group_info(void *app_arg, struct cbuf *b, bool dump_all)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL, 0, 0 };
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_rda)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_rda)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    iter_arg.data = app_arg;
    if (!dump_all) {
        iter_arg.wr_ptr = app_arg;
    }

    cofp_rda = (void *)(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_rda->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, U642ULL(ntohll(cofp_rda->datapath_id)));
        if (!cofp_rda->datapath_id) {
            c_switch_traverse_all(&ctrl_hdl, c_app_per_switch_group_info,
                                   &iter_arg);
            goto done;
        }
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }
    c_app_per_switch_group_info(sw, NULL, &iter_arg);
    c_switch_put(sw);

done:
    c_remote_app_notify_success(app_arg);

    return;
}

static int
c_app_per_switch_per_group_info(void *k, uint32_t group_id, void *arg)
{
    c_switch_t  *sw = k;
    struct c_buf_iter_arg *iter_arg = arg;
    c_switch_group_t *grp = NULL;

    c_rd_lock(&sw->lock);
    if (sw->groups) {
        if((grp = g_hash_table_lookup(sw->groups, &group_id))) {
            c_app_send_per_group_info(iter_arg, grp);
            c_rd_unlock(&sw->lock);
            return 0;
        }
    }
    c_rd_unlock(&sw->lock);
    return -1;
}


static void 
c_app_send_single_group_info(void *app_arg, struct cbuf *b, bool dump_all)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL, 0, 0 };
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_group_info *cofp_gi = NULL;
    c_switch_t *sw = NULL;
    uint32_t group_id = 0;
    int ret = 0;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_gi)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_gi)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    iter_arg.data = app_arg;
    if (!dump_all) {
        iter_arg.wr_ptr = app_arg;
    }

    cofp_gi = (void *)(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_gi->datapath_id));
    group_id = ntohl(cofp_gi->group_id);
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN,
                U642ULL(ntohll(cofp_gi->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }
    ret = c_app_per_switch_per_group_info(sw, group_id, &iter_arg);
    c_switch_put(sw);
    if(ret) {
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    c_remote_app_notify_success(app_arg);

    return;
}


static void
c_app_per_switch_brief_info(void *k, void *v UNUSED, void *arg)
{   
    c_switch_t   *sw = k;
    struct c_buf_iter_arg *iter_arg = arg;
    struct c_ofp_switch_brief *cofp_sb = (void *)(iter_arg->wr_ptr);

    c_rd_lock(&sw->lock);
    of_switch_brief_info(sw, cofp_sb);

    c_rd_unlock(&sw->lock);
    iter_arg->wr_ptr += sizeof(*cofp_sb);
}
   
static void 
c_app_send_brief_switch_info(void *app_arg, struct cbuf *b)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL, 0, 0 };
    size_t n_switches = 0;
    struct c_ofp_auxapp_cmd *cofp_aac;

    c_rd_lock(&ctrl_hdl.lock);

    if (!ctrl_hdl.sw_hash_tbl ||
        !(n_switches = g_hash_table_size(ctrl_hdl.sw_hash_tbl))) {
        c_rd_unlock(&ctrl_hdl.lock);
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_NO_INFO);
        return;
    }

    b = of_prep_msg(sizeof(c_ofp_auxapp_cmd_t) +
                    (n_switches * sizeof(c_ofp_switch_brief_t)),
                    C_OFPT_AUX_CMD, 0); 
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = ntohl(C_AUX_CMD_MUL_GET_SWITCHES_REPLY);
    iter_arg.wr_ptr = cofp_aac->data;
    iter_arg.data = (void *)(b->data);

    __c_switch_traverse_all(&ctrl_hdl, c_app_per_switch_brief_info,
                             &iter_arg);

    c_rd_unlock(&ctrl_hdl.lock);

    c_remote_app_event(app_arg, b);
}

static void
c_app_send_detail_switch_info(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_switch_t *sw;

    if (ntohs(cofp_aac->header.length) < 
        sizeof(*cofp_aac) + sizeof(*cofp_rda)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN, ntohs(cofp_aac->header.length), 
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_rda)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    cofp_rda = (void *)(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_rda->datapath_id));
    if (!sw) {
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_NO_INFO);
        return;
    }

    b = c_app_dpreg_event_prep(sw, NULL);
    c_switch_put(sw);

    c_remote_app_event(app_arg, b);
}

static void
c_app_rcv_ha_sync_done(void *app_arg UNUSED, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_switch_t *sw;

    if (ntohs(cofp_aac->header.length) < 
        sizeof(*cofp_aac) + sizeof(*cofp_rda)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN, ntohs(cofp_aac->header.length), 
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_rda)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    cofp_rda = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_rda->datapath_id));
    if (!sw) {
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_NO_INFO);
        return;
    }

    c_wr_lock(&sw->lock);
    if (sw->switch_state & SW_HA_SYNCD_REQ) {
        sw->switch_state &= ~SW_HA_SYNCD_REQ;
    } 
    c_wr_unlock(&sw->lock);

    c_log_debug("|HA| Sync-complete for |0x%llx|", U642ULL(sw->DPID));
    c_switch_put(sw);
}

static void
c_app_rcv_ha_sync_req(void *app_arg UNUSED, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_switch_t *sw;

    if (ntohs(cofp_aac->header.length) < 
        sizeof(*cofp_aac) + sizeof(*cofp_rda)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN, ntohs(cofp_aac->header.length), 
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_rda)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    cofp_rda = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_rda->datapath_id));
    if (!sw) {
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_NO_INFO);
        return;
    }

    c_ha_per_sw_sync_state(sw, NULL, NULL);
    c_ha_switch_state_sync_done(sw->DPID);

    c_log_debug("|HA| Sync-request for |0x%llx|", U642ULL(sw->DPID));
    c_switch_put(sw);
}

static void 
c_app_send_switch_group_features(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b);
    struct c_ofp_switch_feature_common *cofp_f;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_f)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_f)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_f = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_f->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, U642ULL(ntohll(cofp_f->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    b = c_of_prep_group_feature_msg(sw);
    c_switch_put(sw);
    c_remote_app_event(app_arg, b);

    return;
}

static void 
c_app_send_switch_meter_features(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_feature_common *cofp_f;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_f)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_f)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_f = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_f->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, U642ULL(ntohll(cofp_f->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    b = c_of_prep_meter_feature_msg(sw);
    c_switch_put(sw);
    c_remote_app_event(app_arg, b);

    return;
}

static void 
c_app_send_switch_table_features(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_feature_common *cofp_f;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_f)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_f)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_f = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_f->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, U642ULL(ntohll(cofp_f->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    b = c_of_prep_table_feature_msg(sw, cofp_f->table_id);
    c_switch_put(sw);
    c_remote_app_event(app_arg, b);

    return;
}

static void 
c_app_async_config_handler(void *app_arg, struct cbuf *b, void *data)
{

    c_switch_t *sw = NULL;
    struct c_ofp_async_config *cofp_ac = data;
    struct of_async_config_params ac_parms;

    memset(&ac_parms, 0, sizeof(ac_parms));

    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_ac->DPID));
    if (!sw) {
        if (!c_rlim(&crl))
            c_log_err("%s: Invalid switch:dpid(0x%llx)", FN,
                      U642ULL(ntohll(cofp_ac->DPID)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
    }

    memcpy(ac_parms.packet_in_mask,cofp_ac->packet_in_mask,sizeof(ac_parms.packet_in_mask));
    memcpy(ac_parms.port_status_mask,cofp_ac->port_status_mask,sizeof(ac_parms.port_status_mask));
    memcpy(ac_parms.flow_removed_mask,cofp_ac->flow_removed_mask,sizeof(ac_parms.flow_removed_mask));

    c_switch_async_config(sw, &ac_parms);

    c_thread_sg_tx_sync(&sw->conn);
    c_switch_put(sw);
    c_remote_app_notify_success(app_arg);

    return;
}

static void 
c_app_set_switch_set_rlim(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_rlim *cofp_rl;
    c_switch_t *sw = NULL;
    struct c_rlim_dat *rs = NULL;
    bool is_rx, *on;
    uint32_t pps;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_rl)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_rl)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_rl = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_rl->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found",
                  FN, U642ULL(ntohll(cofp_rl->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    is_rx = ntohl(cofp_rl->is_rx) ? true : false;
    pps = ntohl(cofp_rl->pps);

    c_wr_lock(&sw->lock);
    if (is_rx) {
        rs = &sw->rx_rlim;
        on = &sw->rx_lim_on;
    } else {
        rs = &sw->tx_rlim;
        on = &sw->tx_lim_on;
    }

    if (pps) {
        *on = true;
        c_rlim_dat_update(rs, pps);
    } else {
        *on = false;
    }
    c_wr_unlock(&sw->lock);
    c_switch_put(sw);

    c_ha_proc(b);
    c_remote_app_notify_success(app_arg);
}

static void 
c_app_switch_get_rlim(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_rlim *cofp_rl;
    c_switch_t *sw = NULL;
    bool is_rx;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_rl)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_rl)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_rl = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_rl->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, U642ULL(ntohll(cofp_rl->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    is_rx = ntohl(cofp_rl->is_rx) ? true : false;
    b = c_of_prep_switch_rlims(sw, is_rx, true);
    c_switch_put(sw);

    c_remote_app_event(app_arg, b);
}

static void 
c_app_set_switch_of_dump(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_of_dump *cofp_d;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_d)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_d)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_d = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_d->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found",
                  FN, U642ULL(ntohll(cofp_d->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    c_wr_lock(&sw->lock);

    sw->rx_dump_en = cofp_d->rx_enable ? true: false; 
    sw->tx_dump_en = cofp_d->tx_enable ? true: false; 
    sw->dump_mask[0] = ntohll(cofp_d->dump_mask[0]);
    sw->dump_mask[1] = ntohll(cofp_d->dump_mask[1]);
    sw->dump_mask[2] = ntohll(cofp_d->dump_mask[2]);
    sw->dump_mask[3] = ntohll(cofp_d->dump_mask[3]);

    c_log_info("[SWITCH] |0x%llx| RX-dump|%d| Tx-dump|%d| "
               " mask 0x%llx 0x%llx 0x%llx 0x%llx",
               sw->DPID, sw->rx_dump_en, sw->tx_dump_en,
               U642ULL(sw->dump_mask[0]),
               U642ULL(sw->dump_mask[1]), 
               U642ULL(sw->dump_mask[2]),
               U642ULL(sw->dump_mask[3]));

    c_wr_unlock(&sw->lock);
    c_switch_put(sw);

    c_remote_app_notify_success(app_arg);
}

static void 
c_app_set_switch_stats_strategy(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_stats_strategy *cofp_ss;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_ss)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_ss)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_ss = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_ss->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found",
                  FN, U642ULL(ntohll(cofp_ss->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    c_wr_lock(&sw->lock);

    if (cofp_ss->fl_bulk_enable) {
        sw->switch_state |= SW_BULK_FLOW_STATS;
    } else {
        sw->switch_state &= ~SW_BULK_FLOW_STATS;
    }

    if (cofp_ss->grp_bulk_enable) {
        sw->switch_state |= SW_BULK_GRP_STATS;
    } else {
        sw->switch_state &= ~SW_BULK_GRP_STATS;
    }

    if (cofp_ss->meter_bulk_config_enable) {
        sw->switch_state |= SW_BULK_METER_CONF_STATS;
    } else {
        sw->switch_state &= ~SW_BULK_METER_CONF_STATS;
    }

    c_log_info("[SWITCH] (0x%llx) fl-bulk(0x%llx) grp-bulk(0x%llx) "
               " met-conf-bulk(0x%llx)", U642ULL(sw->DPID),
               U642ULL(sw->switch_state & SW_BULK_FLOW_STATS),
               U642ULL(sw->switch_state & SW_BULK_GRP_STATS),
               U642ULL(sw->switch_state & SW_BULK_METER_CONF_STATS));

    c_wr_unlock(&sw->lock);
    c_switch_put(sw);

    c_ha_proc(b);
    c_remote_app_notify_success(app_arg);
}

static void 
c_app_set_switch_stats_mode_config(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_stats_mode_config *cofp_smc;
    c_switch_t *sw = NULL;
    uint32_t stats_mode = 0;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_smc)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_smc)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }
    cofp_smc = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_smc->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found",
                FN, U642ULL(ntohll(cofp_smc->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }
    
    stats_mode = ntohl(cofp_smc->stats_mode);
    c_wr_lock(&sw->lock);

    if (stats_mode & PORT_STATS_ENABLE) {
        sw->switch_state |= SW_PORT_STATS_ENABLE;
    } else {
        sw->switch_state &= ~SW_PORT_STATS_ENABLE;
    }
    c_log_info("[SWITCH] (0x%llx) port-stats-en(%d) switch-state (%llx)",
               U642ULL(sw->DPID), stats_mode,
               U642ULL(sw->switch_state & SW_PORT_STATS_ENABLE));

    c_wr_unlock(&sw->lock);
    c_switch_put(sw);

    c_ha_proc(b);
    c_remote_app_notify_success(app_arg);
}

static void
c_app_switch_get_table_stats(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_table_stats *cofp_ts;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_ts)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_ts)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_ts = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_ts->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found",
                  FN, U642ULL(ntohll(cofp_ts->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    b = c_of_prep_switch_table_stats(sw, cofp_ts->table_id);
    c_switch_put(sw);

    c_remote_app_event(app_arg, b);
}

static void
c_app_switch_process_port_query(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b); 
    struct c_ofp_switch_port_query *cofp_pq;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_pq)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_pq)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_pq = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_pq->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, U642ULL(ntohll(cofp_pq->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    b = c_of_prep_port_stats(sw, cofp_pq->port_no);

    c_switch_put(sw);

    c_remote_app_event(app_arg, b);
}

static void
c_app_port_per_q_send_info(void *v UNUSED, void *q_arg, void *uarg)
{
    c_pkt_q_t *q = q_arg;
    struct c_buf_iter_arg *iter_arg = uarg;
    struct cbuf *b;
    size_t len;
    struct c_ofp_switch_port_query *cofp_pq;
    struct c_ofp_auxapp_cmd *cofp_aac;

    len = sizeof(*cofp_aac) + sizeof(*cofp_pq) + 
               q->q_prop_len + q->q_stats_len;
    b = of_prep_msg(len, C_OFPT_AUX_CMD, 0);
    
    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_PORT_QQUERY);
    cofp_pq = ASSIGN_PTR(cofp_aac->data);

    cofp_pq->datapath_id = htonll(iter_arg->dpid);
    cofp_pq->qid = htonl(q->qid);

    cofp_pq->stats_len = htonl(q->q_stats_len);

    if (q->q_stats_len && q->q_stats)
        memcpy(cofp_pq->data, q->q_stats, q->q_stats_len);

    if (q->q_prop_len)
        memcpy(cofp_pq->data + q->q_stats_len, q->q_prop, q->q_prop_len);

    c_remote_app_event(iter_arg->data, b);
}

static void 
c_app_get_q_info(void *app_arg, struct cbuf *b)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL, 0, 0};
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_switch_port_query *cofp_pq;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_pq)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_pq)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_pq = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_pq->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN,
                  U642ULL(ntohll(cofp_pq->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    iter_arg.data = app_arg;
    iter_arg.dpid = sw->DPID;
    c_switch_port_q_traverse_all(sw, ntohl(cofp_pq->port_no),
                                 c_app_port_per_q_send_info, &iter_arg); 
    c_switch_put(sw);
    c_remote_app_notify_success(app_arg);

    return;
}

static void 
c_app_set_loop_status(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b);
    struct c_ofp_loop_status_mod *cofp_sm;
    uint64_t loop_status = 0;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_sm)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_sm)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_sm = ASSIGN_PTR(cofp_aac->data);
    loop_status = ntohll(cofp_sm->loop_status);
    
    if (loop_status != C_LOOP_STATE_NONE && 
        loop_status != C_LOOP_STATE_LD && 
        loop_status != C_LOOP_STATE_CONV) {
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    c_topo_loop_change_notify(true, loop_status, false, true);
    c_remote_app_notify_success(app_arg);

    return;
}

static void 
c_app_set_tr_status(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b);
    struct c_ofp_tr_status_mod *cofp_trsm;
    uint64_t tr_status = 0;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_trsm)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_trsm)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_trsm = ASSIGN_PTR(cofp_aac->data);
    tr_status = ntohll(cofp_trsm->tr_status);
    
    if (tr_status != C_RT_APSP_CONVERGED) {
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    /*Set route convergence status in MUL Core*/
    c_topo_loop_change_notify(false, tr_status, false, true);
    c_signal_app_event(NULL, b, C_TR_STATUS, NULL, NULL, false);
    c_remote_app_notify_success(app_arg);

    return;
}

static void
c_app_send_mod_uflow_per_sw(void *app_arg, c_switch_t *sw, void *uarg)
{
    struct ofp_inst_check_args *inst_args = uarg;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_fl_mod_info *cofp_mflow;
    struct cbuf *b;
    size_t len;

    len = sizeof(*cofp_aac) + sizeof(*cofp_mflow); 
               
    b = of_prep_msg(len, C_OFPT_AUX_CMD, 0);

    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_MUL_MOD_UFLOW);
    cofp_mflow = ASSIGN_PTR(cofp_aac->data);
    cofp_mflow->datapath_id = htonll(sw->datapath_id);
    cofp_mflow->out_port = htonl(inst_args->out_port);
    memcpy(&cofp_mflow->flow, inst_args->fl, sizeof(struct flow));

    c_remote_app_event(app_arg, b);
}

static void
c_app_send_modify_flow_info(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = CBUF_DATA(b);
    c_fl_entry_t  *fl_ent = NULL;
    struct c_ofp_fl_mod_info *cofp_mflow;
    c_switch_t *sw = NULL;
    struct ofp_inst_check_args inst_args;
    c_switch_group_t *grp;
    size_t action_len = 0;
    struct ofp_action_header *actions = NULL;
    bool acts_only = false;
    int ret = 0;
    struct flow fl, mask;
    uint8_t table_id = 0;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_mflow)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_mflow)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_mflow = ASSIGN_PTR(cofp_aac->data);
    sw = c_switch_get(&ctrl_hdl, ntohll(cofp_mflow->datapath_id));
    if (!sw || !sw->ofp_ctors->act_modify_uflow) {
        c_log_err("%s: Switch(0x%llx) not found", FN,
                  U642ULL(ntohll(cofp_mflow->datapath_id)));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        if (sw) c_switch_put(sw);
        return;
    }

    memset(&inst_args, 0, sizeof(inst_args));
    inst_args.fl = &cofp_mflow->flow;
    inst_args.check_setf_supp = false;
    inst_args.sw_ctx = sw;
   
    while((fl_ent = c_do_flow_lookup(sw, &cofp_mflow->flow, true))) {

        table_id = fl_ent->fl.table_id;
        inst_args.tbl_prop = sw->rule_flow_tbls[table_id].props;
        action_len = fl_ent->action_len;
        actions = calloc(1, action_len);
        if (!actions) { 
            ret = -EINVAL;
            break;
        }
        memcpy(actions, fl_ent->actions, action_len);
        acts_only = false;

        memcpy(&fl, &fl_ent->fl, sizeof(struct flow));
        memcpy(&mask, &fl_ent->fl_mask, sizeof(struct flow));

        c_flow_entry_put(fl_ent);

traverse_actions:

        sw->ofp_ctors->act_modify_uflow(&fl, &mask,
                                        actions, action_len,
                                        acts_only, &inst_args);

        if (actions) { 
            free(actions);
            actions = NULL;
        }

        if (inst_args.out_port) 
            break;

        if (inst_args.group_id) {
            c_rd_lock(&sw->lock);
            if (!(grp = g_hash_table_lookup(sw->groups, &inst_args.group_id))) {
                c_rd_unlock(&sw->lock);
                c_log_err("[GROUP] No|%u| on switch |0x%llx| exists",
                          inst_args.group_id, sw->DPID);
                ret = -EINVAL;
                break;
            }
            
            if (grp->flags & C_GRP_EXPIRED) {
                c_rd_unlock(&sw->lock);
                c_log_err("[GROUP] |%u| on switch |0x%llx| is expired/dead",
                          inst_args.group_id, sw->DPID);
                ret = -EINVAL;
                break;
            }
            action_len = grp->act_vectors[0]->action_len;;
            actions = calloc(1, action_len);
            if (!actions) { 
                c_rd_unlock(&sw->lock);
                ret = -EINVAL;
                break;
            }
            memcpy(actions, grp->act_vectors[0]->actions, action_len);
 
            c_rd_unlock(&sw->lock);
            acts_only = true;
            goto traverse_actions;
        }
        
        if (inst_args.fl->table_id != table_id) {
            continue;
        }
    }

    if (ret || fl_ent == NULL || inst_args.inst_local) {
        c_remote_app_error(app_arg, b, OFPET_FLOW_MOD_FAILED, OFPFMFC_GENERIC);
        goto out;
    }

    c_app_send_mod_uflow_per_sw(app_arg, sw, &inst_args);
out:
    c_switch_put(sw);
}

static int
c_app_vendor_msg_handler(void *app_arg, struct cbuf *b, void *data)
{
    c_switch_t *sw;
    c_app_info_t *app = app_arg;
    c_ofp_send_vendor_message_t *vm = data;
    struct of_vendor_params vp;
    int ret = -1;
    
    assert(app);
    if(ntohs(vm->header.length) < sizeof(*vm)) {
	c_log_err("%s:Cmd(%u) Size err %u of %lu", FN, C_OFPT_VENDOR_MSG,
		ntohs(vm->header.length),
		(unsigned long)sizeof(*vm));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sw = c_switch_get(&ctrl_hdl, ntohll(vm->datapath_id));
    if (!sw) {
        c_log_err("%s: Invalid switch:dpid(0x%llx) ", FN,
                  U642ULL(ntohll(vm->datapath_id)));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);  
    }

    memset(&vp, 0, sizeof(vp));
    vp.vendor = ntohl(vm->vendor_id);
    vp.data_len = ntohs(vm->header.length) - sizeof(*vm);
    vp.data = vm->data;

    __of_send_vendor_msg(sw, &vp);
    c_thread_sg_tx_sync(&sw->conn);

    c_switch_put(sw);

    RETURN_APP_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED, OFPFMFC_GENERIC); 
}

static int
c_app_aux_request_handler(void *app_arg, struct cbuf *b, void *data)
{
    struct c_ofp_auxapp_cmd *cofp_aac = data;

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        c_log_err("%s: Size err (%x) of (%lx)", FN, ntohs(cofp_aac->header.length), 
                   U322UL(sizeof(struct c_ofp_auxapp_cmd)));
        RETURN_APP_ERR(app_arg, b, -1, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch (ntohl(cofp_aac->cmd_code)) {
    case C_AUX_CMD_MUL_GET_SWITCHES:
        c_app_send_brief_switch_info(app_arg, b);
        break;
    case C_AUX_CMD_MUL_GET_SWITCH_DETAIL:
        c_app_send_detail_switch_info(app_arg, b);
        break;
    case C_AUX_CMD_MUL_GET_APP_FLOW:
        c_app_send_flow_info(app_arg, b, false); 
        break;
    case C_AUX_CMD_MUL_GET_ALL_FLOWS:
        c_app_send_flow_info(app_arg, b, true); 
        break;
    case C_AUX_CMD_MUL_GET_GROUPS:
        c_app_send_group_info(app_arg, b, false); 
        break;
    case C_AUX_CMD_MUL_GET_MATCHED_GROUP:
        c_app_send_single_group_info(app_arg, b, false); 
        break;
    case C_AUX_CMD_MUL_GET_METERS:
        c_app_send_meter_info(app_arg, b, false); 
        break;
    case C_AUX_CMD_HA_STATE:
        c_ha_rcv_peer_state(app_arg, b);
        break;
    case C_AUX_CMD_HA_REQ_STATE:
        c_ha_rcv_state_req(app_arg);
        break;
    case C_AUX_CMD_HA_SYNC_REQ:
        c_app_rcv_ha_sync_req(app_arg, b);
        break;
    case C_AUX_CMD_HA_SYNC_DONE:
        c_app_rcv_ha_sync_done(app_arg, b);
        break;
    case C_AUX_CMD_MUL_SWITCH_GROUP_FEAT:
        c_app_send_switch_group_features(app_arg, b);
        break; 
    case C_AUX_CMD_MUL_SWITCH_METER_FEAT:
        c_app_send_switch_meter_features(app_arg, b);
        break;    
    case C_AUX_CMD_MUL_SWITCH_TABLE_FEAT:
        c_app_send_switch_table_features(app_arg, b);
        break;   
    case C_AUX_CMD_MUL_SWITCH_RLIM:
        c_app_set_switch_set_rlim(app_arg, b); 
        break;
    case C_AUX_CMD_MUL_SWITCH_GET_RLIM:
        c_app_switch_get_rlim(app_arg, b);
        break;
    case C_AUX_CMD_MUL_SWITCH_SET_OF_DUMP:
        c_app_set_switch_of_dump(app_arg, b);
        break;
    case C_AUX_CMD_MUL_SWITCH_SET_STATS_STRAT:
        c_app_set_switch_stats_strategy(app_arg, b);
        break;
    case C_AUX_CMD_ASYNC_CONFIG:
        c_app_async_config_handler(app_arg, b, cofp_aac->data);
        break;
    case C_AUX_CMD_MUL_SWITCH_STATS_MODE_CONFIG:
        c_app_set_switch_stats_mode_config(app_arg, b);
        break;
    case C_AUX_CMD_MUL_SWITCH_GET_TBL_STATS:
        c_app_switch_get_table_stats(app_arg, b);
        break;
    case C_AUX_CMD_MUL_SWITCH_PORT_QUERY:
        c_app_switch_process_port_query(app_arg, b);
        break;
    case C_AUX_CMD_MUL_SWITCH_PORT_QQUERY:
        c_app_get_q_info(app_arg, b);
        break;
    case C_AUX_CMD_MUL_LOOP_STATUS:
        c_app_set_loop_status(app_arg, b);
        break; 
    case C_AUX_CMD_MUL_GET_FLOW:
        c_app_send_matched_flow_info(app_arg, b, false);
        break;
    case C_AUX_CMD_MUL_LOOP_EN:
        c_app_loop_detect_command(app_arg, b, true);
        break;
    case C_AUX_CMD_MUL_LOOP_DIS:
        c_app_loop_detect_command(app_arg, b, false);
        break;
    case C_AUX_CMD_MUL_TR_STATUS:
        c_app_set_tr_status(app_arg, b);
        break;
    case C_AUX_CMD_MUL_MOD_UFLOW:
        c_app_send_modify_flow_info(app_arg, b);
        break;
    default:
        RETURN_APP_ERR(app_arg, b, -1, OFPET_BAD_REQUEST, OFPBRC_BAD_GENERIC);
        break;
    }

    return 0;
}

void
c_aux_app_init(void *app_arg)
{
    c_app_info_t *app = app_arg;

    app->app_flags = C_APP_AUX_REMOTE;
    app->ev_cb = c_remote_app_event;
    strcpy(app->app_name, "remote");
}

static int
c_app_worq_tx(void *app_arg, uint64_t dpid, struct cbuf *b)
{
    c_switch_t          *sw;
    struct c_worker_ctx *c_wrk_ctx = NULL;
    struct c_app_ctx    *app_wrk_ctx  = NULL;
    c_conn_t            *conn;
    c_app_info_t        *app = app_arg;

    app_wrk_ctx = app->ctx;
    sw = c_switch_get(&ctrl_hdl, dpid);

    if (sw) {
        c_wrk_ctx = sw->ctx;
        assert(c_wrk_ctx->thread_idx < C_MAX_THREADS);
        conn = &app_wrk_ctx->work_qs[c_wrk_ctx->thread_idx].wq_conn;
        c_switch_put(sw);

        if (conn->dead) {
            return 1;
        }
        c_thread_tx(conn, b, false);
        
        return 0;
    } 

    return -1;
}

static int
c_app_workq_fb_handler(void *c_arg UNUSED, struct cbuf *b UNUSED)
{             
    /* Nothing to do */
    return 0;
}   
    
void
c_app_workq_fb_thread_read(evutil_socket_t fd, short events UNUSED, void *arg)
{       
    c_conn_t    *wq_conn = arg;
    int         ret;
        
    ret = c_socket_read_nonblock_loop(fd, arg, wq_conn, OFC_RCV_BUF_SZ,
                                      (conn_proc_t)c_app_workq_fb_handler,
                                      of_get_data_len, of_hdr_valid,
                                      sizeof(struct ofp_header));
    if (c_recvd_sock_dead(ret)) {
        c_log_err("[WORKQ] FB socket dead");
        perror("workq");
        c_conn_destroy(wq_conn);
    }
    
    return;
}

int
__mul_app_workq_handler(void *wq_arg UNUSED, struct cbuf *b)
{
    struct ofp_header *hdr = (void *)(b->data);

    switch (hdr->type) {
    case C_OFPT_FLOW_MOD:
        return c_app_flow_mod_wrk_command(NULL, b, hdr);
    }

    return -1;
}

int  __fastpath
__mul_app_command_handler(void *app_arg, struct cbuf *b)
{
    struct ofp_header *hdr = (void *)(b->data);

    switch (hdr->type) {
    case C_OFPT_FLOW_MOD:
        return c_app_flow_mod_command(app_arg, b, hdr);
    case C_OFPT_GROUP_MOD:
        return c_app_group_mod_command(app_arg, b, hdr);
    case C_OFPT_METER_MOD:
        return c_app_meter_mod_command(app_arg, b, hdr);
    case C_OFPT_PACKET_OUT:
        return c_app_packet_out_command(app_arg, b, hdr);
    case C_OFPT_REG_APP:
        return c_app_register_app_command(app_arg, b, hdr);
    case C_OFPT_UNREG_APP:
        return c_app_unregister_app_command(app_arg, b, hdr);
    case C_OFPT_SET_FPOPS:
        return c_app_set_fpops_command(app_arg, b, hdr);
    case C_OFPT_AUX_CMD:
        return c_app_aux_request_handler(app_arg, b, hdr);
    case C_OFPT_PORT_MOD:
        return c_app_port_mod_command(app_arg, b, hdr);
    case C_OFPT_VENDOR_MSG:
        return c_app_vendor_msg_handler(app_arg, b, hdr);
    }

    return -1;
}

int __fastpath
mul_app_command_handler(void *app_name, void *buf)
{
    c_app_info_t *app = NULL;
    struct cbuf *b = buf;
    struct ofp_header *hdr = (void *)(b->data);
    int ret;

    assert(b && app_name);

    c_rd_lock(&ctrl_hdl.lock);

    if (hdr->type != C_OFPT_REG_APP &&
        !(app = __c_app_get(&ctrl_hdl, (char *)app_name))) {
        c_rd_unlock(&ctrl_hdl.lock);
        c_log_err("[APP] %s:failed:|%s| unknown app", FN, (char *)app_name);
        return -1;
    }

    c_rd_unlock(&ctrl_hdl.lock);

    ret = __mul_app_command_handler(app, b);

    c_app_put(app);

    free_cbuf(b);
    return ret;
}

static void
mod_initcalls(struct c_app_ctx *app_ctx)
{
    initcall_t *mod_init;

    mod_init = &__start_modinit_sec;
    do {
        (*mod_init)(app_ctx->cmn_ctx.base);
        mod_init++;
    } while (mod_init < &__stop_modinit_sec);
}

int 
c_builtin_app_start(void *arg)
{   
    struct c_app_ctx    *app_ctx = arg;

    if (app_ctx->thread_idx == 0) {
        mod_initcalls(app_ctx);
    }

    return 0;
}

/* Housekeep Timer for app monitoring */
static void UNUSED
c_app_main_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                 void *arg)
{
    struct c_app_ctx *app_ctx  = arg;
    struct timeval   tv        = { 1 , 0 };
   
    evtimer_add(app_ctx->app_main_timer_event, &tv);
}

static void
c_app_vty(void *arg UNUSED)
{
    /* Nothing to do */ 
    return;
}

static void
c_app_main(void *arg UNUSED)
{
    /* Nothing to do */
    return;
}

module_init(c_app_main);
module_vty_init(c_app_vty);
