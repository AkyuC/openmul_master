/*
 *  mul_ha.c: MUL HA logic 
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

#include "mul.h"
#include "random.h"

/* FIXME : Thread safety.Altough it does not hamper reliable working */

extern ctrl_hdl_t ctrl_hdl;

static void
c_ha_state_transition(ctrl_hdl_t *c_hdl, uint32_t new_state);

static void
__c_ha_generation_id_update(uint64_t gen_id);


void
__c_ha_proc(struct cbuf *b, bool use_cbuf, bool force)
{
    struct cbuf *new_b = NULL;

    if (!force && !c_ha_master(&ctrl_hdl)) {
        if (use_cbuf) free_cbuf(b);
        return;
    }

    if (!use_cbuf) {
        new_b = cbuf_realloc_headroom(b, 0, 0);
        if (!new_b) {
            c_log_err("%s: Failed to alloc buf", FN);
            return;
        }
    } else {
        new_b = b;
    }

    c_thread_tx(&ctrl_hdl.ha_conn, new_b, false);
}

void
c_ha_proc(struct cbuf *b)
{
    return __c_ha_proc(b, false, false);
}

void
c_ha_get_of_state(uint32_t *role, uint64_t *gen_id)
{
    switch(ctrl_hdl.ha_state) {
    case C_HA_STATE_NONE:
    case C_HA_STATE_CONNECTED:
    case C_HA_STATE_NOHA:
    case C_HA_STATE_CONFLICT:
        *role = OFPCR_ROLE_EQUAL;
        break;
    case C_HA_STATE_MASTER:
        *role = OFPCR_ROLE_MASTER;
        break;
    case C_HA_STATE_SLAVE:
        *role = OFPCR_ROLE_SLAVE;
        break;
    }

    *gen_id = ctrl_hdl.gen_id; 
}

static struct cbuf *
c_ha_mk_state_resp(ctrl_hdl_t *c_hdl, uint32_t type)
{
    struct c_ofp_auxapp_cmd *cofp_aac;
    c_ofp_ha_state_t *cofp_ha;
    struct cbuf *b;

    b = of_prep_msg(sizeof(c_ofp_auxapp_cmd_t) +
                    sizeof(c_ofp_ha_state_t),
                    C_OFPT_AUX_CMD, 0);
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = ntohl(type);

    cofp_ha = (void *)(cofp_aac->data);

    cofp_ha->ha_sysid = htonl(c_hdl->ha_sysid);
    cofp_ha->gen_id = htonll(c_hdl->gen_id);
    cofp_ha->ha_state = c_hdl->c_peer ? htonl(c_hdl->ha_state) :
                                        htonl(C_HA_STATE_NOHA);

    return b;
}

static struct cbuf *
c_ha_mk_state_sync_req(uint64_t dpid, uint32_t cmd)
{
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_req_dpid_attr *cofp_rda;
    struct cbuf *b;

    b = of_prep_msg(sizeof(*cofp_aac) +
                    sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);
    cofp_aac = CBUF_DATA(b);
    cofp_aac->cmd_code = ntohl(cmd);

    cofp_rda = ASSIGN_PTR(cofp_aac->data);
    cofp_rda->datapath_id = htonll(dpid);

    return b;
}

void
c_ha_req_switch_state(uint64_t dpid)
{
    struct cbuf *b = c_ha_mk_state_sync_req(dpid, C_AUX_CMD_HA_SYNC_REQ);
    __c_ha_proc(b, true, true);
}

void
c_ha_switch_state_sync_done(uint64_t dpid)
{
    struct cbuf *b = c_ha_mk_state_sync_req(dpid, C_AUX_CMD_HA_SYNC_DONE);
    __c_ha_proc(b, true, true);
}

void
c_ha_rcv_state_req(void *app_arg)
{
    struct cbuf *b;
    c_app_info_t *app = app_arg;

    b = c_ha_mk_state_resp(&ctrl_hdl, C_AUX_CMD_HA_STATE_RESP);
    c_thread_tx(&app->app_conn, b, false);
}

static void
c_ha_send_state(ctrl_hdl_t *c_hdl)
{
    struct cbuf *b;

    b = c_ha_mk_state_resp(c_hdl, C_AUX_CMD_HA_STATE); 

    c_thread_tx(&c_hdl->ha_conn, b, false);

    if (c_hdl->ha_conn.dead) {
        c_ha_state_transition(c_hdl, C_HA_STATE_NONE);
    }
}

void
c_ha_notify(ctrl_hdl_t *c_hdl, void *app)
{
    struct cbuf *b = c_ha_mk_state_resp(c_hdl, C_AUX_CMD_HA_STATE_RESP);

    c_signal_app_event(NULL, b, C_HA_STATE, app, NULL, false);
    free_cbuf(b);
}

void
c_ha_per_sw_sync_state(void *k, void *v UNUSED, void *arg UNUSED)
{
    c_switch_t  *sw = k;

    /* FIXME - Race condition */
    c_switch_rlim_sync(sw);
    c_switch_stats_strategy_sync(sw);
    c_switch_stats_mode_sync(sw);
    c_switch_group_traverse_all(sw, sw, c_switch_group_ha_sync);
    c_switch_meter_traverse_all(sw, sw, c_switch_meter_ha_sync);
    c_flow_traverse_tbl_all(sw, NULL, c_switch_flow_ha_sync);
}

static void
c_ha_req_per_switch_state(void *k, void *v UNUSED, void *arg UNUSED)
{   
    c_switch_t  *sw = k;

    if (!(sw->switch_state & SW_HA_SYNCD_REQ) &&
        c_switch_needs_state_sync(&ctrl_hdl)) {
        c_log_info("%s:switch (0x%llx) state req", FN, U642ULL(sw->DPID));
        c_ha_req_switch_state(sw->DPID);
        sw->switch_state |= SW_HA_SYNCD_REQ;
   }
}

static void
c_ha_req_sync(ctrl_hdl_t *c_hdl)
{
    c_switch_traverse_all(c_hdl, c_ha_req_per_switch_state, NULL);
}

#ifdef C_VIRT_CON_HA

static void
c_ha_disconnect_active_switch(void *k, void *v UNUSED, void *arg UNUSED)
{
    c_switch_t  *sw = k;

    if (c_switch_is_virtual(sw))
        return;

    c_log_debug("[HA] Tick off switch 0x%llx", FN, sw->DPID);
    c_conn_close(&sw->conn);
    c_switch_mark_sticky_del(sw);
}

static void
c_ha_disconnect_all_active_switch(ctrl_hdl_t *c_hdl)
{
    c_switch_traverse_all(c_hdl, c_ha_disconnect_active_switch, NULL);
}

#else
static void
c_ha_disconnect_all_active_switch(ctrl_hdl_t *c_hdl UNUSED)
{
    return;
}

static void
c_ha_update_per_sw_master_view(void *k, void *v UNUSED, void *arg UNUSED)
{
    c_switch_t  *sw = k;
    __of_send_role_request(sw);
}

static void
c_ha_update_all_sw_master_view(ctrl_hdl_t *c_hdl)
{
    c_switch_traverse_all(c_hdl, c_ha_update_per_sw_master_view, NULL);
}

#endif

static void
c_ha_state_transition(ctrl_hdl_t *c_hdl, uint32_t new_state)
{
    c_log_warn("[HA] State change |%u|->|%u|", c_hdl->ha_state, new_state);
    switch(new_state) {
    case C_HA_STATE_SLAVE:
        c_hdl->ha_state = new_state;
        __c_ha_generation_id_update(c_hdl->gen_id+1);
        c_ha_disconnect_all_active_switch(c_hdl);
        c_ha_req_sync(c_hdl);
        break;
    case C_HA_STATE_CONFLICT:
        /* assert(c_hdl->ha_state != C_HA_STATE_NONE); */
        c_hdl->ha_state = new_state;
        ctrl_hdl.conflict_resolve = true;
        break;
    case C_HA_STATE_NONE:
        c_hdl->ha_retries = 0;
        c_conn_destroy(&c_hdl->ha_conn);
        switch (c_hdl->ha_state) {
        case C_HA_STATE_SLAVE:
        case C_HA_STATE_MASTER:
            c_hdl->ha_sysid = 0;
            break;
        case C_HA_STATE_CONFLICT:
            c_hdl->ha_sysid = random_uint32();    
        default:
            break;
        }
        c_hdl->ha_state = new_state;
        break;
    case C_HA_STATE_MASTER:
        c_hdl->ha_state = new_state;
        __c_ha_generation_id_update(c_hdl->gen_id+1);
        break;
    case C_HA_STATE_CONNECTED:
        c_hdl->ha_state = new_state;
        c_ha_send_state(c_hdl);
        break;
    default:
        NOT_REACHED();
    }

    c_ha_update_all_sw_master_view(c_hdl);
    c_ha_notify(c_hdl, NULL);
}


static int
c_ha_feedback_handler(void *c_arg UNUSED, struct cbuf *b UNUSED)
{
    return 0;
}

static void
c_ha_thread_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    ctrl_hdl_t  *c_hdl   = arg;
    c_conn_t    *ha_conn = &c_hdl->ha_conn;
    int         ret;

    ret = c_socket_read_nonblock_loop(fd, c_hdl, ha_conn, OFC_RCV_BUF_SZ,
                                      (conn_proc_t)c_ha_feedback_handler,
                                      of_get_data_len, of_hdr_valid,
                                      sizeof(struct ofp_header));
    if (c_recvd_sock_dead(ret)) {
        c_log_err("[HA] socket dead");
        perror("ha-socket");
        c_ha_state_transition(c_hdl, C_HA_STATE_NONE);
    }

    return;
}

uint64_t
c_ha_generation_id_init(void)
{
    FILE *fp;
    char buf[128];
    uint64_t gen_id = 0;
    char *ptr = NULL;

    ctrl_hdl.gen_id = 0;

    c_wr_lock(&ctrl_hdl.flock);
    fp = fopen(C_GEN_ID_STORE, "r+");
    if (!fp) {
        c_log_err("|HA| %s open err %s",
                  C_GEN_ID_STORE, strerror(errno));
        c_wr_unlock(&ctrl_hdl.flock);
        return 0;
    }

    ptr = fgets(buf, sizeof(buf)-1, fp);
    if (ptr == NULL) {
        c_log_err("|HA| gen-id init i-o err %s", strerror(errno));
        ctrl_hdl.gen_id = 0;
    }
    buf[127]='\0';
    gen_id = strtoull(buf, NULL, 16);
    if (gen_id == ULLONG_MAX && errno == ERANGE)
        gen_id = 0;

    fclose(fp);
    c_wr_unlock(&ctrl_hdl.flock);

    ctrl_hdl.gen_id = gen_id;

    c_log_err("|INIT| gen-id %llx", U642ULL(ctrl_hdl.gen_id));
    return ctrl_hdl.gen_id;
}

static void
__c_ha_generation_id_update(uint64_t gen_id)
{
    FILE *fp;
    int ret = 0;
    char buf[128];

    ctrl_hdl.gen_id = gen_id;

    c_wr_lock(&ctrl_hdl.flock);
    fp = fopen(C_GEN_ID_STORE, "w+");
    if (!fp) {
        c_log_err("|HA| gen-id update fail %s open err %s",
                  C_GEN_ID_STORE, strerror(errno)); 
        c_wr_unlock(&ctrl_hdl.flock);
        return;
    }

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf)-1, "0x%llx", U642ULL(ctrl_hdl.gen_id)); 
    buf[127] = '\0';
    ret = fputs(buf, fp);
    if (ret == EOF) {
        c_log_err("|HA| gen-id update i-o err %s", strerror(errno));
    }

    fclose(fp);
    c_wr_unlock(&ctrl_hdl.flock);
    c_log_info("[HA] generation-id |%llu| updated", U642ULL(gen_id));

    return;
}

void
c_ha_generation_id_update(uint64_t gen_id, size_t inc)
{
    __c_ha_generation_id_update(gen_id + inc);
    c_ha_update_all_sw_master_view(&ctrl_hdl);
}

void
c_ha_rcv_peer_state(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    c_ofp_ha_state_t *cofp_ha;
    struct in_addr peer_addr;
    c_app_info_t *app_info = NULL;

    if (!ctrl_hdl.c_peer) return;

    if (!inet_aton(ctrl_hdl.c_peer,&peer_addr))
    {
        perror("inet_ntoa failed");
        return;
    }

    app_info = (c_app_info_t *)app_arg;

    if(peer_addr.s_addr != app_info->peer_addr.sin_addr.s_addr) {
        return;
    }

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_ha)) {
        c_log_err("%s: Size err (%u) of (%lx)", FN,
                  ntohs(cofp_aac->header.length),
                  U322UL(sizeof(*cofp_aac) + sizeof(*cofp_ha)));
        //c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    cofp_ha = (void *)(cofp_aac->data);
    ctrl_hdl.ha_peer_sysid = ntohl(cofp_ha->ha_sysid);
    ctrl_hdl.ha_peer_state = ntohl(cofp_ha->ha_state);

    if (ctrl_hdl.gen_id < ntohll(cofp_ha->gen_id)) {
        c_ha_generation_id_update(ntohll(cofp_ha->gen_id), 0);
    }

    if ((ctrl_hdl.ha_peer_state == C_HA_STATE_SLAVE &&
        ctrl_hdl.ha_state == C_HA_STATE_SLAVE) || 
        (ctrl_hdl.ha_peer_state == C_HA_STATE_MASTER &&
        ctrl_hdl.ha_state == C_HA_STATE_MASTER) ||
        ctrl_hdl.ha_sysid == ctrl_hdl.ha_peer_sysid ||
        ctrl_hdl.ha_peer_state == C_HA_STATE_CONFLICT) {
        c_log_warn("[HA] |CONFLICT|(Host state:%u, id:%u) "
                    "Peer(state:%u, id:%u)",
                    ctrl_hdl.ha_state, ctrl_hdl.ha_sysid,
                    ctrl_hdl.ha_peer_state, ctrl_hdl.ha_peer_sysid);
        if (!ctrl_hdl.conflict_resolve) { 
            c_ha_state_transition(&ctrl_hdl, C_HA_STATE_CONFLICT);
        } else {
            c_log_info("[HA] |CONFLICT|: No transition");  
        }
    } else {
        ctrl_hdl.conflict_resolve = 0;
    }

    ctrl_hdl.last_ha_hearbeat = time(NULL);
}

static int 
c_ha_connect(ctrl_hdl_t *c_hdl)
{
    c_conn_t *ha_conn = &c_hdl->ha_conn;

    ha_conn->fd = c_client_socket_create(c_hdl->c_peer,
                                         C_AUX_APP_PORT);
    if (ha_conn->fd > 0 ) {
        ha_conn->rd_event = event_new(c_hdl->ha_base,
                                     ha_conn->fd,
                                     EV_READ|EV_PERSIST,
                                     c_ha_thread_read, c_hdl);
        ha_conn->wr_event = event_new(c_hdl->ha_base,
                                     ha_conn->fd,
                                     EV_WRITE, //|EV_PERSIST,
                                     c_thread_write_event, ha_conn);
        event_add(C_EVENT(ha_conn->rd_event), NULL);
        ha_conn->dead = 0;
        c_ha_state_transition(c_hdl, C_HA_STATE_CONNECTED);
    } else {
        ha_conn->dead = 1;
    }

    return ha_conn->fd;
}

void
c_ha_state_machine(ctrl_hdl_t *c_hdl)
{
    time_t curr = time(NULL);

    switch(c_hdl->ha_state) {
    case C_HA_STATE_NONE:
        if (c_hdl->c_peer) c_ha_connect(c_hdl);
        break;
    case C_HA_STATE_CONNECTED:
        c_log_info("|HA| Connected");
        c_ha_send_state(c_hdl);
        if (c_hdl->ha_peer_state >= C_HA_STATE_CONNECTED) {
            if (c_hdl->ha_peer_sysid < c_hdl->ha_sysid) {
                c_ha_state_transition(c_hdl, C_HA_STATE_SLAVE);
                c_log_info("[HA] Role Slave");
            } else if (c_hdl->ha_peer_sysid > c_hdl->ha_sysid) {
                c_ha_state_transition(c_hdl, C_HA_STATE_MASTER);
                c_log_info("[HA] Role Master");
            } else {
                c_log_err("[HA] Role select failed |%u|", c_hdl->ha_peer_sysid) ;
                c_ha_state_transition(c_hdl, C_HA_STATE_CONFLICT);
            }
        } else {
            c_log_info("[HA] Strange Peer HA State(%d)", c_hdl->ha_peer_state);
            c_ha_state_transition(c_hdl, C_HA_STATE_CONFLICT);
        }
        break;
    case C_HA_STATE_MASTER:
        c_ha_send_state(c_hdl);
        break;
    case C_HA_STATE_SLAVE:
        if (ctrl_hdl.last_ha_hearbeat + C_HA_TAKEOVER_TIMEO < curr) {
            c_ha_state_transition(c_hdl, C_HA_STATE_MASTER);
        }
        c_ha_send_state(c_hdl);
        break;
    case C_HA_STATE_CONFLICT:
        c_ha_send_state(c_hdl);
        if (c_hdl->ha_retries++ >= C_HA_MAX_RETRIES &&
            c_hdl->ha_peer_state == C_HA_STATE_CONFLICT) {
            c_ha_state_transition(c_hdl, C_HA_STATE_NONE);
        }
        break;
    default:
        NOT_REACHED();
    }
}


static void
c_ha_timer_event(evutil_socket_t fd UNUSED, short event UNUSED,
                 void *arg)
{
    ctrl_hdl_t *c_hdl = arg;
    struct timeval tv = { C_HA_TIMEO, C_HA_TIMEO_US };

    c_ha_state_machine(c_hdl);
    evtimer_add(C_EVENT(c_hdl->ha_timer_event), &tv);
}

void
c_ha_init(void *base)
{
    struct timeval tv = { C_HA_TIMEO, 0 };

    assert(ctrl_hdl.ha_sysid);
    ctrl_hdl.ha_timer_event = evtimer_new(base,
                                          c_ha_timer_event,
                                          (void *)&ctrl_hdl);
    evtimer_add(C_EVENT(ctrl_hdl.ha_timer_event), &tv);
    ctrl_hdl.ha_base = base;

    c_log_info("[HA] Init");
}

module_init(c_ha_init);
