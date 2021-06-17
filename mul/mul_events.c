/*
 *  mul_events.c: MUL event handling 
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

extern ctrl_hdl_t ctrl_hdl;

void c_worker_do_switch_del(struct c_worker_ctx *c_wrk_ctx, c_switch_t *sw);
void c_worker_do_app_del(struct c_app_ctx *c_app_ctx, c_app_info_t *app);
void c_worker_do_switch_zap(struct c_worker_ctx *c_wrk_ctx, c_switch_t *sw);

static void c_switch_ha_add(c_switch_t *sw, bool slave);
static void c_switch_ha_del(c_switch_t *sw);
static void c_switch_ha_state_machine(c_switch_t *sw);
static void c_switch_events_add(c_switch_t *sw);

int
c_ssl_accept(c_conn_t *conn)
{
    int err = 0;
    int sslerr = 0;
    unsigned long err_code = 0;
    int retries = 0;

    assert(conn->ssl);

ssl_retry:
    if ((err = SSL_accept(conn->ssl)) <= 0) {
        sslerr = SSL_get_error(conn->ssl, err);
        if (sslerr == SSL_ERROR_WANT_WRITE ||
            sslerr == SSL_ERROR_WANT_READ) {
            if (++retries < C_SSL_BUSY_ACCEPT_RETRIES)
                goto ssl_retry;
            conn->ssl_state = C_CONN_SSL_CONNECTING;
            return 1;
        }
        c_log_err("[SSL-Accept] Failed ssl-err|%d|. Non-ssl fallback", sslerr);
        if ((err_code = ERR_get_error())) {
            char *err_str = NULL;
            err_str = ERR_error_string(err_code, NULL);
            c_log_err("[SSL] Extended error code %lu", err_code);
            c_log_err("[SSL] Extended error string %s", err_str);
        }
        SSL_free(conn->ssl);
        SSL_shutdown(conn->ssl);
        conn->ssl = NULL;
        conn->ssl_state = C_CONN_SSL_NONE;
        return -1;
    }

    SSL_set_mode(conn->ssl,
                 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                 SSL_MODE_ENABLE_PARTIAL_WRITE);

    conn->ssl_state = C_CONN_SSL_CONNECTED;
    c_log_debug("[SSL-Accept] New-conn [%s]", SSL_get_cipher(conn->ssl));
    return 0;
}

void
c_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

static void
c_per_virt_sw_timer(c_switch_t *sw, time_t ctime)
{
    time_t                time_diff;

    if (sw->switch_state & SW_DEAD) {
        c_log_warn("[SWITCH] marked dead");
        time_diff = ctime - sw->last_refresh_time;
        if (time_diff > C_SWITCH_ECHO_TIMEO) {
            return c_worker_do_switch_zap(sw->ctx, sw);
        }

        return;
    } else if (sw->switch_state & SW_REINIT ||
               sw->switch_state & SW_REINIT_VIRT) {
        c_log_warn("[SWITCH] marked for reinit");
        c_conn_destroy(&sw->conn);
        c_conn_assign_fd(&sw->conn, sw->reinit_fd);
        sw->reinit_fd = 0;
        c_switch_events_add(sw);
        if (sw->switch_state & SW_REINIT) {
            sw->ha_state = SW_HA_NONE;
            c_per_switch_flow_resync_hw(sw, NULL, NULL);
            /* FIXME : Meter and group */
        }
        sw->switch_state &= ~(SW_REINIT | SW_REINIT_VIRT);
        return;
    }
}

static void
c_per_sw_timer(void *arg_sw, void *arg_time)
{
    c_switch_t          *sw     = arg_sw;
    struct c_worker_ctx *w_ctx  = sw->ctx;
    time_t              ctime    = *(time_t *)arg_time;
    time_t              time_diff;
    c_per_thread_dat_t  *t_data = &w_ctx->thread_data;

    if (sw->rx_pkt_in_dropped ||
        sw->tx_pkt_out_dropped) {
        c_log_debug("[SWITCH] |0x%llx| Rlim dropped Rx(%llx) Tx(%llx)",
                    U642ULL(sw->DPID),
                    U642ULL(sw->rx_pkt_in_dropped),
                    U642ULL(sw->tx_pkt_out_dropped));
        sw->tx_pkt_out_dropped = 0;
        sw->rx_pkt_in_dropped = 0;
    }

    if (c_switch_is_virtual(sw)) {
        return c_per_virt_sw_timer(sw, ctime);
    }

    /* This condition can occur when 1) Switch was previously marked
     * as having virtual connection and then due to HA failover, the
     * connection turned physical. In that case we mark the new 
     * switch as dead and make the existing virtual switch as physical
     * NOTE - In this case we make sure not to close the switch's fd.
     * 2) Switch with same dpid tried to connect and it was denied
     */ 
    if (sw->switch_state & SW_DEAD) {
        c_log_debug("[SWITCH] dead dp_id(0x%llx)", sw->DPID);
        sw->conn.dead ? c_conn_destroy(&sw->conn) : c_conn_events_del(&sw->conn);
        c_worker_do_switch_zap(sw->ctx, sw);
        return;
    }

    if (sw->conn.ssl && sw->conn.ssl_state == C_CONN_SSL_CONNECTING) {
        if (c_ssl_accept(&sw->conn) > 0) {
            c_log_err("|SWITCH| SSL timed I/O wait from switch %p", sw);
            return;
        }

        c_conn_assign_fd(&sw->conn, sw->conn.fd);
        c_switch_events_add(sw);
        of_send_hello(sw);
        return;
    }

    c_switch_ha_state_machine(sw);

    time_diff = ctime - sw->last_refresh_time;
    if (time_diff > C_SWITCH_IDLE_TIMEO) {
        c_log_warn("[SWITCH] |0x%llx| timed-out", sw->DPID);
        t_data->sw_list = g_slist_remove(t_data->sw_list, sw);
        c_worker_do_switch_del(sw->ctx, sw);
        return;
    }

    if (!(sw->switch_state & SW_REGISTERED)) {
        of_send_hello(sw);
        __of_send_echo_request(sw);
        __of_send_features_request(sw);
        return;
    } else if (!(sw->switch_state & SW_PUBLISHED)) {
        c_switch_try_publish(sw, false);
    }

    if (sw->switch_state & SW_HA_SYNCD_REQ &&
        c_switch_needs_state_sync(&ctrl_hdl) &&
        sw->last_sync_req) {
        time_t sync_diff = ctime - sw->last_sync_req;
        if (sync_diff  > C_SWITCH_HA_SYNC_TIMEO) {
            c_log_debug("|HA| Re-sync |0x%llx|", U642ULL(sw->DPID));
            c_ha_req_switch_state(sw->DPID);
            sw->last_sync_req = ctime;
        } 
    }

    if (1) {
        time_diff = ctime - sw->last_sample_time;
        if (time_diff > C_SWITCH_STAT_TIMEO) {
            c_per_switch_stats_scan(sw, ctime);
            sw->last_sample_time = time(NULL);
        }

        time_diff = ctime - sw->last_fp_aging_time;
        if (time_diff > C_SWITCH_FP_AGING_TIMEO) {
            if(sw->fp_ops.fp_aging && !ctrl_hdl.aging_off) {
                sw->fp_ops.fp_aging(sw, 0, false);
            }
            sw->last_fp_aging_time = time(NULL);
        }
    }

    if (!c_switch_of_master_check(&ctrl_hdl)) {
        sw->last_refresh_time = time(NULL);
        c_thread_sg_tx_sync(&sw->conn);
        return;
    }

    time_diff = ctime - sw->last_refresh_time;
    if (time_diff > C_SWITCH_ECHO_TIMEO) {
        of_send_echo_request(sw);
    }

    c_thread_sg_tx_sync(&sw->conn);
}

void
c_per_worker_timer_event(evutil_socket_t fd UNUSED, short event UNUSED, 
                         void *arg)
{
    struct c_worker_ctx *w_ctx  = arg;
    struct timeval      tv      = { C_PER_WORKER_TIMEO, 0 };
    c_per_thread_dat_t  *t_data = &w_ctx->thread_data;
    time_t              curr_time;

    curr_time = time(NULL);
    if (t_data->sw_list) {
        g_slist_foreach(t_data->sw_list, c_per_sw_timer, &curr_time); 
    }

    evtimer_add(w_ctx->worker_timer_event, &tv);
}

void
c_per_app_worker_timer_event(evutil_socket_t fd UNUSED, short event UNUSED, 
                         void *arg)
{
    struct c_app_ctx    *app_ctx  = arg;
    struct timeval      tv        = { C_PER_APP_WORKER_TIMEO, 0 };
    int                 i = 0;
    struct c_work_q     *wq;

    for (i = 0; i < ctrl_hdl.n_threads; i++) {
        wq = &app_ctx->work_qs[i];
        if (!wq->wq_conn.dead) continue;
        while ((wq->wq_conn.fd = c_client_socket_create("127.0.0.1",
                                             C_APP_WQ_LISTEN_PORT + i)) < 0) {
            c_log_err("%s: Unable to create conn to workq for thread(%d)",
                      FN, i);
            continue;
        }
        wq->wq_conn.rd_event = event_new(app_ctx->cmn_ctx.base,
                                     wq->wq_conn.fd,
                                     EV_READ|EV_PERSIST,
                                     c_app_workq_fb_thread_read, &wq->wq_conn);
        wq->wq_conn.wr_event = event_new(app_ctx->cmn_ctx.base,
                                     wq->wq_conn.fd,
                                     EV_WRITE, //|EV_PERSIST,
                                     c_thread_write_event, &wq->wq_conn);
        event_add(C_EVENT(wq->wq_conn.rd_event), NULL);
        c_log_info("[WORKQ] App(%d)->worker(%d) fd (%d) down->up",
                   app_ctx->thread_idx, i, wq->wq_conn.fd);

    }

    evtimer_add(app_ctx->app_main_timer_event, &tv);
}

void
c_worker_ipc_read(evutil_socket_t fd, short event UNUSED, void *arg)
{
    struct c_cmn_ctx    *cmn_ctx  = arg;
    ssize_t             ret;
    c_conn_t            *conn;
    int                 thread_idx;

    switch(cmn_ctx->thread_type) {
    case THREAD_WORKER:
        {
            struct c_worker_ctx *w_ctx = arg;
            conn = &w_ctx->main_wrk_conn;
            thread_idx = w_ctx->thread_idx;
            break;
        }
    case THREAD_APP: 
        {
            struct c_app_ctx *app_ctx = arg;
            conn = &app_ctx->main_wrk_conn;
            thread_idx = app_ctx->thread_idx;
            break;
        }
    default:
        c_log_err("[THREAD]Unhandled type(%u)", cmn_ctx->thread_type);
        return;
    }

   ret = c_socket_read_nonblock_loop(fd, arg, conn, CIPC_RCV_BUF_SZ,
                                     c_ipc_msg_rcv, c_ipc_get_data_len,
                                     c_ipc_hdr_valid, sizeof(struct c_ipc_hdr));

    if (c_recvd_sock_dead(ret)) {
        c_log_warn("[THREAD] type %u id %u ipc rd DEAD(%d)", 
                    cmn_ctx->thread_type, thread_idx, (int)ret);
        perror("[ipc-socket]");
        event_free(C_EVENT(conn->rd_event));
    }

    return;
}

void
c_thread_write_event(evutil_socket_t fd UNUSED, short events UNUSED, void *arg)
{
    c_conn_t *conn = arg;

    if (conn->rd_blk_on_wr) {
        conn->rd_blk_on_wr = 0;
        event_active(conn->rd_event, EV_READ, 0);
    }

    c_wr_lock(&conn->conn_lock);
    c_socket_write_nonblock_loop(conn, c_write_event_sched);
    c_wr_unlock(&conn->conn_lock);
}

static int __fastpath
c_switch_read_nonblock_loop(int fd, void *arg, c_conn_t *conn,
                            const size_t rcv_buf_sz, 
                            conn_proc_t proc_msg )
{
    ssize_t rd_sz = -1, proc_sz = 0;
    size_t curr_buf_sz;
    struct cbuf curr_b, *b = NULL;
    int loop_cnt = 0;

    if (conn->wr_blk_on_rd) {
        conn->wr_blk_on_rd = 0;
        c_log_debug("[SSL] enabling blocked write");  
        event_active(conn->wr_event, EV_WRITE, 0);
    }

    if (conn->rd_blk_on_wr) {
        errno = EAGAIN;
        return -1;
    }

    if (!conn->cbuf) {
        b = alloc_cbuf(rcv_buf_sz);
    } else {
        b = conn->cbuf; 
    }

    while (1) {
        if (cbuf_tailroom(b) < sizeof(struct ofp_header)) {
            b = cbuf_realloc_tailroom(b, rcv_buf_sz, true);
        }

        if (++loop_cnt < 100) {
            if (conn->ssl) {
                rd_sz = SSL_read(conn->ssl, b->tail, cbuf_tailroom(b));
                if (rd_sz <=0) {
                    switch(SSL_get_error(conn->ssl, rd_sz)){
                    case SSL_ERROR_NONE:
                        break;
                    case SSL_ERROR_ZERO_RETURN:
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        conn->rd_blk_on_wr = 1;
                        /* Fall through */
                    case SSL_ERROR_WANT_READ:
                        rd_sz = -1;
                        errno = EAGAIN;
                        break;
                    default:
                        break;
                    }
                }
            } else {
                rd_sz = recv(fd, b->tail, cbuf_tailroom(b), 0);
            }
        } else {
            errno = EAGAIN;
            rd_sz = -1;
        }

        c_thread_sg_tx_sync(conn);

        if (rd_sz <= 0) {
            conn->cbuf = b;
            if (conn->rd_blk_on_wr) {
                c_write_event_sched(conn);
            }
            break;
        }

        cbuf_put_inline(b, rd_sz);

        while (1) {
            if (unlikely(b->len < sizeof(struct ofp_header))) {
                break;
            }

            curr_buf_sz = of_get_data_len(CBUF_DATA(b));
            if (unlikely(!__of_hdr_valid(b->data, curr_buf_sz))) {
                c_log_err("[I/O] Corrupted header(Ignored)");
                if (b) free_cbuf(b);
                conn->cbuf = NULL;
                return c_socket_drain_nonblock(fd); /* Hope peer behaves now */
            }

            if (unlikely(b->len < curr_buf_sz)) {
                break;
            }

            curr_b.data = b->data;
            curr_b.len = curr_buf_sz;
            curr_b.tail = b->data + curr_b.len;
            proc_sz += curr_b.len;

            proc_msg(arg, &curr_b);
            cbuf_pull_inline(b, curr_b.len);

            c_thread_sg_tx_sync(conn);
        }

        if (likely(proc_sz == rd_sz)) {
            b->data -= rd_sz;
            b->tail -= rd_sz;
        }
        proc_sz = 0;
    }

    return rd_sz;
}

static void
c_switch_events_add(c_switch_t *sw)
{
    struct c_worker_ctx *wrk_ctx = sw->ctx;

    /* conn fd has to be valid here */
    sw->conn.rd_event = event_new(wrk_ctx->cmn_ctx.base,
                                  sw->conn.fd,
                                  EV_READ|EV_PERSIST,
                                  c_switch_thread_read, sw);
    sw->conn.wr_event = event_new(wrk_ctx->cmn_ctx.base,
                                  sw->conn.fd,
                                  EV_WRITE, //|EV_PERSIST,
                                  c_thread_write_event, &sw->conn);

    event_add(C_EVENT(sw->conn.rd_event), NULL);
}

void __fastpath
c_switch_thread_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    c_switch_t          *sw = arg;
    int                 ret;
    struct c_worker_ctx *w_ctx = sw->ctx;

    ret = c_switch_read_nonblock_loop(fd, sw, &sw->conn, OFC_RCV_BUF_SZ,
                                      c_switch_recv_msg);
    if (c_recvd_sock_dead(ret)) {
        perror("[I/O] |switch|");
        c_worker_do_switch_del(w_ctx, sw);
    } 

    return;
}

#ifdef C_VIRT_CON_HA

static void
c_switch_recv_blackhole(void *sw_arg UNUSED, struct cbuf *b UNUSED)
{
    c_log_err("[SWITCH] RX blackhole");
}

static void
c_switch_ha_state_machine(c_switch_t *sw)
{
    struct cbuf *b;

    if (!c_ha_master(sw->c_hdl)) {
        return;
    }

    switch (sw->ha_state) {
    case SW_HA_NONE:
        c_switch_ha_add(sw, false);
        break;
    case SW_HA_CONNECTED:
        if (sw->switch_state & SW_REGISTERED) {
            assert(sw->ofp_priv_procs->mk_ofp_features);
            b = sw->ofp_priv_procs->mk_ofp_features(sw);
            __of_ha_proc(sw, b, true);
            c_switch_rlim_sync(sw);
            c_flow_traverse_tbl_all(sw, NULL, c_switch_flow_ha_sync);
            c_switch_group_traverse_all(sw, sw, c_switch_group_ha_sync);
            c_switch_group_traverse_all(sw, sw, c_switch_meter_ha_sync);
            sw->ha_state = SW_HA_SYNCED;
            c_rd_unlock(&sw->lock);
        }
        break;
    default:
        break;
    }
}

static void 
c_switch_ha_thread_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    c_switch_t          *sw = arg;
    int                 ret;

    ret = c_switch_read_nonblock_loop(fd, sw, &sw->ha_conn, OFC_RCV_BUF_SZ,
                                      c_switch_recv_blackhole);
    if (c_recvd_sock_dead(ret)) {
        perror("[I/O] |HA-conn|");
        c_switch_ha_del(sw);
    } 

    return;
}

static void
c_switch_ha_add(c_switch_t *sw, bool slave)
{
    struct c_cmn_ctx *cmn_ctx = sw->ctx;
    ctrl_hdl_t *ctrl          = cmn_ctx->c_hdl;

    if (slave) {
        sw->ha_state = SW_HA_VIRT;
        c_log_info("[SWITCH] virt added");
        return;
    }

    if (!c_ha_master(sw->c_hdl)) {
        c_log_err("[SWITCH] Not master");
        c_conn_mark_dead(&sw->ha_conn);
        return;
    }

    sw->ha_conn.fd = c_client_socket_create(ctrl->c_peer,
                                            MUL_CORE_HA_SERVICE_PORT);
    if (sw->ha_conn.fd > 0 ) {
        sw->ha_conn.rd_event = event_new(cmn_ctx->base,
                                     sw->ha_conn.fd,
                                     EV_READ|EV_PERSIST,
                                     c_switch_ha_thread_read, sw);
        sw->ha_conn.wr_event = event_new(cmn_ctx->base,
                                     sw->ha_conn.fd,
                                     EV_WRITE, //|EV_PERSIST,
                                     c_thread_write_event, &sw->ha_conn);
        event_add(C_EVENT(sw->ha_conn.rd_event), NULL);
        sw->ha_state = SW_HA_CONNECTED;
        c_conn_prep(&sw->ha_conn);
        c_log_info("[SWITCH] HA connected");
    } else {
        c_conn_mark_dead(&sw->ha_conn);
    }
}

static void
c_switch_ha_del(c_switch_t *sw)
{
    if (sw->ha_state == SW_HA_VIRT) {
        return;
    }

    c_conn_destroy(&sw->ha_conn);
    sw->ha_state = SW_HA_NONE;
}

#else

static void
c_switch_ha_state_machine(c_switch_t *sw UNUSED)
{
    return;
}

static void
c_switch_ha_add(c_switch_t *sw UNUSED, bool slave UNUSED)
{
    return;
}

static void
c_switch_ha_del(c_switch_t *sw UNUSED)
{
    return;
}
#endif

static void
c_workq_thread_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    int                 ret;
    struct c_work_q     *wq = arg;

    ret = c_socket_read_nonblock_loop(fd, wq, &wq->wq_conn, OFC_RCV_BUF_SZ,
                                      (conn_proc_t)__mul_app_workq_handler, 
                                      of_get_data_len, of_hdr_valid, 
                                      sizeof(struct ofp_header));
    if (c_recvd_sock_dead(ret)) {
        c_log_err("[WQ] conn dead");
        c_conn_destroy(&wq->wq_conn);
    } 

    return;
}

static void
c_app_thread_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    c_app_info_t        *app = arg;
    int                 ret;
    struct c_app_ctx    *app_ctx = app->ctx;

    ret = c_socket_read_nonblock_loop(fd, app, &app->app_conn, OFC_RCV_BUF_SZ,
                                      (conn_proc_t)__mul_app_command_handler, 
                                      of_get_data_len, of_hdr_valid, 
                                      sizeof(struct ofp_header));
    if (c_recvd_sock_dead(ret)) {
        c_log_err("[APP] |%s| conn dead", 
                  app->app_flags & C_APP_AUX_REMOTE ?"Aux":"Normal");
        perror("[app-socket]");
        c_worker_do_app_del(app_ctx, app);
    } 

    return;
}

void
c_worker_do_app_del(struct c_app_ctx *c_app_ctx, 
                    c_app_info_t *app)
{
    c_per_thread_dat_t  *t_data = &c_app_ctx->thread_data;

    /* FIXME: Can we can survive app conn reset ?? */
    //if (errno == ECONNRESET) 
    //    return;

    c_conn_destroy(&app->app_conn);
    t_data->app_list = g_slist_remove(t_data->app_list, app);

    if (!(app->app_flags & C_APP_AUX_REMOTE)) 
        mul_unregister_app(app->app_name);

    c_app_put(app);
}

void
c_worker_do_switch_zap(struct c_worker_ctx *c_wrk_ctx,
                       c_switch_t *sw)
{
    c_per_thread_dat_t  *t_data = &c_wrk_ctx->thread_data;

    t_data->sw_list = g_slist_remove(t_data->sw_list, sw);
    c_switch_ha_del(sw);
    c_switch_del(sw);
    c_switch_put(sw);
}

void
c_worker_do_switch_del(struct c_worker_ctx *c_wrk_ctx, 
                       c_switch_t *sw)
{
    c_conn_destroy(&sw->conn);

    if (!c_switch_is_virtual(sw)) {
        c_worker_do_switch_zap(c_wrk_ctx, sw);
    } else {
        c_switch_mark_sticky_del(sw);
    }
}

static int
c_worker_do_app_add(void *ctx_arg, void *msg_arg)
{
    struct c_app_ctx        *app_wrk_ctx  = ctx_arg;
    struct c_ipc_thread_msg *msg          = msg_arg;
    c_per_thread_dat_t      *t_data       = &app_wrk_ctx->thread_data;
    c_app_info_t            *app          = NULL;
    struct sockaddr_in      peer_addr;
    socklen_t               peer_sz       = sizeof(peer_addr);

    if (getpeername(msg->new_conn_fd, (void *)&peer_addr, &peer_sz) < 0) {
        c_log_err("[APP] get peer failed");
        return -1;
    }

    if (!(app = c_app_alloc(app_wrk_ctx))) {
        return -1;
    } 

    t_data->app_list = g_slist_append(t_data->app_list, app);
    c_conn_assign_fd(&app->app_conn, msg->new_conn_fd);

    if (msg->aux_conn_valid && msg->aux_conn) {
        c_log_debug("[APP] auxiliary conn");
        c_aux_app_init(app);
    }

    app->peer_addr = peer_addr;

    app->app_conn.rd_event = event_new(app_wrk_ctx->cmn_ctx.base,
                                       msg->new_conn_fd,
                                       EV_READ|EV_PERSIST,
                                       c_app_thread_read, app);
    app->app_conn.wr_event = event_new(app_wrk_ctx->cmn_ctx.base,
                                       msg->new_conn_fd,
                                       EV_WRITE, //|EV_PERSIST,
                                       c_thread_write_event, 
                                       &app->app_conn);
    event_add(C_EVENT(app->app_conn.rd_event), NULL);

    return 0;
}

static int
c_worker_do_switch_add(void *ctx_arg, void *msg_arg)
{
    struct c_worker_ctx     *c_wrk_ctx  = ctx_arg;
    struct c_ipc_thread_msg *msg        = msg_arg;
    c_per_thread_dat_t      *t_data     = &c_wrk_ctx->thread_data;
    c_switch_t              *new_switch;

    if (!msg->new_conn_fd_valid) {
        c_log_err("field invalid indicated");
        return -1;
    }


#ifdef C_VIRT_CON_HA
    /* Prevent switch connection to slave controller node 
     * if running in active-standy mode
     */
    if (c_ha_slave(c_wrk_ctx->cmn_ctx.c_hdl) && !msg->ha_conn) {
        c_log_err("[SWITCH] Denied connect to slave"); 
        close(msg->new_conn_fd);
        return -1;
    } 
#endif

    c_log_debug("[SWITCH] Pinned to thread |%u|", (unsigned)c_wrk_ctx->thread_idx);

    new_switch = c_switch_alloc(c_wrk_ctx);

    t_data->sw_list = g_slist_append(t_data->sw_list, new_switch);
    new_switch->c_hdl = c_wrk_ctx->cmn_ctx.c_hdl;

    if (ctrl_hdl.ssl_ctx) {
        new_switch->conn.ssl = SSL_new(ctrl_hdl.ssl_ctx);
        if (!new_switch->conn.ssl) {
            c_log_err("[SWITCH] New ssl failed"); 
            goto out_err;
        }

        SSL_set_fd(new_switch->conn.ssl, msg->new_conn_fd);
        if (c_ssl_accept(&new_switch->conn) > 0) {
            c_conn_assign_fd(&new_switch->conn, msg->new_conn_fd);
            c_log_err("|SWITCH| SSL I/O wait from switch %p |%d|",
                      new_switch, msg->new_conn_fd);
            return 0; /* SSL need's IO */
        }
    }

    c_conn_assign_fd(&new_switch->conn, msg->new_conn_fd);
    c_switch_events_add(new_switch);
    c_switch_ha_add(new_switch, msg->ha_conn);

    of_send_hello(new_switch);

    return 0;

out_err:
    c_worker_do_switch_zap(c_wrk_ctx, new_switch);
    return -1;
}

int
c_worker_event_new_conn(void *ctx_arg, void *msg_arg)
{
    struct c_cmn_ctx *c_ctx = ctx_arg;

    switch(c_ctx->thread_type) {
    case THREAD_WORKER:
        return c_worker_do_switch_add(ctx_arg, msg_arg);
    case THREAD_APP:
        return c_worker_do_app_add(ctx_arg, msg_arg);
    }

    return -1;
}

static int
c_new_conn_to_thread(struct c_main_ctx *m_ctx, int new_conn_fd,
                     c_event_conn_t conn_type, bool aux_conn)
{
    struct c_ipc_hdr        *ipc_hdr;
    struct c_ipc_thread_msg *ipc_t_msg;
    int                     thread_idx, ipc_wr_fd = -1;

    ipc_hdr = alloc_ipc_msg(C_IPC_THREAD, C_IPC_THREAD_NEW_CONN_FD);
    if (!ipc_hdr) {
        c_log_warn("ipc msg alloc failed");
        return -1;
    }

    ipc_t_msg = (void *)(ipc_hdr + 1);
    ipc_t_msg->new_conn_fd = new_conn_fd;
    ipc_t_msg->new_conn_fd_valid = 1;

    switch (conn_type) {
    case C_EVENT_NEW_SW_CONN:
        thread_idx = c_get_new_switch_worker(m_ctx);
        ipc_wr_fd  = c_tid_to_ipc_wr_fd(m_ctx, thread_idx);
        break;
    case C_EVENT_NEW_APP_CONN:
        thread_idx = c_get_new_app_worker(m_ctx);
        ipc_wr_fd  = c_tid_to_app_ipc_wr_fd(m_ctx, thread_idx);
        if (aux_conn) {
            ipc_t_msg->aux_conn = 1;
            ipc_t_msg->aux_conn_valid = 1;
        }
        break;
    case C_EVENT_NEW_HA_CONN:
        thread_idx = c_get_new_switch_worker(m_ctx);
        ipc_wr_fd  = c_tid_to_ipc_wr_fd(m_ctx, thread_idx);
        ipc_t_msg->ha_conn = 1;
        ipc_t_msg->ha_conn_valid = 1;
        break;
    }

    return c_send_unicast_ipc_msg(ipc_wr_fd, ipc_hdr); 
}

extern int c_sock_set_sndbuf (int fd, size_t size);

static int
c_common_accept(evutil_socket_t listener)
{
    struct sockaddr_storage ss;
    socklen_t               slen = sizeof(ss);
    int fd                  = accept(listener, (struct sockaddr*)&ss, &slen);

    if (fd < 0) {
        perror("accept");
        return -1;
    } else if (fd > FD_SETSIZE) {
        close(fd);
        return -1;
    } else {
        c_make_socket_nonblocking(fd);
    }

    return fd;
}

void
c_app_wq_accept(evutil_socket_t listener, short event UNUSED, void *arg)
{
    struct c_worker_ctx   *w_ctx = arg;
    int                 fd = 0;
    int                 i = 0;
    struct c_work_q     *wq;

    if ((fd = c_common_accept(listener)) < 0)  {
        return;
    }

    for (i = 0; i < ctrl_hdl.n_appthreads; i++) {
        wq = &w_ctx->work_qs[i];

        if (wq->wq_conn.fd > 0)  continue; 

        c_conn_assign_fd(&wq->wq_conn, fd);

        wq->wq_conn.rd_event = event_new(w_ctx->cmn_ctx.base,
                                         fd,
                                         EV_READ|EV_PERSIST,
                                         c_workq_thread_read, wq);
        event_add(C_EVENT(wq->wq_conn.rd_event), NULL);
        c_log_info("[WORKQ] worker(%d)<-app new-conn",
                   w_ctx->thread_idx);
        break;
    }

    if (i >= ctrl_hdl.n_appthreads) {
        c_log_err("Can't map incoming workq conn to worker");
        assert(0);
    }
}

void
c_accept(evutil_socket_t listener, short event UNUSED, void *arg)
{
    struct c_main_ctx   *m_ctx = arg;
    int                 fd = 0;

    if ((fd = c_common_accept(listener)) < 0)  {
        return;
    }

    c_sock_set_recvbuf(fd, 1*1024*1024);
    c_sock_set_sndbuf(fd, 3*1024*1024);
    c_tcpsock_set_nodelay(fd);

    c_new_conn_to_thread(m_ctx, fd, C_EVENT_NEW_SW_CONN, false);
}

void
c_ha_accept(evutil_socket_t listener, short event UNUSED, void *arg)
{
    struct c_main_ctx   *m_ctx = arg;
    int                 fd = 0;

    if ((fd = c_common_accept(listener)) < 0)  {
        return;
    }

    c_new_conn_to_thread(m_ctx, fd, C_EVENT_NEW_HA_CONN, false);
}

void
c_app_accept(evutil_socket_t listener, short event UNUSED, void *arg)
{
    struct c_main_ctx   *m_ctx = arg;
    int                 fd = 0;

    if ((fd = c_common_accept(listener)) < 0)  {
        return;
    }

    c_new_conn_to_thread(m_ctx, fd, C_EVENT_NEW_APP_CONN, false);
}

void
c_aux_app_accept(evutil_socket_t listener, short event UNUSED, void *arg)
{
    struct c_main_ctx   *m_ctx = arg;
    int                 fd = 0;

    if ((fd = c_common_accept(listener)) < 0)  {
        return;
    }

    c_new_conn_to_thread(m_ctx, fd, C_EVENT_NEW_APP_CONN, true);
}
