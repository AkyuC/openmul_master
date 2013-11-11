/*
 *  mul_events.c: MUL event handling 
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

void c_worker_do_switch_del(struct c_worker_ctx *c_wrk_ctx, c_switch_t *sw);
void c_worker_do_app_del(struct c_app_ctx *c_app_ctx, c_app_info_t *app);
void c_worker_do_switch_zap(struct c_worker_ctx *c_wrk_ctx, c_switch_t *sw);

static void c_switch_events_add(c_switch_t *sw);

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
        c_log_err("%s: Switch marked dead", FN);
        time_diff = ctime - sw->last_refresh_time;
        if (time_diff > C_SWITCH_ECHO_TIMEO) {
            return c_worker_do_switch_zap(sw->ctx, sw);
        }

        return;
    } else if (sw->switch_state & SW_REINIT ||
               sw->switch_state & SW_REINIT_VIRT) {
        c_log_err("%s: Switch marked for reinit", FN);
        c_conn_destroy(&sw->conn);
        c_conn_assign_fd(&sw->conn, sw->reinit_fd);
        sw->reinit_fd = 0;
        c_switch_events_add(sw);
        if (sw->switch_state & SW_REINIT) {
            sw->ha_state = SW_HA_NONE;
            c_per_switch_flow_resync_hw(sw, NULL, NULL);
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
    time_t              time    = *(time_t *)arg_time;
    time_t              time_diff;
    c_per_thread_dat_t  *t_data = &w_ctx->thread_data;

    if (c_switch_is_virtual(sw)) {
        return c_per_virt_sw_timer(sw, time);
    }

    /* This condition can occur when 1) Switch was previously marked
     * as having virtual connection and then due to HA failover, the
     * connection turned physical. In that case we mark the new 
     * switch as dead and make the existing virtual switch as physical
     * NOTE - In this case we make sure not to close the switch's fd.
     * 2) Switch with same dpid tried to connect and it was denied
     */ 
    if (sw->switch_state & SW_DEAD) {
        c_log_debug("Switch dead dp_id(0x%llx)\n", sw->DPID);
        sw->conn.dead ? c_conn_destroy(&sw->conn) : c_conn_events_del(&sw->conn);
        c_worker_do_switch_zap(sw->ctx, sw);
        return;
    }



    time_diff = time - sw->last_refresh_time;
    if (time_diff > C_SWITCH_IDLE_TIMEO) {
        c_log_debug("Timing out switch_id(0x%llx)\n", sw->DPID);
        t_data->sw_list = g_slist_remove(t_data->sw_list, sw);
        c_worker_do_switch_del(sw->ctx, sw);

        return;
    }

    if (!(sw->switch_state & SW_REGISTERED)) {
        __of_send_features_request(sw);
        return;
    }

    if (time_diff > C_SWITCH_ECHO_TIMEO) {
        of_send_echo_request(sw);
    }

    if (sw->capabilities & OFPC_FLOW_STATS) {
        time_diff = time - sw->last_sample_time;

        if (time_diff > C_SWITCH_STAT_TIMEO) {
            c_per_switch_flow_stats_scan(sw, time);
        }
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
        c_log_err("%s: Unhandled thread type(%u)", FN, cmn_ctx->thread_type);
        return;
    }

   ret = c_socket_read_nonblock_loop(fd, arg, conn, CIPC_RCV_BUF_SZ,
                                     c_ipc_msg_rcv, c_ipc_get_data_len,
                                     c_ipc_hdr_valid, sizeof(struct c_ipc_hdr));

    if (c_recvd_sock_dead(ret)) {
        c_log_warn("Thread type %u id %u ipc rd socket:DEAD(%d)", 
                    cmn_ctx->thread_type, thread_idx, (int)ret);
        perror("ipc-socket");
        event_free(C_EVENT(conn->rd_event));
    }

    return;
}

void
c_thread_write_event(evutil_socket_t fd UNUSED, short events UNUSED, void *arg)
{
    c_conn_t *conn = arg;

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
            rd_sz = recv(fd, b->tail, cbuf_tailroom(b), 0);
        } else {
            rd_sz = -1;
        }

        c_thread_sg_tx_sync(conn);

        if (rd_sz <= 0) {
            conn->cbuf = b;
            break;
        }

        cbuf_put_inline(b, rd_sz);

        while (1) {
            if (unlikely(b->len < sizeof(struct ofp_header))) {
                break;
            }

            curr_buf_sz = of_get_data_len(CBUF_DATA(b));
            if (unlikely(!__of_hdr_valid(b->data, curr_buf_sz))) {
                c_log_err("%s: Corrupted header(Ignored)", FN);
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
        perror("c_switch_thread_read");
        c_worker_do_switch_del(w_ctx, sw);
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
        c_log_err("%s Application socket dead", 
                  app->app_flags & C_APP_AUX_REMOTE ?"Aux":"");
        perror("app-socket");
        c_worker_do_app_del(app_ctx, app);
    } 

    return;
}

void
c_worker_do_app_del(struct c_app_ctx *c_app_ctx, 
                    c_app_info_t *app)
{
    c_per_thread_dat_t  *t_data = &c_app_ctx->thread_data;

    c_conn_destroy(&app->app_conn);
    t_data->app_list = g_slist_remove(t_data->app_list, app);

    if (!(app->app_flags & C_APP_AUX_REMOTE)) 
        mul_unregister_app(app->app_name);
}

void
c_worker_do_switch_zap(struct c_worker_ctx *c_wrk_ctx,
                       c_switch_t *sw)
{
    c_per_thread_dat_t  *t_data = &c_wrk_ctx->thread_data;

    t_data->sw_list = g_slist_remove(t_data->sw_list, sw);
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
        c_log_err("%s:get peer failed", FN);
        return -1;
    }

    if (!(app = c_app_alloc(app_wrk_ctx))) {
        return -1;
    } 

    t_data->app_list = g_slist_append(t_data->app_list, app);
    c_conn_assign_fd(&app->app_conn, msg->new_conn_fd);

    if (msg->aux_conn_valid && msg->aux_conn) {
        c_log_debug("%s:new aux app", FN);
        c_aux_app_init(app);
    }

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

    c_log_debug("New switch to thread (%u)\n", (unsigned)c_wrk_ctx->thread_idx);

    new_switch = c_switch_alloc(c_wrk_ctx);

    t_data->sw_list = g_slist_append(t_data->sw_list, new_switch);
    new_switch->c_hdl = c_wrk_ctx->cmn_ctx.c_hdl;
    c_conn_assign_fd(&new_switch->conn, msg->new_conn_fd);
    c_switch_events_add(new_switch);

    of_send_hello(new_switch);

    return 0;
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
        free(ipc_hdr);
        c_log_err("ipc type not implemented");
        return -1;
    }

    return c_send_unicast_ipc_msg(ipc_wr_fd, ipc_hdr); 
}


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
