/*
 *  mul_thread_core.c: MUL threading infrastructure 
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

void *c_thread_main(void *arg);
int  c_vty_thread_run(void *arg);

int
c_set_thread_dfl_affinity(void)
{
    extern ctrl_hdl_t ctrl_hdl;
    cpu_set_t cpu;

    /* Set cpu affinity */
    CPU_ZERO(&cpu);
    CPU_SET(ctrl_hdl.n_threads + ctrl_hdl.n_appthreads, &cpu);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu);

    return 0;
}

/* TODO : Better Algo */
int
c_get_new_switch_worker(struct c_main_ctx *m_ctx) 
{
    m_ctx->switch_lb_hint = (m_ctx->switch_lb_hint + 1) % m_ctx->nthreads;
    return m_ctx->switch_lb_hint;
}

int
c_get_new_app_worker(struct c_main_ctx *m_ctx) 
{
    m_ctx->app_lb_hint = (m_ctx->app_lb_hint + 1) % m_ctx->n_appthreads;
    return m_ctx->app_lb_hint;
}

static void *
c_alloc_thread_ctx(struct thread_alloc_args *args)
{
    void *ctx;

    switch(args->thread_type) {
    case THREAD_MAIN: 
        {
            struct c_main_ctx *m_ctx;

            assert(args->nthreads > 0 && args->nthreads <= C_MAX_THREADS);
            assert(args->n_appthreads >= 0 && 
                   args->n_appthreads <= C_MAX_APP_THREADS);
            m_ctx = calloc(1, sizeof(struct c_main_ctx));
            assert(m_ctx);

            ctx = m_ctx;
            m_ctx->nthreads = args->nthreads; 
            m_ctx->n_appthreads = args->n_appthreads; 
            m_ctx->cmn_ctx.thread_type = args->thread_type; 
            m_ctx->cmn_ctx.c_hdl = args->c_hdl;
            break;
        }
    case THREAD_WORKER:
        {
            struct c_worker_ctx *w_ctx;
            w_ctx = calloc(1, sizeof(struct c_worker_ctx));      
            assert(w_ctx);

            ctx = w_ctx;
            w_ctx->cmn_ctx.thread_type = args->thread_type;    
            w_ctx->cmn_ctx.c_hdl = args->c_hdl;
            w_ctx->thread_idx = args->thread_idx;
            break;
        }
    case THREAD_VTY:
        {
            struct c_vty_ctx *vty_ctx;
            vty_ctx = calloc(1, sizeof(struct c_vty_ctx));      
            assert(vty_ctx);

            ctx = vty_ctx;
            vty_ctx->cmn_ctx.thread_type = args->thread_type;    
            vty_ctx->cmn_ctx.c_hdl = args->c_hdl;
            break;
        }
    case THREAD_APP:
        {
            struct c_app_ctx *app_ctx;
            app_ctx = calloc(1, sizeof(struct c_app_ctx));      
            assert(app_ctx);

            ctx = app_ctx;
            app_ctx->cmn_ctx.thread_type = args->thread_type;    
            app_ctx->thread_idx = args->thread_idx;    
            app_ctx->cmn_ctx.c_hdl = args->c_hdl;
            break;
        }
    default:
        return NULL;

    }

    return ctx;
}

static int
c_worker_thread_final_init(struct c_worker_ctx *w_ctx)
{
    cpu_set_t           cpu;
    char                ipc_path_str[64];
    struct timeval      tv = { C_PER_WORKER_TIMEO, 0 };
    int                 i = 0;
    int                 c_listener = 0;
    extern ctrl_hdl_t   ctrl_hdl;

    w_ctx->cmn_ctx.base = event_base_new();
    assert(w_ctx->cmn_ctx.base);

    snprintf(ipc_path_str, 63, "%s%d", C_IPC_PATH, w_ctx->thread_idx);
    w_ctx->main_wrk_conn.rd_fd = open(ipc_path_str, O_RDONLY | O_NONBLOCK);
    assert(w_ctx->main_wrk_conn.rd_fd > 0);

    w_ctx->main_wrk_conn.rd_event = event_new(w_ctx->cmn_ctx.base, 
                                         w_ctx->main_wrk_conn.rd_fd,
                                         EV_READ|EV_PERSIST,
                                         c_worker_ipc_read, (void*)w_ctx);
    event_add(w_ctx->main_wrk_conn.rd_event, NULL);

    w_ctx->worker_timer_event = evtimer_new(w_ctx->cmn_ctx.base, 
                                            c_per_worker_timer_event, 
                                            (void *)w_ctx);
    evtimer_add(w_ctx->worker_timer_event, &tv);

    for (i = 0; i < ctrl_hdl.n_appthreads; i++) {
        nbq_init(&w_ctx->work_qs[i].q);
    }

    c_listener = c_server_socket_create(INADDR_ANY,
                                        C_APP_WQ_LISTEN_PORT+w_ctx->thread_idx);
    assert(c_listener);
    w_ctx->c_app_accept_event = event_new(w_ctx->cmn_ctx.base,
                                          c_listener,
                                          EV_READ|EV_PERSIST,
                                          c_app_wq_accept,
                                          (void*)w_ctx);
    event_add(w_ctx->c_app_accept_event, NULL);

    /* Set cpu affinity */
    CPU_ZERO(&cpu);
    CPU_SET(w_ctx->thread_idx, &cpu);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu);

    w_ctx->cmn_ctx.run_state = THREAD_STATE_RUNNING;

    return 0;
}

static void
c_main_thread_timer_event(evutil_socket_t fd UNUSED, short event UNUSED,
                         void *arg)
{
    struct c_main_ctx   *m_ctx  = arg;
    struct timeval      tv      = { C_MAIN_THREAD_TIMEO , 0 };

    evtimer_add(m_ctx->main_timer_event, &tv);
}

static void
c_thread_ssl_lock_cb(int mode, int n,
                     const char * file UNUSED,
                     int line UNUSED)
{
    extern ctrl_hdl_t ctrl_hdl;

    if (mode & CRYPTO_LOCK)
        c_wr_lock(&ctrl_hdl.ssl_thread_locks[n]);
    else
        c_wr_unlock(&ctrl_hdl.ssl_thread_locks[n]);
}

static
unsigned long c_thread_ssl_id_cb(void)
{
    return ((unsigned long)(pthread_self()));
}

static struct CRYPTO_dynlock_value *
c_dyn_lock_create_cb(const char *file UNUSED, int line UNUSED)
{
    struct CRYPTO_dynlock_value *value;

    value = (struct CRYPTO_dynlock_value *)
                malloc(sizeof(struct CRYPTO_dynlock_value));
    if (!value) {
        goto err;
    }
    c_rw_lock_init(&value->lock);
    return value;

err:
    return (NULL);
}

static void
c_dyn_lock_cb(int mode, struct CRYPTO_dynlock_value *l,
              const char *file UNUSED, int line UNUSED)
{
    if (mode & CRYPTO_LOCK) {
        c_wr_lock(&l->lock);
    } else {
        c_wr_unlock(&l->lock);
    }
}

static void
c_dyn_lock_destroy_cb(struct CRYPTO_dynlock_value *l,
                      const char *file UNUSED, int line UNUSED)
{
    c_rw_lock_destroy(&l->lock);
    free(l);
}

static DH *
tmp_dh_callback(SSL *ssl UNUSED, int is_export UNUSED, int keylength)
{
    struct dh {
        int keylength;
        DH *dh;
        DH *(*constructor)(void);
    };

    static struct dh dh_table[] = {
        {1024, NULL, get_dh1024},
        {2048, NULL, get_dh2048},
        {4096, NULL, get_dh4096},
    };

    struct dh *dh;
    int size = sizeof(dh_table)/sizeof(dh_table[0]);

    for (dh = dh_table; dh < &dh_table[size]; dh++) {
        if (dh->keylength == keylength) {
            if (!dh->dh) {
                dh->dh = dh->constructor();
                assert(dh->dh);
            }
            return dh->dh;
        }
    }
    if (!c_rlim(&crl))
        c_log_err("|SSL| Diffie-Hellman parameters for key length %d",
                  keylength);

    return NULL;
}

static int
c_main_thread_final_init(struct c_main_ctx *m_ctx)
{
    evutil_socket_t             c_listener;
    struct c_worker_ctx         *w_ctx, **w_ctx_slot;
    struct c_vty_ctx            *vty_ctx;
    struct c_app_ctx            *app_ctx, **app_ctx_slot;
    char                        ipc_path_str[64];
    int                         thread_idx;
    ctrl_hdl_t                  *ctrl_hdl = m_ctx->cmn_ctx.c_hdl;
    struct timeval              tv = { C_MAIN_THREAD_BOOT_TIMEO , 0 };
    struct thread_alloc_args    t_args = { 0, 0, 
                                           THREAD_WORKER, 
                                           0, 
                                           m_ctx->cmn_ctx.c_hdl };

    m_ctx->cmn_ctx.base = event_base_new();
    assert(m_ctx->cmn_ctx.base); 

    m_ctx->worker_pool = calloc(m_ctx->nthreads, sizeof(void *));
    assert(m_ctx->worker_pool);

    m_ctx->app_pool = calloc(m_ctx->n_appthreads, sizeof(void *));
    assert(m_ctx->app_pool);

    /* Worker thread creation */
    for (thread_idx = 0; thread_idx < m_ctx->nthreads; thread_idx++) {
        w_ctx_slot = c_tid_to_ctx_slot(m_ctx, thread_idx);

        t_args.thread_idx = thread_idx;
        w_ctx = c_alloc_thread_ctx(&t_args);
        assert(w_ctx);

        *w_ctx_slot = w_ctx;
        
        memset(ipc_path_str, 0, sizeof(ipc_path_str));
        snprintf(ipc_path_str, 63, "%s%d", C_IPC_PATH, thread_idx); 
        if (mkfifo(ipc_path_str, S_IRUSR | S_IWUSR | S_IWGRP) == -1
            && errno != EEXIST) {
            perror("");
            assert(0);
        }

        pthread_create(&w_ctx->cmn_ctx.thread, NULL, c_thread_main, w_ctx);

        w_ctx->main_wrk_conn.conn_type = C_CONN_TYPE_FILE;
        w_ctx->main_wrk_conn.fd = open(ipc_path_str, O_WRONLY);
        assert(w_ctx->main_wrk_conn.fd > 0);

        ctrl_hdl->worker_ctx_list[thread_idx] = (void *)w_ctx;

    }

    /* Application thread creation */
    for (thread_idx = 0; thread_idx < m_ctx->n_appthreads; thread_idx++) {
        app_ctx_slot = c_tid_to_app_ctx_slot(m_ctx, thread_idx);

        t_args.thread_type = THREAD_APP;
        t_args.thread_idx = thread_idx;
        app_ctx = c_alloc_thread_ctx(&t_args);
        assert(app_ctx);

        *app_ctx_slot = app_ctx;

        memset(ipc_path_str, 0, sizeof(ipc_path_str));
        snprintf(ipc_path_str, 63, "%s%d", C_IPC_APP_PATH, thread_idx); 
        if (mkfifo(ipc_path_str, S_IRUSR | S_IWUSR | S_IWGRP) == -1
            && errno != EEXIST) {
            perror("");
            assert(0);
        }

        pthread_create(&app_ctx->cmn_ctx.thread, NULL, c_thread_main, app_ctx);

        app_ctx->main_wrk_conn.conn_type = C_CONN_TYPE_FILE;
        app_ctx->main_wrk_conn.fd = open(ipc_path_str, O_WRONLY);
        assert(app_ctx->main_wrk_conn.fd > 0);

    }

    /* VTY thread creation */    
    t_args.thread_type = THREAD_VTY;
    vty_ctx = c_alloc_thread_ctx(&t_args);
    assert(vty_ctx);
    pthread_create(&vty_ctx->cmn_ctx.thread, NULL, c_thread_main, vty_ctx);


    /* Switch listener */
    c_listener = c_server_socket_create(INADDR_ANY, ctrl_hdl->c_port);
    assert(c_listener > 0);
    m_ctx->c_accept_event = event_new(m_ctx->cmn_ctx.base, c_listener, 
                                      EV_READ|EV_PERSIST,
                                      c_accept, (void*)m_ctx);
    event_add(m_ctx->c_accept_event, NULL);

    /* HA listener */
    c_listener = c_server_socket_create(INADDR_ANY, MUL_CORE_HA_SERVICE_PORT);
    assert(c_listener > 0);
    m_ctx->c_ha_accept_event = event_new(m_ctx->cmn_ctx.base, c_listener, 
                                         EV_READ|EV_PERSIST,
                                         c_ha_accept, (void*)m_ctx);
    event_add(m_ctx->c_ha_accept_event, NULL);

    /* Application listener */
    c_listener = c_server_socket_create(INADDR_ANY, C_APP_LISTEN_PORT);
    assert(c_listener);
    m_ctx->c_app_accept_event = event_new(m_ctx->cmn_ctx.base, c_listener, 
                                          EV_READ|EV_PERSIST,
                                          c_app_accept, (void*)m_ctx);
    event_add(m_ctx->c_app_accept_event, NULL);

    c_listener = c_server_socket_create(INADDR_ANY, C_APP_AUX_LISTEN_PORT);
    assert(c_listener);
    m_ctx->c_app_aux_accept_event= event_new(m_ctx->cmn_ctx.base, c_listener, 
                                          EV_READ|EV_PERSIST,
                                          c_aux_app_accept, (void*)m_ctx);
    event_add(m_ctx->c_app_aux_accept_event, NULL);

    m_ctx->main_timer_event = evtimer_new(m_ctx->cmn_ctx.base,
                                          c_main_thread_timer_event,
                                          (void *)m_ctx);
    evtimer_add(m_ctx->main_timer_event, &tv);

    if (ctrl_hdl->ssl_en) {
        ctrl_hdl->ssl_thread_locks = calloc(CRYPTO_num_locks(),
                                            sizeof(c_rw_lock_t));
        assert(ctrl_hdl->ssl_thread_locks);
        for (thread_idx = 0; thread_idx < CRYPTO_num_locks(); thread_idx++) {
            c_rw_lock_init(&ctrl_hdl->ssl_thread_locks[thread_idx]);
        }
        
        /* Make ssl calls thread safe - static lock callbacks */
        CRYPTO_set_id_callback(c_thread_ssl_id_cb);
        CRYPTO_set_locking_callback(c_thread_ssl_lock_cb);

        /* Make ssl calls thread safe - dynamic lock callbacks */
        CRYPTO_set_dynlock_create_callback(c_dyn_lock_create_cb);
        CRYPTO_set_dynlock_lock_callback(c_dyn_lock_cb);
        CRYPTO_set_dynlock_destroy_callback(c_dyn_lock_destroy_cb);

        /* SSL Library init */
        SSL_load_error_strings();
        SSL_library_init();

        /* Common context setup */ 
        if (!ctrl_hdl->ssl_meth) {
            ctrl_hdl->ssl_meth = (void *)TLSv1_2_method();
            assert(ctrl_hdl->ssl_meth);
        }

        ctrl_hdl->ssl_ctx = SSL_CTX_new(ctrl_hdl->ssl_meth); 
        assert(ctrl_hdl->ssl_ctx);

        SSL_CTX_set_options(ctrl_hdl->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_tmp_dh_callback(ctrl_hdl->ssl_ctx, tmp_dh_callback);

        /* Load the server certificate into the SSL_CTX structure */
        if (SSL_CTX_use_certificate_file(ctrl_hdl->ssl_ctx,
                                        C_RSA_SERVER_CERT,
                                        SSL_FILETYPE_PEM) <= 0) {
            c_log_err("[SEC] Server cert file load failed");
            assert(0);
        }
 
        /* Load the private-key corresponding to the server certificate */
        if (SSL_CTX_use_PrivateKey_file(ctrl_hdl->ssl_ctx,
                                       C_RSA_SERVER_KEY,
                                       SSL_FILETYPE_PEM) <= 0) {
            c_log_err("[SEC] Private key file load failed");
            assert(0);
        }
 
        /* Check if the server certificate and private-key matches */
        if (!SSL_CTX_check_private_key(ctrl_hdl->ssl_ctx)) {
            c_log_err("[SEC] Private key <-> Cert mismatch");
            assert(0);
        }
 
        /* Load the RSA CA certificate into the SSL_CTX structure */
        if (!SSL_CTX_load_verify_locations(ctrl_hdl->ssl_ctx,
                                           C_RSA_CLIENT_CA_CERT, NULL)) {
            c_log_err("[SEC] Client CACert load failed");
            assert(0);
        }
 
        /* Require client certificate verification */
        SSL_CTX_set_verify(ctrl_hdl->ssl_ctx,
                           ctrl_hdl->switch_ca_verify ?
                           SSL_VERIFY_PEER: 
                           SSL_VERIFY_NONE, 
                           NULL);
 
        /* Set the verification depth to 1 */
        SSL_CTX_set_verify_depth(ctrl_hdl->ssl_ctx, 1);
    }

    m_ctx->cmn_ctx.run_state = THREAD_STATE_RUNNING;

    c_set_thread_dfl_affinity();

    return 0;
}

static int
c_thread_event_loop(struct c_cmn_ctx *cmn_ctx)
{
    /* c_log_debug("%s: tid(%u)", __FUNCTION__, (unsigned int)pthread_self()); */
    return event_base_dispatch(cmn_ctx->base);
}

static int
c_main_thread_run(struct c_main_ctx *m_ctx)
{

    switch(m_ctx->cmn_ctx.run_state) {
    case THREAD_STATE_PRE_INIT:
        signal(SIGPIPE, SIG_IGN);
        m_ctx->cmn_ctx.run_state = THREAD_STATE_FINAL_INIT;
        break;
    case THREAD_STATE_FINAL_INIT:
        return c_main_thread_final_init(m_ctx);
    case THREAD_STATE_RUNNING:
        return c_thread_event_loop((void *)m_ctx);
    }
    return 0;
}

static int
c_worker_thread_run(struct c_worker_ctx *w_ctx)
{
    switch(w_ctx->cmn_ctx.run_state) {
    case THREAD_STATE_PRE_INIT:
        signal(SIGPIPE, SIG_IGN);
        w_ctx->cmn_ctx.run_state = THREAD_STATE_FINAL_INIT;
        break;
    case THREAD_STATE_FINAL_INIT:
        return c_worker_thread_final_init(w_ctx);
    case THREAD_STATE_RUNNING:
        return c_thread_event_loop((void *)w_ctx);
    default:
        c_log_err("[THREAD] Unknown run state"); 
        break;
    }

    return 0;
}

static int
c_app_thread_pre_init(struct c_app_ctx *app_ctx)
{
    struct c_work_q   *wq;
    char              ipc_path_str[64];
    extern ctrl_hdl_t ctrl_hdl;
    int               i = 0;

    signal(SIGPIPE, SIG_IGN);
    app_ctx->cmn_ctx.base = event_base_new();
    assert(app_ctx->cmn_ctx.base);

    snprintf(ipc_path_str, 63, "%s%d", C_IPC_APP_PATH, app_ctx->thread_idx);
    app_ctx->main_wrk_conn.rd_fd = open(ipc_path_str,
                                            O_RDONLY | O_NONBLOCK);
    assert(app_ctx->main_wrk_conn.rd_fd > 0);

    app_ctx->main_wrk_conn.rd_event = event_new(app_ctx->cmn_ctx.base,
                                         app_ctx->main_wrk_conn.rd_fd,
                                         EV_READ|EV_PERSIST,
                                         c_worker_ipc_read, (void*)app_ctx);
    event_add(app_ctx->main_wrk_conn.rd_event, NULL);

    /* Work queues init */
    for (i = 0; i < ctrl_hdl.n_threads; i++) {
        wq = &app_ctx->work_qs[i];
        while ((wq->wq_conn.fd = c_client_socket_create("127.0.0.1",
                                             C_APP_WQ_LISTEN_PORT + i)) < 0) {
            c_log_err("%s: Unable to create conn to workq for thread(%d)",
                      FN, i);
            sleep(1);
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
        c_log_info("[WORKQ] App(%d)->worker(%d) up",
                   app_ctx->thread_idx, i);

    }
    app_ctx->cmn_ctx.run_state = THREAD_STATE_FINAL_INIT;

    return 0;
}

static int
c_app_thread_final_init(struct c_app_ctx *app_ctx)
{
    extern ctrl_hdl_t ctrl_hdl;
    cpu_set_t cpu;
    struct timeval tv = { C_PER_APP_WORKER_TIMEO, 0 };

    /* Set cpu affinity */
    CPU_ZERO(&cpu);
    CPU_SET(app_ctx->thread_idx + ctrl_hdl.n_threads, &cpu);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu);

    c_builtin_app_start(app_ctx);

    app_ctx->app_main_timer_event = evtimer_new(app_ctx->cmn_ctx.base,
                                            c_per_app_worker_timer_event,
                                            (void *)app_ctx);
    evtimer_add(app_ctx->app_main_timer_event, &tv);

    app_ctx->cmn_ctx.run_state = THREAD_STATE_RUNNING;

    return 0;
}

static int
c_app_thread_run(struct c_app_ctx *app_ctx)
{
    switch(app_ctx->cmn_ctx.run_state) {
    case THREAD_STATE_PRE_INIT:
        return c_app_thread_pre_init(app_ctx);
    case THREAD_STATE_FINAL_INIT:
        return c_app_thread_final_init(app_ctx);
    case THREAD_STATE_RUNNING:
        return c_thread_event_loop((void *)app_ctx);
    }
    return 0;
}

static int
c_thread_run(void *ctx)
{
    struct c_cmn_ctx *cmn_ctx = ctx;
    
    switch (cmn_ctx->thread_type) {
    case THREAD_MAIN:
       return c_main_thread_run(ctx);
    case THREAD_WORKER:
       return c_worker_thread_run(ctx); 
    case THREAD_VTY:
       return c_vty_thread_run(ctx);
    case THREAD_APP:
       return c_app_thread_run(ctx);
    default:
        break;
    }

    return 0;
}

void *
c_thread_main(void *arg)
{
     C_THREAD_RUN(arg);     
}
    
int
c_thread_start(void *hdl, int nthreads, int n_appthreads)
{
    ctrl_hdl_t *ctrl_hdl = hdl;
    struct thread_alloc_args args = { nthreads, n_appthreads, THREAD_MAIN, 0,
                                      hdl };
    struct c_main_ctx *main_ctx = c_alloc_thread_ctx(&args);
    ctrl_hdl->main_ctx = (void *)main_ctx;

    c_log_info("[THREAD] INIT |%d| switch-threads |%d| app-threads",
               nthreads, n_appthreads);
    pthread_create(&main_ctx->cmn_ctx.thread, NULL, c_thread_main, main_ctx);
    return 0;
}
