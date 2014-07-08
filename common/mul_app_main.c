/*
 *  mul_app_main.c: MUL application main
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * mul_app_main.c: MUL application main
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
#include "mul_common.h"
#include "mul_vty.h"
#include "mul_app_main.h"
#include "mul_app_infra.h"
#include "mul_services.h"

struct c_app_service c_app_service_tbl[MUL_MAX_SERVICE_NUM] = {
    { TR_APP_NAME, MUL_TR_SERVICE_NAME, MUL_TR_SERVICE_PORT, NULL },    
    { "MISC", MUL_ROUTE_SERVICE_NAME, 0, mul_route_service_get },
    { "CORE", MUL_CORE_SERVICE_NAME, C_AUX_APP_PORT, NULL },
    { FAB_APP_NAME, MUL_FAB_CLI_SERVICE_NAME, MUL_FAB_CLI_PORT, NULL },
    { MAKDI_APP_NAME, MUL_MAKDI_SERVICE_NAME, MUL_MAKDI_CLI_PORT, NULL },
    { PRISM_APP_NAME, MUL_PRISM_CLI_SERVICE_NAME, MUL_PRISM_CLI_PORT, NULL},
    { PRISM_APP_NAME, MUL_PRISM_APP_SERVICE_NAME,
        MUL_PRISM_APP_SERVICE_PORT, NULL },
    { PRISM_APP_NAME, MUL_PRISM_AGENT_SERVICE_NAME,
        MUL_PRISM_AGENT_SERVICE_PORT, NULL }
};

static int c_app_sock_init(c_app_hdl_t *hdl, char *server);

/* MUL app main handle */ 
c_app_hdl_t c_app_main_hdl;
char *server = "127.0.0.1";
struct mul_app_client_cb *app_cbs= NULL;
c_atomic_t finish_init;

static void c_app_event_notifier(void *h_arg, void *pkt_arg);

static struct option longopts[] = 
{
    { "daemon",                 no_argument,       NULL, 'd'},
    { "help",                   no_argument,       NULL, 'h'},
    { "server-ip",              required_argument, NULL, 's'},
    { "peer-ip",                required_argument, NULL, 'H'},
    { "vty-shell",              required_argument, NULL, 'V'},
    { "no-init-conf",           required_argument, NULL, 'N'}
};

#ifdef MUL_APP_V2_MLAPI
int c_app_switch_add(c_app_hdl_t *hdl, c_ofp_switch_add_t *cofp_sa);
int c_app_switch_del(c_app_hdl_t *hdl, c_ofp_switch_delete_t *cofp_sa);
void c_switch_port_status(c_app_hdl_t *hdl, c_ofp_port_status_t *ofp_psts);
void c_app_packet_in(c_app_hdl_t *hdl, c_ofp_packet_in_t *ofp_pin);
void c_controller_reconn(c_app_hdl_t *hdl);
void c_controller_disconn(c_app_hdl_t *hdl);
void c_app_notify_ha_event(c_app_hdl_t *hdl, uint32_t ha_sysid, uint32_t ha_state);
void c_app_vendor_msg(c_app_hdl_t *hdl UNUSED, c_ofp_vendor_msg_t *ofp_vm);
void c_app_tr_status(c_app_hdl_t *hdl UNUSED, c_ofp_tr_status_mod_t *ofp_vm);
#endif
int c_app_infra_init(c_app_hdl_t *hdl);
int c_app_infra_vty_init(c_app_hdl_t *hdl);

/* Help information display. */
static void
usage(char *progname, int status)
{
    printf("%s Options:\n", progname);
    printf("-d : Daemon Mode\n");
    printf("-s <server-ip> : Controller server ip address to connect\n");
    printf("-H <server-ip> : App HA server ip address to connect\n");
    printf("-V <vty-port> : vty port address. (enables vty shell)\n");
    printf("-h : Help\n");

    exit(status);
}

static void
c_app_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

static void
c_app_write_event(evutil_socket_t fd UNUSED, short events UNUSED, void *arg)
{
    c_conn_t *conn = arg;

    c_wr_lock(&conn->conn_lock);
    c_socket_write_nonblock_loop(conn, c_app_write_event_sched);
    c_wr_unlock(&conn->conn_lock);
}

static void
c_app_notify_reconnect(c_app_hdl_t *hdl)
{
    struct cbuf *b;

    if (!hdl->ev_cb) {
        c_controller_reconn(hdl);
        return;
    }

    b = of_prep_msg(sizeof(struct ofp_header), C_OFPT_RECONN_APP, 0);

    hdl->ev_cb(hdl, b);

    free_cbuf(b);
}

static void
c_app_notify_disconnect(c_app_hdl_t *hdl)
{
    struct cbuf *b;

    if (!hdl->ev_cb) {
        c_controller_disconn(hdl);
        return;
    }

    b = of_prep_msg(sizeof(struct ofp_header), C_OFPT_NOCONN_APP, 0);

    hdl->ev_cb(hdl, b);

    free_cbuf(b);
}

static void
c_app_reconn_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                         void *arg)
{ 
    c_app_hdl_t *hdl = arg;
    struct timeval tv = { 2, 0 };

    if(!c_app_sock_init(hdl, server)) {
        c_log_debug("Connection to controller restored");
        event_del((struct event *)(hdl->reconn_timer_event));
        event_free((struct event *)(hdl->reconn_timer_event));
        c_app_notify_reconnect(hdl);
        return;
    }

    evtimer_add(hdl->reconn_timer_event, &tv);
}

void
c_app_reconnect(c_app_hdl_t *hdl)
{
    struct timeval tv = { 1, 0 };

    if (hdl->conn.rd_event) {
        event_del((struct event *)(hdl->conn.rd_event));
        event_free((struct event *)(hdl->conn.rd_event));
        hdl->conn.rd_event = NULL;
    }
    if (hdl->conn.wr_event) {
        event_del((struct event *)(hdl->conn.wr_event));
        event_free((struct event *)(hdl->conn.wr_event));
        hdl->conn.wr_event = NULL;
    }
    c_conn_close(&hdl->conn);
    c_conn_clear_buffers(&hdl->conn);

    c_app_notify_disconnect(hdl);

    hdl->reconn_timer_event = evtimer_new(hdl->base,
                                          c_app_reconn_timer,
                                          (void *)hdl);
    evtimer_add(hdl->reconn_timer_event, &tv);
    return;
}

static int
c_app_recv_msg(void *hdl_arg, struct cbuf *b)
{
    c_app_event_notifier(hdl_arg, b);
    return 0;
}

static void
c_app_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    c_app_hdl_t         *hdl = arg;
    int                 ret;

    ret = c_socket_read_nonblock_loop(fd, hdl, &hdl->conn, C_APP_RCV_BUF_SZ,
                                      (conn_proc_t)c_app_recv_msg,
                                       of_get_data_len, of_hdr_valid,
                                      sizeof(struct ofp_header));

    if (c_recvd_sock_dead(ret)) {
        c_log_debug("Controller connection Lost..\n");
        perror("c_app_read");
        c_app_reconnect(hdl);
    }

    return;
}

static void
c_app_event_notifier(void *h_arg, void *pkt_arg)
{
    struct cbuf         *b = pkt_arg;
    struct ofp_header   *hdr;
    c_app_hdl_t         *hdl = h_arg;

    if (!b) {
        c_log_err("%s: invalid arg", FN);
        return;
    }

    hdr = (void *)(b->data);

    switch(hdr->type) {
#ifdef MUL_APP_V2_MLAPI
    case C_OFPT_SWITCH_ADD: 
        if (!hdl->ev_cb)
            c_app_switch_add(hdl, (void *)hdr);
        break;
    case C_OFPT_SWITCH_DELETE:
        if (!hdl->ev_cb)
            c_app_switch_del(hdl, (void *)hdr);
        break;
    case C_OFPT_PACKET_IN: 
        if (!hdl->ev_cb)
            c_app_packet_in(hdl, (void *)hdr);
        break;
    case C_OFPT_PORT_STATUS:
        if (!hdl->ev_cb)
            c_switch_port_status(hdl, (void *)hdr);
        break;
    case C_OFPT_VENDOR_MSG: 
	    if (!hdl->ev_cb)
	        c_app_vendor_msg(hdl, (void *)hdr);
	break;
#endif
    case C_OFPT_AUX_CMD:
    default:
        break;
    }

    if (hdl->ev_cb)
        hdl->ev_cb(hdl, b);
}

static int 
c_app_init(c_app_hdl_t *hdl)
{
    c_rw_lock_init(&hdl->conn.conn_lock);
    hdl->base = event_base_new();
    assert(hdl->base);

    return 0;
}

static int
c_app_sock_init(c_app_hdl_t *hdl, char *server)
{
    hdl->conn.fd = c_client_socket_create(server, C_APP_PORT);
    if (hdl->conn.fd <= 0) { 
        return -1;
    }

    c_conn_prep(&hdl->conn);
    hdl->conn.rd_event = event_new(hdl->base,
                                   hdl->conn.fd,
                                   EV_READ|EV_PERSIST,
                                   c_app_read, hdl);

    hdl->conn.wr_event = event_new(hdl->base,
                                   hdl->conn.fd,
                                   EV_WRITE, //|EV_PERSIST,
                                   c_app_write_event, &hdl->conn);

    event_add((struct event *)(hdl->conn.rd_event), NULL);

    return 0;
}

void *
mul_app_create_service(char *name,  
                       void (*service_handler)(void *service, struct cbuf *msg))
{
    size_t serv_sz = sizeof(c_app_service_tbl)/sizeof(c_app_service_tbl[0]);
    int serv_id = 0;
    struct c_app_service *serv;

    for (; serv_id < serv_sz; serv_id++) {
        serv = &c_app_service_tbl[serv_id];
        if (!strncmp(serv->service_name, name, MAX_SERV_NAME_LEN-1)) {
            return mul_service_start(c_app_main_hdl.base, name, serv->port, 
                                     service_handler, NULL);
        }
    }

    c_log_err("%s service unknown", name);
    return NULL;
}

static void *
__mul_app_get_service(char *name,
                      void (*conn_update)(void *service,
                                          unsigned char conn_event),
                      bool (*keepalive)(void *service),
                      bool retry_conn, const char *server)
{
    size_t serv_sz = sizeof(c_app_service_tbl)/sizeof(c_app_service_tbl[0]);
    int serv_id = 0;
    struct c_app_service *serv_elem;
    mul_service_t *service;

    for (; serv_id < serv_sz; serv_id++) {
        serv_elem = &c_app_service_tbl[serv_id];
        if (!strncmp(serv_elem->service_name, name, MAX_SERV_NAME_LEN-1)) {
            if (serv_elem->service_priv_init) 
                service = serv_elem->service_priv_init();
            else 
                service = mul_service_instantiate(c_app_main_hdl.base, name, 
                                                  serv_elem->port,
                                                  conn_update, keepalive,
                                                  retry_conn, server);
            return service;
        }
    }

    c_log_err("%s service unknown", name);
    return NULL;
}

void *
mul_app_get_service(char *name, const char *server)
{
    return __mul_app_get_service(name, NULL, NULL, false, server);
}
 
void *
mul_app_get_service_notify(char *name,
                          void (*conn_update)(void *service,
                                              unsigned char conn_event),
                          bool retry_conn,
                          const char *server)
{
    return __mul_app_get_service(name, conn_update, NULL, retry_conn, server);
}

void *
mul_app_get_service_notify_ka(char *name,
                              void (*conn_update)(void *service,
                                              unsigned char conn_event),
                              bool (*keepalive)(void *service),  
                              bool retry_conn,
                              const char *server)
{
    return __mul_app_get_service(name, conn_update, keepalive,
                                 retry_conn, server);
}
 
void
mul_app_destroy_service(void *service)
{
    return mul_service_destroy(service);
}

static void
mod_initcalls(c_app_hdl_t *hdl)
{
    initcall_t *mod_init;

    mod_init = &__start_modinit_sec;
    do {
        (*mod_init)(hdl->base);
        mod_init++;
    } while (mod_init < &__stop_modinit_sec);
}

#if !defined(SWIG_INFRA) && defined(MUL_APP_VTY)
static void
modvty__initcalls(void *arg)
{       
    initcall_t *mod_init;                
                                         
    mod_init = &__start_modvtyinit_sec;  
    do {
        (*mod_init)(arg);
        mod_init++;
    } while (mod_init < &__stop_modvtyinit_sec);
}

DEFUN_HIDDEN (show_app_version,
       show_app_version_cmd,
       "show app-host-version",
       SHOW_STR
       "Application Hosting Version")
{
    vty_out(vty, " Version 3.3\r\n");
    return CMD_SUCCESS;
}

DEFUN (c_set_log,
       c_set_log_cmd,
       "set controller-log (console|syslog) level (warning|error|debug)", 
       SET_STR
       "Controller Logging Info\n"
       "Console\n"
       "Or syslog\n"
       "Log Level\n"
       "Warning or above\n"
       "Error or above\n"
       "Debug or above\n")
{
    clog_dest_t dest = 0;
    int level = 0;

    if (!strncmp(argv[0], "console", strlen(argv[0]))) {
        dest = CLOG_DEST_STDOUT;
    } else if (!strncmp(argv[0], "syslog", strlen(argv[0]))) {
        dest = CLOG_DEST_SYSLOG;
    } else {
        NOT_REACHED();
    }

    if (!strncmp(argv[1], "warning", strlen(argv[1]))) {
        level = LOG_WARNING;
    } else if (!strncmp(argv[1], "error", strlen(argv[1]))) {
        level = LOG_ERR;
    } else if (!strncmp(argv[1], "debug", strlen(argv[1]))) { 
        level = LOG_DEBUG;
    } else {
        NOT_REACHED();
    }

    clog_set_level(NULL, dest, level);

    return CMD_SUCCESS;
}

static void *
c_app_vty_main(void *arg)
{   
    struct thread thread;
    c_app_hdl_t *hdl = arg;
    char app_vtysh_path[64];

    strncpy(app_vtysh_path, C_APP_VTY_COMMON_PATH, 63 ); 
    strncat(app_vtysh_path, hdl->progname, 63);


    hdl->vty_master = thread_master_create();

    cmd_init(1);
    vty_init(hdl->vty_master);

    modvty__initcalls(hdl);
    install_element(ENABLE_NODE, &show_app_version_cmd);
    install_element(CONFIG_NODE, &c_set_log_cmd);
    sort_node();

    vty_serv_sock(NULL, hdl->vty_port, app_vtysh_path, 1);
    vty_serv_sock(NULL, hdl->vty_port+1, app_vtysh_path, 0);

    /* Execute each thread. */       
    while (thread_fetch(hdl->vty_master, &thread))
        thread_call(&thread);

    /* Not reached. */
    return (0);
} 

#else

int
vty_out(struct vty *vty UNUSED, const char *format UNUSED, ...)
{
    return 0;
}

void
install_element(enum node_type ntype UNUSED, struct cmd_element *cmd UNUSED)
{
}

static void *
c_app_vty_main(void *arg UNUSED)
{
    return NULL;
}
#endif

static int
__main(int argc, char **argv)
{
    char    *p;
    int     daemon_mode = 0;
    int     vty_shell = 0;
    uint16_t vty_port = 0;
    char    app_pid_path[C_APP_PATH_LEN];
    struct in_addr in_addr;

    /* Set umask before anything for security */
    umask (0027);

    /* Get program name. */
    c_app_main_hdl.progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

    strncpy(app_pid_path, C_APP_PID_COMMON_PATH, C_APP_PATH_LEN - 1);
    strncat(app_pid_path, c_app_main_hdl.progname, 
            C_APP_PATH_LEN - strlen(app_pid_path) - 1);

    /* Command line option parse. */
    while (1) {
        int opt;

        opt = getopt_long (argc, argv, "dhs:V:H:f:N", longopts, 0);
        if (opt == EOF)
            break;

        switch (opt) {
        case 0:
            break;
        case 'd':
            daemon_mode = 1;
            break;
        case 's': 
            server = optarg;
            if (!inet_aton(server, &in_addr)) {
                printf("Invalid Director address");
                exit(0);
            }
            break;
        case 'V':
            vty_shell = 1;
            vty_port = atoi(optarg);
            break;
        case 'H':
            c_app_main_hdl.ha_server = optarg;
            if (!inet_aton(c_app_main_hdl.ha_server, &in_addr)) {
                printf("Invalid HA peer address");
                exit(0);
            }
            break;
        case 'f':
            strcpy(c_app_main_hdl.dpid_file,optarg);
            break;
        case 'h':
            usage(c_app_main_hdl.progname, 0);
            break;
        case 'N':
            c_app_main_hdl.no_init_conf = 1;
            break;
        default:
            usage(c_app_main_hdl.progname, 1);
            break;
        }
    }

    if (daemon_mode) {
        c_daemon(1, 0, app_pid_path);
    } else {
        c_pid_output(app_pid_path);
    }

    clog_default = openclog (c_app_main_hdl.progname, CLOG_MUL,
                             LOG_CONS|LOG_NDELAY, LOG_DAEMON);
    clog_set_level(NULL, CLOG_DEST_SYSLOG, LOG_ERR);
    clog_set_level(NULL, CLOG_DEST_STDOUT, LOG_DEBUG);
    clog_set_name(NULL, CLOG_MUL, c_app_main_hdl.progname);

    c_app_init(&c_app_main_hdl);
    c_app_infra_init(&c_app_main_hdl);
    while (c_app_sock_init(&c_app_main_hdl, server) < 0) { 
        c_log_debug("Trying to connect..\n");
        sleep(1);
    }

    mod_initcalls(&c_app_main_hdl);

    if (vty_shell && vty_port > 0) {
        c_app_main_hdl.vty_port = vty_port;
        pthread_create(&c_app_main_hdl.vty_thread, NULL, c_app_vty_main, &c_app_main_hdl);
    }

    atomic_inc(&finish_init,1);

    while(1) { 
        return event_base_dispatch(c_app_main_hdl.base);
    }

    /* Not reached. */
    return (0);
}

#ifndef SWIG_INFRA
int
main(int argc, char *argv[])
{
    finish_init = 0;
    __main(argc, argv);

    return 0;
}
#else

int nbapi_worker_entry(void);

static void *
nbapi_init(void *arg UNUSED)
{
    char *argv[1];

    argv[0] = "nbapi";
    __main(1, argv);

    return NULL;
}

int
nbapi_worker_entry(void)
{
    pthread_t tid;
    int ret_val;
    struct timespec interval = {0, 10000};

    finish_init = 0;
    ret_val = pthread_create(&tid, NULL, nbapi_init, NULL);

    while(!atomic_read(&finish_init)) {
        nanosleep(&interval, NULL);
    }
    return ret_val;
}
#endif
