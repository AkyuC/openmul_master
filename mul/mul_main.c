/*
 *  mul_main.c: MUL controller main()
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

char c_path_name[C_MAX_PATH_NAME_LEN+1];

/* of-controller options. */
static struct option longopts[] = 
{
    { "daemon",                 no_argument,       NULL, 'd'},
    { "help",                   no_argument,       NULL, 'h'},
    { "switch-threads",         required_argument, NULL, 'S'},
    { "app-threads",            required_argument, NULL, 'A'},
    { "listen-port",            required_argument, NULL, 'P'},
    { "no-dfl-flows",           no_argument,       NULL, 'n'},
    { "dfl-pkt-dump-en",        no_argument,       NULL, 'p'},
    { "ssl-enable",             no_argument,       NULL, 's'},
    { "syslog-level",           required_argument, NULL, 'l'},
    { "switch-verify-ca",       no_argument,       NULL, 'x'},
    { "loop-enable",            no_argument,       NULL, 'L'},
};

/* Process ID saved for use by init system */
const char *pid_file = C_PID_PATH;

/* handle to controller to pass around */
ctrl_hdl_t ctrl_hdl;

/* rate-limiter for critical path logs */
C_RL_DEFINE(crl, 1000, 10);

/* Help information display. */
static void
usage(char *progname, int status)
{
    printf("%s options:\n", progname);
    printf("-d        : Daemon Mode\n");
    printf("-S <num>  : Number of switch handler threads\n");
    printf("-A <num>  : Number of app handler threads\n");
    printf("-P <port> : Port Number for incoming switch connection\n");
    printf("-n        : Don't install default flows in switch\n");
    printf("-p        : Enable OF packet dump for all switches\n");
    printf("-s        : Enable ssl for all switch connections\n");
    printf("-l <level>: Set syslog levels 0:debug, 1:err(default) 2:warning\n");
    printf("-x        : Verify switch-ca cert. Only applicable with -s option\n"); 
    printf("-L        : Enable loop-detection\n"); 
    printf("-h        : Help\n");

    exit(status);
}

static int
of_ctrl_init(ctrl_hdl_t *c_hdl, size_t nthreads, size_t n_appthreads,
             uint16_t port, const char *c_peer, bool master,
             bool no_dfl_flows, bool dump_pkts, bool ssl_en,
             bool switch_ca_verify, bool loop_detect)
{
    memset (c_hdl, 0, sizeof(ctrl_hdl_t));
    c_rw_lock_init(&c_hdl->lock);
    c_rw_lock_init(&c_hdl->flock);

    c_hdl->sw_ipool = ipool_create(MAX_SWITCHES_PER_CLUSTER, 0);
    assert(c_hdl->sw_ipool);

    c_hdl->worker_ctx_list = (struct c_cmn_ctx **)malloc(nthreads * sizeof(void *));
    assert(c_hdl->worker_ctx_list);

    c_hdl->n_threads = nthreads;
    c_hdl->n_appthreads = n_appthreads;
    c_hdl->c_port = port?:C_LISTEN_PORT;
    c_hdl->c_peer = c_peer;
    c_hdl->ha_state = master ? C_HA_STATE_MASTER : C_HA_STATE_NONE;
    c_hdl->ha_sysid = random_uint32();
    c_hdl->no_dfl_flows = no_dfl_flows;
    c_hdl->dfl_dump_pkts = dump_pkts;
    c_hdl->ssl_en = ssl_en;
    c_hdl->switch_ca_verify = switch_ca_verify;
    c_hdl->loop_en = loop_detect;

    return 0;
}

int
main(int argc, char **argv)
{
    char        *p;
    int         daemon_mode = 0;
    int         unlock = 0;
    int         master = 0;
    int         no_dfl_flows = 0;
    int         dfl_dump_pkts = 0;
    int         ssl_en = 0;
    char        *progname;
    int         sthreads = 4, athreads = 2;
    uint16_t    c_port = 0;
    const char  *c_peer = NULL;
    int         dfl_log = LOG_ERR;
    int         switch_ca_verify = 0;
    int         loop_detect = 0;

    /* Set umask before anything for security */
    umask (0027);

    /* Get program name. */
    progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

    /* Command line option parse. */
    while (1) {
        int opt;

        opt = getopt_long (argc, argv, "udhspnxS:A:P:H:l:", longopts, 0);
        if (opt == EOF)
            break;

        switch (opt) {
        case 0:
            break;
        case 'd':
            daemon_mode = 1;
            break;
        case 'u':
            unlock = 1;
            break;
        case 'S': 
            sthreads = atoi(optarg);
            if (sthreads < 0 || sthreads > 16) {
                printf ("Illegal:Too many switch threads\n");    
                exit(0);
            }
            break;
        case 'A':
            athreads = atoi(optarg);
            if (athreads < 0 || athreads > 8) {
                printf ("Illegal:Too many app threads\n");    
                exit(0);
            }
            break;
        case 'P':
            c_port = atoi(optarg);
            break;
        case 'h':
            usage(progname, 0);
            break;
        case 'n':
            no_dfl_flows = 1;
            break;
        case 's':
            ssl_en = 1;
            break;
        case 'p':
            dfl_dump_pkts = 1;
            break;
        case 'g':
            break;
        case 'l':
            switch (atoi(optarg)) {
            case 0:
                dfl_log = LOG_DEBUG;    
                break;
            case 1:
                dfl_log = LOG_ERR;
                break;
            case 2:
                dfl_log = LOG_WARNING;
                break;
            default:
                printf("Invalid log-level specified. Taking default\n");
            }
            break;
        case 'x':
            switch_ca_verify = 1;    
            break;
        case 'L':
            loop_detect = 1;
        default:
            usage(progname, 1);
            break;
        }
    }

    if (!getcwd(c_path_name, sizeof(c_path_name))) {
        printf("Failed to determine curr dir\n");
    }


    if (daemon_mode) {
        c_daemon(0, 0, unlock? NULL:C_PID_PATH);
    } else {
        if (!unlock) {
            c_pid_output(C_PID_PATH);
        }
    }

    clog_default = openclog (progname, CLOG_MUL,
                             LOG_CONS|LOG_NDELAY, LOG_DAEMON);
    clog_set_level(NULL, CLOG_DEST_SYSLOG, dfl_log);
    clog_set_level(NULL, CLOG_DEST_STDOUT, LOG_DEBUG);

    if(geteuid() != 0) {
        c_log_err("!! Run as root !!");
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);

    /* initialize controller handler */
    of_ctrl_init(&ctrl_hdl, sthreads, athreads, c_port,
                 c_peer, master, no_dfl_flows, dfl_dump_pkts,
                 ssl_en, switch_ca_verify, loop_detect);

    c_thread_start(&ctrl_hdl, sthreads, athreads);
    while (1) {
        sleep(1);
    }

    pthread_exit(NULL);

    /* Not reached. */
    return (0);
}
