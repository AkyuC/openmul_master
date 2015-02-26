/*
 *  mul_cli.c: CLI application for MUL Controller 
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
#include "mul_cli.h"
#include "mul_app_main.h"
#include "uuid.h"

#define CLI_CFG_FILE 1
#ifdef MUL_APP_VTY

cli_struct_t *cli;

static int cli_init_mul_service(cli_struct_t *cli, struct vty *vty);
static void cli_switch_add(mul_switch_t *sw);
static void cli_core_closed(void);
static void cli_core_reconn(void);
static char **conf_file_name_get_cb(int *num);
static void cli_timer(evutil_socket_t fd, short event, void *arg);
static bool cli_ha_config_cap(cli_struct_t *cli, struct vty *vty,
                              bool replay);
void cli_ha_state(uint32_t sysid, uint32_t ha_state);

struct mul_app_client_cb cli_app_cbs = {
    .switch_add_cb = cli_switch_add,
    .core_conn_closed = cli_core_closed,
    .core_conn_reconn = cli_core_reconn
};

static void
cli_switch_add(mul_switch_t *sw)
{
    char filename[256];
    char *config_file = filename;

    if (!cli->init_events_triggered || 
        !cli->mul_service_rep)
        return;

    memset(config_file, 0, sizeof(filename));
    strncpy(config_file, CLI_CONF_FILE, strlen(CLI_CONF_FILE));
    snprintf(config_file + strlen(CLI_CONF_FILE),
            sizeof(filename)-strlen(config_file)-1,
            "%llx", U642ULL(sw->dpid));

    c_log_err("%s: Triggering config %s", FN, config_file);
    c_wr_lock(&cli->lock);
    vty_read_config(NULL, config_file, 1, MUL_NODE);
    c_wr_unlock(&cli->lock);
}

static bool
cli_dummy_infra_ka(void *service UNUSED)
{
    return true;
}

static int
cli_service_timer(struct thread *t)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
#define CLI_SERVICE_LEN 4
    mul_service_t *serv_arr[CLI_SERVICE_LEN];
    mul_service_t *service = NULL;
    cli_struct_t *cli = THREAD_ARG(t);
    int i = 0;

    serv_arr[0] = cli->mul_service;
    serv_arr[1] = cli->tr_service;
    serv_arr[2] = cli->fab_service;
    serv_arr[3] = cli->makdi_service;

    c_wr_lock(&cli->lock);
    for (i = 0; i < CLI_SERVICE_LEN; i++) {
        service = serv_arr[i];
   
        if (!service) continue;

        if (service->conn.dead || service->ext_ka_flag)
            continue;

        b = of_prep_msg(sizeof(*cofp_auc), C_OFPT_AUX_CMD, 0);

        cofp_auc = (void *)(b->data);
        cofp_auc->cmd_code = htonl(C_AUX_CMD_ECHO);

        c_service_send(service, b);
        b = c_service_wait_response(service);
        if (b) {
            free_cbuf(b);
            service->ext_ka_flag = 0;
        } else {
            service->ext_ka_flag = 1;
        }
    }

    cli_timer(0, 0, NULL);
    c_wr_unlock(&cli->lock);
    
    thread_add_timer(cli->vty_master,
                     cli_service_timer, cli, CLI_TIMER_TS);
    return 0;
#undef CLI_SERVICE_LEN
}

static void
cli_core_closed(void)
{
    c_log_info("[Core] Disconnect");
    return;
}

static void
cli_core_reconn(void)
{
    c_log_info("[Core] Reconnected");
    mul_register_app_cb(NULL, CLI_APP_NAME, C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &cli_app_cbs);
}

static bool
cli_ha_config_cap(cli_struct_t *cli, struct vty *vty, bool replay UNUSED)
{

    if (cli_init_mul_service(cli, vty)) {
        return false;
    }

    if (mul_get_ha_state(cli->mul_service, &cli->sysid, &cli->state,
                &cli->generation_id)) {
        if (vty) vty_out(vty, "HA state unavailable\r\n");
        return false;
    }

    if ((cli->state == C_HA_STATE_NONE) ||
        cli->state == C_HA_STATE_MASTER ||
        cli->state == C_HA_STATE_NOHA) {
        return true;
    }

    if (vty) vty_out(vty, "Config not allowed for current HA state\r\n");

    return false;
}

/**
 * return_vty -
 *
 * Note - err_str will not be freed here
 */
static int 
return_vty(void *vty_arg, uint16_t type UNUSED,
           uint16_t status, char *err_str)
{
    struct vty *vty = vty_arg;

    if (vty->type != VTY_NBAPI) {
        if (err_str) {
            vty_out(vty, "%s%s", err_str, VTY_NEWLINE);
        }
        return status;
    }

    return status; 
}

/**
 * vty_dump -
 */
static void
vty_dump(void *vty, void *pbuf)
{
    vty_out((struct vty *)vty, "%s", (char *)pbuf);
}

/**
 * vty_config_dump -
 */
static void
vty_config_dump(void *arg, void *pbuf)
{
    struct cli_config_wr_arg *cfg_wr_arg = arg;
    vty_out(cfg_wr_arg->vty, "%s", (char *)pbuf);
    cfg_wr_arg->write++;
}

/** 
 * cli_recv_err_msg -
 *
 * Handler for error notifications from controller/switch 
 */
static void UNUSED
cli_recv_err_msg(cli_struct_t *cli UNUSED, c_ofp_error_msg_t *cofp_err)
{
    c_log_err("%s:error type %hu code %hu", FN,
               ntohs(cofp_err->type), ntohs(cofp_err->code));

    /* FIXME : Handle errors */
}

static void
mul_core_service_conn_event(void *serv_arg UNUSED, unsigned char conn_event)
{
    bool unlock;

    unlock = !c_wr_trylock(&cli->lock);
    if (conn_event == MUL_SERVICE_UP) { 
        if (cli->mul_service_rep || !cli->init_events_triggered) {
            if (unlock) c_wr_unlock(&cli->lock);
            return;
        }
#ifdef CLI_CFG_FILE 
        if (cli_ha_config_cap(cli, NULL, true)) {
            int fl = 0, num_files = 0;
            char **fnames;
            char config_file[256];

            if (!(fnames = conf_file_name_get_cb(&num_files))) { 
                c_log_err("%s: get param failed", FN);
                cli->mul_service_rep = true;
                if (unlock) c_wr_unlock(&cli->lock);
                return;
            }

            for (fl = 0; fl < num_files; fl++) {
                /* Get filename. */
                memset(config_file, 0, sizeof(config_file));
                strncat(config_file, CLI_CONF_FILE, sizeof(config_file)-1);
                strncat(config_file, fnames[fl],
                        sizeof(config_file)-1-strlen(config_file));

                c_log_err("%s: Triggering config %s", FN, config_file);
                vty_read_config(NULL, config_file, 1, MUL_NODE);
            }

            if (fnames) {
                for (fl = 0; fl < num_files; fl++) {
                    if (fnames[fl])
                        free((void *)(fnames[fl]));
                }
                free(fnames);
            }
        }
#endif
        cli->mul_service_rep = true;
    } else {
        cli->mul_service_rep = false;
        cli->init_events_triggered = 0;
    }
    if (unlock) c_wr_unlock(&cli->lock);
}

static void
mul_tr_service_conn_event(void *serv_arg UNUSED, unsigned char conn_event)
{
    c_log_err("%s: %d", FN, conn_event);
}

static void
mul_fab_service_conn_event(void *serv_arg UNUSED, unsigned char conn_event)
{
    c_log_err("%s: %d", FN, conn_event);

    if (conn_event == MUL_SERVICE_UP) { 
#ifdef CLI_CFG_FILE
        if (cli->init_events_triggered) {
            sleep(1);
            if (cli_ha_config_cap(cli, NULL, true)) {
                c_log_err("%s: Triggering config", FN);
                vty_read_config(NULL, CLI_CONF_FILE, 1, MULFAB_NODE);
            }
#endif
            cli->fab_service_rep = true;
        }
    }
}
static void
mul_makdi_service_conn_event(void *serv_arg UNUSED, unsigned char conn_event)
{
    c_log_err("%s: %d", FN, conn_event);
    
    if (conn_event == MUL_SERVICE_UP) {
#ifdef CLI_CFG_FILE
        sleep(1);
        if (cli_ha_config_cap(cli, NULL, true)) {
            c_log_err("%s: Triggering config", FN);
            vty_read_config(NULL, CLI_CONF_FILE, 1, MULMAKDI_NODE);
        }
#endif
        cli->makdi_service_rep = true;
    }
}

static int
cli_init_mul_service(cli_struct_t *cli, struct vty *vty)
{
     if (!cli->mul_service) {
        cli->mul_service = mul_app_get_service_notify_ka(MUL_CORE_SERVICE_NAME,
                                                  mul_core_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
        if (!cli->mul_service) {
            if (vty) vty_out(vty, "mul-core service is not alive\r\n");
            return CMD_WARNING;
        }
    } else if (!mul_service_available(cli->mul_service)) {
         if (vty) vty_out(vty, "mul-core service is not alive\r\n");
         return CMD_WARNING;
    }

    return 0;
}

static int
cli_init_fab_service(cli_struct_t *cli, struct vty *vty)
{
     if (!cli->fab_service) {
        cli->fab_service = mul_app_get_service_notify_ka(MUL_FAB_CLI_SERVICE_NAME,
                                                  mul_fab_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
        if (!cli->fab_service) {
            return return_vty(vty, 0, CMD_WARNING, "mul-fab dead");
        }
    } else if (!mul_service_available(cli->fab_service)) {
        return return_vty(vty, 0, CMD_WARNING, "mul-fab dead");
    }

    return 0;
}

static int
cli_init_tr_service(cli_struct_t *cli, struct vty *vty)
{
     if (!cli->tr_service) {
        cli->tr_service = mul_app_get_service_notify_ka(MUL_TR_SERVICE_NAME,
                                                  mul_tr_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
        if (!cli->tr_service) {
            return return_vty(vty, 0, CMD_WARNING, "mul-tr dead");
        }
    } else if (!mul_service_available(cli->tr_service)) {
        return return_vty(vty, 0, CMD_WARNING, "mul-tr dead");
    }

    return 0;
}

static int
cli_init_makdi_service(cli_struct_t *cli, struct vty *vty)
{
     if (!cli->makdi_service) {
        cli->makdi_service = mul_app_get_service_notify_ka(MUL_MAKDI_SERVICE_NAME,
                                                  mul_makdi_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
        if (!cli->makdi_service) {
            return return_vty(vty, 0, CMD_WARNING, "mul-mak dead");
        }
    } else if (!mul_service_available(cli->makdi_service)) {
        return return_vty(vty, 0, CMD_WARNING, "mul-mak dead");
    }

    return 0;
}


static void UNUSED
cli_exit_mul_service(cli_struct_t *cli)
{
    if (cli->mul_service) {
        mul_app_destroy_service(cli->mul_service);
        cli->mul_service = NULL;
    }
}

static void UNUSED
cli_exit_fab_service(cli_struct_t *cli)
{
    if (cli->fab_service) {
        mul_app_destroy_service(cli->fab_service);
        cli->fab_service = NULL;
    }
}

static void UNUSED
cli_exit_tr_service(cli_struct_t *cli)
{
    if (cli->tr_service) {
        mul_app_destroy_service(cli->tr_service);
        cli->tr_service = NULL;
    }
}

static void UNUSED
cli_exit_makdi_service(cli_struct_t *cli)
{
    if (cli->makdi_service) {
        mul_app_destroy_service(cli->makdi_service);
        cli->makdi_service = NULL;
    }
}


static void
cli_timer(evutil_socket_t fd UNUSED, short event UNUSED, void *arg UNUSED)
{
#ifdef CLI_CFG_FILE
    int64_t curr_time;
#endif

    if (!cli->init_events_triggered) {
        cli->init_events_triggered = true;
    }

#ifdef CLI_CFG_FILE
    curr_time = g_get_monotonic_time();
    if (!cli->last_sync) {
        cli->last_sync = curr_time;
    } else {
        if (cli_ha_config_cap(cli, NULL, true) &&
            cli->state == C_HA_STATE_MASTER) {
            if (cli->last_sync + CLI_TIMER_CFG_SYNC_TMS < curr_time &&
                !cli->need_sync && 
                cli->ha_peer) {
                cli->last_sync = curr_time;
                cli->need_sync = true;
            }
        } else {
            cli->last_sync = curr_time;
        }
    }
#endif

    if (cli->no_init_conf) return;

    if (cli->fab_service &&
        mul_service_available(cli->fab_service) &&
        !cli->fab_service_rep)
        mul_fab_service_conn_event(cli->fab_service,
                                   MUL_SERVICE_UP);

    if (cli->makdi_service &&
        mul_service_available(cli->makdi_service) &&
        !cli->makdi_service_rep)
        mul_makdi_service_conn_event(cli->makdi_service,
                                     MUL_SERVICE_UP);

    if (cli->mul_service &&
        mul_app_core_conn_available() &&
        mul_service_available(cli->mul_service) &&
        !cli->mul_service_rep)
        mul_core_service_conn_event(cli->mul_service,
                                    MUL_SERVICE_UP);
}

/**
 * cli_module_init -
 *
 * CLI application entry point 
 */
void
cli_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    /* struct timeval update_tv = { CLI_TIMER_INIT_TS, CLI_TIMER_INIT_TUS }; */
    
    c_log_debug("%s", FN);

    cli = calloc(1, sizeof(cli_struct_t));
    assert(cli);

    c_rw_lock_init(&cli->lock);
    cli->base = base;

    cli->mul_service = mul_app_get_service_notify_ka(MUL_CORE_SERVICE_NAME,
                                                  mul_core_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
    if (cli->mul_service == NULL) {
        c_log_err("[CORE] service not found");
    }
    cli->tr_service = mul_app_get_service_notify_ka(MUL_TR_SERVICE_NAME,
                                                 mul_tr_service_conn_event,
                                                 cli_dummy_infra_ka,
                                                 false, NULL);
    if (cli->tr_service == NULL) {
        c_log_err("[TopoRoute] service not found");
    }
    cli->fab_service = mul_app_get_service_notify_ka(MUL_FAB_CLI_SERVICE_NAME,
                                                  mul_fab_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
    if (cli->fab_service == NULL) {
        c_log_err("[FABRIC] service not found");
    }

    cli->makdi_service = mul_app_get_service_notify_ka(MUL_MAKDI_SERVICE_NAME,
                                                  mul_makdi_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
    if (cli->makdi_service == NULL) {
        c_log_err("[MAKDI] service not found");
    }

    cli->cli_list = g_slist_append(cli->cli_list, "mul-core");
    cli->cli_list = g_slist_append(cli->cli_list, "mul-tr");
    cli->cli_list = g_slist_append(cli->cli_list, "mul-fab");
    cli->cli_list = g_slist_append(cli->cli_list, "mul-makdi");
    
    /* Timer is invoked from vty timer event */
    /*cli->timer_event = evtimer_new(base, cli_timer, (void *)cli);
    evtimer_add(cli->timer_event, &update_tv); */

    mul_register_app_cb(NULL, CLI_APP_NAME, C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &cli_app_cbs);

    return;
}

struct cmd_node mul_conf_node =
{
    MUL_NODE,
    "(mul-main)# ",
    1,
    NULL,
    NULL
};

struct cmd_node tr_conf_node =
{
    MULTR_NODE,
    "(mul-tr)# ",
    1,
    NULL,
    NULL
};

struct cmd_node fab_conf_node =
{
    MULFAB_NODE,
    "(mul-fab)# ",
    1,
    NULL,
    NULL
};

struct cmd_node makdi_conf_node =
{
    MULMAKDI_NODE,
    "(mul-mak)# ",
    1,
    NULL,
    NULL
};

struct cmd_node flow_inst_node =
{
    FLOW_NODE,
    "(config-flow-instruction)# ",
    1,
    NULL,
    NULL
};

struct cmd_node inst_actions_node =
{
    INST_NODE,
    "(config-inst-action)# ",
    1,
    NULL,
    NULL
};

DEFUN (mul_conf,
       mul_conf_cmd,
       "mul-conf",
       "mul-core conf mode\n")
{
    if (cli_init_mul_service(cli, vty) ||
        !cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    vty->node = MUL_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_conf_exit,
       mul_conf_exit_cmd,
       "exit",
       "Exit mul-core conf mode\n")
{
    /* cli_exit_mul_service(cli); */
    vty->node = ENABLE_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_tr_conf,
       mul_tr_conf_cmd,
       "mul-tr-conf",
       "mul-tr (topo-route) conf mode\n")
{

    if (cli_init_tr_service(cli, vty) ||
        !cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    vty->node = MULTR_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_tr_conf_exit,
       mul_tr_conf_exit_cmd,
       "exit",
       "Exit mul-tr conf mode\n")
{
    /* cli_exit_tr_service(cli); */
    vty->node = ENABLE_NODE;
    return CMD_SUCCESS;
}


DEFUN (mul_fab_conf,
       mul_fab_conf_cmd,
       "mul-fab-conf",
       "mul-fab conf mode\n")
{
    if (cli_init_fab_service(cli, vty) ||
        !cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    vty->node = MULFAB_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_fab_conf_exit,
       mul_fab_conf_exit_cmd,
       "exit",
       "Exit mul-fab conf mode\n")
{
    /* cli_exit_fab_service(cli); */
    vty->node = ENABLE_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_makdi_conf,
       mul_makdi_conf_cmd,
       "mul-mak-conf",
       "mul-makdi conf mode\n")
{
    if (cli_init_makdi_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    vty->node = MULMAKDI_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_makdi_conf_exit,
       mul_makdi_conf_exit_cmd,
       "exit",
       "Exit mul-makdi conf mode\n")
{
    /* cli_exit_makdi_service(cli); */
    vty->node = ENABLE_NODE;
    return CMD_SUCCESS;
}

DEFUN (flow_inst,
       flow_inst_cmd,
       "flow ARGS",
       "Flow\n"
       "Flow tuples\n")
{
    vty->node = FLOW_NODE;

    return CMD_SUCCESS;
}

DEFUN (inst_actions,
       inst_actions_cmd,
       "inst-actions ARGS",
       "Instruction actions\n"
       "Action list\n")
{
    vty->node = INST_NODE;

    return CMD_SUCCESS;
}

DEFUN (show_of_switch,
       show_of_switch_cmd,
       "show of-switch all",
       SHOW_STR
       "Openflow switches\n"
       "Summary information for all")
{
    struct cbuf *b;
    char *pbuf = NULL;

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);


    vty_out (vty,
             "%18s    %-11s %-26s %-8s%s",
            "Switch DPID", "State", "Peer", "Ports", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    b = mul_get_switches_brief(cli->mul_service);
    if (b) {
        pbuf = mul_dump_switches_brief(b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (show_of_switch_detail,
       show_of_switch_detail_cmd,
       "show of-switch X general-features",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "General switch features\n")
{
    uint64_t    dp_id;
    struct cbuf *b;
    char *      pbuf;

    dp_id = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    b = mul_get_switch_detail(cli->mul_service, dp_id);
    if (b) {
        pbuf = mul_dump_switch_detail(b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (of_switch_rx_rlim,
       of_switch_rx_rlim_cmd,
       "set of-switch X rx-rlim-enable <1-1000000>",
       SET_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Enable rate-limit on in-coming packet-ins\n"
       "Enter a valid packets per second count")
{
    uint64_t dp_id;

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);    
        return CMD_SUCCESS;
    }

    if (mul_set_switch_pkt_rlim(cli->mul_service, dp_id,
                                atoi(argv[1]), true)) {
        vty_out(vty, "Failed to set rate-limit%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (of_switch_rx_rlim_disable,
       of_switch_rx_rlim_disable_cmd,
       "set of-switch X rx-rlim-disable",
       SET_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Disable any rate-limit on in-coming packet-ins")
{
    uint64_t dp_id;

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);    
        return CMD_SUCCESS;
    }

    if (mul_set_switch_pkt_rlim(cli->mul_service, dp_id,
                                0, true)) {
        vty_out(vty, "Failed to disable rate-limit%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (of_switch_rx_rlim_get,
       of_switch_rx_rlim_get_cmd,
       "show of-switch X rx-rlimit",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Get rate-limit on in-coming packet-ins")
{
    uint64_t dp_id;
    uint32_t pps = 0;

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);    
        return CMD_SUCCESS;
    }

    if (mul_get_switch_pkt_rlim(cli->mul_service, dp_id,
                                &pps, true)) {
        vty_out(vty, "Failed to get rate-limit%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    vty_out(vty, "RX rate limit(%s):%lu pps%s", pps ? "Enabled":"Disabled",
            U322UL(pps), VTY_NEWLINE); 

    return CMD_SUCCESS;
}

DEFUN (of_switch_tx_rlim,
       of_switch_tx_rlim_cmd,
       "set of-switch X tx-rlim-enable <1-1000000>",
       SET_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Enable rate-limit on out-coming packet-outs\n"
       "Enter a valid packets per second count")
{
    uint64_t dp_id;

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);    
        return CMD_SUCCESS;
    }

    if (mul_set_switch_pkt_rlim(cli->mul_service, dp_id,
                                atoi(argv[1]), false)) {
        vty_out(vty, "Failed to set rate-limit%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (of_switch_tx_rlim_disable,
       of_switch_tx_rlim_disable_cmd,
       "set of-switch X tx-rlim-disable",
       SET_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Disable any rate-limit on out-coming packet-outs")
{
    uint64_t dp_id;

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);    
        return CMD_SUCCESS;
    }

    if (mul_set_switch_pkt_rlim(cli->mul_service, dp_id,
                                0, false)) {
        vty_out(vty, "Failed to disable rate-limit%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (of_switch_tx_rlim_get,
       of_switch_tx_rlim_get_cmd,
       "show of-switch X tx-rlimit",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Get rate-limit on out-going packet-outs")
{
    uint64_t dp_id;
    uint32_t pps = 0;

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);    
        return CMD_SUCCESS;
    }

    if (mul_get_switch_pkt_rlim(cli->mul_service, dp_id,
                                &pps, false)) {
        vty_out(vty, "Failed to get rate-limit%s", VTY_NEWLINE);
    }

    vty_out(vty, "TX rate limit(%s):%lu pps%s", pps ? "Enabled":"Disabled",
            U322UL(pps), VTY_NEWLINE); 

    return CMD_SUCCESS;
}

DEFUN (of_switch_pkt_dump,
       of_switch_pkt_dump_cmd,
       "set of-switch X pkt-dump rx (enable|disable) tx (enable|disable) "
       "mask0 (X|all) mask1 (X|all) mask2 (X|all) mask3 (X|all)",
       SET_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Packet dump attribute\n"
       "RX packet dump behaviour\n"
       "Enable\n"
       "Or Disable\n"
       "TX packet dump behaviour\n"
       "Enable\n"
       "Or Disable\n"
       "Mask0\n"
       "Enter mask\n"
       "Or All\n"
       "Mask1\n"
       "Enter mask\n"
       "Or All\n"
       "Mask2\n"
       "Enter mask\n"
       "Or All\n"
       "Mask3\n"
       "Enter mask\n"
       "Or All\n")
{
    uint64_t dp_id;
    bool rx_en, tx_en;
    uint64_t mask[4];

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);    
        return CMD_SUCCESS;
    }

    if (!strncmp(argv[1], "enable", strlen(argv[1]))) {
        rx_en = true;
    } else {
        rx_en = false;
    }

    if (!strncmp(argv[2], "enable", strlen(argv[2]))) {
        tx_en = true;
    } else {
        tx_en = false;
    }

    if (!strncmp(argv[3], "all", strlen(argv[3]))) {
        mask[0] = (uint64_t)(-1);
    } else {
        mask[0] = strtoull(argv[3], NULL, 16);
    }

    if (!strncmp(argv[4], "all", strlen(argv[4]))) {
        mask[1] = (uint64_t)(-1);
    } else {
        mask[1] = strtoull(argv[4], NULL, 16);
    }

    if (!strncmp(argv[5], "all", strlen(argv[5]))) {
        mask[2] = (uint64_t)(-1);
    } else {
        mask[2] = strtoull(argv[5], NULL, 16);
    }

    if (!strncmp(argv[6], "all", strlen(argv[6]))) {
        mask[3] = (uint64_t)(-1);
    } else {
        mask[3] = strtoull(argv[6], NULL, 16);
    }

    if (mul_set_switch_pkt_dump(cli->mul_service, dp_id,
                                rx_en, tx_en, mask)) {
        vty_out(vty, "Failed to set switch pkt-dump%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (of_switch_port_stats,
       of_switch_port_stats_cmd,
       "set of-switch X port-stats (enable|disable)",
       SET_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Port stats mode\n"
       "Enable the port stats\n"
       "Disable the port stats\n")
{
    uint64_t dp_id;
    bool port_stats_en;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (!strncmp(argv[1], "enable", strlen(argv[1]))) {
        port_stats_en = true;
    } else {
        port_stats_en = false;
    }

    if (mul_set_switch_stats_mode(cli->mul_service, dp_id, port_stats_en)) {
        vty_out(vty, "Failed to set switch port stats mode%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}


DEFUN (of_switch_stats_strategy,
       of_switch_stats_strategy_cmd,
       "set of-switch X stats-gather flow (bulk|single) group (bulk|single) "
       "meter-conf (bulk|single)",
       SET_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Stats gathering attribute\n"
       "Flow stats gather behaviour\n"
       "Bulk mode\n"
       "Or Single\n"
       "Group stats gather behaviour\n"
       "Bulk mode\n"
       "Or Single\n"
       "Meter config stats gather behaviour\n"
       "Bulk mode\n"
       "Or Single\n")
{
    uint64_t dp_id;
    bool flow_bulk_en;
    bool group_bulk_en;
    bool meter_bulk_config_en;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    dp_id = strtoull(argv[0], NULL, 16);

    if (!c_app_switch_get_version_with_id(dp_id)) {
        vty_out(vty, "No such switch%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (!strncmp(argv[1], "bulk", strlen(argv[1]))) {
        flow_bulk_en = true;
    } else {
        flow_bulk_en = false;
    }

    if (!strncmp(argv[2], "bulk", strlen(argv[2]))) {
        group_bulk_en = true;
    } else {
        group_bulk_en = false;
    }

    if (!strncmp(argv[3], "bulk", strlen(argv[3]))) {
        meter_bulk_config_en = true;
    } else {
        meter_bulk_config_en = false;
    }

    if (mul_set_switch_stats_strategy(cli->mul_service, dp_id,
                                      flow_bulk_en, group_bulk_en,
                                      meter_bulk_config_en)) {
        vty_out(vty, "Failed to set switch stats strategy%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (of_switch_port_stats_show,
       of_switch_port_stats_show_cmd,
       "show of-switch X port-stats port <0-4294967295>",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Port statistics\n"
       "Switch Port\n"
       "Enter Port number\n")
{
    uint64_t    dp_id;
    uint32_t    port_no;
    
    struct cbuf *b = NULL;
    char *pbuf = NULL;

    dp_id = strtoull(argv[0], NULL, 16);
    port_no = atoi(argv[1]);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);


    b = mul_get_switch_port_stats(cli->mul_service, dp_id, port_no);

    if (b) {
        pbuf = mul_dump_port_stats (b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (of_switch_table_stats_show,
       of_switch_table_stats_show_cmd,
       "show of-switch X table-stats <0-255>",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Table statistics\n"
       "Enable a valid table-id\n")
{
    uint64_t    dp_id;
    uint32_t    active_count = 0;
    uint64_t    lookup_count = 0;
    uint64_t    matched_count = 0;

    dp_id = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);


    if (mul_get_switch_table_stats(cli->mul_service, dp_id,
                                   atoi(argv[1]), &active_count,
                                   &lookup_count, &matched_count)) {
        vty_out(vty, "Failed to get table stats\r\n");
        return CMD_SUCCESS;
    }

    vty_out (vty, "Active Entries %lu Lookup count %llu "
             "Matched count %llu\r\n", U322UL(active_count),
             U642ULL(lookup_count), U642ULL(matched_count));
                
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (show_of_switch_desc_detail,
       show_of_switch_desc_detail_cmd,
       "show of-switch X desc-features",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Switch description features\n")
{
    uint64_t    dp_id;
    struct cbuf *b;
    char *      pbuf;

    dp_id = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);


    b = mul_get_switch_features(cli->mul_service, dp_id,
                                0, C_AUX_CMD_MUL_GET_SWITCH_DESC);
    if (b) {
        pbuf = mul_dump_switch_desc(b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_group_detail,
       show_of_switch_group_detail_cmd,
       "show of-switch X group-features",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Switch group features\n")
{
    uint64_t    dp_id;
    struct cbuf *b;
    char *      pbuf;

    dp_id = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);


    b = mul_get_switch_features(cli->mul_service, dp_id,
                                0, C_AUX_CMD_MUL_SWITCH_GROUP_FEAT);
    if (b) {
        pbuf = mul_dump_switch_group_features(b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_meter_detail,
       show_of_switch_meter_detail_cmd,
       "show of-switch X meter-features",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Switch meter features\n")
{
    uint64_t    dp_id;
    struct cbuf *b;
    char *      pbuf;

    dp_id = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);


    b = mul_get_switch_features(cli->mul_service, dp_id,
                                0, C_AUX_CMD_MUL_SWITCH_METER_FEAT);
    if (b) {
        pbuf = mul_dump_switch_meter_features(b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_table_detail,
       show_of_switch_table_detail_cmd,
       "show of-switch X table-features <0-254>",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Switch table features\n"
       "Enter a table-id")
{
    uint64_t    dp_id;
    struct cbuf *b;
    char *      pbuf;

    dp_id = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    b = mul_get_switch_features(cli->mul_service, dp_id,
                                atoi(argv[1]), 
                                C_AUX_CMD_MUL_SWITCH_TABLE_FEAT);
    if (b) {
        pbuf = mul_dump_switch_table_features(b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_get_port_queues,
       show_of_switch_get_port_queues_cmd,
       "show of-switch X port-queues <1-4294967040>",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Get queues configured on a port\n"
       "Enter a valid port-no\n")
{
    uint64_t    dp_id;
    uint32_t    port_id;

    dp_id = strtoull(argv[0], NULL, 16);
    port_id = strtoul(argv[1], NULL, 10);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    vty_out (vty,
            "                     Queues Configured%s",
            VTY_NEWLINE); 
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
     
    mul_get_port_q_info(cli->mul_service, dp_id,
                           port_id, vty, vty_dump);
    vty_out (vty,
            "%s-------------------------------------------"
            "----------------------------------%s%s",
           VTY_NEWLINE,  VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_flow_tbid,
       show_of_switch_flow_tbid_cmd,
       "show of-flow switch X table <0-255>",
       SHOW_STR
       "Openflow flow tuple\n"
       "For a particular switch\n"
       "datapath-id in 0xXXX format\n"
       "For a particular table in a given switch\n"
       "table-id in decimal format\n")
{
    uint64_t                    dp_id;
    uint8_t                     tbid;

    dp_id = strtoull(argv[0], NULL, 16);
    tbid = strtoul(argv[1], NULL, 10);

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_get_flow_info(cli->mul_service, dp_id, tbid, false, true, true,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_flow,
       show_of_switch_flow_cmd,
       "show of-flow switch X",
       SHOW_STR
       "Openflow flow tuple\n"
       "For a particular switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t                    dp_id;

    dp_id = strtoull(argv[0], NULL, 16);

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_get_flow_info(cli->mul_service, dp_id, false, false, false, false,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_flow_all,
       show_of_switch_flow_all_cmd,
       "show of-flow switch X all",
       SHOW_STR
       "Openflow flow tuple\n"
       "For a particular switch\n"
       "datapath-id in 0xXXX format\n"
       "all flows in the switch")
{
    uint64_t                    dp_id;

    dp_id = strtoull(argv[0], NULL, 16);

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_get_flow_info(cli->mul_service, dp_id, false, false, true, false,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (show_of_flow_all,
       show_of_flow_all_cmd,
       "show of-flow all",
       SHOW_STR
       "Openflow flow tuple\n"
       "On all switches\n")
{
    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_get_flow_info(cli->mul_service, 0, false, false, true, false,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_flow_static,
       show_of_switch_flow_static_cmd,
       "show of-flow switch X static",
       SHOW_STR
       "Openflow flow tuple\n"
       "For a particular switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t                    dp_id;

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    dp_id = strtoull(argv[0], NULL, 16);

    mul_get_flow_info(cli->mul_service, dp_id, false, true, false, false,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (show_of_flow_all_static,
       show_of_flow_all_static_cmd,
       "show of-flow all-static",
       SHOW_STR
       "Openflow flow tuple\n"
       "All static flows\n")
{
    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_get_flow_info(cli->mul_service, 0, false, true, false, false,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (of_flow_vty_del_extended,
       of_flow_vty_del_extended_cmd,
       "of-flow del switch X smac (X|*) dmac (X|*) eth-type (X|*) vid (<0-4095>|*)"
       " vlan-pcp (<0-7>|*) mpls-label (<0-1048575>|*) mpls-tc (<0-7>|*) mpls-bos (<0-1>|*)"
       " dip (A.B.C.D/M|*) sip (A.B.C.D/M|*) proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "in-port (<1-65535>|*) table <0-254> flow-priority <0-65535> tunnel-id (X|*)",
       "OF-Flow configuration\n"
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "source mac\n"
       "Enter valid source mac\n"
       "* for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac\n"
       "* for wildcard\n"
       "ether type\n"
       "Enter valid ether type (as 0xXXXX)\n"
       "* for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id\n"
       "* for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "* for wildcard\n"
       "dst-ip/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "src-ip/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "IP protocol\n"
       "Enter a valid ip-proto\n"
       "* for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value\n"
       "* for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port\n"
       "* for wildcard\n"
       "src-port\n"
       "Enter valid src port\n"
       "* for wildcard\n"
       "input port\n"
       "Enter input port index\n"
       "* for wildcard\n"
       "table-id\n"
       "Enter table-id\n"
       "flow-priority\n"
       "Enter Flow-Priority\n")
       
{
    int                          i;
    uint64_t                     dp_id;
    struct flow                  *flow;
    struct flow                  *mask;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct prefix_ipv4           dst_p, src_p;
    uint32_t                     nmask = 0;
    uint8_t                      version;
    uint16_t prio;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }
    flow = calloc(1, sizeof(*flow));
    assert(flow);

    mask = calloc(1, sizeof(*mask));
    assert(mask);
    of_mask_set_no_dc(mask); 

    dp_id = strtoull(argv[0], NULL, 16);
    version = c_app_switch_get_version_with_id(dp_id);

    if (!strncmp(argv[1], "*", strlen(argv[1]))) {
        memset(flow->dl_src, 0, 6);
        memset(mask->dl_src, 0, 6);
    } else {
        mac_str = (void *)argv[1];
        for (i = 0; i < 6; i++) {
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[2], "*", strlen(argv[2]))) {
        memset(flow->dl_dst, 0, 6);
        memset(mask->dl_dst, 0, 6);
    } else {
        mac_str = (void *)argv[2];
        for (i = 0; i < 6; i++) {
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[3], "*", strlen(argv[3]))) {
        flow->dl_type = 0;
        mask->dl_type = 0;
    } else {
        nmask = strtoull(argv[3], NULL, 16);
        if ((nmask == ULONG_MAX && errno == ERANGE) ||
             nmask > 0xffff) {
            vty_out (vty, "%% Malformed eth-type %s", VTY_NEWLINE);
            goto free_err_out;
        }
        flow->dl_type = htons((uint16_t)(nmask));
        nmask = 0;
    }

    if (!strncmp(argv[4], "*", strlen(argv[4]))) {
        flow->dl_vlan = 0;
        mask->dl_vlan = 0;
    } else {
        flow->dl_vlan = htons(atoi(argv[4])); // Check ?
    }

    if (!strncmp(argv[5], "*", strlen(argv[5]))) {
        flow->dl_vlan_pcp = 0;
        mask->dl_vlan_pcp = 0;
    } else {
        if (flow->dl_vlan) {
            flow->dl_vlan_pcp = atoi(argv[5]);
        } else {
            vty_out (vty, "vlan_pcp: vlan == NONE %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[6], "*", strlen(argv[6]))) {
        flow->mpls_label = 0;
        mask->mpls_label = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        }
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_label = htonl(atoi(argv[6])); // Check ?
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[7], "*", strlen(argv[7]))) {
        flow->mpls_tc = 0;
        mask->mpls_tc = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        }
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_tc = atoi(argv[7]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[8], "*", strlen(argv[8]))) {
        flow->mpls_bos = 0;
        mask->mpls_bos = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        }
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_bos = atoi(argv[8]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    memset(&mask->ipv6, 0, sizeof(mask->ipv6));
    if (!strncmp(argv[9], "*", strlen(argv[9]))) {
        dst_p.prefixlen = 0;
        dst_p.prefix.s_addr = 0;
        nmask = 0;
    } else {
        ret = str2prefix(argv[9], (void *)&dst_p);
        if (ret <= 0) {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            goto free_err_out;
        }

        if (dst_p.prefixlen) {
            if (flow->dl_type == htons(ETH_TYPE_IP)) {
                nmask = make_inet_mask(dst_p.prefixlen);
            } else {
                vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
                goto free_err_out;
            }
        } else {
            nmask = 0;
        }
    }

    mask->ip.nw_dst = htonl(nmask);
    flow->ip.nw_dst = dst_p.prefix.s_addr & htonl(nmask);

    if (!strncmp(argv[10], "*", strlen(argv[10]))) {
        src_p.prefixlen = 0;
        src_p.prefix.s_addr = 0;
        nmask = 0;
    } else {
        ret = str2prefix(argv[10], (void *)&src_p);
        if (ret <= 0) {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            goto free_err_out;
        }

        if (src_p.prefixlen) {
            if (flow->dl_type == htons(ETH_TYPE_IP)) {
                nmask = make_inet_mask(src_p.prefixlen);
            } else {
                vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
                goto free_err_out;
            }
        } else {
            nmask = 0;
        }
    }

    mask->ip.nw_src = htonl(nmask);
    flow->ip.nw_src = src_p.prefix.s_addr & htonl(nmask);

    if (!strncmp(argv[11], "*", strlen(argv[11]))) {
        flow->nw_proto = 0;
        mask->nw_proto = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_proto = atoi(argv[11]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[12], "*", strlen(argv[12]))) {
        flow->nw_tos = 0;
        mask->nw_tos = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_tos = atoi(argv[12]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[13], "*", strlen(argv[13]))) {
        flow->tp_dst = 0;
        mask->tp_dst = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_dst = htons(atoi(argv[13]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IP || ip_type != UDP/TCP %s",
                    VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[14], "*", strlen(argv[14]))) {
        flow->tp_src = 0;
        mask->tp_src = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_src = htons(atoi(argv[14]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IP || ip_type != UDP/TCP %s",
                    VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[15], "*", strlen(argv[15]))) {
        flow->in_port = 0;
        mask->in_port = 0;
    } else {
        flow->in_port = htonl(atoi(argv[15]));
    }

    flow->table_id = atoi(argv[16]);
    prio = atoi(argv[17]);

    if (!strncmp(argv[18], "*", strlen(argv[18]))) {
        flow->tunnel_id = 0;
        mask->tunnel_id = 0;
    } else {
        flow->tunnel_id = strtoull(argv[18], NULL, 16);
        if ((flow->tunnel_id == (uint64_t)(-1) && errno == ERANGE))  {
            vty_out(vty, "tunnel-id parse fail\r\n");
            goto free_err_out;;
        }
        flow->tunnel_id = htonll(flow->tunnel_id);
        mask->tunnel_id = (uint64_t)(-1);
    }

    mask->metadata = 0;

    mul_service_send_flow_del(cli->mul_service, dp_id, flow, mask,
                          0, prio, C_FL_ENT_STATIC,
                          OFPG_ANY);

    if (c_service_timed_wait_response(cli->mul_service) > 0) {
        vty_out(vty, "Failed to delete a flow. Check log messages%s",
                VTY_NEWLINE);
    }

    free(flow);
    free(mask);

    return CMD_SUCCESS;

free_err_out:
    free(flow);
    free(mask);
    return CMD_WARNING;
}


DEFUN (of_flow_vty_del,
       of_flow_vty_del_cmd,
       "of-flow del switch X smac (X|*) dmac (X|*) eth-type (X|*) vid (<0-4095>|*)"
       " vlan-pcp (<0-7>|*) mpls-label (<0-1048575>|*) mpls-tc (<0-7>|*) mpls-bos (<0-1>|*)"
       " dip (A.B.C.D/M|*) sip (A.B.C.D/M|*) proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "in-port (<1-65535>|*) table <0-254>",
       "OF-Flow configuration\n"
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "source mac\n"
       "Enter valid source mac\n"
       "* for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac\n"
       "* for wildcard\n"
       "ether type\n"
       "Enter valid ether type (as 0xXXXX)\n"
       "* for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id\n"
       "* for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "* for wildcard\n"
       "dst-ip/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "src-ip/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "IP protocol\n"
       "Enter a valid ip-proto\n"
       "* for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value\n"
       "* for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port\n"
       "* for wildcard\n"
       "src-port\n"
       "Enter valid src port\n"
       "* for wildcard\n"
       "input port\n"
       "Enter input port index\n"
       "* for wildcard\n"
       "table-id\n"
       "Enter table-id\n")
       
{
    char *prio = calloc(1,2);
    char *tunnel;
    char **new_argv;
    uint8_t counter = 0;
    int ret_value = CMD_WARNING;

    if (!prio) goto out;

    if (!(tunnel = calloc(1, 2))) goto out;

    new_argv = calloc(argc + 2, sizeof(uint8_t *));
    if (!new_argv) goto out1;

    for (counter = 0; counter < argc;counter++) {
        new_argv[counter] = (char *)argv[counter];
    }

    sprintf(prio, "%d", C_FL_PRIO_FWD);
    strcpy(tunnel, "*");

    new_argv[argc] = prio;
    new_argv[argc+1] = tunnel;

    ret_value = of_flow_vty_del_extended_cmd.func(self, vty, 
                                              argc + 2,
                                              (const char **)new_argv);

    free(prio);
    free(new_argv);
out1:
    free(tunnel);
out:
    return ret_value;

}

DEFUN_NOSH (of_flow_vty_add,
       of_flow_vty_add_cmd,
       "of-flow add switch X smac (X|*) dmac (X|*) eth-type (X|*) vid (<0-4095>|*)"
       " vlan-pcp (<0-7>|*) mpls-label (<0-1048575>|*) mpls-tc (<0-7>|*) mpls-bos (<0-1>|*)"
       " dip (A.B.C.D/M|*) sip (A.B.C.D/M|*) proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "in-port (<1-65535>|*) table <0-254>",
       "OF-Flow configuration\n"
       "Add\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "source mac\n"
       "Enter valid source mac\n"
       "* for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac\n"
       "* for wildcard\n"
       "ether type\n"
       "Enter valid ether type (as 0xXXXX)\n"
       "* for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id\n"
       "* for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "* for wildcard\n"
       "mpls label\n"
       "Enter mpls label(in decimal)\n"
       "* for wildcard\n"
       "mpls tc\n"
       "Enter mpls tc\n"
       "* for wildcard\n"
       "mpls bos\n"
       "Enter mpls bos\n"
       "* for wildcard\n"
       "dst-ip/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "src-ip/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "IP protocol\n"
       "Enter a valid ip-proto\n"
       "* for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value\n"
       "* for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port\n"
       "* for wildcard\n"
       "src-port\n"
       "Enter valid src port\n"
       "* for wildcard\n"
       "input port\n"
       "Enter input port index\n"
       "* for wildcard\n"
       "table-id\n"
       "Enter table-id\n")
{
    int                          i;
    struct flow                  *flow;
    struct flow                  *mask;
    struct mul_act_mdata         *mdata;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct prefix_ipv4           dst_p, src_p;
    struct cli_flow_action_parms *args; 
    uint32_t                     nmask;
    uint8_t                      version;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }
    flow = calloc(1, sizeof(*flow));
    assert(flow);

    mask = calloc(1, sizeof(*mask));
    assert(mask);
    of_mask_set_no_dc(mask);

    mdata= calloc(1, sizeof(*mdata));
    assert(mdata);

    args = calloc(1, sizeof(*args));
    assert(args);

    args->dpid = strtoull(argv[0], NULL, 16);
    version = c_app_switch_get_version_with_id(args->dpid);

    if (!strncmp(argv[1], "*", strlen(argv[1]))) {
        memset(flow->dl_src, 0, 6);
        memset(mask->dl_src, 0, 6);
    } else {
        mac_str = (void *)argv[1];
        for (i = 0; i < 6; i++) {
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[2], "*", strlen(argv[2]))) {
        memset(flow->dl_dst, 0, 6);
        memset(mask->dl_dst, 0, 6);
    } else {
        mac_str = (void *)argv[2];
        for (i = 0; i < 6; i++) {
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[3], "*", strlen(argv[3]))) {
        flow->dl_type = 0;
        mask->dl_type = 0;
    } else {
        nmask = strtoull(argv[3], NULL, 16);
        if ((nmask == ULONG_MAX && errno == ERANGE) ||
             nmask > 0xffff) {
            vty_out (vty, "%% Malformed eth-type %s", VTY_NEWLINE);
            goto free_err_out;
        }
        flow->dl_type = htons((uint16_t)(nmask));
        nmask = 0;
    }

    if (!strncmp(argv[4], "*", strlen(argv[4]))) {
        flow->dl_vlan = 0;
        mask->dl_vlan = 0;
    } else {
        flow->dl_vlan = htons(atoi(argv[4])); // Check ?
    }

    if (!strncmp(argv[5], "*", strlen(argv[5]))) {
        flow->dl_vlan_pcp = 0;
        mask->dl_vlan_pcp = 0;
    } else {
        if (flow->dl_vlan) {
            flow->dl_vlan_pcp = atoi(argv[5]);
        } else {
            vty_out (vty, "vlan_pcp: vlan == NONE %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[6], "*", strlen(argv[6]))) {
        flow->mpls_label = 0;
        mask->mpls_label = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        } 
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_label = htonl(atoi(argv[6])); // Check ?
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[7], "*", strlen(argv[7]))) {
        flow->mpls_tc = 0;
        mask->mpls_tc = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        } 
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_tc = atoi(argv[7]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[8], "*", strlen(argv[8]))) {
        flow->mpls_bos = 0;
        mask->mpls_bos = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        } 
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_bos = atoi(argv[8]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    memset(&mask->ipv6, 0, sizeof(mask->ipv6));
    if (!strncmp(argv[9], "*", strlen(argv[9]))) {
        dst_p.prefixlen = 0;
        dst_p.prefix.s_addr = 0;
        nmask = 0;
    } else {
        ret = str2prefix(argv[9], (void *)&dst_p);
        if (ret <= 0) {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            goto free_err_out;
        }

        if (dst_p.prefixlen) {
            if ((flow->dl_type == htons(ETH_TYPE_IP)) || 
                (flow->dl_type == htons(ETH_TYPE_ARP))) {
                nmask = make_inet_mask(dst_p.prefixlen);
            } else {
                vty_out (vty, "nw_dst:dl_type != ETH_TYPE_IP or \
                        ETH_TYPE_ARP%s", VTY_NEWLINE);
                goto free_err_out;
            }
        } else {
            nmask = 0;
        }
    }

    mask->ip.nw_dst = htonl(nmask);
    flow->ip.nw_dst = dst_p.prefix.s_addr & htonl(nmask);

    if (!strncmp(argv[10], "*", strlen(argv[10]))) {
        src_p.prefixlen = 0;
        src_p.prefix.s_addr = 0;
        nmask = 0;
   } else {
        ret = str2prefix(argv[10], (void *)&src_p);
        if (ret <= 0) {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            goto free_err_out;
        }

        if (src_p.prefixlen) {
            if ((flow->dl_type == htons(ETH_TYPE_IP)) || 
                (flow->dl_type == htons(ETH_TYPE_ARP))) {
                nmask = make_inet_mask(src_p.prefixlen);
            } else {
                vty_out (vty, "nw_src: dl_type != ETH_TYPE_IP or \
                        ETH_TYPE_ARP %s", VTY_NEWLINE);
                goto free_err_out;
            }
        } else {
            nmask = 0;
        }
    }

    mask->ip.nw_src = htonl(nmask);
    flow->ip.nw_src = src_p.prefix.s_addr & htonl(nmask);

    if (!strncmp(argv[11], "*", strlen(argv[11]))) {
        flow->nw_proto = 0;
        mask->nw_proto = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_proto = atoi(argv[11]);
        } else {
            vty_out (vty, "nw_proto:dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[12], "*", strlen(argv[12]))) {
        flow->nw_tos = 0;
        mask->nw_tos = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_tos = atoi(argv[12]);
        } else {
            vty_out (vty, "nw_tos: dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[13], "*", strlen(argv[13]))) {
        flow->tp_dst = 0;
        mask->tp_dst = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_dst = htons(atoi(argv[13]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IP || ip_type != UDP/TCP %s",
                     VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[14], "*", strlen(argv[14]))) {
        flow->tp_src = 0;
        mask->tp_src = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_src = htons(atoi(argv[14]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IP || ip_type != UDP/TCP %s",
                    VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[15], "*", strlen(argv[15]))) {
        flow->in_port = 0;
        mask->in_port = 0;
    } else {
        flow->in_port = htonl(atoi(argv[15]));
    }

    flow->table_id = atoi(argv[16]);
 
    mask->tunnel_id = 0;
    mask->metadata = 0;
    
    mul_app_act_alloc(mdata);
    if (mul_app_act_set_ctors(mdata, args->dpid)) {
        vty_out(vty, "Switch 0x%llx does not exist\r\n", U642ULL(args->dpid));
        goto free_err_out;
    }
    args->fl = flow;
    args->mask = mask;
    args->mdata = mdata;
    args->cmn.flow_act = true;
    args->fl_prio = C_FL_PRIO_FWD;

    vty->index = args;

    if ((ret = flow_inst_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto free_err_out;  
    }

    return CMD_SUCCESS;

free_err_out:
    free(args);
    free(flow);
    mul_app_act_free(mdata);
    free(mdata);
    free(mask);
    return CMD_WARNING;
}

DEFUN (of_flow6_vty_del_extended,
       of_flow6_vty_del_extended_cmd,
       "of-flow del switch X smac (X|*) dmac (X|*) eth-type (X|*) vid (<0-4095>|*)"
       " vlan-pcp (<0-7>|*) mpls-label (<0-1048575>|*) mpls-tc (<0-7>|*) mpls-bos (<0-1>|*)"
       " dip6 (X:X::X:X/M|*) sip6 (X:X::X:X/M|*) proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "in-port (<1-65535>|*) table <0-254> flow-priority <0-65535> tunnel-id (X|*)",
       "OF-Flow configuration\n"
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "source mac\n"
       "Enter valid source mac\n"
       "* for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac\n"
       "* for wildcard\n"
       "ether type\n"
       "Enter valid ether type (as 0xXXXX)\n"
       "* for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id\n"
       "* for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "* for wildcard\n"
       "dst-ipv6 addr/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "src-ipv6 addr/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "IP protocol\n"
       "Enter a valid ip-proto\n"
       "* for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value\n"
       "* for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port\n"
       "* for wildcard\n"
       "src-port\n"
       "Enter valid src port\n"
       "* for wildcard\n"
       "input port\n"
       "Enter input port index\n"
       "* for wildcard\n"
       "table-id\n"
       "Enter table-id\n"
       "flow-priority\n"
       "Enter Flow-Priority\n")
{
    int                          i;
    uint64_t                     dp_id;
    struct flow                  *flow;
    struct flow                  *mask;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct prefix_ipv6           dst_p, src_p;
    uint32_t                     nmask = 0;
    uint8_t                      version;
    uint16_t                     prio;
    struct ipv6_addr             addr6;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }
    flow = calloc(1, sizeof(*flow));
    assert(flow);

    mask = calloc(1, sizeof(*mask));
    assert(mask);
    of_mask_set_no_dc(mask); 

    dp_id = strtoull(argv[0], NULL, 16);
    version = c_app_switch_get_version_with_id(dp_id);

    if (!strncmp(argv[1], "*", strlen(argv[1]))) {
        memset(flow->dl_src, 0, 6);
        memset(mask->dl_src, 0, 6);
    } else {
        mac_str = (void *)argv[1];
        for (i = 0; i < 6; i++) {
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[2], "*", strlen(argv[2]))) {
        memset(flow->dl_dst, 0, 6);
        memset(mask->dl_dst, 0, 6);
    } else {
        mac_str = (void *)argv[2];
        for (i = 0; i < 6; i++) {
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[3], "*", strlen(argv[3]))) {
        flow->dl_type = 0;
        mask->dl_type = 0;
    } else {
        nmask = strtoull(argv[3], NULL, 16);
        if ((nmask == ULONG_MAX && errno == ERANGE) ||
             nmask > 0xffff) {
            vty_out (vty, "%% Malformed eth-type %s", VTY_NEWLINE);
            goto free_err_out;
        }
        flow->dl_type = htons((uint16_t)(nmask));
        nmask = 0;
    }

    if (!strncmp(argv[4], "*", strlen(argv[4]))) {
        flow->dl_vlan = 0;
        mask->dl_vlan = 0;
    } else {
        flow->dl_vlan = htons(atoi(argv[4])); // Check ?
    }

    if (!strncmp(argv[5], "*", strlen(argv[5]))) {
        flow->dl_vlan_pcp = 0;
        mask->dl_vlan_pcp = 0;
    } else {
        if (flow->dl_vlan) {
            flow->dl_vlan_pcp = atoi(argv[5]);
        } else {
            vty_out (vty, "vlan_pcp: vlan == NONE %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[6], "*", strlen(argv[6]))) {
        flow->mpls_label = 0;
        mask->mpls_label = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        }
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_label = htonl(atoi(argv[6])); // Check ?
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[7], "*", strlen(argv[7]))) {
        flow->mpls_tc = 0;
        mask->mpls_tc = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        }
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_tc = atoi(argv[7]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[8], "*", strlen(argv[8]))) {
        flow->mpls_bos = 0;
        mask->mpls_bos = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        }
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_bos = atoi(argv[8]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    memset(&mask->ipv6, 0, sizeof(mask->ipv6));
    if (!strncmp(argv[9], "*", strlen(argv[9]))) {
        dst_p.prefixlen = 0;
        memset(&dst_p.prefix, 0, sizeof(dst_p.prefix));
    } else {
        ret = str2prefix_ipv6(argv[9], (void *)&dst_p);
        if (ret <= 0) {
            vty_out (vty, "%% Malformed ipv6 address%s", VTY_NEWLINE);
            goto free_err_out;
        }

        if (dst_p.prefixlen) {
            if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
                ipv6_addr_set(&addr6, 0xffffffff, 0xffffffff,
                              0xffffffff, 0xffffffff);
                ipv6_addr_prefix(&mask->ipv6.nw_dst, &addr6,
                                 dst_p.prefixlen);
            } else {
                vty_out(vty, "nw_dst6:dl_type != ETH_TYPE_IPV6%s",
                        VTY_NEWLINE);
                goto free_err_out;
            }
        }
    }

    if (dst_p.prefixlen)
        ipv6_addr_prefix(&flow->ipv6.nw_dst,
                         (struct ipv6_addr *)&dst_p.prefix,
                         dst_p.prefixlen);

    if (!strncmp(argv[10], "*", strlen(argv[10]))) {
        src_p.prefixlen = 0;
        memset(&src_p.prefix, 0, sizeof(src_p.prefix));
    } else {
        ret = str2prefix_ipv6(argv[10], (void *)&src_p);
        if (ret <= 0) {
            vty_out (vty, "%% Malformed ipv6 address%s", VTY_NEWLINE);
            goto free_err_out;
        }

        if (src_p.prefixlen) {
            if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
                ipv6_addr_set(&addr6, 0xffffffff, 0xffffffff,
                              0xffffffff, 0xffffffff);
                ipv6_addr_prefix(&mask->ipv6.nw_src, &addr6,
                                 src_p.prefixlen);
            } else {
                vty_out (vty, "nw_src: dl_type != ETH_TYPE_IPV6%s",
                         VTY_NEWLINE);
                goto free_err_out;
            }
        }
    }

    if (src_p.prefixlen)
        ipv6_addr_prefix(&flow->ipv6.nw_src,
                         (struct ipv6_addr *)&src_p.prefix,
                          src_p.prefixlen);


    if (!strncmp(argv[11], "*", strlen(argv[11]))) {
        flow->nw_proto = 0;
        mask->nw_proto = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            flow->nw_proto = atoi(argv[11]);
        } else {
            vty_out (vty, "nw_proto:dl_type != ETH_TYPE_IPV6 %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[12], "*", strlen(argv[12]))) {
        flow->nw_tos = 0;
        mask->nw_tos = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            flow->nw_tos = atoi(argv[12]);
        } else {
            vty_out (vty, "nw_tos:dl_type != ETH_TYPE_IPV6 %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[13], "*", strlen(argv[13]))) {
        flow->tp_dst = 0;
        mask->tp_dst = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IPV6) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_dst = htons(atoi(argv[13]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IPV6 || ip_type != UDP/TCP %s",
                    VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[14], "*", strlen(argv[14]))) {
        flow->tp_src = 0;
        mask->tp_src = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IPV6) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_src = htons(atoi(argv[14]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IPV6 || ip_type != UDP/TCP %s",
                    VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[15], "*", strlen(argv[15]))) {
        flow->in_port = 0;
        mask->in_port = 0;
    } else {
        flow->in_port = htonl(atoi(argv[15]));
    }

    flow->table_id = atoi(argv[16]);
    prio = atoi(argv[17]);

    if (!strncmp(argv[18], "*", strlen(argv[18]))) {
        flow->tunnel_id = 0;
        mask->tunnel_id = 0;
    } else {
        flow->tunnel_id = strtoull(argv[18], NULL, 16);
        if ((flow->tunnel_id == (uint64_t)(-1) && errno == ERANGE))  {
            vty_out(vty, "tunnel-id parse fail\r\n");
            goto free_err_out;;
        }
        flow->tunnel_id = htonll(flow->tunnel_id);
        mask->tunnel_id = (uint64_t)(-1);
    }

    mask->metadata = 0;

    mul_service_send_flow_del(cli->mul_service, dp_id, flow, mask,
                          0, prio, C_FL_ENT_STATIC,
                          OFPG_ANY);

    if (c_service_timed_wait_response(cli->mul_service) > 0) {
        vty_out(vty, "Failed to delete a flow. Check log messages%s",
                VTY_NEWLINE);
    }

    free(flow);
    free(mask);

    return CMD_SUCCESS;

free_err_out:
    free(flow);
    free(mask);
    return CMD_WARNING;
}


DEFUN (of_flow6_vty_del,
       of_flow6_vty_del_cmd,
       "of-flow del switch X smac (X|*) dmac (X|*) eth-type (X|*) vid (<0-4095>|*)"
       " vlan-pcp (<0-7>|*) mpls-label (<0-1048575>|*) mpls-tc (<0-7>|*) mpls-bos (<0-1>|*)"
       " dip6 (X:X::X:X/M|*) sip6 (X:X::X:X/M|*) proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "in-port (<1-65535>|*) table <0-254>",
       "OF-Flow configuration\n"
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "source mac\n"
       "Enter valid source mac\n"
       "* for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac\n"
       "* for wildcard\n"
       "ether type\n"
       "Enter valid ether type (as 0xXXXX)\n"
       "* for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id\n"
       "* for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "* for wildcard\n"
       "dst-ipv6 addr/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "src-ipv6 addr/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "IP protocol\n"
       "Enter a valid ip-proto\n"
       "* for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value\n"
       "* for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port\n"
       "* for wildcard\n"
       "src-port\n"
       "Enter valid src port\n"
       "* for wildcard\n"
       "input port\n"
       "Enter input port index\n"
       "* for wildcard\n"
       "table-id\n"
       "Enter table-id\n")
       
{
    char *prio = calloc(1,2);
    char *tunnel;
    char **new_argv;
    uint8_t counter = 0;
    int ret_value = CMD_WARNING;

    if (!prio) goto out;

    if (!(tunnel = calloc(1, 2))) goto out;

    new_argv = calloc(argc + 2, sizeof(uint8_t *));
    if (!new_argv) goto out1;

    for (counter = 0; counter < argc;counter++) {
        new_argv[counter] = (char *)argv[counter];
    }

    strcpy(prio, "1");
    strcpy(tunnel, "*");

    new_argv[argc] = prio;
    new_argv[argc+1] = tunnel;

    ret_value = of_flow6_vty_del_extended_cmd.func(self, vty,
                                              argc + 2,
                                              (const char **)new_argv);

    free(prio);
    free(new_argv);
out1:
    free(tunnel);
out:
    return ret_value;
}

DEFUN_NOSH (of_flow6_vty_add,
       of_flow6_vty_add_cmd,
       "of-flow add switch X smac (X|*) dmac (X|*) eth-type (X|*) vid (<0-4095>|*)"
       " vlan-pcp (<0-7>|*) mpls-label (<0-1048575>|*) mpls-tc (<0-7>|*) mpls-bos (<0-1>|*)"
       " dip6 (X:X::X:X/M|*) sip6 (X:X::X:X/M|*) proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "in-port (<1-65535>|*) table <0-254>",
       "OF-Flow configuration\n"
       "Add\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "source mac\n"
       "Enter valid source mac\n"
       "* for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac\n"
       "* for wildcard\n"
       "ether type\n"
       "Enter valid ether type (as 0xXXXX)\n"
       "* for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id\n"
       "* for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "* for wildcard\n"
       "mpls label\n"
       "Enter mpls label(in decimal)\n"
       "* for wildcard\n"
       "mpls tc\n"
       "Enter mpls tc\n"
       "* for wildcard\n"
       "mpls bos\n"
       "Enter mpls bos\n"
       "* for wildcard\n"
       "dst-ipv6 addr/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "src-ipv6 addr/mask\n"
       "Enter valid ip address and mask\n"
       "* for wildcard\n"
       "IP protocol\n"
       "Enter a valid ip-proto\n"
       "* for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value\n"
       "* for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port\n"
       "* for wildcard\n"
       "src-port\n"
       "Enter valid src port\n"
       "* for wildcard\n"
       "input port\n"
       "Enter input port index\n"
       "* for wildcard\n"
       "table-id\n"
       "Enter table-id\n")
{
    int                          i;
    struct flow                  *flow;
    struct flow                  *mask;
    struct mul_act_mdata         *mdata;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct prefix_ipv6           dst_p, src_p;
    struct cli_flow_action_parms *args; 
    uint32_t                     nmask;
    uint8_t                      version;
    struct ipv6_addr             addr6;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }
    flow = calloc(1, sizeof(*flow));
    assert(flow);

    mask = calloc(1, sizeof(*mask));
    assert(mask);
    of_mask_set_no_dc(mask);

    mdata= calloc(1, sizeof(*mdata));
    assert(mdata);

    args = calloc(1, sizeof(*args));
    assert(args);

    args->dpid = strtoull(argv[0], NULL, 16);
    version = c_app_switch_get_version_with_id(args->dpid);

    if (!strncmp(argv[1], "*", strlen(argv[1]))) {
        memset(flow->dl_src, 0, 6);
        memset(mask->dl_src, 0, 6);
    } else {
        mac_str = (void *)argv[1];
        for (i = 0; i < 6; i++) {
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[2], "*", strlen(argv[2]))) {
        memset(flow->dl_dst, 0, 6);
        memset(mask->dl_dst, 0, 6);
    } else {
        mac_str = (void *)argv[2];
        for (i = 0; i < 6; i++) {
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[3], "*", strlen(argv[3]))) {
        flow->dl_type = 0;
        mask->dl_type = 0;
    } else {
        nmask = strtoull(argv[3], NULL, 16);
        if ((nmask == ULONG_MAX && errno == ERANGE) ||
             nmask > 0xffff) {
            vty_out (vty, "%% Malformed eth-type %s", VTY_NEWLINE);
            goto free_err_out;
        }
        flow->dl_type = htons((uint16_t)(nmask));
        nmask = 0;
    }

    if (!strncmp(argv[4], "*", strlen(argv[4]))) {
        flow->dl_vlan = 0;
        mask->dl_vlan = 0;
    } else {
        flow->dl_vlan = htons(atoi(argv[4])); // Check ?
    }

    if (!strncmp(argv[5], "*", strlen(argv[5]))) {
        flow->dl_vlan_pcp = 0;
        mask->dl_vlan_pcp = 0;
    } else {
        if (flow->dl_vlan) {
            flow->dl_vlan_pcp = atoi(argv[5]);
        } else {
            vty_out (vty, "vlan_pcp: vlan == NONE %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[6], "*", strlen(argv[6]))) {
        flow->mpls_label = 0;
        mask->mpls_label = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        } 
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_label = htonl(atoi(argv[6])); // Check ?
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[7], "*", strlen(argv[7]))) {
        flow->mpls_tc = 0;
        mask->mpls_tc = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        } 
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_tc = atoi(argv[7]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[8], "*", strlen(argv[8]))) {
        flow->mpls_bos = 0;
        mask->mpls_bos = 0;
    } else {
        if (version ==  OFP_VERSION) {
            vty_out (vty, "No mpls support in switch %s", VTY_NEWLINE);
            goto free_err_out;
        } 
        if (flow->dl_type == htons(ETH_TYPE_MPLS) ||
            flow->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_bos = atoi(argv[8]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_MPLS %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    memset(&mask->ipv6, 0, sizeof(mask->ipv6));
    if (!strncmp(argv[9], "*", strlen(argv[9]))) {
        dst_p.prefixlen = 0;
        memset(&dst_p.prefix, 0, sizeof(dst_p.prefix));
    } else {
        ret = str2prefix_ipv6(argv[9], (void *)&dst_p);
        if (ret <= 0) {
            vty_out (vty, "%% Malformed ipv6 address%s", VTY_NEWLINE);
            goto free_err_out;
        }

        if (dst_p.prefixlen) {
            if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
                ipv6_addr_set(&addr6, 0xffffffff, 0xffffffff,
                              0xffffffff, 0xffffffff);
                ipv6_addr_prefix(&mask->ipv6.nw_dst, &addr6, 
                                 dst_p.prefixlen);
            } else {
                vty_out(vty, "nw_dst6:dl_type != ETH_TYPE_IPV6%s",
                        VTY_NEWLINE);
                goto free_err_out;
            }
        }
    }

    if (dst_p.prefixlen) 
        ipv6_addr_prefix(&flow->ipv6.nw_dst,
                         (struct ipv6_addr *)&dst_p.prefix,
                         dst_p.prefixlen);

    if (!strncmp(argv[10], "*", strlen(argv[10]))) {
        src_p.prefixlen = 0;
        memset(&src_p.prefix, 0, sizeof(src_p.prefix));
    } else {
        ret = str2prefix_ipv6(argv[10], (void *)&src_p);
        if (ret <= 0) {
            vty_out (vty, "%% Malformed ipv6 address%s", VTY_NEWLINE);
            goto free_err_out;
        }

        if (src_p.prefixlen) {
            if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
                ipv6_addr_set(&addr6, 0xffffffff, 0xffffffff,
                              0xffffffff, 0xffffffff);
                ipv6_addr_prefix(&mask->ipv6.nw_src, &addr6,
                                 src_p.prefixlen);
            } else {
                vty_out (vty, "nw_src: dl_type != ETH_TYPE_IPV6%s",
                         VTY_NEWLINE); 
                goto free_err_out;
            }
        }
    }

    if (src_p.prefixlen)
        ipv6_addr_prefix(&flow->ipv6.nw_src,
                         (struct ipv6_addr *)&src_p.prefix,
                          src_p.prefixlen);

    if (!strncmp(argv[11], "*", strlen(argv[11]))) {
        flow->nw_proto = 0;
        mask->nw_proto = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            flow->nw_proto = atoi(argv[11]);
        } else {
            vty_out (vty, "nw_proto:dl_type != ETH_TYPE_IPV6 %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[12], "*", strlen(argv[12]))) {
        flow->nw_tos = 0;
        mask->nw_tos = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            flow->nw_tos = atoi(argv[12]);
        } else {
            vty_out (vty, "nw_tos: dl_type != ETH_TYPE_IPV6 %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[13], "*", strlen(argv[13]))) {
        flow->tp_dst = 0;
        mask->tp_dst = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IPV6) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_SCTP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_dst = htons(atoi(argv[13]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IPV6 || ip_type != UDP/TCP/SCTP %s",
                     VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[14], "*", strlen(argv[14]))) {
        flow->tp_src = 0;
        mask->tp_src = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IPV6) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_SCTP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_src = htons(atoi(argv[14]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IPV6 || ip_type != UDP/TCP/SCTP %s",
                    VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[15], "*", strlen(argv[15]))) {
        flow->in_port = 0;
        mask->in_port = 0;
    } else {
        flow->in_port = htonl(atoi(argv[15]));
    }

    flow->table_id = atoi(argv[16]);
 
    mask->tunnel_id = 0;
    mask->metadata = 0;

    mul_app_act_alloc(mdata);
    if (mul_app_act_set_ctors(mdata, args->dpid)) {
        vty_out(vty, "Switch 0x%llx does not exist\r\n", U642ULL(args->dpid));
        goto free_err_out;
    }
    args->fl = flow;
    args->mask = mask;
    args->mdata = mdata;
    args->cmn.flow_act = true;
    args->fl_prio = C_FL_PRIO_FWD;

    vty->index = args;

    if ((ret = flow_inst_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto free_err_out;  
    }

    return CMD_SUCCESS;

free_err_out:
    free(args);
    free(flow);
    mul_app_act_free(mdata);
    free(mdata);
    free(mask);
    return CMD_WARNING;
}

DEFUN (of_add_meter_inst,
       of_add_meter_inst_cmd,
       "instruction-meter <0-4294967295>",
       "Add openflow Meter\n"
       "Enter meter-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    mul_app_inst_meter(mdata, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN (of_add_goto_instruction,
       of_add_goto_instruction_cmd,
       "instruction-goto <1-254>",
       "goto instruction\n"
       "Enter table-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_inst_goto(mdata, atoi(argv[0]))) {
        vty_out(vty, "Can't add goto instruction\r\n");
    } 

    return CMD_SUCCESS;
}

DEFUN (of_add_write_instruction,
       of_add_write_instruction_cmd,
       "instruction-write",
       "write instruction\n")
{
    int ret = 0;
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_set_inst_write(mdata)) {
        vty_out(vty, "Can't set write instruction\r\n");    
        return CMD_WARNING;
    }
        
    if ((ret = inst_actions_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_apply_instruction,
       of_add_apply_instruction_cmd,
       "instruction-apply",
       "apply instruction\n")
{
    int ret = 0;
    mul_act_mdata_t *mdata = NULL;
    uint8_t version;
    uint64_t dpid = 0;
    CLI_ARGS_TO_ACT_MDATA_DPID(mdata, vty->index, dpid);

    version = c_app_switch_get_version_with_id(dpid);
    if (version ==  OFP_VERSION) {
        goto set_actions;
    }

    if (mul_app_set_inst_apply(mdata)) {
        vty_out(vty, "Can't set apply instruction\r\n");    
        return CMD_WARNING;
    }

set_actions:
    if ((ret = inst_actions_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_instruction_action_fini,
       of_add_instruction_action_fini_cmd,
       "action-list-end",
       "Actions list add complete")
{
    vty->node = FLOW_NODE;
    return CMD_SUCCESS;
}

DEFUN (flow_stats_en,
       flow_stats_en_cmd,
       "flow-stats-enable",
       "Enable stats gathering for this flow\n")
{
    struct cli_flow_action_parms *fl_parms = vty->index;

    fl_parms->flags |= C_FL_ENT_GSTATS;

    return CMD_SUCCESS;
}

DEFUN (flow_barrier_en,
       flow_barrier_en_cmd,
       "flow-barrier-enable",
       "Send an accompanying barrier after this flow-mod\n")
{
    struct cli_flow_action_parms *fl_parms = vty->index;

    fl_parms->flags |= C_FL_ENT_BARRIER;

    return CMD_SUCCESS;
}

DEFUN (flow_no_post_validate,
       flow_no_post_validate_cmd,
       "flow-no-post-validate",
       "Strictly verify if flow has installed in the switch after this flow-mod\n")
{
    struct cli_flow_action_parms *fl_parms = vty->index;

    fl_parms->flags |= C_FL_NO_ACK;

    return CMD_SUCCESS;
}


DEFUN (flow_prio,
       flow_prio_cmd,
       "flow-priority <0-65535>",
       "Sets the flow priority\n"
       "Enter the priority value\n")
{
    struct cli_flow_action_parms *fl_parms = vty->index;

    fl_parms->fl_prio = atoi(argv[0]);

    return CMD_SUCCESS;
}

DEFUN (flow_tunnel,
       flow_tunnel_cmd,
       "flow-tunnel X",
       "Sets the flow tunnel-id\n"
       "Enter the flow tunnel value (in Hex)\n")
{
    uint64_t tunnel_id = 0;
    struct cli_flow_action_parms *fl_parms = vty->index;
    struct flow *fl, *mask;

    if (!fl_parms) return CMD_WARNING;
    fl = fl_parms->fl;
    mask = fl_parms->mask;

    tunnel_id = strtoull(argv[0], NULL, 16);
    if ((tunnel_id == (uint64_t)(-1) && errno == ERANGE))  {
        vty_out(vty, "tunnel-id parse fail\r\n");
        return -1;
    }
    fl->tunnel_id = htonll(tunnel_id);
    mask->tunnel_id = (uint64_t)(-1);

    return CMD_SUCCESS;
}

DEFUN (of_add_output_action,
       of_add_output_action_cmd,
       "action-add output (<1-4294967294>|controller|normal)",
       "Add openflow action\n"
       "Output action\n"
       "Enter port-id\n")
{
    uint32_t oport = 0; 
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (!strncmp(argv[0], "controller", strlen("controller"))) {
        oport = 0; /* Send to the controller */
    }
    else if (!strncmp(argv[0], "normal", strlen("normal"))) {
        oport = 0xfffffffa; /* Send to the Normal port */
    } else {
        oport = strtoull(argv[0], NULL, 0);;
    }

    if (mul_app_action_output(mdata, oport) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_queue_action,
       of_add_queue_action_cmd,
       "action-add set-queue <0-4294967295>",
       "Add openflow action\n"
       "Output to a queue\n"
       "Enter queue-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_queue(mdata, atoi(argv[0])) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_vid_action,
       of_add_set_vid_action_cmd,
       "action-add set-vlan-id <0-4094>",
       "Add openflow action\n"
       "set vlanid action\n"
       "Enter vlan-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_vid(mdata, strtoull(argv[0], NULL, 10)) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_strip_vlan_action,
       of_add_strip_vlan_action_cmd,
       "action-add strip-vlan",
       "Add openflow action\n"
       "Strip vlan action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);    

    if (mul_app_action_strip_vlan(mdata) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_vpcp_action,
       of_add_set_vpcp_action_cmd,
       "action-add set-vlan-pcp <0-7>",
       "Add openflow action\n"
       "set vlan-pcp action\n"
       "Enter vlan-pcp\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_vlan_pcp(mdata,
                                    strtoull(argv[0], NULL, 10)) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_dmac_action,
       of_add_set_dmac_action_cmd,
       "action-add set-dmac X",
       "Add openflow action\n"
       "set dmac action\n"
       "Enter MAC address (xx:xx:xx:xx:xx:xx) \n")
{
    mul_act_mdata_t *mdata = NULL;
    uint8_t                      dmac[6];
    char                         *mac_str, *next = NULL;
    int                          i = 0;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);


    mac_str = (void *)argv[0];
    for (i = 0; i < 6; i++) {
        dmac[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if (mul_app_action_set_dmac(mdata, dmac) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_smac_action,
       of_add_set_smac_action_cmd,
       "action-add set-smac X",
       "Add openflow action\n"
       "set smac action\n"
       "Enter MAC address (xx:xx:xx:xx:xx:xx) \n")
{
    mul_act_mdata_t *mdata = NULL;
    uint8_t                      smac[6];
    char                         *mac_str, *next = NULL;
    int                          i = 0;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);


    mac_str = (void *)argv[0];
    for (i = 0; i < 6; i++) {
        smac[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if (mul_app_action_set_smac(mdata, smac) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_eth_type_action,
       of_add_set_eth_type_action_cmd,
       "action-add set-eth-type <1-65535>",
       "Add openflow action\n"
       "set eth-type action\n"
       "Enter ether type\n")
{
    mul_act_mdata_t *mdata = NULL;
    uint16_t eth_type;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    eth_type = atoi(argv[0]);

    if (mul_app_action_set_eth_type(mdata, eth_type) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_push_mpls,
       of_add_push_mpls_cmd,
       "action-add push-mpls-header",
       "Add openflow action\n"
       "push mpls header action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_push_hdr(mdata, ETH_TYPE_MPLS) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_strip_mpls,
       of_add_strip_mpls_cmd,
       "action-add strip-mpls-header <1-65535>",
       "Add openflow action\n"
       "pop mpls header action\n"
       "Enter next ether-type\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_strip_mpls(mdata, atoi(argv[0])) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_mpls_ttl,
       of_add_set_mpls_ttl_cmd,
       "action-add set-mpls-ttl <1-255>",
       "Add openflow action\n"
       "set mpls ttl action\n"
       "Enter TTL value\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_mpls_ttl(mdata, atoi(argv[0])) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_dec_mpls_ttl,
       of_add_dec_mpls_ttl_cmd,
       "action-add dec-mpls-ttl",
       "Add openflow action\n"
       "dec mpls ttl action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_dec_mpls_ttl(mdata) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_mpls_label,
       of_add_set_mpls_label_cmd,
       "action-add set-mpls-label <1-1048575>",
       "Add openflow action\n"
       "set mpls label action\n"
       "Enter label value\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_mpls_label(mdata, atoi(argv[0])) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_mpls_tc,
       of_add_set_mpls_tc_cmd,
       "action-add set-mpls-tc <0-8>",
       "Add openflow action\n"
       "set mpls tc action\n"
       "Enter TC value\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_mpls_tc(mdata, atoi(argv[0])) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_mpls_bos,
       of_add_set_mpls_bos_cmd,
       "action-add set-mpls-bos <0-1>",
       "Add openflow action\n"
       "set mpls bos action\n"
       "Enter BOS value\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_mpls_bos(mdata, atoi(argv[0])) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_strip_pbb,
       of_add_strip_pbb_cmd,
       "action-add strip-pbb-header",
       "Add openflow action\n"
       "pop PBB header action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_strip_pbb(mdata) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_push_vlan,
       of_add_push_vlan_cmd,
       "action-add push-vlan-header",
       "Add openflow action\n"
       "push vlan header action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_push_hdr(mdata, ETH_TYPE_VLAN) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_push_svlan,
       of_add_push_svlan_cmd,
       "action-add push-svlan-header",
       "Add openflow action\n"
       "push svlan header action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_push_hdr(mdata, ETH_TYPE_SVLAN) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_push_pbb,
       of_add_push_pbb_cmd,
       "action-add push-pbb-header",
       "Add openflow action\n"
       "push pbb header action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_push_hdr(mdata, ETH_TYPE_PBB) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_saddr_action,
       of_add_set_nw_saddr_action_cmd,
       "action-add nw-saddr A.B.C.D",
       "Add openflow action\n"
       "set source ip address action\n"
       "Enter ip address\n")
{
    mul_act_mdata_t *mdata = NULL;
    struct in_addr               ip_addr;
    struct flow *fl = NULL;
    struct cli_common_args *args = vty->index;

    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (inet_aton(argv[0], &ip_addr) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(args->flow_act) {
        fl = ((struct cli_flow_action_parms *)args)->fl;
        
        if(fl->dl_type != htons(ETH_TYPE_IP)) {
            vty_out(vty, "ether_type != ETH_TYPE_IP\r\n");
            return CMD_WARNING;
        }
    }

    if (mul_app_action_set_nw_saddr(mdata, ntohl(ip_addr.s_addr)) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_daddr_action,
       of_add_set_nw_daddr_action_cmd,
       "action-add nw-daddr A.B.C.D",
       "Add openflow action\n"
       "set destination ip address action\n"
       "Enter ip address\n")
{
    mul_act_mdata_t *mdata = NULL;
    struct in_addr               ip_addr;
    struct flow *fl = NULL;
    struct cli_common_args *args = vty->index;

    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (inet_aton(argv[0], &ip_addr) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
 
    if(args->flow_act) {
        fl = ((struct cli_flow_action_parms *)args)->fl;
        
        if(fl->dl_type != htons(ETH_TYPE_IP)) {
            vty_out(vty, "ether_type != ETH_TYPE_IP\r\n");
            return CMD_WARNING;
        }
    }

    if (mul_app_action_set_nw_daddr(mdata, ntohl(ip_addr.s_addr)) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_saddr6_action,
       of_add_set_nw_saddr6_action_cmd,
       "action-add nw-saddr6 X:X::X:X",
       "Add openflow action\n"
       "set source ipv6 address action\n"
       "Enter ipv6 address\n")
{
    mul_act_mdata_t *mdata = NULL;
    struct ipv6_addr               addr6;
    struct flow *fl = NULL;
    struct cli_common_args *args = vty->index;

    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (inet_pton(AF_INET6, argv[0], &addr6) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    
    if(args->flow_act) {
        fl = ((struct cli_flow_action_parms *)args)->fl;
        
        if(fl->dl_type != htons(ETH_TYPE_IPV6)) {
            vty_out(vty, "ether_type != ETH_TYPE_IPV6\r\n");
            return CMD_WARNING;
        }
    }

    if (mul_app_action_set_nw_saddr6(mdata,(void *)&addr6) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_daddr6_action,
       of_add_set_nw_daddr6_action_cmd,
       "action-add nw-daddr6 X:X::X:X",
       "Add openflow action\n"
       "set destination ipv6 address action\n"
       "Enter ipv6 address\n")
{
    mul_act_mdata_t *mdata = NULL;
    struct ipv6_addr               addr6;
    struct cli_common_args *args = vty->index;
    struct flow *fl = NULL;

    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (inet_pton(AF_INET6, argv[0], &addr6) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(args->flow_act) {
        fl = ((struct cli_flow_action_parms *)args)->fl;
        
        if(fl->dl_type != htons(ETH_TYPE_IPV6)) {
            vty_out(vty, "ether_type != ETH_TYPE_IPV6\r\n");
            return CMD_WARNING;
        }
    }

    if (mul_app_action_set_nw_daddr6(mdata,(void*)&addr6) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_dscp,
       of_add_set_nw_dscp_cmd,
       "action-add set-nw-dscp <0-63>",
       "Add openflow action\n"
       "set nw dscp action\n"
       "Enter DSCP value\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_nw_tos(mdata, atoi(argv[0])) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_ttl,
       of_add_set_nw_ttl_cmd,
       "action-add set-nw-ttl <1-255>",
       "Add openflow action\n"
       "set nw ttl action\n"
       "Enter TTL value\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_nw_ttl(mdata, atoi(argv[0])) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_dec_nw_ttl,
       of_add_dec_nw_ttl_cmd,
       "action-add dec-nw-ttl",
       "Add openflow action\n"
       "dec nw ttl action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_dec_nw_ttl(mdata) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_cp_ttl_in,
       of_add_cp_ttl_in_cmd,
       "action-add cp-ttl-in",
       "Add openflow action\n"
       "Copy ttl in action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_cp_ttl(mdata, true) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_cp_ttl_out,
       of_add_cp_ttl_out_cmd,
       "action-add cp-ttl-out",
       "Add openflow action\n"
       "Copy ttl out action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_cp_ttl(mdata, false) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_set_group_action,
       of_add_set_group_action_cmd,
       "action-add group-id <0-4294967293>",
       "Add openflow action\n"
       "set group-id action\n"
       "Enter group-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (mul_app_action_set_group(mdata,
                                 strtoull(argv[0], NULL, 10)) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_set_tunnel_id_action,
       of_add_set_tunnel_id_action_cmd,
       "action-add set-tunnel X",
       "Add openflow action\n"
       "Tunnel-id\n"
       "Enter tunnel-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    uint64_t tunnel;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    tunnel = strtoull(argv[0], NULL, 16);
    if ((tunnel == (uint64_t)(-1) && errno == ERANGE))  {
        vty_out(vty, "tunnel-id parse fail\r\n");
        return CMD_WARNING;
    }

    if (mul_app_action_set_tunnel_id(mdata, tunnel) <= 0) {
        vty_out(vty, "Unable to add action\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (of_add_drop_action,
       of_add_drop_action_cmd,
       "action-add drop",
       "Add openflow action\n"
       "drop packet action\n")
{
    struct cli_common_args *__cmn = vty->index;
    if (__cmn->flow_act) {
        struct cli_flow_action_parms *fl_parms = vty->index;
        fl_parms->drop_pkt = true;
    } else {
        struct cli_group_mod_parms *g_parms = vty->index;
        g_parms->bkt_parms[g_parms->act_vec_len].drop_pkt = true;
    }

    return CMD_SUCCESS;
}

DEFUN (flow_commit,
       flow_commit_cmd,
       "commit",
       "commit the flow and its instructions and actions")
{
    struct cli_flow_action_parms *args = vty->index;
    void *actions = NULL;
    size_t action_len = args->mdata ? mul_app_act_len(args->mdata) : 0;

    if (args) {
        if (action_len >= 4 || args->drop_pkt) {
            /* TODO action validation here */

            if (!args->drop_pkt) {
                actions = args->mdata->act_base;
                action_len = mul_app_act_len(args->mdata);
            } else {
                action_len = 0;
                vty_out(vty, "Ignoring all non-drop actions if any%s",
                        VTY_NEWLINE);
            }
            mul_service_send_flow_add(cli->mul_service, args->dpid,
                                  args->fl, args->mask, 
                                  CLI_UNK_BUFFER_ID,
                                  actions, action_len,
                                  0, 0, args->fl_prio, 
                                  args->flags | C_FL_ENT_STATIC);
            if (!(args->flags & C_FL_NO_ACK) &&
                c_service_timed_wait_response(cli->mul_service) > 0) {
                vty_out(vty, "Failed to add a flow. Check log messages%s", 
                        VTY_NEWLINE);
            }
        } else {
            vty_out(vty, "No actions added.Flow not added%s", VTY_NEWLINE);
        }

        if (args->fl) {
            free(args->fl);
        }
        if (args->mask) {
            free(args->mask);
        }
        if (args->mdata) {
            mul_app_act_free(args->mdata);
            free(args->mdata);
        }
        free(args);
        vty->index = NULL;
    }

    vty->node = MUL_NODE;
    return CMD_SUCCESS;
}

DEFUN (flow_actions_exit,
       flow_actions_exit_cmd,
       "exit",
       "Exit from Flow action configuration mode")
{
    struct cli_flow_action_parms *args = vty->index;

    if (args) {
        if (args->fl) free(args->fl);
        if (args->mdata) {
            mul_app_act_free(args->mdata);
            free(args->mdata);
        }
        free(args);
    }

    vty->node = MUL_NODE;
    return CMD_SUCCESS;
}

DEFUN (show_ha_state,
       show_ha_state_cmd,
       "show ha-state",
       SHOW_STR
       "Display HA state\n")
{
    char *ha_str = NULL;

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    if (mul_get_ha_state(cli->mul_service, &cli->sysid, &cli->state,
                &cli->generation_id)) {
        vty_out(vty, "HA state unavailable");
        return CMD_SUCCESS;
    }

    ha_str = mul_ha_state_to_str(cli->sysid, cli->state);

    vty_out(vty, "%s\r\n", ha_str);
    vty_out(vty, "Generation ID: %llu\r\n", U642ULL(cli->generation_id));

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_group,
       show_of_switch_group_cmd,
       "show of-group switch X",
       SHOW_STR
       "Openflow group\n"
       "For a particular switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t dp_id;

    dp_id = strtoull(argv[0], NULL, 16);

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    mul_get_group_info(cli->mul_service, dp_id,
                       false, false, vty, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    return CMD_SUCCESS;
}

struct cmd_node group_node =
{
    GROUP_NODE,
    "(config-grp-act-vectors)# ",
    1,
    NULL,
    NULL
};

DEFUN (group_act_vec_exit,
       group_act_vec_exit_cmd,
       "exit",
       "Exit from group vector actions configuration mode")
{
    struct cli_group_mod_parms *args = vty->index;
    int act;

    if (args) {
        for (act = 0; act < args->act_vec_len; act++) {
            of_mact_free(&args->bkt_parms[act].mdata);
        }
        free(args);
    }

    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
}

DEFUN (group_actions_vectors,
       group_actions_vectors_cmd,
       "group ARGS",
       "group\n"
       "group entries\n")
{
    vty->node = GROUP_NODE;

    return CMD_SUCCESS;
}

DEFUN (group_act_vector_weight,
       group_act_vector_weight_cmd,
       "group-act-vector weight <0-65535>",
       "Group vector attributes\n"
       "Set vector weight\n"
       "Enter weight\n")
{
    struct cli_group_mod_parms *args = vty->index;

    if (args->type != OFPGT_SELECT) {
        vty_out(vty, "Weight only relevant for SELECT groups\r\n");
        return CMD_SUCCESS;
    } 

    args->bkt_parms[args->act_vec_len-1].weight = atoi(argv[0]); 
    return CMD_SUCCESS;
}

DEFUN (group_act_vector_ff_port,
       group_act_vector_ff_port_cmd,
       "group-act-vector ff-port <1-4294967295>",
       "Group vector attributes\n"
       "Set vector fast failover dependent port\n"
       "Enter port\n")
{
    struct cli_group_mod_parms *args = vty->index;

    if (args->type != OFPGT_FF) {
        vty_out(vty, "FF-port only relevant for FF groups\r\n");
        return CMD_SUCCESS;
    }
    args->bkt_parms[args->act_vec_len-1].ff_port = atol(argv[0]);
    return CMD_SUCCESS;
}

DEFUN (group_act_vector_ff_group,
       group_act_vector_ff_group_cmd,
       "group-act-vector ff-group <0-4294967295>",
       "Group vector attributes\n"
       "Set vector fast failover dependent group\n"
       "Enter group\n")
{
    struct cli_group_mod_parms *args = vty->index;

    if (args->type != OFPGT_FF) {
        vty_out(vty, "FF-group only relevant for FF groups\r\n");
        return CMD_SUCCESS;
    }
    args->bkt_parms[args->act_vec_len-1].ff_group = atol(argv[0]);
    return CMD_SUCCESS;
}

DEFUN (group_act_vector_done,
       group_act_vector_done_cmd,
       "group-act-vector-next",
       "Save the current vector and add a new action vector\n")
{
    struct cli_group_mod_parms *args = vty->index;

    if (args->type == OFPGT_INDIRECT) {
        vty_out(vty, "Indirect group supports only one bucket \r\n");
        vty_out(vty, "Proceed to commit-group\r\n");
        return CMD_SUCCESS;
    }

    if (args->act_vec_len + 1 >= OF_MAX_ACT_VECTORS) {
        vty_out(vty, "Cant add more group action vectors\r\n");
        group_act_vec_exit_cmd.func(self, vty, argc, argv);
        return CMD_SUCCESS;
    }

    if (!args->bkt_parms[args->act_vec_len-1].drop_pkt &&
        !of_mact_len(&args->bkt_parms[args->act_vec_len-1].mdata)) {
        vty_out(vty, "No actions added. Try adding again..\r\n");
        return CMD_SUCCESS;
    }

    assert(args->act_vec_len);

    args->act_vec_len++;
    of_mact_alloc(&args->bkt_parms[args->act_vec_len-1].mdata);
    args->bkt_parms[args->act_vec_len-1].mdata.only_acts = true;
    if (mul_app_act_set_ctors(&args->bkt_parms[args->act_vec_len-1].mdata,
                              args->dpid)) {
        vty_out(vty, "Switch 0x%llx doesnt not exist\r\n", U642ULL(args->dpid));
    }

    return CMD_SUCCESS;
}

DEFUN (group_barrier_en,
       group_barrier_en_cmd,
       "group-barrier-enable",
       "Send an accompanying barrier after this group-mod\n")
{
    struct cli_group_mod_parms *args = vty->index;

    args->flags |= C_GRP_BARRIER_EN;
    return CMD_SUCCESS;
}

DEFUN (group_commit,
       group_commit_cmd,
       "commit-group",
       "commit the group and its actions-vectors")
{
    struct cli_group_mod_parms *args = vty->index;
    struct of_group_mod_params g_parms;
    struct of_act_vec_elem *act_elem;
    int act = 0;

    memset(&g_parms, 0, sizeof(g_parms));

    if (args) {

        if (!args->bkt_parms[args->act_vec_len-1].drop_pkt &&
            !of_mact_len(&args->bkt_parms[args->act_vec_len-1].mdata)) {
            vty_out(vty, "No actions added. Try adding again..\r\n");
            return CMD_SUCCESS;
        }

        g_parms.group = args->group;
        g_parms.type = args->type;
        g_parms.flags = C_GRP_STATIC | args->flags;
        for (act = 0; act < args->act_vec_len; act++) {
            bool drop = args->bkt_parms[act].drop_pkt;
            if (drop) {
                of_mact_free(&args->bkt_parms[act].mdata);
            } else {
                act_elem = calloc(1, sizeof(*act_elem));
                act_elem->actions = args->bkt_parms[act].mdata.act_base;
                act_elem->action_len = of_mact_len(&args->bkt_parms[act].mdata);
                act_elem->weight = args->bkt_parms[act].weight;
                act_elem->ff_port = args->bkt_parms[act].ff_port;
                act_elem->ff_group = args->bkt_parms[act].ff_group;
                g_parms.act_vectors[act] = act_elem;
            }
        }
        g_parms.act_vec_len = args->act_vec_len;
        mul_service_send_group_add(cli->mul_service, args->dpid, &g_parms);
        if (c_service_timed_wait_response(cli->mul_service) > 0) {
            vty_out(vty, "Failed to add group. Check log messages%s",
                    VTY_NEWLINE);
        }
        for (act = 0; act < args->act_vec_len; act++) {
            of_mact_free(&args->bkt_parms[act].mdata);
            free(g_parms.act_vectors[act]);
        }
        free(args);
        vty->index = NULL;
    }

    vty->node = MUL_NODE;
    return CMD_SUCCESS;
}

DEFUN_NOSH (of_group_vty_add,
       of_group_vty_add_cmd,
       "of-group add switch X group <0-4294967293> type (all|select|indirect|ff)",
       "OF-group configuration\n"
       "Add\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "openflow-group\n"
       "Enter valid group-id\n"
       "group-type\n"
       "Executes all action buckets \n"
       "Selects one of the buckets \n"
       "Tndirect single bucket\n"
       "Fast failover bucket\n")
{
    uint64_t dpid;
    struct cli_group_mod_parms *cli_parms;
    uint32_t group;
    uint8_t type, version;
    int ret = CMD_WARNING;
    int i = 0;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    dpid = strtoull(argv[0], NULL, 16);
    if (!dpid) {
        vty_out(vty, "No such switch\r\n");
        return CMD_WARNING;
    }

    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131 && version !=  OFP_VERSION_140) {
        vty_out(vty, "Switch 0x%llx does not support groups\r\n", U642ULL(dpid));
        return CMD_WARNING;
    }

    group = atol(argv[1]);

    if (!strncmp(argv[2], "all", strlen(argv[2]))) {
        type = OFPGT_ALL;
    } else if (!strncmp(argv[2], "select", strlen(argv[2]))) {
        type = OFPGT_SELECT;
    } else if (!strncmp(argv[2], "indirect", strlen(argv[2]))) {
        type = OFPGT_INDIRECT;
    } else if (!strncmp(argv[2], "ff", strlen(argv[2]))) {
        type = OFPGT_FF;
    } else {
        vty_out(vty, "Unrecognized group-type (%s)\r\n", argv[2]);
        return CMD_WARNING;
    }

    cli_parms = calloc(1, sizeof(*cli_parms));
    if (!cli_parms) {
        return CMD_WARNING;
    }

    for (i = 0; i < OF_MAX_ACT_VECTORS; i++) {
        struct cli_group_bucket_parms *ofp_b = &cli_parms->bkt_parms[i];

        ofp_b->ff_port = htonl(OFPP131_ANY);
        ofp_b->ff_group = htonl(OFPG_ANY);
    }

    cli_parms->dpid = dpid;
    cli_parms->group = group;
    cli_parms->type = type;
    of_mact_alloc(&cli_parms->bkt_parms[0].mdata);
    cli_parms->bkt_parms[0].mdata.only_acts = true;
    if (mul_app_act_set_ctors(&cli_parms->bkt_parms[0].mdata, dpid)) {
        vty_out(vty, "Switch 0x%llx does not exist\r\n", U642ULL(dpid));
        goto free_err_out;
    }
    cli_parms->act_vec_len = 1;

    vty->index = cli_parms;

    if ((ret = group_actions_vectors_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto free_err_out;
    }

    return CMD_SUCCESS;

free_err_out:
    /* FIXME - Free action vectors */
    free(cli_parms);
    return CMD_WARNING;
}


DEFUN (of_group_vty_del,
       of_group_vty_del_cmd,
       "of-group del switch X group <0-4294967293>",
       "OF-group configuration\n"
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "openflow-group\n"
       "Enter valid group-id\n")
{
    struct of_group_mod_params gp_parms;
    uint64_t dpid;
    uint32_t group;
    uint8_t version;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }
    memset(&gp_parms, 0, sizeof(gp_parms));

    dpid = strtoull(argv[0], NULL, 16);

    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131 && version !=  OFP_VERSION_140) {
        vty_out(vty, "Switch 0x%llx does not support groups\r\n", U642ULL(dpid));
        return CMD_WARNING;
    }


    group = atol(argv[1]);
    gp_parms.group = group;
    gp_parms.flags = C_GRP_STATIC;

    mul_service_send_group_del(cli->mul_service, dpid, &gp_parms);
    if (c_service_timed_wait_response(cli->mul_service) > 0) {
        vty_out(vty, "Failed to del the group. Check log messages%s",
                VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (group_stats_en,
       group_stats_en_cmd,
       "group-stats-enable",
       "Enable stats gathering for this group\n")
{
    struct cli_group_mod_parms *g_parms = vty->index;

    g_parms->flags |= C_GRP_GSTATS;

    return CMD_SUCCESS;
}

DEFUN (meter_act_vec_exit,
       meter_act_vec_exit_cmd,
       "exit",
       "Exit from meter vector actions configuration mode")
{
    struct cli_meter_mod_params *args = vty->index;
    int act;

    if (args) {
        for (act = 0; act < args->act_vec_len; act++) {
            of_mact_free(&args->meter_band_params[act].mdata);
        }
        free(args);
    }

    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
}

struct cmd_node meter_node =
{
    METER_NODE,
    "(config-meter)# ",
    1,
    NULL,
    NULL
};

DEFUN (meter_actions_vectors,
       meter_actions_vectors_cmd,
       "Meter ARGS",
       "Meter\n"
       "Meter entries\n")
{
    vty->node = METER_NODE;

    return CMD_SUCCESS;
}

DEFUN (of_meter_vty_drop,
       of_meter_vty_drop_cmd,
       "meter-band drop rate <1-4294967295> burst-size <0-4294967295>",
       "OF-meter band configuration\n"
       "Drop\n"
       "Rate for dropping packets\n"
       "Enter valid rate\n"
       "Size of Bursts\n"
       "Enter valid burst-size\n")
{
    struct cli_meter_mod_params *args = vty->index;
    struct of_meter_band_parms meter_band_params;   
    mul_act_mdata_t *mdata = NULL;
    
    meter_band_params.rate = atol(argv[0]);
    meter_band_params.burst_size = atol(argv[1]);

    if ((args->type & OFPMF_BURST) && meter_band_params.burst_size == 0) {
        vty_out(vty, "Burst size cant be 0 if Burst flag is set for meter\r\n");
        return CMD_WARNING;
    }
    if (!(args->type & OFPMF_BURST) && meter_band_params.burst_size != 0) {
        vty_out(vty, "Burst size cant be set if Burst flag is not set for meter\r\n");
        return CMD_WARNING;
    }
    
    mdata = &args->meter_band_params[args->act_vec_len - 1].mdata;
    args->meter_band_params[args->act_vec_len - 1].action_added = true;

    mul_app_set_band_drop(mdata,&meter_band_params);

    return CMD_SUCCESS;

}

DEFUN (of_meter_vty_dscp_remark,
       of_meter_vty_dscp_remark_cmd,
       "meter-band dscp-remark rate <1-4294967295> burst-size <0-4294967295> prec-level <0-7>",
       "OF-meter band configuration\n"
       "Drop\n"
       "Rate for dropping packets\n"
       "Enter valid rate\n"
       "Size of Bursts\n"
       "Enter valid burst-size\n"
       "IP precedence in IP header\n"
       "Enter valid IP precedence\n")
{
    struct cli_meter_mod_params *args = vty->index;
    struct of_meter_band_parms meter_band_params;   
    mul_act_mdata_t *mdata = NULL;

    meter_band_params.rate = atol(argv[0]);
    meter_band_params.burst_size = atol(argv[1]);
    if ((args->type & OFPMF_BURST) && meter_band_params.burst_size == 0) {
        vty_out(vty, "Burst size cant be 0 if Burst flag is set for meter\r\n");
        return CMD_WARNING;
    }
    if (!(args->type & OFPMF_BURST) && meter_band_params.burst_size != 0) {
        vty_out(vty, "Burst size cant be set if Burst flag is not set for meter\r\n");
        return CMD_WARNING;
    }
    mdata = &args->meter_band_params[args->act_vec_len - 1].mdata;
    args->meter_band_params[args->act_vec_len - 1].action_added = true;
    meter_band_params.prec_level = atoi(argv[2]);
    mul_app_set_band_dscp(mdata, &meter_band_params);

    return CMD_SUCCESS;
}

DEFUN (meter_band_done,
       meter_band_done_cmd,
       "meter-band-next",
       "Save the current band and add a new band\n")
{
    struct cli_meter_mod_params *args = vty->index;

    if (args->act_vec_len + 1 >= OF_MAX_ACT_VECTORS) {
        vty_out(vty, "Cant add more meter bands\r\n");
        meter_act_vec_exit_cmd.func(self, vty, argc, argv);
        return CMD_WARNING;
    }

    if (!of_mact_len(&args->meter_band_params[args->act_vec_len-1].mdata)) {
        vty_out(vty, "No band added. Try adding again..\r\n");
        return CMD_WARNING;
    }

    assert(args->act_vec_len);

    args->act_vec_len++;
    of_mact_alloc(&args->meter_band_params[args->act_vec_len-1].mdata);
    args->meter_band_params[args->act_vec_len-1].mdata.only_acts = true;
    if (mul_app_act_set_ctors(&args->meter_band_params[args->act_vec_len-1].mdata,
                              args->dpid)) {
        vty_out(vty, "Switch 0x%llx doesnt not exist\r\n", U642ULL(args->dpid));
    }

    return CMD_SUCCESS;
}

DEFUN (meter_barrier_en,
       meter_barrier_en_cmd,
       "meter-barrier-enable",
       "Send an accompanying barrier after this meter-mod\n")
{
    struct cli_meter_mod_params *args = vty->index;

    args->cflags |= C_METER_BARRIER_EN;
    return CMD_SUCCESS;
}

DEFUN (meter_commit,
       meter_commit_cmd,
       "commit-meter",
       "commit the Meter and its bands")
{
    struct cli_meter_mod_params *args = vty->index;
    struct of_meter_mod_params m_parms;
    struct of_meter_band_elem *band_elem;
    int act = 0;

    if (!of_mact_len(&args->meter_band_params[args->act_vec_len-1].mdata)) {
        vty_out(vty, "No band added. Try adding again..\r\n");
        return CMD_WARNING;
    }

    memset(&m_parms, 0, sizeof(m_parms));

    m_parms.meter = args->meter_id;
    m_parms.flags = args->type; /*Meter type*/
    m_parms.cflags = C_METER_STATIC | args->cflags; /* Controller's Flag*/
    if (args->type & OFPMF_STATS) {
        m_parms.cflags |= C_METER_GSTATS;
    }

    for (act = 0; act < args->act_vec_len; act++) {
        band_elem = calloc(1, sizeof(*band_elem));
        band_elem->band = args->meter_band_params[act].mdata.act_base;
        band_elem->band_len = of_mact_len(&args->meter_band_params[act].mdata);
        m_parms.meter_bands[act] = band_elem;
    }
    m_parms.meter_nbands = args->act_vec_len;
    mul_service_send_meter_add(cli->mul_service, args->dpid, &m_parms);
    if (c_service_timed_wait_response(cli->mul_service) > 0) {
        vty_out(vty, "Failed to add meter. Check log messages%s",
                VTY_NEWLINE);
    }

    for (act = 0; act < args->act_vec_len; act++) {
        of_mact_free(&args->meter_band_params[act].mdata);
        free(m_parms.meter_bands[act]);
    }

    free(args);
    vty->index = NULL;

    vty->node = MUL_NODE;
    return CMD_SUCCESS;
}

DEFUN (of_meter_vty_delete,
       of_meter_vty_delete_cmd,
       "of-meter delete switch X meter-id <0-4294967295>",
       "OF-meter configuration\n"
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "openflow-meter\n"
       "Enter valid meter-id\n")
{
    struct of_meter_mod_params m_parms;
    uint64_t dpid;
    uint32_t meter;
    uint8_t version;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }
    memset(&m_parms, 0, sizeof(m_parms));

    dpid = strtoull(argv[0], NULL, 16);

    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        vty_out(vty, "Switch 0x%llx does not support meter\r\n", U642ULL(dpid));
        return CMD_WARNING;
    }

    meter = atol(argv[1]);
    m_parms.meter = meter;
    m_parms.cflags = C_METER_STATIC;

    mul_service_send_meter_del(cli->mul_service, dpid, &m_parms);
    if (c_service_timed_wait_response(cli->mul_service) > 0) {
        vty_out(vty, "Failed to del the meter. Check log messages%s",
                VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN_NOSH (of_meter_vty_add,
       of_meter_vty_add_cmd,
       "of-meter add switch X meter-id <0-4294967295> meter-type (kbps|pktps) burst (yes|no) stats (yes|no)",
       "OF-meter configuration\n"
       "Add\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "openflow-meter\n"
       "Enter valid meter-id\n"
       "Meter-type\n"
       "Rate value in kb/s (kilo-bit per second).\n"
       "Rate value in packet/sec.\n"
       "Do burst size.\n"
       "Set burst flag\n"
       "Unset burst flag\n"
       "Collect statistics\n"
       "Set stats flag\n"
       "Unset stats flag\n")
{
    uint64_t dpid;
    struct cli_meter_mod_params *cli_parms;
    uint32_t meter_id;
    uint16_t type;
    uint8_t  version;
    int ret = CMD_WARNING;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    dpid = strtoull(argv[0], NULL, 16);
    if (!dpid) {
        vty_out(vty, "No such switch\r\n");
        return CMD_WARNING;
    }

    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        vty_out(vty, "Switch 0x%llx version %u does not support meter\r\n",
                U642ULL(dpid), version);
        return CMD_WARNING;
    }

    meter_id = atol(argv[1]);

    if (!strncmp(argv[2], "kbps", strlen(argv[2]))) {
        type = OFPMF_KBPS;
    } else if (!strncmp(argv[2], "pktps", strlen(argv[2]))) {
        type = OFPMF_PKTPS;
    } else {
        NOT_REACHED();
    }

    if (!strncmp(argv[3], "yes", strlen(argv[3]))) {
        type |= OFPMF_BURST;
    }
    
    if (!strncmp(argv[4], "yes", strlen(argv[4]))) {
        type |= OFPMF_STATS;
    }

    cli_parms = calloc(1, sizeof(*cli_parms));
    if (!cli_parms) {
        return CMD_WARNING;
    }

    cli_parms->dpid = dpid;
    cli_parms->meter_id = meter_id;
    cli_parms->type = type;
    of_mact_alloc(&cli_parms->meter_band_params[0].mdata);
    cli_parms->meter_band_params[0].mdata.only_acts = true;
    if (mul_app_act_set_ctors(&cli_parms->meter_band_params[0].mdata, dpid)) {
        vty_out(vty, "Switch 0x%llx does not exist\r\n", U642ULL(dpid));
        goto free_err_out;
    }
    cli_parms->act_vec_len = 1;

    vty->index = cli_parms;

    if ((ret = meter_actions_vectors_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto free_err_out;
    }

    return CMD_SUCCESS;

free_err_out:
    /* FIXME - Free action vectors */
    free(cli_parms);
    return CMD_WARNING;
}

DEFUN (of_meter_vty_show,
       of_meter_vty_show_cmd,
       "show of-meter switch X",
       SHOW_STR
       "Meter details\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t dpid;

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    dpid = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    
    mul_get_meter_info(cli->mul_service, dpid,
                       false, false, vty, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (show_neigh_switch_detail,
       show_neigh_switch_detail_cmd,
       "show neigh switch X detail",
       SHOW_STR
       "Switch Neighbour Detail\n"
       "Detailed information for the switch")
{
    uint64_t dpid;
    struct cbuf *b;
    char *pbuf = NULL;

    if (cli_init_tr_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    dpid = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    vty_out (vty,"%12s | %10s | %10s | %s%s","port #","status","neighbor #",
             "neighbor port #",VTY_NEWLINE);
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    b = mul_neigh_get(cli->tr_service, dpid);
    if (b) {
        pbuf = mul_dump_neigh(b, true);
        if (pbuf) {
            vty_out(vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);


    return CMD_SUCCESS;
}

DEFUN (tr_loop_en,
       tr_loop_en_cmd,
       "set loop-detect (enable|disable)",
       SET_STR
       "Loop Detection\n"
       "Enable the feature\n"
       "Dosable the feature")
{
    int ret = 0;
    bool enable;

    if (cli_init_tr_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    if (!strncmp(argv[0], "enable", strlen("enable")))
        enable = true;
    else
        enable = false;

    ret = mul_set_loop_detect(cli->mul_service, enable);
    if (!ret) {
        ret = mul_set_tr_loop_detect(cli->tr_service, enable);
        if (ret) {
            mul_set_loop_detect(cli->mul_service, false);
            c_log_err("Failed to set loop detect state");
        }
    }

    return CMD_SUCCESS;
}

DEFUN (of_port_vty_mod,
       of_port_vty_mod_cmd,
       "of-port mod switch X port-no <0-4294967295> port-down"
       " (set|unset|no-change) no-stp (set|unset|no-change) no-recv"
       " (set|unset|no-change) no-recv-stp (set|unset|no-change) no-flood"
       " (set|unset|no-change) no-fwd (set|unset|no-change) no-packet-in"
       " (set|unset|no-change)",
       "OF-port configuration\n"
       "Modification\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "Port number\n"
       "Enter valid port number\n"
       "Bit to set/unset port-down\n"
       "To set the bit\n"
       "To unset the bit\n"
       "No change\n"
       "Bit to set/unset no-stp\n"
       "To set the bit\n"
       "To unset the bit\n"
       "No change\n"
       "Bit to set/unset no-rcv\n"
       "To set the bit\n"
       "To unset the bit\n"
       "No change\n"
       "Bit to set/unset no-rcv-stp\n"
       "To set the bit\n"
       "To unset the bit\n"
       "No change\n"
       "Bit to set/unset no-flood\n"
       "To set the bit\n"
       "To unset the bit\n"
       "No change\n"
       "Bit to set/unset no-fwd\n"
       "To set the bit\n"
       "To unset the bit\n"
       "No change\n"
       "Bit to set/unset no-packet-in\n"
       "To set the bit\n"
       "To unset the bit\n"
       "No change\n")
{
    struct of_port_mod_params pm_params;
    uint64_t dpid = 0; 
    uint32_t port_no = 0;
    uint32_t config = 0;
    uint32_t mask = 0;
    uint8_t  version= 0;

    if (!cli_ha_config_cap(cli, vty, false)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    dpid = strtoull(argv[0], NULL, 16);
    if (!dpid) {
        vty_out(vty, "No such switch\r\n");
        return CMD_WARNING;
    }


    port_no = atol(argv[1]);

    if (!strncmp(argv[2], "set", strlen(argv[2]))) {
        config |= OFPPC_PORT_DOWN;
        mask |= OFPPC_PORT_DOWN;
    } else if (!strncmp(argv[2], "unset", strlen(argv[2]))) {
        mask |= OFPPC_PORT_DOWN;
    } 

    if (!strncmp(argv[3], "set", strlen(argv[3]))) {
        config |= OFPPC_NO_STP;
        mask |= OFPPC_NO_STP;
    } else if (!strncmp(argv[3], "unset", strlen(argv[3]))) {
        mask |= OFPPC_NO_STP;
    } 

    if (!strncmp(argv[4], "set", strlen(argv[4]))) {
        config |= OFPPC_NO_RECV;
        mask |= OFPPC_NO_RECV;
    } else if (!strncmp(argv[4], "unset", strlen(argv[4]))) {
        mask |= OFPPC_NO_RECV;
    } 

    if (!strncmp(argv[5], "set", strlen(argv[5]))) {
        config |= OFPPC_NO_RECV_STP;
        mask |= OFPPC_NO_RECV_STP;
    } else if (!strncmp(argv[5], "unset", strlen(argv[5]))) {
        mask |= OFPPC_NO_RECV_STP;
    } 

    if (!strncmp(argv[6], "set", strlen(argv[6]))) {
        config |= OFPPC_NO_FLOOD;
        mask |= OFPPC_NO_FLOOD;
    } else if (!strncmp(argv[6], "unset", strlen(argv[6]))) {
        mask |= OFPPC_NO_FLOOD;
    } 

    if (!strncmp(argv[7], "set", strlen(argv[7]))) {
        config |= OFPPC_NO_FWD;
        mask |= OFPPC_NO_FWD;
    } else if (!strncmp(argv[7], "unset", strlen(argv[7]))) {
        mask |= OFPPC_NO_FWD;
    } 

    if (!strncmp(argv[8], "set", strlen(argv[8]))) {
        config |= OFPPC_NO_PACKET_IN;
        mask |= OFPPC_NO_PACKET_IN;
    } else if (!strncmp(argv[8], "unset", strlen(argv[8]))) {
        mask |= OFPPC_NO_PACKET_IN;
    } 

    version = c_app_switch_get_version_with_id(dpid);
    if (version ==  OFP_VERSION_131 || version == OFP_VERSION_140) {
        if (config & (OFPPC_NO_STP | OFPPC_NO_RECV_STP | OFPPC_NO_FLOOD )) {
            vty_out(vty, "OpenFlow 1.3 and above doesnot support OFPPC_NO_STP,"
                    " OFPPC_NO_RECV_STP, OFPPC_NO_FLOOD\r\n");
            vty_out(vty, "Reverting these flags..\r\n");
            config &= ~(OFPPC_NO_STP | OFPPC_NO_RECV_STP | OFPPC_NO_FLOOD);
            mask &= ~(OFPPC_NO_STP | OFPPC_NO_RECV_STP | OFPPC_NO_FLOOD);
        }
    }
    memset(&pm_params,0,sizeof(pm_params));
    pm_params.port_no = port_no;
    pm_params.config = config;
    pm_params.mask = mask;

    mul_service_send_port_mod(cli->mul_service, dpid, &pm_params);
    if (c_service_timed_wait_response(cli->mul_service) > 0) {
            vty_out(vty, "Failed to add meter. Check log messages%s",
                            VTY_NEWLINE);
    }

    vty_out (vty,"port %u config %x mask %x \r\n", port_no, config, mask); 
    return CMD_SUCCESS;

}

static int
__add_fab_host_cmd(struct vty *vty, const char **argv, bool is_gw)
{
    uuid_t tenant_id;
    uuid_t network_id;
    uint64_t dpid;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int  i = 0, ret = 0;

    memset(&fl, 0, sizeof(fl));

    ret = uuid_parse(argv[0], tenant_id);
    if(ret == -1) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Malformed TenantID");
    }

	ret = uuid_parse(argv[1], network_id);
    if(ret == -1) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Malformed NetworkID");
    }


    dpid = strtoull(argv[4], NULL, 16);
    fl.in_port= htonl(atoi(argv[5]));

    ret = str2prefix(argv[2], (void *)&host_ip);
    if (ret <= 0) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Malformed address");
    }

    fl.ip.nw_src = host_ip.prefix.s_addr;
    fl.FL_DFL_GW = is_gw;

    mac_str = (void *)argv[3];
    for (i = 0; i < 6; i++) {
        fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        return return_vty(vty, 0, 
                          CMD_WARNING, "Malformed address");
    }

    if (mul_fabric_host_mod(cli->fab_service, dpid, &fl, tenant_id,
                network_id, true)) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Host add failed");
    }

    return return_vty(vty, 0,
                      CMD_SUCCESS, NULL);

}

DEFUN (add_fab_host_nongw,
       add_fab_host_nongw_cmd,
        "add fabric-host tenant (String) network (String) "
        "host-ip A.B.C.D host-mac X "
        "switch X port <0-65535> non-gw",
        "Add a configuration\n"
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n"
        "Switch directly connected to\n"
        "Enter dpid\n"
        "Connected Port on switch\n"
        "Enter port-number\n"
        "This host is non gateway\n")
{
    return __add_fab_host_cmd(vty, argv, false);
}

DEFUN (add_fab_host_gw,
       add_fab_host_gw_cmd,
        "add fabric-host tenant (String) network (String) "
        "host-ip A.B.C.D host-mac X "
        "switch X port <0-65535> gw",
        "Add a configuration\n"
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n"
        "Switch directly connected to\n"
        "Enter dpid\n"
        "Connected Port on switch\n"
        "Enter port-number\n"
        "This host is non gateway\n")
{
    return __add_fab_host_cmd(vty, argv, true);
}


DEFUN (del_fab_host,
       del_fab_host_cmd,
        "del fabric-host tenant (String) network (String) "
        "host-ip A.B.C.D host-mac X",
        "Del a configuration\n"
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n")
{
    uuid_t tenant_id;
    uuid_t network_id;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int  i = 0, ret = 0;

    memset(&fl, 0, sizeof(fl));
    ret = uuid_parse(argv[0], tenant_id);
    if(ret == -1) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Malformed TenantID");
    }

	ret = uuid_parse(argv[1], network_id);
    if(ret == -1) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Malformed NetworkID");
    }

    ret = str2prefix(argv[2], (void *)&host_ip);
    if (ret <= 0) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Malformed address");
    }

    fl.ip.nw_src = host_ip.prefix.s_addr;
    mac_str = (void *)argv[3];
    for (i = 0; i < 6; i++) {
        fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Malformed mac address");
    }

    if (mul_fabric_host_mod(cli->fab_service, 0, &fl, tenant_id, 
                network_id, false)) {
        return return_vty(vty, 0,
                          CMD_WARNING, "Host delete failed");
    }

    return return_vty(vty, 0,
                      CMD_SUCCESS, NULL);
}

DEFUN (show_fab_host_all_active,
       show_fab_host_all_active_cmd,
       "show fabric-hosts all-active",
       SHOW_STR
       "Fabric connected host\n"
       "All active hosts\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_fab_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_fabric_show_hosts(cli->fab_service, true, false, false,
                          (void *)vty, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_fab_host_all_inactive,
       show_fab_host_all_inactive_cmd,
        "show fabric-hosts all-inactive",
        SHOW_STR
        "Fabric connected host\n"
        "All inactive hosts\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_fab_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_fabric_show_hosts(cli->fab_service, false, false, false,
                          (void *)vty, vty_dump);


    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_fab_port_tnid_all,
       show_fab_port_tnid_all_cmd,
       "show fabric-port-tnid all",
       SHOW_STR
       "Fabric registered port-tnid\n"
       "All active hosts\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_fab_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_fabric_port_tnid_show(cli->fab_service, true,
                          (void *)vty, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}
static int
__add_del_fab_port_tnid_cmd(struct vty *vty, const char **argv, bool add)
{
    uuid_t tenant_id, network_id;
    uint64_t dpid;
    int32_t port;
    int ret = 0;

    ret = uuid_parse(argv[0], tenant_id);
    if(ret == -1){
        return return_vty(vty, 0, CMD_WARNING, "Malformed TenantID");
    }

    ret = uuid_parse(argv[1], network_id);
    if(ret == -1){
        return return_vty(vty, 0, CMD_WARNING, "Malformed NetworkID");
    }
   
    dpid = strtoull(argv[2], NULL, 16);

    port = atoi(argv[3]);

    if(mul_fabric_port_tnid_mod(cli->fab_service, dpid, port, tenant_id, network_id, add)){
        return return_vty(vty, 0, CMD_WARNING, "Port_tnid add failed");
    }
    return return_vty(vty, 0, CMD_SUCCESS, NULL);
}
DEFUN (add_fab_port_tnid,
       add_fab_port_tnid_cmd,
        "add fabric-host tenant (String) network (String) "
        "switch X port <0-65535>",
        "Add a configuration\n"
        "Fabric registered port-tnid\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Switch directly connected to\n"
        "Enter dpid\n"
        "Connected Port on switch\n"
        "Enter port-number\n")
{
    return __add_del_fab_port_tnid_cmd(vty, argv, true);    
}

DEFUN (del_fab_port_tnid,
       del_fab_port_tnid_cmd,
        "del fabric-host tenant (String) network (String) "
        "switch X port <0-65535>",
        "Add a configuration\n"
        "Fabric registered port-tnid\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Switch directly connected to\n"
        "Enter dpid\n"
        "Connected Port on switch\n"
        "Enter port-number\n")
{
    return __add_del_fab_port_tnid_cmd(vty, argv, false);
}


static void
vty_src_host_dump(void *vty_arg, char *pbuf)
{
    struct vty *vty = vty_arg;
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);


    vty_out(vty, "%10s:", "Source" );
    vty_dump(vty, pbuf);
}

static void
vty_dst_host_dump(void *vty_arg, char *pbuf)
{
    struct vty *vty = vty_arg;
    vty_out(vty, "%10s:", "Dest" );
    vty_dump(vty, pbuf);
}

static void
vty_route_dump(void *vty_arg, char *pbuf)
{
    struct vty *vty = vty_arg;

    vty_out(vty, "%10s:", "Route" );
    vty_dump(vty, pbuf);
    vty_out(vty, "|||%s", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

}

DEFUN (show_fab_route_all,
       show_fab_route_all_cmd,
       "show fabric-route all",
       SHOW_STR
       "Dump all routes\n")
{

    if (cli_init_fab_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_fabric_show_routes(cli->fab_service, vty, false, vty_src_host_dump,
                           vty_dst_host_dump, vty_route_dump);


    return CMD_SUCCESS;
}

#ifdef CLI_MAKDI

DEFUN (add_makdi_nfv_group,
       add_makdi_nfv_group_cmd,
        "add makdi-nfv-group X ",
        "Add a nfv-group configuration\n"
        "makdi nfv-group service\n"
        "Enter nfv-group name (String)")
{
    int ret;
    char *group_name;

    group_name = (char *)argv[0];
    
    if (cli_init_makdi_service(cli, vty)) {
        return CMD_SUCCESS;
    }
    
    ret = mul_makdi_group_mod(cli->makdi_service, group_name, true);
    return ret;
}

DEFUN (del_makdi_nfv_group,
       del_makdi_nfv_group_cmd,
       "del makdi-nfv-group X ",
       "Del a nfv-group configuration\n"
       "makdi nfv-group service\n"
       "Enter nfv group name (String)")
{
    int ret;
    char *group_name;

    group_name = (char *)argv[0];

    ret = mul_makdi_group_mod(cli->makdi_service, group_name, false);
    return ret;
}

DEFUN (add_makdi_nfv,
       add_makdi_nfv_cmd,
       "add makdi-nfv group X nfv X switch X in-port <1-65535> out-port <1-65535>",
       "Add\n"
       "Add a makdi-nfv attach point\n"
       "NFV group\n"
       "Enter nfv group name\n"
       "NFV on the group\n"
       "Enter nfv name\n"
       "DP information\n"
       "Enter dp-id\n"
       "in-port\n"
       "Enter in port-number\n"
       "out-port\n"
       "Enter out port-number\n")
{
    int ret;
    char *group_name;
    char *nfv_name;

    uint16_t in_port = atoi(argv[3]);
    uint16_t out_port = atoi(argv[4]);
    uint64_t dpid = strtoull(argv[2], NULL, 16);

    group_name = (char *)argv[0];
    nfv_name = (char *)argv[1];

    ret = mul_makdi_nfv_mod(cli->makdi_service, dpid, group_name,
                            in_port, out_port, nfv_name, TRUE);
    return ret;
}

DEFUN (del_makdi_nfv,
       del_makdi_nfv_cmd,
       "del makdi-nfv group X nfv X switch X in-port <1-65535> out-port <1-65535>",
       "Del\n"
       "Del a makdi-nfv attach point\n"
       "NFV group\n"
       "Enter nfv group name\n"
       "NFV on the group\n"
       "Enter nfv name\n"
       "DP information\n"
       "Enter dp-id\n"
       "in-port\n"
       "Enter in port-number\n"
       "out-port\n"
       "Enter out port-number\n")
{
    int ret;
    char *group_name;
    char *nfv_name;

    uint16_t in_port = atoi(argv[3]);
    uint16_t out_port = atoi(argv[4]);
    uint64_t dpid = strtoull(argv[2], NULL, 16);

    group_name = (char *)argv[0];
    nfv_name = (char *)argv[1];

    ret = mul_makdi_nfv_mod(cli->makdi_service, dpid, group_name, in_port,
                            out_port, nfv_name, false);
    return ret;
}

DEFUN (show_makdi_nfv,
       show_makdi_nfv_cmd,
       "show makdi-nfv-group all",
       SHOW_STR
       "NFV informations\n"
       "Summary information for all nfv")
{
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_makdi_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_makdi_show_nfv(cli->makdi_service, (void *)vty, false, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (add_makdi_service,
       add_makdi_service_cmd,
       "add makdi-service X vlan <0-4096>",
       "Add a service configuration\n"
       "makdi service\n"
       "Enter service name\n"
       "makdi service vlan number\n"
       "Enter vlan number")
{
    int ret;
    char *service_name;
    uint16_t vlan = atoi(argv[1]);

    service_name = (char *)argv[0];

    ret = mul_makdi_service_mod(cli->makdi_service, service_name, vlan, TRUE);
    return ret;
}

DEFUN (del_makdi_service,
       del_makdi_service_cmd,
        "del makdi-service X vlan <0-4096>",
        "Del a service configuration\n"
        "makdi service\n"
        "Enter service name\n"
        "makdi service vlan number\n"
        "Enter vlan number")
{
    int ret;
    char *service_name;
    uint16_t vlan = atoi(argv[1]);

    service_name = (char *)argv[0];

    ret = mul_makdi_service_mod(cli->makdi_service, service_name, vlan, false);
    return ret;
}

DEFUN (show_makdi_service,
       show_makdi_service_cmd,
       "show makdi-service all",
       SHOW_STR
       "Service informations\n"
       "Summary information for all service")
{
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_makdi_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_makdi_show_service(cli->makdi_service, (void *)vty, false, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (add_makdi_nfv_sc_rule,
       add_makdi_nfv_sc_rule_cmd,
       "add makdi-service-chain switch X service X host-ip A.B.C.D "
       "nfv-grp1 (X|*) nfv-grp2 (X|*) nfv-grp3 (X|*) nfv-grp4 (X|*)"
       " nfv-grp5 (X|*) nfv-grp6 (X|*)",
       "Add makdi-service-chain\n"
       "makdi service chain configuration\n"
       "Switch info\n"
       "Enter dp-id\n"
       "Service info\n"
       "Enter service name\n"
       "Host info\n"
       "Enter Host IP address\n"
       "NFV List or (None)\n"
       "Enter NFV group\n"
       "* for none\n"
       "NFV List or (None)\n"
       "Enter NFV group\n"
       "* for none\n"
       "NFV List or (None)\n"
       "Enter NFV group\n"
       "* for none\n"
       "NFV List or (None)\n"
       "Enter NFV group\n"
       "* for none")
{
    int ret;
    uint32_t nw_src;
    uint32_t vlan = atoi(argv[3]);
    struct prefix_ipv4 host_ip;
    uint64_t dpid = strtoull(argv[0], NULL, 16);
    int i = 3;
    char **nfv_list;
    char *service;
    int num_nfv = 0;

    nfv_list = (char **)calloc(4, sizeof(char *));

    ret = str2prefix(argv[2], (void *)&host_ip);
    if (ret <= 0) {
        return CMD_WARNING;
    }

    nw_src = ntohl(host_ip.prefix.s_addr);

    for (; i < 9; i++) {
        if (!strncmp(argv[i], "none", MAX_NFV_NAME - 1) ||
            !strncmp(argv[i], "None", MAX_NFV_NAME - 1) ||
            !strncmp(argv[i], "*", MAX_NFV_NAME - 1)) {
            continue;
        }
        nfv_list[num_nfv++] = (char *)argv[i];
    }
    service = (void *)argv[1];

    ret = mul_makdi_servicechain_mod(cli->makdi_service, dpid, 
                        vlan, service, nw_src, num_nfv, nfv_list, TRUE);
    return ret;
}

DEFUN (del_makdi_nfv_sc_rule,
       del_makdi_nfv_sc_rule_cmd,
       "del makdi-service-chain switch X service X host-ip A.B.C.D",
       "Del makdi-service-chain\n"
       "makdi service chain configuration\n"
       "Switch info\n"
       "Enter dp-id\n"
       "Service info\n"
       "Enter service name\n"
       "Host info\n"
       "Enter Host IP address")
{
    int ret;
    uint32_t nw_src;
    struct prefix_ipv4 host_ip;
    uint64_t dpid = strtoull(argv[0], NULL, 16);
    char *service;

    ret = str2prefix(argv[2], (void *)&host_ip);
    if (ret <= 0) {
        return CMD_WARNING;
    }

    nw_src = ntohl(host_ip.prefix.s_addr);
    service = (void *)argv[1];

    ret = mul_makdi_servicechain_mod(cli->makdi_service, dpid, 
                                     0, service, nw_src, 0, NULL, false);
    return ret;
}

DEFUN (show_makdi_nfv_stats,
       show_makdi_nfv_stats_cmd,
       "show makdi-nfv-stats all",
       SHOW_STR
       "NFV Statistics informations\n"
       "Statistics information for all nfv group")
{
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_makdi_service(cli, vty)) {
        return CMD_SUCCESS;
    }
    
    mul_makdi_show_nfv_stats_all(cli->makdi_service,(void *)vty, false, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_makdi_service_stats,
       show_makdi_service_stats_cmd,
       "show makdi-service-stats all",
       SHOW_STR
       "NFV Service Statistics informations\n"
       "Statistics information for all service")
{
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_makdi_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_makdi_show_service_stats_all(cli->makdi_service,(void *)vty, false, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_makdi_user_stats,
       show_makdi_user_stats_cmd,
       "show makdi-user-stats all",
       SHOW_STR
       "User Statistics informations\n"
       "Summary information for all user")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_makdi_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_makdi_show_user_stats_all(cli->makdi_service,(void *)vty, false, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_makdi_service_chain,
       show_makdi_service_chain_cmd,
       "show makdi-service-chain all",
       SHOW_STR
       "Service Chain\n"
       "Summary information for all")

{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_makdi_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_makdi_show_service_chain(cli->makdi_service,(void *)vty, false, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}
#endif

DEFUN_HIDDEN (set_async_config,
              set_async_config_cmd,
              "set-async-config switch X master packet-in X \
              port-status X flow-removed X slave packet-in X \
              port-status X flow-removed X",
              "Set Asynchronous Message Configuration\n"
              "openflow-switch\n"
              "datapath-id in 0xXXX format\n"
              "Set Configuration for MASTER_STATE Controller\n"
              "Packet-in Mask\n"
              "Enter the mask in 0xXXX format - Bit 0: NO-MATCH, Bit"
              "1: ACTION, Bit 2: INVALID\n"
              "Port-Status Mask\n"
              "Enter the mask in 0xXXX format - Bit 0: ADD, Bit1: DELETE," 
              "Bit 2: MODIFY\n"
              "Flow Removed Mask\n"
              "Enter the mask in 0xXXX format - Bit 0: IDLE_TIMEOUT, Bit1: "
              "HARD_TIMEOUT, Bit 2: DELETE, Bit 3: GROUP_DELETE\n"
              "Set Configuration for SLAVE_STATE Controller\n"
              "Packet-in Mask\n"
              "Enter the mask in 0xXXX format - Bit 0: NO-MATCH, Bit "
              "1: ACTION, Bit 2: INVALID\n"
              "Port-Status Mask\n"
              "Enter the mask in 0xXXX format - Bit 0: ADD, Bit1: DELETE, "
              "Bit 2: MODIFY\n"
              "Flow Removed Mask\n"
              "Enter the mask in 0xXXX format - Bit 0: IDLE_TIMEOUT, Bit1: "
              "HARD_TIMEOUT, Bit 2: DELETE, Bit 3: GROUP_DELETE\n")

{
    struct of_async_config_params *args = NULL;
    uint64_t dpid = 0;
    uint8_t version = 0;

    dpid = strtoull(argv[0], NULL, 16);

    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131) {
        vty_out(vty, "Switch 0x%llx does not support async-config, version\
                %d\r\n", U642ULL(dpid),version);
        return CMD_WARNING;
    }
    
    args = calloc(1, sizeof(*args));
    if (!args) {
        return CMD_WARNING;
    }

    /*MASTER_STATE Details*/
    args->packet_in_mask[MASTER_STATE] = strtoul(argv[1], NULL, 16);
    if(args->packet_in_mask[MASTER_STATE] > 7) {
        vty_out(vty, "Packet-In Mask greater than 0x7 is not allowed\r\n");
        return CMD_WARNING;
    }

    args->port_status_mask[MASTER_STATE] = strtoul(argv[2], NULL, 16);
    if(args->port_status_mask[MASTER_STATE] > 7) {
        vty_out(vty, "Port-Status Mask greater than 0x7 is not allowed\r\n");
        return CMD_WARNING;
    }
    args->flow_removed_mask[MASTER_STATE] = strtoul(argv[3], NULL, 16);
    if(args->flow_removed_mask[MASTER_STATE] > 15) {
        vty_out(vty, "Flow-Removed Mask greater than 0x7 is not allowed\r\n");
        return CMD_WARNING;
    }

    /*SLAVE_STATE Details*/
    args->packet_in_mask[SLAVE_STATE] = strtoul(argv[4], NULL, 16);
    if(args->packet_in_mask[SLAVE_STATE] > 7) {
        vty_out(vty, "Packet-In Mask greater than 0x7 is not allowed\r\n");
        return CMD_WARNING;
    }
    args->port_status_mask[SLAVE_STATE] = strtoul(argv[5], NULL, 16);
    if(args->port_status_mask[SLAVE_STATE] > 7) {
        vty_out(vty, "Port-Status Mask greater than 0x7 is not allowed\r\n");
        return CMD_WARNING;
    }
    args->flow_removed_mask[SLAVE_STATE] = strtoul(argv[6], NULL, 16);
    if(args->flow_removed_mask[SLAVE_STATE] > 15) {
        vty_out(vty, "Flow-Removed Mask greater than 0x7 is not allowed\r\n");
        return CMD_WARNING;
    }
    
    mul_service_send_async_config(cli->mul_service, dpid, args);

    if (c_service_timed_wait_response(cli->mul_service) > 0) {
        vty_out(vty, "Failed. Check log messages%s",
                VTY_NEWLINE);
    }
    free(args);
    vty->index = NULL;
    return CMD_SUCCESS;
}


static int
cli_fab_config_write(struct vty *vty)
{
    struct cli_config_wr_arg cfg_wr_arg = { .vty = vty,
                                            .write = 0 };

    c_log_debug("Saving fabric config");
    if (!cli->fab_service) {
        cli->fab_service = mul_app_get_service_notify_ka(MUL_FAB_CLI_SERVICE_NAME,
                                                  mul_fab_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
        if (!cli->fab_service) {
            c_log_err("mul-fab service is not alive");
            return cfg_wr_arg.write;
        }
    }

    vty_out (vty, "mul-fab-conf %s", VTY_NEWLINE);
    cfg_wr_arg.write++;

    mul_fabric_show_hosts(cli->fab_service, true, true, false,
                          (void *)&cfg_wr_arg, vty_config_dump);

    mul_fabric_show_hosts(cli->fab_service, false, true, false,
                          (void *)&cfg_wr_arg, vty_config_dump);

    vty_out (vty, "exit %s", VTY_NEWLINE);
    cfg_wr_arg.write++;

    return cfg_wr_arg.write;
}

static int
cli_makdi_config_write(struct vty *vty)
{
    struct cli_config_wr_arg cfg_wr_arg = { .vty = vty,
                                            .write = 0 };

    c_log_debug("Saving makdi config");
    if (!cli->makdi_service) {
        cli->makdi_service = mul_app_get_service_notify_ka(MUL_MAKDI_SERVICE_NAME,
                                                  mul_makdi_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
        if (!cli->makdi_service) {
            c_log_err(":mul-mak service is not alive");
            return cfg_wr_arg.write;
        }
    }

    vty_out (vty, "mul-mak-conf %s", VTY_NEWLINE);
    cfg_wr_arg.write++;

    mul_makdi_show_nfv(cli->makdi_service, (void *)&cfg_wr_arg,
                       true, vty_config_dump);

    mul_makdi_show_service(cli->makdi_service, (void *)&cfg_wr_arg,
                           true, vty_config_dump);

    mul_makdi_show_service_chain(cli->makdi_service,(void *)&cfg_wr_arg,
                                 true, vty_config_dump);

    vty_out (vty, "exit %s", VTY_NEWLINE);
    cfg_wr_arg.write++;

    return cfg_wr_arg.write;
}


static int
cli_mul_config_write(struct vty *vty)
{
    struct cli_config_wr_arg cfg_wr_arg = { .vty = vty,
                                            .write = 0 };
    uint64_t dpid = 0;

    if (!vty->dpid) {
        c_log_err("%s:Unknown switch", FN);
        return -1;
    }

    dpid = strtoull(vty->dpid, NULL, 16);
    if ((dpid == (uint64_t)(-1) && errno == ERANGE))  {
        c_log_err("%s:switch dpid parse fail", FN);
        return -1;
    }

    if (!c_app_switch_get_version_with_id(dpid)) {
        c_log_err("%s:No such switch 0x%llx", FN, U642ULL(dpid));
        return CMD_SUCCESS;
    }

    c_log_debug("Saving config for switch 0x%llx", U642ULL(dpid));
    if (!cli->mul_service) {
        cli->mul_service = mul_app_get_service_notify_ka(MUL_CORE_SERVICE_NAME,
                                                  mul_core_service_conn_event,
                                                  cli_dummy_infra_ka,
                                                  false, NULL);
        if (!cli->mul_service) {
            c_log_err("%s:mul-core service is not alive", FN);
            return cfg_wr_arg.write;
        }
    }

    vty_out (vty, "mul-conf %s", VTY_NEWLINE);
    cfg_wr_arg.write++;

    mul_get_switch_detail_config(cli->mul_service, dpid,
                                (void *)&cfg_wr_arg, vty_config_dump);

    mul_get_meter_info(cli->mul_service, dpid,
                       true, false, (void *)&cfg_wr_arg, vty_config_dump);

    mul_get_group_info(cli->mul_service, dpid,
                       true, false, (void *)&cfg_wr_arg, vty_config_dump);

    mul_get_flow_info(cli->mul_service, dpid, false, true, false, false, true, false,
                      (void *)&cfg_wr_arg, vty_config_dump); 

    vty_out (vty, "exit %s", VTY_NEWLINE);
    cfg_wr_arg.write++;

    return cfg_wr_arg.write;
}

static void
c_app_per_switch_dpid_fetch(void *key UNUSED, void *sw_arg, void *uarg)
{
    GSList **list = uarg;
    mul_switch_t *sw = sw_arg;
    uint64_t *swid;

    swid = calloc(1, sizeof(*swid));
    if (!swid) return;

    *swid = sw->dpid;
    *list = g_slist_append(*list, swid);
}

static void
cli_elem_free(void *elem)
{
    free(elem);
}

static char ** 
conf_file_name_get_cb(int *num)
{
    GSList *list = NULL;
    GSList *iterator = NULL;
    uint64_t *swid = NULL;
    char **fnames = NULL;

#define MAX_SWITCH_NAME_LEN 64
    if (!num) return NULL;
    *num = 0;

    c_app_traverse_all_switches(c_app_per_switch_dpid_fetch, &list);

    if (!list) return NULL;

    fnames = (char **)calloc(1, g_slist_length(list) * sizeof(char *));
    for (iterator = list; iterator; iterator = iterator->next) {
        swid = iterator->data;
        if (swid) {
            fnames[*num] = calloc(1, MAX_SWITCH_NAME_LEN);
            snprintf(fnames[*num], MAX_SWITCH_NAME_LEN - 1, "%llx",
                     U642ULL(*swid)); 
            ++*num;
        }
    }

    g_slist_free_full(list, cli_elem_free);
    return fnames;
    
#undef MAX_SWITCH_NAME_LEN
}

DEFUN (config_save_file,
       config_save_file_cmd,
       "write",
       "Write running configuration to persistent store\n")
{
    int err = 0;
    if (cli_ha_config_cap(cli, NULL, true)) {
        err = config_write_file_all(vty);
        if (err == CMD_SUCCESS && cli->state == C_HA_STATE_MASTER &&
            cli->ha_peer) {
            cli->need_sync = true;
        }
    }

    return err;
}

DEFUN (config_write_term,
       config_write_term_cmd,
       "write terminal",
       "Write running configuration \n"
       "To terminal\n")
{
    return config_write_terminal_all(vty);
}


DEFUN (config_read_file,
       config_read_file_cmd,
       "read X",
       "Read configuration and apply\n"
       "Enter filename(Absolute Path)\n")
{
    FILE *fp = NULL;

    fp = fopen(argv[0], "r");
    if (!fp) {
        vty_out(vty, "%s read failed\r\n", argv[0]);
    }
    fclose(fp);

    vty_out(vty, "Applying config file %s\r\n", argv[0]);
    vty_read_config(NULL, (void *)argv[0], 1, MUL_NODE);

    return CMD_SUCCESS;
}

/* Write current configuration into the terminal. */
ALIAS (config_write_term,
       show_running_config_cmd,
       "show running-config",
       SHOW_STR
       "running configuration\n")

static void *
c_cfg_fsync_thread(void *arg)
{
    cli_struct_t *cli = arg;

    while (1) {
        if (cli->need_sync) {
            cli->need_sync = false;
            c_log_info("Config-sync Started");
            c_fsync_dir(CLI_CONF_DIR, cli->ha_peer, 0 /* Take default */);
            c_log_info("Config-sync Complete");
        }
        sleep(1);
    }

    return NULL;
}

/**
 * cli_module_vty_init -
 *
 * CLI application's vty entry point 
 */
void
cli_module_vty_init(void *arg)
{
    c_app_hdl_t *hdl = arg;

    if (hdl->ha_server) {
        c_log_info("Starting config sync service");
        cli->ha_peer = hdl->ha_server;
        fsync_server_start();
        pthread_create(&cli->fsync_thread, NULL, c_cfg_fsync_thread, cli); 
    } else {
        c_log_info("Starting without config sync service");
    }

    cli->no_init_conf = hdl->no_init_conf;

#ifdef CLI_CFG_FILE
    install_node(&mul_conf_node, cli_mul_config_write);
    install_node(&fab_conf_node, cli_fab_config_write);
    install_node(&makdi_conf_node, cli_makdi_config_write);
#else
    install_node(&mul_conf_node, NULL);
    install_node(&fab_conf_node, NULL);
    install_node(&makdi_conf_node, NULL);
#endif
    install_node(&tr_conf_node, NULL);
    install_node(&flow_inst_node, NULL);
    install_node(&inst_actions_node, NULL);
    install_node(&group_node, NULL);
    install_node(&meter_node, NULL);

    install_default(MUL_NODE);
    install_default(MULTR_NODE);
    install_default(MULFAB_NODE);
    install_default(MULMAKDI_NODE);
    install_default(FLOW_NODE);
    install_default(INST_NODE);
    install_default(GROUP_NODE);
    install_default(METER_NODE);

#ifdef CLI_CFG_FILE
    install_element(ENABLE_NODE, &config_save_file_cmd);
    install_element(CONFIG_NODE, &config_save_file_cmd);
    install_element(MUL_NODE, &config_save_file_cmd);
    install_element(MULFAB_NODE, &config_save_file_cmd);

    install_element(ENABLE_NODE, &config_write_term_cmd);
    install_element(CONFIG_NODE, &config_write_term_cmd);
    install_element(MUL_NODE, &config_write_term_cmd);
    install_element(MULFAB_NODE, &config_write_term_cmd);
    
    install_element(ENABLE_NODE, &show_running_config_cmd);
    install_element(MUL_NODE, &config_read_file_cmd);
#endif

    install_element_attr_type(CONFIG_NODE, &mul_conf_cmd, MUL_NODE);
    //install_element(MUL_NODE, &mul_conf_exit_cmd);
    install_element(ENABLE_NODE, &show_of_switch_cmd);
    install_element(ENABLE_NODE, &show_of_switch_detail_cmd);
    install_element(ENABLE_NODE, &show_of_switch_desc_detail_cmd);
    install_element(ENABLE_NODE, &show_of_switch_group_detail_cmd);
    install_element(ENABLE_NODE, &show_of_switch_meter_detail_cmd);
    install_element(ENABLE_NODE, &show_of_switch_table_detail_cmd);
/*CLI changes for displaying flow wrt table id*/
    install_element(ENABLE_NODE, &show_of_switch_flow_tbid_cmd);
/*CLI changes for displaying flow wrt table id*/
    install_element(ENABLE_NODE, &show_of_switch_flow_cmd);
    install_element(ENABLE_NODE, &show_of_flow_all_cmd);
    install_element(ENABLE_NODE, &show_of_switch_flow_all_cmd);
    install_element(ENABLE_NODE, &show_of_switch_flow_static_cmd);
    install_element(ENABLE_NODE, &show_of_flow_all_static_cmd);
    install_element(ENABLE_NODE, &show_ha_state_cmd);
    install_element(ENABLE_NODE, &show_of_switch_get_port_queues_cmd);
    install_element(ENABLE_NODE, &of_switch_rx_rlim_get_cmd);
    install_element(ENABLE_NODE, &of_switch_tx_rlim_get_cmd);
    install_element(ENABLE_NODE, &of_switch_table_stats_show_cmd);
    install_element(ENABLE_NODE, &of_switch_port_stats_show_cmd);
    install_element(MUL_NODE, &of_switch_rx_rlim_cmd);
    install_element(MUL_NODE, &of_switch_rx_rlim_disable_cmd);
    install_element(MUL_NODE, &of_switch_tx_rlim_cmd);
    install_element(MUL_NODE, &of_switch_tx_rlim_disable_cmd);
    install_element(MUL_NODE, &of_switch_stats_strategy_cmd);
    install_element(MUL_NODE, &of_switch_port_stats_cmd);
    install_element(MUL_NODE, &of_flow_vty_add_cmd);
    install_element(MUL_NODE, &of_flow6_vty_add_cmd);
    install_element(MUL_NODE, &of_flow_vty_del_cmd);
    install_element(MUL_NODE, &of_flow_vty_del_extended_cmd);
    install_element(MUL_NODE, &of_flow6_vty_del_cmd);
    install_element(MUL_NODE, &of_flow6_vty_del_extended_cmd);
    install_element(MUL_NODE, &of_switch_pkt_dump_cmd);
    install_element(MUL_NODE, &of_port_vty_mod_cmd);
    install_element_attr_type(FLOW_NODE, &of_add_goto_instruction_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_meter_inst_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_write_instruction_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_apply_instruction_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &flow_stats_en_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &flow_barrier_en_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &flow_no_post_validate_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &flow_prio_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &flow_tunnel_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &flow_commit_cmd, MUL_NODE);

    install_element_attr_type(INST_NODE, &of_add_output_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_vid_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_dmac_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_smac_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_eth_type_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_nw_saddr_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_nw_daddr_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_nw_saddr6_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_nw_daddr6_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_strip_vlan_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_vpcp_action_cmd, MUL_NODE);

    install_element_attr_type(INST_NODE, &of_add_push_mpls_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_strip_mpls_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_mpls_ttl_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_dec_mpls_ttl_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_mpls_label_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_mpls_tc_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_mpls_bos_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_push_vlan_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_push_svlan_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_push_pbb_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_strip_pbb_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_nw_ttl_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_dec_nw_ttl_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_nw_dscp_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_cp_ttl_in_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_cp_ttl_out_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_group_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_queue_action_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_set_tunnel_id_action_cmd, MUL_NODE);

    install_element_attr_type(INST_NODE, &of_add_drop_action_cmd, MUL_NODE); 
    install_element_attr_type(INST_NODE, &flow_actions_exit_cmd, MUL_NODE);
    install_element_attr_type(INST_NODE, &of_add_instruction_action_fini_cmd, MUL_NODE);
    
    install_element(ENABLE_NODE, &show_of_switch_group_cmd);
    install_element(MUL_NODE, &of_group_vty_add_cmd);
    install_element(MUL_NODE, &of_group_vty_del_cmd);
    install_element_attr_type(GROUP_NODE, &group_stats_en_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_output_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_vid_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_dmac_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_nw_saddr_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_nw_daddr_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_smac_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_strip_vlan_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_vpcp_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_push_mpls_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_strip_mpls_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_mpls_ttl_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_dec_mpls_ttl_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_mpls_label_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_mpls_tc_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_mpls_bos_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_push_vlan_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_push_svlan_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_push_pbb_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_strip_pbb_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_nw_ttl_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_nw_dscp_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_dec_nw_ttl_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_cp_ttl_in_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_cp_ttl_out_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_group_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_queue_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_tunnel_id_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_act_vector_weight_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_act_vector_ff_port_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_act_vector_ff_group_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_act_vector_done_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_barrier_en_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_commit_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_act_vec_exit_cmd, MUL_NODE);
    
    install_element(ENABLE_NODE, &of_meter_vty_show_cmd);
    install_element(MUL_NODE, &of_meter_vty_add_cmd);
    install_element(MUL_NODE, &of_meter_vty_delete_cmd);
    install_element_attr_type(METER_NODE, &of_meter_vty_drop_cmd, MUL_NODE);
    install_element_attr_type(METER_NODE, &of_meter_vty_dscp_remark_cmd, MUL_NODE);
    install_element_attr_type(METER_NODE, &meter_band_done_cmd, MUL_NODE);
    install_element_attr_type(METER_NODE, &meter_barrier_en_cmd, MUL_NODE);
    install_element_attr_type(METER_NODE, &meter_commit_cmd, MUL_NODE);
    install_element_attr_type(METER_NODE, &meter_act_vec_exit_cmd, MUL_NODE);

#ifdef CLI_TR
    install_element_attr_type(CONFIG_NODE, &mul_tr_conf_cmd, MULTR_NODE);
    install_element(MULTR_NODE, &tr_loop_en_cmd);
    install_element(ENABLE_NODE, &show_neigh_switch_detail_cmd);
#endif

#ifdef CLI_FABRIC
    install_element_attr_type(CONFIG_NODE, &mul_fab_conf_cmd, MULFAB_NODE);
    install_element(MULFAB_NODE, &add_fab_host_gw_cmd);
    install_element(MULFAB_NODE, &add_fab_host_nongw_cmd);
    install_element(MULFAB_NODE, &del_fab_host_cmd);
    install_element(ENABLE_NODE, &show_fab_host_all_active_cmd);
    install_element(ENABLE_NODE, &show_fab_host_all_inactive_cmd);
    install_element(ENABLE_NODE, &show_fab_route_all_cmd);
    install_element(ENABLE_NODE, &show_fab_port_tnid_all_cmd);
#endif

#ifdef CLI_MAKDI
    install_element_attr_type(CONFIG_NODE, &mul_makdi_conf_cmd, MULMAKDI_NODE);
    install_element(ENABLE_NODE, &show_makdi_service_cmd);
    install_element(MULMAKDI_NODE, &add_makdi_nfv_group_cmd);
    install_element(MULMAKDI_NODE, &del_makdi_nfv_group_cmd);
    install_element(MULMAKDI_NODE, &add_makdi_nfv_cmd);
    install_element(MULMAKDI_NODE, &del_makdi_nfv_cmd);
    install_element(ENABLE_NODE, &show_makdi_nfv_cmd);
    install_element(ENABLE_NODE, &show_makdi_nfv_stats_cmd);
    install_element(MULMAKDI_NODE, &add_makdi_service_cmd);
    install_element(MULMAKDI_NODE, &del_makdi_service_cmd);
    install_element(MULMAKDI_NODE, &add_makdi_nfv_sc_rule_cmd);
    install_element(MULMAKDI_NODE, &del_makdi_nfv_sc_rule_cmd);
    install_element(ENABLE_NODE, &show_makdi_service_chain_cmd);
#endif

    install_element(MUL_NODE, &set_async_config_cmd);
    host_config_file_cb_set(CLI_CONF_FILE, conf_file_name_get_cb);

    vty_read_config(NULL, CLI_CONF_FILE, 1, CONFIG_NODE);
    cli->vty_master = hdl->vty_master; 
    thread_add_timer(cli->vty_master,
                     cli_service_timer, cli, CLI_TIMER_INIT_TS);
}

module_init(cli_module_init);
module_vty_init(cli_module_vty_init);
#else

void
cli_module_init(void *base_arg UNUSED)
{
    c_log_debug("%s", FN);
    return;
}

module_init(cli_module_init);
#endif
