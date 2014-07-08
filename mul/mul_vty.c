/*
 *  mul_vty.c: MUL vty implementation 
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
#include "mul_vty.h"

int c_vty_thread_run(void *arg);

#ifdef MUL_APP_VTY
char              *vty_addr = NULL;
int               vty_port  = C_VTY_PORT;
extern ctrl_hdl_t ctrl_hdl;

struct vty_common_args
{
    bool flow_act;
};

struct vty_flow_action_parms
{
    struct vty_common_args cmn;
    void *sw;
    void *fl;
    void *mask;
    mul_act_mdata_t mdata;
    uint32_t wildcards;
    bool drop_pkt;
};

struct vty_group_mod_parms
{
    struct vty_common_args cmn;
    void *sw;
    uint32_t group;
    uint8_t type;
    mul_act_mdata_t mdata[OF_MAX_ACT_VECTORS];
    bool drop_pkt[OF_MAX_ACT_VECTORS];
    size_t act_vec_len;
};

#define VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, args) \
do { \
    struct vty_common_args *__cmn = (void *)(args); \
    if (__cmn->flow_act) { \
        struct vty_flow_action_parms *fl_parms = args; \
        (mdata) = &fl_parms->mdata; \
        (sw) = fl_parms->sw; \
    } else { \
        struct vty_group_mod_parms *g_parms = args; \
        (mdata) = &g_parms->mdata[g_parms->act_vec_len-1]; \
        (sw) = g_parms->sw; \
    } \
} while (0)

static void
ofp_switch_states_tostr(char *string, uint32_t state)
{
    if (state == 0) {
        strcpy(string, "Init\n");
        return;
    }
    if (state & SW_REGISTERED) {
        strcpy(string, "Registered ");
    }
    if (state & SW_REINIT) {
        strcat(string, "Reinit");
    }
    if (state & SW_REINIT_VIRT) {
        strcat(string, "Reinit-Virt");
    }
    if (state & SW_DEAD) {
        strcat(string, "Dead");
    }
}
 

static void
ofp_capabilities_tostr(char *string, uint32_t capabilities)
{
    if (capabilities == 0) {
        strcpy(string, "No capabilities\n");
        return;
    }
    if (capabilities & OFPC_FLOW_STATS) {
        strcpy(string, "FLOW_STATS ");
    }
    if (capabilities & OFPC_TABLE_STATS) {
        strcat(string, "TABLE_STATS ");
    }
    if (capabilities & OFPC_PORT_STATS) {
        strcat(string, "PORT_STATS ");
    }
    if (capabilities & OFPC_STP) {
        strcat(string, "STP ");
    }
    if (capabilities & OFPC_IP_REASM) {
        strcat(string, "IP_REASM ");
    }
    if (capabilities & OFPC_QUEUE_STATS) {
        strcat(string, "QUEUE_STATS ");
    }
    if (capabilities & OFPC_ARP_MATCH_IP) {
        strcat(string, "ARP_MATCH_IP");
    }
}

static void UNUSED
ofp_port_features_tostr(char *string, uint32_t features)
{
    if (features == 0) {
        strcpy(string, "Unsupported\n");
        return;
    }
    if (features & OFPPF_10MB_HD) {
        strcat(string, "10MB-HD ");
    }
    if (features & OFPPF_10MB_FD) {
        strcat(string, "10MB-FD ");
    }
    if (features & OFPPF_100MB_HD) {
        strcat(string, "100MB-HD ");
    }
    if (features & OFPPF_100MB_FD) {
        strcat(string, "100MB-FD ");
    }
    if (features & OFPPF_1GB_HD) {
        strcat(string, "1GB-HD ");
    }
    if (features & OFPPF_1GB_FD) {
        strcat(string, "1GB-FD ");
    }
    if (features & OFPPF_10GB_FD) {
        strcat(string, "10GB-FD ");
    }
    if (features & OFPPF_COPPER) {
        strcat(string, "COPPER ");
    }
    if (features & OFPPF_FIBER) {
        strcat(string, "FIBER ");
    }
    if (features & OFPPF_AUTONEG) {
        strcat(string, "AUTO_NEG ");
    }
    if (features & OFPPF_PAUSE) {
        strcat(string, "AUTO_PAUSE ");
    }
    if (features & OFPPF_PAUSE_ASYM) {
        strcat(string, "AUTO_PAUSE_ASYM ");
    }
}

static void
c_port_config_tostr(char *string, uint32_t config)
{
    if (config & C_MLPC_DOWN) {
        strcat(string, " PORT_DOWN");
    } else {
        strcat(string, " PORT_UP");
    }
}

static void
c_port_state_tostr(char *string, uint32_t config)
{
    if (config & C_MLPS_DOWN) {
        strcat(string, " LINK_DOWN");
    } else {
        strcat(string, " LINK_UP");
    }
}

static void
of_show_switch_info(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;
    struct      vty *vty = arg;
    char        string[OFP_PRINT_MAX_STRLEN];

    ofp_switch_states_tostr(string, sw->switch_state);

    vty_out (vty, "0x%012llx    %-11s %-26s %-8d %s",
             sw->datapath_id,
             string,
             sw->conn.conn_str,
             sw->n_ports,
             VTY_NEWLINE);
}


DEFUN (show_of_switch,
       show_of_switch_cmd,
       "show of-switch all",
       SHOW_STR
       "Openflow switches\n"
       "Summary information for all")
{

    vty_out (vty,
            "%sSwitch-DP-id    |   State     |  "
            "Peer                 | Ports%s",
            VTY_NEWLINE, VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    c_switch_traverse_all(&ctrl_hdl, of_show_switch_info, vty);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

static void
of_show_switch_port_info(void *k UNUSED, void *v, void *arg)
{
    c_port_t *p_info = v;
    struct vty *vty = arg;
    char string[OFP_PRINT_MAX_STRLEN];

    memset(string, 0, OFP_PRINT_MAX_STRLEN);
    c_port_config_tostr(string, p_info->sw_port.config);
    c_port_state_tostr(string, p_info->sw_port.state);

    vty_out(vty, "%-6u %-10s %02x:%02x:%02x:%02x:%02x:%02x %-15s",
            p_info->sw_port.port_no, p_info->sw_port.name,
            p_info->sw_port.hw_addr[0], p_info->sw_port.hw_addr[1],
            p_info->sw_port.hw_addr[2], p_info->sw_port.hw_addr[3],
            p_info->sw_port.hw_addr[4], p_info->sw_port.hw_addr[5],
            string);

    memset(string, 0, OFP_PRINT_MAX_STRLEN);
    vty_out(vty, "%s", VTY_NEWLINE);
}

DEFUN (show_of_switch_detail,
       show_of_switch_detail_cmd,
       "show of-switch X detail",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Detailed information\n")
{
    uint64_t dp_id;
    c_switch_t *sw;
    char string[OFP_PRINT_MAX_STRLEN];

    dp_id = strtoull(argv[0], NULL, 16);

    sw = c_switch_get(&ctrl_hdl, dp_id);

    if (!sw) {
        return CMD_SUCCESS;
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);
    vty_out (vty, "Datapath-id : 0x%llx%s", (unsigned long long)dp_id, VTY_NEWLINE);
    vty_out (vty, "Alias-id    : 0x%u%s", (unsigned int)sw->alias_id, VTY_NEWLINE);
    vty_out (vty, "OFP-Version : 0x%d%s", sw->version, VTY_NEWLINE);
    vty_out (vty, "Buffers     : %d%s", sw->n_buffers, VTY_NEWLINE);
    vty_out (vty, "Tables      : %d%s", sw->n_tables, VTY_NEWLINE);
    vty_out (vty, "Actions     : 0x%x%s", sw->actions, VTY_NEWLINE);

    memset(string, 0, OFP_PRINT_MAX_STRLEN);
    ofp_capabilities_tostr(string, sw->capabilities);

    vty_out (vty, "Capabilities: 0x%x(%s)%s", sw->capabilities,
            string, VTY_NEWLINE);
    vty_out (vty, "Num Ports   : %d%s", sw->n_ports, VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    vty_out (vty, "                              Port info%s",
            VTY_NEWLINE);
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_rd_lock(&sw->lock);
    __c_switch_port_traverse_all(sw, of_show_switch_port_info, vty);
    c_rd_unlock(&sw->lock);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    c_switch_put(sw);

    return CMD_SUCCESS;

}

DEFUN (of_flow_reset,
       of_flow_reset_cmd,
       "of-flow reset-all switch X",
       "Openflow flow\n"  
       "reset-all flows\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t                     dp_id;
    c_switch_t                   *sw;
    struct flow                  flow;
    struct flow                  mask;
    struct of_flow_mod_params    fl_parms;

    memset(&fl_parms, 0, sizeof(fl_parms));
    memset(&flow, 0, sizeof(flow));
    memset(&mask, 0, sizeof(mask));

    dp_id = strtoull(argv[0], NULL, 16);
    sw = c_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        return CMD_WARNING;
    }

    __of_send_flow_del_direct(sw, &flow, &mask, OFPP_NONE,
                              false, C_FL_PRIO_DFL, OFPG_ANY);

    c_switch_flow_tbl_reset(sw);
    c_switch_put(sw);

    vty_out(vty, "All Flows reset\r\n");

    return CMD_SUCCESS;
}

DEFUN (c_send_pkt,
       c_send_pkt_cmd,
       "send-dummy-pkt-out dpid X oport <1-4294967295> num-pkt <1-1000>", 
       "Send a dummy packet-out to a switch (Only for testing)\n"
       "Switch datapath\n"
       "Enter the value in 0xXXXX format\n")
{
    uint64_t    dpid = 0;
    c_switch_t *sw = NULL;
    struct cbuf *b = NULL;
    mul_act_mdata_t mdata;
    uint32_t oport;
    uint16_t num_pkt = 0, counter = 0;
    struct of_pkt_out_params parms;
    uint8_t eth_hdr[2*OFP_ETH_ALEN + 2] = {0x01,0x80,0xc2,0x00,0x00,0x0e,
                                           0x00,0x01,0x02,0x03,0x04,0x05,
                                           0x88, 0xcc};
    uint8_t pkt[64];
    uint8_t *ptr = pkt;

    dpid = strtoull(argv[0], NULL, 16);
    sw = c_switch_get(&ctrl_hdl, dpid);
    if (!sw) {
        vty_out(vty, "No such switch\r\n");
        return CMD_WARNING;
    }

    oport = strtoull(argv[1], NULL, 0);;
    num_pkt = atol(argv[2]);

    memcpy(ptr, eth_hdr, sizeof(eth_hdr));
     
    of_mact_alloc(&mdata);
    mdata.only_acts = true;
    if (sw->ofp_ctors->act_output) {
        sw->ofp_ctors->act_output(&mdata, oport);
    }

    if (sw->ofp_ctors && sw->ofp_ctors->pkt_out) {
        parms.buffer_id = 0xffffffff;
        parms.action_list  = mdata.act_base;
        parms.action_len = of_mact_len(&mdata);
        parms.in_port = OF_NO_PORT;
        parms.data = pkt;
        parms.data_len = sizeof(pkt);
        for (counter = 0; counter < num_pkt; counter++) {
            b = sw->ofp_ctors->pkt_out(&parms);
            if (sw->tx_dump_en && sw->ofp_ctors->dump_of_msg) {
                sw->ofp_ctors->dump_of_msg(b, true, sw->DPID);
            }
            c_thread_tx(&sw->conn, b, false);
        }
    }

    c_switch_put(sw);
    of_mact_free(&mdata);
    
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

DEFUN (c_set_aging,
       c_set_aging_cmd,
       "set controller-l2-aging-compaction (enable|disable)", 
       SET_STR
       "Controller L2 Aging and FDB compaction\n"
       "Enables aging and compaction\n"
       "Disables aging and compaction\n")
{
    if (!strncmp(argv[0], "enable", strlen(argv[0]))) {
        ctrl_hdl.aging_off = false;
    } else if (!strncmp(argv[0], "disable", strlen(argv[0]))) {
        ctrl_hdl.aging_off = true;
    } else {
        NOT_REACHED();
    }

    return CMD_SUCCESS;
}

DEFUN (c_set_switch_debug,
       c_set_switch_debug_cmd,
       "set switch-debug X (enable|disable)", 
       SET_STR
       "Set switch in debug mode\n"
       "Enter the dpid value in 0xXXXX format\n"
       "Enables aging and compaction\n"
       "Disables aging and compaction\n")
{
    uint64_t    dpid = 0;
    c_switch_t *sw = NULL;

    dpid = strtoull(argv[0], NULL, 16);
    sw = c_switch_get(&ctrl_hdl, dpid);
    if (!sw) {
        vty_out(vty, "No such switch\r\n");
        return CMD_WARNING;
    }

    if (!strncmp(argv[1], "enable", strlen(argv[1]))) {
        sw->debug_flag = 1;
    } else if (!strncmp(argv[1], "disable", strlen(argv[1]))) {
        sw->debug_flag = 0;
    } else {
        NOT_REACHED();
    }

    c_switch_put(sw);

    return CMD_SUCCESS;
}

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

static void
mul_vty_init(void)
{
    install_element(ENABLE_NODE, &show_of_switch_cmd);
    install_element(ENABLE_NODE, &show_of_switch_detail_cmd);
    install_element(CONFIG_NODE, &c_send_pkt_cmd);
    install_element(CONFIG_NODE, &of_flow_reset_cmd);
    install_element(CONFIG_NODE, &c_set_log_cmd);
    install_element(CONFIG_NODE, &c_set_aging_cmd);
    install_element(CONFIG_NODE, &c_set_switch_debug_cmd);
    
    modvty__initcalls(NULL);
}

int
c_vty_thread_run(void *arg)
{
    uint64_t            dpid = 0;
    struct thread       thread;
    struct c_vty_ctx    *vty_ctx = arg;
    ctrl_hdl_t          *c_hdl = vty_ctx->cmn_ctx.c_hdl; 

    c_set_thread_dfl_affinity();

    signal(SIGPIPE, SIG_IGN);

    /* Register vty as an app for static flow install */
    mul_register_app(NULL, C_VTY_NAME, 0, 0, 1, &dpid, NULL);

    c_hdl->vty_master = thread_master_create();

    cmd_init(1);
    vty_init(c_hdl->vty_master);
    mul_vty_init();
    sort_node();

    vty_serv_sock(vty_addr, vty_port, C_VTYSH_PATH, 1);

     /* Execute each thread. */
    while (thread_fetch(c_hdl->vty_master, &thread))
        thread_call(&thread);

    /* Not reached. */
    return (0);
}

#else
int
c_vty_thread_run(void *arg UNUSED)
{
    while (1) {
        sleep(1);
    }
}
#endif
