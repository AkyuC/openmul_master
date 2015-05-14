/*
 *  mul_cli.h: Mul cli application headers
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
#ifndef __MUL_CLI_H__
#define __MUL_CLI_H__

#include "config.h"
#include "mul_common.h"
#include "mul_vty.h"
#include "mul_fabric_servlet.h"
#include "makdi_servlet.h"

#define CLI_TR 1
#define CLI_MAKDI 1
#define CLI_FABRIC 1

#define CLI_CONF_DIR "/etc/mul/config/"
#define CLI_CONF_FILE "/etc/mul/config/mulcli.conf"

#define CLI_TIMER_TS  (3)
#define CLI_TIMER_TUS (0)

#define CLI_TIMER_INIT_TS  (5)
#define CLI_TIMER_INIT_TUS (0)

#define CLI_TIMER_CFG_SYNC_TMS (60*60*1000000LL) /* Every hour */

#define CLI_UNK_BUFFER_ID (0xffffffff)

struct cli_common_args {
    bool flow_act;
};

struct cli_flow_action_parms {
    struct cli_common_args cmn;    
    uint64_t dpid;
    void *fl;
    void *mask;
    uint64_t flags;
    struct mul_act_mdata *mdata;
    bool drop_pkt;
    uint16_t fl_prio;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
};

struct cli_group_bucket_parms
{
    mul_act_mdata_t mdata;
    bool drop_pkt;
    uint16_t weight;
    uint32_t ff_port;
    uint32_t ff_group;
};

struct cli_group_mod_parms
{
    struct cli_common_args cmn;
    uint64_t dpid;
    uint32_t group;
    uint8_t type;
    uint8_t flags;
    struct cli_group_bucket_parms bkt_parms[OF_MAX_ACT_VECTORS];
    size_t act_vec_len;
};

struct cli_meter_band_param
{
    mul_act_mdata_t mdata;
    bool        action_added;
    uint16_t    type;
    uint32_t    rate;
    uint32_t    burst_size;
    uint8_t     prec_level;   /* used for OFPMBT_DSCP_REMARK */
    uint32_t    experimenter; /* used for OFPMBT_EXPERIMENTER */
};

struct cli_meter_mod_params
{
    struct  cli_common_args cmn;
    uint64_t dpid;
    uint32_t meter_id;
    uint16_t type;
    uint8_t cflags;
    size_t act_vec_len;
    struct cli_meter_band_param meter_band_params[OF_MAX_METER_VECTORS];
};

#define MASTER_STATE    0
#define SLAVE_STATE     1

#define CLI_ARGS_TO_ACT_MDATA_SW(mdata, args) \
do { \
    struct cli_common_args *__cmn = (void *)(args); \
    if (__cmn->flow_act) { \
        struct cli_flow_action_parms *fl_parms = args; \
        (mdata) = fl_parms->mdata; \
    } else { \
        struct cli_group_mod_parms *g_parms = args; \
        (mdata) = &g_parms->bkt_parms[g_parms->act_vec_len-1].mdata; \
    } \
} while (0)

#define CLI_ARGS_TO_ACT_MDATA_DPID(mdata, args, dpid) \
do { \
    struct cli_common_args *__cmn = (void *)(args); \
    if (__cmn->flow_act) { \
        struct cli_flow_action_parms *fl_parms = args; \
        (mdata) = fl_parms->mdata; \
        (dpid) = fl_parms->dpid; \
    } else { \
        struct cli_group_mod_parms *g_parms = args; \
        (mdata) = &g_parms->bkt_parms[g_parms->act_vec_len-1].mdata; \
        (dpid) = g_parms->dpid; \
    } \
} while (0)

/* Main fabric context struct holding all info */
struct cli_struct {
    GSList        *cli_list;
    c_rw_lock_t   lock;
    void          *vty_master;
    void          *base;
    bool          init_events_triggered;
    struct event  *timer_event;

    mul_service_t *mul_service; /* Traffic-Routing Service Instance */
    mul_service_t *tr_service; /* Traffic-Routing Service Instance */
    mul_service_t *fab_service; /* Fabric Service Instance */
    mul_service_t *makdi_service; /* Fabric Service Instance */

    bool          fab_service_rep;
    bool          mul_service_rep;
    bool          makdi_service_rep;

    bool          no_init_conf;

    uint32_t      sysid;
    uint32_t      state;
    uint64_t      generation_id;

    pthread_t     fsync_thread;
    bool          need_sync;
    const char    *ha_peer;
    int64_t       last_sync;
};
typedef struct cli_struct cli_struct_t;

struct cli_config_wr_arg {
    struct vty *vty;
    int write;        
};

void cli_module_init(void *ctx);
void cli_module_vty_init(void *arg);

#endif
