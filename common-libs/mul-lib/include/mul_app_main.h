/*
 * mul_app_main.h: MUL application main headers
 * Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#ifndef __MUL_APP_MAIN_H___
#define __MUL_APP_MAIN_H___

#define C_APP_RCV_BUF_SZ 4096
#define C_APP_PATH_LEN 64
#define C_APP_VTY_COMMON_PATH "/var/run/app_"
#define C_APP_PID_COMMON_PATH "/var/run/mul_app"
#define C_APP_LOG_COMMON_PATH "/var/log/"
#define C_APP_FILENAME_SZ   32
#define MAX_NUMBER_DPID     50
#define DPID_CHAR_SZ        32
struct c_app_service {
   char app_name[MAX_SERV_NAME_LEN];
   uint32_t app_cookie;
   char service_name[MAX_SERV_NAME_LEN];
   uint16_t  port;
   void * (*service_priv_init)(void);
};

struct c_app_hdl_
{
    char *progname;
    char dpid_file[C_APP_FILENAME_SZ];
    c_conn_t conn;
    struct event_base *base;
    struct event *reconn_timer_event;
    void (*ev_cb)(void *app, void *buf);

	const char *ha_server;
	mul_service_t *ha_service;
	mul_service_t *ctrlr_service;
	uint32_t peer_mini_state;
	uint32_t ha_state;

    uint32_t app_cookie;

    c_rw_lock_t infra_lock;
    GHashTable *switches;

    /* For VTY thread */
    pthread_t vty_thread;
    void  *vty_master;
    uint16_t vty_port;

#define MUL_APP_LOG_WARN (0)
#define MUL_APP_LOG_NOT  (1)
#define MUL_APP_LOG_ERR  (2)
#define MUL_APP_LOG_INFO (3)
#define MUL_APP_LOG_DBG  (4)
    int log_lvl;
    struct c_rlim_dat dlog_rlim;
    struct c_rlim_dat ilog_rlim;
    struct c_rlim_dat elog_rlim;

    bool no_init_conf;
};
typedef struct c_app_hdl_ c_app_hdl_t;

extern c_app_hdl_t c_app_main_hdl;

#define mul_app_log(_log, lvl, ...) \
do { \
    if (c_app_main_hdl.log_lvl >= lvl) { \
        _log(__VA_ARGS__); \
    }  \
} while(0)

#define mul_app_rlog(_log, lvl, _rlim, ...) \
do { \
    if (c_app_main_hdl.log_lvl >= lvl && !c_rlim((_rlim))) { \
        _log(__VA_ARGS__); \
    }  \
} while(0)

#define app_log_debug(args...) mul_app_log(c_log_debug, MUL_APP_LOG_DBG, args)
#define app_log_info(args...) mul_app_log(c_log_info, MUL_APP_LOG_INFO, args)
#define app_log_err(args...) mul_app_log(c_log_err, MUL_APP_LOG_ERR, args)
#define app_log_notice(args...) mul_app_log(c_log_notice, MUL_APP_LOG_NOT, args)
#define app_log_warn(args...) mul_app_log(c_log_warn, MUL_APP_LOG_WARN, args)

#define app_rlog_debug(args...) mul_app_rlog(c_log_debug, MUL_APP_LOG_DBG, &c_app_main_hdl.dlog_rlim, args)
#define app_rlog_info(args...) mul_app_rlog(c_log_info, MUL_APP_LOG_INFO, &c_app_main_hdl.ilog_rlim, args)
#define app_rlog_err(args...) mul_app_rlog(c_log_err, MUL_APP_LOG_ERR, &c_app_main_hdl.elog_rlim, args)

void c_app_reconnect(c_app_hdl_t *hdl);
void c_service_conn_update(void *service, unsigned char conn_event);

#endif
