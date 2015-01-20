/*
 *  mul_priv.h: MUL private defines 
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
#ifndef __MUL_PRIV_H__
#define __MUL_PRIV_H__

/* Generic defines */
#define C_VTY_NAME                "mul-vty"

#define C_LISTEN_PORT               6653
#define C_APP_LISTEN_PORT           7744 
#define C_APP_AUX_LISTEN_PORT       7745 
#define C_APP_WQ_LISTEN_PORT        7766
#define C_IPC_PATH                  "/var/run/cipc_x"
#define C_IPC_APP_PATH              "/var/run/cipc_app_x"
#define C_PER_WORKER_TIMEO          1
#define C_PER_APP_WORKER_TIMEO      1
#define C_MAIN_THREAD_BOOT_TIMEO    5 
#define C_MAIN_THREAD_TIMEO         10
#define C_SSL_BUSY_ACCEPT_RETRIES   5000

#define C_SWITCH_IDLE_TIMEO         (90)
#define C_SWITCH_ECHO_TIMEO         (10)
#define C_SWITCH_STAT_TIMEO         (5)
#define C_SWITCH_HA_SYNC_TIMEO      (2)
#define C_SWITCH_FP_AGING_TIMEO     (10)
#define C_SWITCH_PROBE_REP_TIMEO    (4)
#define C_SWITCH_FEAT_PROBE_TIMEO   (4)
#define C_SWITCH_PROBE_PASS_TIMEO   (10)
#define C_MAX_RULE_FLOW_TBLS        (255)
#define C_TBL_HW_IDX_DFL            (0)

#define C_OPT_NO_TABLES             (3)
#define C_MAX_Q_PROP_LEN            (2048)

#define C_CP_METER_ID               (0)

#define C_VTY_PORT                  7000
#define C_PID_PATH                  "/var/run/mul.pid"
#define C_VTYSH_PATH 	            "/var/run/mul.vty"
#define C_MAX_PATH_NAME_LEN         (1024)

#define C_INLINE_BUF_SZ             (96)
#define C_INLINE_ACT_SZ             (64)

#define OFSW_MAX_PORTS              65536	
#define OFSW_MAX_REAL_PORTS         1024 
#define OFSW_MAX_FLOW_STATS         65536
#define OFSW_MAX_FLOW_STATS_COLL    2048 
#define OFSW_MAX_GROUP_STATS_COLL   5000 
#define OFSW_MAX_METER_STATS_COLL   5000 
#define OFSW_MAX_PORT_STATS_COLL    5000 
#define OFC_SUCCESS                 0
#define OFC_FAIL                    -1
#define OFC_SW_TIME                 20
#define true                        1
#define false                       0
#define OFC_SW_PORT_VALID           true
#define OFC_SW_PORT_INVALID         false
#define OFC_SW_PORT_INFO_DIRTY      0x80000000
#define OFC_RCV_BUF_SZ              4096 
#define CIPC_RCV_BUF_SZ             512

#define C_PER_SW_DFL_PPS            (100000)

#define C_RSA_SERVER_CERT           "/etc/mul/ctrl.crt"
#define C_RSA_SERVER_KEY            "/etc/mul/ctrl.key"
#define C_RSA_CLIENT_CA_CERT        "/etc/mul/switch_ca.crt"

#define C_GEN_ID_STORE              "/etc/mul/genid"

#define C_MAX_CP_PKTIN_RATE         5000
#define C_MAX_CP_PKTIN_BURST_SIZE   50

#define MUL_FLOW_DEBUG 1

typedef enum port_state {
    P_DISABLED = 1 << 0,
    P_LISTENING = 1 << 1,
    P_LEARNING = 1 << 2,
    P_FORWARDING = 1 << 3,
    P_BLOCKING = 1 << 4
} port_state_t;

struct c_iter_args
{
    void *u_arg;
    void *u_fn;
};

/* Forward declaration */
struct c_switch;
struct c_fl_entry_;
struct c_sw_port;

typedef void (*c_ofp_rx_handler_op_t)(struct c_switch *sw, struct cbuf *b);

struct c_ofp_rx_handler {
    c_ofp_rx_handler_op_t handler;
    size_t min_size;
    c_ofp_rx_handler_op_t ha_handler;
}; 

typedef struct c_ofp_rx_handler c_ofp_rx_handler_t;

struct c_ofp_proc_helpers {
    struct c_port *(*xlate_port_desc)(struct c_switch *sw, void *opp);
    struct cbuf *(*mk_ofp_features)(struct c_switch *sw); 
    int (*proc_one_flow_stats)(struct c_switch *sw, void *ofps);
    void (*proc_one_port_stats)(struct c_switch *sw, void *ofps);
    int (*proc_one_tbl_feature)(struct c_switch *sw, void *ofptf);
    int (*refresh_ports)(struct c_switch *sw);
};

typedef struct c_ofp_proc_helpers c_ofp_proc_helpers_t;

/* Controller handle structure */
typedef struct ctrl_hdl_ {

    c_rw_lock_t lock;
    c_rw_lock_t flock;

    GHashTable *sw_hash_tbl;
    ipool_hdl_t *sw_ipool;
    GSList *app_list;

    struct c_cmn_ctx *main_ctx;
    struct c_cmn_ctx **worker_ctx_list;
    struct c_cmn_ctx **app_ctx_list;

    void *vty_master;
    c_rw_lock_t *ssl_thread_locks;

    int n_threads;
    int n_appthreads;
    bool no_dfl_flows;
    bool dfl_dump_pkts;

    /* SSL related */
    bool ssl_en;
    bool switch_ca_verify;
    SSL_METHOD *ssl_meth;
    SSL_CTX *ssl_ctx;

    uint32_t ha_state;
    uint32_t ha_sysid;
    uint32_t ha_peer_sysid;
    uint32_t ha_peer_state;
    uint64_t gen_id;
    bool conflict_resolve;
    const char *c_peer;
    c_conn_t ha_conn;
    void *ha_timer_event;
    void *ha_base;
#define C_HA_MAX_RETRIES (5)
    int ha_retries;
    time_t last_ha_hearbeat;

    uint16_t c_port;    
    uint8_t h_of_ver;
    bool aging_off;
    bool loop_en;
    bool bench_en;
    bool no_strict_of;
    volatile uint64_t loop_status;
    volatile uint64_t tr_status;
} ctrl_hdl_t;

#define c_sw_hier_rdlock(sw)            \
do {                                    \
    c_rd_lock(&ctrl_hdl.lock);          \
    if (sw) c_rd_lock(&sw->lock);       \
} while(0) 

#define c_sw_hier_unlock(sw)            \
do {                                    \
    if (sw) c_rd_unlock(&sw->lock);     \
    c_rd_unlock(&ctrl_hdl.lock);        \
} while(0) 

typedef struct c_app_info_
{
    void *ctx;
    c_atomic_t ref;
    struct sockaddr_in peer_addr;
    c_conn_t app_conn;
    uint32_t ev_mask;
    uint32_t app_flags;    
#define C_APP_FP_L2 (0x01)
    uint32_t priv_flags;
    uint32_t n_dpid;
    uint32_t app_cookie;
    GHashTable *dpid_hlist;
    void (*ev_cb)(void *app_arg, void *pkt_arg);
    char app_name[C_MAX_APP_STRLEN];
} c_app_info_t;

struct c_sw_event_q_ent
{
    c_app_info_t *app;
    struct cbuf *b;
};

struct c_pkt_in_mdata
{
    struct flow *fl;
    size_t pkt_ofs;
    size_t pkt_len;
    uint32_t buffer_id;
};

struct c_port_chg_mdata
{
    struct c_sw_port *port_desc;
    void *chg_mask;
    uint8_t reason;
};

struct c_port_cfg_state_mask
{
    uint32_t config_mask;
    uint32_t state_mask;
};

struct c_vendor_mdata
{
    uint32_t    vendor_id;
    size_t      data_ofs;  
    size_t      data_len;  
    uint8_t     pad[4];
};

struct c_switch_fp_ops
{
    int (*fp_fwd)(struct c_switch *sw,
                  struct cbuf *b,
                  void *in_data,
                  size_t len,
                  struct c_pkt_in_mdata *mdata,
                  uint32_t iport);
    int (*fp_port_status)(struct c_switch *sw,
                          uint32_t port,
                          uint32_t cfg,
                          uint32_t state,
                          struct c_port_cfg_state_mask *mask);
    void (*fp_topo_change)(struct c_switch *sw, uint64_t new_state,
                           bool locked);
    void (*fp_aging)(struct c_switch *sw, uint32_t port, bool check_port);
    int (*fp_db_ctor)(struct c_switch *sw, bool locked);
    void (*fp_db_dtor)(struct c_switch *sw, bool locked);
    void (*fp_db_dump)(struct c_switch *sw,
                       void *arg,
                       void (*show_fn)(void *arg,
                       struct c_fl_entry_ *ent));
};

#if 0
typedef struct c_sw_port {
    uint32_t port_no;
    uint8_t hw_addr[OFP_ETH_ALEN];
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */

#define C_MLPC_DOWN 0x1
#define C_MLPC_NO_STP 0x2
    uint32_t config;        
#define C_MLPS_DOWN 0x1
    uint32_t state;         

    uint32_t of_config;
    uint32_t of_state;

    uint32_t curr;          /* Current features. */
    uint32_t advertised;    /* Features being advertised by the port. */
    uint32_t supported;     /* Features supported by the port. */
    uint32_t peer;          /* Features advertised by peer. */
} c_sw_port_t;
#endif

typedef struct c_fl_entry_hdr_
{
    c_rw_lock_t lock;
    uint8_t c_fl_ent_type;
    uint64_t flags;
    uint16_t prio;
    bool installed;
    c_atomic_t ref;
#define C_FL_IDLE_DFL_TIMEO (120)
    uint16_t i_timeo;
#define C_FL_HARD_DFL_TIMEO (900)
    uint16_t h_timeo;
    uint32_t xid;
    uint64_t cookie;
}c_fl_entry_hdr_t;

#define FL_INSTALLED fl_hdr.installed
#define FL_LOCK fl_hdr.lock
#define FL_ENT_TYPE fl_hdr.c_fl_ent_type
#define FL_REF fl_hdr.ref
#define FL_FLAGS fl_hdr.flags
#define FL_PRIO fl_hdr.prio
#define FL_WILDCARDS fl_hdr.wildcards
#define FL_ITIMEO fl_hdr.i_timeo
#define FL_HTIMEO fl_hdr.h_timeo
#define FL_COOKIE fl_hdr.cookie
#define FL_XID fl_hdr.xid

typedef struct c_fl_entry_stats_
{
    uint64_t byte_count;
    uint64_t pkt_count;                

    uint32_t duration_sec;
    uint32_t duration_nsec;

    double pps;
    double bps;

#define C_FL_STAT_TIMEO (5)
    time_t last_refresh;
    time_t last_scan;
}c_fl_entry_stats_t;

typedef struct c_fl_entry_
{
    c_fl_entry_hdr_t fl_hdr;
    struct c_switch *sw;

    struct flow fl;
    struct flow fl_mask;

    union {
        GSList *cloned_list;
        void *parent;
    };

    c_atomic_t app_ref;
    GSList *app_owner_list;

    size_t action_len;
    struct ofp_action_header *actions;

    GSList *groups;
    GSList *meters;

#define C_FL_STALE_TIMEO (17)
    time_t stale_time;

    c_fl_entry_stats_t fl_stats;
}c_fl_entry_t;

typedef struct c_flow_tbl_
{
#define C_TBL_EXM  (0)
#define C_TBL_RULE (1)
#define C_TBL_UNK  (2)
    uint8_t c_fl_tbl_type;
    uint8_t hw_tbl_active; /* +ve: Active, 0: Inactive */ 
    uint8_t v_tbl; /* Virtual Table Id */
    uint32_t sw_active_entries;
    uint32_t hw_active_count;
    uint64_t hw_lookup_count;
    uint64_t hw_matched_count;

    union {
        GHashTable *exm_fl_hash_tbl;
        GSList *rule_fl_tbl; /* Would change */
    };
    struct of_flow_tbl_props *props;
    void (*dtor)(void *sw, void *tbl);
} c_flow_tbl_t;

#define C_SWITCH_SUPPORTS_GROUP(sw) ((sw)->ofp_ctors && \
                                     (sw)->ofp_ctors->group_add && \
                                     (sw)->ofp_ctors->group_del && \
                                     (sw)->ofp_ctors->group_validate)
struct c_switch_group
{
    struct c_switch *sw;
    void *app_owner;
    c_atomic_t ref;
    uint32_t group;
    uint8_t type;
    uint8_t flags;
    struct of_act_vec_elem *act_vectors[OF_MAX_ACT_VECTORS];
    size_t act_vec_len;

    /* Stats */
    bool installed;
#define C_GRP_STAT_TIMEO  (4)
    time_t last_scan;
    time_t last_seen;
#define C_GRP_STALE_TIMEO (20) 
    time_t stale_time;

#define C_GRP_EXP_TIMEO (10)
    time_t last_expired;
#define C_GRP_DEAD_EXPIRE_CNT (10)
    uint32_t try_expire_cnt;

    uint64_t byte_count;
    uint64_t packet_count;
    uint32_t duration_sec;
    uint32_t duration_nsec;
};
typedef struct c_switch_group c_switch_group_t;

#define C_SWITCH_SUPPORTS_METER(sw) ((sw)->ofp_ctors && \
                                     (sw)->ofp_ctors->meter_add && \
                                     (sw)->ofp_ctors->meter_del)

struct c_switch_meter
{
    struct c_switch *sw;
    void *app_owner;
    c_atomic_t ref;
    uint32_t meter;
    uint16_t flags;
    uint8_t cflags;
    struct of_meter_band_elem *meter_bands[OF_MAX_ACT_VECTORS];
    size_t meter_nbands;

    /* Stats */
    bool installed;
#define C_METER_STAT_TIMEO (3)
    time_t last_scan;
    time_t last_seen;
#define C_METER_STALE_TIMEO (20)
    time_t stale_time;

#define C_METER_EXP_TIMEO (10)
    time_t last_expired;
#define C_METER_DEAD_EXPIRE_CNT (10)
    uint32_t try_expire_cnt;

    uint32_t flow_count;
    uint64_t byte_count;
    uint64_t packet_count;
    uint32_t duration_sec;
    uint32_t duration_nsec;
};
typedef struct c_switch_meter c_switch_meter_t;

enum switch_clone_type{
    SW_CLONE_USE,
    SW_CLONE_DENY,
    SW_CLONE_OLD
};

/* controller's switch abstraction */
struct c_switch 
{
    void *ctx __aligned;   
    struct c_switch_fp_ops  fp_ops; 
    ctrl_hdl_t *c_hdl;                      /* Controller handle */ 
    size_t ofp_rx_handler_sz;               /* Handler array sz */
    c_ofp_rx_handler_t *ofp_rx_handlers;    /* OF protocol RX handler CBs */
    c_ofp_ctors_t *ofp_ctors;               /* OF protocol msg ctors */ 
    c_ofp_proc_helpers_t *ofp_priv_procs;   /* Extended OF handlers */
#define DPID datapath_id
    unsigned long long int  datapath_id;	/* DP Identifier */
    void *app_flow_tbl;   
    c_flow_tbl_t exm_flow_tbl;
    c_flow_tbl_t rule_flow_tbls[C_MAX_RULE_FLOW_TBLS];
    uint8_t xphys_map_tbl[C_MAX_RULE_FLOW_TBLS];
    GHashTable *fl_cookies;                 /* Flow index hash */
    uint32_t fl_idx_cookie;                 /* Flow cookie generation hint */
    GSList *app_list;                       /* App list interested in switch */
    GSList *app_eventq;                     /* App event queue */
   
    c_conn_t conn;                          /* Man switch connection descriptor */

    c_atomic_t ref;
    c_rw_lock_t lock;
    time_t last_refresh_time;
    time_t last_sample_time;
    time_t last_fp_aging_time;

    GHashTable *sw_ports;                   /* Switch port hash table */
    GHashTable *groups;                     /* Groups */
    GHashTable *meters;                     /* Meter tables */        

    GSList *exp_list;                       /* Expired entries */

    void *group_features;                   /* Group features */
    size_t group_feat_len;                  /* Group features length */
    void *meter_features;                   /* Meter features */
    size_t meter_feat_len;                  /* Meter features length */

    void *fp_owner;                         /* Owner of FP handling */
    uint32_t fp_type;                       /* Fast path handling mode */
    uint64_t switch_state;                  /* Switch connection state */
    time_t last_feat_probed;                /* Last timestamp of feature probe */ 
    time_t start_probe;                     /* First timestamp of probe */ 
    time_t last_probed;                     /* Last timestamp of probe */ 
    int n_tbl_probed;                       /* Number of flow tables probed */

    uint32_t n_buffers;                     /* Max packets buffered at once. */
    int alias_id;                           /* Canonical switch id */
    uint8_t version;                        /* OFP version */
    uint8_t n_tables;                       /* Number of tables supported by
                                              datapath. */
    uint32_t actions;                       /* Bitmap of supported
                                              "ofp_action_type"s. */
    uint32_t capabilities;                  /* Switch capabilites */
    uint32_t n_ports;                       /* Number of active ports */

    uint32_t cp_meter_id;                   /* Meter-id used to meter CP connection */

#define SW_HA_NONE  (0)
#define SW_HA_CONNECTED (1)
#define SW_HA_SYNCED (2)
#define SW_HA_VIRT (3)
    uint32_t ha_state;                      /* Switch HA state */
    c_conn_t ha_conn;                       /* Switch HA Conn descriptor */
    int reinit_fd;
    time_t last_sync_req;

    bool rx_lim_on;                         /* RX rate-limiter on-off */
    bool tx_lim_on;                         /* TX rate-limiter on-off */
    struct c_rlim_dat rx_rlim;              /* RX packet-in rate-limiter */
    struct c_rlim_dat tx_rlim;              /* TX packet-out rate-limiter */
    uint64_t rx_pkt_in_dropped;             /* Rx packet-ins rate-limited */
    uint64_t tx_pkt_out_dropped;            /* TX packet-out rate-limited */  

    uint64_t dump_mask[4];                  /* Mask of dump-able messages */
    bool tx_dump_en;                        /* RX OFP dump parser on-off */
    bool rx_dump_en;                        /* TX OFP dump parser on-off */

    int  debug_flag;                        /* For debugging switches */
    struct cbuf *sav_b;                     /* Scratch buffer */
};
typedef struct c_switch c_switch_t;

struct c_port {
    struct c_sw_port sw_port;
    void *port_stats;
    size_t port_stat_len;
    GHashTable *pkt_qs;
#define C_Q_STAT_CONFIG_TIMEO (3)
    time_t last_q_conf;
};
typedef struct c_port c_port_t;

struct c_pkt_q {
    uint32_t qid;
    uint32_t port_no;
    void *q_stats;
    size_t q_stats_len;
    void *q_prop;
    size_t q_prop_len;
#define C_Q_STAT_TIMEO (6)
    time_t last_seen;
    time_t last_stats_query;
};
typedef struct c_pkt_q c_pkt_q_t;

struct c_pkt_q_iter_arg
{
    GSList *qlist;
    c_switch_t *sw;
};

struct c_sw_replay_q_ent
{
    c_switch_t *sw;
    struct cbuf *b;
};

struct c_sw_expired_ent
{
    void *app;
    struct cbuf *b;
};

struct c_buf_iter_arg
{
    uint8_t *wr_ptr;
    void *data;
    uint32_t max_blocks;
    uint64_t dpid;
};

static inline void
g_slist_cmn_ent_free(void *arg)
{
    free(arg);
}

static inline struct c_port *
__c_switch_port_find(c_switch_t *sw, uint32_t port_no)
{
    if (sw->sw_ports) {
        return g_hash_table_lookup(sw->sw_ports, &port_no);
    } else {
        return NULL;
    }
}

static inline bool
__c_switch_needs_probe(c_switch_t *sw, uint64_t state)
{
    time_t ctime = time(NULL);
    if (!(sw->switch_state & state) ||
        (sw->switch_state & state && 
        (!sw->last_probed ||
         (ctime - sw->last_probed  > C_SWITCH_PROBE_REP_TIMEO))))
        return true;
    return false;
}

static inline bool
__c_switch_port_valid(c_switch_t *sw, uint32_t port)
{
    if (port >=  OF_MAX_LOG_PORTS) {
        return true;
    }
    return port && __c_switch_port_find(sw, port) ? true : false;
}

static inline bool
c_ha_master(ctrl_hdl_t *hdl)
{
    return hdl->ha_state == C_HA_STATE_MASTER ? true: false;
}

static inline bool
c_ha_slave(ctrl_hdl_t *hdl)
{
    return hdl->ha_state == C_HA_STATE_SLAVE ? true: false;
}


#ifdef C_VIRT_CON_HA
static inline bool
c_switch_is_virtual(c_switch_t *sw)
{
    return sw->ha_state == SW_HA_VIRT ? true : false;
}

static inline bool
c_switch_of_master_check(ctrl_hdl_t *hdl)
{   
    return true;
}

static inline bool
c_switch_needs_state_sync(ctrl_hdl_t *hdl)
{
    return false;
}
#else
static inline bool
c_switch_is_virtual(c_switch_t *sw UNUSED)
{
    return false;
}

static inline bool
c_switch_of_master_check(ctrl_hdl_t *hdl)
{
    return hdl->ha_state == C_HA_STATE_SLAVE ? false: true;  
}

static inline bool
c_switch_needs_state_sync(ctrl_hdl_t *hdl)
{
    return hdl->ha_state == C_HA_STATE_SLAVE ? true : false;
}
#endif

void    c_l2fdb_show(c_switch_t *sw, void *arg,
             void (*show_fn)(void *arg, c_fl_entry_t *ent));
int     c_l2_lrn_fwd(c_switch_t *sw, struct cbuf *b, void *opi, size_t pkt_len, 
                     struct c_pkt_in_mdata *arg, uint32_t in_port); 
int     c_l2_port_status(c_switch_t *sw, uint32_t port,
                         uint32_t cfg, uint32_t state,
                         struct c_port_cfg_state_mask *mask);
void    c_l2fdb_aging(c_switch_t *sw, uint32_t port, bool check_port);
int     c_l2fdb_init(c_switch_t *sw, bool locked);
void    c_l2fdb_destroy(c_switch_t *sw, bool locked);
void    c_l2_topo_change(c_switch_t *sw, uint64_t new_state, bool locked);
void    c_ipc_msg_rcv(void *ctx_arg, struct cbuf *buf);
int     c_send_unicast_ipc_msg(int fd, void *msg);
void    *alloc_ipc_msg(uint8_t ipc_type, uint16_t ipc_msg_type);

c_app_info_t *c_app_alloc(void *ctx);
c_app_info_t *c_app_get(ctrl_hdl_t *c_hdl, char *app_name);
void    c_app_put(c_app_info_t *app);
bool    c_app_hdr_valid(void *h_arg);
int     c_builtin_app_start(void *arg);
void    c_signal_app_event(c_switch_t *sw, void *b, c_app_event_t event,
                           void *app_arg, void *priv, bool locked);
int     __mul_app_workq_handler(void *wq_arg, struct cbuf *b);
void    c_app_workq_fb_thread_read(evutil_socket_t fd, short events, void *arg);
int     __mul_app_command_handler(void *app_arg, struct cbuf *b);
void    c_aux_app_init(void *app_arg);

c_fl_entry_t *c_do_rule_lookup_with_detail(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio);

static inline void 
c_app_ref(void *app_arg)
{
    c_app_info_t *app = app_arg;
    atomic_inc(&app->ref, 1);
}

static inline void 
c_app_unref(void *app_arg)
{
    c_app_info_t *app = app_arg;
    atomic_dec(&app->ref, 1);
}

static inline uint8_t
c_buf_ofp_ver(struct cbuf *b)
{
    return b?((struct ofp_header *)CBUF_DATA(b))->version:
           0;
}

static inline uint32_t
c_buf_ofp_xid(struct cbuf *b)
{
    return b ? ((struct ofp_header *)CBUF_DATA(b))->xid : 0;
}

#ifdef C_PROF_SUPPORT
uint64_t curr_time;

#define start_prof(X) \
do { \
    if (((struct c_worker_ctx *)(X))->thread_idx == 1) \
        curr_time = g_get_monotonic_time(); \
} while(0)

#define get_prof(X, str)  \
do { \
    if (((struct c_worker_ctx *)(X))->thread_idx == 1) { \
        printf ("%s: time %lluus\n", str, g_get_monotonic_time() - \
                curr_time); \
        curr_time = g_get_monotonic_time(); \
    } \
}while (0)
#else
#define start_prof(X)
#define get_prof(X, str)
#endif

#endif
