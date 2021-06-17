/*
 *  mul_app_interface.h: MUL application interface public headers
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
#ifndef __MUL_APP_INTERFACE_H__
#define __MUL_APP_INTERFACE_H__
#include "uuid.h"

typedef void (*initcall_t)(void *);
extern initcall_t __start_modinit_sec, __stop_modinit_sec;
#define data_attr         __attribute__ ((section ("modinit_sec")))
#define module_init(x)   initcall_t _##x data_attr = x

#ifndef SWIG
extern initcall_t __start_modvtyinit_sec, __stop_modvtyinit_sec;
#define vty_attr         __attribute__ ((section ("modvtyinit_sec")))
#define module_vty_init(x)  initcall_t _##x vty_attr = x
#endif

/* Registered application names */
#define HELLO_APP_NAME "mul-hello"
#define MY_CONTROLLER_APP_NAME "mul-my_controller"
#define FAB_APP_NAME "mul-fabric"
#define CLI_APP_NAME "mul-cli"
#define L2SW_APP_NAME "mul-l2sw"
#define TR_APP_NAME "mul-tr"
#define MAKDI_APP_NAME "mul-makdi"
#define FEMTO_APP_NAME "mul-femto"
#define PRISM_APP_NAME "prism"
#define CONX_APP_NAME "ConX"
#define DRONE_APP_NAME "Drone"

#define FAB_APP_COOKIE 0x1111 
#define CLI_APP_COOKIE 0x0
#define L2SW_APP_COOKIE 0x5555 
#define TR_APP_COOKIE 0x6666 
#define MAKDI_APP_COOKIE 0x2222 
#define FEMTO_APP_COOKIE 0x0 
#define PRISM_APP_COOKIE 0x3333 
#define CONX_APP_COOKIE 0x4444 
#define MUL_MAX_SERVICE_NUM 11 

/* Controller app event notifications */
typedef enum c_app_event {
    C_DP_REG,
    C_DP_UNREG,
    C_PACKET_IN,
    C_PORT_CHANGE,
    C_FLOW_REMOVED,
    C_FLOW_MOD_FAILED,
    C_HA_STATE,
    C_VENDOR_MSG,
    C_TR_STATUS,
    C_GROUP_MOD_FAILED,
    C_METER_MOD_FAILED,
    C_EVENT_MAX
} c_app_event_t;
#define C_APP_ALL_EVENTS  ((1 << C_EVENT_MAX) - 1) 

#define C_OFP_VERSION             (0xfe)
#define C_OFPT_BASE               (0xc0)
#define C_OFPT_SWITCH_ADD         (OFPT_FEATURES_REPLY)
#define C_OFPT_PACKET_IN          (OFPT_PACKET_IN)
#define C_OFPT_VENDOR_MSG         (OFPT_VENDOR)
#define C_OFPT_PACKET_OUT         (OFPT_PACKET_OUT)
#define C_OFPT_PORT_STATUS        (OFPT_PORT_STATUS)
#define C_OFPT_SWITCH_DELETE      (C_OFPT_BASE)
#define C_OFPT_FLOW_MOD           (OFPT_FLOW_MOD)
#define C_OFPT_PACKET_IN          (OFPT_PACKET_IN)
#define C_OFPT_FLOW_REMOVED       (OFPT_FLOW_REMOVED)
#define C_OFPT_ERR_MSG            (OFPT_ERROR)
#define C_OFPT_REG_APP            (C_OFPT_BASE + 1)
#define C_OFPT_UNREG_APP          (C_OFPT_BASE + 2)
#define C_OFPT_RECONN_APP         (C_OFPT_BASE + 3)
#define C_OFPT_NOCONN_APP         (C_OFPT_BASE + 4)
#define C_OFPT_SET_FPOPS          (C_OFPT_BASE + 5)
#define C_OFPT_GROUP_MOD          (C_OFPT_BASE + 6)
#define C_OFPT_METER_MOD          (C_OFPT_BASE + 7)
#define C_OFPT_AUX_CMD            (C_OFPT_BASE + 8)
#define C_OFPT_PORT_MOD           (C_OFPT_BASE + 9)

struct c_ofp_switch_delete {
    struct ofp_header header;
    uint64_t          datapath_id;
    uint32_t          sw_alias;
    uint32_t          pad;
};
OFP_ASSERT(sizeof(struct c_ofp_switch_delete) == (24));

struct c_ofp_vendor_message {
    struct ofp_header header;
    uint64_t          datapath_id;
    uint32_t          sw_alias;
    uint32_t          pad;
    uint8_t           data[0];
};
OFP_ASSERT(sizeof(struct c_ofp_vendor_message) == (24));

struct c_ofp_send_vendor_message {
    struct ofp_header header;
    uint64_t          datapath_id;
    uint32_t          vendor_id;
    uint8_t           pad[4];
    uint8_t           data[0];
};
OFP_ASSERT(sizeof(struct c_ofp_send_vendor_message) == (24));

struct c_sw_port {
    uint32_t port_no;
    uint8_t hw_addr[OFP_ETH_ALEN];
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */

    uint16_t type;
    uint8_t pad[4];

#define C_MLPC_DOWN 0x1
#define C_MLPC_NO_STP 0x2
    uint32_t config;

#define C_MLPS_DOWN 0x1
    uint32_t state;

    uint32_t of_config;     /* Openflow port config */
    uint32_t of_state;      /* Openflow port state */

    uint32_t curr;          /* Current features. */
    uint32_t advertised;    /* Features being advertised by the port. */
    uint32_t supported;     /* Features supported by the port. */
    uint32_t peer;          /* Features advertised by peer. */

    uint32_t curr_speed;    /* Current speed */
    uint32_t max_speed;     /* Max speed */
};
OFP_ASSERT(sizeof(struct c_sw_port) == 72);

/* Switch Add message */
struct c_ofp_switch_add {
    struct ofp_header header;
    uint64_t datapath_id;   /* Datapath unique ID.  The lower 48-bits are for
                               a MAC address, while the upper 16-bits are
                               implementer-defined. */
    uint32_t sw_alias;
    uint32_t n_buffers;     /* Max packets buffered at once. */

    uint64_t state;         /* Switch state */
    uint32_t rx_rlim_pps;   /* RX rate-limit */
    uint32_t tx_rlim_pps;   /* TX rate-limit */

    uint8_t n_tables;       /* Number of tables supported by datapath. */
    uint8_t ver;            /* Switch's negotiated version */
    uint8_t rx_dump_en;     /* RX dump is enabled */
    uint8_t tx_dump_en;     /* TX dump is enabled */ 
    uint8_t pad1[4];        /* Align to 64-bits. */

    uint32_t capabilities;  /* Bitmap of support "ofp_capabilities". */
    uint32_t actions;       /* Deprecated */

    /* Port info.*/
    struct c_sw_port ports[0];  /* Port definitions.  The number of ports
                                   is inferred from the length field in
                                   the header. */
};
OFP_ASSERT(sizeof(struct c_ofp_switch_add) == 56);

struct c_ofp_port_status {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            sw_alias;
    uint32_t            config_mask;
    uint32_t            state_mask;
    uint8_t             reason;  /* One of common across OF versions */
    uint8_t             pad[7];  /* Align to 64-bits. */
    struct c_sw_port    desc;
};

// /* A physical port has changed in the datapath */
// struct ofp_port_status {
//     struct ofp_header header;
//     uint8_t reason;          /* One of OFPPR_*. */
//     uint8_t pad[7];          /* Align to 64-bits. */
//     struct ofp_phy_port desc;
// };

struct flow {
    uint32_t            in_port;      /* Input switch port. */
    uint16_t            dl_vlan;      /* Input VLAN id. */
    uint16_t            dl_type;      /* Ethernet frame type. */
    uint8_t             dl_dst[6];    /* Ethernet destination address. */
    uint8_t             dl_src[6];    /* Ethernet source address. */
    uint8_t             dl_vlan_pcp;  /* Input VLAN priority. */
#define C_FL_TBL_ID_DFL 0
    uint8_t             table_id;     /* Table-id in cases necessary */
    uint8_t             nw_tos;       /* IPv4 DSCP. */
    uint8_t             nw_proto;     /* IP protocol. */
    uint32_t            mpls_label;   /* MPLS Outer label */
    uint16_t            tp_src;       /* TCP/UDP source port. */
    uint16_t            tp_dst;       /* TCP/UDP destination port. */
    union {
        struct ip_flow {
            uint32_t    nw_src;       /* IP source address. */
            uint32_t    nw_dst;       /* IP destination address. */
        }ip;
        struct ipv6_flow {
            struct ipv6_addr nw_src;   /* Ipv6 source address. */
            struct ipv6_addr nw_dst;   /* IPv6 destination address. */
        }ipv6;
    };
    uint64_t            tunnel_id;    /* Tunnel-id */
    uint64_t            metadata;     /* Metadata */
    uint8_t             mpls_bos;     /* MPLS Outer label BOS field */
    uint8_t             mpls_tc;      /* MPLS Outer label EXP field */
#define FL_DFL_GW pad[0]
    uint8_t             pad[6];
};
OFP_ASSERT(sizeof(struct flow)==88);

struct c_ofp_packet_in {
    struct ofp_header header;
    uint64_t          datapath_id;   /* Switch id */  
    uint32_t          sw_alias;      /* Switch Alias id */
    uint32_t          buffer_id;     /* ID assigned by datapath. */
    struct flow       fl;
    uint32_t          in_port;       /* Port on which frame was received. */
    uint16_t          total_len;     /* Full length of frame. */
    uint8_t           reason;        /* Reason packet is being sent (one of OFPR_*) */
    uint8_t           pad;
    uint8_t           data[0];       /* Ethernet frame */
};
OFP_ASSERT(sizeof(struct c_ofp_packet_in) == (120));

struct c_ofp_flow_mod {
    struct ofp_header   header;
    uint64_t            datapath_id;

    struct flow         flow; 
    struct flow         mask; 
#define C_FL_ENT_STATIC     (0x1)   /* A static flow */
#define C_FL_ENT_CLONE      (0x2)   /* A cloned flow */
#define C_FL_ENT_LOCAL      (0x4)   /* A Local flow which is not installed in the switch 
                                       but only kept in local DB */
#define C_FL_ENT_NOCACHE    (0x8)   /* Push the flow to the switch without keeping in 
                                       local DB */
#define C_FL_ENT_NOT_INST   (0x8)   /* Flow was not installed */
#define C_FL_ENT_NOSYNC     (0x10)  /* Whether flow needs resyncing after HA event */ 
#define C_FL_ENT_GSTATS     (0x20)  /* Gather stats flor this flow */
#define C_FL_ENT_SWALIAS    (0x40)  /* Flow add should happen via switch alias-id rather
                                       than dpid */
#define C_FL_ENT_BARRIER    (0x80)  /* Send accompanying barrier message with flow mod */
#define C_FL_ENT_RESIDUAL   (0x100) /* Flow is residual flow read from switch */
#define C_FL_ENT_STALE      (0x200) /* Flow is stale */
#define C_FL_NO_ACK         (0x400) /* Dont wait for ACK after flow add */
#define C_FL_ENT_CTRL_LOCAL (0x800) /* Flow is meant for local controller delivery */
#define C_FL_ENT_TBL_PHYS   (0x1000) /* Table-id in flow should not be translated to 
                                        virtual table-id */
#define C_FL_ENT_RES_STALE  (0x2000) /* Force this entry to stale if no updates received 
                                        after switch re-add/reset */
    uint64_t             flags;
    uint8_t              pad0;
#define C_OFPC_ADD  0
#define C_OFPC_DEL  1
    uint8_t             command;
#define C_FL_PRIO_DFL  0
#define C_FL_PRIO_LDFL 1
#define C_FL_PRIO_FWD  2
#define C_FL_PRIO_DRP  3
#define C_FL_PRIO_EXM 65535
    uint16_t            priority;
    uint32_t            sw_alias;
    uint32_t            wildcards;
    uint16_t            itimeo;
    uint16_t            htimeo;
    uint32_t            oport;
    uint32_t            buffer_id;
    uint32_t            ogroup;
    uint16_t            mod_flags;
    uint8_t             pad1[2];
    uint32_t            cookie;
    uint32_t            seq_cookie;
    struct ofp_action_header actions[0];
};
OFP_ASSERT(sizeof(struct c_ofp_flow_mod) == (240));

struct c_ofp_flow_info {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            sw_alias;
    uint32_t            pad;
    struct flow         flow; 
    struct flow         mask; 
    uint64_t            flags;
    uint8_t             pad0;
    uint8_t             command;
    uint16_t            priority;
    uint32_t            wildcards;
    uint16_t            itimeo;
    uint16_t            htimeo;
    uint16_t            mod_flags;
    uint16_t            oport;
    uint32_t            buffer_id;
    uint32_t            pad1;
    uint64_t            byte_count;
    uint64_t            packet_count;
    uint32_t            duration_sec;
    uint32_t            duration_nsec;
#define C_FL_XPS_SZ 32
    uint8_t             bps[C_FL_XPS_SZ];
    uint8_t             pps[C_FL_XPS_SZ];
    struct ofp_action_header actions[0];
};
OFP_ASSERT(sizeof(struct c_ofp_flow_info) == (320));

// /* Body of reply to OFPST_FLOW request. */
// struct ofp_flow_stats {
//     uint16_t length;          /* Length of this entry. */
//     uint8_t table_id;         /* ID of table flow came from. */
//     uint8_t pad;
//     struct ofp_match match;   /* Description of fields. */
//     uint32_t duration_sec;    /* Time flow has been alive in seconds. */
//     uint32_t duration_nsec;   /* Time flow has been alive in nanoseconds beyond
//                                  duration_sec. */
//     uint16_t priority;        /* Priority of the entry. Only meaningful
//                                  when this is not an exact-match entry. */
//     uint16_t idle_timeout;    /* Number of seconds idle before expiration. */
//     uint16_t hard_timeout;    /* Number of seconds before expiration. */
//     uint8_t pad2[6];          /* Align to 64-bits. */
//     uint64_t cookie;          /* Opaque controller-issued identifier. */
//     uint64_t packet_count;    /* Number of packets in flow. */
//     uint64_t byte_count;      /* Number of bytes in flow. */
//     struct ofp_action_header actions[0]; /* Actions. */
// };

/* Flow removed (datapath -> controller). */
struct c_ofp_flow_removed {
    struct ofp_header   header;
    uint64_t            datapath_id;
    struct flow         flow;
    struct flow         mask;
    uint64_t            cookie;         /* Opaque controller-issued identifier.*/
    uint32_t            duration_sec;   /* Time flow was alive in seconds. */
    uint32_t            duration_nsec;  /* Time flow was alive in nanosecs beyond
                                           duration_sec. */               
    uint16_t            idle_timeout;   /* Idle timeout from original flow mod.*/
    uint16_t            priority;       /* Priority level of flow entry. */
    uint8_t             reason;         /* One of OFPRR_*. */             
 
    uint8_t             pad[3];         /* Align to 64-bits. */           
    uint64_t            packet_count;                                      
    uint64_t            byte_count;                                        
};  
OFP_ASSERT(sizeof(struct c_ofp_flow_removed) == 232);

struct c_ofp_bkt {
    uint16_t weight;
    uint16_t act_len;
    uint32_t ff_port;
    uint32_t ff_group;
    uint8_t  pad[4];
    struct ofp_action_header actions[0];
};
OFP_ASSERT(sizeof(struct c_ofp_bkt) == 16);

struct c_ofp_group_mod {
    struct ofp_header   header;
    uint64_t            datapath_id;

#define C_OFPG_ADD  0
#define C_OFPG_DEL  1
    uint8_t             command;
    uint8_t             type;      /* One of OFPGT_*. */
#define C_GRP_STATIC 0x1
#define C_GRP_GSTATS 0x2
#define C_GRP_EXPIRED 0x4
#define C_GRP_BARRIER_EN 0x8
#define C_GRP_NOT_INSTALLED 0x10
#define C_GRP_RESIDUAL 0x20
#define C_GRP_STALE 0x40
#define C_GRP_LOCAL 0x80
    uint8_t             flags;     
    uint8_t             pad;
    uint32_t            group_id;
    uint64_t            packet_count;
    uint64_t            byte_count;
    uint32_t            duration_sec;
    uint32_t            duration_nsec;
    struct c_ofp_bkt    buckets[0];
};
OFP_ASSERT(sizeof(struct c_ofp_group_mod) == 48);

struct c_ofp_meter_mod {
    struct ofp_header   header;
    uint64_t            datapath_id;

#define C_OFPMC_ADD 0
#define C_OFPMC_DEL 1
    uint8_t             command;
#define C_METER_STATIC 0x1
#define C_METER_GSTATS 0x2
#define C_METER_EXPIRED 0x4
#define C_METER_BARRIER_EN 0x8
#define C_METER_NOT_INSTALLED 0x10
#define C_METER_RESIDUAL 0x20
#define C_METER_STALE 0x40
    uint8_t             c_flags;     
    uint16_t            flags;      /* One of OFPMBT_*. */
    uint32_t            meter_id;
    uint64_t            byte_count;
    uint64_t            packet_count;
    uint32_t            flow_count;
    uint32_t            pad;
    uint32_t            duration_sec;
    uint32_t            duration_nsec;
    struct ofp_meter_band_header  bands[0];
};
OFP_ASSERT(sizeof(struct c_ofp_meter_mod) == 56);

struct c_ofp_port_mod {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            port_no;
    uint32_t            config;
    uint32_t            mask;
    uint8_t             pad[4];
};
OFP_ASSERT(sizeof(struct c_ofp_port_mod) == 32);

struct c_ofp_packet_out {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            buffer_id;    
    uint32_t            in_port;
    uint16_t            actions_len; 
    uint8_t             pad[6];
    struct ofp_action_header actions[0]; 
    /* uint8_t data[0]; */        /* Packet data.  The length is inferred
                                     from the length field in the header.
                                     (Only meaningful if buffer_id == -1.) */
};
OFP_ASSERT(sizeof(struct c_ofp_packet_out) == 32);

struct c_ofp_register_app {
    struct ofp_header   header;
#define C_MAX_APP_STRLEN  64 
    char                app_name[C_MAX_APP_STRLEN];
#define C_APP_ALL_SW        0x01
#define C_APP_REMOTE        0x02
#define C_APP_AUX_REMOTE    0x04
    uint32_t            app_flags;
    uint32_t            ev_mask;
    uint32_t            dpid;
    uint32_t            app_cookie;
    uint64_t            dpid_list[0];
};
OFP_ASSERT(sizeof(struct c_ofp_register_app) == 88);

struct c_ofp_unregister_app {
   struct ofp_header   header;
   char                app_name[C_MAX_APP_STRLEN];
  
};
OFP_ASSERT(sizeof(struct c_ofp_unregister_app) == 72);

struct c_ofp_set_fp_ops {
    struct ofp_header   header;
    uint64_t            datapath_id;
#define C_FP_TYPE_DFL 0
#define C_FP_TYPE_L2 1
    uint32_t            fp_type;
    uint32_t            pad;
}; 
OFP_ASSERT(sizeof(struct c_ofp_set_fp_ops) == 24);

struct c_ofp_async_config{
    uint64_t            datapath_id;
    uint32_t            packet_in_mask[2];
    uint32_t            port_status_mask[2];
    uint32_t            flow_removed_mask[2];
}; 
OFP_ASSERT(sizeof(struct c_ofp_set_fp_ops) == 24);

struct c_ofp_auxapp_cmd {
    struct ofp_header   header;

#define C_AUX_CMD_SUCCESS (0) 
#define C_AUX_CMD_ECHO (C_AUX_CMD_SUCCESS) 
#define C_AUX_CMD_MUL_CORE_BASE (1) 
#define C_AUX_CMD_MUL_GET_SWITCHES (C_AUX_CMD_MUL_CORE_BASE + 1) 
#define C_AUX_CMD_MUL_GET_SWITCHES_REPLY (C_AUX_CMD_MUL_CORE_BASE + 2) 
#define C_AUX_CMD_MUL_GET_SWITCH_DETAIL (C_AUX_CMD_MUL_CORE_BASE + 3) 
#define C_AUX_CMD_MUL_GET_APP_FLOW (C_AUX_CMD_MUL_CORE_BASE + 4)
#define C_AUX_CMD_MUL_GET_ALL_FLOWS (C_AUX_CMD_MUL_CORE_BASE + 5)
#define C_AUX_CMD_MUL_GET_GROUPS (C_AUX_CMD_MUL_CORE_BASE + 6)
#define C_AUX_CMD_MUL_GET_METERS (C_AUX_CMD_MUL_CORE_BASE + 7)
#define C_AUX_CMD_MUL_SWITCH_METER_FEAT (C_AUX_CMD_MUL_CORE_BASE + 8)
#define C_AUX_CMD_MUL_SWITCH_GROUP_FEAT (C_AUX_CMD_MUL_CORE_BASE + 9)
#define C_AUX_CMD_MUL_SWITCH_TABLE_FEAT (C_AUX_CMD_MUL_CORE_BASE + 10)
#define C_AUX_CMD_MUL_SWITCH_RLIM (C_AUX_CMD_MUL_CORE_BASE + 11)
#define C_AUX_CMD_MUL_SWITCH_GET_RLIM (C_AUX_CMD_MUL_CORE_BASE + 12)
#define C_AUX_CMD_MUL_SWITCH_SET_OF_DUMP (C_AUX_CMD_MUL_CORE_BASE + 13)
#define C_AUX_CMD_MUL_SWITCH_SET_STATS_STRAT (C_AUX_CMD_MUL_CORE_BASE + 14)
#define C_AUX_CMD_ASYNC_CONFIG (C_AUX_CMD_MUL_CORE_BASE + 15)
#define C_AUX_CMD_MUL_SWITCH_STATS_MODE_CONFIG (C_AUX_CMD_MUL_CORE_BASE + 16)
#define C_AUX_CMD_MUL_SWITCH_GET_TBL_STATS (C_AUX_CMD_MUL_CORE_BASE + 17)
#define C_AUX_CMD_MUL_SWITCH_PORT_QUERY (C_AUX_CMD_MUL_CORE_BASE + 18)
#define C_AUX_CMD_MUL_SWITCH_PORT_QQUERY (C_AUX_CMD_MUL_CORE_BASE + 19)
#define C_AUX_CMD_MUL_LOOP_STATUS (C_AUX_CMD_MUL_CORE_BASE + 20)
#define C_AUX_CMD_MUL_GET_FLOW (C_AUX_CMD_MUL_CORE_BASE + 21)
#define C_AUX_CMD_MUL_LOOP_EN (C_AUX_CMD_MUL_CORE_BASE + 22)
#define C_AUX_CMD_MUL_LOOP_DIS (C_AUX_CMD_MUL_CORE_BASE + 23)
#define C_AUX_CMD_MUL_TR_STATUS (C_AUX_CMD_MUL_CORE_BASE + 24)
#define C_AUX_CMD_MUL_GET_MATCHED_GROUP (C_AUX_CMD_MUL_CORE_BASE + 25)
#define C_AUX_CMD_MUL_GET_MATCHED_METER (C_AUX_CMD_MUL_CORE_BASE + 26)
#define C_AUX_CMD_MUL_MOD_UFLOW (C_AUX_CMD_MUL_CORE_BASE + 27)
#define C_AUX_CMD_MUL_GET_SWITCH_DESC (C_AUX_CMD_MUL_CORE_BASE + 28)

#define C_AUX_CMD_TR_BASE (C_AUX_CMD_MUL_CORE_BASE + 1000) 
#define C_AUX_CMD_TR_GET_NEIGH (C_AUX_CMD_TR_BASE + 1)
#define C_AUX_CMD_TR_NEIGH_STATUS (C_AUX_CMD_TR_GET_NEIGH + 1)

#define C_AUX_CMD_FAB_BASE (C_AUX_CMD_MUL_CORE_BASE + 2000) 
#define C_AUX_CMD_FAB_HOST_ADD (C_AUX_CMD_FAB_BASE + 1) 
#define C_AUX_CMD_FAB_HOST_DEL (C_AUX_CMD_FAB_BASE + 2) 
#define C_AUX_CMD_FAB_SHOW_ACTIVE_HOSTS (C_AUX_CMD_FAB_BASE + 3)
#define C_AUX_CMD_FAB_SHOW_INACTIVE_HOSTS (C_AUX_CMD_FAB_BASE + 4)
#define C_AUX_CMD_FAB_SHOW_ROUTES (C_AUX_CMD_FAB_BASE + 5)
#define C_AUX_CMD_FAB_ROUTE (C_AUX_CMD_FAB_BASE + 6)
#define C_AUX_CMD_FAB_SHOW_TENANT_NW (C_AUX_CMD_FAB_BASE + 7) 
#define C_AUX_CMD_FAB_PORT_TNID_ADD (C_AUX_CMD_FAB_BASE + 8)
#define C_AUX_CMD_FAB_PORT_TNID_DEL (C_AUX_CMD_FAB_BASE + 9)
#define C_AUX_CMD_FAB_PORT_TNID_SHOW (C_AUX_CMD_FAB_BASE + 10)
#define C_AUX_CMD_FAB_SHOW_HOST_ROUTE (C_AUX_CMD_FAB_BASE + 11)

#define C_AUX_CMD_HA_BASE (C_AUX_CMD_MUL_CORE_BASE + 3000)
#define C_AUX_CMD_HA_STATE (C_AUX_CMD_HA_BASE + 1)
#define C_AUX_CMD_HA_REQ_STATE (C_AUX_CMD_HA_BASE + 2)
#define C_AUX_CMD_HA_STATE_RESP (C_AUX_CMD_HA_BASE + 3)
#define C_AUX_CMD_HA_SYNC_REQ  (C_AUX_CMD_HA_BASE + 4)
#define C_AUX_CMD_HA_SYNC_DONE  (C_AUX_CMD_HA_BASE + 5)

#define C_AUX_CMD_MAKDI_BASE (C_AUX_CMD_MUL_CORE_BASE + 4000) 
#define C_AUX_CMD_MAKDI_USER_ADD (C_AUX_CMD_MAKDI_BASE + 1) 
#define C_AUX_CMD_MAKDI_USER_DEL (C_AUX_CMD_MAKDI_BASE + 2) 
#define C_AUX_CMD_MAKDI_SHOW_USER (C_AUX_CMD_MAKDI_BASE + 3) 
#define C_AUX_CMD_MAKDI_USER (C_AUX_CMD_MAKDI_BASE + 4) 

#define C_AUX_CMD_MAKDI_SERVICE_ADD (C_AUX_CMD_MAKDI_BASE + 5)
#define C_AUX_CMD_MAKDI_SERVICE_DEL (C_AUX_CMD_MAKDI_BASE + 6)
#define C_AUX_CMD_MAKDI_SHOW_SERVICE (C_AUX_CMD_MAKDI_BASE + 7)
#define C_AUX_CMD_MAKDI_NFV_GROUP_ADD (C_AUX_CMD_MAKDI_BASE + 8)
#define C_AUX_CMD_MAKDI_NFV_GROUP_DEL (C_AUX_CMD_MAKDI_BASE + 9)
#define C_AUX_CMD_MAKDI_SHOW_NFV_GROUP (C_AUX_CMD_MAKDI_BASE + 10)
#define C_AUX_CMD_MAKDI_NFV_ADD (C_AUX_CMD_MAKDI_BASE + 11)
#define C_AUX_CMD_MAKDI_NFV_DEL (C_AUX_CMD_MAKDI_BASE + 12)
#define C_AUX_CMD_MAKDI_SHOW_NFV (C_AUX_CMD_MAKDI_BASE + 13)
#define C_AUX_CMD_MAKDI_SERVICE_CHAIN_ADD (C_AUX_CMD_MAKDI_BASE + 14)
#define C_AUX_CMD_MAKDI_SERVICE_CHAIN_DEL (C_AUX_CMD_MAKDI_BASE + 15)
#define C_AUX_CMD_MAKDI_SHOW_SERVICE_CHAIN (C_AUX_CMD_MAKDI_BASE + 16)
#define C_AUX_CMD_MAKDI_DEFAULT_SERVICE_ADD (C_AUX_CMD_MAKDI_BASE + 17)
#define C_AUX_CMD_MAKDI_DEFAULT_SERVICE_DEL (C_AUX_CMD_MAKDI_BASE + 18)
#define C_AUX_CMD_MAKDI_SHOW_DEFAULT_SERVICE (C_AUX_CMD_MAKDI_BASE + 19)
#define C_AUX_CMD_MAKDI_NFV_STATS (C_AUX_CMD_MAKDI_BASE + 20)
#define C_AUX_CMD_MAKDI_SERVICE_STATS (C_AUX_CMD_MAKDI_BASE + 21)
#define C_AUX_CMD_MAKDI_USER_STATS (C_AUX_CMD_MAKDI_BASE + 22)
#define C_AUX_CMD_MAKDI_NFV_STATS_ALL (C_AUX_CMD_MAKDI_BASE + 23)
#define C_AUX_CMD_MAKDI_SERVICE_STATS_ALL (C_AUX_CMD_MAKDI_BASE + 24)
#define C_AUX_CMD_MAKDI_USER_STATS_ALL (C_AUX_CMD_MAKDI_BASE + 25)
#define C_AUX_CMD_MAKDI_SHOW_SERVICE_CHAIN_ALL (C_AUX_CMD_MAKDI_BASE + 26)

#define C_AUX_CMD_CONX_BASE (C_AUX_CMD_MUL_CORE_BASE + 5000)
#define C_AUX_CMD_CONX_ADD_UFLOW (C_AUX_CMD_CONX_BASE + 1)
#define C_AUX_CMD_CONX_DEL_UFLOW (C_AUX_CMD_CONX_BASE + 2)
#define C_AUX_CMD_CONX_STALE (C_AUX_CMD_CONX_BASE + 3)
    uint32_t            cmd_code;
    uint32_t            pad;
    uint8_t             data[0];
};
OFP_ASSERT(sizeof(struct c_ofp_auxapp_cmd) == 16);

struct c_ofp_req_dpid_attr {
    uint64_t            datapath_id;
};
OFP_ASSERT(sizeof(struct c_ofp_req_dpid_attr) == 8);

struct c_ofp_group_info {
    uint64_t            datapath_id;
    uint32_t            group_id;
    uint32_t            pad;
};
OFP_ASSERT(sizeof(struct c_ofp_group_info) == 16);

struct c_ofp_port_neigh {
    uint16_t            port_no;
#define COFP_NEIGH_SWITCH 0x1
    uint16_t            neigh_present; 
    uint16_t            neigh_port;
    uint16_t            pad;
    uint64_t            neigh_dpid;
};
OFP_ASSERT(sizeof(struct c_ofp_port_neigh) == 16);

struct c_ofp_switch_neigh {
    struct c_ofp_req_dpid_attr switch_id;
    uint8_t                    data[0]; 
};
OFP_ASSERT(sizeof(struct c_ofp_switch_neigh) == 8);

#define SW_INIT                     (0)
#define SW_OFP_NEGOTIATED           (0x1)
#define SW_REGISTERED               (0x2)
#define SW_DEAD                     (0x4)
#define SW_REINIT                   (0x8)
#define SW_REINIT_VIRT              (0x10)
#define SW_OFP_PORT_FEAT            (0x20)
#define SW_OFP_TBL_FEAT             (0x40)
#define SW_OFP_MET_FEAT             (0x80)
#define SW_OFP_GRP_FEAT             (0x100)
#define SW_HA_SYNCD_REQ             (0x200)
#define SW_BULK_FLOW_STATS          (0x400)
#define SW_BULK_GRP_STATS           (0x800)
#define SW_BULK_METER_CONF_STATS    (0x1000)
#define SW_PORT_STATS_ENABLE        (0x2000)
#define SW_PUBLISHED                (0x4000)
#define SW_FLOW_PROBED              (0x8000)
#define SW_GROUP_PROBED             (0x10000)
#define SW_METER_PROBED             (0x20000)
#define SW_FLOW_PROBE_DONE          (0x80000)
#define SW_GROUP_PROBE_DONE         (0x100000)
#define SW_METER_PROBE_DONE         (0x200000)
#define SW_VTBL_MAP_DONE            (0x400000)
#define MAX_SERVICE_NAME    64

struct c_ofp_switch_brief {
    struct c_ofp_req_dpid_attr switch_id;
    uint32_t                   n_ports;
    uint32_t                   res;
    uint64_t                   state;
#define OFP_CONN_DESC_SZ (32)
    char                       conn_str[OFP_CONN_DESC_SZ];
};
OFP_ASSERT(sizeof(struct c_ofp_switch_brief) == 56);

struct c_ofp_switch_feature_common {
    uint64_t                   datapath_id;
    uint8_t                    table_id;
    uint8_t                    pad[7];
    uint8_t                    data[0];
};
OFP_ASSERT(sizeof(struct c_ofp_switch_feature_common) == 16);

struct c_ofp_switch_rlim {
    uint64_t                   datapath_id;
    uint32_t                   is_rx;
    uint32_t                   pps;
};
OFP_ASSERT(sizeof(struct c_ofp_switch_rlim) == 16);

struct c_ofp_switch_of_dump {
    uint64_t                   datapath_id;
    uint32_t                   rx_enable;
    uint32_t                   tx_enable;
    uint64_t                   dump_mask[4];
};
OFP_ASSERT(sizeof(struct c_ofp_switch_of_dump) == 48);

struct c_ofp_switch_stats_strategy {
    uint64_t                   datapath_id;
    uint32_t                   fl_bulk_enable;
    uint32_t                   grp_bulk_enable;
    uint32_t                   meter_bulk_config_enable;
    uint32_t                   meter_bulk_enable;
};
OFP_ASSERT(sizeof(struct c_ofp_switch_stats_strategy) == 24);

struct c_ofp_switch_stats_mode_config {
    uint64_t                   datapath_id;
#define FLOW_STATS_ENABLE       0x0001
#define GROUP_STATS_ENABLE      0x0002
#define METER_STATS_ENABLE      0x0004
#define PORT_STATS_ENABLE       0x0008
    uint32_t                   stats_mode;
    uint32_t                   pad;
};
OFP_ASSERT(sizeof(struct c_ofp_switch_stats_mode_config) == 16);

struct c_ofp_switch_table_stats {
    uint64_t                   datapath_id;
    uint8_t                    table_id;
    uint8_t                    pad[3];
    uint32_t                   active_count;
    uint64_t                   lookup_count;
    uint64_t                   matched_count;
};
OFP_ASSERT(sizeof(struct c_ofp_switch_table_stats) == 32);

struct c_ofp_switch_port_query {
    uint64_t                   datapath_id;
    uint32_t                   port_no;
    uint32_t                   qid;
    uint32_t                   stats_len;
    uint32_t                   pad;
    uint8_t                    data[0];
};
OFP_ASSERT(sizeof(struct c_ofp_switch_port_query) == 24);

struct c_ofp_host_mod {
    struct c_ofp_req_dpid_attr switch_id;
    uuid_t                     tenant_id; 
    uuid_t                     network_id; 
    struct flow                host_flow;
};
OFP_ASSERT(sizeof(struct c_ofp_host_mod) == 128);

struct c_ofp_port_tnid_mod {
    uint64_t		       datapath_id; 
    uint32_t		       port;
    uint32_t                   pad;
    uuid_t                     tenant_id; 
    uuid_t                     network_id;
};  
OFP_ASSERT(sizeof(struct c_ofp_port_tnid_mod) == 48);

struct c_ofp_tenant_nw_mod {
    uuid_t 		       tenant_id;
    uuid_t		       network_id;
};
OFP_ASSERT(sizeof(struct c_ofp_tenant_nw_mod) == 32 );

struct c_ofp_route {
    struct c_ofp_host_mod      src_host;
    struct c_ofp_host_mod      dst_host;
    uint8_t                    route_links[0];
};
OFP_ASSERT(sizeof(struct c_ofp_route) == 256);

struct c_ofp_route_link {
    uint64_t                   datapath_id;
    uint16_t                   src_link;
    uint16_t                   dst_link; 
    uint32_t                   pad;
};
OFP_ASSERT(sizeof(struct c_ofp_route_link) == 16);

struct c_ofp_ha_state {
    uint32_t                   ha_sysid;
#define C_HA_STATE_NONE (0)
#define C_HA_STATE_CONNECTED (1)
#define C_HA_STATE_MASTER (2)
#define C_HA_STATE_SLAVE (3)
#define C_HA_STATE_CONFLICT (4)
#define C_HA_STATE_NOHA (5)
    uint32_t                   ha_state;
    uint64_t                   gen_id;
};
OFP_ASSERT(sizeof(struct c_ofp_ha_state) == 16);

struct c_ofp_loop_status_mod {
#define C_LOOP_STATE_NONE (0)
#define C_LOOP_STATE_LD (1)
#define C_LOOP_STATE_CONV (2)
    uint64_t                   loop_status;
};
OFP_ASSERT(sizeof(struct c_ofp_loop_status_mod) == 8);

struct c_ofp_tr_status_mod {
#define C_RT_APSP_NONE (0)
#define C_RT_APSP_INIT (1)
#define C_RT_APSP_ADJ_INIT (2)
#define C_RT_APSP_RUN  (3) 
#define C_RT_APSP_CONVERGED (4)
    uint64_t                   tr_status;
};
OFP_ASSERT(sizeof(struct c_ofp_tr_status_mod) == 8);

struct c_ofp_fl_mod_info {
    struct flow  flow;
    uint64_t     datapath_id;
    uint32_t     out_port;
    uint32_t     pad;
};
OFP_ASSERT(sizeof(struct c_ofp_fl_mod_info) == 104);

enum user_level_type {
    USER_LEVEL_PREMIUM,
    USER_LEVEL_GOLD,
    USER_LEVEL_DEFAULT
};

struct c_ofp_s_chain_mod {
    struct c_ofp_host_mod      user_info;
    uint64_t                   num_nfvs;
#define MAX_NFV 10
#define MAX_NFV_NAME 16
#define MAX_SC 100
#define MAX_SERVICE 5
    char                       nfv_list[MAX_NFV][MAX_NFV_NAME];
    char                       service[MAX_NFV_NAME];
};
OFP_ASSERT(sizeof(struct c_ofp_s_chain_mod) == 312);

struct c_ofp_default_s_chain_mod {
    uint16_t                   num_nfvs;
    uint16_t                    level;
    char                       nfv_list[MAX_NFV][MAX_NFV_NAME];
    char                       service[MAX_NFV_NAME];
};
OFP_ASSERT(sizeof(struct c_ofp_default_s_chain_mod) == 180);

struct c_ofp_s_chain_nfv_info {
    uint64_t                    dpid;
    char                        nfv[MAX_NFV_NAME];
    char                        nfv_group[MAX_NFV_NAME];
    uint16_t                    oif;
    uint16_t                    iif;
    uint8_t                     pad[4];
};
OFP_ASSERT(sizeof(struct c_ofp_s_chain_nfv_info) == 48);

struct c_ofp_s_chain_nfv_list {
    uint64_t                        num_nfvs;
    struct c_ofp_s_chain_nfv_info   nfv_info[MAX_NFV]; 
};
OFP_ASSERT(sizeof(struct c_ofp_s_chain_nfv_list) == 488);

struct c_ofp_s_chain_info {
    struct c_ofp_host_mod           user_info;      
    struct c_ofp_s_chain_nfv_list   nfv_list;      
};
OFP_ASSERT(sizeof(struct c_ofp_s_chain_info) == 616);

struct c_ofp_service_info {
    uint16_t                        vlan;
    char                            service[MAX_NFV_NAME];
};
OFP_ASSERT(sizeof(struct c_ofp_service_info) == 18);

struct c_ofp_s_chain_show {
    uint64_t                        dpid;
    uint32_t                        nw_src;
    uint32_t                        pad;
    char                            service[MAX_SERVICE_NAME];
    struct c_ofp_s_chain_nfv_list   nfv_list;
};
OFP_ASSERT(sizeof(struct c_ofp_s_chain_show) == 568);

struct c_ofp_service_show {
    struct ofp_header               header;                 
    struct c_ofp_service_info       service_list;
    uint8_t                         pad[2];
};
OFP_ASSERT(sizeof(struct c_ofp_service_show) == 28);

struct c_ofp_s_chain_nfv_group_info {
    uint64_t                        num_nfvs;
    char                            nfv_group[MAX_NFV_NAME];
    struct c_ofp_s_chain_nfv_list   nfv_list;
};
OFP_ASSERT(sizeof(struct c_ofp_s_chain_nfv_group_info) == 512);

struct c_ofp_group_show {
    uint64_t                                num_groups;
    struct c_ofp_s_chain_nfv_group_info     group_list[MAX_NFV];
};
OFP_ASSERT(sizeof(struct c_ofp_group_show) == 5128);

struct c_ofp_nfv_show {
    uint64_t                                num_nfvs;
    struct c_ofp_s_chain_nfv_list           nfv_list;
};
OFP_ASSERT(sizeof(struct c_ofp_nfv_show) == 496);

struct c_ofp_default_rule {
    char                            nfv_group[MAX_NFV_NAME];
};
OFP_ASSERT(sizeof(struct c_ofp_default_rule) == 16);

struct c_ofp_default_rule_info {
	uint16_t						num_nfvs;               
    uint16_t                        level;
    uint8_t                         pad[4];                 
	char							service[MAX_NFV_NAME];  
	struct c_ofp_default_rule		group_list[MAX_NFV];    
};
OFP_ASSERT(sizeof(struct c_ofp_default_rule_info) == 184);

struct c_ofp_user_flow_info {
    uint64_t                    datapath_id;
    struct flow                 flow;
};
OFP_ASSERT(sizeof(struct c_ofp_user_flow_info) == 96);

struct c_ofp_default_rule_show {
    uint16_t                        num_services;               
    uint8_t                         pad[2];
    struct c_ofp_default_rule_info  service_list[MAX_SERVICE];  
};
OFP_ASSERT(sizeof(struct c_ofp_default_rule_show) == 924);

struct c_ofp_nfv_stats_show {
    char                        group_name[MAX_NFV_NAME];
    char                        name[MAX_NFV_NAME];
};
OFP_ASSERT(sizeof(struct c_ofp_nfv_stats_show) == 32);

struct c_ofp_service_stats_show {
    char                        service_name[MAX_NFV_NAME]; 
    struct c_ofp_flow_info      stats;               
};
OFP_ASSERT(sizeof(struct c_ofp_service_stats_show) == 336);

struct c_ofp_user_stats_show {
    struct c_ofp_flow_info      stats;              
};
OFP_ASSERT(sizeof(struct c_ofp_user_stats_show) == 320);

typedef enum {
    CONX_TUNNEL_OF,
    CONX_TUNNEL_VXLAN,
    CONX_TUNBEL_GRE,
}conx_tunnel_t;

struct c_conx_user_flow {
    struct ofp_header           header;
    uint64_t                    dst_dpid;
    uint64_t                    n_src;
    uint64_t                    fl_flags;

    struct flow                 flow;
    struct flow                 mask;

    uint32_t                    tunnel_key;
    uint32_t                    tunnel_type;

    uint32_t                    app_cookie;
#define CONX_UFLOW_FORCE 0x1
#define CONX_UFLOW_DFL 0x2
    uint32_t                    conx_flags;
    
    uint8_t                     src_dpid_list[0];
    // uint8_t                  actions[0];
};
OFP_ASSERT(sizeof(struct c_conx_user_flow) == 224);

#define C_OFP_ERR_CODE_BASE (100)

/* More bad request codes */
#define OFPBRC_BAD_DPID     (C_OFP_ERR_CODE_BASE)
#define OFPBRC_BAD_APP_REG  (C_OFP_ERR_CODE_BASE + 1)
#define OFPBRC_BAD_APP_UREG (C_OFP_ERR_CODE_BASE + 2)
#define OFPBRC_BAD_NO_INFO  (C_OFP_ERR_CODE_BASE + 3)
#define OFPBRC_BAD_GENERIC  (C_OFP_ERR_CODE_BASE + 4)
//#define OFPBRC_BAD_LEN      (C_OFP_ERR_CODE_BASE + 5)
#define OFPBRC_BAD_GROUP_ID (C_OFP_ERR_CODE_BASE + 6)
#define OFPBRC_BAD_METER_ID (C_OFP_ERR_CODE_BASE + 7)

/* More bad action codes */
#define OFPBAC_BAD_GENERIC  (C_OFP_ERR_CODE_BASE + 100)

/* More flow mod failed codes */
#define OFPFMFC_BAD_FLAG    (C_OFP_ERR_CODE_BASE + 200)   
#define OFPFMFC_GENERIC     (OFPFMFC_BAD_FLAG + 1)   
#define OFPFMFC_FLOW_EXIST  (OFPFMFC_BAD_FLAG + 2)

#define C_OFP_MAX_ERR_LEN 128

#define C_ADD_ALIAS_IN_SWADD(sw_add, alias)         \
    do {                                            \
        *((uint16_t *)(sw_add->pad)) = htons((uint16_t)alias);     \
    } while (0)

#define C_GET_ALIAS_IN_SWADD(sw_add) (int)ntohs(*((uint16_t *)(sw_add->pad)))

typedef struct c_sw_port c_sw_port_t;
typedef struct c_ofp_switch_delete c_ofp_switch_delete_t;
typedef struct c_ofp_switch_add c_ofp_switch_add_t;
typedef struct c_ofp_packet_in c_ofp_packet_in_t;
typedef struct c_ofp_vendor_message c_ofp_vendor_msg_t;;
typedef struct c_ofp_send_vendor_message c_ofp_send_vendor_message_t;
typedef struct c_ofp_port_status c_ofp_port_status_t;
typedef struct c_ofp_phy_port c_ofp_phy_port_t;
typedef struct c_ofp_flow_mod c_ofp_flow_mod_t;
typedef struct c_ofp_flow_info c_ofp_flow_info_t;
typedef struct c_ofp_group_mod c_ofp_group_mod_t;
typedef struct c_ofp_meter_mod c_ofp_meter_mod_t;
typedef struct c_ofp_packet_out c_ofp_packet_out_t; 
typedef struct c_ofp_register_app c_ofp_register_app_t;
typedef struct c_ofp_unregister_app c_ofp_unregister_app_t;
typedef struct c_ofp_set_fp_ops c_ofp_set_fp_ops_t;
typedef struct ofp_error_msg c_ofp_error_msg_t;
typedef struct c_ofp_auxapp_cmd c_ofp_auxapp_cmd_t; 
typedef struct c_ofp_req_dpid_attr c_ofp_req_dpid_attr_t;
typedef struct c_ofp_switch_neigh c_ofp_switch_neigh_t;
typedef struct c_ofp_port_neigh c_ofp_port_neigh_t;
typedef struct c_ofp_switch_brief c_ofp_switch_brief_t;
typedef struct c_ofp_host_mod c_ofp_host_mod_t; 
typedef struct c_ofp_port_tnid_mod c_ofp_port_tnid_mod_t;
typedef struct c_ofp_tenant_nw_mod c_ofp_tenant_nw_mod_t;
typedef struct c_ofp_route c_ofp_route_t;
typedef struct c_ofp_route_link c_ofp_route_link_t;
typedef struct c_ofp_ha_state c_ofp_ha_state_t;
typedef struct c_ofp_loop_status_mod c_ofp_loop_status_mod_t;
typedef struct c_ofp_tr_status_mod c_ofp_tr_status_mod_t;
typedef struct c_ofp_s_chain_mod c_ofp_s_chain_mod_t;
typedef struct c_ofp_s_chain_nfv_info c_ofp_s_chain_nfv_info_t;
typedef struct c_ofp_s_chain_nfv_group_info c_ofp_s_chain_nfv_group_info_t;
typedef struct c_ofp_service_info c_ofp_service_info_t;
typedef struct c_opf_default_rule_info c_ofp_default_rule_info_t;
typedef struct c_ofp_nfv_stats_show c_ofp_nfv_stats_show_t;
typedef struct c_ofp_service_stats_show c_ofp_service_stats_show_t;
typedef struct c_ofp_user_stats_show c_ofp_user_stats_show_t;
typedef struct c_conx_user_flow c_conx_user_flow_t;

#endif
