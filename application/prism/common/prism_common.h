/*
 *  prism_common.h: PRISM common headers
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
#ifndef __PRISM_COMMON_H__
#define __PRISM_COMMON_H__
#include "mul_app_main.h"

#define PRISM_VIF_FILE "/etc/mul/prism/vif.conf"
#define PRISM_PKT_NEXT_HDR(h_, tot, rem) ((void *)((uint8_t *)h_ + tot - rem))

enum prism_idl_message_type
{
PRISM_LEGACY_PACKET_IN,               /* Legacy packet in from SDN edge */
PRISM_LEGACY_PACKET_OUT,           /* Legacy packet out toward SDN edge */ 
PRISM_LEGACY_RT_ADD,                     /* Legacy route addition */ 
PRISM_LEGACY_RT_DEL,                     /* Legacy route deletion */   
PRISM_LEGACY_NH_ADD,                    /* Legacy next-hop addition */ 
PRISM_LEGACY_NH_DEL,                     /* Legacy next-hop deletion */ 
PRISM_SDN_VIRT_IF_ADD,               /* Virtual interface addition from SDN core */
PRISM_SDN_VIRT_IF_DEL,                /* Virtual interface deletion from SDN core */
PRISM_SDN_VIRT_IF_UPDATE,        /* Virtual interface update */ 
PRISM_LEGACY_CONFIG_REPLAY,        /* REPLAY Config */ 
PRISM_PORT_CONFIG_REPLAY,
PRISM_SERVICE_ECHO,
PRISM_SERVICE_SUCCESS,
PRISM_SERVICE_ERROR
};

enum prism_err_type
{
    PRISM_UNKNOWN_MESSAGE = 1,
    PRISM_IDL_LENGTH_ERROR,
    PRISM_LEGACY_RT_MOD_FAILED,
    PRISM_LEGACY_NH_MOD_FAILED,
    PRISM_SDN_VIF_MOD_FAILED,
    PRISM_LEGACY_PKT_OUT_FAILED
};

enum prism_rt_mod_failed_code 
{
    PRTM_LENGTH_ERROR = 1,
    PRTM_INTERNAL_ERROR,
    PRTM_DUP_ROUTE,
    PRTM_ROUTE_NOT_EXIST
};

enum prism_nh_mod_failed_code
{
    PNHM_LENGTH_ERROR = 1,
    PNHM_INTERNAL_ERROR,
    PNHM_DUP_NEXT_HOP,
    PNHM_NEXT_HOP_NOT_EXIST,
    PNHM_DPID_NOT_EXIST,
    PNHM_PORT_NOT_EXIST
};

enum prism_vif_failed_code
{
    PRISM_LENGTH_ERROR,
    PRISM_DUP_VIF,
    PRISM_VIF_NOT_EXIST
};

enum prism_agent_err_type
{
    PRISM_AGENT_UNKNOWN_MESSAGE = 1,
    PRISM_AGENT_IDL_LENGTH_ERROR,
    PRISM_AGENT_IDL_PKT_IN_ERROR,
    PRISM_AGENT_VIRT_IF_ADD_FAILED,
    PRISM_AGENT_VIRT_IF_DEL_FAILED,
    PRISM_AGENT_VIRT_IF_UPDATE_FAILED,
    PRISM_PORT_CONFIG_REPLAY_FAILED
};

enum prism_legacy_pkt_out_code
{
    PLPO_LENGTH_ERROR
};

enum prism_legacy_pkt_in_code
{
    PLPI_LENGTH_ERROR,
    PLPI_NO_VIF
};

enum prism_virt_if_code
{
    PVIC_LENGTH_ERROR,
    PVIC_NO_VIF
};

enum prism_port_config_replay_code
{
    PPCR_LENGTH_ERROR,
    PPCR_NO_VIF,
    PPCR_MSG_REJ
};

enum prism_port_config
{
    PPCR_PORT_DOWN    = 1 << 0  /* Port is down. */
};

enum prism_port_state 
{
    PPCR_LINK_DOWN   = 1 << 0 /* No physical link present. */
};

struct prism_idl_hdr
{
    uint8_t     version;
    uint8_t     cmd;
    uint16_t    len;
    uint32_t    xid;
    uint8_t     data[0];
};

struct prism_ipv4_rt_cmd
{
    struct prism_idl_hdr hdr;
    uint32_t    dst_nw;          /* Destination network */
    uint32_t    dst_nm;          /* Destination netmask */ 
    uint32_t    nh;              /* Nexthop IP address */
    uint32_t    oif;             /* Output Interface port-no */
    uint32_t    rt_flags;        /* rt flags like RTN_UNICAST, RTN_LOCAL */
    uint64_t    dpid;            /* Outgoing switch identifier */  
};

struct prism_ipv4_nh_cmd
{
    struct prism_idl_hdr hdr;
    uint32_t    nh;                           /* Nexthop IP address */     
    uint32_t    nh_flags;                     /* Nexthop flags*/
    uint64_t    dpid;                         /* Outgoing switch identifier */                          
    uint32_t    oif;                          /* Output Interface port-no */
    uint8_t     mac_addr[ETH_ADDR_LEN];       /* Nexthop MAC-Address */ 
};

struct prism_packet_in
{
    struct prism_idl_hdr hdr;
    uint64_t    dpid;            /* Incoming switch identifier */                          
    uint32_t    iif;               /* Incoming interface port-no */
    uint32_t    pkt_len;           /* Packet Len */  
    uint8_t     pkt_data[0];       /* Packet Data */ 
};

struct prism_packet_out
{
    struct prism_idl_hdr hdr;
    uint64_t    dpid;            /* Outgoing switch identifier */                          
    uint32_t    oif;               /* Outgoing port-no */
    uint64_t    in_switch;         /* Incoming switch identifier */                          
    uint16_t    iif;               /* Incoming interface port-no */
    uint32_t    pkt_len;           /* Packet Len */  
    uint8_t     pkt_data[0];       /* Packet Data */ 
};

struct prism_error_msg
{
    struct prism_idl_hdr hdr;
    uint32_t type;
    uint32_t code;
};

struct prism_success_msg
{
    struct prism_idl_hdr hdr;
};

struct prism_service_echo_msg
{
    struct prism_idl_hdr hdr;
};

struct prism_legacy_config_replay
{
    struct prism_idl_hdr hdr;
};

struct prism_port
{
    uint16_t port_no;
    uint16_t pad1;
    uint32_t config;
    uint32_t state;
    uint8_t hw_addr[ETH_ADDR_LEN];
    uint16_t pad2;
};
typedef struct prism_port prism_port_t;

struct prism_edge_port_info
{
    struct prism_idl_hdr hdr;
    uint64_t dpid;
    prism_port_t port;
};

#define PRISM_VIF_ADD       1
#define PRISM_VIF_DEL       2
#define PRISM_VIF_UPDATE    3

struct prism_vif_cmd
{
    struct prism_idl_hdr hdr;
    uint16_t if_flags;
    uint64_t dpid;
    uint32_t port;
    uint8_t mac_addr[ETH_ADDR_LEN];
};

#endif
