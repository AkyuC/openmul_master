/*
 * mul_nbapi_statistics.h: Mul Northbound Statistics API application headers
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
#ifndef __MUL_NBAPI_STATISTICS_H__
#define __MUL_NBAPI_STATISTICS_H__

#include "mul_app_interface.h"
#include "mul_nbapi_swig_helper.h"
#include "mul_nbapi_flow.h"

#ifdef SWIG
    %newobject nbapi_parse_bps_to_str;
    %newobject nbapi_parse_pps_to_str;
    %newobject show_port_stats;
    %newobject get_switch_statistics_all;
#endif

typedef struct Port_Stats {
    float  bps;
    float  pps;
} Port_Stats_t;

nbapi_switch_flow_list_t  get_switch_statistics_all(uint64_t datapath_id);
Port_Stats_t *get_switch_statistics_port(uint64_t datapath_id, uint16_t port);

char *nbapi_parse_bps_to_str(uint8_t *bps);
char *nbapi_parse_pps_to_str(uint8_t *pps);

struct c_ofp_switch_table_stats *get_table_stats(uint64_t dp_id, uint8_t tbl_id);
int set_port_stats(uint64_t dpid, bool enable);
struct ofp131_port_stats *show_port_stats (uint64_t dpid, uint32_t port_no);
int get_switch_pkt_rx_rlim(uint64_t datapath_id);
int get_switch_pkt_tx_rlim(uint64_t datapath_id);
int nbapi_set_switch_pkt_rx_rlim(uint64_t datapath_id, uint32_t pps);
int nbapi_set_switch_pkt_tx_rlim(uint64_t datapath_id, uint32_t pps);
int nbapi_disable_switch_pkt_rx_rlim(uint64_t datapath_id);
int nbapi_disable_switch_pkt_tx_rlim(uint64_t datapath_id);

#endif
