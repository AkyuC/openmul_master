/*
 * mul_nbapi_topology.h: Mul Northbound Topology API application headers
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
#ifndef __MUL_NBAPI_TOPOLOGY_H__
#define __MUL_NBAPI_TOPOLOGY_H__

#include "mul_app_interface.h"
#include "mul_nbapi_swig_helper.h"

MUL_NBAPI_PYLIST_RETURN(c_ofp_switch_brief, nbapi_switch_brief_list_t)
MUL_NBAPI_PYLIST_RETURN(ofp_phy_port, nbapi_port_list_t)
MUL_NBAPI_PYLIST_RETURN(c_sw_port, nbapi_swport_list_t)
MUL_NBAPI_PYLIST_RETURN(c_ofp_bkt, nbapi_bucket_list_t)
MUL_NBAPI_PYLIST_RETURN(ofp_action_header, nbapi_action_list_t)

#ifdef SWIG
    %newobject get_switch_general;
    %newobject get_switch;
    %newobject get_switch_port;
    %newobject get_switch_meter;
    %newobject get_switch_table;
    %newobject get_switch_group;
    %newobject get_switch_all;
    %newobject get_switch_port_all;
    %newobject get_switch_group_table;

    %include "carrays.i"
    %array_class(struct ofp_phy_port, ofp_phy_port_array);
    %array_class(struct c_sw_port, c_sw_port_array);
    %array_class(struct c_ofp_bkt, c_ofp_bkt_array);
    %array_class(struct ofp_action_header, ofp_action_header_array);

#endif

bool get_bit_in_32mask(uint32_t *mask, int bit);

struct mband_nbapi_input
{
    int rate;
    int burst_size;
    int prec_level;
};

struct c_ofp_switch_add *get_switch_general(uint64_t datapath_id);
int parse_alias_id(uint32_t alias_id);
uint32_t get_switch_alias_from_switch_info(struct ofp_switch_features *switch_info);
struct ofp_switch_features  *get_switch(uint64_t datapath_id);
struct ofp_meter_features *get_switch_meter(uint64_t dpid);
struct of_flow_tbl_props *get_switch_table(uint64_t dpid, uint8_t table);
struct ofp_group_features *get_switch_group(uint64_t dpid);
uint32_t get_group_act_type(uint32_t *actions, int type);
uint32_t get_max_group(uint32_t *max_groups, int type);

nbapi_switch_brief_list_t  get_switch_all(void);
struct c_sw_port *get_switch_port(uint64_t datapath_id, uint16_t port_no);
nbapi_swport_list_t get_switch_port_all(uint64_t datapath_id);
void nbapi_ntoh_actions(void *actions, size_t act_len);
c_ofp_group_mod_t *get_switch_group_table(uint64_t datapath_id, uint32_t group_id);


#endif
