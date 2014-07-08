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
MUL_NBAPI_PYLIST_RETURN(c_ofp_port_neigh, nbapi_port_neigh_list_t)
MUL_NBAPI_PYLIST_RETURN(ofp_phy_port, nbapi_port_list_t)
MUL_NBAPI_PYLIST_RETURN(c_sw_port, nbapi_swport_list_t)
MUL_NBAPI_PYLIST_RETURN(c_ofp_bkt, nbapi_bucket_list_t)
MUL_NBAPI_PYLIST_RETURN(ofp_action_header, nbapi_action_list_t)

#ifdef SWIG
    %newobject get_switch_general;
    %newobject general_capabilities_tostr;
    %newobject general131_capabilities_tostr;
    %newobject get_switch_port;
    %newobject get_switch_meter;
    %newobject get_band_type;
    %newobject get_band_flag;
    %newobject get_switch_table;
    %newobject get_table_bminstruction;
    %newobject get_table_next_tables;
    %newobject get_act_type;
    %newobject get_table_set_field;
    %newobject get_switch_group;
    %newobject get_supported_group;
    %newobject get_group_capabilities;

    %include "carrays.i"
    %array_class(struct ofp_phy_port, ofp_phy_port_array);
    %array_class(struct c_sw_port, c_sw_port_array);
    %array_class(struct c_ofp_bkt, c_ofp_bkt_array);
    %array_class(struct ofp_action_header, ofp_action_header_array);

#endif

struct mband_nbapi_input
{
    int rate;
    int burst_size;
    int prec_level;
};

struct c_ofp_switch_add *get_switch_general(uint64_t datapath_id);
char *general_capabilities_tostr(uint32_t capabilities);
int parse_alias_id(uint32_t alias_id);
char *general131_capabilities_tostr(uint32_t capabilities);
struct ofp_meter_features *get_switch_meter(uint64_t dpid);
char *get_band_type(uint32_t band_types);
char *get_band_flag(uint32_t capabilities);
struct of_flow_tbl_props *get_switch_table(uint64_t dpid, uint8_t table);
char *get_table_bminstruction(uint32_t bm_inst);
char *get_table_next_tables(uint32_t *bm_next_tables);
char *get_act_type(uint32_t actions);
char *get_table_set_field(uint32_t *set_field);
struct ofp_group_features *get_switch_group(uint64_t dpid);
char *get_supported_group(uint32_t types);
char *get_group_capabilities(uint32_t types);
char *get_group_act_type(uint32_t *actions, int type);
int nbapi_meter_add (uint64_t dpid, uint32_t meter_id, char * meter_type, int burst, int stats, char * c_rates, char * c_bursts, char * c_prec, int nbands);
int * ctomdata(char * cdata, int n);
struct of_meter_band_elem * make_band_elem(int rate, int burst_size, int  prec_level, mul_act_mdata_t *mdata);
uint16_t set_type(char * meter_type, int burst, int stats);

int nbapi_delete_meter(uint64_t dpid, uint32_t meter);

nbapi_switch_brief_list_t  get_switch_all(void);
#if 0
void nbapi_mem_free_c_ofp_switch_brief_t(c_ofp_switch_brief_t *switch_brief);
void dummy(void * a, void * b);
int get_flow_number(uint64_t dpid);
int get_meter_number(uint64_t dpid);
int get_group_number(uint64_t dpid);
void nbapi_mem_free_c_ofp_port_neigh(struct c_ofp_port_neigh *port);
#endif
nbapi_port_neigh_list_t get_switch_neighbor_all(uint64_t datapath_id);
struct c_sw_port *get_switch_port(uint64_t datapath_id, uint16_t port_no);
nbapi_swport_list_t get_switch_port_all(uint64_t datapath_id);
c_ofp_group_mod_t *get_switch_group_table(uint64_t datapath_id, uint32_t group_id);

#endif
