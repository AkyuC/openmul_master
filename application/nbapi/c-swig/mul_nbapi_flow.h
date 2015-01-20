/*
 *  mul_nbapi_topology.h: Mul Northbound Static Flow API application headers
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
#ifndef __MUL_NBAPI_FLOW_H__
#define __MUL_NBAPI_FLOW_H__

#include "mul_app_interface.h"
#include "mul_nbapi_swig_helper.h"
#include "mul_vty.h"
#include "glib.h"

#ifdef SWIG

    %newobject nbapi_parse_mac_to_str;
    %newobject nbapi_fab_parse_nw_addr_to_str;
    %newobject nbapi_parse_ipv6_nw_addr_to_str;
    %newobject nbapi_parse_nw_addr_to_str;
    %newobject get_flow_number;

    %newobject get_flow;
    %newobject get_single_flow;
    %newobject get_group;
    %newobject nbapi_fabric_make_flow;
    %newobject nbapi_dump_single_flow_action;
    %newobject nbapi_dump_single_group_bkt;

#endif

MUL_NBAPI_PYLIST_RETURN(c_ofp_flow_info, nbapi_switch_flow_list_t)
MUL_NBAPI_PYLIST_RETURN(c_ofp_group_mod, nbapi_switch_group_list_t)

void regist_nbapi_cb(char *port);
int add_static_flow(uint64_t datapath_id, struct flow *fl, struct flow *mask,
                    uint8_t priority, mul_act_mdata_t *mdata, uint64_t flags, int drop);
struct of_group_mod_params *prepare_add_group(char *group, char *type);
void nbapi_group_action_add(int act_len, struct of_group_mod_params *g_parms,
                            mul_act_mdata_t *mdata, char *weight, char *ff_port, char *ff_group);
int nbapi_group_add(int act_len, uint64_t datapath_id, struct of_group_mod_params * g_parms);
void nbapi_group_free(int act_len, struct of_group_mod_params * g_parms);
int compare_flows(struct flow *fl1, struct flow *fl2);
mul_act_mdata_t *nbapi_group_mdata_alloc(uint64_t dpid);

int delete_static_flow(uint64_t datapath_id, struct flow *fl, struct flow *mask, uint16_t priority);

/* helpers to access data */
char *nbapi_parse_mac_to_str(uint8_t *mac);
char *nbapi_fab_parse_nw_addr_to_str(struct flow *flow);
char *nbapi_parse_ipv6_nw_addr_to_str(struct flow *flow, struct flow *mask, int i);
char *nbapi_parse_nw_addr_to_str(struct flow *flow, struct flow *mask, int i);

/* helpers to create arguments */
uint8_t nbapi_get_switch_version_with_id(uint64_t dpid);
struct flow *nbapi_make_flow(char *smac, char *dmac, char *eth_type, char *vid, 
                             char *vlan_pcp, char *mpls_label, char *mpls_tc,
                             char *mpls_bos, char *dip, char *sip, 
                             char *proto, char *tos, char *dport, 
                             char *sport, char *inport, char *table);

struct flow *nbapi_make_mask(char *smac, char *dmac, char *eth_type,
                             char *vid, char *vlan_pcp, char *mpls_label,
                             char *mpls_tc, char *mpls_bos, char *dip,
                             char *sip, char *proto, char *tos, char *dport, 
                             char *sport, char *inport);
mul_act_mdata_t *nbapi_mdata_alloc(uint64_t dpid);
int nbapi_mdata_inst_write(mul_act_mdata_t *mdata);
int nbapi_mdata_inst_apply(mul_act_mdata_t *mdata);
int nbapi_mdata_inst_meter(mul_act_mdata_t *mdata, uint32_t meter);
int nbapi_mdata_inst_goto(mul_act_mdata_t *mdata, uint8_t table);
int nbapi_action_to_mdata(mul_act_mdata_t *mdata, char *action_type, char *action_value);
void nbapi_mdata_free(mul_act_mdata_t *mdata);
void nbapi_flow_free(struct flow * flow);

/* helpers to create arguments */
struct flow *nbapi_fabric_make_flow(char *nw_src, char *dl_src, char * in_port);

/* helpers to make action structs */
struct ofp_action_output *nbapi_make_action_output(uint16_t oport);
struct ofp_action_vlan_vid *nbapi_make_action_set_vid(uint16_t vid);
struct ofp_action_header *nbapi_make_action_strip_vlan(void);
struct ofp_action_dl_addr *nbapi_make_action_set_dmac(char *dmac_str);
struct ofp_action_dl_addr *nbapi_make_action_set_smac(char *smac_str);
struct ofp_action_nw_addr *nbapi_make_action_set_nw_saddr(char * nw_saddr_str);
struct ofp_action_nw_addr *nbapi_make_action_set_nw_daddr(char * nw_daddr_str);
struct ofp_action_vlan_pcp *nbapi_make_action_set_vlan_pcp(uint8_t vlan_pcp);
struct ofp_action_nw_tos *nbapi_make_action_set_nw_tos(uint8_t tos);
struct ofp_action_tp_port *nbapi_make_action_set_tp_dport(uint16_t port);
struct ofp_action_tp_port *nbapi_make_action_set_tp_sport(uint16_t port);

struct ofp_action_group *nbapi_make_action_group(uint32_t gid);
struct ofp_action_push *nbapi_make_action_push(uint16_t eth_type);
struct ofp_action_pop_mpls *nbapi_make_action_strip_mpls(uint16_t eth_type);
struct ofp_action_header *nbapi_make_action_strip_pbb(void);
struct ofp_action_mpls_ttl *nbapi_make_action_set_mpls_ttl(uint8_t ttl);
struct ofp_action_header *nbapi_make_action_dec_mpls_ttl(void);
struct ofp_action_nw_ttl *nbapi_make_action_set_ip_ttl(uint8_t ttl);
struct ofp_action_header *nbapi_make_action_dec_ip_ttl(void);
struct ofp_action_header *nbapi_make_action_cp_ttl(bool in);
struct ofp_action_set_field *nbapi_make_action_set_eth_type(uint16_t eth_type);
struct ofp_action_set_field *nbapi_make_action_set_mpls_label(uint32_t label);
struct ofp_action_set_field *nbapi_make_action_set_mpls_tc(uint8_t tc);
struct ofp_action_set_field *nbapi_make_action_set_mpls_bos(uint8_t bos);
struct ofp_action_set_field *nbapi_make_action_set_tp_port(uint8_t ip_proto, 
                                                  bool is_src, uint16_t port);
struct ofp_action_set_field *nbapi_make_action_set_tp_udp_sport(uint16_t port);
struct ofp_action_set_field *nbapi_make_action_set_tp_udp_dport(uint16_t port);
struct ofp_action_set_field *nbapi_make_action_set_tp_tcp_sport(uint16_t port);
struct ofp_action_set_field *nbapi_make_action_set_tp_tcp_dport(uint16_t port);
struct ofp131_action_set_queue *nbapi_make_action_set_queue(uint32_t queue);

nbapi_switch_flow_list_t get_flow(uint64_t datapath_id);
nbapi_switch_flow_list_t get_single_flow(uint64_t datapath_id,
                                         struct flow *flow,
                                         struct flow *mask,
                                         uint32_t prio);
int get_flow_number(uint64_t dpid);
nbapi_switch_group_list_t get_group(uint64_t datapath_id);
int get_group_number(uint64_t dpid);
char *nbapi_dump_single_group_bkt(c_ofp_group_mod_t *cofp_gm);
char *nbapi_dump_single_flow_action(c_ofp_flow_info_t *cofp_fi);
char *nbapi_of10_dump_actions(void *actions, size_t actions_len);
char *nbapi_of131_dump_actions(void *inst_list, size_t inst_len,
                               bool acts_only);

#endif
