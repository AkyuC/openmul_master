/*
 * mul_nbapi_flow.c: Mul Northbound Static Flow Application for Mul Controller
 * Copyright (C) 2012-2014, Dipjyoti Saikia (dipjyoti.saikia@gmail.com)
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

#include "mul_common.h"
#include "mul_nbapi_common.h"
#include "mul_nbapi_flow.h"
#include "mul_nbapi_endian.h"

void regist_nbapi_cb(char *addr_port)
{
    c_log_info("%s : %s",FN, addr_port);
    gui_server_list = g_slist_append(gui_server_list, addr_port); 
}

int
add_static_flow(uint64_t datapath_id, 
                struct flow *fl, struct flow *mask, 
                uint8_t priority,
                mul_act_mdata_t *mdata,
                uint64_t flags,
                int drop) 
{
    void *actions = NULL;
    size_t action_len = 0;
    int ret = 0;

    if (!fl || !mask || !mdata) return -1;

    hton_flow(fl);
    hton_flow(mask);
    if( drop == 0) {
        action_len = mul_app_act_len(mdata);
        actions = mdata->act_base;
    } else if ( drop == 1 ) {
        action_len = 0;
    }
    mul_service_send_flow_add(nbapi_app_data->mul_service, datapath_id,
                                fl, mask, 0xffffffff, 
                                actions, action_len, 
                                0, 0, priority, flags);
    if (c_service_timed_wait_response(nbapi_app_data->mul_service) > 0) {
        c_log_err("%s: Failed to add a flow.", FN);
        ret = -1;
    }

    ntoh_flow(fl);

    return ret;
}

struct of_group_mod_params *
prepare_add_group(char *group, char *type)
{
    struct of_group_mod_params * g_parms;

    g_parms = calloc(1, sizeof(* g_parms));
    memset(g_parms, 0, sizeof(* g_parms));

    if(!strncmp(group, "None", strlen(group))){
        c_log_err("%s: No group id", FN);
    } else {
        g_parms->group = atol(group);
    }

    if (!strncmp(type, "all", strlen(type))){
        g_parms->type = OFPGT_ALL;
    } else if (!strncmp(type, "select", strlen(type))){
        g_parms->type = OFPGT_SELECT;
    } else if (!strncmp(type, "indirect", strlen(type))){
        g_parms->type = OFPGT_INDIRECT;
    } else if(!strncmp(type, "ff", strlen(type))){
        g_parms->type = OFPGT_FF;
    } else {
        c_log_err("%s: Malformed group-type", FN);
    }
    g_parms->flags = C_GRP_STATIC;
    return g_parms;
}

void nbapi_group_action_add(int act_len, struct of_group_mod_params * g_parms, mul_act_mdata_t * mdata, 
                            char * weight, char * ff_port, char * ff_group){
    struct of_act_vec_elem * act_elem;
    act_elem = calloc(1, sizeof(*act_elem));
    if (weight!=NULL){
         c_log_err("%s: ",weight);
        act_elem->weight = atoi(weight);
    }
    if (ff_port != NULL){
        act_elem->ff_port = atol(ff_port);
    }
    if (ff_group!=NULL){
        act_elem->ff_port = atol(ff_port);
    }
    act_elem->actions = mdata->act_base;
    act_elem->action_len = of_mact_len(mdata);
    g_parms->act_vectors[act_len] = act_elem;
}

int nbapi_group_add(int act_len, uint64_t datapath_id, struct of_group_mod_params * g_parms){
    g_parms->act_vec_len = act_len;
    mul_service_send_group_add(nbapi_app_data->mul_service, datapath_id, g_parms);
    if (c_service_timed_wait_response(nbapi_app_data->mul_service)>0){
        c_log_err("%s : Failed to add group",FN);
        return -1;
    }
    return 0;
}
void nbapi_group_free(int act_len, struct of_group_mod_params * g_parms){
    int i = 0;
    for(i = 0; i<act_len ; i++){
        free(g_parms->act_vectors[i]);
    }
    free(g_parms);
}

int compare_flows(struct flow *fl1, struct flow *fl2){
    return memcmp(fl1, fl2, sizeof(* fl1));
}
int
delete_static_flow(uint64_t datapath_id, 
                struct flow *fl, struct flow *mask, 
                uint16_t priority)
{
    int ret = 0;

    hton_flow(fl);
    /* Just pass params to Controller ML API interface */

    mul_service_send_flow_del(nbapi_app_data->mul_service, datapath_id,
                              fl, mask, 0, priority, C_FL_ENT_STATIC, OFPG_ANY);

    if (c_service_timed_wait_response(nbapi_app_data->mul_service) > 0) {
        c_log_err("%s: Failed to delete flow.", FN);
        return -1;
    }
    ntoh_flow(fl);
    return ret;
}

char *
nbapi_parse_mac_to_str(uint8_t *mac)
{
    char *ret = calloc(sizeof(char), 64);
    if (!ret) return NULL;

    sprintf(ret, "%02X:%02X:%02X:%02X:%02X:%02X", 
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ret;
}

char *nbapi_fab_parse_nw_addr_to_str(struct flow * flow)
{
    uint32_t nw_addr;
    char *ret;

    ret = calloc(sizeof(char), 64);
    nw_addr = ntohl(flow->ip.nw_src);
    
    if (!ret) return NULL;

    sprintf(ret, "%d.%d.%d.%d", (nw_addr >> 24) & 0xFF,
                                (nw_addr >> 16) & 0xFF,
                                (nw_addr >> 8) & 0xFF,
                                 nw_addr& 0xFF);
    return ret;
}

char *nbapi_parse_ipv6_nw_addr_to_str(struct flow *flow, struct flow *mask, int i){
    char *ret = calloc(sizeof(char), 1000);
    char ip6_addr_str[INET6_ADDRSTRLEN];
    char ip6_mask_str[INET6_ADDRSTRLEN];
    struct ipv6_addr flow_addr;
    struct ipv6_addr mask_addr;
    int i_mask = 0;

    if (!ret) return NULL;

    if( i == 1) {
        flow_addr = flow->ipv6.nw_src;
        mask_addr = mask->ipv6.nw_src;
    } else {
        flow_addr = flow->ipv6.nw_dst;
        mask_addr = mask->ipv6.nw_dst;
    }

    sprintf(ret, "-1");
    if(ipv6_addr_nonzero(&mask_addr) &&
           inet_ntop(AF_INET6, &flow_addr,  
                     ip6_addr_str, INET6_ADDRSTRLEN) &&
           inet_ntop(AF_INET6, &mask_addr,
                     ip6_mask_str, INET6_ADDRSTRLEN)){
        for ( i = 0; i<strlen(ip6_mask_str); i++){
            switch (ip6_mask_str[i]){
                case 'f' : i_mask+=4; break;
                case 'e' : i_mask+=3; break;
                case 'c' : i_mask+=2; break;
                case '8' : i_mask+=1; break;
            }
        }
        sprintf(ret,"%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X/%d",
                flow_addr.ip6_addr16[0],
                flow_addr.ip6_addr16[1],
                flow_addr.ip6_addr16[2],
                flow_addr.ip6_addr16[3],
                flow_addr.ip6_addr16[4],
                flow_addr.ip6_addr16[5],
                flow_addr.ip6_addr16[6],
                flow_addr.ip6_addr16[7],
                i_mask);
    } 
    return ret;
}

char *nbapi_parse_nw_addr_to_str(struct flow * flow, struct flow * mask, int i){
    char * ret = calloc(sizeof(char), 30);
    struct in_addr in_addr, in_mask;
    int i_mask = 0;
    memset(&in_addr, 0, sizeof(in_addr));
    memset(&in_mask, 0, sizeof(in_mask));
    if (!ret) return NULL;
    sprintf(ret, "-1");
    if ( i == 0 ){
        if(!mask->ip.nw_src) return ret;
        in_addr.s_addr = flow->ip.nw_src & mask->ip.nw_src;
        in_mask.s_addr = mask->ip.nw_src;
    } else {
        if(!mask->ip.nw_dst) return ret;
        in_addr.s_addr = flow->ip.nw_dst & mask->ip.nw_dst;
        in_mask.s_addr = mask->ip.nw_dst;
    }
    for ( i_mask=0 ; i_mask<32 ; i_mask++ ) {
        if(!(ntohl(in_mask.s_addr)<<i_mask & 0x80000000)){
            break;
        }
    }
    sprintf(ret, "%s/%d",inet_ntoa(in_addr), i_mask);
    return ret;
}

static uint32_t
parse_nw_addr(char * nw_addr_str)
{
    uint32_t nw_addr;
    uint8_t a,b,c,d;

    sscanf(nw_addr_str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
    nw_addr = (((((a<<8) + b) << 8) + c) << 8) + d;

    return nw_addr;
}

static void
parse_mac(char * mac_str, uint8_t mac[OFP_ETH_ALEN])
{
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           mac, mac+1, mac+2, mac+3, mac+4, mac+5);
}

uint8_t
nbapi_get_switch_version_with_id(uint64_t dpid)
{
    return c_app_switch_get_version_with_id(dpid);
}

/**
 * nbapi_flow_make_flow -
 *
 * Helpers to create flow and mask arguments 
 */

struct flow *
nbapi_make_flow(char *smac, char *dmac, char *eth_type,
                char *vid, char *vlan_pcp, char *mpls_label, char *mpls_tc,
                char *mpls_bos, char * dip, char *sip, char *proto,
                char *tos, char *dport, char *sport, char *inport,
                char *table)
{
    struct flow *flow;
    int i = 0;
    char *mac_str = NULL, *next = NULL;
    struct prefix_ipv4 dst_p, src_p;
    struct prefix_ipv6 dst_p6, src_p6;
    struct ipv6_addr addr6;
    uint64_t nmask;
    
    flow = calloc(1, sizeof(*flow));
    if (!flow) {
        c_log_err("%s : flow not alloc", FN);
        return NULL;
    }
    assert(flow);

    mac_str = (void *)smac;
    for ( i = 0 ; i < 6 ; i++ ) {
        flow->dl_src[i] = (uint8_t)strtoull(mac_str, &next, 16);
        if(mac_str == next) 
            break;
        mac_str = next +1;
    }
    mac_str = (void *)dmac;
    for ( i = 0 ; i < 6 ; i++ ) {
        flow->dl_dst[i] = (uint8_t)strtoull(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next +1;
    }
    flow->dl_type = (uint16_t)strtoull(eth_type, NULL, 16);
    flow->dl_vlan = atoi(vid);
    flow->dl_vlan_pcp = atoi(vlan_pcp);
    flow->mpls_label = atoi(mpls_label);
    flow->mpls_tc = atoi(mpls_tc);
    flow->mpls_bos = atoi(mpls_bos);
   
    if(flow->dl_type == ETH_TYPE_IPV6){
        if (!strncmp(dip, "None", strlen(dip))){
            dst_p6.prefixlen = 0;
            memset(&dst_p6.prefix, 0, sizeof(dst_p6.prefix));
        } else {
            str2prefix_ipv6(dip, (void *)&dst_p6);
            ipv6_addr_set(&addr6, 0xffffffff, 0xffffffff,
                              0xffffffff, 0xffffffff);
        }
        if(dst_p6.prefixlen)
            ipv6_addr_prefix(&flow->ipv6.nw_dst, (struct ipv6_addr *)&dst_p6.prefix, dst_p6.prefixlen);
    } else { 
        if (!strncmp(dip, "None", strlen(dip))){
            dst_p.prefixlen = 0;
            dst_p.prefix.s_addr = 0;
            nmask = 0;
        } else {
            str2prefix(dip, (void*)&dst_p);
            nmask = make_inet_mask(dst_p.prefixlen);
        }
        flow->ip.nw_dst = dst_p.prefix.s_addr & htonl(nmask);
    }
 
    if(flow->dl_type == ETH_TYPE_IPV6){
        if (!strncmp(sip, "None", strlen(sip))){
            src_p6.prefixlen = 0;
            memset(&src_p6.prefix, 0, sizeof(src_p6.prefix));
        } else {
            str2prefix_ipv6(sip, (void *)&src_p6);
            ipv6_addr_set(&addr6, 0xffffffff, 0xffffffff,
                              0xffffffff, 0xffffffff);
        }
        if(src_p6.prefixlen)
            ipv6_addr_prefix(&flow->ipv6.nw_src, (struct ipv6_addr *)&src_p6.prefix, src_p6.prefixlen);
    } else {
        if (!strncmp(sip, "None", strlen(sip))){
            src_p.prefixlen = 0;
            src_p.prefix.s_addr = 0;
             nmask = 0;
        } else {
            str2prefix(sip, (void*)&src_p);
            nmask = make_inet_mask(src_p.prefixlen);
        }
        flow->ip.nw_src = src_p.prefix.s_addr & htonl(nmask);
    }
    flow->nw_proto = atoi(proto);
    flow->nw_tos = atoi(tos);
    flow->tp_dst = atoi(dport);
    flow->tp_src = atoi(sport);
    flow->in_port = atoi(inport);
    flow->table_id = atoi(table);
 
    return flow;
}

struct flow *
nbapi_make_mask(char *smac, char *dmac, char *eth_type,
                char *vid, char *vlan_pcp, char *mpls_label, char *mpls_tc,
                char *mpls_bos, char *dip, char *sip, char *proto,
                char *tos, char *dport, char *sport, char *inport) {
    struct flow *mask;
    struct prefix_ipv4 dst_p, src_p;
    struct prefix_ipv6 dst_p6, src_p6;
    struct ipv6_addr addr6;
    uint32_t nmask = 0;

    mask = calloc(1, sizeof(*mask));
    if (!mask) {
        c_log_err("%s : mask not alloc",FN);
        return NULL;
    }
    assert(mask);
    of_mask_set_no_dc(mask);

    if(!strncmp(smac,"None",strlen(smac))){
        memset(mask->dl_src, 0, 6);
    }
    if(!strncmp(dmac,"None",strlen(smac))){
        memset(mask->dl_dst, 0, 6);
    }
    if(!strncmp(eth_type,"None",strlen(eth_type))){
        mask->dl_type = 0;
    }
    if(!strncmp(vid,"None",strlen(vid))){
        mask->dl_vlan = 0;
    }
    if(!strncmp(vlan_pcp,"None",strlen(vlan_pcp))){
        mask->dl_vlan_pcp = 0;
    }
    if(!strncmp(mpls_label,"None",strlen(mpls_label))){
        mask->mpls_label = 0;
    }
    if(!strncmp(mpls_tc,"None",strlen(mpls_tc))){
        mask->mpls_tc = 0;
    }
    if(!strncmp(mpls_bos,"None",strlen(mpls_bos))){
        mask->mpls_bos = 0;
    }

    memset(&mask->ipv6, 0, sizeof(mask->ipv6));
    if(strtoull(eth_type, NULL, 16) == ETH_TYPE_IPV6) {
        if(!strncmp(dip, "None", strlen(dip))){
            dst_p6.prefixlen = 0;
            memset(&dst_p6.prefix, 0, sizeof(dst_p6.prefix));
        } else {
            str2prefix_ipv6(dip, (void *)&dst_p6);
            ipv6_addr_set(&addr6, 0xffffffff, 0xffffffff,
                              0xffffffff, 0xffffffff);
            ipv6_addr_prefix(&mask->ipv6.nw_dst, &addr6, dst_p6.prefixlen);
        }
    } else {
        if(!strncmp(dip, "None", strlen(dip))){
            dst_p.prefixlen = 0;
            dst_p.prefix.s_addr = 0;
            nmask = 0;
        } else {
            str2prefix(dip, (void *)&dst_p);
            nmask = make_inet_mask(dst_p.prefixlen);
        }
        mask->ip.nw_dst = htonl(nmask);
    }
    if(strtoull(eth_type, NULL, 16) == ETH_TYPE_IPV6){
        if(!strncmp(sip, "None", strlen(sip))){
            src_p6.prefixlen = 0;
             memset(&src_p6.prefix, 0, sizeof(src_p6.prefix));
        } else {
            str2prefix_ipv6(sip, (void *)&src_p6);
            ipv6_addr_set(&addr6, 0xffffffff, 0xffffffff,
                              0xffffffff, 0xffffffff);
            ipv6_addr_prefix(&mask->ipv6.nw_src, &addr6, src_p6.prefixlen);
        }
    } else {
        if(!strncmp(sip, "None", strlen(sip))){
            src_p.prefixlen = 0;
            src_p.prefix.s_addr = 0;
            nmask = 0;
        } else {
            str2prefix(sip, (void *)&src_p);
            nmask = make_inet_mask(src_p.prefixlen);
        }
        mask->ip.nw_src = htonl(nmask);
    }
    if(!strncmp(proto, "None", strlen(proto))){
        mask->nw_proto = 0;
    }
    if(!strncmp(tos, "None", strlen(tos))){
        mask->nw_tos = 0;
    }
    if(!strncmp(dport, "None", strlen(dport))){
        mask->tp_dst = 0;
    }
    if(!strncmp(sport, "None", strlen(sport))){
        mask->tp_src = 0;
    }
    if(!strncmp(inport, "None", strlen(inport))){
        mask->in_port = 0;
    }
    mask->metadata = 0;
    mask->tunnel_id = 0;

    return mask;
}
/* helpers to create arguments */
struct flow *
nbapi_fabric_make_flow(char *nw_src_str, char *dl_src_str,
                       char *in_port_str)
{
    return nbapi_make_flow(dl_src_str, "None", "None",
                           "None", "None", "None", "None",
                           "None", "None", nw_src_str, "None",
                           "None", "None", "None", in_port_str,
                           "0");
}


mul_act_mdata_t *
nbapi_mdata_alloc(uint64_t dpid)
{        
    struct mul_act_mdata        *mdata;
    mdata = calloc(1, sizeof(*mdata));
    mul_app_act_alloc(mdata);
    if(mul_app_act_set_ctors(mdata, dpid))  {
        c_log_err("%s : Switch does not exist!",FN);
        mul_app_act_free(mdata);
        free(mdata);
        return NULL;
    }
    return mdata;
}              

mul_act_mdata_t *
nbapi_group_mdata_alloc(uint64_t dpid)
{
    struct mul_act_mdata *mdata;
    mdata = calloc(1, sizeof(*mdata));
    of_mact_alloc(mdata);
    mdata->only_acts = true;
    if(mul_app_act_set_ctors(mdata, dpid)){
        c_log_err("%s : Switch does not exist!!!", FN);
        mul_app_act_free(mdata);
        free(mdata);
        return NULL;
    }
    return mdata;
}

int
nbapi_mdata_inst_write(mul_act_mdata_t* mdata)
{
    if(mul_app_set_inst_write(mdata)){
        c_log_err("%s : can't set write instruction. ",FN);
        return -1;
    }
    return 0;
}          

int
nbapi_mdata_inst_apply(mul_act_mdata_t* mdata)
{
    if(mul_app_set_inst_apply(mdata)) {
        c_log_err("%s : can't set apply instruction. ",FN);
        return -1;
    }
    return 0;
}

int nbapi_mdata_inst_meter(mul_act_mdata_t * mdata, uint32_t meter)
{
    if (mul_app_inst_meter(mdata, meter)) {
        c_log_err("%s : can't add meter. ",FN);
        return -1;
    }
    return 0;
}

int nbapi_mdata_inst_goto(mul_act_mdata_t * mdata, uint8_t table){
    if (mul_app_inst_goto(mdata, table)) {
        c_log_err("%s : can't goto table", FN);
        return -1;
    }
    return 0;
}

int nbapi_action_to_mdata(mul_act_mdata_t* mdata, char * action_type, char * action_value){

    if(!strncmp(action_type, "OUTPUT", strlen(action_type))){
        if( mul_app_action_output(mdata, (uint32_t)strtoull(action_value, NULL, 0))<=0)  return -1;
    } else if(!strncmp(action_type, "CP_TTL_IN", strlen(action_type))){
        if(mul_app_action_cp_ttl(mdata, true) <= 0)return -1;
    } else if(!strncmp(action_type, "CP_TTL_OUT", strlen(action_type))){
        if(mul_app_action_cp_ttl(mdata, false) <= 0 )return -1;
    } else if(!strncmp(action_type, "DEC_MPLS_TTL", strlen(action_type))){
        if(mul_app_action_dec_mpls_ttl(mdata) <=0 )return -1;
    } else if(!strncmp(action_type, "DEC_NW_TTL", strlen(action_type))){
        if(mul_app_action_dec_nw_ttl(mdata) <= 0 )return -1;
    } else if(!strncmp(action_type, "GROUP", strlen(action_type))){
        if(mul_app_action_set_group(mdata, strtoull(action_value,NULL,10)) <=0 )return -1;
    } else if(!strncmp(action_type, "SET_NW_DST", strlen(action_type))){
        struct in_addr ip_addr;
        if(inet_aton(action_value, &ip_addr)<=0)return -1;
        if( mul_app_action_set_nw_daddr(mdata, ntohl(ip_addr.s_addr)) <= 0)return -1;
    } else if(!strncmp(action_type, "SET_NW_SRC", strlen(action_type))){
        struct in_addr ip_addr;
        if(inet_aton(action_value, &ip_addr)<=0)return -1;
    } else if(!strncmp(action_type, "PUSH_MPLS", strlen(action_type))){
        if(mul_app_action_push_hdr(mdata, ETH_TYPE_MPLS)<=0)return -1;
    } else if(!strncmp(action_type, "SET_NW_TOS", strlen(action_type))){
        if(mul_app_action_set_nw_tos(mdata, atoi(action_value))<= 0 )return -1;
    } else if(!strncmp(action_type, "PUSH_PBB", strlen(action_type))){
        if(mul_app_action_push_hdr(mdata, ETH_TYPE_PBB)<=0 )return -1;
    } else if(!strncmp(action_type, "PUSH_VLAN", strlen(action_type))){
        if( mul_app_action_push_hdr(mdata, ETH_TYPE_VLAN)<=0)return -1;
    } else if(!strncmp(action_type, "PUSH_SVLAN", strlen(action_type))){
        if( mul_app_action_push_hdr(mdata, ETH_TYPE_SVLAN)<=0)return -1;
    } else if(!strncmp(action_type, "SET_DL_DST", strlen(action_type))){
        uint8_t dmac[6];
        char *mac_str, *next = NULL;
        int i = 0;
        mac_str = (void *)action_value;
        for(i = 0; i<6;i++){
            dmac[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next) break; 
            mac_str = next +1;
        }
        if(i != 6)return -1;
        if( mul_app_action_set_dmac(mdata, dmac) <=0)return -1;
    } else if(!strncmp(action_type, "SET_ETH_TYPE", strlen(action_type))){
        if(mul_app_action_set_eth_type(mdata, (uint16_t)strtoull(action_value, NULL, 16))<=0) return -1;
    } else if(!strncmp(action_type, "SET_MPLS_BOS", strlen(action_type))){
        if(mul_app_action_set_mpls_bos(mdata, atoi(action_value) )<=0)return -1;
    } else if(!strncmp(action_type, "SET_MPLS_LABEL", strlen(action_type))){
        if(mul_app_action_set_mpls_label(mdata, atoi(action_value))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_MPLS_TC", strlen(action_type))){
        if(mul_app_action_set_mpls_tc(mdata, atoi(action_value))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_MPLS_TTL", strlen(action_type))){
        if(mul_app_action_set_mpls_ttl(mdata, atoi(action_value))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_NW_TTL", strlen(action_type))){
        if(mul_app_action_set_nw_ttl(mdata, atoi(action_value))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_QUEUE", strlen(action_type))){
        if(mul_app_action_set_queue(mdata, atoi(action_value))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_DL_SRC", strlen(action_type))){
        uint8_t smac[6];
        char *mac_str, *next = NULL;
        int i = 0;
        mac_str = (void *)action_value;
        for(i = 0; i<6; i++){
            smac[i] = (uint8_t)strtoull(mac_str, &next, 16);
            if(mac_str == next){ break; }
            mac_str = next + 1;
        }
        if(i != 6)return -1;
        if(mul_app_action_set_smac(mdata, smac) <=0 )return -1;
    } else if(!strncmp(action_type, "SET_VLAN_VID", strlen(action_type))){
        if(mul_app_action_set_vid(mdata, strtoull(action_value, NULL, 10))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_VLAN_PCP", strlen(action_type))){
        if(mul_app_action_set_vlan_pcp(mdata, strtoull(action_value, NULL, 10))<=0 )return -1;
    } else if(!strncmp(action_type, "POP_MPLS", strlen(action_type))){
        if(mul_app_action_set_eth_type(mdata, (uint16_t)strtoull(action_value, NULL, 16))<=0) return -1;
    } else if(!strncmp(action_type, "POP_PBB", strlen(action_type))){
        if(mul_app_action_strip_pbb(mdata) <=0)return -1;
    } else if(!strncmp(action_type, "STRIP_VLAN", strlen(action_type)) || 
        !strncmp(action_type, "POP_VLAN", strlen(action_type)) ){
        if( mul_app_action_strip_vlan(mdata)<=0)return -1;
    } else if(!strncmp(action_type, "SET_TP_UDP_SRC", strlen(action_type)) ){
        if( mul_app_action_set_tp_udp_sport(mdata, atoi(action_value))<=0)return -1;
    } else if(!strncmp(action_type, "SET_TP_TCP_SRC", strlen(action_type))){
        if(mul_app_action_set_tp_tcp_sport(mdata, atoi(action_value))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_TP_UDP_DST", strlen(action_type)) ){
        if(mul_app_action_set_tp_udp_dport(mdata, atoi(action_value))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_TP_TCP_DST", strlen(action_type)) ){
        if(mul_app_action_set_tp_tcp_dport(mdata, atoi(action_value))<=0 )return -1;
    } else if(!strncmp(action_type, "SET_NW_SRC6", strlen(action_type))){
        struct ipv6_addr addr6;
        if(inet_pton(AF_INET6, action_value, &addr6) <=0)return -1;
        if(mul_app_action_set_nw_saddr6(mdata, (void*)&addr6) <=0 )return -1;
    } else if(!strncmp(action_type, "SET_NW_DST6", strlen(action_type))){
        struct ipv6_addr addr6;
        if(inet_pton(AF_INET6, action_value, &addr6) <=0)return -1;
        if(mul_app_action_set_nw_daddr6(mdata, (void*)&addr6) <=0 )return -1;
    }
    else {
        return -2;
    }
/*  else if(!strncmp(action_type, "", strlen(action_type))){
        if( )   return -1;
        return 0;
    } */
    return 0;
}
void        
nbapi_mdata_free(mul_act_mdata_t *mdata)
{
    if(mdata != NULL){
        mul_app_act_free(mdata);
        free(mdata);
    }
}
void
nbapi_flow_free(struct flow * flow)
{
    if(flow != NULL){
        free(flow);
    }
}
struct ofp_action_output *
nbapi_make_action_output(uint16_t eoport)
{ 
    struct ofp_action_output *op_act;
    uint16_t oport;
    
    if (eoport == OF_ALL_PORTS) {
        oport = OFPP_ALL;
    } else if (eoport == OF_SEND_IN_PORT) {
        oport = OFPP_IN_PORT;
    } else {
        oport = (uint16_t)(eoport);
    }

    op_act = calloc(1, sizeof(struct ofp_action_output));
    oport = oport?: OFPP_CONTROLLER;     
    op_act->type = OFPAT_OUTPUT;
    op_act->len = sizeof(*op_act);
    op_act->port = oport;
    op_act->max_len = (oport == OFPP_CONTROLLER) ?
                       OF_MAX_MISS_SEND_LEN : 0;

    return (void *)op_act;
}

struct ofp_action_vlan_vid *nbapi_make_action_set_vid(uint16_t vid)
{
    struct ofp_action_vlan_vid *vid_act;

    vid_act = calloc(1, sizeof(*vid_act));
    
    vid_act->type = OFPAT_SET_VLAN_VID;
    vid_act->len  = sizeof(*vid_act);
    vid_act->vlan_vid = vid;

    return (void *)vid_act;
}

struct ofp_action_header *nbapi_make_action_strip_vlan(void)
{
    struct ofp_action_header *vid_strip_act;

    vid_strip_act = calloc(1, sizeof(*vid_strip_act));
    
    vid_strip_act->type = OFPAT_STRIP_VLAN;
    vid_strip_act->len  = sizeof(*vid_strip_act);

    return (void *)vid_strip_act;
}

struct ofp_action_dl_addr *nbapi_make_action_set_dmac(char *dmac_str)
{
    struct ofp_action_dl_addr *dmac_act;
        uint8_t        dmac[OFP_ETH_ALEN];
        parse_mac(dmac_str, dmac);

    dmac_act = calloc(1, sizeof(*dmac_act));

    dmac_act->type = OFPAT_SET_DL_DST;
    dmac_act->len  = sizeof(*dmac_act);
    memcpy(dmac_act->dl_addr, dmac, OFP_ETH_ALEN);

    return (void *)dmac_act;
}

struct ofp_action_dl_addr *nbapi_make_action_set_smac(char *smac_str)
{
    struct ofp_action_dl_addr *smac_act;
        uint8_t        smac[OFP_ETH_ALEN];
        parse_mac(smac_str, smac);

    smac_act = calloc(1, sizeof(*smac_act));

    smac_act->type = OFPAT_SET_DL_SRC;
    smac_act->len  = sizeof(*smac_act);
    memcpy(smac_act->dl_addr, smac, OFP_ETH_ALEN);

    return (void *)smac_act;
}

struct ofp_action_nw_addr *nbapi_make_action_set_nw_saddr(char * nw_saddr_str)
{
    struct ofp_action_nw_addr *nw_addr_act;
    uint32_t nw_saddr;

    nw_saddr = parse_nw_addr(nw_saddr_str);

    nw_addr_act = calloc(1, sizeof(*nw_addr_act));

    nw_addr_act->type = OFPAT_SET_NW_SRC;
    nw_addr_act->len  = sizeof(*nw_addr_act);
    nw_addr_act->nw_addr = nw_saddr;

    return (void *)nw_addr_act;
}

struct ofp_action_nw_addr *nbapi_make_action_set_nw_daddr(char * nw_daddr_str)
{
    struct ofp_action_nw_addr *nw_addr_act;
    uint32_t nw_daddr;

    nw_daddr = parse_nw_addr(nw_daddr_str);

    nw_addr_act = calloc(1, sizeof(*nw_addr_act));

    nw_addr_act->type = OFPAT_SET_NW_DST;
    nw_addr_act->len  = htons(sizeof(*nw_addr_act));
    nw_addr_act->nw_addr = nw_daddr;

    return (void *)nw_addr_act;
}

struct ofp_action_vlan_pcp *nbapi_make_action_set_vlan_pcp(uint8_t vlan_pcp)
{
    struct ofp_action_vlan_pcp *vpcp_act;

    vpcp_act = calloc(1, sizeof(*vpcp_act));

    vpcp_act->type = OFPAT_SET_VLAN_PCP;
    vpcp_act->len = sizeof(*vpcp_act);
    vpcp_act->vlan_pcp = (vlan_pcp & 0x7);

    return (void *)vpcp_act;
}

struct ofp_action_nw_tos *nbapi_make_action_set_nw_tos(uint8_t tos)
{
    struct ofp_action_nw_tos *nw_tos_act;

    nw_tos_act = calloc(1, sizeof(*nw_tos_act));

    nw_tos_act->type = OFPAT_SET_NW_TOS;
    nw_tos_act->len  = sizeof(*nw_tos_act);
    nw_tos_act->nw_tos = tos & ((0x1<<7) - 1);

    return (void *)nw_tos_act;
}

struct ofp_action_tp_port *nbapi_make_action_set_tp_dport(uint16_t port)
{
    struct ofp_action_tp_port *tp_port_act;

    tp_port_act = calloc(1, sizeof(*tp_port_act));

    tp_port_act->type = OFPAT_SET_TP_DST;
    tp_port_act->len  = sizeof(*tp_port_act);
    tp_port_act->tp_port = port;

    return (void *)tp_port_act;
}

struct ofp_action_tp_port *nbapi_make_action_set_tp_sport(uint16_t port)
{
    struct ofp_action_tp_port *tp_port_act;

    tp_port_act = calloc(1, sizeof(*tp_port_act));

    tp_port_act->type = OFPAT_SET_TP_SRC;
    tp_port_act->len  = sizeof(*tp_port_act);
    tp_port_act->tp_port = port;

    return (void *)tp_port_act;
}

struct ofp_action_group *nbapi_make_action_group(uint32_t gid) 
{
    struct ofp_action_group *op_group;

    op_group = calloc(1, sizeof(struct ofp_action_group));
    op_group->type = OFPAT131_GROUP;
    op_group->len = sizeof(*op_group);
    op_group->group_id = gid;

    return (void *)op_group;
}

struct ofp_action_push *nbapi_make_action_push(uint16_t eth_type)
{
    struct ofp_action_push *pv_act;
    uint16_t ptype = 0;

    switch (eth_type) {
    case ETH_TYPE_VLAN:
    case ETH_TYPE_SVLAN:
        ptype = OFPAT131_PUSH_VLAN;
        break;
    case ETH_TYPE_MPLS:
    case ETH_TYPE_MPLS_MCAST:
        ptype = OFPAT131_PUSH_MPLS;
        break;
    case ETH_TYPE_PBB:
        ptype = OFPAT131_PUSH_PBB;
        break;
    default:
        c_log_err("No push type for eth_type(0x%x)", eth_type);
        return 0;
    }

    pv_act = calloc(1, sizeof(struct ofp_action_push));
    pv_act->type = ptype;
    pv_act->len = sizeof(*pv_act);
    pv_act->ethertype = eth_type;

    return (void *)pv_act;
}

struct ofp_action_pop_mpls *nbapi_make_action_strip_mpls(uint16_t eth_type)
{
    struct ofp_action_pop_mpls *p_act;

    p_act = calloc(1, sizeof(struct ofp_action_pop_mpls));
    p_act->type = OFPAT131_POP_MPLS;
    p_act->len = sizeof(*p_act);
    p_act->ethertype = eth_type;

    return (void *)p_act;
}

struct ofp_action_header *nbapi_make_action_strip_pbb(void)
{
    struct ofp_action_header *strip_pbb;

    strip_pbb = calloc(1, sizeof(struct ofp_action_header));
    strip_pbb->type = OFPAT131_POP_PBB;
    strip_pbb->len = sizeof(*strip_pbb);

    return (void *)strip_pbb;
}

struct ofp_action_mpls_ttl *nbapi_make_action_set_mpls_ttl(uint8_t ttl)
{
    struct ofp_action_mpls_ttl *m_ttl;
    
    m_ttl = calloc(1, sizeof(struct ofp_action_mpls_ttl));
    m_ttl->type = OFPAT131_MPLS_TTL;
    m_ttl->len = sizeof(*m_ttl);
    m_ttl->mpls_ttl = ttl;

    return (void *)m_ttl;
}

struct ofp_action_header *nbapi_make_action_dec_mpls_ttl(void)
{
    struct ofp_action_header *dec_mpls_ttl;

    dec_mpls_ttl = calloc(1, sizeof(struct ofp_action_header));
    dec_mpls_ttl->type = OFPAT131_DEC_MPLS_TTL;
    dec_mpls_ttl->len = sizeof(*dec_mpls_ttl);

    return (void *)dec_mpls_ttl;
}

struct ofp_action_nw_ttl *nbapi_make_action_set_ip_ttl(uint8_t ttl)
{
    struct ofp_action_nw_ttl *m_ttl;

    m_ttl = calloc(1, sizeof(struct ofp_action_nw_ttl));
    m_ttl->type = OFPAT131_SET_NW_TTL;
    m_ttl->len = sizeof(*m_ttl);
    m_ttl->nw_ttl = ttl;

    return (void *)m_ttl;
}

struct ofp_action_header *nbapi_make_action_dec_ip_ttl(void)
{
    struct ofp_action_header *dec_ip_ttl;

    dec_ip_ttl = calloc(1, sizeof(struct ofp_action_header));
    dec_ip_ttl->type = OFPAT131_DEC_NW_TTL;
    dec_ip_ttl->len = sizeof(*dec_ip_ttl);

    return (void *)dec_ip_ttl;
}

struct ofp_action_header *nbapi_make_action_cp_ttl(bool in)
{
    struct ofp_action_header *cp_ttl;

    cp_ttl = calloc(1, sizeof(struct ofp_action_header));
    cp_ttl->type = in ? OFPAT131_COPY_TTL_IN : OFPAT131_COPY_TTL_OUT;
    cp_ttl->len = sizeof(*cp_ttl);

    return (void *)cp_ttl;
}

struct 
ofp_action_set_field *nbapi_make_action_set_eth_type(uint16_t eth_type)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_ETH_TYPE_SZ);

    ofp_sf = calloc(1, sizeof(struct ofp_action_set_field));
    ofp_sf->type = OFPAT131_SET_FIELD;
    ofp_sf->len = len;

    oxm = (void *)ofp_sf->field;
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_TYPE);
    oxm->length = OFPXMT_OFB_ETH_TYPE_SZ;
    *(uint16_t *)(oxm->data) = eth_type;

    return (void *)ofp_sf;
}

struct
ofp_action_set_field *nbapi_make_action_set_mpls_label(uint32_t label)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_MPLS_LABEL_SZ);

    ofp_sf = calloc(1, sizeof(struct ofp_action_set_field));
    ofp_sf->type = OFPAT131_SET_FIELD;
    ofp_sf->len = len;

    oxm = (void *)ofp_sf->field;
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_LABEL);
    oxm->length = OFPXMT_OFB_MPLS_LABEL_SZ;
    of_put_mpls_label_oxm(oxm->data, label, 3);

    return (void *)ofp_sf; 
}

struct
ofp_action_set_field *nbapi_make_action_set_mpls_tc(uint8_t tc)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_MPLS_TC_SZ);

    ofp_sf = calloc(1, sizeof(struct ofp_action_set_field));
    ofp_sf->type = OFPAT131_SET_FIELD;
    ofp_sf->len = len;

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_TC);
    oxm->length = OFPXMT_OFB_MPLS_TC_SZ;
    *(uint8_t *)oxm->data = tc;

    return (void *)ofp_sf;
}

struct
ofp_action_set_field *nbapi_make_action_set_mpls_bos(uint8_t bos)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_MPLS_BOS_SZ);

    ofp_sf = calloc(1, sizeof(struct ofp_action_set_field));
    ofp_sf->type = OFPAT131_SET_FIELD;
    ofp_sf->len = len;

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_BOS);
    oxm->length = OFPXMT_OFB_MPLS_BOS_SZ;
    *(uint8_t *)oxm->data = bos ? 1 : 0;

    return (void *)ofp_sf;
}

struct ofp_action_set_field *
nbapi_make_action_set_tp_port(uint8_t ip_proto, bool is_src, uint16_t port)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_L4_PORT_SZ);
    uint8_t port_type;

    switch (ip_proto) {
    case IP_TYPE_TCP:
        if (is_src) {
            port_type = OFPXMT_OFB_TCP_SRC;
        } else {
            port_type = OFPXMT_OFB_TCP_DST;
        }
        break;
    case IP_TYPE_UDP:
        if (is_src) {
            port_type = OFPXMT_OFB_UDP_SRC;
        } else {
            port_type = OFPXMT_OFB_UDP_DST;
        }
        break;
    default:
        c_log_err("%s: Unsupported act tp-port", FN);
        return NULL;
    }

    ofp_sf = calloc(1, sizeof(struct ofp_action_set_field));
    ofp_sf->type = OFPAT131_SET_FIELD;
    ofp_sf->len = len;

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, port_type);
    oxm->length = OFPXMT_OFB_L4_PORT_SZ;
    *(uint16_t *)(oxm->data) = port;

    return (void *)ofp_sf;
}

struct
ofp_action_set_field *nbapi_make_action_set_tp_udp_sport(uint16_t port)
{
    return nbapi_make_action_set_tp_port(IP_TYPE_UDP, true, port);
}

struct 
ofp_action_set_field *nbapi_make_action_set_tp_udp_dport(uint16_t port)
{
    return nbapi_make_action_set_tp_port(IP_TYPE_UDP, false, port);
}

struct
ofp_action_set_field *nbapi_make_action_set_tp_tcp_sport(uint16_t port)
{
    return nbapi_make_action_set_tp_port(IP_TYPE_TCP, true, port);
}

struct
ofp_action_set_field *nbapi_make_action_set_tp_tcp_dport(uint16_t port)
{
    return nbapi_make_action_set_tp_port(IP_TYPE_TCP, false, port);
}

struct
ofp131_action_set_queue *nbapi_make_action_set_queue(uint32_t queue)
{
    struct ofp131_action_set_queue *q_act;

    q_act = calloc(1, sizeof(struct ofp131_action_set_queue));
    q_act->type = OFPAT131_SET_QUEUE;
    q_act->queue_id = queue;
    q_act->len = sizeof(*q_act);

    return (void *)q_act;
}

static void 
make_flow_list(nbapi_switch_flow_list_t *list, c_ofp_flow_info_t *cofp_fi)
{
    c_ofp_flow_info_t *cofp_arg;

    cofp_arg = calloc(1, ntohs(cofp_fi->header.length));
    if (!cofp_arg) return;

    memcpy(cofp_arg, cofp_fi, ntohs(cofp_fi->header.length));
    ntoh_c_ofp_flow_info(cofp_arg);
    list->array = g_slist_prepend(list->array, cofp_arg);
}

static void
nbapi_make_flow_list(void *list, void *cofp_fi)
{
    make_flow_list((nbapi_switch_flow_list_t *)list, 
                    (c_ofp_flow_info_t *)cofp_fi);
}

static void
make_group_list(nbapi_switch_group_list_t *list, c_ofp_group_mod_t *cofp_gm)
{
    c_ofp_group_mod_t * cofp_arg;
    cofp_arg = calloc(1, ntohs(cofp_gm->header.length));
    memcpy(cofp_arg, cofp_gm, ntohs(cofp_gm->header.length));
    ntoh_c_ofp_group_mod(cofp_arg);
    list->array = g_slist_prepend(list->array, cofp_arg);
}
static void 
nbapi_make_group_list(void *list, void *cofp_gm)
{
    make_group_list((nbapi_switch_group_list_t *)list,
                    (c_ofp_group_mod_t *)cofp_gm);
}

nbapi_switch_group_list_t
get_group(uint64_t datapath_id)
{
    int n_groups;
    nbapi_switch_group_list_t list;
    uint8_t version;

    list.array = NULL;
    list.length = 0;

    version = c_app_switch_get_version_with_id(datapath_id);

    if(version != OFP_VERSION_131){
        c_log_err("Unable to parse group : not supported OFP version");
        return list;
    }    

    c_rd_lock(&nbapi_app_data->lock);
    if(!nbapi_app_data->mul_service) {
        c_rd_unlock(&nbapi_app_data->lock);
        return list;
    }
    n_groups = mul_get_group_info(nbapi_app_data->mul_service,
                                  datapath_id, false, true, 
                                  &list, nbapi_make_group_list);
    c_rd_unlock(&nbapi_app_data->lock);
    list.length = n_groups;
    list.array = g_slist_reverse(list.array);
    return list;
}
int get_group_number(uint64_t dpid){
    nbapi_switch_group_list_t list;
    return mul_get_group_info(nbapi_app_data->mul_service,
                                dpid, false, true,
                                &list, nbapi_make_group_list);
}
char * nbapi_dump_single_group_bkt(c_ofp_group_mod_t * cofp_gm){
    char *pbuf;
    struct c_ofp_bkt *bkt;
    size_t bkt_dist = 0;
    ssize_t tot_len= ntohs(cofp_gm->header.length);
    int act = 0, len = 0;

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    bkt_dist = sizeof(*cofp_gm);
    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, "[");
    while(tot_len >= (int)sizeof(*bkt) && act < OF_MAX_ACT_VECTORS) {
        size_t act_len = 0;
        
        bkt = INC_PTR8(cofp_gm, bkt_dist);
        act_len = ntohs(bkt->act_len);
        bkt_dist += sizeof(*bkt) + act_len;
        if (act_len <= 0 ) break;
        if (act_len > (tot_len - sizeof(*bkt))){
            break;
        }
        if(act >0){
            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, ",");
        }
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "{'action_bucket':'%d','actions':[",act);
        
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "%s",nbapi_of131_dump_actions(bkt->actions, act_len, true));
        len--;
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "]}");

        tot_len -= act_len +sizeof(*bkt);
        act++;

    }

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, "]");
    return pbuf;
}

nbapi_switch_flow_list_t get_flow(uint64_t datapath_id)
{
    int n_flows;
    nbapi_switch_flow_list_t list;

    list.array = NULL;
    list.length = 0;

    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_rd_unlock(&nbapi_app_data->lock);
        return list;
    }
    n_flows = mul_get_flow_info(nbapi_app_data->mul_service,
                                datapath_id, 0, false, true,false,
                                false, true, &list,
                                nbapi_make_flow_list);
    c_rd_unlock(&nbapi_app_data->lock);

    list.length = n_flows;
    list.array = g_slist_reverse(list.array);
    return list;
}
nbapi_switch_flow_list_t
get_single_flow(uint64_t datapath_id, struct flow *flow, struct flow *mask, uint32_t prio){
    int n_flows;
    nbapi_switch_flow_list_t list;

    list.array = NULL;
    list.length = 0;


    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_rd_unlock(&nbapi_app_data->lock);
        return list;
    }
    hton_flow(flow);
    hton_flow(mask);
    n_flows = mul_get_matched_flow_info(nbapi_app_data->mul_service,
                                        datapath_id, false, true, &list,
                                        flow, mask, prio, nbapi_make_flow_list);
    c_rd_unlock(&nbapi_app_data->lock);
    list.length = n_flows;
    list.array = g_slist_reverse(list.array);
    return list;
}

int
get_flow_number(uint64_t dpid)
{
    nbapi_switch_flow_list_t list;

    return mul_get_flow_info(nbapi_app_data->mul_service,
                                dpid, 0, false, true, false,
                                false, true, &list,
                                nbapi_make_flow_list);
}
char *
nbapi_dump_single_flow_action(c_ofp_flow_info_t *cofp_fi)
{
    char        *pbuf;
    size_t      action_len;
    uint64_t    dpid = U642ULL(cofp_fi->datapath_id);
    uint8_t     version;

    version = c_app_switch_get_version_with_id(dpid);

    if (version != OFP_VERSION && version != OFP_VERSION_131 &&
        version != OFP_VERSION_140) {
        c_log_err("%s: Unable to parse flow:Unknown OFP version", FN);
        return NULL;
    }

    action_len = ntohs(cofp_fi->header.length) - sizeof(*cofp_fi);
    if (version == OFP_VERSION)
        pbuf = nbapi_of10_dump_actions(cofp_fi->actions, action_len);
    else if (version == OFP_VERSION_131)
        pbuf = nbapi_of131_dump_actions(cofp_fi->actions, action_len, false);
    else if (version == OFP_VERSION_140)
        pbuf = nbapi_of131_dump_actions(cofp_fi->actions, action_len, false);
    else {
        NOT_REACHED();
    }
    
    return pbuf;
}

static void *
nbapi_inst_parser_alloc(struct flow *fl, struct flow *mask,
                        void *u_arg, struct ofp_inst_parsers *parsers,
                        struct ofp_act_parsers *act_parsers)
{
    struct ofp_inst_parser_arg *ofp_dp = calloc(1, sizeof(*ofp_dp));

    if (!ofp_dp) {
        c_log_err("%s: Failed to instruction parse", FN);
        return NULL;
    }

    ofp_dp->pbuf = calloc(1, OF_DUMP_INST_SZ);
    if (!ofp_dp->pbuf) {
        c_log_err("%s: Failed to instruction parse", FN);
        free(ofp_dp);
        return NULL;
    }

    ofp_dp->fl = fl;
    ofp_dp->mask = mask;
    ofp_dp->u_arg = u_arg;
    ofp_dp->parsers = parsers;
    ofp_dp->act_parsers = act_parsers;

    return ofp_dp;
}

static void 
nbapi_dump_inst_parser_pre_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len,
                        OF_DUMP_INST_SZ - dp->len -1,
                        "{'instructions':[ ");
    dp->len += snprintf(dp->pbuf + dp->len,
                        OF_DUMP_INST_SZ - dp->len -1,
                        "{'type':'%s','actions':[ ", "WRITE_ACTION");
    assert(dp->len < OF_DUMP_INST_SZ - 1);
}

static void 
nbapi_dump_inst_parser_post_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    
    snprintf(dp->pbuf + dp->len-1, OF_DUMP_INST_SZ - (dp->len)-1, "]");
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                "}]}");

    assert(dp->len < OF_DUMP_INST_SZ-1);
}

static int
nbapi_of_dump_act_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t port = ntohs(of_ao->port);

    if (port == OFPP_CONTROLLER)  {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%s'},",
                        "OUTPUT", "CONTROLLER");
    } else if (port == OFPP_LOCAL)  {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%s'},",
                        "OUTPUT", "LOCAL");
    } else {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",
                        "OUTPUT", port);
    }
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of_dump_act_set_vlan(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_vid *vid_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%d'}",//0x%04x'},",
                        "SET_VLAN_VID", ntohs(vid_act->vlan_vid));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vid_act);
 }

static int
nbapi_of_dump_act_set_vlan_pcp(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_pcp *vlan_pcp_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",
                        "SET_VLAN_PCP", vlan_pcp_act->vlan_pcp);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vlan_pcp_act);
}

static int
nbapi_of_dump_act_set_dl_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_dl_addr *dmac_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                   "{'action':'%s','value':'%02X:%02X:%02X:%02X:%02X:%02X'},",
                   "SET_DL_DST", 
                   dmac_act->dl_addr[0], dmac_act->dl_addr[1],
                   dmac_act->dl_addr[2], dmac_act->dl_addr[3],
                   dmac_act->dl_addr[4], dmac_act->dl_addr[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*dmac_act);
}

static int
nbapi_of_dump_act_set_dl_src(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_dl_addr *smac_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                   "{'action':'%s','value':'%02X:%02X:%02X:%02X:%02X:%02X'},",
                   "SET_DL_SRC", 
                   smac_act->dl_addr[0], smac_act->dl_addr[1],
                   smac_act->dl_addr[2], smac_act->dl_addr[3],
                   smac_act->dl_addr[4], smac_act->dl_addr[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*smac_act);
}

static int
nbapi_of_dump_act_set_nw_src(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t nw_addr = ntohl(nw_addr_act->nw_addr);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%d.%d.%d.%d'},",
                        //"{'action':'%s','value':'0x%08x'},", 
                        "SET_NW_SRC",
                                (nw_addr >> 24) & 0xFF,
                                (nw_addr >> 16) & 0xFF,
                                (nw_addr >> 8) & 0xFF,
                                nw_addr& 0xFF);
                        //"SET_NW_SRC", ntohl(nw_addr_act->nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static int
nbapi_of_dump_act_set_nw_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t nw_addr = ntohl(nw_addr_act->nw_addr);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value': '%d.%d.%d.%d' },",
                                "SET_NW_DST",
                                (nw_addr >> 24) & 0xFF,
                                (nw_addr >> 16) & 0xFF,
                                (nw_addr >> 8) & 0xFF,
                                nw_addr& 0xFF);
                        //"{'action':'%s','value':'0x%08x'},", 
                        //"SET_NW_DST", ntohl(nw_addr_act->nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static void 
nbapi_of131_dump_inst_parser_pre_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len,
                        OF_DUMP_INST_SZ - dp->len - 1,
                        "{'instructions':[ ");
    assert(dp->len < OF_DUMP_INST_SZ - 1);
}

static int
nbapi_of131_dump_goto_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_goto_table *ofp_ig = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'instruction':'%s','value':%d},", 
                        "GOTO_TABLE", ofp_ig->table_id);
    assert(dp->len < OF_DUMP_INST_SZ - 1);

    return ntohs(inst->len);
}

static int
nbapi_of131_dump_wr_meta_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_write_metadata *ofp_iwm = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "{'type':'%s','metadata':0x%llx},",
                        "WRITE_METADATA",
                        U642ULL(ntohll(ofp_iwm->metadata)));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len);
}

static int
nbapi_of131_dump_act_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_actions *ofp_ia = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;
    char *pinst = NULL;

    switch (ntohs(ofp_ia->type)) {
    case OFPIT_WRITE_ACTIONS:
        pinst = "WRITE_ACTIONS";
        break;
    case OFPIT_APPLY_ACTIONS:
        pinst = "APPLY_ACTIONS";
        break;
    case OFPIT_CLEAR_ACTIONS:
        pinst = "CLEAR_ACTIONS";
        break;
    default:
        return -1;
    }

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "{'instruction':'%s','actions': [ ", pinst);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    if (ntohs(ofp_ia->len) > sizeof(*ofp_ia)) {
        of131_parse_actions((void *)(ofp_ia->actions),
                            ntohs(ofp_ia->len) - sizeof(*ofp_ia), arg);
    }

    snprintf(dp->pbuf + dp->len - 1, OF_DUMP_INST_SZ - (dp->len) - 1,
             "]");
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "},");

    return ntohs(inst->len);
}

static int
nbapi_of131_dump_meter_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_meter *ofp_im = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'instruction':'%s','value':%d},",
                        "METER", ntohl(ofp_im->meter_id));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    
    return ntohs(inst->len);
}

static void
nbapi_of131_dump_inst_parser_post_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    snprintf(dp->pbuf + dp->len - 1, OF_DUMP_INST_SZ - dp->len - 1,
                        "]");
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "}");
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
}

static struct ofp_inst_parser_arg *
nbapi_inst_parser_fini(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    return dp;
}


static int
nbapi_of131_dump_act_output(struct ofp_action_header *action, void *arg)
{
    struct ofp131_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t port = ntohl(of_ao->port);

    if (port == OFPP131_CONTROLLER) {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%s'},",
                        "OUTPUT", "CONTROLLER");
    } else if (port == OFPP131_LOCAL) {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%s'},",
                        "OUTPUT", "LOCAL");
    } else if (port == OFPP131_ALL) {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%s'},",
                        "OUTPUT", "ALL");
    } else if (port == OFPP131_FLOOD) {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%s'},",
                        "OUTPUT", "FLOOD");
    } else if (port == OFPP131_NORMAL) {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%s'},",
                        "OUTPUT", "NORMAL");
    } else {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},", 
                        "OUTPUT", port);
    }
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
nbapi_of131_dump_push_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_push *ofp_ap = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    char *push_str;

    switch(ntohs(ofp_ap->type)) {
    case OFPAT131_PUSH_VLAN:
        if (ntohs(ofp_ap->ethertype) == ETH_TYPE_VLAN){
            push_str = "PUSH_VLAN";
        } else if (ntohs(ofp_ap->ethertype) == ETH_TYPE_SVLAN){
            push_str = "PUSH_SVLAN";
        }
        break;
    case OFPAT131_PUSH_MPLS:
        push_str = "PUSH_MPLS";
        break;
    case OFPAT131_PUSH_PBB:
        push_str = "PUSH_PBB";
        break;
    default:
        return -1;
    }
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'0x%x'},",
                        push_str, ntohs(ofp_ap->ethertype));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
nbapi_of131_dump_pop_vlan_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s'},", "POP_VLAN");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of131_dump_pop_pbb_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s'},", "POP_PBB");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of131_dump_pop_mpls_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_pop_mpls *ofp_pm = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'0x%x'},", 
                        "POP_MPLS", ntohs(ofp_pm->ethertype));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of131_dump_set_queue(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp131_action_set_queue *ofp_sq = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",
                        //"{'action':'%s','value':0x%x},",
                        "SET_QUEUE", ntohl(ofp_sq->queue_id));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of131_dump_set_nw_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_nw_ttl *ofp_snt = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",//0x%x},",
                        "SET_NW_TTL", ofp_snt->nw_ttl);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int 
nbapi_of131_dump_dec_nw_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s'},", "DEC_NW_TTL");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int 
nbapi_of131_dump_set_mpls_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_mpls_ttl *ofp_smt = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",
                        //"{'action':'%s','value':0x%x},", 
                        "SET_MPLS_TTL", ofp_smt->mpls_ttl);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of131_dump_dec_mpls_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s'},", "DEC_MPLS_TTL");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of131_dump_cp_ttl_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s'},", "CP_TTL_OUT");
    assert(dp->len < OF_DUMP_INST_SZ-1); 
    return ntohs(action->len);
}

static int
nbapi_of131_dump_cp_ttl_in(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s'},", "CP_TTL_IN");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of131_dump_act_set_field(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_set_field *ofp_sf = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    of131_parse_act_set_field_tlv(ofp_sf, dp->act_parsers, arg);
    return ntohs(action->len);
}

static int
nbapi_of131_dump_set_field_dl_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *mac = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
             "{'action':'%s','value':'%02X:%02X:%02X:%02X:%02X:%02X'},",
             "SET_DL_DST", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
nbapi_of131_dump_set_field_dl_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *mac = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                "{'action':'%s','value':'%02X:%02X:%02X:%02X:%02X:%02X'},",
                "SET_DL_SRC", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
nbapi_of131_dump_set_field_dl_type(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t dl_type = *(uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':0x%x},", 
                        "SET_ETH_TYPE", ntohs(dl_type));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    
    return oxm->length;
}

static int
nbapi_of131_dump_set_field_dl_vlan(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t *vid = (uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",
                        //"{'action':'%s','value':0x%x},", 
                        "SET_VLAN_VID", ntohs(*vid) & 0xfff);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
nbapi_of131_dump_set_field_dl_vlan_pcp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *vlan_pcp = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",
                        //"{'action':'%s','value':0x%x},", 
                        "SET_VLAN_PCP", *vlan_pcp);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
nbapi_of131_dump_set_field_mpls_label(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t label;

    of_get_mpls_label_oxm(oxm->data, &label, 3);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",
                        //"{'action':'%s','value':0x%x},",
                        "SET_MPLS_LABEL", ntohl(label));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
nbapi_of131_dump_set_field_mpls_tc(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *tc = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},",
                        //"{'action':'%s','value':0x%x},",
                        "SET_MPLS_TC", *tc);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
nbapi_of131_dump_set_field_mpls_bos(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *bos = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':0x%x},",
                        "SET_MPLS_BOS", *bos);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
nbapi_of131_dump_set_field_ipv4_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t nw_addr = *(uint32_t *)(oxm->data);
    nw_addr = ntohl(nw_addr);
    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'%d.%d.%d.%d'},",
                        //"SET_IPV4_SRC", 
                        "SET_NW_SRC",
                                (nw_addr >> 24) & 0xFF,
                                (nw_addr >> 16) & 0xFF,
                                (nw_addr >> 8) & 0xFF,
                                nw_addr& 0xFF);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
nbapi_of131_dump_set_field_ipv4_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t nw_addr = *(uint32_t *)(oxm->data);
    nw_addr = ntohl(nw_addr);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value': '%d.%d.%d.%d' },",
                        //"SET_IPV4_DST", 
                                "SET_NW_DST",
                                (nw_addr >> 24) & 0xFF,
                                (nw_addr >> 16) & 0xFF,
                                (nw_addr >> 8) & 0xFF,
                                nw_addr& 0xFF);//ntohl(nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
nbapi_of131_dump_set_field_ipv4_dscp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t dscp  = *(uint8_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':0x%x},",
                        //"SET_IPV4_DSCP"
                        "SET_NW_TOS", dscp);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}
static int
nbapi_of131_dump_set_field_ipv6_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct in6_addr nw_addr;
    char nw_addr_str[INET6_ADDRSTRLEN];

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    memcpy(nw_addr.s6_addr32, (uint8_t *)(oxm->data), OFPXMT_OFB_IPV6_SZ);
    if(!inet_ntop(AF_INET6, &nw_addr, nw_addr_str, INET6_ADDRSTRLEN))
        return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value': '%s' },",
                                "SET_NW_SRC6", nw_addr_str);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}
static int
nbapi_of131_dump_set_field_ipv6_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct in6_addr nw_addr;
    char nw_addr_str[INET6_ADDRSTRLEN];

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    memcpy(nw_addr.s6_addr32, (uint8_t *)(oxm->data), OFPXMT_OFB_IPV6_SZ);
    if(!inet_ntop(AF_INET6, &nw_addr, nw_addr_str, INET6_ADDRSTRLEN))
        return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value': '%s' },",
                                "SET_NW_DST6", nw_addr_str);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
nbapi_of131_dump_set_field_tp_port(struct ofp_oxm_header *oxm, void *arg,
                             char *str)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t port = *(uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        //"{'action':'%s','value':0x%x},", 
                        "{'action':'%s','value':%d},",
                        str, ntohs(port));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
nbapi_of131_dump_set_field_tp_tcp_sport(struct ofp_oxm_header *oxm, void *arg)
{
    return nbapi_of131_dump_set_field_tp_port(oxm, arg, "SET_TCP_SPORT");
}

static int
nbapi_of131_dump_set_field_tp_tcp_dport(struct ofp_oxm_header *oxm, void *arg)
{
    return nbapi_of131_dump_set_field_tp_port(oxm, arg, "SET_TCP_DPORT");
}

static int
nbapi_of131_dump_set_field_tp_udp_sport(struct ofp_oxm_header *oxm, void *arg)
{
    return nbapi_of131_dump_set_field_tp_port(oxm, arg, "SET_UDP_SPORT");
}

static int
nbapi_of131_dump_set_field_tp_udp_dport(struct ofp_oxm_header *oxm, void *arg)
{
    return nbapi_of131_dump_set_field_tp_port(oxm, arg, "SET_UDP_DPORT");
}

static int
nbapi_of131_dump_group_act(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_group *grp_act = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%lu},",
                       //"{'action':'%s','value':%lu},",
                        "GROUP", U322UL(ntohl(grp_act->group_id)));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

struct ofp_act_parsers nbapi_of10_dump_act_parsers = {
    .act_output = nbapi_of_dump_act_out,
    .act_set_vlan = nbapi_of_dump_act_set_vlan,
    .act_set_vlan_pcp = nbapi_of_dump_act_set_vlan_pcp,
    .act_set_dl_dst = nbapi_of_dump_act_set_dl_dst,
    .act_set_dl_src = nbapi_of_dump_act_set_dl_src,
    .act_set_nw_src = nbapi_of_dump_act_set_nw_src,
    .act_set_nw_dst = nbapi_of_dump_act_set_nw_dst
};

struct ofp_inst_parsers nbapi_of10_dump_inst_parsers = {
    .prep_inst_parser = nbapi_inst_parser_alloc,
    .pre_proc = nbapi_dump_inst_parser_pre_proc,
    .post_proc = nbapi_dump_inst_parser_post_proc,
    .fini_inst_parser = nbapi_inst_parser_fini,
};

struct ofp_act_parsers nbapi_of131_dump_act_parsers = {
    .act_output = nbapi_of131_dump_act_output,
    .act_push = nbapi_of131_dump_push_action,
    .act_pop_vlan = nbapi_of131_dump_pop_vlan_action,
    .act_pop_pbb = nbapi_of131_dump_pop_pbb_action,
    .act_pop_mpls = nbapi_of131_dump_pop_mpls_action,
    .act_set_queue = nbapi_of131_dump_set_queue,
    .act_set_nw_ttl = nbapi_of131_dump_set_nw_ttl,
    .act_dec_nw_ttl = nbapi_of131_dump_dec_nw_ttl,
    .act_set_mpls_ttl = nbapi_of131_dump_set_mpls_ttl,
    .act_dec_mpls_ttl = nbapi_of131_dump_dec_mpls_ttl,
    .act_cp_ttl_out = nbapi_of131_dump_cp_ttl_out,
    .act_cp_ttl_in = nbapi_of131_dump_cp_ttl_in,
    .act_set_field = nbapi_of131_dump_act_set_field,
    .act_setf_dl_dst = nbapi_of131_dump_set_field_dl_dst,
    .act_setf_dl_src = nbapi_of131_dump_set_field_dl_src,
    .act_setf_dl_type = nbapi_of131_dump_set_field_dl_type,
    .act_setf_dl_vlan = nbapi_of131_dump_set_field_dl_vlan,
    .act_setf_dl_vlan_pcp = nbapi_of131_dump_set_field_dl_vlan_pcp,
    .act_setf_mpls_label = nbapi_of131_dump_set_field_mpls_label,
    .act_setf_mpls_tc = nbapi_of131_dump_set_field_mpls_tc,
    .act_setf_mpls_bos = nbapi_of131_dump_set_field_mpls_bos,
    .act_setf_ipv4_src = nbapi_of131_dump_set_field_ipv4_src,
    .act_setf_ipv4_dst = nbapi_of131_dump_set_field_ipv4_dst,
    .act_setf_ipv4_dscp = nbapi_of131_dump_set_field_ipv4_dscp,
    .act_setf_ipv6_src = nbapi_of131_dump_set_field_ipv6_src,
    .act_setf_ipv6_dst = nbapi_of131_dump_set_field_ipv6_dst,
    .act_setf_tcp_src = nbapi_of131_dump_set_field_tp_tcp_sport,
    .act_setf_tcp_dst = nbapi_of131_dump_set_field_tp_tcp_dport,
    .act_setf_udp_src = nbapi_of131_dump_set_field_tp_udp_sport,
    .act_setf_udp_dst = nbapi_of131_dump_set_field_tp_udp_dport,
    .act_set_grp = nbapi_of131_dump_group_act
};

struct ofp_inst_parsers nbapi_of131_dump_inst_parsers = {
    .prep_inst_parser = nbapi_inst_parser_alloc,
    .pre_proc = nbapi_of131_dump_inst_parser_pre_proc,
    .post_proc = nbapi_of131_dump_inst_parser_post_proc,
    .goto_inst = nbapi_of131_dump_goto_inst,
    .meter_inst = nbapi_of131_dump_meter_inst,
    .wr_meta_inst = nbapi_of131_dump_wr_meta_inst,
    .wr_act_inst = nbapi_of131_dump_act_inst,
    .apply_act_inst = nbapi_of131_dump_act_inst,
    .clear_act_inst = nbapi_of131_dump_act_inst,
    .fini_inst_parser = nbapi_inst_parser_fini,
};  

char *
nbapi_of10_dump_actions(void *actions, size_t action_len)
{
    struct ofp_inst_parser_arg *dp;
    char *pbuf = NULL;

    dp = of10_parse_actions(NULL, NULL, actions, action_len,
                            &nbapi_of10_dump_inst_parsers,
                            &nbapi_of10_dump_act_parsers, NULL);
    pbuf = dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}

char *
nbapi_of131_dump_actions(void *inst_list, size_t inst_len, bool acts_only)
{
    struct  ofp_inst_parser_arg *dp;
    char    *pbuf;

    dp = of131_parse_instructions(NULL, NULL, inst_list, inst_len,
                                  &nbapi_of131_dump_inst_parsers,
                                  &nbapi_of131_dump_act_parsers,
                                  NULL, acts_only);
    pbuf = dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}
