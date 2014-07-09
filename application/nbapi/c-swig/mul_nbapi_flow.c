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

int
add_static_flow(uint64_t datapath_id, 
                struct flow *fl,
                struct flow *mask, 
                uint16_t priority,
                uint8_t flags,
                mul_act_mdata_t *mdata) 
{
    size_t action_len = 0;
    int ret = 0;

    if (!fl || !mask || !mdata) return -1;

    hton_flow(fl);
    hton_flow(mask);
    action_len = mul_app_act_len(mdata);

    c_wr_lock(&nbapi_app_data->lock);
    mul_service_send_flow_add(nbapi_app_data->mul_service,
                              datapath_id,
                              fl, mask,
                              0xffffffff, 
                              mdata->act_base,
                              action_len, 
                              0, 0,
                              priority,
                              C_FL_ENT_STATIC | flags);
    if (c_service_timed_wait_response(nbapi_app_data->mul_service) > 0) {
        c_log_err("%s: Failed to add a flow.", FN);
        ret = -1;
    }
    c_wr_unlock(&nbapi_app_data->lock);

    ntoh_flow(fl);
    ntoh_flow(mask);

    mul_app_act_free(mdata);
    return ret;
}

int
compare_flows(struct flow *fl1, struct flow *fl2)
{
    return memcmp(fl1, fl2, sizeof(* fl1));
}

int
delete_static_flow(uint64_t datapath_id, 
                   struct flow *fl,
                   struct flow *mask,
                   uint16_t out_port_no, 
                   uint16_t priority,
                   uint8_t flag)

{
    int ret = 0;

    if (!nbapi_app_data->mul_service)
        return -1;

    hton_flow(fl);

    c_wr_lock(&nbapi_app_data->lock);
    mul_service_send_flow_del(nbapi_app_data->mul_service,
                              datapath_id,
                              fl, mask,
                              out_port_no,
                              priority,
                              flag | C_FL_ENT_STATIC,
                              OFPG_ANY);
    if (c_service_timed_wait_response(nbapi_app_data->mul_service) > 0) {
        c_log_err("%s: Failed to delete flow.", FN);
        c_wr_unlock(&nbapi_app_data->lock);
        ret = -1;
    }
    c_wr_unlock(&nbapi_app_data->lock);

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

char *
nbapi_parse_nw_addr_to_str(struct flow * flow, int i)
{
    char *ret = calloc(sizeof(char), 16);
    uint32_t nw_addr;

    if (i == 0) nw_addr = ntohl(flow->ip.nw_src);
    else nw_addr = ntohl(flow->ip.nw_dst);

    if (!ret) return NULL;

    sprintf(ret, "%d.%d.%d.%d", (nw_addr >> 24) & 0xFF,
                                (nw_addr >> 16) & 0xFF,
                                (nw_addr >> 8) & 0xFF,
                                 nw_addr& 0xFF);
    return ret;
}

char *
nbapi_parse_cidr_to_str(uint32_t nw_addr, uint8_t prefix_len)
{
    char *ret;
    if (prefix_len > 32) return NULL;

    ret = calloc(sizeof(char), 64);
    if (!ret) return NULL;

    sprintf(ret, "%d.%d.%d.%d/%d",
            (nw_addr >> 24) & 0xFF,
            (nw_addr >> 16) & 0xFF,
            (nw_addr >> 8) & 0xFF,
             nw_addr& 0xFF,
             prefix_len);
    return ret;
}

/**
 * nbapi_flow_make_flow -
 *
 * Helpers to create flow and mask arguments 
 */
struct flow *
nbapi_make_flow_mask(int which, uint64_t dpid, 
                     char *smac, char *dmac, char *eth_type,
                     char *vid, char *vlan_pcp,
                     char * mpls_label, char *mpls_tc,
                     char *mpls_bos,
                     char * dip, char * sip, char *proto,
                     char *tos, char *dport, char *sport,
                     char *inport, char *table)
{
    int i;
    struct flow * flow;
    struct flow * mask;
    char * mac_str = NULL, *next = NULL;
    struct prefix_ipv4 dst_p, src_p;
    uint32_t nmask;
    uint8_t version;

    flow = calloc(1, sizeof(*flow));
    assert(flow);
    
    mask = calloc(1, sizeof(*mask));
    assert(mask);

    of_mask_set_no_dc(mask);

    if (!dpid) version = 1; /* Special Handling */
    
    version = c_app_switch_get_version_with_id(dpid);
    if(version == 0){
        goto out_err;
    }

    if(!strncmp(smac, "None", strlen(smac))){
        memset(flow->dl_src, 0, 6);
        memset(mask->dl_src, 0, 6); 
    } else {
        mac_str = (void *)smac;
        for(i = 0; i<6;i++){
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next) break;
            mac_str = next +1;
        }
        if(i != 6) {
            c_log_err("%s: Malformed smac address.", FN);
            goto out_err;
        }
    }
    if(!strncmp(dmac,"None", strlen(dmac))){
        memset(flow->dl_dst, 0, 6);
        memset(mask->dl_dst, 0, 6);
    } else {
        mac_str = (void *)dmac;
        for( i = 0; i<6;i++ ){
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next) break;
            mac_str = next + 1;
        }
        if(i != 6) {
            c_log_err("%s: Malformed dmac address. ", FN);
            goto out_err;
        }
    }
    if(!strncmp(eth_type,"None", strlen(eth_type))){
        flow->dl_type = 0;
        mask->dl_type = 0;
    } else {
        nmask = strtoull(eth_type, NULL, 16);
        if ((nmask == ULONG_MAX && errno == ERANGE) ||
             nmask > 0xffff) {
            c_log_err("%s: Malformed eth-type", FN);
            goto out_err;
        }
        flow->dl_type = (uint16_t)(nmask);
        nmask = 0;
    }
    if(!strncmp(vid, "None", strlen(vid))){
        flow->dl_vlan = 0;
        mask->dl_vlan = 0;
    } else {
        flow->dl_vlan = atoi(vid);
        if (flow->dl_vlan > 4095) {
            c_log_err("%s: Malformed vlan-id", FN);
            goto out_err;
        }
    }
    if(!strncmp(vlan_pcp,"None", strlen(vlan_pcp))){
        flow->dl_vlan_pcp = 0;
        mask->dl_vlan_pcp = 0;
    } else {
        if(flow->dl_vlan) {
            flow->dl_vlan_pcp = atoi(vlan_pcp);
            if (flow->dl_vlan_pcp > 7) {
                c_log_err("%s : vlan_pcp out-of-range", FN);
                goto out_err;
            }
        } else {
            c_log_err("%s : vlan_pcp : vlan == NONE. ", FN);
            goto out_err;
        }
    }
    if(!strncmp(mpls_label,"None", strlen(mpls_label))){
        flow->mpls_label = 0;
        mask->mpls_label = 0;
    } else {
        if(version == OFP_VERSION){
            c_log_err("%s : No mpls support in switch. ", FN);
            goto out_err;
        } 
        if(flow->dl_type == (ETH_TYPE_MPLS) ||
           flow->dl_type == (ETH_TYPE_MPLS_MCAST)){
            flow->mpls_label = atoi(mpls_label);
            if (flow->mpls_label > 1048575) {
                c_log_err("%s : mpls_label out-of-range", FN);
                goto out_err;
            }
        } else {
            c_log_err("%s : dl_type != ETH_TYPE_MPLS! ", FN);
            goto out_err;
        }
    }
    if(!strncmp(mpls_tc, "None", strlen(mpls_tc))){
        flow->mpls_tc = 0;
        mask->mpls_tc = 0;
    } else {
        if(version == OFP_VERSION){
            c_log_err("%s : No mpls support in switch. ", FN);
            goto out_err;
        }
        if(flow->dl_type == (ETH_TYPE_MPLS) ||
           flow->dl_type == (ETH_TYPE_MPLS_MCAST)) {
            flow->mpls_tc = atoi(mpls_tc);
            if (flow->mpls_tc > 7) {
                c_log_err("%s : mpls_tc out-of-range", FN);
                goto out_err;
            }
        } else {
            c_log_err("%s : dl_type != ETH_TYPE_MPLS! ", FN);
            goto out_err;
        }
    }
    if(!strncmp(mpls_bos, "None", strlen(mpls_bos))){
        flow->mpls_bos = 0;
        mask->mpls_bos = 0;
    } else {
        if(version == OFP_VERSION){
            c_log_err("%s : No mpls support in switch. ", FN);
            goto out_err;
        }
        if(flow->dl_type == (ETH_TYPE_MPLS) ||
           flow->dl_type == (ETH_TYPE_MPLS_MCAST)){
            flow->mpls_bos = atoi(mpls_bos);
            if (flow->mpls_bos > 1) {
                c_log_err("%s : mpls_bos out-of-range", FN);
                goto out_err;
            }
        } else {
            c_log_err("%s : dl_type != ETH_TYPE_MPLS! ", FN);
            goto out_err;
        }
    }
    
    memset(&mask->ipv6, 0, sizeof(mask->ipv6));
    if(!strncmp(dip, "None", strlen(dip))){
        dst_p.prefixlen = 0;
        dst_p.prefix.s_addr = 0;
        nmask = 0;
    } else {
        i = str2prefix(dip, (void *)&dst_p);
        if ( i <= 0){
            c_log_err("%s : Malformed dip address",FN);
            goto out_err;
        }
        if (dst_p.prefixlen){
            if(flow->dl_type == (ETH_TYPE_IP) || 
               flow->dl_type == (ETH_TYPE_ARP)){
                nmask = make_inet_mask(dst_p.prefixlen);
            } else {
                c_log_err("%s : dl_type != ETH_TYPE_IP or EYH_TYPE_ARP. ", FN);
                goto out_err;
            }
        } 
    }   

    mask->ip.nw_dst = (nmask);
    flow->ip.nw_dst = dst_p.prefix.s_addr & htonl(nmask);
    flow->ip.nw_dst = ntohl(flow->ip.nw_dst);

    if(!strncmp(sip, "None", strlen(sip))) {
        src_p.prefixlen = 0;
        src_p.prefix.s_addr = 0;
        nmask = 0;
    } else {
        i = str2prefix(sip, (void *)&src_p);
        if(i <= 0){
            c_log_err("%s : Malformed sip. ", FN);
            goto out_err;
        }
        if(src_p.prefixlen){
            if(flow->dl_type == (ETH_TYPE_IP)){
                nmask = make_inet_mask(src_p.prefixlen);
            } else {
                c_log_err("%s : dl_type error. ", FN);
                goto out_err;
            }
        } else {
            nmask = 0;
        }
    }

    mask->ip.nw_src = (nmask);
    flow->ip.nw_src = src_p.prefix.s_addr & htonl(nmask);
    flow->ip.nw_src = ntohl(flow->ip.nw_src);

    if(!strncmp(proto, "None", strlen(proto))) {
        flow->nw_proto = 0;
        mask->nw_proto = 0;
    } else {
        if(flow->dl_type == (ETH_TYPE_IP)) {
            flow->nw_proto = atoi(proto);
        } else {
            c_log_err("%s proto : dl_type != ETH_TYPE_IP", FN);
            goto out_err;
        }
    }
    if(!strncmp(tos, "None", strlen(tos))){
        flow->nw_tos = 0;
        mask->nw_tos = 0;
    } else {
        if(flow->dl_type == (ETH_TYPE_IP)){
            flow->nw_tos = atoi(tos);
            if (flow->nw_tos > 63) {
                c_log_err("%s : nw_tos out-of-range", FN);
                goto out_err; 
            }
        } else {
            c_log_err("%s nw_tos : dl_type != ETH_TYPE_IP", FN);
            goto out_err;
        }
    }
    if(!strncmp(dport, "None", strlen(dport))){
        flow->tp_dst = 0;
        mask->tp_dst = 0;
    } else {
        if((flow->dl_type == ( ETH_TYPE_IP) ) &&
            (flow->nw_proto == IP_TYPE_UDP || flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_dst = atoi(dport);
        } else {
            c_log_err("%s : dl_type != ETH_TYPE_IP and ip_type != UDP/TCP. ", FN);
            goto out_err;
        }
    }
    if(!strncmp(sport, "None", strlen(sport))){
        flow->tp_src = 0;
        mask->tp_src = 0;
        } else {
        if((flow->dl_type = ETH_TYPE_IP) &&
        (flow->nw_proto == (IP_TYPE_UDP) || flow->nw_proto == (IP_TYPE_TCP))) {
            flow->tp_src = (atoi(sport));
        } else {
            c_log_err("%s : dl_type != ETH_TYPE_IP || ip_type != UDP/TCP. ",FN);
            goto out_err;
        }
    }
    if(!strncmp(inport,"None", strlen(inport))){
        flow->in_port = 0;
        mask->in_port = 0;
    } else {
        flow->in_port = atoi(inport);
    }

    flow->table_id = atoi(table);

    mask->tunnel_id = 0;
    mask->metadata = 0;

    switch(which){
    case 0:
        free(mask);
        return flow; 
    case 1:
        free(flow);
        return mask;
    }

out_err:
    if (flow) free(flow);
    if (mask) free(mask);
    return NULL;
}


/* helpers to create arguments */
struct flow *
nbapi_fabric_make_flow(char *nw_src_str, char *dl_src_str,
                       uint16_t in_port)
{
    char *mac_str = NULL, *next = NULL;
    struct in_addr in_addr;
    struct flow *fl;
    int i = 0;

    fl = calloc(1, sizeof(fl));
    if (!fl) return NULL;

    if (inet_pton(AF_INET, nw_src_str, &in_addr) <= 0) {
        free(fl);
        return NULL;
    }

    fl->ip.nw_src = ntohl(in_addr.s_addr);

    mac_str = (void *)dl_src_str;
    for(i = 0; i < 6; i++) {
        fl->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next) break;
        mac_str = next +1;
    }
    if(i != 6) {
        c_log_err("%s: Malformed smac address.", FN);
        free(fl);
        return NULL;
    }

    fl->in_port = in_port; 
    return fl;
}

mul_act_mdata_t *
nbapi_mdata_alloc(uint64_t dpid)
{   
    struct mul_act_mdata *mdata;
    
    mdata = calloc(1, sizeof(*mdata));
    if (!mdata) return NULL;
    mul_app_act_alloc(mdata);
    
    if(mul_app_act_set_ctors(mdata, dpid))  {
        c_log_err("%s : No such switch 0x%llx", FN,
                  U642ULL(dpid));
        mul_app_act_free(mdata);
        free(mdata);
        return NULL;
    }
    return mdata;
}       

void
nbapi_mdata_inst_write(mul_act_mdata_t* mdata, uint64_t dpid)
{
    uint8_t version;

    version = c_app_switch_get_version_with_id(dpid);
    if(version == OFP_VERSION) {
        return;
    }

    if(mul_app_set_inst_write(mdata)) {
        c_log_err("%s : can't set write instruction. ",FN);
        free(mdata);
        return;
    }
}   

void
nbapi_mdata_inst_apply(mul_act_mdata_t* mdata, uint64_t dpid)
{
    uint8_t version;
    version = c_app_switch_get_version_with_id(dpid);

    if (version == OFP_VERSION) {
        return;
    }

    if (mul_app_set_inst_apply(mdata)) {
        c_log_err("%s : can't set apply instruction. ", FN);
        free(mdata);
        return;
    }
}

int
nbapi_action_to_mdata(mul_act_mdata_t* mdata, 
                              char *action_type,
                              char *action_value)
{
    if(!strncmp(action_type, "OUTPUT", strlen(action_type))) {
        if(mul_app_action_output(mdata,
            (uint32_t)strtoull(action_value, NULL, 0)) <= 0){
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "CP_TTL_IN", strlen(action_type))) {
        if(mul_app_action_cp_ttl(mdata, true) <= 0) {
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "CP_TTL_OUT", strlen(action_type))) {
        if(mul_app_action_cp_ttl(mdata, false) <= 0) {
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "DEC_MPLS_TTL", strlen(action_type))) {
        if(mul_app_action_dec_mpls_ttl(mdata) <=0) {
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "DEC_NW_TTL", strlen(action_type))) {
        if(mul_app_action_dec_nw_ttl(mdata) <= 0 ) {
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "GROUP", strlen(action_type))) {
        if(mul_app_action_set_group(mdata,
                strtoull(action_value, NULL, 10)) <=0) {
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "SET_NW_DST", strlen(action_type))) {
        struct in_addr ip_addr;
        if(inet_aton(action_value, &ip_addr)<=0){
            return -3;
        }
        if (mul_app_action_set_nw_daddr(mdata, ntohl(ip_addr.s_addr)) <= 0){
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "SET_NW_SRC", strlen(action_type))) {
        struct in_addr ip_addr;
        if(inet_aton(action_value, &ip_addr)<=0){
            return -3;
        }
        if (mul_app_action_set_nw_saddr(mdata, ntohl(ip_addr.s_addr)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "PUSH_MPLS", strlen(action_type))) {
        if(mul_app_action_push_hdr(mdata, ETH_TYPE_MPLS) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_NW_TOS", strlen(action_type))) {
        if(mul_app_action_set_nw_tos(mdata, atoi(action_value)) <= 0 ) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "PUSH_PBB", strlen(action_type))) {
        if(mul_app_action_push_hdr(mdata, ETH_TYPE_PBB)<=0 ) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "PUSH_VLAN", strlen(action_type))) {
        if( mul_app_action_push_hdr(mdata, ETH_TYPE_VLAN) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_DL_DST", strlen(action_type))) {
        uint8_t dmac[6];
        char *mac_str, *next = NULL;
        int i = 0;
        mac_str = (void *)action_value;
        for(i = 0; i < 6; i++){
            dmac[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next) break;
            mac_str = next +1;
        }
        if(i != 6)
            return -1;
        if( mul_app_action_set_dmac(mdata, dmac) <=0){
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_ETH_TYPE", strlen(action_type))){
        if(mul_app_action_set_eth_type(mdata,
                                       (uint16_t)atoi(action_value)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_MPLS_BOS", strlen(action_type))){
        if(mul_app_action_set_mpls_bos(mdata, atoi(action_value)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_MPLS_LABEL", strlen(action_type))) {
        if(mul_app_action_set_mpls_label(mdata, atoi(action_value)) <= 0) { 
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_MPLS_TC", strlen(action_type))){
        if(mul_app_action_set_mpls_tc(mdata, atoi(action_value)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_MPLS_TTL", strlen(action_type))){
        if(mul_app_action_set_mpls_ttl(mdata, atoi(action_value)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_NW_TTL", strlen(action_type))){
        if(mul_app_action_set_nw_ttl(mdata, atoi(action_value)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_QUEUE", strlen(action_type))){
        if(mul_app_action_set_queue(mdata, atoi(action_value)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_DL_SRC", strlen(action_type))) { 
        uint8_t smac[6];
        char *mac_str, *next = NULL;
        int i = 0;
        mac_str = (void *)action_value;
        for(i = 0; i<6; i++) {
            smac[i] = (uint8_t)strtoull(mac_str, &next, 16);
            if(mac_str == next) break;
            mac_str = next + 1;
        }
        if(i != 6) return -1;
        if(mul_app_action_set_smac(mdata, smac) <=0 ){
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "SET_VLAN_VID", strlen(action_type))) {
        if(mul_app_action_set_vid(mdata, strtoull(action_value, NULL, 10)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "SET_VLAN_PCP", strlen(action_type))) { 
        if (mul_app_action_set_vlan_pcp(mdata,
                            strtoull(action_value, NULL, 10)) <= 0) {
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "POP_MPLS", strlen(action_type))) {
        if (mul_app_action_strip_mpls(mdata, atoi(action_value)) <=0) {
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "POP_PBB", strlen(action_type))) {
        if (mul_app_action_strip_pbb(mdata) <= 0){
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "STRIP_VLAN", strlen(action_type)) || 
       !strncmp(action_type, "POP_VLAN", strlen(action_type)) ){
        if (mul_app_action_strip_vlan(mdata)<=0){
            return -1;
        }
        return 0;
    }
    else if (!strncmp(action_type, "SET_TP_UDP_SRC", strlen(action_type)) ||
    !strncmp(action_type, "SET_UDP_SPORT", strlen(action_type)) ){
        if (mul_app_action_set_tp_udp_sport(mdata, atoi(action_value)) <= 0){
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_TP_TCP_SRC", strlen(action_type)) ||
            !strncmp(action_type, "SET_TCP_SPORT", strlen(action_type))) {
        if(mul_app_action_set_tp_tcp_sport(mdata, atoi(action_value)) <= 0 ) {
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_UDP_DPORT", strlen(action_type)) ||
        !strncmp(action_type, "SET_TP_UDP_DST", strlen(action_type)) ) {
        if(mul_app_action_set_tp_udp_dport(mdata, atoi(action_value)) <= 0 ){
            return -1;
        }
        return 0;
    }
    else if(!strncmp(action_type, "SET_TCP_DPORT", strlen(action_type)) ||
            !strncmp(action_type, "SET_TP_TCP_DST", strlen(action_type)) ) {
        if(mul_app_action_set_tp_tcp_dport(mdata, atoi(action_value)) <= 0 ) {
            return -1;
        }
        return 0;
    }

    return -2;
}

void    
nbapi_mdata_free(mul_act_mdata_t *mdata)
{
    mul_app_act_free(mdata);
}

static void 
make_flow_list(nbapi_switch_flow_list_t *list, c_ofp_flow_info_t *cofp_fi)
{
    c_ofp_flow_info_t *cofp_arg;

    cofp_arg = calloc(1, ntohs(cofp_fi->header.length));
    if (!cofp_arg) return;

    memcpy(cofp_arg, cofp_fi, ntohs(cofp_fi->header.length));
    ntoh_c_ofp_flow_info(cofp_arg);
    list->array = g_slist_append(list->array, cofp_arg);
}

static void
nbapi_make_flow_list(void *list, void *cofp_fi)
{
    make_flow_list((nbapi_switch_flow_list_t *)list, 
                    (c_ofp_flow_info_t *)cofp_fi);
}

//not used
struct flow * nbapi_ntoh_flow(struct flow * fl){
   // ntoh_flow(fl);
    return fl;
}
//not used
uint64_t str_dpid_to64(char * dpid){
    uint64_t datapath_id = strtoull(dpid, NULL, 16);
    return datapath_id;
}

nbapi_switch_flow_list_t
get_flow(uint64_t datapath_id)
{
    int n_flows;
    nbapi_switch_flow_list_t list;

    list.array = NULL;
    list.length = 0;

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return list;
    }
    n_flows = mul_get_flow_info(nbapi_app_data->mul_service,
                                datapath_id, false,
                                false, true, &list,
                                nbapi_make_flow_list);
    c_wr_unlock(&nbapi_app_data->lock);

    list.length = n_flows;

    return list;
}

char *
nbapi_dump_single_flow_action(c_ofp_flow_info_t *cofp_fi)
{
    char        *pbuf;
    size_t      action_len;
    uint64_t    dpid = U642ULL(cofp_fi->datapath_id);
    uint8_t     version;

    version = c_app_switch_get_version_with_id(dpid);
    if (version != OFP_VERSION && version != OFP_VERSION_131) {
        c_log_err("%s: Unable to parse flow:Unknown OFP version", FN);
        return NULL;
    }

    action_len = ntohs(cofp_fi->header.length) - sizeof(*cofp_fi);
    //action_len = cofp_fi->header.length - sizeof(*cofp_fi);
    if (version == OFP_VERSION)
        pbuf = nbapi_of10_dump_actions(cofp_fi->actions, action_len, false);
    else if (version == OFP_VERSION_131)
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

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%u},",
                        "OUTPUT", ntohs(of_ao->port));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
nbapi_of_dump_act_set_vlan(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_vid *vid_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'0x%04x'},",
                        "SET_VLAN", ntohs(vid_act->vlan_vid));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vid_act);
 }

static int
nbapi_of_dump_act_set_vlan_pcp(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_pcp *vlan_pcp_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'0x%04x'},", 
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
                   "{'action':'%s','value':'%02x:%02x:%02x:%02x:%02x:%02x'},",
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
                   "{'action':'%s','value':'%02x:%02x:%02x:%02x:%02x:%02x'},",
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

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'0x%08x'},", 
                        "SET_NW_SRC", ntohl(nw_addr_act->nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static int
nbapi_of_dump_act_set_nw_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':'0x%08x'},", 
                        "SET_NW_DST", ntohl(nw_addr_act->nw_addr));
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
                        "{'type':'%s','table_id':%d},", 
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
                        "{'type':'%s','actions': [ ", pinst);
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
                        "{'type':'%s','meter-id':%d},",
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

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':%d},", 
                        "OUTPUT", ntohl(of_ao->port));
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
        push_str = "PUSH_VLAN";
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
                        "{'action':'%s','value':0x%x},",
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
                        "{'action':'%s','value':0x%x},", 
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
                        "{'action':'%s','value':0x%x},",
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
                        "{'action':'%s','value':0x%x},",
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
                        "{'action':'%s','value':0x%x},", 
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
             "{'action':'%s','value':'0x%02x:%02x:%02x:%02x:%02x:%02x'},",
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
                "{'action':'%s','value':'0x%02x:%02x:%02x:%02x:%02x:%02x'},",
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
                       "{'action':'%s','value':0x%x},", 
                        "SET_VLAN", ntohs(*vid));
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
                        "{'action':'%s','value':0x%x},", 
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
                        "{'action':'%s','value':0x%x},",
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
                        "{'action':'%s','value':0x%x},",
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

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':0x%x},",
                        "SET_IPV4_SRC", ntohl(nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
nbapi_of131_dump_set_field_ipv4_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t nw_addr = *(uint32_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "{'action':'%s','value':0x%x},",
                        "SET_IPV4_DST", ntohl(nw_addr));
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
                        "SET_IPV4_DSCP", dscp);
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
                       "{'action':'%s','value':0x%x},", str, ntohs(port));
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
nbapi_of10_dump_actions(void *actions, size_t action_len, bool acts_only UNUSED)
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
nbapi_of131_dump_actions(void *inst_list, size_t inst_len, bool acts_only UNUSED)
{
    struct  ofp_inst_parser_arg *dp;
    char    *pbuf;

    dp = of131_parse_instructions(NULL, NULL, inst_list, inst_len,
                                  &nbapi_of131_dump_inst_parsers,
                                  &nbapi_of131_dump_act_parsers,
                                  NULL, false);
    pbuf = dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}
