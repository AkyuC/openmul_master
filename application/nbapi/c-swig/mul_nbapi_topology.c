/*
 *  mul_nbapi_topology.c: Mul Northbound Topology API for Mul Controller
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

#include "mul_common.h"
#include "mul_nbapi_common.h"
#include "mul_nbapi_topology.h"
#include "mul_nbapi_endian.h"

struct c_ofp_switch_add *
get_switch_general(uint64_t datapath_id)
{
    struct cbuf *b;
    struct c_ofp_switch_add *osf;
    struct c_ofp_switch_add *ret_osf;

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return NULL;
    }

    b = mul_get_switch_detail(nbapi_app_data->mul_service, datapath_id);
    c_wr_unlock(&nbapi_app_data->lock);

    if (!b) {
        return NULL;
    }

    osf = CBUF_DATA(b);
    ret_osf = calloc(1, ntohs(osf->header.length));
    if (!ret_osf) {
        free_cbuf(b);
        return NULL;
    }

    memcpy(ret_osf, osf, ntohs(osf->header.length));

    /* convert to host encoding */
    ntoh_c_ofp_switch_add(ret_osf);
    free_cbuf(b);
    
    return ret_osf;
}

#if 0
/* This function is Unused */
void nbapi_mem_free_c_ofp_switch_add(struct c_ofp_switch_add * ret_val){
    free(ret_val);
}
#endif
char *
general_capabilities_tostr(uint32_t capabilities)
{
    char *pbuf;
    size_t len = 0;

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);

    if (!pbuf) return NULL;

    if (capabilities == 0) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ -1,
                        "  no_capabilities");
        return pbuf;
    }
    if (capabilities & OFPC_FLOW_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len - 1, 
                        " FLOW_STATS ");
    }
    if (capabilities & OFPC_TABLE_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len - 1,
                        " TABLE_STATS ");
    }
    if (capabilities & OFPC_PORT_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len - 1,
                        " PORT_STATS ");
    }
    if (capabilities & OFPC_STP) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len - 1,
                        " STP ");
    }
    if (capabilities & OFPC_IP_REASM) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len - 1,
                        " IP_REASM ");
    }
    if (capabilities & OFPC_QUEUE_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len - 1,
                        " QUEUE_STATS ");
    }
    if (capabilities & OFPC_ARP_MATCH_IP) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len -1,
                        " ARP_MATCH_IP");
    }

    assert(len < MUL_SERVLET_PBUF_DFL_SZ -1);
    return pbuf;
}

char *
general131_capabilities_tostr(uint32_t capabilities) 
{
    char *pbuf;
    size_t len = 0;

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    if (!pbuf ) return NULL;

    if (capabilities == 0) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ -len - 1,
                        " no_capabilities");
        return pbuf;
    }
    if (capabilities & OFPC131_FLOW_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ -len - 1,
                        " FLOW_STATS ");
    }
    if (capabilities & OFPC131_TABLE_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ -len - 1,
                        " TABLE_STATS ");
    }
    if (capabilities & OFPC131_PORT_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ -len - 1,
                        " PORT_STATS ");
    }
    if (capabilities & OFPC131_GROUP_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ -len - 1,
                        " GROUP_STATS ");
    }
    if (capabilities & OFPC131_IP_REASM) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len -1,
                        " IP_REASM ");
    }
    if (capabilities & OFPC131_QUEUE_STATS) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len -1,
                        " QUEUE_STATS ");
    }
    if (capabilities & OFPC131_PORT_BLOCKED) {
        len += snprintf(pbuf + len, MUL_SERVLET_PBUF_DFL_SZ - len -1,
                        " PORT_BLOCKED");
    }

    assert(len < MUL_SERVLET_PBUF_DFL_SZ -1);
    return pbuf;
}

int
parse_alias_id(uint32_t alias_id)
{
    int i_aid = 0;
    i_aid = (int)(U322UL(alias_id));

    return i_aid;
}
#if 0
struct ofp_switch_features *
get_switch(uint64_t datapath_id)
{
    struct ofp_switch_features *ret_val;
    struct ofp_switch_features *osf;
    struct cbuf *b;

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return NULL;
    }

    b = mul_get_switch_detail(nbapi_app_data->mul_service, datapath_id);
    c_wr_unlock(&nbapi_app_data->lock);

    if (!b) {
        return NULL;
    }

    osf = (void *)(b->data);
    ret_val = calloc(ntohs(osf->header.length),1);
    
    if (!ret_val) {
        free_cbuf(b);
        return NULL;
    }

    memcpy(ret_val,osf,ntohs(osf->header.length));
    
    /*convert to host encoding */
    ntoh_ofp_switch_features(ret_val);

    free_cbuf(b);

    return ret_val;
}
#endif

struct of_flow_tbl_props *
get_switch_table(uint64_t dpid, uint8_t table)
{
    struct cbuf *b = NULL;
    struct c_ofp_auxapp_cmd * cofp_auc;
    struct c_ofp_switch_feature_common *cofp_f;
    struct of_flow_tbl_props *ofp_tb;
    uint8_t version;

    version = c_app_switch_get_version_with_id(dpid);
    if (version != OFP_VERSION_131) return NULL;

    c_wr_lock(&nbapi_app_data->lock);

    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
    }
    
    b = mul_get_switch_features(nbapi_app_data->mul_service, dpid, table,
                                C_AUX_CMD_MUL_SWITCH_TABLE_FEAT);
    c_wr_unlock(&nbapi_app_data->lock);
     
    if (!b) return NULL;

    cofp_auc = CBUF_DATA(b);
    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_TABLE_FEAT)) {
        free_cbuf(b);
        return NULL;
    }

    if(ntohs(cofp_auc->header.length) - 
        (sizeof(*cofp_auc) + sizeof(*cofp_f)) <
        sizeof(struct of_flow_tbl_props)) {
        free_cbuf(b);
        return NULL;
    }

    cofp_f = ASSIGN_PTR(cofp_auc->data);
    ofp_tb = calloc(1, sizeof(*ofp_tb));
    memcpy(ofp_tb, cofp_f->data, sizeof(*ofp_tb));
    free_cbuf(b);

    c_log_debug("%s Done", FN);
    return ofp_tb;
}
#if 0
void nbapi_mem_free_of_flow_tbl_props(struct of_flow_tbl_props * ofp_tb){
    free(ofp_tb);
}
#endif

char *
get_table_bminstruction(uint32_t bm_inst) 
{
    //bm_inst, bm_inst_miss
    char *pbuf;
    int bit = 0;
    size_t len = 0;
    
    pbuf = calloc(1, OF_DUMP_TBL_FEAT_SZ);

    for(; bit <= OFPIT_METER; bit++) {
        if (1<<bit & bm_inst) {
            switch(bit) {
                case OFPIT_GOTO_TABLE:
                    len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ -len -1,
                                    " inst-goto");
                    break;
                case OFPIT_WRITE_METADATA:
                    len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ -len -1, 
                                    " inst-metadata");
                    break;
                case OFPIT_WRITE_ACTIONS:
                    len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ -len -1,
                                    " inst-write-act");
                    break;
                case OFPIT_APPLY_ACTIONS:
                    len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ -len -1,
                                    " inst-apply-act");
                    break;
                case OFPIT_CLEAR_ACTIONS:
                    len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ -len -1,
                                    " inst-clear-act");
                    break;
                case OFPIT_METER:
                    len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ -len -1,
                                    " inst-meter");
                    break;
            }
        }
    }
    assert(len < OF_DUMP_TBL_FEAT_SZ -1);
    return pbuf;
}

char *
get_table_next_tables(uint32_t *bm_next_tables)
{
    char *pbuf;
    int bit = 0;
    size_t len = 0;

    pbuf = calloc(1, OF_DUMP_TBL_FEAT_SZ);
    for(bit = 0; bit<=254; bit++) {
        if (GET_BIT_IN_32MASK(bm_next_tables, bit)){
            len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, 
                            " %d", bit);
        }
    }
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
    return pbuf;
}

char *
get_act_type(uint32_t actions)
{
    char *pbuf;
    int bit = 0;
    size_t len = 0;

    pbuf = calloc(1, OF_DUMP_TBL_FEAT_SZ);
    for (; bit < OFPAT131_POP_PBB; bit++) {
        if(1<<bit & actions){
            switch(bit){
            case OFPAT131_OUTPUT:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-output");
                break;
            case OFPAT131_COPY_TTL_OUT:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-copy-ttl-out");
                break;
            case OFPAT131_COPY_TTL_IN:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-copy-ttl-in");
                break;
            case OFPAT131_MPLS_TTL:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-mpls-ttl");
                break;
            case OFPAT131_DEC_MPLS_TTL:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-mpls-dec-ttl");
                break;
            case OFPAT131_PUSH_VLAN:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-push-vlan");
                break;
            case OFPAT131_POP_VLAN:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-pop-vlan");
                break;
            case OFPAT131_PUSH_MPLS:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-push-mpls");
                break;
            case OFPAT131_POP_MPLS:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-pop-mpls");
                break;
            case OFPAT131_SET_QUEUE:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-set-queue");
                break;
            case OFPAT131_GROUP:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-set-group");
                break;
            case OFPAT131_SET_NW_TTL:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-set-nw-ttl");
                break;
            case OFPAT131_DEC_NW_TTL:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-dec-nw-ttl");
                break;
            case OFPAT131_SET_FIELD:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-set-field");
                break;
            case OFPAT131_PUSH_PBB:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-push-pbb");
                break;
            case OFPAT131_POP_PBB:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ- len -1, " act-pbb");
                break;
            }
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    return pbuf;
}

char *
get_table_set_field(uint32_t *set_field)
{
    char *pbuf;
    int bit = 0;
    size_t len = 0;

    pbuf = calloc(1, OF_DUMP_TBL_FEAT_SZ);

    for (bit = 0; bit < OFPXMT_OFB_IPV6_EXTHDR; bit++) {
    if (GET_BIT_IN_32MASK(set_field, bit)) {
        switch (bit) {
            case OFPXMT_OFB_IN_PORT:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " in-port");
                break;
            case OFPXMT_OFB_IN_PHY_PORT:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " in-phy-port");
                break;
            case OFPXMT_OFB_METADATA:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " metadata");
                break;
            case OFPXMT_OFB_ETH_DST:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " eth-dst");
                break;
            case OFPXMT_OFB_ETH_SRC:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " eth-src");
                break;
            case OFPXMT_OFB_ETH_TYPE:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " eth-type");
                break;
            case OFPXMT_OFB_VLAN_VID:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " vlan-vid");
                break;
            case OFPXMT_OFB_VLAN_PCP:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " vlan-pcp");
                break;
            case OFPXMT_OFB_IP_DSCP:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ip-dscp");
                break;
            case OFPXMT_OFB_IP_ECN:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ip-ecn");
                break;
            case OFPXMT_OFB_IP_PROTO:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ip-proto");
                break;
            case OFPXMT_OFB_IPV4_SRC:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipv4-src");
                break;
            case OFPXMT_OFB_IPV4_DST:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipv4-dst");
                break;
            case OFPXMT_OFB_TCP_SRC:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " tcp-src");
                break;
            case OFPXMT_OFB_TCP_DST:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " tcp-dst");
                break;
            case OFPXMT_OFB_UDP_SRC:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " udp-src");
                break;
            case OFPXMT_OFB_UDP_DST:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " udp-dst");
                break;
            case OFPXMT_OFB_SCTP_SRC:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " sctp-src");
                break;
            case OFPXMT_OFB_SCTP_DST:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " sctp-dst");
                break;
            case OFPXMT_OFB_ICMPV4_TYPE:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipcmp4-type");
                break;
            case OFPXMT_OFB_ICMPV4_CODE:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " icmp4-code");
                break;
            case OFPXMT_OFB_ARP_OP:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " arp-opcode");
                break;
            case OFPXMT_OFB_ARP_SPA:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " arp-ipv4-src");
                break;
            case OFPXMT_OFB_ARP_TPA:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " arp-ipv4-dst");
                break;
            case OFPXMT_OFB_ARP_SHA:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " arp-src-mac");
                break;
            case OFPXMT_OFB_ARP_THA:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " arp-dst-mac");
                break;
            case OFPXMT_OFB_IPV6_SRC:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipv6-src");
                break;
            case OFPXMT_OFB_IPV6_DST:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipv6-dst");
                break;
            case OFPXMT_OFB_IPV6_FLABEL:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipv6-fl-label");
                break;
            case OFPXMT_OFB_ICMPV6_TYPE:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " icmpv6-type");
                break;
            case OFPXMT_OFB_ICMPV6_CODE:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " icmpv6-code");
                break;
            case OFPXMT_OFB_IPV6_ND_TARGET:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipv6-nd-target");
                break;
            case OFPXMT_OFB_IPV6_ND_SLL:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipv6-nd-sll");
                break;
            case OFPXMT_OFB_IPV6_ND_TLL:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " ipv6-nd-tll");
                break;
            case OFPXMT_OFB_MPLS_LABEL:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " mpls-label");
                break;
            case OFPXMT_OFB_MPLS_TC:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " mpls-tc");
                break;
            case OFPXMT_OFB_MPLS_BOS:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " mpls-bos");
                break;
            case OFPXMT_OFB_PBB_ISID:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " pbb-isid");
                break;
            case OFPXMT_OFB_TUNNEL_ID:
                len += snprintf(pbuf + len, OF_DUMP_TBL_FEAT_SZ - len - 1, " tun-id");
                break;
            }
        }
    }
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
    return pbuf;
}

struct ofp_group_features *
get_switch_group(uint64_t dpid)
{
    struct cbuf *b = NULL;
    struct c_ofp_auxapp_cmd * cofp_auc;
    struct c_ofp_switch_feature_common *cofp_f;
    struct ofp_group_features *ofp_gf;
    uint8_t version;

    version = c_app_switch_get_version_with_id(dpid);
    if(version != OFP_VERSION_131) return NULL;

    c_wr_lock(&nbapi_app_data->lock);
    b = mul_get_switch_features(nbapi_app_data->mul_service, dpid,
                                0, C_AUX_CMD_MUL_SWITCH_GROUP_FEAT);
    c_wr_unlock(&nbapi_app_data->lock);
    if (!b) return NULL;

    cofp_auc = CBUF_DATA(b);
    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_GROUP_FEAT)){
        free_cbuf(b);
        return NULL;
    }

    if(ntohs(cofp_auc->header.length) -
        (sizeof(*cofp_auc) + sizeof(*cofp_f)) <
        sizeof(struct ofp_group_features)) {
        free_cbuf(b);
        return NULL;
    }

    cofp_f = ASSIGN_PTR(cofp_auc->data);
    ofp_gf = calloc(1, sizeof(*ofp_gf));
    memcpy(ofp_gf, cofp_f->data, sizeof(*ofp_gf));
    ntoh_ofp_group_features(ofp_gf);
    free_cbuf(b);
    return ofp_gf;
}
#if 0
void nbapi_mem_free_ofp_group_features(struct ofp_group_features *ofp_gf){
    free(ofp_gf);
}
#endif

char *
get_supported_group(uint32_t types) 
{//to .h
    //group_features -> types
    int bit = 0;
    size_t len = 0;
    char * pbuf;
    pbuf = calloc(1, OF_DUMP_GRP_FEAT_SZ);

    if (!pbuf) return NULL;

    for(;bit <= OFPGT_FF;bit++) {
        if(1<<bit & types) {
            switch(bit) {
            case OFPGT_ALL:
                len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1, " grp-all");
                break;
            case OFPGT_SELECT:
                len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1, " grp-select");
                break;
            case OFPGT_INDIRECT:
                len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1, " grp-indirect");
                break;
            case OFPGT_FF:
                len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1, " grp-ff");
                break;
            }
        }
    }
    assert(len < OF_DUMP_GRP_FEAT_SZ -1);
    return pbuf;
}

char *
get_group_capabilities(uint32_t types)
{
    int bit = 0;
    size_t len = 0;
    char * pbuf;
    pbuf = calloc(1, OF_DUMP_GRP_FEAT_SZ);
    for(;bit <= 3;bit++) {
        if(1<<bit & types) {
            switch(bit) {
            case OFPGFC_SELECT_WEIGHT:
                len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1,
                                " grp-flags-select-weight");
                break;
            case OFPGFC_SELECT_LIVENESS:
                len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1,
                                "grp-flags-select-liveness");
                break;
            case OFPGFC_CHAINING:
                len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1,
                                "grp-flags-chaining");
                break;
            case OFPGFC_CHAINING_CHECKS:
               len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1,
                               "grp-flags-chaining-check");
                break;
            }
        }
    }
    assert(len < OF_DUMP_GRP_FEAT_SZ -1);
    return pbuf;
}

char *
get_group_act_type(uint32_t *actions, int type)
{
    return get_act_type(actions[type]);
}

struct ofp_meter_features *
get_switch_meter(uint64_t dpid)
{
    struct cbuf *b = NULL;
    struct c_ofp_auxapp_cmd * cofp_auc;
    struct c_ofp_switch_feature_common *cofp_f;
    struct ofp_meter_features *ofp_mf;
    uint8_t version;

    version = c_app_switch_get_version_with_id(dpid);
    if(version != OFP_VERSION_131) return NULL;

    c_wr_lock(&nbapi_app_data->lock);
    b = mul_get_switch_features(nbapi_app_data->mul_service, dpid,
                                0, C_AUX_CMD_MUL_SWITCH_METER_FEAT);
    c_wr_unlock(&nbapi_app_data->lock);
    if (!b) return NULL;

    cofp_auc = CBUF_DATA(b);
    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_METER_FEAT)){
        free_cbuf(b);
        return NULL;
    }

    if(ntohs(cofp_auc->header.length) -
        (sizeof(*cofp_auc) + sizeof(*cofp_f)) <
        sizeof(struct ofp_meter_features)) {
        free_cbuf(b);
        return NULL;
    }

    cofp_f = ASSIGN_PTR(cofp_auc->data);
    ofp_mf = calloc(1, sizeof(*ofp_mf));
    memcpy(ofp_mf, cofp_f->data, sizeof(*ofp_mf));
    ntoh_ofp_meter_features(ofp_mf);
    free_cbuf(b);
    return ofp_mf;
}
#if 0
void nbapi_mem_free_ofp_meter_features(struct ofp_meter_features *ofp_mf){
    free(ofp_mf);
}
#endif

char *
get_band_type(uint32_t band_types) 
{
    int bit = 0;
    size_t len = 0;
    char * pbuf;
    pbuf = calloc(1, OF_DUMP_METER_FEAT_SZ);
    for(;bit <= OFPMBT_DSCP_REMARK;bit++) {
        if(1<<bit & band_types) {
            switch(bit) {
                case OFPMBT_DROP:
                    len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1, " band-drop");
                break;
                case OFPMBT_DSCP_REMARK:
                    len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1    , " band-dscp-mark");
                break;
                case OFPMBT_EXPERIMENTER:
                    len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ -len -1    , " band-exp");
                break;
            }
        }
    }
    assert(len < OF_DUMP_METER_FEAT_SZ -1);
    return pbuf;
}

char *
get_band_flag(uint32_t capabilities) 
{
    int bit = 0;
    size_t len = 0;
    char * pbuf;
    pbuf = calloc(1, OF_DUMP_METER_FEAT_SZ);
    for(;bit <= 3 ; bit++){
        if(1<<bit & capabilities) {
            switch(1<<bit) {
            case OFPMF_KBPS:
            len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ - len -1,
                            " meter-kbps");
            break;
            case OFPMF_PKTPS:
            len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ - len -1,
                            " meter-pps");
            break;
            case OFPMF_BURST:
            len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ - len -1,
                            " meter-burst");
            break;
            case OFPMF_STATS:
            len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ - len -1,
                            " meter_stats");
            break;
            }
        }
    }
    assert(len < OF_DUMP_METER_FEAT_SZ -1);
    return pbuf;
}

int 
nbapi_meter_add (uint64_t dpid, uint32_t meter_id, char * meter_type, 
                int burst, int stats, char * c_rates, char * c_bursts, 
                char * c_prec, int nbands) 
{
    struct of_meter_mod_params m_parms;
    mul_act_mdata_t * mdata;//array
    int * rates, * bursts, * prec;
    int i, ret = -1;
    mdata = (mul_act_mdata_t *)malloc(nbands*sizeof(mul_act_mdata_t));
    rates = ctomdata(c_rates, nbands);
    bursts = ctomdata(c_bursts, nbands);
    prec = ctomdata(c_prec, nbands);
    
    if(nbands == 0) {
        return -2;
    }
    if(nbands >= OF_MAX_ACT_VECTORS){
    }
    memset(&m_parms, 0, sizeof(m_parms));
    m_parms.meter = meter_id;
    m_parms.flags = set_type(meter_type, burst, stats);
    m_parms.cflags = C_METER_STATIC;
    if(m_parms.flags & OFPMF_STATS){
        m_parms.cflags |= C_METER_GSTATS;
    }
    m_parms.meter_nbands = nbands;

    for(i = 0;i<nbands;i++){
        m_parms.meter_bands[i] = make_band_elem(rates[i], bursts[i], prec[i] ,&mdata[i]);
    }

    c_wr_lock(&nbapi_app_data->lock);
    mul_service_send_meter_add(nbapi_app_data->mul_service, dpid, &m_parms);
    if(c_service_timed_wait_response(nbapi_app_data->mul_service) > 0){
        c_wr_unlock(&nbapi_app_data->lock);
        return -3;
    }
    c_wr_unlock(&nbapi_app_data->lock);
    ret = m_parms.meter;
    for(i = 0; i<nbands;i++){
        of_mact_free(&mdata[i]);
        free(m_parms.meter_bands[i]);
    }
    free(mdata);
    free(rates);
    free(bursts);
    free(prec);
    return ret;
}

struct of_meter_band_elem * 
make_band_elem(int rate, int burst_size, int prec_level, 
               mul_act_mdata_t *mdata)
{
    struct of_meter_band_elem * band_elem;
    struct of_meter_band_parms meter_band_params;
    
    of_mact_alloc(mdata);
    mdata->only_acts = true;
    
    meter_band_params.rate = rate;
    meter_band_params.burst_size = burst_size;
    if(prec_level==-1){//drop
        mul_app_set_band_drop(mdata, &meter_band_params);
    }
    else{//dscp
        meter_band_params.prec_level = prec_level;
        mul_app_set_band_dscp(mdata, &meter_band_params);
    }
    
    band_elem = calloc(1, sizeof(*band_elem));
    band_elem->band = mdata->act_base;
    band_elem->band_len = of_mact_len(mdata);

    return band_elem;
}

uint16_t 
set_type(char * meter_type, int burst, int stats)
{
    uint16_t type;

    if(!strncmp(meter_type, "kbps", strlen(meter_type))){
        type = OFPMF_KBPS;
    }    else if(!strncmp(meter_type, "pktps", strlen(meter_type))){
        type = OFPMF_PKTPS;
    }    else{
        NOT_REACHED();
    }
    if(burst != 0){
        type |= OFPMF_BURST;
    }
    if(stats != 0){
        type |= OFPMF_STATS;
    }
    return type;
}

int* 
ctomdata(char * cdata, int n)
{
    int i , ri, ci;
    int *ret;
    char cbuf[32] = "";
    ret = (int*)malloc(n*sizeof(int));
    i = ri = ci = 0;
    while(1){
        if(cdata[i] == '/'){
            cbuf[ci] = '\0';
            if(ri >= n) break;
            ret[ri] = atoi(cbuf);
            ri++;
            ci = 0;
        }
        else {
            cbuf[ci] = cdata[i];
            ci++;
        }
        i++;
        if(cdata[i] == '\0') break;
    }
    return ret;
}

int 
nbapi_delete_meter(uint64_t dpid, uint32_t meter) 
{
    struct of_meter_mod_params m_parms;

    memset(&m_parms, 0, sizeof(m_parms));

    m_parms.meter = meter;
    m_parms.cflags = C_METER_STATIC;
    
    c_wr_lock(&nbapi_app_data->lock);
    mul_service_send_meter_del(nbapi_app_data->mul_service, dpid, &m_parms);
    if(c_service_timed_wait_response(nbapi_app_data->mul_service)>0){
        c_wr_unlock(&nbapi_app_data->lock);
        return -1;
    }
    c_wr_unlock(&nbapi_app_data->lock);
    return 0;
}
/*
int nbapi_show_meter(uint64_t dpid, uint32_t meter_id){
    struct cbuf *b;
    struct c_ofp_auxapp_cmd * cofp_auc;
    struct c_ofp_req_dpid_attr * cofp_rda;
    c_ofp_meter_mod_t *cofp_mm;
    struct ofp_header *h;
    int n_meters = 0;
    struct cbuf_head bufs;
    int retries = 0;

    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_GET_METERS);
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);

    c_service_send(nbapi_app_data->mul_service, b);
    while (1){
        b = c_service_wait_response(service);
        if (b) {
            h = (void *)(b->data);
            if (h->type != C_OFPT_METER_MOD) {
                free_cbuf(b);
                break;
            }
            cofp_mm = (void *)(b->data);
            if(ntohs(cofp_mm->header.length) < sizeof(*cofp_mm)){
                free_cbuf(b);
                goto try_restart;
            }
            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_meters++;
        } else {
            goto try_restart;
        }
    }
    while ((b = cbuf_list_dequeue(&bufs))){
        cofp_mm = (void *)(b->data);
        if(U322UL(ntohl(cofp_mm->meter_id)) == meter_id) {
            
        }
    }

}
*/

/* returns array of switch_brief */
nbapi_switch_brief_list_t 
get_switch_all(void) 
{
    int i, n_switches;
    nbapi_switch_brief_list_t list;
    c_ofp_auxapp_cmd_t *cofp_auc;
    c_ofp_switch_brief_t *cofp_swb;
    c_ofp_switch_brief_t *switch_brief;

    struct cbuf *b;

    list.array = NULL;
    list.length = 0;

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return list;
    }

    b = mul_get_switches_brief(nbapi_app_data->mul_service); 

    c_wr_unlock(&nbapi_app_data->lock);
    if(b){

        cofp_auc = (void *)(b->data);
        n_switches = (ntohs(cofp_auc->header.length) - sizeof(c_ofp_auxapp_cmd_t))/
                     sizeof(c_ofp_switch_brief_t);

        list.length = n_switches;

        cofp_swb = (void *)(cofp_auc->data);
        for (i=0; i < n_switches; i++) {
            switch_brief = calloc(1, sizeof(*switch_brief));

            *switch_brief = *cofp_swb;
            ntoh_c_ofp_switch_brief(switch_brief);
            list.array = g_slist_append(list.array, switch_brief);
            cofp_swb += 1;
        }

        free_cbuf(b);
        //list.array = g_slist_reverse(list.array);
    }

    return list;
}

#if 0
void nbapi_mem_free_c_ofp_switch_brief_t(c_ofp_switch_brief_t *switch_brief){
    free(switch_brief);
}
void dummy(void * a, void * b){
}

int 
get_flow_number(uint64_t dpid)
{
    return mul_get_flow_info(nbapi_app_data->mul_service, dpid, false, false, NULL, NULL, dummy );
}
int 
get_meter_number(uint64_t dpid)
{
    return mul_get_meter_info(nbapi_app_data->mul_service, dpid, false, false, NULL, dummy );
}
int 
get_group_number(uint64_t dpid)
{
    return mul_get_group_info(nbapi_app_data->mul_service, dpid, false, false, NULL,  dummy );
}

#endif
/** get port information from datapath_id and port id. #newobject required */
struct 
c_sw_port *get_switch_port(uint64_t datapath_id, uint16_t port_no) 
{
    int i, n_ports;
    //struct ofp_phy_port *ret_val;
    struct c_sw_port *ret_val, *p_info;

    //struct ofp_switch_features *osf;
    struct c_ofp_switch_add *osf;

    struct cbuf *b;

    /* TODO: We only have heavy mul_get_switch_detail, which includes information of
     *       all ports which isn't really relevant to this function.
     */

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return NULL;
    }

    b = mul_get_switch_detail(nbapi_app_data->mul_service, datapath_id);

    c_wr_unlock(&nbapi_app_data->lock);

    if (!b) {
        return NULL;
    }
    osf = (void *)b->data;
    n_ports = ((ntohs(osf->header.length)
                - offsetof(struct c_ofp_switch_add, ports))
            / sizeof *osf->ports);

    /* check if port exists and copy info if found. */
    /* TODO: Existence check will be much faster if we use tr-service
     *       but for not we just do manual traversal.
     */

    for (i = 0; i < n_ports; i ++) {
        //struct ofp_phy_port   *p_info = &osf->ports[i];
        p_info = &osf->ports[i];
        if (ntohl(p_info->port_no) == port_no) {
            /* found */
            ret_val = calloc(1, sizeof(*ret_val));
            if (!ret_val) {
                break;
            }
            *ret_val = *p_info;
            //ntoh_ofp_phy_port(ret_val);
            ntoh_c_sw_port(ret_val);
            free_cbuf(b);
            return ret_val;
        }
    }
    /* port not found */

    free_cbuf(b);
    return NULL;
}

/* return array of port_brief for all ports in switch */
//nbapi_port_list_t get_switch_port_all(uint64_t datapath_id) {
nbapi_swport_list_t 
get_switch_port_all(uint64_t datapath_id) 
{
    int i, n_ports;
    //nbapi_port_list_t list;
    nbapi_swport_list_t list;

    //struct ofp_switch_features *osf;
    struct c_ofp_switch_add *osf;

    struct cbuf *b;
    struct c_sw_port *p_info, *copy;

    list.array = NULL;
    list.length = 0;

    /* TODO: We only have heavy mul_get_switch_detail, which includes information of
     *       all ports which isn't really relevant to this function.
     */

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return list;
    }

    b = mul_get_switch_detail(nbapi_app_data->mul_service, datapath_id);

    c_wr_unlock(&nbapi_app_data->lock);

    if (b) {
        osf = (void *)b->data;
        n_ports = ((ntohs(osf->header.length)
                    - offsetof(struct c_ofp_switch_add, ports))
                / sizeof (*osf->ports));

        /* check if port exists and copy info if found. */
        /* TODO: Existence check will be much faster if we use tr-service
         *       but for not we just do manual traversal.
         */
        list.length = n_ports;
        for (i = 0; i < n_ports; i ++) {
            //struct ofp_phy_port   *p_info = &osf->ports[i];
            //struct ofp_phy_port   *copy = calloc(sizeof(*copy), 1);
            p_info = &osf->ports[i];
            copy   = calloc(1, sizeof(*copy));

            *copy = *p_info;
            //ntoh_ofp_phy_port(copy);
            ntoh_c_sw_port(copy);
            list.array = g_slist_append(list.array, copy);
            
        }

        free_cbuf(b);
        //list.array = g_slist_reverse(list.array);
    }
    return list;
}
#if 0
void nbapi_mem_free_c_sw_port(struct c_sw_port * copy){
    free(copy);
}
#endif

static void
nbapi_switch_group_table_dump(c_ofp_group_mod_t *list,
                                c_ofp_group_mod_t *cofp_gm)
{
    if (list->group_id == ntohl(cofp_gm->group_id)) {
        *list = *cofp_gm;
    }
}

static void 
switch_group_table_dump(void *list, void *cofp_gm)
{
    nbapi_switch_group_table_dump((c_ofp_group_mod_t *)list,
                                    (c_ofp_group_mod_t *)cofp_gm);
}

static void 
nbapi_ntoh_actions(void *actions, size_t act_len)
{
    struct ofp_action_header *act = actions;
    int n_act = 0;

    if (!actions || !act_len) {
        c_log_err("%s : No Actions or Parsers", FN);
        return ;
    }

    while (act_len) {
        if (n_act++ > OFP_MAX_ACTIONS) {
            c_log_err("%s : Too many actions or parse error" , FN);
            return ;
        }

        ntoh_ofp_action_header(act);
        act_len -= act->len;
        act = INC_PTR8(act, act->len);
    }
}

c_ofp_group_mod_t *
get_switch_group_table(uint64_t datapath_id, uint32_t group_id)
{
    c_ofp_group_mod_t *list;
    ssize_t tot_len = 0;
    size_t bkt_dist = 0;
    struct c_ofp_bkt *bkt;
    int n_groups = 0, act = 0;

    list = calloc(1, sizeof(c_ofp_group_mod_t));
    list->group_id = group_id;

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return list;
    }

    n_groups = mul_get_group_info(nbapi_app_data->mul_service, 
                            datapath_id, false, true, 
                            list, switch_group_table_dump);

    if (n_groups <= 0) goto out;
    c_wr_unlock(&nbapi_app_data->lock);

    tot_len = ntohs(list->header.length) - sizeof(*list);
    bkt_dist = sizeof(*list);

    ntoh_c_ofp_group_mod(list);

    while(tot_len >= (int)sizeof(*bkt) && act < OF_MAX_ACT_VECTORS) {
        size_t act_len = 0;

        bkt = INC_PTR8(list, bkt_dist);
        act_len = ntohs(bkt->act_len);

        bkt_dist += sizeof(*bkt) + act_len;
        if (act_len > (tot_len - sizeof(*bkt))) {
            break;
        }

        //n to h c_ofp_bkt and ofp_action_header
        ntoh_c_ofp_bkt(bkt);
        nbapi_ntoh_actions(bkt->actions, act_len);
 
        tot_len -= act_len + sizeof(*bkt);
        act++;
    }
    
out:
    return list;
}

nbapi_port_neigh_list_t 
get_switch_neighbor_all(uint64_t datapath_id) 
{
    nbapi_port_neigh_list_t list;
    struct cbuf *b;
    int i = 0, num_ports = 0;
    struct c_ofp_port_neigh *port, *copy;
    c_ofp_auxapp_cmd_t *cofp_auc;
    c_ofp_switch_neigh_t *neigh;

    list.array = NULL;
    list.length = 0;

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->tr_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return list;
    }

    b = mul_neigh_get(nbapi_app_data->tr_service, datapath_id);
    c_wr_unlock(&nbapi_app_data->lock);

    if (b) {
        cofp_auc = (void *)(b->data);
        neigh = (void *)(cofp_auc->data);
        num_ports = (ntohs(cofp_auc->header.length) - (sizeof(c_ofp_switch_neigh_t) 
                + sizeof(c_ofp_auxapp_cmd_t)))/ sizeof(struct c_ofp_port_neigh);

        port = (void *) (neigh->data);
        for (i = 0; i < num_ports; i++, port++) {
            copy = calloc(1, sizeof(*port));
            if (!copy) {
                g_slist_free_full(list.array, free);
                list.array = NULL;
                list.length = 0;
                return list;
            }

            memcpy(copy, port, sizeof(*port));
            ntoh_c_ofp_port_neigh(copy);
            list.array = g_slist_append(list.array, copy);
        }
        free_cbuf(b);
        list.length = num_ports;
    }
    return list;

}
#if 0
void nbapi_mem_free_c_ofp_port_neigh(struct c_ofp_port_neigh *port){
    free(port);
}
#endif
