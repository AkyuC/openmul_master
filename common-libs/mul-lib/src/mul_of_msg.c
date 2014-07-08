/*
 *  mul_of_msg.c: MUL openflow message handling 
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

#include "mul_common.h"
#include "random.h"

C_RL_DEFINE(rl, 100, 100);

static uint8_t zero_mac_addr[OFP_ETH_ALEN] = { 0, 0, 0, 0, 0, 0};

void
of_capabilities_tostr(char *string, uint32_t capabilities)
{
    if (capabilities == 0) {
        strcpy(string, "No capabilities\n");
        return;
    }
    if (capabilities & OFPC_FLOW_STATS) {
        strcat(string, "FLOW_STATS ");
    }
    if (capabilities & OFPC_TABLE_STATS) {
        strcat(string, "TABLE_STATS ");
    }
    if (capabilities & OFPC_PORT_STATS) {
        strcat(string, "PORT_STATS ");
    }
    if (capabilities & OFPC_STP) {
        strcat(string, "STP ");
    }
    if (capabilities & OFPC_IP_REASM) {
        strcat(string, "IP_REASM ");
    }
    if (capabilities & OFPC_QUEUE_STATS) {
        strcat(string, "QUEUE_STATS ");
    }
    if (capabilities & OFPC_ARP_MATCH_IP) {
        strcat(string, "ARP_MATCH_IP");
    }
}

bool
of_switch_supports_flow_stats(uint32_t cap)
{
    return cap & OFPC_FLOW_STATS;
}

static void *
of_inst_parser_alloc(struct flow *fl, struct flow *mask,
                     void *u_arg, struct ofp_inst_parsers *parsers,
                     struct ofp_act_parsers *act_parsers)
{
    struct ofp_inst_parser_arg *ofp_dp = calloc(1, sizeof(*ofp_dp));

    assert(ofp_dp);

    ofp_dp->pbuf = calloc(1, OF_DUMP_INST_SZ);
    assert(ofp_dp->pbuf);

    ofp_dp->fl = fl;
    ofp_dp->mask = mask;
    ofp_dp->u_arg = u_arg;
    ofp_dp->parsers = parsers;
    ofp_dp->act_parsers = act_parsers;

    return ofp_dp;
}

static void
of_inst_parser_free(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    if (dp) {
        if (dp->pbuf) free(dp->pbuf);
        free(dp);
    }
}

static struct ofp_inst_parser_arg * 
of_inst_parser_fini(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    return dp;
}

static void
of_dump_inst_parser_pre_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len,
                        OF_DUMP_INST_SZ - dp->len - 1,
                        "instructions: ");
    assert(dp->len < OF_DUMP_INST_SZ-1);
}

static void
of_dump_inst_apply_parser_pre_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len,
                        OF_DUMP_INST_SZ - dp->len - 1,
                        "instruction-apply\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
}

static void
of_dump_cmd_inst_parser_pre_proc(void *arg UNUSED)
{
    return;
}

static void
of_check_inst_parser_pre_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    
    if (!dp->fl || !dp->mask) {
        return;
    }

    if (dp->mask->dl_vlan) {
        dp->push_vlan++;
    }    
    if (dp->mask->mpls_label) {
        dp->push_mpls++;
    } 
}

static void
of_dump_inst_parser_post_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
}

static void
of_dump_cmd_inst_parser_post_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "action-list-end\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "commit\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
}

static void
of131_dump_cmd_inst_parser_post_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "commit\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
}

static void
of_dump_cmd_inst_parser_no_act(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "instruction-apply\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "action-add drop\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
}

void
of_mact_alloc(mul_act_mdata_t *mdata)
{
    mdata->act_base = calloc(1, MUL_ACT_BUF_SZ);
    assert(mdata->act_base);
    of_mact_mdata_init(mdata, MUL_ACT_BUF_SZ);
}

void
of_mact_free(mul_act_mdata_t *mdata)
{
    if (mdata->act_base)
        free(mdata->act_base);
    mdata->act_base = NULL;
}

static void
of_check_realloc_act(mul_act_mdata_t *mdata, size_t  len)
{
    uint8_t *new_base;
    size_t old_room = of_mact_buf_room(mdata);

    if (old_room < len) {
        new_base = calloc(1, old_room + len);
        assert(new_base);
        memcpy(new_base, mdata->act_base, old_room);
        of_mact_free(mdata);
        mdata->act_base = new_base;
        mdata->act_wr_ptr = mdata->act_base + old_room;
        mdata->buf_len = old_room + len;
    }
}

size_t
of_make_action_output(mul_act_mdata_t *mdata, uint32_t eoport)
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

    of_check_realloc_act(mdata, sizeof(*op_act));

    oport = oport?: OFPP_CONTROLLER;
    
    op_act = (void *)(mdata->act_wr_ptr);

    op_act->type = htons(OFPAT_OUTPUT);
    op_act->len  = htons(sizeof(*op_act));
    op_act->port = htons(oport);
    op_act->max_len = (oport == OFPP_CONTROLLER) ?
                       htons(OF_MAX_MISS_SEND_LEN) : 0;

    mdata->act_wr_ptr += (sizeof(*op_act));
    return (sizeof(*op_act));
}

size_t
of_make_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid)
{
    struct ofp_action_vlan_vid *vid_act;

    of_check_realloc_act(mdata, sizeof(*vid_act));
    
    vid_act = (void *)(mdata->act_wr_ptr);
    vid_act->type = htons(OFPAT_SET_VLAN_VID);
    vid_act->len  = htons(sizeof(*vid_act));
    vid_act->vlan_vid = htons(vid);

    mdata->act_wr_ptr += sizeof(*vid_act);
    return (sizeof(*vid_act));
}

size_t
of_make_action_strip_vlan(mul_act_mdata_t *mdata)
{
    struct ofp_action_header *vid_strip_act;

    of_check_realloc_act(mdata, sizeof(*vid_strip_act));
    
    vid_strip_act = (void *)(mdata->act_wr_ptr);
    vid_strip_act->type = htons(OFPAT_STRIP_VLAN);
    vid_strip_act->len  = htons(sizeof(*vid_strip_act));

    mdata->act_wr_ptr += sizeof(*vid_strip_act);
    return (sizeof(*vid_strip_act));
}

size_t
of_make_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac)
{
    struct ofp_action_dl_addr *dmac_act;

    of_check_realloc_act(mdata, sizeof(*dmac_act));

    dmac_act = (void *)(mdata->act_wr_ptr);

    dmac_act->type = htons(OFPAT_SET_DL_DST);
    dmac_act->len  = htons(sizeof(*dmac_act));
    memcpy(dmac_act->dl_addr, dmac, OFP_ETH_ALEN);

    mdata->act_wr_ptr += sizeof(*dmac_act);
    return (sizeof(*dmac_act));
}

size_t
of_make_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac)
{
    struct ofp_action_dl_addr *smac_act;

    of_check_realloc_act(mdata, sizeof(*smac_act));

    smac_act = (void *)(mdata->act_wr_ptr);
    smac_act->type = htons(OFPAT_SET_DL_SRC);
    smac_act->len  = htons(sizeof(*smac_act));
    memcpy(smac_act->dl_addr, smac, OFP_ETH_ALEN);

    mdata->act_wr_ptr += sizeof(*smac_act);
    return (sizeof(*smac_act));
}

size_t
of_make_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp)
{
    struct ofp_action_vlan_pcp *vpcp_act;

    of_check_realloc_act(mdata, sizeof(*vpcp_act));

    vpcp_act = (void *)(mdata->act_wr_ptr);
    vpcp_act->type = htons(OFPAT_SET_VLAN_PCP);
    vpcp_act->len = htons(sizeof(*vpcp_act));
    vpcp_act->vlan_pcp = (vlan_pcp & 0x7);

    mdata->act_wr_ptr += sizeof(*vpcp_act);
    return (sizeof(*vpcp_act));
}

static size_t
of_make_action_set_nw_ip(mul_act_mdata_t *mdata, uint32_t ip, 
                         uint16_t type)
{
    struct ofp_action_nw_addr *nw_addr_act;

    of_check_realloc_act(mdata, sizeof(*nw_addr_act));

    nw_addr_act = (void *)(mdata->act_wr_ptr);
    nw_addr_act->type = htons(type);
    nw_addr_act->len  = htons(sizeof(*nw_addr_act));
    nw_addr_act->nw_addr = htonl(ip);

    mdata->act_wr_ptr += sizeof(*nw_addr_act);
    return (sizeof(*nw_addr_act));
}

size_t
of_make_action_set_nw_saddr(mul_act_mdata_t *mdata, uint32_t nw_saddr) 
{
    return of_make_action_set_nw_ip(mdata, nw_saddr, OFPAT_SET_NW_SRC); 
}

size_t
of_make_action_set_nw_daddr(mul_act_mdata_t *mdata, uint32_t nw_daddr) 
{
    return of_make_action_set_nw_ip(mdata, nw_daddr, OFPAT_SET_NW_DST); 
}

size_t
of_make_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos) 
{
    struct ofp_action_nw_tos *nw_tos_act;

    of_check_realloc_act(mdata, sizeof(*nw_tos_act));

    nw_tos_act = (void *)(mdata->act_wr_ptr);
    nw_tos_act->type = htons(OFPAT_SET_NW_TOS);
    nw_tos_act->len  = htons(sizeof(*nw_tos_act));
    nw_tos_act->nw_tos = tos & ((0x1<<7) - 1);

    mdata->act_wr_ptr += sizeof(*nw_tos_act);
    return (sizeof(*nw_tos_act));
}

static size_t
of_make_action_set_tp_port(mul_act_mdata_t *mdata, uint8_t ip_proto UNUSED,
                           bool is_src, uint16_t port)
{
    struct ofp_action_tp_port *tp_port_act;
    uint16_t type = is_src ? OFPAT_SET_TP_SRC : OFPAT_SET_TP_DST;

    of_check_realloc_act(mdata, sizeof(*tp_port_act));

    tp_port_act = (void *)(mdata->act_wr_ptr);
    tp_port_act->type = htons(type);
    tp_port_act->len  = htons(sizeof(*tp_port_act));
    tp_port_act->tp_port = htons(port);

    mdata->act_wr_ptr += sizeof(*tp_port_act);
    return (sizeof(*tp_port_act));
}

size_t
of_make_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of_make_action_set_tp_port(mdata, IP_TYPE_UDP, true, port);
}

size_t
of_make_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of_make_action_set_tp_port(mdata, IP_TYPE_UDP, false, port);
}

size_t
of_make_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of_make_action_set_tp_port(mdata, IP_TYPE_TCP, true, port);
}

size_t
of_make_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of_make_action_set_tp_port(mdata, IP_TYPE_TCP, false, port);
}

char *
of_dump_wildcards(uint32_t wildcards)
{
    uint32_t                 nw_dst_mask, nw_src_mask;   
    char                     *pbuf;
    size_t                   len = 0;
    uint32_t                 ip_wc;

    pbuf = calloc(1, OF_DUMP_WC_SZ);
    assert(pbuf);

    wildcards = ntohl(wildcards);

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = ip_wc >= 32 ? 0 : 
                           make_inet_mask(32-ip_wc); 

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = ip_wc >= 32 ? 0 : 
                           make_inet_mask(32-ip_wc);
    
    /* Reduce this to a line please.... */
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "Wildcards:\r\n");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "smac", (wildcards & OFPFW_DL_SRC) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "dmac", (wildcards & OFPFW_DL_DST) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "eth-type", (wildcards & OFPFW_DL_TYPE) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "vlan-id", (wildcards & OFPFW_DL_VLAN) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "vlan-pcp", (wildcards & OFPFW_DL_VLAN_PCP) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: 0x%08x\r\n",
                    "dst-ip-mask", nw_dst_mask);
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: 0x%08x\r\n",
                    "src-ip-mask", nw_src_mask);
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "ip-proto", (wildcards & OFPFW_NW_PROTO) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "src-port", (wildcards & OFPFW_TP_SRC) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "dst-port", (wildcards & OFPFW_TP_DST) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "in-port", (wildcards & OFPFW_IN_PORT) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);

    return pbuf;
}

char *
of_dump_flow_all(struct flow *fl)
{
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow tuple:\r\n");
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%-10s:%02x:%02x:%02x:%02x:%02x:%02x\r\n"
                   "%-10s:%02x:%02x:%02x:%02x:%02x:%02x\r\n",
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5],
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%-10s:0x%04x\r\n%-10s:0x%04x\r\n%-10s:0x%04x\r\n",
                     "eth-type", ntohs(fl->dl_type),
                     "vlan-id",  ntohs(fl->dl_vlan),
                     "vlan-pcp", ntohs(fl->dl_vlan_pcp));
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%-10s:0x%08x\r\n%-10s:0x%08x\r\n%-10s:0x%02x\r\n%-10s:0x%x\r\n",
                     "dest-ip", ntohl(fl->ip.nw_dst),
                     "src-ip", ntohl(fl->ip.nw_src),
                     "ip-proto", fl->nw_proto,
                     "ip-tos", fl->nw_tos);
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%-10s:0x%04x\r\n%-10s:0x%04x\r\n%-10s:0x%x\r\n",
                    "src-port", ntohs(fl->tp_src),
                    "dst-port", ntohs(fl->tp_dst),
                    "in-port", ntohs(fl->in_port));

    return pbuf;
}


struct ofp_inst_parser_arg *
of10_parse_actions(struct flow *fl, struct flow *mask,
                   void *actions, size_t action_len,
                   struct ofp_inst_parsers *inst_parsers, 
                   struct ofp_act_parsers *act_parsers,
                   void *u_arg)                            
{
    struct ofp_action_header *hdr;
    void *parse_ctx;
    uint16_t act_type;
    size_t parsed_len = 0;
    size_t len = 0;

    if (!act_parsers || !inst_parsers ) {
        c_log_err("%s: No parser specified", FN);
        return NULL;
    }

    parse_ctx = inst_parsers->prep_inst_parser(fl, mask, u_arg, inst_parsers, 
                                               act_parsers);
    if (!action_len) {
        if (inst_parsers->no_inst) {
            inst_parsers->no_inst(parse_ctx);
            goto done;
        }
    }

    if (inst_parsers->pre_proc)
        inst_parsers->pre_proc(parse_ctx);

    hdr =  (struct ofp_action_header *)actions;
    while ((int)(action_len) > 0) {

        act_type = ntohs(hdr->type);

        switch (act_type) {
        case OFPAT_OUTPUT:
            if (act_parsers->act_output)
                act_parsers->act_output(hdr, parse_ctx); 
            len = sizeof(struct ofp_action_output);
            break;
        case OFPAT_SET_VLAN_VID:
            if (act_parsers->act_set_vlan)
                act_parsers->act_set_vlan(hdr, parse_ctx);
            len = sizeof(struct ofp_action_vlan_vid);
            break;
        case OFPAT_SET_DL_DST:
            if (act_parsers->act_set_dl_dst)
                act_parsers->act_set_dl_dst(hdr, parse_ctx);
            len = sizeof(struct ofp_action_dl_addr);
            break;
        case OFPAT_SET_DL_SRC:
            if (act_parsers->act_set_dl_src)
                act_parsers->act_set_dl_src(hdr, parse_ctx);
            len = sizeof(struct ofp_action_dl_addr);
            break;    
        case OFPAT_SET_VLAN_PCP:
            if (act_parsers->act_set_vlan_pcp)
                act_parsers->act_set_vlan_pcp(hdr, parse_ctx);
            len = sizeof(struct ofp_action_vlan_pcp);
            break;
        case OFPAT_STRIP_VLAN:
            if (act_parsers->act_pop_vlan)
                act_parsers->act_pop_vlan(hdr, parse_ctx);
            len = sizeof(struct ofp_action_header);
            break;
        case OFPAT_SET_NW_SRC:
            if (act_parsers->act_set_nw_src)
                act_parsers->act_set_nw_src(hdr, parse_ctx);
            len = sizeof(struct ofp_action_nw_addr);
            break;
        case OFPAT_SET_NW_DST:
            if (act_parsers->act_set_nw_dst)
                act_parsers->act_set_nw_dst(hdr, parse_ctx);
            len = sizeof(struct ofp_action_nw_addr);
            break;
        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST:
            /* FIXME */
            len = sizeof(struct ofp_action_tp_port);
            break;
        case OFPAT_SET_NW_TOS:
            if (act_parsers->act_set_nw_tos)
                act_parsers->act_set_nw_tos(hdr, parse_ctx);
            len = sizeof(struct ofp_action_nw_tos);
            break;
        default:
            c_log_err("%s:unhandled action %u", FN, act_type);
            goto done;
        }

        parsed_len += len;
        action_len -= len;
        hdr = INC_PTR8(actions, parsed_len);
    }
done:
    if (inst_parsers->post_proc)
        inst_parsers->post_proc(parse_ctx);

    if (inst_parsers->fini_inst_parser)
        inst_parsers->fini_inst_parser(parse_ctx);

    return parse_ctx;
}

static int 
of_dump_act_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-Port(%u),",
                        "act-output", ntohs(of_ao->port));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int 
of_dump_cmd_act_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add output ");
    assert(dp->len < OF_DUMP_INST_SZ-1);

    if (of_ao->port) {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%d\r\n", ntohs(of_ao->port));
    } else {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                            "controller\r\n");
    }
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int 
of_check_act_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_output *op_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    if (!ntohs(op_act->port)) {
        dp->res = -1;
    }

    return sizeof(*op_act);
}

static int 
of_dump_act_set_vlan(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_vid *vid_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-vid 0x%04x,", "set-vid",
                        ntohs(vid_act->vlan_vid));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vid_act);
}

static int 
of_dump_cmd_act_set_vlan(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_vid *vid_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-vlan-id %d\r\n",
                        ntohs(vid_act->vlan_vid));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vid_act);
}

static int 
of_dump_act_set_vlan_pcp(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_pcp *vlan_pcp_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s 0x%04x,", "set-vlan-pcp", vlan_pcp_act->vlan_pcp);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vlan_pcp_act);
}

static int 
of_dump_cmd_act_set_vlan_pcp(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_pcp *vlan_pcp_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-vlan-pcp %d", vlan_pcp_act->vlan_pcp);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vlan_pcp_act);
}

static int 
of_dump_act_set_nw_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s 0x%08x,", "set-nw-dst", ntohl(nw_addr_act->nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static int 
of_dump_cmd_act_set_nw_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;
    struct in_addr in;

    in.s_addr = nw_addr_act->nw_addr;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add nw-daddr %s\r\n", inet_ntoa(in));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static int 
of_dump_act_set_nw_src(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s 0x%08x,", "set-nw-src", ntohl(nw_addr_act->nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static int 
of_dump_cmd_act_set_nw_src(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;
    struct in_addr in;

    in.s_addr = nw_addr_act->nw_addr;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add nw-saddr %s\r\n", inet_ntoa(in));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static int 
of_dump_act_set_nw_tos(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_tos *nw_tos_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s 0x%04x,", "set-nw-tos", (nw_tos_act->nw_tos));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_tos_act);
}

static int 
of_dump_cmd_act_set_nw_tos(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_tos *nw_tos_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-nw-dscp %d", nw_tos_act->nw_tos);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_tos_act);
}

static int 
of_dump_act_set_dl_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_dl_addr *dmac_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-%02x:%02x:%02x:%02x:%02x:%02x,",
                        "set-dmac", dmac_act->dl_addr[0], dmac_act->dl_addr[1],
                        dmac_act->dl_addr[2], dmac_act->dl_addr[3],
                        dmac_act->dl_addr[4], dmac_act->dl_addr[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*dmac_act);
}

static int 
of_dump_cmd_act_set_dl_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_dl_addr *dmac_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-dmac %02x:%02x:%02x:%02x:%02x:%02x\r\n",
                        dmac_act->dl_addr[0], dmac_act->dl_addr[1],
                        dmac_act->dl_addr[2], dmac_act->dl_addr[3],
                        dmac_act->dl_addr[4], dmac_act->dl_addr[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*dmac_act);
}

static int 
of_dump_act_set_dl_src(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_dl_addr *smac_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-%02x:%02x:%02x:%02x:%02x:%02x,",
                        "set-smac", smac_act->dl_addr[0], smac_act->dl_addr[1],
                        smac_act->dl_addr[2], smac_act->dl_addr[3],
                        smac_act->dl_addr[4], smac_act->dl_addr[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*smac_act);
}

static int 
of_dump_cmd_act_set_dl_src(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_dl_addr *smac_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-smac %02x:%02x:%02x:%02x:%02x:%02x\r\n",
                        smac_act->dl_addr[0], smac_act->dl_addr[1],
                        smac_act->dl_addr[2], smac_act->dl_addr[3],
                        smac_act->dl_addr[4], smac_act->dl_addr[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*smac_act);
}

struct ofp_act_parsers of10_dump_act_parsers = {
    .act_output = of_dump_act_out,
    .act_set_vlan = of_dump_act_set_vlan,
    .act_set_vlan_pcp = of_dump_act_set_vlan_pcp,
    .act_set_dl_dst = of_dump_act_set_dl_dst,
    .act_set_dl_src = of_dump_act_set_dl_src, 
    .act_set_nw_src = of_dump_act_set_nw_src,
    .act_set_nw_dst = of_dump_act_set_nw_dst,
    .act_set_nw_tos = of_dump_act_set_nw_tos
};

struct ofp_act_parsers of10_dump_cmd_act_parsers = {
    .act_output = of_dump_cmd_act_out,
    .act_set_vlan = of_dump_cmd_act_set_vlan,
    .act_set_vlan_pcp = of_dump_cmd_act_set_vlan_pcp,
    .act_set_dl_dst = of_dump_cmd_act_set_dl_dst,
    .act_set_dl_src = of_dump_cmd_act_set_dl_src, 
    .act_set_nw_src = of_dump_cmd_act_set_nw_src,
    .act_set_nw_dst = of_dump_cmd_act_set_nw_dst,
    .act_set_nw_tos = of_dump_cmd_act_set_nw_tos
};

struct ofp_inst_parsers of10_dump_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .pre_proc = of_dump_inst_parser_pre_proc,
    .post_proc = of_dump_inst_parser_post_proc,
    .fini_inst_parser = of_inst_parser_fini,
};

struct ofp_inst_parsers of10_dump_cmd_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .no_inst = of_dump_cmd_inst_parser_no_act,
    .pre_proc = of_dump_inst_apply_parser_pre_proc,
    .post_proc = of_dump_cmd_inst_parser_post_proc,
    .fini_inst_parser = of_inst_parser_fini,
};

char *
of10_dump_actions(void *actions, size_t action_len, bool acts_only UNUSED)
{
    struct ofp_inst_parser_arg *dp;
    char *pbuf = NULL;

    dp = of10_parse_actions(NULL, NULL, actions, action_len,
                            &of10_dump_inst_parsers,
                            &of10_dump_act_parsers, NULL);
    pbuf =  dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}

char *
of10_dump_actions_cmd(void *actions, size_t action_len, bool acts_only UNUSED)
{
    struct ofp_inst_parser_arg *dp;
    char *pbuf = NULL;

    dp = of10_parse_actions(NULL, NULL, actions, action_len,
                            &of10_dump_cmd_inst_parsers,
                            &of10_dump_cmd_act_parsers, NULL);
    pbuf =  dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}

struct ofp_act_parsers of10_validate_act_parsers = {
    .act_output = of_check_act_out,
};

struct ofp_inst_parsers of10_cmn_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .fini_inst_parser = of_inst_parser_fini,
};

int
of_validate_actions(struct flow *fl, struct flow *mask,
                    void *actions, size_t action_len,
                    bool acts_only UNUSED, void *u_arg)
{
    struct ofp_inst_parser_arg *dp;
    int ret = -1;

    dp = of10_parse_actions(fl, mask, actions, action_len,
                            &of10_dump_inst_parsers,
                            &of10_dump_act_parsers, u_arg);
    ret =  dp ? dp->res : -1;
    of_inst_parser_free(dp);

    return ret;
}

char *
of_dump_flow(struct flow *fl, uint32_t wildcards)
{
#define FL_PBUF_SZ 4096
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;
    uint32_t nw_dst_mask, nw_src_mask;
    uint32_t dip_wc, sip_wc;
    struct in_addr in_addr;

    wildcards = ntohl(wildcards);
    dip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = dip_wc >= 32 ? 0 :
                           make_inet_mask(32-dip_wc);

    sip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = sip_wc >= 32 ? 0 :
                           make_inet_mask(32-sip_wc);

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow: ");
    assert(len < FL_PBUF_SZ-1);

    if (wildcards == OFPFW_ALL) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "All Fields Wildcards");
        assert(len < FL_PBUF_SZ-1);
        return pbuf;
    }

    if (!(wildcards & OFPFW_DL_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5]);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "eth-type", ntohs(fl->dl_type));
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_VLAN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-id",  ntohs(fl->dl_vlan));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_VLAN_PCP)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-pcp", fl->dl_vlan_pcp);
        assert(len < FL_PBUF_SZ-1);

    }
    if (nw_dst_mask) {
        in_addr.s_addr = fl->ip.nw_dst & htonl(nw_dst_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:%s/%d ",
                     "dst-ip", inet_ntoa(in_addr),
                     dip_wc >= 32 ? 0 : 32 - dip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (nw_src_mask) {
        in_addr.s_addr = fl->ip.nw_src & htonl(nw_src_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                     "%s:%s/%d ", 
                     "src-ip", inet_ntoa(in_addr),
                     sip_wc >= 32 ? 0 : 32-sip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_PROTO)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-proto", fl->nw_proto);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_TOS)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-tos", fl->nw_tos);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "src-port", ntohs(fl->tp_src));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "dst-port", ntohs(fl->tp_dst));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_IN_PORT)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "in-port", ntohl(fl->in_port));
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "\r\n");

    return pbuf;
}

char *
of10_dump_flow(struct flow *fl, struct flow *mask)
{
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;
    uint32_t nw_dst_mask, nw_src_mask;
    uint32_t dip_wc, sip_wc;
    struct in_addr in_addr;
    uint32_t wildcards = 0;

    wildcards = ntohl(of10_mask_to_wc(mask));
    dip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = dip_wc >= 32 ? 0 :
                           make_inet_mask(32-dip_wc);

    sip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = sip_wc >= 32 ? 0 :
                           make_inet_mask(32-sip_wc);

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow: ");
    assert(len < FL_PBUF_SZ-1);

    if (wildcards == OFPFW_ALL) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "All Fields Wildcards");
        assert(len < FL_PBUF_SZ-1);
        return pbuf;
    }

    if (!(wildcards & OFPFW_DL_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5]);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "eth-type", ntohs(fl->dl_type));
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_VLAN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-id",  ntohs(fl->dl_vlan));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_VLAN_PCP)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-pcp", fl->dl_vlan_pcp);
        assert(len < FL_PBUF_SZ-1);

    }
    if (nw_dst_mask) {
        in_addr.s_addr = fl->ip.nw_dst & htonl(nw_dst_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:%s/%d ",
                     "dst-ip", inet_ntoa(in_addr),
                     dip_wc >= 32 ? 0 : 32 - dip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (nw_src_mask) {
        in_addr.s_addr = fl->ip.nw_src & htonl(nw_src_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                     "%s:%s/%d ", 
                     "src-ip", inet_ntoa(in_addr),
                     sip_wc >= 32 ? 0 : 32-sip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_PROTO)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-proto", fl->nw_proto);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_TOS)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-tos", fl->nw_tos);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "src-port", ntohs(fl->tp_src));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "dst-port", ntohs(fl->tp_dst));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_IN_PORT)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "in-port", ntohl(fl->in_port));
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "\r\n");

    return pbuf;
}

char *
of_dump_flow_generic_cmd(struct flow *fl, struct flow *mask)
{
    char *pbuf = calloc(1, FL_PBUF_SZ);
    int len = 0;
    struct in_addr in_addr, in_mask;
    char ip6_addr_str[INET6_ADDRSTRLEN];
    int i = 0;

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "smac ");
    assert(len < FL_PBUF_SZ-1);

    if (memcmp(mask->dl_src, zero_mac_addr, OFP_ETH_ALEN)) {
        for (i = 0; i < OFP_ETH_ALEN; i++) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "%02x:",
                            fl->dl_src[i] & mask->dl_src[i]);
            assert(len < FL_PBUF_SZ-1);
        }
        len -= 1;
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, " ");

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "dmac ");
    assert(len < FL_PBUF_SZ-1);
    if (memcmp(mask->dl_dst, zero_mac_addr, OFP_ETH_ALEN)) {
        for (i = 0; i < OFP_ETH_ALEN; i++) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "%02x:",
                            fl->dl_dst[i] & mask->dl_dst[i]);
            assert(len < FL_PBUF_SZ-1);
        }
        len -= 1;
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, " ");

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "eth-type ");
    assert(len < FL_PBUF_SZ-1);

    if (mask->dl_type) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "0x%x ", ntohs(fl->dl_type));
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "vid ");
    assert(len < FL_PBUF_SZ-1);
 
    if (mask->dl_vlan) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%d ", ntohs(fl->dl_vlan));
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "vlan-pcp ");
    assert(len < FL_PBUF_SZ-1);

    if (mask->dl_vlan_pcp) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%d ", fl->dl_vlan_pcp);
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "mpls-label ");
    assert(len < FL_PBUF_SZ-1);

    if (mask->mpls_label) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "%lu ",
                        U322UL(ntohl(fl->mpls_label) & MPLS_LABEL_MASK));
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "mpls-tc ");
    assert(len < FL_PBUF_SZ-1);

    if (mask->mpls_tc) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%d ", fl->mpls_tc);
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "mpls-bos ");
    assert(len < FL_PBUF_SZ-1);

    if (mask->mpls_bos) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%d ", fl->mpls_bos);
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    if (mask->dl_type &&
        (fl->dl_type == htons(ETH_TYPE_IP) ||
        fl->dl_type == htons(ETH_TYPE_IPV6) ||
        fl->dl_type == htons(ETH_TYPE_ARP))) {

        if (fl->dl_type == htons(ETH_TYPE_IP)||
            fl->dl_type == htons(ETH_TYPE_ARP)) {

            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "dip ");
            assert(len < FL_PBUF_SZ-1);

            if (mask->ip.nw_dst) {
                in_addr.s_addr = fl->ip.nw_dst & mask->ip.nw_dst;
                in_mask.s_addr = mask->ip.nw_dst;
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                                "%s/%d ", inet_ntoa(in_addr), 
                                (int)c_count_one_bits(ntohl(in_mask.s_addr)));
                assert(len < FL_PBUF_SZ-1);
            } else {
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
                assert(len < FL_PBUF_SZ-1);
            }

            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "sip ");
            assert(len < FL_PBUF_SZ-1);

            if (mask->ip.nw_src) {
                in_addr.s_addr = fl->ip.nw_src & mask->ip.nw_src;
                in_mask.s_addr = mask->ip.nw_src;
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                                "%s/%d ", inet_ntoa(in_addr),
                                (int)c_count_one_bits(ntohl(in_mask.s_addr)));
                assert(len < FL_PBUF_SZ-1);
            } else {
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
                assert(len < FL_PBUF_SZ-1);
            }

            if (fl->dl_type == htons(ETH_TYPE_ARP)) {
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "proto * "
                                "tos * dport * sport * ");
                assert(len < FL_PBUF_SZ-1);
                goto fl_match_done;
            }
        } else if (fl->dl_type == htons(ETH_TYPE_IPV6)) {

            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "dip6 ");
            assert(len < FL_PBUF_SZ-1);

            if(ipv6_addr_nonzero(&mask->ipv6.nw_dst)) { 
               if (!inet_ntop(AF_INET6, &fl->ipv6.nw_dst, 
                         ip6_addr_str, INET6_ADDRSTRLEN))
                    goto err_out;
 
               len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                         "%s/%d ", ip6_addr_str,
                         (int)c_count_ipv6_plen((void *)&mask->ipv6.nw_dst));
                assert(len < FL_PBUF_SZ-1);
            } else {
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
                assert(len < FL_PBUF_SZ-1);
            }

            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "sip6 ");
            assert(len < FL_PBUF_SZ-1);

            if (ipv6_addr_nonzero(&mask->ipv6.nw_src)) {
                if (!inet_ntop(AF_INET6, &fl->ipv6.nw_src,
                          ip6_addr_str, INET6_ADDRSTRLEN))
                    goto err_out;
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                         "%s/%d ", ip6_addr_str,
                         (int)c_count_ipv6_plen((void *)&mask->ipv6.nw_dst));
                assert(len < FL_PBUF_SZ-1);
            } else {
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
                assert(len < FL_PBUF_SZ-1);
            }
        }

        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "proto ");
        assert(len < FL_PBUF_SZ-1);

        if (mask->nw_proto) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                            "%d ", fl->nw_proto);
            assert(len < FL_PBUF_SZ-1);
        } else {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
            assert(len < FL_PBUF_SZ-1);
        }

        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "tos ");
        assert(len < FL_PBUF_SZ-1);

        if (mask->nw_tos) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                            "%d ", fl->nw_tos);
            assert(len < FL_PBUF_SZ-1);
        } else {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
            assert(len < FL_PBUF_SZ-1);
        }

        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "dport ");
        assert(len < FL_PBUF_SZ-1);

        if (mask->tp_src) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%d ", ntohs(fl->tp_src));
            assert(len < FL_PBUF_SZ-1);
        } else {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
            assert(len < FL_PBUF_SZ-1);
        }

        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "sport ");
        assert(len < FL_PBUF_SZ-1);

        if (mask->tp_src) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%d ", ntohs(fl->tp_src));
            assert(len < FL_PBUF_SZ-1);
        } else {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
            assert(len < FL_PBUF_SZ-1);
        }
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "dip * sip * proto * "
                                "tos * dport * sport * ");
        assert(len < FL_PBUF_SZ-1);
    }

fl_match_done:

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "in-port ");
    assert(len < FL_PBUF_SZ-1);

    if (mask->in_port) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%lu ", U322UL(ntohl(fl->in_port)));
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "table %d\r\n",
                     fl->table_id);
    assert(len < FL_PBUF_SZ-1);

    return pbuf;

err_out:
    if (pbuf)
        free(pbuf);
    return NULL;
}

char *
of_dump_flow_generic(struct flow *fl, struct flow *mask)
{
    char *pbuf = calloc(1, FL_PBUF_SZ);
    int len = 0;
    struct in_addr in_addr, in_mask;
    char ip6_addr_str[INET6_ADDRSTRLEN];
    char ip6_mask_str[INET6_ADDRSTRLEN];
    int i = 0;

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow: ");
    assert(len < FL_PBUF_SZ-1);

    if (memcmp(mask->dl_src, zero_mac_addr, OFP_ETH_ALEN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, " smac:");
        assert(len < FL_PBUF_SZ-1);
        for (i = 0; i < OFP_ETH_ALEN; i++) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "%02x:",
                            fl->dl_src[i] & mask->dl_src[i]);
            assert(len < FL_PBUF_SZ-1);
        }
    }
    if (memcmp(mask->dl_dst, zero_mac_addr, OFP_ETH_ALEN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, " dmac:");
        assert(len < FL_PBUF_SZ-1);
        for (i = 0; i < OFP_ETH_ALEN; i++) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "%02x:",
                            fl->dl_dst[i] & mask->dl_dst[i]);
            assert(len < FL_PBUF_SZ-1);
        }
    }

    if (mask->dl_type) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " eth-type", ntohs(fl->dl_type));
        assert(len < FL_PBUF_SZ-1);
    }
    if (mask->dl_vlan) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " vlan-id", ntohs(fl->dl_vlan));
        assert(len < FL_PBUF_SZ-1);
    }
    if (mask->dl_vlan_pcp) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " vlan-pcp", fl->dl_vlan_pcp);
        assert(len < FL_PBUF_SZ-1);
    }
    if (mask->mpls_label) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " mpls-label",
                        ntohl(fl->mpls_label) & MPLS_LABEL_MASK);
        assert(len < FL_PBUF_SZ-1);
    }
    if (mask->mpls_tc) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " mpls-tc", fl->mpls_tc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (mask->mpls_bos) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " mpls-bos", fl->mpls_bos);
        assert(len < FL_PBUF_SZ-1);
    }

    if (mask->dl_type &&
        ((fl->dl_type == htons(ETH_TYPE_IP) || 
          (fl->dl_type == htons(ETH_TYPE_ARP))) ||
        fl->dl_type == htons(ETH_TYPE_IPV6))) {

        if ((fl->dl_type == htons(ETH_TYPE_IP)) || 
                (fl->dl_type == htons(ETH_TYPE_ARP))) {
            if (mask->ip.nw_dst) {
                in_addr.s_addr = fl->ip.nw_dst & mask->ip.nw_dst;
                in_mask.s_addr = mask->ip.nw_dst;
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                                "%s:%s (0x%04x) ", " dst-ip",
                                inet_ntoa(in_addr), ntohl(in_mask.s_addr));
                assert(len < FL_PBUF_SZ-1);
            }
            if (mask->ip.nw_src) {
                in_addr.s_addr = fl->ip.nw_src & mask->ip.nw_src;
                in_mask.s_addr = mask->ip.nw_src;
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                                "%s:%s (0x%04x) ", " src-ip", 
                                inet_ntoa(in_addr), ntohl(in_mask.s_addr));
                assert(len < FL_PBUF_SZ-1);
            }
        } else if (fl->dl_type == htons(ETH_TYPE_IPV6)) {
            if (ipv6_addr_nonzero(&mask->ipv6.nw_src) &&
                inet_ntop(AF_INET6, &fl->ipv6.nw_src, 
                          ip6_addr_str, INET6_ADDRSTRLEN) &&
                inet_ntop(AF_INET6, &mask->ipv6.nw_src,
                          ip6_mask_str, INET6_ADDRSTRLEN)) {
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                                "%s:%s (%s) ", " src-ip6",
                                ip6_addr_str, ip6_mask_str);
                assert(len < FL_PBUF_SZ-1);
            }

            if(ipv6_addr_nonzero(&mask->ipv6.nw_dst) &&
               inet_ntop(AF_INET6, &fl->ipv6.nw_dst, 
                         ip6_addr_str, INET6_ADDRSTRLEN) &&
               inet_ntop(AF_INET6, &mask->ipv6.nw_dst,
                         ip6_mask_str, INET6_ADDRSTRLEN)) {
                len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                                "%s:%s (%s) ", " dst-ip6",
                                ip6_addr_str, ip6_mask_str);
                assert(len < FL_PBUF_SZ-1);
            }
        }

        if (mask->nw_proto) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                            "%s:0x%x ", " ip-proto", fl->nw_proto);
            assert(len < FL_PBUF_SZ-1);
        }
        if (mask->nw_tos) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " ip-tos", fl->nw_tos);
            assert(len < FL_PBUF_SZ-1);
        }

        if (mask->tp_src) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " src-port", ntohs(fl->tp_src));
            assert(len < FL_PBUF_SZ-1);
        }

        if (mask->tp_dst) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " dst-port", ntohs(fl->tp_dst));
            assert(len < FL_PBUF_SZ-1);
        }
    }

    if (mask->in_port) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " in-port", ntohl(fl->in_port));
        assert(len < FL_PBUF_SZ-1);
    }

    if (mask->tunnel_id) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%llx ", " tunnel-id",
                    U642ULL(ntohll(fl->tunnel_id)));
        assert(len < FL_PBUF_SZ-1);
    }

    if (len <= 6) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "ALL wildcards");
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "\r\n");
    return pbuf;
}

int
of10_flow_correction(struct flow *fl, struct flow *mask)
{
    uint16_t eth_proto;
    uint32_t wildcards;
    uint32_t ip_wc;

    if (!fl || !mask) return -1;

    wildcards = ntohl(of10_mask_to_wc(mask));

    if (!(wildcards & OFPFW_IN_PORT) &&
        (!fl->in_port)) {
        return -1;    
    }

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    if (ip_wc >= 32) {
        wildcards &= ~OFPFW_NW_DST_MASK;
        wildcards |= OFPFW_NW_DST_ALL;
    }

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    if (ip_wc >= 32) {
        wildcards &= ~OFPFW_NW_SRC_MASK;
        wildcards |= OFPFW_NW_SRC_ALL;
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        eth_proto = ntohs(fl->dl_type);

        if (eth_proto == ETH_TYPE_ARP) {
            fl->nw_proto = 0;
            fl->nw_tos = 0;
            fl->tp_src = 0;
            fl->tp_dst = 0;
            wildcards |= OFPFW_NW_PROTO | OFPFW_NW_TOS |
                         OFPFW_TP_DST | OFPFW_TP_SRC;
        } else if (eth_proto == ETH_TYPE_IP) {
            if (wildcards & OFPFW_NW_PROTO) {
                fl->tp_src = 0;
                fl->tp_dst = 0;
                wildcards |= OFPFW_TP_DST | OFPFW_TP_SRC;
            }
        } else {
            fl->tp_src = 0;
            fl->tp_dst = 0;
            fl->ip.nw_src = 0;
            fl->ip.nw_dst = 0;
            fl->nw_tos = 0;
            fl->nw_proto = 0;
            wildcards |= OFPFW_NW_DST_ALL | OFPFW_NW_SRC_ALL | OFPFW_NW_PROTO |
                         OFPFW_NW_TOS | OFPFW_TP_DST | OFPFW_TP_SRC;
        }
    } else {
        fl->tp_src = 0;
        fl->tp_dst = 0;
        fl->ip.nw_src = 0;
        fl->ip.nw_dst = 0;
        fl->nw_tos = 0;
        fl->nw_proto = 0;
        wildcards |= OFPFW_NW_DST_ALL | OFPFW_NW_SRC_ALL | OFPFW_NW_PROTO |
                     OFPFW_NW_TOS | OFPFW_TP_DST | OFPFW_TP_SRC;
    }

    of10_wc_to_mask(htonl(wildcards), mask);

    return 0;
}


static inline uint32_t
of_alloc_xid(void)
{
    return random_uint32();
}

void *__fastpath
of_prep_msg_common(uint8_t ver, size_t len, uint8_t type, uint32_t xid)
{
    struct cbuf *b;
    struct ofp_header *h;

    b = alloc_cbuf(len);
    h = cbuf_put(b, len);

    h->version = ver;
    h->type = type;
    h->length = htons(len);

    if (xid) {
        h->xid = xid;
    } else {
        h->xid = of_alloc_xid();
    }

    memset(h + 1, 0, len - sizeof(*h));

    return b;

}

void * __fastpath
of_prep_msg(size_t len, uint8_t type, uint32_t xid)
{
    return of_prep_msg_common(OFP_VERSION, len, type, xid);
}

static void * __fastpath
of131_prep_msg(size_t len, uint8_t type, uint32_t xid)
{
    return of_prep_msg_common(OFP_VERSION_131, len, type, xid);
}

static void * __fastpath
of140_prep_msg(size_t len, uint8_t type, uint32_t xid)
{
    return of_prep_msg_common(OFP_VERSION_140, len, type, xid);
}

struct cbuf *
of_prep_hello(void)
{
    return of_prep_msg(sizeof(struct ofp_header), OFPT_HELLO, 0);
}

struct cbuf *
of_prep_echo(void)
{
    return of_prep_msg(sizeof(struct ofp_header), OFPT_ECHO_REQUEST, 0);
}

struct cbuf *
of_prep_echo_reply(uint32_t xid)
{
    return of_prep_msg(sizeof(struct ofp_header), OFPT_ECHO_REPLY, xid);
}

struct cbuf *
of_prep_features_request(void)
{
    return of_prep_msg(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, 0);
}

struct cbuf *
of_prep_set_config(uint16_t flags, uint16_t miss_len)
{
    struct cbuf *b;
    struct ofp_switch_config *ofp_sc;

    /* Send OFPT_SET_CONFIG. */
    b = of_prep_msg(sizeof(struct ofp_switch_config), OFPT_SET_CONFIG, 0);
    ofp_sc = (void *)(b->data);
    ofp_sc->flags = htons(flags);
    ofp_sc->miss_send_len = htons(miss_len);

    return b;
}

uint32_t 
of10_mask_to_wc(const struct flow *mask)
{
    size_t pref_len;    
    uint32_t wildcards = 0;

    assert(mask);

    /* Mixed IP masks are not allowed */

    pref_len = c_count_one_bits(mask->ip.nw_dst);
    if (pref_len) {
        wildcards |= ((32 - pref_len) & ((1 << OFPFW_NW_DST_BITS)-1))
                              << OFPFW_NW_DST_SHIFT;
    } else {
        wildcards |= OFPFW_NW_DST_ALL;
    }

    pref_len = c_count_one_bits(mask->ip.nw_src);
    if (pref_len) {
        wildcards |= ((32 - pref_len) & ((1 << OFPFW_NW_SRC_BITS)-1))
                              << OFPFW_NW_SRC_SHIFT;
    } else {
        wildcards |= OFPFW_NW_SRC_ALL;
    }
    if (!(mask->in_port)) {
        wildcards |= OFPFW_IN_PORT;
    } 
    if (!(mask->dl_vlan)) {
        wildcards |= OFPFW_DL_VLAN;
    }
    if (!(mask->dl_vlan_pcp)) {
        wildcards |= OFPFW_DL_VLAN_PCP;
    }
    if (!(mask->dl_type)) {
        wildcards |= OFPFW_DL_TYPE;
    }
    if (!(mask->tp_src)) {
        wildcards |= OFPFW_TP_SRC;
    }
    if (!(mask->tp_dst)) {
        wildcards |= OFPFW_TP_DST;
    }
    if (!(mask->nw_tos)) {
        wildcards |= OFPFW_NW_TOS;
    }
    if (!(mask->nw_proto)) {
        wildcards |= OFPFW_NW_PROTO;
    }

    if (!memcmp(mask->dl_dst, zero_mac_addr, 6)) {
        wildcards |= OFPFW_DL_DST;
    }
    if (!memcmp(mask->dl_src, zero_mac_addr, 6)) {
        wildcards |= OFPFW_DL_SRC;
    }

    return htonl(wildcards);
}

void 
of10_wc_to_mask(uint32_t wildcards, struct flow *mask)
{
    size_t pref_len;    

    assert(mask);
    wildcards = ntohl(wildcards);
    memset(mask, 0xff, sizeof(*mask));

    /* Mixed IP masks are not allowed */
    memset(&mask->ipv6, 0, sizeof(mask->ipv6));
    if (wildcards & OFPFW_NW_DST_ALL) {
        pref_len = 0;
    } else {
        pref_len = 32 - ((wildcards >> OFPFW_NW_DST_SHIFT) & 
                        ((1 << OFPFW_NW_DST_BITS)-1));
    }
    mask->ip.nw_dst = htonl(make_inet_mask(pref_len));

    if (wildcards & OFPFW_NW_SRC_ALL) {
        pref_len = 0;
    } else {
        pref_len = 32 - ((wildcards >> OFPFW_NW_SRC_SHIFT) & 
                        ((1 << OFPFW_NW_SRC_BITS)-1));
    }
    mask->ip.nw_src = htonl(make_inet_mask(pref_len));

    if (wildcards & OFPFW_IN_PORT) {
        mask->in_port = 0;
    } 

    if (wildcards & OFPFW_DL_VLAN) {
        mask->dl_vlan = 0;
    }

    if (wildcards & OFPFW_DL_VLAN_PCP) {
        mask->dl_vlan_pcp = 0;
    }

    if (wildcards & OFPFW_DL_TYPE) {
        mask->dl_type = 0;
    }

    if (wildcards & OFPFW_TP_SRC) {
        mask->tp_src = 0;
    }

    if (wildcards & OFPFW_TP_DST) {
        mask->tp_dst = 0;
    }

    if (wildcards & OFPFW_NW_TOS) {
        mask->nw_tos = 0;
    }

    if (wildcards & OFPFW_NW_PROTO) {
        mask->nw_proto = 0;
    }

    if (wildcards & OFPFW_DL_DST) {
        memcpy(mask->dl_dst, zero_mac_addr, 6);
    }

    if (wildcards & OFPFW_DL_SRC) {
        memcpy(mask->dl_src, zero_mac_addr, 6);
    }

    mask->tunnel_id = 0;
    mask->metadata = 0;
    mask->mpls_label = 0;
    mask->mpls_tc = 0;
    mask->mpls_bos = 0;
    mask->table_id = 0xff;

    return;
}

struct cbuf * __fastpath
of_prep_flow_mod(uint16_t command, const struct flow *flow, 
                 const struct flow *mask, size_t actions_len)
{
    struct ofp_flow_mod *ofm;
    size_t len = sizeof *ofm + actions_len;
    struct cbuf *b;
    uint16_t inport = (uint16_t)ntohl(flow->in_port);

    b = alloc_cbuf(len);
    ofm = cbuf_put(b, len);

    memset(ofm, 0, len);
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(len);
    ofm->match.wildcards = of10_mask_to_wc(mask);
    ofm->match.in_port = htons(inport);
    memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
    memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
    ofm->match.dl_vlan = flow->dl_vlan;
    ofm->match.dl_type = flow->dl_type;
    ofm->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofm->match.nw_src = flow->ip.nw_src;
    ofm->match.nw_dst = flow->ip.nw_dst;
    ofm->match.nw_proto = flow->nw_proto;
    ofm->match.tp_src = flow->tp_src;
    ofm->match.tp_dst = flow->tp_dst;
    ofm->command = htons(command);

    return b;
}

struct cbuf * __fastpath
of_prep_flow_add_msg(const struct flow *flow, const struct flow *mask,
                     uint32_t buffer_id, void *actions, size_t actions_len,
                     uint16_t i_timeo, uint16_t h_timeo, uint16_t prio,
                     uint64_t cookie, bool mod)
{
    struct cbuf *b = of_prep_flow_mod(mod ? OFPFC_MODIFY_STRICT : OFPFC_ADD,
                                      flow, mask, 
                                      actions_len);
    struct ofp_flow_mod *ofm = CBUF_DATA(b);
    struct ofp_action_header *ofp_actions;

    ofm->idle_timeout = htons(i_timeo);
    ofm->hard_timeout = htons(h_timeo);
    ofm->priority = htons(prio);
    ofm->buffer_id = htonl(buffer_id);
    ofm->cookie = htonll(cookie);
    ofp_actions = (void *)(ofm + 1);
    memcpy(ofp_actions, actions, actions_len);

    return b;
}

struct cbuf *
of_prep_flow_del_msg(const struct flow *flow, 
                     const struct flow *mask, 
                     uint32_t oport, bool strict,
                     uint16_t prio, uint32_t group UNUSED)
{
    struct cbuf *b = of_prep_flow_mod(strict ? OFPFC_DELETE_STRICT:OFPFC_DELETE, 
                                      flow, mask, 0);
    struct ofp_flow_mod *ofm = CBUF_DATA(b);
    ofm->priority = htons(prio);
    ofm->out_port = htons(oport?:OFPP_NONE);
    return b;
}

struct cbuf * __fastpath
of_prep_pkt_out_msg(struct of_pkt_out_params *parms)
{
    size_t                tot_len;
    struct ofp_packet_out *out;
    struct cbuf           *b;
    void                  *data;

    tot_len = sizeof(struct ofp_packet_out) + parms->action_len
                        + parms->data_len;

    b = of_prep_msg(tot_len, OFPT_PACKET_OUT, (unsigned long)parms->data);

    out = (void *)b->data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htons(parms->in_port ? : OFPP_NONE);
    out->actions_len = htons(parms->action_len);

    data = (uint8_t *)out->actions + parms->action_len;
    /* Hate it !! */
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy(data, parms->data, parms->data_len);


    return b;
}

struct cbuf * 
of_prep_flow_stat_msg(const struct flow *flow, 
                      const struct flow *mask,
                      uint32_t eoport,
                      uint32_t group UNUSED)
{
    struct ofp_stats_request *osr;
    struct ofp_flow_stats_request *ofsr;
    size_t len = sizeof *osr + sizeof *ofsr;
    struct cbuf *b;
    uint16_t oport = *(uint16_t *)(&eoport);
    uint32_t iport = ntohl(flow->in_port);

    b = of_prep_msg(len, OFPT_STATS_REQUEST, 0);
    osr = (void *)(b->data);

    osr->type = htons(OFPST_FLOW);

    ofsr = (void *)(osr->body);

    ofsr->table_id = flow->table_id;
    ofsr->out_port = htons(oport?:OFPP_NONE);

    ofsr->match.wildcards = of10_mask_to_wc(mask);
    ofsr->match.in_port = htons((uint16_t)(iport));
    memcpy(ofsr->match.dl_src, flow->dl_src, sizeof ofsr->match.dl_src);
    memcpy(ofsr->match.dl_dst, flow->dl_dst, sizeof ofsr->match.dl_dst);
    ofsr->match.dl_vlan = flow->dl_vlan;
    ofsr->match.dl_type = flow->dl_type;
    ofsr->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofsr->match.nw_src = flow->ip.nw_src;
    ofsr->match.nw_dst = flow->ip.nw_dst;
    ofsr->match.nw_proto = flow->nw_proto;
    ofsr->match.tp_src = flow->tp_src;
    ofsr->match.tp_dst = flow->tp_dst;

    return b;
}

struct cbuf *
of_prep_port_stat_msg(uint32_t port_no)
{
    struct cbuf *b;
    struct ofp_port_stats_request *ofp_psr; 
    struct ofp_stats_request *ofp_sr;
    size_t len = sizeof *ofp_sr + sizeof *ofp_psr;

    b = of_prep_msg(len, OFPT_STATS_REQUEST, 0);
    
    ofp_sr = CBUF_DATA(b);

    ofp_sr->type = htons(OFPST_PORT);

    ofp_psr = ASSIGN_PTR(ofp_sr->body); 
    ofp_psr->port_no = htons((uint16_t)(port_no));

    return b;
}

struct cbuf *
of_prep_port_mod_msg(uint32_t port_no, 
                     struct of_port_mod_params *pm_params, 
                     uint8_t *hw_addr)
{
    size_t tot_len = 0;
    struct ofp_port_mod *ofp_pm;
    struct cbuf *b;

    tot_len = sizeof(struct ofp_port_mod);

    b = of_prep_msg(tot_len, OFPT_PORT_MOD, 0);
    ofp_pm = CBUF_DATA(b);
    ofp_pm->port_no = htons(port_no);
    ofp_pm->config = htonl(pm_params->config);
    ofp_pm->mask = htonl(pm_params->mask);
    memcpy(ofp_pm->hw_addr, hw_addr, OFP_ETH_ALEN);
            
    return b;
}

struct cbuf *
of_prep_q_get_config(uint32_t port_no)
{
    struct cbuf *b;
    struct ofp_queue_get_config_request *ofp_gcf; 

    b = of_prep_msg(sizeof(*ofp_gcf), OFPT_QUEUE_GET_CONFIG_REQUEST, 0);
    ofp_gcf = CBUF_DATA(b);
    ofp_gcf->port = htons((uint16_t)(port_no));

    return b;
}

struct cbuf *
of_prep_vendor_msg(struct of_vendor_params *vp)
{
    struct cbuf *b;
    struct ofp_vendor_header *ofpv;

    b = of_prep_msg(sizeof(*ofpv) + vp->data_len, OFPT_VENDOR, 0);
    ofpv = CBUF_DATA(b);
    ofpv->vendor = htonl(vp->vendor);
    memcpy(ofpv->body, vp->data, vp->data_len);
   
    return b;
}

void
of131_capabilities_tostr(char *string, uint32_t capabilities)
{
    if (capabilities == 0) {
        strcpy(string, "No capabilities\n");
        return;
    }
    if (capabilities & OFPC131_FLOW_STATS) {
        strcat(string, "FLOW_STATS ");
    }
    if (capabilities & OFPC131_TABLE_STATS) {
        strcat(string, "TABLE_STATS ");
    }
    if (capabilities & OFPC131_PORT_STATS) {
        strcat(string, "PORT_STATS ");
    }
    if (capabilities & OFPC131_GROUP_STATS) {
        strcat(string, "GROUP_STATS ");
    }
    if (capabilities & OFPC131_IP_REASM) {
        strcat(string, "IP_REASM");
    }
    if (capabilities & OFPC131_QUEUE_STATS) {
        strcat(string, "QUEUE_STATS ");
    }
    if (capabilities & OFPC131_PORT_BLOCKED) {
        strcat(string, "PORT_BLOCKED");
    }
}

struct cbuf *
of131_prep_hello_msg(void)
{
    uint32_t v_bmap = htonl(0x12); 
    size_t hello_len = sizeof(struct ofp_hello) + 
                       C_ALIGN_8B_LEN(sizeof(struct ofp_hello_elem_versionbitmap) +
                       sizeof(v_bmap));
    struct cbuf *b;
    struct ofp_hello_elem_versionbitmap *ofp_hemv;

    b = of131_prep_msg(hello_len, OFPT131_HELLO, 0);
    ofp_hemv = (void *)(((struct ofp_hello *)(b->data))->elements);
    ofp_hemv->type = htons(OFPHET_VERSIONBITMAP);
    ofp_hemv->length = htons(sizeof(*ofp_hemv) + sizeof(v_bmap));
    
    ofp_hemv->bitmaps[0] = v_bmap;

    return b;
}

struct cbuf *
of131_prep_echo_msg(void)
{
    return of131_prep_msg(sizeof(struct ofp_header), OFPT131_ECHO_REQUEST, 0);
}

struct cbuf *
of131_prep_echo_reply_msg(uint32_t xid)
{
    return of131_prep_msg(sizeof(struct ofp_header), OFPT131_ECHO_REQUEST, xid);
}

struct cbuf *
of131_prep_set_config_msg(uint16_t flags, uint16_t miss_len)
{
    struct cbuf *b;
    struct ofp_switch_config *ofp_sc;

    /* Send OFPT_SET_CONFIG. */
    b = of131_prep_msg(sizeof(struct ofp_switch_config), OFPT131_SET_CONFIG, 0);
    ofp_sc = (void *)(b->data);
    ofp_sc->flags = htons(flags);
    ofp_sc->miss_send_len = htons(miss_len);

    return b;
}

const char *
of_role_to_str(uint32_t role)
{
    switch (role) {
    case OFPCR_ROLE_EQUAL:
        return "HA-role-equal";
    case OFPCR_ROLE_MASTER:
        return "HA-role-master";    
    case OFPCR_ROLE_SLAVE:
        return "HA-role-slave";
    default:
        break;
    }
    return "HA-role-unknown";
}

struct cbuf *
of131_prep_role_request_msg(uint32_t role, uint64_t gen_id)
{
    struct cbuf *b;
    struct ofp_role_request *ofp_rr;

    b = of131_prep_msg(sizeof(*ofp_rr), OFPT131_ROLE_REQUEST, 0);
    ofp_rr = (void *)(b->data);
    ofp_rr->role = htonl(role);
    ofp_rr->generation_id = htonll(gen_id);

    return b;
}

struct cbuf *
of131_prep_features_request_msg(void)
{
    return of131_prep_msg(sizeof(struct ofp_header), OFPT131_FEATURES_REQUEST, 0);
}

struct cbuf * __fastpath
of131_prep_pkt_out_msg(struct of_pkt_out_params *parms)
{
    size_t                   tot_len;
    struct ofp131_packet_out *out;
    struct cbuf              *b;
    void                     *data;

    tot_len = sizeof(struct ofp131_packet_out) + parms->action_len
                        + parms->data_len;

    b = of131_prep_msg(tot_len, OFPT131_PACKET_OUT, (unsigned long)parms->data);

    out = (void *)b->data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htonl(parms->in_port ?: OFPP131_CONTROLLER);
    out->actions_len = htons(parms->action_len);

    data = (uint8_t *)out->actions + parms->action_len;
    /* Hate it !! */
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy(data, parms->data, parms->data_len);

    return b;
}

static struct cbuf *
of13_14_prep_mpart_msg(uint16_t type, uint16_t flags, size_t body_len,
                       uint8_t version)
{
    struct cbuf *b;
    struct ofp_multipart_request *ofp_mr;

    if(version == OFP_VERSION_131) {
        b = of131_prep_msg(sizeof(*ofp_mr) + body_len, 
                OFPT131_MULTIPART_REQUEST, 0);
    }
    else {
        b = of140_prep_msg(sizeof(*ofp_mr) + body_len, 
                OFPT140_MULTIPART_REQUEST, 0);
    }

    ofp_mr = CBUF_DATA(b);
    ofp_mr->type = htons(type);
    ofp_mr->flags = htons(flags);
    
    return b;
}


struct cbuf *
of131_prep_mpart_msg(uint16_t type, uint16_t flags, size_t body_len)
{
    struct cbuf *b;
    b = of13_14_prep_mpart_msg(type, flags, body_len, OFP_VERSION_131);
    return b;
}

struct cbuf *
of140_prep_mpart_msg(uint16_t type, uint16_t flags, size_t body_len)
{
    struct cbuf *b;
    b = of13_14_prep_mpart_msg(type, flags, body_len, OFP_VERSION_140);
    return b;
}



struct cbuf *
of131_prep_barrier_req(void)
{
    struct cbuf *b;
    struct ofp_header *oh;
    
    b = of131_prep_msg(sizeof(*oh), OFPT131_BARRIER_REQUEST, 0);
    return b;
}


static size_t
of131_add_oxm_fields(uint8_t *buf,
                     size_t buf_len UNUSED,
                     const struct flow *flow,
                     const struct flow *mask)
{
    struct ofp_oxm_header *oxm = (void *)buf;
    size_t oxm_field_sz = 0;
    uint32_t *nw_addr;
    uint8_t zero_mac_addr[] = { 0, 0, 0, 0, 0, 0};
    uint8_t oxm_src_port = 0, oxm_dst_port = 0;
    bool has_l4_ports = false;

    /* Add this point only ip addresses have hasmask if 
     * needed
     */

    if (mask->in_port) { /* Not partially maskable */
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC; 
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IN_PORT);
        oxm->length = OFPXMT_OFB_IN_PORT_SZ; 
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint32_t *)(oxm->data) = flow->in_port;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (memcmp(mask->dl_dst, zero_mac_addr, OFP_ETH_ALEN)) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_DST);
        oxm->length = OFPXMT_OFB_ETH_SZ; 
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        memcpy((uint8_t *)(oxm->data), flow->dl_dst, OFP_ETH_ALEN);
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (memcmp(mask->dl_src, zero_mac_addr, OFP_ETH_ALEN)) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_SRC);
        oxm->length = OFPXMT_OFB_ETH_SZ; 
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        memcpy((uint8_t *)(oxm->data), flow->dl_src, OFP_ETH_ALEN);
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (mask->dl_type) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_TYPE);
        oxm->length = OFPXMT_OFB_ETH_TYPE_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint16_t *)(oxm->data) = flow->dl_type;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (mask->dl_vlan) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_VLAN_VID); // FIXME : OFPVID_PRESENT ??
        oxm->length = OFPXMT_OFB_VLAN_VID_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint16_t *)(oxm->data) = flow->dl_vlan;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (mask->dl_vlan && mask->dl_vlan_pcp) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_VLAN_PCP);
        oxm->length = OFPXMT_OFB_VLAN_PCP_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint8_t *)(oxm->data) = flow->dl_vlan_pcp;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }

    if (mask->dl_type &&
        (htons(flow->dl_type) == ETH_TYPE_MPLS ||
        htons(flow->dl_type) == ETH_TYPE_MPLS_MCAST)) {

        if (mask->mpls_label) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 0);
            OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_LABEL);
            oxm->length = OFPXMT_OFB_MPLS_LABEL_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            of_put_mpls_label_oxm(oxm->data, flow->mpls_label,
                                  oxm->length);
            oxm = INC_PTR8(buf, oxm_field_sz);
        }
        if (mask->mpls_tc) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 0);
            OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_TC);
            oxm->length = OFPXMT_OFB_MPLS_TC_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            *(uint8_t *)(oxm->data) = flow->mpls_tc;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }

        if (mask->mpls_bos) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 0);
            OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_BOS);
            oxm->length = OFPXMT_OFB_MPLS_BOS_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            *(uint8_t *)(oxm->data) = flow->mpls_bos;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }
    }

    if (mask->dl_type &&
        htons(flow->dl_type) == ETH_TYPE_IP) {
        if (mask->ip.nw_src) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 1);
            OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV4_SRC);
            oxm->length = 2*OFPXMT_OFB_IPV4_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            nw_addr = (void *)(oxm->data);
            *nw_addr++ = flow->ip.nw_src;
            *nw_addr++ = mask->ip.nw_src;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }
        if (mask->ip.nw_dst) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 1);
            OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV4_DST);
            oxm->length = 2*OFPXMT_OFB_IPV4_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            nw_addr = (void *)(oxm->data);
            *nw_addr++ = flow->ip.nw_dst;
            *nw_addr++ = mask->ip.nw_dst;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }
    }
    if (mask->dl_type &&
        htons(flow->dl_type) == ETH_TYPE_IPV6) {
        if (ipv6_addr_nonzero(&mask->ipv6.nw_src)) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 1);
            OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV6_SRC);
            oxm->length = 2*OFPXMT_OFB_IPV6_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            memcpy(oxm->data, &flow->ipv6.nw_src, sizeof(flow->ipv6.nw_src));
            memcpy(INC_PTR8(oxm->data, 16),
                   &mask->ipv6.nw_src, sizeof(mask->ipv6.nw_src));
            oxm = INC_PTR8(buf, oxm_field_sz);
        }
        if (ipv6_addr_nonzero(&mask->ipv6.nw_dst)) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 1);
            OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV6_DST);
            oxm->length = 2*OFPXMT_OFB_IPV6_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            memcpy(oxm->data, &flow->ipv6.nw_dst, sizeof(flow->ipv6.nw_dst));
            memcpy(INC_PTR8(oxm->data, 16),
                   &mask->ipv6.nw_dst, sizeof(mask->ipv6.nw_dst));
            oxm = INC_PTR8(buf, oxm_field_sz);
        }
    }

    if (mask->dl_type && 
        (htons(flow->dl_type) == ETH_TYPE_IP ||
         htons(flow->dl_type) == ETH_TYPE_IPV6) &&
        mask->nw_tos) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IP_DSCP);
        oxm->length = OFPXMT_OFB_IP_DSCP_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint8_t *)(oxm->data) = flow->nw_tos;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }

    if (mask->dl_type && 
        (htons(flow->dl_type) == ETH_TYPE_IP ||
         htons(flow->dl_type) == ETH_TYPE_IPV6) &&
        mask->nw_proto) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IP_PROTO);
        oxm->length = OFPXMT_OFB_IP_PROTO_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint8_t *)(oxm->data) = flow->nw_proto;
        oxm = INC_PTR8(buf, oxm_field_sz);

        if (flow->nw_proto == IP_TYPE_TCP) {
            oxm_src_port = OFPXMT_OFB_TCP_SRC;
            oxm_dst_port = OFPXMT_OFB_TCP_DST;
            has_l4_ports = true;
        } else if (flow->nw_proto == IP_TYPE_UDP) {
            oxm_src_port = OFPXMT_OFB_UDP_SRC;
            oxm_dst_port = OFPXMT_OFB_UDP_DST;
            has_l4_ports = true;
        }
    }
    
    if (has_l4_ports) {
        if (mask->tp_src) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 0);
            OFP_OXM_SHDR_FIELD(oxm, oxm_src_port);
            oxm->length = OFPXMT_OFB_L4_PORT_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            *(uint16_t *)(oxm->data) = flow->tp_src;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }

        if (mask->tp_dst) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 0);
            OFP_OXM_SHDR_FIELD(oxm, oxm_dst_port);
            oxm->length = OFPXMT_OFB_L4_PORT_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            *(uint16_t *)(oxm->data) = flow->tp_dst;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }
    }
    return oxm_field_sz;
}

/** 
 * of131_prep_ofpx_match - 
 *
 * Makes an ofpx_match given flow and mask
 * Return val is 8-byte aligned length of ofpx_match
 */
static size_t
of131_prep_ofpx_match(struct ofpx_match *match, size_t oxm_tlv_room,
                      const struct flow *flow, const struct flow *mask)
{
    size_t tlv_len, match_len;

    tlv_len = of131_add_oxm_fields((uint8_t *)(match->oxm_fields),
                                   oxm_tlv_room, flow, mask); 

    match_len = OFPX_MATCH_HDR_SZ + tlv_len;
    match->type = htons(OFPMT_OXM);
    match->length = htons(match_len);

    return C_ALIGN_8B_LEN(match_len);
}

static struct cbuf * __fastpath
of13_14_prep_flow_mod_match(uint8_t command, const struct flow *flow, 
                          const struct flow *mask, uint8_t *inst_list,
                          size_t inst_len, uint8_t version)
{
    struct ofp131_flow_mod *ofm; /* flow mod structure is not changed in
                                    OF1.4, thats why using same structure
                                    for OF1.3.x and above*/

    size_t match_len = 0, frame_len = 0; 
    struct cbuf *b;

    b = zalloc_cbuf(OF_MAX_FLOW_MOD_BUF_SZ); /* It should suffice for now */
    ofm = CBUF_DATA(b);
    match_len = of131_prep_ofpx_match(&ofm->match, 
                                OF_MAX_FLOW_MOD_BUF_SZ - sizeof(*ofm),
                                flow, mask); 
    match_len -= sizeof(ofm->match); /* match_len includes match size */
    frame_len = sizeof(*ofm) + match_len + inst_len;
    cbuf_put(b, frame_len);
    ofm->header.version = version;
    ofm->header.type = version == OFP_VERSION_131 ? OFPT131_FLOW_MOD:
        OFPT140_FLOW_MOD;
    ofm->header.length = htons(frame_len);
    ofm->header.xid = of_alloc_xid(); 
    ofm->command = command;

    if (inst_len) {
        memcpy(INC_PTR8(ofm, sizeof(*ofm) + match_len), 
                       inst_list, inst_len);
    }

    return b;
}

int 
of131_ofpx_match_to_flow(struct ofpx_match *ofx,
                         struct flow *flow, struct flow *mask)
{
    int len = ntohs(ofx->length);
    struct ofp_oxm_header *oxm_ptr = (void *)(ofx->oxm_fields);
    struct ofp_oxm_header *oxm, oxm_hdr;
    int n_tlvs = 0, min_tlv_len = 0;
    uint8_t hm = 0;

    memset(flow, 0, sizeof(*flow));
    memset(mask, 0, sizeof(*mask));

    if (len < sizeof(*ofx)) {
        return 0; // All wildcards??
    }

    if (ntohs(ofx->type) != OFPMT_OXM) {
        if (!c_rlim(&rl))
            c_log_err("%s: ofpx_type err", FN);
        return -1;
    }

    oxm = &oxm_hdr;
    len -= OFPX_MATCH_HDR_SZ;

    while (len > (int)sizeof(*oxm)) {

        ASSIGN_OXM_HDR(oxm, oxm_ptr);
        NTOH_OXM_HDR(oxm);

        if (oxm->oxm_class != OFPXMC_OPENFLOW_BASIC ||
            n_tlvs++ >= OFP_MAX_OXM_TLVS ) {
            
            if (!c_rlim(&rl))
                c_log_err("%s: ERROR rem-len %d", FN, len);
            return -1;
        }

        switch (OFP_OXM_GHDR_FIELD(oxm)) {
        case OFPXMT_OFB_IN_PORT:
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_IN_PORT_SZ ||
                oxm->length != OFPXMT_OFB_IN_PORT_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: in-port err", FN);
                return -1;
            }
            
            flow->in_port = *(uint32_t *)(oxm_ptr->data);
            mask->in_port = 0xffffffff;
            break;
        case OFPXMT_OFB_ETH_DST:
            hm = OFP_OXM_GHDR_HM(oxm);
            min_tlv_len = hm ? 2 * OFPXMT_OFB_ETH_SZ: OFPXMT_OFB_ETH_SZ; 
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: eth-dst err", FN);
                return -1;
            }
            memcpy(flow->dl_dst, oxm_ptr->data, OFPXMT_OFB_ETH_SZ);
            if (hm) {
                memcpy(mask->dl_dst, oxm_ptr->data + OFPXMT_OFB_ETH_SZ, 
                       OFPXMT_OFB_ETH_SZ);
            } else {
                memset(mask->dl_dst, 0xff, OFPXMT_OFB_ETH_SZ);
            } 
            break;
        case OFPXMT_OFB_ETH_SRC:
            hm = OFP_OXM_GHDR_HM(oxm);
            min_tlv_len = hm ? 2 * OFPXMT_OFB_ETH_SZ: OFPXMT_OFB_ETH_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: eth-src err", FN);
                return -1;
            }
            memcpy(flow->dl_src, oxm_ptr->data, OFPXMT_OFB_ETH_SZ);
            if (hm) {
                memcpy(mask->dl_src, oxm_ptr->data + OFPXMT_OFB_ETH_SZ, 
                       OFPXMT_OFB_ETH_SZ);
            } else {
                memset(mask->dl_src, 0xff, OFPXMT_OFB_ETH_SZ);
            } 
            break;
        case OFPXMT_OFB_VLAN_VID:
            hm = OFP_OXM_GHDR_HM(oxm);
            min_tlv_len = hm ? 2*OFPXMT_OFB_VLAN_VID_SZ:OFPXMT_OFB_VLAN_VID_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: vlan-vid err", FN);
                return -1;
            }
            flow->dl_vlan = *(uint16_t *)(oxm_ptr->data);
            if (OFP_OXM_GHDR_HM(oxm)) {
                mask->dl_vlan = *(uint16_t *)(oxm_ptr->data +
                                              OFPXMT_OFB_VLAN_VID_SZ);
            } else {
                mask->dl_vlan = 0xffff;
            }
            break;
        case OFPXMT_OFB_VLAN_PCP:
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_VLAN_PCP_SZ  ||
                oxm->length != OFPXMT_OFB_VLAN_PCP_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: vlan-pcp err", FN);
                return -1;
            }
            flow->dl_vlan_pcp = *(uint8_t *)(oxm_ptr->data);
            mask->dl_vlan_pcp = 0xff;
            break;
        case OFPXMT_OFB_ETH_TYPE:
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_ETH_TYPE_SZ ||
                oxm->length != OFPXMT_OFB_ETH_TYPE_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: eth-type err", FN);
                return -1;
            }
            flow->dl_type = *(uint16_t *)(oxm_ptr->data);
            mask->dl_type = 0xffff;
            break;
        case OFPXMT_OFB_MPLS_LABEL:
            if (flow->dl_type != htons(ETH_TYPE_MPLS) && 
                flow->dl_type != htons(ETH_TYPE_MPLS_MCAST)) break;
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_MPLS_LABEL_SZ || 
                oxm->length < OFPXMT_OFB_MPLS_LABEL_SZ-1) {
                if (!c_rlim(&rl))
                    c_log_err("%s: mpls-label err", FN);
                return -1;
            }
            of_get_mpls_label_oxm(oxm_ptr->data, &flow->mpls_label,
                                  oxm->length);
            mask->mpls_label = 0xffffffff;
            break;
        case OFPXMT_OFB_MPLS_TC:
            if (flow->dl_type != htons(ETH_TYPE_MPLS) && 
                flow->dl_type != htons(ETH_TYPE_MPLS_MCAST)) break;
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_MPLS_TC_SZ || 
                oxm->length != OFPXMT_OFB_MPLS_TC_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: mpls-tc err", FN);
                return -1;
            }
            flow->mpls_tc = *(uint8_t *)(oxm_ptr->data);
            mask->mpls_tc = 0xff;
            break;
        case OFPXMT_OFB_MPLS_BOS: 
            if (flow->dl_type != htons(ETH_TYPE_MPLS) &&
                flow->dl_type != htons(ETH_TYPE_MPLS_MCAST)) break;
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_MPLS_BOS_SZ ||
                oxm->length != OFPXMT_OFB_MPLS_BOS_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: mpls-bos err", FN);
                return -1;
            }
            flow->mpls_bos = *(uint8_t *)(oxm_ptr->data);
            mask->mpls_bos = 0xff;
            break;
        case OFPXMT_OFB_IPV4_SRC:
            hm = OFP_OXM_GHDR_HM(oxm);
            if (flow->dl_type != htons(ETH_TYPE_IP)) break;
            min_tlv_len = hm ? 2 * OFPXMT_OFB_IPV4_SZ: OFPXMT_OFB_IPV4_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ipv4-src err", FN);
                return -1;
            }
            flow->ip.nw_src = *(uint32_t *)(oxm_ptr->data);
            if (hm) {
                mask->ip.nw_src = *(uint32_t *)(oxm_ptr->data + OFPXMT_OFB_IPV4_SZ);
            } else {
                mask->ip.nw_src = 0xffffffff;
            }
            break;
        case OFPXMT_OFB_IPV4_DST:
            hm = OFP_OXM_GHDR_HM(oxm);
            if (flow->dl_type != htons(ETH_TYPE_IP)) break;
            min_tlv_len = hm ? 2 * OFPXMT_OFB_IPV4_SZ: OFPXMT_OFB_IPV4_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ipv4-dst err", FN);
                return -1;
            }
            flow->ip.nw_dst = *(uint32_t *)(oxm_ptr->data);
            if (hm) {
                mask->ip.nw_dst = *(uint32_t *)(oxm_ptr->data + OFPXMT_OFB_IPV4_SZ);
            } else {
                mask->ip.nw_dst = 0xffffffff;
            }
            break;
        case OFPXMT_OFB_IPV6_DST:
            hm = OFP_OXM_GHDR_HM(oxm);
            if (flow->dl_type != htons(ETH_TYPE_IPV6)) break;
            min_tlv_len = hm ? 2 * OFPXMT_OFB_IPV6_SZ: OFPXMT_OFB_IPV6_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ipv6-dst err", FN);
                return -1;
            }
            memcpy(&flow->ipv6.nw_dst, oxm_ptr->data, OFPXMT_OFB_IPV6_SZ);
            if (hm) {
                memcpy(&mask->ipv6.nw_dst,
                       INC_PTR8(oxm_ptr->data, OFPXMT_OFB_IPV6_SZ),
                       OFPXMT_OFB_IPV6_SZ);
            } else {
                memset(&mask->ipv6.nw_dst, 0xff, OFPXMT_OFB_IPV6_SZ);
            }
            break;
        case OFPXMT_OFB_IPV6_SRC:
            hm = OFP_OXM_GHDR_HM(oxm);
            if (flow->dl_type != htons(ETH_TYPE_IPV6)) break;
            min_tlv_len = hm ? 2 * OFPXMT_OFB_IPV6_SZ: OFPXMT_OFB_IPV6_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ipv6-src err", FN);
                return -1;
            }
            memcpy(&flow->ipv6.nw_src, oxm_ptr->data, OFPXMT_OFB_IPV6_SZ);
            if (hm) {
                memcpy(&mask->ipv6.nw_src,
                       INC_PTR8(oxm_ptr->data, OFPXMT_OFB_IPV6_SZ),
                       OFPXMT_OFB_IPV6_SZ);
            } else {
                memset(&mask->ipv6.nw_src, 0xff, OFPXMT_OFB_IPV6_SZ);
            }
            break;
        case OFPXMT_OFB_IP_DSCP:
            if (flow->dl_type != htons(ETH_TYPE_IP) &&
                flow->dl_type != htons(ETH_TYPE_IPV6)) break;
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_IP_DSCP_SZ ||
                oxm->length != OFPXMT_OFB_IP_DSCP_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ip-dscp err", FN);
                return -1;
            }
            flow->nw_tos = *(uint8_t *)(oxm_ptr->data);
            mask->nw_tos = 0xff;
            break;
        case OFPXMT_OFB_IP_PROTO:
            if (flow->dl_type != htons(ETH_TYPE_IP) &&
                flow->dl_type != htons(ETH_TYPE_IPV6)) break;
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_IP_PROTO_SZ ||
                oxm->length != OFPXMT_OFB_IP_PROTO_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ip-proto err", FN);
                return -1;
            }
            flow->nw_proto = *(uint8_t *)(oxm_ptr->data);
            mask->nw_proto = 0xff;
            break;
        case OFPXMT_OFB_TCP_SRC:
        case OFPXMT_OFB_UDP_SRC:
            if ((flow->dl_type != htons(ETH_TYPE_IP) &&
                flow->dl_type != htons(ETH_TYPE_IPV6)) ||
                (flow->nw_proto != IP_TYPE_UDP && 
                flow->nw_proto != IP_TYPE_TCP)) {
                return -1;
            }
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_L4_PORT_SZ ||
                oxm->length != OFPXMT_OFB_L4_PORT_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: l4-src-port err", FN);
                break;;
            }
            flow->tp_src = *(uint16_t *)(oxm_ptr->data);
            mask->tp_src = 0xffff;
            break;
        case OFPXMT_OFB_TCP_DST:
        case OFPXMT_OFB_UDP_DST:
            if ((flow->dl_type != htons(ETH_TYPE_IP) && 
                flow->dl_type != htons(ETH_TYPE_IPV6)) ||
                (flow->nw_proto != IP_TYPE_UDP  &&
                flow->nw_proto != IP_TYPE_TCP)) {
                break;
            }
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_L4_PORT_SZ ||
                oxm->length != OFPXMT_OFB_L4_PORT_SZ) {
                return -1;
            }
            flow->tp_dst = *(uint16_t *)(oxm_ptr->data);
            mask->tp_dst = 0xffff;
            break;
        case OFPXMT_OFB_TUNNEL_ID:
            hm = OFP_OXM_GHDR_HM(oxm);
            min_tlv_len = hm ? 2 * OFPXMT_OFB_TUNNEL_ID_SZ:
                               OFPXMT_OFB_TUNNEL_ID_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: tunnel-id err", FN);
                return -1;
            }
            flow->tunnel_id = *(uint64_t *)(oxm_ptr->data);
            if (hm) {
                mask->tunnel_id = *(uint64_t *)(oxm_ptr->data +
                                                OFPXMT_OFB_TUNNEL_ID_SZ);
            } else {
                mask->tunnel_id = (uint64_t)(-1);
            }
            break;
        default:
            //if (!c_rlim(&rl))
            //    c_log_err("%s:Unhandled OXM %u", FN, OFP_OXM_GHDR_FIELD(oxm)); 
            break;
        } 

        len -= oxm->length + sizeof(*oxm);

        //c_log_err("%s: n_tlv(%d) type (%u) oxm-length %u rem %d",
        //           FN, n_tlvs, OFP_OXM_GHDR_FIELD(oxm), oxm->length, len);

        oxm_ptr = INC_PTR8(oxm_ptr, oxm->length + sizeof(*oxm));
    }

    return 0;
}

static struct cbuf *
of13_14_prep_flow_add_msg(const struct flow *flow, const struct flow *mask,
                        uint32_t buffer_id, void *ins_list,
                        size_t ins_len, uint16_t i_timeo,
                        uint16_t h_timeo, uint16_t prio,
                        uint64_t cookie, bool mod, uint8_t version)
{
    struct cbuf *b = 
        of13_14_prep_flow_mod_match(mod ? OFPFC_MODIFY_STRICT:OFPFC_ADD, 
                                        flow, mask, ins_list, ins_len, 
                                               version);
    struct ofp131_flow_mod *ofm = CBUF_DATA(b);

    ofm->idle_timeout = htons(i_timeo);
    ofm->hard_timeout = htons(h_timeo);
    ofm->priority = htons(prio);
    ofm->table_id = flow->table_id;
    ofm->buffer_id = htonl(buffer_id);
    ofm->cookie = htonll(cookie);
    ofm->cookie_mask = 0xffffffffffffffff;

    /* FIXME - flags ?? */

    return b;
}

struct cbuf *
of131_prep_flow_add_msg(const struct flow *flow, const struct flow *mask,
                        uint32_t buffer_id, void *ins_list,
                        size_t ins_len, uint16_t i_timeo,
                        uint16_t h_timeo, uint16_t prio,
                        uint64_t cookie, bool mod)
{
    struct cbuf *b = of13_14_prep_flow_add_msg(flow, mask, buffer_id,
            ins_list, ins_len, i_timeo, h_timeo, prio, cookie, mod,
            OFP_VERSION_131);

    return b;
}

struct cbuf *
of140_prep_flow_add_msg(const struct flow *flow, const struct flow *mask,
                        uint32_t buffer_id, void *ins_list,
                        size_t ins_len, uint16_t i_timeo,
                        uint16_t h_timeo, uint16_t prio,
                        uint64_t cookie, bool mod)
{
    struct cbuf *b = of13_14_prep_flow_add_msg(flow, mask, buffer_id,
            ins_list, ins_len, i_timeo, h_timeo, prio, cookie, mod,
            OFP_VERSION_140);

    return b;
}

static struct cbuf *
of13_14_prep_flow_del_msg(const struct flow *flow,
                        const struct flow *mask,
                        uint32_t oport, bool strict,
                        uint16_t prio, uint32_t group, uint8_t version)
{
    struct cbuf *b = 
        of13_14_prep_flow_mod_match(strict?OFPFC_DELETE_STRICT:OFPFC_DELETE,
                                    flow, mask, NULL, 0, version);
    struct ofp131_flow_mod *ofm = (void *)(b->data);

    ofm->priority = htons(prio);
    ofm->table_id = flow->table_id;
    ofm->out_port = htonl(oport?:OFPP131_ANY);
    ofm->out_group = htonl(group);
    return b;
}

struct cbuf *
of131_prep_flow_del_msg(const struct flow *flow,
                        const struct flow *mask,
                        uint32_t oport, bool strict,
                        uint16_t prio, uint32_t group)
{
    struct cbuf *b = of13_14_prep_flow_del_msg( flow, mask, oport, strict,
                                                prio, group, 
                                                OFP_VERSION_131);
    return b;
}

struct cbuf *
of140_prep_flow_del_msg(const struct flow *flow,
                        const struct flow *mask,
                        uint32_t oport, bool strict,
                        uint16_t prio, uint32_t group)
{
    struct cbuf *b = of13_14_prep_flow_del_msg( flow, mask, oport, strict,
                                                prio, group, 
                                                OFP_VERSION_140);
    return b;
}

static struct cbuf * 
of13_14_prep_flow_stat_msg(const struct flow *flow, 
                         const struct flow *mask,
                         uint32_t eoport,
                         uint32_t group,
                         uint8_t version)
{
    struct ofp131_flow_stats_request *ofsr;
    struct cbuf *b;
    struct ofp_multipart_request *ofp_mr;
    uint16_t oport = *(uint16_t *)(&eoport);
    void *ofpx_match_buf = NULL;
    size_t mlen;

    ofpx_match_buf = calloc(1, OF_MAX_FLOW_MOD_BUF_SZ); 
                               /* It should suffice for now */

    if (!ofpx_match_buf) return NULL;

    mlen = of131_prep_ofpx_match(ofpx_match_buf, 
                                OF_MAX_FLOW_MOD_BUF_SZ - 
                                sizeof(struct ofpx_match),
                                flow, mask);
    b = of13_14_prep_mpart_msg(OFPMP_FLOW, 0,
                             sizeof(*ofsr) + mlen - sizeof(ofsr->match),
                             version);
    ofp_mr = CBUF_DATA(b);
    ofsr = ASSIGN_PTR(ofp_mr->body);
    ofsr->table_id = flow->table_id;
    ofsr->out_port = htonl(oport?:OFPP131_ANY);
    ofsr->out_group = htonl(group);
    memcpy(&ofsr->match, ofpx_match_buf, mlen);
    
    free(ofpx_match_buf);
    return b;
}

struct cbuf * 
of131_prep_flow_stat_msg(const struct flow *flow, 
                         const struct flow *mask,
                         uint32_t eoport,
                         uint32_t group)
{
    struct cbuf *b;
    b = of13_14_prep_flow_stat_msg(flow, mask, eoport, group,
            OFP_VERSION_131);
    return b;
}

struct cbuf * 
of140_prep_flow_stat_msg(const struct flow *flow, 
                         const struct flow *mask,
                         uint32_t eoport,
                         uint32_t group)
{
    struct cbuf *b;
    b = of13_14_prep_flow_stat_msg(flow, mask, eoport, group,
            OFP_VERSION_140);
    return b;
}

static struct cbuf *
of13_14_prep_queue_stat_msg(uint32_t port, uint32_t queue, uint8_t version)
{
    struct ofp131_queue_stats_request *ofp_q_stats;
    struct cbuf *b;
    struct ofp_multipart_request *ofp_mr;

    b = of13_14_prep_mpart_msg(OFPMP_QUEUE, 0, sizeof(*ofp_q_stats), version);
    ofp_mr = CBUF_DATA(b);
    ofp_q_stats = ASSIGN_PTR(ofp_mr->body);
    ofp_q_stats->port_no = htonl(port?:OFPP131_ANY);
    ofp_q_stats->queue_id = htonl(queue);
    return b;
}

struct cbuf *
of131_prep_queue_stat_msg(uint32_t port, uint32_t queue)
{
    struct cbuf *b;
     b = of13_14_prep_queue_stat_msg(port, queue, OFP_VERSION_131);
     return b;
}

struct cbuf *
of140_prep_queue_stat_msg(uint32_t port, uint32_t queue)
{
    struct cbuf *b;
     b = of13_14_prep_queue_stat_msg(port, queue, OFP_VERSION_140);
     return b;
}

bool
of131_group_validate_parms(bool add, uint32_t group, uint8_t type, 
                           struct of_act_vec_elem *act_vectors[] UNUSED,
                           size_t act_vec_len)
{

    if (group == OFPG_ANY || group > OFPG_MAX)
        return false;

    if (add) {
        if (group == OFPG_ALL)
            return false;
        if (type == OFPGT_INDIRECT && act_vec_len > 1) 
            return false;
    }

    return true;
}
 
static struct cbuf * 
of13_14_prep_group_add_msg(uint32_t group, uint8_t type, 
                         struct of_act_vec_elem *act_vectors[],
                         size_t act_vec_len, bool modify, uint8_t version)
{
    size_t tot_len = 0;
    struct of_act_vec_elem *elem;
    struct ofp_group_mod *ofp_gm;
    struct ofp_bucket *ofp_b;
    size_t bkt_len = 0;
    struct cbuf *b;
    int act = 0;

    for (act = 0; act < act_vec_len; act++) {
        elem = act_vectors[act];
        if (elem) 
            tot_len += C_ALIGN_8B_LEN(sizeof(struct ofp_bucket) + 
                                  elem->action_len); 
    }
    
    tot_len += sizeof(struct ofp_group_mod);
    
    if(version == OFP_VERSION_131) {
        b = of131_prep_msg(tot_len, OFPT131_GROUP_MOD, 0);
    }
    else {
        b = of140_prep_msg(tot_len, OFPT140_GROUP_MOD, 0);
    }
    ofp_gm = CBUF_DATA(b);
    ofp_gm->command = htons(modify ? OFPGC_MODIFY : OFPGC_ADD);
    ofp_gm->type = type;
    ofp_gm->group_id = htonl(group);

    ofp_b = ASSIGN_PTR(ofp_gm->buckets);

    for (act = 0; act < act_vec_len; act++) {
        elem = act_vectors[act];
        if (elem) {
            ofp_b = INC_PTR8(ofp_b, bkt_len); 
            bkt_len = C_ALIGN_8B_LEN(sizeof(struct ofp_bucket) +
                                 elem->action_len);

            ofp_b->len = htons(bkt_len);
            ofp_b->watch_port = htonl(OFPP131_ANY);
            ofp_b->watch_group = htonl(OFPG_ANY);

            if (type == OFPGT_SELECT)
                ofp_b->weight = htons(elem->weight);
            else if (type == OFPGT_FF) {
                if (elem->ff_port)
                    ofp_b->watch_port = htonl(elem->ff_port);
                ofp_b->watch_group = htonl(elem->ff_group);
            }
            memcpy(ofp_b->actions, elem->actions, elem->action_len);
        }
    }
            
    return b;
}

struct cbuf * 
of131_prep_group_add_msg(uint32_t group, uint8_t type, 
                         struct of_act_vec_elem *act_vectors[],
                         size_t act_vec_len, bool modify)
{
    struct cbuf *b;
     b = of13_14_prep_group_add_msg(group, type, act_vectors, act_vec_len,
             modify, OFP_VERSION_131);
     return b;
}

struct cbuf * 
of140_prep_group_add_msg(uint32_t group, uint8_t type, 
                         struct of_act_vec_elem *act_vectors[],
                         size_t act_vec_len, bool modify)
{
    struct cbuf *b;
     b = of13_14_prep_group_add_msg(group, type, act_vectors, act_vec_len,
             modify, OFP_VERSION_140);
     return b;
}

static struct cbuf * 
of13_14_prep_group_del_msg(uint32_t group, uint8_t version) 
{
    size_t tot_len = 0;
    struct ofp_group_mod *ofp_gm;
    struct cbuf *b;

    tot_len = sizeof(struct ofp_group_mod);
    if(version == OFP_VERSION_131) {
        b = of131_prep_msg(tot_len, OFPT131_GROUP_MOD, 0);
    }
    else {
        b = of140_prep_msg(tot_len, OFPT140_GROUP_MOD, 0);
    }
    ofp_gm = CBUF_DATA(b);
    ofp_gm->command = htons(OFPGC_DELETE);
    ofp_gm->group_id = htonl(group);

    return b;
}

struct cbuf * 
of131_prep_group_del_msg(uint32_t group) 
{
    struct cbuf *b;
    b = of13_14_prep_group_del_msg(group, OFP_VERSION_131);
    return b;
}

struct cbuf * 
of140_prep_group_del_msg(uint32_t group) 
{
    struct cbuf *b;
    b = of13_14_prep_group_del_msg(group, OFP_VERSION_140);
    return b;
}

static struct cbuf *
of13_14_prep_meter_add_msg(uint32_t meter, uint16_t flags, 
                         struct of_meter_band_elem *band_vectors[],
                         size_t nbands, bool modify, uint8_t version)
{
    size_t tot_len = 0;
    struct of_meter_band_elem *elem;
    struct ofp_meter_mod *ofp_mm;
    struct ofp_meter_band_header *ofp_band;
    size_t bkt_len = 0;
    struct cbuf *b;
    int met = 0;

    for (met = 0; met < nbands; met++) {
        elem = band_vectors[met];
        if (elem) 
            tot_len += elem->band_len; 
    }

    tot_len += sizeof(struct ofp_meter_mod);

    if (version == OFP_VERSION_131) {
        b = of131_prep_msg(tot_len, OFPT131_METER_MOD, 0);
    }
    else {
        b = of140_prep_msg(tot_len, OFPT140_METER_MOD, 0);
    }
    ofp_mm = CBUF_DATA(b);
    ofp_mm->command = htons(modify ? OFPMC_MODIFY: OFPMC_ADD);
    ofp_mm->flags = htons(flags);
    ofp_mm->meter_id = htonl(meter);

    ofp_band = ASSIGN_PTR(ofp_mm->bands);

    for (met = 0; met < nbands; met++) {
        elem = band_vectors[met];
        if (elem) {
            ofp_band = INC_PTR8(ofp_band, bkt_len); 
            bkt_len = elem->band_len; 
            memcpy(ofp_band, elem->band, elem->band_len);
        }
    }
            
    return b;
}

struct cbuf *
of131_prep_meter_add_msg(uint32_t meter, uint16_t flags, 
                         struct of_meter_band_elem *band_vectors[],
                         size_t nbands, bool modify)
{
    struct cbuf *b;
    b = of13_14_prep_meter_add_msg(meter, flags, band_vectors, nbands,
            modify, OFP_VERSION_131);
    return b;
}

struct cbuf *
of140_prep_meter_add_msg(uint32_t meter, uint16_t flags, 
                         struct of_meter_band_elem *band_vectors[],
                         size_t nbands, bool modify)
{
    struct cbuf *b;
    b = of13_14_prep_meter_add_msg(meter, flags, band_vectors, nbands,
            modify, OFP_VERSION_140);
    return b;
}

static struct cbuf * 
of13_14_prep_meter_del_msg(uint32_t meter, uint8_t version) 
{
    size_t tot_len = 0;
    struct ofp_meter_mod *ofp_mm;
    struct cbuf *b;

    tot_len = sizeof(struct ofp_meter_mod);
    
    if (version == OFP_VERSION_131) {
        b = of131_prep_msg(tot_len, OFPT131_METER_MOD, 0);
    }
    else {
        b = of140_prep_msg(tot_len, OFPT140_METER_MOD, 0);
    }
    ofp_mm = CBUF_DATA(b);
    ofp_mm->command = htons(OFPMC_DELETE);
    ofp_mm->meter_id = meter ? htonl(meter): htonl(OFPM_ALL); 

    return b;
}

struct cbuf * 
of131_prep_meter_del_msg(uint32_t meter) 
{
    struct cbuf *b;
    b = of13_14_prep_meter_del_msg(meter, OFP_VERSION_131);
    return b;
}

struct cbuf * 
of140_prep_meter_del_msg(uint32_t meter) 
{
    struct cbuf *b;
    b = of13_14_prep_meter_del_msg(meter, OFP_VERSION_140);
    return b;
}

struct cbuf *
of131_prep_port_mod_msg(uint32_t port_no, 
        struct of_port_mod_params *pm_params, 
        uint8_t *hw_addr)
{
    size_t tot_len = 0;
    struct ofp131_port_mod *ofp_pm;
    struct cbuf *b;

    tot_len = sizeof(struct ofp131_port_mod);

    b = of131_prep_msg(tot_len, OFPT131_PORT_MOD, 0);
    ofp_pm = CBUF_DATA(b);
    ofp_pm->port_no = htonl(port_no);
    ofp_pm->config = htonl(pm_params->config);
    ofp_pm->mask = htonl(pm_params->mask);
    memcpy(ofp_pm->hw_addr, hw_addr, OFP_ETH_ALEN);
            
    return b;
}

struct cbuf *
of140_prep_port_mod_msg(uint32_t port_no, 
        struct of_port_mod_params *pm_params, 
        uint8_t *hw_addr)
{
    size_t tot_len = 0;
    struct ofp140_port_mod *ofp_pm;
    struct ofp_port_mod_prop_ethernet *eth_prop;
    struct ofp_port_mod_prop_optical *opt_prop;
    struct cbuf *b;

    if (pm_params->type == OFPPMPT_ETHERNET) {
        tot_len = sizeof(struct ofp140_port_mod) 
            + sizeof(struct ofp_port_mod_prop_ethernet);
    }
    else {
        tot_len = sizeof(struct ofp140_port_mod) 
            + sizeof(struct ofp_port_mod_prop_optical);
    }

    b = of140_prep_msg(tot_len, OFPT140_PORT_MOD, 0);
    ofp_pm = CBUF_DATA(b);
    ofp_pm->port_no = htonl(port_no);
    ofp_pm->config = htonl(pm_params->config);
    ofp_pm->mask = htonl(pm_params->mask);
    memcpy(ofp_pm->hw_addr, hw_addr, OFP_ETH_ALEN);

    if (pm_params->type == OFPPMPT_ETHERNET) {
        eth_prop = (struct ofp_port_mod_prop_ethernet *)ofp_pm->properties;
        eth_prop->type = htons(OFPPMPT_ETHERNET);
        eth_prop->length = htons(sizeof(struct ofp_port_mod_prop_ethernet));
        eth_prop->advertise = htonl(pm_params->properties.advertise);
    }
    else {
        opt_prop = (struct ofp_port_mod_prop_optical* )ofp_pm->properties;
        opt_prop->type = htons(OFPPMPT_OPTICAL);
        opt_prop->length = htons(sizeof(struct ofp_port_mod_prop_optical));
        opt_prop->configure = htonl(pm_params->properties.configure);
        opt_prop->freq_lmda= htonl(pm_params->properties.freq_lmda);
        opt_prop->fl_offset = htonl(pm_params->properties.fl_offset);
        opt_prop->grid_span = htonl(pm_params->properties.grid_span);
        opt_prop->tx_pwr = htonl(pm_params->properties.tx_pwr);
    }
    return b;
}

struct cbuf * 
of131_prep_async_config(const struct of_async_config_params *ac_params) 
{
    size_t tot_len = 0;
    struct ofp_async_config *ofp_ac;
    struct cbuf *b;

    tot_len = sizeof(struct ofp_async_config);
    b = of131_prep_msg(tot_len, OFPT131_SET_ASYNC, 0);
    ofp_ac = CBUF_DATA(b);
    memcpy(ofp_ac->packet_in_mask, ac_params->packet_in_mask, 
           sizeof(ofp_ac->packet_in_mask));
    memcpy(ofp_ac->port_status_mask, ac_params->port_status_mask,
           sizeof(ofp_ac->port_status_mask));
    memcpy(ofp_ac->flow_removed_mask, ac_params->flow_removed_mask,
           sizeof(ofp_ac->flow_removed_mask));
    return b;
}

int
of131_set_inst_action_type(mul_act_mdata_t *mdata, uint16_t type)
{
    /* only applicable for OFPIT_WRITE_ACTIONS or OFPIT_APPLY_ACTIONS */
    assert(type == OFPIT_WRITE_ACTIONS  ||
           type ==  OFPIT_APPLY_ACTIONS); 

    if ((type == OFPIT_WRITE_ACTIONS &&
        mdata->act_inst_wr_ptr != NULL) ||
        (type == OFPIT_APPLY_ACTIONS &&
         mdata->act_inst_app_ptr != NULL)) {
        return -1;
    }

    mdata->act_inst_type = type;
    return 0;
}
 
size_t 
of131_make_inst_actions(mul_act_mdata_t *mdata, uint16_t type)
{
    struct ofp_instruction_actions *ofp_ia;

    if (mdata->only_acts) return 0;

    if ((type == OFPIT_WRITE_ACTIONS && 
        mdata->act_inst_wr_ptr != NULL) ||
        (type == OFPIT_APPLY_ACTIONS && 
         mdata->act_inst_app_ptr != NULL)) {
        return 0;
    }

    of_check_realloc_act(mdata, sizeof(*ofp_ia));

    ofp_ia = (void *)(mdata->act_wr_ptr);
    ofp_ia->type = htons(type);
    ofp_ia->len = htons(sizeof(*ofp_ia));


    if (type == OFPIT_WRITE_ACTIONS) {
        mdata->act_inst_wr_ptr = mdata->act_wr_ptr;
    } else if (type == OFPIT_APPLY_ACTIONS) {
        mdata->act_inst_app_ptr = mdata->act_wr_ptr;
    } else {
        NOT_REACHED();
    }
 
    mdata->act_wr_ptr += sizeof(*ofp_ia);

    return (sizeof(*ofp_ia)); 
}

static inline size_t 
__of131_make_inst_actions(mul_act_mdata_t *mdata)
{
    if (mdata->act_inst_type != OFPIT_WRITE_ACTIONS && 
        mdata->act_inst_type !=  OFPIT_APPLY_ACTIONS) {
        mdata->act_inst_type = OFPIT_APPLY_ACTIONS; //Default
    }

    return of131_make_inst_actions(mdata, mdata->act_inst_type);
}

void
of131_fini_inst_actions(mul_act_mdata_t *mdata)
{
    struct ofp_instruction_actions *ofp_ia;
    void *inst_ptr = NULL;

    if (mdata->only_acts) return;

    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        inst_ptr = mdata->act_inst_wr_ptr;
    } else if (mdata->act_inst_type == OFPIT_APPLY_ACTIONS) {
        inst_ptr = mdata->act_inst_app_ptr;
    }

    if  (!inst_ptr) return;
    
    ofp_ia = ASSIGN_PTR(inst_ptr);
    ofp_ia->len = htons(of_mact_inst_act_len(mdata));
    return;
}

size_t 
of131_make_inst_goto(mul_act_mdata_t *mdata, uint8_t table_id)
{
    struct ofp_instruction_goto_table *ofp_ig;

    if (mdata->inst_bm & (1 << OFPIT_GOTO_TABLE)) {
        c_log_err("|OF13| Cant add > 1 goto inst");
        return 0;
    }
    mdata->inst_bm |= (1 << OFPIT_GOTO_TABLE);

    of_check_realloc_act(mdata, sizeof(*ofp_ig));

    ofp_ig = (void *)(mdata->act_wr_ptr);
    ofp_ig->type = htons(OFPIT_GOTO_TABLE);
    ofp_ig->len = htons(sizeof(*ofp_ig));

    ofp_ig->table_id = table_id;

    mdata->act_wr_ptr += sizeof(*ofp_ig);
    return (sizeof(*ofp_ig)); 
}

size_t 
of131_make_inst_meter(mul_act_mdata_t *mdata, uint32_t meter)
{
    struct ofp_instruction_meter *ofp_im;

    if (mdata->inst_bm & (1 << OFPIT_METER)) {
        c_log_err("|OF13| Cant add > 1 meter inst");
        return 0;
    }
    mdata->inst_bm |= (1 << OFPIT_METER);

    of_check_realloc_act(mdata, sizeof(*ofp_im));

    ofp_im = (void *)(mdata->act_wr_ptr);
    ofp_im->type = htons(OFPIT_METER);
    ofp_im->len = htons(sizeof(*ofp_im));

    ofp_im->meter_id = htonl(meter);

    mdata->act_wr_ptr += sizeof(*ofp_im);
    return (sizeof(*ofp_im)); 
}

size_t 
of131_make_inst_clear_act(mul_act_mdata_t *mdata)
{
    struct ofp_instruction_actions *ofp_ica;

    if (mdata->inst_bm & (1 << OFPIT_CLEAR_ACTIONS)) {
        c_log_err("|OF13| Cant add > 1 clear act-inst");
        return 0;
    }
    mdata->inst_bm |= (1 << OFPIT_CLEAR_ACTIONS);

    of_check_realloc_act(mdata, sizeof(*ofp_ica));

    ofp_ica = (void *)(mdata->act_wr_ptr);
    ofp_ica->type = htons(OFPIT_CLEAR_ACTIONS);
    ofp_ica->len = htons(sizeof(*ofp_ica));

    mdata->act_wr_ptr += sizeof(*ofp_ica);
    return (sizeof(*ofp_ica)); 
}

size_t
of131_make_action_output(mul_act_mdata_t *mdata, uint32_t oport)
{
    struct ofp131_action_output *op_act;

    __of131_make_inst_actions(mdata);

    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm & (1 << OFPAT131_OUTPUT)) { 
            c_log_err("|OF13| Cant add > 1 act output");
            return 0;
        }
        mdata->act_bm |= (1 << OFPAT131_OUTPUT);
    }

    of_check_realloc_act(mdata, sizeof(*op_act));
    oport = oport ? : OFPP131_CONTROLLER;

    op_act = (void *)(mdata->act_wr_ptr);
    op_act->type = htons(OFPAT131_OUTPUT);
    op_act->len  = htons(sizeof(*op_act));
    op_act->port = htonl(oport);

    op_act->max_len = (oport == OFPP131_CONTROLLER) ? 
                            htons(OFPCML_NO_BUFFER) : htons(OF_MAX_MISS_SEND_LEN);
    mdata->act_wr_ptr += sizeof(*op_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*op_act));
}

size_t
of131_make_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_VLAN_VID_SZ); 

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_VLAN_VID)) {
            c_log_err("|OF13| Cant add > 1 setf vlan-vid");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_VLAN_VID);
    }

    of_check_realloc_act(mdata, len);
    
    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_VLAN_VID); //OFPVID_PRESENT ??
    oxm->length = OFPXMT_OFB_VLAN_VID_SZ;
    HTON_OXM_HDR(oxm);  
    *(uint16_t *)(oxm->data) = htons(vid & 0xfff);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_mpls_label(mul_act_mdata_t *mdata, uint32_t label)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_MPLS_LABEL_SZ); 

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_MPLS_LABEL)) {
            c_log_err("|OF13| Cant add > 1 setf mpls-label");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_MPLS_LABEL);
    }

    of_check_realloc_act(mdata, len);
    
    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_LABEL);
    oxm->length = OFPXMT_OFB_MPLS_LABEL_SZ;
    HTON_OXM_HDR(oxm);
    of_put_mpls_label_oxm(oxm->data, htonl(label), oxm->length);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_mpls_tc(mul_act_mdata_t *mdata, uint8_t tc)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_MPLS_TC_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_MPLS_TC)) {
            c_log_err("|OF13| Cant add > 1 setf mpls-tc");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_MPLS_TC);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_TC);
    oxm->length = OFPXMT_OFB_MPLS_TC_SZ;
    HTON_OXM_HDR(oxm);
    *(uint8_t *)oxm->data = tc;

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_mpls_bos(mul_act_mdata_t *mdata, uint8_t bos)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_MPLS_BOS_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_MPLS_BOS)) {
            c_log_err("|OF13| Cant add > 1 setf mpls-bos");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_MPLS_BOS);
    }
    
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_MPLS_BOS);
    oxm->length = OFPXMT_OFB_MPLS_BOS_SZ;
    HTON_OXM_HDR(oxm);
    *(uint8_t *)oxm->data = bos ? 1 : 0;

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_push(mul_act_mdata_t *mdata, uint16_t eth_type)
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

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << ptype)) {
            c_log_err("|OF13| Cant add > 1 push-%d", ptype);
            return 0;
        }
        mdata->act_bm |= 1 << ptype;
    }
    of_check_realloc_act(mdata, sizeof(*pv_act));

    pv_act = (void *)(mdata->act_wr_ptr);
    pv_act->type = htons(ptype);
    pv_act->len  = htons(sizeof(*pv_act));
    pv_act->ethertype = htons(eth_type);

    mdata->act_wr_ptr += sizeof(*pv_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*pv_act));
}

size_t
of131_make_action_strip_mpls(mul_act_mdata_t *mdata, uint16_t eth_type)
{
    struct ofp_action_pop_mpls *p_act;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_POP_MPLS)) {
            c_log_err("|OF13| Cant add > 1 pop-mpls");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_POP_MPLS;
    }
    of_check_realloc_act(mdata, sizeof(*p_act));

    p_act = (void *)(mdata->act_wr_ptr);
    p_act->type = htons(OFPAT131_POP_MPLS);
    p_act->len  = htons(sizeof(*p_act));
    p_act->ethertype = htons(eth_type);

    mdata->act_wr_ptr += sizeof(*p_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*p_act));
}

size_t
of131_make_action_set_mpls_ttl(mul_act_mdata_t *mdata, uint8_t ttl)
{
    struct ofp_action_mpls_ttl *m_ttl;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_MPLS_TTL)) {
            c_log_err("|OF13| Cant add > 1 set mpls-ttl act");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_MPLS_TTL;
    }
    of_check_realloc_act(mdata, sizeof(*m_ttl));

    m_ttl = (void *)(mdata->act_wr_ptr);
    m_ttl->type = htons(OFPAT131_MPLS_TTL);
    m_ttl->len  = htons(sizeof(*m_ttl));
    m_ttl->mpls_ttl = ttl;

    mdata->act_wr_ptr += sizeof(*m_ttl);
    of131_fini_inst_actions(mdata);
    return (sizeof(*m_ttl));
}

size_t
of131_make_action_dec_mpls_ttl(mul_act_mdata_t *mdata)
{
    struct ofp_action_header *dec_mpls_ttl;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_DEC_MPLS_TTL)) {
            c_log_err("|OF13| Cant add > 1 set mpls-ttl act");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_DEC_MPLS_TTL;
    }
    of_check_realloc_act(mdata, sizeof(*dec_mpls_ttl));

    dec_mpls_ttl = (void *)(mdata->act_wr_ptr);
    dec_mpls_ttl->type = htons(OFPAT131_DEC_MPLS_TTL);
    dec_mpls_ttl->len  = htons(sizeof(*dec_mpls_ttl));

    mdata->act_wr_ptr += sizeof(*dec_mpls_ttl);
    of131_fini_inst_actions(mdata);
    return (sizeof(*dec_mpls_ttl));
}

size_t
of131_make_action_set_ip_ttl(mul_act_mdata_t *mdata, uint8_t ttl)
{
    struct ofp_action_nw_ttl *m_ttl;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_SET_NW_TTL)) {
            c_log_err("|OF13| Cant add > 1 set nw-ttl act");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_SET_NW_TTL;
    }
    of_check_realloc_act(mdata, sizeof(*m_ttl));

    m_ttl = (void *)(mdata->act_wr_ptr);
    m_ttl->type = htons(OFPAT131_SET_NW_TTL);
    m_ttl->len  = htons(sizeof(*m_ttl));
    m_ttl->nw_ttl = ttl;

    mdata->act_wr_ptr += sizeof(*m_ttl);
    of131_fini_inst_actions(mdata);
    return (sizeof(*m_ttl));
}

size_t
of131_make_action_dec_ip_ttl(mul_act_mdata_t *mdata)
{
    struct ofp_action_header *dec_ip_ttl;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_DEC_NW_TTL)) {
            c_log_err("|OF13| Cant add > 1 dec nw-ttl act");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_DEC_NW_TTL;
    }
    of_check_realloc_act(mdata, sizeof(*dec_ip_ttl));

    dec_ip_ttl = (void *)(mdata->act_wr_ptr);
    dec_ip_ttl->type = htons(OFPAT131_DEC_NW_TTL);
    dec_ip_ttl->len  = htons(sizeof(*dec_ip_ttl));

    mdata->act_wr_ptr += sizeof(*dec_ip_ttl);
    of131_fini_inst_actions(mdata);
    return (sizeof(*dec_ip_ttl));
}

size_t
of131_make_action_cp_ttl(mul_act_mdata_t *mdata, bool in)
{
    struct ofp_action_header *cp_ttl;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << in ? OFPAT131_COPY_TTL_IN:
                                        OFPAT131_COPY_TTL_OUT)) {
            c_log_err("|OF13| Cant add > 1 cp-ttl act");
            return 0;
        }
        mdata->act_bm |= 1 <<  in ? OFPAT131_COPY_TTL_IN:
                                    OFPAT131_COPY_TTL_OUT;
    }
    of_check_realloc_act(mdata, sizeof(*cp_ttl));

    cp_ttl = (void *)(mdata->act_wr_ptr);
    cp_ttl->type = in ? htons(OFPAT131_COPY_TTL_IN) : 
                        htons(OFPAT131_COPY_TTL_OUT);
    cp_ttl->len  = htons(sizeof(*cp_ttl));

    mdata->act_wr_ptr += sizeof(*cp_ttl);
    of131_fini_inst_actions(mdata);
    return (sizeof(*cp_ttl));
}

size_t
of131_make_action_strip_pbb(mul_act_mdata_t *mdata)
{
    struct ofp_action_header *strip_pbb;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_POP_PBB)) {
            c_log_err("|OF13| Cant add > 1 pop pbb act");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_POP_PBB;
    }
    of_check_realloc_act(mdata, sizeof(*strip_pbb));

    strip_pbb = (void *)(mdata->act_wr_ptr);
    strip_pbb->type = htons(OFPAT131_POP_PBB);
    strip_pbb->len  = htons(sizeof(*strip_pbb));

    mdata->act_wr_ptr += sizeof(*strip_pbb);
    of131_fini_inst_actions(mdata);
    return (sizeof(*strip_pbb));
}

size_t
of131_make_action_strip_vlan(mul_act_mdata_t *mdata)
{
    struct ofp_action_header *vid_strip_act;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_POP_VLAN)) {
            c_log_err("|OF13| Cant add > 1 pop vlan act");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_POP_VLAN;
    }

    of_check_realloc_act(mdata, sizeof(*vid_strip_act));

    vid_strip_act = (void *)(mdata->act_wr_ptr);
    vid_strip_act->type = htons(OFPAT131_POP_VLAN);
    vid_strip_act->len  = htons(sizeof(*vid_strip_act));

    mdata->act_wr_ptr += sizeof(*vid_strip_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*vid_strip_act));
}

size_t
of131_make_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_VLAN_PCP_SZ); 

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_VLAN_PCP)) {
            c_log_err("|OF13| Cant add > 1 setf-vlan-pcp");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_VLAN_PCP);
    }

    of_check_realloc_act(mdata, len);
    
    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_VLAN_PCP); //OFPVID_PRESENT ??
    oxm->length = OFPXMT_OFB_VLAN_PCP_SZ;
    HTON_OXM_HDR(oxm);  
    *(uint8_t *)(oxm->data) = vlan_pcp;
    
    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_ETH_SZ); 

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_ETH_DST)) {
            c_log_err("|OF13| Cant add > 1 setf-dmac");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_ETH_DST);
    }
    of_check_realloc_act(mdata, len);
    
    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_DST);
    oxm->length = OFPXMT_OFB_ETH_SZ;
    HTON_OXM_HDR(oxm);
    memcpy((uint8_t *)(oxm->data), dmac, OFP_ETH_ALEN);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_ETH_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_ETH_SRC)) {
            c_log_err("|OF13| Cant add > 1 setf-smac");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_ETH_SRC);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_SRC);
    oxm->length = OFPXMT_OFB_ETH_SZ;
    HTON_OXM_HDR(oxm);
    memcpy((uint8_t *)(oxm->data), smac, OFP_ETH_ALEN);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_eth_type(mul_act_mdata_t *mdata, uint16_t eth_type)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_ETH_TYPE_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_ETH_TYPE)) {
            c_log_err("|OF13| Cant add > 1 setf-eth-type");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_ETH_TYPE);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_TYPE);
    oxm->length = OFPXMT_OFB_ETH_TYPE_SZ;
    HTON_OXM_HDR(oxm);
    *(uint16_t *)(oxm->data) = htons(eth_type);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_ipv4_src(mul_act_mdata_t *mdata, uint32_t nw_saddr)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_IPV4_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IPV4_SRC)) {
            c_log_err("|OF13| Cant add > 1 setf-ipv4-src");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IPV4_SRC);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV4_SRC);
    oxm->length = OFPXMT_OFB_IPV4_SZ;
    HTON_OXM_HDR(oxm);
    *(uint32_t *)(oxm->data) = htonl(nw_saddr);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_ipv4_dst(mul_act_mdata_t *mdata, uint32_t nw_daddr)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_IPV4_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IPV4_DST)) {
            c_log_err("|OF13| Cant add > 1 setf-ipv4-dst");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IPV4_DST);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV4_DST);
    oxm->length = OFPXMT_OFB_IPV4_SZ;
    HTON_OXM_HDR(oxm);
    *(uint32_t *)(oxm->data) = htonl(nw_daddr);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_ipv6_src(mul_act_mdata_t *mdata, uint8_t *nw_saddr)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_IPV6_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IPV6_SRC)) {
            c_log_err("|OF13| Cant add > 1 setf-ipv6-src");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IPV6_SRC);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV6_SRC);
    oxm->length = OFPXMT_OFB_IPV6_SZ;
    HTON_OXM_HDR(oxm);
    
    memcpy((uint8_t *)(oxm->data), nw_saddr, OFPXMT_OFB_IPV6_SZ);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_ipv6_dst(mul_act_mdata_t *mdata, uint8_t *nw_daddr)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_IPV6_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IPV6_DST)) {
            c_log_err("|OF13| Cant add > 1 setf-ipv6-dst");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IPV6_DST);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV6_DST);
    oxm->length = OFPXMT_OFB_IPV6_SZ;
    HTON_OXM_HDR(oxm);
    
    memcpy((uint8_t *)(oxm->data), nw_daddr, OFPXMT_OFB_IPV6_SZ);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_IP_DSCP_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IP_DSCP)) {
            c_log_err("|OF13| Cant add > 1 setf-ipv4-dscp");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_IP_DSCP);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IP_DSCP);
    oxm->length = OFPXMT_OFB_IP_DSCP_SZ;
    HTON_OXM_HDR(oxm);
    *(uint8_t *)(oxm->data) = tos & ((0x1<<7) - 1);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

static size_t
of131_make_action_set_tp_port(mul_act_mdata_t *mdata, uint8_t ip_proto, 
                              bool is_src, uint16_t port)
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
        return 0;
    }

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, port_type)) {
            c_log_err("|OF13| Cant add > 1 setf-tp-port|%d|",
                      port_type);
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, port_type);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, port_type);
    oxm->length = OFPXMT_OFB_L4_PORT_SZ;
    HTON_OXM_HDR(oxm);
    *(uint16_t *)(oxm->data) = htons(port);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of131_make_action_set_tp_port(mdata, IP_TYPE_UDP, true, port);
}

size_t
of131_make_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of131_make_action_set_tp_port(mdata, IP_TYPE_UDP, false, port);
}

size_t
of131_make_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of131_make_action_set_tp_port(mdata, IP_TYPE_TCP, true, port);
}

size_t
of131_make_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of131_make_action_set_tp_port(mdata, IP_TYPE_TCP, false, port);
}

size_t
of131_make_action_group(mul_act_mdata_t *mdata, uint32_t group)
{
    struct ofp_action_group *grp_act;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_GROUP)) {
            c_log_err("|OF13| Cant add > 1 group-act");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_GROUP;
    }
    of_check_realloc_act(mdata, sizeof(*grp_act));

    grp_act = (void *)(mdata->act_wr_ptr);
    grp_act->type = htons(OFPAT131_GROUP);
    grp_act->group_id = htonl(group);
    grp_act->len  = htons(sizeof(*grp_act));

    mdata->act_wr_ptr += sizeof(*grp_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*grp_act));
}

size_t
of131_make_action_set_queue(mul_act_mdata_t *mdata, uint32_t queue)
{
    struct ofp131_action_set_queue *q_act;

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (mdata->act_bm &  (1 << OFPAT131_SET_QUEUE)) {
            c_log_err("|OF13| Cant add > 1 set-q act");
            return 0;
        }
        mdata->act_bm |= 1 << OFPAT131_SET_QUEUE;
    }
    of_check_realloc_act(mdata, sizeof(*q_act));

    q_act = (void *)(mdata->act_wr_ptr);
    q_act->type = htons(OFPAT131_SET_QUEUE);
    q_act->queue_id = htonl(queue);
    q_act->len  = htons(sizeof(*q_act));

    mdata->act_wr_ptr += sizeof(*q_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*q_act));
}

size_t
of131_make_action_set_tunnel_id(mul_act_mdata_t *mdata, uint64_t tunnel_id)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_TUNNEL_ID_SZ);

    __of131_make_inst_actions(mdata);
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        if (GET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_TUNNEL_ID)) {
            c_log_err("|OF13| Cant add > 1 setf-tunnel");
            return 0;
        }
        SET_BIT_IN_32MASK(mdata->setf_bm, OFPXMT_OFB_TUNNEL_ID);
    }
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_TUNNEL_ID);
    oxm->length = OFPXMT_OFB_TUNNEL_ID_SZ;
    HTON_OXM_HDR(oxm);
    *(uint64_t *)(oxm->data) = htonll(tunnel_id);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

static void
of131_make_meter_band_common(void *band_ptr, uint16_t type, 
                             struct of_meter_band_parms *bparms)
{
    struct ofp_meter_band_header *bhdr = band_ptr;
    
    bhdr->type = htons(type);
    bhdr->rate = htonl(bparms->rate); 
    bhdr->burst_size = htonl(bparms->burst_size); 
}

size_t
of131_make_meter_band_drop(mul_act_mdata_t *mdata,
                           struct of_meter_band_parms *bparms)
{
    struct ofp_meter_band_drop *mb_drp;

    of_check_realloc_act(mdata, sizeof(*mb_drp));

    mb_drp = (void *)(mdata->act_wr_ptr);
    of131_make_meter_band_common(mb_drp, OFPMBT_DROP, bparms);

    mdata->act_wr_ptr += sizeof(*mb_drp);
    /*of131_fini_inst_actions(mdata); */
    return (sizeof(*mb_drp));
}

size_t
of131_make_meter_band_mark_dscp(mul_act_mdata_t *mdata,
                                struct of_meter_band_parms *bparms)
{
    struct ofp_meter_band_dscp_remark *mb_dm;

    of_check_realloc_act(mdata, sizeof(*mb_dm));

    mb_dm = (void *)(mdata->act_wr_ptr);
    of131_make_meter_band_common(mb_dm, OFPMBT_DSCP_REMARK,
                                 bparms);
    mb_dm->prec_level = bparms->prec_level;

    mdata->act_wr_ptr += sizeof(*mb_dm);
    /*of131_fini_inst_actions(mdata); */
    return (sizeof(*mb_dm));
}

static int
of131_dump_act_output(struct ofp_action_header *action, void *arg)
{
    struct ofp131_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-port(%u):max-len(0x%x),",
                        "act-out", ntohl(of_ao->port),
                        ntohs(of_ao->max_len));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
of131_dump_cmd_act_output(struct ofp_action_header *action, void *arg)
{
    struct ofp131_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add output ");
    assert(dp->len < OF_DUMP_INST_SZ-1);

    if (of_ao->port) {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%lu\r\n", U322UL(ntohl(of_ao->port)));
    } else {
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                            "controller\r\n");
    }
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
of131_check_act_output(struct ofp_action_header *action, void *arg)
{
    struct ofp131_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_inst_check_args *u_arg =  dp->u_arg;
    
    if (!of_ao->port ||
        (u_arg && u_arg->check_port &&
         !u_arg->check_port(u_arg->sw_ctx, ntohl(of_ao->port)))) {
        c_log_err("%s: output port invalid", FN); 
        dp->res = -1;
        return 0;
    }

    return ntohs(action->len);
}

static bool 
of131_check_inst_supported(struct ofp_inst_parser_arg *dp,
                           uint16_t type)
{
    struct ofp_inst_check_args *u_arg = dp->u_arg;
    of_flow_tbl_props_t *prop = NULL;
    uint32_t inst_supp_bmask = 0;

    if (u_arg && (prop = u_arg->tbl_prop)) {
        inst_supp_bmask = prop->bm_inst; 

        if (!(inst_supp_bmask & (1 << type))) {
            c_log_err("%s: Not supported instruction %x", FN, type);
            return false;
        }
    }

    return true;
} 

static bool 
of131_check_action_supported(struct ofp_inst_parser_arg *dp,
                             uint16_t action)
{
    struct ofp_inst_check_args *u_arg = dp->u_arg;
    of_flow_tbl_props_t *prop = NULL;
    struct ofp_group_features *gprop = NULL;
    uint32_t act_supp_bmask = 0;

    if (action > OFPAT131_POP_PBB) {
        return false;
    }

    if (!u_arg) return true;

    if (u_arg->group_act_check) {
        if ((gprop = u_arg->grp_prop)) {
            act_supp_bmask = ntohl(gprop->actions[0]); // FIXME
            if (!(act_supp_bmask & (1 << action))) {
                c_log_err("%s: Not supported act %x", FN, action);
                return false;
            }
        }
    } else {
        if ((prop = u_arg->tbl_prop)) {
            act_supp_bmask = dp->act_set ?
                            prop->bm_wr_actions :
                            prop->bm_app_actions;

            if (!(act_supp_bmask & (1 << action))) {
                c_log_err("%s: Not supported action %x", FN, action);
                return false;
            }
        }
    }

    return true;
} 

static bool 
of131_check_setfield_supported(struct ofp_inst_parser_arg *dp,
                               uint8_t oxm_field)
{
    struct ofp_inst_check_args *u_arg = dp->u_arg;
    of_flow_tbl_props_t *prop = NULL;
    uint32_t *setf_supp_bmask = 0;

    if (u_arg && u_arg->check_setf_supp &&
        (prop = u_arg->tbl_prop)) {
        setf_supp_bmask = dp->act_set ?
                            prop->bm_wr_set_field:
                            prop->bm_app_set_field;

        if (!(GET_BIT_IN_32MASK(setf_supp_bmask, oxm_field))) {
            c_log_err("%s: Not supported set-field %x", FN, oxm_field);
            return false;
        }
    }

    return true;
} 

static int
of131_dump_push_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_push *ofp_ap = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    char *push_str;

    switch(ntohs(ofp_ap->type)) {
    case OFPAT131_PUSH_VLAN:
        push_str = "push-vlan";
        break;
    case OFPAT131_PUSH_MPLS:
        push_str = "push-mpls";
        break;
    case OFPAT131_PUSH_PBB:
        push_str = "push-pbb";
        break;
    default:
        return -1;
    }

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s:eth-type(0x%x),",
                        push_str, ntohs(ofp_ap->ethertype));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
of131_dump_cmd_push_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_push *ofp_ap = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    char *push_str;

    switch(ntohs(ofp_ap->type)) {
    case OFPAT131_PUSH_VLAN:
        if (ntohs(ofp_ap->ethertype) == ETH_TYPE_VLAN) {
            push_str = "push-vlan-header";
        } else if (ntohs(ofp_ap->ethertype) == ETH_TYPE_SVLAN) {
            push_str = "push-svlan-header";
        } else {
            return -1;
        }
        break;
    case OFPAT131_PUSH_MPLS:
        push_str = "push-mpls-header";
        break;
    case OFPAT131_PUSH_PBB:
        push_str = "push-pbb-header";
        break;
    default:
        return -1;
    }

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add %s\r\n", push_str);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}


static int
of131_check_push_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_push *ofp_ap = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    switch(ntohs(ofp_ap->type)) {
    case OFPAT131_PUSH_VLAN:
        dp->push_vlan++;
        break;
    case OFPAT131_PUSH_MPLS:
        dp->push_mpls++;
        break;
    case OFPAT131_PUSH_PBB:
        dp->push_pbb++;
        break;
    default:
        dp->res = -1;
        return 0;
    }

    if (!of131_check_action_supported(dp, ntohs(ofp_ap->type))) {
        dp->res = -1;
        return 0;
    }

    return ntohs(action->len);
}

static int
of131_dump_pop_vlan_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "pop-vlan,");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_pop_vlan_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add strip-vlan\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_pop_vlan_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_POP_VLAN)) {
        dp->res = -1;
        return 0;
    }

    dp->push_vlan--;

    return ntohs(action->len);
}

static int
of131_dump_pop_pbb_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "pop-pbb,");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_pop_pbb_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add strip-pbb-header\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_pop_pbb_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_POP_PBB)) {
        dp->res = -1;
        return 0;
    }
    dp->push_pbb--;

    return ntohs(action->len);
}

static int
of131_dump_pop_mpls_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_pop_mpls *ofp_pm = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "pop-mpls:next_eth_type(0x%x),",
                        ntohs(ofp_pm->ethertype));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_pop_mpls_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_pop_mpls *ofp_pm = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add strip-mpls-heade %d\r\n",
                        ntohs(ofp_pm->ethertype));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_pop_mpls_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_POP_MPLS)) {
        dp->res = -1;
        return 0;
    }

    if (dp->push_mpls <=0 ) {
        c_log_err("%s: no mpls header to pop", FN);
        dp->res = -1;
        return 0;
    }
    dp->push_mpls--;
    return ntohs(action->len);
}

static int
of131_dump_dec_mpls_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "dec-mpls-ttl,");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_dec_mpls_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add dec-mpls-ttl\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_dec_mpls_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_DEC_MPLS_TTL)) {
        dp->res = -1;
        return 0;
    }

    if (dp->push_mpls <=0 ) {
        c_log_err("%s: no mpls header to dec-ttl", FN);
        dp->res = -1;
        return 0;
    }
    return ntohs(action->len);
}

static int
of131_dump_set_mpls_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_mpls_ttl *ofp_smt = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-mpls-ttl:0x%x,", ofp_smt->mpls_ttl);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_set_mpls_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_mpls_ttl *ofp_smt = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-mpls-ttl %d", ofp_smt->mpls_ttl);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_set_mpls_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_MPLS_TTL)) {
        dp->res = -1;
        return 0;
    }

    if (dp->push_mpls <=0 ) {
        c_log_err("%s: no mpls header to set-mpls-ttl", FN);
        dp->res = -1;
        return 0;
    }

    return ntohs(action->len);
}

static int
of131_dump_dec_nw_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "dec-nw-ttl,");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_dec_nw_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add dec-nw-ttl\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_dec_nw_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_DEC_NW_TTL)) {
        dp->res = -1;
        return 0;
    }

    return ntohs(action->len);
}

static int
of131_dump_set_nw_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_nw_ttl *ofp_snt = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-nw-ttl:0x%x,", ofp_snt->nw_ttl);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_set_nw_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_action_nw_ttl *ofp_snt = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-nw-ttl %d\r\n", ofp_snt->nw_ttl);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_set_nw_ttl(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_SET_NW_TTL)) {
        dp->res = -1;
        return 0;
    }

    return ntohs(action->len);
}

static int
of131_dump_cp_ttl_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "cp-ttl-out, ");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_cp_ttl_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add cp-ttl-out\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_cp_ttl_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_COPY_TTL_OUT)) {
        dp->res = -1;
        return 0;
    }

    return ntohs(action->len);
}

static int
of131_dump_cp_ttl_in(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "cp-ttl-in, ");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_cp_ttl_in(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add cp-ttl-in\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_cp_ttl_in(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (!of131_check_action_supported(dp, OFPAT131_COPY_TTL_IN)) {
        dp->res = -1;
        return 0;
    }

    return ntohs(action->len);
}

static int
of131_dump_set_queue(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp131_action_set_queue *ofp_sq = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-queue:0x%x, ", ntohl(ofp_sq->queue_id));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_cmd_set_queue(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp131_action_set_queue *ofp_sq = (void *)(action);

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-queue %lu\r\n",
                        U322UL(ntohl(ofp_sq->queue_id)));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_check_set_queue(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    //struct ofp131_action_set_queue *ofp_sq = (void *)(action);
    // FIXME : Queue-id validation

    if (!of131_check_action_supported(dp, OFPAT131_SET_QUEUE)) {
        dp->res = -1;
        return 0;
    }

    return ntohs(action->len);
}

static int
of131_dump_group_act(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_group *grp_act = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s:group-id(%lu),",
                        "act-group", U322UL(ntohl(grp_act->group_id))); 
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
of131_dump_cmd_group_act(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_group *grp_act = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add group-id %lu\r\n",
                        U322UL(ntohl(grp_act->group_id))); 
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
of131_check_group_act(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_group *grp_act = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_inst_check_args *u_arg = dp->u_arg;

    if (!of131_check_action_supported(dp, OFPAT131_GROUP) ||
        (u_arg && u_arg->check_add_group &&
         !u_arg->check_add_group(u_arg->sw_ctx, ntohl(grp_act->group_id),
                                 u_arg))) {
        dp->res = -1;
        return 0;
    }
    
    return ntohs(action->len);
}

static int
of131_check_set_field_in_port(struct ofp_oxm_header *oxm UNUSED, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->res = -1;
    return 0;
}

static int
of131_dump_set_field_dl_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *mac = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%02x:%02x:%02x:%02x:%02x:%02x,",
                        "set-dmac", mac[0], mac[1], mac[2], mac[3],
                        mac[4], mac[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_dl_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *mac = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                   "action-add set-dmac %02x:%02x:%02x:%02x:%02x:%02x\r\n",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_dl_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) || 
        !of131_check_setfield_supported(dp, OFPXMT_OFB_ETH_DST)) {
        dp->res = -1;
        return 0;
    }

    return oxm->length;
}

static int
of131_dump_set_field_dl_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *mac = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%02x:%02x:%02x:%02x:%02x:%02x,",
                        "set-smac", mac[0], mac[1], mac[2], mac[3],
                        mac[4], mac[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_dl_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *mac = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-smac 0x%02x:%02x:%02x:%02x:%02x:%02x\r\n",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_dl_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_ETH_SRC)) {
        dp->res = -1;
        return 0;
    }

    return oxm->length;
}

static int
of131_dump_set_field_dl_type(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t dl_type = *(uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-dl-type-0x%x", ntohs(dl_type));
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_dl_type(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t dl_type = *(uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-eth-type %d\r\n", ntohs(dl_type));
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_dl_type(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_ETH_TYPE)) {
        dp->res = -1;
        return 0;
    }

    return oxm->length;
}

static int
of131_dump_set_field_dl_vlan(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t *vid = (uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%x,", "set-vlan", ntohs(*vid));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
of131_dump_cmd_set_field_dl_vlan(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t *vid = (uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-vlan-id %d\r\n", ntohs(*vid));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
of131_check_set_field_dl_vlan(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_VLAN_VID)) {
        dp->res = -1;
        return 0;
    }

    if (dp->push_vlan <= 0) {
        c_log_err("%s: No outer vlan header", FN);
        dp->res = -1;
        return 0;
    }

    return oxm->length;
}

static int
of131_dump_set_field_dl_vlan_pcp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *vlan_pcp = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%x,", "set-vlan-pcp", *vlan_pcp);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
of131_dump_cmd_set_field_dl_vlan_pcp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *vlan_pcp = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-vlan-pcp %d\r\n", *vlan_pcp);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
of131_check_set_field_dl_vlan_pcp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_VLAN_PCP)) {
        dp->res = -1;
        return 0;
    }

    if (dp->push_vlan <= 0) {
        c_log_err("%s: No outer vlan header", FN);
        dp->res = -1;
        return 0;
    }
    return oxm->length;
}

static int
of131_dump_set_field_mpls_label(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t label;

    of_get_mpls_label_oxm(oxm->data, &label, oxm->length);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-mpls-label-0x%x", ntohl(label));
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_mpls_label(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t label;

    of_get_mpls_label_oxm(oxm->data, &label, oxm->length);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-mpls-label %lu\r\n",
                        U322UL(ntohl(label)));
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_mpls_label(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_MPLS_LABEL)) {
        dp->res = -1;
        return 0;
    }

    if (dp->push_mpls <= 0) {
        c_log_err("%s: No outer mpls header", FN);
        dp->res = -1;
        return 0;
    }

    return oxm->length;
}

static int
of131_dump_set_field_mpls_tc(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *tc = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-mpls-tc-0x%x", *tc);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_mpls_tc(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *tc = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-mpls-tc %d\r\n", *tc);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_mpls_tc(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_MPLS_TC)) {
        dp->res = -1;
        return 0;
    } 

    if (dp->push_mpls <= 0) {
        c_log_err("%s: No outer mpls header", FN);
        dp->res = -1;
        return 0;
    }
                        
    return oxm->length;
}

static int
of131_dump_set_field_mpls_bos(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *bos = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-mpls-bos-0x%x", *bos);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_mpls_bos(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *bos = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-mpls-bos %d\r\n", *bos);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_mpls_bos(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_MPLS_BOS)) {
        dp->res = -1;
        return 0;
    }

    if (dp->push_mpls <= 0) {
        c_log_err("%s: No outer mpls header", FN);
        dp->res = -1;
        return 0;
    }

    return oxm->length;
}

static int
of131_dump_set_field_ipv4_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t nw_addr = *(uint32_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-ipv4-src-0x%x,", ntohl(nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_ipv4_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct in_addr in;

    in.s_addr = *(uint32_t *)(oxm->data);
 
    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add nw-saddr %s\r\n",inet_ntoa(in));
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_ipv4_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_IPV4_SRC)) {
        dp->res = -1;
        return 0;
    }

    if (dp->fl && dp->mask) {
        if (!dp->mask->dl_type ||
            (dp->fl->dl_type != htons(ETH_TYPE_IP) &&
            dp->fl->dl_type != htons(ETH_TYPE_ARP))) {
            dp->res = -1;
            return 0;
        }
    }

    return oxm->length;
}

static int
of131_dump_set_field_ipv4_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint32_t nw_addr = *(uint32_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-ipv4-dst-0x%x, ", ntohl(nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_ipv4_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct in_addr in;

    in.s_addr = *(uint32_t *)(oxm->data);
 
    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add nwdsaddr %s\r\n",inet_ntoa(in));
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_ipv4_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_IPV4_DST)) {
        dp->res = -1;
        return 0;
    }

    if (dp->fl && dp->mask) {
        if (!dp->mask->dl_type ||
            (dp->fl->dl_type != htons(ETH_TYPE_IP) &&
            dp->fl->dl_type != htons(ETH_TYPE_ARP))) {
            dp->res = -1;
            return 0;
        }
    }

    return oxm->length;
}

static int
of131_dump_set_field_ipv6_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct in6_addr nw_addr;
    char nw_addr_str[INET6_ADDRSTRLEN];
    
    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    memcpy(nw_addr.s6_addr32, (uint8_t *)(oxm->data), OFPXMT_OFB_IPV6_SZ);
    if (!inet_ntop(AF_INET6, &nw_addr, nw_addr_str, INET6_ADDRSTRLEN))
        return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-ipv6-src- %s,", nw_addr_str);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_ipv6_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct in6_addr nw_addr;
    char nw_addr_str[INET6_ADDRSTRLEN];
    
    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    memcpy(nw_addr.s6_addr32, (uint8_t *)(oxm->data), OFPXMT_OFB_IPV6_SZ);
    if (!inet_ntop(AF_INET6, &nw_addr, nw_addr_str, INET6_ADDRSTRLEN))
        return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add nw-saddr6 %s\r\n", nw_addr_str);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_ipv6_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_IPV6_SRC)) {
        dp->res = -1;
        return 0;
    }

    if (dp->fl && dp->mask) {
        if (!dp->mask->dl_type ||
            (dp->fl->dl_type != htons(ETH_TYPE_IPV6))) { 
            dp->res = -1;
            return 0;
        }
    }

    return oxm->length;
}

static int
of131_dump_set_field_ipv6_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct in6_addr nw_addr;
    char nw_addr_str[INET6_ADDRSTRLEN];

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    memcpy(nw_addr.s6_addr32, (uint8_t *)(oxm->data), OFPXMT_OFB_IPV6_SZ);
    if (!inet_ntop(AF_INET6, &nw_addr, nw_addr_str, INET6_ADDRSTRLEN))
        return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-ipv6-dst- %s, ", nw_addr_str);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_ipv6_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    struct in6_addr nw_addr;
    char nw_addr_str[INET6_ADDRSTRLEN];

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    memcpy(nw_addr.s6_addr32, (uint8_t *)(oxm->data), OFPXMT_OFB_IPV6_SZ);
    if (!inet_ntop(AF_INET6, &nw_addr, nw_addr_str, INET6_ADDRSTRLEN))
        return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add nw-daddr6 %s\r\n", nw_addr_str);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}


static int
of131_check_set_field_ipv6_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_IPV6_DST)) {
        dp->res = -1;
        return 0;
    }

    if (dp->fl && dp->mask) {
        if (!dp->mask->dl_type ||
            (dp->fl->dl_type != htons(ETH_TYPE_IPV6))) {
            dp->res = -1;
            return 0;
        }
    }

    return oxm->length;
}

static int
of131_dump_set_field_dscp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t dscp  = *(uint8_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-dscp-0x%x, ", dscp); 
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_dscp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t dscp  = *(uint8_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add set-nw-dscp %d\r\n", dscp); 
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_ipv4_dscp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, OFPXMT_OFB_IP_DSCP)) {
        dp->res = -1;
        return 0;
    }

    if (dp->fl && dp->mask) {
        if (!dp->mask->dl_type ||
            dp->fl->dl_type != htons(ETH_TYPE_IP)) {
            dp->res = -1;
            return 0;
        }
    }

    return oxm->length;
}

static int
of131_dump_set_field_tp_port(struct ofp_oxm_header *oxm, void *arg,
                             char *str)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t port = *(uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%x", str, ntohs(port)); 
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_cmd_set_field_tp_port(struct ofp_oxm_header *oxm, void *arg,
                             char *str)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t port = *(uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "action-add %s %d\r\n", str, ntohs(port)); 
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_check_set_field_tp_port(struct ofp_oxm_header *oxm, void *arg,
                              uint8_t oxm_field)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (OFP_OXM_GHDR_HM(oxm) ||
        !of131_check_setfield_supported(dp, oxm_field)) {
        dp->res = -1;
        return 0;
    }

    if (dp->fl && dp->mask) {
        if (dp->mask->dl_type && 
            (dp->fl->dl_type == htons(ETH_TYPE_IP) ||
             dp->fl->dl_type == htons(ETH_TYPE_IPV6)) &&
            dp->mask->nw_proto && 
            (dp->fl->nw_proto == IP_TYPE_TCP ||
             dp->fl->nw_proto == IP_TYPE_UDP ||
             dp->fl->nw_proto == IP_TYPE_SCTP)) { 
            return oxm->length;
        } else {
            dp->res = -1;
            c_log_err("%s: No udp,tcp or sctp", FN);
            return 0;
        }
    }

    return oxm->length;
}

static int
of131_dump_set_field_tp_udp_sport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_dump_set_field_tp_port(oxm, arg, "set-udp-sport");
}

static int
of131_dump_set_field_tp_udp_dport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_dump_set_field_tp_port(oxm, arg, "set-udp-dport");
}

static int
of131_dump_set_field_tp_tcp_sport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_dump_set_field_tp_port(oxm, arg, "set-tcp-sport");
}

static int
of131_dump_set_field_tp_tcp_dport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_dump_set_field_tp_port(oxm, arg, "set-tcp-dport");
}

static int
of131_dump_cmd_set_field_tp_udp_sport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_dump_cmd_set_field_tp_port(oxm, arg, "set-udp-sport");
}

static int
of131_dump_cmd_set_field_tp_udp_dport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_dump_cmd_set_field_tp_port(oxm, arg, "set-udp-dport");
}

static int
of131_dump_cmd_set_field_tp_tcp_sport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_dump_cmd_set_field_tp_port(oxm, arg, "set-tcp-sport");
}

static int
of131_dump_cmd_set_field_tp_tcp_dport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_dump_cmd_set_field_tp_port(oxm, arg, "set-tcp-dport");
}

static int
of131_check_set_field_tp_udp_sport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_check_set_field_tp_port(oxm, arg, OFPXMT_OFB_UDP_SRC);
}

static int
of131_check_set_field_tp_udp_dport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_check_set_field_tp_port(oxm, arg, OFPXMT_OFB_UDP_DST);
}

static int
of131_check_set_field_tp_tcp_sport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_check_set_field_tp_port(oxm, arg, OFPXMT_OFB_TCP_SRC);
}

static int
of131_check_set_field_tp_tcp_dport(struct ofp_oxm_header *oxm, void *arg)
{
    return of131_check_set_field_tp_port(oxm, arg, OFPXMT_OFB_TCP_DST);
}

static int
of131_dump_set_tunnel(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint64_t tunnel = *(uint64_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                   "set-tunnel:0x%llx, ", U642ULL(ntohll(tunnel)));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
of131_dump_cmd_set_tunnel(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint64_t tunnel = *(uint64_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                   "action-add set-tunnel 0x%llx\r\n",
                    U642ULL(ntohll(tunnel)));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return oxm->length;
}

static int
of131_dump_act_set_field(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_set_field *ofp_sf = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        " set-field: ");
    assert(dp->len < OF_DUMP_INST_SZ-1);

    of131_parse_act_set_field_tlv(ofp_sf, dp->act_parsers, arg);
    return ntohs(action->len);
}

static int
of131_dump_cmd_act_set_field(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_set_field *ofp_sf = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    of131_parse_act_set_field_tlv(ofp_sf, dp->act_parsers, arg);
    return ntohs(action->len);
}

static int
of131_check_act_set_field(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_set_field *ofp_sf = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    /* Has to be supported */

    of131_parse_act_set_field_tlv(ofp_sf, dp->act_parsers, arg);
    return ntohs(action->len);
}

static int
of131_dump_meter_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_meter *ofp_im = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-%lu,", "meter-id",
                        U322UL(ntohl(ofp_im->meter_id)));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len); 
}

static int
of131_dump_cmd_meter_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_meter *ofp_im = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s %lu\r\n", "instruction-meter",
                        U322UL(ntohl(ofp_im->meter_id)));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len); 
}

static int
of131_dump_goto_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_goto_table *ofp_ig = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-%d,", "goto", ofp_ig->table_id);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len); 
}

static int
of131_dump_cmd_goto_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_goto_table *ofp_ig = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s %d,", "instruction-goto", ofp_ig->table_id);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len); 
}

static int
of131_check_meter_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_meter *ofp_im = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;
    struct ofp_inst_check_args *u_arg = dp->u_arg;

#if 0
    if (!of131_check_inst_supported(arg, ntohs(inst->type))) {
        dp->res = -1;
        return 0;
    }
#endif

    if (dp->inst_meter ||
        (u_arg && u_arg->check_add_meter &&
         !u_arg->check_add_meter(u_arg->sw_ctx, ntohl(ofp_im->meter_id),
                                 u_arg))) {
        dp->res = -1;
        c_log_err("%s: Duplicate meter instr or no such meter", FN);
        return 0;
    }

    dp->inst_meter = true;

    return ntohs(inst->len); 
}

static int
of131_check_goto_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (dp->inst_goto) {
        dp->res = -1;
        c_log_err("%s: duplicate goto instr", FN);
        return 0;
    }

    if (!of131_check_inst_supported(arg, ntohs(inst->type))) {
        dp->res = -1;
        return 0;
    }

    dp->inst_goto = true;

    return ntohs(inst->len); 
}

static int
of131_dump_wr_meta_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_write_metadata *ofp_iwm = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1, 
                        "%s-0x%llx:0x%llx,", "write-meta",
                        U642ULL(ntohll(ofp_iwm->metadata)), 
                        U642ULL(ntohll(ofp_iwm->metadata_mask))); 
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len);
}

static int
of131_dump_cmd_wr_meta_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_write_metadata *ofp_iwm = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1, 
                        "%s 0x%llx:0x%llx,", "instruction-meta",
                        U642ULL(ntohll(ofp_iwm->metadata)), 
                        U642ULL(ntohll(ofp_iwm->metadata_mask))); 
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len);
}

static int
of131_check_wr_meta_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    if (dp->inst_wr_meta) {
        dp->res = -1;
        c_log_err("%s: duplicate metadata instr", FN);
        return 0;
    }

    if (!of131_check_inst_supported(arg, ntohs(inst->type))) {
        dp->res = -1;
        return 0;
    }

    dp->inst_wr_meta = true;

    return ntohs(inst->len);
}

static int
of131_dump_act_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_actions *ofp_ia = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg; 
    char *pinst = NULL;
    
    switch(ntohs(ofp_ia->type)) {
    case OFPIT_WRITE_ACTIONS:
        pinst = "write-act";
        break;
    case OFPIT_APPLY_ACTIONS:
        pinst = "apply-act";
        break;
    case OFPIT_CLEAR_ACTIONS:
        pinst = "clr-act";
        break;
    default:
        return -1;
    }
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "%s: ", pinst);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    if (ntohs(ofp_ia->len) > sizeof(*ofp_ia)) {
        of131_parse_actions((void *)(ofp_ia->actions), 
                        ntohs(ofp_ia->len) - sizeof(*ofp_ia), arg);
    }
    return ntohs(inst->len);
}

static int
of131_dump_cmd_act_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_actions *ofp_ia = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg; 
    char *pinst = NULL;
    
    switch(ntohs(ofp_ia->type)) {
    case OFPIT_WRITE_ACTIONS:
        pinst = "instruction-write";
        break;
    case OFPIT_APPLY_ACTIONS:
        pinst = "instruction-apply";
        break;
    case OFPIT_CLEAR_ACTIONS:
        pinst = "instruction-clear";
        break;
    default:
        return -1;
    }
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "%s\r\n", pinst);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    if (ntohs(ofp_ia->type) != OFPIT_CLEAR_ACTIONS) {
        if (ntohs(ofp_ia->len) > sizeof(*ofp_ia)) {
            of131_parse_actions((void *)(ofp_ia->actions), 
                            ntohs(ofp_ia->len) - sizeof(*ofp_ia), arg);
        } else {
            dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "action-add drop\r\n");
            assert(dp->len < OF_DUMP_INST_SZ-1);
        }
        dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "action-list-end\r\n");
        assert(dp->len < OF_DUMP_INST_SZ-1);
    }

    return ntohs(inst->len);
}

static int
of131_check_act_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_actions *ofp_ia = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg; 
    
    switch(ntohs(ofp_ia->type)) {
    case OFPIT_WRITE_ACTIONS:
        if (dp->inst_wr) {
            dp->res = -1;
            c_log_err("%s: duplicate write instr", FN);
            return 0;
        }
        dp->inst_wr = true;
        dp->act_set = true;
        break;
    case OFPIT_APPLY_ACTIONS:
        if (dp->inst_wr) {
            dp->res = -1;
            c_log_err("%s: duplicate app instr", FN);
            return 0;
        }
        dp->inst_app = true;
        dp->act_set = false;
        break;
    case OFPIT_CLEAR_ACTIONS:
        if (dp->inst_clear) {
            dp->res = -1;
            c_log_err("%s: duplicate clear instr", FN);
            return 0;
        }
        dp->inst_clear = true;
        return ntohs(inst->len);
    default:
        c_log_err("%s: Unknown", FN);
        dp->res = -1;
        return 0;
    }

    if (!of131_check_inst_supported(arg, ntohs(ofp_ia->type))) {
        dp->res = -1;
        return 0;
    }
    
    if (ntohs(ofp_ia->len) > sizeof(*ofp_ia)) {
        of131_parse_actions((void *)(ofp_ia->actions), 
                        ntohs(ofp_ia->len) - sizeof(*ofp_ia), arg);
    }
    return ntohs(inst->len);
}


void
of131_parse_act_set_field_tlv(struct ofp_action_set_field *ofp_sf,
                              struct ofp_act_parsers *act_parsers, 
                              void *parse_ctx)
{
    struct ofp_oxm_header *oxm = (void *)(ofp_sf->field);

    NTOH_OXM_HDR(oxm);
    if (oxm->oxm_class != OFPXMC_OPENFLOW_BASIC) {
        HTON_OXM_HDR(oxm);
        return;
    }

    switch (OFP_OXM_GHDR_FIELD(oxm)) {
    case OFPXMT_OFB_IN_PORT:
        if (act_parsers->act_setf_in_port)
            act_parsers->act_setf_in_port(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_ETH_DST:
        if (act_parsers->act_setf_dl_dst)
            act_parsers->act_setf_dl_dst(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_ETH_SRC:
        if (act_parsers->act_setf_dl_src)
            act_parsers->act_setf_dl_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_VLAN_VID:
        if (act_parsers->act_setf_dl_vlan)
            act_parsers->act_setf_dl_vlan(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_VLAN_PCP:
        if (act_parsers->act_setf_dl_vlan_pcp)
            act_parsers->act_setf_dl_vlan_pcp(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_ETH_TYPE:
        if (act_parsers->act_setf_dl_type)
            act_parsers->act_setf_dl_type(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_IPV4_SRC:
        if (act_parsers->act_setf_ipv4_src)
            act_parsers->act_setf_ipv4_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_IPV4_DST:
        if (act_parsers->act_setf_ipv4_dst)
            act_parsers->act_setf_ipv4_dst(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_IPV6_SRC:
        if (act_parsers->act_setf_ipv6_src)
            act_parsers->act_setf_ipv6_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_IPV6_DST:
        if (act_parsers->act_setf_ipv6_dst)
            act_parsers->act_setf_ipv6_dst(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_IP_DSCP:
        if (act_parsers->act_setf_ipv4_dscp)
            act_parsers->act_setf_ipv4_dscp(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_TCP_SRC:
        if (act_parsers->act_setf_tcp_src)
            act_parsers->act_setf_tcp_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_UDP_SRC:
        if (act_parsers->act_setf_udp_src)
            act_parsers->act_setf_udp_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_TCP_DST:
        if (act_parsers->act_setf_tcp_dst)
            act_parsers->act_setf_tcp_dst(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_UDP_DST:
        if (act_parsers->act_setf_udp_dst)
            act_parsers->act_setf_udp_dst(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_MPLS_LABEL:
        if (act_parsers->act_setf_mpls_label)
            act_parsers->act_setf_mpls_label(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_MPLS_TC:
        if (act_parsers->act_setf_mpls_tc)
            act_parsers->act_setf_mpls_tc(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_MPLS_BOS:
        if (act_parsers->act_setf_mpls_bos)
            act_parsers->act_setf_mpls_bos(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_TUNNEL_ID:
        if (act_parsers->act_setf_tunnel)
            act_parsers->act_setf_tunnel(oxm, parse_ctx);
        break;
    default:
        c_log_err("%s:Unhandled set-field", FN);
        break;
    }

    HTON_OXM_HDR(oxm);

    return;
}

void
of131_parse_actions(void *actions, size_t act_len,
                    void *parse_ctx)
{
    struct ofp_action_header *act = actions;
    struct ofp_inst_parser_arg *parser = parse_ctx;
    struct ofp_act_parsers *act_parsers = parser->act_parsers;
    int n_act = 0;

    if (!actions || !act_len || !act_parsers) {
        c_log_err("%s: No Actions or Parsers", FN);
        return;
    }

    while (act_len) {
        if (n_act++ > OFP_MAX_ACTIONS ||
            parser->res) {
            c_log_err("%s: Too many actions or parse error", FN);
            goto done;
        } 

        switch(ntohs(act->type)) {
        case OFPAT_OUTPUT:
            if (act_parsers->act_output) 
                act_parsers->act_output(act, parse_ctx);
            break;
        case OFPAT131_PUSH_VLAN:
            if (act_parsers->act_push)
                act_parsers->act_push(act, parse_ctx);
            break;
        case OFPAT131_POP_VLAN:
             if (act_parsers->act_pop_vlan)
                act_parsers->act_pop_vlan(act, parse_ctx);
            break;
        case OFPAT131_PUSH_MPLS:
            if (act_parsers->act_push)
                act_parsers->act_push(act, parse_ctx);
            break;
        case OFPAT131_POP_MPLS:
            if (act_parsers->act_pop_mpls)
                act_parsers->act_pop_mpls(act, parse_ctx); 
            break;
        case OFPAT131_PUSH_PBB:
            if (act_parsers->act_push)
                act_parsers->act_push(act, parse_ctx);
            break;
        case OFPAT131_POP_PBB:
            if (act_parsers->act_pop_pbb)
                act_parsers->act_pop_pbb(act, parse_ctx); 
            break;
        case OFPAT131_SET_FIELD:
            if (act_parsers->act_set_field)
                act_parsers->act_set_field(act, parse_ctx);
            break;
        case OFPAT131_GROUP:
            if (act_parsers->act_set_grp)
                act_parsers->act_set_grp(act, parse_ctx);
            break;
        case OFPAT131_SET_NW_TTL:
            if (act_parsers->act_set_nw_ttl)
                act_parsers->act_set_nw_ttl(act, parse_ctx);
            break;
        case OFPAT131_DEC_NW_TTL:
            if (act_parsers->act_dec_nw_ttl)
                act_parsers->act_dec_nw_ttl(act, parse_ctx);
            break;
        case OFPAT131_MPLS_TTL:
            if (act_parsers->act_set_mpls_ttl)
                act_parsers->act_set_mpls_ttl(act, parse_ctx);
            break;
        case OFPAT131_DEC_MPLS_TTL:
            if (act_parsers->act_dec_mpls_ttl)
                act_parsers->act_dec_mpls_ttl(act, parse_ctx);
            break;
        case OFPAT131_COPY_TTL_OUT:
           if (act_parsers->act_cp_ttl_out)
                act_parsers->act_cp_ttl_out(act, parse_ctx);
            break;
        case OFPAT131_COPY_TTL_IN:
           if (act_parsers->act_cp_ttl_in)
                act_parsers->act_cp_ttl_in(act, parse_ctx);
           break;
        case OFPAT131_SET_QUEUE:
            if (act_parsers->act_set_queue)
                act_parsers->act_set_queue(act, parse_ctx);
            break;
        default:
            c_log_err("%s: Unhandled actions", FN);
            goto done;
        }

        act_len -= ntohs(act->len);
        act = INC_PTR8(act, ntohs(act->len));
    }

done:
    return;
}

struct ofp_act_parsers of131_dump_act_parsers = {
    .act_output = of131_dump_act_output,
    .act_push = of131_dump_push_action,
    .act_pop_vlan = of131_dump_pop_vlan_action,
    .act_pop_pbb = of131_dump_pop_pbb_action,
    .act_pop_mpls = of131_dump_pop_mpls_action,
    .act_set_queue = of131_dump_set_queue,
    .act_set_nw_ttl = of131_dump_set_nw_ttl,
    .act_dec_nw_ttl = of131_dump_dec_nw_ttl,
    .act_set_mpls_ttl = of131_dump_set_mpls_ttl,
    .act_dec_mpls_ttl = of131_dump_dec_mpls_ttl,
    .act_cp_ttl_out = of131_dump_cp_ttl_out,
    .act_cp_ttl_in = of131_dump_cp_ttl_in,
    .act_set_field = of131_dump_act_set_field,
    .act_setf_in_port = of131_check_set_field_in_port,
    .act_setf_dl_dst = of131_dump_set_field_dl_dst,
    .act_setf_dl_src = of131_dump_set_field_dl_src,
    .act_setf_dl_type = of131_dump_set_field_dl_type,
    .act_setf_dl_vlan = of131_dump_set_field_dl_vlan,
    .act_setf_dl_vlan_pcp = of131_dump_set_field_dl_vlan_pcp, 
    .act_setf_mpls_label = of131_dump_set_field_mpls_label,
    .act_setf_mpls_tc = of131_dump_set_field_mpls_tc,
    .act_setf_mpls_bos = of131_dump_set_field_mpls_bos,
    .act_setf_ipv4_src = of131_dump_set_field_ipv4_src,
    .act_setf_ipv4_dst = of131_dump_set_field_ipv4_dst,
    .act_setf_ipv4_dscp = of131_dump_set_field_dscp,
    .act_setf_ipv6_src = of131_dump_set_field_ipv6_src,
    .act_setf_ipv6_dst = of131_dump_set_field_ipv6_dst,
    .act_setf_tcp_src = of131_dump_set_field_tp_tcp_sport,
    .act_setf_tcp_dst = of131_dump_set_field_tp_tcp_dport,
    .act_setf_udp_src = of131_dump_set_field_tp_udp_sport,
    .act_setf_udp_dst = of131_dump_set_field_tp_udp_dport,
    .act_setf_tunnel = of131_dump_set_tunnel,
    .act_set_grp = of131_dump_group_act
};

struct ofp_act_parsers of131_dump_cmd_act_parsers = {
    .act_output = of131_dump_cmd_act_output,
    .act_push = of131_dump_cmd_push_action,
    .act_pop_vlan = of131_dump_cmd_pop_vlan_action,
    .act_pop_pbb = of131_dump_cmd_pop_pbb_action,
    .act_pop_mpls = of131_dump_cmd_pop_mpls_action,
    .act_set_queue = of131_dump_cmd_set_queue,
    .act_set_nw_ttl = of131_dump_cmd_set_nw_ttl,
    .act_dec_nw_ttl = of131_dump_cmd_dec_nw_ttl,
    .act_set_mpls_ttl = of131_dump_cmd_set_mpls_ttl,
    .act_dec_mpls_ttl = of131_dump_cmd_dec_mpls_ttl,
    .act_cp_ttl_out = of131_dump_cmd_cp_ttl_out,
    .act_cp_ttl_in = of131_dump_cmd_cp_ttl_in,
    .act_set_field = of131_dump_cmd_act_set_field,
    .act_setf_in_port = of131_check_set_field_in_port,
    .act_setf_dl_dst = of131_dump_cmd_set_field_dl_dst,
    .act_setf_dl_src = of131_dump_cmd_set_field_dl_src,
    .act_setf_dl_type = of131_dump_cmd_set_field_dl_type,
    .act_setf_dl_vlan = of131_dump_cmd_set_field_dl_vlan,
    .act_setf_dl_vlan_pcp = of131_dump_cmd_set_field_dl_vlan_pcp, 
    .act_setf_mpls_label = of131_dump_cmd_set_field_mpls_label,
    .act_setf_mpls_tc = of131_dump_cmd_set_field_mpls_tc,
    .act_setf_mpls_bos = of131_dump_cmd_set_field_mpls_bos,
    .act_setf_ipv4_src = of131_dump_cmd_set_field_ipv4_src,
    .act_setf_ipv4_dst = of131_dump_cmd_set_field_ipv4_dst,
    .act_setf_ipv4_dscp = of131_dump_cmd_set_field_dscp,
    .act_setf_ipv6_src = of131_dump_cmd_set_field_ipv6_src,
    .act_setf_ipv6_dst = of131_dump_cmd_set_field_ipv6_dst,
    .act_setf_tcp_src = of131_dump_cmd_set_field_tp_tcp_sport,
    .act_setf_tcp_dst = of131_dump_cmd_set_field_tp_tcp_dport,
    .act_setf_udp_src = of131_dump_cmd_set_field_tp_udp_sport,
    .act_setf_udp_dst = of131_dump_cmd_set_field_tp_udp_dport,
    .act_setf_tunnel = of131_dump_cmd_set_tunnel,
    .act_set_grp = of131_dump_cmd_group_act
};

struct ofp_act_parsers of131_check_act_parsers = {
    .act_output = of131_check_act_output,
    .act_push = of131_check_push_action,
    .act_pop_vlan = of131_check_pop_vlan_action,
    .act_pop_pbb = of131_check_pop_pbb_action,
    .act_pop_mpls = of131_check_pop_mpls_action,
    .act_set_queue = of131_check_set_queue,
    .act_set_nw_ttl = of131_check_set_nw_ttl,
    .act_dec_nw_ttl = of131_check_dec_nw_ttl,
    .act_set_mpls_ttl = of131_check_set_mpls_ttl,
    .act_dec_mpls_ttl = of131_check_dec_mpls_ttl,
    .act_cp_ttl_out = of131_check_cp_ttl_out,
    .act_cp_ttl_in = of131_check_cp_ttl_in,
    .act_set_field = of131_check_act_set_field,
    .act_setf_dl_dst = of131_check_set_field_dl_dst,
    .act_setf_dl_src = of131_check_set_field_dl_src,
    .act_setf_dl_type = of131_check_set_field_dl_type,
    .act_setf_dl_vlan = of131_check_set_field_dl_vlan,
    .act_setf_dl_vlan_pcp = of131_check_set_field_dl_vlan_pcp,
    .act_setf_mpls_label = of131_check_set_field_mpls_label,
    .act_setf_mpls_tc = of131_check_set_field_mpls_tc,
    .act_setf_mpls_bos = of131_check_set_field_mpls_bos,
    .act_setf_ipv4_src = of131_check_set_field_ipv4_src,
    .act_setf_ipv4_dst = of131_check_set_field_ipv4_dst,
    .act_setf_ipv6_src = of131_check_set_field_ipv6_src,
    .act_setf_ipv6_dst = of131_check_set_field_ipv6_dst,
    .act_setf_ipv4_dscp = of131_check_set_field_ipv4_dscp,
    .act_setf_tcp_src = of131_check_set_field_tp_tcp_sport,
    .act_setf_tcp_dst = of131_check_set_field_tp_tcp_dport,
    .act_setf_udp_src = of131_check_set_field_tp_udp_sport,
    .act_setf_udp_dst = of131_check_set_field_tp_udp_dport,
    .act_set_grp = of131_check_group_act
};


struct ofp_inst_parsers of131_dump_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .pre_proc = of_dump_inst_parser_pre_proc,
    .post_proc = of_dump_inst_parser_post_proc,
    .goto_inst = of131_dump_goto_inst,
    .meter_inst = of131_dump_meter_inst,
    .wr_meta_inst = of131_dump_wr_meta_inst,
    .wr_act_inst = of131_dump_act_inst,
    .apply_act_inst = of131_dump_act_inst,
    .clear_act_inst = of131_dump_act_inst,
    .fini_inst_parser = of_inst_parser_fini,
}; 

struct ofp_inst_parsers of131_dump_cmd_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .pre_proc = of_dump_cmd_inst_parser_pre_proc,
    .post_proc = of131_dump_cmd_inst_parser_post_proc,
    .goto_inst = of131_dump_cmd_goto_inst,
    .meter_inst = of131_dump_cmd_meter_inst,
    .wr_meta_inst = of131_dump_cmd_wr_meta_inst,
    .wr_act_inst = of131_dump_cmd_act_inst,
    .apply_act_inst = of131_dump_cmd_act_inst,
    .clear_act_inst = of131_dump_cmd_act_inst,
    .fini_inst_parser = of_inst_parser_fini,
}; 

struct ofp_inst_parsers of131_check_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .pre_proc = of_check_inst_parser_pre_proc,
    .post_proc = NULL,
    .goto_inst = of131_check_goto_inst,
    .meter_inst = of131_check_meter_inst,
    .wr_meta_inst = of131_check_wr_meta_inst,
    .wr_act_inst = of131_check_act_inst,
    .apply_act_inst = of131_check_act_inst,
    .clear_act_inst = of131_check_act_inst,
    .fini_inst_parser = of_inst_parser_fini,
}; 

struct ofp_inst_parser_arg *
of131_parse_instructions(struct flow *fl, struct flow *mask,
                         void *inst_list, size_t inst_len,
                         struct ofp_inst_parsers *inst_handlers,
                         struct ofp_act_parsers *act_handlers,
                         void *u_arg, bool acts_only)
{
    struct ofp_instruction *inst = inst_list;
    int n_inst = 0;
    void *parse_ctx;

    if (!inst_handlers  || !inst_handlers->prep_inst_parser) {
        c_log_err("%s: No parser specified for instructions", FN);
        return NULL;
    }

    parse_ctx = inst_handlers->prep_inst_parser(fl, mask, u_arg, inst_handlers,
                                                act_handlers);
    if (!inst_len) {
        if (inst_handlers->no_inst) {
            inst_handlers->no_inst(parse_ctx);
            goto done;
        }
    }

    if (acts_only) {
        of131_parse_actions(inst_list, inst_len, parse_ctx);
        goto done;
    }

    if (inst_handlers->pre_proc)
        inst_handlers->pre_proc(parse_ctx);


    while (inst_len) {
        if (n_inst++ > OFP_MAX_INSTRUCTIONS || 
            ((struct ofp_inst_parser_arg *)(parse_ctx))->res) {
            c_log_err("%s: Too many instructions or parse err", FN);
            goto done;
        } 
        switch(ntohs(inst->type)) {
        case OFPIT_GOTO_TABLE:
            if (inst_handlers->goto_inst) 
                inst_handlers->goto_inst(inst, parse_ctx);
            break;
        case OFPIT_WRITE_METADATA:
            if (inst_handlers->wr_meta_inst)
                inst_handlers->wr_meta_inst(inst, parse_ctx);
            break;
        case OFPIT_WRITE_ACTIONS:
            if (inst_handlers->wr_act_inst)
                inst_handlers->wr_act_inst(inst, parse_ctx);
            break;
        case OFPIT_APPLY_ACTIONS:
            if (inst_handlers->apply_act_inst)
                inst_handlers->apply_act_inst(inst, parse_ctx);
            break;
        case OFPIT_CLEAR_ACTIONS:
            if (inst_handlers->clear_act_inst)
                inst_handlers->clear_act_inst(inst, parse_ctx); 
            break;
        case OFPIT_METER:
            if (inst_handlers->meter_inst)
                inst_handlers->meter_inst(inst, parse_ctx);
            break;
        case OFPIT_EXPERIMENTER:
            if (inst_handlers->exp_inst)
                inst_handlers->exp_inst(inst, parse_ctx);
            break;
        default:
            c_log_err("%s: Unhandled instruction", FN);
            goto done;
        }

        inst_len -= ntohs(inst->len);
        inst = INC_PTR8(inst, ntohs(inst->len));
    }

    if (inst_handlers->post_proc)
        inst_handlers->post_proc(parse_ctx);

done:
    if (inst_handlers->fini_inst_parser)
        inst_handlers->fini_inst_parser(parse_ctx);

    return parse_ctx;
}

int
of131_validate_actions(struct flow *fl, struct flow *mask,
                       void *inst_list, size_t inst_len,
                       bool acts_only, void *arg)
{
    struct ofp_inst_parser_arg *dp;
    int ret = 0;

    dp = of131_parse_instructions(fl, mask, inst_list, inst_len,
                                  &of131_check_inst_parsers,
                                  &of131_check_act_parsers, arg,
                                  acts_only);
    ret =  dp ? dp->res : -1;
    of_inst_parser_free(dp);
    return ret;
}

char *
of131_dump_actions(void *inst_list, size_t inst_len, bool acts_only)
{
    struct ofp_inst_parser_arg *dp;
    char *pbuf;

    dp = of131_parse_instructions(NULL, NULL, inst_list, inst_len,
                                  &of131_dump_inst_parsers,
                                  &of131_dump_act_parsers, NULL,
                                  acts_only);
    pbuf =  dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}

char *
of131_dump_actions_cmd(void *inst_list, size_t inst_len, bool acts_only)
{
    struct ofp_inst_parser_arg *dp;
    char *pbuf;

    dp = of131_parse_instructions(NULL, NULL, inst_list, inst_len,
                                  &of131_dump_cmd_inst_parsers,
                                  &of131_dump_cmd_act_parsers, NULL,
                                  acts_only);
    pbuf =  dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}

char *
of131_dump_queue_stats(void *q_stats, size_t stat_len)
{
    char *pbuf;
    size_t len = 0;
    struct ofp131_queue_stats *ofp_q_stat = q_stats;

    if (stat_len != sizeof(*ofp_q_stat)) {
        return NULL;
    }

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    assert(pbuf);

    len += snprintf(pbuf + len, OF_DUMP_MSG_SZ - len - 1,
                    "tx_bytes %llu tx_packets %llu tx_err %llu Alive(%lus:%luns)\r\n",
                    U642ULL(ntohll(ofp_q_stat->tx_bytes)),
                    U642ULL(ntohll(ofp_q_stat->tx_packets)),
                    U642ULL(ntohll(ofp_q_stat->tx_errors)),
                    U322UL(ntohl(ofp_q_stat->duration_sec)),
                    U322UL(ntohl(ofp_q_stat->duration_nsec)));
    return pbuf;
}

bool
of131_supports_multi_tables(uint8_t n_tables UNUSED, uint8_t table_id UNUSED)
{
    return true;
}


/**
 * of131_flow_normalize - 
 *
 * Returns :
 * -1 if flow is invalid
 * 0 if no change in flow
 * 1 if flow normalized 
 */
int
of131_flow_normalize(struct flow *fl, struct flow *mask)
{
    int ret = 0;

    mask->table_id = 0xff;

    if (mask->in_port && !fl->in_port) {
        c_log_err("%s: In port invalid", FN);
        return -1;
    }

    if (!mask->dl_vlan) {
        if (mask->dl_vlan_pcp) {
            ret = 1;
            fl->dl_vlan_pcp = 0;
            mask->dl_vlan_pcp = 0; 
            c_log_err("%s: vlan-pcp normalized", FN);
        }
    }

    if (!mask->dl_type || 
        (fl->dl_type != htons(ETH_TYPE_MPLS) && 
        fl->dl_type != htons(ETH_TYPE_MPLS))) { 
        if (mask->mpls_tc || 
            mask->mpls_bos || 
            mask->mpls_label) {
            ret = 1;
            mask->mpls_tc = 0;
            mask->mpls_bos = 0;
            mask->mpls_label = 0; 
            fl->mpls_tc = 0;
            fl->mpls_bos = 0;
            fl->mpls_label = 0; 
            c_log_err("%s: mpls normalized", FN);
        }
    }

    if (!mask->dl_type || 
        ((fl->dl_type != htons(ETH_TYPE_IP)) && 
        (fl->dl_type != htons(ETH_TYPE_IPV6)) &&
        (fl->dl_type != htons(ETH_TYPE_ARP)))) {    
        if (ipv6_addr_nonzero(&mask->ipv6.nw_src) || 
            ipv6_addr_nonzero(&mask->ipv6.nw_dst) ||
            mask->nw_proto ||
            mask->tp_dst ||
            mask->tp_src) {
            ret = 1;
            memset(&mask->ipv6, 0, sizeof(&mask->ipv6));
            mask->nw_proto = 0; 
            mask->tp_dst = 0; 
            mask->tp_src = 0;
            memset(&fl->ipv6, 0, sizeof(&fl->ipv6));
            fl->nw_proto = 0; 
            fl->tp_dst = 0; 
            fl->tp_src = 0;
            c_log_err("%s: IP fields normalized", FN);
        }
    }

    if (mask->dl_type && 
        (fl->dl_type == htons(ETH_TYPE_ARP))) {
        if(mask->nw_proto ||
           mask->nw_tos ||
           mask->tp_src ||
           mask->tp_dst) {
           ret = 1;
           mask->nw_proto = 0;
           mask->nw_tos = 0; 
           mask->tp_src = 0; 
           mask->tp_dst = 0;
           fl->nw_proto = 0;
           fl->nw_tos = 0; 
           fl->tp_src = 0; 
           fl->tp_dst = 0;
           c_log_err("%s: ARP Normalized", FN);
        }
    }

    if (mask->dl_type && 
        (fl->dl_type == htons(ETH_TYPE_IP) ||
         fl->dl_type == htons(ETH_TYPE_IPV6))) {
        if (!mask->nw_proto ||
            (fl->nw_proto != IP_TYPE_TCP && 
            fl->nw_proto != IP_TYPE_SCTP && 
            fl->nw_proto != IP_TYPE_UDP)) {
            if (mask->tp_dst ||
                mask->tp_src) {
                ret = 1;
                fl->tp_dst = 0;
                fl->tp_src = 0;
                mask->tp_dst = 0;
                mask->tp_src = 0;
                c_log_err("%s: L4 fields normalized", FN);
            }
        }
    }
    return ret;
}

static char *
of131_group_type_to_name(uint16_t type)
{
    switch(type) {
    case OFPGT_ALL:
        return "grp-all";
    case OFPGT_SELECT:
        return "grp-select";
    case OFPGT_INDIRECT:
        return "grp-indirect";
    case OFPGT_FF:
        return "grp-fast-failover";
    default:
        break;
    }
    return "None";
}

static char *
of131_group_cap_to_name(uint16_t type)
{
    switch(type) {
    case OFPGFC_SELECT_WEIGHT:
        return "grp-flags-select-weight";
    case OFPGFC_SELECT_LIVENESS:
        return "grp-flags-select-liveness";
    case OFPGFC_CHAINING:
        return "grp-flags-chaining";
    case OFPGFC_CHAINING_CHECKS:
        return "grp-flags-chaining-check";
    default:
        break;
    }
    return "None";
}

int
of131_group_validate_feat(struct of_group_mod_params *g_parms,
                          void *gp_feat)
{
    struct ofp_group_features *ofp_gf = gp_feat;
    struct ofp_inst_check_args inst_args;
    struct of_act_vec_elem *act_elem;
    int i = 0;

    if (!gp_feat) return 0;

    if (!(1 << g_parms->type & ntohl(ofp_gf->types))) {
        if (!c_rlim(&rl))
            c_log_err("%s: group type %d not supported ", 
                      FN, g_parms->type); 
        return -1;
    }

    switch (g_parms->type) {
    case OFPGT_ALL:
        if (g_parms->group >= ntohl(ofp_gf->max_groups[OFPGT_ALL])) {
            if (!c_rlim(&rl))
                c_log_err("%s: group num %u exceed",
                          FN, g_parms->group);
            return -1;
        } 
        break; 
    case OFPGT_SELECT:
        if (g_parms->group >= ntohl(ofp_gf->max_groups[OFPGT_SELECT])) {
            if (!c_rlim(&rl))
                c_log_err("%s: group num %u exceed",
                          FN, g_parms->group);
            return -1;
        } 
        break;
    case OFPGT_INDIRECT:
        if (g_parms->group >= ntohl(ofp_gf->max_groups[OFPGT_INDIRECT])) {
            if (!c_rlim(&rl))
                c_log_err("%s: group num %u exceed",
                          FN, g_parms->group);
            return -1;
        }
        break;
    case OFPGT_FF:
        if (g_parms->group >= ntohl(ofp_gf->max_groups[OFPGT_FF])) {
            if (!c_rlim(&rl))
                c_log_err("%s: group num %u exceed",
                          FN, g_parms->group);
            return -1;
        }
        break;
    default:
        return -1;
    }

    memset(&inst_args, 0, sizeof(inst_args));

    inst_args.group_act_check = true; 
    inst_args.check_setf_supp = false;

    for (i = 0; i < g_parms->act_vec_len; i++) {
        act_elem = g_parms->act_vectors[i];
        if (act_elem && act_elem->actions) {
            if (of131_validate_actions(NULL, NULL,
                                       act_elem->actions,
                                       act_elem->action_len,
                                       true, &inst_args)) {
                if (!c_rlim(&rl))
                    c_log_err("%s: group num %u action not supported",
                               FN, g_parms->group);
                return -1;
            }
        }
    }

    return 0;
}

static char *
of131_act_type_to_name(uint16_t act)
{
    switch(act) {
    case OFPAT131_OUTPUT:
        return "act-output";
    case OFPAT131_COPY_TTL_OUT:
        return "act-copy-ttl-out";
    case OFPAT131_COPY_TTL_IN:
        return "act-copy-ttl-in";
    case OFPAT131_MPLS_TTL:
        return "act-mpls-ttl";
    case OFPAT131_DEC_MPLS_TTL:
        return "act-mpls-dec-ttl";
    case OFPAT131_PUSH_VLAN:
        return "act-push-vlan";
    case OFPAT131_POP_VLAN:
        return "act-pop-vlan";
    case OFPAT131_PUSH_MPLS:
        return "act-push-mpls";
    case OFPAT131_POP_MPLS:
        return "act-pop-mpls";
    case OFPAT131_SET_QUEUE:
        return "act-set-queue";
    case OFPAT131_GROUP:
        return "act-set-group";
    case OFPAT131_SET_NW_TTL:
        return "act-set-nw-ttl";
    case OFPAT131_DEC_NW_TTL:
        return "act-dec-nw-ttl";
    case OFPAT131_SET_FIELD:
        return "act-set-field";
    case OFPAT131_PUSH_PBB:
        return "act-push-pbb";
    case OFPAT131_POP_PBB:
        return "act-pbb";
    default:
        break;
    }
    return "";
}



char *
of131_group_features_dump(void *feat, size_t feat_len)
{
    char *pbuf, *buf;
    size_t len = 0;
    struct ofp_group_features *ofp_gf = feat;
    int bit = 0;

    if (feat_len != sizeof(*ofp_gf)) {
        c_log_err("%s: Can't dump size err", FN);
        return NULL;
    }
    pbuf =  calloc(1, OF_DUMP_GRP_FEAT_SZ);
    assert(pbuf);

    len += snprintf(pbuf + len, OF_DUMP_GRP_FEAT_SZ - len - 1,
                    "Supported-groups: ");
    for (; bit <= OFPGT_FF; bit++) {
        if (1<<bit & ntohl(ofp_gf->types)) {
            buf = of131_group_type_to_name(bit); 
            if (buf) {
                len += snprintf(pbuf + len, 
                                OF_DUMP_GRP_FEAT_SZ - len - 1,
                                "%s ", buf); 
            }
        }
    } 

    len += snprintf(pbuf + len, OF_DUMP_GRP_FEAT_SZ - len - 1,
                    "\r\nCapability: ");
    for (; bit <= 3; bit++) {
        if (1<<bit & ntohl(ofp_gf->capabilities)) {
            buf = of131_group_cap_to_name(bit); 
            if (buf) {
                len += snprintf(pbuf + len, 
                                OF_DUMP_GRP_FEAT_SZ - len - 1,
                                "%s ", buf); 
            }
        }
    }

    len += snprintf(pbuf + len, OF_DUMP_GRP_FEAT_SZ - len - 1,
                    "\r\nGrp-all-max %u grp-select-max %u "
                    "grp-ind-max %u grp-ff-max %u",
                    ntohl(ofp_gf->max_groups[OFPGT_ALL]),
                    ntohl(ofp_gf->max_groups[OFPGT_SELECT]),
                    ntohl(ofp_gf->max_groups[OFPGT_INDIRECT]),
                    ntohl(ofp_gf->max_groups[OFPGT_FF]));

    len += snprintf(pbuf + len, OF_DUMP_GRP_FEAT_SZ - len - 1,
                    "\r\nGrp-all-actions: ");
    assert(len < OF_DUMP_GRP_FEAT_SZ- 1);
    for (bit = 0; bit < OFPAT131_POP_PBB; bit++) {
        if (1<<bit & ntohl(ofp_gf->actions[OFPGT_ALL])) {
            buf = of131_act_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_GRP_FEAT_SZ- len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_GRP_FEAT_SZ- 1);
        }
    }
    len += snprintf(pbuf + len, OF_DUMP_GRP_FEAT_SZ - len - 1,
                    "\r\nGrp-select-actions: ");
    assert(len < OF_DUMP_GRP_FEAT_SZ- 1);
    for (bit = 0; bit < OFPAT131_POP_PBB; bit++) {
        if (1<<bit & ntohl(ofp_gf->actions[OFPGT_SELECT])) {
            buf = of131_act_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_GRP_FEAT_SZ- len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_GRP_FEAT_SZ- 1);
        }
    }

    len += snprintf(pbuf + len, OF_DUMP_GRP_FEAT_SZ - len - 1,
                    "\r\nGrp-indirect-actions: ");
    assert(len < OF_DUMP_GRP_FEAT_SZ - 1);
    for (bit = 0; bit < OFPAT131_POP_PBB; bit++) {
        if (1<<bit & ntohl(ofp_gf->actions[OFPGT_INDIRECT])) {
            buf = of131_act_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_GRP_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_GRP_FEAT_SZ - 1);
        }
    }

    len += snprintf(pbuf + len, OF_DUMP_GRP_FEAT_SZ - len - 1,
                    "\r\nGrp-FF-actions: ");
    assert(len < OF_DUMP_GRP_FEAT_SZ - 1);
    for (bit = 0; bit < OFPAT131_POP_PBB; bit++) {
        if (1<<bit & ntohl(ofp_gf->actions[OFPGT_FF])) {
            buf = of131_act_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_GRP_FEAT_SZ- len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_GRP_FEAT_SZ - 1);
        }
    }

    len += snprintf(pbuf + len, OF_DUMP_GRP_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_GRP_FEAT_SZ - 1);
    return pbuf;
}

static char *
of131_band_type_to_name(uint16_t type)
{
    switch(type) {
    case OFPMBT_DROP:
        return "band-drop";
    case OFPMBT_DSCP_REMARK:
        return "band-dscp-mark";
    case OFPMBT_EXPERIMENTER:
        return "band-exp";
    default:
        break;
    }
    return "None";
}

static char *
of131_meter_flags_to_name(uint16_t flags)
{
    switch(flags) {
    case OFPMF_KBPS:
        return "meter-kbps";
    case OFPMF_PKTPS:
        return "meter-pps";
    case OFPMF_BURST:
        return "meter-burst";
   case OFPMF_STATS:
        return "meter-stats";
    default:
        break;
    }
    return "None";
}

int
of131_meter_validate_feat(struct of_meter_mod_params *m_parms,
                          void *m_feat)
{
    struct ofp_meter_features *ofp_mf = m_feat;
    int i = 0;
    struct of_meter_band_elem *band_elem;
    struct ofp_meter_band_header *band_hdr;

    if (!m_feat) return 0;

    if (m_parms->meter >= ntohl(ofp_mf->max_meter)) {
        if (!c_rlim(&rl))
            c_log_err("%s: meter num %u too high",
                      FN, m_parms->meter);
        return -1;
    }

    if ((m_parms->flags & ntohl(ofp_mf->capabilities)) != m_parms->flags) {
        if (!c_rlim(&rl))
            c_log_err("%s: meter num %u cap error",
                      FN, m_parms->meter);
        return -1; 
    }

    if (m_parms->meter_nbands > ofp_mf->max_bands) {
        if (!c_rlim(&rl))
            c_log_err("%s: meter (%u) bands too high",
                      FN, m_parms->meter);
        return -1;
    }

    for (i = 0; i < m_parms->meter_nbands; i++) {
        band_elem = m_parms->meter_bands[i];
        if (band_elem && band_elem->band) {
            band_hdr = band_elem->band;
            if (!(1 << ntohs(band_hdr->type) & ntohl(ofp_mf->band_types))) {
                if (!c_rlim(&rl))
                    c_log_err("%s: meter (%u) band not supported",
                              FN, m_parms->meter);
                return -1;
            }
        }
    }
    return 0;
}

char *
of131_port_stats_dump(void *feat, size_t feat_len)
{
    char *pbuf;
    size_t len = 0;
    struct ofp131_port_stats *ofp_ps = feat;

    if (feat_len != sizeof(*ofp_ps)) {
        c_log_err("%s: Can't dump size err", FN);
        return NULL;
    }
    pbuf =  calloc(1, OF_DUMP_PORT_STATS_SZ);
    assert(pbuf);
    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "Port No. %u\r\n", ntohl(ofp_ps->port_no));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Rx Packets:",
                    U642ULL(ntohll(ofp_ps->rx_packets)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Tx Packets:",
                    U642ULL(ntohll(ofp_ps->tx_packets)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Rx Bytes:",
                    U642ULL(ntohll(ofp_ps->rx_bytes)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu\r\n", "Tx Bytes:",
                    U642ULL(ntohll(ofp_ps->tx_bytes)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Rx Dropped:", 
                    U642ULL(ntohll(ofp_ps->rx_dropped)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Tx Dropped:",
                    U642ULL(ntohll(ofp_ps->tx_dropped)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "RX Errors:",
                    U642ULL(ntohll(ofp_ps->rx_errors)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu\r\n", "Tx Errors:",
                    U642ULL(ntohll(ofp_ps->tx_errors)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "RxFrameErr:",
                    U642ULL(ntohll(ofp_ps->rx_frame_err)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "RxOverErr:",
                    U642ULL(ntohll(ofp_ps->rx_over_err)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "RxCRCErr:",
                    U642ULL(ntohll(ofp_ps->rx_crc_err)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu\r\n", "Collisions:",
                    U642ULL(ntohll(ofp_ps->collisions)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "\r\nDuration:%lu sec %lu nsec\r\n",
                    U322UL(ntohl(ofp_ps->duration_sec)),
                    U322UL(ntohl(ofp_ps->duration_nsec)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    return pbuf;
}


char *
of131_meter_features_dump(void *feat, size_t feat_len)
{
    char *pbuf, *buf;
    size_t len = 0;
    struct ofp_meter_features *ofp_mf = feat;
    int bit = 0;

    if (feat_len != sizeof(*ofp_mf)) {
        c_log_err("%s: Can't dump size err", FN);
        return NULL;
    }
    pbuf =  calloc(1, OF_DUMP_METER_FEAT_SZ);
    assert(pbuf);
    len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ - len - 1,
                    "Max-meter: %u\r\n", ntohl(ofp_mf->max_meter));

    len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ - len - 1,
                    "Supported Bands: ");
    for (; bit <= OFPMBT_DSCP_REMARK; bit++) {
        if (1<<bit & ntohl(ofp_mf->band_types)) {
            buf = of131_band_type_to_name(bit); 
            if (buf) {
                len += snprintf(pbuf + len, 
                                OF_DUMP_METER_FEAT_SZ - len - 1,
                                "%s ", buf); 
            }
        }
    } 
    len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ - len - 1,
                    "\r\nSupported flags: ");
    for (bit = 0; bit <= 3; bit++) {
        if (1<<bit & ntohl(ofp_mf->capabilities)) {
            buf = of131_meter_flags_to_name(1<<bit); 
            if (buf) {
                len += snprintf(pbuf + len, 
                                OF_DUMP_METER_FEAT_SZ - len - 1,
                                "%s ", buf); 
            }
        }
    }

    len += snprintf(pbuf + len, OF_DUMP_METER_FEAT_SZ - len - 1,
                    "\r\nMax-bands %d max-color %d\r\n",
                    ofp_mf->max_bands, ofp_mf->max_color);
    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    return pbuf;
}

static char *
of_inst_type_to_name(uint16_t inst_type)
{
    switch(inst_type) {
    case OFPIT_GOTO_TABLE:
        return "inst-goto"; 
    case OFPIT_WRITE_METADATA:
        return "inst-metadata";
    case OFPIT_WRITE_ACTIONS:
        return "inst-write-act";
    case OFPIT_APPLY_ACTIONS:
        return "inst-apply-act";
    case OFPIT_CLEAR_ACTIONS:
        return "inst-clear-act";
    case OFPIT_METER:
        return "inst-meter"; 
    default:
        break;
    }
    return "";
}

static char *
of131_oxm_field_to_name(uint16_t setf)
{
    switch (setf) {
    case OFPXMT_OFB_IN_PORT:
        return "in-port";
    case OFPXMT_OFB_IN_PHY_PORT:
        return "in-phy-port";
    case OFPXMT_OFB_METADATA:
        return "metadata";
    case OFPXMT_OFB_ETH_DST:
        return "eth-dst";
    case OFPXMT_OFB_ETH_SRC:
        return "eth-src";
    case OFPXMT_OFB_ETH_TYPE:
        return "eth-type";
    case OFPXMT_OFB_VLAN_VID:
        return "vlan-vid";
    case OFPXMT_OFB_VLAN_PCP:
        return "vlan-pcp";
    case OFPXMT_OFB_IP_DSCP:
        return "ip-dscp";
    case OFPXMT_OFB_IP_ECN:
        return "ip-ecn";
    case OFPXMT_OFB_IP_PROTO:
        return "ip-proto";
    case OFPXMT_OFB_IPV4_SRC:
        return "ipv4-src";
    case OFPXMT_OFB_IPV4_DST:
        return "ipv4-dst";
    case OFPXMT_OFB_TCP_SRC:
        return "tcp-src";
    case OFPXMT_OFB_TCP_DST:
        return "tcp-dst";
    case OFPXMT_OFB_UDP_SRC:
        return "udp-src";
    case OFPXMT_OFB_UDP_DST:
        return "udp-dst";
    case OFPXMT_OFB_SCTP_SRC:
        return "sctp-src";
    case OFPXMT_OFB_SCTP_DST:
        return "sctp-dst";
    case OFPXMT_OFB_ICMPV4_TYPE:
        return "ipcmp4-type";
    case OFPXMT_OFB_ICMPV4_CODE:
        return "icmp4-code";
    case OFPXMT_OFB_ARP_OP:
        return "arp-opcode";
    case OFPXMT_OFB_ARP_SPA:
        return "arp-ipv4-src";
    case OFPXMT_OFB_ARP_TPA:
        return "arp-ipv4-dst";
    case OFPXMT_OFB_ARP_SHA:
        return "arp-src-mac";
    case OFPXMT_OFB_ARP_THA:
        return "arp-dst-mac";
    case OFPXMT_OFB_IPV6_SRC:
        return "ipv6-src";
    case OFPXMT_OFB_IPV6_DST:
        return "ipv6-dst";
    case OFPXMT_OFB_IPV6_FLABEL:
        return "ipv6-fl-label";
    case OFPXMT_OFB_ICMPV6_TYPE:
        return "icmpv6-type";
    case OFPXMT_OFB_ICMPV6_CODE:
        return "icmpv6-code";
    case OFPXMT_OFB_IPV6_ND_TARGET:
        return "ipv6-nd-target";
    case OFPXMT_OFB_IPV6_ND_SLL:
        return "ipv6-nd-sll";
    case OFPXMT_OFB_IPV6_ND_TLL:
        return "ipv6-nd-tll";
    case OFPXMT_OFB_MPLS_LABEL:
        return "mpls-label";
    case OFPXMT_OFB_MPLS_TC:
        return "mpls-tc";
    case OFPXMT_OFB_MPLS_BOS:
        return "mpls-bos";
    case OFPXMT_OFB_PBB_ISID:
        return "pbb-isid";
    case OFPXMT_OFB_TUNNEL_ID:
        return "tun-id";
    default:
        break;
    }
    return "";
}

char *
of131_table_features_dump(of_flow_tbl_props_t *prop)
{
    char *pbuf, *buf;
    size_t len = 0;
    int bit = 0;

    if (!prop) {
        c_log_err("%s: No table props", FN);
        return NULL;
    }

    pbuf =  calloc(1, OF_DUMP_TBL_FEAT_SZ);
    assert(pbuf);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "Instructions: ");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
    for (bit = 0; bit <= OFPIT_METER; bit++) {
        if (1<<bit & prop->bm_inst) {
            buf = of_inst_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "Instructions-Miss: ");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
    for (bit = 0; bit <= OFPIT_METER; bit++) {
        if (1<<bit & prop->bm_inst) {
            buf = of_inst_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "next-table: ");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
    for (bit = 0; bit <= 254; bit++) {
        if (GET_BIT_IN_32MASK(prop->bm_next_tables, bit)) {
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                            "%d ", bit);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "next-table-miss: ");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
    for (bit = 0; bit <= 254; bit++) {
        if (GET_BIT_IN_32MASK(prop->bm_next_tables_miss, bit)) {
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                            "%d ", bit);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);


    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "write-actions: ");
    for (bit = 0; bit < OFPAT131_POP_PBB; bit++) {
        if (1<<bit & prop->bm_wr_actions) {
            buf = of131_act_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "write-actions-miss: ");
    for (bit = 0; bit < OFPAT131_POP_PBB; bit++) {
        if (1<<bit & prop->bm_wr_actions_miss) {
            buf = of131_act_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "apply-actions: ");
    for (bit = 0; bit < OFPAT131_POP_PBB; bit++) {
        if (1<<bit & prop->bm_app_actions) {
            buf = of131_act_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "apply-action-miss: ");
    for (bit = 0; bit < OFPAT131_POP_PBB; bit++) {
        if (1<<bit & prop->bm_app_actions_miss) {
            buf = of131_act_type_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "set-field: ");
    for (bit = 0; bit < OFPXMT_OFB_IPV6_EXTHDR; bit++) {
        if (GET_BIT_IN_32MASK(prop->bm_wr_set_field, bit)) {
            buf = of131_oxm_field_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "set-field-miss: ");
    for (bit = 0; bit < OFPXMT_OFB_IPV6_EXTHDR; bit++) {
        if (GET_BIT_IN_32MASK(prop->bm_wr_set_field_miss, bit)) {
            buf = of131_oxm_field_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "apply-set-field: ");
    for (bit = 0; bit < OFPXMT_OFB_IPV6_EXTHDR; bit++) {
        if (GET_BIT_IN_32MASK(prop->bm_app_set_field, bit)) {
            buf = of131_oxm_field_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "apply-set-field-miss: ");
    for (bit = 0; bit < OFPXMT_OFB_IPV6_EXTHDR; bit++) {
        if (GET_BIT_IN_32MASK(prop->bm_app_set_field_miss, bit)) {
            buf = of131_oxm_field_to_name(bit);
            len += snprintf(pbuf + len,
                            OF_DUMP_TBL_FEAT_SZ - len - 1,
                             "%s ", buf);
            assert(len < OF_DUMP_TBL_FEAT_SZ - 1);
        }
    }
    len += snprintf(pbuf + len,
                    OF_DUMP_TBL_FEAT_SZ - len - 1,
                    "\r\n");
    assert(len < OF_DUMP_TBL_FEAT_SZ - 1);

    return pbuf;
}

bool
of131_switch_supports_group_stats(uint32_t cap)
{
    return cap & OFPC131_GROUP_STATS;
}

bool
of131_switch_supports_flow_stats(uint32_t cap)
{
    return cap & OFPC131_FLOW_STATS;
}

bool
of131_switch_supports_table_stats(uint32_t cap)
{
    return cap & OFPC131_TABLE_STATS;
}

static struct cbuf *
of13_14_prep_group_stat_req(uint32_t group_id, uint8_t version)
{
    struct cbuf *b;
    struct ofp_group_stats_request *ofp_gsr; 
    struct ofp_multipart_request *ofp_mr;

    b = of13_14_prep_mpart_msg(OFPMP_GROUP, 0, sizeof(*ofp_gsr), version);

    ofp_mr = CBUF_DATA(b);
    ofp_gsr = ASSIGN_PTR(ofp_mr->body); 
    ofp_gsr->group_id = htonl(group_id);

    return b;
}

struct cbuf *
of131_prep_group_stat_req(uint32_t group_id)
{
    struct cbuf *b;
    b = of13_14_prep_group_stat_req(group_id, OFP_VERSION_131);
    return b;
}

struct cbuf *
of140_prep_group_stat_req(uint32_t group_id)
{
    struct cbuf *b;
    b = of13_14_prep_group_stat_req(group_id, OFP_VERSION_140);
    return b;
}

static struct cbuf *
of13_14_prep_meter_stat_req(uint32_t meter_id, uint8_t version)
{
    struct cbuf *b;
    struct ofp_meter_multipart_request *ofp_mmr; 
    struct ofp_multipart_request *ofp_mr;

    b = of13_14_prep_mpart_msg(OFPMP_METER, 0, sizeof(*ofp_mmr), version);

    ofp_mr = CBUF_DATA(b);
    ofp_mmr = ASSIGN_PTR(ofp_mr->body); 
    ofp_mmr->meter_id = htonl(meter_id);

    return b;
}

struct cbuf *
of131_prep_meter_stat_req(uint32_t meter_id)
{
    struct cbuf *b;
    b = of13_14_prep_meter_stat_req(meter_id, OFP_VERSION_131);
    return b;
}

struct cbuf *
of140_prep_meter_stat_req(uint32_t meter_id)
{
    struct cbuf *b;
    b = of13_14_prep_meter_stat_req(meter_id, OFP_VERSION_140);
    return b;
}

static struct cbuf *
of13_14_prep_meter_config_req(uint32_t meter_id, uint8_t version)
{
    struct cbuf *b;
    struct ofp_meter_multipart_request *ofp_mmr; 
    struct ofp_multipart_request *ofp_mr;

    b = of13_14_prep_mpart_msg(OFPMP_METER_CONFIG, 0, sizeof(*ofp_mmr),
            version);

    ofp_mr = CBUF_DATA(b);
    ofp_mmr = ASSIGN_PTR(ofp_mr->body); 
    ofp_mmr->meter_id = htonl(meter_id);

    return b;
}

struct cbuf *
of131_prep_meter_config_req(uint32_t meter_id)
{
    struct cbuf *b;
    b = of13_14_prep_meter_config_req(meter_id, OFP_VERSION_131);
    return b;
}

struct cbuf *
of140_prep_meter_config_req(uint32_t meter_id)
{
    struct cbuf *b;
    b = of13_14_prep_meter_config_req(meter_id, OFP_VERSION_140);
    return b;
}

static struct cbuf *
of13_14_prep_port_stat_req(uint32_t port_no, uint8_t version)
{
    struct cbuf *b;
    struct ofp131_port_stats_request *ofp_psr; 
    struct ofp_multipart_request *ofp_mr;

    b = of13_14_prep_mpart_msg(OFPMP_PORT_STATS, 0, sizeof(*ofp_psr), version);

    ofp_mr = CBUF_DATA(b);
    ofp_psr = ASSIGN_PTR(ofp_mr->body); 
    ofp_psr->port_no = htonl(port_no);

    return b;
}

struct cbuf *
of131_prep_port_stat_req(uint32_t port_no)
{
    struct cbuf *b;
    b = of13_14_prep_port_stat_req(port_no, OFP_VERSION_131);
    return b;
}

struct cbuf *
of140_prep_port_stat_req(uint32_t port_no)
{
    struct cbuf *b;
    b = of13_14_prep_port_stat_req(port_no, OFP_VERSION_140);
    return b;
}

struct cbuf *
of131_prep_q_get_config(uint32_t port_no)
{
    struct cbuf *b;
    struct ofp131_queue_get_config_request *ofp_gcf;

    b = of131_prep_msg(sizeof(*ofp_gcf), OFPT131_QUEUE_GET_CONFIG_REQUEST, 0);
    ofp_gcf = CBUF_DATA(b);
    ofp_gcf->port = htonl(port_no);

    return b;
}

static char *
of131_dump_error_msg(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    struct ofp_error_msg *ofp_err = ASSIGN_PTR(ofp);
    char *err_type = NULL;
    char *err_code = NULL;
    char *pbuf;
    int len = 0;

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp->length) < sizeof(*ofp_err)) {
        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP error");
        assert(len < OF_DUMP_MSG_SZ - 1);
        return pbuf;
    }

    switch (htons(ofp_err->type)) {
    case OFPET131_HELLO_FAILED:
        err_type = "hello failed";
        switch (htons(ofp_err->code)) {
        case OFPHFC_INCOMPATIBLE:
            err_code = "incompatible";
            break;
        case OFPHFC_EPERM:
            err_code = "permission error";
            break;
        }
        break;
    case OFPET131_BAD_REQUEST:
        err_type = "bad request"; 
        switch (htons(ofp_err->code)) {
        case OFPBRC131_BAD_VERSION:
            err_code = "version";
            break;
        case OFPBRC131_BAD_TYPE:
            err_code = "bad type";
            break;
        case OFPBRC131_BAD_MULTIPART:
            err_code = "bad multipart";
            break;
        case OFPBRC131_BAD_EXPERIMENTER:
            err_code = "bad experimenter";
            break;
        case OFPBRC131_BAD_EXP_TYPE:
            err_code = "bad exp type";
            break;
        case OFPBRC131_EPERM:
            err_code = "permission";
            break;
        case OFPBRC131_BAD_LEN:
            err_code = "bad len";
            break;
        case OFPBRC131_BUFFER_EMPTY:
            err_code = "buffer empty";
            break;
        case OFPBRC131_BUFFER_UNKNOWN:
            err_code = "buffer unknown";
            break;
        case OFPBRC131_BAD_TABLE_ID:
            err_code = "bad table id";
            break;
        case OFPBRC131_IS_SLAVE:
            err_code = "slave";
            break;
        case OFPBRC131_BAD_PORT:
            err_code = "bad port";
            break;
        case OFPBRC131_BAD_PACKET:
            err_code = "bad packet";
            break;
        case OFPBRC131_MULTIPART_BUFFER_OVERFLOW:
            err_code = "mpart buffer overflow";
            break;
        default:
            break;
        }
        break;
    case OFPET131_BAD_ACTION:
        err_type = "bad action";
        switch (htons(ofp_err->code)) {
        case OFPBAC131_BAD_TYPE:
            err_code = "bad type";
            break;
        case OFPBAC131_BAD_LEN:
            err_code = "bad len";
            break;
        case OFPBAC131_BAD_EXPERIMENTER:
            err_code = "bad experimenter";
            break;
        case OFPBAC131_BAD_EXP_TYPE:
            err_code = "bad exp type";
            break;
        case OFPBAC131_BAD_OUT_PORT:
            err_code = "bad outport";
            break;
        case OFPBAC131_BAD_ARGUMENT:
            err_code = "bad arg";
            break;
        case OFPBAC131_EPERM:
            err_code = "eperm";
            break; 
        case OFPBAC131_TOO_MANY:
            err_code = "too many";
            break;
        case OFPBAC131_BAD_QUEUE:
            err_code = "bad queue";
            break;
        case OFPBAC131_BAD_OUT_GROUP:
            err_code = "bad output group";
            break;
        case OFPBAC131_MATCH_INCONSISTENT:
            err_code = "match consistent";
            break;
        case OFPBAC131_UNSUPPORTED_ORDER:
            err_code = "unsupp order";
            break;
        case OFPBAC131_BAD_TAG:
            err_code = "bad tag";
            break;
        case OFPBAC131_BAD_SET_TYPE:
            err_code = "bad set type";
            break;
        case OFPBAC131_BAD_SET_LEN:
            err_code = "bad set len";
            break;
        case OFPBAC131_BAD_SET_ARGUMENT: 
            err_code = "bad set arg";
            break;
        default:
            break;
        } 
        break;
    case OFPET131_BAD_INSTRUCTION:
        err_type = "bad instruction";
        switch (htons(ofp_err->code)) {
        case OFPBIC131_UNKNOWN_INST:
            err_code = "unknown inst";
            break;
        case OFPBIC131_UNSUP_INST:
            err_code = "unsup inst";
            break;
        case OFPBIC131_BAD_TABLE_ID:
            err_code = "bad table id";
            break;
        case OFPBIC131_UNSUP_METADATA:
            err_code = "unsup metadata";
            break;
        case OFPBIC131_UNSUP_METADATA_MASK:
            err_code = "unsup metadata";
            break;
        case OFPBIC131_BAD_EXPERIMENTER:
            err_code = "bad experimenter";
            break;
        case OFPBIC131_BAD_EXP_TYPE:
            err_code = "bad exp type";  
            break;
        case OFPBIC131_BAD_LEN:
            err_code = "bad len";
            break;
        case OFPBIC131_EPERM:
            err_code = "eperm";
            break;
        default:
            break;
        }
        break;
    case OFPET131_BAD_MATCH:
        err_type = "bad match";
        switch (htons(ofp_err->code)) {
        case OFPBMC131_BAD_TYPE: 
            err_code = "bad type";
            break;
        case OFPBMC131_BAD_LEN:
            err_code = "bad len";
            break;
        case OFPBMC131_BAD_TAG:
            err_code = "bad tag";
            break;
        case OFPBMC131_BAD_DL_ADDR_MASK:
            err_code = "bad dl addr mask";
            break;
        case OFPBMC131_BAD_NW_ADDR_MASK:
            err_code = "bad nw addr mask";
            break;
        case OFPBMC131_BAD_WILDCARDS:
            err_code = "bad wildcards";
            break;
        case OFPBMC131_BAD_FIELD:
            err_code = "bad field";
            break;
        case OFPBMC131_BAD_VALUE:
            err_code = "bad value";
            break;
        case OFPBMC131_BAD_MASK:
            err_code = "bad mask";
            break;
        case OFPBMC131_BAD_PREREQ:
            err_code = "bad prereq";
            break;
        case OFPBMC131_DUP_FIELD:
            err_code = "dup field";
            break;
        case OFPBMC131_EPERM:
            err_code = "eperm";
            break;
        default:
            break;
        }
        break;
    case OFPET131_FLOW_MOD_FAILED:
        err_type = "flow mod failed";
        switch (htons(ofp_err->code)) {
        case OFPFMFC131_UNKNOWN:
            err_code = "unknown";
            break;
        case OFPFMFC131_TABLE_FULL: /* Flow not added because table was full. */
            err_code = "table-full";
            break;
        case OFPFMFC131_BAD_TABLE_ID:
            err_code = "bad table id";
            break;
        case OFPFMFC131_OVERLAP:
            err_code = "overlap";
            break;
        case OFPFMFC131_EPERM:
            err_code = "eperm";
            break;
        case OFPFMFC131_BAD_TIMEOUT:
            err_code = "bad timeo";
            break;
        case OFPFMFC131_BAD_COMMAND:
            err_code = "bad command";
            break;
        case OFPFMFC131_BAD_FLAGS:
            err_code = "bad timeo";
            break;
        default:
            break;
        }
        break;
    case OFPET131_GROUP_MOD_FAILED:
        err_type = "group mod failed";
        switch (htons(ofp_err->code)) {
        case OFPGMFC131_GROUP_EXISTS:
            err_code = "group exists";
            break;
        case OFPGMFC131_INVALID_GROUP:
            err_code = "invalid group";
            break;
        case OFPGMFC131_WEIGHT_UNSUPPORTED:
            err_code = "weight unsupported";
            break;
        case OFPGMFC131_OUT_OF_GROUPS:
            err_code = "out of groups";
            break;
        case OFPGMFC131_OUT_OF_BUCKETS:
            err_code = "out of buckets";
            break;
        case OFPGMFC131_CHAINING_UNSUPPORTED:
            err_code = "chaining unsupp";
            break;
        case OFPGMFC131_WATCH_UNSUPPORTED:
            err_code = "watch unsupp";
            break;
        case OFPGMFC131_LOOP:
            err_code = "loop detected";
            break;
        case OFPGMFC131_UNKNOWN_GROUP:
            err_code = "unknown group";
            break;
        case OFPGMFC131_CHAINED_GROUP:
            err_code = "chained group";
            break;
        case OFPGMFC131_BAD_TYPE:
            err_code = "bad type";
            break;
        case OFPGMFC131_BAD_COMMAND:
            err_code = "bad command";
            break;
        case OFPGMFC131_BAD_BUCKET:
            err_code = "bad bucket";
            break;
        case OFPGMFC131_BAD_WATCH:
            err_code = "bad watch";
            break;
        case OFPGMFC131_EPERM:
            err_code = "eperm";
            break;
        default:
            break;     
        }
        break;
    case OFPET131_PORT_MOD_FAILED:
        err_type = "port mod failed";
        switch (htons(ofp_err->code)) {
        case OFPPMFC131_BAD_PORT:
            err_code = "bad port";
            break;
        case OFPPMFC131_BAD_HW_ADDR:
            err_code = "bad hw addr";
            break;
        case OFPPMFC131_BAD_CONFIG:
            err_code = "bad config";
            break;
        case OFPPMFC131_BAD_ADVERTISE:
            err_code = "bad config";
            break;
        case OFPPMFC131_EPERM:
            err_code = "eperm";
            break;
        default:
            break;
        }
        break;
    case OFPET131_TABLE_MOD_FAILED:
        err_type = "table mod failed";
        switch (htons(ofp_err->code)) {
        case OFPTMFC_BAD_TABLE: 
            err_code = "bad table";
            break;
        case OFPTMFC_BAD_CONFIG:
            err_code = "bad config";
            break;
        case OFPTMFC_EPERM:
            err_code = "eperm";
            break;
        default:
            break; 
        }     
        break;
    case OFPET131_QUEUE_OP_FAILED:
        err_type = "queue OP failed";
        switch (htons(ofp_err->code)) {
        case OFPQOFC131_BAD_PORT:
            err_code = "bad port";
            break;
        case OFPQOFC131_BAD_QUEUE:
            err_code = "bad queue";
            break;
        case OFPQOFC131_EPERM:
            err_code = "eperm";
            break;
        default:
            break;
        }
        break;
    case OFPET131_SWITCH_CONFIG_FAILED:
        err_type = "switch config failed";
        switch (htons(ofp_err->code)) {
        case OFPSCFC_BAD_FLAGS:
            err_code = "bad flags";
            break;
        case OFPSCFC_BAD_LEN:
            err_code = "bad len";
            break;
        case OFPSCFC_EPERM:
            err_code = "eperm";
            break;
        default:
            break;
        }
        break;
    case OFPET131_ROLE_REQUEST_FAILED:
        err_type = "role request";
        switch (htons(ofp_err->code)) {
        case OFPRRFC_STALE:
            err_code = "stale";
            break;
        case OFPRRFC_UNSUP:
            err_code = "unsup";
            break;
        case OFPRRFC_BAD_ROLE:
            err_code = "bad role";
            break;
        default:
            break;
        }
        break;
    case OFPET131_METER_MOD_FAILED:
        err_type = "meter-mod failed";
        switch (htons(ofp_err->code)) {
        case OFPMMFC_UNKNOWN:
            err_code = "unknown";
            break;
        case OFPMMFC_METER_EXISTS:
            err_code = "meter exists";
            break;
        case OFPMMFC_INVALID_METER:
            err_code = "invalid meter";
            break;
        case OFPMMFC_UNKNOWN_METER:
            err_code = "unknown";
            break;
        case OFPMMFC_BAD_COMMAND:
            err_code = "bad command";
            break;
        case OFPMMFC_BAD_FLAGS:
            err_code = "bad flags";
            break;
        case OFPMMFC_BAD_RATE:
            err_code = "bad rate";
            break;
        case OFPMMFC_BAD_BURST:
            err_code = "bad burst";
            break;
        case OFPMMFC_BAD_BAND:
            err_code = "bad band";
            break;
        case OFPMMFC_BAD_BAND_VALUE:
            err_code = "bad band value";
            break;
        case OFPMMFC_OUT_OF_METERS:
            err_code = "out of meters";
            break;
        case OFPMMFC_OUT_OF_BANDS:
            err_code = "out of bands";
            break;
        default:
            break;
        }
        break;
    case OFPET131_TABLE_FEATURES_FAILED:
        err_type = "table features failed";
        switch (htons(ofp_err->code)) {
        case OFPTFFC_BAD_TABLE:
            err_code = "bad table";
            break;
        case OFPTFFC_BAD_METADATA:
            err_code = "bad metadata";
            break;
        case OFPTFFC_BAD_TYPE:
            err_code = "bad type";
            break;
        case OFPTFFC_BAD_LEN:
            err_code = "bad len";
            break;
        case OFPTFFC_BAD_ARGUMENT:
            err_code = "bad arg";
            break;
        case OFPTFFC_EPERM:
            err_code = "eperm";
            break;
        default:
            break;
        }
        break;
    case OFPET131_EXPERIMENTER:
        err_type = "experimenter error";
        break;
    default:
        break;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP error type %s code %s", err_type, err_code);
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
}

static char *
of131_dump_header_msg(struct ofp_header *ofp, ssize_t tot_len UNUSED,
                      char *type)
{
    char *pbuf;
    int len = 0;

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp->length) < sizeof(*ofp)) {
        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP %s", type);
        assert(len < OF_DUMP_MSG_SZ - 1);
        return pbuf;
    } 

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP %s", type);
    assert(len < OF_DUMP_MSG_SZ - 1);

    return pbuf;
}

static char *
of131_dump_feat_reply_msg(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf;
    int len = 0;
    struct ofp131_switch_features *osf = ASSIGN_PTR(ofp);

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp->length) < sizeof(*osf)) {
        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP feature reply");
        assert(len < OF_DUMP_MSG_SZ - 1);
        return pbuf;
    } 

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP feature reply: dpid 0x%llx nbufs %lu n_tables %d"
                    " aux_id %d cap 0x%08lx", 
                    U642ULL(ntohll(osf->datapath_id)),
                    U322UL(ntohl(osf->n_buffers)),
                    osf->n_tables,
                    osf->auxiliary_id,
                    U322UL(ntohl(osf->capabilities)));
    assert(len < OF_DUMP_MSG_SZ - 1);

    return pbuf;
}

static char *
of131_dump_config_msg(struct ofp_header *ofp, ssize_t tot_len UNUSED,
                      char *type)
{
    char *pbuf;
    int len = 0;
    struct ofp_switch_config *osc = ASSIGN_PTR(ofp);

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp->length) < sizeof(*osc)) {
        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP config %s", type);
        assert(len < OF_DUMP_MSG_SZ - 1);
        return pbuf;
    } 

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP config %s: flags 0x%x miss_send_len %hu",
                    type, ntohs(osc->flags), ntohs(osc->miss_send_len));
    assert(len < OF_DUMP_MSG_SZ - 1);

    return pbuf;
}

static char *
of131_dump_packet_in(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf;
    int len = 0, i = 0;
    struct ofp131_packet_in *opi = ASSIGN_PTR(ofp);
    char *str = NULL;
    struct flow fl;
    struct flow mask;
    size_t pkt_len, pkt_ofs;
    uint8_t *data;
    ssize_t match_len;

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    match_len = C_ALIGN_8B_LEN(htons(opi->match.length)); /* Aligned match-length */
    match_len -= sizeof(opi->match);

    if (ntohs(opi->header.length) < sizeof(*opi) + match_len || 
        of131_ofpx_match_to_flow(&opi->match, &fl, &mask)) {
        goto malformed;
    }

    pkt_ofs = (sizeof(*opi) + match_len + 2);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    data = INC_PTR8(opi, pkt_ofs);

    str = of_dump_flow_generic(&fl, &mask);

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP packet-in : buf-id 0x%lx table-id %d cookie 0x%llx " 
                    "pkt-len %d\n",
                    U322UL(ntohl(opi->buffer_id)),
                    opi->table_id, U642ULL(ntohll(opi->cookie)),
                    (int)pkt_len);
    assert(len < OF_DUMP_MSG_SZ - 1);

    if (str) {
        len += snprintf(pbuf + len,
                        OF_DUMP_MSG_SZ - len - 1,
                        "\t%s", str);
        assert(len < OF_DUMP_MSG_SZ - 1);
        free(str);
    }

    len += snprintf(pbuf + len,
                        OF_DUMP_MSG_SZ - len - 1,
                        "\tPacket-dump(First 64B):");
    assert(len < OF_DUMP_MSG_SZ - 1);

    for (i = 0; i < 64 && pkt_len; i++) {
        len += snprintf(pbuf + len,
                        OF_DUMP_MSG_SZ - len - 1,
                        "%x", *data++);
        assert(len < OF_DUMP_MSG_SZ - 1);
        pkt_len--;
    } 
    return pbuf;

malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP packet in");
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
}

static char *
of131_dump_port_desc(struct ofp131_port *port)
{
    char *pbuf;
    char name[OFP_MAX_PORT_NAME_LEN];

    pbuf =  calloc(1, OF_DUMP_PORT_DESC_SZ);
    if (!pbuf) return NULL;

    memcpy(name, port->name, OFP_MAX_PORT_NAME_LEN);
    name[OFP_MAX_PORT_NAME_LEN-1] ='\0';
    snprintf(pbuf, OF_DUMP_PORT_DESC_SZ - 1,
             "port-no %lu mac-addr 0x%02x:%02x:%02x:%02x:%02x:%02x"
             " name %s config 0x%lx state 0x%lx curr 0x%lx adv 0x%lx"
             " supp 0x%lx curr-speed 0x%lx max-speed 0x%lx",
             U322UL(ntohl(port->port_no)), port->hw_addr[0],
             port->hw_addr[1], port->hw_addr[2], port->hw_addr[3],
             port->hw_addr[4], port->hw_addr[5], name,
             U322UL(ntohl(port->config)), U322UL(ntohl(port->state)),
             U322UL(ntohl(port->curr)), U322UL(ntohl(port->advertised)),
             U322UL(ntohl(port->supported)), U322UL(ntohl(port->curr_speed)),
             U322UL(ntohl(port->max_speed)));
    return pbuf;
}

static char *
of131_dump_port_status(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf, *port_str;
    int len = 0;
    struct ofp131_port_status *opp = ASSIGN_PTR(ofp);

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(opp->header.length) < sizeof(*opp)) {
        goto malformed;
    }

    port_str = of131_dump_port_desc(&opp->desc); 
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP port-status reason %d port-dest-%s",
                    opp->reason, port_str);
    if (port_str) free(port_str);
    return pbuf;

malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP port-status");
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
} 

static char *
of131_dump_packet_out(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf, *act_str = NULL;
    int len = 0;
    struct ofp131_packet_out *out = ASSIGN_PTR(ofp);

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(out->header.length) < sizeof(*out) + ntohs(out->actions_len)) {
        goto malformed;
    }

    act_str =  of131_dump_actions(out->actions, ntohs(out->actions_len), true);
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP packet-out: buffer-id 0x%lx in-port %lu"
                    " actions:%s",
                    U322UL(ntohl(out->buffer_id)),
                    U322UL(ntohl(out->in_port)),
                    act_str);
    if (act_str) free(act_str);
    return pbuf;
malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP packet in");
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
}

static char *
of131_dump_flow_removed(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf;
    struct ofp131_flow_removed *ofr = ASSIGN_PTR(ofp);
    char *str = NULL;
    struct flow fl;
    struct flow mask;
    int len = 0;

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp->length) < 
        (sizeof(*ofr) + C_ALIGN_8B_LEN(htons(ofr->match.length))) ||
        of131_ofpx_match_to_flow(&ofr->match, &fl, &mask)) {
        goto malformed;
    }

    str = of_dump_flow_generic(&fl, &mask);
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP flow-removed : cookie 0x%llx priority %hu" 
                    " reason %d table-id %d life-secs %lu life-nsecs %lu"
                    " itimeo %d htimeo %d pkt-count %llu byte-count %llu",
                    U642ULL(ntohll(ofr->cookie)), ntohs(ofr->priority),
                    ofr->reason, ofr->table_id,
                    U322UL(ntohl(ofr->duration_sec)),
                    U322UL(ntohl(ofr->duration_nsec)),
                    ntohs(ofr->idle_timeout), ntohs(ofr->hard_timeout),
                    U642ULL(ntohll(ofr->packet_count)),
                    U642ULL(ntohll(ofr->byte_count)));
    assert(len < OF_DUMP_MSG_SZ - 1);

    if (str) {
        len += snprintf(pbuf + len,
                        OF_DUMP_MSG_SZ - len - 1,
                        "   Flow-match: %s\n", str);
        assert(len < OF_DUMP_MSG_SZ - 1);
        free(str);
    }

    return pbuf;

malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP flow removed");
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
}

static char *
of131_dump_flow_mod(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf, *inst_str = NULL, *fl_str = NULL;
    int len = 0;
    struct ofp131_flow_mod *ofm = ASSIGN_PTR(ofp);
    ssize_t match_len = 0, ins_len = 0;
    struct flow fl, mask;

    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    match_len = C_ALIGN_8B_LEN(htons(ofm->match.length));
    match_len -= sizeof(ofm->match);
    if (ntohs(ofm->header.length) < sizeof(*ofm) + match_len ||
        of131_ofpx_match_to_flow(&ofm->match, &fl, &mask)) {
        goto malformed;
    }

    ins_len = ntohs(ofm->header.length) - (sizeof(*ofm) + match_len);
    if (ins_len) {
        inst_str = of131_dump_actions(INC_PTR8(ofm, sizeof(*ofm) + match_len),
                                      ins_len, false);
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP flow-mod: cookie 0x%llx cookie-mask 0x%llx\n"
                    "\ttable-id %d command %d prio %hu oport %lu ogrp %lu"
                    " itimeo %d htimeo %d buffer-id 0x%lx flags 0x%x\n",
                    U642ULL(ntohll(ofm->cookie)),
                    U642ULL(ntohll(ofm->cookie_mask)),
                    ofm->table_id, ofm->command,
                    ntohs(ofm->priority),
                    U322UL(ntohl(ofm->out_port)),
                    U322UL(ntohl(ofm->out_group)),
                    ntohs(ofm->idle_timeout), ntohs(ofm->hard_timeout),
                    U322UL(ntohl(ofm->buffer_id)),
                    ntohs(ofm->flags));
    assert(len < OF_DUMP_MSG_SZ - 1);

    fl_str = of_dump_flow_generic(&fl, &mask);
    if (fl_str) {
        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "\t%s", fl_str);
        assert(len < OF_DUMP_MSG_SZ - 1);
        free(fl_str);
    }

    if (inst_str) {
        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "\t%s", inst_str);
        assert(len < OF_DUMP_MSG_SZ - 1);
        free(inst_str);
    }

    return pbuf;

malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP flow mod");
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
}

static char *
of131_dump_group_mod(struct ofp_header *ofp, ssize_t tot_len)
{
    char *pbuf;
    int len = 0;
    struct ofp_group_mod *ofg = ASSIGN_PTR(ofp);
    struct ofp_bucket *ofp_b;
    ssize_t bkt_len = 0;
    size_t bkt_off = 0;
    int  i = 0;
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    tot_len = ntohs(ofg->header.length);
    if (tot_len < sizeof(*ofg)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP group-mod: command %hu type %d group-id %lu\n",
                    ntohs(ofg->command), ofg->type, 
                    U322UL(ntohl(ofg->group_id)));
    assert(len < OF_DUMP_MSG_SZ - 1);
               
    bkt_len = tot_len - sizeof(*ofg);
    tot_len -= sizeof(*ofg);

    while (bkt_len >= sizeof(*ofp_b)) {
        char *act_str = NULL;

        if (i > 32) break;

        ofp_b = ASSIGN_PTR(INC_PTR8(ofg->buckets, bkt_off));
        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "\tBucket %d: Weight %hu watch-port %lu watch-group %lu\n",
                    i++, ntohs(ofp_b->weight),
                    U322UL(ntohl(ofp_b->watch_port)),
                    U322UL(ntohl(ofp_b->watch_group)));    
        assert(len < OF_DUMP_MSG_SZ - 1);

        act_str = of131_dump_actions(ofp_b->actions,
                                 ntohs(ofp_b->len) - sizeof(*ofp_b), true);
        if (act_str) {
            len += snprintf(pbuf + len,
                        OF_DUMP_MSG_SZ - len - 1,
                        "\tActions: %s", act_str);
            assert(len < OF_DUMP_MSG_SZ - 1);
            free(act_str); 
        }

        bkt_off += ntohs(ofp_b->len);
        bkt_len -= ntohs(ofp_b->len);
    }

    return pbuf;

malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP group mod");
    return pbuf;
} 

static char *
of131_dump_port_mod(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf;
    int len = 0;
    struct ofp131_port_mod *ofpm = ASSIGN_PTR(ofp);
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofpm->header.length) < sizeof(*ofpm)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP port-mod: port-no %lu mac_addr "
                    "0x%02X:%02X:%02X:%02X:%02X:%02x config 0x%lx"
                    " mask 0x%lx adv 0x%lx",
                    U322UL(ntohl(ofpm->port_no)), ofpm->hw_addr[0],
                    ofpm->hw_addr[1],ofpm->hw_addr[2], ofpm->hw_addr[3],
                    ofpm->hw_addr[4],ofpm->hw_addr[5],
                    U322UL(ntohl(ofpm->config)), U322UL(ntohl(ofpm->mask)),
                    U322UL(ntohl(ofpm->advertise)));
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP port mod");
    return pbuf;
} 

static char *
of131_dump_table_mod(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf;
    int len = 0;
    struct ofp_table_mod *ofptm = ASSIGN_PTR(ofp);
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofptm->header.length) < sizeof(*ofptm)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP table-mod: table-id %d config 0x%lx",
                    ofptm->table_id, U322UL(ntohl(ofptm->config)));
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP table mod");
    return pbuf;
}

static char *
of131_dump_mpart(struct ofp_header *ofp, ssize_t tot_len UNUSED,
                 char *type)
{
    char *pbuf;
    int len = 0;
    struct ofp_multipart_request *ofp_mr = ASSIGN_PTR(ofp);
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp_mr->header.length) < sizeof(*ofp_mr)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP mpart-%s: type %hu flags 0x%x body-len %lu",
                    type, ntohs(ofp_mr->type),ntohs(ofp_mr->flags),
                    (unsigned long)(ntohs(ofp_mr->header.length) 
                        - sizeof(*ofp_mr)));
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP mpart request");
    return pbuf;
}

static char *
of131_dump_queue_conf_req(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf;
    int len = 0;
    struct ofp131_queue_get_config_request *ofp_qg = ASSIGN_PTR(ofp);
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp_qg->header.length) < sizeof(*ofp_qg)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP queue-conf request port %lu",
                    U322UL(ntohl(ofp_qg->port)));
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed queue-conf request");
    return pbuf;
}

static char *
of131_dump_queue_conf_reply(struct ofp_header *ofp, ssize_t tot_len UNUSED)
{
    char *pbuf;
    int len = 0;
    struct ofp131_queue_get_config_reply *ofp_qg = ASSIGN_PTR(ofp);
    struct ofp131_packet_queue *q;
    ssize_t q_len = 0;
    int q_off = 0;
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp_qg->header.length) < sizeof(*ofp_qg)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP queue-conf reply port %lu:",
                    U322UL(ntohl(ofp_qg->port)));
    assert(len < OF_DUMP_MSG_SZ - 1);

    q_len = ntohs(ofp_qg->header.length) -  sizeof(*ofp_qg);
    while (q_len >= sizeof(*q)) {
        q = ASSIGN_PTR(INC_PTR8(ofp_qg->queues, q_off));

        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "%lu ", U322UL(ntohl(q->queue_id)));
        if (len >= OF_DUMP_MSG_SZ - 1) break;

        q_off += ntohs(q->len);
        q_len -= ntohs(q->len);
    }
    return pbuf;
malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed queue-conf request");
    return pbuf;
}

static char *
of131_dump_role(struct ofp_header *ofp, ssize_t tot_len UNUSED,
                 char *type)
{
    char *pbuf;
    int len = 0;
    struct ofp_role_request *ofp_rr = ASSIGN_PTR(ofp);
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp_rr->header.length) < sizeof(*ofp_rr)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP role-%s: Role %lu gen-id 0x%llx",
                    type, U322UL(ntohl(ofp_rr->role)),
                    U642ULL(ntohll(ofp_rr->generation_id)));
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP role request");
    return pbuf;
}

static char *
of131_dump_async(struct ofp_header *ofp, ssize_t tot_len UNUSED,
                 char *type)
{
    char *pbuf;
    int len = 0;
    struct ofp_async_config *ofp_ac = ASSIGN_PTR(ofp);
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    if (ntohs(ofp_ac->header.length) < sizeof(*ofp_ac)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP async-%s: pin0 0x%lx pin1 0x%lx"
                    " ports0 0x%lx ports1 0x%lx"
                    " flowr0 0x%lx flowr1 0x%lx",
                    type, U322UL(ntohl(ofp_ac->packet_in_mask[0])),
                    U322UL(ntohl(ofp_ac->packet_in_mask[1])),
                    U322UL(ntohl(ofp_ac->port_status_mask[0])),
                    U322UL(ntohl(ofp_ac->port_status_mask[1])),
                    U322UL(ntohl(ofp_ac->flow_removed_mask[0])),
                    U322UL(ntohl(ofp_ac->flow_removed_mask[1])));
    assert(len < OF_DUMP_MSG_SZ - 1);
    return pbuf;
malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP async %s", type);
    return pbuf;
}

static char *
of131_dump_meter_mod(struct ofp_header *ofp, ssize_t tot_len)
{
    char *pbuf;
    int len = 0;
    struct ofp_meter_mod *ofm = ASSIGN_PTR(ofp);
    struct ofp_meter_band_header *ofp_b;
    ssize_t band_len = 0;
    size_t band_off = 0;
    int i = 0;
    
    pbuf =  calloc(1, OF_DUMP_MSG_SZ);
    if (!pbuf) return NULL;

    tot_len = ntohs(ofm->header.length);
    if (tot_len < sizeof(*ofm)) {
        goto malformed;
    }

    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "OFP meter-mod: command %hu flags 0x%x meter-id %lu\n",
                    ntohs(ofm->command), ntohs(ofm->flags),  
                    U322UL(ntohl(ofm->meter_id)));
    assert(len < OF_DUMP_MSG_SZ - 1);
               
    band_len = tot_len - sizeof(*ofm);

    while (band_len >= sizeof(*ofp_b)) {
        if (i > 32) break;

        ofp_b = ASSIGN_PTR(INC_PTR8(ofm->bands, band_off));
        len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "\tBand %d: type %hu len %hu rate %lu burst %lu\n",
                    i++, ntohs(ofp_b->type), ntohs(ofp_b->len),
                    U322UL(ntohl(ofp_b->rate)),
                    U322UL(ntohl(ofp_b->burst_size)));
        assert(len < OF_DUMP_MSG_SZ - 1);

        band_off += ntohs(ofp_b->len);
        band_len -= ntohs(ofp_b->len);
    }

    return pbuf;

malformed:
    len += snprintf(pbuf + len,
                    OF_DUMP_MSG_SZ - len - 1,
                    "Malformed OFP group mod");
    return pbuf;
} 

void
of131_dump_msg(struct cbuf *b, bool tx, uint64_t dpid)
{
    struct ofp_header *ofp = CBUF_DATA(b);
    ssize_t tot_len = b->len; 
    char *pbuf = NULL;
    char *str = tx ? "TX" : "RX";

    if (b->len < ntohs(ofp->length)) {
        c_log_err("%s: Buf len problem. Aborting parse", FN);
        return;
    }

    switch(ofp->type) {
    case OFPT131_HELLO:
        pbuf = of131_dump_header_msg(ofp, tot_len, "hello");
        break;
    case OFPT131_ERROR:
        pbuf = of131_dump_error_msg(ofp, tot_len);
        break;
    case OFPT131_ECHO_REQUEST:
        pbuf = of131_dump_header_msg(ofp, tot_len, "echo req");
        break;
    case OFPT131_ECHO_REPLY:
        pbuf = of131_dump_header_msg(ofp, tot_len, "echo reply");
        break;
    case OFPT131_EXPERIMENTER:
        pbuf = of131_dump_header_msg(ofp, tot_len, "experimenter");
        break;
    case OFPT131_FEATURES_REQUEST:
        pbuf = of131_dump_header_msg(ofp, tot_len, "feature request");
        break;
    case OFPT131_FEATURES_REPLY:
        pbuf = of131_dump_feat_reply_msg(ofp, tot_len);
        break;
    case OFPT131_GET_CONFIG_REQUEST: 
        pbuf = of131_dump_header_msg(ofp, tot_len, "config request");
        break;
    case OFPT131_GET_CONFIG_REPLY:
        pbuf = of131_dump_config_msg(ofp, tot_len, "reply"); 
        break;
    case OFPT131_SET_CONFIG:
        pbuf = of131_dump_config_msg(ofp, tot_len, "set");
        break;
    case OFPT131_PACKET_IN:
        pbuf = of131_dump_packet_in(ofp, tot_len);
        break;
    case OFPT131_FLOW_REMOVED:
        pbuf = of131_dump_flow_removed(ofp, tot_len);
        break;
    case OFPT131_PORT_STATUS:
        pbuf = of131_dump_port_status(ofp, tot_len);
        break;
    case OFPT131_PACKET_OUT:
        pbuf = of131_dump_packet_out(ofp, tot_len);
        break;
    case OFPT131_FLOW_MOD:
        pbuf = of131_dump_flow_mod(ofp, tot_len);
        break;
    case OFPT131_GROUP_MOD:
        pbuf = of131_dump_group_mod(ofp, tot_len);
        break;
    case OFPT131_PORT_MOD:
        pbuf = of131_dump_port_mod(ofp, tot_len);
        break;
    case OFPT131_TABLE_MOD:
        pbuf = of131_dump_table_mod(ofp, tot_len);
        break;
    case OFPT131_MULTIPART_REQUEST:
        pbuf = of131_dump_mpart(ofp, tot_len, "req");
        break;
    case OFPT131_MULTIPART_REPLY:
        pbuf = of131_dump_mpart(ofp, tot_len, "reply");
        break;
    case OFPT131_BARRIER_REQUEST:
        pbuf = of131_dump_header_msg(ofp, tot_len, "barrier req");
        break;
    case OFPT131_BARRIER_REPLY:
        pbuf = of131_dump_header_msg(ofp, tot_len, "barrier reply");
        break;
    case OFPT131_QUEUE_GET_CONFIG_REQUEST:
        pbuf = of131_dump_queue_conf_req(ofp, tot_len);
        break;
    case OFPT131_QUEUE_GET_CONFIG_REPLY: 
        pbuf = of131_dump_queue_conf_reply(ofp, tot_len);
        break;
    case OFPT131_ROLE_REQUEST:
        pbuf = of131_dump_role(ofp, tot_len, "request");
        break;
    case OFPT131_ROLE_REPLY:
        pbuf = of131_dump_role(ofp, tot_len, "reply");
        break;
    case OFPT131_GET_ASYNC_REQUEST:
        pbuf = of131_dump_header_msg(ofp, tot_len, "get async request");
        break;
    case OFPT131_GET_ASYNC_REPLY:
        pbuf = of131_dump_async(ofp, tot_len, "reply");
        break; 
    case OFPT131_SET_ASYNC:
        pbuf = of131_dump_async(ofp, tot_len, "set");
        break;
    case OFPT131_METER_MOD:
        pbuf = of131_dump_meter_mod(ofp, tot_len);
        break;
    default:
        break;
    }

    c_log_debug("[SWITCH] 0x%llx (%s): type %d len %hu xid 0x%lx",
                U642ULL(dpid), str, ofp->type, ntohs(ofp->length),
                U322UL(ntohl(ofp->xid)));
    if (pbuf) {
        c_log_debug("[OF-DUMP]: %s\n", pbuf);
        free(pbuf);
    }
}

/****************** Openflow1.4 constructors *************/

struct cbuf *
of140_prep_hello_msg(void)
{
    uint32_t v_bmap = htonl(0x32); 
    size_t hello_len = sizeof(struct ofp_hello) + 
                       C_ALIGN_8B_LEN(sizeof(struct ofp_hello_elem_versionbitmap) +
                       sizeof(v_bmap));
    struct cbuf *b;
    struct ofp_hello_elem_versionbitmap *ofp_hemv;

    b = of140_prep_msg(hello_len, OFPT140_HELLO, 0);
    ofp_hemv = (void *)(((struct ofp_hello *)(b->data))->elements);
    ofp_hemv->type = htons(OFPHET_VERSIONBITMAP);
    ofp_hemv->length = htons(sizeof(*ofp_hemv) + sizeof(v_bmap));
    
    ofp_hemv->bitmaps[0] = v_bmap;

    return b;
}

struct cbuf *
of140_prep_echo_msg(void)
{
    return of140_prep_msg(sizeof(struct ofp_header), OFPT140_ECHO_REQUEST, 0);
}

struct cbuf *
of140_prep_echo_reply_msg(uint32_t xid)
{
    return of140_prep_msg(sizeof(struct ofp_header), OFPT140_ECHO_REPLY, xid);
}

struct cbuf *
of140_prep_features_request_msg(void)
{
    return of140_prep_msg(sizeof(struct ofp_header), OFPT140_FEATURES_REQUEST, 0);
}

struct cbuf *
of140_prep_role_request_msg(uint32_t role, uint64_t gen_id)
{
    struct cbuf *b;
    struct ofp_role_request *ofp_rr;

    b = of140_prep_msg(sizeof(*ofp_rr), OFPT131_ROLE_REQUEST, 0);
    ofp_rr = (void *)(b->data);
    ofp_rr->role = htonl(role);
    ofp_rr->generation_id = htonll(gen_id);

    return b;
}


/*********************************************************/



char *
of_port_stats_dump(void *feat, size_t feat_len)
{
    char *pbuf;
    size_t len = 0;
    struct ofp_port_stats *ofp_ps = feat;

    if (feat_len != sizeof(*ofp_ps)) {
        c_log_err("%s: Can't dump size err", FN);
        return NULL;
    }
    pbuf =  calloc(1, OF_DUMP_PORT_STATS_SZ);
    assert(pbuf);
    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "Port No. %u\r\n", ntohs(ofp_ps->port_no));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Rx Packets:",
                    U642ULL(ntohll(ofp_ps->rx_packets)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Tx Packets:",
                    U642ULL(ntohll(ofp_ps->tx_packets)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Rx Bytes:",
                    U642ULL(ntohll(ofp_ps->rx_bytes)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu\r\n", "Tx Bytes:",
                    U642ULL(ntohll(ofp_ps->tx_bytes)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Rx Dropped:", 
                    U642ULL(ntohll(ofp_ps->rx_dropped)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "Tx Dropped:",
                    U642ULL(ntohll(ofp_ps->tx_dropped)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "RX Errors:",
                    U642ULL(ntohll(ofp_ps->rx_errors)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu\r\n", "Tx Errors:",
                    U642ULL(ntohll(ofp_ps->tx_errors)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "RxFrameErr:",
                    U642ULL(ntohll(ofp_ps->rx_frame_err)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "RxOverErr:",
                    U642ULL(ntohll(ofp_ps->rx_over_err)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu ", "RxCRCErr:",
                    U642ULL(ntohll(ofp_ps->rx_crc_err)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    len += snprintf(pbuf + len, OF_DUMP_PORT_STATS_SZ - len - 1,
                    "%12s%10llu\r\n", "Collisions:",
                    U642ULL(ntohll(ofp_ps->collisions)));

    assert(len < OF_DUMP_METER_FEAT_SZ-1);

    return pbuf;
}

void
ofp131_dump_port_details(char *string, uint32_t config, uint32_t state)
{
    if (config & OFPPC131_PORT_DOWN) {
        strcat(string, " DOWN");
    } else {
        strcat(string, " UP");
    }

    if (config & OFPPC131_NO_RECV) {
        strcat(string, " DROP");
    } else {
        strcat(string, " RECV");
    }

    if (config & OFPPC131_NO_FWD) {
        strcat(string, " NO-FWD");
    } else {
        strcat(string, " FWD");
    }
    if (config & OFPPC131_NO_PACKET_IN) {
        strcat(string, " NO-PKTIN");
    } else {
        strcat(string, " PKTIN");
    }

    if (!(state & OFPPS131_LINK_DOWN)) {
        strcat(string, " RUNNING");
    } 
    if (state & OFPPS131_LIVE) {
        strcat(string, " LIVE");
    } 
    if(state & OFPPS131_BLOCKED) {
        strcat(string, " BLOCKED");
    }
}

void 
ofp_dump_port_type(char *string, uint16_t type) 
{
    if(type == OFPPSPT_ETHERNET)
        strcat(string, " ETHERNET ");
    else
        strcat(string, " OPTICAL ");
}

void
ofp_dump_port_details(char *string, uint32_t config, uint32_t state)
{
    if (config & OFPPC_PORT_DOWN) {
        strcat(string, " DOWN");
    } else {
        strcat(string, " UP");
    }

    if (config & OFPPC_NO_RECV) {
        strcat(string, " DROP");
    } else {
        strcat(string, " RECV");
    }

    if (config & OFPPC_NO_FWD) {
        strcat(string, " NO-FWD");
    } else {
        strcat(string, " FWD");
    }
    if (config & OFPPC_NO_PACKET_IN) {
        strcat(string, " NO-PKTIN");
    } else {
        strcat(string, " PKTIN");
    }

    if (!(state & OFPPS_LINK_DOWN)) {
        strcat(string, " RUNNING");
    }
}


