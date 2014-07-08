/*
 *  mul_fabric_arp.c: Fabric proxy arping
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
#include "mul_fabric_common.h"

extern fab_struct_t *fab_ctx;


struct fab_pkt_out_params  {
    struct of_pkt_out_params of_parms;
    uint64_t dpid;
};

uint8_t fab_mac[ETH_ADDR_LEN] = { 0x0a, 0x0b, 0x0c, 0x0d, 0xe, 0xff }; 
uint8_t fab_bcast_mac[ETH_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; 

/**
 * fab_add_dhcp_tap_per_switch -
 *
 * Add a local flow for dhcp processing
 */
void
fab_add_dhcp_tap_per_switch(void *opq, uint64_t dpid)
{
    struct flow fl;
    struct flow mask;

    of_mask_set_dc_all(&mask);

    /* Add Flow to receive DHCP Packet type */
    memset(&fl, 0, sizeof(fl));
    fl.dl_type = htons(0x0800);
    of_mask_set_dl_type(&mask);

    memset(fl.dl_dst, 0xff, ETH_ADDR_LEN);
    of_mask_set_dl_dst(&mask);

    fl.ip.nw_dst = 0xffffffff;
    of_mask_set_nw_dst(&mask, 32);

    fl.nw_proto = 0x11;
    of_mask_set_nw_proto(&mask);

    mul_app_send_flow_add(FAB_APP_NAME, opq, dpid, &fl, &mask,
                          (uint32_t)-1, NULL, 0, 0, 0, C_FL_PRIO_DFL,
                          C_FL_ENT_LOCAL);
}


/**
 * fab_dhcp_relay_end_host -
 *
 * Relay dhcp packet to end host
 */
static void
fab_dhcp_relay_end_host(void *h_arg, void *v_arg UNUSED, void *parms_arg)
{
    fab_host_t                *host = h_arg;
    struct fab_pkt_out_params *f_parms = parms_arg;
    struct of_pkt_out_params  *parms = &f_parms->of_parms;
    struct ofp_action_output  *op_act = parms->action_list; 
    uint32_t                  in_port = parms->in_port;

    if (host->sw.port == in_port && host->sw.swid == f_parms->dpid) {
        return;
    }

    parms->in_port = ntohl(OF_NO_PORT);
    op_act->port = htons(host->sw.port);
    mul_app_send_pkt_out(NULL, host->sw.swid, parms);
    parms->in_port = in_port;
}


/**
 * fab_dhcp_rcv - 
 *
 * dhcp relay style processing 
 */
void
fab_dhcp_rcv(void *opq UNUSED, fab_struct_t *fab_ctx UNUSED, struct flow *fl,
             uint32_t in_port, uint8_t *raw, size_t pkt_len, uint64_t dpid)
{
    struct fab_pkt_out_params f_parms;
    struct of_pkt_out_params  *parms;
    struct mul_act_mdata      mdata;
    uint32_t                  oport = OF_NO_PORT;

    c_log_debug("%s: dhcp from 0x%llx port %u", FN,
                (unsigned long long)dpid, in_port);
    
    memset(&f_parms, 0, sizeof(f_parms));
    parms = &f_parms.of_parms;

    if (fl->dl_type != htons(ETH_TYPE_IP) ||
        memcmp(fl->dl_dst, fab_bcast_mac, ETH_ADDR_LEN) ||
        fl->ip.nw_dst != 0xffffffff || fl->nw_proto != 0x11 ||
        (fl->tp_dst == fl->tp_src) || 
        (fl->tp_dst != htons(0x43) && fl->tp_dst != htons(0x44)) || 
        (fl->tp_src != htons(0x43) && fl->tp_src != htons(0x44)))  {

        return;
    }

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, dpid);
    mul_app_action_output(&mdata, oport);
    parms->buffer_id = FAB_UNK_BUFFER_ID;
    parms->in_port = in_port;
    parms->action_list = mdata.act_base;
    parms->action_len = mul_app_act_len(&mdata);
    parms->data_len = pkt_len;
    parms->data = raw;
    f_parms.dpid = dpid;

    fab_loop_all_hosts(fab_ctx, fab_dhcp_relay_end_host, &f_parms);
    mul_app_act_free(&mdata);

    return;
}

#ifdef CONFIG_HAVE_PROXY_ARP

static void *
fab_mk_proxy_arp_reply(struct arp_eth_header *arp_req)
{
    uint8_t               *out_pkt;
    struct eth_header     *eth;
    struct arp_eth_header *arp_reply;

    out_pkt = fab_zalloc(sizeof(struct arp_eth_header) +
                         sizeof(struct eth_header));

    eth = (struct eth_header *)out_pkt;
    arp_reply = (struct arp_eth_header *)(eth + 1);
    
    memcpy(eth->eth_dst, arp_req->ar_sha, ETH_ADDR_LEN);
    memcpy(eth->eth_src, fab_mac, ETH_ADDR_LEN);
    eth->eth_type = htons(ETH_TYPE_ARP);

    arp_reply->ar_hrd = htons(ARP_HRD_ETHERNET);
    arp_reply->ar_pro = htons(ARP_PRO_IP); 
    arp_reply->ar_pln = IP_ADDR_LEN;
    arp_reply->ar_hln = ETH_ADDR_LEN;
    arp_reply->ar_op = htons(ARP_OP_REPLY);
    memcpy(arp_reply->ar_sha, fab_mac, ETH_ADDR_LEN);
    arp_reply->ar_spa = arp_req->ar_tpa;
    memcpy(arp_reply->ar_tha, arp_req->ar_sha, ETH_ADDR_LEN);
    arp_reply->ar_tpa = arp_req->ar_spa;

    return out_pkt; 
}

/**
 * fab_add_arp_tap_per_switch -
 *
 * Add a local flow for arp processing
 */
void
fab_add_arp_tap_per_switch(void *opq, uint64_t dpid)
{
    struct flow fl;
    struct flow mask;

    of_mask_set_dc_all(&mask);

    /* Add Flow to receive ARP Packet type */
    memset(&fl, 0, sizeof(fl));

    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);

    mul_app_send_flow_add(FAB_APP_NAME, opq, dpid, &fl, &mask,
                          (uint32_t)-1, NULL, 0, 0, 0, C_FL_PRIO_DFL,
                          C_FL_ENT_LOCAL);
}


void
fab_arp_rcv(void *opq UNUSED, fab_struct_t *fab_ctx UNUSED,
            struct flow *fl, uint32_t in_port,
            uint8_t *raw, uint64_t datapath_id)
{
    struct arp_eth_header     *arp;
    struct of_pkt_out_params  parms;
    struct mul_act_mdata      mdata;

    if (fl->dl_type != htons(ETH_TYPE_ARP)) {
        return;
    }

    /* Controller does all packet length and other validations
     * so we can ignore doing those
     */
    arp = (void *)(raw + sizeof(struct eth_header)  +
                   (fl->dl_vlan ? VLAN_HEADER_LEN : 0));

    /* Here we don't care  to learn a host from gratutious arp
     * as we will learn the host before arp_rcv()
     */
    if (arp->ar_pro != htons(ARP_PRO_IP) || 
        arp->ar_pln != IP_ADDR_LEN ||
        arp->ar_op != htons(ARP_OP_REQUEST ||
        (arp->ar_spa == arp->ar_tpa &&
        eth_addr_is_zero(arp->ar_tha)))) {
        return;
    }

    /* FIXME - Validate the source mac/ip credentials */ 

    memset(&parms, 0, sizeof(parms));

    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    mul_app_act_set_ctors(&mdata, datapath_id);
    mul_app_action_output(&mdata, in_port);
    parms.buffer_id = FAB_UNK_BUFFER_ID;
    parms.in_port = OF_NO_PORT;
    parms.action_list = mdata.act_base;
    parms.action_len = mul_app_act_len(&mdata);
    parms.data_len = sizeof(struct eth_header) + sizeof(struct arp_eth_header);
    parms.data = fab_mk_proxy_arp_reply(arp);
    mul_app_send_pkt_out(NULL, datapath_id, &parms);
    mul_app_act_free(&mdata);

    return;
}

#else

void
fab_add_arp_tap_per_switch(void *opq UNUSED, uint64_t dpid UNUSED)
{
}

void
fab_arp_rcv(void *opq, fab_struct_t *fab_ctx UNUSED,
            struct flow *fl, uint16_t in_port, uint8_t *raw)
{
}
#endif
