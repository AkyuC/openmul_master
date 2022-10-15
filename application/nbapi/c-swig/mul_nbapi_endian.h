/*
 *  mul_nbapi_endian.h: Mul Northbound Endian convert application headers
 *  Copyright (C) 2012-2014, Dipjyoti Saikia (dipjyoti.saikia@gmail.com) 
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


#ifndef __MUL_NBAPI_ENDIAN_H__
#define __MUL_NBAPI_ENDIAN_H__

#include "openflow-10.h"
#include "openflow-131.h"
#include "mul_app_interface.h"

static inline void 
nbapi_endian_convert_c_sw_port(struct c_sw_port *port, 
                               uint32_t (*convl)(uint32_t))
{
    port->port_no = convl(port->port_no);
    port->config = convl(port->config);
    port->state = convl(port->state);
    port->curr = convl(port->curr);
    port->advertised = convl(port->advertised);
    port->supported = convl(port->supported);
    port->peer = convl(port->peer);
}

static inline void
ntoh_c_sw_port(struct c_sw_port *port)
{
    nbapi_endian_convert_c_sw_port(port, ntohl);
}

static inline void
hton_c_sw_port(struct c_sw_port *port)
{
    nbapi_endian_convert_c_sw_port(port, htonl);
}

static inline void
nbapi_endian_convert_ofp_phy_port(struct ofp_phy_port *port,
                                  uint16_t (*convs)(uint16_t),
                                  uint32_t (*convl)(uint32_t))
{
    port->port_no = convs(port->port_no);
    port->config = convl(port->config);
    port->state = convl(port->state);
    port->curr = convl(port->curr);
    port->advertised = convl(port->advertised);
    port->supported = convl(port->supported);
    port->peer = convl(port->peer);
}

static inline void
ntoh_ofp_phy_port(struct ofp_phy_port *port)
{
    nbapi_endian_convert_ofp_phy_port(port,ntohs,ntohl);
}

static inline void
hton_ofp_phy_port(struct ofp_phy_port *port)
{
    nbapi_endian_convert_ofp_phy_port(port,htons,htonl);
}

static inline void
nbapi_endian_convert_ofp_header(struct ofp_header *header,
                                uint16_t (*convs)(uint16_t) UNUSED,
                                uint32_t (*convl)(uint32_t))
{
    header->xid = convl(header->xid);
}

static inline void
ntoh_ofp_header(struct ofp_header *header)
{
    nbapi_endian_convert_ofp_header(header,ntohs,ntohl);
}
static inline void
hton_ofp_header(struct ofp_header *header)
{
    nbapi_endian_convert_ofp_header(header,htons,htonl);
}

static inline void
nbapi_endian_convert_c_ofp_switch_add(struct c_ofp_switch_add *switch_info,
                                      uint16_t (*convs)(uint16_t),
                                      uint32_t (*convl)(uint32_t),
                                      uint64_t (*convll)(uint64_t))
{
    int i, n_ports = ((convs(switch_info->header.length)
                        - offsetof(struct ofp_switch_features, ports)) 
                            / sizeof(*switch_info->ports));

    switch_info->header.length = convs(switch_info->header.length);
    switch_info->datapath_id = convll(switch_info->datapath_id);
    switch_info->sw_alias = convl(switch_info->sw_alias);
    switch_info->n_buffers = convl(switch_info->n_buffers);
    switch_info->capabilities = convl(switch_info->capabilities);
    switch_info->actions = convl(switch_info->actions);
    for (i = 0; i < n_ports; i ++) {
        nbapi_endian_convert_c_sw_port(&switch_info->ports[i],convl);
    }
}

static inline void
ntoh_c_ofp_switch_add(struct c_ofp_switch_add *switch_info)
{
    nbapi_endian_convert_c_ofp_switch_add(switch_info, ntohs, ntohl, ntohll);
}

static inline void
hton_c_ofp_switch_add(struct c_ofp_switch_add *switch_info)
{
    nbapi_endian_convert_c_ofp_switch_add(switch_info, htons, htonl, htonll);
}

static inline void
nbapi_endian_convert_ofp_switch_features(struct ofp_switch_features *switch_info,
                                         uint16_t (*convs)(uint16_t),
                                         uint32_t (*convl)(uint32_t),
                                         uint64_t (*convll)(uint64_t))
{
    int i, n_ports = ((convs(switch_info->header.length)
                - offsetof(struct ofp_switch_features, ports))
            / sizeof(*switch_info->ports));

    nbapi_endian_convert_ofp_header(&switch_info->header,convs,convl);
    switch_info->datapath_id = convll(switch_info->datapath_id);
    switch_info->n_buffers = convl(switch_info->n_buffers);
    switch_info->capabilities = convl(switch_info->capabilities);
    switch_info->actions = convl(switch_info->actions);
    for (i = 0; i < n_ports; i ++) {
        nbapi_endian_convert_ofp_phy_port(&switch_info->ports[i],convs,convl);
    }
}

static inline void
ntoh_ofp_switch_features(struct ofp_switch_features *switch_info)
{
    nbapi_endian_convert_ofp_switch_features(switch_info,ntohs,ntohl,ntohll);
}
static inline void
hton_ofp_switch_features(struct ofp_switch_features *switch_info)
{
    nbapi_endian_convert_ofp_switch_features(switch_info,htons,htonl,htonll);
}

static inline void
nbapi_endian_convert_c_ofp_req_dpid_attr(struct c_ofp_req_dpid_attr *dpid_attr,
                                         uint64_t (*convll)(uint64_t))
{
    dpid_attr->datapath_id = convll(dpid_attr->datapath_id);
}

static inline void
ntoh_c_ofp_req_dpid_attr(struct c_ofp_req_dpid_attr *dpid_attr)
{
    nbapi_endian_convert_c_ofp_req_dpid_attr(dpid_attr,ntohll);
}

static inline void
hton_c_ofp_req_dpid_attr(struct c_ofp_req_dpid_attr *dpid_attr)
{
    nbapi_endian_convert_c_ofp_req_dpid_attr(dpid_attr,htonll);
}

static inline void
nbapi_endian_convert_c_ofp_switch_brief(struct c_ofp_switch_brief *switch_brief,
                                        uint32_t (*convl)(uint32_t),
                                        uint64_t (*convll)(uint64_t))
{
    nbapi_endian_convert_c_ofp_req_dpid_attr(&switch_brief->switch_id,convll);
    switch_brief->n_ports = convl(switch_brief->n_ports);
    switch_brief->state = convll(switch_brief->state);
}

static inline void
ntoh_c_ofp_switch_brief(struct c_ofp_switch_brief *switch_brief)
{
    nbapi_endian_convert_c_ofp_switch_brief(switch_brief,ntohl,ntohll);
}

static inline void
hton_c_ofp_switch_brief(struct c_ofp_switch_brief *switch_brief)
{
    nbapi_endian_convert_c_ofp_switch_brief(switch_brief,htonl,htonll);
}

static inline void
nbapi_endian_convert_flow(struct flow *fl,
                          uint16_t (*convs)(uint16_t),
                          uint32_t (*convl)(uint32_t),
                          uint64_t (*convll)(uint64_t))
{
    fl->in_port = convl(fl->in_port);
    fl->dl_vlan = convs(fl->dl_vlan);
    fl->dl_type = convs(fl->dl_type);
    fl->mpls_label = convl(fl->mpls_label);
    fl->tp_src = convs(fl->tp_src);
    fl->tp_dst = convs(fl->tp_dst);
    fl->ip.nw_src = convl(fl->ip.nw_src);
    fl->ip.nw_dst = convl(fl->ip.nw_dst);
    fl->tunnel_id = convll(fl->tunnel_id);
    fl->metadata =  convll(fl->metadata);
}

static inline void
ntoh_flow(struct flow *fl)
{
    nbapi_endian_convert_flow(fl, ntohs, ntohl, ntohll);
}

static inline void
hton_flow(struct flow *fl)
{
    nbapi_endian_convert_flow(fl, htons, htonl, htonll);
}

static inline void
nbapi_endian_convert_c_ofp_port_neigh(struct c_ofp_port_neigh *port,
                                      uint16_t (*convs)(uint16_t),
                                      uint64_t (*convll)(uint64_t))
{
    port->port_no = convs(port->port_no);
    port->neigh_present = convs(port->neigh_present);
    port->neigh_port = convs(port->neigh_port);
    port->neigh_dpid = convll(port->neigh_dpid);
}

static inline void
ntoh_c_ofp_port_neigh(struct c_ofp_port_neigh *port)
{
    nbapi_endian_convert_c_ofp_port_neigh(port, ntohs, ntohll);
}

static inline void
hton_c_ofp_port_neigh(struct c_ofp_port_neigh *port)
{
    nbapi_endian_convert_c_ofp_port_neigh(port, htons, htonll);
}

static inline void
nbapi_endian_convert_c_ofp_flow_info(struct c_ofp_flow_info *cofp_fi,
                                     uint16_t (*convs)(uint16_t),
                                     uint32_t (*convl)(uint32_t),
                                     uint64_t (*convll)(uint64_t))
{
    nbapi_endian_convert_ofp_header(&(cofp_fi->header), convs, convl);  
    cofp_fi->datapath_id = convll(cofp_fi->datapath_id);
    nbapi_endian_convert_flow(&(cofp_fi->flow), convs, convl, convll);
    cofp_fi->flags = convll(cofp_fi->flags);
    cofp_fi->oport = convl(cofp_fi->oport);
    cofp_fi->priority = convs(cofp_fi->priority);
    cofp_fi->byte_count = convll(cofp_fi->byte_count);
    cofp_fi->packet_count = convll(cofp_fi->packet_count);
    cofp_fi->duration_sec = convl(cofp_fi->duration_sec);
}

static inline void
nbapi_endian_convert_c_ofp_host_mod(struct c_ofp_host_mod *cofp_host,
                                    uint16_t (*convs)(uint16_t),
                                    uint32_t (*convl)(uint32_t),
                                    uint64_t (*convll)(uint64_t))
{
    nbapi_endian_convert_flow(&(cofp_host->host_flow), convs, convl, convll);
    nbapi_endian_convert_c_ofp_req_dpid_attr(&cofp_host->switch_id,convll);
}

static inline void
ntoh_c_ofp_flow_info(struct c_ofp_flow_info *cofp_fi)
{
    nbapi_endian_convert_c_ofp_flow_info(cofp_fi, ntohs, ntohl, ntohll);
}

static inline void
ntoh_c_ofp_fabric_host(struct c_ofp_host_mod *cofp_host)
{
    nbapi_endian_convert_c_ofp_host_mod(cofp_host, ntohs, ntohl, ntohll);
}

static inline void
nbapi_endian_convert_c_ofp_group_mod(struct c_ofp_group_mod *cofp_gm,
                                     uint32_t (*convl)(uint32_t),
                                     uint64_t (*convll)(uint64_t))
{
    cofp_gm->datapath_id = convll(cofp_gm->datapath_id);
    cofp_gm->group_id = convl(cofp_gm->group_id);
    cofp_gm->packet_count = convll(cofp_gm->packet_count);
    cofp_gm->byte_count = convll(cofp_gm->byte_count);
    cofp_gm->duration_sec = convl(cofp_gm->duration_sec);
    cofp_gm->duration_nsec = convl(cofp_gm->duration_nsec);
}

static inline void
ntoh_c_ofp_group_mod(struct c_ofp_group_mod *cofp_gm) 
{
    nbapi_endian_convert_c_ofp_group_mod(cofp_gm, ntohl, ntohll);
}

static inline void
nbapi_endian_convert_c_ofp_bkt(struct c_ofp_bkt *bkt,
                               uint16_t (*convs)(uint16_t),
                               uint32_t (*convl)(uint32_t)) 
{
    bkt->weight = convs(bkt->weight);
    bkt->act_len = convs(bkt->act_len);
    bkt->ff_port = convl(bkt->ff_port);
    bkt->ff_group = convl(bkt->ff_group);
}

static inline void
ntoh_c_ofp_bkt(struct c_ofp_bkt *bkt) 
{
    nbapi_endian_convert_c_ofp_bkt(bkt, ntohs, ntohl);
}

static inline void nbapi_endian_convert_c_ofp_meter_mod(struct c_ofp_meter_mod * cofp_mm, uint16_t(*convs)(uint16_t), uint32_t(*convl)(uint32_t), uint64_t(*convll)(uint64_t)){
    cofp_mm->datapath_id = convll(cofp_mm->datapath_id);
    cofp_mm->flags = convs(cofp_mm->flags);
    cofp_mm->meter_id = convl(cofp_mm->meter_id);
    cofp_mm->byte_count = convll(cofp_mm->byte_count);
    cofp_mm->packet_count = convll(cofp_mm->packet_count);
    cofp_mm->flow_count = convl(cofp_mm->flow_count);
    cofp_mm->duration_sec = convl(cofp_mm->duration_sec);
    cofp_mm->duration_nsec = convl(cofp_mm->duration_nsec);
}

static inline void ntoh_c_ofp_meter_mod(struct c_ofp_meter_mod *cofp_mm){
    nbapi_endian_convert_c_ofp_meter_mod(cofp_mm, ntohs, ntohl, ntohll);
}

static inline void
nbapi_endian_convert_ofp_action_header(struct ofp_action_header *header,
                                       uint16_t(*convs)(uint16_t)) 
{
    header->type = convs(header->type);
    header->len = convs(header->len);
}

static inline void
ntoh_ofp_action_header(struct ofp_action_header *header) 
{
    nbapi_endian_convert_ofp_action_header(header, ntohs);
}

static inline void 
nbapi_endian_convert_nbapi_flow_brief(struct c_ofp_flow_info *cofp_fi, 
                                      uint16_t(*convs)(uint16_t),
                                      uint32_t(*convl)(uint32_t), 
                                      uint64_t(*convll)(uint64_t))
{
    nbapi_endian_convert_ofp_header(&(cofp_fi->header), convs, convl);
    nbapi_endian_convert_flow(&(cofp_fi->flow), convs, convl, convll);
    cofp_fi->datapath_id = convll(cofp_fi->datapath_id);
    cofp_fi->oport = convs(cofp_fi->oport);
    cofp_fi->byte_count = convll(cofp_fi->byte_count);
    cofp_fi->packet_count = convll(cofp_fi->packet_count);
}

static inline void 
ntoh_nbapi_flow_brief(struct c_ofp_flow_info *cofp_fi)
{
    nbapi_endian_convert_nbapi_flow_brief(cofp_fi, ntohs, ntohl, ntohll);
}

static inline void
ntoh_ofp140_port_stats(struct ofp140_port_stats *ofp_ps){
    ofp_ps->port_no = ntohl(ofp_ps->port_no);
    ofp_ps->duration_sec = ntohl(ofp_ps->duration_sec);
    ofp_ps->duration_nsec = ntohl(ofp_ps->duration_nsec);
    ofp_ps->rx_packets = ntohll(ofp_ps->rx_packets);
    ofp_ps->tx_packets = ntohll(ofp_ps->tx_packets);
    ofp_ps->rx_bytes = ntohll(ofp_ps->rx_bytes);
    ofp_ps->tx_bytes = ntohll(ofp_ps->tx_bytes);
    ofp_ps->rx_dropped = ntohll(ofp_ps->rx_dropped);
    ofp_ps->tx_dropped = ntohll(ofp_ps->tx_dropped);
    ofp_ps->rx_errors = ntohll(ofp_ps->rx_errors);
    ofp_ps->tx_errors = ntohll(ofp_ps->tx_errors);
}
static inline void ntoh_ofp_port_stats_prop_ethernet(struct ofp_port_stats_prop_ethernet *eth_prop){
    eth_prop->rx_frame_err = ntohll(eth_prop->rx_frame_err);
    eth_prop->rx_over_err = ntohll(eth_prop->rx_over_err);
    eth_prop->rx_crc_err = ntohll(eth_prop->rx_crc_err);
    eth_prop->collisions = ntohll(eth_prop->collisions);
}
static inline void ntoh_ofp_port_stats_prop_optical(struct ofp_port_stats_prop_optical *opt_prop){
    opt_prop->flags = ntohl(opt_prop->flags);
    opt_prop->tx_freq_lmda = ntohl(opt_prop->tx_freq_lmda);
    opt_prop->tx_offset = ntohl(opt_prop->tx_offset);
    opt_prop->tx_grid_span = ntohl(opt_prop->tx_grid_span);
    opt_prop->rx_freq_lmda = ntohl(opt_prop->rx_freq_lmda);
    opt_prop->rx_offset = ntohl(opt_prop->rx_offset);
    opt_prop->rx_grid_span = ntohl(opt_prop->rx_grid_span);
    opt_prop->tx_pwr = ntohs(opt_prop->tx_pwr);
    opt_prop->rx_pwr = ntohs(opt_prop->rx_pwr);
    opt_prop->bias_current = ntohs(opt_prop->bias_current);
    opt_prop->temperature = ntohs(opt_prop->temperature);

}

static inline void 
nbapi_endian_convert_ofp131_port_stats(struct ofp131_port_stats *ofp_ps,
                                       uint32_t(*convl)(uint32_t),
                                       uint64_t(*convll)(uint64_t))
{
    ofp_ps->port_no = convl(ofp_ps->port_no);
    ofp_ps->rx_packets = convll(ofp_ps->rx_packets);
    ofp_ps->tx_packets = convll(ofp_ps->tx_packets);
    ofp_ps->rx_bytes = convll(ofp_ps->rx_bytes);
    ofp_ps->tx_bytes = convll(ofp_ps->tx_bytes);
    ofp_ps->rx_dropped = convll(ofp_ps->rx_dropped);
    ofp_ps->tx_dropped = convll(ofp_ps->tx_dropped);
    ofp_ps->rx_errors = convll(ofp_ps->rx_errors);
    ofp_ps->tx_errors = convll(ofp_ps->tx_errors);
    ofp_ps->rx_frame_err = convll(ofp_ps->rx_frame_err);
    ofp_ps->rx_over_err = convll(ofp_ps->rx_over_err);
    ofp_ps->rx_crc_err = convll(ofp_ps->rx_crc_err);
    ofp_ps->collisions = convll(ofp_ps->collisions);
    ofp_ps->duration_sec = convl(ofp_ps->duration_sec);
    ofp_ps->duration_nsec = convl(ofp_ps->duration_nsec);
}

static inline void
ntoh_ofp131_port_stats(struct ofp131_port_stats *ofp_ps)
{
    nbapi_endian_convert_ofp131_port_stats(ofp_ps, ntohl, ntohll);
}

static inline void 
nbapi_endian_convert_ofp_port_stats(struct ofp_port_stats *ofp_ps,
                                    uint16_t(*convs)(uint16_t),
                                    uint64_t(*convll)(uint64_t))
{
    ofp_ps->port_no = convs(ofp_ps->port_no);
    ofp_ps->rx_packets = convll(ofp_ps->rx_packets);
    ofp_ps->tx_packets = convll(ofp_ps->tx_packets);
    ofp_ps->rx_bytes = convll(ofp_ps->rx_bytes);
    ofp_ps->tx_bytes = convll(ofp_ps->tx_bytes);
    ofp_ps->rx_dropped = convll(ofp_ps->rx_dropped);
    ofp_ps->tx_dropped = convll(ofp_ps->tx_dropped);
    ofp_ps->rx_errors = convll(ofp_ps->rx_errors);
    ofp_ps->tx_errors = convll(ofp_ps->tx_errors);
    ofp_ps->rx_frame_err = convll(ofp_ps->rx_frame_err);
    ofp_ps->rx_over_err = convll(ofp_ps->rx_over_err);
    ofp_ps->rx_crc_err = convll(ofp_ps->rx_crc_err);
    ofp_ps->collisions = convll(ofp_ps->collisions);
}
static inline void ntoh_ofp_port_stats(struct ofp_port_stats *ofp_ps){
    nbapi_endian_convert_ofp_port_stats(ofp_ps, ntohs, ntohll);
}


static inline void
nbapi_endian_convert_ofp_group_features(struct ofp_group_features *ofp_gf, 
                                        uint32_t(*convl)(uint32_t))
{
    ofp_gf->types = convl(ofp_gf->types);
    ofp_gf->capabilities = convl(ofp_gf->capabilities);
    ofp_gf->max_groups[OFPGT_ALL]= convl(ofp_gf->max_groups[OFPGT_ALL]);
    ofp_gf->max_groups[OFPGT_SELECT] = convl(ofp_gf->max_groups[OFPGT_SELECT]);
    ofp_gf->max_groups[OFPGT_INDIRECT] = convl(ofp_gf->max_groups[OFPGT_INDIRECT]);
    ofp_gf->max_groups[OFPGT_FF] = convl(ofp_gf->max_groups[OFPGT_FF]);
    ofp_gf->actions[OFPGT_ALL] = convl(ofp_gf->actions[OFPGT_ALL]);
    ofp_gf->actions[OFPGT_SELECT] = convl(ofp_gf->actions[OFPGT_SELECT]);
    ofp_gf->actions[OFPGT_INDIRECT] = convl(ofp_gf->actions[OFPGT_INDIRECT]);
    ofp_gf->actions[OFPGT_FF] = convl(ofp_gf->actions[OFPGT_FF]);
}

static inline void
nbapi_endian_convert_ofp_meter_features(struct ofp_meter_features *ofp_mf,
                                        uint32_t(*convl)(uint32_t))
{
    ofp_mf->max_meter = convl(ofp_mf->max_meter);
    ofp_mf->band_types = convl(ofp_mf->band_types);
    ofp_mf->capabilities = convl(ofp_mf->capabilities);
}

static inline void
ntoh_ofp_group_features(struct ofp_group_features *ofp_gf)
{
    nbapi_endian_convert_ofp_group_features(ofp_gf, ntohl);
}

static inline void
ntoh_ofp_meter_features(struct ofp_meter_features *ofp_mf)
{
    nbapi_endian_convert_ofp_meter_features(ofp_mf, ntohl);
}

static inline void nbapi_endian_convert_c_ofp_fabric_route_link(struct c_ofp_route_link *cofp_rl, uint16_t(*convs)(uint16_t), uint64_t(*convll)(uint64_t))
{
    cofp_rl->datapath_id = convll(cofp_rl->datapath_id);
    cofp_rl->src_link = convs(cofp_rl->src_link);
}
static inline void ntoh_c_ofp_fabric_route_link(struct c_ofp_route_link * cofp_rl){
    nbapi_endian_convert_c_ofp_fabric_route_link(cofp_rl, ntohs, ntohll);
}


#endif
