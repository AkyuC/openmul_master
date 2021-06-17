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

int
parse_alias_id(uint32_t alias_id)
{
    int i_aid = 0;
    i_aid = (int)(U322UL(alias_id));

    return i_aid;
}

uint32_t get_switch_alias_from_switch_info(struct ofp_switch_features *switch_info) {
    return C_GET_ALIAS_IN_SWADD(switch_info);
}


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
    ret_val = calloc(1, ntohs(osf->header.length));
    
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
    return ofp_tb;
}
bool get_bit_in_32mask(uint32_t *mask, int bit)
{
    return (((*((uint32_t *)(mask) + ((bit)/32))) >> ((bit)%32)) & 0x1);
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
uint32_t get_group_act_type(uint32_t *actions, int type)
{
    return actions[type];
}
uint32_t 
get_max_group(uint32_t *max_groups, int type)
{
    return (uint32_t)max_groups[type];
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

nbapi_switch_brief_list_t get_switch_all(void) {
    int i, n_switches;
    nbapi_switch_brief_list_t list;
    c_ofp_auxapp_cmd_t *cofp_auc;
    c_ofp_switch_brief_t *cofp_swb;

    struct cbuf *b;

    list.array = NULL;
    list.length = 0;

    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_rd_unlock(&nbapi_app_data->lock);
        return list;
    }

    b = mul_get_switches_brief(nbapi_app_data->mul_service); 


    c_rd_unlock(&nbapi_app_data->lock);
    if(b){

        cofp_auc = (void *)(b->data);
        n_switches = (ntohs(cofp_auc->header.length) - sizeof(c_ofp_auxapp_cmd_t))/
                     sizeof(c_ofp_switch_brief_t);

        list.length = n_switches;

        cofp_swb = (void *)(cofp_auc->data);
        for (i=0; i < n_switches; i++) {
            c_ofp_switch_brief_t *switch_brief = calloc(1, sizeof(*switch_brief));
            *switch_brief = *cofp_swb;
            ntoh_c_ofp_switch_brief(switch_brief);
            list.array = g_slist_prepend(list.array, switch_brief);
            cofp_swb += 1;
        }

        free_cbuf(b);
        list.array = g_slist_reverse(list.array);
    }

    return list;
}
struct 
c_sw_port *get_switch_port(uint64_t datapath_id, uint32_t port_no) 
{
    int i, n_ports;
    struct c_sw_port *ret_val;

    struct c_ofp_switch_add *osf;

    struct cbuf *b;

    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_rd_unlock(&nbapi_app_data->lock);
        return NULL;
    }

    b = mul_get_switch_detail(nbapi_app_data->mul_service, datapath_id);

    c_rd_unlock(&nbapi_app_data->lock);

    if (!b) {
        return NULL;
    }
    osf = (void *)b->data;
    n_ports = ((ntohs(osf->header.length)
                - offsetof(struct c_ofp_switch_add, ports))
            / sizeof *osf->ports);

    for (i = 0; i < n_ports; i ++) {
        struct c_sw_port        *p_info = &osf->ports[i];
        if (ntohl(p_info->port_no) == port_no) {
            ret_val = calloc(sizeof(*ret_val),1);
            if (!ret_val) {
                break;
            }
            *ret_val = *p_info;
            ntoh_c_sw_port(ret_val);
            free_cbuf(b);
            return ret_val;
        }
    }

    free_cbuf(b);
    return NULL;
}

nbapi_swport_list_t get_switch_port_all(uint64_t datapath_id) 
{
    int i, n_ports;
    nbapi_swport_list_t list;

    struct c_ofp_switch_add *osf;

    struct cbuf *b;

    list.array = NULL;
    list.length = 0;

    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_rd_unlock(&nbapi_app_data->lock);
        return list;
    }

    b = mul_get_switch_detail(nbapi_app_data->mul_service, datapath_id);

    c_rd_unlock(&nbapi_app_data->lock);

    if (b) {
        osf = (void *)b->data;
        n_ports = ((ntohs(osf->header.length)
                    - offsetof(struct c_ofp_switch_add, ports))
                / sizeof *osf->ports);

        list.length = n_ports;
        for (i = 0; i < n_ports; i ++) {
            struct c_sw_port *p_info = &osf->ports[i];
            struct c_sw_port *copy   = calloc(sizeof(*copy), 1);

            *copy = *p_info;
            ntoh_c_sw_port(copy);
            copy->name[OFP_MAX_PORT_NAME_LEN-1]= '\0';
            list.array = g_slist_prepend(list.array, copy);
            
        }

        free_cbuf(b);
        list.array = g_slist_reverse(list.array);
    }
    return list;
}

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

void nbapi_ntoh_actions(void *actions, size_t act_len)
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
    int act = 0;

    list = calloc(1, sizeof(c_ofp_group_mod_t));
    list->group_id = group_id;

    c_wr_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_wr_unlock(&nbapi_app_data->lock);
        return list;
    }

    mul_get_group_info(nbapi_app_data->mul_service, 
                            datapath_id, false, true, 
                            list, switch_group_table_dump);

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

        ntoh_c_ofp_bkt(bkt);
        nbapi_ntoh_actions(bkt->actions, act_len);
 
        tot_len -= act_len + sizeof(*bkt);
        act++;
    }
    return list;
}

