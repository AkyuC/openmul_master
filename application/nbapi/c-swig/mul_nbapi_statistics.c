/*
 * mul_nbapi_statistics.h: Mul Northbound Statistics API application headers
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

#include "mul_common.h"
#include "mul_nbapi_common.h"
#include "mul_nbapi_statistics.h"
#include "mul_nbapi_endian.h"


char *nbapi_parse_bps_to_str(uint8_t *bps) {
    char *ret = calloc(sizeof(char), 32);
    if (!ret) return NULL;
    sprintf(ret, "%s", bps);
    return ret;
}
char *nbapi_parse_pps_to_str(uint8_t *pps) {
    char *ret = calloc(sizeof(char), 32);
    if (!ret) return NULL;
    sprintf(ret, "%s", pps);
    return ret;
}
/* callback function to return an array of flow_info */
static void
nbapi_make_switch_flow_dump(nbapi_switch_flow_list_t *list, c_ofp_flow_info_t *cofp_fi)
{
    /* add the flow_info to flow_list *
     *
     */
	c_ofp_flow_info_t *cofp_arg = calloc(1, sizeof(*cofp_fi));
    *cofp_arg = *cofp_fi;
	ntoh_c_ofp_flow_info(cofp_arg); // flow , byte count, packet count conversion
	list->array = g_slist_prepend(list->array, cofp_arg);
}
static void
nbapi_switch_flow_dump(void *list, void * cofp_fi){
    nbapi_make_switch_flow_dump((nbapi_switch_flow_list_t *)list,
                           (c_ofp_flow_info_t *)cofp_fi);
}

/* returns array of flow_info */
nbapi_switch_flow_list_t get_switch_statistics_all(uint64_t datapath_id) {
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
    		datapath_id, 0, false, true, false,
            false, true, &list,
            nbapi_switch_flow_dump);

    c_rd_unlock(&nbapi_app_data->lock);

    list.length = n_flows;
    list.array = g_slist_reverse(list.array);
    return list;
}

static void
list_array_ent_free(void *arg)
{
    free(arg);
}

Port_Stats_t 
*get_switch_statistics_port(uint64_t datapath_id, uint16_t port){//, int type) {
    int n_flows;
    nbapi_switch_flow_list_t list;
    float pps=0;
    float bps=0;
    c_ofp_flow_info_t *cofp_arg = NULL;
    Port_Stats_t *port_stats_arg = NULL;
    int i;

    if (!port_stats_arg) {
        port_stats_arg = calloc(1, sizeof(Port_Stats_t));
    }

    list.array = NULL;
    list.length = 0;

    c_rd_lock(&nbapi_app_data->lock);
    if (!nbapi_app_data->mul_service) {
        c_rd_unlock(&nbapi_app_data->lock);
        return 0;
    }

    n_flows = mul_get_flow_info(nbapi_app_data->mul_service,
    		datapath_id, 0, false, true, false,
            false, true, &list,
            nbapi_switch_flow_dump);

    c_rd_unlock(&nbapi_app_data->lock);

    list.length = n_flows;

    for(i=0;i<n_flows;i++)
    {
    	cofp_arg = g_slist_nth_data(list.array, (guint)i);
    	if(cofp_arg &&
           (cofp_arg->oport == port || cofp_arg->flow.in_port == port))
    	{
    		bps += atof((const char *)cofp_arg->bps);
    		pps += atof((const char *)cofp_arg->pps);
    	}
    }
    port_stats_arg->bps = bps;
    port_stats_arg->pps = pps;

    if (list.array) {
        g_slist_free_full(list.array, list_array_ent_free);
    }
    return port_stats_arg;
}

static bool nbapi_ha_config_cap(void) { //bool replay)
    uint32_t sysid = 0, state = 0;
    uint64_t generation_id = 0;

    if (mul_get_ha_state(nbapi_app_data->mul_service, &sysid, &state, 
                            &generation_id)) {
        return false;
    }

    if ((state == C_HA_STATE_NONE) ||
        (state == C_HA_STATE_MASTER) ||
        (state == C_HA_STATE_NOHA)) {
        return true;
    }

    return false;
}

int 
set_port_stats(uint64_t dpid, bool enable) 
{

    if (!nbapi_ha_config_cap()) {//false)) {
        return 0;
    }

    if (!c_app_switch_get_version_with_id(dpid)) {
        return 0;
    }

    if (mul_set_switch_stats_mode(nbapi_app_data->mul_service, 
                                                dpid, enable)) {
        return 0;
    }

    return 1;
}

struct ofp131_port_stats *show_port_stats (uint64_t dpid, uint32_t port_no){

    struct cbuf *b = NULL;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_port_query *cofp_pq;
    struct ofp131_port_stats *ofp_ps = NULL;
    int version = 0;
    size_t feat_len = 0;
    set_port_stats(dpid,true);
    b =  mul_get_switch_port_stats(nbapi_app_data->mul_service ,dpid, port_no);

    if (!b) return NULL;

    cofp_auc = CBUF_DATA(b);
    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_PORT_QUERY)) {
        free_cbuf(b);
        return NULL;
    }

    feat_len = ntohs(cofp_auc->header.length) - (sizeof(*cofp_auc) +
                        sizeof(*cofp_pq));
    
    cofp_pq = ASSIGN_PTR(cofp_auc->data);

    version = c_app_switch_get_version_with_id(ntohll(cofp_pq->datapath_id));

    if (version == OFP_VERSION_131) {
	if (feat_len < sizeof(struct ofp131_port_stats)) {
	    free_cbuf(b);
	    return NULL;
	}
        ofp_ps = calloc(1, sizeof(*ofp_ps));
        memcpy(ofp_ps, cofp_pq->data, sizeof(*ofp_ps));
        ntoh_ofp131_port_stats(ofp_ps);
    }

    return ofp_ps;
}
struct c_ofp_switch_table_stats *get_table_stats(uint64_t dpid, uint8_t table)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_table_stats *cofp_ts;

    if (!nbapi_app_data->mul_service) return NULL;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_ts),
                    C_OFPT_AUX_CMD, 0);
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_GET_TBL_STATS);
    cofp_ts = ASSIGN_PTR(cofp_auc->data);
    cofp_ts->datapath_id = htonll(dpid);
    cofp_ts->table_id = table;
    
    c_service_send(nbapi_app_data->mul_service, b);
    b = c_service_wait_response(nbapi_app_data->mul_service);
    if (b) {
        cofp_auc = CBUF_DATA(b);
        if (cofp_auc->header.type != C_OFPT_AUX_CMD ||
            ntohs(cofp_auc->header.length) < (sizeof(*cofp_auc) + sizeof(*cofp_ts)) ||
            ntohl(cofp_auc->cmd_code) != C_AUX_CMD_MUL_SWITCH_GET_TBL_STATS) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return NULL;
        }

        cofp_ts = ASSIGN_PTR(cofp_auc->data);
        free_cbuf(b);
    }

    return cofp_ts;

}

static int 
nbapi_get_switch_pkt_rlim(uint64_t datapath_id, bool is_rx)
{
    uint32_t pps = 0;

    if (!c_app_switch_get_version_with_id(datapath_id)) {
        c_log_err("%s : No such switch", FN);
        return -1;
    }

    if (mul_get_switch_pkt_rlim(nbapi_app_data->mul_service, 
                                datapath_id,
                                &pps, is_rx)) {
        c_log_err("%s : Failed to get rate-limit", FN);
        return -1;
    }

    return pps;
}

int get_switch_pkt_rx_rlim(uint64_t datapath_id)
{
    return nbapi_get_switch_pkt_rlim(datapath_id, true);
}

int get_switch_pkt_tx_rlim(uint64_t datapath_id)
{
    return nbapi_get_switch_pkt_rlim(datapath_id, false);
}

static int 
nbapi_set_switch_pkt_rlim(uint64_t datapath_id, uint32_t pps, bool is_rx)
{
    if (!c_app_switch_get_version_with_id(datapath_id)) {
        c_log_err("%s : No such switch", FN);
        return -1;
    }

    if (mul_set_switch_pkt_rlim(nbapi_app_data->mul_service,
                                datapath_id, pps, is_rx)) {
        c_log_err("%s : Failed to set rate-limit", FN);
        return -1;
    }

    return 0;   
}

int nbapi_set_switch_pkt_rx_rlim(uint64_t datapath_id, uint32_t pps)
{
    return nbapi_set_switch_pkt_rlim(datapath_id, pps, true);
}

int nbapi_set_switch_pkt_tx_rlim(uint64_t datapath_id, uint32_t pps)
{
    return nbapi_set_switch_pkt_rlim(datapath_id, pps, false);
}

int nbapi_disable_switch_pkt_rx_rlim(uint64_t datapath_id)
{
    return nbapi_set_switch_pkt_rlim(datapath_id, 0, true);
}

int nbapi_disable_switch_pkt_tx_rlim(uint64_t datapath_id)
{
    return nbapi_set_switch_pkt_rlim(datapath_id, 0, false);
}
