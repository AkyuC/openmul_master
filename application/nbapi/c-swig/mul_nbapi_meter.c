/*
 *  mul_nbapi_flow.c: Mul Northbound Static Flow Application for Mul Controller
 *  Copyright (C) 2013, Jun Woo Park (johnpa@gmail.com)
 *                      Dipjyoti Saikia (dipjyoti.saikia@gmail.com)
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
#include "mul_nbapi_meter.h"
#include "mul_nbapi_endian.h"

struct of_meter_mod_params *prepare_add_meter(char *meter_id, char *type, char *burst, char *stat){
    struct of_meter_mod_params *m_parms;

    m_parms = calloc(1, sizeof(*m_parms));
    memset(m_parms, 0, sizeof(*m_parms));

    m_parms->meter = atol(meter_id);
    m_parms->cflags = C_METER_STATIC;
    if (!strncmp(type, "kbps", strlen(type))){
	m_parms->flags = OFPMF_KBPS;
    } else if (!strncmp(type, "pktps", strlen(type))) {
	m_parms->flags = OFPMF_PKTPS;
    }

    if (!strncmp(burst, "yes", strlen(burst))){
	m_parms->flags |= OFPMF_BURST;
    }

    if (!strncmp(stat, "yes", strlen(stat))){
	m_parms->flags |= OFPMF_STATS;
	m_parms->cflags |= C_METER_GSTATS;
    }
    return m_parms;
}

mul_act_mdata_t *nbapi_meter_band_add(uint64_t datapath_id, int act_len, struct of_meter_mod_params *m_parms, char *band_type, char *rate, char *burst_size, char *prec_level){
    struct of_meter_band_elem *band_elem;
    struct of_meter_band_parms meter_band_params;
    mul_act_mdata_t *mdata;

    mdata = calloc(1, sizeof(*mdata));
    of_mact_alloc(mdata);
    mdata->only_acts = true;
    if(mul_app_act_set_ctors(mdata, datapath_id)){
	//switch not exist
	return NULL;
    }

    meter_band_params.rate = atol(rate);
    meter_band_params.burst_size = atol(burst_size);

    if(!strncmp(band_type,"drop",strlen(band_type))){
	mul_app_set_band_drop(mdata, &meter_band_params);
    } else if (!strncmp(band_type, "dscp_remark",strlen(band_type))){
	if(!strncmp(prec_level, "None", strlen(prec_level))){
	    return NULL;
	}
	meter_band_params.prec_level = atoi(prec_level);
	mul_app_set_band_dscp(mdata, &meter_band_params);
    }    

    band_elem = calloc(1, sizeof(*band_elem));
    band_elem->band = mdata->act_base;
    band_elem->band_len = of_mact_len(mdata);
    m_parms->meter_bands[act_len] = band_elem;

    return mdata;
}
int nbapi_meter_add(int act_len, uint64_t datapath_id, struct of_meter_mod_params *m_parms){

    m_parms->meter_nbands = act_len;
    mul_service_send_meter_add(nbapi_app_data->mul_service, datapath_id, m_parms);
    if (c_service_timed_wait_response(nbapi_app_data->mul_service) > 0){
	return -1;
    }
    return 0;
}

void nbapi_meter_free(int act_len, struct of_meter_mod_params *m_parms){
    int i = 0;
    for (i = 0; i<act_len; i++){
	free(m_parms->meter_bands[i]);
    }
    free(m_parms);
}

int nbapi_delete_meter(uint64_t dpid, uint32_t meter) {
    struct of_meter_mod_params m_parms;

    memset(&m_parms, 0, sizeof(m_parms));

    m_parms.meter = meter;
    m_parms.cflags = C_METER_STATIC;
    mul_service_send_meter_del(nbapi_app_data->mul_service, dpid, &m_parms);
    if(c_service_timed_wait_response(nbapi_app_data->mul_service)>0){
        return -1;
    }
    return 0;
}

static void
make_meter_list(nbapi_switch_meter_list_t * list, c_ofp_meter_mod_t * cofp_mm){
    c_ofp_meter_mod_t * cofp_arg;
    cofp_arg = calloc(1, ntohs(cofp_mm->header.length));
    memcpy(cofp_arg, cofp_mm, ntohs(cofp_mm->header.length));
    ntoh_c_ofp_meter_mod(cofp_arg);
    list->array = g_slist_prepend(list->array, cofp_arg);
}

static void
nbapi_make_meter_list(void *list, void *cofp_mm){
    make_meter_list((nbapi_switch_meter_list_t *)list, 
		    (c_ofp_meter_mod_t *)cofp_mm);
}

nbapi_switch_meter_list_t get_meter(uint64_t datapath_id){
    int n_meters;
    nbapi_switch_meter_list_t list;

    list.array = NULL;
    list.length = 0;

    c_rd_lock(&nbapi_app_data->lock);
    if(!nbapi_app_data->mul_service) {
	c_rd_unlock(&nbapi_app_data->lock);
	return list;
    }
    n_meters = mul_get_meter_info(nbapi_app_data->mul_service,
				  datapath_id, false, true, 
				  &list, nbapi_make_meter_list);
    c_rd_unlock(&nbapi_app_data->lock);
    list.length = n_meters;
    list.array = g_slist_reverse(list.array);
    return list;
}
int get_meter_number(uint64_t dpid){
    nbapi_switch_meter_list_t list;
    return mul_get_meter_info(nbapi_app_data->mul_service,
				dpid, false, true,
				&list, nbapi_make_meter_list);
}
char * nbapi_get_band_type(c_ofp_meter_mod_t * cofp_mm){
    char * pbuf;
    int len = 0, act = 0;
    struct ofp_meter_band_header * band;
    size_t band_dist = 0;
    ssize_t tot_len = ntohs(cofp_mm->header.length);
    char * band_types[] = {"", "drop", "dscp_remark"};
    band_dist = sizeof(*cofp_mm);
    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    while((tot_len >= (int)sizeof(*band)) && (act < OF_MAX_ACT_VECTORS)) {
	size_t band_len = 0;
	band = INC_PTR8(cofp_mm, band_dist);
	band_len = ntohs(band->len);
	band_dist += band_len;
	if (band_len <= 0 ) break;
	if (band_len > tot_len) break;
	len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
			"%s ", band_types[htons(band->type)]);	
	tot_len -= band_len;
	act++;
    }

    return pbuf;
}
char * nbapi_get_band_rate(c_ofp_meter_mod_t * cofp_mm){
    char * pbuf;
    int len = 0, act = 0;
    struct ofp_meter_band_header * band;
    size_t band_dist = 0;
    ssize_t tot_len = ntohs(cofp_mm->header.length);
    band_dist = sizeof(*cofp_mm);
    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    while((tot_len >= (int)sizeof(*band)) && (act < OF_MAX_ACT_VECTORS)) {
        size_t band_len = 0;
        band = INC_PTR8(cofp_mm, band_dist);
        band_len = ntohs(band->len);
        band_dist += band_len;
        if (band_len <= 0 ) break;
        if (band_len > tot_len) break;
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "%d ", htonl(band->rate));
        tot_len -= band_len;
        act++;
    }

    return pbuf;
}
char * nbapi_get_band_burst_size(c_ofp_meter_mod_t * cofp_mm){
    char * pbuf;
    int len = 0, act = 0;
    struct ofp_meter_band_header * band;
    size_t band_dist = 0;
    ssize_t tot_len = ntohs(cofp_mm->header.length);
    band_dist = sizeof(*cofp_mm);
    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    while((tot_len >= (int)sizeof(*band)) && (act < OF_MAX_ACT_VECTORS)) {
        size_t band_len = 0;
        band = INC_PTR8(cofp_mm, band_dist);
        band_len = ntohs(band->len);
        band_dist += band_len;
        if (band_len <= 0 ) break;
        if (band_len > tot_len) break;
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "%u ", htonl(band->burst_size));
        tot_len -= band_len;
        act++;
    }

    return pbuf;
}
char * nbapi_get_band_prec_level(c_ofp_meter_mod_t * cofp_mm){
    struct ofp_meter_band_dscp_remark * dscp_band;
    char * pbuf;
    int len = 0, act = 0;
    struct ofp_meter_band_header * band;
    size_t band_dist = 0;
    ssize_t tot_len = ntohs(cofp_mm->header.length);
    band_dist = sizeof(*cofp_mm);
    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    while((tot_len >= (int)sizeof(*band)) && (act < OF_MAX_ACT_VECTORS)) {
        size_t band_len = 0;
        band = INC_PTR8(cofp_mm, band_dist);
        band_len = ntohs(band->len);
        band_dist += band_len;
        if (band_len <= 0 ) break;
        if (band_len > tot_len) break;
	if (htons(band->type) ==OFPMBT_DSCP_REMARK) {
	    dscp_band = (struct ofp_meter_band_dscp_remark *)band;
            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "%u ", dscp_band->prec_level);
	} else {
	    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
			"-1 ");
	}
        tot_len -= band_len;
        act++;
    }

    return pbuf;
}














