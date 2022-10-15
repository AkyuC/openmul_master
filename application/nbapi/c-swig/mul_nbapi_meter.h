/*
 *  mul_nbapi_meter.h: Mul Northbound Static Flow API application headers
 *  Copyright (C) 2013, Jun Woo Park <johnpa@gmail.com>
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
#ifndef __MUL_NBAPI_METER_H__
#define __MUL_NBAPI_METER_H__

#include "mul_app_interface.h"
#include "mul_nbapi_swig_helper.h"
#include "mul_vty.h"
#include "glib.h"

#ifdef SWIG
/* Note: 
 *      When passing action list from python, we are expecting following data format:
 *          [(ofp_action* objects, type of such object),
 *           (struct ofp_aciton_ *, NBAPI_FLOW_STRUCT_TYPE constant)
 *           ...]
 *
 *      where ofp_action* object is return values from nbapi_make_action functions
 *
 * Remark: I added NBAPI_FLOW_STRUCT_TYPE constant since I needed type information to 
 *         convert objects from list. 
 */  
    %newobject get_meter; 
    %newobject nbapi_get_band_type;
    %newobject nbapi_get_band_rate;
    %newobject nbapi_get_band_burst_size;
    %newobject nbapi_get_band_prec_level;
    %newobject get_meter_number;
#endif

MUL_NBAPI_PYLIST_RETURN(c_ofp_meter_mod, nbapi_switch_meter_list_t)

struct of_meter_mod_params *prepare_add_meter(char *meter_id, char *type, char *burst, char *stat);
mul_act_mdata_t *nbapi_meter_band_add(uint64_t datapath_id, int act_len, struct of_meter_mod_params *m_parms, char *band_type, char *rate, char *burst_size, char *prec_level);
int nbapi_meter_add(int act_len, uint64_t datapath_id, struct of_meter_mod_params *m_parms);
void nbapi_meter_free(int act_len, struct of_meter_mod_params *m_parms);
int nbapi_delete_meter(uint64_t dpid, uint32_t meter);
nbapi_switch_meter_list_t get_meter(uint64_t datapath_id);
int get_meter_number(uint64_t dpid);
char * nbapi_get_band_type(c_ofp_meter_mod_t * cofp_mm);
char * nbapi_get_band_rate(c_ofp_meter_mod_t * cofp_mm);
char * nbapi_get_band_burst_size(c_ofp_meter_mod_t * cofp_mm);
char * nbapi_get_band_prec_level(c_ofp_meter_mod_t * cofp_mm);
#endif
