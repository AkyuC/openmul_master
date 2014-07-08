/*
 * mul_nbapi_topology.h: Mul Northbound Static Flow API application headers
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
#ifndef __MUL_NBAPI_FLOW_H__
#define __MUL_NBAPI_FLOW_H__

#include "mul_app_interface.h"
#include "mul_nbapi_swig_helper.h"
#include "mul_vty.h"
#include "glib.h"

enum nbapi_flow_struct_type {
    NBAPI_FLOW_STRUCT_TYPE_OUTPUT,
    NBAPI_FLOW_STRUCT_TYPE_VLAN_VID,
    NBAPI_FLOW_STRUCT_TYPE_HEADER,
    NBAPI_FLOW_STRUCT_TYPE_DL_ADDR,
    NBAPI_FLOW_STRUCT_TYPE_NW_ADDR,
    NBAPI_FLOW_STRUCT_TYPE_VLAN_PCP,
    NBAPI_FLOW_STRUCT_TYPE_NW_TOS,
    NBAPI_FLOW_STRUCT_TYPE_TP_PORT,
    NBAPI_FLOW_STRUCT_TYPE_GROUP,
    NBAPI_FLOW_STRUCT_TYPE_PUSH,
    NBAPI_FLOW_STRUCT_TYPE_POP_MPLS,
    NBAPI_FLOW_STRUCT_TYPE_MPLS_TTL,
    NBAPI_FLOW_STRUCT_TYPE_NW_TTL,
    NBAPI_FLOW_STRUCT_TYPE_SET_FIELD,
    NBAPI_FLOW_STRUCT_TYPE_SET_QUEUE
};


#if 0
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

    %{
        static GSList *__nbapi_typemap_glist_actions(PyObject *list) {
            if (PyList_Check(list)) {
                int size = PyList_Size(list);
                int i = 0;
                GSList *ret_val = NULL;
                for (i = 0; i < size; i++) {
                    PyObject *tuple = PyList_GetItem(list,i);
                    if (PyTuple_Check(tuple)) {
                        PyObject *proxy = PyTuple_GetItem(tuple, 0);
                        int type = PyInt_AsLong(PyTuple_GetItem(tuple, 1));
                        swig_type_info *type_info;
                        void *struct_ptr;

                        switch (type) {
                            case NBAPI_FLOW_STRUCT_TYPE_OUTPUT:
                                type_info = SWIGTYPE_p_ofp_action_output;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_VLAN_VID:
                                type_info = SWIGTYPE_p_ofp_action_vlan_vid;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_HEADER:
                                type_info = SWIGTYPE_p_ofp_action_header;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_DL_ADDR:
                                type_info = SWIGTYPE_p_ofp_action_dl_addr;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_NW_ADDR:
                                type_info = SWIGTYPE_p_ofp_action_nw_addr;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_VLAN_PCP:
                                type_info = SWIGTYPE_p_ofp_action_vlan_pcp;   
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_NW_TOS:
                                type_info = SWIGTYPE_p_ofp_action_nw_tos;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_TP_PORT:
                                type_info = SWIGTYPE_p_ofp_action_tp_port;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_GROUP:
                                type_info = SWIGTYPE_p_ofp_action_group;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_PUSH:
                                type_info = SWIGTYPE_p_ofp_action_push;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_POP_MPLS:
                                type_info = SWIGTYPE_p_ofp_action_pop_mpls;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_MPLS_TTL:
                                type_info = SWIGTYPE_p_ofp_action_mpls_ttl;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_NW_TTL:
                                type_info = SWIGTYPE_p_ofp_action_nw_ttl;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_SET_FIELD:
                                type_info = SWIGTYPE_p_ofp_action_set_field;
                                break;
                            case NBAPI_FLOW_STRUCT_TYPE_SET_QUEUE:
                                type_info = SWIGTYPE_p_ofp131_action_set_queue;
                                break;
                            default:
                                PyErr_SetString(PyExc_TypeError, "invalid type const detected");
                                return NULL;
                        }

                        if ((SWIG_ConvertPtr(proxy, &struct_ptr, type_info, 
                                           SWIG_POINTER_EXCEPTION)) == -1) {
                            return NULL;
                        }
                        ret_val = g_slist_prepend(ret_val, struct_ptr);

                    } else {
                        PyErr_SetString(PyExc_TypeError,"not a list");
                        return NULL;
                    }
                }
                ret_val = g_slist_reverse(ret_val);
                return ret_val;
            } 
            PyErr_SetString(PyExc_TypeError,"not a list");
            return NULL;
            
        }
        static PyObject *__nbapi_wrap_ofp_action_struct(void *obj, swig_type_info *type_info, int type_no) {
            PyObject *tuple = PyTuple_New(2);
            PyObject *proxy, *type;
            if (!tuple) return NULL;
            
            proxy = SWIG_NewPointerObj(obj, type_info, SWIG_POINTER_OWN);
            type = PyInt_FromLong(type_no);
            if (!proxy || !type) {
                return NULL;
            }
            PyTuple_SetItem(tuple, 0, proxy);
            PyTuple_SetItem(tuple, 1, type);
            return tuple;
        }
    %}

    %newobject nbapi_parse_mac_to_str;
    %newobject nbapi_parse_nw_addr_to_str;
    %newobject nbapi_parse_cidr_to_str;
    %newobject nbapi_flow_make_flow;
    %newobject nbapi_flow_make_mask;
    %newobject nbapi_make_flow_mask;
    %newobject nbapi_mdata_alloc;
    %newobject nbapi_mdata_input_actions;
    %newobject nbapi_dump_single_flow_action;

    %typemap(in) GSList *actions {
        $1 = __nbapi_typemap_glist_actions($input);
        if (!$1) {
            return NULL;
        }

        
    }
    #define NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(Type, Const)     \
        %typemap(out) ##Type## * {                                           \
        PyObject *tuple = __nbapi_wrap_ofp_action_struct($1, $1_descriptor   \
                                            , ##Const##);                    \
        if (!tuple) {                                                        \
            PyErr_SetString(PyExc_TypeError,                                 \
                            "Error converting Type * to PyObject"); \
        }                                                                    \
        return tuple;                                                        \
    }

#if 0
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_output,
                                        NBAPI_FLOW_STRUCT_TYPE_OUTPUT)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_vlan_vid,
                                        NBAPI_FLOW_STRUCT_TYPE_VLAN_VID)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_header,
                                        NBAPI_FLOW_STRUCT_TYPE_HEADER)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_dl_addr,
                                        NBAPI_FLOW_STRUCT_TYPE_DL_ADDR)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_nw_addr,
                                        NBAPI_FLOW_STRUCT_TYPE_NW_ADDR)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_vlan_pcp,
                                        NBAPI_FLOW_STRUCT_TYPE_VLAN_PCP)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_nw_tos,
                                        NBAPI_FLOW_STRUCT_TYPE_NW_TOS)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_tp_port,
                                        NBAPI_FLOW_STRUCT_TYPE_TP_PORT)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_group,
                                        NBAPI_FLOW_STRUCT_TYPE_GROUP)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_push,
                                        NBAPI_FLOW_STRUCT_TYPE_PUSH)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_pop_mpls,
                                        NBAPI_FLOW_STRUCT_TYPE_POP_MPLS)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_mpls_ttl,
                                        NBAPI_FLOW_STRUCT_TYPE_MPLS_TTL)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_nw_ttl,
                                        NBAPI_FLOW_STRUCT_TYPE_NW_TTL)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp_action_set_field,
                                        NBAPI_FLOW_STRUCT_TYPE_SET_FIELD)
    NBAPI_FLOW_WRAP_OFP_ACTION_TYPEMAP(struct ofp131_action_set_queue,
                                        NBAPI_FLOW_STRUCT_TYPE_SET_QUEUE)
#endif
#endif

MUL_NBAPI_PYLIST_RETURN(c_ofp_flow_info, nbapi_switch_flow_list_t)

int add_static_flow(uint64_t datapath_id,
                struct flow *fl,
                struct flow *mask,
                uint16_t priority,
                uint8_t flag,
                mul_act_mdata_t *mdata);

int delete_static_flow(uint64_t datapath_id, 
                struct flow *fl, struct flow *mask, 
                uint16_t out_port_no, 
                uint16_t priority, uint8_t flag);

int compare_flows(struct flow *fl1, struct flow *fl2);

/* helpers to access data */
char *nbapi_parse_mac_to_str(uint8_t *mac);
char *nbapi_parse_nw_addr_to_str(struct flow * flow, int i);//(uint32_t nw_addr)
char *nbapi_parse_cidr_to_str(uint32_t nw_addr, uint8_t prefix_len);

/* helpers to create arguments */
struct flow * nbapi_make_flow_mask(int which, uint64_t dpid, 
		             char *smac, char *dmac, char *eth_type,
                     char *vid, char *vlan_pcp, char * mpls_label, char *mpls_tc,
                     char *mpls_bos, char * dip, char * sip, char *proto,
                     char *tos, char *dport, char *sport, char *inport,
                     char *table);

mul_act_mdata_t *nbapi_mdata_alloc(uint64_t dpid);
void nbapi_mdata_inst_write(mul_act_mdata_t* mdata, uint64_t dpid);
void nbapi_mdata_inst_apply(mul_act_mdata_t* mdata, uint64_t dpid);
int nbapi_action_to_mdata(mul_act_mdata_t* mdata,
                          char * action_type, char * action_value);
void nbapi_mdata_free(mul_act_mdata_t *mdata);

/* helpers to create arguments */
struct flow *nbapi_fabric_make_flow(char *nw_src, char *dl_src,
                                    uint16_t in_port);

struct flow * nbapi_ntoh_flow(struct flow * fl);
uint64_t str_dpid_to64(char * dpid);
nbapi_switch_flow_list_t get_flow(uint64_t datapath_id);
char *nbapi_dump_single_flow_action(c_ofp_flow_info_t *cofp_fi);
char *nbapi_of10_dump_actions(void *actions, size_t actions_len, bool acts_only);
char *nbapi_of131_dump_actions(void *inst_list, size_t inst_len, bool acts_only);

#endif
