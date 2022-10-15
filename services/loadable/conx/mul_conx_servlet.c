/**
 *  @file mul_conx_servlet.c
 *  @brief Mul Conx service APIs 
 *  @author Dipjyoti Saikia  <dipjyoti.saikia@gmail.com> 
 *  @copyright Copyright (C) 2012, Dipjyoti Saikia 
 *
 * @license This program is free software; you can redistribute it and/or
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
 *
 *
 * @see www.openmul.org
 */

#include "mul_common.h"
#include "mul_app_main.h"
#include "mul_conx_servlet.h"

extern c_app_hdl_t c_app_main_hdl;

/**
 * @name mul_conx_mod_uflow -
 * @brief Add/Del a conx association for a user-supplied flow flow  
 * @param [in] add flag to specify add or del operation
 * @param [in] n_dpid number of source dpids requested 
 * @param [in] src_dps list of source dpids
 * @param [in] dst_dp Destination dpid 
 * @param [in] in_fl User-flow to match in incoming (source) switches
 * @param [in] tunnel_key Tunnel-id if connection between src and dest is overlay
 * @param [in] tunnel_type Tunnel-type (undefined for now)
 * @param [in] actions Actions to be applied at the egress node
 * @param [in] action_len Length of the actions 
 * @param [in] fl_flags Flow flags using which flow is to be installed in the core
 * @param [in] conx_flags Mask of following flags - 
 *                        CONX_UFLOW_FORCE: Force to add all path-flows irrespective of 
 *                                          failure in any path
 *                        CONX_UFLOW_DFL: Install the user flow with default low priority * 
 * @retval int 0 for success or non-0 for failure
 */
int
mul_conx_mod_uflow(void *service,
                   bool add,
                   size_t n_dpid,
                   uint64_t *src_dps,
                   uint64_t dst_dp,
                   struct flow *in_fl,
                   struct flow *in_mask,
                   uint32_t tunnel_key,
                   uint32_t tunnel_type,
                   void *actions,
                   size_t action_len,
                   uint64_t fl_flags,
                   uint32_t conx_flags)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_conx_user_flow *conx_fl;
    int ret = 0;
    int i = 0;
    uint8_t zero_mac[6] = { 0, 0, 0, 0, 0, 0};
    size_t ext_len = 0;
    uint8_t *act_ptr = NULL;
    uint64_t *src_dpid;

    if (!service || n_dpid < 1 || n_dpid > 1024) return -1;

    if (tunnel_type == CONX_TUNNEL_OF &&
        (memcmp(in_mask->dl_dst, zero_mac, 6) ||
        memcmp(in_mask->dl_src, zero_mac, 6))) {
        c_log_err("uFlow can't use src-dst Mac match");
        return -1;
    }

    if (of_check_flow_wildcard_generic(in_fl, in_mask)) {
        c_log_debug("Conx add-uflow all-wc not allowed");
        return -1;
    }

    ext_len = action_len + (sizeof(uint64_t)*n_dpid);

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*conx_fl) + ext_len,
                    C_OFPT_AUX_CMD, 0);
    if (!b) return -1;
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = add ? htonl(C_AUX_CMD_CONX_ADD_UFLOW):
                               htonl(C_AUX_CMD_CONX_DEL_UFLOW);

    conx_fl = ASSIGN_PTR(cofp_auc->data);   
    conx_fl->dst_dpid = htonll(dst_dp);
    conx_fl->tunnel_key = htonl(tunnel_key); /* Overridden as tenant-id */
    conx_fl->tunnel_type = htonl(tunnel_type);
    conx_fl->app_cookie = htonl(c_app_main_hdl.app_cookie);
    conx_fl->fl_flags = htonll(fl_flags);
    conx_fl->conx_flags = htonl(conx_flags);
    conx_fl->n_src = htonll(n_dpid);

    memcpy(&conx_fl->flow, in_fl, sizeof(struct flow));
    memcpy(&conx_fl->mask, in_mask, sizeof(struct flow));

    src_dpid = ASSIGN_PTR(conx_fl->src_dpid_list);
    for (i = 0; i < n_dpid; i++) {
        src_dpid[i] = htonll(src_dps[i]);
    }

    if (add && action_len) {
        act_ptr = INC_PTR8(conx_fl->src_dpid_list, sizeof(uint64_t)*n_dpid);
        memcpy(act_ptr, actions, action_len); 
    }

    c_service_send(service, b);
    if (!(fl_flags & C_FL_NO_ACK))  {
        b = c_service_wait_response(service);
        if (b) {
            cofp_auc = CBUF_DATA(b);
            if (!c_check_reply_type(b, C_AUX_CMD_SUCCESS)) {
                ret = 0;
            }
            free_cbuf(b);
        }
    }
    return ret;
}

/**
 * @name mul_conx_stale -
 * @brief Start user-flow staling at ConX for a particular cookie
 * @param [in] service Pointer to client service
 * @param [in] cookie Cookie-id associated with an application
 * 
 * @retval int 0 for success non-0 for failure 
 */
int
mul_conx_stale(void *service, uint32_t cookie)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_conx_user_flow *conx_fl;
    int ret = -1;

    if (!service) return ret;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*conx_fl),
                    C_OFPT_AUX_CMD, 0);
    if (!b) return -1;

    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_CONX_STALE);

    conx_fl = ASSIGN_PTR(cofp_auc->data);   
    conx_fl->app_cookie = htonl(cookie);

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        cofp_auc = CBUF_DATA(b);
        if (!c_check_reply_type(b, C_AUX_CMD_SUCCESS)) {
            ret = 0;
        }
        free_cbuf(b);
    }
    return ret;
}
