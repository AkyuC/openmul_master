/**
 *  @file mul_tr_servlet.c
 *  @brief Mul topology service APIs 
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
#include "mul_tr_servlet.h"

static bool
check_reply_type(struct cbuf *b, uint32_t cmd_code)
{
    c_ofp_auxapp_cmd_t *cofp_auc  = (void *)(b->data);

    if (ntohs(cofp_auc->header.length) < sizeof(*cofp_auc)) {
        return false;
    }

    if (cofp_auc->header.type != C_OFPT_AUX_CMD ||
        cofp_auc->cmd_code != htonl(cmd_code)) {
        return false;
    }

    return true;
}

/**
 * @name mul_dump_neigh -
 * @brief Dump a switch's neighbour to a printable buffer
 * @param [in] b struct cbuf buffer containing response from the server
 * @param [in] free_bug flag to specify if buffer needs to be freed
 * 
 * @retval char * Print buffer
 */
char *
mul_dump_neigh(struct cbuf *b, bool free_buf)
{
    char *pbuf = calloc(1, TR_DFL_PBUF_SZ);
    c_ofp_auxapp_cmd_t *cofp_auc  = (void *)(b->data);    
    int num_ports, i = 0, len = 0;
    struct c_ofp_port_neigh *port;
    c_ofp_switch_neigh_t *neigh = (void *)(cofp_auc->data);
    bool neigh_switch = false;

    num_ports = (ntohs(cofp_auc->header.length) - (sizeof(c_ofp_switch_neigh_t) 
                + sizeof(c_ofp_auxapp_cmd_t)))/ sizeof(struct c_ofp_port_neigh);

    port = (void *)(neigh->data);
    for (; i < num_ports; i++) {
        neigh_switch = ntohs(port->neigh_present) & COFP_NEIGH_SWITCH ? 
                          true: false;
        len += snprintf(pbuf + len, TR_DFL_PBUF_SZ-len-1,
                    "%12u | %10s | 0x%10llx | %u\r\n",
                     ntohs(port->port_no), neigh_switch ? "SWITCH" : "EXT",
                     U642ULL(ntohll(port->neigh_dpid)),
                     ntohs(port->neigh_port));
        if (len >= TR_DFL_PBUF_SZ-1) {
            goto out_buf_err;
        }
        port++;
    }
out:
    if (free_buf) {
        free_cbuf(b);
    }
    return pbuf;
out_buf_err:
    c_log_err("%s: pbuf alloc failed", FN);
    goto out;
}


/**
 * @name mul_neigh_get -
 * @brief Get a switch's neighbour info using TR service
 * @param [in] service Pointer to the client's service
 * @param [in] dpid datapath-id of the switch whose neighborhood 
 *                  info us required 
 * @retval struct cbuf * Pointer to the buffer response from the server
 *
 * This function uses auxillary mlapi type C_AUX_CMD_TR_GET_NEIGH
 * Caller needs to free returned cbuf (if not NULL)
 */
struct cbuf *
mul_neigh_get(void *service, uint64_t dpid)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_req_dpid_attr *cofp_rda;
    struct ofp_header *h;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
                    sizeof(struct c_ofp_req_dpid_attr),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_TR_GET_NEIGH);
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);
    
    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        h = (void *)(b->data);
        if (h->type == C_OFPT_ERR_MSG) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return NULL;
        }
    }

    return b;
}

/**
 * @name mul_set_tr_loop_detect -
 * @brief Set mul tr loop detection status in topo module
 * @param [in] service Pointer to the client's service
 * @param [in] enable Enable or disable 
 *
 * @retval int zero if no error else non-zero
 */
int
mul_set_tr_loop_detect(void *service, bool enable)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_port_query *cofp_pq;
    int ret = -1;

    if (!service) return ret;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_pq),
                    C_OFPT_AUX_CMD, 0);
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = enable ? htonl(C_AUX_CMD_MUL_LOOP_EN):
                                  htonl(C_AUX_CMD_MUL_LOOP_DIS);

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        cofp_auc = CBUF_DATA(b);
        if (check_reply_type(b, C_AUX_CMD_SUCCESS)) {
            ret = 0;
        }
        free_cbuf(b);
    }
    return ret;
}
