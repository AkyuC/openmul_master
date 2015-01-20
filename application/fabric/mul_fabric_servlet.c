/**
 *  @file mul_fabric_servlet.c
 *  @brief Mul fabric service APIs 
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


#include "mul_fabric_servlet.h"

/**
 * @name  fab_dump_add_host_cmd_from_flow -
 *
 */
static char *
fab_dump_add_host_cmd_from_flow(uint64_t dpid, struct flow *fl,
                               uint8_t *host_tenant_id, uint8_t *host_network_id)
{
    char     *pbuf = calloc(1, HOST_PBUF_SZ);
    int      len = 0;
    struct in_addr in_addr = { .s_addr = fl->ip.nw_src };
    uint8_t tenant_id[FAB_UUID_STR_SZ], network_id[FAB_UUID_STR_SZ];

    uuid_unparse((const uint8_t *) host_tenant_id, (char *) tenant_id);
    uuid_unparse((const uint8_t *) host_network_id, (char *) network_id);

    len += snprintf(pbuf+len, HOST_PBUF_SZ-len-1,
                    "add fabric-host tenant %s network %s host-ip %s host-mac "
                    "%02x:%02x:%02x:%02x:%02x:%02x switch "
                    "0x%llx port %hu %s \r\n",
                    tenant_id, network_id,
                    inet_ntoa(in_addr),
                    fl->dl_src[0], fl->dl_src[1],
                    fl->dl_src[2], fl->dl_src[3],
                    fl->dl_src[4], fl->dl_src[5],
                    (unsigned long long)dpid,
                    ntohs(fl->in_port),
                    fl->FL_DFL_GW ? "gw" : "non-gw");
    assert(len < HOST_PBUF_SZ-1);
    return pbuf;
}

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
 * @name  mul_fabric_route_link_dump -
 * @brief Dump each route link
 *
 */
static char *
mul_fabric_route_link_dump(struct c_ofp_route_link *rl, size_t n_links)
{
    int i = 0 , len = 0;
    char *pbuf = calloc(1, FAB_DFL_PBUF_SZ);

    if (!pbuf) {
        return NULL;
    }

    for (; i < n_links; i++) {
        len += snprintf(pbuf+len, FAB_DFL_PBUF_SZ-len-1,
                        "Node(0x%llx):Link(%hu)",
                        (unsigned long long)(ntohll(rl->datapath_id)),
                        ntohs(rl->src_link));
        if (len >= FAB_DFL_PBUF_SZ-1) {
            c_log_err("%s: print buf overrun", FN);
            free(pbuf);
            return NULL;
        }
        rl++;
    }

    return pbuf;
}

/**
 * @name mul_fabric_host_mod
 * @brief Fabric application host modification ml-api
 * @ingroup Fabric Application 
 * 
 * @param [in] service pointer to fabric service pointer 
 * @param [in] dpid: datapath-id of the switch to which host is connected
 * @param [in] fl: Pointer to struct flow which represents the host.
 *                 Only dl_src, nw_src and in_port are valid
 * @param [in] tenant_id: Tenant-id in UUID format
 * @param [in] network_id: Network-id in UUID format
 * @param [in] add: true for add and false for delete operation 
 *
 * @retval int zero for success and non-zero for failure
 */
int
mul_fabric_host_mod(void *service, uint64_t dpid, struct flow *fl, 
                    uint8_t *tenant_id,  uint8_t *network_id, bool add)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_host_mod *cofp_hm;
    int ret = -1;

    if (!service) return ret;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
                    sizeof(struct c_ofp_host_mod),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = add ? htonl(C_AUX_CMD_FAB_HOST_ADD): 
                               htonl(C_AUX_CMD_FAB_HOST_DEL);
    cofp_hm = (void *)(cofp_auc->data);
    cofp_hm->switch_id.datapath_id = htonll(dpid);
    memcpy(&cofp_hm->host_flow, fl, sizeof(*fl));
    memcpy(cofp_hm->tenant_id, tenant_id, sizeof(uuid_t));
    memcpy(cofp_hm->network_id, network_id, sizeof(uuid_t));
    
    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        if (check_reply_type(b, C_AUX_CMD_SUCCESS)) {
            ret = 0;
        }
        
        free_cbuf(b);
    }

    return ret;
}

/**
 * @name mul_fabric_show_hosts -
 * @brief ml-api to get all hosts registered in fabric
 * @ingroup Fabric Application 
 * 
 * @param [in] service pointer to fabric service pointer 
 * @param [in] active: true if user wants active hosts else false
 * @param [in] dump_cmd: true if it is dump is required in cli command format 
 * @param [in] nbapi: true if it a nbapi client 
 * @param [in] arg: Argument pointer to be passed to cb_fn param 
 * @param [in] cb_fb: Callback function to be called for each host received
 *
 * @retval number of hosts available
 */
int
mul_fabric_show_hosts(void *service, bool active, bool dump_cmd, bool nbapi,
                      void *arg, void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_host_mod *cofp_hm;
    char *pbuf;
    int n_hosts=0;

    if (!service) return -1;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = active ?
                         htonl(C_AUX_CMD_FAB_SHOW_ACTIVE_HOSTS): 
                         htonl(C_AUX_CMD_FAB_SHOW_INACTIVE_HOSTS);
    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_FAB_HOST_ADD)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *)(b->data);
            cofp_hm = (void *)(cofp_auc->data);

            if (ntohs(cofp_auc->header.length)  <
                sizeof(*cofp_auc) + sizeof(*cofp_hm)) {
                free_cbuf(b);
                break;

            }
            
            if (!dump_cmd) {
                pbuf = fab_dump_single_host_from_flow(
                                    ntohll(cofp_hm->switch_id.datapath_id),
                                    &cofp_hm->host_flow, 
                                    (uint8_t*) cofp_hm->tenant_id, 
                                    (uint8_t*) cofp_hm->network_id);
            } else {
                pbuf = fab_dump_add_host_cmd_from_flow(
                                    ntohll(cofp_hm->switch_id.datapath_id),
                                    &cofp_hm->host_flow,
                                    (uint8_t*) cofp_hm->tenant_id, 
                                    (uint8_t*) cofp_hm->network_id);
            }
            if (pbuf) {
		        if (nbapi){
		            cb_fn(arg, cofp_hm);
		        } else {
                    cb_fn(arg, pbuf); 
		        }
                free(pbuf);
            }
            n_hosts++;
            free_cbuf(b);
        } else {
            break;
        }
    }
    return n_hosts;
}

/**
 * @name mul_fabric_show_routes -
 * @brief ml-api to get all host-routes in fabric
 * @ingroup Fabric Application 
 * 
 * @param [in] service pointer to fabric service pointer 
 * @param [in] arg: Argument pointer to be passed to cb_fn param 
 * @param [in] call_cb: true if user wants cb_fn to be called for each route 
 * @param [in] show_src_host: callback function for parsing each source 
 * @param [in] show_dst_host:  callback function for parsing each destination 
 * @param [in] show_route_links: Argument pointer to be passed to cb_fn param 
 *
 * @retval int number of routes available 
 */
int
mul_fabric_show_routes(void *service,
                       void *arg,
		               bool call_cb,
                       void (*show_src_host)(void *arg, char *pbuf),
                       void (*show_dst_host)(void *arg, char *pbuf),
                       void (*show_route_links)(void *arg, char *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_route *cofp_r;
    struct c_ofp_route_link *cofp_rl;
    char *pbuf;
    size_t n_links = 0;
    int n_routes = 0;

    if (!service) return 0;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_FAB_SHOW_ROUTES); 
    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_FAB_ROUTE)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *)(b->data);

            if (ntohs(cofp_auc->header.length) <
                sizeof(*cofp_auc) + sizeof(*cofp_r)) {
                free_cbuf(b);
                continue;
            }

    	    if (call_cb){
	        	show_src_host(arg, (char *)cofp_auc);
	        } else {
		        n_links = (ntohs(cofp_auc->header.length) -
                          (sizeof(*cofp_auc) + sizeof(*cofp_r)))/sizeof(*cofp_rl);

                cofp_r = (void *)(cofp_auc->data);
                pbuf = fab_dump_single_host_from_flow(
                           ntohll(cofp_r->src_host.switch_id.datapath_id),
                           &cofp_r->src_host.host_flow,
                           (uint8_t *) cofp_r->src_host.tenant_id,
                           (uint8_t *) cofp_r->src_host.network_id);
                if (pbuf) {
                    show_src_host(arg, pbuf); 
                    free(pbuf);
                }
                pbuf = fab_dump_single_host_from_flow(
                           ntohll(cofp_r->dst_host.switch_id.datapath_id),
                           &cofp_r->dst_host.host_flow,
                           (uint8_t*) cofp_r->dst_host.tenant_id,
                           (uint8_t*) cofp_r->dst_host.network_id);
                if (pbuf) {
                    show_dst_host(arg, pbuf); 
                    free(pbuf);
                }

                pbuf = mul_fabric_route_link_dump(
                                (void *)(cofp_r->route_links), n_links);
                if (pbuf) {
                    show_route_links(arg, pbuf);
                    free(pbuf);
                }
                free_cbuf(b);
	        }
	        n_routes++;
        } else {
            break;
        }
    }
    return n_routes;
}

/**
 * @name mul_fabric_show_tenant_nw -
 *
 */
int
mul_fabric_show_tenant_nw(void *service, void *arg, 
                          void (*cb_fn)(void *arg, void *pbuf)){
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_port_tnid_mod *cofp_tnm;
    int n_tenant = 0;

    if(!service) return n_tenant;
    
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
		    sizeof(struct c_ofp_port_tnid_mod),
		    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_FAB_SHOW_TENANT_NW);
    c_service_send(service, b);
    while(1){
	b = c_service_wait_response(service);
	if (!b)	    break;
	if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
	    !check_reply_type(b, C_AUX_CMD_FAB_SHOW_TENANT_NW)){
	    free_cbuf(b);
	    break;
	}
	cofp_auc = (void *)(b->data);
	if (ntohs(cofp_auc->header.length) <
	    sizeof(*cofp_auc) + sizeof(*cofp_tnm)){
	    free_cbuf(b);
	    break;
	}
	cofp_tnm = (void *)(cofp_auc->data);
	cb_fn(arg, cofp_tnm);
	free_cbuf(b);
	n_tenant++;
    }
    return n_tenant;
}

/**
 * @name mul_fabric_port_tnid_mod
 * @brief Fabric application tenant network modification ml-api
 * @ingroup Fabric Application 
 * 
 * @param [in] service pointer to fabric service pointer 
 * @param [in] dpid: datapath-id of the switch to which tenant network
 *                   needs to be attached 
 * @param [in] port : Port-id of the switch to which tentant network
 *                   needs to be attached.
 * @param [in] tenant_id: Tenant-id in UUID format
 * @param [in] network_id: Network-id in UUID format
 * @param [in] add: true for add and false for delete operation 
 *
 * @retval int zero for success and non-zero for failure
 */
int
mul_fabric_port_tnid_mod(void *service, uint64_t dpid, uint32_t port,
        uint8_t *tenant_id,  uint8_t *network_id, bool add)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_port_tnid_mod * cofp_ptm;
    int ret = -1;

    if (!service) return ret;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
                    sizeof(struct c_ofp_port_tnid_mod),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = add ? htonl(C_AUX_CMD_FAB_PORT_TNID_ADD):
                               htonl(C_AUX_CMD_FAB_PORT_TNID_DEL);
    cofp_ptm = (void *)(cofp_auc->data);
    cofp_ptm->datapath_id = htonll(dpid);
    cofp_ptm->port = htonl(port);
    memcpy(cofp_ptm->tenant_id, tenant_id, sizeof(uuid_t));
    memcpy(cofp_ptm->network_id, network_id, sizeof(uuid_t));

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        if (check_reply_type(b, C_AUX_CMD_SUCCESS)) {
            ret = 0;
        }

        free_cbuf(b);
    }

    return ret;
}

/**
 * @name mul_fabric_port_tnid_show -
 *
 */
int
mul_fabric_port_tnid_show(void *service, bool dump, void *arg,
                          void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_port_tnid_mod *cofp_ptm;
    int n_hosts=0;
    char *pbuf;

    if (!service) return -1;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_FAB_PORT_TNID_SHOW);
    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_FAB_PORT_TNID_ADD)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *)(b->data);
            cofp_ptm = (void *)(cofp_auc->data);

            if (ntohs(cofp_auc->header.length)  <
                sizeof(*cofp_auc) + sizeof(*cofp_ptm)) {
                free_cbuf(b);
                break;

            }
	    if(dump){
		    pbuf = fab_dump_port_tnid(ntohll(cofp_ptm->datapath_id),
			                		  ntohl(cofp_ptm->port),
					                  cofp_ptm->tenant_id,
                					  cofp_ptm->network_id);
	 	    cb_fn(arg, pbuf);
	    } else {
		    cb_fn(arg, (void *)cofp_ptm);
	    }
	    n_hosts++;
	    free_cbuf(b);
	} else {
	    break;
	}
    }
    return n_hosts;
}

/**
 * @name mul_fabric_show_host_routes -
 *
 */
int
mul_fabric_show_host_routes(void *service, void *arg, 
            				struct flow *fl, 
                            uint8_t *tenant_id, uint8_t *network_id,
			            	void (*cb_fn)(void *arg, char *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_host_mod *cofp_hm;
    struct c_ofp_route *cofp_r;
    int ret = -1, n_routes = 0;

    if (!service) return ret;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
                    sizeof(struct c_ofp_host_mod),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_FAB_SHOW_HOST_ROUTE);
    cofp_hm = (void *)(cofp_auc->data);
    memcpy(&cofp_hm->host_flow, fl, sizeof(*fl));
    memcpy(cofp_hm->tenant_id, tenant_id, sizeof(uuid_t));
    memcpy(cofp_hm->network_id, network_id, sizeof(uuid_t));

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_FAB_ROUTE)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *)(b->data);

            if (ntohs(cofp_auc->header.length) <
                sizeof(*cofp_auc) + sizeof(*cofp_r)) {
                free_cbuf(b);
                continue;
            }
	        cb_fn(arg, (char *)cofp_auc);
            free_cbuf(b);
            n_routes++;
        } else {
            break;
        }
    }
    return n_routes;
}
