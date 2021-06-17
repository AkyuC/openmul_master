/*
 *  makdi_servlet.c: makdi cli service 
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
#include "mul_common.h"
#include "makdi_servlet.h"
#include "mul_app_main.h"

#define SERV_CHAIN_PBUF_SZ  4096

static bool check_reply_type(struct cbuf *b, uint32_t cmd_code) {
    c_ofp_auxapp_cmd_t *cofp_auc = (void *) (b->data);

    if (ntohs(cofp_auc->header.length) < sizeof(*cofp_auc)) {
        return false;
    }

    if (cofp_auc->header.type != C_OFPT_AUX_CMD
            || cofp_auc->cmd_code != htonl(cmd_code)) {
        return false;
    }

    return true;
}

/**
 * mul_makdi_show_service_chain -
 *
 * Dump service chain user information
 */
char *
makdi_dump_service_chain(struct c_ofp_s_chain_show *sc_info) 
{
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    struct c_ofp_s_chain_show *_chain_info;
    struct c_ofp_s_chain_nfv_info *_nfv_info;
    int nfv_counter = 0;
    uint8_t len = 0;
    struct in_addr in;
    
    _chain_info = sc_info;
    in.s_addr = _chain_info->nw_src;
    len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                    "User IP(%s) : DP[0x%llx] \r\n", inet_ntoa(in),
                    U642ULL(ntohll(_chain_info->dpid)));

    while (nfv_counter < _chain_info->nfv_list.num_nfvs) {
        _nfv_info = &_chain_info->nfv_list.nfv_info[nfv_counter++];
        len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                            " - NFV Group(%s) : NFV(%s) : dpid(0x%llx) "
                            "iif(%hu) oif(%hu)\r\n",
                            _nfv_info->nfv_group, _nfv_info->nfv,
                            U642ULL(ntohll(_nfv_info->dpid)),
                            ntohs(_nfv_info->iif), ntohs(_nfv_info->oif));
    }
    assert(len < SERV_CHAIN_PBUF_SZ - 1);

    return pbuf;
}

/**
 * mul_makdi_show_service_chain_cmd -
 *
 * Dump service chain user information in command format
 */
static void
makdi_dump_service_chain_cmd(struct c_ofp_s_chain_show *sc_info,
                             void *arg,
                             void (*cb_fn)(void *arg, void *pbuf)) 
{
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    struct c_ofp_s_chain_show *_chain_info;
    struct c_ofp_s_chain_nfv_info *_nfv_info;
    int nfv_counter = 0;
    uint8_t len = 0;
    struct in_addr in;

    if (!pbuf) return;
    
    _chain_info = sc_info;
    in.s_addr = _chain_info->nw_src;
    len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                    "add makdi-service-chain switch 0x%llx service %s "
                    "host-ip %s",
                    U642ULL(ntohll(_chain_info->dpid)),
                    _chain_info->service,
                    inet_ntoa(in));

    while (nfv_counter < 6) { /* Max number allowed by CLI may change */
        _nfv_info = &_chain_info->nfv_list.nfv_info[nfv_counter];
        len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                        " nfv-grp%d %s",
                        nfv_counter+1,
                        nfv_counter < _chain_info->nfv_list.num_nfvs ?
                        _nfv_info->nfv_group : "*");
        nfv_counter++;
        assert(len < SERV_CHAIN_PBUF_SZ - 1);
    }

    len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1, "\r\n");
    assert(len < SERV_CHAIN_PBUF_SZ - 1);

    cb_fn(arg, pbuf);
    free(pbuf);
    return;
}

/**
 * mul_makdi_show_service_chain -
 * To dump service chain user information
 *
 */
char *
makdi_dump_service_chain_user(struct c_ofp_host_mod* user_info,
                              struct c_ofp_s_chain_nfv_list* nfv_list)
{
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    char *fl_str = NULL;

    int len = 0;
    int fl_len = 0;
    uint8_t nfv_counter = 0;

    struct flow* fl = &user_info->host_flow;
    struct flow mask;
    struct c_ofp_s_chain_nfv_info* nfv_info = NULL;

    memset(&mask, 0xff, sizeof(struct flow));
    /* Dumping User Info*/
    fl_str = of_dump_flow_generic(fl, &mask);
    fl_len = strlen(fl_str);
    strcpy(pbuf, fl_str);
    len += fl_len;
    assert(len < SERV_CHAIN_PBUF_SZ - 1);
    free(fl_str);

    /*Dumping NFV list*/
    while (nfv_counter < nfv_list->num_nfvs) {
        nfv_info = &nfv_list->nfv_info[nfv_counter];

        len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                "\nNFV(%s) dpid(0x%llx) iif(%hu) oif(%hu)", nfv_info->nfv,
                U642ULL(nfv_info->dpid), nfv_info->iif, nfv_info->oif);
        assert(len < SERV_CHAIN_PBUF_SZ - 1);
    }

    return pbuf;

}

/**
 * makdi_dump_services -
 */
char *
makdi_dump_services(struct c_ofp_service_info *service_info) {
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    struct c_ofp_service_info *_service_info;
    uint8_t len = 0;

    /*Dumping Service list*/
    _service_info = service_info;
    len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                "Service(%s) vlan(%u)\r\n", _service_info->service,
                ntohs(_service_info->vlan));
    assert(len < SERV_CHAIN_PBUF_SZ - 1);
    return pbuf;
}

/**
 * makdi_dump_services_cmd -
 */
static void
makdi_dump_services_cmd(struct c_ofp_service_info *service_info,
                        void *arg,
                        void (*cb_fn)(void *arg, void *pbuf))
{
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    struct c_ofp_service_info *_service_info;
    uint8_t len = 0;

    if (!pbuf) return;

    /*Dumping Service list*/
    _service_info = service_info;
    _service_info->service[MAX_NFV_NAME - 1] = '\0';
    len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                    "add makdi-service %s vlan %hu\r\n",
                    _service_info->service,
                    ntohs(_service_info->vlan));
    assert(len < SERV_CHAIN_PBUF_SZ - 1);
    cb_fn(arg, pbuf);
    free(pbuf);
    return;
}

int
mul_makdi_group_mod(void *service, char *group_id, bool add)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_s_chain_nfv_group_info *cofp_nfv_group_info;
    int ret = -1;

    if (!service)
        return -1;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
                    sizeof(struct c_ofp_s_chain_nfv_group_info),
                    C_OFPT_AUX_CMD, 0);
   cofp_auc = (void *) (b->data);

   if (add)
       cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_NFV_GROUP_ADD);
   else
       cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_NFV_GROUP_DEL);
   cofp_nfv_group_info = (void *) (cofp_auc->data);
   strncpy(cofp_nfv_group_info->nfv_group, group_id, MAX_NFV_NAME - 1);

   cofp_nfv_group_info->nfv_group[MAX_NFV_NAME - 1] = '\0';

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
 * makdi_dump_nfv_groups -
 */
char *
makdi_dump_nfv_groups(struct c_ofp_s_chain_nfv_group_info *nfv_group_info)
{
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    struct c_ofp_s_chain_nfv_info *_nfv_info;
    int nfv_counter = 0;
    uint8_t len = 0;

    /*Dumping Service list*/
    len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                        "NFV Group(%s) \r\n", nfv_group_info->nfv_group);
    while (nfv_counter < nfv_group_info->nfv_list.num_nfvs) {
        _nfv_info = &nfv_group_info->nfv_list.nfv_info[nfv_counter++];
        len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                        " - NFV(%s) : dpid(0x%llx) iif(%hu) oif(%hu)\r\n",
                        _nfv_info->nfv,
                        U642ULL(ntohll(_nfv_info->dpid)),
                        ntohs(_nfv_info->iif),
                        ntohs(_nfv_info->oif));
    }
    assert(len < SERV_CHAIN_PBUF_SZ - 1);
    return pbuf;
}

/**
 * makdi_dump_nfv_groups -
 */
char *
makdi_dump_servicechain_default(
        struct c_ofp_default_rule_info *cofp_default_rule_info) {
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    struct c_ofp_default_rule *default_rule;
    uint8_t nfv_counter = 0;
    uint8_t len = 0;

    /*Dumping Service list*/
        len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                "Service (%s) : Level (%x) : ", cofp_default_rule_info->service, ntohs(cofp_default_rule_info->level));
        while (nfv_counter < cofp_default_rule_info->num_nfvs) {
            default_rule = &cofp_default_rule_info->group_list[nfv_counter++];
            len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                    " NFV(%s) ", default_rule->nfv_group);
        }
        len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                "\r\n");
        nfv_counter = 0;
        assert(len < SERV_CHAIN_PBUF_SZ - 1);
    
    return pbuf;
}

/**
 * makdi_dump_nfv -
 *
 *
 */
char *
makdi_dump_nfv(struct c_ofp_s_chain_nfv_list *nfv_info) {
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    struct c_ofp_s_chain_nfv_info *_nfv_info;
    uint8_t nfv_counter = 0;
    uint8_t len = 0;

    while (nfv_counter < nfv_info->num_nfvs) {
        _nfv_info = &nfv_info->nfv_info[nfv_counter++];
        len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                "NFV(%s) : dpid(0x%llx) iif(%hu) oif(%hu)\r\n ", _nfv_info->nfv,
                U642ULL(_nfv_info->dpid), _nfv_info->iif, _nfv_info->oif);
    }
    assert(len < SERV_CHAIN_PBUF_SZ - 1);

    return pbuf;
}

/**
 * mul_makdi_show_service_chain -
 * Dumps service chain
 */
int mul_makdi_show_service_chain(void *service, void *arg, bool dump_cmd,
                                 void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_s_chain_show *cofp_serv_chain_show;
    char *pbuf;
    int n_chains = 0;
    struct cbuf_head bufs;
    int retries = 0;

    if (!service)
        return -1;
    
    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SHOW_SERVICE_CHAIN_ALL);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_MAKDI_SHOW_SERVICE_CHAIN_ALL)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *)(b->data);
            cofp_serv_chain_show = (void *)(b->data);
            if (ntohs(cofp_auc->header.length) <
                sizeof(*cofp_serv_chain_show) + sizeof(*cofp_auc)) {
                free_cbuf(b);
                goto try_restart;
            }
            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_chains++;
        } else {
            goto try_restart;
        }
    }
    
    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_auc = (void *) (b->data);
        cofp_serv_chain_show = (void *)(cofp_auc->data);
        if (dump_cmd) {
            makdi_dump_service_chain_cmd(cofp_serv_chain_show, arg,
                                         cb_fn);
        } else {
            pbuf = makdi_dump_service_chain(cofp_serv_chain_show);
            if (pbuf) {
                cb_fn(arg, pbuf);
                free(pbuf);
            }
        }
        free_cbuf(b);
    }
    return n_chains;

try_restart:
    cbuf_list_purge(&bufs);
    if (retries++ >= C_SERV_RETRY_CNT) {
        cbuf_list_purge(&bufs);
        c_log_err("%s: Restarting serv msg", FN);
        goto try_again;
    }
    c_log_err("%s: Can't restart serv msg", FN);
    return 0;
}


/**
 * mul_makdi_show_service -
 *
 */
int
mul_makdi_show_service(void *service, void *arg, bool dump_cmd,
                       void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_service_info *cofp_services;
    char *pbuf;
    int n_services = 0;
    struct cbuf_head bufs;
    int retries = 0;

    if (!service)
        return -1;
    
    cbuf_list_head_init(&bufs);

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SHOW_SERVICE);

try_again:
    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_MAKDI_SHOW_SERVICE)) {
                /*Service sends SUCCESS as last response message*/
                free_cbuf(b);
                break;
            }
            cofp_auc = CBUF_DATA(b);
            cofp_services = (void *) (cofp_auc->data);
            if (ntohs(cofp_auc->header.length) <
                    sizeof(*cofp_services) + sizeof(*cofp_auc)) {
                free_cbuf(b);
                goto try_restart;
            } 
            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_services++;
        } else {
            goto try_restart;
        }
    }
    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_auc = (void *) (b->data);
        cofp_services = (void *)(cofp_auc->data);
        if (dump_cmd) {
            makdi_dump_services_cmd(cofp_services, arg, cb_fn);
        } else {
            pbuf = makdi_dump_services(cofp_services);
            if (pbuf) {
                cb_fn(arg, pbuf);
                free(pbuf);
            }
        }
        free_cbuf(b);
    }
    return n_services;

try_restart:
    cbuf_list_purge(&bufs);
    if (retries++ >= C_SERV_RETRY_CNT) {
        cbuf_list_purge(&bufs);
        c_log_err("%s: Restarting serv msg", FN);
        goto try_again;
    }
    c_log_err("%s: Can't restart serv msg", FN);
    return 0;
}

/**
 * mul_makdi_nfvtopology_node_mod -
 *
 *
 */
int mul_makdi_nfv_mod(void *service, uint64_t dpid, char *group_id,
        uint16_t iif, uint16_t oif, char *nfv, bool add) {
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_s_chain_nfv_info *cofp_nfv_info;
    int ret = -1;

    if (!service)
        return -1;

    b = of_prep_msg(
            sizeof(struct c_ofp_auxapp_cmd)
                    + sizeof(struct c_ofp_s_chain_nfv_info), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    if (add)
        cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_NFV_ADD);
    else
        cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_NFV_DEL);
    cofp_nfv_info = (void *) (cofp_auc->data);
    cofp_nfv_info->dpid = htonll(dpid);
    cofp_nfv_info->iif = htons(iif);
    cofp_nfv_info->oif = htons(oif);

    strncpy(cofp_nfv_info->nfv_group, group_id, MAX_NFV_NAME - 1);
    cofp_nfv_info->nfv_group[MAX_NFV_NAME - 1] = '\0';
    strncpy(cofp_nfv_info->nfv, nfv, MAX_NFV_NAME - 1);
    cofp_nfv_info->nfv[MAX_NFV_NAME - 1] = '\0';

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        if (check_reply_type(b, C_AUX_CMD_SUCCESS)) {
            ret = 0;
        } else
            ret = 1;

        free_cbuf(b);
    }
    return ret;
}

static void
makdi_dump_nfv_groups_cmd(struct c_ofp_s_chain_nfv_group_info *nfv_group_info,
                          void *arg, void (*cb_fn)(void *arg, void *pbuf))
{
    char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
    struct c_ofp_s_chain_nfv_info *_nfv_info;
    int nfv_counter = 0;
    uint8_t len = 0;

    if (!pbuf) return;

    nfv_group_info->nfv_group[MAX_NFV_NAME - 1] = '\0';
    len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                    "add makdi-nfv-group %s\r\n", nfv_group_info->nfv_group);
    while (nfv_counter < nfv_group_info->nfv_list.num_nfvs) {
        _nfv_info = &nfv_group_info->nfv_list.nfv_info[nfv_counter++];
        _nfv_info->nfv[MAX_NFV_NAME - 1] = '\0';
        len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1,
                        "add makdi-nfv group %s nfv %s switch 0x%llx "
                        "in-port %hu out-port %hu\r\n",
                        nfv_group_info->nfv_group,
                        _nfv_info->nfv,
                        U642ULL(ntohll(_nfv_info->dpid)),
                        ntohs(_nfv_info->iif),
                        ntohs(_nfv_info->oif));
    }
    assert(len < SERV_CHAIN_PBUF_SZ - 1);

    cb_fn(arg, pbuf);
    free(pbuf);
    return;
}

/**
 * mul_makdi_show_nfv -
 */
int mul_makdi_show_nfv(void *service, void *arg, bool dump_cmd,
                       void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_s_chain_nfv_group_info *cofp_nfv_group;
    char *pbuf;
    int n_groups = 0;
    struct cbuf_head bufs;
    int retries = 0;

    if (!service)
        return -1;

    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SHOW_NFV);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_MAKDI_SHOW_NFV_GROUP)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *) (b->data);
            cofp_nfv_group = (void *) (cofp_auc->data);
            if (ntohs(cofp_auc->header.length)
                   < sizeof(*cofp_nfv_group) + sizeof(*cofp_auc)) {
                free_cbuf(b);
                goto try_restart;
            }
            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_groups++;
        } else {
            goto try_restart;
            break;
        }
    }
    
    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_auc = (void *) (b->data);
        cofp_nfv_group = (void *)(cofp_auc->data);
        if (dump_cmd) {
            makdi_dump_nfv_groups_cmd(cofp_nfv_group, arg, cb_fn);
        } else {
            pbuf = makdi_dump_nfv_groups(cofp_nfv_group);
            if (pbuf) {
                cb_fn(arg, pbuf);
                free(pbuf);
            }
        }
        free_cbuf(b);
    }
    return n_groups;

try_restart:
    cbuf_list_purge(&bufs);
    if (retries++ < C_SERV_RETRY_CNT) {
        cbuf_list_purge(&bufs);
        c_log_err("%s: Restarting serv msg", FN);
        goto try_again;
    }
    c_log_err("%s: Can't restart serv msg", FN);
    return 0;
}

/**
 * mul_makdi_servicechain_mod -
 *
 * Call static int nfv_add(makdi_hdl_t *hdl, const char *name, uint64_t dpid,
 uint16_t iif, uint16_t oif) function
 */
int mul_makdi_servicechain_mod(void *service, uint64_t dpid, uint32_t port,
                               char *service_name, uint32_t user_ip, int nfvc, 
                               char **nfv_group_list, bool add)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_s_chain_mod *cofp_scm;
    int ret = -1;
    int i = 0;

    if (!service)
        return -1;

    if (dpid == ULONG_MAX && errno == ERANGE) {
        return -1;
    }

    b = of_prep_msg(
            sizeof(struct c_ofp_auxapp_cmd) + sizeof(struct c_ofp_s_chain_mod),
            C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code =
            add ? htonl(C_AUX_CMD_MAKDI_SERVICE_CHAIN_ADD) : htonl(
                            C_AUX_CMD_MAKDI_SERVICE_CHAIN_DEL);
    cofp_scm = (void *) (cofp_auc->data);
    cofp_scm->user_info.switch_id.datapath_id = htonll(dpid);
    cofp_scm->user_info.host_flow.ip.nw_src = htonl(user_ip);
    cofp_scm->user_info.host_flow.in_port = htonl(port);
    strncpy(cofp_scm->service, service_name, MAX_NFV_NAME - 1);

    if (add) {
        cofp_scm->num_nfvs = htonll(nfvc);
        for (i = 0; i < nfvc; i++) {
            strncpy(cofp_scm->nfv_list[i], nfv_group_list[i], MAX_NFV_NAME - 1);
            cofp_scm->nfv_list[i][MAX_NFV_NAME - 1] = '\0';
        }
    }

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
 * mul_makdi_show_nfv -
 */
int mul_makdi_show_servicechain_default(void *service, void *arg, bool nbapi,
        void (*cb_fn)(void *arg, void *pbuf)) {
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_default_rule_info *cofp_servicechain_default;
    char *pbuf;
    int n_services = 0;
    struct cbuf_head bufs;
    int retries = 0;

    if (!service)
        return -1;
    
    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SHOW_DEFAULT_SERVICE);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS)
                    || !check_reply_type(b, C_AUX_CMD_MAKDI_SHOW_DEFAULT_SERVICE)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *) (b->data);
            cofp_servicechain_default = (void *) (cofp_auc->data);
            /*  FIXME : Length missmtach, header.length == 2050
                
            if (ntohs(cofp_nfv_group->header.length) < sizeof(*cofp_nfv_group))
            {   
                free_cbuf(b);
                goto try_restart;
            }
            */
            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_services++;
        } else {
            goto try_restart;
        }
    }

    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_auc = (void *) (b->data);
        cofp_servicechain_default = (void *)(cofp_auc->data);
        if (nbapi) {
            cb_fn(arg, cofp_servicechain_default);
        } else {
            pbuf = makdi_dump_servicechain_default(
                        cofp_servicechain_default);
            if (pbuf) {
                cb_fn(arg, pbuf);
                free(pbuf);
            }
            free_cbuf(b);
        }
    }
    return n_services;

try_restart:
    cbuf_list_purge(&bufs);
    if (retries++ >= C_SERV_RETRY_CNT) {
        cbuf_list_purge(&bufs);
        c_log_err("%s: Restarting serv msg", FN);
        goto try_again;
    }
    c_log_err("%s: Can't restart serv msg", FN);
    return 0;
}

/**
 * mul_makdi_serv_mod -
 *
 * Call static int nfv_add(makdi_hdl_t *hdl, const char *name, uint64_t dpid,
 uint16_t iif, uint16_t oif) function
 */
int mul_makdi_servicechain_default_mod(void *service, char *service_name,
        int nfvc, char **nfv_group_list, bool add, uint16_t level) {
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_default_s_chain_mod *cofp_scm;
    int ret = -1;
    int i = 0;

    if (!service)
        return ret;

    b = of_prep_msg(
            sizeof(struct c_ofp_auxapp_cmd) + sizeof(struct c_ofp_s_chain_mod),
            C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code =
            add ? htonl(C_AUX_CMD_MAKDI_DEFAULT_SERVICE_ADD) : htonl(
                            C_AUX_CMD_MAKDI_DEFAULT_SERVICE_DEL);
    cofp_scm = (void *) (cofp_auc->data);
    cofp_scm->level = htons(level);
    strncpy(cofp_scm->service, service_name, MAX_NFV_NAME - 1);

    if (add) {
        cofp_scm->num_nfvs = htons(nfvc);
        for (i = 0; i < nfvc; i++) {
            strncpy(cofp_scm->nfv_list[i], nfv_group_list[i], MAX_NFV_NAME - 1);
            cofp_scm->nfv_list[i][MAX_NFV_NAME - 1] = '\0';
        }
    }

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
 * mul_makdi_serv_mod -
 *
 * Call static int nfv_add(makdi_hdl_t *hdl, const char *name, uint64_t dpid,
 uint16_t iif, uint16_t oif) function
 */
int mul_makdi_service_mod(void *service, char *service_name, uint16_t vlan,
        bool add) {
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_service_info *cofp_seri;
    int ret = -1;

    if (!service)
        return ret;

    b = of_prep_msg(
            sizeof(struct c_ofp_auxapp_cmd) + sizeof(struct c_ofp_s_chain_mod),
            C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code =
            add ? htonl(C_AUX_CMD_MAKDI_SERVICE_ADD) : htonl(
                            C_AUX_CMD_MAKDI_SERVICE_DEL);
    cofp_seri = (void *) (cofp_auc->data);
    strncpy(cofp_seri->service, service_name, MAX_NFV_NAME);

    if (add)
        cofp_seri->vlan = htons(vlan);

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

static char *
makdi_dump_port_stats(struct c_ofp_auxapp_cmd *cofp_auc,
                      struct c_ofp_switch_port_query *cofp_pq)
{
    char *pbuf = NULL;
    char *buf = NULL;
    size_t feat_len = 0;
    uint8_t version;

    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_PORT_QUERY)) {
        return NULL;
    }

    feat_len = ntohs(cofp_auc->header.length) - (sizeof(*cofp_auc) +
                        sizeof(*cofp_pq));


    cofp_pq = ASSIGN_PTR(cofp_auc->data);
    version = c_app_switch_get_version_with_id(ntohll(cofp_pq->datapath_id));

    if (version == OFP_VERSION_131) {
        if (feat_len < sizeof(struct ofp131_port_stats)) {
            goto err_out;
        }
        buf = of131_port_stats_dump(cofp_pq->data, feat_len);
    }
    else {
        if (feat_len < sizeof(struct ofp_port_stats)) {
            goto err_out;
        }
        buf = of_port_stats_dump(cofp_pq->data, feat_len);
    }

    pbuf = calloc(1, strlen(buf) + 1024);
    if (pbuf) {
        sprintf(pbuf, "attach point->DP[0x%llx]\r\n",
                U642ULL(ntohll(cofp_pq->datapath_id)));
        if (buf) {
            strcat(pbuf, buf);
            free(buf);
        }
        buf = pbuf;
    }
    
    return buf;

err_out:
    buf = calloc(1, 1024);
    if (buf) sprintf(buf, "port-stats disabled for DP[0x%llx]\r\n",
                     U642ULL(ntohll(cofp_pq->datapath_id)));
    return buf;
}

/*
 *
 * mul_makdi_show_nfv_stats_all - return the every nfv ingress/egress port statistics
 *
 */
void
mul_makdi_show_nfv_stats_all(void *service,  void *arg, bool nbapi, 
                             void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_port_query *cofp_pq;
    int n_nfvs = 0;
    struct cbuf_head bufs;
    int retries = 0;
    char *pbuf;

    if (!service)
        return;
    
    cbuf_list_head_init(&bufs);


try_again:
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_NFV_STATS_ALL);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_MUL_SWITCH_PORT_QUERY)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *) (b->data);
            cofp_pq = (void *) (cofp_auc->data);
            if (ntohs(cofp_auc->header.length) <
                    sizeof(*cofp_pq) + sizeof(*cofp_auc)) {
                free_cbuf(b);
                goto try_restart;
            }
            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_nfvs++;
        } else {
            goto try_restart;
        }
    }
    
    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_auc = (void *) (b->data);
        cofp_pq = (void *) (cofp_auc->data);
        if (nbapi) {
            cb_fn(arg, cofp_pq);
        } else {
            pbuf = makdi_dump_port_stats(cofp_auc, cofp_pq);
            if (pbuf) {
                cb_fn(arg, pbuf);
                free(pbuf);
            }
            free_cbuf(b);
        }
    }
    return;

try_restart:
    cbuf_list_purge(&bufs);
    if (retries++ >= C_SERV_RETRY_CNT) {
        cbuf_list_purge(&bufs);
        c_log_err("%s: Restarting serv msg", FN);
        goto try_again;
    }
    c_log_err("%s: Can't restart serv msg", FN);
    return;
}

/*
 *
 * mul_makdi_show_nfv_stats - return the nfv ingress/egress port statistics
 *
 */
void
mul_makdi_show_nfv_stats(void *service, char* nfv_name,
                         void *arg, bool nbapi UNUSED,
                         void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_nfv_stats_show *cofp_nfv_stats;
    char *pbuf;

    if (!service)
        return;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +   
                    sizeof(struct c_ofp_nfv_stats_show), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_NFV_STATS);
    cofp_nfv_stats = (void *) (cofp_auc->data);
    strncpy(cofp_nfv_stats->name, nfv_name, MAX_NFV_NAME);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_MUL_SWITCH_PORT_QUERY)) {
                free_cbuf(b);
                break;
            }
            pbuf = mul_dump_port_stats(b, true);
            if (pbuf) {
                cb_fn(arg, pbuf);
                free(pbuf);
            }
            free_cbuf(b);
        } else {
            break;
        }
    }

}

/*
 * mul_makdi_show_service_stats_all -
 *
 * Return every service ingress/egress port statistics
 *
 */
int mul_makdi_show_service_stats_all(void *service,
                                      void *arg, bool nbapi,
                                      void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_service_stats_show *cofp_services;
    struct cbuf_head bufs;
    int retries = 0;
    int n_chains = 0;

    if (!service)
        return n_chains;
    
    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SERVICE_STATS_ALL);

    c_service_send(service, b);
    
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_MAKDI_SERVICE_STATS_ALL)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *) (b->data);
            cofp_services = (void *) (cofp_auc->data);

            if (ntohs(cofp_auc->header.length) <
                    sizeof(*cofp_services) + sizeof(*cofp_auc)) {
                free_cbuf(b);
                goto try_restart;
            }
            n_chains++;
 
            if (nbapi) {
                cb_fn(arg, &cofp_services->stats);
            } else {
                char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
                uint8_t len = 0;
                len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1, 
                            "Service(%s) : User IP(0x%04x) : dpid(0x%016llx) :"
                            " vlan(%hu) : Packet_Count(%llu) : Byte_Count(%llu)"
                            " : Bps(%s) : PPS(%s) : Inport(%hu) \r\n", 
                    cofp_services->service_name,
                    ntohl(cofp_services->stats.flow.ip.nw_src & 0xffffffff), 
                    U642ULL(ntohll(cofp_services->stats.datapath_id)), 
                    ntohs(cofp_services->stats.flow.dl_vlan), 
                    U642ULL(ntohll(cofp_services->stats.packet_count)), 
                    U642ULL(ntohll(cofp_services->stats.byte_count)), 
                    cofp_services->stats.bps,
                    cofp_services->stats.pps,
                    ntohl(cofp_services->stats.flow.in_port));
                cb_fn(arg, pbuf);
                free_cbuf(b);
                free(pbuf);
            }
        } else {
            goto try_restart;
        }
    }
        
    return n_chains;

try_restart:
    cbuf_list_purge(&bufs);
    if (retries++ >= C_SERV_RETRY_CNT) {
        cbuf_list_purge(&bufs);
        c_log_err("%s: Restarting serv msg", FN);
        goto try_again;
    }
    c_log_err("%s: Can't restart serv msg", FN);
    return 0;
}

/*
 * mul_makdi_show_service_stats -
 *
 * Returns the service ingress/egress port statistics
 *
 */
void mul_makdi_show_service_stats(void *service UNUSED, char* name UNUSED,
                                  void *arg UNUSED, bool nbapi UNUSED,
                                  void (*cb_fn)(void *arg, void *pbuf) UNUSED)
{
    // TODO:
}

/*
 * mul_makdi_show_user_stats_all - 
 * 
 * Return the every user statistics on service chain domain
 *
 */
int mul_makdi_show_user_stats_all(void *service,
        void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_user_stats_show *cofp_user_stats;  
    struct cbuf_head bufs;
    int retries = 0;
    int n_chains = 0;

    if (!service)
        return n_chains;
    
    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_USER_STATS_ALL);

    c_service_send(service, b);
    while (1) {
    b = c_service_wait_response(service);
    if (b) {
        if (check_reply_type(b, C_AUX_CMD_SUCCESS)
                    || !check_reply_type(b, C_AUX_CMD_MAKDI_USER_STATS_ALL)) {
            free_cbuf(b);
            break;
        }
        cofp_auc = (void *) (b->data);
        cofp_user_stats  = (void *) (cofp_auc->data);
        
        n_chains++;   
   
        if (nbapi) {
            cb_fn(arg, &cofp_user_stats->stats);
        } else {
            char *pbuf = calloc(1, SERV_CHAIN_PBUF_SZ);
            uint8_t len = 0;
            len += snprintf(pbuf + len, SERV_CHAIN_PBUF_SZ - len - 1, "User Flow : %sPacket_Count(%llu) : Byte_Count(%llu) : Bps(%s) : PPS(%s) \r\n", 
                    of_dump_flow(&cofp_user_stats->stats.flow, 0),
                    U642ULL(ntohll(cofp_user_stats->stats.packet_count)), 
                    U642ULL(ntohll(cofp_user_stats->stats.byte_count)), 
                    cofp_user_stats->stats.bps, cofp_user_stats->stats.pps);
            cb_fn(arg, pbuf);
            free_cbuf(b);
            free(pbuf);
        }
    } else {
        goto try_restart;
    }
    }
    return n_chains;

try_restart:
    cbuf_list_purge(&bufs);
    if (retries++ >= C_SERV_RETRY_CNT) {
        cbuf_list_purge(&bufs);
        c_log_err("%s: Restarting serv msg", FN);
        goto try_again;
    }
    c_log_err("%s: Can't restart serv msg", FN);
    return -1;
}

/*
 * mul_makdi_show_user_stats - 
 *
 * Return the user ingress/egress port statistics
 * on the edge ingress switch
 */
void
mul_makdi_show_user_stats(void *service UNUSED, char* user UNUSED,
                          void *arg UNUSED, bool nbapi UNUSED,
                          void (*cb_fn)(void *arg, void *pbuf) UNUSED)
{
    // TODO
}


