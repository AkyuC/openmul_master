/*
 *  mul_servlet.c: MUL controller service 
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
#include "mul_servlet.h"

static char print_sep[] =
            "-------------------------------------------"
            "----------------------------------\r\n";

static char print_nl[] = "\r\n";

static void
ofp_switch_states_tostr(char *string, uint32_t state)
{
    if (state == 0) {
        strcpy(string, "Init\n");
        return;
    }
    if (state & SW_PUBLISHED) {
        strcpy(string, "Published");
    }
    else if (state & SW_REGISTERED) {
        strcpy(string, "Registered ");
    }
    if (state & SW_REINIT) {
        strcat(string, "Reinit");
    }
    if (state & SW_REINIT_VIRT) {
        strcat(string, "Reinit-Virt");
    }
    if (state & SW_DEAD) {
        strcat(string, "Dead");
    }
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
        /* c_log_err("%s: type(%hu) cmd_code (%u)", FN,
                  cofp_auc->header.type, ntohl(cofp_auc->cmd_code)); */
        return false;
    }
 
    return true;
}

/**
 * mul_get_switches_brief -
 *
 * Get a brief of all switches connected to mul 
 */
struct cbuf *
mul_get_switches_brief(void *service)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;

    if (!service) return NULL;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_GET_SWITCHES);

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        if (!check_reply_type(b, C_AUX_CMD_MUL_GET_SWITCHES_REPLY)) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return NULL;
        }
    }

    return b;
}
     

/**
 * mul_dump_switches_brief -
 */
char *
mul_dump_switches_brief(struct cbuf *b, bool free_buf)
{
    char    *pbuf = calloc(1, SWITCH_BR_PBUF_SZ);
    int     len = 0; 
    int     i = 0, n_switches;
    char    string[OFP_PRINT_MAX_STRLEN];
    c_ofp_auxapp_cmd_t *cofp_auc;
    c_ofp_switch_brief_t *cofp_swb;
    
    if (!pbuf) {
        c_log_err("%s: pbuf alloc failed", FN);
        goto out;
    }

    cofp_auc = (void *)(b->data);
    n_switches = (ntohs(cofp_auc->header.length) - sizeof(c_ofp_auxapp_cmd_t))/
                 sizeof(c_ofp_switch_brief_t);

    cofp_swb = (void *)(cofp_auc->data);
    for (; i < n_switches; i++) {
        cofp_swb->conn_str[OFP_CONN_DESC_SZ-1] = '\0';
        ofp_switch_states_tostr(string, ntohll(cofp_swb->state));
        len += snprintf(pbuf + len, SWITCH_BR_PBUF_SZ-len-1,
                        "0x%016llx    %-11s %-26s %-8d\r\n",
                        U642ULL(ntohll(cofp_swb->switch_id.datapath_id)),
                        string,
                        cofp_swb->conn_str,
                        ntohl(cofp_swb->n_ports));
        if (len >= SWITCH_BR_PBUF_SZ-1) {
            c_log_err("%s: pbuf overrun", FN);
            break;
        }
        cofp_swb += 1;
    }

out:
    if (free_buf) {
        if (b) free_cbuf(b);
    }    

    return pbuf;
}

/**
 * mul_get_switch_detail -
 *
 * Get detail switch info connected to mul 
 */
struct cbuf *
mul_get_switch_detail(void *service, uint64_t dpid)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_req_dpid_attr *cofp_rda;
    struct ofp_header *h;

    if (!service) return NULL;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_GET_SWITCH_DETAIL);
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        h = (void *)(b->data);
        if (h->type != C_OFPT_SWITCH_ADD ||
            ntohs(h->length) < sizeof(struct ofp_switch_features)) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return NULL;
        }
    }

    return b;
}
 

/**
 * mul_dump_switch_detail -
 */
char *
mul_dump_switch_detail(struct cbuf *b, bool free_buf)
{
    char    *pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    int     len = 0; 
    int     i = 0, n_ports;
    struct c_ofp_switch_add *osf = CBUF_DATA(b);
    char    string[OFP_PRINT_MAX_STRLEN];
    uint8_t version;

    version = c_app_switch_get_version_with_id(ntohll(osf->datapath_id));
    if (version != OFP_VERSION && version !=  OFP_VERSION_131 && 
            version != OFP_VERSION_140) {
        c_log_err("%s: Unsupported OFP version %d", FN,version );
        return NULL;
    }

    
    if (!pbuf) {
        c_log_err("%s: pbuf alloc failed", FN);
        goto out;
    }

    n_ports = ((ntohs(osf->header.length)
                - offsetof(struct ofp_switch_features, ports))
            / sizeof *osf->ports);

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, "Datapath-id : 0x%llx\r\n",
                    U642ULL(ntohll(osf->datapath_id)));
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, "Alias-id    : %d\r\n",
                    (int)(U322UL(ntohl(osf->sw_alias))));
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, "OFP-ver     : %d\r\n",
                    osf->ver);
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Buffers     : %d\r\n",ntohl(osf->n_buffers));
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Tables      : %d\r\n", osf->n_tables);
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

#if 0 // This is deprecated with OF1.3.1
    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Actions     : 0x%x\r\n", ntohl(osf->actions));
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 
#endif

    memset(string, 0, 64);
    if (version == OFP_VERSION) {
        of_capabilities_tostr(string, ntohl(osf->capabilities));
    } else if (version == OFP_VERSION_131 || version == OFP_VERSION_140) {
        of131_capabilities_tostr(string, ntohl(osf->capabilities));
    }

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Capabilities: 0x%x(%s)\r\n", ntohl(osf->capabilities),
                    string);
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Num Ports   : %d\r\n", n_ports);
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
            "-------------------------------------------"
            "----------------------------------\r\n");
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "                              Port info\r\n");
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
            "-------------------------------------------"
            "----------------------------------\r\n");
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 


    for (i = 0; i < n_ports; i ++) {
        struct c_sw_port   *p_info = &osf->ports[i];

        p_info->name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
        memset(string, 0, OFP_PRINT_MAX_STRLEN);

        ofp_dump_port_type(string, p_info->type);

        if (version == OFP_VERSION) {
            ofp_dump_port_details(string, ntohl(p_info->of_config),
                    ntohl(p_info->of_state));
        } else {
            ofp131_dump_port_details(string, ntohl(p_info->of_config),
                    ntohl(p_info->of_state));
        }
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                "0x%-12x %-10s %02x:%02x:%02x:%02x:%02x:%02x %-15s\r\n",
                ntohl(p_info->port_no), p_info->name,
                p_info->hw_addr[0], p_info->hw_addr[1],
                p_info->hw_addr[2], p_info->hw_addr[3],
                        p_info->hw_addr[4], p_info->hw_addr[5],
                        string);
        if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

        memset(string, 0, OFP_PRINT_MAX_STRLEN);
    }


out:
    if (free_buf) {
        if (b) free_cbuf(b);
    }    

    return pbuf;
out_pbuf_err:
    c_log_err("%s: pbuf overrun", FN);
    goto out;
}

/**
 * mul_get_switch_features -
 *
 * Get detail switch info connected to mul 
 */
struct cbuf *
mul_get_switch_features(void *service, uint64_t dpid, uint8_t table,
                        uint32_t type)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_feature_common *cofp_f;
    struct ofp_header *h;
    uint8_t version;

    if (!service) return NULL;

    version = c_app_switch_get_version_with_id(dpid);
    if (version != OFP_VERSION && version !=  OFP_VERSION_131 
            && version != OFP_VERSION_140) {
        c_log_err("%s:Unsupported OFP version", FN);
        return NULL;
    }

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_f),
                    C_OFPT_AUX_CMD, 0);

    switch (type) {
    case C_AUX_CMD_MUL_SWITCH_METER_FEAT:
    case C_AUX_CMD_MUL_SWITCH_TABLE_FEAT:
    case C_AUX_CMD_MUL_SWITCH_GROUP_FEAT:
        break; 
    default:
        free_cbuf(b);
        NOT_REACHED();
    }

    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(type);
    cofp_f = ASSIGN_PTR(cofp_auc->data);
    cofp_f->datapath_id = htonll(dpid);
    cofp_f->table_id = table;

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        h = CBUF_DATA(b);
        if (h->type != C_OFPT_AUX_CMD ||
            ntohs(h->length) < sizeof(*cofp_f)) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return NULL;
        }
    }

    return b;
}
 
/**
 * mul_dump_switch_table_features -
 */
char *
mul_dump_switch_table_features(struct cbuf *b, bool free_buf)
{
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_feature_common *cofp_f;
    char *buf = NULL;
    uint8_t version;

    if (!b) return NULL;

    cofp_auc = CBUF_DATA(b);
    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_TABLE_FEAT)) {
        goto free_out;
    }

    if (ntohs(cofp_auc->header.length) -
        (sizeof(*cofp_auc) + sizeof(*cofp_f)) < 
        sizeof(struct of_flow_tbl_props)) {
        c_log_err("%s: Len error", FN);
        goto free_out;
    }

    cofp_f = ASSIGN_PTR(cofp_auc->data);

    version = c_app_switch_get_version_with_id(ntohll(cofp_f->datapath_id));
    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        c_log_err("%s:Unsupported OFP version", FN);
        goto free_out;
    }
                                
    buf = of131_table_features_dump((void *)(cofp_f->data));
free_out:
    if (free_buf) {
        free_cbuf(b);
    }
    return buf;
}

/**
 * mul_dump_switch_group_features -
 */
char *
mul_dump_switch_group_features(struct cbuf *b, bool free_buf)
{
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_feature_common *cofp_f;
    char *buf = NULL;
    uint8_t version;

    if (!b) return NULL;

    cofp_auc = CBUF_DATA(b);
    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_GROUP_FEAT)) {
        goto free_out;
    }

    if (ntohs(cofp_auc->header.length) -
        (sizeof(*cofp_auc) + sizeof(*cofp_f)) < 
        sizeof(struct ofp_group_features)) {
        c_log_err("%s: Len error", FN);
        goto free_out;
    }

    cofp_f = ASSIGN_PTR(cofp_auc->data);
    
    version = c_app_switch_get_version_with_id(ntohll(cofp_f->datapath_id));
    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        c_log_err("%s:Unsupported OFP version", FN);
        goto free_out;
    }

    buf = of131_group_features_dump(cofp_f->data,
                                    sizeof(struct ofp_group_features));
free_out:
    if (free_buf) {
        free_cbuf(b);
    }
    return buf;
}

/**
 * mul_dump_switch_meter_features -
 */
char *
mul_dump_switch_meter_features(struct cbuf *b, bool free_buf)
{
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_feature_common *cofp_f;
    char *buf = NULL;
    uint8_t version;

    if (!b) return NULL;

    cofp_auc = CBUF_DATA(b);
    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_METER_FEAT)) {
        goto free_out;
    }

    if (ntohs(cofp_auc->header.length) -
        (sizeof(*cofp_auc) + sizeof(*cofp_f)) < 
        sizeof(struct ofp_meter_features)) {
        c_log_err("%s: Len error", FN);
        goto free_out;
    }
    
    cofp_f = ASSIGN_PTR(cofp_auc->data);

    version = c_app_switch_get_version_with_id(ntohll(cofp_f->datapath_id));
    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        c_log_err("%s:Unsupported OFP version", FN);
        goto free_out;
    }

    buf = of131_meter_features_dump(cofp_f->data,
                                    sizeof(struct ofp_meter_features));

free_out:
    if (free_buf) {
        free_cbuf(b);
    }
    return buf;
}

/**
 * mul_dump_port_stats -
 */
char *
mul_dump_port_stats(struct cbuf *b, bool free_buf)
{
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_port_query *cofp_pq;
    char *buf = NULL;
    size_t feat_len = 0;
    uint8_t version;

    if (!b) return NULL;

    cofp_auc = CBUF_DATA(b);
    if (cofp_auc->cmd_code != htonl(C_AUX_CMD_MUL_SWITCH_PORT_QUERY)) {
        goto free_out;
    }

    feat_len = ntohs(cofp_auc->header.length) - (sizeof(*cofp_auc) +
                        sizeof(*cofp_pq));

    
    cofp_pq = ASSIGN_PTR(cofp_auc->data);

    version = c_app_switch_get_version_with_id(ntohll(cofp_pq->datapath_id));

    if (version == OFP_VERSION_131) {
        if (feat_len < sizeof(struct ofp131_port_stats)) {
            c_log_err("%s: Len error", FN);
            goto free_out;
        }
        buf = of131_port_stats_dump(cofp_pq->data, feat_len);
    }
    else
    {
        if (feat_len < sizeof(struct ofp_port_stats)) {
            c_log_err("%s OF10: Len error", FN);
            goto free_out;
        }
        buf = of_port_stats_dump(cofp_pq->data, feat_len);
    }

free_out:
    if (free_buf) {
        free_cbuf(b);
    }
    return buf;
}

static void
mul_dump_single_flow(struct c_ofp_flow_info *cofp_fi, void *arg,
                     void (*cb_fn)(void *arg, void *pbuf))
{
    char     *pbuf;
    int      len = 0;
    size_t   action_len;
    uint64_t dpid = U642ULL(ntohll(cofp_fi->datapath_id));
    uint8_t  version;
    uint64_t flags;

    version = c_app_switch_get_version_with_id(dpid);
    if (version != OFP_VERSION && version !=  OFP_VERSION_131 &&
            version !=  OFP_VERSION_140) {
        c_log_err("%s: Unable to parse flow:Unknown OFP version", FN);
        return;
    }

    action_len = ntohs(cofp_fi->header.length) - sizeof(*cofp_fi);

    cb_fn(arg, print_sep);
    pbuf = of_dump_flow_generic(&cofp_fi->flow, &cofp_fi->mask);
    if (pbuf) {
        cb_fn(arg, pbuf);
        free(pbuf);
    }

    if (version == OFP_VERSION)
        pbuf = of10_dump_actions(cofp_fi->actions, action_len, false);
    else if (version == OFP_VERSION_131 || version == OFP_VERSION_140)
        pbuf = of131_dump_actions(cofp_fi->actions, action_len, false);
    else {
        NOT_REACHED();
    }
    if (pbuf) {
        cb_fn(arg, pbuf);
        free(pbuf);
    }

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ); 
    if (!pbuf) return; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "%s:%hu %s:%d ", "Prio", ntohs(cofp_fi->priority),
                    "Table", cofp_fi->flow.table_id);

    flags = ntohll(cofp_fi->flags);
    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "%s: %s %s %s %s %s", "Flags",
                    flags & C_FL_ENT_STATIC ? "static":"dynamic",
                    flags & C_FL_ENT_CLONE ? "clone": "no-clone",
                    flags & C_FL_ENT_NOT_INST ? "not-verified" : "verified",
                    flags & C_FL_ENT_LOCAL ? "local": "non-local", 
                    flags & C_FL_ENT_RESIDUAL ? "residual ":" "); 
    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Datapath-id: 0x%llx ",
                    U642ULL(ntohll(cofp_fi->datapath_id)));

    if (flags & C_FL_ENT_GSTATS) {
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "\r\nStats: Bytes %llu Packets %llu ",
                        U642ULL(ntohll(cofp_fi->byte_count)), 
                        U642ULL(ntohll(cofp_fi->packet_count)));
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Bps %s Pps %s Alive %lu secs:%lu nsecs",
                        cofp_fi->bps, cofp_fi->pps,
                        U322UL(htonl(cofp_fi->duration_sec)),
                        U322UL(htonl(cofp_fi->duration_nsec)));
    }

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "%s", "\r\n");
            
    cb_fn(arg, pbuf);
    free(pbuf);

    cb_fn(arg, print_sep);

    return;

}

static void
mul_dump_single_meter(c_ofp_meter_mod_t *cofp_mm, void *arg,
                      void (*cb_fn)(void *arg, void *pbuf))
{
    char *pbuf, *type, *burst, *stats;
    int len = 0, act = 0;
    ssize_t tot_len = ntohs(cofp_mm->header.length);
    uint64_t dpid = U642ULL(ntohll(cofp_mm->datapath_id));
    uint8_t version;
    char *band_types[] = { "", "drop", "dscp-remark"};
    struct ofp_meter_band_header *band;
    struct ofp_meter_band_dscp_remark *dscp_remark_band;
    size_t band_dist = 0;
    uint16_t flags, c_flags, band_type;
    uint32_t band_rate, burst_size;
    version = c_app_switch_get_version_with_id(dpid);

    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        c_log_err("Unable to parse meter :Unknown OFP version");
        return;
    }

    cb_fn(arg, print_sep);

    flags = htons(cofp_mm->flags);
    c_flags = cofp_mm->c_flags;

    if (flags & OFPMF_KBPS) {
        type = "Kbps";
    } else  if (flags & OFPMF_PKTPS) {
        type = "Pktps";
    } 
    
    if (flags & OFPMF_BURST) {
        burst = "Yes";
    } else {
        burst = "No";
    }
    
    if (flags & OFPMF_STATS) {
        stats = "Yes";
    } else {
        stats = "No";
    }

    tot_len -= sizeof(*cofp_mm);

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    if (!pbuf) return;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "meter-id: %lu Meter Type: %s Burst: %s %s %s Stats: %s\r\n", 
                    U322UL(ntohl(cofp_mm->meter_id)), type, burst, 
                    c_flags & C_METER_EXPIRED ? "(Expired)":"" ,
                    c_flags & C_METER_NOT_INSTALLED ? "(Not-verified)":"",
                    stats);

    if (cofp_mm->c_flags & C_METER_GSTATS) {
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Bytes-in:%llu Packets-in:%llu Flow-Count:%lu\r\n",
                        U642ULL(ntohll(cofp_mm->byte_count)),
                        U642ULL(ntohll(cofp_mm->packet_count)),
                        U322UL(ntohl(cofp_mm->flow_count)));
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Duration: %lu secs %lu nsecs\r\n",
                        U322UL(ntohl(cofp_mm->duration_sec)),
                        U322UL(ntohl(cofp_mm->duration_nsec)));
    }

    cb_fn(arg, pbuf);

    band_dist = sizeof(*cofp_mm);
    while((tot_len >= (int)sizeof(*band)) && (act < OF_MAX_ACT_VECTORS)) {
        size_t band_len = 0;

        band = INC_PTR8(cofp_mm, band_dist);
        band_len = ntohs(band->len);

        band_dist += band_len;

        if (band_len > tot_len) {
            break;
        }

        len = 0;
        band_type = htons(band->type);
        band_rate = htonl(band->rate);
        burst_size = htonl(band->burst_size);
        
        if(band_type != OFPMBT_DSCP_REMARK && band_type != OFPMBT_DROP) {
            c_log_err("%s: Invalid Band Type %u",FN, band_type);
            break;
        }
        
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Band Type %s ", band_types[band_type]);

        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Rate %u ", band_rate);
        
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Burst Size %u ", burst_size);

        if(band_type == OFPMBT_DSCP_REMARK) {

            dscp_remark_band = (struct ofp_meter_band_dscp_remark*) band;

            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Precedence Level %u ", dscp_remark_band->prec_level);
        }
        len+= snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "\r\n");

        cb_fn(arg, pbuf);
        tot_len -= band_len; //+ sizeof(*band);
        act++;
    }

    free(pbuf);
    cb_fn(arg, print_sep);

    return;
}

static void
mul_dump_single_meter_cmd(c_ofp_meter_mod_t *cofp_mm, void *arg,
                          void (*cb_fn)(void *arg, void *pbuf))
{
    char *pbuf, *type, *burst, *stats;
    int len = 0, act = 0;
    ssize_t tot_len = ntohs(cofp_mm->header.length);
    uint64_t dpid = U642ULL(ntohll(cofp_mm->datapath_id));
    uint8_t version;
    char *band_types[] = { "", "drop", "dscp-remark"};
    struct ofp_meter_band_header *band;
    struct ofp_meter_band_dscp_remark *dscp_remark_band;
    size_t band_dist = 0;
    uint16_t flags, c_flags, band_type;
    uint32_t band_rate, burst_size;
    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        c_log_err("Unable to parse meter :Unknown OFP version");
        return;
    }

    flags = htons(cofp_mm->flags);
    c_flags = cofp_mm->c_flags;

    if (c_flags & C_METER_EXPIRED ||
        c_flags & C_METER_NOT_INSTALLED) {
        return;
    }

    if (flags & OFPMF_KBPS) {
        type = "kbps";
    } else  if (flags & OFPMF_PKTPS) {
        type = "pktps";
    } 
    
    if (flags & OFPMF_BURST) {
        burst = "yes";
    } else {
        burst = "no";
    }
    
    if (flags & OFPMF_STATS) {
        stats = "yes";
    } else {
        stats = "no";
    }

    tot_len -= sizeof(*cofp_mm);

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    if (!pbuf) return;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "of-meter add switch 0x%llx meter-id %lu meter-type %s"
                    " burst %s stats %s\r\n", U642ULL(dpid),
                    U322UL(ntohl(cofp_mm->meter_id)), type, burst, 
                    stats);

    band_dist = sizeof(*cofp_mm);
    while((tot_len >= (int)sizeof(*band)) && (act < OF_MAX_ACT_VECTORS)) {
        size_t band_len = 0;

        band = INC_PTR8(cofp_mm, band_dist);
        band_len = ntohs(band->len);

        band_dist += band_len;

        if (band_len > tot_len) {
            break;
        }

        band_type = htons(band->type);
        band_rate = htonl(band->rate);
        burst_size = htonl(band->burst_size);
        
        if(band_type != OFPMBT_DSCP_REMARK && band_type != OFPMBT_DROP) {
            c_log_err("%s: Invalid Band Type %u",FN, band_type);
            goto out;
        }
        
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "meter-band %s rate %u burst-size %u",
                        band_types[band_type], band_rate, burst_size);

        if(band_type == OFPMBT_DSCP_REMARK) {
            dscp_remark_band = (struct ofp_meter_band_dscp_remark*) band;
            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        " prec-level %u", dscp_remark_band->prec_level);
        }
        len+= snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "\r\n");
        tot_len -= band_len; //+ sizeof(*band);
        act++;

        if ((tot_len >= (int)sizeof(*band)) &&
            (act < OF_MAX_ACT_VECTORS)) {
            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "meter-band-next\r\n");
        }

    }

    if (c_flags & C_METER_BARRIER_EN) {
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "meter-barrier-enable\r\n");
    }

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "commit-meter\r\n");
    cb_fn(arg, pbuf);

out:
    free(pbuf);

    return;
}

/**
 * mul_get_meter_info-
 *
 * Dump all meters
 */
int
mul_get_meter_info(void *service, uint64_t dpid,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_ofp_meter_mod_t *cofp_mm;
    struct ofp_header *h;
    int n_meters = 0;
    struct cbuf_head bufs;
    int retries = 0;

    if (!service) return -1;

    if (!cb_fn) {
        c_log_err("%s: cb fn is null", FN);
        return -1;
    }

    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_GET_METERS); 
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            h = (void *)(b->data);
            if (h->type  != C_OFPT_METER_MOD) { 
                free_cbuf(b);
                break;
            }
            cofp_mm = (void *)(b->data);
            if (ntohs(cofp_mm->header.length) < sizeof(*cofp_mm)) {
                free_cbuf(b);
                goto try_restart;
            } 

            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_meters++;
        } else {
            goto try_restart;
        }
    }

    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_mm = (void *)(b->data);
        if (!dump_cmd) {
            if (!nbapi_cmd) {
                mul_dump_single_meter(cofp_mm, arg, cb_fn);
            } else {
                cb_fn(arg, cofp_mm);
            }
        } else {
            mul_dump_single_meter_cmd(cofp_mm, arg, cb_fn);
        }
        free_cbuf(b);
    }
    return n_meters;

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

static void
mul_dump_single_group(c_ofp_group_mod_t *cofp_gm, void *arg,
                      void (*cb_fn)(void *arg, void *pbuf))
{
    char *pbuf, *apbuf, *type;
    int len = 0, act = 0;
    ssize_t tot_len = ntohs(cofp_gm->header.length);
    uint64_t dpid = U642ULL(ntohll(cofp_gm->datapath_id));
    uint8_t version;
    char *grp_types[] = { "all", "select", "indirect", "ff" };
    struct c_ofp_bkt *bkt;
    size_t bkt_dist = 0;
    uint8_t flags;

    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        c_log_err("Unable to parse group:Unknown OFP version");
        return;
    }

    cb_fn(arg, print_sep);

    if (cofp_gm->type > OFPGT_FF) {
        type = "Unknown";
    } else {
        type = grp_types[cofp_gm->type];
    }

    flags = cofp_gm->flags;
    tot_len -= sizeof(*cofp_gm);

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    if (!pbuf) return;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "group-id: %lu %s %s %s\r\n", U322UL(ntohl(cofp_gm->group_id)),
                    type, flags & C_GRP_EXPIRED ? "(Expired)" :"",
                    flags & C_GRP_NOT_INSTALLED ? "(Not-verfied)":""); 
    cb_fn(arg, pbuf);

    if (cofp_gm->flags & C_GRP_GSTATS) {
        len = 0;
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Stats: byte-count %llu packet-count %llu "
                    "Alive %lus %luns\r\n",
                    U642ULL(ntohll(cofp_gm->byte_count)),
                    U642ULL(ntohll(cofp_gm->packet_count)),
                    U322UL(ntohl(cofp_gm->duration_sec)),
                    U322UL(ntohl(cofp_gm->duration_nsec))); 
        cb_fn(arg, pbuf);
    }

    bkt_dist = sizeof(*cofp_gm);
    while(tot_len >= (int)sizeof(*bkt) && act < OF_MAX_ACT_VECTORS) {
        size_t act_len = 0;

        bkt = INC_PTR8(cofp_gm, bkt_dist);
        act_len = ntohs(bkt->act_len);

        bkt_dist += sizeof(*bkt) + act_len;
        if (act_len > (tot_len - sizeof(*bkt))) {
            break;
        }

        len = 0;
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Action-bucket %d:", act);
        cb_fn(arg, pbuf);

        if (version ==  OFP_VERSION_131 || version == OFP_VERSION_140) {
            apbuf = of131_dump_actions(bkt->actions, act_len, true);
        }
        else {
            NOT_REACHED();
        }

        cb_fn(arg, apbuf);
        cb_fn(arg, print_nl);
        if (apbuf) free(apbuf);
        tot_len -= act_len + sizeof(*bkt);
        act++;
    }

    free(pbuf);
    cb_fn(arg, print_sep);

    return;
}

static void
mul_dump_single_group_cmd(c_ofp_group_mod_t *cofp_gm, void *arg,
                          void (*cb_fn)(void *arg, void *pbuf))
{
    char *pbuf, *apbuf, *type;
    int len = 0, act = 0;
    ssize_t tot_len = ntohs(cofp_gm->header.length);
    uint64_t dpid = ntohll(cofp_gm->datapath_id);
    uint8_t version;
    char *grp_types[] = { "all", "select", "indirect", "ff" };
    struct c_ofp_bkt *bkt;
    size_t bkt_dist = 0;

    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131 && version != OFP_VERSION_140) {
        c_log_err("%s:Unable to parse group:Unknown OF ver", FN);
        return;
    }

    if (cofp_gm->type > OFPGT_FF) {
        c_log_err("%s: Parse error: Unknown group type", FN);
        return;
    } else {
        type = grp_types[cofp_gm->type];
    }

    if (cofp_gm->flags & C_GRP_EXPIRED ||
        cofp_gm->flags & C_GRP_NOT_INSTALLED ||
        cofp_gm->flags & C_GRP_RESIDUAL) {
        return;
    }

    tot_len -= sizeof(*cofp_gm);

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    if (!pbuf) return;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "of-group add switch 0x%llx group %lu type %s\r\n", 
                    U642ULL(dpid), U322UL(ntohl(cofp_gm->group_id)), type); 

    bkt_dist = sizeof(*cofp_gm);
    while(tot_len >= (int)sizeof(*bkt) && act < OF_MAX_ACT_VECTORS) {
        size_t act_len = 0;

        bkt = INC_PTR8(cofp_gm, bkt_dist);
        act_len = ntohs(bkt->act_len);

        bkt_dist += sizeof(*bkt) + act_len;
        if (act_len > (tot_len - sizeof(*bkt))) {
            break;
        }

        if (version ==  OFP_VERSION_131 || version == OFP_VERSION_140) {
            apbuf = of131_dump_actions_cmd(bkt->actions, act_len, true);
        }
        else {
            NOT_REACHED();
        }

        strncat(pbuf, apbuf, MUL_SERVLET_PBUF_DFL_SZ-len-1);  
        len += strlen(apbuf);
        if (apbuf) free(apbuf);

        if (cofp_gm->type == OFPGT_FF) {
            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "group-act-vector ff-port %lu\r\n",
                    U322UL(ntohl(bkt->ff_port)));
            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "group-act-vector ff-group %lu\r\n",
                    U322UL(ntohl(bkt->ff_group)));
        } else if (cofp_gm->type == OFPGT_SELECT) {
            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "group-act-vector weight %hu\r\n",
                    ntohs(bkt->weight));
        }
        tot_len -= act_len + sizeof(*bkt);
        act++;
        if (tot_len >= (int)sizeof(*bkt) && act < OF_MAX_ACT_VECTORS) {
            len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                            "group-act-vector-next\r\n");
        }
    }

    if (cofp_gm->flags & C_GRP_GSTATS) {
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "group-stats-enable\r\n");
    } 

    if (cofp_gm->flags & C_GRP_BARRIER_EN) {
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "group-barrier-enable\r\n");
    } 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "commit-group\r\n"); 

    cb_fn(arg, pbuf);
    free(pbuf);

    return;
}

/**
 * mul_get_group_info -
 *
 * Dump all groups 
 */
int
mul_get_group_info(void *service, uint64_t dpid,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_ofp_group_mod_t *cofp_gm;
    struct ofp_header *h;
    int n_groups = 0;
    struct cbuf_head bufs;
    int retries = 0;

    if (!service) return -1;

    if (!cb_fn) {
        c_log_err("%s: cb fn is null", FN);
        return -1;
    }

    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_GET_GROUPS); 
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            h = (void *)(b->data);
            if (h->type  != C_OFPT_GROUP_MOD) { 
                free_cbuf(b);
                break;
            }
            cofp_gm = (void *)(b->data);
            if (ntohs(cofp_gm->header.length) < sizeof(*cofp_gm)) {
                free_cbuf(b);
                goto try_restart;
            } 

            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_groups++;
        } else {
            goto try_restart;
        }
    }

    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_gm = (void *)(b->data);
        if (!dump_cmd) {
            if (!nbapi_cmd) {
                mul_dump_single_group(cofp_gm, arg, cb_fn);
            } else {
                cb_fn(arg, cofp_gm);
            }
        } else {
            mul_dump_single_group_cmd(cofp_gm, arg, cb_fn); 
        }
        free_cbuf(b);
    }
    return n_groups;

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
 * mul_get_flow_info -
 *
 * Dump all flows 
 */
int
mul_get_flow_info(void *service, uint64_t dpid, bool flow_self,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_req_dpid_attr *cofp_rda;
    struct c_ofp_flow_info *cofp_fi;
    struct ofp_header *h;
    int n_flows = 0;
    struct cbuf_head bufs;
    int retries = 0;

    if (!service) return -1;

    if (!cb_fn) {
        c_log_err("%s: cb fn is null", FN);
        return -1;
    }

    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = flow_self ?
                         htonl(C_AUX_CMD_MUL_GET_APP_FLOW):
                         htonl(C_AUX_CMD_MUL_GET_ALL_FLOWS);
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            h = (void *)(b->data);
            if (h->type  != OFPT_FLOW_MOD) { 
                free_cbuf(b);
                break;
            }
            cofp_fi = (void *)(b->data);
            if (ntohs(cofp_fi->header.length) < sizeof(*cofp_fi)) {
                free_cbuf(b);
                goto try_restart;
            } 

            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_flows++;
        } else {
            goto try_restart;
        }
    }

    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_fi = (void *)(b->data);
        if (!dump_cmd) {
            if (!nbapi_cmd) {
                mul_dump_single_flow(cofp_fi, arg, cb_fn);
            } else {
                cb_fn(arg, cofp_fi);
            }
        } else {
            /* TODO */
        }
        free_cbuf(b);
    }
    return n_flows;

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


static void
mul_dump_single_port_q(struct c_ofp_switch_port_query *cofp_pq, 
                       size_t prop_len UNUSED, void *arg,
                       void (*cb_fn)(void *arg, void *pbuf))
{
    char     *pbuf, *q_stat_pbuf = NULL;
    int      len = 0;
    uint64_t dpid = U642ULL(ntohll(cofp_pq->datapath_id));
    uint8_t  version;

    version = c_app_switch_get_version_with_id(dpid);
    if (version != OFP_VERSION && version !=  OFP_VERSION_131) {
        c_log_err("Unable to parse port q:Unknown OFP version");
        return;
    }

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    if (!pbuf) return;

    if (version == OFP_VERSION_131) {
        q_stat_pbuf = of131_dump_queue_stats(cofp_pq->data,
                                             ntohl(cofp_pq->stats_len));
    }

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "q(%lu) %s", U322UL(ntohl(cofp_pq->qid)),
                    q_stat_pbuf ?:"");
    cb_fn(arg, pbuf);
    free(pbuf);
    if (q_stat_pbuf) free(q_stat_pbuf);
}

/**
 * mul_get_flow_info -
 *
 * Dump matched flow for stats
 */
int
mul_get_matched_flow_info(void *service, uint64_t dpid, bool flow_self,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  struct flow *fl, struct flow *mask UNUSED,
                  void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_req_dpid_attr *cofp_rda;

    struct c_ofp_flow_info *cofp_fi;
    struct ofp_header *h;
    int n_flows = 0;
    struct cbuf_head bufs;
    int retries = 0;
    
    if (!service) return -1;
    
    if (!cb_fn) {
        c_log_err("%s: cb fn is null", FN);
        return -1;
    }
    
    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = flow_self ?
                         htonl(C_AUX_CMD_MUL_GET_APP_FLOW):
                         htonl(C_AUX_CMD_MUL_GET_ALL_FLOWS);
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            h = (void *)(b->data);
            if (h->type  != OFPT_FLOW_MOD) { 
                free_cbuf(b);
                break;
            }
            cofp_fi = (void *)(b->data);
            if (ntohs(cofp_fi->header.length) < sizeof(*cofp_fi)) {
                free_cbuf(b);
                goto try_restart;
            }
            
            if (!memcmp(&cofp_fi->flow, &fl, sizeof(struct flow)))
            {  
                b = cbuf_realloc_headroom(b, 0, true);
                cbuf_list_queue_tail(&bufs, b);
                n_flows++;
                goto find;
            }
        } else {
            goto try_restart;
        }
    }

find :
    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_fi = (void *)(b->data);
        if (!dump_cmd) {
            if (!nbapi_cmd) {
                mul_dump_single_flow(cofp_fi, arg, cb_fn);
            } else {
                cb_fn(arg, cofp_fi);
            }
        } else {
            /* TODO */
        }
        free_cbuf(b);
    }
    return n_flows;

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
 * mul_get_port_q_info -
 *
 * Dump all configured queues for a given switch port 
 */
int
mul_get_port_q_info(void *service, uint64_t dpid, uint32_t port, 
                    void *arg, void (*cb_fn)(void *arg, void *pbuf)) 
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_port_query *cofp_pq;
    int n_queues = 0;
    struct cbuf_head bufs;
    int retries = 0;
    size_t q_prop_len = 0;

    if (!service) return -1;

    if (!cb_fn) {
        c_log_err("%s: cb fn is null", FN);
        return -1;
    }

    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_pq),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = CBUF_DATA(b); 
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_PORT_QQUERY);
    cofp_pq = (void *)(cofp_auc->data);
    cofp_pq->datapath_id = htonll(dpid);
    cofp_pq->port_no = htonl(port);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (!check_reply_type(b, C_AUX_CMD_MUL_SWITCH_PORT_QQUERY)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = CBUF_DATA(b);
            if (ntohs(cofp_auc->header.length) <
                sizeof(*cofp_auc) + sizeof(*cofp_pq)) {
                free_cbuf(b);
                goto try_restart;
            } 

            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_queues++;
        } else {
            goto try_restart;
        }
    }

    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_auc = CBUF_DATA(b);
        cofp_pq = ASSIGN_PTR(cofp_auc->data);
        q_prop_len = ntohs(cofp_auc->header.length) - 
                     (sizeof(*cofp_auc) + sizeof(*cofp_pq) +
                      ntohl(cofp_pq->stats_len));
        mul_dump_single_port_q(cofp_pq, q_prop_len, arg, cb_fn);
        free_cbuf(b);
    }
    return n_queues;

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
 * mul_set_switch_pkt_rlim -
 *
 * Set packet processing rate-limit 
 */
int
mul_set_switch_pkt_rlim(void *service, uint64_t dpid,
                        uint32_t pps, bool is_rx)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_rlim *cofp_rl;
    int ret = -1;

    if (!service) return -1;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rl),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_RLIM);
    cofp_rl = ASSIGN_PTR(cofp_auc->data);
    cofp_rl->datapath_id = htonll(dpid);
    cofp_rl->pps = htonl(pps);
    cofp_rl->is_rx = is_rx ? htonl(1):0;
    
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
 * mul_get_switch_pkt_rlim -
 *
 * Get packet processing rate-limit 
 */
int
mul_get_switch_pkt_rlim(void *service, uint64_t dpid,
                        uint32_t *pps, bool is_rx)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_rlim *cofp_rl;
    int ret = -1;

    if (!service) return -1;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rl),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_GET_RLIM);
    cofp_rl = ASSIGN_PTR(cofp_auc->data);
    cofp_rl->datapath_id = htonll(dpid);
    cofp_rl->is_rx = is_rx ? htonl(1):0;
    
    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        if (check_reply_type(b, C_AUX_CMD_MUL_SWITCH_GET_RLIM)) {
            cofp_auc = CBUF_DATA(b);
            if (ntohs(cofp_auc->header.length) >= 
                sizeof(*cofp_auc) + sizeof(*cofp_rl)) {
                ret = 0;
                cofp_rl = ASSIGN_PTR(cofp_auc->data);
                *pps = ntohl(cofp_rl->pps);
            }
        }
        free_cbuf(b);
    }

    return ret;
}

/**
 * mul_set_switch_pkt_dump -
 *
 * Set packet processing dump enable/disable 
 */
int
mul_set_switch_pkt_dump(void *service, uint64_t dpid,
                        bool rx_en, bool tx_en)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_of_dump *cofp_d;
    int ret = -1;

    if (!service) return -1;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_d),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_SET_OF_DUMP);
    cofp_d = ASSIGN_PTR(cofp_auc->data);
    cofp_d->datapath_id = htonll(dpid);
    cofp_d->rx_enable = rx_en ? htonl(0x1):0;
    cofp_d->tx_enable = tx_en ? htonl(0x1):0;
    
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
 * mul_set_switch_stats_strategy -
 *
 * Set bulk mode or fine grained flow stats gathering 
 */
int
mul_set_switch_stats_strategy(void *service, uint64_t dpid,
                              bool flow_bulk_en, bool group_bulk_en,
                              bool meter_bulk_config_en)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_stats_strategy *cofp_ss;
    int ret = -1;

    if (!service) return -1;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_ss),
                    C_OFPT_AUX_CMD, 0);
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_SET_STATS_STRAT);
    cofp_ss = ASSIGN_PTR(cofp_auc->data);
    cofp_ss->datapath_id = htonll(dpid);
    cofp_ss->fl_bulk_enable = flow_bulk_en ? htonl(0x1):0;
    cofp_ss->grp_bulk_enable = group_bulk_en ? htonl(0x1):0;
    cofp_ss->meter_bulk_config_enable = meter_bulk_config_en ?
                                               htonl(0x1):0;
    
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
 * mul_set_switch_stats_mode -
 *
 * Set port stats mode - enable/disable 
 */
int
mul_set_switch_stats_mode(void *service, uint64_t dpid, bool port_stats_en)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_stats_mode_config *cofp_smc;
    int ret = -1;
    uint32_t stats_mode = 0;

    if (!service) return -1;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_smc),
                    C_OFPT_AUX_CMD, 0);
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_STATS_MODE_CONFIG);
    cofp_smc = ASSIGN_PTR(cofp_auc->data);
    cofp_smc->datapath_id = htonll(dpid);
    if(port_stats_en)
        stats_mode |= PORT_STATS_ENABLE;

    cofp_smc->stats_mode = htonl(stats_mode);
 
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

/*
 * mul_get_switch_table_stats -
 *
 * Get switch table stats 
 */
int
mul_get_switch_table_stats(void *service, uint64_t dpid, uint8_t table,
                           uint32_t *active_count, uint64_t *lookup_count,
                           uint64_t *matched_count)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_table_stats *cofp_ts;
    int ret = -1;

    if (!service) return -1;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_ts),
                    C_OFPT_AUX_CMD, 0);
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_GET_TBL_STATS);
    cofp_ts = ASSIGN_PTR(cofp_auc->data);
    cofp_ts->datapath_id = htonll(dpid);
    cofp_ts->table_id = table;
    
    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        cofp_auc = CBUF_DATA(b);
        if (cofp_auc->header.type != C_OFPT_AUX_CMD ||
            ntohs(cofp_auc->header.length) < (sizeof(*cofp_auc) + sizeof(*cofp_ts)) ||
            ntohl(cofp_auc->cmd_code) != C_AUX_CMD_MUL_SWITCH_GET_TBL_STATS) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return -1;
        }

        cofp_ts = ASSIGN_PTR(cofp_auc->data);
        *active_count = ntohl(cofp_ts->active_count);
        *lookup_count = ntohll(cofp_ts->lookup_count);
        *matched_count = ntohll(cofp_ts->matched_count);
        
        ret = 0;
        free_cbuf(b);
    }

    return ret;
}

/*
 * mul_get_switch_port_stats -
 *
 * Get switch port stats 
 */
struct cbuf *
mul_get_switch_port_stats(void *service, uint64_t dpid, 
                          uint32_t port_no)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_port_query *cofp_pq;

    if (!service) return NULL;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_pq),
                    C_OFPT_AUX_CMD, 0);
    cofp_auc = CBUF_DATA(b);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_SWITCH_PORT_QUERY);
    cofp_pq = ASSIGN_PTR(cofp_auc->data);
    cofp_pq->datapath_id = htonll(dpid);
    cofp_pq->port_no = htonl(port_no);
    
    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        cofp_auc = CBUF_DATA(b);
        if (cofp_auc->header.type != C_OFPT_AUX_CMD ||
            ntohs(cofp_auc->header.length) < (sizeof(*cofp_auc) +
                sizeof(*cofp_pq)) ||
            ntohl(cofp_auc->cmd_code) != C_AUX_CMD_MUL_SWITCH_PORT_QUERY) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return NULL;
        }
    }
    return b;
}

/*
 * mul_set_loop_detect -
 *
 * Set mul loop detection status 
 */
int
mul_set_loop_detect(void *service, bool enable) 
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
