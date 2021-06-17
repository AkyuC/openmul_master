#include "drone.h"

drone_struct_t *dr_ctx;
struct mul_app_client_cb drone_app_cbs;

void drone_module_init(void *);

static void 
ofp_convert_flow_endian_ntoh(struct flow *fl) 
{
    fl->in_port = ntohl(fl->in_port);
    fl->dl_vlan = ntohs(fl->dl_vlan);
    fl->dl_type = ntohs(fl->dl_type);
    fl->mpls_label = ntohl(fl->mpls_label);
    fl->ip.nw_src = ntohl(fl->ip.nw_src);
    fl->ip.nw_dst = ntohl(fl->ip.nw_dst);
    fl->tp_src = ntohs(fl->tp_src);
    fl->tp_dst = ntohs(fl->tp_dst);
    fl->tunnel_id = ntohll(fl->tunnel_id);
    fl->metadata = ntohll(fl->metadata);
}

/**
 * drone_check_neigh -
 *
 * It will receive modified flow from controller & send that flow to next switch if needed  
 */
static void
drone_check_neigh(void *arg, uint64_t dpid,
                  uint32_t oport, struct flow *flow)
{
    struct cbuf *b;
    drone_neigh_info_t *neigh_info = arg;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_neigh *neigh_sw;
    struct c_ofp_port_neigh *port_neigh;
    int num_ports, i = 0;
    char *pbuf = NULL;
 
    pbuf = of_dump_flow_generic(flow,flow);
    if (pbuf != NULL) {
        printf("\n ==> Dpid :0x%llx, Oport : %u, %s\n", U642ULL(dpid), oport, pbuf);
        free(pbuf);
    }

    b = mul_neigh_get(dr_ctx->tr_service, dpid);

    if (b) {
        cofp_auc = (void *)(b->data);

        num_ports = (ntohs(cofp_auc->header.length) - (sizeof(struct c_ofp_switch_neigh)
                    + sizeof(struct c_ofp_auxapp_cmd)))/ sizeof(struct c_ofp_port_neigh);

        neigh_sw = (void *)(cofp_auc->data);
        port_neigh = (void *)(neigh_sw->data);
      
        for (; i < num_ports; i++) {
            neigh_info->neigh_switch_present = ntohs(port_neigh->neigh_present) & COFP_NEIGH_SWITCH ? 
                                                       true: false;

            if (neigh_info->neigh_switch_present &&
               (ntohs(port_neigh->port_no) == oport)) {
                neigh_info->dpid = htonll(port_neigh->neigh_dpid);
                memcpy(&neigh_info->flow, flow, sizeof(struct flow));
                neigh_info->flow.in_port = htonl((uint32_t)((ntohs((port_neigh->neigh_port)))));
                neigh_info->flow.table_id = 0;
                neigh_info->send_neigh_switch = true;
            }

            port_neigh++;
        }
            
        free(b);
    }
}

/**
 * drone_send_uflow_and_check_neigh -
 *
 * It read flows from file & send to Controller  
 */
static void
drone_send_uflow_and_check_neigh(void)
{
    struct flow u_flow, u_flow_p;
    drone_neigh_info_t neigh_info;
    uint64_t dp_id;
    FILE *file_p;
    char buf[250];
    uint8_t ipbytes_src[4];
    uint8_t ipbytes_dst[4];
    int ret = 0;
    char *pbuf = NULL;

    file_p = fopen("flowConfiguration.cfg", "r");
    
    if (file_p == NULL) {
        perror("Error");
        return;
    }

    while (fgets (buf, sizeof(buf), file_p) != NULL) {

        if ((buf[0] == '#') || (buf [0] == '\n'))
            continue;
        
        if (strlen (buf) < 50) {
            c_log_err("%s: Invalid Flow", FN);
            continue;
        }

        sscanf (buf,"0x%llx %u %hu %hu %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhx:%hhx:%hhx:%hhx:%hhx:%hhx \
                     %hhu %hhu %hhu %hhu %u %hu %hu %hhu.%hhu.%hhu.%hhu %hhu.%hhu.%hhu.%hhu %lu %lu %hhu %hhu ",
                     (long long unsigned *)&dp_id, &u_flow.in_port, &u_flow.dl_vlan, &u_flow.dl_type,
                     &u_flow.dl_dst[0], &u_flow.dl_dst[1], &u_flow.dl_dst[2],
                     &u_flow.dl_dst[3], &u_flow.dl_dst[4], &u_flow.dl_dst[5],
                     &u_flow.dl_src[0], &u_flow.dl_src[1], &u_flow.dl_src[2],
                     &u_flow.dl_src[3], &u_flow.dl_src[4], &u_flow.dl_src[5],
                     &u_flow.dl_vlan_pcp, &u_flow.table_id, &u_flow.nw_tos,
                     &u_flow.nw_proto, &u_flow.mpls_label, &u_flow.tp_src, &u_flow.tp_dst, 
                     &ipbytes_src[0], &ipbytes_src[1], &ipbytes_src[2], &ipbytes_src[3], 
                     &ipbytes_dst[0], &ipbytes_dst[1], &ipbytes_dst[2], &ipbytes_dst[3],
                     &u_flow.tunnel_id, &u_flow.metadata, &u_flow.mpls_bos, &u_flow.mpls_tc);

        u_flow.ip.nw_src = ipbytes_src[3] | ipbytes_src[2] << 8 | ipbytes_src[1] << 16 | ipbytes_src[0] << 24;
        u_flow.ip.nw_dst = ipbytes_dst[3] | ipbytes_dst[2] << 8 | ipbytes_dst[1] << 16 | ipbytes_dst[0] << 24;

        memcpy(&u_flow_p, &u_flow, sizeof(u_flow));
        ofp_convert_flow_endian_hton(&u_flow_p);

        pbuf = of_dump_flow_generic(&u_flow_p, &u_flow_p);
        if (pbuf != NULL) {
            printf("\n-----------------------------------"
                   "-------------------------------------\n");
            printf("START || Dpid :0x%llx, %s", U642ULL(dp_id), pbuf);
            free(pbuf);
        }

        while (1) {

            memset(&neigh_info, 0, sizeof(drone_neigh_info_t));

            ret = mul_get_mod_uflow_info(dr_ctx->mul_service, dp_id, &u_flow, (void *)&neigh_info, drone_check_neigh);
            if (ret < 0)
                break;

            if (neigh_info.send_neigh_switch) {
                dp_id = neigh_info.dpid;
                memcpy(&u_flow, &neigh_info.flow, sizeof(struct flow));
                ofp_convert_flow_endian_ntoh(&u_flow);
                continue;
            }
            else
                break;
        }
    }
    exit(0);
}

/**
 * drone_module_init -
 *
 * Drone application entry point 
 */
void
drone_module_init(void *arg UNUSED)
{
    
    dr_ctx = calloc(1, sizeof(drone_struct_t));
    assert(dr_ctx);

    c_rw_lock_init(&dr_ctx->lock);

    /*Controller Service*/
    dr_ctx->mul_service = mul_app_get_service(MUL_CORE_SERVICE_NAME, NULL);
    if (dr_ctx->mul_service == NULL) {
        c_log_err("[CORE] service not found");
    }

    /*TR Service*/
    dr_ctx->tr_service = mul_app_get_service(MUL_TR_SERVICE_NAME, NULL);
    if (dr_ctx->tr_service == NULL) {
        c_log_err("[TR] service not found");
    }

    mul_register_app_cb(NULL, DRONE_APP_NAME, C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &drone_app_cbs);

    drone_send_uflow_and_check_neigh();
}

module_init(drone_module_init);
