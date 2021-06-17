#include "port_stats.h"

void mul_app_send_stats_request(uint64_t dpid, uint32_t port_no)
{
    struct cbuf *b;

    b = of_prep_port_stat_msg(port_no);//create the flame

    mul_app_command_handler(NULL, b);//send to the openmul controller core
}

// void
// mul_app_send_pkt_out(void *arg UNUSED, uint64_t dpid, void *parms_arg)
// {
//     struct of_pkt_out_params *parms = parms_arg;
//     void *out_data;
//     struct cbuf *b;
//     uint8_t *act;
//     struct c_ofp_packet_out *cofp_po;

//     b = of_prep_msg(sizeof(*cofp_po) + parms->action_len + parms->data_len,
//                     OFPT_PACKET_OUT, 0);

//     cofp_po = (void *)(b->data);
//     cofp_po->datapath_id = htonll(dpid);
//     cofp_po->in_port = htonl(parms->in_port);
//     cofp_po->buffer_id = htonl(parms->buffer_id);
//     cofp_po->actions_len = htons(parms->action_len);

//     act = (void *)(cofp_po+1);
//     memcpy(act, parms->action_list, parms->action_len);

//     if (parms->data_len) {
//         out_data = (void *)(act + parms->action_len);
//         memcpy(out_data, parms->data, parms->data_len);
//     }

//     mul_app_command_handler(NULL, b);

//     return;
// }

// struct cbuf * __fastpath
// of_prep_pkt_out_msg(struct of_pkt_out_params *parms)
// {
//     size_t                tot_len;
//     struct ofp_packet_out *out;
//     struct cbuf           *b;
//     void                  *data;

//     tot_len = sizeof(struct ofp_packet_out) + parms->action_len
//                         + parms->data_len;

//     b = of_prep_msg(tot_len, OFPT_PACKET_OUT, (unsigned long)parms->data);

//     out = (void *)b->data;
//     out->buffer_id = htonl(parms->buffer_id);
//     out->in_port   = htons(parms->in_port ? : OFPP_NONE);
//     out->actions_len = htons(parms->action_len);

//     data = (uint8_t *)out->actions + parms->action_len;
//     /* Hate it !! */
//     memcpy(out->actions, parms->action_list, parms->action_len);
//     memcpy(data, parms->data, parms->data_len);


//     return b;
// }