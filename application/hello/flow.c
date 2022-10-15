#include "flow.h"

RET_RESULT hello_add_flow(uint64_t sw_dpid, struct flow* fl, struct flow* mask, uint32_t buffer_id,
                 mul_act_mdata_t* mdata, uint16_t itimeo, uint16_t htimeo, uint16_t prio)
{
    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, fl, mask,
                         buffer_id, mdata->act_base, mul_app_act_len(mdata),
                         itimeo, htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            return FAILURE;
                         }

    return SUCCESS;
}

RET_RESULT hello_add_flow_to_ctrl(uint64_t sw_dpid, uint16_t htimeo, uint16_t prio)
{  
    struct flow fl;
    struct flow mask;
    mul_act_mdata_t mdata;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    memset(&mdata, 0, sizeof(mdata));

    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);
    fl.table_id = 1;
    of_mask_set_table_id(&mask);

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, sw_dpid);
    mul_app_action_output(&mdata, 0);   // 发送到控制器

    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         (uint32_t)-1, mdata.act_base, mul_app_act_len(&mdata), 0,
                         htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            return FAILURE;
                         }
    fl.dl_type = htons(ETH_TYPE_IP);
    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         (uint32_t)-1, mdata.act_base, mul_app_act_len(&mdata), 0,
                         htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            return FAILURE;
                         }
    return SUCCESS;
}

RET_RESULT hello_add_flow_transport(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst, uint32_t buffer_id,
                                    uint32_t outport, uint16_t htimeo, uint16_t prio)
{
    struct flow fl;
    struct flow mask;
    mul_act_mdata_t mdata;

    c_log_debug("sw_dpid:%ld, nw_src:%x, nw_dst:%x, buffer_id:%d, outport:%d, htimeo:%d, prio:%d",sw_dpid, nw_src, nw_dst, buffer_id, outport, htimeo, prio);

    memset(&fl, 0, sizeof(fl));
    memset(&mdata, 0, sizeof(mdata));
    of_mask_set_dc_all(&mask);

    fl.ip.nw_dst = nw_dst;
    fl.ip.nw_src = nw_src;
    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_nw_src(&mask, 32);
    fl.table_id = 0;
    of_mask_set_table_id(&mask);

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, sw_dpid);
    mul_app_action_output(&mdata, outport);

    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         buffer_id, mdata.act_base, mul_app_act_len(&mdata), 0,
                         htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            c_log_debug("hello_add_flow_transport arp fail!");
                            return FAILURE;
                         }
    fl.dl_type = htons(ETH_TYPE_IP);
    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         buffer_id, mdata.act_base, mul_app_act_len(&mdata), 0,
                         htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            c_log_debug("hello_add_flow_transport ip fail!");
                            return FAILURE;
                         }
    c_log_debug("hello_add_flow_transport success!");
    return SUCCESS;
}

RET_RESULT hello_add_flow_transport_d2d(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst, uint32_t buffer_id,
                                    uint32_t outport1, uint32_t outport2, uint16_t htimeo, uint16_t prio)
{
    struct flow fl;
    struct flow mask;
    mul_act_mdata_t mdata;

    c_log_debug("d2d sw_dpid:%ld, nw_src:%x, nw_dst:%x, buffer_id:%d, outport1:%d, outport2:%d, htimeo:%d, prio:%d",sw_dpid, nw_src, nw_dst, buffer_id, outport1, outport2, htimeo, prio);

    memset(&fl, 0, sizeof(fl));
    memset(&mdata, 0, sizeof(mdata));
    of_mask_set_dc_all(&mask);

    fl.ip.nw_dst = nw_dst;
    fl.ip.nw_src = nw_src;
    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_nw_src(&mask, 32);
    fl.table_id = 0;
    of_mask_set_table_id(&mask);

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, sw_dpid);
    mul_app_action_output(&mdata, outport1);
    mul_app_action_output(&mdata, outport2);

    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         buffer_id, mdata.act_base, mul_app_act_len(&mdata), 0,
                         htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            c_log_debug("hello_add_flow_transport_d2d arp fail!");
                            return FAILURE;
                         }
    fl.dl_type = htons(ETH_TYPE_IP);
    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         buffer_id, mdata.act_base, mul_app_act_len(&mdata), 0,
                         htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            c_log_debug("hello_add_flow_transport_d2d ip fail!");
                            return FAILURE;
                         }
    c_log_debug("hello_add_flow_transport_d2d success!");
    return SUCCESS;
}

RET_RESULT hello_add_flow_transport_d2d_inport(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst, uint32_t buffer_id,
                                    uint32_t outport1, uint32_t inport, uint16_t htimeo, uint16_t prio)
{
    struct flow fl;
    struct flow mask;
    mul_act_mdata_t mdata;

    c_log_debug("d2d sw_dpid:%ld, nw_src:%x, nw_dst:%x, buffer_id:%d, outport1:%d, inport:%d, htimeo:%d, prio:%d",sw_dpid, nw_src, nw_dst, buffer_id, outport1, inport, htimeo, prio);

    memset(&fl, 0, sizeof(fl));
    memset(&mdata, 0, sizeof(mdata));
    of_mask_set_dc_all(&mask);

    fl.ip.nw_dst = nw_dst;
    fl.ip.nw_src = nw_src;
    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_nw_src(&mask, 32);
    fl.table_id = 0;
    of_mask_set_table_id(&mask);
    fl.in_port = htonl((uint32_t)inport);
    of_mask_set_in_port(&mask);

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, sw_dpid);
    mul_app_action_output(&mdata, outport1);

    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         buffer_id, mdata.act_base, mul_app_act_len(&mdata), 0,
                         htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            c_log_debug("hello_add_flow_transport_d2d_inport arp fail!");
                            return FAILURE;
                         }
    fl.dl_type = htons(ETH_TYPE_IP);
    if(mul_app_send_flow_add(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         buffer_id, mdata.act_base, mul_app_act_len(&mdata), 0,
                         htimeo, prio, C_FL_ENT_NOCACHE) != 0)
                         {
                            c_log_debug("hello_add_flow_transport_d2d_inport ip fail!");
                            return FAILURE;
                         }
    c_log_debug("hello_add_flow_transport_d2d_inport success!");
    return SUCCESS;
}

RET_RESULT hello_del_flow(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst)
{
    struct flow fl;
    struct flow mask;
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);

    fl.ip.nw_dst = nw_dst;
    fl.ip.nw_src = nw_src;
    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_nw_src(&mask, 32);
    fl.table_id = 0;
    of_mask_set_table_id(&mask);

    if(mul_app_send_flow_del(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask, 0, 0, PRO_NORMAL, 0)!=0)
    {
        c_log_debug("hello_del_flow ip fail!");
        return FAILURE;
    }
    fl.dl_type = htons(ETH_TYPE_IP);
    if(mul_app_send_flow_del(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask, 0, 0, PRO_NORMAL, 0)!=0)
    {
        c_log_debug("hello_del_flow arp fail!");
        return FAILURE;
    }
    c_log_debug("hello_del_flow success!");
    return SUCCESS;
}