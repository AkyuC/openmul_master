#include "flow.h"
#include "mul_common.h"
#include "global.h"

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

    fl.table_id = 0;
    of_mask_set_table_id(&mask);
    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);

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

    memset(&fl, 0, sizeof(fl));
    memset(&mdata, 0, sizeof(mdata));
    of_mask_set_dc_all(&mask);

    fl.table_id = 0;
    fl.ip.nw_dst = nw_dst;
    fl.ip.nw_src = nw_src;
    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_nw_src(&mask, 32);
    of_mask_set_table_id(&mask);

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, sw_dpid);
    mul_app_action_output(&mdata, outport);

    if(hello_add_flow(sw_dpid, &fl, &mask, buffer_id, &mdata, 0 ,htimeo, prio) == FAILURE)return FAILURE;

    fl.dl_type = htons(ETH_TYPE_IP);
    return hello_add_flow(sw_dpid, &fl, &mask, buffer_id, &mdata, 0 ,htimeo, prio);
}

RET_RESULT hello_add_flow_dafault(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst, uint32_t buffer_id,
                                  uint16_t htimeo, uint16_t prio)
{
    struct flow fl;
    struct flow mask;
    mul_act_mdata_t mdata;

    memset(&fl, 0, sizeof(fl));
    memset(&mdata, 0, sizeof(mdata));
    of_mask_set_dc_all(&mask);

    fl.table_id = 0;
    fl.ip.nw_dst = nw_dst;
    fl.ip.nw_src = nw_src;
    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_nw_src(&mask, 32);
    of_mask_set_table_id(&mask);

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, sw_dpid);
    mul_app_inst_goto(&mdata, TABLE_DEFAULT);

    if(hello_add_flow(sw_dpid, &fl, &mask, buffer_id, &mdata, 0 ,htimeo, prio) == FAILURE)return FAILURE;

    fl.dl_type = htons(ETH_TYPE_IP);
    return hello_add_flow(sw_dpid, &fl, &mask, buffer_id, &mdata, 0 ,htimeo, prio);
}

RET_RESULT hello_del_flow(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst)
{
    struct flow fl;
    struct flow mask;
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);

    fl.table_id = 0;
    fl.ip.nw_dst = nw_dst;
    fl.ip.nw_src = nw_src;
    fl.dl_type = htons(ETH_TYPE_ARP);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_nw_src(&mask, 32);
    of_mask_set_table_id(&mask);

    if(mul_app_send_flow_del(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask, 0, 0, PRO_NORMAL, 0)!=0)
    {
        return FAILURE;
    }
    fl.dl_type = htons(ETH_TYPE_IP);
    if(mul_app_send_flow_del(HELLO_APP_NAME, NULL, sw_dpid, &fl, &mask, 0, 0, PRO_NORMAL, 0)!=0)
    {
        return FAILURE;
    }
    return SUCCESS;
}