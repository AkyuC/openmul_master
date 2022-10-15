#ifndef __MUL_FLOW_H__
#define __MUL_FLOW_H__

#include "mul_common.h"
#include "global.h"

/** 
 * @name hello_add_flow
 * @brief 添加一条流表到指定交换机 
 * @param [in] sw_dpid Switch dipd
 * @param [in] fl Flow match in struct flow *
 * @param [in] mask Flow mask in struct flow *
 * @param [in] buffer_id Buffer-id associated with this flow (as per OF spec) 
 * @param [in] actions Pointer to the buffer containing actions 
 * @param [in] action_len Action length 
 * @param [in] itimeo Idle timeout (as per OF Spec)
 * @param [in] htimeo Hard timeout (as per OF Spec) 
 * @param [in] prio Flow priority 
 *
 * @retval success or failure  
 */
RET_RESULT hello_add_flow(uint64_t sw_dpid, struct flow* fl, struct flow* mask, uint32_t buffer_id,
                 mul_act_mdata_t* mdata, uint16_t itimeo, uint16_t htimeo, uint16_t prio);

/** 
 * @name hello_add_flow_to_flow
 * @brief 下发指定时间的发送到控制器的流表
 * @param [in] sw_dpid Switch dipd
 * @param [in] htimeo Hard timeout (as per OF Spec) 
 * @param [in] prio Flow priority 
 *
 * @retval success or failure  
 */
RET_RESULT hello_add_flow_to_ctrl(uint64_t sw_dpid, uint16_t htimeo, uint16_t prio);

/** 
 * @name hello_add_flow_transport
 * @brief 下发转发流表
 * @param [in] sw_dpid Switch dipd
 * @param [in] nw_src 源地址
 * @param [in] nw_dst 目的地址
 * @param [in] buffer_id Buffer-id associated with this flow (as per OF spec)
 * @param [in] outport 转发端口
 * @param [in] htimeo Hard timeout (as per OF Spec) 
 * @param [in] prio Flow priority 
 *
 * @retval success or failure  
 */
RET_RESULT hello_add_flow_transport(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst, uint32_t buffer_id,
                                    uint32_t outport, uint16_t htimeo, uint16_t prio);

/** 
 * @name hello_add_flow_transport_d2d
 * @brief 下发d2d流表
 * @param [in] sw_dpid Switch dipd
 * @param [in] nw_src 源地址
 * @param [in] nw_dst 目的地址
 * @param [in] buffer_id Buffer-id associated with this flow (as per OF spec)
 * @param [in] outport1 转发端口
 * @param [in] outport2 转发端口
 * @param [in] htimeo Hard timeout (as per OF Spec) 
 * @param [in] prio Flow priority 
 *
 * @retval success or failure  
 */
RET_RESULT hello_add_flow_transport_d2d(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst, uint32_t buffer_id,
                                    uint32_t outport1, uint32_t outport2, uint16_t htimeo, uint16_t prio);

/** 
 * @name hello_add_flow_transport_d2d_inport
 * @brief 下发d2d流表，包含入端口匹配
 * @param [in] sw_dpid Switch dipd
 * @param [in] nw_src 源地址
 * @param [in] nw_dst 目的地址
 * @param [in] buffer_id Buffer-id associated with this flow (as per OF spec)
 * @param [in] inport 入端口
 * @param [in] outport1 转发端口
 * @param [in] htimeo Hard timeout (as per OF Spec) 
 * @param [in] prio Flow priority 
 *
 * @retval success or failure  
 */
RET_RESULT hello_add_flow_transport_d2d_inport(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst, uint32_t buffer_id,
                                    uint32_t outport1, uint32_t inport, uint16_t htimeo, uint16_t prio);

/** 
 * @name hello_del_flow
 * @brief 删除流表
 * @param [in] sw_dpid Switch dipd
 * @param [in] nw_src 源地址
 * @param [in] nw_dst 目的地址
 *
 * @retval success or failure  
 */
RET_RESULT hello_del_flow(uint64_t sw_dpid, uint32_t nw_src, uint32_t nw_dst);

#endif