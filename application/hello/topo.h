#ifndef __MUL_TOPO_H__
#define __MUL_TOPO_H__

#include <stdint.h>
#include <stddef.h>
#include "global.h"

//the link node
typedef struct tp_link_t
{
    uint32_t sw_adj_dpid;//adjacent switch dpid
    uint64_t delay;//the link delay
    uint32_t port;//the sw port
    uint32_t port_adj;//this node's port
    struct tp_link_t ** pprev;//point to the precursor node's next
    struct tp_link_t * next;//next link node
}tp_link;

//the switch node
typedef struct tp_sw_t
{
    uint32_t sw_dpid;//switch dpid
    int ctrl_no; // 所属的控制器id
    tp_link* list_link;//the switch link head
}tp_sw;

/**
 * store the link(switch_switch or host_switch)无向的
 * @sw_dpid: switch id
 * @port: link port
 * @delay: link delay
 * @sw_list: 想要加的目标列表
 * @return: success 1, Failure -1
 */
RET_RESULT tp_add_link(uint32_t sw_dpid, uint32_t port1, uint32_t sw_dpid_adj, uint32_t port2, uint64_t delay, tp_sw sw_list[SW_NUM]);

/**
 * get a link from a switch link_head(correspond the __tp_head_add_link function)
 * @head: topo_switch_node
 * @dpid: node dpid
 * @return: the link pointer
 */
tp_link* tp_get_link_in_head(tp_link *head, uint32_t dpid);

/**
 * add a link to a switch link_head(the link switch_switch or switch_host but need to store twice)
 * @head: topo_switch_node
 * @n: the struct of link pointer
 */
void __tp_head_add_link(tp_sw *head, tp_link * n);

/**
 * delete a link in topo 无向的
 * @sw_dpid: switch id
 * @sw_list: 想要加的目标列表
 * @return: success 1, Failure -1
 */
RET_RESULT tp_delete_link(uint32_t sw_dpid, uint32_t sw_dpid_adj, tp_sw sw_list[SW_NUM]);

/**
 * delete a link in a switch link_head
 * @del_n: the struct of link pointer
 */
void __tp_delete_link_in_head(tp_link *del_n);

/**
 * set a link delay in topo
 * @sw_dpid: switch id
 * @delay: link delay
 * @sw_list: 想要加的目标列表
 * @return: success 1, Failure -1
 */
RET_RESULT tp_set_link_delay(uint32_t sw_dpid, uint32_t sw_dpid_adj, uint64_t delay, tp_sw sw_list[SW_NUM]);

/**
 * get a link delay in topo
 * @sw_dpid: switch id
 * @sw_list: 目标列表
 * @return: success delay, Failure -1
 */
RET_RESULT tp_get_link_delay(uint32_t sw_dpid, uint32_t sw_dpid_adj, tp_sw sw_list[SW_NUM]);

/**
 * Destroys and cleans up topo.
 * @sw_list: 目标列表
 */
void tp_distory(tp_sw sw_list[SW_NUM]);

/**
 * store the link(switch_switch or host_switch)有向的
 * @sw_dpid: switch id
 * @port: link port
 * @delay: link delay
 * @sw_list: 想要加的目标列表
 * @return: success 1, Failure -1
 */
RET_RESULT tp_add_link_vector(uint32_t sw_dpid, uint32_t port1, uint32_t sw_dpid_adj, uint32_t port2, uint64_t delay, tp_sw sw_list[SW_NUM]);

/**
 * delete a link in topo 有向的
 * @sw_dpid: switch id
 * @sw_list: 想要加的目标列表
 * @return: success 1, Failure -1
 */
RET_RESULT tp_delete_link_vector(uint32_t sw_dpid, uint32_t sw_dpid_adj, tp_sw sw_list[SW_NUM]);

#endif