#ifndef __MUL_TP_ROUTE_H__
#define __MUL_TP_ROUTE_H__

#include "tp_graph.h"
#include "mul_common.h"

#ifndef IP_ROUTE_REQ_PKT
#define IP_ROUTE_REQ_PKT 3
#endif

#ifndef IP_ROUTE_REPLY_PKT
#define IP_ROUTE_REPLY_PKT 4
#endif

//use to store the pre_node
typedef struct rt_node_t{
    uint32_t prev_key; //read only
    uint32_t key; //node id
    UT_hash_handle hh;         /* makes this structure hashable */
}rt_node;

/**
 * use the key to find node from rt_set
 * @key: the node ky
 * @rt_set: route_set handler
 * @return: the corresponding rt_node
 */
rt_node * rt_find_node(uint32_t key, rt_node ** rt_set);

/**
 * add a node to re_set
 * @key: the node key
 * @prev_key: precursor key
 * @rt_set: route_set handler
 * @return: success added_node, fail NULL
 */
rt_node * rt_add_node(uint32_t key, uint32_t prev_key, rt_node ** rt_set);

/**
 * delete a node from re_set
 * @key: the node ky
 * @rt_set: route_set handler
 * @return: success 1, fail 0
 */
int rt_del_node(uint32_t key, rt_node ** rt_set);

/**
 * Destroys and cleans up route_set.
 * @rt_set: the dst set
 */
void rt_distory(rt_node ** rt_set);







/**
 * load the topo from redis
 * @return: success 1, fail 0
*/
int rt_load_glabol_topo(void);
int rt_load_glabol_topo_sw(void);
int rt_load_glabol_topo_link(void);
/**
 * get the a path between src_ip to dst_ip from redis, and than set flow in this path
 * @src_ip: source ip address
 * @dst_ip: destination ip address
 * @return: success 1, fail 0
*/
int rt_set_ip_flow_path_from_redis(uint32_t src_ip, uint32_t dst_ip, uint16_t type);

/**
 * set the flow in switch
 * @sw_dpid: switch dpid
 * @src_ip: source ip address
 * @dst_ip: destination ip address
 * @outport: the outport of flow
 * @return: success 1, fail 0
*/
int rt_ip_issue_flow(uint64_t sw_dpid, uint32_t src_ip, uint32_t dst_ip, uint32_t outport, uint16_t type);

/**
 * calculate the route path
 * @sw_start: source sw key
 * @sw_end: destination sw key
 * @return: success rt_node contained the route path, fail NULL
*/
rt_node* rt_ip_get_path(uint32_t sw_start, uint32_t sw_end);

/**
 * the function of ip route and issue flow_table
 * @nw_src: ip source address
 * @nw_dst: ip destination
 * @return: success 1, fail 0
 */
int rt_ip(uint32_t nw_src, uint32_t nw_dst, uint16_t type);

int rt_stp(uint32_t src_ip, uint32_t dst_ip);
int rt_set_arp_flow_path_from_redis(uint32_t src_ip);
int rt_stp_issue_flow(uint32_t src_ip, uint64_t * path, uint32_t len);
int rt_load_pc(void);
#endif