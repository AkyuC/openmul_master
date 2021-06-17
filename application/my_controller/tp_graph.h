#ifndef __MUL_TP_GRAPH_H__
#define __MUL_TP_GRAPH_H__

#include "uthash.h"
#include <stdlib.h>
//#include "mul_common.h"

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

//network adapter
#ifndef CONTROLLER_IP
#define CONTROLLER_IP "192.168.10.226"
#endif
 
#ifndef REDIS_SREVER_IP
#define REDIS_SREVER_IP "192.168.10.226"
#endif

//ethernet address len
#ifndef ETH_ADDR_LEN
#define ETH_ADDR_LEN 6
#endif

#ifndef DELAY_MEASURE_TIMES
#define DELAY_MEASURE_TIMES 6
#endif

//the link node
typedef struct tp_link_t
{
    uint32_t key;//the link key
    uint64_t delay;//the link delay
    uint8_t delay_measure_times;//this switch measure dalay times
    uint16_t all_bw;//all bandwidth
    uint16_t re_bw; //remain bandwidth
    uint32_t port_h;//the head port
    uint32_t port_n;//this node's port
    struct tp_link_t ** pprev;//point to the precursor node's next
    struct tp_link_t * next;//next link node
}tp_link;

//the port information of switch
typedef struct tp_sw_port_t
{
    uint32_t port_no;//port number
    uint8_t dl_hw_addr[ETH_ADDR_LEN];//data links MAC address
    struct tp_sw_port_t ** pprev;//point to the precursor node's next
    struct tp_sw_port_t * next;//next port node
}tp_sw_port;

//the information of switch
typedef struct tp_sw_t
{
    uint32_t key;//the node key(switch or host)
    uint64_t sw_dpid;//switch dpid
    tp_link * list_link;//the switch link head
    tp_sw_port * list_port;//the switch port head
    uint64_t delay;//the delay between controller and switch
    uint8_t delay_measure_times;//this switch measure dalay times
    UT_hash_handle hh;//hash handler
}tp_sw;//switch hash table node

//sw_dpid hash to glabol switch id(when add a switch, you need to change sw_dpid to the glabol key)
typedef struct tp_swdpid_glabolkey_t
{
    uint64_t key;//switch dpid
    uint32_t sw_gid;//switch glabol id
    UT_hash_handle hh;//hash handler
}tp_swdpid_glabolkey;

/**
 * add a sw_dpid to the glabol key table
 * @sw_dpid: switch dpid
 * @return: the corresponding glabolkey or 0
*/
uint32_t tp_set_sw_glabol_id(uint64_t sw_dpid);

/**
 * use the key to find switch node from tb
 * @sw_dpid: switch dpid
 * @return: the corresponding glabolkey or 0
 */
uint32_t tp_get_sw_glabol_id(uint64_t sw_dpid);

/**
 * delete the key node from glabol key table
 * @sw_dpid: switch dpid
 * @return: success 1, fail 0
 */
int tp_del_sw_glabol_id(uint64_t sw_dpid);

/**
 * return local ip address
 */
uint32_t tp_get_local_ip(void);

/**
 * get controller area from the database, and assign to the global variable controller_area
 * @ip_addr: local ip address that use to identify this controller
 * @return: controller id
*/
uint32_t tp_get_area_from_db(uint32_t ip_addr);

/**
 * set controller area to the database
 * @ip_addr: local ip address that use to identify this controller
 * @cid: controller id
 * @return: success 1, fail 0
*/
int tp_set_area_to_db(uint32_t ip_addr, uint32_t cid);

/**
 * use the key to find switch node from tp_graph
 * @key: the node key(sw_dpid or host ip)
 * @return: the corresponding tp_sw or NULL
 */
tp_sw * tp_find_sw(uint32_t key);

/**
 * add a switch node to tp_graph
 * @key: the node key(sw_dpid or host ip)
 * @return: success added_topo_switch, fail NULL
 */
tp_sw * tp_add_sw(uint32_t key);

/**
 * add a link to a switch link_head(the link switch_switch or switch_host but need to store twice)
 * @head: topo_switch_node
 * @n: the struct of link pointer
 */
void __tp_head_add_link(tp_sw *head, tp_link * n);

/**
 * store the link(switch_switch or host_switch)
 * @key: switch id
 * @port: link port
 * @return: success 1, fail 0
 */
int tp_add_link(uint32_t key1, uint32_t port1, uint32_t key2, uint32_t port2);

/**
 * get a link from a switch link_head(correspond the __tp_head_add_link function)
 * @head: topo_switch_node
 * @key: node_key
 * @return: the link pointer
 */
tp_link * __tp_get_link_in_head(tp_link *head, uint32_t key);

/**
 * delete a link in a switch link_head
 * @del_n: the struct of link pointer
 */
void __tp_delete_link_in_head(tp_link *del_n);

/**
 * delete a link in topo
 * @key: two key of link_node
 * @return: success 1, fail 0
 */
int tp_delete_link(uint32_t key1, uint32_t key2);

/**
 * delete a switch(host) in topo
 * @key: key of tp_node
 * @return: success 1, fail 0
 */
int tp_delete_sw(uint32_t key);

/**
 * Destroys and cleans up topo.
 */
void tp_distory(void);

/**
 * add a port information in topo_switch
 * @head: topo_switch
 * @port_no: port number
 * @dl_hww_addr: the data links address
 */
void __tp_sw_add_port(tp_sw *head, uint32_t port_no, uint8_t dl_hw_addr[ETH_ADDR_LEN]);

/**
 * delete a port from switch
 * @head: topo_switch
 * @port_no: port number
 */
void __tp_sw_del_port(tp_sw *head, uint32_t port_no);

/**
 * use the port number to find port node from topo_switch
 * @head: topo_switch
 * @port_no: port number
 * @return: the corresponding tp_sw_port
 */
tp_sw_port * __tp_sw_find_port(tp_sw *head, uint32_t port_no);

/**
 * Destroys and cleans up all port information from topo_switch.
 * @head: topo_switch
 */
void __tp_sw_del_all_port(tp_sw *head);

/**
 * set the delay between controller and switch
 * @key: topo_switch_dpid
 * @delay: unit(us)
 * @return: success 1, fail 0
 */
int tp_set_sw_delay(uint32_t key, uint64_t delay);

// int tp_set_link_delay(uint32_t key1, uint32_t key2, uint64_t delay);
// int tp_set_link_all_bw(uint32_t key1, uint32_t key2, uint16_t all_bw;
// int tp_set_link_re_bw(uint32_t key1, uint32_t key2, uint16_t re_bwh);
// prams is dalay or all_bw or re_bw(the name of struct tp_link member), 
// equal the three function above
// have some limit! because of the variable declaration
#ifndef TP_SET_LINK
#define TP_SET_LINK(key1,key2,prams,set)\
    if(tp_find_sw(key1) && tp_find_sw(key2))\
    {\
        __tp_get_link_in_head(tp_find_sw(key1)->list_link, key2)->prams = set;\
        __tp_get_link_in_head(tp_find_sw(key2)->list_link, key1)->prams = set;\
    }
#endif

/**
 * get the delay between controller and switch
 * @key: topo_switch_dpid
 * @return: delay(us)
 */
uint64_t tp_get_sw_delay(uint32_t key);

// uint64_t tp_get_link_delay(uint32_t key1, uint32_t key2);
// uint16_t tp_get_link_all_bw(uint32_t key1, uint32_t key2);
// uint16_t tp_get_link_re_bw(uint32_t key1, uint32_t key2);
// prams is dalay or all_bw or re_bw(the name of struct tp_link member), 
// ret(return) is the result(uint64_t*)
// equal the three function above
#ifndef TP_GET_LINK
#define TP_GET_LINK(key1,key2,prams,ret)\
    if(!tp_find_sw(key1)) ret = 0;\
    else\
    {\
        ret = __tp_get_link_in_head(tp_find_sw(key1)->list_link, key2)->prams;\
    }
#endif

#endif