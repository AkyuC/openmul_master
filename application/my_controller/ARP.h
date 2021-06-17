#ifndef __MUL_ARP_H__
#define __MUL_ARP_H__

#include "uthash.h"
#include <stdlib.h>  /* malloc */
#include "mul_common.h"

#ifndef ARP_REQ_PKT
#define ARP_REQ_PKT 1
#endif

#ifndef ARP_REPLY_PKT
#define ARP_REPLY_PKT 2
#endif
//structure of arp store table
typedef struct arp_hash_table_
{
    uint32_t id;//key ip address
    uint8_t dl_hw_addr[ETH_ADDR_LEN];//data links address
    uint32_t sw_key;//connect to the switch
    uint32_t port_no;//the switch port number
    UT_hash_handle hh;         /* makes this structure hashable */
}arp_hash_table_t;

typedef struct controll_packet
{
    uint8_t type;
    uint32_t nw_src;
    uint32_t nw_dst;
}ctrl_pkt;

/**
 * add a key_ip into table
 * @key_ip: ipv4 address
 * @dl_hw_addr: data links MAC address
 */
void arp_add_key(uint32_t key_ip, uint8_t dl_hw_addr[ETH_ADDR_LEN]);

/**
 * find the MAC address
 * @key_ip: ipv4 address
 * @return: the corresponding arp_table that shore MAC address
 */
arp_hash_table_t* arp_find_key(uint32_t key_ip);

/**
 * delete the table instance of key_ip 
 * @key_ip: ipv4 address
 */
void arp_delete_key(uint32_t key_ip);

/**
 * Destroys and cleans up all arp_table.
 */
void arp_distory(void);

/**
 * make the arp reply flame(packet) 
 * @arp_req: the arp request of ethernet header
 * @fab_mac: the dst_ip mac address
 * @return: the reply flame pointer
 */
void * get_proxy_arp_reply(struct arp_eth_header *arp_req, uint8_t fab_mac[ETH_ADDR_LEN]);

/**
 * the function of arp process
 * @sw: switch argument passed by infra layer (read-only)
 * @fl: Flow associated with the packet-in
 * @inport: in-port that this packet-in was received
 * @buffer_id: packet_in buffer_id
 * @raw: Raw packet data pointer
 * @pkt_len: Packet length
 */
void arp_proc(mul_switch_t *sw, struct flow *fl, uint32_t inport, uint32_t buffer_id, \
              uint8_t *raw, size_t pkt_len);

/**
 * store the mac address from the arp_request
 * @arp_req: the arp request of ethernet header
 * @sw_dpid: connect the switch dpid
 * @port: the switch connect port
 */
void arp_learn(struct arp_eth_header *arp_req, uint64_t sw_dpid, uint32_t port);
#endif