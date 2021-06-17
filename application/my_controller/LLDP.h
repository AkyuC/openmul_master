#ifndef __MUL_MY_CONTROLLER_LLDP_H__
#define __MUL_MY_CONTROLLER_LLDP_H__
#include "mul_common.h"
#include "tp_graph.h"

#ifndef LLDP_DEFAULT_TTL
#define LLDP_DEFAULT_TTL 20 
#endif

//user tlv type
//use to measure the delay between controller and switch
#ifndef USER_TLV_DATA_TYPE_CTOS
#define USER_TLV_DATA_TYPE_CTOS 1
#endif

//use to measure the delay between switch and switch
#ifndef USER_TLV_DATA_TYPE_STOS
#define USER_TLV_DATA_TYPE_STOS 2
#endif

enum lldp_chassis_id_subtype {
    LLDP_CHASSIS_ID_LOCALLY_ASSIGNED = 7
};

enum lldp_port_id_subtype {
    LLDP_PORT_ID_LOCALLY_ASSIGNED = 7
};

/* hard coded lldp packet layout */
struct lldp_pkt_ {
    //data link information
	struct eth_header eth_head;

    //the switch information (sw_dpid)
	unsigned chassis_tlv_type : 7;
	unsigned chassis_tlv_length : 9;
	uint8_t chassis_tlv_subtype;
	uint64_t chassis_tlv_id;

    //the switch outport
	unsigned port_tlv_type : 7;
	unsigned port_tlv_length : 9;
	uint8_t port_tlv_subtype;
	uint16_t port_tlv_id;

    //lldp pkt ttl set
	unsigned ttl_tlv_type : 7;
	unsigned ttl_tlv_length : 9;
	uint16_t ttl_tlv_ttl;

    //lldp user data(include time stamp)
    unsigned user_tlv_type : 7;
	unsigned user_tlv_length : 9;
    uint8_t user_tlv_data_type;//==1,measure the delay between controller and switch; ==2,measure c->s->s->c 
    uint64_t user_tlv_data_timeval;//the time stamp

    //lldp pkt end
	unsigned end_of_lldpdu_tlv_type : 7;
	unsigned end_of_lldpdu_tlv_length : 9;
} __attribute__((packed));

typedef struct lldp_pkt_ lldp_pkt_t;

/* 802.1AB-2005 LLDP support code */
enum lldp_tlv_type{
    /* start of mandatory TLV */
    LLDP_END_OF_LLDPDU_TLV = 0,
    LLDP_CHASSIS_ID_TLV = 1,
    LLDP_PORT_ID_TLV = 2,
    LLDP_TTL_TLV = 3,
    /* end of mandatory TLV */
    /* start of optional TLV */ /*NOT USED */
    LLDP_PORT_DESC_TLV = 4,
    LLDP_SYSTEM_NAME_TLV = 5,
    LLDP_SYSTEM_DESC_TLV = 6,
    LLDP_SYSTEM_CAPABILITY_TLV = 7,
    LLDP_MGMT_ADDR_TLV = 8,
    /* end of optional TLV */
    LLDP_USERE_LINK_DATA = 127 //use to define user data
};

/**
 * the function of lldp process
 * @sw: switch argument passed by infra layer (read-only)
 * @fl: Flow associated with the packet-in
 * @inport: in-port that this packet-in was received
 * @buffer_id: packet_in buffer_id
 * @raw: Raw packet data pointer
 * @pkt_len: Packet length
 */
void lldp_proc(mul_switch_t *sw, uint32_t inport, uint8_t *raw);

/**
 * Generates lldp_packet with source switch id/port into specified buffer
 * @src_addr: sw_port MAC address
 * @srcId: sw_dpid
 * @srcPort: outport
 * @buffer: lldp_pkt address pointer
 * @user_type: lldp_type
 * @return: the corresponding tp_sw_port
 */
void lldp_create_packet(void *src_addr, uint32_t srcId, uint32_t srcPort, 
                        lldp_pkt_t *buffer, uint8_t user_type);

/**
 * send the lldp packet(measure the dalay between switch and switch) to adj_switch 
 * @sw: the switch need to measure the delay the links
 */
void lldp_flood(tp_sw *sw);

/**
 * get the sys timestamp
 * @return: timestamp
 */
uint64_t lldp_get_timeval(void);

/**
 * send the lldp packet to switch
 * @sw_dpid: the dst switch dpid
 * @buffer: lldp packet pointer
 * @inport: lldp packet inport
 * @outport: lldp packet out port
 */
void lldp_send_packet(uint64_t sw_dpid, lldp_pkt_t *buffer, uint32_t inport, uint32_t outport);

/**
 * measure the delay between switch and this controller
 * @sw_dpid: the dst switch dpid
 */
void lldp_measure_delay_ctos(uint64_t sw_dpid);

#endif
