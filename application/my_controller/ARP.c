#include "ARP.h"
#include "tp_graph.h"
#include "redis_interface.h"
#include <string.h>
#include <msg_udp.h>
#include <pthread.h>
#include "tp_route.h"

extern tp_swdpid_glabolkey * key_table;
arp_hash_table_t * arp_table = NULL;
extern tp_sw * tp_graph;
extern uint32_t controller_area;
extern uint8_t MASTER_CONTROLLER;


void arp_add_key(uint32_t key_ip, uint8_t dl_hw_addr[ETH_ADDR_LEN]) 
{
    arp_hash_table_t *s;

    if(arp_find_key(key_ip))return;
    s = malloc(sizeof(arp_hash_table_t));
    s->id = key_ip;
    memcpy(s->dl_hw_addr, dl_hw_addr, ETH_ADDR_LEN);
    // c_log_debug("src s->dl_hw_addr learn mac %x%x%x%x%x%x", s->dl_hw_addr[0],s->dl_hw_addr[1],s->dl_hw_addr[2],s->dl_hw_addr[3],s->dl_hw_addr[4],s->dl_hw_addr[5]);
    // c_log_debug("src dl_hw_addr learn mac %x%x%x%x%x%x", dl_hw_addr[0],dl_hw_addr[1],dl_hw_addr[2],dl_hw_addr[3],dl_hw_addr[4],dl_hw_addr[5]);
    HASH_ADD_INT(arp_table, id, s);  /* id: name of key field */
}

arp_hash_table_t* arp_find_key(uint32_t key_ip)
{
    arp_hash_table_t* s = NULL;
    HASH_FIND_INT(arp_table, &key_ip, s);
    return s;
}

void arp_delete_key(uint32_t key_ip)
{
    arp_hash_table_t* s = NULL;
    s = arp_find_key(key_ip);
    HASH_DEL(arp_table, s);  /* user: pointer to delete */
    free(s);             /* optional; it's up to you! */
}


void arp_distory(void)
{
    arp_hash_table_t * s, * tmp;

    HASH_ITER(hh, arp_table, s, tmp) {
      HASH_DEL(arp_table, s);
      free(s);
    }

    arp_table = NULL;
}

void arp_learn(struct arp_eth_header *arp_req, uint64_t sw_dpid, uint32_t port)
{
    arp_hash_table_t * tmp;
    uint8_t src_addr[OFP_ETH_ALEN];
    c_log_debug("src learn mac %x%x%x%x%x%x", arp_req->ar_sha[0],arp_req->ar_sha[1],arp_req->ar_sha[2],arp_req->ar_sha[3],arp_req->ar_sha[4],arp_req->ar_sha[5]);
    arp_add_key(arp_req->ar_spa, arp_req->ar_sha);
    tmp = arp_find_key(arp_req->ar_spa);
    tmp->sw_key = tp_get_sw_glabol_id(sw_dpid);
    tmp->port_no = port;
    // c_log_debug("src learn end mac %x%x%x%x%x%x", tmp->dl_hw_addr[0], tmp->dl_hw_addr[1], tmp->dl_hw_addr[2], tmp->dl_hw_addr[3], tmp->dl_hw_addr[4], tmp->dl_hw_addr[5]);

    //write in redis database
    // c_log_debug("set port and sw_key");
    if(!redis_Get_Pc_MAC(arp_req->ar_spa, (uint8_t*)src_addr))
    {
        redis_Set_Pc_Sw_Port(arp_req->ar_spa, tmp->sw_key, port);
        // c_log_debug("set mac");
        redis_Set_Pc_MAC(arp_req->ar_spa, arp_req->ar_sha);
        // c_log_debug("set maced");
        redis_Set_Sw2PC_Port(tmp->sw_key + port, arp_req->ar_spa);
    }
}

void arp_proc(mul_switch_t *sw, struct flow *fl, uint32_t inport, uint32_t buffer_id, \
              uint8_t *raw, size_t pkt_len)
{
    struct arp_eth_header     *arp;
    struct of_pkt_out_params  parms;
    struct mul_act_mdata      mdata;
    uint8_t mac[6] = {'\0'};
    ctrl_pkt pkt;

    arp = (void *)(raw + sizeof(struct eth_header)  +
                   (fl->dl_vlan ? VLAN_HEADER_LEN : 0));

    arp_learn(arp, sw->dpid, inport);

    memset(&parms, 0, sizeof(parms));
    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    if(htons(arp->ar_op) == 1){
        if(redis_Get_Pc_MAC(arp->ar_tpa, mac))
        {
            //arp cache reply
            c_log_info("ARP Cache reply!");
            mul_app_act_set_ctors(&mdata, sw->dpid);
            mul_app_action_output(&mdata, inport);
            parms.buffer_id = buffer_id;
            parms.in_port = OF_NO_PORT;
            parms.action_list = mdata.act_base;
            parms.action_len = mul_app_act_len(&mdata);
            parms.data_len = sizeof(struct eth_header) + sizeof(struct arp_eth_header);
            parms.data = get_proxy_arp_reply(arp, mac);
            mul_app_send_pkt_out(NULL, sw->dpid, &parms);
            mul_app_act_free(&mdata);
        }else
        {
            //STP flood c2s
            c_log_info("ARP Flood!");
            if(rt_stp(arp->ar_spa, arp->ar_tpa))return;
            if(!MASTER_CONTROLLER){
                pkt.type = ARP_OP_REQUEST;
                pkt.nw_src = arp->ar_spa;
                pkt.nw_dst = arp->ar_tpa;
                msg_send(inet_addr(REDIS_SERVER_IP), (uint8_t*)&pkt, sizeof(pkt));
            }
        }
    }else
    {
        rt_ip(arp->ar_spa, arp->ar_tpa, ETH_TYPE_ARP);
    }
}

void * get_proxy_arp_reply(struct arp_eth_header *arp_req, uint8_t fab_mac[ETH_ADDR_LEN])
{
    uint8_t               *out_pkt;
    struct eth_header     *eth;
    struct arp_eth_header *arp_reply;

    out_pkt = malloc(sizeof(struct arp_eth_header) +
                         sizeof(struct eth_header));

    eth = (struct eth_header *)out_pkt;
    arp_reply = (struct arp_eth_header *)(eth + 1);
    
    memcpy(eth->eth_dst, arp_req->ar_sha, ETH_ADDR_LEN);
    memcpy(eth->eth_src, fab_mac, ETH_ADDR_LEN);
    eth->eth_type = htons(ETH_TYPE_ARP);

    arp_reply->ar_hrd = htons(ARP_HRD_ETHERNET);
    arp_reply->ar_pro = htons(ARP_PRO_IP); 
    arp_reply->ar_pln = IP_ADDR_LEN;
    arp_reply->ar_hln = ETH_ADDR_LEN;
    arp_reply->ar_op = htons(ARP_OP_REPLY);

    memcpy(arp_reply->ar_sha, fab_mac, ETH_ADDR_LEN);
    arp_reply->ar_spa = arp_req->ar_tpa;
    memcpy(arp_reply->ar_tha, arp_req->ar_sha, ETH_ADDR_LEN);
    arp_reply->ar_tpa = arp_req->ar_spa;

    return out_pkt; 
}
