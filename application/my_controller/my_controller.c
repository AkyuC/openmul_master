/*
 *  my_controller.c: my_controller application for MUL Controller 
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "config.h"
#include "mul_common.h"
#include "mul_vty.h"
#include "my_controller.h"
#include "LLDP.h"
#include "tp_graph.h"
#include "tp_route.h"
#include "ARP.h"
#include "redis_interface.h"
#include "msg_udp.h"
#include <pthread.h>

struct event *my_controller_timer;
struct mul_app_client_cb my_controller_app_cbs;

pthread_t pid;
extern arp_hash_table_t * arp_table;//arp hash table handler
extern tp_sw * tp_graph;//topo hash handler
extern tp_swdpid_glabolkey * key_table;
extern uint32_t controller_area;

/**
 * my_controller_intall_dfl_flows -
 * Installs default flows on a switch
 *
 * @dpid : Switch's datapath-id
 * @return : void
 */
static void
my_controller_install_dfl_flows(uint64_t dpid)
{
    struct flow fl;
    struct flow mask;
    //controller mac(used to arp proxy)
    // uint8_t src_addr[OFP_ETH_ALEN] = {0x02, 0x42, 0xf7, 0x6d, 0x93, 0x67};
    //struct mul_act_mdata mdata; 
    //mul_act_mdata_t mdata;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);

    /* Clear all entries for this switch */
    mul_app_send_flow_del(MY_CONTROLLER_APP_NAME, NULL, dpid, &fl,
                          &mask, OFPP_NONE, 0, C_FL_ENT_NOCACHE, OFPG_ANY);

    /* Zero DST MAC Drop */
    of_mask_set_dl_dst(&mask); 
    mul_app_send_flow_add(MY_CONTROLLER_APP_NAME, NULL, dpid, &fl, &mask,
                          MY_CONTROLLER_UNK_BUFFER_ID, NULL, 0, 0, 0, 
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);  

    /* Zero SRC MAC Drop */
    of_mask_set_dc_all(&mask);
    of_mask_set_dl_src(&mask); 
    mul_app_send_flow_add(MY_CONTROLLER_APP_NAME, NULL, dpid, &fl, &mask, 
                          MY_CONTROLLER_UNK_BUFFER_ID, NULL, 0, 0, 0,  
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Broadcast SRC MAC Drop */
    memset(&fl.dl_src, 0xff, OFP_ETH_ALEN);
    mul_app_send_flow_add(MY_CONTROLLER_APP_NAME, NULL, dpid, &fl, &mask,
                          MY_CONTROLLER_UNK_BUFFER_ID, NULL, 0, 0, 0,
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Send any unknown flow to app */
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    mul_app_send_flow_add(MY_CONTROLLER_APP_NAME, NULL, dpid, &fl, &mask,
                          MY_CONTROLLER_UNK_BUFFER_ID, NULL, 0, 0, 0,
                          C_FL_PRIO_LDFL, C_FL_ENT_LOCAL);
}


/**
 * my_controller_sw_add -
 * Switch join event notifier
 * 
 * @sw : Switch arg passed by infra layer
 * @return : void
 */
static void 
my_controller_sw_add(mul_switch_t *sw)
{
    uint32_t sw_glabol_key;

    /* Add few default flows in this switch */
    my_controller_install_dfl_flows(sw->dpid);
    
    // create glabol key
    sw_glabol_key = tp_set_sw_glabol_id(sw->dpid);
    // c_log_debug("sw_glabol_key: %x", sw_glabol_key);
    //topo Add a sw node to the topo
    tp_add_sw(sw_glabol_key);
    tp_find_sw(sw_glabol_key)->sw_dpid = sw->dpid;
    c_log_debug("sw %x added", sw_glabol_key);
    lldp_measure_delay_ctos(sw->dpid);
}

/**
 * my_controller_sw_del -
 * Switch delete event notifier
 *
 * @sw : Switch arg passed by infra layer
 * @return : void
 */
static void
my_controller_sw_del(mul_switch_t *sw)
{
    c_log_debug("sw %x deleted", tp_get_sw_glabol_id(sw->dpid));
    tp_delete_sw(tp_get_sw_glabol_id(sw->dpid));
    tp_del_sw_glabol_id(sw->dpid);
    // c_log_debug("switch %lx left network", (uint64_t)(sw->dpid));
    // 从数据库中删除

}

/**
 * my_controller_packet_in -
 * my_controller app's packet-in notifier call-back
 *
 * @sw : switch argument passed by infra layer (read-only)
 * @fl : Flow associated with the packet-in
 * @inport : in-port that this packet-in was received
 * @raw : Raw packet data pointer
 * @pkt_len : Packet length
 * 
 * @return : void
 */
static void 
my_controller_packet_in(mul_switch_t *sw UNUSED,
                struct flow *fl UNUSED,
                uint32_t inport UNUSED,
                uint32_t buffer_id UNUSED,
                uint8_t *raw UNUSED,
                size_t pkt_len UNUSED)
{
    //uint32_t                    oport = OF_ALL_PORTS;
    struct of_pkt_out_params    parms;
    //struct mul_act_mdata mdata;
    uint16_t type;

    memset(&parms, 0, sizeof(parms));

    /* Check packet validity */
    if (is_zero_ether_addr(fl->dl_src) || 
        is_zero_ether_addr(fl->dl_dst) ||
        is_multicast_ether_addr(fl->dl_src) || 
        is_broadcast_ether_addr(fl->dl_src)) {
        c_log_err("%s: Invalid src/dst mac addr", FN);
        return;
    }

    if (buffer_id != MY_CONTROLLER_UNK_BUFFER_ID) {
        pkt_len = 0;
    }

    /* check ether type. common-libs/mul-lib/include/packets.h 104 row*/
    type = ntohs(fl->dl_type);
    // c_log_info("sw %x", tp_get_sw_glabol_id(sw->dpid));
    switch (type){
    case ETH_TYPE_LLDP:
        //LLDP 0x88cc
        c_log_info("LLDP packet-in from network");
        lldp_proc(sw, inport, raw);
        //c_log_debug("sw %x delay %llu us", sw->dpid, tp_find_sw(tp_get_sw_glabol_id(sw->dpid))->delay);
        break;
    case ETH_TYPE_IP:
        //IP 0x0800
        c_log_info("IP packet-in from network");
        rt_ip(fl->ip.nw_src, fl->ip.nw_dst, ETH_TYPE_IP);
        break;
    case ETH_TYPE_ARP:
        //ARP 0x0806
        c_log_info("ARP packet-in from network");
        arp_proc(sw, fl, inport, buffer_id, raw, pkt_len);
        break;
    case ETH_TYPE_IPV6:
        //IPv6 0x86dd
        //c_log_info("IPv6 packet-in from network");
        break;
    default:
        c_log_debug("%s: ethertype 0x%hx not recognized ", FN, fl->dl_type);
        return;
    }
}

/**
 * my_controller_core_closed -
 * mul-core connection drop notifier
 */
static void
my_controller_core_closed(void)
{
    c_log_info("%s: ", FN);

    /* Nothing to do */
    pthread_cancel(pid);
	pthread_join(pid, NULL);
    return;
}

/**
 * my_controller_core_reconn -
 * mul-core reconnection notifier
 */
static void
my_controller_core_reconn(void)
{
    c_log_info("%s: ", FN);

    /* 
     * Once core connection has been re-established,
     * we need to re-register the app
     */
    mul_register_app_cb(NULL,                 /* Application specific arg */
                        MY_CONTROLLER_APP_NAME,       /* Application Name */
                        C_APP_ALL_SW,         /* Send any switch's notification */
                        C_APP_ALL_EVENTS,     /* Send all event notification per switch */
                        0,                    /* If any specific dpid filtering is requested */
                        NULL,                 /* List of specific dpids for filtering events */
                        &my_controller_app_cbs);      /* Event notifier call-backs */
}

/**
 * lldp_port_add_cb -
 *
 * Application port add callback 
 */
static void
lldp_port_add_cb(mul_switch_t *sw,  mul_port_t *port)
{
    uint32_t sw_port_tmp = 0;
    // c_log_debug("sw start %x add a port %x, MAC %s, config %x, state %x, n_stale %x", sw->dpid, port->port_no, port->hw_addr, port->config, port->state, port->n_stale);
    if(port->port_no != 0xfffe)
    {
        __tp_sw_add_port(tp_find_sw(tp_get_sw_glabol_id(sw->dpid)), port->port_no, port->hw_addr);
        sw_port_tmp = tp_get_sw_glabol_id(sw->dpid) + port->port_no;
        redis_Set_Sw2PC_Port(sw_port_tmp, 0);
    }
    // c_log_debug("sw end %x add a port %x", sw->dpid, port->port_no);
}

/**
 * lldp_port_del_cb -
 *
 * Application port del callback 
 */
static void
lldp_port_del_cb(mul_switch_t *sw,  mul_port_t *port)
{
    uint32_t sw_port_tmp = 0;
    // c_log_debug("sw start %x del a port %x", sw->dpid, port->port_no);
    if(port->port_no != 0xfffe)
    {
        __tp_sw_del_port(tp_find_sw(tp_get_sw_glabol_id(sw->dpid)), port->port_no);
        sw_port_tmp = tp_get_sw_glabol_id(sw->dpid) + port->port_no;
        redis_Del_Sw2PC_Port(sw_port_tmp);
    }
        
    // c_log_debug("sw end %x del a port %x", sw->dpid, port->port_no);
}

/* Network event callbacks */
struct mul_app_client_cb my_controller_app_cbs = {
    .switch_priv_alloc = NULL,
    .switch_priv_free = NULL,
    .switch_add_cb =  my_controller_sw_add,         /* Switch add notifier */
    .switch_del_cb = my_controller_sw_del,          /* Switch delete notifier */
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = lldp_port_add_cb,
    .switch_port_del_cb = lldp_port_del_cb,
    .switch_port_link_chg = NULL,
    .switch_port_adm_chg = NULL,
    .switch_packet_in = my_controller_packet_in,    /* Packet-in notifier */ 
    .core_conn_closed = my_controller_core_closed,  /* Core connection drop notifier */
    .core_conn_reconn = my_controller_core_reconn   /* Core connection join notifier */
};  

/**
 * my_controller_timer_event -
 * Timer running at specified interval 
 * 
 * @fd : File descriptor used internally for scheduling event
 * @event : Event type
 * @arg : Any application specific arg
 */
static void
my_controller_timer_event(evutil_socket_t fd UNUSED,
                  short event UNUSED,
                  void *arg UNUSED)
{
    struct timeval tv = { 1 , 0 }; /* Timer set to run every one second */
    
    evtimer_add(my_controller_timer, &tv);
}  

/**
 * my_controller_module_init -
 * my_controller application's main entry point
 * 
 * @base_arg: Pointer to the event base used to schedule IO events
 * @return : void
 */
void
my_controller_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval tv = { 1, 0 };

    c_log_debug("%s", FN);

    // tp_set_area_to_db(tp_get_local_ip(), controller_area);
    c_log_debug("controller area: %x", controller_area);
    if(tp_set_area_to_db(tp_get_local_ip(), controller_area))
    {
        c_log_debug("Can connect to the server!");
    }else
    {
        c_log_debug("Can't connect to the server!");
    }
    
    if(msg_udp_init())
    {
        pthread_create(&pid, NULL, pkt_listen, NULL);
        c_log_debug("UDP listen start!");
    }else
    {
        c_log_debug("Can't get the udp socket!");
    }
	
	
    /* Fire up a timer to do any housekeeping work for this application */
    my_controller_timer = evtimer_new(base, my_controller_timer_event, NULL); 
    evtimer_add(my_controller_timer, &tv);

    mul_register_app_cb(NULL,                 /* Application specific arg */
                        MY_CONTROLLER_APP_NAME,       /* Application Name */ 
                        C_APP_ALL_SW,         /* Send any switch's notification */
                        C_APP_ALL_EVENTS,     /* Send all event notification per switch */
                        0,                    /* If any specific dpid filtering is requested */
                        NULL,                 /* List of specific dpids for filtering events */
                        &my_controller_app_cbs);      /* Event notifier call-backs */

    return;
}

/**
 * my_controller_module_vty_init -
 * my_controller Application's vty entry point. If we want any private cli
 * commands. then we register them here
 *
 * @arg : Pointer to the event base(mostly left unused)
 */
void
my_controller_module_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
}

void* pkt_listen(void *arg)
{
    uint8_t buf[UDP_BUFF_LEN] = {'\0'};
    uint8_t mac[OFP_ETH_ALEN];
    int len = 0;
    ctrl_pkt * pkt = NULL;

	while(1)
	{
        len = msg_udp_listen((uint8_t*)buf);
        if(len>0)
        {
            pkt = (ctrl_pkt*)buf;
            switch (pkt->type)
            {
            case ARP_OP_REQUEST:
                if(!redis_Get_Pc_MAC(pkt->nw_dst, (uint8_t*)mac))
                {
                    rt_stp(pkt->nw_src, pkt->nw_dst);
                }
                break;
            case IP_ROUTE_REQ_PKT:
                rt_ip(pkt->nw_src, pkt->nw_dst, ETH_TYPE_IP);
                break;
            default:
                break;
            }
        }
        // c_log_debug("no arp req");
        pthread_testcancel();
	}
}

module_init(my_controller_module_init);
module_vty_init(my_controller_module_vty_init);