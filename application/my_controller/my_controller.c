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
#include "hello.h"
#include "topo.h"
#include "flow.h"
#include "db_wr.h"
#include "global.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <byteswap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

struct event *my_controller_timer;
struct mul_app_client_cb my_controller_app_cbs;

char local_ip[20] = "192.168.67.";  // 本地控制器ip
int ctrl_id = -1;  // 控制器id
char proxy_ip[20] = "192.168.68.";  // 数据库代理ip
int slot_no = 0;    // 时间片

pthread_t pid_pkt;  // 和服务器通信的线程
int skfd_pkt = -1;  // 和服务器的通信套接字
pthread_t pid_slot; // 接收时间片切换信号的线程
int skfd_slot = -1;  // 获取时间片切换信息的套接字
pthread_t pid_ctrl; // 定时下发上传控制器的流表线程
int skfd_ctrl = -1;  // 定时下发上传控制器的流表线程的套接字

tp_sw sw_list[SW_NUM];  // 卫星交换机的列表，当前时间片探知得到的

uint64_t slot_start_tvl = 0;    // 时间片开始的时间戳

int load_conf(void); // 读取配置文件
void* pkt_listen(void *arg UNUSED);    // 监听数据库代理的消息线程
void* slot_change_listen(void *arg UNUSED);    // 监听时间片开始或者切换的线程
void* flow_issue_ctrl(void *arg UNUSED);       // 周期性的下发上传到控制器的流表
uint64_t hello_get_timeval(void);    // 获取时间戳
RET_RESULT hello_route(uint32_t nw_src, uint32_t nw_dst, tp_sw sw_list[SW_NUM]);    // 路由


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
    /* Add few default flows in this switch */
    c_log_debug("switch dpid 0x%llx joined network", (unsigned long long)(sw->dpid-SW_DPID_OFFSET));
    // 添加到数据库当中，表示该交换机所属于这个控制器
    sw_list[sw->dpid-SW_DPID_OFFSET].ctrl_no = ctrl_id;
    Add_Sw_Set(ctrl_id, sw->dpid-SW_DPID_OFFSET, slot_no, proxy_ip);
    c_log_debug("my_controller_sw_add ctrl_id:%x ctrl_no:%x end",ctrl_id,sw_list[sw->dpid-SW_DPID_OFFSET].ctrl_no);
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
    uint64_t timenow = hello_get_timeval();
    if((SLOT_TIME + (slot_start_tvl - timenow)/1000) < 2) return;
    c_log_debug("switch dpid 0x%llx left network", (unsigned long long)(sw->dpid-SW_DPID_OFFSET));
    // 将数据库当中的交换机所属删除，或者设置为初始值，表示现在这个交换机没有连接到控制器
    sw_list[sw->dpid-SW_DPID_OFFSET].ctrl_no = -1;
    Del_Sw_Set(ctrl_id, sw->dpid-SW_DPID_OFFSET, slot_no, proxy_ip);
    c_log_debug("my_controller_sw_del end");
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
    char c_nw_src[9] = {'\0'};
    char c_nw_dst[9] = {'\0'};
    c_log_info("my_controller_packet_in - packet-in from network sw%llx", (unsigned long long)(sw->dpid-SW_DPID_OFFSET));
    tp_distory(sw_list);
    // 更新拓扑
    Get_Real_Topo(slot_no, proxy_ip, sw_list);
    // 计算路由
    if(hello_route(fl->ip.nw_src, fl->ip.nw_dst, sw_list)==FAILURE)
    {
        sprintf(c_nw_src, "%08x", ntohl(fl->ip.nw_src));
        sprintf(c_nw_dst, "%08x", ntohl(fl->ip.nw_dst));
        Set_Cal_Fail_Route(c_nw_src, c_nw_dst, proxy_ip);
        // hello_add_flow_dafault(sw->dpid+SW_DPID_OFFSET, fl->ip.nw_src, fl->ip.nw_dst, buffer_id, 5, PRO_NORMAL);
    }
    c_log_debug("my_controller_packet_in end");
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
    close(skfd_pkt);
    close(skfd_slot);
    pthread_cancel(pid_pkt);
	pthread_join(pid_pkt, NULL);
    pthread_cancel(pid_slot);
	pthread_join(pid_slot, NULL);
    pthread_cancel(pid_ctrl);
	pthread_join(pid_ctrl, NULL);
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
 * my_controller_port_add_cb -
 *
 * Application port add callback 
 */
static void
my_controller_port_add_cb(mul_switch_t *sw,  mul_port_t *port)
{
    c_log_debug("my_controller_port_add_cb sw:0x%llx, port:%x",(unsigned long long)(sw->dpid-SW_DPID_OFFSET), port->port_no);
    if(port->port_no != 0xfffe)
    {
        // 将此链路添加到数据库，设置为当前时间片以及确认的链路
        Add_Real_Topo(port->port_no-SW_DPID_OFFSET, sw->dpid - SW_DPID_OFFSET, slot_no, proxy_ip);
    }
    c_log_debug("my_controller_port_add_cb end");
}

/**
 * hello_port_del_cb -
 *
 * Application port del callback 
 */
static void
my_controller_port_del_cb(mul_switch_t *sw,  mul_port_t *port)
{
    uint64_t timenow = hello_get_timeval();
    c_log_debug("my_controller_port_del_cb sw:0x%llx, port:%d",(unsigned long long)(sw->dpid-SW_DPID_OFFSET), port->port_no);
    if(port->port_no != 0xfffe && (SLOT_TIME + (slot_start_tvl - timenow)/1000) >= 2)
    {
        // 将此链路从数据库中的当前时间片中删除
        Del_Real_Topo(port->port_no-SW_DPID_OFFSET, sw->dpid-SW_DPID_OFFSET, slot_no, proxy_ip);
    }
    c_log_debug("my_controller_port_del_cb end");
}

/* Network event callbacks */
struct mul_app_client_cb my_controller_app_cbs = {
    .switch_priv_alloc = NULL,
    .switch_priv_free = NULL,
    .switch_add_cb =  my_controller_sw_add,         /* Switch add notifier */
    .switch_del_cb = my_controller_sw_del,          /* Switch delete notifier */
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = my_controller_port_add_cb,
    .switch_port_del_cb = my_controller_port_del_cb,
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
    int ret;

    c_log_debug("hello_module_init %s", FN);
    for(ret=0; ret<SW_NUM; ret++)
    {
        sw_list[ret].ctrl_no = -1;
        sw_list[ret].sw_dpid = ret;
    }

    if(load_conf())
        c_log_debug("Load config success！");
    else
        c_log_debug("Load config failed！");

    ret = pthread_create(&pid_pkt, NULL, pkt_listen, NULL);
    if (ret == -1) 
        c_log_debug("TCP listen failed!"); 
    else
        c_log_debug("TCP listen start!");

    ret = pthread_create(&pid_slot, NULL, slot_change_listen, NULL);
    if (ret == -1) 
        c_log_debug("Slot change thread create listen failed!"); 
    else
        c_log_debug("Slot change thread create listen success!");

    ret = pthread_create(&pid_ctrl, NULL, flow_issue_ctrl, NULL);
    if (ret == -1) 
        c_log_debug("下方上传到控制器的线程创建失败！"); 
    else
        c_log_debug("下方上传到控制器的线程创建成功！");	
	
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


int load_conf(void)
{
    FILE * fp = NULL;
    fp = fopen(CONF_FILE_PATH, "r");

    if(fp == NULL) return 0;

    if(fscanf(fp, "%d", &slot_no)<1)return 0;
    c_log_debug("slot_no:%d", slot_no);
    if(fscanf(fp, "%s", &local_ip[11])<1)return 0;
    ctrl_id = atoi(&local_ip[11]);
    c_log_debug("local_ip:%s", local_ip);
    if(fscanf(fp, "%s", &proxy_ip[11])<1)return 0;
    c_log_debug("proxy_ip:%s", proxy_ip);
    fclose(fp);
    return 1;
}

void* pkt_listen(void *arg UNUSED)
{
    int ret = -1;
    struct sockaddr_in addr;
    char rec[BUFSIZE] = {0};
    uint64_t sw_dpid = 0;
    uint32_t outport = 0;
    uint32_t nw_src = 0;
    uint32_t nw_dst = 0;
    uint32_t timeout = 0;
    uint64_t timenow = 0;

	skfd_pkt = socket(AF_INET, SOCK_STREAM, 0);
	if ( -1 == skfd_pkt) {
		c_log_debug("socket failed");
	}

	addr.sin_family = AF_INET; //设置tcp协议族
	addr.sin_port = htons(PROXY_PORT); //设置端口号
	addr.sin_addr.s_addr = inet_addr(proxy_ip); //设置ip地址
	
	//主动发送连接请求
	ret = connect(skfd_pkt,(struct sockaddr*)&addr, sizeof(addr));
	if(-1 == ret) 
    {
        c_log_debug("connect failed");
        return NULL;
    }
    printf("pkt_listen starting!\n");

	//客户端接收来自服务端的消息
	while (1) 
    {
		bzero(&rec, sizeof(rec));
		ret = recv(skfd_pkt, &rec, sizeof(rec), 0);
        pthread_testcancel();
		if(-1 == ret) c_log_debug("recv failed");// 切换到备用控制器，待完成
        // type:1,sw:3,ip_src:8,ip_dst:8,outport:3,timeout:3
        // %d%03d%s%s%03d%03d
		else if(ret > 0) 
		{
            rec[26] = '\0';
            sscanf(&rec[23], "%d", &timeout);
            rec[23] = '\0';
            sscanf(&rec[20], "%d", &outport);
            rec[20] = '\0';
            sscanf(&rec[12], "%x", &nw_dst);
            nw_dst = htonl(nw_dst);
            rec[12] = '\0';
            sscanf(&rec[4], "%x", &nw_src);
            nw_src = htonl(nw_src);
            rec[4] = '\0';
            sscanf(&rec[1], "%ld", &sw_dpid);
			switch (rec[0])
            {
            case ROUTE_ADD:
                if(timeout == 5 || timeout == 0)
                {
                    hello_add_flow_transport(sw_dpid+SW_DPID_OFFSET, nw_src, nw_dst, (uint32_t)-1, outport+SW_DPID_OFFSET, timeout, PRO_NORMAL);
                }else{
                    timenow = hello_get_timeval();
                    timeout = timenow - slot_start_tvl;
                    hello_add_flow_transport(sw_dpid+SW_DPID_OFFSET, nw_src, nw_dst, (uint32_t)-1, outport+SW_DPID_OFFSET, timeout, PRO_NORMAL);
                }
                break;
            case ROUTE_DEL:
                hello_del_flow(sw_dpid+SW_DPID_OFFSET, nw_src, nw_dst);
                break;
            default:
                break;
            }
            pthread_testcancel();
		}
	}
}

void* slot_change_listen(void *arg UNUSED)
{
    struct sockaddr_in srvaddr;
	socklen_t len = sizeof(srvaddr);
    char buf[BUFSIZE], tmp[20] = "192.168.68.";
    int ret, i;
    FILE * fp = NULL;

	bzero(&srvaddr, len);
    skfd_slot = socket(AF_INET, SOCK_DGRAM, 0);

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(SLOT_LiSTEN_PORT);
	srvaddr.sin_addr.s_addr = inet_addr(local_ip);

	// 绑定本地IP和端口
    printf("slot_change_listen starting!\n");
	bind(skfd_slot, &srvaddr, len);

	while(1)
	{
		bzero(buf, 30);
		recvfrom(skfd_slot, buf, BUFSIZE, 0, NULL, NULL);
        slot_start_tvl = hello_get_timeval();   // 获取时间片开始的时间
        pthread_testcancel();
        // 读取配置文件
        fp = fopen(CONF_FILE_PATH, "r");
        if(fp == NULL) return 0;
        if(fscanf(fp, "%d", &slot_no)<1)return NULL;
        if(fscanf(fp, "%s", &local_ip[11])<1)return NULL;
        ctrl_id = atoi(&local_ip[11]);
        if(fscanf(fp, "%s", &tmp[11])<1)return NULL;
        fclose(fp);
        for(i=0; i<3; i++)
        {
            if(tmp[11+i] != proxy_ip[11+i])
            {
                close(skfd_pkt);
                pthread_cancel(pid_pkt);
                pthread_join(pid_pkt, NULL);
                for(i=0; i<3; i++)
                {
                    proxy_ip[11+i] = tmp[11+i];
                }
                ret = pthread_create(&pid_pkt, NULL, pkt_listen, NULL);
                if (ret == -1) 
                    c_log_debug("link to other db. TCP listen create failed!"); 
                else
                    c_log_debug("link to other db. TCP listen create success!");
                    break;
            }
        }
        memset(&tmp[11], 0, 3);
		// printf("%s", buf);
	}
    return NULL;
}

void* flow_issue_ctrl(void *arg UNUSED)
{
    int i;
    printf("flow_issue_ctrl starting!\n");

    while(1)
    {
        for(i = 0; i<SW_NUM; i++)
        {
            if(sw_list[i].ctrl_no == ctrl_id)
            {
                hello_add_flow_to_ctrl(i+SW_DPID_OFFSET, 5, PRO_SW2CTRL);
                // printf("flow_issue_ctrl sw:%x\n", sw_list[i].sw_dpid);
            }
        }
        pthread_testcancel();
        sleep(4);
    }
    return NULL;
}

RET_RESULT hello_route(uint32_t nw_src, uint32_t nw_dst, tp_sw sw_list[SW_NUM])
{
    uint64_t sw_src = (nw_src >> 24)& 0x000000ff;
    uint64_t sw_dst = (nw_dst >> 24)& 0x000000ff;
    tp_link * tmp = NULL;  // 迭代的中间变量
    int i = 0;
    int sw_min = sw_src;  // 当前迭代的最小的sw
    int sw_min_weight = 0x0fffffff;  // 当前迭代的最小的sw的权重
    // uint32_t outport = 0;  
    int D[SW_NUM][2];    // 第一列为权重，第二列为前序节点，第三列为前序节点转发的出端口
    char rt[SW_NUM] = {'\0'};
    char c_nw_src[9] = {'\0'};
    char c_nw_dst[9] = {'\0'};

    // 初始化
    for(i=0; i<SW_NUM; i++)
    {
        D[i][1] = -1;
    }
    D[sw_src][0] = 0;
    D[sw_src][1] = sw_src;
    tmp = sw_list[sw_src].list_link;
    while(tmp != NULL)
    {
        D[tmp->sw_adj_dpid][0] = tmp->delay;
        D[tmp->sw_adj_dpid][1] = sw_src;
        tmp = tmp->next;
    }

    while(true)
    {
        for(i=0; i<SW_NUM; i++)
        {
            if(D[i][1] == -1 && D[i][0] < sw_min_weight)
            {
                sw_min = i;
            }
        }
        if(sw_min == sw_dst)
        {
            // 找到了路径，一起写
            i = SW_NUM-2;
            // outport = sw_min + 1000;
            rt[i--] = (char)sw_min;
            sw_min = D[sw_min][1];
            while(sw_min != sw_src)
            {
                // 写入数据库
                // if(sw_list[sw_min].ctrl_no == ctrl_id)  // 本控制下的直接下发
                // {
                //     hello_add_flow_transport((uint64_t)sw_min+SW_DPID_OFFSET, nw_src, nw_dst, (uint32_t)-1, outport+SW_DPID_OFFSET, 0, PRO_NORMAL);
                // }
                // outport = sw_min + 1000;
                rt[i--] = (char)sw_min;
                sw_min = D[sw_min][1];
            }
            // 写入数据库
            rt[i] = (char)sw_min;
            sprintf(c_nw_src, "%08x", ntohl(nw_src));
            sprintf(c_nw_dst, "%08x", ntohl(nw_dst));
            Set_Cal_Route(c_nw_src, c_nw_dst, rt, proxy_ip);
            // hello_add_flow_transport((uint64_t)sw_min+SW_DPID_OFFSET, nw_src, nw_dst, buffer_id, outport+SW_DPID_OFFSET, 0, PRO_NORMAL);
            return SUCCESS;
        }
        if(D[sw_min][1] != -1)return FAILURE;   // 找不到路径
        // 更新权重
        tmp = sw_list[sw_min].list_link;
        while(tmp != NULL)
        {
            if(D[sw_min][0] + tmp->delay < D[tmp->sw_adj_dpid][0])
            {
                D[tmp->sw_adj_dpid][0] = D[sw_min][0] + tmp->delay;
                D[tmp->sw_adj_dpid][1] = sw_min;
            }
            tmp = tmp->next;
        }
        sw_min_weight = 0x0fffffff;
    }

    return FAILURE;
}

uint64_t hello_get_timeval(void)    // 获取时间戳
{
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_sec*1000000 + t.tv_usec;//us
}


module_init(my_controller_module_init);
module_vty_init(my_controller_module_vty_init);