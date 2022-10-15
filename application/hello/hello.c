/*
 *  hello.c: Hello application for MUL Controller 
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
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>


struct event *hello_timer;
struct mul_app_client_cb hello_app_cbs;

char local_ip[20] = "192.168.66.";  // 本地控制器ip
int ctrl_id = -1;  // 控制器id
char proxy_ip[20] = "192.168.68.";  // 数据库代理ip
int db_id = -1;     // 连接的数据库id
int slot_no = 0;    // 时间片
int ctrl2db[SLOT_NUM][DB_NUM];    // 每个时间片该控制器连接所有数据库的远近顺序

int skfd_rt = -1;  // 和服务器的通信套接字
pthread_t pid_slot; // 接收时间片切换信号的线程
int skfd_slot = -1; // 获取时间片切换信息的套接字
int is_connDB = 0;  // 全局判断是否已经连接上数据库
int is_connSW = 0;  // 全局判断是否已经连接上卫星交换机
int keepAlive = 1; // 开启keepalive属性
int keepIdle = 1; // 如该连接在1秒内没有任何数据往来,则进行探测 
int keepInterval = 1; // 探测时发包的时间间隔为1秒
int keepCount = 2; // 探测尝试的次数

tp_sw sw_list[SW_NUM];  // 卫星交换机的列表，当前时间片探知得到的
int sw_adj_list[SW_NUM] = {0};      // 当前卫星交换机的邻近卫星交换机

int load_conf(void); // 读取配置文件
void* socket_listen(void *arg UNUSED);    // 套接字管理线程
int conn_db(int slot_no);   // 连接数据库函数，成功返回SUCCESS，失败返回FAILURE
RET_RESULT rt_set2sw(char* rec);    // 流表操作，一条
int rt_recv(void);  // 路由接收函数，成功返回SUCCESS，失败返回FAILURE
RET_RESULT Get_Wait_Exec(uint32_t ctrl, char* redis_ip); // 查看数据库当中是否需要进行流表操作
RET_RESULT hello_route(uint32_t nw_src, uint32_t nw_dst, uint32_t inport, tp_sw sw_list[SW_NUM]);    // 路由
RET_RESULT Set_Del_Link(int slot_no, char* redis_ip, tp_sw sw_list[SW_NUM]);
int sw_disconnected_db_times = 0;
void write_sw_times(int ctrl_id, int sw_disconnected_db_times); // 统计切换次数
int msg_send(unsigned int server_addr, char *msg, unsigned int len);

/**
 * hello_install_dfl_flows -
 * Installs default flows on a switch
 *
 * @dpid : Switch's datapath-id
 * @return : void
 */
static void
hello_install_dfl_flows(uint64_t dpid)
{
    struct flow fl;
    struct flow mask;
    
    /* Send any unknown flow to app */
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    mul_app_send_flow_add(HELLO_APP_NAME, NULL, dpid, &fl, &mask, 
                          HELLO_UNK_BUFFER_ID, NULL, 0, 0, 0,  
                          1, C_FL_ENT_LOCAL);
}

/**
 * hello_sw_add -
 * Switch join event notifier
 * 
 * @sw : Switch arg passed by infra layer
 * @return : void
 */
static void 
hello_sw_add(mul_switch_t *sw)
{    
    /* Add few default flows in this switch */
    c_log_debug("\t\nswitch dpid 0x%llx joined network", (unsigned long long)(sw->dpid-SW_DPID_OFFSET));
    is_connSW = 1;
    hello_install_dfl_flows(sw->dpid);
    hello_add_flow_to_ctrl(sw->dpid, 0, PRO_SW2CTRL);
    // 添加到数据库当中，表示该交换机所属于这个控制器
    while(is_connDB != 1) sleep(1);
    while(Set_Ctrl_Conn_Db(ctrl_id, db_id, proxy_ip) == FAILURE)
    {
        c_log_debug("hello_sw_add, Cant connect to db");
        sleep(1);
    }

    c_log_debug("hello_sw_add ctrl_id:%x ctrl_no:%x end",ctrl_id,sw_list[sw->dpid-SW_DPID_OFFSET].ctrl_no);
}

/**
 * hello_sw_del -
 * Switch delete event notifier
 *
 * @sw : Switch arg passed by infra layer
 * @return : void
 */
static void
hello_sw_del(mul_switch_t *sw)
{
    c_log_debug("\t\nswitch dpid 0x%llx left network", (unsigned long long)(sw->dpid-SW_DPID_OFFSET));
    is_connSW = 0;
    c_log_debug("hello_sw_del end");
}


/**
 * hello_port_add_cb -
 *
 * Application port add callback 
 */
static void
hello_port_add_cb(mul_switch_t *sw,  mul_port_t *port)
{
    if(port->port_no != 0xfffe && port->port_no < 1999)
    {
        c_log_debug("\t\nhello_port_add_cb sw:0x%llx, port:%d",(unsigned long long)(sw->dpid-SW_DPID_OFFSET), port->port_no);
        sw_adj_list[port->port_no - SW_DPID_OFFSET] = 1; // 记录邻居
        // 将此链路添加到数据库，设置为当前时间片以及确认的链路
        while(is_connDB != 1) sleep(1);
        while(Add_Real_Topo(sw->dpid - SW_DPID_OFFSET, port->port_no-SW_DPID_OFFSET, slot_no, proxy_ip) == FAILURE)
        {
            c_log_debug("hello_port_add_cb, Cant connect to db");
            sleep(1);
        }
        c_log_debug("hello_port_add_cb db_ip:%s", proxy_ip);
        c_log_debug("hello_port_add_cb end");
    }
}

/**
 * hello_port_del_cb -
 *
 * Application port del callback 
 */
static void
hello_port_del_cb(mul_switch_t *sw,  mul_port_t *port)
{   
    int db_id = atoi(&proxy_ip[11]) -1;
    if(port->port_no != 0xfffe && port->port_no < 1999)
    {
        c_log_debug("hello_port_del_cb sw:0x%llx, port:%d",(unsigned long long)(sw->dpid-SW_DPID_OFFSET), port->port_no);
        sw_adj_list[port->port_no - SW_DPID_OFFSET] = 0;// 删除记录邻居
        sleep(1);   // 与可能需要连接数据库的时间错开
        // usleep(500*1000);
        // 将此链路从数据库中的当前时间片中删除
        while(is_connDB != 1) sleep(1);
        while(Del_Real_Topo(sw->dpid - SW_DPID_OFFSET, port->port_no-SW_DPID_OFFSET, proxy_ip) == FAILURE)
        {
            c_log_debug("hello_port_del_cb, Cant connect to db");
            sleep(1);
        }
        c_log_debug("hello_port_del_cb db_ip:%s", proxy_ip);
        // Del_Real_Topo(port->port_no-SW_DPID_OFFSET, sw->dpid - SW_DPID_OFFSET, proxy_ip);
        Set_Fail_Link(sw->dpid - SW_DPID_OFFSET, port->port_no-SW_DPID_OFFSET, db_id, slot_no, proxy_ip);
        // Set_Fail_Link(port->port_no-SW_DPID_OFFSET, sw->dpid - SW_DPID_OFFSET, db_id, slot_no, proxy_ip);
        c_log_debug("hello_port_del_cb end");
    }
}


/**
 * hello_packet_in -
 * Hello app's packet-in notifier call-back
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
hello_packet_in(mul_switch_t *sw UNUSED,
                struct flow *fl UNUSED,
                uint32_t inport UNUSED,
                uint32_t buffer_id UNUSED,
                uint8_t *raw UNUSED,
                size_t pkt_len UNUSED)
{
    if(((fl->ip.nw_src >> 16) & 0x000000ff) == 68 || ((fl->ip.nw_dst >> 16) & 0x000000ff) == 68 || fl->ip.nw_src == 0 || fl->ip.nw_dst == 0)return;
    if(((fl->ip.nw_src >> 24) & 0x000000ff) != ctrl_id + 1)return;
    c_log_info("\nhello app - packet-in from network src %x - dst %x，ntohs(fl->dl_type)： %x", fl->ip.nw_src, fl->ip.nw_dst, ntohs(fl->dl_type));
    tp_distory(sw_list);
    c_log_debug("tp_distory end");
    // 更新拓扑
    while(is_connDB != 1) sleep(1);
    while(Get_Real_Topo(proxy_ip, sw_list) == FAILURE)
    {
        c_log_debug("hello_packet_in, Cant connect to db");
        sleep(1);
    }
    c_log_debug("Get_Real_Topo end");
    Set_Del_Link(slot_no, proxy_ip, sw_list);
    c_log_debug("Set_Del_Link end");
    // 计算路由
    // 只为从源节点上传的packet-in包计算路由
    // c_log_debug("((fl->ip.nw_src >> 24) & 0x000000ff) -1 = %d, ctrl_id = %d", ((fl->ip.nw_src >> 24) & 0x000000ff) -1, ctrl_id);
    if(hello_route(fl->ip.nw_src, fl->ip.nw_dst, inport, sw_list)==FAILURE)
    {
        c_log_debug("hello_route %08x <--> %08x fail", (fl->ip.nw_src), (fl->ip.nw_dst));
    }
    c_log_debug("hello_packet_in end");
}

/**
 * hello_core_closed -
 * mul-core connection drop notifier
 */
static void
hello_core_closed(void)
{
    c_log_info("%s: ", FN);

    /* Nothing to do */
    close(skfd_slot);
    close(skfd_rt);
    pthread_cancel(pid_slot);
	pthread_join(pid_slot, NULL);
    
    c_log_debug("hello_core_closed end");
}

/**
 * hello_core_reconn -
 * mul-core reconnection notifier
 */
static void
hello_core_reconn(void)
{
    c_log_info("%s: ", FN);

    /* 
     * Once core connection has been re-established,
     * we need to re-register the app
     */
    mul_register_app_cb(NULL,                 /* Application specific arg */
                        HELLO_APP_NAME,       /* Application Name */
                        C_APP_ALL_SW,         /* Send any switch's notification */
                        C_APP_ALL_EVENTS,     /* Send all event notification per switch */
                        0,                    /* If any specific dpid filtering is requested */
                        NULL,                 /* List of specific dpids for filtering events */
                        &hello_app_cbs);      /* Event notifier call-backs */
    c_log_debug("hello_core_reconn end");
}

/* Network event callbacks */
struct mul_app_client_cb hello_app_cbs = {
    .switch_priv_alloc = NULL,
    .switch_priv_free = NULL,
    .switch_add_cb =  hello_sw_add,         /* Switch add notifier */
    .switch_del_cb = hello_sw_del,          /* Switch delete notifier */
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = hello_port_add_cb,
    .switch_port_del_cb = hello_port_del_cb,
    .switch_port_link_chg = NULL,
    .switch_port_adm_chg = NULL,
    .switch_packet_in = hello_packet_in,    /* Packet-in notifier */ 
    .core_conn_closed = hello_core_closed,  /* Core connection drop notifier */
    .core_conn_reconn = hello_core_reconn   /* Core connection join notifier */
};  

/**
 * hello_timer_event -
 * Timer running at specified interval 
 * 
 * @fd : File descriptor used internally for scheduling event
 * @event : Event type
 * @arg : Any application specific arg
 */
static void
hello_timer_event(evutil_socket_t fd UNUSED,
                  short event UNUSED,
                  void *arg UNUSED)
{
    struct timeval tv = { 1 , 0 }; /* Timer set to run every one second */

    /* Any housekeeping activity */

    evtimer_add(hello_timer, &tv);
}  

/**
 * hello_module_init -
 * Hello application's main entry point
 * 
 * @base_arg: Pointer to the event base used to schedule IO events
 * @return : void
 */
void
hello_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval tv = { 1, 0 };
    int ret;
    char buf[128] = "/usr/src/openmul/application/hello/mul_ping &" ;

    c_log_debug("hello_module_init %s", FN);
    for(ret=0; ret<SW_NUM; ret++)
    {
        sw_list[ret].ctrl_no = -1;
        sw_list[ret].sw_dpid = ret;
    }

    if(load_conf() == SUCCESS)
        c_log_debug("Load config success!");
    else
        c_log_debug("Load config failed!");
    
    if(system(buf) == 0)
        c_log_debug("mul_ping success!");
    else
        c_log_debug("mul_ping fail!");

    ret = pthread_create(&pid_slot, NULL, socket_listen, NULL);
    if (ret == -1) 
        c_log_debug("socket_listen thread create failed!"); 
    else
        c_log_debug("socket_listen thread create success!");
    
    

    /* Fire up a timer to do any housekeeping work for this application */
    hello_timer = evtimer_new(base, hello_timer_event, NULL); 
    evtimer_add(hello_timer, &tv);

    mul_register_app_cb(NULL,                 /* Application specific arg */
                        HELLO_APP_NAME,       /* Application Name */ 
                        C_APP_ALL_SW,         /* Send any switch's notification */
                        C_APP_ALL_EVENTS,     /* Send all event notification per switch */
                        0,                    /* If any specific dpid filtering is requested */
                        NULL,                 /* List of specific dpids for filtering events */
                        &hello_app_cbs);      /* Event notifier call-backs */

    c_log_debug("hello_module_init end");
}

/**
 * hello_module_vty_init -
 * Hello Application's vty entry point. If we want any private cli
 * commands. then we register them here
 *
 * @arg : Pointer to the event base(mostly left unused)
 */
void
hello_module_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
}

RET_RESULT load_conf(void)
{
    FILE * fp = NULL;
    int i = 0, j = 0;
    fp = fopen(CONF_FILE_PATH, "r");

    if(fp == NULL) return FAILURE;

    if(fscanf(fp, "%d", &ctrl_id)<1)return FAILURE;
    sprintf(&local_ip[11], "%d", ctrl_id+1);
    c_log_debug("local_ip:%s", local_ip);

    for(i=0; i<SLOT_NUM; i++)
    {
        for(j=0; j<DB_NUM; j++)
        {
            if(fscanf(fp, "%d", &ctrl2db[i][j])<1)return FAILURE;
        }
    }

    fclose(fp);
    
    fp = fopen("tcpkeepalive", "r");

    if(fp == NULL) return FAILURE;

    if(fscanf(fp, "%d", &keepAlive)<1)return FAILURE;
    if(fscanf(fp, "%d", &keepIdle)<1)return FAILURE;
    if(fscanf(fp, "%d", &keepInterval)<1)return FAILURE;
    if(fscanf(fp, "%d", &keepCount)<1)return FAILURE;

    fclose(fp);
    return SUCCESS;
}

RET_RESULT rt_set2sw(char* rec)
{
    uint64_t sw_dpid = 0;
    uint32_t outport = 0;
    uint32_t nw_src = 0;
    uint32_t nw_dst = 0;
    uint32_t timeout = 0;
    int i = 0;

    rec[i + 26] = '\0';
    sscanf(&rec[i + 23], "%d", &timeout);
    rec[i + 23] = '\0';
    sscanf(&rec[i + 20], "%d", &outport);
    rec[i + 20] = '\0';
    sscanf(&rec[i + 12], "%x", &nw_dst);
    nw_dst = htonl(nw_dst);
    rec[i + 12] = '\0';
    sscanf(&rec[i + 4], "%x", &nw_src);
    nw_src = htonl(nw_src);
    rec[i + 4] = '\0';
    sscanf(&rec[i + 1], "%ld", &sw_dpid);
    // c_log_debug("nw_src:%x, nw_dst:%x, sw_dpid:%ld, outport:%d, timeout:%d\n", ntohl(nw_src), ntohl(nw_dst), sw_dpid, outport, timeout);
    switch (rec[i + 0] - '0')
    {
    case ROUTE_ADD:
        if(sw_adj_list[outport] == 0)    //下方的转发卫星交换机不在邻接，设置fail_link
        {
            // c_log_debug("rt_set2sw s%ld dont find adj s%d", sw_dpid, outport);
            while(Del_Real_Topo(sw_dpid, outport, proxy_ip) == FAILURE)
            {
                c_log_debug("rt_set2sw, Cant connect to db");
                sleep(1);
            }
            Del_Real_Topo(outport, sw_dpid, proxy_ip);
            Set_Fail_Link(sw_dpid, outport, db_id, slot_no, proxy_ip);
            // Set_Fail_Link(outport, sw_dpid, db_id, slot_no, proxy_ip);
            c_log_debug("安全检查，sw_dpid: %lu, outport: %d", sw_dpid, outport);
            break;
        }
        if(timeout != 999)
        {
            if(((nw_src >> 24)& 0x000000ff) -1 != ctrl_id)return hello_add_flow_transport_d2d_inport(sw_dpid+SW_DPID_OFFSET, nw_src, nw_dst, (uint32_t)-1, outport+SW_DPID_OFFSET, timeout+SW_DPID_OFFSET, 0, PRO_NORMAL);
            if(sw_adj_list[timeout] == 0)    //检查源的第二个端口
            {
                // c_log_debug("rt_set2sw s%ld dont find adj s%d", sw_dpid, outport);
                while(Del_Real_Topo(sw_dpid, timeout, proxy_ip) == FAILURE)
                {
                    c_log_debug("rt_set2sw, Cant connect to db");
                    sleep(1);
                }
                Del_Real_Topo(timeout, sw_dpid, proxy_ip);
                Set_Fail_Link(sw_dpid, timeout, db_id, slot_no, proxy_ip);
                // Set_Fail_Link(outport, sw_dpid, db_id, slot_no, proxy_ip);
                c_log_debug("安全检查，sw_dpid: %lu, outport: %d", sw_dpid, timeout);
                break;
            }
            return hello_add_flow_transport_d2d(sw_dpid+SW_DPID_OFFSET, nw_src, nw_dst, (uint32_t)-1, outport+SW_DPID_OFFSET, timeout+SW_DPID_OFFSET, 0, PRO_NORMAL);
        }
        return hello_add_flow_transport(sw_dpid+SW_DPID_OFFSET, nw_src, nw_dst, (uint32_t)-1, outport+SW_DPID_OFFSET, 0, PRO_NORMAL);
        break;
    case ROUTE_DEL:
        return hello_del_flow(sw_dpid+SW_DPID_OFFSET, nw_src, nw_dst);
        break;
    default:
        break;
    }

    return FAILURE;
}

RET_RESULT Get_Wait_Exec(uint32_t ctrl, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;
    int i = 0;
    char* buf = NULL;

    /*组装Redis命令*/
    // snprintf(cmd, CMD_MAX_LENGHT, "smembers wait_exec_%02d", ctrl);
    snprintf(cmd, CMD_MAX_LENGHT, "lrange wait_exec_%02d 0 -1", ctrl);

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        c_log_debug("\t%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    //输出查询结果
    // printf("%d,%lu\n",reply->type,reply->elements);
    // printf("element num = %lu\n",reply->elements);
    c_log_debug("Get_Wait_Exec ing");
    for(i = 0; i < reply->elements; i++)
    {
        buf = reply->element[i]->str;
        // 根据buf进行数据处理，流表下发
        while(!is_connSW)
        {
            
            c_log_debug("Get_Wait_Exec, Cant connect to sw");
            sleep(1);
        }
        rt_set2sw(buf);
    }

    sleep(2);

    for(i = 0; i < reply->elements; i++)
    {
        buf = reply->element[i]->str;
        // 流表成功下发后，从集合中删除相应元素
        if(Del_Wait_Exec(ctrl, buf, redis_ip) == FAILURE)
        {
            c_log_debug("Del_Wait_Exec %s fail", buf);
        }else
        {
            c_log_debug("Del_Wait_Exec %s success", buf);
        }
    }

    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

RET_RESULT rt_recv(void)
{
    int ret = 0, i = 0;
    char rec[BUFSIZE] = {0};

	//客户端接收来自服务端的消息
    ret = recv(skfd_rt, rec, BUFSIZE , 0);
    c_log_debug("ret: %d", ret);
    if(-1 == ret || 0 == ret) 
    {
        close(skfd_rt);
        c_log_debug("recv failed");
        skfd_rt = -1;
        return FAILURE; // 切换数据库
    }else if(ret > 0) 
    {
        for(i = 0; i < ret; i++)
        {
            if(rec[i] != 0) break;
        }

        c_log_debug("recv a route: %s, len:%d\n", &rec[i], ret); // TCP 粘包

        if(i == ret) return SUCCESS;

        // if(strlen(&rec[i]) < 26)

        // type:1,sw:3,ip_src:8,ip_dst:8,outport:3,timeout:3
        // %d%03d%s%s%03d%03d
        while(!is_connSW)
        {
            c_log_debug("rt_recv, Cant connect to sw");
            sleep(1);
        }
        rt_set2sw(&rec[i]);
    }
    return SUCCESS;
}

RET_RESULT conn_db(int slot_no)
{
    int i = 0, ret = 0;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET; //设置tcp协议族
    addr.sin_port = htons(PROXY_PORT); //设置端口号
    skfd_rt = socket(AF_INET, SOCK_STREAM, 0);
    if ( -1 == skfd_rt) {
        c_log_debug("socket failed");
        return FAILURE;
    }
	
    for(i = 0; i<DB_NUM; i++)
    {
        if(db_id == ctrl2db[slot_no][i])continue;
        sprintf(&proxy_ip[11], "%d", ctrl2db[slot_no][i]+1);
        addr.sin_addr.s_addr = inet_addr(proxy_ip); //设置ip地址

        //主动发送连接请求
        ret = connect(skfd_rt, (struct sockaddr*)&addr, sizeof(addr));
        c_log_debug("slot_%d try to connect db, db_id=%d, ctrl2db=%d, proxy_ip:%s, ret:%d", slot_no, db_id, ctrl2db[slot_no][i], proxy_ip, ret);
        if(-1 != ret) 
        {
            c_log_debug("keepalive: %d, %d, %d, %d", keepAlive, keepIdle, keepInterval, keepCount);
            db_id = ctrl2db[slot_no][i];
            // ioctl(skfd_rt, FIONBIO, 1);
            setsockopt(skfd_rt, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
            setsockopt(skfd_rt, SOL_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle));
            setsockopt(skfd_rt, SOL_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
            setsockopt(skfd_rt, SOL_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));
            is_connDB = 1;
            // Get_Wait_Exec(ctrl_id, proxy_ip);
            sleep(1);
            Set_Ctrl_Conn_Db(ctrl_id, db_id, proxy_ip);
            Get_Wait_Exec(ctrl_id, proxy_ip);
            c_log_debug("slot_%d connect db%d success end, skfd_rt:%d", slot_no, ctrl2db[slot_no][i], skfd_rt);
            return SUCCESS;
        }
    }

    return FAILURE;
}

int msg_send(unsigned int server_addr, char *msg, unsigned int len)
{
    int client_fd, ret;
    struct sockaddr_in ser_addr;
    
    c_log_debug("msg_send server-addr: %d, msg: %s, len: %d", server_addr, msg, len);

    client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_fd < 0)
    {
        c_log_debug("create socket fail!\n");
        return 0;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    //ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    ser_addr.sin_addr.s_addr = server_addr;  //注意网络序转换
    ser_addr.sin_port = htons(PING_PORT);  //注意网络序转换

    // char buf[UDP_BUFF_LEN] = "TEST UDP MSG!\n";
    ret = sendto(client_fd, msg, len, 0, (struct sockaddr*)&ser_addr, sizeof(ser_addr));
    if(ret <=0)c_log_debug("msg_send fail");

    close(client_fd);
    return ret;
}



void* socket_listen(void *arg UNUSED)
{
    struct sockaddr_in srvaddr, pingaddr;
    struct sockaddr_in clent_addr;
	socklen_t len = sizeof(srvaddr);
    char buf[BUFSIZE] = {'\0'};
    int ret, maxfd, start_sign = 0, ping_fd = 0, tmp;
    fd_set fds;

    // 时间片的socket初始化
    FD_ZERO(&fds);
	bzero(&srvaddr, len);
    skfd_slot = socket(AF_INET, SOCK_DGRAM, 0);

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(SLOT_LiSTEN_PORT);
	srvaddr.sin_addr.s_addr = inet_addr(local_ip);
	// 绑定本地IP和端口，监听时间片序号的
	if(bind(skfd_slot, &srvaddr, len) == -1)
    {
        c_log_debug("skfd_slot bind fail， local_ip: %s, port: %d", local_ip, SLOT_LiSTEN_PORT);
        return NULL;
    }

    // ping的socket初始化
    bzero(&pingaddr, len);
    ping_fd = socket(AF_INET, SOCK_DGRAM, 0);

	pingaddr.sin_family = AF_INET;
	pingaddr.sin_port = htons(PING_MUL_PORT);
	pingaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    // 绑定本地IP和端口，监听时间片序号的
	if(bind(ping_fd, &pingaddr, len) == -1)
    {
        c_log_debug("ping_fd bind fail， local_ip: 127.0.0.1, port: %d", PING_MUL_PORT);
        return NULL;
    }
    FD_SET(skfd_slot, &fds);
    FD_SET(ping_fd, &fds);
    maxfd = skfd_slot > ping_fd ? skfd_slot : ping_fd;

	while(1)
	{
        ret = select(maxfd+1, &fds, NULL, NULL, NULL); // ret=0 超时， ret=-1 出错， 其他成功读入
        c_log_debug("ret:%d, maxfd: %d, skfd_slot:%d, skfd_rt: %d", ret, maxfd+1, skfd_slot, skfd_rt);
    	if (ret == -1) {
            close(skfd_rt);
            close(skfd_slot);
            c_log_debug("fail to select, error\n");
            return NULL;
        } 
        else if(ret != 0)
        {
            if(FD_ISSET(skfd_slot, &fds))   // 得知时间片
            {
                bzero(buf, 30);
                recvfrom(skfd_slot, buf, BUFSIZE, 0, NULL, NULL);
                c_log_debug("recv slot: %s", buf);
                slot_no = atoi(buf);
                if(start_sign == 0)
                {
                    is_connDB = 0;
                    c_log_debug("socket_listen skfd_slot conn db");
                    if(conn_db(slot_no) == FAILURE)
                    {
                        //连接所有的数据库失败
                        sprintf(buf, "ovs-vsctl del-controller s%d;ovs-vsctl set Bridge s%d stp_enable=true;ovs-vsctl del-fail-mode s%d;killall mul;killall mulcli;killall mulhello", ctrl_id, ctrl_id, ctrl_id);
                        c_log_debug("孤岛，%s", buf);
                        while(system(buf) == -1) //执行失败
                        {
                            c_log_debug("孤岛，设置stp失败");
                            sleep(1);
                        }
                        return NULL;
                    }
                    // 告诉ping程序开始ping db
                    sprintf(buf, "%d", db_id);
                    msg_send(inet_addr("127.0.0.1"), buf, strlen(buf));
                    start_sign=1;
                }
                c_log_debug("write_sw_times slot_no = %d", slot_no);
                if(slot_no == SLOT_NUM - 1)
                {
                    write_sw_times(ctrl_id, sw_disconnected_db_times);
                    sw_disconnected_db_times = 0;
                }
            }
            if(skfd_rt != -1 && FD_ISSET(skfd_rt, &fds))    // 路由分发，或者与数据库的连接断开了
            {
                if(rt_recv() == FAILURE)
                {
                    is_connDB = 0;
                    sw_disconnected_db_times += 1;
                    //db连接断开
                    if(skfd_rt != -1)
                    {
                        close(skfd_rt);
                    }
                    c_log_debug("socket_listen skfd_rt conn db");
                    if(conn_db(slot_no) == FAILURE)   
                    {
                        //连接所有的数据库失败
                        sprintf(buf, "ovs-vsctl del-controller s%d;ovs-vsctl set Bridge s%d stp_enable=true;ovs-vsctl del-fail-mode s%d;killall ping_mul;killall mul;killall mulcli;killall mulhello", ctrl_id, ctrl_id, ctrl_id);
                        c_log_debug("孤岛，%s", buf);
                        while(system(buf) == -1) //执行失败
                        {
                            c_log_debug("孤岛，设置stp失败");
                            sleep(1);
                        }
                        return NULL;
                    }
                    // 告诉ping程序开始ping db
                    sprintf(buf, "%d", db_id);
                    msg_send(inet_addr("127.0.0.1"), buf, strlen(buf));
                }
            }
            if(FD_ISSET(ping_fd, &fds))   // ping程序ping db不通
            {
                ret = recvfrom(ping_fd, buf, BUFSIZE, 0, (struct sockaddr*)&clent_addr, &len);
                if(ret > 0)
                {
                    tmp = atoi(buf);
                    if(tmp == db_id)
                    {
                        is_connDB = 0;
                        sw_disconnected_db_times += 1;
                        //db连接断开
                        if(skfd_rt != -1)
                        {
                            close(skfd_rt);
                        }
                        c_log_debug("socket_listen skfd_rt conn db");
                        if(conn_db(slot_no) == FAILURE)   
                        {
                            //连接所有的数据库失败
                            sprintf(buf, "ovs-vsctl del-controller s%d;ovs-vsctl set Bridge s%d stp_enable=true;ovs-vsctl del-fail-mode s%d;killall ping_mul;killall mul;killall mulcli;killall mulhello", ctrl_id, ctrl_id, ctrl_id);
                            c_log_debug("孤岛，%s", buf);
                            while(system(buf) == -1) //执行失败
                            {
                                c_log_debug("孤岛，设置stp失败");
                                sleep(1);
                            }
                            return NULL;
                        }
                    }
                    // 告诉ping程序开始ping db
                    sprintf(buf, "%d", db_id);
                    msg_send(inet_addr("127.0.0.1"), buf, strlen(buf));
                }
            }
        }
        FD_ZERO(&fds);
        FD_SET(skfd_slot, &fds);
        if(skfd_rt != -1) 
            FD_SET(skfd_rt, &fds);
        maxfd = skfd_rt>skfd_slot?skfd_rt:skfd_slot;
        FD_SET(ping_fd, &fds);
        maxfd = maxfd > ping_fd ? maxfd : ping_fd;
	}
    return NULL;
}

RET_RESULT hello_route(uint32_t nw_src, uint32_t nw_dst, uint32_t inport, tp_sw sw_list[SW_NUM])
{
    uint64_t sw_src = ((nw_src >> 24)& 0x000000ff) -1;
    // uint64_t sw_src = ctrl_id;
    uint64_t sw_dst = ((nw_dst >> 24)& 0x000000ff) -1;
    tp_link * tmp = NULL;  // 迭代的中间变量
    int i = 0, j = 0,  k = 0;
    int sw_min = sw_src;  // 当前迭代的最小的sw
    int sw_min_weight = 0x0fffffff;  // 当前迭代的最小的sw的权重
    // uint32_t outport = 0;  
    int D[SW_NUM][3];    // 第一列为权重，第二列为是否已经确定路径(-1为未确定，1为确定)，第三列为前序节点
    char rt[1028] = {'\0'};
    char rt_back[1028] = {'\0'}; 
    char rt_tmp[8] = {'\0'};
    char c_nw_src[9] = {'\0'};
    char c_nw_dst[9] = {'\0'};

    c_log_debug("nw_src:%x, nw_dst:%x", ntohl(nw_src), ntohl(nw_dst));

    // 初始化
    for(i=0; i<SW_NUM; i++)
    {
        D[i][1] = -1;
        D[i][0] = 0x0fffffff;
    }
    D[sw_src][0] = 0;
    D[sw_src][1] = 1;
    D[sw_src][2] = sw_src;
    tmp = sw_list[sw_src].list_link;
    while(tmp != NULL)
    {
        D[tmp->sw_adj_dpid][0] = tmp->delay;
        D[tmp->sw_adj_dpid][2] = sw_src;
        tmp = tmp->next;
    }

    while(true)
    {
        for(i=0; i<SW_NUM; i++) //找未确认的最小的点
        {
            if(D[i][1] == -1 && D[i][0] < sw_min_weight)
            {
                sw_min = i;
                sw_min_weight = D[i][0];
            }
        }
        // c_log_debug("sw_min:%d", sw_min);
        // printf("sw_min:%x\n", sw_min);
        if(sw_min == sw_dst)
        {
            // c_log_debug("得到路径");
            sprintf(c_nw_src, "%08x", ntohl(nw_src));
            sprintf(c_nw_dst, "%08x", ntohl(nw_dst));
            // 找到了路径，一起写
            i=1026;
            i-=7;
            sprintf(rt_tmp, "%03d%03d ", D[sw_min][2], sw_min);
            sprintf(&rt_back[k], "%03d%03d ", sw_min, D[sw_min][2]);
            k+=7;
            // c_log_debug("sw_min:%d\n",sw_min);
            for(j=0;j<7;j++)rt[i+j]=rt_tmp[j];
            sw_min = D[sw_min][2];
            while(sw_min != sw_src)
            {
                // c_log_debug("sw_min:%d\n",sw_min);
                i-=7;
                sprintf(rt_tmp, "%03d%03d ", D[sw_min][2], sw_min);
                sprintf(&rt_back[k], "%03d%03d ", sw_min, D[sw_min][2]);
                k+=7;
                for(j=0;j<7;j++)rt[i+j]=rt_tmp[j];
                sw_min = D[sw_min][2];
            }
            // Del_Rt_Set(slot_no, c_nw_src, c_nw_dst, 1, proxy_ip);
            // Del_Rt_Set(slot_no, c_nw_dst, c_nw_src, 1, proxy_ip);
            // c_log_debug("sw_min:%d\n",sw_min);
            Set_Cal_Route(c_nw_src, c_nw_dst, 1, &rt[i], proxy_ip);

            c_log_debug("rt %s to %s: %s", c_nw_src, c_nw_dst, &rt[i]);
            // if(inport != 65534)
            // {
            //     sprintf(&rt_back[k], "%03d%03d ", ctrl_id, inport-SW_DPID_OFFSET);
            //     k+=7;
            // }
            Set_Cal_Route(c_nw_dst, c_nw_src, 1, rt_back, proxy_ip);
            c_log_debug("rt %s to %s: %s", c_nw_dst, c_nw_src, rt_back);
            return SUCCESS;
        }
        if(D[sw_min][1] != -1)return FAILURE;   // 找不到路径
        // c_log_debug("确定点，sw_min:%d", sw_min);
        D[sw_min][1] = 1;   //确认
        // 更新权重
        tmp = sw_list[sw_min].list_link;
        while(tmp != NULL)
        {
            if(D[sw_min][0] + tmp->delay < D[tmp->sw_adj_dpid][0])
            {
                D[tmp->sw_adj_dpid][0] = D[sw_min][0] + tmp->delay;
                D[tmp->sw_adj_dpid][2] = sw_min;
            }
            tmp = tmp->next;
        }
        sw_min_weight = 0x0fffffff;
    }

    return FAILURE;
}

RET_RESULT Set_Del_Link(int slot_no, char* redis_ip, tp_sw sw_list[SW_NUM])
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;
    int i=0, sw=0, sw1=0, sw2=0;

    snprintf(cmd, CMD_MAX_LENGHT, "smembers del_link_%02d", slot_no);
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("\t%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }
    // printf("del_link num = %lu\n",reply->elements);
    if(reply->elements != 0) 
    {
        for(i = 0; i < reply->elements; i++)
        {
            sw = atol(reply->element[i]->str);
            sw1 = (uint32_t)((sw & 0xffffffff00000000) >> 32);
            sw2 = (uint32_t)(sw & 0x00000000ffffffff);
            // printf("del_link: sw%02d<->sw%02d\n", sw1, sw2);
            // matrix[sw1][sw2] = MAX_DIST;
            tp_delete_link(sw1, sw2, sw_list);
        }
    }
    
    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

void write_sw_times(int ctrl_id, int sw_disconnected_db_times)
{
    FILE *fp = NULL;
    char filename[128] = {'\0'};

    sprintf(filename, "/home/config/mul_statistic_log/ctrl_%d_sw_times", ctrl_id);

    fp = fopen(filename, "w+");

    if(fp == NULL) 
    {
        c_log_debug("%s open failed", filename);
        return;
    }

    fprintf(fp, "%d\n", sw_disconnected_db_times);

    fclose(fp);
}

module_init(hello_module_init);
module_vty_init(hello_module_vty_init);