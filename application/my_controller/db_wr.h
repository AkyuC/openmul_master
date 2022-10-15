/***************************************************************
*   文件名称：db_wr.h
*   描    述：用于向Redis数据库进行读写操作

1、设置交换机的默认主控制器 "hset active_ctrl_%02d %u %u", slot, sw, ctrl
2、设置交换机的默认备用控制器 "hset standby_ctrl_%02d %u %u", slot, sw, ctrl
3、设置控制器的默认数据库 "hset db_%02d %u %u", slot, ctrl, db

// 维护controller当前连接的sw集合，db代理分发路由时需要查询结果，发送给相应的控制器
// 可采用set数据结构存储，https://blog.csdn.net/Xiejingfa/article/details/50594005
4、交换机连接控制器后，将该交换机添加到对应控制器的控制集合中 "sadd sw_set_%02d_%02d %u", ctrl, slot, sw
5、交换机断开连接后，将该交换机从对应控制器的控制集合中删除 "srem sw_set_%02d_%02d %u", ctrl, slot, sw

6、设置默认拓扑 "hset dfl_topo_%02d %lu %lu", slot, sw, delay	"sadd dfl_set_%02d %lu", slot, sw
7、控制器确认链路连接之后，将该链路添加到真实拓扑中  "hset real_topo_%02d %lu %lu", slot, sw, delay	"sadd real_set_%02d %lu", slot, sw
8、控制器确认链路断开连接之后，将该链路从真实拓扑中删除  "hdel real_topo_%02d %lu", slot, sw	"srem real_set_%02d %lu", slot, sw
9、控制器确认链路断开连接之后，将该链路添加到失效链路列表中 "rpush fail_link_%02d %lu", slot, sw
注意：何时清空失效链路列表？下一个时间片

10、控制器下发新增（非定时）流表后，把路由条目加入该链路的（非定时）路由集合中 "sadd rt_set_%02d_%02d %s%s", sw1, sw2, ip_src, ip_dst
11、控制器下发新增（定时）流表后，把路由条目加入该链路的（定时）路由集合中 "sadd rt_set_t_%02d_%02d_%02d %s%s", sw1, sw2, slot, ip_src, ip_dst
12、链路失效，控制器下发删除该链路的全部流表后，从链路的（定时+非定时）路由集合中删去相应路由条目 
"srem rt_set_%02d_%02d %s%s", sw1, sw2, ip_src, ip_dst	"srem rt_set_t_%02d_%02d_%02d %s%s", sw1, sw2, slot, ip_src, ip_dst
13、控制器下发设置流表定时后，把路由条目该链路的从（非定时）路由集合中取出，加入（定时）路由集合中
"smove rt_set_%02d_%02d rt_set_t_%02d_%02d_%02d %s%s", sw1, sw2, sw1, sw2, slot, ip_src, ip_dst

14、设置默认路由列表 "rpush dflrt_%s%s_%02d %s", ip_src, ip_dst, slot, out_sw_port
15、设置控制器计算出的路由列表 "rpush calrt_%s%s %s", ip_src, ip_dst, out_sw_port
16、设置控制器未成功计算出的路由列表，goto table2走默认路由 "rpush failrt_%s%s 1", ip_src, ip_dst

17、设置下个时间片要删除的链路集合 "sadd del_link_%02d %lu", slot, sw
18、拓扑收敛之后，校对得到失效链路，添加到失效链路列表中 
"sdiff dfl_set_%02d real_set_%02d", slot, slot	"rpush fail_link_%02d %lu", slot, sw
    
***************************************************************/

#include "hiredis.h"
#include "topo.h"

/*宏定义*/
#define CMD_MAX_LENGHT 256
// #define REDIS_SERVER_IP "192.168.10.215"
#define REDIS_SERVER_PORT 8102
#define redis_ip_len 20

#ifndef RETURN_RESULT
#define RETURN_RESULT
typedef enum RET_RESULT
{
    SUCCESS = 1,
    FAILURE = -1
} RET_RESULT;
#endif

/*写函数*/
// RET_RESULT Set_Ctrl_Id(uint32_t ip, uint16_t id);                         /*设置控制器信息 IP->ID*/
// RET_RESULT Set_Link_Delay(uint32_t port1, uint32_t port2, uint64_t delay);   /*设置链路信息 (node1,node2)->时延*/
// RET_RESULT Clr_Link_Delay(uint32_t port1, uint32_t port2);                   /*清除链路信息*/
// RET_RESULT Set_Pc_Sw_Port(uint32_t ip, uint32_t port);                       /*设置PC信息 IP->连接的交换机端口*/
// RET_RESULT Set_Sw_Delay(uint16_t cid, uint8_t sid, uint64_t delay);          /*设置交换机信息 (CID,SID)->到控制器的时延*/
// RET_RESULT Clr_Sw_Delay(uint16_t cid, uint8_t sid);                          /*清除交换机信息*/
// RET_RESULT Set_Route(uint32_t ip_src, uint32_t ip_dst, uint32_t out_sw_port);/*设置路由信息 添加到列表头部*/
// RET_RESULT Clr_Route(uint32_t ip_src, uint32_t ip_dst);                      /*清除路由信息*/

// write switch <-> controller(active and standby)
RET_RESULT Set_Active_Ctrl(uint32_t sw, uint32_t ctrl, int slot, char* redis_ip);
RET_RESULT Set_Standby_Ctrl(uint32_t sw, uint32_t ctrl, int slot, char* redis_ip);
// write controller <-> switches set
RET_RESULT Add_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip);
RET_RESULT Del_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip);
// write controller <-> database
RET_RESULT Set_Ctrl_Conn_Db(uint32_t ctrl, uint32_t db, int slot, char* redis_ip);
// write default topo
RET_RESULT Set_Topo(uint32_t sw1, uint32_t sw2, uint64_t delay, int slot, char* redis_ip);
// write real topo that links must be connected
RET_RESULT Add_Real_Topo(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip);
RET_RESULT Del_Real_Topo(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip);
// write default routes(s2s/d2d/c2s/c2d)
RET_RESULT Set_Dfl_Route(char *ip_src, char *ip_dst, char *out_sw_port, int slot, char* redis_ip);
RET_RESULT Set_Cal_Route(char *ip_src, char *ip_dst, char *out_sw_port, char* redis_ip);
RET_RESULT Set_Cal_Fail_Route(char *ip_src, char *ip_dst, char* redis_ip);
// write links that next slot will be deleted
RET_RESULT Set_Del_Link(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip);
// write links that have been disconnected
//注意：何时清空失效链路列表？下一个时间片
RET_RESULT Set_Fail_Link(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip); 
// write link <-> routes set
RET_RESULT Add_Rt_Set(uint32_t sw1, uint32_t sw2, char *ip_src, char *ip_dst, char* redis_ip);
RET_RESULT Del_Rt_Set(int slot, char *ip_src, char *ip_dst, char* redis_ip);
RET_RESULT Add_Rt_Set_Time(uint32_t sw1, uint32_t sw2, int slot, char *ip_src, char *ip_dst, char* redis_ip);
RET_RESULT Mov_Rt_Set(uint32_t sw1, uint32_t sw2, int slot, char *ip_src, char *ip_dst, char* redis_ip);
// write fail_link(dfl_set - real_set)
RET_RESULT Diff_Topo(int slot, char* redis_ip);


/*读函数*/
// uint16_t Get_Ctrl_Id(uint32_t ip);                       /*获取控制器ID*/
// uint64_t Get_Link_Delay(uint32_t port1, uint32_t port2); /*获取链路时延*/
// uint32_t Get_Pc_Sw_Port(uint32_t ip);                    /*获取PC连接的交换机端口*/
// uint64_t Get_Sw_Delay(uint16_t cid, uint8_t sid);        /*获取交换机到控制器的时延*/

// read switch <-> controller(active and standby)
uint32_t Get_Active_Ctrl(uint32_t sw, int slot, char* redis_ip);
uint32_t Get_Standby_Ctrl(uint32_t sw, int slot, char* redis_ip);
// lookup controller <-> switches set
RET_RESULT Lookup_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip);
// read controller <-> database
uint32_t Get_Ctrl_Conn_Db(uint32_t ctrl, int slot, char* redis_ip);
//read default topo from redis to sw_list
RET_RESULT Get_Topo(int slot, char* redis_ip, tp_sw sw_list[SW_NUM]);
//read real topo from redis to sw_list
RET_RESULT Get_Real_Topo(int slot, char* redis_ip, tp_sw sw_list[SW_NUM]);
// lookup whether link will be deleted in next slot
RET_RESULT Lookup_Del_Link(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip);
// read link delay
uint64_t Get_Link_Delay(uint32_t port1, uint32_t port2, int slot, char* redis_ip);

/*执行命令*/
RET_RESULT redis_connect(redisContext **context, char* redis_ip);
RET_RESULT exeRedisIntCmd(char *cmd, char* redis_ip); // 写操作返回int
