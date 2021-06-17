#ifndef __MUL_REDIS_INTERFACE_H__
#define __MUL_REDIS_INTERFACE_H__

#include "hiredis.h"

/*宏定义*/
#ifndef CMD_MAX_LENGHT
#define CMD_MAX_LENGHT 256
#endif

#ifndef REDIS_SERVER_IP
#define REDIS_SERVER_IP "192.168.10.226"
#endif

#ifndef REDIS_SERVER_PORT
#define REDIS_SERVER_PORT 8102
#endif


typedef enum DB_RESULT
{
    SUCCESS = 1,
    FAILURE = 0
} DB_RESULT;

/**
 * connect the redis server, use the define REDIS_SERVER_IP and port REDIS_SERVER_PORT
 * @return: success 1, fail 0
*/
DB_RESULT redis_connect(redisContext **context);

/**
 * disconnect the redis server, use the define REDIS_SERVER_IP and port REDIS_SERVER_PORT
 * @return: success 1, fail 0
*/
DB_RESULT redis_disconnect(redisContext *context);

/**
 * 获取控制器ID
 * @ip: pram in, contoller ip
 * @cid: pram out, controller id
 * @return: success 1, fail 0
 */
DB_RESULT redis_Get_Ctrl_Id(uint32_t ip, uint32_t *cid);    

/**
 * 获取链路时延
 * @sw1: pram in, sw1 id
 * @sw2: pram in, sw2 id
 * @delay: pram out, link delay
 * @return: success 1, fail 0
*/
DB_RESULT redis_Get_Link_Delay(uint32_t sw1, uint32_t sw2, uint64_t *delay); 

/**
 * set the delay of link
 * @sw1: pram in, sw1 id
 * @port1: pram in, the port of link in sw1
 * @sw2: pram in, sw2 id
 * @port2: pram in, the port of link in sw2
 * @delay: pram in, link delay
 * @return: success 1, fail 0
*/
DB_RESULT redis_Set_Link_Delay(uint32_t sw1, uint32_t sw2, uint64_t delay); 

/**
 * 获取链路 port
 * @sw1: pram in, sw1 id
 * @port1: pram out, the port of link in sw1
 * @sw2: pram in, sw2 id
 * @port2: pram out, the port of link in sw2
 * @return: success 1, fail 0
*/
DB_RESULT redis_Get_Link_Port(uint32_t sw1, uint32_t *port1, uint32_t sw2, uint32_t *port2); 

/**
 * set the port of link
 * @sw1: pram in, sw1 id
 * @port1: pram in, the port of link in sw1
 * @sw2: pram in, sw2 id
 * @port2: pram in, the port of link in sw2
 * @return: success 1, fail 0
*/
DB_RESULT redis_Set_Link_Port(uint32_t sw1, uint32_t port1, uint32_t sw2, uint32_t port2); 


/**
 * 获取PC连接的交换机端口
 * @ip: pram in, pc ip
 * @sw: pram out, the sw of pc connected
 * @port: pram out, the port of link in sw
 * @return: success 1, fail 0
*/
DB_RESULT redis_Get_Pc_Sw_Port(uint32_t ip, uint32_t *sw, uint32_t *port); 

/**
 * SET PC连接的交换机端口
 * @ip: pram in, pc ip
 * @sw: pram in, the sw of pc connected
 * @port: pram in, the port of link in sw
 * @return: success 1, fail 0
*/
DB_RESULT redis_Set_Pc_Sw_Port(uint32_t ip, uint32_t sw, uint32_t port); 

/**
 * 获取PC的MAC
 * @ip: pram in, pc ip
 * @mac: mac address
 * @return: success 1, fail 0
*/
DB_RESULT redis_Get_Pc_MAC(uint32_t ip, uint8_t *mac); 

/**
 * SET PC的MAC
 * @ip: pram in, pc ip
 * @mac: mac address
 * @return: success 1, fail 0
*/
DB_RESULT redis_Set_Pc_MAC(uint32_t ip, uint8_t *mac);

/**
 * 获取交换机到控制器的时延
 * @sw: pram in, sw id
 * @delay: pram out, link delay
 * @return: success 1, fail 0
*/
DB_RESULT redis_Get_Sw_Delay(uint32_t sw, uint64_t *delay);

/**
 * SET 交换机到控制器的时延
 * @sw: pram in, sw id
 * @delay: pram in, link delay
 * @return: success 1, fail 0
*/
DB_RESULT redis_Set_Sw_Delay(uint32_t sw, uint64_t delay);

/**
 * 执行命令
 * @cmd: pram in, the command needed to send to redis
 * @return: success 1, fail 0
*/
DB_RESULT exeRedisIntCmd_wr(char *cmd);

redisReply * exeRedisIntCmd_rd(char *cmd);

DB_RESULT exeRedisIntCmd_rd_One(char *cmd, void* ret, uint8_t len);

/**
 * set the route path
 * @nw_src: pram in, src ip address
 * @nw_dst: pram in, dst ip address
 * @path: pram in, the sw_id array of route path
 * @len: pram in, the length of path
 * @return: success 1, fail 0
*/
DB_RESULT redis_Set_Route_Path(uint32_t nw_src, uint32_t nw_dst, uint64_t *path, uint8_t len);

/**
 * get the route path
 * @nw_src: pram in, src ip address
 * @nw_dst: pram in, dst ip address
 * @path: pram out, the sw_id array of route path
 * @len: pram out, the length of path
 * @return: success 1, fail 0
*/
DB_RESULT redis_Get_Route_Path(uint32_t nw_src, uint32_t nw_dst, uint64_t **path, uint32_t *len);

/**
 * check the redis if have a route path
 * @nw_src: pram in, src ip address
 * @nw_dst: pram in, dst ip address
 * @return: success 1, fail 0
*/
DB_RESULT redis_Is_Route_Path(uint32_t nw_src, uint32_t nw_dst);

DB_RESULT redis_Set_Sw2PC_Port(uint32_t sw_port, uint32_t ip);
DB_RESULT redis_Del_Sw2PC_Port(uint32_t sw_port);
#endif
