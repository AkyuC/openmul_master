/***************************************************************
*   文件名称：db_wr.h
*   描    述：用于向Redis数据库进行读写操作 
***************************************************************/

#include "hiredis.h"

/*宏定义*/
#define CMD_MAX_LENGHT 256
#define REDIS_SERVER_IP "192.168.10.215"
#define REDIS_SERVER_PORT 6379

typedef enum DB_RESULT
{
    SUCCESS = 0,
    FAILURE = 1
} DB_RESULT;

/*结构体定义*/
// typedef struct Ctrl_Struct
// {
//     uint32_t ip; // 控制器IP
//     uint16_t id; // 控制器ID
// }Ctrl_Struct;

// typedef struct Link_Struct
// {
//     uint32_t port1; // 连接的交换机端口1
//     uint32_t port2; // 连接的交换机端口2
//     uint64_t delay;// S2S时延
// }Link_Struct;

// typedef struct Pc_Struct
// {
//     uint32_t ip; // IP
//     uint32_t port; // 连接的交换机端口
// }Pc_Struct;

// typedef struct Sw_Struct
// {
//     uint16_t cid; // 控制器ID
//     uint8_t sid; // 交换机ID
//     uint64_t delay;// C2S时延
// }Sw_Struct;

/*写函数*/
// DB_RESULT Set_Ctrl_Id(uint32_t ip, uint16_t id);/*设置控制器信息 IP->ID*/
DB_RESULT Set_Link_Delay(uint32_t port1, uint32_t port2, uint64_t delay); /*设置链路信息 (node1,node2)->时延*/
DB_RESULT Set_Pc_Sw_Port(uint32_t ip, uint32_t port);                     /*设置PC信息 IP->连接的交换机端口*/
DB_RESULT Set_Sw_Delay(uint16_t cid, uint8_t sid, uint64_t delay);        /*设置交换机信息 (CID,SID)->到控制器的时延*/
/*读函数*/
uint16_t Get_Ctrl_Id(uint32_t ip);                       /*获取控制器ID*/
uint64_t Get_Link_Delay(uint32_t port1, uint32_t port2); /*获取链路时延*/
uint32_t Get_Pc_Sw_Port(uint32_t ip);                    /*获取PC连接的交换机端口*/
uint64_t Get_Sw_Delay(uint16_t cid, uint8_t sid);        /*获取交换机到控制器的时延*/
/*执行命令*/
DB_RESULT exeRedisIntCmd(char *cmd); // 写操作返回int
