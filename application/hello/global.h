#ifndef __MUL_GLOBAL_H__
#define __MUL_GLOBAL_H__

#include <sys/time.h>

#define SW_NUM 66
#define SLOT_TIME 80

#ifndef SLOT_NUM
#define SLOT_NUM 44
#endif

#ifndef RETURN_RESULT
#define RETURN_RESULT
typedef enum RET_RESULT
{
    SUCCESS = 1,
    FAILURE = -1
} RET_RESULT;
#endif

#define PRO_CTRL 100   // 控制通道流表优先级
#define PRO_SW2CTRL 40  // 上传到控制器的流表优先级
#define PRO_NORMAL 100   // 普通的流表优先级
#define PRO_DEFAULT 20   // 默认流表优先级

#define TABLE_NORMAL 0  // 普通流表项所在table
#define TABLE_DEFAULT 1 // 默认流表项所在table

#define SW_DPID_OFFSET 1000 //防止由于交换机是0开始的编号，设置的偏移量

#define ROUTE_ADD 1 // type_1 add
#define ROUTE_DEL 2 // type_2 del

#define CONF_FILE_PATH "/home/ctrl2db"
#define PROXY_PORT 2345  // 数据库监听的端口
#define SLOT_LiSTEN_PORT 12000  // 本地时间片切换时，需要知道时间片切换，收消息的套接字
#define PING_MUL_PORT 4566  // 是否能ping通的套接字监听，ping程序会向这个数据包发送udp包
#define PING_PORT 4567 // ping 程序接收ping的目的地址，发送db_id到这个端口
#define BUFSIZE 512 // 套接字缓存大小

#define SLOT_NUM 44
#define SW_NUM 66
#define DB_NUM 6

#define REDIS_CONN_TIMEOUT 5 // redis连接超时时间

#endif