#ifndef __MUL_GLOBAL_H__
#define __MUL_GLOBAL_H__

#include <sys/time.h>

#define SW_NUM 66
#define SLOT_TIME 40

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

#define PRO_SW2CTRL 45  // 上传到控制器的流表优先级
#define PRO_NORMAL 50   // 普通的流表优先级

#define TABLE_NORMAL 0  // 普通流表项所在table
#define TABLE_DEFAULT 1 // 默认流表项所在table

#define SW_DPID_OFFSET 1000 //防止由于交换机是0开始的编号，设置的偏移量

#define ROUTE_ADD 1 // type_1 add
#define ROUTE_DEL 2 // type_2 del

#define CONF_FILE_PATH "/home/ctrl_connect"
#define PROXY_PORT 2345  // 数据库监听的端口
#define SLOT_LiSTEN_PORT 12000  // 本地时间片切换时，需要知道时间片切换，收消息的套接字
#define BUFSIZE 512 // 套接字缓存大小

#endif