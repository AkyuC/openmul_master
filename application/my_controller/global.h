#ifndef GLOBAL_H
#define GLOBAL_H

#ifndef IP_ARRAY_LEN
#define IP_ARRAY_LEN 16
#endif

extern unsigned char CONTROLLER_IP[IP_ARRAY_LEN];   //控制器ip
extern unsigned char REDIS_SREVER_IP[IP_ARRAY_LEN]; //所属的分布式数据库ip
extern unsigned int CTRL_ID;                        //控制器的区域ID
extern unsigned int MASTER_CONTROLLER;              //是否为主控制器

typedef enum RESULT
{
    SUCCESS = 1,
    FAILURE = 0
} RESULT;

/**
 * 从配置文件中读取配置，初始化加载配置，即第一个时间片的配置
 * 返回是否成功读写，SUCCESS为成功，FAILURE为失败
*/
RESULT global_init(void);

/**
 * 时间片切换时，区域和是否为上层控制器的重新设置
 * 返回是否成功，SUCCESS为成功，FAILURE为失败
*/
RESULT global_change_timeslot(void);
#endif