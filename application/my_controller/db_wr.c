/***************************************************************
*   文件名称：db_wr.c
*   描    述：用于向Redis数据库进行读写操作 
***************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "db_wr.h"

/**************************************
函数名:exeRedisIntCmd
函数功能:执行redis 返回值为int类型命令
输入参数:cmd  redis命令
输出参数:
返回值:DB_RESULT
*************************************/
DB_RESULT exeRedisIntCmd(char *cmd)
{
    redisContext *context;
    redisReply *reply;

    /*检查入参*/
    if (NULL == cmd)
    {
        printf("NULL pointer");
        return FAILURE;
    }
    /*连接redis*/
    context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
    if (context->err)
    {
        redisFree(context);
        printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
        return FAILURE;
    }
    printf("connect redis server success\n");

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    freeReplyObject(reply);
    redisFree(context);
    printf("%d execute command:%s success\n", __LINE__, cmd);
    return SUCCESS;
}

DB_RESULT Set_Link_Delay(uint32_t port1, uint32_t port2, uint64_t delay)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t port = (((uint64_t)port1) << 32) + port2;
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset link_delay %lu %lu",
             port, delay);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd))
    {
        printf("set link:%lx, delay:%lx failure\n", port, delay);
        return FAILURE;
    }
    printf("set link:%lx, delay:%lx success\n", port, delay);
    return SUCCESS;
}

DB_RESULT Set_Pc_Sw_Port(uint32_t ip, uint32_t port)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset pc %u %u",
             ip, port);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd))
    {
        printf("set pc:%x, port:%x failure\n", ip, port);
        return FAILURE;
    }
    printf("set pc:%x, port:%x success\n", ip, port);
    return SUCCESS;
}

DB_RESULT Set_Sw_Delay(uint16_t cid, uint8_t sid, uint64_t delay)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t id = (((uint32_t)cid) << 16) + (((uint16_t)sid) << 8);
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset sw %u %lu",
             id, delay);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd))
    {
        printf("set sw:%x, delay:%lx failure\n", id, delay);
        return FAILURE;
    }
    printf("set sw:%x, delay:%lx success\n", id, delay);
    return SUCCESS;
}

uint16_t Get_Ctrl_Id(uint32_t ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint16_t ret = -1;
    redisContext *context;
    redisReply *reply;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hget ctrl %u", ip);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
    if (context->err)
    {
        redisFree(context);
        printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
        return ret;
    }
    printf("connect redis server success\n");

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    printf("ctrl id:%s\n", reply->str);
    ret = atoi(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}
uint64_t Get_Link_Delay(uint32_t port1, uint32_t port2)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t ret = -1;
    uint64_t port = (((uint64_t)port1) << 32) + port2;
    redisContext *context;
    redisReply *reply;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hget link_delay %lu", port);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
    if (context->err)
    {
        redisFree(context);
        printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
        return ret;
    }
    printf("connect redis server success\n");

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    printf("link delay:%s\n", reply->str);
    ret = atoi(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}

uint32_t Get_Pc_Sw_Port(uint32_t ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t ret = -1;
    redisContext *context;
    redisReply *reply;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hget pc %u", ip);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
    if (context->err)
    {
        redisFree(context);
        printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
        return ret;
    }
    printf("connect redis server success\n");

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    printf("pc sw_port:%s\n", reply->str);
    ret = atoi(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}

uint64_t Get_Sw_Delay(uint16_t cid, uint8_t sid)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint16_t ret = -1;
    uint32_t id = (((uint32_t)cid) << 16) + (((uint16_t)sid) << 8);
    redisContext *context;
    redisReply *reply;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hget sw %u", id);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
    if (context->err)
    {
        redisFree(context);
        printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
        return ret;
    }
    printf("connect redis server success\n");

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    printf("sw delay:%s\n", reply->str);
    ret = atoi(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}

// int main(int argc,char *argv[])
// {
//     Set_Link_Delay(1, 2, 500);
//     Set_Pc_Sw_Port(10216, 7777); 
//     Set_Sw_Delay(3, 9, 50);    

//     uint16_t ctrl_id = Get_Ctrl_Id(10215);
//     uint64_t link_delay = Get_Link_Delay(1, 2);
//     uint32_t pc_sw_port = Get_Pc_Sw_Port(10216);
//     uint64_t sw_delay = Get_Sw_Delay(3, 9);

//     printf("ctrl_id=%hu,link_delay=%lu,pc_sw_port=%u,sw_delay=%lu\n",
//             ctrl_id,link_delay,pc_sw_port,sw_delay);
// 	printf("ctrl_id=%hx,link_delay=%lx,pc_sw_port=%x,sw_delay=%lx\n",
//             ctrl_id,link_delay,pc_sw_port,sw_delay);
//     return 0;
// }
