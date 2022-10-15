/***************************************************************
*   文件名称：db_wr.c
*   描    述：用于向Redis数据库进行读写操作 
***************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "db_wr.h"
#include "topo.h"
#include "global.h"

RET_RESULT redis_connect(redisContext **context, char* redis_ip)
{
    if(*context)
        redisFree(*context);
	*context = redisConnect(redis_ip, REDIS_SERVER_PORT);
    
    if((*context)->err)
    {
        printf("%d connect redis server failure:%s\n", __LINE__, (*context)->errstr);
        redisFree(*context);
        return FAILURE;
    }
	// printf("connect redis server success\n");
	return SUCCESS;
}

/**************************************
函数名:exeRedisIntCmd
函数功能:执行redis 返回值为int类型命令
输入参数:cmd  redis命令
输出参数:
返回值:RET_RESULT
*************************************/
RET_RESULT exeRedisIntCmd(char *cmd, char *redis_ip)
{
    redisContext *context = NULL;
    redisReply *reply = NULL;
    RET_RESULT ret = redis_connect(&context, redis_ip);
    // usleep(3000);

    /*检查入参*/
    if (NULL == cmd)
    {
        printf("NULL pointer");
        return FAILURE;
    }

    /*连接redis*/

    while(ret == FAILURE)
    {
        context = NULL;
        sleep(1);
        ret = redis_connect(&context, redis_ip); 
    }

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

RET_RESULT Set_Active_Ctrl(uint32_t sw, uint32_t ctrl, int slot, char* redis_ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset active_ctrl_%02d %u %u",
             slot, sw, ctrl);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("set active_ctrl_%02d sw:%u, ctrl:%u failure\n", slot, sw, ctrl);
        return FAILURE;
    }
    printf("set active_ctrl_%02d sw:%u, ctrl:%u success\n", slot, sw, ctrl);
    return SUCCESS;
}

RET_RESULT Set_Standby_Ctrl(uint32_t sw, uint32_t ctrl, int slot, char* redis_ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset standby_ctrl_%02d %u %u",
             slot, sw, ctrl);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("set standby_ctrl_%02d sw:%u, ctrl:%u failure\n", slot, sw, ctrl);
        return FAILURE;
    }
    printf("set standby_ctrl_%02d sw:%u, ctrl:%u success\n", slot, sw, ctrl);
    return SUCCESS;
}

RET_RESULT Add_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sadd sw_set_%02d_%02d %u",
             ctrl, slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("add sw_set_ctrl%02d_%02d sw:%u failure\n", ctrl, slot, sw);
        return FAILURE;
    }
    printf("add sw_set_ctrl%02d_%02d sw:%u success\n", ctrl, slot, sw);
    return SUCCESS;
}

RET_RESULT Del_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "srem sw_set_%02d_%02d %u",
             ctrl, slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("del sw_set_ctrl%02d_%02d sw:%u failure\n", ctrl, slot, sw);
        return FAILURE;
    }
    printf("del sw_set_ctrl%02d_%02d sw:%u success\n", ctrl, slot, sw);
    return SUCCESS;
}

RET_RESULT Set_Ctrl_Conn_Db(uint32_t ctrl, uint32_t db, int slot, char* redis_ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset db_%02d %u %u",
             slot, ctrl, db);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("set db_%02d ctrl:%u, db:%u failure\n", slot, ctrl, db);
        return FAILURE;
    }
    printf("set db_%02d ctrl:%u, db:%u success\n", slot, ctrl, db);
    return SUCCESS;
}

RET_RESULT Set_Topo(uint32_t sw1, uint32_t sw2, uint64_t delay, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset dfl_topo_%02d %lu %lu",
             slot, sw, delay);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("set topo_%02d link:sw%u<->sw%u, delay:%lu us failure\n", slot, sw1, sw2, delay);
        return FAILURE;
    }
    printf("set topo_%02d link:sw%u<->sw%u, delay:%lu us success\n", slot, sw1, sw2, delay);

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sadd dfl_set_%02d %lu",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("add dfl_set_%02d link:sw%u<->sw%u failure\n", slot, sw1, sw2);
        return FAILURE;
    }
    printf("add dfl_set_%02d link:sw%u<->sw%u success\n", slot, sw1, sw2);
    return SUCCESS;
}

RET_RESULT Add_Real_Topo(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    uint64_t delay = Get_Link_Delay(sw1+1000, sw2+1000, slot, redis_ip);
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset real_topo_%02d %lu %lu",
             slot, sw, delay);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("add real_topo_%02d link:sw%u<->sw%u, delay:%lu us failure\n", slot, sw1, sw2, delay);
        return FAILURE;
    }
    printf("add real_topo_%02d link:sw%u<->sw%u, delay:%lu us success\n", slot, sw1, sw2, delay);

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sadd real_set_%02d %lu",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("add real_set_%02d link:sw%u<->sw%u failure\n", slot, sw1, sw2);
        return FAILURE;
    }
    printf("add real_set_%02d link:sw%u<->sw%u success\n", slot, sw1, sw2);
    return SUCCESS;
}

RET_RESULT Del_Real_Topo(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hdel real_topo_%02d %lu",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("del real_topo_%02d link:sw%u<->sw%u failure\n", slot, sw1, sw2);
        return FAILURE;
    }
    printf("del real_topo_%02d link:sw%u<->sw%u success\n", slot, sw1, sw2);

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "srem real_set_%02d %lu",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("del real_set_%02d link:sw%u<->sw%u failure\n", slot, sw1, sw2);
        return FAILURE;
    }
    printf("del real_set_%02d link:sw%u<->sw%u success\n", slot, sw1, sw2);
    return SUCCESS;
}

RET_RESULT Set_Dfl_Route(char *ip_src, char *ip_dst, char *out_sw_port, int slot, char* redis_ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "rpush dflrt_%s%s_%02d %s",
             ip_src, ip_dst, slot, out_sw_port);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("set default_route_%02d ip_src:%s, ip_dst:%s, out_sw:%s failure\n", slot, ip_src, ip_dst, out_sw_port);
        return FAILURE;
    }
    printf("set default_route_%02d ip_src:%s, ip_dst:%s, out_sw:%s success\n", slot, ip_src, ip_dst, out_sw_port);
    return SUCCESS;
}

RET_RESULT Set_Cal_Route(char *ip_src, char *ip_dst, char *out_sw_port, char* redis_ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};
    
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "del calrt_%s%s",
             ip_src, ip_dst);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("del calculate_route ip_src:%s, ip_dst:%s failure\n", ip_src, ip_dst);
        return FAILURE;
    }
    printf("del calculate_route ip_src:%s, ip_dst:%s success\n", ip_src, ip_dst);
    
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "rpush calrt_%s%s %s",
             ip_src, ip_dst, out_sw_port);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("set calculate_route ip_src:%s, ip_dst:%s, out_sw:%s failure\n", ip_src, ip_dst, out_sw_port);
        return FAILURE;
    }
    printf("set calculate_route ip_src:%s, ip_dst:%s, out_sw:%s success\n", ip_src, ip_dst, out_sw_port);
    return SUCCESS;
}

RET_RESULT Set_Cal_Fail_Route(char *ip_src, char *ip_dst, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "rpush failrt_%s%s 1",
             ip_src, ip_dst);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("set calculate_failed_route ip_src:%s, ip_dst:%s, goto table2 failure\n", ip_src, ip_dst);
        return FAILURE;
    }
    printf("set calculate_failed_route ip_src:%s, ip_dst:%s, goto table2 success\n", ip_src, ip_dst);
    return SUCCESS;
}

RET_RESULT Set_Del_Link(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sadd del_link_%02d %lu",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("add del_link_%02d link:sw%u<->sw%u failure\n", slot, sw1, sw2);
        return FAILURE;
    }
    printf("add del_link_%02d link:sw%u<->sw%u success\n", slot, sw1, sw2);
    return SUCCESS;
}

RET_RESULT Set_Fail_Link(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "del fail_link_%02d",
             (slot-1+SLOT_NUM)%SLOT_NUM);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("del fail_link_%02d failure\n", (slot-1+SLOT_NUM)%SLOT_NUM);
        return FAILURE;
    }
    printf("del fail_link_%02d success\n", (slot-1+SLOT_NUM)%SLOT_NUM);

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "rpush fail_link_%02d %lu",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("set fail_link_%02d link:sw%u<->sw%u failure\n", slot, sw1, sw2);
        return FAILURE;
    }
    printf("set fail_link_%02d link:sw%u<->sw%u success\n", slot, sw1, sw2);
    return SUCCESS;
}

RET_RESULT Add_Rt_Set(uint32_t sw1, uint32_t sw2, char *ip_src, char *ip_dst, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sadd rt_set_%02d_%02d %s%s",
             sw1, sw2, ip_src, ip_dst);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("add rt_set_sw%02d_sw%02d rt:%s<->%s failure\n", sw1, sw2, ip_src, ip_dst);
        return FAILURE;
    }
    printf("add rt_set_sw%02d_sw%02d rt:%s<->%s success\n", sw1, sw2, ip_src, ip_dst);
    return SUCCESS;
}

RET_RESULT Del_Rt_Set(int slot, char *ip_src, char *ip_dst, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;
    uint32_t sw1, sw2;
    int i = 0;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "lrange calrt_%s%s 0 -1",
             ip_src, ip_dst);

    /*连接redis*/
    context = redisConnect(redis_ip, REDIS_SERVER_PORT);
    if (context->err)
    {
        redisFree(context);
        printf("Error: %s\n", context->errstr);
        return -1;
    }
    printf("connect redis server success\n");

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (reply == NULL)
    {
        printf("execute command:%s failure\n", cmd);
        redisFree(context);
        return -1;
    }

    // 输出查询结果
    printf("\tentry num = %lu\n",reply->elements);
    if(reply->elements == 0) return -1;
    for(i = 0; i < reply->elements; i++)
    {
        printf("\tout_sw_port: %s\n",reply->element[i]->str);
        sw1 = atoi(reply->element[i]->str)/1000;
        sw2 = atoi(reply->element[i]->str)%1000;

        /*组装redis命令*/
        snprintf(cmd, CMD_MAX_LENGHT, "srem rt_set_%02d_%02d %s%s",
                sw1, sw2, ip_src, ip_dst);
        // for(int i=0;cmd[i]!='\0';i++)
        //  printf("%c",cmd[i]);
        // printf("\n");

        /*执行redis命令*/
        if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
        {
            printf("del rt_set_sw%02d_sw%02d rt:%s<->%s failure\n", sw1, sw2, ip_src, ip_dst);
            return FAILURE;
        }
        printf("del rt_set_sw%02d_sw%02d rt:%s<->%s success\n", sw1, sw2, ip_src, ip_dst);

        /*组装redis命令*/
        snprintf(cmd, CMD_MAX_LENGHT, "srem rt_set_t_%02d_%02d_%02d %s%s",
                sw1, sw2, slot, ip_src, ip_dst);
        // for(int i=0;cmd[i]!='\0';i++)
        //  printf("%c",cmd[i]);
        // printf("\n");

        /*执行redis命令*/
        if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
        {
            printf("del rt_set_t_%02d_sw%02d_sw%02d rt:%s<->%s failure\n", slot, sw1, sw2, ip_src, ip_dst);
            return FAILURE;
        }
        printf("del rt_set_t_%02d_sw%02d_sw%02d rt:%s<->%s success\n", slot, sw1, sw2, ip_src, ip_dst);

    }

    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

RET_RESULT Add_Rt_Set_Time(uint32_t sw1, uint32_t sw2, int slot, char *ip_src, char *ip_dst, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "del rt_set_t_%02d_%02d_%02d",
             sw1, sw2, (slot-1+SLOT_NUM)%SLOT_NUM);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("del rt_set_t_%02d_%02d_%02d failure\n", sw1, sw2, (slot-1+SLOT_NUM)%SLOT_NUM);
        return FAILURE;
    }
    printf("del rt_set_t_%02d_%02d_%02d success\n", sw1, sw2, (slot-1+SLOT_NUM)%SLOT_NUM);
    
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sadd rt_set_t_%02d_%02d_%02d %s%s",
             sw1, sw2, slot, ip_src, ip_dst);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("add rt_set_t_%02d_sw%02d_sw%02d rt:%s<->%s failure\n", slot, sw1, sw2, ip_src, ip_dst);
        return FAILURE;
    }
    printf("add rt_set_t_%02d_sw%02d_sw%02d rt:%s<->%s success\n", slot, sw1, sw2, ip_src, ip_dst);
    return SUCCESS;
}

RET_RESULT Mov_Rt_Set(uint32_t sw1, uint32_t sw2, int slot, char *ip_src, char *ip_dst, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "smove rt_set_%02d_%02d rt_set_t_%02d_%02d_%02d %s%s", 
             sw1, sw2, sw1, sw2, slot, ip_src, ip_dst);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("move to rt_set_t_%02d from rt_set_sw%02d_sw%02d rt:%s<->%s failure\n", slot, sw1, sw2, ip_src, ip_dst);
        return FAILURE;
    }
    printf("move to rt_set_t_%02d from rt_set_sw%02d_sw%02d rt:%s<->%s success\n", slot, sw1, sw2, ip_src, ip_dst);
    return SUCCESS;
}

RET_RESULT Diff_Topo(int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;
    uint64_t sw = 0;
    uint32_t sw1, sw2 = 0;
    int i = 0;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sdiff dfl_set_%02d real_set_%02d", slot, slot);

    /*连接redis*/
    context = redisConnect(redis_ip, REDIS_SERVER_PORT);
    if (context->err)
    {
        redisFree(context);
        printf("Error: %s\n", context->errstr);
        return FAILURE;
    }
    printf("connect redis server success\n");

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (reply == NULL)
    {
        printf("execute command:%s failure\n", cmd);
        redisFree(context);
        return FAILURE;
    }

    // 输出查询结果
    printf("\tfail_link num = %lu\n",reply->elements);
    if(reply->elements == 0) return FAILURE;
    for(i = 0; i < reply->elements; i++)
    {
        sw = atol(reply->element[i]->str);
        sw1 = (uint32_t)((sw & 0xffffffff00000000) >> 32);
        sw2 = (uint32_t)(sw & 0x00000000ffffffff);
        Set_Fail_Link(sw1, sw2, slot, redis_ip);
    }

    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

/****************************************************************************************************/

uint32_t Get_Active_Ctrl(uint32_t sw, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t ret = -1;
    redisContext *context=NULL;
    redisReply *reply=NULL;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hget active_ctrl_%02d %u",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    if(reply->str == NULL)
    {
        printf("return NULL\n");
        return ret;
    }
    printf("active_ctrl_%02d sw:%u, ctrl:%s\n", slot, sw, reply->str);
    ret = atoi(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}

uint32_t Get_Standby_Ctrl(uint32_t sw, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t ret = -1;
    redisContext *context=NULL;
    redisReply *reply=NULL;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hget standby_ctrl_%02d %u",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    if(reply->str == NULL)
    {
        printf("return NULL\n");
        return ret;
    }
    printf("standby_ctrl_%02d sw:%u, ctrl:%s\n", slot, sw, reply->str);
    ret = atoi(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}

RET_RESULT Lookup_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sismember sw_set_%02d_%02d %u",
             ctrl, slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    //  printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    //输出查询结果
    if(reply->str == NULL)
    {
        printf("return NULL\n");
        return FAILURE;
    }
    else if(atoi(reply->str) == 1)
    {
        printf("sw:%u exists in sw_set_ctrl%02d_%02d\n", sw, ctrl, slot);
        freeReplyObject(reply);
        redisFree(context);
        return SUCCESS;
    }
    else
    {
        printf("sw:%u don't exists in sw_set_ctrl%02d_%02d\n", sw, ctrl, slot);
        freeReplyObject(reply);
        redisFree(context);
        return FAILURE;
    }
}

uint32_t Get_Ctrl_Conn_Db(uint32_t ctrl, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t ret = -1;
    redisContext *context=NULL;
    redisReply *reply=NULL;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hget db_%02d %u",
             slot, ctrl);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    if(reply->str == NULL)
    {
        printf("return NULL\n");
        return ret;
    }
    printf("db_%02d ctrl:%u, db:%s\n", slot, ctrl, reply->str);
    ret = atoi(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}

RET_RESULT Get_Topo(int slot, char* redis_ip, tp_sw sw_list[SW_NUM])
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;

    uint32_t sw_dpid=0;
    uint32_t sw_dpid_adj=0;
    uint32_t port1=0, port2=0;
    uint64_t sw=0, delay=0;

    int i;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hgetall dfl_topo_%02d", slot);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    //输出查询结果
    // printf("%d,%lu\n",reply->type,reply->elements);
    // printf("element num = %lu\n",reply->elements);
    for(i = 0; i < reply->elements; i++)
    {
        if(i % 2 ==0)// port
        {
            printf("link %s delay: ",reply->element[i]->str);
            sw = atol(reply->element[i]->str);
            // c_log_debug("port = %lu", port);
            
            sw_dpid = (uint32_t)((sw & 0xffffffff00000000) >> 32);
            // c_log_debug("sw1 = %x", sw1);
            sw_dpid_adj = (uint32_t)(sw & 0x00000000ffffffff);
            // c_log_debug("sw1 = %x", sw2);
            port1 = sw_dpid_adj;
            // c_log_debug("port1 = %u", port1);
            port2 = sw_dpid;
            // c_log_debug("port2 = %u", port2);
        }
        else// delay
        {
            printf("%s us\n",reply->element[i]->str);
            delay = atol(reply->element[i]->str);
            tp_add_link(sw_dpid, port1, sw_dpid_adj, port2, delay, sw_list);
        }
    }

    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

RET_RESULT Get_Real_Topo(int slot, char* redis_ip, tp_sw sw_list[SW_NUM])
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;

    uint32_t sw_dpid=0;
    uint32_t sw_dpid_adj=0;
    uint32_t port1=0, port2=0;
    uint64_t sw=0, delay=0;

    int i;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hgetall real_topo_%02d", slot);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    //输出查询结果
    // printf("%d,%lu\n",reply->type,reply->elements);
    // printf("element num = %lu\n",reply->elements);
    for(i = 0; i < reply->elements; i++)
    {
        if(i % 2 ==0)// port
        {
            printf("real link %s delay: ",reply->element[i]->str);
            sw = atol(reply->element[i]->str);
            // c_log_debug("port = %lu", port);
            
            sw_dpid = (uint32_t)((sw & 0xffffffff00000000) >> 32);
            // c_log_debug("sw1 = %x", sw1);
            sw_dpid_adj = (uint32_t)(sw & 0x00000000ffffffff);
            // c_log_debug("sw1 = %x", sw2);
            port1 = sw_dpid_adj;
            // c_log_debug("port1 = %u", port1);
            port2 = sw_dpid;
            // c_log_debug("port2 = %u", port2);
        }
        else// delay
        {
            printf("%s us\n",reply->element[i]->str);
            delay = atol(reply->element[i]->str);
            tp_add_link(sw_dpid, port1, sw_dpid_adj, port2, delay, sw_list);
        }
    }

    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

RET_RESULT Lookup_Del_Link(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    redisContext *context=NULL;
    redisReply *reply=NULL;

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sismember del_link_%02d %lu",
             slot, sw);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    //输出查询结果
    if(reply->str == NULL)
    {
        printf("return NULL\n");
        return FAILURE;
    }
    else if(atoi(reply->str) == 1)
    {
        printf("link:sw%02d<->sw%02d exists in del_link%02d\n", sw1, sw2, slot);
        freeReplyObject(reply);
        redisFree(context);
        return SUCCESS;
    }
    else
    {
        printf("link:sw%02d<->sw%02d don't exists in sdel_link%02d\n", sw1, sw2, slot);
        freeReplyObject(reply);
        redisFree(context);
        return FAILURE;
    }
}

uint64_t Get_Link_Delay(uint32_t port1, uint32_t port2, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t ret = -1;
    redisContext *context=NULL;
    redisReply *reply=NULL;

    uint64_t port = (((uint64_t)port1) << 32) + port2;
    /*组装redis命令*/
    printf("getting topo_%02d link:sw%u<->sw%u\n", slot, port1-1000, port2-1000);
    snprintf(cmd, CMD_MAX_LENGHT, "hget dfl_topo_%02d %lu",
             slot, port);
    // for(int i=0;cmd[i]!='\0';i++)
    // 	printf("%c",cmd[i]);
    // printf("\n");

    /*连接redis*/
    if(redis_connect(&context, redis_ip)==FAILURE)
    {
        printf("redis_connect failure\n");
    }else{
        printf("redis_connect success\n");
    }

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    if(reply->str == NULL)
    {
        printf("return NULL\n");
        return ret;
    }
    printf("got topo_%02d link:sw%u<->sw%u, delay:%s us success\n", slot, port1-1000, port2-1000, reply->str);
    ret = atol(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}

/**********************************************************************************************************************/

// RET_RESULT Set_Link_Delay(uint32_t port1, uint32_t port2, uint64_t delay)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint64_t port = (((uint64_t)port1) << 32) + port2;
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hset link_delay %lu %lu",
//              port, delay);
//     // for(int i=0;cmd[i]!='\0';i++)
//     //  printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd))
//     {
//         printf("set link:%lx, delay:%lu us failure\n", port, delay);
//         return FAILURE;
//     }
//     printf("set link:%lx, delay:%lu us success\n", port, delay);
//     return SUCCESS;
// }

// RET_RESULT Clr_Link_Delay(uint32_t port1, uint32_t port2)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint64_t port = (((uint64_t)port1) << 32) + port2;

//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hdel link_delay %lu",
//              port);
//     // for(int i=0;cmd[i]!='\0';i++)
//     //  printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd))
//     {
//         printf("clear link:%lx failure\n", port);
//         return FAILURE;
//     }
//     printf("clear link:%lx success\n", port);
//     return SUCCESS;
// }

// RET_RESULT Set_Pc_Sw_Port(uint32_t ip, uint32_t port)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hset pc %u %u",
//              ip, port);
//     // for(int i=0;cmd[i]!='\0';i++)
//     //  printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd))
//     {
//         printf("set pc:%x, port:%x failure\n", ip, port);
//         return FAILURE;
//     }
//     printf("set pc:%x, port:%x success\n", ip, port);
//     return SUCCESS;
// }

// RET_RESULT Set_Sw_Delay(uint16_t cid, uint8_t sid, uint64_t delay)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint32_t id = (((uint32_t)cid) << 16) + (((uint16_t)sid) << 8);
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hset sw %u %lu",
//              id, delay);
//     // for(int i=0;cmd[i]!='\0';i++)
//     // 	printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd))
//     {
//         printf("set sw:%x, delay:%lu us failure\n", id, delay);
//         return FAILURE;
//     }
//     printf("set sw:%x, delay:%lu us success\n", id, delay);
//     return SUCCESS;
// }

// RET_RESULT Clr_Sw_Delay(uint16_t cid, uint8_t sid)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint32_t id = (((uint32_t)cid) << 16) + (((uint16_t)sid) << 8);

//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hdel sw %u",
//              id);
//     // for(int i=0;cmd[i]!='\0';i++)
//     //  printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd))
//     {
//         printf("clear sw:%x delay failure\n", id);
//         return FAILURE;
//     }
//     printf("clear sw:%x delay success\n", id);
//     return SUCCESS;
// }

// RET_RESULT Set_Route(uint32_t ip_src, uint32_t ip_dst, uint32_t out_sw_port)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint64_t ip = (((uint64_t)ip_src) << 32) + ip_dst;
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "lpush %lu %u",
//              ip, out_sw_port);
//     // for(int i=0;cmd[i]!='\0';i++)
//     // 	printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd))
//     {
//         printf("set route ip_src:%x, ip_dst:%x, out_sw_port:%x failure\n", ip_src, ip_dst, out_sw_port);
//         return FAILURE;
//     }
//     printf("set route ip_src:%x, ip_dst:%x, out_sw_port:%x success\n", ip_src, ip_dst, out_sw_port);
//     return SUCCESS;
// }

// RET_RESULT Clr_Route(uint32_t ip_src, uint32_t ip_dst)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint64_t ip = (((uint64_t)ip_src) << 32) + ip_dst;
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "ltrim %lu 1 0",
//              ip);
//     // for(int i=0;cmd[i]!='\0';i++)
//     // 	printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd))
//     {
//         printf("clear route ip_src:%x, ip_dst:%x failure\n", ip_src, ip_dst);
//         return FAILURE;
//     }
//     printf("clear route ip_src:%x, ip_dst:%x success\n", ip_src, ip_dst);
//     return SUCCESS;
// }

// uint16_t Get_Ctrl_Id(uint32_t ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint16_t ret = -1;
//     redisContext *context=NULL;
//     redisReply *reply=NULL;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hget ctrl %u", ip);
//     // for(int i=0;cmd[i]!='\0';i++)
//     // 	printf("%c",cmd[i]);
//     // printf("\n");

//     /*连接redis*/
//     context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
//     if (context->err)
//     {
//         redisFree(context);
//         printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
//         return ret;
//     }
//     printf("connect redis server success\n");

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return ret;
//     }

//     //输出查询结果
//     if(reply->str == NULL)
//     {
//         printf("return NULL\n");
//         return ret;
//     }
//     printf("ctrl id:%s\n", reply->str);
//     ret = atoi(reply->str);
//     freeReplyObject(reply);
//     redisFree(context);
//     return ret;
// }

// uint64_t Get_Link_Delay(uint32_t port1, uint32_t port2)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint64_t ret = -1;
//     uint64_t port = (((uint64_t)port1) << 32) + port2;
//     redisContext *context=NULL;
//     redisReply *reply=NULL;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hget link_delay %lu", port);
//     // for(int i=0;cmd[i]!='\0';i++)
//     // 	printf("%c",cmd[i]);
//     // printf("\n");

//     /*连接redis*/
//     context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
//     if (context->err)
//     {
//         redisFree(context);
//         printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
//         return ret;
//     }
//     printf("connect redis server success\n");

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return ret;
//     }

//     //输出查询结果
//     if(reply->str == NULL)
//     {
//         printf("return NULL\n");
//         return ret;
//     }
//     printf("link delay:%s us\n", reply->str);
//     ret = atol(reply->str);
//     freeReplyObject(reply);
//     redisFree(context);
//     return ret;
// }

// uint32_t Get_Pc_Sw_Port(uint32_t ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint32_t ret = -1;
//     redisContext *context=NULL;
//     redisReply *reply=NULL;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hget pc %u", ip);
//     // for(int i=0;cmd[i]!='\0';i++)
//     // 	printf("%c",cmd[i]);
//     // printf("\n");

//     /*连接redis*/
//     context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
//     if (context->err)
//     {
//         redisFree(context);
//         printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
//         return ret;
//     }
//     printf("connect redis server success\n");

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return ret;
//     }

//     //输出查询结果
//     if(reply->str == NULL)
//     {
//         printf("return NULL\n");
//         return ret;
//     }
//     printf("pc sw_port:%s\n", reply->str);
//     ret = atoi(reply->str);
//     freeReplyObject(reply);
//     redisFree(context);
//     return ret;
// }

// uint64_t Get_Sw_Delay(uint16_t cid, uint8_t sid)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint16_t ret = -1;
//     uint32_t id = (((uint32_t)cid) << 16) + (((uint16_t)sid) << 8);
//     redisContext *context=NULL;
//     redisReply *reply=NULL;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hget sw %u", id);
//     // for(int i=0;cmd[i]!='\0';i++)
//     // 	printf("%c",cmd[i]);
//     // printf("\n");

//     /*连接redis*/
//     context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
//     if (context->err)
//     {
//         redisFree(context);
//         printf("%d connect redis server failure:%s\n", __LINE__, context->errstr);
//         return ret;
//     }
//     printf("connect redis server success\n");

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return ret;
//     }

//     //输出查询结果
//     if(reply->str == NULL)
//     {
//         printf("return NULL\n");
//         return ret;
//     }
//     printf("sw delay:%s us\n", reply->str);
//     ret = atol(reply->str);
//     freeReplyObject(reply);
//     redisFree(context);
//     return ret;
// }

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
// 	   printf("ctrl_id=%hx,link_delay=%lx,pc_sw_port=%x,sw_delay=%lx\n",
//             ctrl_id,link_delay,pc_sw_port,sw_delay);
//     return 0;
// }
