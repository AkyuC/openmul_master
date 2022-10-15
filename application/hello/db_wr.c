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
    struct timeval tv;
    tv.tv_sec = 5;

    if(*context)
        redisFree(*context);
	*context = redisConnectWithTimeout(redis_ip, REDIS_SERVER_PORT_W, tv);
    
    if((*context)->err)
    {
        printf("\t%d connect redis server failure:%s\n", __LINE__, (*context)->errstr);
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
        printf("\tNULL pointer");
        redisFree(context);
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
        // printf("%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    freeReplyObject(reply);
    redisFree(context);
    // printf("%d execute command:%s success\n", __LINE__, cmd);
    return SUCCESS;
}

// RET_RESULT Set_Active_Ctrl(uint32_t sw, uint32_t ctrl, int slot, char* redis_ip)
// {
// 	char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hset active_ctrl_%02d %u %u", slot, sw, ctrl);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tset active_ctrl_%02d sw:%u, ctrl:%u failure\n", slot, sw, ctrl);
//         return FAILURE;
//     }
//     printf("\tset active_ctrl_%02d sw:%u, ctrl:%u success\n", slot, sw, ctrl);
//     return SUCCESS;
// }

// RET_RESULT Set_Standby_Ctrl(uint32_t sw, uint32_t ctrl, int slot, char* redis_ip)
// {
// 	char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hset standby_ctrl_%02d %u %u", slot, sw, ctrl);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tset standby_ctrl_%02d sw:%u, ctrl:%u failure\n", slot, sw, ctrl);
//         return FAILURE;
//     }
//     printf("\tset standby_ctrl_%02d sw:%u, ctrl:%u success\n", slot, sw, ctrl);
//     return SUCCESS;
// }

// RET_RESULT Add_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "sadd sw_set_%02d_%02d %u",
//              ctrl, slot, sw);
//     // for(int i=0;cmd[i]!='\0';i++)
//     //  printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("add sw_set_ctrl%02d_%02d sw:%u failure\n", ctrl, slot, sw);
//         return FAILURE;
//     }
//     printf("add sw_set_ctrl%02d_%02d sw:%u success\n", ctrl, slot, sw);
//     return SUCCESS;
// }

// RET_RESULT Del_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "srem sw_set_%02d_%02d %u",
//              ctrl, slot, sw);
//     // for(int i=0;cmd[i]!='\0';i++)
//     //  printf("%c",cmd[i]);
//     // printf("\n");

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("del sw_set_ctrl%02d_%02d sw:%u failure\n", ctrl, slot, sw);
//         return FAILURE;
//     }
//     printf("del sw_set_ctrl%02d_%02d sw:%u success\n", ctrl, slot, sw);
//     return SUCCESS;
// }

// RET_RESULT Add_Conn_Ctrl(uint32_t sw, uint32_t ctrl, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hset conn_ctrl %u %u", sw, ctrl);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tadd conn_ctrl sw:%u, ctrl:%u failure\n", sw, ctrl);
//         return FAILURE;
//     }
//     printf("\tadd conn_ctrl sw:%u, ctrl:%u success\n", sw, ctrl);
//     return SUCCESS;
// }

// RET_RESULT Del_Conn_Ctrl(uint32_t sw, uint32_t ctrl, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hset conn_ctrl %u -1", sw);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tdel conn_ctrl sw:%u, ctrl:%u failure\n", sw, ctrl);
//         return FAILURE;
//     }
//     printf("\tdel conn_ctrl sw:%u, ctrl:%u success\n", sw, ctrl);
//     return SUCCESS;
// }

RET_RESULT Set_Ctrl_Conn_Db(uint32_t ctrl, uint32_t db, char* redis_ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset ctrl_conn_db %u %u", ctrl, db);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tset ctrl_conn_db ctrl:%u, db:%u failure\n", ctrl, db);
        return FAILURE;
    }
    printf("\tset ctrl_conn_db ctrl:%u, db:%u success\n", ctrl, db);
    return SUCCESS;
}

RET_RESULT Set_Topo(uint32_t sw1, uint32_t sw2, uint64_t delay, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset dfl_topo_%02d %lu %lu", slot, sw, delay);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tset topo_%02d link:sw%u<->sw%u, delay:%lu us failure\n", slot, sw1, sw2, delay);
        return FAILURE;
    }
    printf("\tset topo_%02d link:sw%u<->sw%u, delay:%lu us success\n", slot, sw1, sw2, delay);

    // /*组装redis命令*/
    // snprintf(cmd, CMD_MAX_LENGHT, "sadd dfl_set_%02d %lu", slot, sw);

    // /*执行redis命令*/
    // if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    // {
    //     printf("\tadd dfl_set_%02d link:sw%u<->sw%u failure\n", slot, sw1, sw2);
    //     return FAILURE;
    // }
    // printf("\tadd dfl_set_%02d link:sw%u<->sw%u success\n", slot, sw1, sw2);
    return SUCCESS;
}

RET_RESULT Add_Real_Topo(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    uint64_t delay = Get_Link_Delay(sw1, sw2, slot, redis_ip);
    // 如果没有查询到新增链路时延，初始化为常数
    if(delay == -1) delay = 1300;
    
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hset real_topo %lu %lu", sw, delay);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tadd real_topo link:sw%u<->sw%u, delay:%lu us failure\n", sw1, sw2, delay);
        return FAILURE;
    }
    printf("\tadd real_topo link:sw%u<->sw%u, delay:%lu us success\n", sw1, sw2, delay);

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sadd real_set %lu", sw);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tadd real_set link:sw%u<->sw%u failure\n", sw1, sw2);
        return FAILURE;
    }
    printf("\tadd real_set link:sw%u<->sw%u success\n", sw1, sw2);
    return SUCCESS;
}

RET_RESULT Del_Real_Topo(uint32_t sw1, uint32_t sw2, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hdel real_topo %lu", sw);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tdel real_topo link:sw%u<->sw%u failure\n", sw1, sw2);
        return FAILURE;
    }
    printf("\tdel real_topo link:sw%u<->sw%u success\n", sw1, sw2);

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "srem real_set %lu", sw);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tdel real_set link:sw%u<->sw%u failure\n", sw1, sw2);
        return FAILURE;
    }
    printf("\tdel real_set link:sw%u<->sw%u success\n", sw1, sw2);
    return SUCCESS;
}

RET_RESULT Set_Dfl_Route(char *ip_src, char *ip_dst, char *out_sw_port, int slot, char* redis_ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "rpush dflrt_%s%s_%02d %s", ip_src, ip_dst, slot, out_sw_port);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tset default_route_%02d ip_src:%s, ip_dst:%s, out_sw:%s failure\n", slot, ip_src, ip_dst, out_sw_port);
        return FAILURE;
    }
    printf("\tset default_route_%02d ip_src:%s, ip_dst:%s, out_sw:%s success\n", slot, ip_src, ip_dst, out_sw_port);
    return SUCCESS;
}

RET_RESULT Set_Cal_Route(char *ip_src, char *ip_dst, int num, char *out_sw_port, char* redis_ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};
    
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "del calrt_%s%s_%d", ip_src, ip_dst, num);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tdel calculate_route_%d ip_src:%s, ip_dst:%s failure\n", num, ip_src, ip_dst);
        return FAILURE;
    }
    printf("\tdel calculate_route_%d ip_src:%s, ip_dst:%s success\n", num, ip_src, ip_dst);
    
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "rpush calrt_%s%s_%d %s", ip_src, ip_dst, num, out_sw_port);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tset calculate_route_%d ip_src:%s, ip_dst:%s, out_sw:%s failure\n", num, ip_src, ip_dst, out_sw_port);
        return FAILURE;
    }
    printf("\tset calculate_route_%d ip_src:%s, ip_dst:%s, out_sw:%s success\n", num, ip_src, ip_dst, out_sw_port);
    return SUCCESS;
}

// RET_RESULT Set_Cal_Fail_Route(char *ip_src, char *ip_dst, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};

//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "rpush failrt_%s%s 1", ip_src, ip_dst);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tset calculate_failed_route ip_src:%s, ip_dst:%s, goto table2 failure\n", ip_src, ip_dst);
//         return FAILURE;
//     }
//     printf("\tset calculate_failed_route ip_src:%s, ip_dst:%s, goto table2 success\n", ip_src, ip_dst);
//     return SUCCESS;
// }

// RET_RESULT Set_Del_Link(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "sadd del_link_%02d %lu", slot, sw);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tadd del_link_%02d link:sw%u<->sw%u failure\n", slot, sw1, sw2);
//         return FAILURE;
//     }
//     printf("\tadd del_link_%02d link:sw%u<->sw%u success\n", slot, sw1, sw2);
//     return SUCCESS;
// }

RET_RESULT Set_Fail_Link(uint32_t sw1, uint32_t sw2, int db_id, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t sw = (((uint64_t)sw1) << 32) + sw2;
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "del fail_link_%02d_%02d", db_id, (slot-1+SLOT_NUM)%SLOT_NUM);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tdel fail_link_db%02d_%02d failure\n", db_id, (slot-1+SLOT_NUM)%SLOT_NUM);
        return FAILURE;
    }
    printf("\tdel fail_link_db%02d_%02d success\n", db_id, (slot-1+SLOT_NUM)%SLOT_NUM);

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "rpush fail_link_%02d_%02d %lu", db_id, slot, sw);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tset fail_link_%02d_%02d link:sw%u<->sw%u failure\n", db_id, slot, sw1, sw2);
        return FAILURE;
    }
    printf("\tset fail_link_%02d_%02d link:sw%u<->sw%u success\n", db_id, slot, sw1, sw2);
    return SUCCESS;
}

RET_RESULT Add_Rt_Set(uint32_t sw1, uint32_t sw2, char *ip_src, char *ip_dst, int num, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "sadd rt_set_%02d_%02d %s%s%d", sw1, sw2, ip_src, ip_dst, num);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tadd rt_set_sw%02d_sw%02d rt_num%d:%s<->%s failure\n", sw1, sw2, num, ip_src, ip_dst);
        return FAILURE;
    }
    printf("\tadd rt_set_sw%02d_sw%02d rt_num%d:%s<->%s success\n", sw1, sw2, num, ip_src, ip_dst);
    return SUCCESS;
}

RET_RESULT Del_Rt_Set(int slot, char *ip_src, char *ip_dst, int num, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;
    uint32_t sw1, sw2;
    int i = 0;
    struct timeval tv;
    tv.tv_sec = 5;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "lrange calrt_%s%s_%d 0 -1", ip_src, ip_dst, num);

    /*连接redis*/
    context = redisConnectWithTimeout(redis_ip, REDIS_SERVER_PORT_R, tv);
    if (context->err)
    {
        printf("\tError: %s\n", context->errstr);
        redisFree(context);
        return -1;
    }
    printf("\tconnect redis server success\n");

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (reply == NULL)
    {
        printf("\texecute command:%s failure\n", cmd);
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
        snprintf(cmd, CMD_MAX_LENGHT, "srem rt_set_%02d_%02d %s%s%d",
                sw1, sw2, ip_src, ip_dst, num);
        // for(int i=0;cmd[i]!='\0';i++)
        //  printf("%c",cmd[i]);
        // printf("\n");

        /*执行redis命令*/
        if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
        {
            printf("\t\tdel rt_set_sw%02d_sw%02d rt_num%d:%s<->%s failure\n", sw1, sw2, num, ip_src, ip_dst);
            return FAILURE;
        }
        printf("\t\tdel rt_set_sw%02d_sw%02d rt_num%d:%s<->%s success\n", sw1, sw2, num, ip_src, ip_dst);

        // /*组装redis命令*/
        // snprintf(cmd, CMD_MAX_LENGHT, "srem rt_set_t_%02d_%02d_%02d %s%s", sw1, sw2, slot, ip_src, ip_dst);

        // /*执行redis命令*/
        // if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
        // {
        //     printf("\t\tdel rt_set_t_%02d_sw%02d_sw%02d rt:%s<->%s failure\n", slot, sw1, sw2, ip_src, ip_dst);
        //     return FAILURE;
        // }
        // printf("\t\tdel rt_set_t_%02d_sw%02d_sw%02d rt:%s<->%s success\n", slot, sw1, sw2, ip_src, ip_dst);

    }

    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

// RET_RESULT Add_Rt_Set_Time(uint32_t sw1, uint32_t sw2, int slot, char *ip_src, char *ip_dst, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "del rt_set_t_%02d_%02d_%02d", sw1, sw2, (slot-1+SLOT_NUM)%SLOT_NUM);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tdel rt_set_t_%02d_%02d_%02d failure\n", sw1, sw2, (slot-1+SLOT_NUM)%SLOT_NUM);
//         return FAILURE;
//     }
//     printf("\tdel rt_set_t_%02d_%02d_%02d success\n", sw1, sw2, (slot-1+SLOT_NUM)%SLOT_NUM);
    
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "sadd rt_set_t_%02d_%02d_%02d %s%s", sw1, sw2, slot, ip_src, ip_dst);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tadd rt_set_t_%02d_sw%02d_sw%02d rt:%s<->%s failure\n", slot, sw1, sw2, ip_src, ip_dst);
//         return FAILURE;
//     }
//     printf("\tadd rt_set_t_%02d_sw%02d_sw%02d rt:%s<->%s success\n", slot, sw1, sw2, ip_src, ip_dst);
//     return SUCCESS;
// }

// RET_RESULT Mov_Rt_Set(uint32_t sw1, uint32_t sw2, int slot, char *ip_src, char *ip_dst, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "smove rt_set_%02d_%02d rt_set_t_%02d_%02d_%02d %s%s",  sw1, sw2, sw1, sw2, slot, ip_src, ip_dst);

//     /*执行redis命令*/
//     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
//     {
//         printf("\tmove to rt_set_t_%02d from rt_set_sw%02d_sw%02d rt:%s<->%s failure\n", slot, sw1, sw2, ip_src, ip_dst);
//         return FAILURE;
//     }
//     printf("\tmove to rt_set_t_%02d from rt_set_sw%02d_sw%02d rt:%s<->%s success\n", slot, sw1, sw2, ip_src, ip_dst);
//     return SUCCESS;
// }

// RET_RESULT Diff_Topo(int slot, int DB_ID, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     redisContext *context=NULL;
//     redisReply *reply=NULL;
//     uint64_t sw = 0;
//     uint32_t sw1, sw2 = 0;
//     int i = 0;
//     int ctrl_id = 0; // 记录控制器ID
//     int db_id = 0;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "sdiff dfl_set_%02d real_set_%02d", slot, slot);

//     /*连接redis*/
//     context = redisConnect(redis_ip, REDIS_SERVER_PORT_R);
//     if (context->err)
//     {
//         printf("\tError: %s\n", context->errstr);
//         redisFree(context);
//         return FAILURE;
//     }
//     printf("\tconnect redis server success\n");

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (reply == NULL)
//     {
//         printf("\texecute command:%s failure\n", cmd);
//         redisFree(context);
//         return FAILURE;
//     }

//     // 输出查询结果
//     printf("\tfail_link num = %lu\n",reply->elements);
//     if(reply->elements == 0) 
//     {
//         freeReplyObject(reply);
//         redisFree(context);
//         return FAILURE;
//     }
//     for(i = 0; i < reply->elements; i++)
//     {
//         sw = atol(reply->element[i]->str);
//         sw1 = (uint32_t)((sw & 0xffffffff00000000) >> 32);
//         sw2 = (uint32_t)(sw & 0x00000000ffffffff);

//         // 判断该fail_link属于本区域
//         // ctrl_id = Get_Active_Ctrl((uint32_t)sw1, slot, redis_ip);
//         // if(Lookup_Sw_Set((uint32_t)ctrl_id, (uint32_t)sw1, slot, redis_ip) == FAILURE)
//         // {
//         //     ctrl_id = Get_Standby_Ctrl((uint32_t)sw1, slot, redis_ip);
//         // }
//         ctrl_id = sw1;
//         db_id = Get_Ctrl_Conn_Db((uint32_t)ctrl_id, redis_ip);

//         if(db_id == DB_ID)
//             Set_Fail_Link(sw1, sw2, DB_ID, slot, redis_ip);
//     }

//     freeReplyObject(reply);
//     redisFree(context);
//     return SUCCESS;
// }

RET_RESULT Add_Wait_Exec(uint32_t ctrl, char *buf, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    redisContext *context=NULL;
    redisReply *reply=NULL;

    // /*组装redis命令*/
    // snprintf(cmd, CMD_MAX_LENGHT, "sismember wait_exec_%02d %s", ctrl, buf);

    // /*连接redis*/
    // redis_connect(&context, redis_ip);

    // /*执行redis命令*/
    // reply = (redisReply *)redisCommand(context, cmd);
    // if (NULL == reply)
    // {
    //     printf("\t%d execute command:%s failure\n", __LINE__, cmd);
    //     redisFree(context);
    //     return FAILURE;
    // }

    // //输出查询结果
    // if(reply->integer == 1)
    // {
    //     printf("\twait_exec_ctrl%02d buf:%s exist\n", ctrl, buf);
    //     freeReplyObject(reply);
    //     redisFree(context);
    //     return SUCCESS;
    // }
    // else
    // {
    //     /*组装redis命令*/
    //     snprintf(cmd, CMD_MAX_LENGHT, "sadd wait_exec_%02d %s", ctrl, buf);

    //     /*执行redis命令*/
    //     if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    //     {
    //         printf("\tadd wait_exec_ctrl%02d buf:%s failure\n", ctrl, buf);
    //         freeReplyObject(reply);
    //         redisFree(context);
    //         return FAILURE;
    //     }
    //     printf("\tadd wait_exec_ctrl%02d buf:%s success\n", ctrl, buf);
    //     freeReplyObject(reply);
    //     redisFree(context);
    //     return SUCCESS;
    // }

    /*组装redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "rpush wait_exec_%02d %s", ctrl, buf);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tadd wait_exec_ctrl%02d buf:%s failure\n", ctrl, buf);
        freeReplyObject(reply);
        redisFree(context);
        return FAILURE;
    }
    printf("\tadd wait_exec_ctrl%02d buf:%s success\n", ctrl, buf);
    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

RET_RESULT Del_Wait_Exec(uint32_t ctrl, char *buf, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    /*组装redis命令*/
    // snprintf(cmd, CMD_MAX_LENGHT, "srem wait_exec_%02d %s", ctrl, buf);
    snprintf(cmd, CMD_MAX_LENGHT, "lpop wait_exec_%02d", ctrl);

    /*执行redis命令*/
    if (FAILURE == exeRedisIntCmd(cmd, redis_ip))
    {
        printf("\tdel wait_exec_ctrl%02d buf:%s failure\n", ctrl, buf);
        return FAILURE;
    }
    printf("\tdel wait_exec_ctrl%02d buf:%s success\n", ctrl, buf);
    return SUCCESS;
}


/****************************************************************************************************/

// uint32_t Get_Active_Ctrl(uint32_t sw, int slot, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint32_t ret = -1;
//     redisContext *context=NULL;
//     redisReply *reply=NULL;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hget active_ctrl_%02d %u", slot, sw);

//     /*连接redis*/
//     redis_connect(&context, redis_ip);

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("\t%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return ret;
//     }

//     //输出查询结果
//     if(reply->str == NULL)
//     {
//         printf("\t%d Get_Active_Ctrl: failure\n", __LINE__);
//         freeReplyObject(reply);
//         redisFree(context);
//         return ret;
//     }
//     printf("\tactive_ctrl_%02d sw:%u, ctrl:%s\n", slot, sw, reply->str);
//     ret = atoi(reply->str);
//     freeReplyObject(reply);
//     redisFree(context);
//     return ret;
// }

// uint32_t Get_Standby_Ctrl(uint32_t sw, int slot, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint32_t ret = -1;
//     redisContext *context=NULL;
//     redisReply *reply=NULL;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hget standby_ctrl_%02d %u", slot, sw);

//     /*连接redis*/
//     redis_connect(&context, redis_ip);

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("\t%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return ret;
//     }

//     //输出查询结果
//     if(reply->str == NULL)
//     {
//         printf("\t%d Get_Standby_Ctrl: failure\n", __LINE__);
//         freeReplyObject(reply);
//         redisFree(context);
//         return ret;
//     }
//     printf("\tstandby_ctrl_%02d sw:%u, ctrl:%s\n", slot, sw, reply->str);
//     ret = atoi(reply->str);
//     freeReplyObject(reply);
//     redisFree(context);
//     return ret;
// }

// uint32_t Get_Conn_Ctrl(uint32_t sw, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     uint32_t ret = -1;
//     redisContext *context=NULL;
//     redisReply *reply=NULL;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "hget conn_ctrl %u", sw);

//     /*连接redis*/
//     redis_connect(&context, redis_ip);

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("\t%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return ret;
//     }

//     //输出查询结果
//     if(reply->str == NULL)
//     {
//         printf("\t%d Get_Conn_Ctrl: failure\n", __LINE__);
//         return ret;
//     }
//     printf("\tconn_ctrl sw:%u, ctrl:%s\n", sw, reply->str);
//     ret = atoi(reply->str);
//     freeReplyObject(reply);
//     redisFree(context);
//     return ret;
// }

// RET_RESULT Lookup_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     redisContext *context=NULL;
//     redisReply *reply=NULL;

//     /*组装redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "sismember sw_set_%02d_%02d %u",
//              ctrl, slot, sw);
//     // for(int i=0;cmd[i]!='\0';i++)
//     //  printf("%c",cmd[i]);
//     // printf("\n");

//     /*连接redis*/
//     redis_connect(&context, redis_ip);

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return FAILURE;
//     }

//     //输出查询结果
//     if(reply->integer == 1)
//     {
//         printf("sw:%u exists in sw_set_ctrl%02d_%02d\n", sw, ctrl, slot);
//         freeReplyObject(reply);
//         redisFree(context);
//         return SUCCESS;
//     }
//     else
//     {
//         printf("sw:%u don't exists in sw_set_ctrl%02d_%02d\n", sw, ctrl, slot);
//         freeReplyObject(reply);
//         redisFree(context);
//         return FAILURE;
//     }
// }

uint32_t Get_Ctrl_Conn_Db(uint32_t ctrl, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t ret = -1;
    redisContext *context=NULL;
    redisReply *reply=NULL;

    /*组装Redis命令*/
    snprintf(cmd, CMD_MAX_LENGHT, "hget ctrl_conn_db %u", ctrl);

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("\t%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    if(reply->str == NULL)
    {
        printf("\t%d Get_Ctrl_Conn_Db: fail\n", __LINE__);
        freeReplyObject(reply);
        redisFree(context);
        return ret;
    }
    printf("\tctrl_conn_db ctrl:%u, db:%s\n", ctrl, reply->str);
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

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("\t%d execute command:%s failure\n", __LINE__, cmd);
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
            // printf("\t\tlink %s delay: ",reply->element[i]->str);
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
            // printf("%s us\n",reply->element[i]->str);
            delay = atol(reply->element[i]->str);
            tp_add_link(sw_dpid, port1, sw_dpid_adj, port2, delay, sw_list);
        }
    }

    freeReplyObject(reply);
    redisFree(context);
    return SUCCESS;
}

RET_RESULT Get_Real_Topo(char* redis_ip, tp_sw sw_list[SW_NUM])
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
    snprintf(cmd, CMD_MAX_LENGHT, "hgetall real_topo");

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("\t%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    //输出查询结果
    printf("\tGet_Real_Topo:%d, element num = %lu\n",reply->type,reply->elements);
    // printf("element num = %lu\n",reply->elements);
    for(i = 0; i < reply->elements; i++)
    {
        if(i % 2 ==0)// port
        {
            sw = atol(reply->element[i]->str);
            // c_log_debug("port = %lu", port);
            // printf("real link %lx delay: ",sw);
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
            // printf("%s us\n",reply->element[i]->str);
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
    snprintf(cmd, CMD_MAX_LENGHT, "sismember del_link_%02d %lu", slot, sw);

    /*连接redis*/
    redis_connect(&context, redis_ip);

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("\t%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return FAILURE;
    }

    //输出查询结果
    if(reply->integer == 1)
    {
        printf("\tlink:sw%02d<->sw%02d exists in del_link%02d\n", sw1, sw2, slot);
        freeReplyObject(reply);
        redisFree(context);
        return SUCCESS;
    }
    else
    {
        printf("\tlink:sw%02d<->sw%02d don't exists in del_link%02d\n", sw1, sw2, slot);
        freeReplyObject(reply);
        redisFree(context);
        return FAILURE;
    }
}

uint64_t Get_Link_Delay(uint32_t sw1, uint32_t sw2, int slot, char* redis_ip)
{
    char cmd[CMD_MAX_LENGHT] = {0};
    uint64_t ret = -1;
    redisContext *context=NULL;
    redisReply *reply=NULL;

    uint64_t port = (((uint64_t)sw1) << 32) + sw2;
    /*组装redis命令*/
    printf("\tgetting topo_%02d link:sw%u<->sw%u\n", slot, sw1, sw2);
    snprintf(cmd, CMD_MAX_LENGHT, "hget dfl_topo_%02d %lu", slot, port);

    /*连接redis*/
    if(redis_connect(&context, redis_ip)==FAILURE)
    {
        printf("\tredis_connect failure\n");
    }else{
        printf("\tredis_connect success\n");
    }

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("\t%d execute command:%s failure\n", __LINE__, cmd);
        redisFree(context);
        return ret;
    }

    //输出查询结果
    if(reply->str == NULL)
    {
        printf("\t%d Get_Link_Delay: get link delay fail\n", __LINE__);
        freeReplyObject(reply);
        redisFree(context);
        return ret;
    }
    printf("\tgot topo_%02d link:sw%u<->sw%u, delay:%s us success\n", slot, sw1, sw2, reply->str);
    ret = atol(reply->str);
    freeReplyObject(reply);
    redisFree(context);
    return ret;
}

// RET_RESULT Get_Wait_Exec(uint32_t ctrl, char *buf, char* redis_ip)
// {
//     char cmd[CMD_MAX_LENGHT] = {0};
//     redisContext *context=NULL;
//     redisReply *reply=NULL;
//     int i = 0;

//     /*组装Redis命令*/
//     snprintf(cmd, CMD_MAX_LENGHT, "smembers wait_exec_%02d", ctrl);

//     /*连接redis*/
//     redis_connect(&context, redis_ip);

//     /*执行redis命令*/
//     reply = (redisReply *)redisCommand(context, cmd);
//     if (NULL == reply)
//     {
//         printf("\t%d execute command:%s failure\n", __LINE__, cmd);
//         redisFree(context);
//         return FAILURE;
//     }

//     //输出查询结果
//     // printf("%d,%lu\n",reply->type,reply->elements);
//     // printf("element num = %lu\n",reply->elements);
//     for(i = 0; i < reply->elements; i++)
//     {
//         buf = reply->element[i]->str;
//         // 根据buf进行数据处理，流表下发
        
//         // 流表成功下发后，从集合中删除相应元素
//         Del_Wait_Exec(ctrl, buf, redis_ip);
//     }

//     freeReplyObject(reply);
//     redisFree(context);
//     return SUCCESS;
// }

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
