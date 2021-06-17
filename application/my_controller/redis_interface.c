#include "redis_interface.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mul_common.h"

DB_RESULT redis_connect(redisContext **context)
{
	if(*context)redisFree(context);
	*context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
    if ((*context)->err)
    {
        redisFree(context);
        printf("%d connect redis server failure:%s\n", __LINE__, (*context)->errstr);
        return FAILURE;
    }

	return SUCCESS;
}

DB_RESULT redis_disconnect(redisContext *context)
{
	if(context)redisFree(context);
	context = NULL;
	return SUCCESS;
}

DB_RESULT exeRedisIntCmd_wr(char *cmd)
{
	redisContext *context = NULL;
    redisReply *reply;

	if(!redis_connect(&context))return FAILURE;
    /*检查入参*/
    if (NULL == cmd)
    {
        printf("NULL pointer\n");
		goto fail;
    }

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
		goto fail;
    }

    freeReplyObject(reply);
	redis_disconnect(context);
    //printf("%d execute command:%s success\n", __LINE__, cmd);
    return SUCCESS;

fail:
	redis_disconnect(context);
    return FAILURE;
}

redisReply * exeRedisIntCmd_rd(char *cmd)
{
	redisContext *context = NULL;
	redisReply *reply;
	if(!redis_connect(&context))return NULL;
    /*检查入参*/
    if (NULL == cmd)
    {
        printf("NULL pointer");
		goto fail;
    }

    /*执行redis命令*/
    reply = (redisReply *)redisCommand(context, cmd);
    if (NULL == reply)
    {
        printf("%d execute command:%s failure\n", __LINE__, cmd);
		goto fail;
    }

	return reply;

fail:
	redis_disconnect(context);
    return NULL;
}

DB_RESULT exeRedisIntCmd_rd_One(char *cmd, void * ret, uint8_t len)
{
	redisReply *reply = exeRedisIntCmd_rd(cmd);
    if (!reply || !reply->str)return FAILURE;

	switch (len)
	{
	case sizeof(uint32_t):
		*(uint32_t*)ret = atoi(reply->str);
		break;
	case sizeof(uint64_t):
		*(uint64_t*)ret = atol(reply->str);
		break;
	default:
		return FAILURE;
		break;
	}
	freeReplyObject(reply);

	return SUCCESS;
}

DB_RESULT redis_Get_Ctrl_Id(uint32_t ip, uint32_t *cid)
{
	char cmd[CMD_MAX_LENGHT] = {0};

    snprintf(cmd, CMD_MAX_LENGHT, "hget ctrl %u", ip);
    if(!exeRedisIntCmd_rd_One(cmd, (void*)cid, sizeof(uint32_t)))return FAILURE;

    return SUCCESS;
}

DB_RESULT redis_Set_Link_Delay(uint32_t sw1, uint32_t sw2, uint64_t delay)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)sw1) << 32) + sw2;
	
	snprintf(cmd, CMD_MAX_LENGHT, "hset link_delay %lu %lu", redis_key, delay);	
    return exeRedisIntCmd_wr(cmd);
}

DB_RESULT redis_Get_Link_Delay(uint32_t sw1, uint32_t sw2, uint64_t *delay)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)sw1) << 32) + sw2;
	// c_log_debug("redis_key: %lx", redis_key);

	snprintf(cmd, CMD_MAX_LENGHT, "hget link_delay %lu", redis_key);
    if(!exeRedisIntCmd_rd_One(cmd, (void*)delay, sizeof(uint64_t)))return FAILURE;
	
    return SUCCESS;
}

DB_RESULT redis_Set_Link_Port(uint32_t sw1, uint32_t port1, uint32_t sw2, uint32_t port2)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)sw1) << 32) + sw2;
	int ret = 0;
	// c_log_debug("redis_key: %lx", redis_key);

    snprintf(cmd, CMD_MAX_LENGHT, "hset link_port_h %lu %u", redis_key, port1);
	ret &= exeRedisIntCmd_wr(cmd);
	memset(cmd, 0, CMD_MAX_LENGHT);
	snprintf(cmd, CMD_MAX_LENGHT, "hset link_port_n %lu %u", redis_key, port2);
    return ret & exeRedisIntCmd_wr(cmd);
}

DB_RESULT redis_Get_Link_Port(uint32_t sw1, uint32_t *port1, uint32_t sw2, uint32_t *port2)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)sw1) << 32) + sw2;
	// c_log_debug("redis_key: %lx", redis_key);

    snprintf(cmd, CMD_MAX_LENGHT, "hget link_port_h %lu", redis_key);
	if(!exeRedisIntCmd_rd_One(cmd, (void*)port1, sizeof(uint32_t)))return FAILURE;

	memset(cmd, 0, CMD_MAX_LENGHT);
	snprintf(cmd, CMD_MAX_LENGHT, "hget link_port_n %lu", redis_key);
	if(!exeRedisIntCmd_rd_One(cmd, (void*)port2, sizeof(uint32_t)))return FAILURE;

    return SUCCESS;
}

DB_RESULT redis_Set_Pc_Sw_Port(uint32_t ip, uint32_t sw, uint32_t port)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	int ret = 0;

	snprintf(cmd, CMD_MAX_LENGHT, "hset pc_sw %u %u", ip, sw);
	ret &= exeRedisIntCmd_wr(cmd);
	memset(cmd, 0, CMD_MAX_LENGHT);
	snprintf(cmd, CMD_MAX_LENGHT, "hset pc_port %u %u", ip, port);
    return ret&exeRedisIntCmd_wr(cmd);;
}

DB_RESULT redis_Get_Pc_Sw_Port(uint32_t ip, uint32_t *sw, uint32_t *port)
{
	char cmd[CMD_MAX_LENGHT] = {0};

	snprintf(cmd, CMD_MAX_LENGHT, "hget pc_sw %u", ip);
    if(!exeRedisIntCmd_rd_One(cmd, (void*)sw, sizeof(uint32_t)))return FAILURE;

	memset(cmd, 0, CMD_MAX_LENGHT);
	snprintf(cmd, CMD_MAX_LENGHT, "hget pc_port %u", ip);
	if(!exeRedisIntCmd_rd_One(cmd, (void*)port, sizeof(uint32_t)))return FAILURE;

	return SUCCESS;
}

DB_RESULT redis_Get_Pc_MAC(uint32_t ip, uint8_t *mac)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t maci = 0;
	int i;

	snprintf(cmd, CMD_MAX_LENGHT, "hget pc_mac %u", ip);
	if(!exeRedisIntCmd_rd_One(cmd, (void*)&maci, sizeof(uint64_t)))return FAILURE;
	// c_log_debug("maci:%lx", maci);

	for(i=5; i>=0; i--)
	{
		mac[i] = 0x00000000000000ff&maci;
		maci = (maci>>8) & 0x00ffffffffffffff;
	}

	return SUCCESS;
}

DB_RESULT redis_Set_Pc_MAC(uint32_t ip, uint8_t *mac)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t maci = 0;
	int i;

	for(i = 0; i<5; i++)
	{
		maci += mac[i];
		maci = (maci << 8) & 0xffffffffffffff00;
	}
	maci += mac[5];

	snprintf(cmd, CMD_MAX_LENGHT, "hset pc_mac %u %lu", ip, maci);

    return exeRedisIntCmd_wr(cmd);
}

DB_RESULT redis_Set_Sw_Delay(uint32_t sw, uint64_t delay)
{
	char cmd[CMD_MAX_LENGHT] = {0};

	// set the PC information
    snprintf(cmd, CMD_MAX_LENGHT, "hset sw %u %lu", sw, delay);

    return exeRedisIntCmd_wr(cmd);
}

DB_RESULT redis_Get_Sw_Delay(uint32_t sw, uint64_t *delay)
{
	char cmd[CMD_MAX_LENGHT] = {0};

    snprintf(cmd, CMD_MAX_LENGHT, "hget sw %u", sw);
    if(!exeRedisIntCmd_rd_One(cmd, (void*)delay, sizeof(uint64_t)))return FAILURE;

	return SUCCESS;
}

DB_RESULT redis_Set_Route_Path(uint32_t nw_src, uint32_t nw_dst, uint64_t *path, uint8_t len)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)nw_src) << 32) + nw_dst;
	int i;

	if(redis_Is_Route_Path(nw_src, nw_dst))
	{
		snprintf(cmd, CMD_MAX_LENGHT, "del %lu", redis_key);
		if(!exeRedisIntCmd_wr(cmd))return FAILURE;
		memset(cmd, 0, CMD_MAX_LENGHT);
	}

	for(i = 0; i<len; i++)
	{
		snprintf(cmd, CMD_MAX_LENGHT, "rpush %lu %lu", redis_key, path[i]);
		if(!exeRedisIntCmd_wr(cmd))return FAILURE;
		memset(cmd, 0, CMD_MAX_LENGHT);
	}

	return SUCCESS;
}

DB_RESULT redis_Get_Route_Path(uint32_t nw_src, uint32_t nw_dst, uint64_t **path, uint32_t *len)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	redisContext *context = NULL;
	redisReply *reply;
	uint64_t redis_key = (((uint64_t)nw_src) << 32) + nw_dst;
	int i;

	if(!redis_Is_Route_Path(nw_src, nw_dst))return FAILURE;
	
	snprintf(cmd, CMD_MAX_LENGHT, "llen %lu", redis_key);
	reply = exeRedisIntCmd_rd(cmd);
	if(NULL == reply || !reply->integer)return FAILURE;
	*len = reply->integer;
	// c_log_debug("path len: %u", *len);
	
	memset(cmd, 0, CMD_MAX_LENGHT);
	(*path) = malloc(*len * sizeof(uint64_t));
	if(!redis_connect(&context))return FAILURE;

	for(i = 0; i<*len; i++)
	{
		snprintf(cmd, CMD_MAX_LENGHT, "lindex %lu %d", redis_key, i);
		reply = (redisReply *)redisCommand(context, cmd);
		if (NULL == reply)
		{
			printf("%d execute command:%s failure\n", __LINE__, cmd);
			return !redis_disconnect(context);//disconnect is always success
		}
		if(!reply->str)return !redis_disconnect(context);
		(*path)[i] = atol(reply->str);
		// c_log_debug("path: %u", *len);
		freeReplyObject(reply);
		memset(cmd, 0, CMD_MAX_LENGHT);
	}

	redis_disconnect(context);
	return SUCCESS;
}

DB_RESULT redis_Is_Route_Path(uint32_t nw_src, uint32_t nw_dst)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	redisReply *reply;
	uint64_t redis_key = (((uint64_t)nw_src) << 32) + nw_dst;

	snprintf(cmd, CMD_MAX_LENGHT, "exists %lu", redis_key);
    reply = exeRedisIntCmd_rd(cmd);
    if (NULL == reply)return FAILURE;
	if(reply->integer == 1L)
	{
		freeReplyObject(reply);
		return SUCCESS;
	}
	freeReplyObject(reply);
	return FAILURE;
}

DB_RESULT redis_Set_Sw2PC_Port(uint32_t sw_port, uint32_t ip)
{
	char cmd[CMD_MAX_LENGHT] = {0};

    snprintf(cmd, CMD_MAX_LENGHT, "hset sw2pc_port %u %u", sw_port, ip);
    return exeRedisIntCmd_wr(cmd);
}

DB_RESULT redis_Del_Sw2PC_Port(uint32_t sw_port)
{
	char cmd[CMD_MAX_LENGHT] = {0};

    snprintf(cmd, CMD_MAX_LENGHT, "hdel sw2pc_port %u", sw_port);
    return exeRedisIntCmd_wr(cmd);
}
