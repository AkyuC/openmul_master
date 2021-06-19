#include "redis_interface.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mul_common.h"

DB_RESULT redis_connect(redisContext **context)
{
	if(*context)redisFree(*context);
	*context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
    if ((*context)->err)
    {
        redisFree(*context);
        printf("%d connect redis server failure:%s\n", __LINE__, (*context)->errstr);
        return FAILURE;
    }
	// printf("connect redis server success\n");
	return SUCCESS;
}

DB_RESULT redis_disconnect(redisContext **context)
{
	if(*context)redisFree(*context);
	*context = NULL;
	// printf("disconnect redis server success\n");
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
	redis_disconnect(&context);
    //printf("%d execute command:%s success\n", __LINE__, cmd);
    return SUCCESS;

fail:
	redis_disconnect(&context);
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

	redis_disconnect(&context);
	return reply;

fail:
	redis_disconnect(&context);
    return NULL;
}

DB_RESULT exeRedisIntCmd_rd_One(char *cmd, void * ret, uint8_t len)
{
	char * tmp;
	redisReply *reply = exeRedisIntCmd_rd(cmd);
    if (!reply || !reply->str)return FAILURE;

	switch (len)
	{
	case sizeof(uint32_t):
		*(uint32_t*)ret = (uint32_t)strtol(reply->str, &tmp, 16);
		break;
	case sizeof(uint64_t):
		*(uint64_t*)ret = (uint64_t)strtol(reply->str, &tmp, 16);
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

    snprintf(cmd, CMD_MAX_LENGHT, "hget ctrl %x", ip);
    if(!exeRedisIntCmd_rd_One(cmd, (void*)cid, sizeof(uint32_t)))return FAILURE;
	printf("read from redis success -> get controller:%x cid:%x\n", ip, *cid);
    return SUCCESS;
}

DB_RESULT redis_Set_Link_Delay(uint32_t sw1, uint32_t sw2, uint64_t delay)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)sw1) << 32) + sw2;
	
	snprintf(cmd, CMD_MAX_LENGHT, "hset link_delay %lx %lx", redis_key, delay);	
	if(exeRedisIntCmd_wr(cmd))
	{
		printf("write into redis success -> set link:sw%x-sw%x delay:%lu us\n", sw1, sw2, delay);
		return SUCCESS;
	}
	printf("write into redis fail -> set link:sw%x-sw%x delay:%lu us\n", sw1, sw2, delay);
    return FAILURE;
}

DB_RESULT redis_Get_Link_Delay(uint32_t sw1, uint32_t sw2, uint64_t *delay)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)sw1) << 32) + sw2;
	// c_log_debug("redis_key: %lx", redis_key);

	snprintf(cmd, CMD_MAX_LENGHT, "hget link_delay %lx", redis_key);
    if(!exeRedisIntCmd_rd_One(cmd, (void*)delay, sizeof(uint64_t)))return FAILURE;
	
    return SUCCESS;
}

DB_RESULT redis_Set_Link_Port(uint32_t sw1, uint32_t port1, uint32_t sw2, uint32_t port2)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)sw1) << 32) + sw2;
	int ret = 0;
	// c_log_debug("redis_key: %lx", redis_key);

    snprintf(cmd, CMD_MAX_LENGHT, "hset link_port_h %lx %x", redis_key, port1);
	if(exeRedisIntCmd_wr(cmd))
	{
		printf("write into redis success -> set link:sw%x-sw%x port1:%u\n", sw1, sw2, port1);
		ret &= SUCCESS;
	}
	else
	{
		printf("write into redis fail -> set link:sw%x-sw%x port1:%u\n", sw1, sw2, port1);
		ret &= FAILURE;
	}
	
	memset(cmd, 0, CMD_MAX_LENGHT);
	snprintf(cmd, CMD_MAX_LENGHT, "hset link_port_n %lx %x", redis_key, port2);
	if(exeRedisIntCmd_wr(cmd))
	{
		printf("write into redis success -> set link:sw%x-sw%x port2:%u\n", sw1, sw2, port2);
		return ret & SUCCESS;
	}
	printf("write into redis fail -> set link:sw%x-sw%x port2:%u\n", sw1, sw2, port2);
    return ret & FAILURE;
}

DB_RESULT redis_Get_Link_Port(uint32_t sw1, uint32_t *port1, uint32_t sw2, uint32_t *port2)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t redis_key = (((uint64_t)sw1) << 32) + sw2;
	// c_log_debug("redis_key: %lx", redis_key);

    snprintf(cmd, CMD_MAX_LENGHT, "hget link_port_h %lx", redis_key);
	if(!exeRedisIntCmd_rd_One(cmd, (void*)port1, sizeof(uint32_t)))return FAILURE;

	memset(cmd, 0, CMD_MAX_LENGHT);
	snprintf(cmd, CMD_MAX_LENGHT, "hget link_port_n %lx", redis_key);
	if(!exeRedisIntCmd_rd_One(cmd, (void*)port2, sizeof(uint32_t)))return FAILURE;

    return SUCCESS;
}

DB_RESULT redis_Set_Pc_Sw_Port(uint32_t ip, uint32_t sw, uint32_t port)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	int ret = 0;

	snprintf(cmd, CMD_MAX_LENGHT, "hset pc_sw %x %x", ip, sw);
	if(exeRedisIntCmd_wr(cmd))
	{
		printf("write into redis success -> set pc:%x sw:%x\n", ip, sw);
		ret &= SUCCESS;
	}
	else
	{
		printf("write into redis fail -> set pc:%x sw:%x\n", ip, sw);
		ret &= FAILURE;
	}	
	
	memset(cmd, 0, CMD_MAX_LENGHT);
	snprintf(cmd, CMD_MAX_LENGHT, "hset pc_port %x %x", ip, port);
	if(exeRedisIntCmd_wr(cmd))
	{
		printf("write into redis success -> set pc:%x port:%x\n", ip, port);
		return ret & SUCCESS;
	}
	printf("write into redis fail -> set pc:%x port:%x\n", ip, port);
    return ret & FAILURE;
}

DB_RESULT redis_Get_Pc_Sw_Port(uint32_t ip, uint32_t *sw, uint32_t *port)
{
	char cmd[CMD_MAX_LENGHT] = {0};

	snprintf(cmd, CMD_MAX_LENGHT, "hget pc_sw %x", ip);
    if(!exeRedisIntCmd_rd_One(cmd, (void*)sw, sizeof(uint32_t)))return FAILURE;

	memset(cmd, 0, CMD_MAX_LENGHT);
	snprintf(cmd, CMD_MAX_LENGHT, "hget pc_port %x", ip);
	if(!exeRedisIntCmd_rd_One(cmd, (void*)port, sizeof(uint32_t)))return FAILURE;

	return SUCCESS;
}

DB_RESULT redis_Get_Pc_MAC(uint32_t ip, uint8_t *mac)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	uint64_t maci = 0;
	int i;

	snprintf(cmd, CMD_MAX_LENGHT, "hget pc_mac %x", ip);
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

	snprintf(cmd, CMD_MAX_LENGHT, "hset pc_mac %x %lx", ip, maci);
	if(exeRedisIntCmd_wr(cmd))
	{
		printf("write into redis success -> set pc:%x mac:%lx\n", ip, maci);
		return SUCCESS;
	}
	printf("write into redis fail -> set pc:%x mac:%lx\n", ip, maci);
    return FAILURE;
}

DB_RESULT redis_Set_Sw_Delay(uint32_t sw, uint64_t delay)
{
	char cmd[CMD_MAX_LENGHT] = {0};

	// set the PC information
    snprintf(cmd, CMD_MAX_LENGHT, "hset sw %x %lx", sw, delay);
	if(exeRedisIntCmd_wr(cmd))
	{
		printf("write into redis success -> set link:sw%x-controller delay:%lx us\n", sw, delay);
		return SUCCESS;
	}
	printf("write into redis fail -> set link:sw%x-controller delay:%lx us\n", sw, delay);
    return FAILURE;
}

DB_RESULT redis_Get_Sw_Delay(uint32_t sw, uint64_t *delay)
{
	char cmd[CMD_MAX_LENGHT] = {0};

    snprintf(cmd, CMD_MAX_LENGHT, "hget sw %x", sw);
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
		snprintf(cmd, CMD_MAX_LENGHT, "del %lx", redis_key);
		if(!exeRedisIntCmd_wr(cmd))
		{
			printf("update redis fail -> del route ip_src:%x ip_dst:%x\n", nw_src, nw_dst);
			return FAILURE;
		}
		printf("update redis success -> del route ip_src:%x ip_dst:%x\n", nw_src, nw_dst);
		memset(cmd, 0, CMD_MAX_LENGHT);
	}

	for(i = 0; i<len; i++)
	{
		snprintf(cmd, CMD_MAX_LENGHT, "rpush %lx %lx", redis_key, path[i]);
		if(!exeRedisIntCmd_wr(cmd))
		{
			printf("write into redis fail -> set route ip_src:%x ip_dst:%x out_sw_port:%lx\n", nw_src, nw_dst, path[i]);
			return FAILURE;
		}
		printf("write into redis success -> set route ip_src:%x ip_dst:%x out_sw_port:%lx\n", nw_src, nw_dst, path[i]);
		memset(cmd, 0, CMD_MAX_LENGHT);
	}

	return SUCCESS;
}

DB_RESULT redis_Get_Route_Path(uint32_t nw_src, uint32_t nw_dst, uint64_t **path, uint32_t *len)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	redisContext *context = NULL;
	redisReply *reply;
	char * tmp;
	uint64_t redis_key = (((uint64_t)nw_src) << 32) + nw_dst;
	int i;

	if(!redis_Is_Route_Path(nw_src, nw_dst))return FAILURE;
	
	snprintf(cmd, CMD_MAX_LENGHT, "llen %lx", redis_key);
	reply = exeRedisIntCmd_rd(cmd);
	if(NULL == reply || !reply->integer)return FAILURE;
	*len = reply->integer;
	// c_log_debug("path len: %u", *len);
	
	memset(cmd, 0, CMD_MAX_LENGHT);
	(*path) = malloc(*len * sizeof(uint64_t));
	freeReplyObject(reply);
	if(!redis_connect(&context))return FAILURE;

	for(i = 0; i<*len; i++)
	{
		snprintf(cmd, CMD_MAX_LENGHT, "lindex %lx %d", redis_key, i);
		reply = (redisReply *)redisCommand(context, cmd);
		if (NULL == reply)
		{
			printf("%d execute command:%s failure\n", __LINE__, cmd);
			return !redis_disconnect(&context);//disconnect is always success
		}
		if(!reply->str)return !redis_disconnect(&context);
		(*path)[i] = (uint64_t)strtol(reply->str, &tmp, 16);
		printf("read from redis success -> get route ip_src:%x ip_dst:%x out_sw_port:%lx\n", nw_src, nw_dst, (*path)[i]);
		// c_log_debug("path: %u", *len);
		freeReplyObject(reply);
		memset(cmd, 0, CMD_MAX_LENGHT);
	}

	redis_disconnect(&context);
	return SUCCESS;
}

DB_RESULT redis_Is_Route_Path(uint32_t nw_src, uint32_t nw_dst)
{
	char cmd[CMD_MAX_LENGHT] = {0};
	redisReply *reply;
	uint64_t redis_key = (((uint64_t)nw_src) << 32) + nw_dst;

	snprintf(cmd, CMD_MAX_LENGHT, "exists %lx", redis_key);
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

    snprintf(cmd, CMD_MAX_LENGHT, "hset sw2pc_port %x %x", sw_port, ip);
	if(exeRedisIntCmd_wr(cmd))
	{
		printf("write into redis success -> set sw_port:%x pc:%x\n", sw_port, ip);
		return SUCCESS;
	}
	printf("write into redis fail -> set sw_port:%x pc:%x\n", sw_port, ip);
    return FAILURE;
}

DB_RESULT redis_Del_Sw2PC_Port(uint32_t sw_port)
{
	char cmd[CMD_MAX_LENGHT] = {0};

    snprintf(cmd, CMD_MAX_LENGHT, "hdel sw2pc_port %x", sw_port);
    return exeRedisIntCmd_wr(cmd);
}
