#include <stdio.h>
#include <string.h>
#include  <stdlib.h>
#include "global.h"

unsigned char CONTROLLER_IP[IP_ARRAY_LEN] = {'\0'};   //控制器ip
unsigned char REDIS_SREVER_IP[IP_ARRAY_LEN] = {'\0'}; //所属的分布式数据库ip
unsigned int CTRL_ID;                                 //控制器的区域ID
unsigned int MASTER_CONTROLLER;                       //是否为主控制器

//从配置文件中读取配置，初始化加载配置，即第一个时间片的配置
RESULT global_init(void)
{
    char buf[100] = {'\0'}, *tmp;
    int i = 0, j = 0;
    const char filename[] = "conf.txt";

    FILE *fp = fopen(filename, "r");
    if(fp ==  NULL)return FAILURE;

    //从配置文件中获取是否是主控制器
    if(fgets(buf, 100, fp) == NULL)return FAILURE;
    while (buf[i++] != '=');
    if(buf[i] == '1')
    {
        MASTER_CONTROLLER = 1;
    }else
    {
        MASTER_CONTROLLER = 0;
    }
    memset((void*)buf, 0, 100);

    //从配置文件当中获取控制器的ID
    if(fgets(buf, 100, fp) == NULL)return FAILURE;
    while (buf[i++] != 'x');
    buf[i+4] = 0;//清除行末的换行符\r
    buf[i+5] = 0;//清除行末的换行符\n
    CTRL_ID = (unsigned int)strtol((char*)buf, &tmp, 16);
    memset((void*)buf, 0, 100);

    //从配置文件当中获取控制器的本地ip地址
    if(fgets(buf, 100, fp) == NULL)return FAILURE;
    while (buf[i++] != '=');
    j = 0;
    while(buf[i] != '\r' || buf[i] != '\n')
    {
        CONTROLLER_IP[j++] = buf[i++];
    }
    memset((void*)buf, 0, 100);

    //从配置文件当中获取控制器的所属分布式数据库的ip地址
    if(fgets(buf, 100, fp) == NULL)return FAILURE;
    while (buf[i++] != '=');
    j = 0;
    while(buf[i] != '\r' || buf[i] != '\n')
    {
        REDIS_SREVER_IP[j++] = buf[i++];
    }

    fclose(fp);
    return SUCCESS;
}

RESULT global_change_timeslot(void)
{
    return SUCCESS;
}