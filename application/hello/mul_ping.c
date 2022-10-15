#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdlib.h>
#include <pthread.h>

#define PING_PORT 4567
#define MUL_PING_PORT 4566
#define PING_UDP_BUFF_LEN 128

int ping_fd = -1;
char db_ip[16] = "192.168.68.";
int db_id = 0;
int is_ping = 0;

int msg_udp_init(void)
{
    int ret;
    struct sockaddr_in ser_addr;

    ping_fd = socket(AF_INET, SOCK_DGRAM, 0); //AF_INET:IPV4;SOCK_DGRAM:UDP
    if(ping_fd < 0)
    {
        printf("create socket fail!\n");
        return 0;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
    ser_addr.sin_port = htons(PING_PORT);  //端口号，需要网络序转换

    ret = bind(ping_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr));
    if(ret < 0)
    {
        printf("socket bind fail!\n");
        return 0;
    }
    return 1;
}

void msg_udp_close(void)
{
    close(ping_fd);
    ping_fd = -1;
}

int select_read(int fd, long sec, long usec)
{
    fd_set fdSet; 
    struct timeval waitTime; 
    int ret = 0; 

    FD_ZERO(&fdSet);    
    FD_SET(fd, &fdSet);      
    
    waitTime.tv_sec = sec;    
    waitTime.tv_usec = usec; 

    ret = select(fd + 1, &fdSet, NULL, NULL, NULL);   
    if(ret < 0)//error
    {
        return -1;
    }
    else if(ret == 0)//timeout
    {   
        return 0;   
    }
    else//readable
    {
        return 1;
    }
}

int udpServer_waitData(int fd, struct sockaddr_in *clent_addr, char* data, int dataLength)
{
    socklen_t len = sizeof(struct sockaddr_in);
    int ret = recvfrom(fd, data, dataLength, 0, (struct sockaddr*)clent_addr, &len);
    if(ret == -1)
    {
        return -1;
    }
    return ret;
}

int udpServer_waitData_timeout(int fd, struct sockaddr_in * clent_addr, char* data, int dataLength, long s, long us)
{
    int ret = select_read(fd, s, us);
    if(ret < 0)//error
    {
        return -1;
    }
    else if(ret == 0)//timeout
    {  
        return 0;   
    }
    else//readable
    {
        return udpServer_waitData(fd, clent_addr, data, dataLength); 
    }
}

int msg_udp_listen(char *buf)
{
    struct sockaddr_in clent_addr;  //clent_addr用于记录发送方的地址信息
    memset(buf, 0, PING_UDP_BUFF_LEN);
    if(ping_fd<0)return -1;
    return udpServer_waitData_timeout(ping_fd, &clent_addr, (char*)buf, PING_UDP_BUFF_LEN, 1, 0);
}

int msg_send(unsigned int server_addr, char *msg, unsigned int len)
{
    int client_fd, ret;
    struct sockaddr_in ser_addr;

    client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_fd < 0)
    {
        printf("create socket fail!\n");
        return 0;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    //ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    ser_addr.sin_addr.s_addr = server_addr;  //注意网络序转换
    ser_addr.sin_port = htons(MUL_PING_PORT);  //注意网络序转换

    // char buf[UDP_BUFF_LEN] = "TEST UDP MSG!\n";
    ret = sendto(client_fd, msg, len, 0, (struct sockaddr*)&ser_addr, sizeof(ser_addr));

    close(client_fd);
    return ret;
}

void * mul_ping(void * arg)
{
    char command[PING_UDP_BUFF_LEN] = {'\0'};
    char buf[PING_UDP_BUFF_LEN] = {'\0'};

    while(1){
        sprintf(command, "ping -c 3 -W 5000 %s > /dev/null", db_ip);
        if(is_ping == 1 && system(command) != 0)
        {
            is_ping = 0;
            sprintf(buf, "%d", db_id);
            msg_send(inet_addr("127.0.0.1"), buf, strlen(buf));
        }
        sleep(5);
    }
    return NULL;
}

int main(void)
{
    char buf[PING_UDP_BUFF_LEN] = {'\0'};
    int ret;
    pthread_t pid;

    ret = pthread_create(&pid, NULL, mul_ping, NULL);

    if(msg_udp_init() == -1)return 1;
    while (1)
    {
        while(msg_udp_listen(buf) == -1);

        db_id = atoi(buf);

        sprintf(&db_ip[11], "%d", db_id+1);

        is_ping = 1;
    }
    
    return 0;
}