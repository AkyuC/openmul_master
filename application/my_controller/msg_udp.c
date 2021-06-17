#include "msg_udp.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "tp_graph.h"

int server_fd = -1;

int msg_send(uint32_t server_addr, uint8_t *msg, uint32_t len)
{
    int client_fd, ret;
    struct sockaddr_in ser_addr, cli_addr;

    client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_fd < 0)
    {
        printf("create socket fail!\n");
        return 0;
    }
    memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = inet_addr("172.17.0.2"); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
    cli_addr.sin_port = htons(CLIENT_PORT);  //端口号，需要网络序转换

    ret = bind(client_fd, (struct sockaddr*)&cli_addr, sizeof(cli_addr));
    if(ret < 0)
    {
        printf("socket bind fail!\n");
        return 0;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    //ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    ser_addr.sin_addr.s_addr = server_addr;  //注意网络序转换
    ser_addr.sin_port = htons(SERVER_PORT);  //注意网络序转换

    // char buf[UDP_BUFF_LEN] = "TEST UDP MSG!\n";
    ret = sendto(client_fd, msg, len, 0, (struct sockaddr*)&ser_addr, sizeof(ser_addr));

    close(client_fd);
    return ret;
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

    ret = select(fd + 1, &fdSet, NULL, NULL, &waitTime);   
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

//*************************** RW Function *****************************/
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

int msg_udp_init(void)
{
    int ret;
    struct sockaddr_in ser_addr;

    server_fd = socket(AF_INET, SOCK_DGRAM, 0); //AF_INET:IPV4;SOCK_DGRAM:UDP
    if(server_fd < 0)
    {
        printf("create socket fail!\n");
        return 0;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr("172.17.0.2"); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
    ser_addr.sin_port = htons(SERVER_PORT);  //端口号，需要网络序转换

    ret = bind(server_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr));
    if(ret < 0)
    {
        printf("socket bind fail!\n");
        return 0;
    }
    return 1;
}

void msg_udp_close(void)
{
    close(server_fd);
    server_fd = -1;
}

int msg_udp_listen(uint8_t *buf)
{
    // char buf[UDP_BUFF_LEN];  //接收缓冲区，1024字节
    // socklen_t len;
    struct sockaddr_in clent_addr;  //clent_addr用于记录发送方的地址信息
    memset(buf, 0, UDP_BUFF_LEN);
    // len = sizeof(clent_addr);
    // count = recvfrom(fd, buf, UDP_BUFF_LEN, 0, (struct sockaddr*)&clent_addr, &len);  //recvfrom是拥塞函数，没有数据就一直拥塞
    // sendto(fd, buf, UDP_BUFF_LEN, 0, (struct sockaddr*)&clent_addr, len);  //发送信息给client，注意使用了clent_addr结构体指针
    if(server_fd<0)return 0;
    return udpServer_waitData_timeout(server_fd, &clent_addr, (char*)buf, UDP_BUFF_LEN, 1, 0);
}
