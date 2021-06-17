#ifndef __MUL_MSG_UDP_H__
#define __MUL_MSG_UDP_H__
#include <netinet/in.h>

#define SERVER_PORT 23451
#define CLIENT_PORT 23452
#define UDP_BUFF_LEN 1024

int msg_send(uint32_t server_addr, uint8_t *msg, uint32_t len);
int select_read(int fd, long sec, long usec);
int udpServer_waitData(int fd, struct sockaddr_in *clent_addr, char* data, int dataLength);
int udpServer_waitData_timeout(int fd, struct sockaddr_in * clent_addr, char* data, int dataLength, long s, long us);
void msg_udp_close(void);
int msg_udp_init(void);
int msg_udp_listen(uint8_t *buf);
#endif