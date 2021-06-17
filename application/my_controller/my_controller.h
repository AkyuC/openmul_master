#ifndef __MUL_MY_CONTROLLER_H__
#define __MUL_MY_CONTROLLER_H__

#define MY_CONTROLLER_UNK_BUFFER_ID 0xffffffff

void my_controller_module_init(void *ctx);
void my_controller_module_vty_init(void *arg);

void* pkt_listen(void *arg);

#endif

