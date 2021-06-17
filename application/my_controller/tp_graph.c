#include "tp_graph.h"
// #include <glib.h>
#include <arpa/inet.h>
#include "redis_interface.h"
// #include "mul_common.h"

tp_sw * tp_graph = NULL;
tp_swdpid_glabolkey * key_table = NULL;
uint32_t controller_area = 0x01010000;

uint32_t tp_get_area_from_db(uint32_t ip_addr)
{
    // some command send to Redis 
    uint32_t ret = 0;
    // ctrl_id = Get_Ctrl_Id(ip_addr);
    redis_Get_Ctrl_Id(ip_addr, &ret);
    return ret;
}

int tp_set_area_to_db(uint32_t ip_addr, uint32_t cid)
{
    char cmd[CMD_MAX_LENGHT] = {0};

	// set the link information
    // c_log_debug("tp_set_area_to_db 1");
	snprintf(cmd, CMD_MAX_LENGHT, "hset ctrl %u %u", ip_addr, cid);
    // c_log_debug("tp_set_area_to_db 2");
    return exeRedisIntCmd_wr(cmd);
}

uint32_t tp_set_sw_glabol_id(uint64_t sw_dpid)
{
    static uint8_t sw_count = 0;
    tp_swdpid_glabolkey *s = NULL;
    sw_count++;

    if(tp_get_sw_glabol_id(sw_dpid))return 0;

    s = malloc(sizeof(tp_swdpid_glabolkey));
    memset(s, 0, sizeof(tp_swdpid_glabolkey));
    s->key = sw_dpid;
    s->sw_gid = controller_area + ((sw_count|0x00000000) << 8);
    HASH_ADD(hh,key_table,key,sizeof(uint64_t),s);

    return s->sw_gid;
}

uint32_t tp_get_sw_glabol_id(uint64_t sw_dpid)
{
    tp_swdpid_glabolkey *s = NULL;
    // tp_swdpid_glabolkey *tmp;
    
    HASH_FIND(hh, key_table, &sw_dpid, sizeof(uint64_t), s);
    if(s)return s->sw_gid;
    return 0;
}

int tp_del_sw_glabol_id(uint64_t sw_dpid)
{
    tp_swdpid_glabolkey *s = NULL;

    HASH_FIND(hh, key_table, &sw_dpid, sizeof(uint64_t), s);
    if(!s)return 0;

    HASH_DEL(key_table, s);
    free(s);

    return 1;
}

uint32_t tp_get_local_ip(void)
{
    return inet_addr(CONTROLLER_IP);
}

// int tp_set_sw_delay(uint32_t key, uint64_t delay)
// {
//     tp_sw *s = tp_find_sw(key);
//     if(!s)return 0;
//     s->delay = delay;
//     return 1;
// }

// uint64_t tp_get_sw_delay(uint32_t key)
// {
//     tp_sw *s = tp_find_sw(key);
//     if(!s)return 0;
//     return s->delay;
// }

tp_sw * tp_find_sw(uint32_t key)
{
    tp_sw *s = NULL;
    //c_log_debug("sw %x tp_find_sw", key);
    HASH_FIND(hh, tp_graph, &key, sizeof(uint32_t), s);
    return s;
}

tp_sw * tp_add_sw(uint32_t key)
{
    tp_sw *s = NULL;

    if(tp_find_sw(key))return NULL;

    s = malloc(sizeof(tp_sw));
    memset(s, 0, sizeof(tp_sw));
    s->key = key;
    HASH_ADD(hh,tp_graph,key,sizeof(uint32_t),s);

    return s;
}

void __tp_sw_add_port(tp_sw *head, uint32_t port_no, uint8_t dl_hw_addr[ETH_ADDR_LEN])
{
    tp_sw_port * s = head->list_port;
    tp_sw_port * tmp = malloc(sizeof(tp_sw_port));
    memset(tmp, 0, sizeof(tp_sw_port));
    tmp->port_no = port_no;
    if(dl_hw_addr)
    {
        strncpy((char*)tmp->dl_hw_addr, (const char*)dl_hw_addr, ETH_ADDR_LEN);
    }
    tmp->next = s;
    if(s)s->pprev = &tmp->next;
    head->list_port = tmp;
    tmp->pprev = &head->list_port;
}

tp_sw_port * __tp_sw_find_port(tp_sw *head, uint32_t port_no)
{
    tp_sw_port * s = head->list_port;
    while(s!= NULL && s->port_no != port_no)s = s->next;
    return s;
}

void __tp_sw_del_port(tp_sw *head, uint32_t port_no)
{
    tp_sw_port * s = __tp_sw_find_port(head, port_no);
    if(s != NULL)
    {
        tp_sw_port *next = s->next;
        tp_sw_port **pprev = s->pprev;

        *pprev = next;
        if(next != NULL)next->pprev = pprev;

        free(s);
    }
}
void __tp_sw_del_all_port(tp_sw *head)
{
    tp_sw_port *tmp, * s = head->list_port;
    while(s != NULL)
    {
        tmp = s->next;
        free(s);
        s = tmp;
    }
    head->list_port = NULL;
}

void __tp_head_add_link(tp_sw *head, tp_link * n)
{
    tp_link *list_link = head->list_link;
    n->next = list_link;
    if(list_link)list_link->pprev = &n->next;
    head->list_link = n;
    n->pprev = &head->list_link;
}

int tp_add_link(uint32_t key1, uint32_t port1, uint32_t key2, uint32_t port2)
{
    tp_sw *n1 = tp_find_sw(key1);
    tp_sw *n2 = tp_find_sw(key2);
    tp_link *n1ton2;
    tp_link *n2ton1;

    if(!n1 || !n2)return 0;
    if(__tp_get_link_in_head(n1->list_link, n2->key))return 0;
    
    n1ton2 = malloc(sizeof(tp_link));
    n2ton1 = malloc(sizeof(tp_link));
    memset(n1ton2, 0, sizeof(tp_link));
    memset(n2ton1, 0, sizeof(tp_link));
    n1ton2->key = key2;
    n1ton2->port_h = port1;
    n1ton2->port_n = port2;
    n2ton1->key = key1;
    n2ton1->port_h = port2;
    n2ton1->port_n = port1;
    __tp_head_add_link(n1, n1ton2);
    __tp_head_add_link(n2, n2ton1);

    return 1;
}

tp_link* __tp_get_link_in_head(tp_link *head, uint32_t key)
{
    tp_link * ret = head;
    while(ret != NULL)
    {
        if(ret->key == key)break;
        ret = ret->next;
    }
    return ret;
}

void __tp_delete_link_in_head(tp_link *del_n)
{
    tp_link *next = del_n->next;
    tp_link **pprev = del_n->pprev;

    *pprev = next;
    if(next)next->pprev = pprev;

    free(del_n);
}

int tp_delete_link(uint32_t key1, uint32_t key2)
{
    tp_link * del_n1, *del_n2;
    tp_sw *n1 = tp_find_sw(key1);
    tp_sw *n2 = tp_find_sw(key2);

    if(n1 == NULL || n2 == NULL)return 0;

    del_n1 = __tp_get_link_in_head(n1->list_link, key2);
    del_n2 = __tp_get_link_in_head(n2->list_link, key1);

    if(del_n1 == NULL && del_n2 == NULL)return 0;
    if(del_n1)__tp_delete_link_in_head(del_n1);
    if(del_n2)__tp_delete_link_in_head(del_n2);

    return 1;
}

int tp_delete_sw(uint32_t key)
{
    tp_sw *s = NULL;

    s = tp_find_sw(key);
    if(!s)return 0;

    tp_del_sw_glabol_id(s->sw_dpid);
    while(s->list_link != NULL)
    {
        tp_delete_link(key, s->list_link->key);
    }
    HASH_DEL(tp_graph, s);
    free(s);

    return 1;
}

void tp_distory(void)
{
    tp_sw * s, * tmp;
    tp_link * next_tmp1, * next_tmp2;

    HASH_ITER(hh, tp_graph, s, tmp) 
    {
        next_tmp1 = s->list_link;
        while(next_tmp1 != NULL)
        {
            next_tmp2 = next_tmp1->next;
            free(next_tmp1);
            next_tmp1 = next_tmp2;
        }
        tp_del_sw_glabol_id(s->sw_dpid);
        HASH_DEL(tp_graph, s);
        free(s);
    }

    tp_graph = NULL;
}