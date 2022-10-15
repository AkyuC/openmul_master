#include "topo.h"
#include <stdlib.h>
#include <string.h>

RET_RESULT tp_add_link(uint32_t sw_dpid, uint32_t port1, uint32_t sw_dpid_adj, uint32_t port2, uint64_t delay, tp_sw sw_list[SW_NUM])
{
    tp_link *sw1tosw2;
    tp_link *sw2tosw1;

    if(tp_get_link_in_head(sw_list[sw_dpid].list_link, sw_dpid_adj) != NULL)return FAILURE;
    
    sw1tosw2 = malloc(sizeof(tp_link));
    sw2tosw1 = malloc(sizeof(tp_link));
    memset(sw1tosw2, 0, sizeof(tp_link));
    memset(sw2tosw1, 0, sizeof(tp_link));

    sw1tosw2->sw_adj_dpid = sw_dpid_adj;
    sw1tosw2->port = port1;
    sw1tosw2->port_adj = port2;
    sw1tosw2->delay = delay;
    sw2tosw1->sw_adj_dpid = sw_dpid;
    sw2tosw1->port = port2;
    sw2tosw1->port_adj = port1;
    sw2tosw1->delay = delay;

    __tp_head_add_link(&sw_list[sw_dpid], sw1tosw2);
    __tp_head_add_link(&sw_list[sw_dpid_adj], sw2tosw1);

    return SUCCESS;
}

tp_link* tp_get_link_in_head(tp_link *head, uint32_t dpid)
{
    tp_link * ret = head;
    while(ret != NULL)
    {
        if(ret->sw_adj_dpid == dpid)return ret;
        ret = ret->next;
    }
    return NULL;
}

void __tp_head_add_link(tp_sw *head, tp_link * n)
{
    tp_link *list_link = head->list_link;
    n->next = list_link;
    if(list_link)list_link->pprev = &n->next;
    head->list_link = n;
    n->pprev = &head->list_link;
}

RET_RESULT tp_delete_link(uint32_t sw_dpid, uint32_t sw_dpid_adj, tp_sw sw_list[SW_NUM])
{
    tp_link * del_n1, *del_n2;

    del_n1 = tp_get_link_in_head(sw_list[sw_dpid].list_link, sw_dpid_adj);
    del_n2 = tp_get_link_in_head(sw_list[sw_dpid_adj].list_link, sw_dpid);

    if(del_n1 == NULL && del_n2 == NULL)return FAILURE;
    if(del_n1)__tp_delete_link_in_head(del_n1);
    if(del_n2)__tp_delete_link_in_head(del_n2);

    return SUCCESS;
}

void __tp_delete_link_in_head(tp_link *del_n)
{
    tp_link *next = del_n->next;
    tp_link **pprev = del_n->pprev;

    *pprev = next;
    if(next)next->pprev = pprev;

    free(del_n);
}

RET_RESULT tp_set_link_delay(uint32_t sw_dpid, uint32_t sw_dpid_adj, uint64_t delay, tp_sw sw_list[SW_NUM])
{
    tp_link * n1, * n2;

    n1 = tp_get_link_in_head(sw_list[sw_dpid].list_link, sw_dpid_adj);
    n2 = tp_get_link_in_head(sw_list[sw_dpid_adj].list_link, sw_dpid);

    if(n1 == NULL && n2 == NULL)return FAILURE;
    if(n1)n1->delay = delay;
    if(n2)n2->delay = delay;
    return SUCCESS;
}

RET_RESULT tp_get_link_delay(uint32_t sw_dpid, uint32_t sw_dpid_adj, tp_sw sw_list[SW_NUM])
{
    tp_link * n1, * n2;

    n1 = tp_get_link_in_head(sw_list[sw_dpid].list_link, sw_dpid_adj);
    n2 = tp_get_link_in_head(sw_list[sw_dpid_adj].list_link, sw_dpid);

    if(n1 == NULL && n2 == NULL)return FAILURE;
    return n1->delay;
}

void tp_distory(tp_sw sw_list[SW_NUM])
{
    tp_link * next_tmp1, * next_tmp2;
    int i = 0;

    for(i=0; i<SW_NUM; i++)
    {
        next_tmp1 = sw_list[i].list_link;
        while(next_tmp1 != NULL)
        {
            next_tmp2 = next_tmp1->next;
            free(next_tmp1);
            next_tmp1 = next_tmp2;
        }
        sw_list[i].list_link = NULL;
    }
}

RET_RESULT tp_add_link_vector(uint32_t sw_dpid, uint32_t port1, uint32_t sw_dpid_adj, uint32_t port2, uint64_t delay, tp_sw sw_list[SW_NUM])
{
    tp_link *sw1tosw2;

    if(tp_get_link_in_head(sw_list[sw_dpid].list_link, sw_dpid_adj) != NULL)return FAILURE;
    
    sw1tosw2 = malloc(sizeof(tp_link));
    memset(sw1tosw2, 0, sizeof(tp_link));

    sw1tosw2->sw_adj_dpid = sw_dpid_adj;
    sw1tosw2->port = port1;
    sw1tosw2->port_adj = port2;
    sw1tosw2->delay = delay;

    __tp_head_add_link(&sw_list[sw_dpid], sw1tosw2);

    return SUCCESS;
}

RET_RESULT tp_delete_link_vector(uint32_t sw_dpid, uint32_t sw_dpid_adj, tp_sw sw_list[SW_NUM])
{
    tp_link *del_n1;

    del_n1 = tp_get_link_in_head(sw_list[sw_dpid].list_link, sw_dpid_adj);

    if(del_n1 == NULL)return FAILURE;
    if(del_n1)__tp_delete_link_in_head(del_n1);

    return SUCCESS;
}