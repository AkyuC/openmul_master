#include "tp_route.h"
#include "heap.h"
#include "msg_udp.h"
#include "ARP.h"
#include "redis_interface.h"

extern tp_sw * tp_graph;
extern tp_swdpid_glabolkey * key_table;
extern uint32_t controller_area;

uint8_t MASTER_CONTROLLER = 1;

int rt_stp_issue_flow(uint32_t src_ip, uint64_t * path, uint32_t len)
{
    struct flow fl;
    struct flow mask;
    mul_act_mdata_t mdata;
    uint32_t sw_key, outport, sw_key_tmp;
    int i, j;
    tp_sw * sw;
    uint8_t src_mac[OFP_ETH_ALEN], *index;
    uint8_t broadcastmac[OFP_ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    redis_Get_Pc_MAC(src_ip, (uint8_t*)src_mac);
    index = malloc(len);
    memset(index, 0, len);

    for ( i = 0; i < len; i++)
    {
        sw_key = (path[i] >> 32)&0x00000000ffffffff;
        if((sw_key & 0xffff0000) ==  controller_area && index[i] == 0)
        {
            sw = tp_find_sw(sw_key);
            memset(&fl, 0, sizeof(fl));
            memset(&mdata, 0, sizeof(mdata));
            of_mask_set_dc_all(&mask);

            // fl.ip.nw_dst = dst_ip;
            fl.ip.nw_src = src_ip;
            fl.dl_type = htons(ETH_TYPE_ARP);
            of_mask_set_dl_type(&mask);
            // of_mask_set_nw_dst(&mask, 32);
            of_mask_set_nw_src(&mask, 32);
            memcpy(&fl.dl_src, src_mac, OFP_ETH_ALEN);
            of_mask_set_dl_src(&mask);
            memcpy(&fl.dl_dst, broadcastmac, OFP_ETH_ALEN);
            of_mask_set_dl_dst(&mask);

            mul_app_act_alloc(&mdata);
            mul_app_act_set_ctors(&mdata, sw->sw_dpid);
            for(j = i; j<len; j++)
            {
                sw_key_tmp = (path[j] >> 32)&0x00000000ffffffff;
                c_log_debug("sw_key_tmp:%x, sw_key:%x", sw_key_tmp, sw_key);
                if( sw_key_tmp == sw_key && index[j] == 0)
                {
                    outport = path[j]&0x00000000ffffffff;
                    mul_app_action_output(&mdata, outport);
                    index[j] = 1;
                    c_log_debug("add a outport:%x",outport);
                }
            }

            if(!mul_app_send_flow_add(MY_CONTROLLER_APP_NAME, NULL, sw->sw_dpid, &fl, &mask,
                                (uint32_t)-1, mdata.act_base, mul_app_act_len(&mdata),
                                0, 0, C_FL_PRIO_FWD, C_FL_ENT_NOCACHE))
            {
                c_log_debug("issue flow add success");
            }else
            {
                c_log_debug("issue flow add fail");
            }
            mul_app_act_free(&mdata);
        }
    }
    free(index);
    return SUCCESS;
}

int rt_load_pc(void)
{
    redisReply * reply, **reply_tmp;
	char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t cursor, sw_key_tmp1, sw_key_tmp2, i;
    redisContext *context = NULL;

    if(!redis_connect(&context))return FAILURE;

    // c_log_debug("loading sw send command!");
    snprintf(cmd, CMD_MAX_LENGHT, "hscan sw2pc_port 0 match * count 500");
	reply = (redisReply *)redisCommand(context, cmd);
	if (NULL == reply)
	{
		printf("%d execute command:%s failure\n", __LINE__, cmd);
        redis_disconnect(context);
		return FAILURE;
	}
	// c_log_debug("loading sw send command reply");
	if(reply->elements != 0)
	{
		cursor = atoi(reply->element[0]->str);
		while(cursor != 0)
		{
            // c_log_debug("need to get the less sw infor");
			reply_tmp = reply->element[1]->element;	
			for(i = 0; i<reply->element[1]->elements; i++)
			{
				sw_key_tmp1 = atoi(reply_tmp[i++]->str);
                tp_add_sw(sw_key_tmp1);
                c_log_debug("add pc node %x", sw_key_tmp1);
				sw_key_tmp2 = sw_key_tmp1&0xffffff00;
                tp_add_link(sw_key_tmp2, (sw_key_tmp1&0x000000ff), sw_key_tmp1, 0);
			}
			freeReplyObject(reply);
			memset(cmd, 0, CMD_MAX_LENGHT);
			snprintf(cmd, CMD_MAX_LENGHT, "hscan sw2pc_port %u match * count 500", cursor);
			reply = (redisReply *)redisCommand(context, cmd);
			if (NULL == reply)
			{
				printf("%d execute command:%s failure\n", __LINE__, cmd);
                redis_disconnect(context);
				return FAILURE;
			}
			cursor = atoi(reply->element[0]->str);
		}
        // c_log_debug("sw add to topo");
		reply_tmp = reply->element[1]->element;	
		for(i = 0; i<reply->element[1]->elements; i++)
		{
			sw_key_tmp1 = atoi(reply_tmp[i++]->str);
            tp_add_sw(sw_key_tmp1);
            c_log_debug("add pc node %x", sw_key_tmp1);
            sw_key_tmp2 = sw_key_tmp1&0xffffff00;
            tp_add_link(sw_key_tmp2, (sw_key_tmp1&0x000000ff), sw_key_tmp1, 0);
		}
	}
    freeReplyObject(reply);
    redis_disconnect(context);
    return SUCCESS;
}

int rt_set_arp_flow_path_from_redis(uint32_t src_ip)
{
    uint64_t *path;
    uint32_t pathlen;

    if(!redis_Get_Route_Path(src_ip, 0xffffffff, &path, &pathlen))return FAILURE;

    rt_stp_issue_flow(src_ip, path, pathlen);
    free(path);
    return SUCCESS;
}

int rt_stp(uint32_t src_ip, uint32_t dst_ip)
{
    tp_sw * src_node, * start_node;
    tp_link * adj_node;
    heap rt_minheap;
    rt_node * rt_visited_set = NULL, *tmp, * sw_flow_tmp = NULL, *s;
    uint64_t * delay_get;
    uint32_t * sw_visiting_key, sw_start, sw_start_port, all_node;
    uint64_t delay_set = 0, *path, redis_key;
    int i;
    char cmd[CMD_MAX_LENGHT] = {0};
    
    if(redis_Is_Route_Path(src_ip, 0xffffffff))
    {
        if(!rt_set_arp_flow_path_from_redis(src_ip))return FAILURE;
        else return SUCCESS;
    }
    if(!MASTER_CONTROLLER)return FAILURE;

    if(!rt_load_glabol_topo() || !rt_load_pc())return FAILURE;
    c_log_debug("stp loaded topo!");
    redis_Get_Pc_Sw_Port(src_ip, &sw_start, &sw_start_port);
    c_log_debug("sw_key:%x port:%x", sw_start, sw_start_port);
    src_node = tp_find_sw(sw_start + sw_start_port);
    if(src_node == NULL)
    {
        c_log_debug("can't get pc_node %x!", sw_start + sw_start_port);
        return FAILURE;
    }
    start_node = src_node;
    // c_log_debug("src_node %x, dst_node %x!", src_node->key, dst_node->key);
    // c_log_debug("heap_create!");
    c_log_debug("start stp!");
    all_node = HASH_COUNT(tp_graph);
    heap_create(&rt_minheap, 0, NULL);
    c_log_debug("rt_set add src_node %x!", src_node->key);
    rt_add_node(src_node->key, 0, &rt_visited_set);
    c_log_debug("heap insert src_node %x!", src_node->key);
    heap_insert(&rt_minheap, (void*)&(src_node->key), (void*)&delay_set);

    while(HASH_COUNT(rt_visited_set) < all_node)
    {
        heap_delmin(&rt_minheap, (void*)&sw_visiting_key, (void*)&delay_get);
        c_log_debug("get the min_delay node %x %lu from heap", *sw_visiting_key, *delay_get);
        start_node = tp_find_sw(*sw_visiting_key);
        adj_node = start_node->list_link;//找到一个点开始遍历
        c_log_debug("get the sw links_head");
        if(adj_node == NULL) continue;
        c_log_debug("start traverse the sw links");
        while(adj_node)//遍历邻接点
        {
            if(!rt_find_node(adj_node->key, &rt_visited_set))//没有被遍历过
            {
                c_log_debug("calculate the sum of delay");
                delay_set = *delay_get + adj_node->delay;
                c_log_debug("add the adj sw %x to heap", adj_node->key);
                heap_insert(&rt_minheap, (void*)&adj_node->key, (void*)&delay_set);//添加要遍历的点
                c_log_debug("add the adj sw %x to rt_visited_set", adj_node->key);
                rt_add_node(adj_node->key, start_node->key, &rt_visited_set);//添加已经遍历的点
            }
            adj_node = adj_node->next;
        }
    }

    c_log_debug("geting path! rt_visited_set len:%u, all node:%u", HASH_COUNT(rt_visited_set), all_node);
    path = malloc(sizeof(uint64_t)*(all_node));
    i = 0;
    redis_key = (((uint64_t)src_ip << 32) & 0xffffffff00000000)|0x00000000ffffffff;
    c_log_debug("write stp to redis!");
    HASH_ITER(hh, rt_visited_set, s, tmp) 
    {
        if(s->prev_key != src_node->key && s->prev_key)
        {
            c_log_debug("s->prev_key:%x, s->key:%x", s->prev_key, s->key);
            if(!tp_find_sw(s->prev_key))c_log_debug("tp_find_sw(s->prev_key) == NULL");
            if(!__tp_get_link_in_head(tp_find_sw(s->prev_key)->list_link, s->key))
                c_log_debug("__tp_get_link_in_head(tp_find_sw(s->prev_key)->list_link, s->key) == NULL");
            sw_start_port = __tp_get_link_in_head(tp_find_sw(s->prev_key)->list_link, s->key)->port_h;
            c_log_debug("sw_start_port:%x", sw_start_port);
            path[i] = (((uint64_t)(s->prev_key) << 32) & 0xffffffff00000000) + sw_start_port;
            snprintf(cmd, CMD_MAX_LENGHT, "rpush %lu %lu", redis_key, path[i]);
            if(!exeRedisIntCmd_wr(cmd))return FAILURE;
            memset(cmd, 0, CMD_MAX_LENGHT);
            i++;
            // rt_add_node(s->prev_key, sw_start_port, &sw_flow_tmp);
            c_log_debug("add success");
        }
    }
    c_log_debug("add success");
    
    c_log_debug("rt_stp_issue_flow!");
    rt_stp_issue_flow(src_ip, path, i);
    free(path);
    rt_distory(&sw_flow_tmp);
    rt_distory(&rt_visited_set);
    heap_destroy(&rt_minheap);
    return SUCCESS;
}

int rt_load_glabol_topo_sw(void)
{
    redisReply * reply, **reply_tmp;
	char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t cursor, sw_key_tmp1, i;
    tp_sw * sw_tmp;
    redisContext *context = NULL;

    if(!redis_connect(&context))return FAILURE;
    c_log_debug("loading sw from db!");
    snprintf(cmd, CMD_MAX_LENGHT, "hscan sw 0 match * count 500");
	reply = (redisReply *)redisCommand(context, cmd);
	if (NULL == reply)
	{
		printf("%d execute command:%s failure\n", __LINE__, cmd);
        redis_disconnect(context);
		return FAILURE;
	}
    if(reply->elements != 0)
	{
		cursor = atoi(reply->element[0]->str);
		while(cursor != 0)
		{
            c_log_debug("need to get the less sw information");
			reply_tmp = reply->element[1]->element;	
			for(i = 0; i<reply->element[1]->elements; i++)
			{
				sw_key_tmp1 = atoi(reply_tmp[i++]->str);
                sw_tmp = tp_add_sw(sw_key_tmp1);
				sw_tmp->delay = atol(reply_tmp[i]->str);
			}
			freeReplyObject(reply);
			memset(cmd, 0, CMD_MAX_LENGHT);
			snprintf(cmd, CMD_MAX_LENGHT, "hscan sw %u match * count 500", cursor);
			reply = (redisReply *)redisCommand(context, cmd);
			if (NULL == reply)
			{
				printf("%d execute command:%s failure\n", __LINE__, cmd);
                redis_disconnect(context);
				return FAILURE;
			}
			cursor = atoi(reply->element[0]->str);
		}
        // c_log_debug("sw add to topo");
		reply_tmp = reply->element[1]->element;	
		for(i = 0; i<reply->element[1]->elements; i++)
		{
			sw_key_tmp1 = atoi(reply_tmp[i++]->str);
            if(!tp_find_sw(sw_key_tmp1))
            {
                sw_tmp = tp_add_sw(sw_key_tmp1);
                sw_tmp->delay = atol(reply_tmp[i]->str);
            }
		}
	}
    freeReplyObject(reply);
    redis_disconnect(context);
    c_log_debug("loaded sw from db!");
    return SUCCESS;
}

int rt_load_glabol_topo_link(void)
{
    redisReply * reply, **reply_tmp;
	char cmd[CMD_MAX_LENGHT] = {0};
    uint32_t cursor, sw_key_tmp1, sw_key_tmp2, sw_port1, sw_port2, i;
    uint64_t redis_key_tmp, delay_tmp;
    redisContext *context = NULL;

    if(!redis_connect(&context))return FAILURE;
    c_log_debug("loading link");
    snprintf(cmd, CMD_MAX_LENGHT, "hscan link_delay 0 match * count 500");
	reply = (redisReply *)redisCommand(context, cmd);
	if (NULL == reply)
	{
        redis_disconnect(context);
		printf("%d execute command:%s failure\n", __LINE__, cmd);
		return FAILURE;
	}
	if(reply->elements != 0)
	{
		cursor = atoi(reply->element[0]->str);
		while(cursor != 0)
		{
			reply_tmp = reply->element[1]->element;	
			for(i = 0; i<reply->element[1]->elements; i++)
			{
				redis_key_tmp = atol(reply_tmp[i++]->str);
                sw_key_tmp1 = (uint32_t)(((0xffffffff00000000&redis_key_tmp)>>32)&0x00000000ffffffff);
                sw_key_tmp2 = (uint32_t)(0x00000000ffffffff&redis_key_tmp);
                // c_log_debug("redis_key_tmp %lx add a link between %x and %x", redis_key_tmp, sw_key_tmp1, sw_key_tmp2);
				delay_tmp = atol(reply_tmp[i]->str);
                redis_Get_Link_Port(sw_key_tmp1, &sw_port1, sw_key_tmp2, &sw_port2);
                tp_add_link(sw_key_tmp1, sw_port1, sw_key_tmp2, sw_port2);
                TP_SET_LINK(sw_key_tmp1, sw_key_tmp2, delay, delay_tmp);
			}
			freeReplyObject(reply);
			memset(cmd, 0, CMD_MAX_LENGHT);
			snprintf(cmd, CMD_MAX_LENGHT, "hscan link_delay %u match * count 500", cursor);
			reply = (redisReply *)redisCommand(context, cmd);
			if (NULL == reply)
			{
                redis_disconnect(context);
				printf("%d execute command:%s failure\n", __LINE__, cmd);
				return FAILURE;
			}
			cursor = atoi(reply->element[0]->str);
		}
		reply_tmp = reply->element[1]->element;	
		for(i = 0; i<reply->element[1]->elements; i++)
		{
			redis_key_tmp = atol(reply_tmp[i++]->str);
            sw_key_tmp1 = (uint32_t)(((0xffffffff00000000&redis_key_tmp)>>32)&0x00000000ffffffff);
            sw_key_tmp2 = (uint32_t)(0x00000000ffffffff&redis_key_tmp);
            // c_log_debug("redis_key_tmp %lx add a link between %x and %x", redis_key_tmp, sw_key_tmp1, sw_key_tmp2);
            delay_tmp = atol(reply_tmp[i]->str);
            redis_Get_Link_Port(sw_key_tmp1, &sw_port1, sw_key_tmp2, &sw_port2);
            tp_add_link(sw_key_tmp1, sw_port1, sw_key_tmp2, sw_port2);
            TP_SET_LINK(sw_key_tmp1, sw_key_tmp2, delay, delay_tmp);
		}
	}
    freeReplyObject(reply);
    redis_disconnect(context);
    c_log_debug("loaded link");
    return SUCCESS;
}

int rt_load_glabol_topo(void)
{
    if(!rt_load_glabol_topo_sw())
    {
        c_log_debug("load sw fail");
        return FAILURE;
    }
    if(!rt_load_glabol_topo_link())
    {
        c_log_debug("load link fail");
        return FAILURE;
    }

    return SUCCESS;
}

rt_node * rt_find_node(uint32_t key, rt_node ** rt_set)
{
    rt_node *s = NULL;
    HASH_FIND(hh, *rt_set, &key, sizeof(uint32_t), s);
    return s;
}

rt_node * rt_add_node(uint32_t key, uint32_t prev_key, rt_node ** rt_set)
{
    rt_node *s = NULL;

    // c_log_debug("rt_find_node");
    if(rt_find_node(key, rt_set))return NULL;

    // c_log_debug("start add node to rt_set");
    s = malloc(sizeof(rt_node));
    memset(s, 0, sizeof(rt_node));
    s->key = key;
    s->prev_key = prev_key;
    HASH_ADD(hh, *rt_set, key, sizeof(uint32_t), s);
    // c_log_debug("end add node to rt_set");

    return s;
}

int rt_del_node(uint32_t key, rt_node ** rt_set)
{
    rt_node *s = NULL;

    s = rt_find_node(key, rt_set);
    if(!s)return 0;
    HASH_DEL(*rt_set, s);
    free(s);

    return 1;
}

void rt_distory(rt_node ** rt_set)
{
    rt_node * s, * tmp;

    HASH_ITER(hh, *rt_set, s, tmp) 
    {
        HASH_DEL(*rt_set, s);
        free(s);
    }
}

rt_node* rt_ip_get_path(uint32_t sw_start, uint32_t sw_end)
{
    tp_sw * src_node, * dst_node, * start_node;
    tp_link * adj_node;
    heap rt_minheap;
    rt_node * rt_visited_set = NULL, *path = NULL, *path_tmp;
    uint64_t * delay_get;
    uint32_t * sw_visiting_key;
    uint64_t delay_set = 0;
    
    if(MASTER_CONTROLLER)
    {
        c_log_debug("loading topo from redis");
        rt_load_glabol_topo();
        c_log_debug("loaded topo from redis");
    }
    src_node = tp_find_sw(sw_start);
    dst_node = tp_find_sw(sw_end);
    start_node = src_node;
    if(!src_node || !dst_node) return NULL;
    c_log_debug("src_node %x, dst_node %x!", src_node->key, dst_node->key);

    c_log_debug("heap_create!");
    heap_create(&rt_minheap, 0, NULL);
    c_log_debug("rt_set add src_node %x!", src_node->key);
    rt_add_node(src_node->key, 0, &rt_visited_set);
    c_log_debug("heap insert src_node %x!", src_node->key);
    heap_insert(&rt_minheap, (void*)&(src_node->key), (void*)&delay_set);

    while(heap_size(&rt_minheap))
    {
        heap_delmin(&rt_minheap, (void*)&sw_visiting_key, (void*)&delay_get);
        c_log_debug("get the min_delay node %x %lu from heap", *sw_visiting_key, *delay_get);
        start_node = tp_find_sw(*sw_visiting_key);
        adj_node = start_node->list_link;//找到一个点开始遍历
        c_log_debug("get the sw links_head");
        if(adj_node == NULL) continue;
        c_log_debug("start traverse the sw links");
        while(adj_node)//遍历邻接点
        {
            if(adj_node->key == dst_node->key)
            {
                //找到了，下发流表
                c_log_debug("find the dst and than issue the flow table");
                c_log_debug("add the adj sw %x to rt_visited_set", adj_node->key);
                rt_add_node(adj_node->key, start_node->key, &rt_visited_set);
                c_log_debug("issue the flow table");
                //rt_set_ip_flow_path(nw_src, nw_dst, &rt_visited_set);
                while(sw_start != sw_end)
                {
                    path_tmp = rt_find_node(sw_end, &rt_visited_set);
                    rt_add_node(sw_end, path_tmp->prev_key, &path);
                    sw_end = path_tmp->prev_key;
                }
                rt_add_node(sw_start, 0, &path);
                c_log_debug("free the malloc and return Path");
                rt_distory(&rt_visited_set);
                heap_destroy(&rt_minheap);
                return path;
            }
            if(!rt_find_node(adj_node->key, &rt_visited_set))//没有被遍历过
            {
                c_log_debug("calculate the sum of delay");
                delay_set = *delay_get + adj_node->delay;
                c_log_debug("add the adj sw %x to heap", adj_node->key);
                heap_insert(&rt_minheap, (void*)&adj_node->key, (void*)&delay_set);//添加要遍历的点
                c_log_debug("add the adj sw %x to rt_visited_set", adj_node->key);
                rt_add_node(adj_node->key, start_node->key, &rt_visited_set);//添加已经遍历的点
            }
            adj_node = adj_node->next;
        }
    }

    c_log_debug("free the malloc and return NULL");
    rt_distory(&rt_visited_set);
    heap_destroy(&rt_minheap);

    return path;
}

int rt_ip(uint32_t nw_src, uint32_t nw_dst, uint16_t type)
{
    rt_node * rt_path = NULL, * rt_tmp;
    tp_link * link_tmp;
    uint64_t * path = NULL, *path_b = NULL;
    uint32_t sw1_key, sw1_port, sw2_key, sw2_port, path_len, tmp;
    int i;
    ctrl_pkt pkt;

    if(!redis_Get_Pc_Sw_Port(nw_src, &sw1_key, &sw1_port) || !redis_Get_Pc_Sw_Port(nw_dst, &sw2_key, &sw2_port))return 0;
    c_log_debug("get_src %x sw %x and port %x", nw_src, sw1_key, sw1_port);
    c_log_debug("get_dst %x sw %x and port %x", nw_dst, sw2_key, sw2_port);

    if(redis_Is_Route_Path(nw_src, nw_dst))
    {
        c_log_debug("have a route before!");
        if(rt_set_ip_flow_path_from_redis(nw_src, nw_dst, type))return 1;
    }else
    {
        c_log_debug("dont have a path before, first cul");
        rt_path = rt_ip_get_path(sw1_key, sw2_key);
    }

    if(rt_path)
    {
        path_len = HASH_COUNT(rt_path);
        c_log_debug("have a route, seting, path len %u path:", path_len);
        path = malloc(sizeof(uint64_t)*path_len);
        path_b = malloc(sizeof(uint64_t)*path_len);
        rt_add_node(sw2_key + sw2_port, sw2_key, &rt_path);
        rt_add_node(sw1_key, sw1_key + sw1_port, &rt_path);
        // c_log_debug("get the path from s%x to s%x", nw_src, nw_dst);
        tmp = sw2_key;
        path[path_len-1] = (((uint64_t)sw2_key) <<32) + sw2_port;
        for(i=path_len-2; i>=0; i--)
        {
            HASH_FIND(hh, rt_path, &tmp, sizeof(uint32_t), rt_tmp);
            // c_log_debug("rt_tmp->key:%x", rt_tmp->key);
            // c_log_debug("1");
            link_tmp = __tp_get_link_in_head(tp_find_sw(rt_tmp->prev_key)->list_link, rt_tmp->key);
            // c_log_debug("2");
            path[i] = (((uint64_t)rt_tmp->prev_key) <<32) + link_tmp->port_h;
            // c_log_debug("path[i]:%lx", path[i]);
            // c_log_debug("3");
            tmp = rt_tmp->prev_key;
        }
        // c_log_debug("get the path from s%x to s%x", nw_dst, nw_src);
        tmp = sw2_key;
        path_b[path_len-1] = (((uint64_t)sw1_key) <<32) + sw1_port;
        for(i=0; i<path_len-1; i++)
        {
            HASH_FIND(hh, rt_path, &tmp, sizeof(uint32_t), rt_tmp);
            // c_log_debug("rt_tmp->key:%x", rt_tmp->key);
            // c_log_debug("1");
            // c_log_debug("rt_tmp->prev_key:%x", rt_tmp->prev_key);
            link_tmp = __tp_get_link_in_head(tp_find_sw(rt_tmp->prev_key)->list_link, rt_tmp->key);
            // c_log_debug("2");
            path_b[i] = (((uint64_t)rt_tmp->key) <<32) + link_tmp->port_n;
            // c_log_debug("path[i]:%lx", path[path_len - i -1]);
            // c_log_debug("3");
            tmp = rt_tmp->prev_key;
        }
        c_log_debug("path write to redis");
        redis_Set_Route_Path(nw_src, nw_dst, path, path_len);
        redis_Set_Route_Path(nw_dst, nw_src, path_b, path_len);
        c_log_debug("send to the sw");
        for(i = 0; i < path_len; i++)
        {
            sw1_key = (path[i] >> 32)&0x00000000ffffffff;
            sw1_port = path[i]&0x00000000ffffffff;
            sw2_key = (path_b[i] >> 32)&0x00000000ffffffff;
            sw2_port = path_b[i]&0x00000000ffffffff;
            c_log_debug("sw1_key: %x, sw1_port:%x, sw2_key: %x, sw2_port:%x", sw1_key, sw1_port, sw2_key, sw2_port);
            if((sw1_key&0xffff0000) == controller_area)
            {
                rt_ip_issue_flow(tp_find_sw(sw1_key)->sw_dpid, nw_src, nw_dst, sw1_port, type);
            }
            if((sw2_key&0xffff0000) == controller_area)
            {
                rt_ip_issue_flow(tp_find_sw(sw2_key)->sw_dpid, nw_dst, nw_src, sw2_port, type);
            }
        }
        free(path_b);
        free(path);
        return 1;
    }else
    {
        pkt.type = IP_ROUTE_REQ_PKT;
        pkt.nw_src = nw_src;
        pkt.nw_dst  =nw_dst;
        msg_send(inet_addr(REDIS_SERVER_IP), (uint8_t*)&pkt, sizeof(pkt));
    }
    
    return 0;
}

int rt_set_ip_flow_path_from_redis(uint32_t src_ip, uint32_t dst_ip, uint16_t type)
{
    uint32_t path_len, sw_key, outport, i;
    uint64_t * path;

    c_log_debug("get path from redis");
    if(!redis_Get_Route_Path(src_ip, dst_ip, &path, &path_len))
    {
        c_log_debug("get path from redis fail between %x and %x", src_ip, dst_ip);
        free(path);
        return 0;
    }
    c_log_debug("look for the sw that I controll, path len: %x", path_len);
    for (i = 0; i < path_len; i++)
    {
        sw_key = (path[i] >> 32)&0x00000000ffffffff;
        outport = path[i]&0x00000000ffffffff;
        if((sw_key&0xfffff0000) == controller_area)
        {
            rt_ip_issue_flow(tp_find_sw(sw_key)->sw_dpid, src_ip, dst_ip, outport, type);
        }
    }
    free(path);
    return 1;
}

int rt_ip_issue_flow(uint64_t sw_dpid, uint32_t src_ip, uint32_t dst_ip, uint32_t outport, uint16_t type)
{
    struct flow fl;
    struct flow mask;
    mul_act_mdata_t mdata;

    memset(&fl, 0, sizeof(fl));
    memset(&mdata, 0, sizeof(mdata));
    of_mask_set_dc_all(&mask);

    fl.ip.nw_dst = dst_ip;
    fl.ip.nw_src = src_ip;
    fl.dl_type = htons(type);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_nw_src(&mask, 32);

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, sw_dpid);
    mul_app_action_output(&mdata, outport); 

    if(!mul_app_send_flow_add(MY_CONTROLLER_APP_NAME, NULL, sw_dpid, &fl, &mask,
                         (uint32_t)-1, mdata.act_base, mul_app_act_len(&mdata),
                         0, 0, C_FL_PRIO_EXM, C_FL_ENT_NOCACHE))
    {
        c_log_debug("issue flow add success");
    }else
    {
        c_log_debug("issue flow add fail");
    }
    mul_app_act_free(&mdata);
                        
    return 1;
}