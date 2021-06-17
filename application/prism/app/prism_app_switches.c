/*
 *  prism_switches.c: PRISM switch  manager 
 *  Copyright (C) 2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "prism_app.h"

extern prism_app_struct_t *prism_ctx;

/**
 * prism_portid_hash_func -
 * 
 * Hash  function for a port
 */
static unsigned int
prism_portid_hash_func(const void* key)
{
    return *((uint16_t *)key);
}

/**
 * prism_portid_eq_func -
 * 
 * Determine if two ports are equal
 */
static int
prism_portid_eq_func(const void *key1, const void *key2)
{
    uint16_t idA = *((uint16_t *)key1);
    uint16_t idB = *((uint16_t *)key2);

    return idA == idB;
}

/**
 * prism_port_add -
 *
 * Add a port to a switch 
 */
int
prism_port_add(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no, 
               uint32_t config, uint32_t state, uint8_t *hw_addr)
{
    prism_port_t *port;

    if (!sw) {
        app_log_err("%s: Null switch", FN);
        return -1;
    }

    if (port_no > OFPP_MAX && port_no != OFPP_LOCAL){
        return -1;
    }

    port = calloc(1, sizeof(prism_port_t));
    assert(port);
    port->port_no = port_no;
    port->config = config;
    port->state = state;
    memcpy(port->hw_addr, hw_addr, ETH_ADDR_LEN);

    c_wr_lock(&sw->lock);
    if (g_hash_table_lookup(sw->port_htbl, port)) {
        app_log_err("%s: Sw(0x%llx) port (%u) already present",
                  FN, (unsigned long long)(sw->dpid), port_no);
        c_wr_unlock(&sw->lock);
        free(port);
        return -1;
    }

    g_hash_table_insert(sw->port_htbl, port, port);

    /* Send the updated info to Prism Agent*/
    prism_send_port_info(NULL, port, &sw->dpid);
    c_wr_unlock(&sw->lock);

    app_log_debug("%s:switch (0x%llx) port(%d) added",
            FN, U642ULL(sw->dpid), port_no); 

    return 0;
}

/**
 * prism_port_delete -
 *
 * Delete a port to a switch
 */
int
prism_port_delete(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no, 
               uint32_t config, uint32_t state)
{
    prism_port_t *port;

    c_wr_lock(&sw->lock);

    port = __prism_port_find(ctx, sw, port_no);
    if (!port) {
        app_log_err("%s failed", FN);
        c_wr_unlock(&sw->lock);
        return -1;
    }
    
    port->config = config;
    port->state = state;

    if (!g_hash_table_remove(sw->port_htbl, port)) {
        app_log_err("Failed to delete port 0x%llx:%hu",
                  U642ULL(sw->dpid), port_no);
    }

    c_wr_unlock(&sw->lock);

    return 0;
}

/**
 * prism_port_update  -
 *
 * Update flags of a port 
 */
void
prism_port_update(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no,
                  uint32_t config, uint32_t state, uint8_t *hw_addr)
{
    prism_port_t lkup_port;
    prism_port_t *port;

    if (!sw) {
        app_log_err("%s: Null switch", FN);
        return;
    }

    memset(&lkup_port, 0, sizeof(lkup_port));
    lkup_port.port_no = port_no;

    c_wr_lock(&sw->lock);
    if ((port = g_hash_table_lookup(sw->port_htbl, &lkup_port))) {
        port->config = config;
        port->state = state;
        if(memcmp(port->hw_addr, hw_addr, ETH_ADDR_LEN)) {
            /* Port's hardware address have been changed */
            memcpy(port->hw_addr, hw_addr, ETH_ADDR_LEN);
        }
        /* Send the updated info to Prism Agent*/
        prism_send_port_info(NULL, port, &sw->dpid);

    }

    c_wr_unlock(&sw->lock);

    return;
}
 

/**
 * prism_port_valid  -
 *
 * Check if a port is valid on a switch 
 */
bool
prism_port_valid(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no)
{
    prism_port_t port;

    if (!sw) {
        app_log_err("%s: Null switch", FN);
        return false;
    }

    memset(&port, 0, sizeof(port));
    port.port_no = port_no;

    c_rd_lock(&sw->lock);
    if (g_hash_table_lookup(sw->port_htbl, &port)) {
        c_rd_unlock(&sw->lock);
        return true;
    }

    c_rd_unlock(&sw->lock);
    return false;
}

/**
 * __prism_port_find  -
 *
 * Get a port is valid on a switch 
 */
prism_port_t *
__prism_port_find(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no)
{
    prism_port_t lkup_port;

    if (!sw) {
        app_log_err("%s: Null switch", FN);
        return NULL;
    }

    memset(&lkup_port, 0, sizeof(lkup_port));
    lkup_port.port_no = port_no;

    return (prism_port_t *)(g_hash_table_lookup(sw->port_htbl, &lkup_port));
}


/**
 * prism_port_up  -
 *
 * Check if a port is up/running on a switch 
 */
bool
prism_port_up(prism_app_struct_t *ctx UNUSED, prism_switch_t *sw, uint16_t port_no)
{
    prism_port_t lkup_port;
    prism_port_t *port;

    if (!sw) {
        app_log_err("%s: Null switch", FN);
        return false;
    }

    memset(&lkup_port, 0, sizeof(lkup_port));
    lkup_port.port_no = port_no;

    c_rd_lock(&sw->lock);
    if ((port = g_hash_table_lookup(sw->port_htbl, &lkup_port)) &&
        !(port->config & OFPPC_PORT_DOWN) && 
        !(port->state & OFPPS_LINK_DOWN)) {
        c_rd_unlock(&sw->lock);
        return true;
    }

    c_rd_unlock(&sw->lock);

    return false;
}


/**
 * prism_traverse_all_switch_ports - 
 *
 * Loop through all switch ports and call iter_fn for each 
 */
static void
prism_traverse_all_switch_ports(prism_switch_t *prism_sw, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&prism_sw->lock);
    if (prism_sw->port_htbl) {
        g_hash_table_foreach(prism_sw->port_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&prism_sw->lock);
}

/**
 * prism_dpid_hash_func - 
 *
 */
static unsigned int
prism_dpid_hash_func(const void *p)
{
    prism_switch_t *sw = (prism_switch_t*) p;

    return (unsigned int)(sw->dpid);
}

/**
 * prism_dpid_eq_func - 
 *
 */
static int
prism_dpid_eq_func(const void *p1, const void *p2)
{
    const prism_switch_t *sw1 = (prism_switch_t *) p1;
    const prism_switch_t *sw2 = (prism_switch_t *) p2;

    if (sw1->dpid == sw2->dpid) {
        return 1; /* TRUE */
    } else {
        return 0; /* FALSE */
    }
}

/**
 * prism_switch_put - 
 * @switch : switch pointer 
 *
 * Remove a reference to a switch 
 */
void
prism_switch_put(void *sw_arg)
{
    prism_switch_t *prism_sw = sw_arg;
    if (!atomic_read(&prism_sw->ref)) {
        app_log_debug("%s: switch Destroyed 0x%llx", FN, 
                    (unsigned long long)prism_sw->dpid);
        g_hash_table_destroy(prism_sw->port_htbl);
        free(prism_sw);
    } else {
        atomic_dec(&prism_sw->ref, 1);
    }
}

/**
 * prism_switch_get - 
 * @prism_ctx : main ctx struct
 * @dpid : datapath_id 
 *
 * Get a reference to a switch 
 */
prism_switch_t *
prism_switch_get(prism_app_struct_t *prism_ctx, uint64_t dpid)
{
    prism_switch_t *prism_sw = NULL;
    prism_switch_t prism_lkup_sw;

    prism_lkup_sw.dpid = dpid;

    c_rd_lock(&prism_ctx->lock);
    prism_sw = g_hash_table_lookup(prism_ctx->switch_htbl, &prism_lkup_sw);
    if (prism_sw) {
        atomic_inc(&prism_sw->ref, 1);
    }
    c_rd_unlock(&prism_ctx->lock);

    return prism_sw;
}

/**
 * __prism_switch_get - 
 * @prism_ctx : main ctx struct
 * @dpid : datapath_id 
 *
 * Get a reference to a switch lockless
 */
prism_switch_t *
__prism_switch_get(prism_app_struct_t *prism_ctx, uint64_t dpid)
{
    prism_switch_t *prism_sw = NULL;
    prism_switch_t prism_lkup_sw;

    prism_lkup_sw.dpid = dpid;

    prism_sw = g_hash_table_lookup(prism_ctx->switch_htbl, &prism_lkup_sw);
    if (prism_sw) {
        atomic_inc(&prism_sw->ref, 1);
    }

    return prism_sw;
}

/**
 * prism_switch_del -
 *
 * Delete a switch
 */
int
prism_switch_del(prism_app_struct_t *prism_ctx, uint64_t dpid)
{
    prism_switch_t *prism_sw; 
    prism_switch_t prism_lkup_sw;

    prism_lkup_sw.dpid = dpid;

    c_wr_lock(&prism_ctx->lock);
    prism_sw = g_hash_table_lookup(prism_ctx->switch_htbl, &prism_lkup_sw);
    if (!prism_sw) {
        c_wr_unlock(&prism_ctx->lock);
        app_log_err("%s: 0x%llx del failed", FN, (unsigned long long)dpid);
        return -1;
        
    }

    g_hash_table_remove(prism_ctx->switch_htbl, prism_sw);
    c_wr_unlock(&prism_ctx->lock);

    app_log_debug("%s:switch (0x%llx) deleted",
                FN, (unsigned long long)(dpid)); 

    return 0;
}

/**
 * prism_switch_add -
 *
 * Add a switch
 */
int
prism_switch_add(prism_app_struct_t *prism_ctx, uint64_t dpid, int alias)
{
    prism_switch_t *prism_sw; 
    struct flow fl, mask;

    prism_sw = calloc(1, sizeof(*prism_sw));

    assert(prism_sw);

    prism_sw->dpid = dpid;
    prism_sw->alias = alias;
    c_rw_lock_init(&prism_sw->lock);

    c_wr_lock(&prism_ctx->lock);
    if (g_hash_table_lookup(prism_ctx->switch_htbl, prism_sw)) {
        c_wr_unlock(&prism_ctx->lock);
        app_log_err("%s: 0x%llx already present", FN, (unsigned long long)dpid);
        return -1;
    }

    prism_sw->port_htbl = g_hash_table_new_full(prism_portid_hash_func,
                                              prism_portid_eq_func,
                                              NULL, free);
    if (!prism_sw->port_htbl) {
        c_wr_unlock(&prism_ctx->lock);
        app_log_err("%s: port htbl alloc failed", FN);
        free(prism_sw);
        return -1;
    }
    /* Creating Pool for Next Hop Group Index*/
    prism_sw->group_ipool = ipool_create(PRISM_NEXT_HOP_MAX_GROUP_ENTRIES, 1);
    assert(prism_sw->group_ipool);

    g_hash_table_insert(prism_ctx->switch_htbl, prism_sw, prism_sw);
    c_wr_unlock(&prism_ctx->lock);

    app_log_debug("%s:switch (0x%llx) added",
            FN, (unsigned long long)(dpid)); 
    /* Install default flow in Controller to send unknown packets to PRISM
     * APP */
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    mul_app_send_flow_add(PRISM_APP_NAME, NULL, dpid, &fl, &mask,
            PRISM_UNK_BUFFER_ID, NULL,
            0, 0, 0, C_FL_PRIO_LDFL,
            C_FL_ENT_LOCAL);

    return 0;
}

void 
prism_send_port_info(void *key UNUSED, void *port_arg, void *u_arg)
{
    struct cbuf *b;
    struct prism_edge_port_info *edge_port_info;
    size_t len = 0;
    uint64_t dpid = *(uint64_t*) u_arg;
    prism_port_t *port = (prism_port_t*) port_arg;
    
    len = sizeof(struct prism_edge_port_info); 
  
    b = alloc_cbuf(len);

    edge_port_info = cbuf_put(b, len);
	edge_port_info->hdr.version = OFP_VERSION;
    edge_port_info->hdr.cmd = PRISM_PORT_CONFIG_REPLAY;
    edge_port_info->hdr.len = htons(len);
    edge_port_info->dpid = htonll(dpid);

    edge_port_info->port.port_no = htons(port->port_no);
    edge_port_info->port.config  = htonl(port->config);
    edge_port_info->port.state   = htonl(port->state);
    memcpy(edge_port_info->port.hw_addr, port->hw_addr, ETH_ADDR_LEN);

    if(prism_app_service_send(prism_ctx->prism_agent_service, b, false,
                PRISM_SERVICE_SUCCESS)) {
        app_log_err("%s: Error in sending DPID %llx Port %d info to Prism Agent", FN,
                U642ULL(dpid), port->port_no);
        return;
    } 
    app_log_debug("%s:DPID %llx Port %d Config %u State %u sent", FN,
                            U642ULL(dpid), port->port_no, port->config,
                            port->state);
}

void 
prism_send_edge_node_msg(void *key UNUSED, 
                         struct prism_switch *prism_sw, 
                         void *arg UNUSED)
{
    prism_traverse_all_switch_ports(prism_sw, prism_send_port_info,
            &prism_sw->dpid);
}

/**
 * __prism_traverse_all_switch -
 *
 * Loop through all switch and call iter_fn for each
 */
static void
__prism_traverse_all_switch(prism_app_struct_t *prism_ctx, GHFunc iter_fn, void *arg)
{
    if (prism_ctx->switch_htbl) {
        g_hash_table_foreach(prism_ctx->switch_htbl,
                             (GHFunc)iter_fn, arg);
    }
}

/**
 * prism_traverse_all_switch -
 *
 * Loop through all switch and call iter_fn for each
 */
void
prism_traverse_all_switch(prism_app_struct_t *prism_ctx, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&prism_ctx->lock);
    __prism_traverse_all_switch(prism_ctx, iter_fn, arg);
    c_rd_unlock(&prism_ctx->lock);
}

/**
 * prism_switches_reset -
 *
 * Reset all the switches struct 
 */
void
prism_switches_reset(prism_app_struct_t *ctx) 
{
    c_wr_lock(&ctx->lock);
    g_hash_table_destroy(ctx->switch_htbl);
    ctx->switch_htbl = NULL;
    c_wr_unlock(&ctx->lock);

    prism_switches_init(ctx);

    app_log_debug("%s: ", FN);
}


/**
 * prism_switches_init -
 *
 * Initialize the switches struct
 */
int
prism_switches_init(prism_app_struct_t *prism_ctx)
{
    assert(prism_ctx);

    prism_ctx->switch_htbl = g_hash_table_new_full(prism_dpid_hash_func,
                                              prism_dpid_eq_func,
                                              NULL, prism_switch_put);
    assert(prism_ctx->switch_htbl);
    return 0;
}

