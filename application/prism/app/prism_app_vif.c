/*
 *  prism_app_vif.c: PRISM application for MUL Controller 
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
#include "prism_app_vif.h"

/**
 * prism_dump_single_vif- 
 * @vif: Pointer to vif element 
 *
 * Dumps the information of Virtual Interface
 */

char *
prism_dump_single_vif(prism_vif_elem_t *vif)
{
    char     *pbuf = calloc(1, VIF_PBUF_SZ);
    int len = 0;

    len += snprintf(pbuf+len, VIF_PBUF_SZ - len - 1,
        "VIF-mac 0x%02x:%02x:%02x:%02x:%02x:%02x"
        " conn-dpid 0x%lx Outport %u Flags %u\n",
        vif->vif_mac[0], vif->vif_mac[1], vif->vif_mac[2],
        vif->vif_mac[3], vif->vif_mac[4], vif->vif_mac[5],vif->hkey.dpid,
        vif->hkey.port, vif->vif_flags);
    assert(len < VIF_PBUF_SZ);

    return pbuf;

}

/**
 * prism_vif_hash_func- 
 * @key: Prism Virtual I/F hash key 
 *
 * Derive a hash val from vif key 
 */
unsigned int                     
prism_vif_hash_func(const void *key)
{
    const prism_vif_elem_t *vif_elem = key;

    return hash_bytes(vif_elem, sizeof(prism_vif_hash_key_t), 1);
}

/**
 * prism_vif_equal_func - 
 * @key1: prism  Virtual Interface1 hash key 
 * @key2: prism  Virtual Interface2 hash key 
 *
 * Deduce if two  Virtual Interface are equal
 */
int 
prism_vif_equal_func(const void *key1, const void *key2)
{       
    return !memcmp(key1, key2, sizeof(prism_vif_hash_key_t));
} 

/**
 * prism_compare_vif_key-
 *
 * Key comparison function for  Virtual Interface
 */
int
prism_compare_vif_key(void *h_arg, void *v_arg UNUSED, void *u_arg)
{
    prism_vif_hash_key_t *key = u_arg;
    prism_vif_elem_t *vif_elem = h_arg;

    if(vif_elem->hkey.port == key->port &&
       vif_elem->hkey.dpid == key->dpid)
        return true;

    return false;
}

/**
 * __prism_vif_add-
 *
 * Service handler for  Virtual Interface resolved state
 */
unsigned int
__prism_vif_add(prism_app_struct_t *prism_ctx, uint64_t dpid,
                   uint32_t port, uint32_t vif_flags, uint8_t *mac_addr)
{
    prism_vif_elem_t *vif_elem = NULL;
    prism_vif_hash_key_t vif_key;

    memset(&vif_key, 0, sizeof(prism_vif_hash_key_t));
 
    /* Prepare  Virtual Interface Key*/
    vif_key.dpid = dpid;
    vif_key.port = port;
        
    if(!(vif_elem = g_hash_table_lookup(prism_ctx->vif_hasher_db,
                                   &vif_key))) {

        /*No VIF entry present*/
        vif_elem = calloc(1, sizeof(prism_vif_elem_t));
        assert(vif_elem);

        vif_elem->hkey = vif_key;
        vif_elem->vif_flags = vif_flags;
        memcpy(vif_elem->vif_mac, mac_addr, ETH_ADDR_LEN);

        /* Store a new entry for Virtual Interface*/
        g_hash_table_insert(prism_ctx->vif_hasher_db, vif_elem, vif_elem);

        vif_elem = g_hash_table_lookup(prism_ctx->vif_hasher_db, &vif_key);

        app_log_info("%s: VIF entry dpid (%llx) port (%u)",
                FN, U642ULL(vif_elem->hkey.dpid), vif_elem->hkey.port);

    }
    else {
        app_log_info("%s: VIF entry already present dpid (%llx) port (%u)",
                FN,(unsigned long long)dpid, vif_elem->hkey.port);
        return PRISM_DUP_VIF;
    }

    return 0;
}

/**
 * prism_vif_add-
 *
 * Service handler for Virtaul Interface add
 */

unsigned int
prism_vif_add(prism_app_struct_t *prism_ctx, uint64_t dpid,
                   uint32_t port,uint32_t vif_flags, uint8_t *mac_addr)
{
    uint32_t code = 0;
    c_wr_lock(&prism_ctx->lock);
    code = __prism_vif_add(prism_ctx, dpid, port, vif_flags, mac_addr);
    c_wr_unlock(&prism_ctx->lock);

    return code;
}

/**
 * prism_vif_del-
 *
 * Service handler for virtual interface del
 */
unsigned int
__prism_vif_del(prism_app_struct_t *prism_ctx, uint64_t dpid,
                   uint32_t port)
{
    prism_vif_hash_key_t vif_key;
    prism_vif_elem_t *vif_elem = NULL;
    
    memset(&vif_key, 0, sizeof(prism_vif_hash_key_t));
    
    /* Prepare Virtual Interface Key*/
    vif_key.dpid = dpid;
    vif_key.port = port;

    if((vif_elem = g_hash_table_find(prism_ctx->vif_hasher_db,
                prism_compare_vif_key,
                &vif_key))) {
        g_hash_table_remove(prism_ctx->vif_hasher_db, vif_elem);
    }
    else {
        app_log_err("%s: Virtual Interface dpid (%llx) Port (%u) not present",
                FN, (unsigned long long)dpid, port);
        return PRISM_VIF_NOT_EXIST;
    }
    
    return 0;
}

/**
 * prism_vif_del-
 *
 * Service handler for  Virtual Interface resolved state
 */

unsigned int
prism_vif_del(prism_app_struct_t *prism_ctx, uint64_t dpid,
                   uint32_t port)
{
    uint32_t code = 0;
    c_wr_lock(&prism_ctx->lock);
    code = __prism_vif_del(prism_ctx, dpid, port);
    c_wr_unlock(&prism_ctx->lock);

    return code;
}

/**
 * __prism_vif_modify-
 *
 * Service handler for virtual interface modification
 */
unsigned int
__prism_vif_modify(prism_app_struct_t *prism_ctx, uint64_t dpid,
                   uint32_t port, uint32_t vif_flags, uint8_t *mac_addr,
                   bool update_ip, uint32_t intf_ip)
{
    prism_vif_elem_t *vif_elem = NULL;
    prism_vif_hash_key_t vif_key;
    memset(&vif_key, 0, sizeof(prism_vif_hash_key_t));
 
    /* Prepare  Virtual Interface Key*/
    vif_key.dpid = dpid;
    vif_key.port = port;

    if((vif_elem = g_hash_table_lookup(prism_ctx->vif_hasher_db,
                    &vif_key))) {

        if(update_ip) {
            vif_elem->intf_ip_addr = intf_ip;
        } else {
            vif_elem->vif_flags = vif_flags;
            memcpy(vif_elem->vif_mac, mac_addr, ETH_ADDR_LEN);
        }
    }
    else {
        app_log_info("%s: VIF entry not present dpid (%llx) port (%u)",
                FN,(unsigned long long)dpid, port);
        return PRISM_VIF_NOT_EXIST;
    }

    return 0;
}


/**
 * prism_vif_modify-
 *
 * Service handler for Virtaul Interface modify
 */

unsigned int
prism_vif_modify(prism_app_struct_t *prism_ctx, uint64_t dpid,
                   uint32_t port,uint32_t vif_flags, uint8_t *mac_addr,
                   bool update_ip, uint32_t intf_ip)
{
    uint32_t code = 0;
    c_wr_lock(&prism_ctx->lock);
    code = __prism_vif_modify(prism_ctx, dpid, port, vif_flags, mac_addr,
                              update_ip, intf_ip);
    c_wr_unlock(&prism_ctx->lock);

    return code;
}


/**
 * __prism_loop_all_vif -
 * @prism_ctx  : Pointer to Prism APP context
 * @iter_fn    : Iteration callback 
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all  Virtual Interface and invoke callback for each
 * NOTE - lockless version and assumes prism_ctx lock as held
 */
void
__prism_loop_all_vif(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
                               void *u_data)
{
    if (prism_ctx->vif_hasher_db) {
        g_hash_table_foreach(prism_ctx->vif_hasher_db,
                        (GHFunc)iter_fn, u_data);
    }
}

/**
 * prism_loop_all_vif-
 * @prism_ctx  : Pointer to Prism APP context
 * @iter_fn    : Iteration callback 
 * @u_data     : User arg to be passed to iter_fn
 *
 * Loop over all  Virtual Interface and invoke callback for each
 */
void
prism_loop_all_vif(prism_app_struct_t *prism_ctx, GHFunc iter_fn,
                               void *u_data)
{
    c_wr_lock(&prism_ctx->lock);
    __prism_loop_all_vif(prism_ctx, iter_fn, u_data);
    c_wr_unlock(&prism_ctx->lock);
}

/**
 * prism_app_vif_init-
 *
 * Reads virtual Interfaces info from file and stores them in Prism CTX
 */

void
prism_app_vif_init(prism_app_struct_t *prism_ctx)
{
    FILE *fp;
    char buf[2048];
    char *tmp1, *tmp2, *name;
	uint64_t dpid;
	uint32_t port;
    uint8_t dummy_mac[ETH_ADDR_LEN];

    memset(dummy_mac, 0, ETH_ADDR_LEN);

    fp = fopen(PRISM_VIF_FILE, "r");
    if (!fp) {
        app_log_err("%s: File open error", FN);
        return;
    }
       
	while (fgets(buf, sizeof(buf), fp) != NULL) {

        if((buf[0] == '#') || (buf[0] == ' ') || (buf[0] == '\n'))
            continue;
		
		tmp1 = strtok(buf, "|");
        tmp2 = strtok(NULL, "|");
        name = strtok(NULL, "|\n");
		dpid = strtoull(tmp1, NULL, 16);
		port = atoi(tmp2);
		fprintf(stdout,"dpid : %lx , port: %d\n", dpid, port);
		
        if (prism_vif_add(prism_ctx, dpid, port, 0, dummy_mac) < 0) {
            app_log_err("%s: Failed to add VIF, DPID:%llx Port: %u %s", FN,
                    U642ULL(dpid), port, name);
        }
          
    }

    fclose(fp);
}
