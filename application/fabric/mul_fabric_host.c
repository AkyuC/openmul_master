/**
 *  @file mul_fabric_host.c
 *  @brief Mul fabric host manager   
 *  @author Dipjyoti Saikia  <dipjyoti.saikia@gmail.com> 
 *  @copyright Copyright (C) 2012, Dipjyoti Saikia 
 *
 * @license This program is free software; you can redistribute it and/or
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
 *
 *
 * @see www.openmul.org
 */
#include "mul_fabric_common.h"

extern fab_struct_t *fab_ctx;

/**
 * @name fab_dump_single_host
 * @brief Dump a single host 
 */
char *
fab_dump_single_host(fab_host_t *host)
{
    char     *pbuf = calloc(1, HOST_PBUF_SZ);
    int      len = 0;
    uint8_t tenant_id[FAB_UUID_STR_SZ], network_id[FAB_UUID_STR_SZ];

    uuid_unparse((const uint8_t*) host->tenant_id, 
                 (char *)tenant_id);
    uuid_unparse((const uint8_t*) host->network_id, 
                 (char *)network_id);

    len += snprintf(pbuf+len, HOST_PBUF_SZ-len-1,
                    "Tenant %s, Network %s, TNid %u host-ip 0x%-8x,host-mac "
                    "%02x:%02x:%02x:%02x:%02x:%02x on switch "
                    "0x%016llx %4d port %4hu (%s) (%s)\r\n",
                    tenant_id, network_id,
                    host->hkey.tn_id,
                    host->hkey.host_ip,
                    host->hkey.host_mac[0], host->hkey.host_mac[1],
                    host->hkey.host_mac[2], host->hkey.host_mac[3],
                    host->hkey.host_mac[4], host->hkey.host_mac[5],
                    (unsigned long long)(host->sw.swid), host->sw.alias,
                    host->sw.port,
                    host->dfl_gw?"dfl-gw":"non-gw",
                    host->dead ? "dead":"alive");
    assert(len < HOST_PBUF_SZ-1);

    return pbuf;
}

/**
 * @name fab_dump_single_host_to_flow
 * @brief Dump a single host to a flow struct
 */
void
fab_dump_single_host_to_flow(fab_host_t *host, struct flow *fl,
                             uint64_t *dpid)
{

    *dpid = host->sw.swid;
    fl->in_port = htons(host->sw.port);
    fl->ip.nw_src = htonl(host->hkey.host_ip);
    memcpy(fl->dl_src, host->hkey.host_mac, 6);
    fl->FL_DFL_GW = host->dfl_gw;
}

/**
 * @name fab_tenant_nw_hash_fn
 * @brief Hash function for a tenant network 
 * @param [in] key Key pointer which is tenant network
 *
 */
unsigned int                     
fab_tenant_nw_hash_func(const void *key)
{
    const fab_tenant_net_t *tenant_nw = key;

    return tenant_nw->tn_id;
}   

/**
 * @name fab_tenant_nw_hash_fn
 * @brief Hash function for a tenant network 
 * @param [in] key Key pointer which is tenant network
 */
unsigned int                     
fab_tenant_nw_uuid_hash_func(const void *key)
{
    return hash_bytes(key, sizeof(uuid_t), 1);
} 
/**
 * @name fab_tenant_nw_equal_fn
 * @brief Check and return true if two tenant networks are equal 
 * @param [in] key1 Key pointer which is tenant network
 * @param [in] key2 Key pointer which is tenant network
 *
 * @retval int 0 = equal 1 = not equal 
 */
int 
fab_tenant_nw_equal_func(const void *key1, const void *key2)
{       
    const fab_tenant_net_t *t1 = key1;
    const fab_tenant_net_t *t2 = key2;

    return t1->tn_id == t2->tn_id;
}  

/**
 * @name fab_tenant_nw_put
 * @brief Remove reference to a tenant network 
 * @tenant_nw : Tenant network pointer
 *
 * @retval void Nothing 
 */
static void
fab_tenant_nw_put(fab_tenant_net_t *tenant_nw)
{
    if(!atomic_read(&tenant_nw->ref)) {
        free(tenant_nw);
    } else {
        atomic_dec(&tenant_nw->ref, 1);
    }
}

/**
 * @name __fab_tenant_nw_loop_all_hosts
 * @brief Loop over all hosts of a tenant and invoke callback for each
 * @param [in] tenant_nw Tenant network pointer
 * @param [in] iter_fn Iteration callback for each host of a tenant
 * @param [in] u_data User arg to be passed to iter_fn
 *
 * @retval void Nothing 
 *
 * NOTE - lockless version and assumes fab_ctx lock as held
 */
void
__fab_tenant_nw_loop_all_hosts(fab_tenant_net_t *tenant_nw, GFunc iter_fn,
                               void *u_data)
{
    if (tenant_nw->host_list) {
        g_slist_foreach(tenant_nw->host_list,
                        (GFunc)iter_fn, u_data);
    }
}


/**
 * @name fab_host_unref
 * @brief Remove a reference to a host
 * @param [in] host : Host pointer 
 *
 * @retval void Nothing 
 */
static void
fab_host_unref(fab_host_t *host)
{
    fab_tenant_net_t *ten_nw = host->tenant_nw;
 
    if (!atomic_read(&host->ref)) {
        c_log_debug("%s: Host Destroyed (TNID %u: ip(0x%x) "
                  "mac(%02x:%02x:%02x:%02x:%02x:%02x:",
                  FN, host->hkey.tn_id, host->hkey.host_ip,
                  host->hkey.host_mac[0], host->hkey.host_mac[1],
                  host->hkey.host_mac[2], host->hkey.host_mac[3],
                  host->hkey.host_mac[4], host->hkey.host_mac[5]);
        if (ten_nw) {
            ten_nw->host_list = g_slist_remove(ten_nw->host_list, host);
            fab_tenant_nw_put(ten_nw);
        }
        fab_free(host);
    } else {
        atomic_dec(&host->ref, 1);
    }
}

/**
 * @name fab_host_ref
 * @brief Increment a reference to a host 
 * @param [in] host Pointer to fab_host_t
 *
 * @retval void Nothing
 */
static void
fab_host_ref(fab_host_t *host)
{
    atomic_inc(&host->ref, 1);
}


/**
 * @name __fab_loop_all_hosts
 * @brief Loop through all known hosts and call iter_fn for each
 * @param [in] fab_ctx fabric context pointer 
 * @param [in] iter_fn iteration function for each host 
 * @param [in] arg argument to be passed to iter_fn 
 *
 * @retval void Nothing
 * NOTE - This does not hold any locks 
 */
void
__fab_loop_all_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    if (fab_ctx->host_htbl) {
        g_hash_table_foreach(fab_ctx->host_htbl,
                             (GHFunc)iter_fn, arg);
    }
}

/**
 * @name fab_loop_all_hosts 
 * @brief Loop through all known hosts and call iter_fn for each
 * @param [in] fab_ctx Fabric app context pointer 
 * @param [in] iter_fn iteration function for each host 
 * @arg [in] argument to be passed to iter_fn 
 *
 * @retval void Nothing
 * NOTE - This function can only be used as long as iter_fn
 * does not require any global list manipulations eg host add/del etc. 
 */
void
fab_loop_all_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&fab_ctx->lock);
    __fab_loop_all_hosts(fab_ctx, iter_fn, arg);
    c_rd_unlock(&fab_ctx->lock);
}


/**
 * @name __fab_loop_inactive_all_hosts
 * @brief Loop through all known hosts and call iter_fn for each
 * @param [in] fab_ctx Fabric context pointer
 * @param [in] iter_fn iteration function for each host
 * @param [in] arg argument to be passed to iter_fn
 *
 * @retval void Nothing
 * NOTE - This function does not hold global ctx lock
 */
void
__fab_loop_all_inactive_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    if (fab_ctx->inact_host_htbl) {
        g_hash_table_foreach(fab_ctx->inact_host_htbl,
                             (GHFunc)iter_fn, arg);
    }
}

/**
 * @name fab_loop_inactive_all_hosts
 * @brief Loop through all known hosts and call iter_fn for each 
 * @param [in] fab_ctx fabric context pointer 
 * @param [in] iter_fn iteration function for each host 
 * @param [in] arg argument to be passed to iter_fn 
 *
 * @retval void Nothing
 * NOTE - This function can only be used as long as iter_fn
 * does not require any global list manipulations eg host add/del etc. 
 */
void
fab_loop_all_inactive_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&fab_ctx->lock);
    __fab_loop_all_inactive_hosts(fab_ctx, iter_fn, arg);
    c_rd_unlock(&fab_ctx->lock);
}

/**
 * @name fab_loop_all_hosts_wr
 * @brief Loop through all known hosts and call iter_fn for each for writing 
 *        any global list manipulations eg host add/del etc
 * @param [in] fab_ctx fabric context pointer
 * @param [in] iter_fn iteration function for each host
 * @param [in] arg argument to be passed to iter_fn
 *
 * @retval void Nothing
 */
void
fab_loop_all_hosts_wr(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    c_wr_lock(&fab_ctx->lock);
    if (fab_ctx->host_htbl) {
        g_hash_table_foreach(fab_ctx->host_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_wr_unlock(&fab_ctx->lock);
}

/**
 * @name fab_host_get 
 * @brief Increment ref-count of a host
 * @param [in] host fabric host pointer
 *
 * @retval void Nothing
 */
void
fab_host_get(fab_host_t *host)
{
    atomic_inc(&host->ref, 1);
}

/**
 * @name fab_host_put
 * @brief Decrement ref count of a host
 * @param [in] host: fabric host pointer
 *
 * @retval void Nothing
 */
void
fab_host_put(fab_host_t *host)
{
    if (host) fab_host_unref(host);
}

/**
 * @name fab_host_put_locked
 * @brief Version of fab_host_put() with locks taken
 * @param [in] host: fabric host pointer
 *
 * @retval void Nothing
 */
void
fab_host_put_locked(fab_host_t *host)
{
    c_wr_lock(&fab_ctx->lock);
    fab_host_unref(host);
    c_wr_unlock(&fab_ctx->lock);
}

/**
 * @name fab_host_hash_func
 * @brief Derive a hash val from a host key
 * @param [in] key: fabric host hash key 
 *
 * @retval int hash-value 
 */
unsigned int                     
fab_host_hash_func(const void *key)
{
    const fab_host_t *host = key;

    return hash_bytes(host, sizeof(fab_hkey_t), 1);
}   

/**
 * @name fab_host_equal_func - 
 * @brief Deduce if two hosts are equal
 * @param [in] key1: fabric host1 hash key 
 * @param [n] key2: fabric host2 hash key 
 *
 * @retval int 0 if equal else not equal 
 */
int 
fab_host_equal_func(const void *key1, const void *key2)
{       
    return !memcmp(key1, key2, sizeof(fab_hkey_t) - 6);
}  

/**
 * @name __fab_host_delete
 * @brief Delete a fabric host. wrapper over fab_host_put 
 * @param [in] data: host pointer 
 *
 * @retval void Nothing
 * NOTE - Unlocked version and assumes fab_ctx lock held
 */
void
__fab_host_delete(void *data)
{
    fab_host_put((fab_host_t *)data);
} 

/**
 * @name fab_host_create
 * @brief Allocate and initialize a host struct
 */
static fab_host_t *
fab_host_create(uint64_t dpid, uint32_t sw_alias, struct flow *fl, 
        uint8_t *tenant_id, uint8_t *network_id)
{
    fab_host_t *host;

    host = fab_zalloc(sizeof(fab_host_t));

    c_rw_lock_init(&host->lock);
    host->sw.swid = dpid;
    host->sw.alias = sw_alias;
    host->sw.port = ntohl(fl->in_port);
    FAB_MK_TEN_NET_ID(host->hkey.tn_id, 
                      fab_tenant_nw_uuid_hash_func(tenant_id), 
                      fab_tenant_nw_uuid_hash_func(network_id)); 
    host->hkey.host_ip = ntohl(fl->ip.nw_src);
    memcpy(host->hkey.host_mac, fl->dl_src, 6);
    memcpy(host->tenant_id, tenant_id, sizeof(uuid_t));
    memcpy(host->network_id, network_id, sizeof(uuid_t));
    host->dfl_gw = fl->FL_DFL_GW;

    return host;
}

/**
 * @name fab_host_clone_prop -
 * @brief Clone src host properties to dst host  
 *
 * Note: Tenant network and host routes would not be cloned
 */
static fab_host_t * 
fab_host_clone_prop(fab_host_t *dst, fab_host_t *src)
{
    if (!dst) {
        dst = fab_zalloc(sizeof(fab_host_t));
    } else {
        memset(dst, 0, sizeof(*dst)); 
    }

    c_rw_lock_init(&dst->lock);
    memcpy(&dst->sw, &src->sw, sizeof(fab_host_sw_t));
    memcpy(&dst->hkey, &src->hkey, sizeof(fab_hkey_t));
    dst->dfl_gw = src->dfl_gw;
    dst->dead = src->dead;

    return dst;
}

/**
 * @name fab_host_cmp_association -
 * @brief Check if two hosts have same associated switch and port
 */
static bool UNUSED
fab_host_cmp_association(fab_host_t *host1, fab_host_t *host2)
{
    if (host1->sw.swid == host2->sw.swid &&
        host1->sw.alias == host2->sw.alias &&
        host1->sw.port == host2->sw.port && 
        host1->dfl_gw == host2->dfl_gw) {
        return true;
    }

    return false;
}

/**
 * @name fab_host_delete_inactive - 
 * @brief Delete an inactive fabric host 
 * @param [in] fab_ctx : fab context pointer 
 * @param [in] lkup_host : host instance
 * @param [in] locked : flag to specify whether fab_ctx is already held or not
 *
 * @retval int zero if no error else non-zero
 */
int
fab_host_delete_inactive(fab_struct_t *fab_ctx, fab_host_t *lkup_host, 
                         bool locked) 
{
    fab_host_t *host;
    int err = 0;
    char *host_pstr;

    if (!locked) c_wr_lock(&fab_ctx->lock);

    if (!(host = g_hash_table_lookup(fab_ctx->inact_host_htbl, lkup_host))) {
        app_rlog_debug("%s: No such inactive host", FN);
        err = -1;
        goto done;
    } 

    host_pstr = fab_dump_single_host(host);
    app_log_debug("%s: Inactive Host deleted %s", FN, host_pstr);
    free(host_pstr);

    if (host->tenant_nw) {
        host->tenant_nw->host_list =
                g_slist_remove(host->tenant_nw->host_list, host);
        fab_tenant_nw_put(host->tenant_nw);
        host->tenant_nw = NULL;
    }
    g_hash_table_remove(fab_ctx->inact_host_htbl, host);

done:
    if (!locked) c_wr_unlock(&fab_ctx->lock);

    return err;

}

/**
 * @name fab_host_delete - 
 * @brief Delete a fabric host
 * @parama [in] fab_ctx: fab context pointer 
 * @param [in] dpid: switch dpid to the connected host
 * @param [in] sw_alias: switch alias id to the connected host
 * @param [un] fl: struct flow defining a host 
 * @param [in] locked: flag to specify whether fab_ctx is already held or not
 * @param [in] deactivate: flag to specify whether to only deactivate not delete 
 *
 * @retval int zero if no error else non-zero
 */
int
fab_host_delete(fab_struct_t *fab_ctx, struct flow *fl, 
                uint8_t *tenant_id, uint8_t *network_id,
                bool locked, bool deactivate, bool sync_ha) 
{
    fab_host_t *lkup_host, *host;
    char *host_pstr;
    int err = 0;
    bool dont_free = false;
    fab_port_t *port;
    fab_switch_t *sw;
    struct fab_host_service_arg iter_arg = { false, NULL,
                                             (send_cb_t)mul_app_ha_proc };
    
    lkup_host = fab_host_create(0, 0, fl, tenant_id, network_id);
    if (sync_ha && mul_app_is_master()) {
        fabric_service_send_host_info(lkup_host, NULL, &iter_arg);
    }   
    
    if (!locked) c_wr_lock(&fab_ctx->lock);

    if (!(host = g_hash_table_lookup(fab_ctx->host_htbl, lkup_host))) {
        if (!deactivate) {
            err = fab_host_delete_inactive(fab_ctx, lkup_host, true);
        } else {
            app_log_debug("%s: No active host", FN);
            err = -1;
        }
        goto done;
    }

    host->dead = true;
    __fab_host_route_delete(host, NULL, fab_ctx);
    __fab_del_pending_routes_tofro_host(fab_ctx, host);

    if (host->tenant_nw) {
        host->tenant_nw->host_list =
            g_slist_remove(host->tenant_nw->host_list, host);
        fab_tenant_nw_put(host->tenant_nw);
        host->tenant_nw = NULL;
    }

    if (deactivate) {
        fab_host_clone_prop(lkup_host, host);
        host_pstr = fab_dump_single_host(lkup_host);
        app_log_debug("%s: Host Active->Inactive %s", FN, host_pstr);
        free(host_pstr);
        fab_host_add_inactive(fab_ctx, lkup_host, true);
        dont_free = true;
    } else {

        /* Force port off the host and hence its host ref */
        if ((sw = __fab_switch_get(fab_ctx, host->sw.swid))) {
            c_rd_lock(&sw->lock);
            if ((port = __fab_port_find(fab_ctx, sw, host->sw.port)) &&
                port->host == host) { 
                fab_host_put(port->host);
                port->host = NULL;
            }
            fab_switch_put_locked(sw);
            c_rd_unlock(&sw->lock);
        }

        host_pstr = fab_dump_single_host(lkup_host);
        app_log_debug("%s: Host Deleted %s", FN, host_pstr);
        free(host_pstr);
    }

    g_hash_table_remove(fab_ctx->host_htbl, host);
    
done:
    if (!locked) c_wr_unlock(&fab_ctx->lock);

    if (!dont_free) fab_free(lkup_host);

    return err;
} 

/**
 * @name fab_host_on_switch
 * @retval true if switch connected to this host
 */
static int UNUSED
fab_host_on_switch(void *h_arg, void *v_arg UNUSED, void *u_arg)
{
    fab_host_t *host = h_arg;
    uint64_t dpid = *(uint64_t *)u_arg;

    if (!host->no_scan && host->sw.swid == dpid)  return true;

    return false;
}

/**
 * @name fab_host_on_switch_port - 
 * @retval Returns true if switch port connected to this host
 */
static int
fab_host_on_switch_port(void *h_arg, void *v_arg UNUSED, void *u_arg)
{
    fab_host_t *host = h_arg;
    fab_host_sw_t *sw = u_arg;

    if (!host->no_scan &&
        host->sw.swid == sw->swid &&
        host->sw.port == sw->port)
        return true;

    return false;
}

/**
 * @name fab_host_reset_scan_ban
 * @brief Resets the scan ban in a host for certain conditions
 *        to avoid infinite loops
 */
static void UNUSED
fab_host_reset_scan_ban(void *h_arg, void *v_arg UNUSED, void *arg UNUSED)
{
    fab_host_t *host = h_arg;

    host->no_scan = false;
}


/**
 * @name fab_activate_all_hosts_on_switch_port -
 * @brief Activate all inactive hosts that were connected to a switch-port
 * @param [in] fab_ctx: fabric context pointer
 * @param [in] dpid: switch-dpid
 * @param [in] port: port-num
 *
 * @retval void Nothing
 */
void
fab_activate_all_hosts_on_switch_port(fab_struct_t *fab_ctx, uint64_t dpid,
                                      uint16_t port)
{
    fab_host_t *host;
    fab_host_sw_t host_sw = { dpid, 0, port }; /* alias  unused */
    struct flow fl;
    fab_switch_t *fab_sw;
    uuid_t tenant_id, network_id;

    if (!(fab_sw = fab_switch_get(fab_ctx, dpid))) {
        app_rlog_err("%s: Invalid switch", FN);
        return;
    }

    c_wr_lock(&fab_ctx->lock);
    while ((host = g_hash_table_find(fab_ctx->inact_host_htbl,
                                     fab_host_on_switch_port,
                                     &host_sw))) {
        memset(&fl, 0, sizeof(fl));
        fl.ip.nw_src = htonl(host->hkey.host_ip);
        fl.in_port = htons(host->sw.port);
        fl.FL_DFL_GW = host->dfl_gw;
        memcpy(fl.dl_src, host->hkey.host_mac, 6);
        memcpy(tenant_id, host->tenant_id, sizeof(uuid_t));
        memcpy(network_id, host->network_id, sizeof(uuid_t));

        host->no_scan = true; /* Double confirm  we dont loop forever */
        fab_host_delete_inactive(fab_ctx, host, true);

        app_rlog_debug("%s: Activating a host", FN);

        /* Delete host if we cant activate */ 
        __fab_host_add(fab_ctx, fab_sw->dpid, &fl, (uint8_t*)tenant_id,
                (uint8_t*)network_id, false);
    } 

    fab_switch_put_locked(fab_sw);
    c_wr_lock(&fab_ctx->lock);
}

/**
 * @name fab_host_add_to_tenant_nw
 * @brief Add a host to a tenant network
 */
static void
fab_host_add_to_tenant_nw(fab_struct_t *fab_ctx, fab_host_t *host)
{
    fab_tenant_net_t *tenant_nw = NULL;
    uint8_t tenant_id[FAB_UUID_STR_SZ], network_id[FAB_UUID_STR_SZ];

    uuid_unparse((const uint8_t *)host->tenant_id, (char *)tenant_id);
    uuid_unparse((const uint8_t *)host->network_id, (char *)network_id);

    assert(fab_ctx->tenant_net_htbl);
    if (!(tenant_nw = g_hash_table_lookup(fab_ctx->tenant_net_htbl,
                                       &(host->hkey.tn_id)))) {
        tenant_nw = fab_zalloc(sizeof(fab_tenant_net_t));

        tenant_nw->tn_id = host->hkey.tn_id;
        memcpy(tenant_nw->tenant_id, host->tenant_id, sizeof(uuid_t));
        memcpy(tenant_nw->network_id, host->network_id, sizeof(uuid_t));
        g_hash_table_insert(fab_ctx->tenant_net_htbl, tenant_nw, tenant_nw);
        app_rlog_info("New tenant-nw tenant %s network %s", tenant_id, network_id);
    } else {
        app_log_debug("Existing tenant nw");
    }

    atomic_inc(&tenant_nw->ref, 1);
    host->tenant_nw = tenant_nw;
    tenant_nw->host_list = g_slist_append(tenant_nw->host_list, host);
}


/**
 * @name fab_host_add_active
 * @brief Add a fabric host to active 
 * @param [in] fab_ctx: fab context pointer 
 * @param [in] host: host instance
 * @param [in] dpid: switch dpid to the connected host
 * @param [in] locked: Flag to denote if called under global lock
 *
 * @retval int zero if no error else non-zero
 */
static int
fab_host_add_active(fab_struct_t *fab_ctx, fab_host_t *host, uint64_t dpid, 
                    bool locked)
{
    fab_switch_t *sw;
    fab_port_t *port;
    fab_host_t *exist_host = NULL;
    bool install_route_pair = true;
    char *host_pstr;

    if (!locked) c_wr_lock(&fab_ctx->lock);

    fab_host_delete_inactive(fab_ctx, host, true);

    if(!(sw = __fab_switch_get(fab_ctx, dpid))) {
        app_rlog_err("%s:Switch(0x%llx) not valid", FN, U642ULL(dpid));
        goto out_invalid_sw;
    } 

    c_rd_lock(&sw->lock);

    if (!(port = __fab_port_find(fab_ctx, sw, host->sw.port))) {
        app_rlog_err("%s:Switch(0x%llx):port(%x) not valid", FN,
                  (unsigned long long)dpid,  host->sw.port);
        goto out_invalid_sw_port;
    }
    app_rlog_err("%s:Switch(0x%llx):port(%x) valid", FN,
                  (unsigned long long)dpid,  host->sw.port);

    assert(fab_ctx->host_htbl);
    if ((exist_host = g_hash_table_lookup(fab_ctx->host_htbl, host))) {
        host_pstr = fab_dump_single_host(host);
        app_log_debug("%s: Known Host %s", FN, host_pstr);
        free(host_pstr);
        exist_host = NULL;
        goto out_host_exists;
    }

    host->sw.alias = sw->alias;

    exist_host = port->host;
    port->host = host;
    fab_host_ref(host);

    g_hash_table_insert(fab_ctx->host_htbl, host, host);
    fab_host_add_to_tenant_nw(fab_ctx, host);

    __fab_routes_tofro_host_add(host, NULL, &install_route_pair);

    host_pstr = fab_dump_single_host(host);
    app_log_debug("%s: Host Added %s", FN, host_pstr);
    free(host_pstr);

out_host_exists:

    c_rd_unlock(&sw->lock);
    fab_switch_put_locked(sw);

    if (!locked) c_wr_unlock(&fab_ctx->lock);

    if (exist_host) {
        struct flow fl;

        app_rlog_info("%s: Overwriting exisitng port<->host association", FN);
        fl.ip.nw_src = htonl(exist_host->hkey.host_ip);
        memcpy(fl.dl_src, exist_host->hkey.host_mac, 6);
        fab_host_delete(fab_ctx, &fl, exist_host->tenant_id,
                exist_host->network_id, locked, false, false);
        fab_host_put(exist_host);
    }

    return 0;

out_invalid_sw_port:
    fab_switch_put_locked(sw);
    c_rd_unlock(&sw->lock);
out_invalid_sw:
    if (!locked) c_wr_unlock(&fab_ctx->lock);
    return -1;
}

/**
 * @name fab_host_add_inactive
 * @brief Add a fabric host to active 
 * @param [in] fab_ctx: fab context pointer 
 * @param [in] host: host instance
 * @param [in] locked: Flag to denote if called under global lock
 *
 * @retval int zero if no error else non-zero
 */
int
fab_host_add_inactive(fab_struct_t *fab_ctx, fab_host_t *host, bool locked)
{
    fab_host_t *exist_host = NULL;
    char *host_pstr;
    int ret = 0;

    if (!locked) c_wr_lock(&fab_ctx->lock);

    if ((exist_host = g_hash_table_lookup(fab_ctx->inact_host_htbl, host))) {
        host_pstr = fab_dump_single_host(host);
        ret = -1;
        app_rlog_err("%s: Known Host (%s) already inactive", FN, host_pstr);
        goto done;

    }

    host->dead = true;
    host->tenant_nw = NULL;
    //fab_host_add_to_tenant_nw(fab_ctx, host);
    host_pstr = fab_dump_single_host(host);
    app_rlog_info("%s: Host Added as Inactive %s", FN, host_pstr);
    free(host_pstr);
    g_hash_table_insert(fab_ctx->inact_host_htbl, host, host);

done:
    if (!locked) c_wr_lock(&fab_ctx->lock);

    return ret;

}


/**
 * @name __fab_host_add - 
 * @brief Add a fabric host 
 * @param [in] fab_ctx: fab context pointer 
 * @param [in] dpid: switch dpid to the connected host
 * @param [in] fl: flow defining a host 
 * @param [in] always_add: Add to inactive list if host can not be active
 *
 * @retval int zero if no error else non-zero
 */
int
__fab_host_add(fab_struct_t *fab_ctx, uint64_t dpid, struct flow *fl,
        uint8_t *tenant_id, uint8_t *network_id,
                bool always_add) 
{
    struct fab_host_service_arg iter_arg = { true, NULL, 
                                             (send_cb_t)mul_app_ha_proc };
    fab_host_t *host = NULL;
    int err = 0;

    host = fab_host_create(dpid, FAB_INV_SW_ALIAS, fl, tenant_id, network_id);

    if (fab_host_add_active(fab_ctx, host, dpid, true)) {
        if (always_add &&
            !fab_host_add_inactive(fab_ctx, host, true)) {
            goto done;
        }
            
        fab_free(host);
        err = -1; 
    } 

done:
    if (!err) {
        /* FIXME : Prior handling of any error in HA installation */
        if (mul_app_is_master())
            fabric_service_send_host_info(host, NULL, &iter_arg);       
    }
    return err;
}

/**
 * @name fab_host_add - 
 * @brief Add a fabric host with explicit locking
 * @param [in] fab_ctx: fab context pointer 
 * @param [in] dpid: switch dpid to the connected host
 * @param [in] fl: flow defining a host 
 * @param [in] always_add: Add to inactive list if host can not be active
 *
 * @retval int zero if no error else non-zero
 */
int
fab_host_add(fab_struct_t *fab_ctx, uint64_t dpid, struct flow *fl,
             uint8_t *tenant_id, uint8_t *network_id, bool always_add) 
{
    int err = 0;
    c_wr_lock(&fab_ctx->lock);
    err = __fab_host_add(fab_ctx, dpid, fl, tenant_id, network_id, always_add);
    c_wr_unlock(&fab_ctx->lock);
    return err;
}

/**
 * @name __fab_loop_all_tenant_nw
 * @brief Loop through all known tenant_nw and call iter_fn for each
 * @param [in] fab_ctx : fabric context pointer 
 * @param [in] iter_fn : iteration function for each host 
 * @param [in] arg : arg to be passed to iter_fn 
 *
 * @retval void Nothing
 * NOTE - This does not hold any locks 
 */
void
__fab_loop_all_tenant_nw(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    if (fab_ctx->tenant_net_htbl) {
        g_hash_table_foreach(fab_ctx->tenant_net_htbl,
                             (GHFunc)iter_fn, arg);
    }
}

/**
 * @name fab_loop_all_tenant_nw - 
 * @brief Loop through all known teanant_nw and call iter_fn for each
 * @param [in] fab_ctx : fabric context pointer 
 * @param [in] iter_fn : iteration function for each host 
 * @param [in] arg : arg to be passed to iter_fn 
 *
 * @retval void Nothing
 * NOTE - This function can only be used as long as iter_fn
 * does not require any global list manipulations eg host add/del etc. 
 */
void
fab_loop_all_tenant_nw(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&fab_ctx->lock);
    __fab_loop_all_tenant_nw(fab_ctx, iter_fn, arg);
    c_rd_unlock(&fab_ctx->lock);
}

/**
 * @name fab_port_tnid_hash_func - 
 * @brief Derive a hash val from a port_tnid key 
 * @param [in] key: fabric port_tnid hash key 
 *
 * @retval int hash value 
 */
unsigned int
fab_port_tnid_hash_func(const void *key)
{
    const fab_port_tnid_t *pt_hkey = key;
    return hash_bytes(pt_hkey, sizeof(fab_pt_hkey_t), 1);
}

/**
 * @name fab_port_tnid_equal_func - 
 * @brief Deduce if two hosts are equal
 * @param [in] key1: fabric port_tnid1 hash key 
 * @param [in] key2: fabric port_tnid2 hash key 
 *
 * @retval 0 if equal else non-zero
 */
int
fab_port_tnid_equal_func(const void *key1, const void *key2)
{
    return !memcmp(key1, key2, sizeof(fab_pt_hkey_t));
}

/**
 * @name __fab_loop_all_port_tnids - 
 * @brief Loop through all known port_tnids and call iter_fn for each
 * @param [in] fab_ctx : fabric context pointer 
 * @param [in] iter_fn : iteration function for each host 
 * @param [in] arg : arg to be passed to iter_fn 
 *
 * @retval void Nothing
 * NOTE - This does not hold any locks
 */
void
__fab_loop_all_port_tnids(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    if (fab_ctx->port_tnid_htbl) {
    g_hash_table_foreach(fab_ctx->port_tnid_htbl,
                 (GHFunc)iter_fn, arg);
    }
}

/**
 * @name fab_loop_all_port_tnids
 * @brief Loop through all known port_tnids and call iter_fn for each
 *        with explicit locking
 * @param [in] fab_ctx : fabric context pointer 
 * @param [in] iter_fn : iteration function for each host 
 * @param [in] arg : arg to be passed to iter_fn 
 *
 * @retval void Nothing
 *
 * NOTE - This function can only be used as long as iter_fn
 * does not require any global list manipulations eg host add/del etc. 
 */
void
fab_loop_all_port_tnids(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&fab_ctx->lock);
    __fab_loop_all_port_tnids(fab_ctx, iter_fn, arg);
    c_rd_unlock(&fab_ctx->lock);
}

/**
 * @name __fab_port_tnid_add
 * @brief Add a fabric port_tnid 
 * @param [in] fab_ctx: fab context pointer 
 * @param [in] tenant_id : tenant id
 * @param [in] tetwork_id : network id
 * @param [datapath_id] : switch dpid to the connected host
 * @param [in] port : port number 
 *
 * @retval int zero if no error else non-zero
 */
int
__fab_port_tnid_add(fab_struct_t *fab_ctx, uint8_t *tenant_id, uint8_t *network_id,
          uint64_t datapath_id, uint32_t port)
{
    fab_port_tnid_t *port_tnid = NULL;
    fab_port_tnid_t lkup_host;
    memset(&lkup_host, 0, sizeof(fab_port_tnid_t));

    memcpy(lkup_host.tenant_id, tenant_id, sizeof(uuid_t));
    memcpy(lkup_host.network_id, network_id, sizeof(uuid_t));
    lkup_host.pt_hkey.datapath_id = datapath_id;
    lkup_host.pt_hkey.port = port;
    assert(fab_ctx->port_tnid_htbl);
    if(!(port_tnid = g_hash_table_lookup(fab_ctx->port_tnid_htbl, 
                                         &lkup_host))) {
        port_tnid = fab_zalloc(sizeof(fab_port_tnid_t));
        memcpy(port_tnid, &lkup_host, sizeof(fab_port_tnid_t));
        g_hash_table_insert(fab_ctx->port_tnid_htbl, port_tnid, port_tnid);
        app_rlog_info("New port-tnid( %llx, %hu)",
                      U642ULL(port_tnid->pt_hkey.datapath_id), 
                      port_tnid->pt_hkey.port);
    } else {
        app_rlog_info("already exist( %llx, %u) ", 
                      U642ULL(port_tnid->pt_hkey.datapath_id), 
                      port_tnid->pt_hkey.port);
        return -1;
    }
   return 0;   
}

/**
 * @name fab_port_tnid_add - 
 * @brief Add a fabric port_tnid with explicit locking
 * @param [in] fab_ctx: fab context pointer 
 * @param [in] tenant_id : tenant id
 * @param [in] network_id : network id
 * @param [in] datapath_id : switch dpid to the connected host
 * @param [in] port : port number 
 *
 * @retval int zero if no error else non-zero
 */
int
fab_port_tnid_add(fab_struct_t *fab_ctx, uint8_t *tenant_id, uint8_t *network_id,
        uint64_t datapath_id, uint32_t port)
{
    int err = 0;

    c_wr_lock(&fab_ctx->lock);
    err = __fab_port_tnid_add(fab_ctx, tenant_id, network_id,
                              datapath_id, port);
    c_wr_unlock(&fab_ctx->lock);

    return err;
}

/**
 * @name  __fab_port_tnid_delete - 
 * @brief Delete a fabric port tnid
 * @param [in] fab_ctx : fab context pointer
 * @param [in] tenant_id : tenant id
 * @param [in] network_id : network id
 * @param [in] datapath_id : switch dpid to the connected host
 * @param [in] port : port number  
 *
 * @retval int zero if no error else non-zero
 */
int
__fab_port_tnid_delete(fab_struct_t *fab_ctx, uint8_t *tenant_id, uint8_t *network_id,
            uint64_t datapath_id, uint32_t port)
{
    fab_port_tnid_t *port_tnid = NULL;
    fab_port_tnid_t lkup_host;
    memset(&lkup_host, 0, sizeof(fab_port_tnid_t));

    memcpy(lkup_host.tenant_id, tenant_id, sizeof(uuid_t));
    memcpy(lkup_host.network_id, network_id, sizeof(uuid_t));
    lkup_host.pt_hkey.datapath_id = datapath_id;
    lkup_host.pt_hkey.port = port;

    assert(fab_ctx->port_tnid_htbl);
    if((port_tnid = g_hash_table_lookup(fab_ctx->port_tnid_htbl,
                                        &lkup_host))){
        g_hash_table_remove(fab_ctx->port_tnid_htbl, port_tnid);
    } else {
        return -1;
    }
    return 0;
}

/**
 * @name fab_port_tnid_delete - 
 * @brief Delete a fabric port_tnid with explicit locking
 * @param [in] fab_ctx : fab context pointer
 * @param [in] tenant_id : tenant id
 * @param [in] network_id : network id
 * @param [in] datapath_id : switch dpid to the connected host
 * @param [in] port : port number  
 *
 * @retval int zero if no error else non-zero
 */
int
fab_port_tnid_delete(fab_struct_t *fab_ctx, uint8_t *tenant_id, uint8_t *network_id,
           uint64_t datapath_id, uint32_t port)
{
    int err = 0;

    c_wr_lock(&fab_ctx->lock);
    err = __fab_port_tnid_delete(fab_ctx, tenant_id, network_id, datapath_id, port);
    c_wr_unlock(&fab_ctx->lock);
    return err;
}

/**
 * @name __fab_port_get_tnid
 * @brief Get tenant id and network id with datapath_id and port in port_tnid table 
 * @param [in] fab_ctx : fab context pointer
 * @param [in] datapath_id : switch dpid to the connected host
 * @param [in] port : port number  
 *
 * @retval fab_port_tnid_t *  Pointer to a port tnid
 */
fab_port_tnid_t * 
__fab_port_get_tnid(fab_struct_t *fab_ctx, uint64_t datapath_id, uint32_t port)
{
    fab_port_tnid_t lkup_port;
    fab_port_tnid_t * ret_port = NULL;

    app_rlog_info("%s : dpid - 0x%llx, port - %u",FN, U642ULL(datapath_id), port);

    memset(&lkup_port, 0, sizeof(fab_port_tnid_t));
    lkup_port.pt_hkey.datapath_id = datapath_id;
    lkup_port.pt_hkey.port = port;
    ret_port = g_hash_table_lookup(fab_ctx->port_tnid_htbl, &lkup_port);

    return ret_port;
}

/**
 * @name fab_port_get_tnid
 * @brief  Get tenant id and network id with datapath_id and 
           port in port_tnid table with explicit locking
 * @param [in] fab_ctx : fab context pointer
 * @param [in] datapath_id : switch dpid to the connected host
 * @param [in] port : port number  
 *
 * @retval fab_port_tnid_t *  Pointer to a port tnid
 */
fab_port_tnid_t *
fab_port_get_tnid(fab_struct_t *fab_ctx, uint64_t datapath_id, uint32_t port)
{
    fab_port_tnid_t * ret_port;

    c_rd_lock(&fab_ctx->lock);
    ret_port = __fab_port_get_tnid(fab_ctx, datapath_id, port);
    c_rd_unlock(&fab_ctx->lock);
    return ret_port;
}

/**
 * @name fab_find_host_route 
 * @brief  Find a host route for a given host  
 */
void
fab_find_host_route(fab_struct_t *fab_ctx, struct flow *fl,
                    uint8_t *tenant_id, uint8_t *network_id,
                    GFunc iter_fn, void* arg)
{
    fab_host_t *lkup_host, *host;

    lkup_host = fab_host_create(0,0, fl, tenant_id, network_id);

    c_rd_lock(&fab_ctx->lock);
    if ((host = g_hash_table_lookup(fab_ctx->host_htbl, lkup_host))) {
        fab_loop_all_host_routes(host, iter_fn, arg);
    }
    c_rd_unlock(&fab_ctx->lock);

    fab_free(lkup_host);
}
