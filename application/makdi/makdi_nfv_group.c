/*
 *  makdi_nfv_group.c: makdi nfv group logic for MUL Controller 
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#include "makdi_common.h"

extern makdi_hdl_t *makdi_hdl;

static void check_nfv_exists_in_group(void *key, void *nfv_group, void *uarg);

static unsigned int
nfv_entry_hash(const void *p)
{
    const uint8_t *key = p;
    return hash_bytes(key, sizeof(nfv_key_t), 1);
}

static int
nfv_entry_equal(const void *p1, const void *p2)
{
    return !memcmp(p1, p2, sizeof(nfv_key_t));
}

static nfv_ent_t *
nfv_ent_alloc(const char *name, uint64_t dpid,
              uint16_t iif, uint16_t oif)
{
    nfv_ent_t *ent;

    ent = calloc(1, sizeof(*ent));
    if (!ent) return NULL;

    ent->key.dpid = dpid;
    ent->key.iif = iif;
    ent->key.oif = oif;

    strncpy(ent->name, name, MAX_NFV_NAME-1);
    ent->name[MAX_NFV_NAME-1] = '\0';

    return ent;
}

static void
nfv_ent_put(void *ent)
{
    free(ent);
}

int
__nfv_add(makdi_hdl_t *hdl, const char *group_name,
          const char *name, uint64_t dpid,
          uint16_t iif, uint16_t oif,
          bool lock)
{
    nfv_ent_t *ent = NULL, *eent = NULL;
    nfv_group_ent_t group_lkup_arg;
    nfv_group_ent_t *group_ent = NULL;
    nfv_ent_group_find_iter_t arg;

    memset(&arg, 0, sizeof(arg));
    nfv_group_key_init(&group_lkup_arg, group_name);

    if (lock) c_wr_lock(&hdl->lock);
    if (hdl->nfv_group_htbl) {
        group_ent = g_hash_table_lookup(hdl->nfv_group_htbl, &group_lkup_arg);
        if (!group_ent) {
            c_log_err("[nfv-add] No such group (%s)",
                      group_lkup_arg.key.name);
            if (lock) c_wr_unlock(&hdl->lock);
            return -1;
        }
    } else {
        if (lock) c_wr_unlock(&hdl->lock);
        return -1;
    }

    ent = nfv_ent_alloc(name, dpid, iif, oif);
    if (!ent) {
        c_log_err("[nfv-add] enomem");
        if (lock) c_wr_unlock(&hdl->lock); 
        return -1;
    }

    ent->nfv_group = group_ent;

    if ((eent = g_hash_table_lookup(group_ent->nfvs, ent))) {
        c_log_err("[nfv-add] already exists");
        if (lock) c_wr_unlock(&hdl->lock);
        nfv_ent_put(ent);
        return -1;
    }

    memcpy(&arg.nfv_key, &ent->key, sizeof(nfv_key_t));
    arg.group_owner = group_ent;
    __nfv_group_traverse_all(makdi_hdl, check_nfv_exists_in_group, &arg);
    if (arg.present) {
        c_log_err("[nfv-add] already exists in another group");
        if (lock) c_wr_unlock(&hdl->lock);
        nfv_ent_put(ent);
        return -1;
    }

    if (!c_app_switch_get_version_with_id(dpid)) {
        ent->inactive = true;         
    }

    g_hash_table_insert(group_ent->nfvs, ent, ent);
    __nfv_group_nfv_count_update(group_ent);
    if (lock) c_wr_unlock(&hdl->lock);

    c_log_info("[nfv-add] group_ent: group(%s) nfv: name(%s)",
               group_ent->key.name, ent->name);

    return 0;
}

int
nfv_add(makdi_hdl_t *hdl, const char *group_name,
        const char *name, uint64_t dpid, uint16_t iif,
        uint16_t oif)
{
    return __nfv_add(hdl, group_name, name, dpid, iif, oif, true);
}

int
nfv_del(makdi_hdl_t *hdl, const char *group_name,
        const char *name, uint64_t dpid,
        uint16_t oif, uint16_t iif)
{
    nfv_ent_t *ent, *eent = NULL;
    nfv_group_ent_t *group_ent, group_lkup_arg;
    int ret = 0;

    nfv_group_key_init(&group_lkup_arg, group_name);

    ent = nfv_ent_alloc(name, dpid, iif, oif);
    if (!ent) {
        c_log_err("[nfv-del] No mem: alloc fail");
        return -1;
    }
    c_wr_lock(&hdl->lock);
    if (hdl->nfv_group_htbl) {
        if ((group_ent = g_hash_table_lookup(hdl->nfv_group_htbl,
                                             &group_lkup_arg.key))) {
            if (!(eent = g_hash_table_lookup(group_ent->nfvs, ent))) {
                c_log_err("[nfv-del] No such NFV");
                ret = -1;
            } else {
                __sc_reset_all_users_with_nfv(&eent->key, true);
                g_hash_table_remove(group_ent->nfvs, eent);
                __nfv_group_nfv_count_update(group_ent);
            }
        } else {
            c_log_err("[nfv-del] No such group %s", group_name);
        }
    } else {
        ret = -1;
    }
    c_wr_unlock(&hdl->lock);
    nfv_ent_put(ent);
    return ret;
}

nfv_ent_t *
__nfv_ent_get_from_group(makdi_hdl_t *hdl, const char *group_name, bool ref)
{
    nfv_ent_t *ent;
    nfv_group_ent_t l_group_ent, *group_ent = NULL;
    int list_len = 0, num = 0, i = 0;
    GHashTableIter iter;
    gpointer key;

    if (!group_name) return NULL;

    nfv_group_key_init(&l_group_ent, group_name);

    if (hdl->nfv_group_htbl) {
        group_ent = g_hash_table_lookup(hdl->nfv_group_htbl,
                                        &l_group_ent.key);

        if (group_ent) {
            if (group_ent->nfvs)
                list_len = group_ent->active_nfvs;

            if (list_len) {
                // FIXME : Check inactive nfvs
                num = rand() % list_len;
                g_hash_table_iter_init(&iter, group_ent->nfvs);
                while (g_hash_table_iter_next(&iter, &key, NULL)) {
                    ent = key;
                    if (!ent->inactive) {
                        if (i++ == num) {
                            if (ref)
                                atomic_inc(&group_ent->ref, 1);
                            return (nfv_ent_t *)(key);    
                        }
                    }

                }
            }
        }

    }


    return NULL;
}

void
nfv_dump_print(void *k UNUSED, void *ent_arg, void *u_arg UNUSED)
{
    nfv_ent_t *nfv_ent = ent_arg;

    c_log_debug("[nfv-dump] %s nfv(%s:%s) dpid(0x%llx)(%lu:%lu)=>",
                nfv_ent->inactive ? "inactive" : "active",
                nfv_ent->name, NFV_ENT_GROUP_NAME(nfv_ent),
                U642ULL(nfv_ent->key.dpid), U322UL(nfv_ent->key.iif),
                U322UL(nfv_ent->key.oif));
}

void
nfv_dump_msg(void *k UNUSED, void *ent_arg, void *uarg)
{
    nfv_ent_t *nfv_ent = ent_arg;
    struct c_ofp_s_chain_nfv_list *nfv_list = uarg;
    struct c_ofp_s_chain_nfv_info *nfv_info;

    if (nfv_list->num_nfvs >= MAX_NFV) return;

    nfv_info = &nfv_list->nfv_info[nfv_list->num_nfvs];

    nfv_info->dpid = htonll(nfv_ent->key.dpid);
    strcpy(nfv_info->nfv_group, NFV_ENT_GROUP_NAME(nfv_ent));
    strcpy(nfv_info->nfv, nfv_ent->name);
    nfv_info->oif = htons((uint16_t)(nfv_ent->key.oif));
    nfv_info->iif = htons((uint16_t)(nfv_ent->key.iif));

    nfv_list->num_nfvs++;
    c_log_debug("%s: NFV(%s) NFV_GROUP(%s) dpid(0x%llx) iif(%hu) oif(%hu)",
                FN, nfv_ent->name, NFV_ENT_GROUP_NAME(nfv_ent),
                U642ULL(ntohll(nfv_info->dpid)),
                ntohs(nfv_info->iif), ntohs(nfv_info->oif));
}

static int
nfv_match_any_port(void *key, void *val UNUSED, void *key_m)
{
    nfv_key_t *key_ent = key;
    nfv_key_t *key_match = key_m;

    if (key_ent->dpid == key_match->dpid &&
        (key_ent->iif == key_match->iif ||
        key_ent->oif == key_match->oif)) {
        return true;
    }

    return false;
}

static int
nfv_match_dpid(void *key, void *val UNUSED, void *key_m)
{
    nfv_key_t *key_ent = key;
    nfv_key_t *key_match = key_m;

    if (key_ent->dpid == key_match->dpid) {
        return true;
    }

    return false;
}

void
__nfv_group_nfv_count_update(nfv_group_ent_t *group_ent)
{
    nfv_ent_t *ent;
    GHashTableIter iter;
    gpointer key, value;
    int count = 0;

    if (group_ent->nfvs) {
        g_hash_table_iter_init(&iter, group_ent->nfvs);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            ent = key;
            if (!ent->inactive) count++;
        }
    }

    c_log_debug("[sc-group] %s active-nfs %d", group_ent->key.name, count);
    group_ent->active_nfvs = count;;
}

static void
mark_nfv_in_group_for_ev(nfv_group_ent_t *group, void *key_arg,
                         bool dp_ev, bool alive)
{
    nfv_key_t *key =  key_arg;
    nfv_ent_t *ent = NULL;
    
    /* FIXME : Lookup should match any of the iif or oif in nfv */
    if (group->nfvs &&
        ((dp_ev && 
        (ent = g_hash_table_find(group->nfvs, nfv_match_dpid, key))) || 
        (ent = g_hash_table_find(group->nfvs, nfv_match_any_port, key)))) {
        ent->inactive = !alive;
        __nfv_group_nfv_count_update(group);
    }
}

static void
check_nfv_exists_in_group(void *key UNUSED, void *nfv_group, void *uarg)
{
    nfv_group_ent_t *group = nfv_group;
    nfv_ent_group_find_iter_t *arg = uarg;
    nfv_ent_t *ent = NULL;

    if (arg->group_owner &&
        arg->group_owner == nfv_group)
        return;

    if (group->nfvs &&
        (ent = g_hash_table_find(group->nfvs, nfv_match_any_port, key))) {
        arg->present = true;
        arg->count++;
    }
}

void
mark_nfv_inactive_in_group_port_ev(void *key UNUSED,
                                   void *nfv_group,
                                   void *uarg)
{
    mark_nfv_in_group_for_ev(nfv_group, uarg, false, false); 
}

void
mark_nfv_active_in_group_port_ev(void *key UNUSED,
                                 void *nfv_group,
                                 void *uarg)
{
    mark_nfv_in_group_for_ev(nfv_group, uarg, false, true);
}

void
mark_nfv_inactive_in_group_dpid_ev(void *key UNUSED,
                                   void *nfv_group,
                                   void *uarg)
{
    mark_nfv_in_group_for_ev(nfv_group, uarg, true, false); 
}

void
mark_nfv_active_in_group_dpid_ev(void *key UNUSED,
                                 void *nfv_group,
                                 void *uarg)
{
    mark_nfv_in_group_for_ev(nfv_group, uarg, true, true);
}

static void
nfv_dump_per_group(void *key UNUSED, void *nfv_group, void *uarg)
{
    nfv_group_ent_t *g_ent = nfv_group;

    if (!uarg) {
        c_log_debug(" ------ [GROUP] %s ref %d ----- ",
                    g_ent->key.name, (int)g_ent->ref);
    }

    g_hash_table_foreach(g_ent->nfvs,
                         uarg ? (GHFunc)nfv_dump_msg:
                                (GHFunc)nfv_dump_print,
                         uarg);
}

void
nfv_group_all_dump_nfvs(makdi_hdl_t *hdl)
{
    nfv_group_traverse_all(hdl, nfv_dump_per_group, NULL);
}

void
nfv_group_ent_put(void *ent)
{
    nfv_group_ent_t *nfv_group = ent;

    if (atomic_read(&nfv_group->ref) == 0){
        if (nfv_group->nfvs)
            g_hash_table_destroy(nfv_group->nfvs);
        nfv_group->nfvs = NULL;
        free(ent);
    } else {
        atomic_dec(&nfv_group->ref, 1);
    }
}

void
nfv_group_key_init(nfv_group_ent_t *nfv_group, const char *name)
{
    strncpy(nfv_group->key.name, name, MAX_NFV_NAME-1);
    nfv_group->key.name[MAX_NFV_NAME-1] = '\0';
}

nfv_group_ent_t *
nfv_group_ent_alloc(const char *name)
{
    nfv_group_ent_t *ent;

    ent = calloc(1, sizeof(*ent));
    if (!ent) return NULL;

    nfv_group_key_init(ent, name);
    ent->nfvs = g_hash_table_new_full(nfv_entry_hash, nfv_entry_equal,
                                      NULL, nfv_ent_put);
    if (!ent->nfvs) {
        free(ent);
        ent = NULL;
    }
    return ent;
}

nfv_group_ent_t * 
__nfv_group_get(makdi_hdl_t *hdl, const char *name)
{
    nfv_group_ent_t *ent;
    nfv_group_key_t key;

    nfv_group_key_init((nfv_group_ent_t *)&key, name); 

    ent = g_hash_table_lookup(hdl->nfv_group_htbl, &key);
    return ent;
}

static int
__nfv_group_add(makdi_hdl_t *hdl, const char *name)
{
    nfv_group_ent_t *ent;

    ent = nfv_group_ent_alloc(name);
    if (!ent) return -1;

    if (g_hash_table_lookup(hdl->nfv_group_htbl, &ent->key)) {
        c_log_err("%s: nfv_group (%s) exists", FN, name);
        nfv_group_ent_put(ent);
        return -1;
    }

    g_hash_table_insert(hdl->nfv_group_htbl, &ent->key, ent);

    return 0;
}

int
nfv_group_add(makdi_hdl_t *hdl, const char *name)
{
    int ret = 0;
    c_wr_lock(&hdl->lock);
    ret = __nfv_group_add(hdl, name);
    c_wr_unlock(&hdl->lock);
    return ret; 
}

int
nfv_group_del(makdi_hdl_t *hdl, const char *name)
{
    nfv_group_ent_t *lkup_ent = NULL;
    nfv_group_ent_t *ent = NULL;

    lkup_ent = nfv_group_ent_alloc(name);
    if (!lkup_ent) return -1;

    c_wr_lock(&hdl->lock);
    ent = g_hash_table_lookup(hdl->nfv_group_htbl, &lkup_ent->key);
    if (ent) {
        g_hash_table_remove(hdl->nfv_group_htbl, &ent->key);
    }
    c_wr_unlock(&hdl->lock);

    nfv_group_ent_put(lkup_ent);

    return 0;
}

void
__nfv_group_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    if (hdl->nfv_group_htbl) {
        g_hash_table_foreach(hdl->nfv_group_htbl,
                             (GHFunc)iter_fn, arg);
    } 
}

void
nfv_group_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&hdl->lock);
    __nfv_group_traverse_all(hdl, iter_fn, arg);
    c_rd_unlock(&hdl->lock);
    return;
}

void
nfv_group_traverse_all_writer(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    c_wr_lock(&hdl->lock);
    __nfv_group_traverse_all(hdl, iter_fn, arg);
    c_wr_unlock(&hdl->lock);
    return;
}

static void
makdi_app_send_group_all(nfv_group_ent_t *group, void *arg)
{
    struct makdi_iter_arg *iter_arg = arg;
    struct c_ofp_s_chain_nfv_group_info *group_info;
    struct c_ofp_auxapp_cmd *cofp_auc = NULL;
    struct cbuf *b;

	b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*group_info),
				C_OFPT_AUX_CMD, 0);
    
    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SHOW_NFV_GROUP);
    group_info = (void *)(cofp_auc->data);

    group_info->num_nfvs = 0;
    group_info->nfv_list.num_nfvs = 0;

    strncpy(group_info->nfv_group, group->key.name, MAX_NFV_NAME);
    nfv_dump_per_group(group, group, &group_info->nfv_list);

    iter_arg->send_cb((iter_arg)->serv, b);
}

static void
__nfv_stats_traverse_all(void *k UNUSED, void *nfv, void *uarg)
{
	nfv_ent_t *nfv_ent = nfv;
	struct cbuf **b = uarg;
    *b = mul_get_switch_port_stats(makdi_hdl->mul_service, 
                                   nfv_ent->key.dpid,
                                   (uint32_t)(nfv_ent->key.iif));
}

static void
__makdi_app_send_group_stats_all(nfv_group_ent_t *group, void *arg)
{

    struct makdi_iter_arg *iter_arg = arg;
    struct cbuf *b = NULL;

    if (group->nfvs) {
        g_hash_table_foreach(group->nfvs, __nfv_stats_traverse_all, &b);
        if (b)
            iter_arg->send_cb((iter_arg)->serv, b);
    }
}

void
__makdi_app_per_group_info(void *k UNUSED, void *group, void *arg)
{
    struct makdi_iter_arg *iter_arg = arg;
    nfv_group_ent_t *group_ent = group;

    makdi_app_send_group_all(group_ent, iter_arg);
}

void
__makdi_app_per_group_stats_info(void *k UNUSED, void *group, void *arg)
{
    struct makdi_iter_arg *iter_arg = arg;
    nfv_group_ent_t *group_ent = group;

    __makdi_app_send_group_stats_all(group_ent, iter_arg);
}

int
makdi_nfv_group_init(makdi_hdl_t *hdl)
{
    hdl->nfv_group_htbl = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                NULL, nfv_group_ent_put);
    assert(hdl->nfv_group_htbl);
    return 0;
}
