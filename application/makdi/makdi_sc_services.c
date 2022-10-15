/*
 *  makdi_user_services.c: makdi application for MUL Controller 
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>,
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

static void
service_key_init(service_ent_t *service, const char *name)
{
    strncpy(service->key.name, name, MAX_SERVICE_NAME-1);
    service->key.name[MAX_SERVICE_NAME-1] = '\0';
}

static service_ent_t *
service_ent_alloc(const char *name, uint16_t vlan)
{
    service_ent_t *ent;

    ent = calloc(1, sizeof(*ent));
    if (ent) {
        service_key_init(ent, name);
        ent->vlan = vlan;
    }

    return ent;
}

void
service_ent_put(void *ent)
{
    service_ent_t *service = ent;

    if (atomic_read(&service->ref) == 0){
        if (service->usr_list)
            g_slist_free(service->usr_list);
        free(ent);
    } else {
        atomic_dec(&service->ref, 1);
    }
}

static int
__service_add(makdi_hdl_t *hdl, const char *name, uint16_t vlan, bool lock)
{
    service_ent_t *ent;

    ent = service_ent_alloc(name, vlan);
    if (!ent) {
        c_log_err("[service-add] Cant alloc service");
        return -1;
    }

    if(lock) c_wr_lock(&hdl->lock);

    if (g_hash_table_lookup(hdl->service_htbl, &ent->key)) {
        if(lock) c_wr_unlock(&hdl->lock);
        c_log_err("[service-add] service (%s) exists", name);
        service_ent_put(ent);
        return -1;
    }

    g_hash_table_insert(hdl->service_htbl, &ent->key, ent);
    if(lock) c_wr_unlock(&hdl->lock);

    return 0;
}

int
service_add(makdi_hdl_t *hdl, const char *name, uint16_t vlan)
{
    return __service_add(hdl, name, vlan, true);
}

int
service_del(makdi_hdl_t *hdl, const char *name)
{
    service_ent_t ent;
    service_ent_t *eent;
    GSList *iter = NULL;
    s_user_ent_t *u_ent;

    service_key_init(&ent, name);

    c_wr_lock(&hdl->lock);
    if (!(eent = g_hash_table_lookup(hdl->service_htbl, &ent.key))) {
        c_wr_unlock(&hdl->lock);
        c_log_err("[service-del] no such service (%s)", name);
        return -1;
    }
    if (hdl->s_user_htbl) {
        for (iter = eent->usr_list; iter; iter = iter->next) {
            u_ent = iter->data;
            g_hash_table_remove(hdl->s_user_htbl, &u_ent->key);
        }
    }
    g_hash_table_remove(hdl->service_htbl, &ent.key);
    c_wr_unlock(&hdl->lock);

    return 0;
}

service_ent_t *
__service_ent_get(makdi_hdl_t *hdl, char *name)
{
    service_ent_t l_ent, *ent = NULL;
    service_key_init(&l_ent, name);

    if (hdl->service_htbl) {
        ent = g_hash_table_lookup(hdl->service_htbl, &l_ent.key);
        if (ent) {
            atomic_inc(&ent->ref, 1);
        }
    }
    return ent;
}

service_ent_t *
service_ent_get(makdi_hdl_t *hdl, char *name)
{
    service_ent_t *ent;
    c_rd_lock(&hdl->lock);
    ent = __service_ent_get(hdl, name);
    c_rd_unlock(&hdl->lock);
    return ent;
}

static void UNUSED
service_find_by_vlan(void *key UNUSED, void *ent, void *uarg)
{
    service_ent_t *service_ent = ent;
    service_ent_t *r_service_ent = uarg;

    if (service_ent->vlan == r_service_ent->vlan) {
        memcpy(r_service_ent, service_ent, sizeof(service_ent_t));
    }
}

static int
service_entry_from_tbl(void *service_arg, void *v_arg UNUSED, void *u_arg)
{
    service_ent_t *service_ent = service_arg;
    uint16_t serv_id = *(uint16_t *)u_arg;

    if(serv_id == service_ent->SERV_ID)
        return true;
    else
        return false;
}

service_ent_t *
__service_ent_get_by_id(makdi_hdl_t *hdl, uint16_t serv_id)
{
    service_ent_t *ent = NULL;

    if (hdl->service_htbl) {
        ent = g_hash_table_find(hdl->service_htbl,
                                service_entry_from_tbl,
                                &serv_id);
    }
    return ent;
}

void
service_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&hdl->lock);
    if (hdl->service_htbl) {
        g_hash_table_foreach(hdl->service_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&hdl->lock);

    return;
}

void
service_chain_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&hdl->lock);
    if (hdl->s_user_htbl) {
        g_hash_table_foreach(hdl->s_user_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&hdl->lock);

    return;
}

void
service_stats_collect_cb(void *arg, void *pbuf)
{
    struct c_ofp_service_stats_show *service_stats = arg;
    struct c_ofp_flow_info *cofp_fi = pbuf;

    memcpy(&service_stats->stats, cofp_fi, sizeof(*cofp_fi));
}

static void
show_service_info_log(void *key UNUSED, void *service, void *uarg UNUSED)
{
    service_ent_t *ent = service;

    c_log_info("%s: service(%s) vlan(0x%hu) ",
               FN, ent->key.name, ent->vlan);
}

void
service_dump_all(makdi_hdl_t *hdl, void *arg UNUSED)
{
    service_traverse_all(hdl, show_service_info_log, arg);
}

static void
makdi_app_send_service_all(service_ent_t *service, void *arg)
{
    struct makdi_iter_arg *iter_arg = arg;
    struct c_ofp_service_info *service_info;
    struct c_ofp_auxapp_cmd *cofp_auc = NULL;
    struct cbuf *b;

	b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*service_info),
				C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *) (b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MAKDI_SHOW_SERVICE);
    service_info = (void *)(cofp_auc->data);

    service_info->vlan = htons(service->vlan);
	strncpy(service_info->service, service->key.name, MAX_NFV_NAME);

    iter_arg->send_cb((iter_arg)->serv, b);
}

void
__makdi_app_per_service_info(void *_key UNUSED, void *service, void *arg)
{
    struct makdi_iter_arg *iter_arg = arg;
    service_ent_t *service_ent = service;

    makdi_app_send_service_all(service_ent, iter_arg);
}

int
makdi_nfv_service_init(makdi_hdl_t *hdl)
{
    hdl->service_htbl = g_hash_table_new_full(g_str_hash, g_str_equal,
                                              NULL, service_ent_put);
    assert(hdl->service_htbl);
    return 0;
}
