/*
 *  makdi_user_services.h: makdi user service header
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
#ifndef __MAKDI_USER_SERVICES_H__
#define __MAKDI_USER_SERVICES_H__

struct service_key
{
    char name[MAX_SERVICE_NAME];
};
typedef struct service_key service_key_t;

struct service_ent
{
    service_key_t key;
    c_atomic_t    ref;
    uint16_t      vlan;
    GSList        *usr_list;
    GSList        *nfv_list;
};
typedef struct service_ent service_ent_t;

int service_add(makdi_hdl_t *hdl, const char *name, uint16_t serv_id);
int service_del(makdi_hdl_t *hdl, const char *name);
void service_stats_collect_cb(void *arg, void *pbuf);
service_ent_t *service_ent_get(makdi_hdl_t *hdl, char *name);
service_ent_t *__service_ent_get(makdi_hdl_t *hdl, char *name);
void service_ent_put(void *ent);
void service_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg);
service_ent_t * __service_ent_get_by_id(makdi_hdl_t *hdl, uint16_t vlan);
void service_dump_all(makdi_hdl_t *hdl, void *arg);
void service_chain_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg);
void __makdi_app_per_service_info(void *_key UNUSED, void *service, void *arg);
int makdi_nfv_service_init(makdi_hdl_t *hdl);

#endif
