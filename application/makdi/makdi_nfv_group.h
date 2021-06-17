/*
 *  makdi_nfv_group.h: makdi nfv group logic headers
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
#ifndef __MAKDI_NFV_GROUP_H__
#define __MAKDI_NFV_GROUP_H__

struct nfv_group_key
{
    char name[MAX_NFV_NAME];
};
typedef struct nfv_group_key nfv_group_key_t;

struct nfv_group_ent
{
    nfv_group_key_t key;
    int active_nfvs;
    c_atomic_t ref;
    GHashTable *nfvs;
};
typedef struct nfv_group_ent nfv_group_ent_t;

struct nfv_key
{
    uint64_t dpid;
    uint16_t oif;
    uint16_t iif;
};
typedef struct nfv_key nfv_key_t;

struct nfv_ent_group_find_iter
{
    nfv_key_t nfv_key;
    void *group_owner;
    bool present;
    int count;
};
typedef struct nfv_ent_group_find_iter nfv_ent_group_find_iter_t;

struct nfv_ent
{
    nfv_key_t key;
    bool      inactive;
    char      name[MAX_NFV_NAME];
    c_atomic_t ref;
#define NFV_ENT_GROUP_NAME(ent) (((nfv_group_ent_t *)((ent)->nfv_group))->key.name)
    void      *nfv_group;
};
typedef struct nfv_ent nfv_ent_t;

void nfv_group_key_init(nfv_group_ent_t *nfv_group, const char *name);
nfv_group_ent_t *nfv_group_ent_alloc(const char *name);
nfv_group_ent_t *__nfv_group_get(makdi_hdl_t *hdl, const char *name);
void nfv_group_ent_put(void *ent);
int nfv_group_add(makdi_hdl_t *hdl, const char *name);
int nfv_group_del(makdi_hdl_t *hdl, const char *name);
void nfv_group_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg);
void nfv_group_traverse_all_writer(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg);
void __nfv_group_traverse_all(makdi_hdl_t *hdl, GHFunc iter_fn, void *arg);
void nfv_group_all_dump_nfvs(makdi_hdl_t *hdl);
void __makdi_app_per_group_info(void *k, void *group, void *arg);
void __makdi_app_per_group_stats_info(void *k, void *group, void *arg);

void nfv_dump_print(void *k, void *ent_arg, void *u_arg);
void nfv_dump_msg(void *k, void *ent_arg, void *uarg);
int __nfv_add(makdi_hdl_t *hdl, const char *group_name,
              const char *name, uint64_t dpid,
              uint16_t iif, uint16_t oif,
              bool lock);
int nfv_add(makdi_hdl_t *hdl, const char *group_name,
            const char *name, uint64_t dpid, uint16_t iif,
            uint16_t oif);
int nfv_del(makdi_hdl_t *hdl, const char *group_name,
            const char *name, uint64_t dpid,
            uint16_t oif, uint16_t iif);
nfv_ent_t *__nfv_ent_get_from_group(makdi_hdl_t *hdl, const char *group_name,
                                    bool ref);
void __nfv_group_nfv_count_update(nfv_group_ent_t *group_ent);
void mark_nfv_inactive_in_group_port_ev(void *key UNUSED, void *nfv_group,
                                        void *uarg);
void mark_nfv_active_in_group_port_ev(void *key UNUSED, void *nfv_group,
                                      void *uarg);
void mark_nfv_inactive_in_group_dpid_ev(void *key UNUSED, void *nfv_group,
                                        void *uarg);
void mark_nfv_active_in_group_dpid_ev(void *key UNUSED, void *nfv_group,
                                      void *uarg);

int makdi_nfv_group_init(makdi_hdl_t *makdi_hdl);

#endif
