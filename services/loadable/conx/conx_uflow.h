/*
 *  conx_uflow.h: Connector uflow module header file
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
#ifndef __CONX_UFLOW_H__
#define __CONX_UFLOW_H__

#define CONX_UFLOW_STALE_TIME (10)
#define CONX_UFLOW_STALE_TGR_TIME (12)

struct conx_ucookie_ent {
    uint32_t u_app_cookie;
    GSList *stale_list;
    struct event *stale_timer_event;
};
typedef struct conx_ucookie_ent conx_ucookie_ent_t;

struct uflow_iter_arg {
    GFunc uflow_iter_fn;
    void *uarg;
    bool stale;
    int ctr;
    conx_ucookie_ent_t *ucookie;
};

void conx_ucookie_hent_destroy(void *arg);
void conx_ufl_hent_destroy(void *e_arg);
void conx_uflow_scan(conx_ent_t *conx_ent, conx_ufl_hent_t *hent, bool active);
void conx_uflow_stale_begin(uint32_t cookie);

int conx_uflow_add(uint64_t src_dp,
               uint64_t dst_dp,
               struct flow *in_fl,
               struct flow *in_mask,
               uint32_t tunnel_key,
               uint32_t tunnel_type,
               uint32_t app_cookie,
               void *actions,
               size_t action_len,
               uint64_t flags,
               bool src_flow,
               uint16_t prio);

int conx_uflow_del(uint64_t src_dp,
                   uint64_t dst_dp,
                   struct flow *in_fl,
                   struct flow *in_mask,
                   uint64_t flags);

#endif
