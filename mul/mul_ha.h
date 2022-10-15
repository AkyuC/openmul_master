/*
 *  mul_ha.h: MUL HA logic header
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
#ifndef __MUL_HA_H__
#define __MUL_HA_H__

#define C_HA_TAKEOVER_TIMEO (10)

#define C_HA_TIMEO 0
#define C_HA_TIMEO_US 250000 

uint64_t c_ha_generation_id_init(void);
void c_ha_get_of_state(uint32_t *role, uint64_t *gen_id);
void __c_ha_proc(struct cbuf *b, bool use_cbuf, bool force);
void c_ha_proc(struct cbuf *b);
void c_ha_state_machine(ctrl_hdl_t *c_hdl);
void c_ha_init(void *base);
void c_ha_rcv_peer_state(void *app_arg, struct cbuf *b);
void c_ha_rcv_state_req(void *app_arg);
void c_ha_notify(ctrl_hdl_t *c_hdl, void *app);
void c_ha_per_sw_sync_state(void *k, void *v, void *arg);
void c_ha_req_switch_state(uint64_t dpid);
void c_ha_switch_state_sync_done(uint64_t dpid);
void c_ha_generation_id_update(uint64_t gen_id, size_t inc);

#endif
