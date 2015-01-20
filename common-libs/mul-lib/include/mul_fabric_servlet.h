/*
 * mul_fabric_servlet.h - MUL fabric service header
 * Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#ifndef  __MUL_FABRIC_SERVLET_H__
#define  __MUL_FABRIC_SERVLET_H__

#include "mul_common.h"
#include "mul_fabric_util.h"
#include "mul_route.h"
#include "mul_route_apsp.h"

#define FAB_DFL_PBUF_SZ (4096) 

int mul_fabric_host_mod(void *service, uint64_t dpid, struct flow *fl, 
        uint8_t *tenant_id, uint8_t *network_id, bool add);
int mul_fabric_show_hosts(void *service, bool active, bool dump_cmd, bool nbapi,
                           void *arg, void (*cb_fn)(void *arg, void *pbuf));
int mul_fabric_show_routes(void *service,
                       void *arg,
		       bool call_cb,
                       void (*show_src_host)(void *arg, char *pbuf),
                       void (*show_dst_host)(void *arg, char *pbuf),
                       void (*show_route_links)(void *arg, char *pbuf));
int mul_fabric_show_tenant_nw(void *service, void *arg, void (*cb_fn)(void *arg, void *pbuf));
int mul_fabric_port_tnid_mod(void *service, uint64_t dpid, uint32_t port,
        uint8_t *tenant_id,  uint8_t *network_id, bool add);
int mul_fabric_port_tnid_show(void *service, bool dump, void *arg, void (*cb_fn)(void *arg, void *pbuf));
int mul_fabric_show_host_routes(void *service, void *arg,
                                struct flow *fl, uint8_t *tenant_id, uint8_t *network_id,
                                void (*cb_fn)(void *arg, char *pbuf));
#endif
