/*
 *  mul_nbapi_fabric.h: Mul Northbound Fabric Manager API application headers
 *  Copyright (C) Kulcloud <engg@kulcloud.net>
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
#ifndef __MUL_NBAPI_FABRIC_H__
#define __MUL_NBAPI_FABRIC_H__

#include "mul_app_interface.h"
#include "glib.h"
#include "mul_nbapi_swig_helper.h"

#ifdef SWIG

#endif

MUL_NBAPI_PYLIST_RETURN( c_ofp_host_mod , nbapi_fabric_host_list_t )

nbapi_fabric_host_list_t get_fabric_host_all(int active);
int add_fabric_host(uint64_t datapath_id,
				uint16_t tenant_id,
				uint16_t network_id,
                struct flow *fl,
                int is_gw);

int delete_fabric_host(uint64_t datapath_id,
		        uint16_t tenant_id,
				uint16_t network_id,
                struct flow *fl);

#endif
