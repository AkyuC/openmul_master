/*
 * mul_nbapi_topology.h: Mul Northbound Static Path API application headers
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
#ifndef __MUL_NBAPI_PATH_H__
#define __MUL_NBAPI_PATH_H__

#include "mul_app_interface.h"
#include "glib.h"
#include "mul_route.h"
#include "mul_nbapi_swig_helper.h"

#ifdef SWIG

#endif

typedef struct nbapi_path_elem
{
	uint32_t switch_alias;
	uint16_t ingress_port_no;
	uint16_t egress_port_no;
} nbapi_path_elem_t;
MUL_NBAPI_PYLIST_RETURN( nbapi_path_elem , nbapi_path_elem_list_t )

nbapi_path_elem_list_t get_simple_path(int src_sw_alias, 
									uint16_t src_port_no, 
									int dest_sw_alias, 
									uint16_t dest_port_no);






#endif
