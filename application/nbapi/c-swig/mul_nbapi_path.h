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
#include "mul_nbapi_swig_helper.h"
#include "mul_vty.h"
#include "glib.h"

#ifdef SWIG
    %newobject get_simple_path;
    %newobject get_switch_neighbor_all;
#endif

MUL_NBAPI_PYLIST_RETURN( rt_path_elem_ , nbapi_path_elem_list_t)
MUL_NBAPI_PYLIST_RETURN(c_ofp_port_neigh, nbapi_port_neigh_list_t)

nbapi_path_elem_list_t get_simple_path(int src_sw_alias, int dest_sw_alias);
nbapi_port_neigh_list_t get_switch_neighbor_all(uint64_t datapath_id);






#endif
