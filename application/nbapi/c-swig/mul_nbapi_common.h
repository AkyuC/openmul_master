/*
 * mul_nbapi_common.h: Mul Northbound API Common Library headers
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

#ifndef __MUL_NBAPI_COMMON_H__
#define __MUL_NBAPI_COMMON_H__

#include "mul_common.h"
#include "mul_fabric_servlet.h"
#include "makdi_servlet.h"
#include "mul_servlet.h"
#include "mul_tr_servlet.h"
#include "mul_route.h"

#define NBAPI_APP_NAME "mul-nbapi"
#define NBAPI_SERVICE_NAME MUL_APP_NAME
#define NBAPI_CONF_FILE "mulnbapi.conf"

#define MUL_NB_TIMEO (2)

typedef struct {
    c_rw_lock_t   lock;
    void          *base;
    struct event  *nbapi_timer_event;
    mul_service_t *mul_service; /* Traffic-Routing Service Instance */
    mul_service_t *route_service; /* Route Service Instance */
    mul_service_t *fab_service; /* Fabric Service Instance */
    mul_service_t *tr_service; /* Traffic-Routing Service Instance */
    mul_service_t *makdi_service; /* Traffic-Routing Service Instance */
} nbapi_struct_t;

extern nbapi_struct_t *nbapi_app_data;
extern struct mul_app_client_cb nbapi_app_cbs;

GSList *gui_server_list;

void nbapi_module_init(void *ctx);

#endif
