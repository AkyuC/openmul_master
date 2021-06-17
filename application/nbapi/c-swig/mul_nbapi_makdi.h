/*
 *  mul_nbapi_makdi.h: Mul Northbound Makdi API headers
 *  Copyright (C) Dipjyoti Saikia <dipjyoti.saikia@gmail.com> 
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
#ifndef __MUL_NBAPI_MAKDI_H__
#define __MUL_NBAPI_MAKDI_H__

int nbapi_add_makdi_service(char *user_ip_str, char *dpid, char *port_str,
                            char *nfv0, char *nfv1, char *nfv2, char *nfv3,
                            char *nfv4, char *nfv5, char *nfv6, char *nfv7,
                            int nfv_size);
int nbapi_del_makdi_service(char *user_ip_str, char *dpid, char *port_str);

#endif
