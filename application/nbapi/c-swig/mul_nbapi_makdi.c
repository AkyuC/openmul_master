/*
 *  mul_nbapi_makdi.c: Mul Northbound Makdi Application for Mul Controller
 *  Copyright (C) 2013, Dipjyoti Saikia (dipjyoti.saikia@gmail.com)
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
#include "mul_nbapi_common.h"
#include "mul_nbapi_makdi.h"

/**
 * nbapi_add_makdi_service -
 *
 * Add a makdi service 
 */ 
int
nbapi_add_makdi_service(char *user_ip_str, char *dpid_str, char *port_str,
                        char *nfv0, char *nfv1, char *nfv2, char *nfv3,
                        char *nfv4, char *nfv5, char *nfv6, char *nfv7,
                        int nfv_size)
{
    struct in_addr usr_v4_addr;
    uint64_t dpid;
    uint32_t port;
    int i = 0, ret = 0;
    char **nfv_list;

    if (nfv_size < 1 || nfv_size > 8) {
        c_log_err("%s:nfv list arg invalid", FN);
        return -1;
    }

    if (!nbapi_app_data->makdi_service) {
        c_log_err("%s: Makdi service not alive", FN);
        return -1;
    }

    if (!inet_aton(user_ip_str ,&usr_v4_addr)) {
        c_log_err("%s: Invalid user ip address", FN);
        return -1;
    }

    dpid = strtoull(dpid_str, NULL, 16);
    if (dpid == ULONG_MAX && errno == ERANGE) {
        c_log_err("%s: Invalid user ip address", FN);
        return -1;
    }

    port = atoi(port_str);
    if (port >= 0xffff) {
        c_log_err("%s: Invalid port", FN);
        return -1;
    }

    nfv_list = calloc(1, nfv_size * sizeof(char *));
    if (!nfv_list) {
        return -1;
    }

    if (nfv0 && i < nfv_size) {
        nfv_list[i++] = nfv0;
    }

    if (nfv1 && i < nfv_size) {
        nfv_list[i++] = nfv1;
    }

    if (nfv2 && i < nfv_size) {
        nfv_list[i++] = nfv2;
    }

    if (nfv3 && i < nfv_size) {
        nfv_list[i++] = nfv3;
    }

    if (nfv4 && i < nfv_size) {
        nfv_list[i++] = nfv4;
    }

    if (nfv5 && i < nfv_size) {
        nfv_list[i++] = nfv5;
    }

    if (nfv6 && i < nfv_size) {
        nfv_list[i++] = nfv6;
    }

    if (nfv7 && i < nfv_size) {
        nfv_list[i++] = nfv7;
    }

    ret = mul_makdi_serv_mod(nbapi_app_data->makdi_service, dpid,
                             usr_v4_addr.s_addr, port,
                             nfv_size, nfv_list, true);

    if (ret) c_log_err("%s: Failed", FN);
    free(nfv_list);
    return ret;
}


/**
 * nbapi_del_makdi_service -
 *
 * Del a makdi service 
 */ 
int
nbapi_del_makdi_service(char *user_ip_str, char *dpid_str, char *port_str)
{
    struct in_addr usr_v4_addr;
    uint64_t dpid;
    uint32_t port;
    int ret = 0;

    if (!nbapi_app_data->makdi_service) {
        return -1;
    }

    if (!inet_aton(user_ip_str ,&usr_v4_addr)) {
        return -1;
    }

    dpid = strtoull(dpid_str, NULL, 16);
    if (dpid == ULONG_MAX && errno == ERANGE) {
        return -1;
    }

    port = atoi(port_str);
    if (port >= 0xffff) {
        return -1;
    }

    ret = mul_makdi_serv_mod(nbapi_app_data->makdi_service, dpid, usr_v4_addr.s_addr, port,
                             0, NULL, false);
    return ret;
}
