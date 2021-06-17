/*
 *  makdi_servlet.h: makdi service header
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
#ifndef  __MAKDI_SERVLET_H__
#define  __MAKDI_SERVLET_H__

#include "mul_common.h"

int mul_makdi_serv_mod(void *service, uint64_t dpid, uint32_t nw_src,
                   uint16_t iif, int nfvc, char **nfvv, bool add);


int mul_makdi_show_service_chain(void *service,
	void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
int mul_makdi_serv_mod(void *service, uint64_t dpid, uint32_t nw_src,
                   uint16_t iif, int nfvc, char **nfvv, bool add) ;
int mul_makdi_show_service(void *service,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
void mul_makdi_show_nfvtopology_node(void *service, uint64_t dpid, char *group_id,
                   uint16_t iif, uint16_t oif, char *nfv, bool add);
int mul_makdi_show_nfv_group(void *service,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
int mul_makdi_show_nfv(void *service,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
int mul_makdi_show_servicechain_default(void *service,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
void mul_makdi_show_nfv_stats(void *service, char* nfv_name,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
void mul_makdi_show_nfv_stats_all(void *service, 
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
void mul_makdi_show_service_stats(void *service, char* name,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
int mul_makdi_show_service_stats_all(void *service,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
void mul_makdi_show_user_stats(void *service, char* user,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));
int mul_makdi_show_user_stats_all(void *service,
		void *arg, bool nbapi, void (*cb_fn)(void *arg, void *pbuf));

int mul_makdi_group_mod(void *service, char *group_id, bool add);
int mul_makdi_servicechain_mod(void *service, uint64_t dpid, uint32_t port,
    		char *service_name, uint32_t user_ip, int nfvc, char **nfv_group_list, bool add);
int mul_makdi_servicechain_default_mod(void *service, char *service_name,
		int nfvc, char **nfv_group_list, bool add, uint16_t level);
int mul_makdi_nfv_mod(void *service, uint64_t dpid, char *group_id,
                   uint16_t iif, uint16_t oif, char *nfv, bool add);
int mul_makdi_service_mod(void *service, char *service_name,
		uint16_t vlan, bool add);
char *makdi_dump_service_chain_user(struct c_ofp_host_mod *user_info,
                              struct c_ofp_s_chain_nfv_list *nfv_list);
char *makdi_dump_nfv_groups(struct c_ofp_s_chain_nfv_group_info *nfv_group_info);
char *makdi_dump_servicechain_default(struct c_ofp_default_rule_info *cofp_default_rule);
char *makdi_dump_services(struct c_ofp_service_info *service_info);
char *makdi_dump_nfv(struct c_ofp_s_chain_nfv_list *nfv_info);
char *makdi_dump_service_chain(struct c_ofp_s_chain_show *sc_info);
char *makdi_dump_nfv_stats(void);
char *makdi_dump_service_stats(void);

#endif
