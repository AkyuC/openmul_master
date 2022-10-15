/*
 * mul_servlet.h: MUL controller service header
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

#ifndef __MUL_SERVLET_H__
#define __MUL_SERVLET_H__

#define OFP_PRINT_MAX_STRLEN (256*4)
#define MUL_SERVLET_PBUF_DFL_SZ (10240)
#define SWITCH_BR_PBUF_SZ (MUL_SERVLET_PBUF_DFL_SZ) 

struct cbuf *mul_get_switches_brief(void *service);
struct cbuf *mul_get_switch_detail(void *service, uint64_t dpid);
int mul_get_switch_detail_config(void *service, uint64_t dpid, void *arg,
                             void (*cb_fn)(void *arg, void *pbuf));
void *mul_nbapi_dump_switch_brief(struct cbuf *b, bool free_buf);
char *mul_dump_switches_brief(struct cbuf *b, bool free_buf);
char *mul_dump_switch_detail(struct cbuf *b, bool free_buf);
int mul_get_group_info(void *service, uint64_t dpid,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  void (*cb_fn)(void *arg, void *pbuf));
int mul_get_matched_group_info(void *service, uint64_t dpid, 
                  uint32_t group_id, bool dump_cmd, bool nbapi_cmd, 
                  void *arg, void (*cb_fn)(void *arg, void *pbuf));
int mul_get_flow_info(void *service, uint64_t dpid, uint8_t tbid,
                  bool flow_self,  bool show_res, bool flow_tbid,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  void (*cb_fn)(void *arg, void *pbuf));
int mul_get_matched_flow_info(void *service, uint64_t dpid, 
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  struct flow *fl, struct flow *mask, uint32_t prio,
                  void (*cb_fn)(void *arg, void *pbuf));
int mul_get_ha_state(void *service, uint32_t *ha_sysid, uint32_t *ha_state,
                     uint64_t *gen_id);
bool mul_ha_enabled(void *service);
char *mul_ha_state_to_str(uint32_t sysid, uint32_t state);

int mul_get_meter_info(void *service, uint64_t dpid,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  void (*cb_fn)(void *arg, void *pbuf));
struct cbuf * mul_get_switch_features(void *service, uint64_t dpid,
                                      uint8_t table, uint32_t type);
char *mul_dump_switch_desc(struct cbuf *b, bool free_buf);
char *mul_dump_switch_meter_features(struct cbuf *b, bool free_buf);
char *mul_dump_switch_group_features(struct cbuf *b, bool free_buf);
char *mul_dump_switch_table_features(struct cbuf *b, bool free_buf);
int mul_set_switch_pkt_rlim(void *service, uint64_t dpid,
                            uint32_t pps, bool is_rx);
int mul_get_switch_pkt_rlim(void *service, uint64_t dpid,
                            uint32_t *pps, bool is_rx);
int mul_set_switch_pkt_dump(void *service, uint64_t dpid,
                            bool rx_en, bool tx_en, uint64_t *mask);
int mul_set_switch_stats_strategy(void *service, uint64_t dpid,
                              bool flow_bulk_en, bool group_bulk_en,
                              bool meter_bulk_config_en);
int mul_set_switch_stats_mode(void *service, uint64_t dpid, 
                                  bool port_stats_en);
int mul_get_switch_table_stats(void *service, uint64_t dpid, uint8_t table,
                           uint32_t *active_count, uint64_t *lookup_count,
                           uint64_t *matched_count);
struct cbuf * mul_get_switch_port_stats(void *service, uint64_t dpid,
                                  uint32_t port_no);
int mul_get_port_q_info(void *service, uint64_t dpid, uint32_t port,
                        void *arg, void (*cb_fn)(void *arg, void *pbuf));
char * mul_dump_port_stats(struct cbuf *b, bool free_buf);
int mul_set_loop_detect(void *service, bool enable); 

int mul_get_mod_uflow_info(void *service, uint64_t dpid, struct flow *fl,
                           void *arg, void (*cb_fn)(void *arg, uint64_t datapath_id,
                                         uint32_t out_port, struct flow *flow));


#endif
