#!/usr/bin/env python

# Copyright (C) 2013-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See
# the
# License for the specific language governing permissions and limitations
# under the License.
import json
import logging

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("SwitchHandler")
logger.setLevel(logging.DEBUG)

class SwitchHandler(BaseHandler):
    """
    This Handler manages the following URL:
        GET     topology/switch                             : get_switch_all
        GET     topology/switch/{dpid}                      : get_switch(dpid)
        GET     topology/switch/{dpid}/table/{table_id}     : get_switch_table(table_id)
        GET     topology/switch/{dpid}/meter                : get_switch_meter(dpid)
        GET     topology/switch/{dpid}/group                : get_switch_group(dpid)
        GET     topology/switch/{dpid}/limit                : get_switch_limit(dpid)
        POST    topology/switch/{dpid}/limit                : set_switch_limit(dpid)
        GET     topology/switch/{dpid}/port                 : get_switch_port_all(dpid)
        GET     topology/switch/{dpid}/port/{port_no}       : get_switch_port(dpid)
    """
    BASE_URL = "/topology/switch" 

    request_mapper = {
        "^$":                             "get_switch_all",
        "^0x[0-9a-fA-F]+$":               "get_switch",
        "^0x[0-9a-fA-F]+/port$":          "get_switch_port_all",
        "^0x[0-9a-fA-F]+/port/[0-9]+$":   "get_switch_port",
        "^0x[0-9a-fA-F]+/meter$":         "get_switch_meter",
        "^0x[0-9a-fA-F]+/group$":         "get_switch_group",
        "^0x[0-9a-fA-F]+/table/[0-9]+$":  "get_switch_table",
        "^0x[0-9a-fA-F]+/limit$":         "handle_limit"
    }

    def get_request_mapper(self):
        return self.request_mapper

    def get_base_uri(self):
        return self.BASE_URL

    def get(self, dpid=None, port_no=None):
        self.__execute(dpid, port_no)

    def post(self, dpid=None, port_no=None):
        self.__execute(dpid, port_no)

    def options(self, dpid=None, port_no=None):
        self.write("ok")

    def __execute(self, *args):
        func = self.match()
        logger.debug("matched func: %s, args: %s", func, args)
        if func is not None:
            getattr(self, func)(*args)

    def get_switch_all(self, *args):
        try:
            res = mul.get_switch_all()
        except:#no switch
            self.write({"switches" : []})
            self.finish()
            res = self.__nbapi_switch_brief_list_t_serialization(res)
            self.write(json.dumps(res))
            self.finish()

    def get_switch(self, *args):
        dpid = int(args[0], 0)
        res = mul.get_switch_general(dpid)
        ret = self.__ofp_switch_add_serialization(res)
        self.write(json.dumps(ret))

    def get_switch_port_all(self, *args):
        dpid = int(args[0], 0)
        res = mul.get_switch_port_all(dpid)
        res = [self.__ofp_phy_port_serialization(port) for port in res]
        self.write(json.dumps({
            'ports': res
        }))

    def get_switch_port(self, *args):
        dpid = int(args[0], 0)
        port_no = int(args[1])
        res = mul.get_switch_port(dpid, port_no)
        res = self.__ofp_phy_port_serialization(res)
        self.write(json.dumps(res))

    def get_switch_meter(self, *args):
        dpid = int(args[0], 0)
        res = mul.get_switch_meter(dpid)
        if res:
            bands = mul.get_band_type(res.band_types)
            flags = mul.get_band_flag(res.capabilities)
            ret = {
                "max-meter" : 	res.max_meter,
                "bands"		:	bands.split(),
                "flags"		:	flags.split(),
                "max-bands"	:	res.max_bands,
                "max-color"	:	res.max_color
            }
            self.write(ret)
        else:
            self.raise_error(-1, "Failed to get meter features", reason="Unsupported OFP version")
	    return

    def get_switch_group(self, *args):
        dpid = int(args[0], 0)
        print 'Getting group info for 0x%lx'%dpid  
        res = mul.get_switch_group(dpid)
        print 'Got for 0x%lx'%dpid  
        if res is None:
            self.raise_error(-1, "Failed to get group features", reason="")
        else:
            print '1 0x%lx'%dpid  
            supported_group =   mul.get_supported_group(res.types)
            capability =        mul.get_group_capabilities(res.capabilities)
            all_actions =       mul.get_group_act_type(res.actions, mul.OFPGT_ALL)
            select_actions =    mul.get_group_act_type(res.actions, mul.OFPGT_SELECT)

            indirect_actions =  mul.get_group_act_type(res.actions, mul.OFPGT_INDIRECT)

            ff_actions =        mul.get_group_act_type(res.actions, mul.OFPGT_FF)
            self.write({
                "groups":       supported_group.split() ,
                "capability":   capability.split(),
                "group_all_actions":            all_actions.split(),
                "group_select_actions":         select_actions.split(),
                "group_indirect_actions":       indirect_actions.split(),
                "gruop_ff_actions":             ff_actions.split(),
            })

    def get_switch_table(self, *args):
        dpid = int(args[0], 0)
        table_no = int(args[1], 0)
        table = mul.get_switch_table(dpid, table_no)
        if table:
            inst                = 	mul.get_table_bminstruction(table.bm_inst)
            inst_miss           = 	mul.get_table_bminstruction(table.bm_inst_miss)
            next_tables         =	mul.get_table_next_tables(table.bm_next_tables)
            next_tables_miss    = 	mul.get_table_next_tables(table.bm_next_tables_miss)
            wr_actions          = 	mul.get_act_type(table.bm_wr_actions)
            wr_actions_miss     = 	mul.get_act_type(table.bm_wr_actions_miss)
            app_actions         = 	mul.get_act_type(table.bm_app_actions)
            app_actions_miss    = 	mul.get_act_type(table.bm_app_actions_miss)
            set_field           = 	mul.get_table_set_field(table.bm_wr_set_field)
            set_field_miss      = 	mul.get_table_set_field(table.bm_wr_set_field_miss)
            app_set_field       =  	mul.get_table_set_field(table.bm_app_set_field)
            app_set_field_miss  =   mul.get_table_set_field(table.bm_app_set_field_miss)

            res = {
                "tables" : {
                    "instruction": inst.split(),
                    "instruction_miss": inst.split(),
                    "next_table": next_tables.split(),
                    "next_table_miss": next_tables_miss.split(),
                    "write_actions": wr_actions.split(),
                    "write_actions_miss": wr_actions_miss.split(),
                    "apply_actions": app_actions.split(),
                    "apply_actions_miss": app_actions_miss.split(),
                    "set_field": set_field.split(),
                    "set_field_miss": set_field_miss.split(),
                    "apply_set_field": app_set_field.split(),
                    "apply_set_field_miss": app_set_field_miss.split()
                }
            }
            self.write(res)
        else:
            self.raise_error(-1, "Failed to get table features")
	    return

    def handle_limit(self, *args):
        if self.request.method in 'GET':
            res = self.__get_switch_rate_limit(args[0])
            if res:
                self.write(json.dumps(res))
            else:
                self.raise_error(-1, "Failed to get limit features")
		return
        elif self.request.method in 'POST':
            res = self.__set_switch_rate_limit(args[0])
            if res:
                self.write(json.dumps(res))
            else:
                self.raise_error(-1, "Failed to set limit features")
		return

    def __to_str_switch_state(self, status):
        if status == 0:
            return "Init"

        elif status & mul.SW_PUBLISHED:
            return "Published"

        elif status & mul.SW_REGISTERED:
            return "Registerd"

        elif status & mul.SW_REINIT:
            return "Reinit"

        elif status & mul.SW_REINIT_VIRT:
            return "Reinit|Virt"

        elif status & mul.SW_DEAD:
            return "Dead"

        return "Unknown"

    def __nbapi_switch_brief_list_t_serialization(self, resp):
        res = []
        for s in resp:
            dpid = int(s.switch_id.datapath_id)
            res.append(
                {'flows':   str(mul.get_flow_number(dpid)),
                 'status':  self.__to_str_switch_state(s.state),
                 'meters':  str(mul.get_meter_number(dpid)),
                 'groups':  str(mul.get_group_number(dpid)),
                 'dpid':    '0x%lx' % dpid,
                 'peer':    s.conn_str,
                 'ports':   str(s.n_ports)}
            )
	    #mul.nbapi_mem_free_c_ofp_switch_brief_t(s)
        return {'switches': res}

    def __ofp_switch_add_serialization(self, resp):
        of_ver = 'not supported'
	capabilities = ""
        if resp.ver &  mul.OFP_VERSION:
            of_ver = '1.0'
	    capabilities = mul.general_capabilities_tostr(resp.capabilities)

        if resp.ver & mul.OFP_VERSION_131:
            of_ver = '1.3'
	    capabilities = mul.general131_capabilities_tostr(resp.capabilities)

        result = {
            'dpid'      :   '0x%lx' % resp.datapath_id,
            'alias_id'  :   mul.parse_alias_id(resp.sw_alias),
            'n_buffers' :   resp.n_buffers,
            'n_tables'  :   resp.n_tables,
            'capabilites':  capabilities.split(),
            'actions':      resp.actions,
            'ports':        (resp.header.length-40)/64,
            'of_version':   of_ver
        }
        return result

    def __ofp_phy_port_serialization(self, resp):
        config = 'PORT_UP'
        state = 'LINK_UP'

        if resp.config & 0x1: config = 'PORT_DOWN'
        if resp.state & 0x1: state = 'LINK_DOWN'

        result = {
            'port_no':      resp.port_no,
            'hw_addr':      mul.nbapi_parse_mac_to_str(resp.hw_addr),
            'name':         resp.name,
            'config':       config,
            'state':        state,
            'curr':         None,
            'advertised':   None,
            'supported':    None,
            'peer':         None
        }
        return result

    def __get_switch_rate_limit(self, dpid):
        dpid = int(dpid, 0)
        rx = mul.get_switch_pkt_rx_rlim(dpid)
        tx = mul.get_switch_pkt_tx_rlim(dpid)

        rx_status = tx_status = "Enable"
        if rx < 0 or tx < 0:
            return None

        if rx == 0:
            rx_status = "Disable"
        if tx == 0:
            tx_status = "Disable"

        result = {
            "rx": {
                "status":   rx_status,
                "limit":    rx
            },
            "tx" : {
                "status":   tx_status,
                "limit":    tx
            }
        }
	#no malloc problem. they return int.
        return result

    def __set_switch_rate_limit(self, dpid):
        dpid = int(dpid, 0)
        data = json.loads(self.request.body)
        rx = data['rx']
        tx = data['tx']
        rx_status = tx_status = "Enable"

        if mul.nbapi_set_switch_pkt_rx_rlim(dpid, rx) != 0:
            return None

        if mul.nbapi_set_switch_pkt_tx_rlim(dpid, tx) != 0:
            return None

        if rx == 0:
            rx_status = "Disable"
        if tx == 0:
            tx_status = "Disable"

        return {
            "rx": rx_status,
            "tx": tx_status
        }
