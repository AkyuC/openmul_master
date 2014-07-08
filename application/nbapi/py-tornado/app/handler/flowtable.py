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
import logging
import json
import colander

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler
from app.handler.ids import FlowHolder

logger = logging.getLogger("FlowTableHandler")
logger.setLevel(logging.DEBUG)

class FlowTableHandler(BaseHandler):

    def get(self, dpid=None, flow_id=None):
        logger.debug("requset url - %s", self.get_request_uri())
        logger.debug("request params - dpid: %s, flow_id: %s", dpid, flow_id)

        if dpid and flow_id is None:
            res = self.__get_switch_flow(dpid)
            self.write(res)
        elif dpid and flow_id:
            res = self.__get_switch_flow_with_id(dpid, flow_id)
            self.write(res)

    def options(self, dpid=None, flow_id=None):
        self.write("ok")

    def post(self, dpid=None, flow_id=None):
        logger.debug("requset url - %s", self.get_request_uri())
        logger.debug("request params - dpid: %s, flow_id: %s", dpid, flow_id)

        try:
            body = FlowSchema().deserialize(json.loads(self.request.body))
        except :
            self.raise_error(-1, "Failed to add flow", reason="Marformed input data")

        logger.debug(str(body))

        mdata = mul.nbapi_mdata_alloc(int(dpid, 16))
        if mdata is None:
            self.raise_error(-1, "Failed to add flow", reason="no such switch!")
	
        flow = mul.nbapi_make_flow_mask(0,
                                        int(dpid, 16),
                                        str(body['dl_src']),
                                        str(body['dl_dst']),
                                        str(body['dl_type']),
                                        str(body['dl_vlan']),
                                        str(body['dl_vlan_pcp']),
                                        str(body['mpls_label']),
                                        str(body['mpls_tc']),
                                        str(body['mpls_bos']),
                                        str(body['nw_dst']),
                                        str(body['nw_src']),
                                        str(body['nw_proto']),
                                        str(body['nw_tos']),
                                        str(body['tp_dst']),
                                        str(body['tp_src']),
                                        str(body['in_port']),
                                        str(body['table_id'])
                                       )

        if flow is None:
            self.raise_error(-1, "Failed to add flow", reason="Malformed flow data")

        mask = mul.nbapi_make_flow_mask(1,
                                        int(dpid, 16),
                                        str(body['dl_src']),
                                        str(body['dl_dst']),
                                        str(body['dl_type']),
                                        str(body['dl_vlan']),
                                        str(body['dl_vlan_pcp']),
                                        str(body['mpls_label']),
                                        str(body['mpls_tc']),
                                        str(body['mpls_bos']),
                                        str(body['nw_dst']),
                                        str(body['nw_src']),
                                        str(body['nw_proto']),
                                        str(body['nw_tos']),
                                        str(body['tp_dst']),
                                        str(body['tp_src']),
                                        str(body['in_port']),
                                        str(body['table_id'])
                                      )

        if mask is None:
            self.raise_error(-1, "Failed to add flow", reason="Malformed mask data")

        instructions = body['instructions']

        for instruction in instructions:
            if instruction['instruction'] == "instruction-apply":
                mul.nbapi_mdata_inst_apply(mdata, int(dpid, 16))
            elif instruction['instruction'] == 'instruction-write':
                mul.nbapi_mdata_inst_write(mdata, int(dpid, 16))
            else :
                self.raise_error(-1, "Falied to add flow", reason="Malformed instruction data")
            for action in instruction["actions"]:
                #these actions need more flow infomation..
                check = -1
                if action['action'] == "SET_TP_SRC":
                    if flow.dl_type != 0x0800:
                        self.raise_error(-1, 'Failed to add flow', reason="SET_TP_SRC, eth-type != ETH_TYPE_IP ")
                    if flow.nw_proto == 17:#mul.IP_TYPE_UDP
                        check = mul.nbapi_dayoung_action_to_mdata(mdata, 'SET_TP_UDP_SRC', str(action['value']))
                    elif flow.nw_proto == 6:#mul.IP_TYPE_TCP
                        check = mul.nbapi_dayoung_action_to_mdata(mdata, 'SET_TP_TCP_SRC', str(action['value']))
                    else:
                        self.raise_error(-1, 'Failed to add flow', reason="SET_TP_SRC, nw_proto != IP_TYPE_UDP or IP_TYPE_TCP")
                        continue

                if action['action'] == "SET_TP_DST":
                    if flow.dl_type != 0x0800:
                        self.raise_eroor(-1,'Failed to add flow', reason="SET_TP_DST, eth-type != ETH_TYPE_IP ")
                    if flow.nw_proto == 17:#mul.IP_TYPE_UDP:
                        check = mul.nbapi_dayoung_action_to_mdata(mdata, 'SET_TP_UDP_DST', str(action['value']))
                    elif flow.nw_proto == 6:#mul.IP_TYPE_TCP:
                        check = mul.nbapi_dayoung_action_to_mdata(mdata, 'set_TP_TCP_DST', str(action['value']))
                    else:
                        self.raise_error(-1, 'Failed to add flow', reason="SET_TP_DST, nw_proto != IP_TYPE_UDP or IP_TYPE_TCP")
                        continue
		    
                check = mul.nbapi_action_to_mdata(mdata, str(action['action']), str(action['value']))
                if check is not 0:
                    self.raise_error(-1, "Failed to add flow", reason="Malformed action data "+action['action'])

                if mdata is None:
                    self.raise_error(-1, "Failed to add flow", reason="Malformed mdata")

        ret = mul.add_static_flow(int(dpid, 16), flow, mask,
                                  int(body['priority']),
                                  int(body['flags']),
                                  mdata)
        if ret is 0:
            flow_id = FlowHolder.getInstance().save(int(dpid, 16), flow)
            if flow_id:
                res = { "flow_id": flow_id }
                self.finish(res) 
            else:
                self.raise_error(-1, "Failed to add flow")
        else:
            self.raise_error(-1, "Failed to add flow  (or Existed flow)")

    def put(self, dpid=None, flow_id=None):
        pass

    def delete(self, dpid=None, flow_id=None):
        try:
            flow = FlowHolder.getInstance().get(flow_id)

            res = mul.delete_static_flow(flow.datapath_id,
                                         flow.flow,
                                         flow.mask,
                                         0, 0, 0)
            if res != 0:
                self.raise_error(-1, "Failed to delete flow")
            else:
                FlowHolder.getInstance().remove(flow_id)
                res = {
                    "flow_id": flow_id
                }
                self.write(res)
        except KeyError:
            self.raise_error(-1, "No such flow_id")

    def __get_switch_flow(self, dpid):
        ret = []
        flows = mul.get_flow(int(dpid, 16))
        for flow in flows:
            flow_id = FlowHolder.getInstance().save(int(dpid, 16), flow.flow)
            flow_dict = self.__c_ofp_flow_info_serialization(flow)
            flow_dict.update({'flow_id': flow_id})
            flow_dict.update(self.__nbapi_action_serialization(flow))
            ret.append(flow_dict)
	
        return {'flows':ret}

    def __get_switch_flow_with_id(self, dpid, flow_id):
        flow = FlowHolder.getInstance().get(flow_id)
        flow_dict = {"flow_id":flow_id}
        flow_dict.update(self.__c_ofp_flow_info_serialization(flow))
        flow_dict.update(self.__nbapi_action_serialization(flow))

        return flow_dict


    def __c_ofp_flow_info_serialization(self, resp):
        flag = ""
        if resp.flags & mul.C_FL_ENT_STATIC:
            flag = 'static'
        else:
            flag = 'dynamic'

        if resp.flags & mul.C_FL_ENT_CLONE:
            flag += ' clone'
        else :
            flag += ' no-clone'

        if resp.flags & mul.C_FL_ENT_NOT_INST:
            flag += ' not-verified'
        else:
            flag += ' verified'
        if resp.flags & mul.C_FL_ENT_LOCAL:
            flag +=' local'
        else:
            flag += ' non-local'
        if resp.flags & mul.C_FL_ENT_RESIDUAL:
            flag += ' residual'

        return {
            'dpid': '0x%lx' % resp.datapath_id,
            'flow': self.__flow_struct_serialization(resp.flow),
            'bps': mul.nbapi_parse_bps_to_str(resp.bps),
            'pps': mul.nbapi_parse_bps_to_str(resp.pps),
            'pkt_count': resp.packet_count,
            'byte_count': resp.byte_count,
            'flags' : flag,
            'alive' : resp.duration_sec,
            'priority' : resp.priority
        }

    def __nbapi_action_serialization(self, flow):
        str_actions = mul.nbapi_dump_single_flow_action(flow)
        if str_actions:
            #logger.debug("flow - actions: %s", str_actions)
            return eval(str_actions)
        else:
            #logger.debug("flow has no actions")
            return ""

    def __flow_struct_serialization(self, flow):
        nw_src = mul.nbapi_parse_nw_addr_to_str(flow, 0)
        nw_dst = mul.nbapi_parse_nw_addr_to_str(flow, 1)

        dl_src = mul.nbapi_parse_mac_to_str(flow.dl_src)
        dl_dst = mul.nbapi_parse_mac_to_str(flow.dl_dst)

        return {
            'in_port':      flow.in_port,
            'dl_vlan':      flow.dl_vlan,
            'dl_type':      flow.dl_type,
            'dl_dst':       dl_dst,
            'dl_src':       dl_src,
            'dl_vlan_pcp':  flow.dl_vlan_pcp,
            'table_id':     flow.table_id,
            'nw_tos':       flow.nw_tos,
            'nw_proto':     flow.nw_proto,
            'mpls_label':   flow.mpls_label,
            'tp_src':       flow.tp_src,
            'tp_dst':       flow.tp_dst,
            'nw_src':       nw_src,
            'nw_dst' :      nw_dst,
            'mpls_bos' :    flow.mpls_bos,
            'mpls_tc' : flow.mpls_tc
        }


class Action(colander.MappingSchema):
    action_type =[
        'OUTPUT',
        'SET_VLAN_VID',
        'SET_VLAN_PCP',
        'STRIP_VLAN',
        'SET_DL_SRC',
        'SET_DL_DST',
        'SET_NW_SRC',
        'SET_NW_DST',
        'SET_NW_TOS',
        'SET_TP_SRC',
        'SET_TP_DST',

        #OFP131_ACTION
        'CP_TTL_OUT',
        'CP_TTL_IN',
        'NOT_USED',
        'NOT_USED2',
        'SET_MPLS_TTL',
        'DEC_MPLS_TTL',
        'PUSH_VLAN',
        'POP_VLAN',
        'PUSH_MPLS',
        'POP_MPLS',
        'SET_QUEUE',
        'GROUP',
        'SET_NW_TTL',
        'DEC_NW_TTL',
        'SET_FIELD',
        'PUSH_PBB',
        'POP_PBB',

        #SET_FIELD_ACTIONS
        'SET_ETH_TYPE',
        'SET_MPLS_LABEL',
        'SET_MPLS_TC',
        'SET_MPLS_BOS',
        'SET_UDP_SPORT',
        'SET_UDP_DPORT',
        'SET_TCP_SPORT',
        'SET_TCP_DPORT'

        #'SET_GROUP',
        #'SET_PUSH',
        #'SET_POP_MPLS',
        #'SET_STRIP_PBB',
        #'SET_IP_TTL',
        #'DEC_IP_TTL',
        #'SET_ETH_TYPE',
        #'SET_MPLS_LABEL',
        #'SET_MPLS_TC',
        #'SET_MPLS_BOS',
        #'SET_UDP_SPORT',
        #'SET_UDP_DPORT',
        #'SET_TCP_SPORT',
        #'SET_TCP_DPORT',
        #'SET_QUEUE'
    ]

    action = colander.SchemaNode(colander.String(), validator=colander.OneOf(action_type))
    value = colander.SchemaNode(colander.String(), missing=None)

class ActionList(colander.SequenceSchema):
    action = Action()

class Instruction(colander.MappingSchema):
    action_type =[
        "instruction-write",
        "instruction-apply"
    ]

    instruction = colander.SchemaNode(colander.String(), validator=colander.OneOf(action_type))
    actions = ActionList()

class InstructionList(colander.SequenceSchema):
    instruction = Instruction()

class FlowSchema(colander.MappingSchema):
    dl_src = colander.SchemaNode(colander.String(), missing=None)
    dl_dst = colander.SchemaNode(colander.String(), missing=None)
    dl_type = colander.SchemaNode(colander.String(), missing=None)
    dl_vlan = colander.SchemaNode(colander.String(), missing=None)
    dl_vlan_pcp = colander.SchemaNode(colander.String(), missing=None)
    mpls_label = colander.SchemaNode(colander.String(), missing=None)
    mpls_bos =colander.SchemaNode(colander.String(), missing=None)
    mpls_tc =colander.SchemaNode(colander.String(), missing=None)
    mpls_bos = colander.SchemaNode(colander.String(), missing=None)
    nw_src = colander.SchemaNode(colander.String(), missing=None)
    nw_dst = colander.SchemaNode(colander.String(), missing=None)
    nw_proto =colander.SchemaNode(colander.String(), missing=None)
    nw_tos =colander.SchemaNode(colander.String(), missing=None)
    tp_dst = colander.SchemaNode(colander.String(), missing=None)
    tp_src =colander.SchemaNode(colander.String(), missing=None)
    in_port =colander.SchemaNode(colander.String(), missing=None)
    table_id =colander.SchemaNode(colander.String(), missing=0)

    ogroup =colander.SchemaNode(colander.Int(), missing=0xffffffff)
    name =colander.SchemaNode(colander.Int(), missing=0)
    flag =colander.SchemaNode(colander.Int(), missing=0)
    instructions = InstructionList()
    priority = colander.SchemaNode(colander.Int(), missing=0)
