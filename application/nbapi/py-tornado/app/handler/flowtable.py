import logging
import json
import warnings
import colander
import time, datetime

import re

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler
#from app.handler.thread_pool import in_thread_pool, in_ioloop, blocking
#from app.handler.ids import FlowHolder
from tornado.web import asynchronous

logger = logging.getLogger("FlowTableHandler")
#logger.setLevel(BaseHandler.LOG_LEVEL)
logger.setLevel(logging.DEBUG)

class FlowTableHandler(BaseHandler):

    def get(self, dpid=None, flow_id=None):
        logger.debug("requset url - %s", self.get_request_uri())
        logger.debug("request params - dpid: %s, flow_id: %s", dpid, flow_id)
        res = None
        if '/stats/switch/' in self.get_request_uri(): 
            res = self.__get_switch_flow_stat_with_id(dpid, flow_id)
        elif '/table/' in self.get_request_uri():
            res = self.__get_switch_flow(dpid, flow_id)
        elif 'stats' in self.get_request_uri():
            res = self.__get_switch_flow(dpid, -1)
        elif '/all/' in self.get_request_uri():
            res = self.__get_switch_flow('0')
        elif dpid and flow_id is None:
            res = self.__get_switch_flow(dpid)
        elif dpid and flow_id:
            res = self.__get_switch_flow_with_id(dpid, flow_id)
        self.finish(res)

    def options(self, dpid=None, flow_id=None):
        self.write("ok")

    @asynchronous
    def post(self, dpid, flow_id=None):
        ret={}
        try:
            body=json.loads(self.request.body)
            if 'flows' in  body.keys():
#                start=datetime.datetime.now()
                r_list=[]
                for b in body['flows']:
                    r_list.append(self.__add_flow(dpid, b))
                logger.debug(len(r_list))
                self.finish({'flows':r_list})
#                total=datetime.datetime.now()-start
#                self.finish({'flows':r_list})
#                logger.debug("%10f"%(total.total_seconds()*1000))
####
#                self.__add_multiple_flows(dpid, body['flows'], self.finish)
####
#                r_list=[]
#                for b in body['flows']:
#                    self.__add_multiple_flows(dpid, b, r_list.append)
#                logger.debug(len(r_list))
#                self.finish({'flows':r_list})
            else:
                if flow_id:
                    self.delete(dpid, flow_id)
                    #self.__add_flow(dpid, b) 
                else:
                    self.finish({'flow_id':self.__add_flow(dpid, body)})
        except Exception, e:
            logger.debug(str(e))
            self.finish({"error_message" : "failed to add flow!", "reason" : str(e)})
        #finally:
            #logger.debug(ret)
            #self.finish(ret)

    def __blocking_add_flow(self, dpid, b, callback):
        callback(self.__add_flow(dpid, b))
 
    def __add_flow(self, dpid, requestbody):
        body=FlowSchema().deserialize(requestbody)
        #logger.debug(body)
        drop = check = 0
        mdata = mul.nbapi_mdata_alloc(int(dpid, 16))
        if mdata is None:
            return 'switch not exist'
        for instruction in body['instructions']:
            if instruction['instruction'] == 'APPLY_ACTIONS':
                check = mul.nbapi_mdata_inst_apply(mdata)
            elif instruction['instruction'] == 'WRITE_ACTIONS':
                check = mul.nbapi_mdata_inst_write(mdata)
            elif instruction['instruction'] == 'METER':
                check = mul.nbapi_mdata_inst_meter(mdata, int(instruction['value']))
            elif instruction['instruction'] == 'GOTO_TABLE':
                check = mul.nbapi_mdata_inst_goto(mdata, int(instruction['value']))
            if check != 0:
                return 'failed to set instruction'+str(instruction['instruction'])
            check = -1
            for action in instruction['actions']:
                if 'DROP' == str(action['action']):
                    drop = 1
                    check = 0
                else:
                    check = mul.nbapi_action_to_mdata(mdata, str(action['action']), str(action['value']))
                if check != 0:
                    return 'failed to set action '+action['action']+' : '+action['value']+str(check)
        start=datetime.datetime.now()
        check = mul.add_static_flow(int(dpid,16),       
                                    int(body['priority']),str(body['barrier']),str(body['stat']),
                                    mdata, drop,
                                    str(body['dl_src']),str(body['dl_dst']),str(body['dl_type']),str(body['dl_vlan']),str(body['dl_vlan_pcp']),str(body['mpls_label']),str(body['mpls_tc']),str(body['mpls_bos']),str(body['nw_src']),str(body['nw_src6']),str(body['nw_dst']),str(body['nw_dst6']),str(body['nw_proto']),str(body['nw_tos']),str(body['tp_dst']),str(body['tp_src']),str(body['in_port']),str(body['table_id']))
        total=datetime.datetime.now()-start
        if check == 0:
            #flow_id = self.__make_flow_id(int(dpid, 16), flow, mask, int(body['priority']))
            return "%10f"%float(total.total_seconds()*10000)
            #return 'success'
        else:
            return 'flow already exist'

    def put(self, dpid=None, flow_id=None):
        pass

    def delete(self, dpid=None, flow_id=None):
        logger.debug("requset url - %s", self.get_request_uri())
        logger.debug("request params - dpid: %s, flow_id: %s", dpid, flow_id)

        ret = {}
        res = None
        try:
            that_flow_id=None
            flow_list = mul.get_flow(int(dpid, 16))
            for flow in flow_list:
                that_flow_id = self.__make_flow_id(int(dpid,16), flow.flow, flow.mask, flow.priority)
                if that_flow_id == flow_id:
                    res = mul.delete_static_flow(flow.datapath_id,
                                         flow.flow,
                                         flow.mask,
                                         flow.priority)
                    if res != 0:
                        raise Exception, 'cannot delete this flow'
                    else:
                        ret.update({
                            "flow_id": flow_id
                        })
            #if not res:
            #    raise Exception, 'No such flow_id'
        except Exception, e:
            ret.update({'error_message' : 'Failed to delete flow', 'reason' : str(e)})
        finally:
            logger.debug("%.10f"%float((end-start).total_seconds()*1000)+" milliseconds")
            if dpid:
                self.finish(ret)
            else:#modify
                return ret

    def __get_switch_flow(self, dpid, table_id=None):
        ret = []
        flows = mul.get_flow(int(dpid, 16))
        for flow in flows:
            if table_id==None or int(table_id)==flow.flow.table_id \
                 or (table_id==-1 and flow.flags & mul.C_FL_ENT_GSTATS):
                flow_id = self.__make_flow_id(int(dpid, 16), flow.flow, flow.mask, flow.priority)
                flow_dict = self.__c_ofp_flow_info_serialization(flow)
                flow_dict.update({'flow_id': flow_id})
                flow_dict.update(self.__nbapi_action_serialization(flow))
                ret.append(flow_dict)
        return {'flows':ret}

    def __get_switch_flow_with_id(self, dpid, flow_id):
        ret = {}
        flow = mask = None
        try:
            dpid, flow, mask, prio = self.__flow_id_to_dpid_flow_mask_prio(flow_id)
            single_flow_list = mul.get_single_flow(int(dpid, 16) , flow, mask, int(prio, 16))
            if len(single_flow_list) != 1:
                raise Exception
            for resp in single_flow_list:
                #resp = single_flow_list[0]
                ret = {'flow_id' : flow_id}
                ret.update(self.__c_ofp_flow_info_serialization(resp))
                ret.update(self.__nbapi_action_serialization(resp))
        except Exception:
            ret = {'error_message' : 'failed to get flow', 'reason' : 'no such flow'}
        finally:
            if flow != None:
                mul.nbapi_flow_free(flow)
            if mask != None:
                mul.nbapi_flow_free(mask)
            return ret

    def __get_switch_flow_stat_with_id(self, dpid, flow_id):
        ret = {}
        flow = mask = None
        try:
            dpid, flow, mask, prio = self.__flow_id_to_dpid_flow_mask_prio(flow_id)
            single_flow_list = mul.get_single_flow(int(dpid, 16), flow, mask, int(prio, 16))
            if len(single_flow_list) != 1:
                raise Exception, 'no such flow'
            resp = single_flow_list[0]
            if resp.flags & mul.C_FL_ENT_GSTATS:
                ret = {
                    "flow_id":      flow_id,
                    'bps':          mul.nbapi_parse_bps_to_str(resp.bps),
                    'pps':          mul.nbapi_parse_bps_to_str(resp.pps),
                    'pkt_count':    resp.packet_count,
                    'byte_count':   resp.byte_count,
                    'alive' : resp.duration_sec
                }
            else:
                raise Exception, 'this flow disabled' 
        except Exception, e:
            ret = {'error_message' : 'failed to get flow stats' , 'reason' : str(e)} 
        finally:
            if flow != None:
                mul.nbapi_flow_free(flow)
            if mask != None:
                mul.nbapi_flow_free(mask)
            return ret

    def __c_ofp_flow_info_serialization(self, resp):
        flag = 'static' if resp.flags & mul.C_FL_ENT_STATIC else 'dynamic'
        flag += ' clone' if resp.flags & mul.C_FL_ENT_CLONE else ' no-clone'
        flag += ' not-verified' if resp.flags & mul.C_FL_ENT_NOT_INST else ' verified'
        flag += ' local' if resp.flags & mul.C_FL_ENT_LOCAL else ' non-local'
        flag += ' stale' if resp.flags & mul.C_FL_ENT_STALE else ' clean'
        flag += ' residual' if resp.flags & mul.C_FL_ENT_RESIDUAL else ''

        stat = {}
        if resp.flags & mul.C_FL_ENT_GSTATS:
            stat = {
                'bps': mul.nbapi_parse_bps_to_str(resp.bps),
                'pps': mul.nbapi_parse_bps_to_str(resp.pps),
                'pkt_count': resp.packet_count,
                'byte_count': resp.byte_count,
                'alive' : resp.duration_sec
            }

        ret = self.__flow_struct_serialization(resp.flow, resp.mask)
        ret.update({
            'dpid': '0x%lx' % resp.datapath_id,
            'flags' : flag,
            'priority' : resp.priority,
            'stat' : stat
            })
        return ret


    def __nbapi_action_serialization(self, flow):
        str_actions = mul.nbapi_dump_single_flow_action(flow)
        if str_actions:
            return eval(str_actions)
        else:
            return ""

    def __flow_struct_serialization(self, flow, mask):

        dl_src = mul.nbapi_parse_mac_to_str(flow.dl_src)
        dl_dst = mul.nbapi_parse_mac_to_str(flow.dl_dst)
        dl_src_mask = mul.nbapi_parse_mac_to_str(mask.dl_src)
        dl_dst_mask = mul.nbapi_parse_mac_to_str(mask.dl_dst)

        ret = { 'table_id'  : flow.table_id }
        if dl_src_mask != "00:00:00:00:00:00" :
            ret.update({'dl_src' : dl_src})
        if dl_dst_mask != "00:00:00:00:00:00" :
            ret.update({'dl_dst' : dl_dst})
        if mask.dl_type     : ret.update({'dl_type'     : '0x%lx' % flow.dl_type})
        if mask.dl_vlan     : ret.update({'dl_vlan'     : flow.dl_vlan})
        if mask.dl_vlan_pcp : ret.update({'dl_vlan_pcp' : flow.dl_vlan_pcp})
        if mask.mpls_label  : ret.update({'mpls_label'  : flow.mpls_label})
        if mask.mpls_tc     : ret.update({'mpls_tc'     : flow.mpls_tc})
        if mask.mpls_bos    : ret.update({'mpls_bos'    : flow.mpls_bos})
        if mask.in_port     : ret.update({'in_port'    : flow.in_port})

    #if mask.dl_type and (flow.dl_type is mul.ETH_TYPE_IP or mul.ETH_TYPE_ARP or mul.ETH_TYPE_IPV6):
        if mask.dl_type and (flow.dl_type is 0x0800 or 0x0806 or 0x86dd):
            if mask.nw_proto : ret.update({'nw_proto': flow.nw_proto})
            if mask.nw_tos   : ret.update({'nw_tos'  : flow.nw_tos})
            if mask.tp_dst   : ret.update({'tp_dst'  : flow.tp_dst})
            if mask.tp_src   : ret.update({'tp_src'  : flow.tp_src})

        if flow.dl_type == 0x86dd:
            nw_src = mul.nbapi_parse_ipv6_nw_addr_to_str(flow, mask, 0)
            nw_dst = mul.nbapi_parse_ipv6_nw_addr_to_str(flow, mask, 1)
            if nw_dst != '-1' : ret.update({'nw_dst6' : nw_dst})
            if nw_src != '-1' : ret.update({'nw_src6' : nw_src})
        else:
            nw_src = mul.nbapi_parse_nw_addr_to_str(flow, mask, 0)
            nw_dst = mul.nbapi_parse_nw_addr_to_str(flow, mask, 1)
            if nw_dst != '-1' : ret.update({'nw_dst': nw_dst})
            if nw_src != '-1' : ret.update({'nw_src': nw_src})
        return ret


    def __match_check(self, version, body):
        if not body['dl_vlan'] and body['dl_vlan_pcp']:
            raise Exception, 'vlan_pcp : vlan == None'
        if body['mpls_label'] or body['mpls_tc'] or body['mpls_bos']:
            if version == 1:
                raise Exception, 'no mpls support in switch'
            if int(body['dl_type'], 16)!=0x8847:
                raise Exception, 'dl_type not ETH_TYPE_MPLS'
        if (body['nw_src'] or body['nw_dst']) and (body['nw_src6'] or body['nw_dst6']):
            raise Exception, 'nw_src or nw_dst and nw_src6 or nw_dst6 cannot handle together'
        if body['nw_dst'] or body['nw_src']:
            if int(body['dl_type'], 16)!=0x0800 and \
                int(body['dl_type'], 16)!=0x0806:
                raise Exception, 'nw_src or nw_dst but dl_type not ETH_TYPE_IP or ETH_TYPE_ARP'
        if body['nw_src6'] or body['nw_dst6']:
            if int(body['dl_type'], 16)!=0x86dd:
                raise Exception, 'nw_src6 or nw_dst6 but dl_type not ETH_TYPE_IPV6'

        if body['nw_proto'] or body['nw_tos']:
            if int(body['dl_type'], 16)!=0x800:
                raise Exception, 'nw_proto or nw_tos but dl_type not ETH_TYPE_IP'
        if body['tp_dst'] or body['tp_src']:
            if int(body['nw_proto'])!=17 and int(body['nw_proto'])!=6:
                raise Exception, 'tp_dst or tp_src but nw_proto not IP_TYPE_UDP or IP_TYPE_TCP'


    def __inst_action_check(self, version, body):
        only_of13actions = ['CP_TTL_IN', 'CP_TTL_OUT', 'DEC_MPLS_TTL', 'DEC_NW_TTL', 'GROUP', 'PUSH_MPLS', 'PUSH_PBB', 'PUSH_VLAN', 'PUSH_SVLAN', 'SET_MPLS_BOS', 'SET_MPLS_LABEL', 'SET_MPLS_TC', 'SET_MPLS_TTL', 'SET_NW_SRC', 'SET_QUEUE', 'POP_MPLS', 'POP_PBB']#, 'SET_NW_SRC6', 'SET_NW_DST6' ]
        for instruction in body['instructions']:
            if instruction['instruction']=='METER' or instruction['instruction']=='GOTO_TABLE':
                if instruction['value']==None or len(instruction['actions'])!=0:
                    raise Exception, instruction['instruction'] + ' must have value'
            else:
                if len(instruction['actions'])==0 or instruction['value']:
                    raise Exception, instruction['instruction'] + ' must have actions'
            if version == 1:
                if instruction['instruction'] is 'WRITE_ACTIONS' or \
                    instruction['instruction'] is 'METER':
                    raise Exception, 'this switch not support' + instruction['instruction']
                for action in instruction['actions']:
                    if action['action'] in only_of13actions:
                        raise Exception, 'this switch do not support '+str(action['action'])
                for action in instruction['actions']:
                    if action['action']=='SET_TP_SRC' or action['action']=='SET_TP_DST':
                        if int(body['dl_type'],16)!=0x800:
                            raise Exception, 'SET_TP_SRC or SET_TP_DST but dl_type not ETH_TYPE_IP'
                        if int(body['nw_proto'])==17:
                            action['action'] = str(action['action']).replace('TP','TP_UDP')
                        if int(body['nw_proto'])==6:
                            action['action'] = str(action['action']).replace('TP','TP_TCP')
                        else:
                            raise Exception, 'SET_TP_SRC or SET_TP_DST but nw_proto not IP_TYPE_TCP or IP_TYPE_UDP'
                    if action['action']=='SET_NW_SRC' or action['action']=='SET_NW_DST':
                        if int(body['dl_type'])!=0x0800:
                            raise Exception, 'SET_NW_SRC or SET_NW_DST but dl_type not ETH_TYPE_IP or ETH_TYPE_ARP'
                    if action['action']=='SET_NW_SRC6' or action['action']=='SET_NW_DST6': 
                        if int(body['dl_type'], 16)!=0x86dd:
                            raise Exception, 'SET_NW_SRC6 or SET_NW_DST6 but dl_type not ETH_TYPE_IPV6'


    def __check_flow_realy_in_switch(self, dpid, new_flow, new_mask, new_prio):
        flow_id = None
        flow_list = mul.get_flow(dpid)
        for flow in flow_list:
            if mul.compare_flows(new_flow, flow.flow) == 0 and\
               mul.compare_flows(new_mask, flow.mask) == 0 and\
               new_prio == flow.priority:
                flow_id = self.__make_flow_id(dpid, flow.flow, flow.mask, flow.priority)
        return flow_id

    def __make_flow_id(self, dpid, flow, mask, priority):#dpid, resp):
        dl_src = dl_dst = nw_src = nw_dst = ""

        dl_src = mul.nbapi_parse_mac_to_str(flow.dl_src)
        dl_dst = mul.nbapi_parse_mac_to_str(flow.dl_dst)
        dl_src_mask = mul.nbapi_parse_mac_to_str(mask.dl_src)
        dl_dst_mask = mul.nbapi_parse_mac_to_str(mask.dl_dst)

        if mask.dl_type and (flow.dl_type == 0x86dd):
            nw_src = mul.nbapi_parse_ipv6_nw_addr_to_str(flow, mask, 0)
            if nw_src == "-1":
                nw_src = "----:----:----:----:----:----:----:---/80"
                nw_src = str(nw_src).replace(":","").replace("/","")
                nw_dst = mul.nbapi_parse_ipv6_nw_addr_to_str(flow, mask, 1)
            if nw_dst == "-1":
                nw_dst = "----:----:----:----:----:----:----:----/80"
                nw_dst = str(nw_dst).replace(":","").replace("/","")
        else:
            str_sip = mul.nbapi_parse_nw_addr_to_str(flow, mask, 0)
            str_dip = mul.nbapi_parse_nw_addr_to_str(flow, mask, 1)
            for sip in str(str_sip).replace("/",".").split("."):
                nw_src += "%02x" % int(sip)
            for dip in str(str_dip).replace("/",".").split("."):
                nw_dst += "%02x" % int(dip)
            if str_sip == "-1":
                nw_src = "--------20"
            if str_dip == "-1":
                nw_dst = "--------20"
        flow_id = "%016x" %dpid + "%02x" %flow.table_id + "%04x" %priority
        flow_id += dl_src.replace(':','')   if dl_src_mask != '00:00:00:00:00:00' else '------------'
        flow_id += dl_dst.replace(':','')   if dl_dst_mask != '00:00:00:00:00:00' else '------------'
        flow_id += "%04x" %flow.dl_type     if mask.dl_type else '----'
        flow_id += "%03x" %flow.dl_vlan     if mask.dl_vlan else '---'
        flow_id += "%01d" %flow.dl_vlan_pcp if mask.dl_vlan_pcp else '-'
        flow_id += "%05x" %flow.mpls_label  if mask.mpls_label else '-----'
        flow_id += "%01d" %flow.mpls_tc     if mask.mpls_tc else '-'
        flow_id += "%01d" %flow.mpls_bos    if mask.mpls_bos else '-'
        flow_id += "%04x" %flow.in_port     if mask.in_port else '----'
        flow_id += "%02x" %flow.nw_proto    if mask.nw_proto else '--'
        flow_id += "%02x" %flow.nw_tos      if mask.nw_tos else '--'
        flow_id += "%04x" %flow.tp_dst      if mask.tp_dst else '----'
        flow_id += "%04x" %flow.tp_src      if mask.tp_src else '----'
        flow_id += nw_src + nw_dst

        return flow_id

    def __flow_id_slicing(self, flow_id, num, isHex=None):
        ret = flow_id[0:num]
        if '-' in ret:
            return 'None', flow_id[num:]
        if isHex != None:
            if isHex==True:#Hex num
                ret = '0x'+ret
            elif isHex==False:#String
                ret = str(ret)
        else:#isHex==None#Dec Num
            ret = str(int('0x'+ret, 16))
        return ret, flow_id[num:]

    def __flow_id_to_dpid_flow_mask_prio(self, flow_id):
        flow_id = str(flow_id)
        dpid, flow_id = self.__flow_id_slicing(flow_id, 16, True)
        table_id, flow_id = self.__flow_id_slicing(flow_id, 2)
        prio, flow_id = self.__flow_id_slicing(flow_id, 4, True)
        dl_src, flow_id = self.__flow_id_slicing(flow_id, 12, False)
        if dl_src != 'None':
            dl_src = dl_src[0:2]+":"+dl_src[2:4]+":"+dl_src[4:6]+":"+dl_src[6:8]+":"+dl_src[8:10]+":"+dl_src[10:12]
        dl_dst, flow_id = self.__flow_id_slicing(flow_id, 12, False)
        if dl_dst != 'None':
            dl_dst = dl_dst[0:2]+":"+dl_dst[2:4]+":"+dl_dst[4:6]+":"+dl_dst[6:8]+":"+dl_dst[8:10]+":"+dl_dst[10:12]
        dl_type, flow_id = self.__flow_id_slicing(flow_id, 4, True)
        dl_vlan, flow_id = self.__flow_id_slicing(flow_id, 3)
        dl_vlan_pcp, flow_id = self.__flow_id_slicing(flow_id, 1)
        mpls_label, flow_id = self.__flow_id_slicing(flow_id, 5)
        mpls_tc, flow_id = self.__flow_id_slicing(flow_id, 1)
        mpls_bos, flow_id = self.__flow_id_slicing(flow_id, 1)
        in_port, flow_id = self.__flow_id_slicing(flow_id, 4)
        nw_proto, flow_id = self.__flow_id_slicing(flow_id, 2)
        nw_tos, flow_id = self.__flow_id_slicing(flow_id, 2)
        tp_dst, flow_id = self.__flow_id_slicing(flow_id, 4)
        tp_src, flow_id = self.__flow_id_slicing(flow_id, 4)
        nw_src = nw_dst = None
        if dl_type == '0x86dd':
            nw_src, flow_id = self.__flow_id_slicing(flow_id,34, False)
            nw_dst, flow_id = self.__flow_id_slicing(flow_id,34, False)
            if 'None' not in nw_src:
                nw_src = nw_src[0:4]+":"+nw_src[4:8]+":"+nw_src[8:12]+":"+nw_src[12:16]+":"+nw_src[16:20]+":"+nw_src[20:24]+":"+nw_src[24:28]+":"+nw_src[28:32]+"/"+str(int('0x'+nw_src[32:34]), 16)
            if 'None' not in nw_dst:
                nw_dst = nw_dst[0:4]+":"+nw_dst[4:8]+":"+nw_dst[8:12]+":"+nw_dst[12:16]+":"+nw_dst[16:20]+":"+nw_dst[20:24]+":"+nw_dst[24:28]+":"+nw_dst[28:32]+"/"+str(int('0x'+nw_dst[32:34]), 16)
        else:
            nw_src, flow_id = self.__flow_id_slicing(flow_id, 10, False)
            if str(nw_src) != 'None':
                nw_src = str(int(nw_src[0:2],16))+"."+str(int(nw_src[2:4],16))+"."+str(int(nw_src[4:6],16))+"."+str(int(nw_src[6:8],16))+"/"+str(int(nw_src[8:10],16))
            nw_dst, flow_id = self.__flow_id_slicing(flow_id, 10, False)
            if str(nw_dst) != 'None':
                nw_dst = str(int(nw_dst[0:2],16))+"."+str(int(nw_dst[2:4],16))+"."+str(int(nw_dst[4:6],16))+"."+str(int(nw_dst[6:8],16))+"/"+str(int(nw_dst[8:10],16))

        flow = mul.nbapi_make_flow(dl_src, dl_dst, dl_type, dl_vlan, dl_vlan_pcp, mpls_label, mpls_tc, mpls_bos, nw_dst, nw_src, nw_proto, nw_tos, tp_dst, tp_src, in_port, table_id)
        mask = mul.nbapi_make_mask(dl_src, dl_dst, dl_type, dl_vlan, dl_vlan_pcp, mpls_label, mpls_tc, mpls_bos, nw_dst, nw_src, nw_proto, nw_tos, tp_dst, tp_src, in_port)
        return dpid, flow, mask, prio


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
        'SET_NW_SRC6',#
        'SET_NW_DST6',#
        'SET_NW_TOS',
        'SET_TP_SRC',
        'SET_TP_DST',

        #OFP131_ACTION
        'CP_TTL_OUT',
        'CP_TTL_IN',
        'SET_MPLS_TTL',
        'DEC_MPLS_TTL',
        'PUSH_VLAN',
        'PUSH_SVLAN',#not in openflow action
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

        'DROP'

    ]

    action = colander.SchemaNode(colander.String(), validator=colander.OneOf(action_type))
    value = colander.SchemaNode(colander.String(), missing=None)


class ActionList(colander.SequenceSchema):
    action = Action()


class Instruction(colander.MappingSchema):
    
    instruction_type =[
    #"METADATA",
    #"CLEARE_ACTIONS",
    "WRITE_ACTIONS",
    "APPLY_ACTIONS",
    "METER",
    "GOTO_TABLE"
    ]

    instruction = colander.SchemaNode(colander.String(), validator=colander.OneOf(instruction_type))
    value = colander.SchemaNode(colander.String(), missing=None)
    actions = ActionList(missing=[])


class InstructionList(colander.SequenceSchema):
    instruction = Instruction()


class FlowSchema(colander.MappingSchema):
    dl_src = colander.SchemaNode(colander.String(), 
                    missing=None, 
                    validator=colander.Regex(r"([0-9A-Fa-f]{1,2}[:]){5}([0-9A-Fa-f]{1,2})"))
    dl_dst = colander.SchemaNode(colander.String(), 
                    missing=None, 
                    validator=colander.Regex(r"([0-9A-Fa-f]{1,2}[:]){5}([0-9A-Fa-f]{1,2})"))
    dl_type = colander.SchemaNode(colander.String(), 
                    missing=None, 
                    validator=colander.Regex(r"0x([0-9A-Fa-f]){1,4}"))
    dl_vlan = colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(4096)]))
    dl_vlan_pcp = colander.SchemaNode(colander.String(), 
                    missing=None, 
                    validator=colander.OneOf(["%d" %i for i in range(8)]))
    mpls_label =  colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(1048576)]))
    mpls_tc = colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(8)]))
    mpls_bos = colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(['%d' %i for i in range(2)]))
    nw_dst = colander.SchemaNode(colander.String(), 
                    missing=None, 
                    validator=colander.Regex(r"([0-9a-fA-F]{1,3}(\.)){3}[0-9a-fA-F]{1,3}(/[0-9]{1,2}){0,1}"))
    nw_src = colander.SchemaNode(colander.String(), 
                    missing=None, 
                    validator=colander.Regex(r"([0-9a-fA-F]{1,3}(\.)){3}[0-9a-fA-F]{1,3}(/[0-9]{1,2}){0,1}"))
    nw_dst6 = colander.SchemaNode(colander.String(),
                    missing=None,
                    validator=colander.Regex(r"([0-9a-fA-F]{1,4}(:)){5}[0-9a-fA-F]{1,4}(/[0-9]{1,3}){0,1}"))
    nw_src6 = colander.SchemaNode(colander.String(),
                    missing=None,
                    validator=colander.Regex(r"([0-9a-fA-F]{1,4}(:)){5}[0-9a-fA-F]{1,4}(/[0-9]{1,3}){0,1}"))
    nw_proto = colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(256)]))
    nw_tos = colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(64)]))
    tp_dst = colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(65536)]))
    tp_src = colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(65536)]))
    in_port = colander.SchemaNode(colander.String(), 
                    missing=None)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(65536)]))
    table_id = colander.SchemaNode(colander.String(), 
                    missing=0)#, 
                    #validator=colander.OneOf(["%d" %i for i in range(255)]))

    barrier = colander.SchemaNode(colander.String(),
                    missing='disable',
                    validator=colander.OneOf(['enable','disable']))

    stat =  colander.SchemaNode(colander.String(),
                    missing='enable',
                    valicator=colander.OneOf(['enable','disable']))

    instructions = InstructionList()


    priority = colander.SchemaNode(colander.Int(), missing=mul.C_FL_PRIO_FWD)#, #validator=colander.OneOf([i for i in range(65536)]))
    





