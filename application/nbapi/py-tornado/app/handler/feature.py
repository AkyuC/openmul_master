import json
import logging

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("FeatureHandler")
logger.setLevel(logging.DEBUG)


class TableFeatureHandler(BaseHandler):
    """
    This Handler manages the following URL:
        GET     topology/switch/{dpid}/table/{table_id}     : get_switch_table(table_id)
        GET     topology/switch/{dpid}/meter                : get_switch_meter(dpid)
        GET     topology/switch/{dpid}/group                : get_switch_group(dpid)
    """
    BASE_URL = "/topology/switch" 

    request_mapper = {
        "^0x[0-9a-fA-F]+/meter$":         "get_switch_meter",
        "^0x[0-9a-fA-F]+/group$":         "get_switch_group",
        "^0x[0-9a-fA-F]+/table/[0-9]+$":  "get_switch_table",
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

    def __get_band_type(self, flag):
        ret = []
        if 1<<mul.OFPMBT_DROP & flag: ret.append("band-drop")
        if 1<<mul.OFPMBT_DSCP_REMARK & flag: ret.append("band-dscp-mark")
        if 1<<mul.OFPMBT_EXPERIMENTER & flag: ret.append("band-band-exp")
        return ret

    def __get_band_flag(self, flag):
        ret = []
        if mul.OFPMF_KBPS & flag : ret.append("meter-kbps")
        if mul.OFPMF_PKTPS & flag : ret.append("meter-pps")
        if mul.OFPMF_BURST & flag : ret.append("meter-burst")
        if mul.OFPMF_STATS & flag : ret.append("meter-stats")
        return ret

    def get_switch_meter(self, *args):
        ret = {}
        try:
            dpid = int(args[0], 16)
            version = mul.nbapi_get_switch_version_with_id(dpid)
            if version == 0:
                raise Exception, 'no such switch'
            if version == 1:
                raise Exception, 'Not supported switch OFP version'
            res = mul.get_switch_meter(dpid)
            if res:
                #bands = mul.get_band_type(res.band_types)
                #flags = mul.get_band_flag(res.capabilities)
                ret.update({
                    "max-meter" : res.max_meter,
                    "bands"     : self.__get_band_type(res.band_types),    
                    "flags"     : self.__get_band_flag(res.capabilities),
                    "max-bands" : res.max_bands,
                    "max-color" : res.max_color
                })
            else:
                raise Exception, 'cannot get meter feature'
        except Exception, e:
            ret.update({'error_message' : 'failed to get meter feature', 'reason' : str(e)})
        finally:
            self.finish(ret)

    def __get_supported_group(self, flag):
        ret = []
        if 1<<mul.OFPGT_ALL & flag : ret.append("grp-all")
        if 1<<mul.OFPGT_SELECT & flag : ret.append("grp-select")
        if 1<<mul.OFPGT_INDIRECT & flag : ret.append("grp-indiret")
        if 1<<mul.OFPGT_FF & flag : ret.append("grp-ff")
        return ret

    def __get_group_capabilities(self, flag):
        ret = []
        if 1<<mul.OFPGFC_SELECT_WEIGHT & flag : ret.append("grp-flags-select-weight")
        if 1<<mul.OFPGFC_SELECT_LIVENESS & flag : ret.append("grp-flags-select-liveness")
        if 1<<mul.OFPGFC_CHAINING & flag : ret.append("grp-flags-chaining")
        if 1<<mul.OFPGFC_CHAINING_CHECKS & flag : ret.append("grp-flags-chaining-check")
        return ret

    def get_switch_group(self, *args):
        ret = {}
        try:
            dpid = int(args[0], 16 )
            version = mul.nbapi_get_switch_version_with_id(dpid)
            if version == 0:
                raise Exception, 'no such switch'
            elif version == 1:
                 raise Exception, 'Not supported switch OFP version'
            res = mul.get_switch_group(dpid)
            if res is None:
                raise Exception, 'cannot get group feature'
            else:
                ret.update({
                    "groups": self.__get_supported_group(res.types),
                    "capability": self.__get_group_capabilities(res.capabilities),
                    "group_all_actions": self.__get_act_type(mul.get_group_act_type(res.actions, mul.OFPGT_ALL)),
                    "group_select_actions": self.__get_act_type(mul.get_group_act_type(res.actions, mul.OFPGT_SELECT)),
                    "group_indirect_actions": self.__get_act_type(mul.get_group_act_type(res.actions, mul.OFPGT_INDIRECT)),
                    "gruop_ff_actions": self.__get_act_type(mul.get_group_act_type(res.actions, mul.OFPGT_FF)),
                    "max_group":    [
                                        {"all": str(int(mul.get_max_group(res.max_groups, mul.OFPGT_ALL)))},
                                        {"select": str(int(mul.get_max_group(res.max_groups,mul.OFPGT_SELECT)))},
                                        {"indirect": str(int(mul.get_max_group(res.max_groups,mul.OFPGT_INDIRECT)))},
                                        {"fast-failover": str(int(mul.get_max_group(res.max_groups,mul.OFPGT_FF)))}
                                    ]
                })
        except Exception, e:
            ret.update({'error_message':'Failed to get group feature','reason':str(e)})
        finally:
            self.finish(ret)

    def __get_table_bminstruction(self, flag):
        ret = []
        if 1<<mul.OFPIT_GOTO_TABLE & flag     : ret.append("GOTO_TABLE")
        if 1<<mul.OFPIT_WRITE_METADATA & flag : ret.append("METADATA")
        if 1<<mul.OFPIT_WRITE_ACTIONS & flag  : ret.append("WRITE_ACTIONS")
        if 1<<mul.OFPIT_APPLY_ACTIONS & flag  : ret.append("APPLY_ACTIONS")
        if 1<<mul.OFPIT_CLEAR_ACTIONS & flag  : ret.append("CLEAR_ACTIONS")
        if 1<<mul.OFPIT_METER & flag          : ret.append("METER")
        return ret

    def __get_table_next_tables(self, flag):
        ret = []
        for i in range(255):
            if mul.get_bit_in_32mask(flag, i):
                ret.append("%d" %i)
        return ret

    def __act_dict(self, action_name, action_type=None, range=None):
        ran =None
        if not action_type:
            action_type='NONE_TYPE'
            ran = []
        if not range:#SET DEFAULT
            if action_type=='MAC_TYPE' : ran=['0:0:0:0:0:0','ff:ff:ff:ff:ff:ff']
            if action_type=='IP_TYPE': ran=['0.0.0.0','ff.ff.ff.ff']
            if action_type=='IPV6_TYPE': ran=['0:0:0:0:0:0:0:0','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
            if action_type=='STRING_TYPE' : ran=['enable','disable']
            if action_type=='INT_TYPE' : ran=['0','65535']
            if action_type=='INT_HEX_TYPE' : ran=['0x0', '0xffff']
            #if action_type=='PORT_TYPE' : ran=None
        else:
            ran = range
        ret = {
            'action_name' : action_name,
            'action_type' : action_type
        }
        if ran: ret.update({'range':ran})
        return ret


    def __get_act_type(self, flag):
        ret = []
        if 1<<mul.OFPAT131_OUTPUT & flag       : ret.append(self.__act_dict('OUTPUT','PORT_TYPE'))
        if 1<<mul.OFPAT131_COPY_TTL_OUT & flag : ret.append(self.__act_dict("CP_TTL_OUT"))
        if 1<<mul.OFPAT131_COPY_TTL_IN & flag  : ret.append(self.__act_dict("CP_TTL_IN"))
        if 1<<mul.OFPAT131_MPLS_TTL & flag     : 
            ret.append(self.__act_dict("SET_MPLS_TTL",'INT_TYPE',['1','255']))
        if 1<<mul.OFPAT131_DEC_MPLS_TTL & flag : ret.append(self.__act_dict("DEC_MPLS_TTL"))
        if 1<<mul.OFPAT131_PUSH_VLAN & flag : 
            ret.append(self.__act_dict("PUSH_VLAN"))
            ret.append(self.__act_dict("PUSH_SVLAN"))
        if 1<<mul.OFPAT131_POP_VLAN & flag : 
            ret.append(self.__act_dict("STRIP_VLAN"))
            ret.append(self.__act_dict("POP_VLAN"))
        if 1<<mul.OFPAT131_PUSH_MPLS & flag    : ret.append(self.__act_dict("PUSH_MPLS"))
        if 1<<mul.OFPAT131_POP_MPLS & flag     : ret.append(self.__act_dict("POP_MPLS",'INT_HEX_TYPE'))
        if 1<<mul.OFPAT131_SET_QUEUE & flag    : ret.append(self.__act_dict("SET_QUEUE",'INT_TYPE'))
        if 1<<mul.OFPAT131_GROUP & flag        : ret.append(self.__act_dict("GROUP",'INT_TYPE'))
        if 1<<mul.OFPAT131_SET_NW_TTL & flag   : 
            ret.append(self.__act_dict("SET_NW_TTL",'INT_TYPE', ['1','255']))
        if 1<<mul.OFPAT131_DEC_NW_TTL & flag   : ret.append(self.__act_dict("DEC_NW_TTL"))
        if 1<<mul.OFPAT131_SET_FIELD & flag : 
            ret.append(self.__act_dict("SET_FIELD"))
        if 1<<mul.OFPAT131_PUSH_PBB & flag     : ret.append(self.__act_dict("PUSH_PBB"))
        if 1<<mul.OFPAT131_POP_PBB & flag      : ret.append(self.__act_dict("POP_PBB"))
        return ret

    def __get_beem_general_action(self):
        ret = []
        #beem genenral
        ret.append(self.__act_dict("SET_VLAN_VID","INT_TYPE",['0','4094']))
        ret.append(self.__act_dict("SET_VLAN_PCP","INT_TYPE",['0','7']))
        ret.append(self.__act_dict("SET_DL_SRC","MAC_TYPE"))
        ret.append(self.__act_dict("SET_DL_DST","MAC_TYPE"))
        ret.append(self.__act_dict("SET_NW_SRC","IP_TYPE"))
        ret.append(self.__act_dict("SET_NW_DST","IP_TYPE"))
        ret.append(self.__act_dict("SET_NW_SRC6","IPV6_TYPE"))
        ret.append(self.__act_dict("SET_NW_DST6","IPV6_TYPE"))
        ret.append(self.__act_dict("SET_NW_TOS","INT_TYPE",['0','63']))
        ret.append(self.__act_dict("SET_TP_SRC","PORT_TYPE"))
        ret.append(self.__act_dict("SET_TP_DST","PORT_TYPE"))
        ret.append(self.__act_dict("SET_ETH_TYPE","INT_HEX_TYPE"))
        ret.append(self.__act_dict("SET_MPLS_LABEL","INT_TYPE",['1','1048575']))
        ret.append(self.__act_dict("SET_MPLS_TC","INT_TYPE",['0','8']))
        ret.append(self.__act_dict("SET_MPLS_BOS","INT_TYPE",['0','1']))
        return ret

    def __get_table_set_field(self, flag):
        logger.debug(flag)
        ret = []
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IN_PORT)        : ret.append("in_port")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IN_PHY_PORT)    : ret.append("in_phy_port")#
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_METADATA)       : ret.append("metadata")#
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ETH_DST)        : ret.append("dl_dst")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ETH_SRC)        : ret.append("dl_src")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ETH_TYPE)       : ret.append("dl_type")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_VLAN_VID)       : ret.append("dl_vlan")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_VLAN_PCP)       : ret.append("dl_vlan_pcp")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IP_DSCP)        : ret.append("ip_dscp")#
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IP_PROTO)       : ret.append("nw_proto")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IPV4_SRC)       : ret.append("nw_src")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IPV4_DST)       : ret.append("nw_dst")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_TCP_SRC)        : ret.append("tcp_src")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_TCP_DST)        : ret.append("tcp_dst")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_UDP_SRC)        : ret.append("udp_src")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_UDP_DST)        : ret.append("udp_dst")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_SCTP_SRC)       : ret.append("sctp_src")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_SCTP_DST)       : ret.append("sctp_dst")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ICMPV4_TYPE)    : ret.append("ipcmp4_type")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ICMPV4_CODE)    : ret.append("icmp4_code")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ARP_OP)         : ret.append("arp_opcode")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ARP_SPA)        : ret.append("arp_ipv4_src")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ARP_TPA)        : ret.append("arp_ipv4_dst")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ARP_SHA)        : ret.append("arp_src_mac")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IPV6_SRC)       : ret.append("nw_src6")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IPV6_DST)       : ret.append("nw_dst6")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IPV6_FLABEL)    : ret.append("ipv6_fl_label")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ICMPV6_TYPE)    : ret.append("icmpv6_type")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_ICMPV6_CODE)    : ret.append("icmpv6_code")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IPV6_ND_TARGET) : ret.append("ipv6_nd_target")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IPV6_ND_SLL)    : ret.append("ipv6_nd_sll")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_IPV6_ND_TLL)    : ret.append("ipv6_nd_tll")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_MPLS_LABEL)     : ret.append("mpls_label")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_MPLS_TC)        : ret.append("mpls_tc")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_MPLS_BOS)       : ret.append("mpls_bos")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_PBB_ISID)       : ret.append("pbb_isid")
        if mul.get_bit_in_32mask(flag, mul.OFPXMT_OFB_TUNNEL_ID)      : ret.append("tunnel_id")
        return ret

    def __match_dict(self, match_name, match_type=None, range=None):
        ran =None
        if not match_type:
            match_type='NONE_TYPE'
            ran = []
        if not range:
            if match_type=='MAC_TYPE' : ran=['0:0:0:0:0:0','ff:ff:ff:ff:ff:ff']
            if match_type=='IP_TYPE': ran=['0.0.0.0/0','ff.ff.ff.ff/32']
            if match_type=='IPV6_TYPE': ran=['0:0:0:0:0:0:0:0/0','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128']
            if match_type=='STRING_TYPE' : ran=['enable','disable']
            if match_type=='INT_TYPE' : ran=['0','65535']
            if match_type=='INT_HEX_TYPE' : ran=['0x0', '0xffff']
            #if match_type=='PORT_TYPE' : ran=None
        else:
            ran = range
        ret = {
            'match_name' : match_name,
            'match_type' : match_type
        }
        if ran : ret.update({'range':ran})
        return ret

    def __get_beem_match(self):
        ret = [
            self.__match_dict('dl_src','MAC_TYPE',[]),
            self.__match_dict('dl_dst','MAC_TYPE',[]),
            self.__match_dict('dl_type','INT_HEX_TYPE',[]),
            self.__match_dict('dl_vlan','INT_TYPE',['0','4095']),
            self.__match_dict('dl_vlan_pcp','INT_TYPE',['0','7']),
            self.__match_dict('mpls_label','INT_TYPE',['0','1048575']),
            self.__match_dict('mpls_tc','INT_TYPE',['0','7']),
            self.__match_dict('mpls_bos','INT_TYPE',['0','1']),
            self.__match_dict('nw_src','IP_TYPE'),
            self.__match_dict('nw_dst','IP_TYPE'),
            self.__match_dict('nw_src6','IPV6_TYPE'),
            self.__match_dict('nw_dst6','IPV6_TYPE'),
            self.__match_dict('nw_proto','INT_TYPE',['0','255']),
            self.__match_dict('nw_tos','INT_TYPE',['0','63']),
            self.__match_dict('tp_dst','PORT_TYPE'),
            self.__match_dict('tp_src','PORT_TYPE'),
            self.__match_dict('in_port','PORT_TYPE'),
            self.__match_dict('table_id','INT_TYPE',['0','254']),
            self.__match_dict('barrier','STRING_TYPE'),
            self.__match_dict('stat','STRING_TYPE'),
            self.__match_dict('priority','INT_TYPE',[0,65535])
        ]
        return ret


    def get_switch_table(self, *args):
        ret = {}
        try:
            dpid = int(args[0], 16)
            version = mul.nbapi_get_switch_version_with_id(dpid)
            if version == 0:
                raise Exception, 'no such switch'
            table_no = int(args[1], 0)
            table = mul.get_switch_table(dpid, table_no)
            if table:
                ret.update({
                    "tables" : {
                        "match" : self.__get_beem_match(),
                        "instruction": self.__get_table_bminstruction(table.bm_inst),
                        "instruction_miss": self.__get_table_bminstruction(table.bm_inst_miss),
                        "next_table": self.__get_table_next_tables(table.bm_next_tables),
                        "next_table_miss": self.__get_table_next_tables(table.bm_next_tables_miss),
                        "WRITE_ACTIONS": self.__get_act_type(table.bm_wr_actions)+self.__get_beem_general_action(),
                        "WRITE_ACTIONS_miss": self.__get_act_type(table.bm_wr_actions_miss),
                        "APPLY_ACTIONS": self.__get_act_type(table.bm_app_actions)+self.__get_beem_general_action(),
                        "APPLY_ACTIONS_miss": self.__get_act_type(table.bm_app_actions_miss),
                        "set_field": self.__get_table_set_field(table.bm_wr_set_field),
                        "set_field_miss": self.__get_table_set_field(table.bm_wr_set_field_miss),
                        "apply_set_field": self.__get_table_set_field(table.bm_app_set_field),
                        "apply_set_field_miss": self.__get_table_set_field(table.bm_app_set_field_miss)
                }
            })
            else:
                #raise Exception, 'cannot get table feature' if no table feature, suppose as mininet
                ret.update({
                    "tables" : {
                        "match" : self.__get_beem_match(),
                        "instruction": self.__get_table_bminstruction(62),
                        "instruction_miss": [],#self.__get_table_bminstruction(0),
                        "next_table": ['%d' %(i+table_no) for i in range(255-table_no)],#self.__get_table_next_tables(table.bm_next_tables),
                        "next_table_miss": [],#self.__get_table_next_tables(table.bm_next_tables_miss),
                        "WRITE_ACTIONS": self.__get_act_type(234854401)+self.__get_beem_general_action(),
                        "WRITE_ACTIONS_miss": [],#self.__get_act_type(table.bm_wr_actions_miss),
                        "APPLY_ACTIONS": self.__get_act_type(234854401)+self.__get_beem_general_action(),
                        "APPLY_ACTIONS_miss": [],#self.__get_act_type(table.bm_app_actions_miss),
                        "set_field": [],#self.__get_table_set_field(table.bm_wr_set_field),
                        "set_field_miss": [],#self.__get_table_set_field(table.bm_wr_set_field_miss),
                        "apply_set_field": [],#self.__get_table_set_field(table.bm_app_set_field),
                        "apply_set_field_miss": []#self.__get_table_set_field(table.bm_app_set_field_miss)
                }

                })
        except Exception, e:
            ret.update({'error_message':'Falied to get table feature','reason':str(e)})
        finally:
            self.finish(ret)

