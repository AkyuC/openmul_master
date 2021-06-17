import json
import logging

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler
from app.handler.stats import StatHandler

logger = logging.getLogger("SwitchHandler")
logger.setLevel(logging.DEBUG)


class SwitchHandler(BaseHandler):
    """
    This Handler manages the following URL:
        GET     topology/switch                             : get_switch_all
        GET     topology/switch/{dpid}                      : get_switch(dpid)
        GET     topology/switch/all                         : get_switch_general_all
        GET     topology/switch/{dpid}/limit                : get_switch_limit(dpid)
        POST    topology/switch/{dpid}/limit                : set_switch_limit(dpid)
        GET     topology/switch/{dpid}/port                 : get_switch_port_all(dpid)
        GET     topology/switch/all/port                    : get_all_switch_port
        GET     topology/switch/{dpid}/port/{port_no}       : get_switch_port(dpid)
    """
    BASE_URL = "/topology/switch" 

    request_mapper = {
        "^$":                             "get_switch_all",
        "^all$":                          "get_switch_general_all",
        "^0x[0-9a-fA-F]+$":               "get_switch",
        "^all/port$":                     "get_all_switch_port",
        "^0x[0-9a-fA-F]+/port$":          "get_switch_port_all",
        "^0x[0-9a-fA-F]+/port/[0-9]+$":   "get_switch_port",
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
        if res:
            res = self.__ofp_switch_add_serialization(res)
        else:
            res = {}
        self.write(json.dumps(res))

#this fuction is for avior
    def get_switch_general_all(self, *args):
        res = {}
        try:
            ret = []
            switches = mul.get_switch_all()
            for switch in switches:
                sw_gnr = mul.get_switch_general(switch.switch_id.datapath_id)
                ports = mul.get_switch_port_all(switch.switch_id.datapath_id)
                sw_with_port = self.__ofp_switch_add_serialization(sw_gnr)
                sw_with_port['ports'] = [self.__ofp_phy_port_serialization(port) for port in ports]
                ret.append(sw_with_port)
            res = {'switches' : ret}
        except Exception, e:#no switch
            res = {'error_message' : 'Falied to get all switch general feature', 'reason':str(e)}
        self.finish(res)

    def get_switch_port_all(self, *args):
        dpid = int(args[0], 0)
        res = mul.get_switch_port_all(dpid)
        if res:
            res = [self.__ofp_phy_port_serialization(port) for port in res]
            self.finish(json.dumps({
                'ports': res
            }))
        else:
            self.finish({'error_message' : 'Falied to get port' , 'reason' : 'no such switch'})

    def get_switch_port(self, *args):
        try:
            dpid = int(args[0], 0)
            port_no = int(args[1])
            res = mul.get_switch_port(dpid, port_no)
            if res:
                res = self.__ofp_phy_port_serialization(res)
                self.finish(json.dumps(res))
            else:
                raise Exception, 'no such port'
        except Exception, e:
            self.finish({'error_message' : 'Failed to get port', 'reason' :
                    str(e)})

    def get_all_switch_port(self, *args):
        res = {}
        try:
            ret = []
            switches = mul.get_switch_all()
            for switch in switches:
                ports = mul.get_switch_port_all(switch.switch_id.datapath_id)
                sw_ports = [self.__ofp_phy_port_serialization(port) for port in ports]
                ret.append({'dpid' : '0x%lx' % switch.switch_id.datapath_id , 'ports' : sw_ports})
            res={'switch_ports':ret} 
        except Exception, e:
            res={'error_message' : 'failed to get all switch ports', 'reason' :  str(e)}
        self.finish(res)

    def handle_limit(self, *args):
        ret = {}
        try:
            if self.request.method in 'GET':
                res = self.__get_switch_rate_limit(args[0])
                if res:
                    ret = res
                else:
                    raise Exception, "Failed to get limit features"
            elif self.request.method in 'POST':
                res = self.__set_switch_rate_limit(args[0])
                if res:
                    ret = res
                else:
                    raise Exception, "Failed to set limit features"
        except Exception, e:
            ret.update({'error_message':str(e)})
        finally:
            self.finish(ret)

    def __to_str_switch_state(self, status):
        if status == 0 : return "Init"
        elif status & mul.SW_PUBLISHED : return "Published"
        elif status & mul.SW_REGISTERED : return "Registerd"
        elif status & mul.SW_REINIT : return "Reinit"
        elif status & mul.SW_REINIT_VIRT : return "Reinit|Virt"
        elif status & mul.SW_DEAD : return "Dead"
        return "Unknown"

    def __nbapi_switch_brief_list_t_serialization(self, resp):
        res = []
        for s in resp:
            res.append(
                {'flows':   str(mul.get_flow_number(s.switch_id.datapath_id)),
                 'status':  self.__to_str_switch_state(s.state),
                 'meters':  str(mul.get_meter_number(s.switch_id.datapath_id)),
                 'groups':  str(mul.get_group_number(s.switch_id.datapath_id)),
                 'dpid':    '0x%lx' % s.switch_id.datapath_id,
                 'peer':    s.conn_str,
                 'ports':   str(s.n_ports)}
            )
        return {'switches': res}

    def __general_capabilities_tostr(self, flag):
        ret = []
        if flag == 0 : return ret
        if flag & mul.OFPC_FLOW_STATS : ret.append("FLOW_STATS")
        if flag & mul.OFPC_TABLE_STATS : ret.append("TABLE_STATS")
        if flag & mul.OFPC_PORT_STATS : ret.append("PORT_STATS")
        if flag & mul.OFPC_STP : ret.append("STP")
        if flag & mul.OFPC_IP_REASM : ret.append("IP_REASM")
        if flag & mul.OFPC_QUEUE_STATS : ret.append("QUEUE_STATS")
        if flag & mul.OFPC_ARP_MATCH_IP : ret.append("ARP_MATCH_IP")
        return ret

    def __general131_capabilities_tostr(self, flag):
        ret = []
        if flag == 0 : return ret
        if flag & mul.OFPC131_FLOW_STATS : ret.append("FLOW_STATS")
        if flag & mul.OFPC131_TABLE_STATS : ret.append("TABLE_STATS")
        if flag & mul.OFPC131_PORT_STATS : ret.append("PORT_STATS")
        if flag & mul.OFPC131_GROUP_STATS : ret.append("GROUP_STATS")
        if flag & mul.OFPC131_IP_REASM : ret.append("IP_REASM")
        if flag & mul.OFPC131_QUEUE_STATS : ret.append("QUEUE_STATS")
        if flag & mul.OFPC131_PORT_BLOCKED : ret.append("PORT_BLOCKED")
        return ret

    def __ofp_switch_add_serialization(self, resp):
        of_ver = 'not supported'
        capabilities = ""
        if resp.ver &  mul.OFP_VERSION:
            of_ver = '1.0'
            capabilities = self.__general_capabilities_tostr(resp.capabilities)
        elif resp.ver & mul.OFP_VERSION_131:
            of_ver = '1.3'
            capabilities = self.__general131_capabilities_tostr(resp.capabilities)

        result = {
            'dpid'      :   '0x%lx' % resp.datapath_id,
            'alias_id'  :   mul.parse_alias_id(resp.sw_alias),
            'n_buffers' :   resp.n_buffers,
            'n_tables'  :   resp.n_tables,
            'capabilites':  capabilities,
            'actions':      resp.actions,
            'ports':        (resp.header.length-40)/64,
            'of_version':   of_ver
        }
        return result

    def __ofp_phy_port_serialization(self, resp):
        return {
            'port_no':      resp.port_no,
            'hw_addr':      mul.nbapi_parse_mac_to_str(resp.hw_addr),
            'name':         unicode(str(resp.name), errors='ignore'),
            'config':       'PORT_DOWN' if resp.config & 0x1 else 'PORT_UP' ,
            'state':        'LINK_DOWN' if resp.state & 0x1 else 'LINK_UP' ,
            'curr':         resp.curr,
            'advertised':   resp.advertised,
            'supported':    resp.supported,
            'peer':         resp.peer
        }

    def __get_switch_rate_limit(self, dpid):
        dpid = int(dpid, 0)
        rx = mul.get_switch_pkt_rx_rlim(dpid)
        tx = mul.get_switch_pkt_tx_rlim(dpid)

        if rx < 0 or tx < 0:
            return None

        result = {
            "rx": {
                "status":   'Disable' if rx == 0 else 'Enable' ,
                "limit":    rx
            },
            "tx" : {
                "status":   'Disable' if tx == 0 else 'Enable',
                "limit":    tx
            }
        }
        return result

    def __set_switch_rate_limit(self, dpid):
        dpid = int(dpid, 0)
        data = json.loads(self.request.body)
        rx = data['rx']
        tx = data['tx']

        if mul.nbapi_set_switch_pkt_rx_rlim(dpid, rx) != 0:
            return None

        if mul.nbapi_set_switch_pkt_tx_rlim(dpid, tx) != 0:
            return None

        return {
            "rx": 'Disable' if rx == 0 else 'Enable',
            "tx": 'Disable' if tx == 0 else 'Enable'
        }
