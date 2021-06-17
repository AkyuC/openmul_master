import json
import logging

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler
#from app.handler.ids import FlowHolder

logger = logging.getLogger("StatHandler")
logger.setLevel(logging.DEBUG)


class StatHandler(BaseHandler):
    """
    This Handler manages the following URL:
        GET     stats/switch/{dpid}/flow/{flow_id}           : get_(dpid)
        GET     stats/switch/{dpid}/port/{port_no}           : get_(dpid)
        GET     stats/switch/{dpid}/port/all                 : get_(dpid)
    """
    BASE_URL = "/stats/switch"

    request_mapper = {
        "^0x[0-9a-fA-F]+/flow/[0-9a-fA-F-]+$":  "get_flow_stat",
        "^0x[0-9a-fA-F]+/port/[0-9]+$":         "get_port_stat",
        "^0x[0-9a-fA-F]+/port/all$":            "get_port_stat_all",
    }

    def get_request_mapper(self):
        return self.request_mapper

    def get_base_uri(self):
        return self.BASE_URL

    def get(self, dpid=None, stat_id=None):
        self.__execute(dpid, stat_id)

    def options(self, dpid=None, stat_id=None):
        self.write("ok")

    def post(self, dpid=None, stat_id=None):
        self.write("ok")

    def __execute(self, *args):
        func = self.match()
        logger.debug("matched func: %s, args: %s", func, args)
        if func is not None:
            getattr(self, func)(*args)

    def get_port_stat(self, *args):
        dpid = int(args[0],16)
        port_no = int(args[1], 0)
        ret = {}
        try:
            ret = self.__get_port_stat(dpid, port_no)
        except Exception, e:
            ret = {'error_message' : 'Failed to get port stat', 'reason' : str(e)}
        finally:
            self.finish(ret)

    def get_port_stat_all(self, *args):
        ret={}
        try:
            dpid = args[0]
            port_nos = [port.port_no for port in mul.get_switch_port_all(int(dpid, 0))]
            port_stats = [self.__get_port_stat(int(dpid,16), port_no) for port_no in port_nos ]
            ret.update({'port_stats': port_stats})
        except Exception, e:
            ret.update({'error_message' : 'Failed to get port stat', 'reason' : str(e)})
        finally:
            self.finish(ret)

    def __get_port_stat(self, dpid, port_no):
        ret = {}
        version = mul.nbapi_get_switch_version_with_id(dpid)
        if version == 0:
            raise Exception, 'no such switch'
        elif version == 0x1:
            port_stat = mul.show_port_stats(dpid, port_no)
            ret = self.__port_serialization(port_stat)
        elif version == 0x4:
            port_stat = mul.show_port_stats131(dpid, port_no)
            ret = self.__port_serialization131(port_stat)
        elif version == 0x5:
            port_stat = mul.show_port_stats140(dpid, port_no)
            ret = self.__port_serialization140(port_stat)
            prop_type = mul.get_ofp140_port_stats_prop_type(port_stat)
            if prop_type == -1:#no
                pass
            elif prop_type == mul.OFPPSPT_ETHERNET:#0
                eth_prop = mul.show_ofp_port_stats_prop_ethernet(port_stat)
                ret.update(self.__port_eth_prop_serialization(eth_prop))
            elif prop_type == OFPPSPT_OPTICAL:#1
                opt_prop = mul.show_ofp_port_stats_prop_optical(port_stat)
                ret.update(self.__port_opt_prop_serialization(opt_prop))
            else:
                pass
        if ret is None:
            raise Exception, 'No such port on switch'
        return ret

    def __port_serialization(self, port_stat):
        return {
                    'port_no':       port_stat.port_no,
                    'rx_packets':    port_stat.rx_packets,
                    'tx_packets':    port_stat.tx_packets,
                    'rx_bytes':      port_stat.rx_bytes,
                    'tx_bytes':      port_stat.tx_bytes,
                    'rx_dropped':    port_stat.rx_dropped,
                    'tx_dropped':    port_stat.tx_dropped,
                    'rx_errors':     port_stat.rx_errors,
                    'tx_errors':     port_stat.tx_errors,
                    'rx_frame_err':  port_stat.rx_frame_err,
                    'rx_over_err':   port_stat.rx_over_err,
                    'rx_crc_err':    port_stat.rx_crc_err,
                    'collisions':    port_stat.collisions,
                    'duration_sec':  -1,
                    'duration_nsec': -1 
               }

    def __port_serialization131(self, port_stat):
        return {
                    'port_no':       port_stat.port_no,
                    'rx_packets':    port_stat.rx_packets,
                    'tx_packets':    port_stat.tx_packets,
                    'rx_bytes':      port_stat.rx_bytes,
                    'tx_bytes':      port_stat.tx_bytes,
                    'rx_dropped':    port_stat.rx_dropped,
                    'tx_dropped':    port_stat.tx_dropped,
                    'rx_errors':     port_stat.rx_errors,
                    'tx_errors':     port_stat.tx_errors,
                    'rx_frame_err':  port_stat.rx_frame_err,
                    'rx_over_err':   port_stat.rx_over_err,
                    'rx_crc_err':    port_stat.rx_crc_err,
                    'collisions':    port_stat.collisions,
                    'duration_sec':  port_stat.duration_sec,
                    'duration_nsec': port_stat.duration_nsec
                }

    def __port_serialization140(self, port_stat):
        return {
                    'port_no':       port_stat.port_no,
                    'rx_packets':    port_stat.rx_packets,
                    'tx_packets':    port_stat.tx_packets,
                    'rx_bytes':      port_stat.rx_bytes,
                    'tx_bytes':      port_stat.tx_bytes,
                    'rx_dropped':    port_stat.rx_dropped,
                    'tx_dropped':    port_stat.tx_dropped,
                    'rx_errors':     port_stat.rx_errors,
                    'tx_errors':     port_stat.tx_errors,
                    'rx_frame_err':  -1,
                    'rx_over_err':   -1,
                    'rx_crc_err':    -1,
                    'collisions':    -1,
                    'duration_sec':  port_stat.duration_sec,
                    'duration_nsec': port_stat.duration_nsec
               }

    def __port_eth_prop_serialization(self, eth_prop):
        return {
                    'rx_frame_err' : eth_prop.rx_frame_err,
                    'rx_over_err' : eth_prop.rx_over_err,
                    'rx_crc_err' : eth_prop.rx_crc_err,
                    'collisions' : eth_prop.collisions
               }

    def __port_opt_prop_serialization(self, opt_prop):
        return {
                    'flags' : opt_prop.flags,
                    'tx_freq_lmda' : opt_prop.tx_freq_lmda,
                    'tx_offset' : opt_prop.tx_offset,
                    'tx_grid_span' : opt_prop.tx_grid_span,
                    'rx_freq_lmda' : opt_prop.rx_freq_lmda,
                    'rx_offset' : opt_prop.rx_offset,
                    'rx_grid_span' : opt_prop.rx_grid_span,
                    'tx_pwr' : opt_prop.tx_pwr,
                    'rx_pwr' : opt_prop.rx_pwr,
                    'bais_current' : opt_prop.bias_current,
                    'temperature' : opt_prop.temperature
               }

    def get_flow_stat(self, *args):
        ret = {}
        try :
            dpid = int(args[0], 16)
            version = mul.nbapi_get_switch_version_with_id(dpid)#int(dpid, 16))
            if version == 0:
                raise Exception, 'no such switch'
            flow_id = str(args[1])
            flow = None
            #flow = FlowHolder.getInstance().get(flow_id)

            ret.update({
                "flow_id":      flow_id,
                'bps':          mul.nbapi_parse_bps_to_str(flow.bps),
                'pps':          mul.nbapi_parse_bps_to_str(flow.pps),
                'pkt_count':    flow.packet_count,
                'byte_count':   flow.byte_count
            })
        except KeyError:
            ret.update({'error_message':'Failed to get flow stats', 'reason':'No such flow_id'})
        finally:
            self.finish(ret)
