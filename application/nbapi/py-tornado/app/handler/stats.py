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
    """
    BASE_URL = "/stats/switch"

    request_mapper = {
        "^0x[0-9a-fA-F]+/flow/[0-9a-fA-F-]+$":  "get_flow_stat",
        "^0x[0-9a-fA-F]+/port/[0-9]+$":         "get_port_stat",
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
        ret = {}
        try:
            dpid = args[0]
            version = mul.nbapi_get_switch_version_with_id(int(dpid, 16))
            if version == 0:
                raise Exception, 'no such switch'
            port_no = int(args[1])
            port_stat = mul.show_port_stats(int(dpid,16), port_no)

            if port_stat:
                ret.update({
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
                })
            else:
                raise Exception, 'No such port on switch'
        except Exception, e:
            ret.update({'error_message' : 'Failed to get port stat', 'reason' : str(e)})
        finally:
            self.finish(ret)

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
