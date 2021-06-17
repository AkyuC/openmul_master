import json
import logging

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("TopologyHandler")
logger.setLevel(logging.DEBUG)


class TopologyHandler(BaseHandler):

    def get(self, dpid=None, dst_dpid=None):
        if dpid is None:
            self.finish(json.dumps(self.get_all_topology()))
        elif dpid and dst_dpid==None:
            dpid = int(dpid, 16)
            self.finish(json.dumps(self.get_switch_neighbor(dpid)))
        elif dpid and dst_dpid:
            self.finish(json.dumps(self.get_switch_route(dpid, dst_dpid)))

    def get_all_topology(self):
        try :
            switch_list = mul.get_switch_all()
        except :
            return []
        result = []
        for sw in switch_list:
            dpid = sw.switch_id.datapath_id
            neigh = self.get_switch_neighbor(dpid)
            result.append({"dpid" : '0x%lx' % dpid, "neighbors": neigh})
        return result

    def get_switch_neighbor(self, dpid):
        ret = None
        try:
            resp = mul.get_switch_neighbor_all(dpid)
            ret = ret = self.__nbapi_port_neigh_list_t_serialization(resp) 
        except:
            ret = {"error_message" : "failed to get neighbor"}
            
        return ret

    def __nbapi_port_neigh_list_t_serialization(self, resp):
        result = []
        for neigh in resp:
            ret = {
                'port' : neigh.port_no,
            }

            if neigh.neigh_present & mul.COFP_NEIGH_SWITCH:
                ret.update({
                    'status' : 'switch',
                    'neigh_dpid' : '0x%lx' % neigh.neigh_dpid ,
                    'niegh_port' : neigh.neigh_port
                  })
            else:
                ret.update({
                    'status' : 'external'
                })
            result.append(ret)            
        return result

    def get_switch_route(self, src_dpid, dst_dpid):
        src_sw = mul.get_switch_general(int(src_dpid, 16))
        dst_sw = mul.get_switch_general(int(dst_dpid, 16))
        src_alias = mul.parse_alias_id(src_sw.sw_alias)
        dst_alias = mul.parse_alias_id(dst_sw.sw_alias)
        route_path = mul.get_simple_path(src_alias, dst_alias)
        ret = []
        for i in range(len(route_path)):
            node = route_path[i]
            ret.append({
                'hop' : i,
                'to_switch' : '0x%lx' % node.sw_dpid,
                'to_sw_port' : None if node.sw_dpid==int(dst_dpid,16) else node.in_port
            })
        return {'path': ret}

