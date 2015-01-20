import logging
import json
import colander

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("RouteHandler");
logger.setLevel(logging.DEBUG)

class RouteHandler(BaseHandler):

    def get(self, src=None, dst=None):
        logger.debug("request url - %s", self.get_request_uri())
        if src and dst:
            if str(src).startswith('0x') and str(dst).startswith('0x') :
                self.get_route_srcTodst(src, dst)
            elif ":" in str(src):
                self.finish({'route' : "host src_mac to dst_mac not supported yet"})
            elif '.' in str(src):
                self.finish({'route' : 'host src_ip to src_ip not supported yet'})
        elif not src and not dst:
            self.get_route_all()
        else:
            self.finish("><")

    def get_route_srcTodst(self, src_dpid, dst_dpid):
        src_sw = mul.get_switch_general(int(src_dpid, 16))
        dst_sw = mul.get_switch_general(int(dst_dpid, 16))
        src_alias = mul.parse_alias_id(src_sw.sw_alias)
        dst_alias = mul.parse_alias_id(dst_sw.sw_alias)
         #logger.debug("src_alias : %d, dst_alias : %d", src_alias, dst_alias)
        #route_path = mul.get_simple_path(src_alias, int(src_port), dst_alias, int(dst_port))
        route_path = mul.get_simple_path(src_alias, dst_alias)
        ret = []
        for i in range(len(route_path)):
            node = route_path[i]
            ret.append({
                'hop' : i,
                'to_switch' : '0x%lx' % node.sw_dpid,
                'to_sw_port' : None if node.sw_dpid==int(dst_dpid,16) else node.in_port
            })
        self.finish({'path': ret})


    def get_route_all(self):
        route_list = mul.nbapi_get_fabric_route_all()
        ret = {}
        ret_list = []
        for route in route_list:
            ret_dict = self.__route_serialize(route) 
            ret_list.append(ret_dict)
        self.finish({'routes' : ret_list})

    def options(self, src_dpid, src_port, dst_dpid, dst_port):
        self.finish("ok")

    def post(self):
        ret = {}
        try:
            body = RouteSchema().deserialize(json.loads(self.request.body))
            logger.debug(str(body))
            if body['nw_src'] and body['dl_src'] and body['nw_dst'] and body['dl_dst']:
                ret = self.__get_host_route_src2dst(body)
            else:
                if body['nw_src'] and body['dl_src']:
                    ret = self.__get_host_route_from_src(body)
                elif body['nw_dst'] and body['dl_dst']:
                    ret = self.__get_host_route_dst_to(body)
                else:
                    self.raise_404() 
        except Exception, e:
            ret = {'error_message' : 'failed to get routes', 'reason' : str(e)}
        finally:
            self.finish(ret)


    def __get_host_route_src2dst(self, body):
        route_list = mul.nbapi_get_host_route(str(body['tenant_id']),
                                              str(body['network_id']),
                                              str(body['nw_dst']),
                                              str(body['dl_dst']))
        ret_list = []
        for route in route_list:
            ret_dict = None
            if body['dl_src'] and body['nw_src']:
                if mul.nbapi_compare_src_host(route.src_host.host_flow,
                                              str(body['dl_src']),
                                              str(body['nw_src']))==1:
                    ret_dict = self.__route_serialize(route)
            else:
                ret_dict = self.__route_serialize(route)
            if ret_dict:
                ret_list.append(ret_dict)

        return {'routes' : ret_list}

    def __get_host_route_dst_to(self, body):
        route_list = mul.nbapi_get_host_route(str(body['tenant_id']),
                                              str(body['network_id']),
                                              str(body['nw_dst']),
                                              str(body['dl_dst']))
        ret_list = []
        for route in route_list:
            ret_dict = None
            ret_dict = self.__route_serialize(route)
            ret_list.append(ret_dict)
        return {'routes' : ret_list}

    def __get_host_route_from_src(self, body):
        route_list = mul.nbapi_get_fabric_route_all()
        ret_list = []
        for route in route_list:
            ret_dict = None
            if mul.nbapi_compare_src_host(route.src_host.host_flow,
                                          str(body['dl_src']),
                                          str(body['nw_src']))==1:
                ret_dict = self.__route_serialize(route)
                ret_list.append(ret_dict)
        return {'routes' : ret_list}

    def __route_serialize(self, route):
        return {
                    'src_host' : {
                        'tenant_id' : mul.nbapi_uuid_to_str(route.src_host.tenant_id),
                        'network_id' : mul.nbapi_uuid_to_str(route.src_host.network_id),
                        'dl_src' : mul.nbapi_parse_mac_to_str(route.src_host.host_flow.dl_src),
                        'nw_src' : mul.nbapi_fab_parse_nw_addr_to_str(route.src_host.host_flow),
                        'switch_dpid' : '0x%lx' % route.src_host.switch_id.datapath_id,
                        'port' : '%hu' % route.src_host.host_flow.in_port
                    },
                    'dst_host' : {
                        'tenant_id' : mul.nbapi_uuid_to_str(route.dst_host.tenant_id),
                        'network_id' : mul.nbapi_uuid_to_str(route.dst_host.network_id),
                        'dl_src' : mul.nbapi_parse_mac_to_str(route.dst_host.host_flow.dl_src),
                        'nw_src' : mul.nbapi_fab_parse_nw_addr_to_str(route.dst_host.host_flow),
                        'switch_dpid' : '0x%lx' % route.dst_host.switch_id.datapath_id,
                        'port' : '%hu' % route.dst_host.host_flow.in_port
                    },
                    'route_link' : eval(route.str_route)
               }

    def put(self, src_dpid, src_port, dst_dpid, dst_port):
        pass

    def delete(self, src_dpid, src_port, dst_dpid, dst_port):
         pass

class RouteSchema(colander.MappingSchema):
    tenant_id = colander.SchemaNode(colander.String(),
                                        validator=colander.Regex(r"[0-9a-zA-Z-]+"))
    network_id = colander.SchemaNode(colander.String(),
                                        validator=colander.Regex(r"[0-9a-zA-Z-]+"))
    dl_src =    colander.SchemaNode(colander.String(),
                                    missing=None,
                                    validator=colander.Regex(r"([0-9A-Fa-f]{1,2}[:]){5}([0-9A-Fa-f]{1,2})"))
    dl_dst =    colander.SchemaNode(colander.String(),
                                    missing=None,
                                    validator=colander.Regex(r"([0-9A-Fa-f]{1,2}[:]){5}([0-9A-Fa-f]{1,2})"))
    nw_dst =    colander.SchemaNode(colander.String(),
                                    missing=None,
                                    validator=colander.Regex(r"([0-9a-fA-F]{1,4}(\.|:))+[0-9a-fA-F]{1,4}(/[0-9a-fA-F]{1,4}){0,1}"))
    nw_src =    colander.SchemaNode(colander.String(),
                                    missing=None,
                                    validator=colander.Regex(r"([0-9a-fA-F]{1,4}(\.|:))+[0-9a-fA-F]{1,4}(/[0-9a-fA-F]{1,4}){0,1}"))
