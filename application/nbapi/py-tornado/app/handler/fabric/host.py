import logging
import json
import colander
import uuid

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("HostHandler");
logger.setLevel(logging.DEBUG)

class HostHandler(BaseHandler):

    def get(self):#, tenant_id=None, network_id=None, host_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        hosts = mul.get_fabric_host_all(1)
        logger.debug(str(len(hosts)))
        ret = []
        for host in hosts:
            host_flow = host.host_flow
            host_ip = mul.nbapi_fab_parse_nw_addr_to_str(host_flow)
            host_mac = mul.nbapi_parse_mac_to_str(host_flow.dl_src)
            res_d = {
                'tenant_id' : mul.nbapi_uuid_to_str(host.tenant_id),
                'network_id' : mul.nbapi_uuid_to_str(host.network_id),
                'dl_src' : host_mac,
                'nw_src' : host_ip,
                'switch_dpid' : '0x%lx' % host.switch_id.datapath_id,
                'port' : '%4hu' %host_flow.in_port
            }
            ret.append(res_d)
        self.finish({'hosts' : ret })
        

    def options(self, tenant_id=None, network_id=None, host_id=None):
        self.write("ok")

    def post(self, tenant_id=None, network_id=None):#, host_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        self.__add_host(tenant_id, network_id)

    def put(self, tenant_id=None, network_id=None, host_id=None):
        self.write({"message":"put"})

    def delete(self, tenant_id=None, network_id=None, host_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("tenant_id : "+str(tenant_id)+", network_id : "+str(network_id))
        if host_id:
            self.__delete_host(tenant_id, network_id, host_id)
        else:
            self.raise_404()

    def __add_host(self, tenant_id, network_id):
        ret = {}
        try:
            #tenants = mul.get_fabric_tenant_net_all()
        #    check = -1
        #    for tenant in tenants:
#                if str(mul.nbapi_uuid_to_str(tenant.tenant_id)) == str(tenant_id) and \
#                   str(mul.nbapi_uuid_to_str(tenant.network_id)) == str(network_id):
#                    check = 0
#            if check == -1:
#                raise Exception, 'no such tenant and network id'
            body = HostSchema().deserialize(json.loads(self.request.body))
            logger.debug(str(body))
            check = mul.add_fabric_host(int(str(body['dpid']), 16),
                                        str(tenant_id),
                                        str(network_id),
                                        str(body['nw_src']),
                                        str(body['dl_src']),
                                        str(body['in_port']),
                                        str(body['is_gw']))
            if check == 1:
                ret.update({'add host' : 'success' , 'host_id' : 'later..'})
            elif check == -2:
                raise Exception, 'Malformed tenant id'
            elif check == -3:
                raise Exception, 'Malformed network id'
            elif check == -4:
                raise Exception, 'Malformed nw_src'
            elif check == -5:
                raise Exception, 'Malformed dl_src'
            else:
                raise Exception, 'failed to add host'
        except Exception, e:
            ret.update({'error_message' : 'failed to add host', 'reason' : str(e)})
        finally:
            self.finish(ret)

    def __delete_host(self, tenant_id, network_id, host_ip):
        ret={}
        try:
            hosts = mul.get_fabric_host_all(1)
            check = 0
            for host in hosts:
                host_flow = host.host_flow
                if str(tenant_id) == str(mul.nbapi_uuid_to_str(host.tenant_id)) and str(network_id) == str(mul.nbapi_uuid_to_str(host.network_id)) and str(host_ip) == str(mul.nbapi_fab_parse_nw_addr_to_str(host_flow)):
                    host_mac = mul.nbapi_parse_mac_to_str(host_flow.dl_src)
                    check = mul.delete_fabric_host(str(tenant_id), str(network_id), str(host_ip), str(host_mac))
                    if check == 1:
                        ret.update({'delete host' : 'success'})
                        break
                    elif check == -1:
                        raise Exception , 'Malformed tenant_id'
                    elif check == -2:
                        raise Exception , 'Malformed network_id'
                    elif check == -3:
                        raise Exception , 'Malformed host_ip(nw_src)'
                    elif check == -4:
                        raise Exception , 'Malformed host_mac(dl_src)'
                    elif check == -5:
                        raise Exception , 'failed to delete host'
            if check == 0:
                raise Exception , 'no such host'
        except Exception, e:
            ret.update({'fail' : 'failed to delete host', 'reason' : str(e)})
        finally:
            self.finish(ret)


class HostSchema(colander.MappingSchema):
    nw_src = colander.SchemaNode(colander.String(),
                                  validator=colander.Regex(r"([0-9A-Fa-f]{1,3}[.]){3}[0-9A-Fa-f]{1,2}([/][0-9]{0,3}){0,1}"))
    dl_src = colander.SchemaNode(colander.String(),
                                   validator=colander.Regex(r"([0-9A-Fa-f]{1,2}[:]){5}([0-9A-Fa-f]{1,2})"))
    dpid = colander.SchemaNode(colander.String(),
                               validator=colander.Regex(r"0x[0-9A-Fa-f]+"))
    in_port = colander.SchemaNode(colander.String(),
                                  validator=colander.OneOf(["%d" %i for i in range(65536)]))
    is_gw = colander.SchemaNode(colander.String(),
                                validator=colander.OneOf(['yes','no']))




















