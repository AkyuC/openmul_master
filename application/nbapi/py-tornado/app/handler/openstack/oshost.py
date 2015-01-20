import logging
import json
import colander

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("OSHostHandler");
logger.setLevel(logging.DEBUG)

class OSHostHandler(BaseHandler):

    def get(self, tenant_id=None, network_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s",tenant_id)
        if tenant_id or network_id:
            self.raise404()
        ret = []
        hosts = mul.get_fabric_port_tnid_all()
        for host in hosts:
            ret.append({
                'tenant_id' : mul.nbapi_uuid_to_str(host.tenant_id),
                'network_id' : mul.nbapi_uuid_to_str(host.network_id),
                'switch_dpid' : '0x%lx' % host.datapath_id,
                'port' : '%hu' %host.port
            })
        self.finish({"hosts" : ret })

    def options(self, tenant_id=None, network_id=None):
        self.write("ok")

    def post(self, tenant_id=None, network_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s",tenant_id)
        ret = {}
        
        try:
            body = HostSchema().deserialize(json.loads(self.request.body))
            logger.debug(str(body))
            res = mul.add_del_fabric_port_tnid( int(body['dpid'], 16),
                                            str(tenant_id), 
                                            str(network_id), 
                                            str(body['in_port']), 
                                            True)
            if res == 1:
                ret = {"succeess" : "new openstack host added"}
            elif res == -2:
                raise Exception, "tenant id is not uuid format"
            elif res == -3:
                raise Exception, "network id is not uuid format"
            else:
                raise Exception, "add openstack host fail"

            check = self.__add_fabric_host(tenant_id, network_id, body)
            self.finish(ret)
        except Exception, e:
            ret.update({"error_message" : "failed to add openstack host" , 
                        "reason" : str(e)})
            self.send_error(400)


    def put(self, tenant_id=None, network_id=None):
        self.write({"message":"post"})

    def delete(self, tenant_id=None, network_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s",tenant_id)
        ret = {}
        try :
            body = HostSchema().deserialize(json.loads(self.request.body))
            logger.debug(str(body))
            res = mul.add_del_fabric_port_tnid(int(body['datapath_id'], 16), str(tenant_id), str(network_id), str(body['port']), False) 
            if res == 1:
                ret = {"succeess" : "new openstack host deleted"}
            elif res == -2:
                raise Exception, "tenant id is not uuid format"
            elif res == -3:
                raise Exception, "network id is not uuid format"
            else:
                raise Exception, "del openstack host fail"
        except Exception, e:
            ret.update({"error_message" : "failed to del openstack host" , "reason" : str(e)})
        finally:
            self.finish(ret)

    def __add_fabric_host(self, tenant_id, network_id, body):
        logger.debug(str(body))
        check = mul.add_fabric_host(int(str(body['dpid']), 16),
                                    str(tenant_id),
                                    str(network_id),
                                    str(body['nw_src']),
                                    str(body['dl_src']),
                                    str(body['in_port']),
                                    str(body['is_gw']))
        if check == 1:
            return True
        elif check == -2:
            raise Exception, 'Malformed tenant id'
        elif check == -3:
            raise Exception, 'Malformed network id'
        elif check == -4:
            raise Exception, 'Malformed nw_src'
        elif check == -5:
            raise Exception, 'Malformed dl_src'
        else:
            raise Exception, 'failed to add fabric host'


class HostSchema(colander.MappingSchema):
    dpid = colander.SchemaNode(colander.String(), missing=None)
    in_port = colander.SchemaNode(colander.String(), missing=None)
    is_gw = colander.SchemaNode(colander.String(),
                                validator=colander.OneOf(['yes','no']))
    nw_src = colander.SchemaNode(colander.String(),
                                  validator=colander.Regex(r"([0-9A-Fa-f]{1,3}[.]){3}[0-9A-Fa-f]{1,2}([/][0-9]{0,3}){0,1}"))
    dl_src = colander.SchemaNode(colander.String(),
                                   validator=colander.Regex(r"([0-9A-Fa-f]{1,2}[:]){5}([0-9A-Fa-f]{1,2})"))





















