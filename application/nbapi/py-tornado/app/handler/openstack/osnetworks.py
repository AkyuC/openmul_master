import logging
import json
import colander

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("OSNetworksHandler");
logger.setLevel(logging.DEBUG)

class OSNetworksHandler(BaseHandler):

    def get(self, tenant_id=None, network_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s",tenant_id)
        ret = []
        try:
            tenants = mul.get_fabric_tenant_net_all()
            for tenant in tenants:
                ret.append({'tenant_id' : mul.nbapi_uuid_to_str(tenant.tenant_id), 
                            'network_id' : mul.nbapi_uuid_to_str(tenant.network_id)})
        except SystemError:
            pass
        finally:
            self.finish({'tenant_and_networks' : ret})

    def options(self, tenant_id=None, network_id=None):
        self.write("ok")

    def post(self, tenant_id=None, network_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s",tenant_id)
        self.raise_404()
#        if tenant_id is None and network_id is None:
#            self.write({"message":"post"})
#        elif tenant_id and network_id:
#            mul.osfabric_network_mod(str(tenant_id), str(network_id), True)
#            self.write("good")

    def put(self, tenant_id=None, network_id=None):
        self.write({"message":"post"})

    def delete(self, tenant_id=None, network_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s", tenant_id)
        self.raise_404()
#        if tenant_id is None and network_id is None:
#            self.write({"message" : "delete"})
#        elif tenant_id and network_id:
#            mul.osfabric_network_mod(str(tenant_id), str(network_id), False)
#            self.write("good")

class Network(colander.MappingSchema):
    name = colander.SchemaNode(colander.String(), missing=None)
    admin_state_up = colander.SchemaNode(colander.String(), validator=colander.OneOf(['true','false']), missing=None)

class NetworkSchema(colander.MappingSchema):
    network = Network()

class NetworkList(colander.SequenceSchema):
    network = Network()

class MultipleNetworkSchema(colander.MappingSchema):
    networks = NetworkList() 


















