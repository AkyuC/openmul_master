import logging
import json

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("NetworkHandler");
logger.setLevel(logging.DEBUG)

class NetworkHandler(BaseHandler):

    def get(self):#, network_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        #logger.debug("request params - network_id: %s",network_id)
        #self.write({"message":"get"})
        ret = [] 
        tn_list = mul.get_fabric_tenant_net_all()
        for tn in tn_list:
            ret.append({
                "tenant_id" : tn.tenant_id,
                "network_id" : tn.network_id })
        self.finish({"tenant_network" : ret })

    def options(self, network_id=None):
        self.write("ok")

    def post(self, network_id=None):
        self.raise_404()

    def put(self, network_id=None):
        self.raise_404()

    def delete(self, network_id=None):
        self.raise_404()























