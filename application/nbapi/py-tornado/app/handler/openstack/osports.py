import logging
import json
import colander

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("OSPortsHandler");
logger.setLevel(logging.DEBUG)

class OSPortsHandler(BaseHandler):

    def get(self, tenant_id=None, port_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s",tenant_id)
        self.write({"message":"get"})

    def options(self, tenant_id=None, port_id=None):
        self.write("ok")

    def post(self, tenant_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s",tenant_id)
        self.write({"message":"post"})

    def put(self, tenant_id=None, port_id=None):
        self.write({"message":"post"})

    def delete(self, tenant_id=None, port_id=None):
        self.write({"message":"delete"})

class Port(colander.MappingSchema):
    network_id = colander.SchemaNode(colander.String(), missing=None)
    name = colander.SchemaNode(colander.String(), missing=None)
    admin_state_up = colander.SchemaNode(colander.String(), validator=colander.OneOf(['true','false']), missing=None)

class PortSchema(colander.MappingSchema):
    port = Port()

class PortList(colander.SequenceSchema):
    port = Port()

class MultiplePortSchema(colander.MappingSchema):
    ports = PortList()




















