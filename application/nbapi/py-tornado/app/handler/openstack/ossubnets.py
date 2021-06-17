import logging
import json
import colander

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("OSSubnetsHandler");
logger.setLevel(logging.DEBUG)

class OSSubnetsHandler(BaseHandler):

    def get(self, tenant_id=None, subnet_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s, subnet_id: %s",tenant_id, subnet_id)
        self.write({"message":"get"})

    def options(self, tenant_id=None, subnet_id=None):
        self.write("ok")

    def post(self, tenant_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - tenant_id: %s, subnet_id: %s",tenant_id, subnet_id)
        self.write({"message":"post"})

    def put(self, tenant_id=None, subnet_id=None):
        self.write({"message":"post"})

    def delete(self, tenant_id=None, subnet_id=None):
        self.write({"message":"delete"})

class Subnet(colander.MappingSchema):
    network_id = colander.SchemaNode(colander.String(), missing=None)
    ip_version = colander.SchemaNode(colander.String(), missing=None)
    cidr = colander.SchemaNode(colander.String(), missing=None)

class SubnetSchema(colander.MappingSchema):
    subnet = Subnet()

class SubnetList(colander.SequenceSchema):
    subnet = Subnet()

class MultipleSubnetSchema(colander.MappingSchema):
    subnets = SubnetList()
    





















