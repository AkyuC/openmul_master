import logging
import json

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("SubnetHandler");
logger.setLevel(logging.DEBUG)

class SubnetHandler(BaseHandler):

    def get(self, subnet_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - subnet_id: %s",subnet_id)
        self.write({"message":"get"})

    def options(self, subnet_id=None):
        self.write("ok")

    def post(self, subnet_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - subnet_id: %s",subnet_id)
        self.write({"message":"post"})

    def put(self, subnet_id=None):
        self.write({"message":"put"})

    def delete(self, subnet_id=None):
        self.write({"message":"delete"})
























