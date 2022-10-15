import logging
import json

import requests

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("RegistHandler");
logger.setLevel(logging.DEBUG)

class RegistHandler(BaseHandler):

    __gui_server = []

    def get(self):
        logger.debug("request ip -%s, url - %s", self.get_client_ip(),self.get_request_uri())
        self.finish({"gui_servers" : self.__gui_server})

    def options(self):
        self.write("ok")

    def post(self, port):
        logger.debug("request ip -%s, url - %s", self.get_client_ip(),self.get_request_uri())
        gui_server = str(self.get_client_ip())+":"+str(port)
        mul.regist_nbapi_cb(gui_server)
        self.__gui_server.append(gui_server)
        self.finish({"Regist gui callback server" : gui_server})
        #usage
#        r = requests.post("http://"+gui_server+"/notification/switch/0x1")
#        logger.debug(r.text)
#        r = requests.post("http://"+gui_server+"/notification/switch/0x1/port/1")
#        logger.debug(r.text)
#        r = requests.delete("http://"+gui_server+"/notification/switch/0x1")
#        logger.debug(r.text)
#        r = requests.delete("http://"+gui_server+"/notification/switch/0x1/port/1")
#        logger.debug(r.text)

    def put(self):
        self.write({"message":"post"})

    def delete(self):
        logger.debug("request ip -%s, url - %s", self.get_client_ip(),self.get_request_uri())

        ip = str(self.get_client_ip())
        delete_server = []
        ret = []
        for gui_server in self.__gui_server:
            if ip in gui_server:
                delete_server.append(gui_server)

        for gui_server in delete_server:
            self.__gui_server.remove(gui_server)
            ret.append({"gui callback server" : gui_server})

        self.finish({"gui callback server removed" : ret})
