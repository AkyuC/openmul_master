import logging
import json
import colander
import re

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

import app.handler.openstack.utils as utils

logger = logging.getLogger("OSRoutersHandler");
logger.setLevel(logging.DEBUG)

class OSRoutersHandler(BaseHandler):
    PRISM_SERVER = '127.0.0.1'
    PRISM_PORT = 7171
    # demo
    left_intf_name = 'pr-s1-eth0'
    left_intf_ip = '1.1.1.1/24'

    right_intf_name = 'pr-s2-eth0'
    right_intf_ip = '21.21.21.2/24'
    # demo_end
    BASE_URL = "/openstack/routers"
    request_mapper = {
        "^[0-9a-zA-Z-]+$":        "create_router",
        #"^[0-9a-zA-Z-]+/ports$":  "demo_create_router_interface"
        "^[0-9a-zA-Z-]+/ports$":  "create_router_interface"
    }

    request_delete_mapper = {
        "^[0-9a-zA-Z-]+$":                      "delete_router",
        #"^[0-9a-zA-Z-]+/ports/[0-9a-zA-Z-]+$":  "demo_delete_router_interface"
        "^[0-9a-zA-Z-]+/ports/[0-9a-zA-Z-]+$":  "delete_router_interface"
    }

    def post(self, *args):
        logger.debug("[POST]: %s", self.get_request_uri())
        self.__execute_post(args)
        
    def delete(self, *args):
        self.__execute_delete(*args)

    def create_router(self, name):
        pass

    """
    def demo_create_router_interface(self, name):
        logger.debug("[POST-PARAMS]: %s", self.request.body)

        try:
            body = json.loads(self.request.body)
            if body['ip_address'] == self.left_intf_ip:
                body['prism_intf_name'] = self.left_intf_name
            elif body['ip_address'] == self.right_intf_ip:
                body['prism_intf_name'] = self.right_intf_name

            self.__add_prism_router_interface(body['prism_intf_name'],
                                              body['ip_address'])
            resp = self.__create_prism_router_network('bgp',
                                                      body['router_id'],
                                                      body['network_cidr'],
                                                      '10')
            self.finish()
        except RuntimeError, e:
            logger.exception("")
            self.send_error(400, message=e)
    """
    def create_router_interface(self, name):
        logger.debug("[POST-PARAMS]: %s", self.request.body)

        try:
            body = json.loads(self.request.body)
            self.__add_prism_router_interface(body['prism_intf_name'],
                                              body['ip_address'])
            resp = self.__create_prism_router_network('bgp',
                                                      body['router_id'],
                                                      body['network_cidr'],
                                                      '10')
            self.finish()
        except RuntimeError, e:
            logger.exception(" ")
            self.send_error(400, message=e)

    def delete_router(self, name):
        pass

    """
    def demo_delete_router_interface(self, router_name, intf_name):
        logger.debug("[DELETE-PARAMS]: %s", self.request.body)

        try:
            body = json.loads(self.request.body)
            if body['ip_address'] == self.left_intf_ip:
                intf_name = self.left_intf_name
            elif body['ip_address'] == self.right_intf_ip:
                intf_name = self.right_intf_name

            self.__delete_prism_router_network('ospf',
                                               body['router_id'],
                                               body['network_cidr'])
            self.__remove_prism_router_interface(intf_name,
                                                 body['ip_address'])
            self.finish()
        except RuntimeError, e:
            logger.exception("")
            self.send_error(400, message=e)
    """

    def delete_router_interface(self, router_name, intf_name):
        logger.debug("[DELETE-PARAMS]: %s", self.request.body)

        try:
            body = json.loads(self.request.body)

            self.__delete_prism_router_network('bgp',
                                               body['router_id'],
                                               body['network_cidr'],
                                               '10')
            self.__remove_prism_router_interface(intf_name,
                                                 body['ip_address'])
            self.finish()
        except RuntimeError, e:
            logger.exception(" ")
            self.send_error(400, message=e)

    def __add_prism_router_interface(self, intf_name, ip_address):
        url = "/prism/router/interface"
        data = dict(interface_name = intf_name,
                    interface_address = ip_address)
        resp = self.rest_call("POST", url, data)
        if resp[0] not in utils.SUCCESS_CODES:
            raise RuntimeError(resp)
        return resp
                                           
    def __create_prism_router_network(self, proto, id, cidr, pvalue=None):
        url = "/prism/router/network"
        data = dict(routing_protocol = proto,
                    protocol_value = pvalue,
                    value = dict(router_id = id,
                                 network = cidr)
                    )
        resp = self.rest_call("POST", url, data)
        if resp[0] not in utils.SUCCESS_CODES:
            raise RuntimeError(resp)
        return resp

    def __delete_prism_router_network(self, proto, id, cidr, value=None):
        url = "/prism/router/network"
        data = dict(routing_protocol = proto,
                    protocol_value = value,
                    value = dict(router_id = id,
                                 network = cidr)
                   )
        resp = self.rest_call("DELETE", url, data)
        if resp[0] not in utils.SUCCESS_CODES:
            raise RuntimeError(resp)
        return resp

    def __remove_prism_router_interface(self, intf_name, ip_address):
        url = "/prism/router/interface"
        data = dict(interface_name = intf_name,
                    interface_address = ip_address)
        resp = self.rest_call("DELETE", url, data)
        if resp[0] not in utils.SUCCESS_CODES:
            raise RuntimeError(resp)
        return resp

    def rest_call(self, action, url, data):
        return utils.rest_call(self.PRISM_SERVER, self.PRISM_PORT,
                                                action, url, data)

    # Private
    def __execute_post(self, *args):
        func = self.match()
        if func is not None:
            getattr(self, func)(*args)

    def __execute_delete(self, *args):
        func = self.match(request_mapper=self.request_delete_mapper)
        if func is not None:
            getattr(self, func)(*args)

    def match(self, request_mapper=None):
        if request_mapper is None:
            request_mapper = self.request_mapper

        request_uri = self.get_request_uri()
        base_url = self.get_base_uri()
        url = request_uri[ request_uri.find(base_url) + len(base_url) + 1 :]
        
        for pattern in request_mapper:
            m = re.match(pattern, url)
            if m:
                return request_mapper[pattern]

    def get_base_uri(self):
        return self.BASE_URL

    def write_error(self, status_code, **kwargs):
        res = {'error' : ''}

        if 'message' in kwargs:
            if type(kwargs['message']) is dict:
                res = message
            else:
                res['err_msg'] = kwargs['message']
        elif int(status_code) == 404:
            res['err_msg'] = 'no such api'
        else:
            res['err_msg'] = 'unknown error'
        self.write(res)

        

