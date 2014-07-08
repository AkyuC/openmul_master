#!/usr/bin/env python

# Copyright (C) 2013-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See
# the
# License for the specific language governing permissions and limitations
# under the License.

import json
import logging

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler
from app.handler.ids import FlowHolder

logger = logging.getLogger("StatHandler")
logger.setLevel(logging.DEBUG)

class StatHandler(BaseHandler):
    """
    This Handler manages the following URL:
        GET     stats/switc/{dpid}/flow/{flow_id}           : get_(dpid)
        GET     stats/switc/{dpid}/port/{port_no}           : get_(dpid)
    """
    BASE_URL = "/stats/switch"

    request_mapper = {
        "^0x[0-9a-fA-F]+/flow/[0-9a-fA-F-]+$":  "get_flow_stat",
        "^0x[0-9a-fA-F]+/port/[0-9]+$":         "get_port_stat",
    }

    def get_request_mapper(self):
        return self.request_mapper

    def get_base_uri(self):
        return self.BASE_URL

    def get(self, dpid=None, stat_id=None):
        self.__execute(dpid, stat_id)

    def options(self, dpid=None, stat_id=None):
        self.write("ok")

    def post(self, dpid=None, stat_id=None):
        self.write("ok")

    def __execute(self, *args):
        func = self.match()
        logger.debug("matched func: %s, args: %s", func, args)
        if func is not None:
            getattr(self, func)(*args)

    def get_port_stat(self, *args):
        self.raise_error(-1, "Failed to get port stats", reason="Not implemented")
        return

    def get_flow_stat(self, *args):
        dpid = int(args[0], 0)
        flow_id = str(args[1])
        flow = None
        try:
            flow = FlowHolder.getInstance().get(flow_id)
        except KeyError:
            self.raise_error(-1, "Failed to get flow stats", reason="No such flow_id")
	    return

        self.write({
            "flow_id":      flow_id,
            'bps':          mul.nbapi_parse_bps_to_str(flow.bps),
            'pps':          mul.nbapi_parse_bps_to_str(flow.pps),
            'pkt_count':    flow.packet_count,
            'byte_count':   flow.byte_count
        })
