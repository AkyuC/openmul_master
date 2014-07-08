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

logger = logging.getLogger("TopologyHandler")
logger.setLevel(logging.DEBUG)


class TopologyHandler(BaseHandler):

    def get(self, dpid=None, dump=None):
        if dpid is None:
            logger.debug("Get all switches")
            self.finish(json.dumps(self.get_all_topology()))
        else:
            dpid = int(dpid, 16)
            self.write(json.dumps(self.get_switch_neighbor(dpid)))

    def get_all_topology(self):
        try :
            switch_list = mul.get_switch_all()
        except :
	        return []
        result = []
        for sw in switch_list:
            dpid = sw.switch_id.datapath_id
            neigh = self.get_switch_neighbor(dpid)
            result.append({"dpid" : '0x%lx' % dpid, "neighbors": neigh})
        return result

    def get_switch_neighbor(self, dpid):
        logger.debug("Get all switches 0x%lx"%dpid)
        resp = mul.get_switch_neighbor_all(dpid)
        logger.debug("GOT  all switches 0x%lx"%dpid)
        return self.__nbapi_port_neigh_list_t_serialization(resp)

    def __nbapi_port_neigh_list_t_serialization(self, resp):
        result = []
        for neigh in resp:
            if neigh.neigh_present != 1:
                continue
            result.append({
                "port": neigh.port_no,
                "to":   self.__c_ofp_port_neigh_serialization(neigh)
            })
        return result

    def __c_ofp_port_neigh_serialization(self, resp):
        if resp.neigh_present == 1:
            neigh_type = "switch"
        else:
            neigh_type = "external"

        return {
            'dpid': '0x%lx' % resp.neigh_dpid,
            'port_no' : resp.neigh_port
        }
