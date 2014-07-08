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
import thread
import logging
import uuid

from app.lib import mul_nbapi as mul

logger = logging.getLogger("FlowHolder")
logger.setLevel(logging.DEBUG)

class FlowHolder(object):
    __flow_map = {}

    __instance = None
    __lock = thread.allocate_lock()

    def __init__(self):
        pass

    def __new__(cls, *args, **kargs):
        return cls.getInstance(cls, *args, **kargs)

    @classmethod
    def getInstance(cls, *args, **kargs):
        cls.__lock.acquire()
        try:
            if cls.__instance is None:
                cls.__instance = object.__new__(cls, *args, **kargs)
        finally:
            cls.__lock.release()

        return cls.__instance

    def load(self):
        logger.info("Loading flows")
        switch_list = None
        try:
            switch_list = mul.get_switch_all()
        except:
	        logger.info("No switch. So No flow loaded")
	        return
        for switch in switch_list:
            dpid = switch.switch_id.datapath_id
            logger.debug("starting to load flows from switch (0x%016x)", dpid)
            try :
                flow_list = mul.get_flow(dpid)
            except Exception as exception:
                name_of_exception = exception.__class__.__name__
                print 'Error in loading flows - ', name_of_exception 
            else:
                for flow in flow_list:
                    flow_id = str(uuid.uuid4())
                    self.__flow_map[ flow_id ] = flow

            logger.info("Total (%d) flows has loaded", len(self.__flow_map))

    def find(self, dpid, that_flow):
        for flow_id in self.__flow_map:
            this_flow = self.__flow_map[ flow_id ]
            if dpid == this_flow.datapath_id:
                if mul.compare_flows(this_flow.flow, that_flow) == 0:
                    logger.debug("found flow id: %s", flow_id)
                    return flow_id
        raise KeyError

    def get(self, flow_id):
        return self.__flow_map[ flow_id ]

    def save(self, dpid, new_flow):
        flow_id = None
        try:
            flow_id = self.find(dpid, new_flow)
        except KeyError:
            flow_list = mul.get_flow(dpid) # switch's update can be delayed
            for flow in flow_list:
                if mul.compare_flows(new_flow, flow.flow) == 0:
                    FlowHolder.__lock.acquire()
                    flow_id = str(uuid.uuid4())
                    logger.debug("generated flow id : %s", flow_id)
                    self.__flow_map[flow_id] = flow
                    logger.debug("save to flow map : %s", flow_id)
                    FlowHolder.__lock.release()
                    return flow_id
        return flow_id

    def remove(self, flow_id):
        if flow_id is None:
            return

        try:
            FlowHolder.__lock.acquire()
            del self.__flow_map[ flow_id ]
            FlowHolder.__lock.release()
        except KeyError:
            logger.error("No such flow %s", flow_id)

    def map(self):
        return self.__flow_map

