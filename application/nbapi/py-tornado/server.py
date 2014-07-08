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

import logging
import time
import tornado.web
import tornado.ioloop
import tornado.httpserver

from app.handler.base import BaseHandler
from app.handler.switch import SwitchHandler
from app.handler.flowtable import FlowTableHandler
from app.handler.topology import TopologyHandler
from app.handler.stats import StatHandler

from tornado.options import define, options
from daemon import runner 

define("port", default=8181, help="run on the given port", type=int)
define("debug", default=False)

logger = logging.getLogger('nbapi:')
logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S',
    level=options.debug
)

class App(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", BaseHandler),
            (r"/1.0/topology/switch", SwitchHandler),
            (r"/1.0/topology/switch/(0x[0-9a-zA-Z]+)", SwitchHandler),
            (r"/1.0/topology/switch/(0x[0-9a-zA-Z]+)/port", SwitchHandler),
            (r"/1.0/topology/switch/(0x[0-9a-zA-Z]+)/port/([0-9]+)", SwitchHandler),
            (r"/1.0/topology/switch/(0x[0-9a-zA-Z]+)/meter", SwitchHandler),
            (r"/1.0/topology/switch/(0x[0-9a-zA-Z]+)/group", SwitchHandler),
            (r"/1.0/topology/switch/(0x[0-9a-zA-Z]+)/table/([0-9]+)", SwitchHandler),
            (r"/1.0/topology/switch/(0x[0-9a-zA-Z]+)/limit", SwitchHandler),
            (r"/1.0/flowtable/(0x[0-9a-zA-Z]+)/flow", FlowTableHandler),
            (r"/1.0/flowtable/(0x[0-9a-zA-Z]+)/flow/([0-9a-fA-F-]+)", FlowTableHandler),
            (r"/1.0/topology", TopologyHandler),
            (r"/1.0/stats/switch/(0x[0-9a-zA-Z]+)/flow/([0-9a-fA-F-]+)", StatHandler),
            (r"/1.0/stats/switch/(0x[0-9a-zA-Z]+)/port/([0-9]+)", StatHandler),
            (r"/1.0/topology/switch/(0x[0-9a-zA-Z]+)/neighbor", TopologyHandler),
            (r"/1.0/stats/switch/(0x[0-9a-zA-Z]+)/flow/([0-9a-fA-F-]+)", StatHandler),
            (r"/1.0/stats/switch/(0x[0-9a-zA-Z]+)/port/([0-9]+)", StatHandler)
        ]
        tornado.web.Application.__init__(self, handlers, debug=True)

class Start:
    init = 0
    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/tty'
        self.stderr_path = '/dev/tty'
        self.pidfile_path = '/var/run/openmul.pid'
        self.pidfile_timeout = 1

    def run(self):
            # Define your tasks here
            # Anything written in python is permitted
            # For example you can clean up your server logs every
            # hour

        try:
            pass
        except Exception, e:
            logging.exception('Human friendly error message, the exception will be captured and added to the log file automaticaly')

        if self.init is 0:
            from app.lib import mul_nbapi as mul
            from app.handler.ids import FlowHolder
            mul.nbapi_worker_entry()
            FlowHolder.getInstance().load()
            http_server = tornado.httpserver.HTTPServer(App())
            http_server.listen(options.port)    
            self.init = 1

        while True:
            tornado.ioloop.IOLoop.instance().start()

tornado.web.ErrorHandler = BaseHandler

if __name__ == "__main__":
    #from app.handler.ids import FlowHolder
    #FlowHolder.getInstance().load()
    tornado.options.parse_command_line()
    #http_server = tornado.httpserver.HTTPServer(App())
    #http_server.listen(options.port)
    logger.info("[tornado] Starting API server on port %d", options.port)
    app = Start()
    daemon_runner = runner.DaemonRunner(app)
    daemon_runner.do_action()
