import logging
import json
import colander

import psutil
import os
import sys
from datetime import datetime, timedelta

from app.handler.base import BaseHandler

logger = logging.getLogger("DashboardHandler")
logger.setLevel(logging.DEBUG)
mul_app = ['mulcli', 'mulfab','mull2sw','multr', 'mulmakdi', 'prismapp','prismagent', 'mulconx']
class DashboardHandler(BaseHandler):

    def get(self):
        if 'appname' in self.get_request_uri():
            self.finish({ "mul_app_name" :  mul_app })
        else:
            self.__get_mul_app()

    def __get_mul_app(self):
        loads = []
        for load in os.getloadavg():
            loads.append(load)
        cpus = []
        for cpu_num, perc in enumerate(psutil.cpu_percent(interval=0.1, percpu=True)):
            cpus.append({'cpu_num' : cpu_num, 'cpu_percent' : perc})
        mul_processes = []
        for pid in psutil.pids():
            p = psutil.Process(pid)
            #if 'python' in str(p.cmdline()):#for test
            if str(p.name()) in mul_app:
                pstatus = str(p.status())
                if str(p.status()) is 'sleeping':
                    pstatus = 'running'
                mul_processes.append({
                    'pname' : str(p.name()),
                    'virt' : p.get_memory_info().vms,
                    'res' : p.get_memory_info().rss,
                    'cpu_percent' : p.get_cpu_percent(interval=0.1),
                    'p_status' : pstatus,
                    'mem_percent' : p.get_memory_percent()
                })
        ret = {
            'mem_percent' : psutil.phymem_usage().percent,
            'load_average' : loads,
            'uptime' : str(datetime.now() - datetime.fromtimestamp(psutil.BOOT_TIME)),
            'cpus' : cpus,
            'mul_process' : mul_processes
        }

        self.write(ret)

    def options(self):
        self.write("ok")

    def post(self):
        logger.debug("request url - %s", self.get_request_uri())
        path = ""
        ret = {}
        try :
            body = DashboardSchema().deserialize(json.loads(self.request.body))
            app = str(body['name'])
            ret = {app:'on'}
            if app=='mulcli':
                os.system("mulcli -V 10000 -d")
            elif app=='mulfab':
                os.system("mulfab -V 9000 -d")
            elif app=='mull2sw':
                os.system("mull2sw -d")
            elif app=='multr':
                os.system("multr -d")
            else:
                ret = {app:'on fail'}
        except Exception, e:
            ret.update({'error_message' : 'failed to start application', 'reason' : str(e)})
        finally:
            self.finish(ret)

    def delete(self):
        logger.debug("requests url - %s", self.get_request_uri())
        logger.debug("requests params -%s", self.request.body)
        ret = {}
        try :
            body = DashboardSchema().deserialize(json.loads(self.request.body))
            app = body['name']
            for process in psutil.process_iter():
                if str(app) in str(process.name):
                    process.kill()
                    ret.update({str(app):'killed'})
            if len(ret)==0:
                raise Exception, 'no such process name'
        except Exception, e:
            ret.update({'error_message' : 'failed to kill application', 'reason' : str(e)})
        finally:
            self.finish(ret)

    def put(self):
        pass



class DashboardSchema(colander.MappingSchema):
    name = colander.SchemaNode(colander.String(), validator=colander.OneOf(mul_app))

