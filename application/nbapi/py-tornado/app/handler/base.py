import re
import logging
import httplib

import tornado
import tornado.web

logger = logging.getLogger("BaseHandler")
logger.setLevel(logging.DEBUG)

class MulError(Exception):
    def __init__(self, message):
	self.log_message = message
	self.reason = message

    def __str__(self):
	return str(self.log_message)


class BaseHandler(tornado.web.RequestHandler):
    URL_VERSION = "1.0"

    def __init__(self, application, request, **kwargs):
        tornado.web.RequestHandler.__init__(self, application, request)

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
        self.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")

    def get_request_uri(self):
        return self.request.uri

    def get_request_data(self):
        data = {}
        for arg in list(self.request.arguments.keys()):
            data[arg] = self.get_argument(arg)
            if data[arg] == '':
                data[arg] = None
        return data

    def get_request_mapper(self):
        pass

    def get_base_uri(self):
        pass

    def match(self):
        request_uri = self.get_request_uri()
        base_url = self.get_base_uri()
        url = request_uri[ request_uri.find(base_url) + len(base_url) + 1 : ]
        mapper = self.get_request_mapper()

        for pattern in mapper:
            logger.debug("pattern: %s, url: %s", pattern, url)
            m = re.match(pattern, url)
            if m:
                return mapper[pattern]

    def get(self):
        if self.request.path == '/':
            res = {
                'name': 'NBAPI REST Server',
                'version': '0.0.1'
            }
            self.write(res)
        else:
            self.send_error(404)

    def raise403(self):
        raise tornado.web.HTTPError(403, 'Not enough permissions to perform this action')

    def raise404(self):
        raise tornado.web.HTTPError(404, 'Object not found')

    def raise405(self):
        raise tornado.web.HTTPError(405, 'Method Not Allowed')

    def write_error(self, status_code, **kwargs):
        res = {
            'error_code':       status_code,
            'error_message':    httplib.responses[status_code]
        }
        self.write(res)

    def _handle_request_exception(self, e):
	if isinstance(e, MulError):
	    self.finish()


    def raise_error(self, status_code, message, **kwargs):
	reason = ""
        if 'reason' in kwargs:
            res = {
                'error_code':       status_code,
                'error_message':    message,
                'reason':      kwargs.get('reason')
            }
	    reason = kwargs.get('reason')
        else:
            res = {
                'error_code':       status_code,
                'error_message':    message
            }
	#self.write(res)
	self.finish(res)
	#raise MulError(res)
