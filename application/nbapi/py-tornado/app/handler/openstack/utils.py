import httplib
import json
import socket

SUCCESS_CODES = range(200, 207)

def rest_call(server, port, action, url, data,
                                    headers=None, timeout=10):
    body = json.dumps(data)
    if not headers:
        headers = {}
    headers['Content-type'] = 'application/json'
    headers['Accept'] = 'application/json'

    conn = httplib.HTTPConnection(
            server, port=port, timeout=timeout)
    if conn is None:
        return 0, None, None, None

    try:
        conn.request(action, url, body, headers)
        response = conn.getresponse()
        respstr = response.read()
        respdata = respstr
        if response.status in SUCCESS_CODES:
            try:
                respdata = json.loads(respstr)
            except ValueError:
                # response was not JSON, ignore the exception
                pass

        ret = (response.status, response.reason, respstr, respdata)
    except (socket.timeout, socket.error) as e:
        ret = 0, None, None, None

    conn.close()
    return ret
