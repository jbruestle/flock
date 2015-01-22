#!/usr/bin/env python
# pylint: disable=missing-docstring

import asyncore
import StringIO
import BaseHTTPServer
import logging
import socket
import sys
import simplejson as json
import traceback
from email.utils import formatdate

from flock import async

logger = logging.getLogger('http') # pylint: disable=invalid-name

class HttpException(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, "HTTP Error: %d %s" % (status, message))
        self.status = status
        self.message = message

# TODO: The 'reuse' of HttpRequest to parse the request is a bit
# questionable, since it relies on implementation details, but good
# enough for the time being
class HttpRequest(BaseHTTPServer.BaseHTTPRequestHandler):
    # pylint: disable=too-few-public-methods
    def __init__(self, request_text):
        # pylint: disable=super-init-not-called
        self.rfile = StringIO.StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message=None):
        self.error_code = code
        self.error_message = message

class HttpResponse(object):
    # pylint: disable=too-few-public-methods
    def __init__(self, status, message):
        self.status = status
        self.message = message
        self.headers = dict()

    def add_header(self, header, value):
        self.headers[header] = value

class HttpConnection(async.Connection):
    def __init__(self, sock, server):
        async.Connection.__init__(self, server.asm, sock)
        self.server = server
        self.recv_until("\r\n\r\n", self.on_header)

    def on_header(self, buf):
        req = HttpRequest(buf)
        if req.error_code is not None:
            raise ValueError("Unable to parse headers")
        if 'Transfer-Encoding' in req.headers:
            self.send_error(400, "Too lazy to allow transfer-encoding")
            self.close()
            return
        if 'Content-Length' in req.headers:
            clen = int(req.headers['Content-Length'])
            ctype = req.headers.getheader('Content-Type')
            if ctype is None:
                self.send_error(400, "Content-Type required")
                self.close()
                return
            self.recv_buffer(clen, lambda body: self.on_request(req, ctype, body))
        else:
            self.on_request(req, None, None)

    def on_request(self, req, ctype, body):
        try:
            logger.info("Request %s %s", req.command, req.path)
            if not hasattr(self, 'on_' + req.command.lower()):
                raise HttpException(505, "Method not allowed")
            getattr(self, 'on_' + req.command.lower())(req, ctype, body)
        except HttpException as herr:
            logger.info("Got http exception: %d %s", herr.status, herr.message)
            self.send_error(herr.status, herr.message)
        except Exception as err: # pylint: disable=broad-except
            logger.warning("http request: got error: %s", sys.exc_info()[1])
            logger.warning("%s", traceback.format_exc())
            self.send_error(500, str(err))

    def parse_tid_url(self, path):
        _ = self
        if len(path) < 42 or path[0] != '/' or path[41] != '/':
            raise HttpException(404, "Not Found")
        try:
            tid = path[1:41].decode('hex')
        except TypeError:
            raise HttpException(404, "Not Found")
        key = path[42:]
        return (tid, key)

    def on_get(self, req, ctype, body):
        _ = body
        if ctype is not None:
            raise HttpException(400, "No body allowed for method")
        (tid, key) = self.parse_tid_url(req.path)
        (rtype, rbody) = self.server.api.get(tid, key)
        resp = HttpResponse(200, "OK")
        resp.add_header('Content-Type', rtype)
        self.write_response(resp, rbody)

    def on_put(self, req, ctype, body):
        _ = body
        if ctype is None:
            raise HttpException(411, "Length Required")
        (tid, key) = self.parse_tid_url(req.path)
        self.server.api.put(tid, key, ctype, body)
        resp = HttpResponse(204, "No body")
        self.write_response(resp, None)

    def on_delete(self, req, ctype, body):
        if ctype is not None:
            raise HttpException(400, "No body allowed for method")
        (tid, key) = self.parse_tid_url(req.path)
        self.server.api.put(tid, key, ctype, body)
        resp = HttpResponse(204, "No body")
        self.write_response(resp, None)

    def on_post(self, req, ctype, body):
        if ctype is None:
            raise HttpException(411, "Length Required")
        if ctype != 'application/json':
            raise HttpException(415, "Unsupported Media Type")
        try:
            obj = json.loads(body)
        except ValueError:
            raise HttpException(400, "Invalid JSON")
        if len(req.path) < 1 or req.path[0] != '/':
            raise HttpException(404, "Not Found")
        if '/' in req.path[1:]:
            (tid, action) = self.parse_tid_url(req.path)
        else:
            (tid, action) = (None, req.path[1:])
        jout = self.server.api.post(tid, action, obj)
        sout = json.dumps(jout)
        resp = HttpResponse(200, "OK")
        resp.add_header('Content-Type', 'application/json')
        self.write_response(resp, sout)

    def write_response(self, resp, body):
        self.push("HTTP/1.1 %d %s\r\n" % (resp.status, resp.message))
        headers = dict(resp.headers)
        if body is not None:
            headers['Content-Length'] = str(len(body))
        headers['Server'] = 'LameServer/0.1'
        headers['Date'] = formatdate(timeval=None, localtime=False, usegmt=True)
        for (key, value) in headers.iteritems():
            self.push("%s: %s\r\n" % (key, value))
        self.push("\r\n")
        if body is not None:
            self.push(body)
        self.recv_until("\r\n\r\n", self.on_header)

    def send_error(self, status, message):
        resp = HttpResponse(status, message)
        resp.add_header('Content-Type', 'application/json')
        body = json.dumps({"success" : False, "error" : message})
        self.write_response(resp, body)

class HttpServer(asyncore.dispatcher):
    def __init__(self, asm, api, cfg):
        self.asm = asm
        self.api = api
        self.port = cfg.get('http_port', 8000)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', self.port))
        asyncore.dispatcher.__init__(self, sock=sock, map=self.asm.async_map)
        self.listen(5)

    def handle_request(self, req, body):
        (resp, body) = self.api.handle_request(req, body)
        return (resp, body)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            return
        (sock, addr) = pair # pylint: disable=unpacking-non-sequence
        logger.info("Incoming connection from %s", addr)
        _ = HttpConnection(sock, self)

class TestApi(object):
    def get(self, tid, key):
        _ = (self, tid)
        if key == 'hello':
            return ('text/plain', 'world')
        return None

    def put(self, tid, key, ctype, body):
        _ = (self, tid, key, ctype, body)
        return True

    def delete(self, tid, key):
        _ = (self, tid, key)
        return True

    def post(self, tid, action, obj):
        _ = (self, tid, action, obj)
        return {}

def main():
    logging.basicConfig(level=logging.INFO)
    asm = async.AsyncMgr()
    api = TestApi()
    _ = HttpServer(asm, api, {})
    asm.run()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()


