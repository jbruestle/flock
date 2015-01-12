#!/usr/bin/env python
# pylint: disable=missing-docstring
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-branches

import async
import asyncore
import StringIO
import BaseHTTPServer
import logging
import socket
import sys
import simplejson as json
import traceback
from email.utils import formatdate

logger = logging.getLogger('http') # pylint: disable=invalid-name

# TODO: The 'reuse' of HttpRequest to parse the request is a bit
# questionable, since it relies on implementation details, but good
# enough for the time being
class HttpRequest(BaseHTTPServer.BaseHTTPRequestHandler):
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
    def __init__(self, status, message):
        self.status = status
        self.message = message
        self.headers = dict()

    def add_header(self, header, value):
        self.headers[header] = value

class HttpConnection(async.Connection):
    def __init__(self, sock, server):
        async.Connection.__init__(self, sock, map=server.asm.async_map)
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
        if req.command == 'PUT' or req.command == 'POST':
            if ctype is None:
                self.send_error(411, "Length Required")
                return
        if req.command == 'POST':
            if ctype != 'application/json':
                self.send_error(415, "Unsupported Media Type")
                return
            self.on_post(req, body)
            return
        if req.command == 'GET' or req.command == 'DELETE':
            if ctype is not None:
                self.send_error(400, "No body allowed for method")
                return
        if req.command not in ['GET', 'DELETE', 'PUT']:
            self.send_error(405, "Method Not Allowed")
            return
        if len(req.path) < 42 or req.path[0] != '/' or req.path[41] != '/':
            self.send_error(404, "Not Found")
            return
        try:
            tid = req.path[1:41].decode('hex')
        except TypeError:
            self.send_error(404, "Not Found")
            return
        key = req.path[42:]
        if req.command == 'GET':
            getr = self.server.api.get(tid, key)
            if getr == None:
                self.send_error(404, "Not Found")
                return
            print "Got %s" % (getr,)
            (rtype, rbody) = getr
            resp = HttpResponse(200, "OK")
            resp.add_header('Content-Type', rtype)
            self.write_response(resp, rbody)
            return

        if req.command == 'PUT':
            (status, mesg) = self.server.api.put(tid, key, ctype, body)
        else:
            (status, mesg) = self.server.api.put(tid, key, ctype, body)

        if status == 204:
            self.write_no_body(status, mesg)
        else:
            self.send_error(status, mesg)

    def on_post(self, req, body):
        try:
            obj = json.loads(body)
        except ValueError:
            self.send_error(400, "Invalid JSON")
            return
        if len(req.path) != 1 and len(req.path) != 41:
            self.send_error(404, "Not Found")
            return
        if req.path[0] != '/':
            self.send_error(404, "Not Found")
            return
        tid = None
        if len(req.path) == 41:
            try:
                tid = req.path[1:41].decode('hex')
            except TypeError:
                self.send_error(404, "Not Found")
                return
        try:
            jout = self.server.api.post(tid, obj)
        except Exception: # pylint: disable=broad-except
            logger.warning("%s: got error: %s", id(self), sys.exc_info()[1])
            logger.warning("%s", traceback.format_exc())
            self.send_error(500, "Internal Server Error")
            return
        sout = json.dumps(jout)
        resp = HttpResponse(200, "OK")
        resp.add_header('Content-Type', 'application/json')
        self.write_response(resp, sout)

    def write_no_body(self, status, mesg):
        resp = HttpResponse(status, mesg)
        self.write_response(resp, None)

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

    def post(self, tid, obj):
        _ = (self, tid, obj)
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


