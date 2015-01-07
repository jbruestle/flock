#!/usr/bin/python

import async
import asyncore
import StringIO
import BaseHTTPServer
import logging
import socket
import sys
import simplejson as json
from email.utils import formatdate

logger = logging.getLogger('http')

class HttpRequest(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO.StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
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
            nid = req.path[1:41].decode('hex')
        except TypeError:
            self.send_error(404, "Not Found")
            return
        key = req.path[42:]
        if req.command == 'GET':
            getr = self.server.api.get(nid, key)
            if getr == None:
                self.send_error(404, "Not Found")
                return
            (rtype, rbody) = getr
            resp = HttpResponse(200, "OK")
            resp.add_header('Content-Type', rtype)
            self.write_response(resp, rbody)
            return

        if req.command == 'PUT':
            good = self.server.api.put(nid, key, ctype, body)
        else:
            good = self.server.api.delete(nid, key)

        if good:
            self.write_no_body(204, "No content")
        else:
            self.send_error(404, "Not Found")

    def on_post(self, req, body):
        try:
            obj = json.loads(body)
        except ValueError:
            self.send_error(400, "Invalid JSON")
        if len(req.path) != 1 and len(req.path) != 41:
            self.send_error(404, "Not Found")
            return
        if req.path[0] != '/':
            self.send_error(404, "Not Found")
            return
        nid = None
        if len(req.path) == 41:
            try:
                nid = req.path[1:41].decode('hex')
            except TypeError:
                self.send_error(404, "Not Found")
                return
        jout = self.server.api.post(nid, obj)
        sout = json.dumps(jout)
        resp = HttpResponse(200, "OK")
        resp.add_header('Content-Type', 'application/json')
        self.write_response(resp, sout)

    def write_no_body(self, status, mesg):
        resp = HttpResponse(status, mesg)
        self.write_response(resp, None)

    def write_response(self, resp, body):
        self.push("HTTP/1.1 %d: %s\r\n" % (resp.status, resp.message))
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
        body = json.dumps({ "success" : False, "error" : message})
        self.write_response(resp, body)

class HttpServer(asyncore.dispatcher):
    def __init__(self, asm, api, port):
        self.asm = asm
        self.api = api
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', port))
        asyncore.dispatcher.__init__(self, sock=sock, map=self.asm.async_map)
        self.listen(5)

    def handle_request(self, req, body):
        (resp, body) = self.api.handle_request(req, body)
        return (resp, body)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            return
        (sock, addr) = pair
        logger.info("Incoming connection from %s", addr)
        _ = HttpConnection(sock, self)
 

class TestApi(object):
    def get(self, nid, key):
        if key == 'hello':
            return ('text/plain', 'world')
        return None

    def put(self, nid, key, ctype, body):
        return True

    def delete(self, nid, key):
        return True
        pass

    def post(self, nid, obj):
        return {}

def main():
    logging.basicConfig(level=logging.INFO)
    asm = async.AsyncMgr()
    api = TestApi()
    server = HttpServer(asm, api, 8000)
    asm.run()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()


