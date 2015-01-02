#!/usr/bin/python
#pylint: disable=missing-docstring

from collections import deque
import asyncore
import asynchat
import struct
import hashlib
import traceback
import socket
import unittest
import logging

from worktoken import WorkToken
from store import SyncStore

logger = logging.getLogger('sync')

class Connection(asynchat.async_chat):
    def __init__(self, sock, map=None):
        asynchat.async_chat.__init__(self, sock=sock, map=map)
        self.__term_callback = None
        self.__ibuffer = []
        self.__fmt = None

    def handle_error(self):
        logger.warning("got error: %s", traceback.format_exc())
        self.close()

    def collect_incoming_data(self, data):
        self.__ibuffer.append(data)

    def found_terminator(self):
        #pylint: disable=star-args
        if self.__fmt is None:
            self.__term_callback("".join(self.__ibuffer))
        else:
            params = struct.unpack(self.__fmt, "".join(self.__ibuffer))
            self.__term_callback(*params)

    def send_buffer(self, buf):
        self.push(buf)

    def send_struct(self, fmt, *t):
        buf = struct.pack(fmt, *t)
        self.push(buf)

    def recv_buffer(self, size, callback):
        self.__ibuffer = []
        self.__fmt = None
        self.__term_callback = callback
        self.set_terminator(size)

    def recv_struct(self, fmt, callback):
        self.__ibuffer = []
        self.__fmt = fmt
        self.__term_callback = callback
        self.set_terminator(struct.calcsize(fmt))

HELLO_FMT = '!4s32s'  # Magic #, ID 
HELLO_ACK_FMT = '!QL'  # Seq No, Buffer size
SUMMARY_FMT = '!Q32sQQ' # Seq No, Hash, Timestamp, Nonce
DATA_HDR_FMT = '!H' # Data size
ADVANCE_FMT = '!?'

class SyncConnection(Connection):
    def __init__(self, nid, sstore, sock, map=None):
        Connection.__init__(self, sock, map=map)
        self.nid = nid
        self.remote = None
        self.store = sstore
        self.send_struct(HELLO_FMT, '0net', self.nid)
        self.recv_struct(HELLO_FMT, self.on_hello)
        self.await_advance = deque()
        self.await_data = deque()
        self.max_outstanding = 0
        self.send_seq = 0
        self.recv_seq = 0

    def handle_error(self):
        Connection.handle_error(self)
        if self.recv_seq != None:
            self.store.on_disconnect(self.remote)

    def on_hello(self, magic, remote):
        logger.debug("Got hello")
        if magic != '0net':
            logger.debug("Invalid magic")
            raise ValueError('Invalid magic')
        self.remote = remote
        self.recv_seq = self.store.on_connect(remote)
        if self.recv_seq == None:
            raise ValueError('Already connected to remote')
        self.send_struct(HELLO_ACK_FMT, self.recv_seq, 50)
        self.recv_struct(HELLO_ACK_FMT, self.on_hello_ack)
        
    def on_hello_ack(self, seq, max_outstanding):
        logger.debug("Got hello ack")
        if max_outstanding > 100:
            max_outstanding = 100
        self.max_outstanding = max_outstanding
        self.send_seq = seq
        self.fill_queue()
        self.recv_buffer(1, self.on_type)

    def on_type(self, buf):
        logger.debug("Got type %s", buf)
        if buf[0] == 'S':
            self.recv_struct(SUMMARY_FMT, self.on_summary)
        elif buf[0] == 'D':
            self.recv_struct(DATA_HDR_FMT, self.on_data_header)
        elif buf[0] == 'R':
            _ = self.outstanding.popleft()
            self.recv_buffer(1, self.on_type)
        elif buf[0] == 'N':
            self.on_advance(True)
        elif buf[0] == 'O':
            self.on_advance(False)
        else:
            raise ValueError('Invalid type')

    def on_summary(self, seq, hid, timestamp, nonce):
        _ = seq
        wtok = WorkToken(hid, timestamp, nonce)
        need_data = self.store.on_worktoken(wtok)
        if need_data:
            logger.debug("requesting data")
            self.await_data.append((seq, wtok))
            self.send_buffer('N')
        else:
            self.send_buffer('O')
        self.recv_seq = seq
        self.update_seq()
        self.recv_buffer(1, self.on_type)

    def on_data_header(self, dsize):
        (_, wtok) = self.await_data.popleft()
        callback = lambda data: self.on_data(wtok, data)
        self.recv_buffer(dsize, callback)

    def on_data(self, wtok, data):
        logger.debug("adding data")
        if hashlib.sha256(data).digest() != wtok.hid:
            raise ValueError("Data-hash mismatch, erroring connection")
        self.store.on_record(wtok, data)
        self.update_seq()
        self.recv_buffer(1, self.on_type)

    def update_seq(self):
        if len(self.await_data) == 0:
            seq = self.recv_seq
        else:
            seq = self.await_data[0][0] - 1
        logger.debug("new seq = %s", seq)
        self.store.on_seq_update(self.remote, seq)

    def on_advance(self, need_data):
        logger.debug("Got advance")
        hid = self.await_advance.popleft()
        if need_data:
            data = self.store.get_data(hid)
            if data == None:
                logger.debug("sending R")
                self.send_buffer('R')
            else:
                logger.debug("sending D")
                self.send_buffer('D')
                self.send_struct(DATA_HDR_FMT, len(data))
                self.send_buffer(data)
        self.fill_queue()
        self.recv_buffer(1, self.on_type)

    def fill_queue(self):
        while len(self.await_advance) < self.max_outstanding:
            (seq, wtok) = self.store.get_worktoken(self.send_seq)
            if wtok is None:
                logger.debug("got null wtok")
                break
            self.send_seq = seq
            logger.debug("sending seq %s", seq)
            self.await_advance.append(wtok.hid)
            self.send_buffer("S")
            self.send_struct(SUMMARY_FMT, seq, wtok.hid, wtok.time, wtok.nonce)

class SyncPeer(asyncore.dispatcher):
    def __init__(self, nid, store, sock):
        self.async_map = {}
        self.store = store
        self.nid = nid
        asyncore.dispatcher.__init__(self, sock=sock, map=self.async_map)

    def on_peer_discover(self, addr, port):
        pass

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            return
        (sock, addr) = pair
        logger.info("Incoming connection from %s", addr)
        SyncConnection(self.nid, self.store, sock, map=self.async_map)

class TestSync(unittest.TestCase):
    #pylint: disable=too-few-public-methods
    def test_simple(self):
        # Make room for 40 cakes
        ss1 = SyncStore(":memory:", WorkToken.overhead * 41)
        # Insert some records
        all_data = []
        for i in range(20):
            data = str(i)
            hid = hashlib.sha256(data).digest()
            wtok = WorkToken(hid)
            all_data.append((wtok, data))
            ss1.on_record(wtok, data)
        # Make something to sync it to
        ss2 = SyncStore(":memory:", WorkToken.overhead * 41)
        # Make some fake socket action
        for i in range(20, 40):
            data = str(i)
            hid = hashlib.sha256(data).digest()
            wtok = WorkToken(hid)
            all_data.append((wtok, data))
            ss2.on_record(wtok, data)
        (sock1, sock2) = socket.socketpair()
        # Make the connections
        n1 = SyncConnection('a' * 32, ss1, sock1)
        n2 = SyncConnection('b' * 32, ss2, sock2)
        # Kick off some async action
        asyncore.loop(timeout=1, count=5)
        # Check the client has records
        for i in range(20):
            self.assertTrue(ss1.get_data(all_data[i][0].hid) is not None)
            self.assertTrue(ss2.get_data(all_data[i][0].hid) is not None)
        _ = n1
        _ = n2

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()


