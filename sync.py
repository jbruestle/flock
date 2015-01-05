#!/usr/bin/python
#pylint: disable=missing-docstring

from collections import deque
import time
import asyncore
import asynchat
import struct
import hashlib
import socket
import unittest
import logging
import random
import sys

from worktoken import WorkToken
from store import SyncStore
from async import AsyncMgr

logger = logging.getLogger('sync')

GOAL_PEERS = 8
MAX_PEERS = 20
CONNECT_TIMEOUT = 5
NEGOTIATE_TIMEOUT = 2 

class Connection(asynchat.async_chat):
    def __init__(self, sock, map=None):
        asynchat.async_chat.__init__(self, sock=sock, map=map)
        self.__term_callback = None
        self.__ibuffer = []
        self.__fmt = None

    def handle_error(self):
        logger.warning("%s: got error: %s", id(self), sys.exc_info()[1])
        self.close()

    def handle_close(self):
        logger.info("%s: Got a close", id(self))
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

HELLO_FMT = '!4s20s'  # Magic #, ID
HELLO_ACK_FMT = '!QL'  # Seq No, Buffer size
SUMMARY_FMT = '!QB32sQQ' # Seq No, Hash, Timestamp, Nonce
DATA_HDR_FMT = '!H' # Data size
ADVANCE_FMT = '!?'

class SyncConnection(Connection):
    def __init__(self, nid, sstore, sock, map=None):
        Connection.__init__(self, sock, map=map)
        self.nid = nid
        self.remote = None
        self.addr = None
        self.store = sstore
        self.await_advance = deque()
        self.await_data = deque()
        self.max_outstanding = 0
        self.send_seq = 0
        self.recv_seq = None

    def compute_score(self, rtype, rsum):
        return 1.0

    def validate(self, rtype, rsum, data):
        return True 

    def start(self):
        self.send_struct(HELLO_FMT, '0net', self.nid)
        self.recv_struct(HELLO_FMT, self.on_hello)

    def handle_error(self):
        Connection.handle_error(self)
        self.store.on_disconnect(self.addr, self.remote)

    def handle_close(self):
        Connection.handle_close(self)
        self.store.on_disconnect(self.addr, self.remote)

    def on_hello(self, magic, remote):
        logger.debug("Got hello")
        if magic != '0net':
            logger.debug("Invalid magic")
            raise ValueError('Invalid magic')
        self.recv_seq = self.store.on_connect(self.addr, remote)
        if self.recv_seq == None:
            raise ValueError('Already connected to remote')
        self.remote = remote
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

    def on_summary(self, seq, rtype, hid, timestamp, nonce):
        _ = seq
        rsum = (hid, timestamp, nonce)
        score = self.compute_score(rtype, rsum)
        need_data = self.store.on_summary(rtype, rsum, score)
        if need_data:
            logger.debug("requesting data")
            self.await_data.append((seq, rtype, rsum, score))
            self.send_buffer('N')
        else:
            self.send_buffer('O')
        self.recv_seq = seq
        self.update_seq()
        self.recv_buffer(1, self.on_type)

    def on_data_header(self, dsize):
        (_, rtype, rsum, score) = self.await_data.popleft()
        callback = lambda data: self.on_data(rtype, rsum, score, data)
        self.recv_buffer(dsize, callback)

    def on_data(self, rtype, rsum, score, data):
        logger.debug("adding data")
        if not self.validate(rtype, rsum, data):
            raise ValueError("Validation failure, erroring connection")
        self.store.on_record(rtype, rsum, score, data)
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
        (rtype, hid) = self.await_advance.popleft()
        if need_data:
            data = self.store.get_data(rtype, hid)
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
            (seq, rtype, rsum) = self.store.get_summary(self.send_seq)
            if seq is None:
                logger.debug("got null seq")
                break
            self.send_seq = seq
            logger.debug("sending seq %s", seq)
            self.await_advance.append((rtype, rsum[0]))
            self.send_buffer("S")
            self.send_struct(SUMMARY_FMT, seq, rtype, rsum[0], rsum[1], rsum[2])

class SyncPeerConn(SyncConnection):
    def __init__(self, peer, sock, timeout):
        self.peer = peer
        SyncConnection.__init__(self, peer.nid, peer.store, sock, map=peer.asm.async_map)
        self.timer = peer.asm.add_timer(time.time() + timeout, self.timeout)

    def on_done(self):
        self.peer.on_disconnect()
        if self.timer is not None:
            self.peer.asm.cancel(self.timer)

    def handle_error(self):
        SyncConnection.handle_error(self)
        self.on_done()

    def handle_close(self):
        SyncConnection.handle_close(self)
        self.on_done()

    def timeout(self):
        self.timer = None
        if self.remote is None:
            logger.info("%s: Negotiation not complete, remote = %s", id(self), self.addr)
            self.close()
            self.handle_close()

class SyncServerConn(SyncPeerConn):
    def __init__(self, peer, sock):
        logger.info("Constructing server connection: %s", id(self))
        self.peer = peer
        SyncPeerConn.__init__(self, peer, sock, NEGOTIATE_TIMEOUT)
        self.start()

class SyncClientConn(SyncPeerConn):
    def __init__(self, peer, addr):
        logger.info("Constructing client connection to %s: %s", addr, id(self))
        self.peer = peer
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SyncPeerConn.__init__(self, peer, sock, CONNECT_TIMEOUT + NEGOTIATE_TIMEOUT)
        self.addr = addr
        self.connect(addr)

    def handle_connect(self):
        self.start()

class SyncPeer(asyncore.dispatcher):
    def __init__(self, asm, nid, store, sock):
        self.asm = asm
        self.store = store
        self.nid = nid
        self.store.clear_conn_state()
        self.connections = 0
        asyncore.dispatcher.__init__(self, sock=sock, map=self.asm.async_map)
        self.listen(5)

        self.asm.add_timer(time.time() + 1, self.on_timer)

    def add_peer(self, addr):
        self.store.on_add_peer(addr)

    def on_timer(self):
        self.asm.add_timer(time.time() + 1, self.on_timer)
        if self.connections >= GOAL_PEERS:
            return
        peer = self.store.find_peer()
        if peer == None:
            return
        self.connections += 1
        logger.info("Making connection to %s", peer)
        _ = SyncClientConn(self, peer)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            return
        (sock, addr) = pair
        if self.connections >= MAX_PEERS:
            sock.close()
            return
        self.connections += 1
        logger.info("Incoming connection from %s", addr)
        _ = SyncServerConn(self, sock)

    def on_disconnect(self):
        self.connections -= 1

class TestSync(unittest.TestCase):
    @staticmethod
    def add_data(all_data, store, num):
        data = str(num)
        hid = hashlib.sha256(data).digest()
        rtime = int(time.time())
        nonce = random.randint(0, 1000)
        score = random.random()
        rsum = (hid, rtime, nonce)
        all_data.append(hid)
        store.on_record(0, rsum, score, data)

    def test_simple(self):
        # Make room for 40 cakes
        ss1 = SyncStore(":memory:", WorkToken.overhead * 41)
        # Insert some records
        all_data = []
        for i in range(20):
            TestSync.add_data(all_data, ss1, i)
        # Make something to sync it to
        ss2 = SyncStore(":memory:", WorkToken.overhead * 41)
        # Make some fake socket action
        for i in range(20, 40):
            TestSync.add_data(all_data, ss2, i)
        # Make the connections
        (sock1, sock2) = socket.socketpair()
        n1 = SyncConnection('a' * 32, ss1, sock1)
        n2 = SyncConnection('b' * 32, ss2, sock2)
        n1.start()
        n2.start()
        # Kick off some async action
        asyncore.loop(timeout=1, count=5)
        # Check the client has records
        for i in range(40):
            self.assertTrue(ss1.get_data(0, all_data[i]) is not None)
            self.assertTrue(ss2.get_data(0, all_data[i]) is not None)

    @staticmethod
    def make_node(asm, store, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local = ('', port)
        sock.bind(local)
        nid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        return SyncPeer(asm, nid, store, sock)

    def test_node(self):
        asm = AsyncMgr()
        ss1 = SyncStore(":memory:", WorkToken.overhead * 41)
        ss2 = SyncStore(":memory:", WorkToken.overhead * 41)
        node1 = TestSync.make_node(asm, ss1, 6000)
        node2 = TestSync.make_node(asm, ss2, 6001)
        all_data = []
        for i in range(20):
            TestSync.add_data(all_data, ss1, i)
        for i in range(20, 40):
            TestSync.add_data(all_data, ss2, i)
        # Checks the no-connect timeout works
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local = ('', 7001)
        sock.bind(local)
        sock.listen(5)
        node1.add_peer(('127.0.0.1', 8001))
        node1.add_peer(('127.0.0.1', 7001))
        node1.add_peer(('127.0.0.1', 6001))
        asm.run(20.0)
        for i in range(40):
            self.assertTrue(ss1.get_data(0, all_data[i]) is not None)
            self.assertTrue(ss2.get_data(0, all_data[i]) is not None)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()


