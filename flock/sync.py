#!/usr/bin/python
# pylint: disable=missing-docstring
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-few-public-methods

import collections
import time
import asyncore
import socket
import unittest
import logging
import random

from flock import store
from flock import async
from flock import record

logger = logging.getLogger('sync') # pylint: disable=invalid-name

GOAL_PEERS = 8
MAX_PEERS = 20
CONNECT_TIMEOUT = 5
NEGOTIATE_TIMEOUT = 2

HELLO_FMT = '!4s20s'  # Magic #, ID
HELLO_ACK_FMT = '!QL'  # Seq No, Buffer size
SUMMARY_HDR_FMT = '!QB32sB' # Seq No, RType, Hash, Summary Size
DATA_HDR_FMT = '!H' # Data size
ADVANCE_FMT = '!?'

class SyncConnection(async.Connection):
    def __init__(self, nid, sstore, sock, map=None): #pylint: disable=redefined-builtin
        async.Connection.__init__(self, sock, map=map)
        self.nid = nid
        self.remote = None
        self.addr = None
        self.store = sstore
        self.await_advance = collections.deque()
        self.await_data = collections.deque()
        self.max_outstanding = 0
        self.send_seq = 0
        self.recv_seq = None

    def start(self):
        self.send_struct(HELLO_FMT, '0net', self.nid)
        self.recv_struct(HELLO_FMT, self.on_hello)

    def handle_error(self):
        async.Connection.handle_error(self)
        if self.store is not None:
            self.store.on_disconnect(self.addr, self.remote)

    def handle_close(self):
        async.Connection.handle_close(self)
        if self.store is not None:
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
            self.recv_struct(SUMMARY_HDR_FMT, self.on_summary_header)
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

    def on_summary_header(self, seq, rtype, hid, slen):
        callback = lambda summary: self.on_summary(seq, rtype, hid, summary)
        self.recv_buffer(slen, callback)

    def on_summary(self, seq, rtype, hid, summary):
        need_data = self.store.on_summary(rtype, hid, summary)
        if need_data:
            logger.debug("requesting data")
            self.await_data.append((seq, rtype, hid, summary))
            self.send_buffer('N')
        else:
            self.send_buffer('O')
        self.recv_seq = seq
        self.update_seq()
        self.recv_buffer(1, self.on_type)

    def on_data_header(self, dsize):
        (_, rtype, hid, summary) = self.await_data.popleft()
        callback = lambda data: self.on_data(rtype, hid, summary, data)
        self.recv_buffer(dsize, callback)

    def on_data(self, rtype, hid, summary, data):
        logger.debug("adding data")
        if not self.store.on_record(rtype, hid, summary, data):
            raise ValueError("Validation failure, erroring connection")
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
            data = self.store.get_raw_data(rtype, hid)
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
            (seq, rtype, hid, summary) = self.store.get_summary(self.send_seq)
            if seq is None:
                logger.debug("got null seq")
                break
            self.send_seq = seq
            logger.debug("sending seq %s", seq)
            self.await_advance.append((rtype, hid))
            self.send_buffer("S")
            self.send_struct(SUMMARY_HDR_FMT, seq, rtype, hid, len(summary))
            self.send_buffer(summary)

class SyncPeerConn(SyncConnection):
    def __init__(self, peer, sock, sstore, timeout):
        self.peer = peer
        SyncConnection.__init__(self, peer.nid, sstore, sock, map=peer.asm.async_map)
        self.timer = peer.asm.add_timer(time.time() + timeout, self.timeout)

    def on_done(self):
        # TODO: This is needlessly linear
        self.peer.connections.remove(self)
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
        SyncPeerConn.__init__(self, peer, sock, None, NEGOTIATE_TIMEOUT)
        self.recv_buffer(20, self.on_tid)

    def on_tid(self, tid):
        logger.info("%s: received tid: %s", id(self), tid.encode('hex'))
        if tid not in self.peer.stores:
            raise ValueError('Unknown tid')
        self.store = self.peer.stores[tid]
        self.store.connections += 1
        logger.info("%s: Incrementing connection on server: %d", id(self), self.store.connections)
        if self.store.connections > MAX_PEERS:
            raise ValueError('Too many connections')
        self.start()

class SyncClientConn(SyncPeerConn):
    def __init__(self, peer, tid, addr):
        logger.info("Constructing client connection to %s: %s", addr, id(self))
        self.peer = peer
        self.tid = tid
        sstore = peer.stores[tid]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SyncPeerConn.__init__(self, peer, sock, sstore, CONNECT_TIMEOUT + NEGOTIATE_TIMEOUT)
        self.addr = addr
        self.connect(addr)

    def handle_connect(self):
        logger.info("%s: sending tid: %s", id(self), self.tid.encode('hex'))
        self.send_buffer(self.tid)
        self.start()

class SyncPeer(asyncore.dispatcher):
    def __init__(self, asm, nid, stores, sock):
        self.asm = asm
        self.stores = stores
        self.nid = nid
        self.connections = []
        asyncore.dispatcher.__init__(self, sock=sock, map=self.asm.async_map)
        self.listen(5)

        self.asm.add_timer(time.time() + 1, self.on_timer)

    def add_peer(self, tid, addr):
        self.stores[tid].on_add_peer(addr)

    def on_timer(self):
        self.asm.add_timer(time.time() + 1, self.on_timer)
        for conn in self.connections:
            # TODO: This is an ineffient way to do this
            conn.fill_queue()
        for tid, sstore in self.stores.iteritems():
            sstore.con.commit()
        for tid, sstore in self.stores.iteritems():
            if sstore.connections >= GOAL_PEERS:
                return
            peer = sstore.find_peer()
            if peer == None:
                return
            logger.info("Making connection to %s", peer)
            self.connections.append(SyncClientConn(self, tid, peer))

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            return
        (sock, addr) = pair # pylint: disable=unpacking-non-sequence
        logger.info("Incoming connection from %s", addr)
        self.connections.append(SyncServerConn(self, sock))

class TestSync(unittest.TestCase):
    @staticmethod
    def add_data(all_data, sstore, num):
        (hid, summary, body) = record.make_worktoken_record('text/plain', str(num))
        all_data.append(hid)
        sstore.on_record(record.RT_WORKTOKEN, hid, summary, body)

    def test_simple(self):
        # Make room for 40 cakes
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        ss1 = store.SyncStore(tid, ":memory:", 21 * (len('text/plain') + store.RECORD_OVERHEAD))
        # Insert some records
        all_data = []
        for i in range(20):
            TestSync.add_data(all_data, ss1, i)
        # Make something to sync it to
        ss2 = store.SyncStore(tid, ":memory:", 21 * (len('text/plain') + store.RECORD_OVERHEAD))
        # Make some fake socket action
        for i in range(20, 40):
            TestSync.add_data(all_data, ss2, i)
        # Make the connections
        (sock1, sock2) = socket.socketpair()
        node1 = SyncConnection('a' * 32, ss1, sock1)
        node2 = SyncConnection('b' * 32, ss2, sock2)
        node1.start()
        node2.start()
        # Kick off some async action
        asyncore.loop(timeout=1, count=5)
        # Check the client has records
        for i in range(40):
            self.assertTrue(ss1.get_data(2, all_data[i]) is not None)
            self.assertTrue(ss2.get_data(2, all_data[i]) is not None)

    @staticmethod
    def make_node(asm, tid, sstore, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local = ('', port)
        sock.bind(local)
        nid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        stores = {}
        stores[tid] = sstore
        return SyncPeer(asm, nid, stores, sock)

    def test_node(self):
        tid = 'aaaabbbbcccceeeeffff'
        asm = async.AsyncMgr()
        ss1 = store.SyncStore(tid, ":memory:", 41 * (len('text/plain') + store.RECORD_OVERHEAD))
        ss2 = store.SyncStore(tid, ":memory:", 41 * (len('text/plain') + store.RECORD_OVERHEAD))
        node1 = TestSync.make_node(asm, tid, ss1, 6000)
        _ = TestSync.make_node(asm, tid, ss2, 6001)
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
        node1.add_peer(tid, ('127.0.0.1', 8001))
        node1.add_peer(tid, ('127.0.0.1', 7001))
        node1.add_peer(tid, ('127.0.0.1', 6001))
        asm.run(20.0)
        for i in range(40):
            self.assertTrue(ss1.get_data(2, all_data[i]) is not None)
            self.assertTrue(ss2.get_data(2, all_data[i]) is not None)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()


