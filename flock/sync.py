#!/usr/bin/python
# pylint: disable=missing-docstring
# pylint: disable=bad-continuation

import collections
import socket
import unittest
import logging
import random

from flock import dbconn
from flock import store
from flock import async
from flock import record

logger = logging.getLogger('sync') # pylint: disable=invalid-name

OUTSTANDING = 50
SUMMARY_HDR_FMT = '!QB32sB' # Seq No, RType, Hash, Summary Size
DATA_HDR_FMT = '!L' # Data size
ADVANCE_FMT = '!?'

class SyncConnection(async.Connection):
    def __init__(self, asm, sock):
        async.Connection.__init__(self, asm, sock)
        self.await_advance = collections.deque()
        self.await_data = collections.deque()
        self.max_outstanding = OUTSTANDING
        self.store = None
        self.send_seq = None
        self.recv_seq = None
        self.on_seq_update = None

    def start_sync(self, sstore, send_seq, on_seq_update):
        self.store = sstore
        self.send_seq = send_seq
        self.on_seq_update = on_seq_update
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
        self.on_seq_update(seq)

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

class TestSync(unittest.TestCase):
    @staticmethod
    def add_data(all_data, sstore, num):
        (hid, summary, body) = record.make_worktoken_record('text/plain', str(num))
        all_data.append(hid)
        sstore.on_record(record.RT_WORKTOKEN, hid, summary, body)

    def test_simple(self):
        # Make asm
        asm = async.AsyncMgr()
        # Make room for 40 cakes
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        db1 = dbconn.DbConn(":memory:")
        ss1 = store.SyncStore(tid, db1, 41 * (len('text/plain') + store.RECORD_OVERHEAD))
        # Insert some records
        all_data = []
        for i in range(20):
            TestSync.add_data(all_data, ss1, i)
        # Make something to sync it to
        db2 = dbconn.DbConn(":memory:")
        ss2 = store.SyncStore(tid, db2, 41 * (len('text/plain') + store.RECORD_OVERHEAD))
        # Make some fake socket action
        for i in range(20, 40):
            TestSync.add_data(all_data, ss2, i)
        # Make the connections
        (sock1, sock2) = socket.socketpair()
        node1 = SyncConnection(asm, sock1)
        node2 = SyncConnection(asm, sock2)
        node1.start_sync(ss1, 0, lambda seq: None)
        node2.start_sync(ss2, 0, lambda seq: None)
        # Kick off some async action
        asm.run(1.0)
        # Check the client has records
        for i in range(40):
            self.assertTrue(ss1.get_data(record.RT_WORKTOKEN, all_data[i])[0] is not None)
            self.assertTrue(ss2.get_data(record.RT_WORKTOKEN, all_data[i])[0] is not None)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()


