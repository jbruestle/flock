#!/usr/bin/env python
# pylint: disable=missing-docstring
# pylint: disable=bad-continuation
# pylint: disable=too-few-public-methods

import asyncore
import random
import time
import socket
import logging
import unittest

from flock import dbconn
from flock import async
from flock import store
from flock import sync

logger = logging.getLogger('syncgroup') # pylint: disable=invalid-name

NEG_TIMEOUT = 1.5
CONN_TIMEOUT = 3.0
NEG_HEADER_FMT = '!4s20s' # Magic number, remote NID
SEQ_HEADER_FMT = '!Q' # Magic number, remote NID

GOAL_CONNECTIONS = 5
MAX_CONNECTIONS = 10

class SyncSetup(sync.SyncConnection):
    def __init__(self, asm, sock, group, addr, timeout): # pylint: disable=too-many-arguments
        sync.SyncConnection.__init__(self, asm, sock)
        self.group = group
        self.addr = addr
        self.local_nid = None
        self.remote_nid = None
        self.timer = self.asm.add_timer(time.time() + timeout, self.on_timeout)

    # Called once TID is negotiated
    def start_negotiate(self):
        logger.debug("%d: Send neg header", id(self))
        self.local_nid = self.group.nid
        self.send_struct(NEG_HEADER_FMT, '0flk', self.local_nid)
        self.recv_struct(NEG_HEADER_FMT, self.on_neg_header)

    def handle_done(self):
        if self.timer is not None:
            self.asm.cancel(self.timer)
            self.timer = None
        if self.group is not None:
            self.group.on_disconnect(self.remote_nid, self.addr)

    def handle_error(self):
        self.handle_done()
        sync.SyncConnection.handle_error(self)

    def handle_close(self):
        self.handle_done()
        sync.SyncConnection.handle_close(self)

    def on_neg_header(self, magic, remote):
        logger.debug("%d: Got neg header", id(self))
        if magic != '0flk':
            raise ValueError("Invalid magic")
        seq = self.group.get_sync_seq(remote, self.addr)
        # Now we are part of connection count
        self.remote_nid = remote
        logger.debug("%d: Send seq header", id(self))
        self.send_struct(SEQ_HEADER_FMT, seq)
        self.recv_struct(SEQ_HEADER_FMT, self.on_seq_header)

    def on_seq_header(self, remote_seq):
        logger.debug("%d: Got seq header", id(self))
        if self.timer is not None:
            self.asm.cancel(self.timer)
            self.timer = None
        logger.info("%d: Sync established, Group: %s, remote: %s, nid: %s", id(self),
            self.group.tid.encode('hex'), self.getpeername(), self.remote_nid.encode('hex'))
        self.group.active[self.remote_nid] = self
        self.start_sync(self.group.store, remote_seq,
            lambda seq: self.group.update_seq(self.remote_nid, seq))

    def on_timeout(self):
        self.timer = None
        logger.debug("%d: Negotiation timeout", id(self))
        self.handle_close()

class OutgoingSync(SyncSetup):
    def __init__(self, asm, group, addr):
        logger.info("%d: Making outgoing connection from %s to %s", id(self),
            group.tid.encode('hex'), addr)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SyncSetup.__init__(self, asm, sock, group, addr, CONN_TIMEOUT + NEG_TIMEOUT)
        self.group.connections += 1
        logger.info("Connection = %d", self.group.connections)
        self.connect(addr)

    def handle_connect(self):
        logger.debug("%d: Got connection to %s", id(self), self.getpeername())
        self.send_buffer(self.group.tid)
        self.start_negotiate()

class IncomingSync(SyncSetup):
    def __init__(self, asm, sock, tid_to_group):
        self.tid_to_group = tid_to_group
        logger.debug("Receiving incoming connection from %s", sock.getpeername())
        SyncSetup.__init__(self, asm, sock, None, None, NEG_TIMEOUT)
        self.recv_buffer(20, self.on_tid)

    def on_tid(self, tid):
        self.group = self.tid_to_group(tid)
        self.group.connections += 1
        logger.info("Connection = %d", self.group.connections)
        self.start_negotiate()

class SyncGroup(object):
    internal_sql = '''
    CREATE TABLE IF NOT EXISTS _ips (
        ip     TEXT,
        port   INTEGER,
        busy   INTEGER,
        wtime  INTEGER,
        ntime  INTEGER,
        nid    BLOB,
        PRIMARY KEY (ip, port)
    );
    CREATE TABLE IF NOT EXISTS _peers (
        nid    BLOB PRIMARY KEY,
        busy   INTEGER,
        seq    INTEGER
    );
    UPDATE _ips SET busy = 0;
    UPDATE _peers SET busy = 0;
    '''
    def __init__(self, asm, tid, nid, dbc):
        self.asm = asm
        self.tid = tid
        self.nid = nid
        self.dbc = dbc
        self.dbc.executescript(SyncGroup.internal_sql)
        self.store = store.SyncStore(tid, dbc)
        self.connections = 0
        self.active = {}

    def get_sync_seq(self, nid, addr):
        # Set 'last nid' on IP record if any
        if addr is not None:
            self.dbc.execute(
                "INSERT OR REPLACE INTO _ips "
                "(ip, port, busy, wtime, ntime, nid) "
                "VALUES (?, ?, 1, 2, ?, ?)",
                (addr[0], addr[1], int(time.time()) + 2, buffer(nid)))
        # Check the stat of the nid
        self.dbc.execute("SELECT busy, seq from _peers WHERE nid = ?", (buffer(nid),))
        row = self.dbc.fetchone()
        if row is not None and row[0] == 1:
            # Busy case, simply fail
            raise ValueError("NID is busy")
        # Set result to busy, and return seq #
        if row is None:
            self.dbc.execute("INSERT INTO _peers (nid, busy, seq) VALUES (?, 1, 0)",
                (buffer(nid),))
            return 0
        else:
            self.dbc.execute("UPDATE _peers SET busy = 1 WHERE nid = ?", (buffer(nid),))
            return row[0]

    def on_timer(self):
        # If enough connections, don't bother
        if self.connections > GOAL_CONNECTIONS:
            return
        # TODO: What should I order by here?
        self.dbc.execute("SELECT ip, port "
            "FROM _ips LEFT OUTER JOIN _peers "
            "ON _peers.nid == _ips.nid "
            "WHERE ntime < ? AND _ips.busy = 0 AND IFNULL(_peers.busy, 0) == 0 "
            "LIMIT 1", (int(time.time()),))
        row = self.dbc.fetchone()
        if row is None:
            return # No one to connect to
        addr = (row[0], row[1])
        self.dbc.execute("UPDATE _ips SET busy = 1 WHERE ip = ? AND port = ?", (addr[0], addr[1]))
        OutgoingSync(self.asm, self, addr)

    def on_disconnect(self, nid, addr):
        self.connections -= 1
        logger.info("Connection = %d", self.connections)
        if nid is not None:
            self.dbc.execute("UPDATE _peers SET busy = 0 WHERE nid = ?", (buffer(nid),))
            if nid in self.active:
                del self.active[nid]
        if addr is not None:
            self.dbc.execute(
                "SELECT wtime, ntime FROM _ips WHERE ip = ? AND port = ?",
                (addr[0], addr[1]))
            row = self.dbc.fetchone()
            if row is None:
                return
            wtime = row[0]
            ntime = row[1]
            if nid is None:
                # Failed to connect
                wtime *= 2
            else:
                wtime = 2
            ntime = time.time() + wtime
            if wtime > 10*60:
                self.dbc.execute("DELETE FROM _ips WHERE ip = ? AND port = ?", (addr[0], addr[1]))
            else:
                self.dbc.execute(
                    "UPDATE _ips SET busy = 0, wtime = ?, ntime = ? WHERE ip = ? AND port = ?",
                    (wtime, ntime, addr[0], addr[1]))

    def update_seq(self, nid, seq):
        self.dbc.execute("UPDATE _peers SET seq = ? WHERE nid = ?", (seq, buffer(nid)))
        self.poke()

    def add_peer(self, addr):
        self.dbc.execute(
            "INSERT OR IGNORE INTO _ips "
            "(ip, port, busy, wtime, ntime, nid) "
            "VALUES (?, ?, 0, 1000, ?, NULL)",
            (addr[0], addr[1], int(time.time())))

    def poke(self):
        for _, conn in self.active.iteritems():
            conn.fill_queue()

class TestNode(asyncore.dispatcher):
    def __init__(self, asm, tid, port):
        self.asm = asm
        self.nid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        self.tid = tid
        self.dbc = dbconn.DbConn(":memory:")
        self.group = SyncGroup(asm, self.tid, self.nid, self.dbc)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local = ('', port)
        sock.bind(local)
        asyncore.dispatcher.__init__(self, sock=sock, map=self.asm.async_map)
        self.listen(5)
        self.on_timer()

    def on_timer(self):
        self.asm.add_timer(time.time() + 1, self.on_timer)
        self.group.on_timer()

    def add_peer(self, addr):
        self.group.add_peer(addr)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            return
        (sock, _) = pair # pylint: disable=unpacking-non-sequence
        IncomingSync(self.asm, sock, self.tid_to_group)

    def tid_to_group(self, tid):
        assert tid == self.tid
        return self.group

class TestSync(unittest.TestCase):
    def test_node(self):
        asm = async.AsyncMgr()
        tid = 'aaaabbbbcccceeeeffff'
        node1 = TestNode(asm, tid, 6000)
        node2 = TestNode(asm, tid, 6001)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local = ('', 7001)
        sock.bind(local)
        sock.listen(5)

        node1.add_peer(('127.0.0.1', 8001))
        node1.add_peer(('127.0.0.1', 7001))
        node1.add_peer(('127.0.0.1', 6001))
        node2.add_peer(('127.0.0.1', 6000))

        asm.run(10.0)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    unittest.main()


