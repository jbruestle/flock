#!/usr/bin/python
#pylint: disable=missing-docstring
#pylint: disable=bad-continuation

import sqlite3
import hashlib
import time
import unittest
import logging
import random

RECORD_OVERHEAD = 100

logger = logging.getLogger('store')

class SyncStore(object):
    internal_sql = '''
    CREATE TABLE records (
        seq    INTEGER PRIMARY KEY AUTOINCREMENT,
        rtype  INTEGER,
        hid    TEXT,
        data   TEXT,
        time   INTEGER,
        nonce  INTEGER,
        score  REAL
    );
    CREATE TABLE ips (
        ip     TEXT,
        port   INTEGER,
        atime  INTEGER,
        ctime  INTEGER,
        dtime  INTEGER,
        wtime  INTEGER,
        busy   INTEGER,
        PRIMARY KEY (ip, port)
    );
    CREATE TABLE peers (
        nid    TEXT PRIMARY KEY,
        busy   INTEGER,
        seq    INTEGER
    );
    CREATE UNIQUE INDEX records_hid ON records (rtype, hid);
    CREATE INDEX records_score ON records (score);
    '''

    def __init__(self, dbfile, max_size):
        self.max_size = max_size
        self.con = sqlite3.connect(dbfile)
        self.cur = self.con.cursor()
        self.cur.executescript(SyncStore.internal_sql)
        self.cur.execute(
            "SELECT ifnull(sum(? + length(data)),0) FROM records", (RECORD_OVERHEAD,))
        self.cur_size = self.cur.fetchone()[0]
        self.cur.execute("UPDATE ips SET busy = 0")
        self.cur.execute("UPDATE peers SET busy = 0")
        self.connections = 0

    def __shrink(self):
        while self.cur_size > self.max_size:
            self.cur.execute(
                "SELECT seq, 100 + length(data) FROM records " +
                "ORDER BY score ASC LIMIT 1")
            (seq, size) = self.cur.fetchone()
            self.cur_size -= size
            self.cur.execute("DELETE FROM records WHERE seq = ?", (seq,))


    def on_add_peer(self, addr):
        self.cur.execute(
            "INSERT OR IGNORE INTO ips "
            "(ip, port, atime, ctime, dtime, wtime, busy) "
            "VALUES (?, ?, ?, NULL, 1, 0, 0)",
            (addr[0], addr[1], int(time.time())))

    def find_peer(self):
        self.cur.execute(
            "DELETE FROM ips where wtime > ?", (time.time() + 15*60,))
        self.cur.execute(
            "SELECT ip, port, dtime FROM ips " +
            "WHERE busy = 0 AND wtime < ? ORDER BY " +
            "IFNULL(ctime, 0) DESC, atime DESC LIMIT 1",
            (time.time(),))
        row = self.cur.fetchone()
        if row == None:
            logger.debug("Finding peers, no result")
            return None
        (ipaddr, port, dtime) = row
        logger.info("Finding peers: r = %s, dtime = %s", (ipaddr, port), dtime)
        dtime *= 2
        self.cur.execute("UPDATE ips SET busy = 1, dtime = ? WHERE ip = ? AND port = ?",
            (dtime, ipaddr, port))
        self.connections += 1
        logger.info("Connections = %d", self.connections)
        return (ipaddr, port)

    def on_connect(self, addr, nid):
        nstr = None
        if nid is not None:
            nstr = nid.encode('hex')
        logger.info("on_connect, addr = %s, nid = %s", addr, nstr)
        self.cur.execute("SELECT busy, seq from peers WHERE nid = ?", (buffer(nid),))
        row = self.cur.fetchone()
        if row is not None and row[0] == 1:
            # Busy case, simply return failue
            return None
        seq = 0
        if row is None:
            self.cur.execute("INSERT INTO peers (nid, busy, seq) VALUES (?, ?, ?)",
                (buffer(nid), 1, seq))
        else:
            self.cur.execute("UPDATE peers SET busy = 1 WHERE nid = ?", (buffer(nid),))
            seq = row[0]

        if addr is not None:
            self.cur.execute(
                "UPDATE ips SET ctime = ?, dtime = 1, wtime = 0 " +
                "WHERE ip = ? AND port = ?",
                (int(time.time()), addr[0], addr[1]))
        else:
            self.connections += 1
            logger.info("Connections = %d", self.connections)

        return seq

    def on_disconnect(self, addr, nid):
        self.connections -= 1
        nstr = None
        if nid is not None:
            nstr = nid.encode('hex')
        logger.info("on_disconnect, addr = %s, nid = %s", addr, nstr)
        logger.info("Connections = %d", self.connections)
        if nid is not None:
            self.cur.execute("UPDATE peers SET busy = 0 WHERE nid = ?", (buffer(nid),))
        if addr is not None:
            self.cur.execute("UPDATE ips SET busy = 0, wtime = dtime + ? WHERE ip = ? AND port = ?", 
                (time.time(), addr[0], addr[1]))

    def on_seq_update(self, nid, seq):
        self.cur.execute("UPDATE peers SET seq = ? WHERE nid = ?", (buffer(nid), seq))

    def on_summary(self, rtype, rsum, score):
        (hid, wtime, nonce) = rsum 
        self.cur.execute(
            "SELECT score, data FROM records "
            "WHERE rtype = ? AND hid = ?", (rtype, buffer(hid)))
        row = self.cur.fetchone()
        if row == None:
            return True
        (cscore, data) = row
        if cscore >= score:
            return False
        self.cur.execute(
            "REPLACE INTO records " +
            "(rtype, hid, data, time, nonce, score) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
            (rtype, buffer(hid), buffer(data), wtime, nonce, score))
        return False

    def on_record(self, rtype, rsum, score, data):
        (hid, wtime, nonce) = rsum 
        # Delete any existing version with lower score
        self.cur.execute(
            "DELETE FROM records " +
            "WHERE rtype = ? AND hid = ? AND score < ?",
            (rtype, buffer(hid), score))
        if self.cur.rowcount > 0:
            self.cur_size -= 100 + len(data)
        # Insert new row if not already there
        self.cur.execute(
            "INSERT OR IGNORE INTO records " +
            "(rtype, hid, data, time, nonce, score) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
            (rtype, buffer(hid), buffer(data), wtime, nonce, score))
        if self.cur.rowcount > 0:
            self.cur_size += 100 + len(data)
        # Shrink as needed
        self.__shrink()

    def get_summary(self, seq):
        self.cur.execute(
            "SELECT seq, rtype, hid, time, nonce " +
            "FROM records WHERE seq > ? " +
            "LIMIT 1", (seq,))
        row = self.cur.fetchone()
        if row is None:
            return None, None, None
        (rseq, rtype, hid, wtime, nonce) = row
        rsum = (str(hid), wtime, nonce)
        return (rseq, rtype, rsum)

    def get_data(self, rtype, hid):
        self.cur.execute("SELECT data FROM records WHERE rtype = ? AND hid = ?", 
            (rtype, buffer(hid)))
        row = self.cur.fetchone()
        if row is None:
            return None
        return str(row[0])

class TestSyncStore(unittest.TestCase):
    def __make_sum(self, data):
        hid = hashlib.sha256(data).digest()
        wtime = int(time.time())
        nonce = random.randint(0, 1000)
        rsum = (hid, wtime, nonce)
        return rsum

    def test_ordered(self):
        # Make a SyncStore that holds 20 objects
        store = SyncStore(":memory:", RECORD_OVERHEAD* 21)
        all_data = []
        # Make 30 random entries and insert them
        for i in range(30):
            data = str(i)
            rsum = self.__make_sum(data)
            score = random.random()
            all_data.append((rsum, score, data))
            store.on_record(0, rsum, score, data)
        # Sort entries by score
        all_data.sort(key=lambda x: x[1])
        # Check the the right elements are there
        for i in range(10):
            self.assertTrue(store.get_data(0, all_data[i][0][0]) == None)
        for i in range(10, 30):
            self.assertTrue(store.get_data(0, all_data[i][0][0]) == all_data[i][2])

    def test_update(self):
        # Make a SyncStore that holds 20 objects
        store = SyncStore(":memory:", RECORD_OVERHEAD * 21)
        all_data = []
        # Make 20 random entries and insert them
        for i in range(20):
            data = str(i)
            rsum = self.__make_sum(data)
            score = random.random()
            all_data.append((rsum, score, data))
            store.on_record(0, rsum, score, data)
        # 'Increase score' for the first 10 and update WT
        for i in range(10):
            store.on_summary(0, all_data[i][0], all_data[i][1] + 10)
        # Now add 10 more 'premined' values
        for i in range(10):
            data = str(20 + i)
            rsum = self.__make_sum(data)
            score = random.random() + 10
            all_data.append((rsum, score, data))
            store.on_record(0, rsum, score, data)
        # Check that right elements survived
        for i in range(10):
            self.assertTrue(store.get_data(0, all_data[i][0][0]) == all_data[i][2])
        for i in range(10, 20):
            self.assertTrue(store.get_data(0, all_data[i][0][0]) == None)

    def test_get_summary(self):
        # Make a SyncStore that holds 20 objects
        store = SyncStore(":memory:", RECORD_OVERHEAD * 21)
        all_data = []
        # Make 20 random entries and insert them
        for i in range(20):
            data = str(i)
            rsum = self.__make_sum(data)
            score = random.random() + 10
            all_data.append((rsum, score, data))
            store.on_record(0, rsum, score, data)
        # 'Mine' for the first 10 and update WT
        for i in range(10):
            store.on_summary(0, all_data[i][0], all_data[i][1] + 10)
        # Check for order of 'events'
        seq = 0
        for i in range(10):
            (seq, rtype, rsum) = store.get_summary(seq)
            self.assertTrue(rtype == 0)
            self.assertTrue(rsum == all_data[i + 10][0])
        for i in range(10, 20):
            (seq, rtype, rsum) = store.get_summary(seq)
            self.assertTrue(rtype == 0)
            self.assertTrue(rsum == all_data[i - 10][0])
        self.assertTrue(store.get_summary(seq)[0] is None)

if __name__ == '__main__':
    unittest.main()


