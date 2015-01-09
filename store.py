#!/usr/bin/python
#pylint: disable=missing-docstring
#pylint: disable=bad-continuation

import sqlite3
import hashlib
import time
import unittest
import logging
import random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

import record

RECORD_OVERHEAD = 100

logger = logging.getLogger('store')

class SyncStore(object):
    internal_sql = '''
    CREATE TABLE records (
        seq     INTEGER PRIMARY KEY AUTOINCREMENT,
        rtype   INTEGER,
        hid     TEXT,
        summary TEXT,
        data    TEXT,
        score   REAL
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

    def __init__(self, tid, dbfile, max_size):
        self.tid = tid
        self.max_size = max_size
        self.con = sqlite3.connect(dbfile)
        self.cur = self.con.cursor()
        self.cur.executescript(SyncStore.internal_sql)
        self.cur.execute(
            "SELECT ifnull(sum(? + length(data)),0) FROM records", (RECORD_OVERHEAD,))
        self.cur_size = self.cur.fetchone()[0]
        self.verify = None
        self.cur.execute("SELECT data FROM records WHERE rtype = ? LIMIT 1", (record.RT_PUBKEY,))
        row = self.cur.fetchone()
        if row is not None:
            __set_pubkey(row[0])
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

    def __set_pubkey(data):
        pubkey = RSA.importKey(data, 'DER')
        self.verify = signer = PKCS1_PSS.new(key)

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

    def on_summary(self, rtype, hid, summary):
        # Check for existing records
        self.cur.execute(
            "SELECT score, data FROM records "
            "WHERE rtype = ? AND hid = ?", (rtype, buffer(hid)))
        row = self.cur.fetchone()
        # If no existing entry, return true
        if row == None:
            return True
        # Score incoming and new record
        score = record.score_record(rtype, hid, summary)
        # If it's negative, drop
        if score < 0:
            return False;
        (cscore, data) = row
        # If new records isn't better, forget it
        if cscore >= score:
            return False
        # If it's a WT records, just update the summary
        if rtype == record.RT_WORKTOKEN:
            self.cur.execute(
                "REPLACE INTO records " +
                "(rtype, hid, score, data, score) " +
                "VALUES (?, ?, ?, ?, ?)",
            (rtype, buffer(hid), buffer(summary), buffer(data), score))
            return False
        # Otherwise I need the whole data
        return True 

    def on_record(self, rtype, hid, summary, data):
        # Validate + Score
        if not record.validate_record(rtype, self.tid, self.verify, hid, summary, data):
            return False
        score = record.score_record(rtype, hid, summary)
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
            "(rtype, hid, summary, data, score) " +
            "VALUES (?, ?, ?, ?, ?)",
            (rtype, buffer(hid), buffer(summary), buffer(data), score))
        if self.cur.rowcount > 0:
            self.cur_size += 100 + len(data)
        # Shrink as needed
        self.__shrink()
        # Maybe found a pubkey?
        if rtype == record.RT_PUBKEY:
            __set_pubkey(data)
        return True

    def get_summary(self, seq):
        self.cur.execute(
            "SELECT seq, rtype, hid, summary " +
            "FROM records WHERE seq > ? " +
            "LIMIT 1", (seq,))
        row = self.cur.fetchone()
        if row is None:
            return None, None, None, None
        (rseq, rtype, hid, summary) = row
        return (rseq, rtype, str(hid), str(summary))

    def get_data(self, rtype, hid):
        self.cur.execute("SELECT data FROM records WHERE rtype = ? AND hid = ?", 
            (rtype, buffer(hid)))
        row = self.cur.fetchone()
        if row is None:
            return None, None
        return record.get_record_content(rtype, str(row[0]))

    def get_raw_data(self, rtype, hid):
        self.cur.execute("SELECT data FROM records WHERE rtype = ? AND hid = ?", 
            (rtype, buffer(hid)))
        row = self.cur.fetchone()
        if row is None:
            return None
        return row[0]

class TestSyncStore(unittest.TestCase):

    def test_ordered(self):
        # Make a SyncStore that holds 20 objects
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        store = SyncStore(tid, ":memory:", 21 * (len('text/plain') + RECORD_OVERHEAD))
        all_data = []
        # Make 30 random entries and insert them
        for i in range(30):
            (hid, summary, data) = record.make_worktoken_record('text/plain', str(i))
            score = record.score_record(record.RT_WORKTOKEN, hid, summary)
            all_data.append((score, hid, str(i)))
            store.on_record(record.RT_WORKTOKEN, hid, summary, data)
        # Sort entries by score
        all_data.sort(key=lambda x: x[0])
        # Check the the right elements are there
        for i in range(10):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, all_data[i][1]) == (None, None))
        for i in range(10, 30):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, all_data[i][1]) == ('text/plain', all_data[i][2]))

    def test_update(self):
        # Make a SyncStore that holds 20 objects
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        store = SyncStore(tid, ":memory:", 21 * (len('text/plain') + RECORD_OVERHEAD))
        all_data = []
        # Make 20 random entries and insert them
        for i in range(20):
            (hid, summary, data) = record.make_worktoken_record('text/plain', str(i))
            all_data.append((hid, str(i)))
            store.on_record(record.RT_WORKTOKEN, hid, summary, data)
        # 'Increase score' for the first 10 and update WT
        for i in range(10):
            (score, summary) = record.mine_worktoken(all_data[i][0], 1000)
            store.on_summary(record.RT_WORKTOKEN, all_data[i][0], summary)
        # Now add 10 more 'premined' values
        for i in range(10):
            (hid, summary, data) = record.make_worktoken_record('text/plain', str(20+i))
            (score, summary) = record.mine_worktoken(hid, 1000)
            store.on_record(record.RT_WORKTOKEN, hid, summary, data)
            all_data.append((hid, str(20+i)))
        # Check that right elements survived
        for i in range(10):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, all_data[i][0])[1] == all_data[i][1])
        for i in range(10, 20):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, all_data[i][0])[1] is None)
        for i in range(20, 30):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, all_data[i][0])[1] == all_data[i][1])

    def test_get_summary(self):
        return
        # Make a SyncStore that holds 20 objects
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        store = SyncStore(tid, ":memory:", 21 * (len('text/plain') + RECORD_OVERHEAD))
        all_data = []
        # Make 20 random entries and insert them
        for i in range(20):
            (hid, summary, data) = record.make_worktoken_record('text/plain', str(i))
            all_data.append((hid, str(i)))
            store.on_record(record.RT_WORKTOKEN, hid, summary, data)
        # 'Mine' for the first 10 and update WT
        for i in range(10):
            (score, summary) = record.mine_worktoken(all_data[i][0], 1000)
            store.on_summary(record.RT_WORKTOKEN, all_data[i][0], summary)
        # Check for order of 'events'
        seq = 0
        for i in range(10):
            (seq, rtype, hid, summary) = store.get_summary(seq)
            self.assertTrue(rtype == record.RT_WORKTOKEN)
            self.assertTrue(hid == all_data[i + 10][0])
        for i in range(10, 20):
            (seq, rtype, rsum) = store.get_summary(seq)
            self.assertTrue(rtype == record.RT_WORKTOKEN)
            self.assertTrue(hid == all_data[i - 10][0])
        self.assertTrue(store.get_summary(seq)[0] is None)

if __name__ == '__main__':
    unittest.main()


