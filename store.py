#!/usr/bin/python
#pylint: disable=missing-docstring

import sqlite3
import hashlib
import unittest
from worktoken import WorkToken

class SyncStore(object):
    internal_sql = '''
    CREATE TABLE records (
        seq    INTEGER PRIMARY KEY AUTOINCREMENT,
        hid    TEXT,
        data   TEXT,
        time   INTEGER,
        nonce  INTEGER,
        score  REAL
    );
    CREATE TABLE ips (
        ip     TEXT,
        port   INTEGER,
        errors INTEGER,
        nid    TEXT,
        PRIMARY KEY (ip, port)
    );
    CREATE TABLE peers (
        nid    TEXT PRIMARY KEY,
        state  INTEGER,
        seq    INTEGER
    );
    CREATE UNIQUE INDEX records_hid ON records (hid);
    CREATE INDEX records_score ON records (score);
    '''

    def __init__(self, dbfile, max_size):
        self.max_size = max_size
        self.con = sqlite3.connect(dbfile)
        self.cur = self.con.cursor()
        self.cur.executescript(SyncStore.internal_sql)
        self.cur.execute(
            "SELECT ifnull(sum(? + length(data)),0) FROM records", (WorkToken.overhead,))
        self.cur_size = self.cur.fetchone()[0]

    def __shrink(self):
        while self.cur_size > self.max_size:
            self.cur.execute(
                "SELECT seq, 100 + length(data) FROM records " +
                "ORDER BY score ASC LIMIT 1")
            (seq, size) = self.cur.fetchone()
            self.cur_size -= size
            self.cur.execute("DELETE FROM records WHERE seq = ?", (seq,))

    def on_connect(self, nid):
        self.cur.execute("SELECT state, seq from peers WHERE nid = ?", (nid,))
        row = self.cur.fetchone()
        if row == None:
            self.cur.execute("INSERT INTO peers (nid, state, seq) VALUES (?, ?, ?)",
                (nid, 1, 0)) 
            return 0
        (state, seq) = row
        if state == 1:
            return None
        return seq

    def on_disconnect(self, nid):
        self.cur.execute("UPDATE peers SET state = 1 WHERE nid = ?", (nid,))

    def on_seq_update(self, nid, seq):
        self.cur.execute("UPDATE peers SET seq = ? WHERE nid = ?", (nid, seq))

    def on_worktoken(self, wtok):
        self.cur.execute(
            "SELECT score, data FROM records "
            "WHERE hid = ?", (buffer(wtok.hid),))
        row = self.cur.fetchone()
        if row == None:
            return True
        (score, data) = row
        if score >= wtok.score:
            return False
        self.cur.execute(
            "REPLACE INTO records " +
            "(hid, data, time, nonce, score) " +
            "VALUES (?, ?, ?, ?, ?)",
            (buffer(wtok.hid), buffer(data), wtok.time, wtok.nonce, wtok.score))
        return False

    def on_record(self, wtok, data):
        # Delete any existing version with lower WT
        self.cur.execute(
            "DELETE FROM records " +
            "WHERE hid = ? AND score < ?",
            (buffer(wtok.hid), wtok.score))
        if self.cur.rowcount > 0:
            self.cur_size -= 100 + len(data)
        # Insert new row if not already there
        self.cur.execute(
            "INSERT OR IGNORE INTO records " +
            "(hid, data, time, nonce, score) " +
            "VALUES (?, ?, ?, ?, ?)",
            (buffer(wtok.hid), buffer(data), wtok.time, wtok.nonce, wtok.score))
        if self.cur.rowcount > 0:
            self.cur_size += 100 + len(data)
        # Shrink as needed
        self.__shrink()

    def get_worktoken(self, seq):
        self.cur.execute(
            "SELECT seq, hid, time, nonce " +
            "FROM records WHERE seq > ? " +
            "LIMIT 1", (seq,))
        row = self.cur.fetchone()
        if row is None:
            return None, None
        (rseq, hid, wtime, nonce) = row
        return (rseq, WorkToken(str(hid), wtime, nonce))

    def get_data(self, hid):
        self.cur.execute("SELECT data FROM records WHERE hid = ?", (buffer(hid),))
        row = self.cur.fetchone()
        if row is None:
            return None
        return str(row[0])

class TestSyncStore(unittest.TestCase):
    def test_ordered(self):
        # Make a SyncStore that holds 20 objects
        store = SyncStore(":memory:", WorkToken.overhead * 21)
        all_data = []
        # Make 30 random entries and insert them
        for i in range(30):
            data = str(i)
            hid = hashlib.sha256(data).digest()
            wtok = WorkToken(hid)
            all_data.append((wtok, data))
            store.on_record(wtok, data)
        # Sort entries by score
        all_data.sort(key=lambda x: x[0].score)
        # Check the the right elements are there
        for i in range(10):
            self.assertTrue(store.get_data(all_data[i][0].hid) == None)
        for i in range(10, 30):
            self.assertTrue(store.get_data(all_data[i][0].hid) == all_data[i][1])

    def test_update(self):
        # Make a SyncStore that holds 20 objects
        store = SyncStore(":memory:", WorkToken.overhead * 21)
        all_data = []
        # Make 20 random entries and insert them
        for i in range(20):
            data = str(i)
            hid = hashlib.sha256(data).digest()
            wtok = WorkToken(hid)
            all_data.append((wtok, data))
            store.on_record(wtok, data)
        # 'Mine' for the first 10 and update WT
        for i in range(10):
            all_data[i][0].mine(1000)
            store.on_worktoken(all_data[i][0])
        # Now add 10 more 'premined' values
        for i in range(10):
            data = str(20 + i)
            hid = hashlib.sha256(data).digest()
            wtok = WorkToken(hid)
            wtok.mine(1000)
            store.on_record(wtok, data)
        # Check that right elements survived
        for i in range(10):
            self.assertTrue(store.get_data(all_data[i][0].hid) == all_data[i][1])
        for i in range(10, 20):
            self.assertTrue(store.get_data(all_data[i][0].hid) == None)

    def test_get_worktoken(self):
        # Make a SyncStore that holds 20 objects
        store = SyncStore(":memory:", WorkToken.overhead * 21)
        all_data = []
        # Make 20 random entries and insert them
        for i in range(20):
            data = str(i)
            hid = hashlib.sha256(data).digest()
            wtok = WorkToken(hid)
            all_data.append((wtok, data))
            store.on_record(wtok, data)
        # 'Mine' for the first 10 and update WT
        for i in range(10):
            all_data[i][0].mine(1000)
            store.on_worktoken(all_data[i][0])
        # Check for order of 'events'
        seq = 0
        for i in range(10):
            (seq, wtok) = store.get_worktoken(seq)
            self.assertTrue(wtok.hid == all_data[i + 10][0].hid)
        for i in range(10, 20):
            (seq, wtok) = store.get_worktoken(seq)
            self.assertTrue(wtok.hid == all_data[i - 10][0].hid)
        self.assertTrue(store.get_worktoken(seq)[0] is None)

if __name__ == '__main__':
    unittest.main()


