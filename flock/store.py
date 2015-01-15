#!/usr/bin/python
# pylint: disable=missing-docstring
# pylint: disable=bad-continuation
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-arguments

import sqlite3
import time
import unittest
import logging
import random
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

from flock import record
from flock import schema

RECORD_OVERHEAD = 100
DEFAULT_APP_SIZE = 100*1024*1024
SCHEMA_HID = hashlib.sha256('_schema').digest()

logger = logging.getLogger('store') # pylint: disable=invalid-name

class SyncStore(object):
    internal_sql = '''
    CREATE TABLE IF NOT EXISTS _singletons (
        key     TEXT PRIMARY KEY,
        data    BLOB
    );
    CREATE TABLE IF NOT EXISTS _records (
        seq     INTEGER PRIMARY KEY AUTOINCREMENT,
        rtype   INTEGER,
        hid     BLOB,
        summary BLOB,
        data    BLOB,
        score   REAL
    );
    CREATE TABLE IF NOT EXISTS _ips (
        ip     TEXT,
        port   INTEGER,
        atime  INTEGER,
        ctime  INTEGER,
        dtime  INTEGER,
        wtime  INTEGER,
        busy   INTEGER,
        PRIMARY KEY (ip, port)
    );
    CREATE TABLE IF NOT EXISTS _peers (
        nid    TEXT PRIMARY KEY,
        busy   INTEGER,
        seq    INTEGER
    );
    CREATE UNIQUE INDEX IF NOT EXISTS _records_hid ON _records (rtype, hid);
    CREATE INDEX IF NOT EXISTS _records_score ON _records (score);
    '''

    def __init__(self, tid, dbfile, max_size):
        self.tid = tid
        self.max_size = max_size
        self.con = sqlite3.connect(dbfile)
        self.con.set_authorizer(self.__authorize)
        self.be_safe = False
        self.cur = self.con.cursor()
        self.cur.executescript(SyncStore.internal_sql)
        self.cur.execute(
            "SELECT ifnull(sum(? + length(data)),0) FROM _records", (RECORD_OVERHEAD,))
        self.cur_size = self.cur.fetchone()[0]
        self.verify = None
        self.cur.execute("SELECT data FROM _records WHERE rtype = ? LIMIT 1", (record.RT_PUBKEY,))
        row = self.cur.fetchone()
        if row is not None:
            self.__set_pubkey(row[0])
        self.signer = None
        self.cur.execute("SELECT data FROM _singletons WHERE key = 'priv_key'")
        row = self.cur.fetchone()
        if row is not None:
            priv_key = RSA.importKey(row[0], 'DER')
            self.signer = PKCS1_PSS.new(priv_key)
        self.cur.execute("UPDATE _ips SET busy = 0")
        self.cur.execute("UPDATE _peers SET busy = 0")
        self.connections = 0
        self.schema = None
        (ctype, sjson) = self.get_data(record.RT_SIGNED, SCHEMA_HID)
        if ctype == 'application/json':
            self.schema = schema.Schema(sjson)

    def __authorize(self, atype, arg1, arg2, table, src):
        _ = (arg1, arg2, table, src)
        if not self.be_safe:
            return sqlite3.SQLITE_OK
        # NOTE: Function and Recursive are not in sqlite3 package
        # Are they needed?
        if (atype == sqlite3.SQLITE_ANALYZE or
            atype == sqlite3.SQLITE_READ or
            atype == sqlite3.SQLITE_OK or
            atype == sqlite3.SQLITE_SELECT):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    def __shrink(self):
        # TODO: This needs to remove projected records
        # Also, should split WT + SIGNED max sizes
        while self.cur_size > self.max_size:
            self.cur.execute(
                "SELECT seq, 100 + length(data) FROM _records " +
                "ORDER BY score ASC LIMIT 1")
            (seq, size) = self.cur.fetchone()
            self.cur_size -= size
            self.cur.execute("DELETE FROM _records WHERE seq = ?", (seq,))

    def __set_pubkey(self, data):
        pub_key = RSA.importKey(data, 'DER')
        self.verify = PKCS1_PSS.new(pub_key)

    def set_priv_key(self, priv_key):
        self.signer = PKCS1_PSS.new(priv_key)
        pub_key = priv_key.publickey()
        self.cur.execute("INSERT INTO _singletons (key, data) VALUES ('priv_key', ?)",
            (buffer(priv_key.exportKey('PEM')),))
        (hid, summary, body) = record.make_pubkey_record(pub_key)
        self.on_record(record.RT_PUBKEY, hid, summary, body)

    def on_add_peer(self, addr):
        self.cur.execute(
            "INSERT OR IGNORE INTO _ips "
            "(ip, port, atime, ctime, dtime, wtime, busy) "
            "VALUES (?, ?, ?, NULL, 1, 0, 0)",
            (addr[0], addr[1], int(time.time())))

    def find_peer(self):
        self.cur.execute(
            "DELETE FROM _ips where wtime > ?", (time.time() + 15*60,))
        self.cur.execute(
            "SELECT ip, port, dtime FROM _ips " +
            "WHERE busy = 0 AND wtime < ? ORDER BY " +
            "IFNULL(ctime, 0) DESC, atime DESC LIMIT 1",
            (time.time(),))
        row = self.cur.fetchone()
        if row == None:
            logger.debug("Finding peers, no result")
            return None
        (ipaddr, port, dtime) = row
        logger.debug("Finding _peers: r = %s, dtime = %s", (ipaddr, port), dtime)
        dtime *= 2
        self.cur.execute("UPDATE _ips SET busy = 1, dtime = ? WHERE ip = ? AND port = ?",
            (dtime, ipaddr, port))
        self.connections += 1
        logger.debug("Adding find peer, Connections = %d", self.connections)
        return (ipaddr, port)

    def on_connect(self, addr, nid, outbound):
        logger.debug("on_connect, addr = %s, nid = %s", addr, nid.encode('hex'))
        self.cur.execute("SELECT busy, seq from _peers WHERE nid = ?", (buffer(nid),))
        row = self.cur.fetchone()
        if row is not None and row[0] == 1:
            # Busy case, simply return failue
            return None
        seq = 0
        if row is None:
            self.cur.execute("INSERT INTO _peers (nid, busy, seq) VALUES (?, ?, ?)",
                (buffer(nid), 1, seq))
        else:
            self.cur.execute("UPDATE _peers SET busy = 1 WHERE nid = ?", (buffer(nid),))
            seq = row[0]
        
        logger.info("Add connection: remote = %s, outbound = %s, tid = %s, nid = %s",
            addr, outbound, self.tid.encode('hex'), nid.encode('hex'))

        if outbound:
            self.cur.execute(
                "UPDATE _ips SET ctime = ?, dtime = 1, wtime = 0 " +
                "WHERE ip = ? AND port = ?",
                (int(time.time()), addr[0], addr[1]))

        return seq

    def on_disconnect(self, addr, nid):
        self.connections -= 1
        nstr = None
        if nid is not None:
            nstr = nid.encode('hex')
        logger.debug("on_disconnect, addr = %s, nid = %s", addr, nstr)
        logger.debug("Connections = %d", self.connections)
        if nid is not None:
            self.cur.execute("UPDATE _peers SET busy = 0 WHERE nid = ?", (buffer(nid),))
            logger.info("Drop connection: tid = %s, nid = %s",
                self.tid.encode('hex'), nid.encode('hex'))
        if addr is not None:
            self.cur.execute(
                "UPDATE _ips SET busy = 0, wtime = dtime + ? WHERE ip = ? AND port = ?",
                (time.time(), addr[0], addr[1]))

    def on_seq_update(self, nid, seq):
        self.cur.execute("UPDATE _peers SET seq = ? WHERE nid = ?", (buffer(nid), seq))

    def on_summary(self, rtype, hid, summary):
        # Check for existing records
        self.cur.execute(
            "SELECT score, data FROM _records "
            "WHERE rtype = ? AND hid = ?", (rtype, buffer(hid)))
        row = self.cur.fetchone()
        # If no existing entry, return true
        if row == None:
            return True
        # Score incoming and new record
        score = record.score_record(rtype, hid, summary)
        # If it's negative, drop
        if score < 0:
            return False
        (cscore, data) = row
        # If new record isn't better, forget it
        if cscore >= score:
            return False
        # If it's a WT record, just update the summary
        if rtype == record.RT_WORKTOKEN:
            self.cur.execute(
                "REPLACE INTO _records " +
                "(rtype, hid, score, data, score) " +
                "VALUES (?, ?, ?, ?, ?)",
            (rtype, buffer(hid), buffer(summary), buffer(data), score))
            return False
        # Otherwise I need the whole data
        return True

    def __new_schema(self):
        (ctype, sjson) = self.get_data(record.RT_SIGNED, SCHEMA_HID)
        if ctype != 'application/json':
            return
        self.schema = schema.Schema(sjson)
        self.schema.install(self.cur)
        for row in self.cur.execute(
            "SELECT hid, summary, data, score FROM _records WHERE rtype = ?",
                (record.RT_WORKTOKEN,)):
            (hid, summary, data, score) = row
            self.schema.insert_record(self.cur, hid, summary, data, score)

    def on_record(self, rtype, hid, summary, data):
        # Validate + Score
        if not record.validate_record(rtype, self.tid, self.verify, hid, summary, data):
            logger.warn("Invalid record, type = %d", rtype)
            return False
        score = record.score_record(rtype, hid, summary)
        # Delete any existing version with lower score
        self.cur.execute(
            "DELETE FROM _records " +
            "WHERE rtype = ? AND hid = ? AND score < ?",
            (rtype, buffer(hid), score))
        if self.cur.rowcount > 0:
            self.cur_size -= 100 + len(data)
            if rtype == record.RT_SIGNED and hid == SCHEMA_HID and self.schema is not None:
                self.schema.uninstall(self.cur)
        # Insert new row if not already there
        self.cur.execute(
            "INSERT OR IGNORE INTO _records " +
            "(rtype, hid, summary, data, score) " +
            "VALUES (?, ?, ?, ?, ?)",
            (rtype, buffer(hid), buffer(summary), buffer(data), score))
        if self.cur.rowcount > 0:
            self.cur_size += 100 + len(data)
            if rtype == record.RT_SIGNED and hid == SCHEMA_HID:
                self.__new_schema()
            if rtype == record.RT_WORKTOKEN and self.schema is not None:
                self.schema.insert_record(self.cur, hid, summary, data, score)
        # Shrink as needed
        self.__shrink()
        # Maybe found a pubkey
        if rtype == record.RT_PUBKEY:
            logger.info("Setting public key")
            self.__set_pubkey(data)
        return True

    def get_summary(self, seq):
        self.cur.execute(
            "SELECT seq, rtype, hid, summary " +
            "FROM _records WHERE seq > ? " +
            "LIMIT 1", (seq,))
        row = self.cur.fetchone()
        if row is None:
            return None, None, None, None
        (rseq, rtype, hid, summary) = row
        return (rseq, rtype, str(hid), str(summary))

    def get_data(self, rtype, hid):
        self.cur.execute("SELECT data FROM _records WHERE rtype = ? AND hid = ?",
            (rtype, buffer(hid)))
        row = self.cur.fetchone()
        if row is None:
            return None, None
        return record.get_record_content(rtype, str(row[0]))

    def get_raw_data(self, rtype, hid):
        self.cur.execute("SELECT data FROM _records WHERE rtype = ? AND hid = ?",
            (rtype, buffer(hid)))
        row = self.cur.fetchone()
        if row is None:
            return None
        return row[0]

    def run_query(self, query, params):
        self.con.commit()
        self.be_safe = True
        try:
            self.cur.execute(query, params)
            results = self.cur.fetchall()
            self.be_safe = False
        except Exception as exc:
            self.be_safe = False
            raise exc
        return results

class TestSyncStore(unittest.TestCase):

    def test_ordered(self):
        # Make a SyncStore that holds 20 objects
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        store = SyncStore(tid, ":memory:", 21 * (len('text/plain') + RECORD_OVERHEAD))
        recs = []
        # Make 30 random entries and insert them
        for i in range(30):
            (hid, summary, data) = record.make_worktoken_record('text/plain', str(i))
            score = record.score_record(record.RT_WORKTOKEN, hid, summary)
            recs.append((score, hid, str(i)))
            store.on_record(record.RT_WORKTOKEN, hid, summary, data)
        # Sort entries by score
        recs.sort(key=lambda x: x[0])
        # Check the the right elements are there
        for i in range(10):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, recs[i][1])[1] == None)
        for i in range(10, 30):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, recs[i][1])[1] == recs[i][2])

    def test_update(self):
        # Make a SyncStore that holds 20 objects
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        store = SyncStore(tid, ":memory:", 21 * (len('text/plain') + RECORD_OVERHEAD))
        recs = []
        # Make 20 random entries and insert them
        for i in range(20):
            (hid, summary, data) = record.make_worktoken_record('text/plain', str(i))
            recs.append((hid, str(i)))
            store.on_record(record.RT_WORKTOKEN, hid, summary, data)
        # 'Increase score' for the first 10 and update WT
        for i in range(10):
            (_, summary) = record.mine_worktoken(recs[i][0], 1000)
            store.on_summary(record.RT_WORKTOKEN, recs[i][0], summary)
        # Now add 10 more 'premined' values
        for i in range(10):
            (hid, summary, data) = record.make_worktoken_record('text/plain', str(20+i))
            (_, summary) = record.mine_worktoken(hid, 1000)
            store.on_record(record.RT_WORKTOKEN, hid, summary, data)
            recs.append((hid, str(20+i)))
        # Check that right elements survived
        for i in range(10):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, recs[i][0])[1] == recs[i][1])
        for i in range(10, 20):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, recs[i][0])[1] is None)
        for i in range(20, 30):
            self.assertTrue(store.get_data(record.RT_WORKTOKEN, recs[i][0])[1] == recs[i][1])

    def test_get_summary(self):
        # Make a SyncStore that holds 20 objects
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        store = SyncStore(tid, ":memory:", 21 * (len('text/plain') + RECORD_OVERHEAD))
        recs = []
        # Make 20 random entries and insert them
        for i in range(20):
            (hid, summary, data) = record.make_worktoken_record('text/plain', str(i))
            recs.append((hid, str(i)))
            store.on_record(record.RT_WORKTOKEN, hid, summary, data)
        # 'Mine' for the first 10 and update WT
        for i in range(10):
            (_, summary) = record.mine_worktoken(recs[i][0], 1000)
            store.on_summary(record.RT_WORKTOKEN, recs[i][0], summary)
        # Check for order of 'events'
        seq = 0
        for i in range(10):
            (seq, rtype, hid, _) = store.get_summary(seq)
            self.assertTrue(rtype == record.RT_WORKTOKEN)
            self.assertTrue(hid == recs[i + 10][0])
        for i in range(10, 20):
            (seq, rtype, hid, _) = store.get_summary(seq)
            self.assertTrue(rtype == record.RT_WORKTOKEN)
            self.assertTrue(hid == recs[i - 10][0])
        self.assertTrue(store.get_summary(seq)[0] is None)

if __name__ == '__main__':
    unittest.main()


