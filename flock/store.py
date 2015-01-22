#!/usr/bin/python
# pylint: disable=missing-docstring
# pylint: disable=bad-continuation

import unittest
import logging
import random
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

from flock import record
from flock import schema
from flock import dbconn

RECORD_OVERHEAD = 100
DEFAULT_APP_SIZE = 100*1024*1024
SCHEMA_HID = hashlib.sha256('_schema').digest()

logger = logging.getLogger('store') # pylint: disable=invalid-name

class SyncStore(object):
    # pylint: disable=too-many-instance-attributes
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
    CREATE UNIQUE INDEX IF NOT EXISTS _records_hid ON _records (rtype, hid);
    CREATE INDEX IF NOT EXISTS _records_score ON _records (score);
    '''

    def __init__(self, tid, dbc, max_size=DEFAULT_APP_SIZE):
        self.tid = tid
        self.dbc = dbc
        self.max_size = max_size
        self.dbc.executescript(SyncStore.internal_sql)
        self.dbc.execute(
            "SELECT ifnull(sum(? + length(data)),0) FROM _records", (RECORD_OVERHEAD,))
        self.db_size = self.dbc.fetchone()[0]
        self.verify = None
        self.dbc.execute("SELECT data FROM _records WHERE rtype = ? LIMIT 1", (record.RT_PUBKEY,))
        row = self.dbc.fetchone()
        if row is not None:
            self.__set_pubkey(row[0])
        self.signer = None
        self.dbc.execute("SELECT data FROM _singletons WHERE key = 'priv_key'")
        row = self.dbc.fetchone()
        if row is not None:
            priv_key = RSA.importKey(row[0], 'DER')
            self.signer = PKCS1_PSS.new(priv_key)
        self.schema = None
        (ctype, sjson) = self.get_data(record.RT_SIGNED, SCHEMA_HID)
        if ctype == 'application/json':
            self.schema = schema.Schema(sjson)

    def __shrink(self):
        # TODO: This needs to remove projected records
        # Also, should split WT + SIGNED max sizes
        while self.db_size > self.max_size:
            self.dbc.execute(
                "SELECT seq, 100 + length(data) FROM _records " +
                "ORDER BY score ASC LIMIT 1")
            (seq, size) = self.dbc.fetchone()
            self.db_size -= size
            self.dbc.execute("DELETE FROM _records WHERE seq = ?", (seq,))

    def __set_pubkey(self, data):
        pub_key = RSA.importKey(data, 'DER')
        self.verify = PKCS1_PSS.new(pub_key)

    def set_priv_key(self, priv_key):
        self.signer = PKCS1_PSS.new(priv_key)
        pub_key = priv_key.publickey()
        self.dbc.execute("INSERT INTO _singletons (key, data) VALUES ('priv_key', ?)",
            (buffer(priv_key.exportKey('PEM')),))
        (hid, summary, body) = record.make_pubkey_record(pub_key)
        self.on_record(record.RT_PUBKEY, hid, summary, body)

    def on_summary(self, rtype, hid, summary):
        # Check for existing records
        self.dbc.execute(
            "SELECT score, data FROM _records "
            "WHERE rtype = ? AND hid = ?", (rtype, buffer(hid)))
        row = self.dbc.fetchone()
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
            self.dbc.execute(
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
        self.schema.install(self.dbc)
        for row in self.dbc.execute(
            "SELECT hid, summary, data, score FROM _records WHERE rtype = ?",
                (record.RT_WORKTOKEN,)):
            (hid, summary, data, score) = row
            self.schema.insert_record(self.dbc, hid, summary, data, score)

    def on_record(self, rtype, hid, summary, data):
        # Validate + Score
        if not record.validate_record(rtype, self.tid, self.verify, hid, summary, data):
            logger.warn("Invalid record, type = %d", rtype)
            return False
        score = record.score_record(rtype, hid, summary)
        # Delete any existing version with lower score
        self.dbc.execute(
            "DELETE FROM _records " +
            "WHERE rtype = ? AND hid = ? AND score < ?",
            (rtype, buffer(hid), score))
        if self.dbc.rowcount > 0:
            self.db_size -= 100 + len(data)
            if rtype == record.RT_SIGNED and hid == SCHEMA_HID and self.schema is not None:
                self.schema.uninstall(self.dbc)
        # Insert new row if not already there
        self.dbc.execute(
            "INSERT OR IGNORE INTO _records " +
            "(rtype, hid, summary, data, score) " +
            "VALUES (?, ?, ?, ?, ?)",
            (rtype, buffer(hid), buffer(summary), buffer(data), score))
        if self.dbc.rowcount > 0:
            self.db_size += 100 + len(data)
            if rtype == record.RT_SIGNED and hid == SCHEMA_HID:
                self.__new_schema()
            if rtype == record.RT_WORKTOKEN and self.schema is not None:
                self.schema.insert_record(self.dbc, hid, summary, data, score)
        # Shrink as needed
        self.__shrink()
        # Maybe found a pubkey
        if rtype == record.RT_PUBKEY:
            logger.info("Setting public key")
            self.__set_pubkey(data)
        return True

    def get_summary(self, seq):
        self.dbc.execute(
            "SELECT seq, rtype, hid, summary " +
            "FROM _records WHERE seq > ? " +
            "LIMIT 1", (seq,))
        row = self.dbc.fetchone()
        if row is None:
            return None, None, None, None
        (rseq, rtype, hid, summary) = row
        return (rseq, rtype, str(hid), str(summary))

    def get_data(self, rtype, hid):
        self.dbc.execute("SELECT data FROM _records WHERE rtype = ? AND hid = ?",
            (rtype, buffer(hid)))
        row = self.dbc.fetchone()
        if row is None:
            return None, None
        return record.get_record_content(rtype, str(row[0]))

    def get_raw_data(self, rtype, hid):
        self.dbc.execute("SELECT data FROM _records WHERE rtype = ? AND hid = ?",
            (rtype, buffer(hid)))
        row = self.dbc.fetchone()
        if row is None:
            return None
        return row[0]

    def run_query(self, query, params):
        self.dbc.commit()
        self.dbc.execute_safe(query, params)
        results = self.dbc.fetchall()
        return results

class TestSyncStore(unittest.TestCase):

    def test_ordered(self):
        # Make a SyncStore that holds 20 objects
        tid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        dbc = dbconn.DbConn(":memory:")
        store = SyncStore(tid, dbc, 21 * (len('text/plain') + RECORD_OVERHEAD))
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
        dbc = dbconn.DbConn(":memory:")
        store = SyncStore(tid, dbc, 21 * (len('text/plain') + RECORD_OVERHEAD))
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
        dbc = dbconn.DbConn(":memory:")
        store = SyncStore(tid, dbc, 21 * (len('text/plain') + RECORD_OVERHEAD))
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


