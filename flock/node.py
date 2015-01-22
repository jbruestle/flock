#!/usr/bin/env python
#pylint: disable=missing-docstring
#pylint: disable=bad-continuation
#pylint: disable=too-many-instance-attributes

import os
import asyncore
import logging
import hashlib
import random
from Crypto.PublicKey import RSA

# For unit tests
import unittest
import tempfile
import httplib
import shutil
import threading
import simplejson as json
import time

from flock import dbconn
from flock import dht
from flock import nat
from flock import async
from flock import http
from flock import api
from flock import syncgroup

logger = logging.getLogger('http') # pylint: disable=invalid-name

class Node(asyncore.dispatcher):
    def __load_nid(self):
        # Create/load nid
        nid_file = os.path.join(self.store_dir, 'nid')
        if not os.path.exists(nid_file):
            nid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
            with open(nid_file, 'w') as nfile:
                nfile.write(nid)
        with open(nid_file, 'r') as nfile:
            self.nid = nfile.read()
        if len(self.nid) != 20:
            raise ValueError('Invalid nid')

    def __load_syncgroups(self):
        self.syncgroups = {}
        for bname in os.listdir(self.store_dir):
            if len(bname) != 40:
                continue
            try:
                tid = bname.decode('hex')
            except Exception: # pylint: disable=broad-except
                continue
            dbc = dbconn.DbConn(os.path.join(self.store_dir, bname))
            self.syncgroups[tid] = syncgroup.SyncGroup(self.asm, tid, self.nid, dbc)

    def __setup_dht(self):
        # Create DHT object
        self.dht = dht.Dht(self.asm, self.nid, self.cfg)

        # Bootstrap DHT
        bootstrap = [
            ("dht.transmissionbt.com", 6881),
            ("router.bittorrent.com", 6881),
            ("cz.magnets.im", 6881),
            ("de.magnets.im", 6881),
        ]
        for addr in bootstrap:
            self.dht.bootstrap_node(addr)

        # Make a DHT location for each store
        for tid, _ in self.syncgroups.iteritems():
            self.dht.add_location(tid, self.net_conn.ext_port,
                lambda addr, tid=tid: self.on_peer(tid, addr))

    def __init__(self, store_dir, cfg):
        # Create/find path
        self.store_dir = store_dir
        self.cfg = cfg
        if not os.path.exists(self.store_dir):
            os.makedirs(self.store_dir)

        # Make asm
        self.asm = async.AsyncMgr()

        # Load nid + syncgroups
        self.__load_nid()
        self.__load_syncgroups()

        # Nat punch out
        self.net_conn = nat.setup_network(self.cfg)
        if self.net_conn is None:
            logging.error("Unable to find internet connection, bailing")
            # TODO: Is this really the right exception
            raise RuntimeError("Unable to find internet")

        # Attach natted connection to myself
        asyncore.dispatcher.__init__(self, sock=self.net_conn.sock, map=self.asm.async_map)
        self.listen(5)

        # Setup DHT is needed
        if self.cfg.get('use_dht', True):
            self.__setup_dht()
        else:
            self.dht = None

        # Setup API goo
        self.api = api.Api(self)
        self.http = http.HttpServer(self.asm, self.api, self.cfg)

        # Kick off self timer
        self.on_timer()

    def on_timer(self):
        self.asm.add_timer(time.time() + 1, self.on_timer)
        for _, group in self.syncgroups.iteritems():
            group.dbc.commit()
            group.on_timer()

    def poke(self, tid):
        self.syncgroups[tid].poke()

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            return
        (sock, addr) = pair # pylint: disable=unpacking-non-sequence
        logger.debug("Incoming node connection, addr = %s", addr)
        syncgroup.IncomingSync(self.asm, sock, self.tid_to_group)
    
    def tid_to_group(self, tid):
        if tid not in self.syncgroups:
            raise ValueError("Incoming conneciton, unknown sync group")
        return self.syncgroups[tid]

    def on_peer(self, tid, addr):
        if addr[0] == self.net_conn.ext_ip and addr[1] == self.net_conn.ext_port:
            # Ignore self connections
            return
        if tid not in self.syncgroups:
            # Ignore stuff I don't care about
            return
        self.syncgroups[tid].add_peer(addr)

    def get_store(self, tid):
        if tid not in self.syncgroups:
            return None
        return self.syncgroups[tid].store

    def create_app(self):
        priv_key = RSA.generate(2048)
        pub_key = priv_key.publickey()
        encoded = pub_key.exportKey('DER')
        hid = hashlib.sha256(encoded).digest()
        tid = hid[0:20]
        store_path = os.path.join(self.store_dir, tid.encode('hex'))
        dbc = dbconn.DbConn(store_path)
        self.syncgroups[tid] = syncgroup.SyncGroup(self.asm, tid, self.nid, dbc)
        self.syncgroups[tid].store.set_priv_key(priv_key)
        if self.dht is not None:
            self.dht.add_location(tid, self.net_conn.ext_port,
                lambda addr: self.on_peer(tid, addr))
        return tid

    def join_app(self, tid):
        store_path = os.path.join(self.store_dir, tid.encode('hex'))
        dbc = dbconn.DbConn(store_path)
        self.syncgroups[tid] = syncgroup.SyncGroup(self.asm, tid, self.nid, dbc)
        if self.dht is not None:
            self.dht.add_location(tid, self.net_conn.ext_port,
                lambda addr: self.on_peer(tid, addr))

    def run(self):
        self.asm.run()

class TestNodes(unittest.TestCase):
    def setUp(self):
        logger.debug("Doing test setup")
        self.cur_port = 30000
        self.next_node = 1
        self.nodes = []
        self.threads = []
        self.store_dir = tempfile.mkdtemp()

    def tearDown(self):
        logger.debug("Shutting down")
        for node in self.nodes:
            node.asm.stop()
        for thread in self.threads:
            thread.join()
        logger.debug("Threads stopped")
        shutil.rmtree(self.store_dir)

    def __next_port(self):
        result = self.cur_port
        self.cur_port += 1
        return result

    def setup_node(self):
        cfg = {}
        cfg['sync_local'] = True
        cfg['use_dht'] = False
        cfg['sync_port'] = self.__next_port()
        cfg['http_port'] = self.__next_port()
        store_dir = os.path.join(self.store_dir, str(self.next_node))
        self.next_node += 1
        node = Node(store_dir, cfg)
        thread = threading.Thread(target=node.run)
        thread.daemon = True
        thread.start()
        self.nodes.append(node)
        self.threads.append(thread)
        return node

    def send_post(self, node, loc, obj):
        _ = self
        conn = httplib.HTTPConnection("localhost:" + str(node.http.port))
        headers = {"Content-type": "application/json"}
        body = json.dumps(obj)
        conn.request("POST", loc, body, headers)
        response = conn.getresponse()
        if response.status != 200:
            conn.close()
            logger.warn("Got non 200 response to post: %d %s", response.status, response.reason)
            return None
        body = response.read()
        conn.close()
        return json.loads(body)

    def send_put(self, node, tid, key, value):
        _ = self
        conn = httplib.HTTPConnection("localhost:" + str(node.http.port))
        headers = {"Content-type": "application/json"}
        conn.request("PUT", '/' + tid + '/' + key, value, headers)
        response = conn.getresponse()
        _ = response.read()
        conn.close()
        return response.status

    def send_get(self, node, tid, key):
        _ = self
        conn = httplib.HTTPConnection("localhost:" + str(node.http.port))
        conn.request("GET", '/' + tid + '/' + key)
        response = conn.getresponse()
        value = response.read()
        conn.close()
        if response.status != 200:
            return None
        return value

    def connect(self, tid, node1, node2):
        _ = self
        port = node2.net_conn.int_port
        result = self.send_post(node1, '/' + tid + '/add_peer',
            {'addr' : '127.0.0.1', 'port' : port})
        if not result['success']:
            raise Exception("Failed to issue add_peer")

    def test_create_store(self):
        test_schema1 = json.dumps({
            "schema": {
                "test_table": {
                    "foo" : "int",
                }
            },
            "indexes": [
                ["test_table", "foo"]
            ]
        })
        test_schema2 = json.dumps({
            "schema": {
                "test_table": {
                    "foo" : "int",
                    "bar" : "text"
                }
            },
            "indexes": [
                ["test_table", "bar"]
            ]
        })
        json_record1 = {
            "_table" : "test_table",
            "foo" : 10,
            "bar" : "hello"
        }
        json_record2 = {
            "_table" : "test_table",
            "foo" : 20,
            "bar" : "world"
        }

        node1 = self.setup_node()
        node2 = self.setup_node()
        time.sleep(1)
        resp = self.send_post(node1, "/create_app", {'max_size' : 100000})
        self.assertTrue(resp['success'])
        logger.debug("Got resp: %s", resp)
        tid = resp['tid']
        status = self.send_put(node1, tid, 'foo', 'Hello')
        self.assertTrue(status == 204)
        status = self.send_put(node1, tid, '_schema', test_schema1)
        self.assertTrue(status == 204)
        resp = self.send_post(node1, "/" + tid + "/add_record", json_record1)
        self.assertTrue(resp['success'])
        resp = self.send_post(node2, "/" + tid + "/join_app", {'max_size' : 100000})
        self.assertTrue(resp['success'])
        self.connect(tid, node1, node2)
        self.connect(tid, node2, node1)
        time.sleep(5)
        val = self.send_get(node2, tid, 'foo')
        self.assertTrue(val == 'Hello')
        resp = self.send_post(node2, "/" + tid + "/query", {
            "query" : "SELECT id, foo FROM test_table"
        })
        self.assertTrue(resp['results'][0][1] == 10)
        status = self.send_put(node1, tid, '_schema', test_schema2)
        self.assertTrue(status == 204)
        status = self.send_put(node1, tid, 'bar', 'World')
        self.assertTrue(status == 204)
        resp = self.send_post(node1, "/" + tid + "/add_record", json_record2)
        self.assertTrue(resp['success'])
        time.sleep(5)
        val = self.send_get(node2, tid, 'bar')
        self.assertTrue(val == 'World')
        resp = self.send_post(node2, "/" + tid + "/query", {
            "query" : "SELECT bar FROM test_table WHERE foo = ?",
            "params" : [20]
        })
        logger.debug("Send resp: %s", resp)
        self.assertTrue(resp['results'][0][0] == 'world')


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()

