#!/usr/bin/env python
#pylint: disable=missing-docstring
#pylint: disable=bad-continuation
#pylint: disable=too-many-instance-attributes

import os
import logging
import hashlib
import random
from Crypto.PublicKey import RSA

import dht
import nat
import async
import sync
import store
import http
import api

class Node(object):
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

    def __load_stores(self):
        self.stores = {}
        for bname in os.listdir(self.store_dir):
            if len(bname) != 40:
                continue
            try:
                tid = bname.decode('hex')
            except Exception: # pylint: disable=broad-except
                continue
            # TODO: Max size?
            nstore = store.SyncStore(tid, os.path.join(self.store_dir, bname), 1*1024*1024)
            self.stores[tid] = nstore

    def __setup_dht(self, dht_cfg):
        # Create DHT object
        self.dht = dht.Dht(self.asm, self.nid, dht_cfg)

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
        for tid, _ in self.stores.iteritems():
            self.dht.add_location(tid, self.net_conn.ext_port,
                lambda addr, tid=tid: self.__on_peer(tid, addr))

    def __init__(self, store_dir, net_cfg, dht_cfg, http_cfg):
        # Create/find path
        self.store_dir = store_dir
        if not os.path.exists(self.store_dir):
            os.makedirs(self.store_dir)

        # Load nid + stores
        self.__load_nid()
        self.__load_stores()

        # Nat punch out
        self.net_conn = nat.autodetect_config(net_cfg)
        if self.net_conn is None:
            logging.error("Unable to find internet connection, bailing")
            # TODO: Is this really the right exception
            raise RuntimeError("Unable to find internet")

        # Setup remaining systems
        self.asm = async.AsyncMgr()
        self.__setup_dht(dht_cfg)
        self.sync = sync.SyncPeer(self.asm, self.nid, self.stores, self.net_conn.sock)
        self.api = api.Api(self)
        self.server = http.HttpServer(self.asm, self.api, http_cfg)

    def __on_peer(self, tid, addr):
        if addr[0] == self.net_conn.ext_ip and addr[1] == self.net_conn.ext_port:
            # Ignore self connections
            return
        self.sync.add_peer(tid, addr)

    def create_app(self, max_size):
        priv_key = RSA.generate(2048)
        pub_key = priv_key.publickey()
        encoded = pub_key.exportKey('DER')
        hid = hashlib.sha256(encoded).digest()
        tid = hid[0:20]
        store_path = os.path.join(self.store_dir, tid.encode('hex'))
        the_store = store.SyncStore(tid, store_path, max_size)
        the_store.set_priv_key(priv_key)
        self.stores[tid] = the_store
        self.dht.add_location(tid, self.net_conn.ext_port,
            lambda addr: self.__on_peer(tid, addr))
        return tid

    def run(self):
        self.asm.run()

