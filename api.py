#!/usr/bin/python

import os
import http
import record
import hashlib 
import simplejson as json
import store
import logging
from Crypto.PublicKey import RSA

logger = logging.getLogger('api')

class Api(object):
    def __init__(self, stores, store_dir):
        self.stores = stores
        self.store_dir = store_dir

    def get(self, nid, key):
        if nid not in self.stores:
            return None
        store = self.stores[nid]
        khash = hashlib.sha256(key).digest()
        (ctype, data) = store.get_data(record.RT_SIGNED, khash)
        if ctype == 'tombstone' and data == 'tombstone':
            return None
        if ctype == None:
            return None
        return (ctype, data)

    def put(self, nid, key, ctype, body):
        if nid not in self.stores:
            return (404, 'Not Found')
        store = self.stores[nid]
        signer = store.signer
        if signer == None:
            return (403, 'Forbidden')
        (hid, summary, data) = record.make_signed_record(signer, key, ctype, body)
        if not store.on_record(record.RT_SIGNED, hid, summary, data):
            raise ValueError('unable to write')
        return (204, 'No Content')

    def delete(self, nid, key):
        if nid not in self.stores:
            return (404, 'Not Found')
        store = self.stores[nid]
        signer = store.get_signer()
        if signer == None:
            return (403, 'Forbidden')
        (hid, summary, data) = record.make_signed_record(signer, key, 'tombstone', 'tombstone')
        store.on_record(record.RT_SIGNED, hid, summary, data)
        return (204, 'No Content')

    def post(self, nid, obj):
        logger.info('Got a post: %s', obj)
        if type(obj) is not dict:
            return { 'success' : False, 'error' : 'API request a json object' }
        if 'action' not in obj:
            return { 'success' : False, 'error' : 'No action specified' }
        action = obj['action']
        if type(action) is not str:
            return { 'success' : False, 'error' : 'Action must be a string' }
        if not hasattr(self, 'do_' + action): 
            return { 'success' : False, 'error' : 'Unknown action' }
        return getattr(self, 'do_' + action)(obj)

    def do_create_app(self, obj):
        if 'max_size' not in obj:
            return { 'success' : False, 'error' : 'create_app requires a storage size' }
        max_size = obj['max_size']
        if type(max_size) is not int:
            return { 'success' : False, 'error' : 'max_size must be an int' }
        if max_size < 0 or max_size > 1*1024*1024*1024:
            return { 'success' : False, 'error' : 'max_size out of range' }
        priv_key = RSA.generate(2048)
        pub_key = priv_key.publickey()
        encoded = pub_key.exportKey('DER')
        hid = hashlib.sha256(encoded).digest()
        tid = hid[0:20]
        store_path = os.path.join(self.store_dir, tid.encode('hex'))
        the_store = store.SyncStore(tid, store_path, max_size)
        the_store.set_priv_key(priv_key)
        self.stores[tid] = the_store 
        return { 'success' : True, 'tid' : tid.encode('hex') }
                
