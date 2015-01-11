#!/usr/bin/env python
# pylint: disable=missing-docstring
# pylint: disable=too-many-return-statements

import record
import hashlib
import logging

logger = logging.getLogger('api') # pylint: disable=invalid-name

class Api(object):
    def __init__(self, node):
        self.node = node

    def get(self, nid, key):
        if nid not in self.node.stores:
            return None
        the_store = self.node.stores[nid]
        khash = hashlib.sha256(key).digest()
        (ctype, data) = the_store.get_data(record.RT_SIGNED, khash)
        if ctype == 'tombstone' and data == 'tombstone':
            return None
        if ctype == None:
            return None
        return (ctype, data)

    def put(self, nid, key, ctype, body):
        if nid not in self.node.stores:
            return (404, 'Not Found')
        the_store = self.node.stores[nid]
        signer = the_store.signer
        if signer == None:
            return (403, 'Forbidden')
        (hid, summary, data) = record.make_signed_record(signer, key, ctype, body)
        if not the_store.on_record(record.RT_SIGNED, hid, summary, data):
            raise ValueError('unable to write')
        return (204, 'No Content')

    def delete(self, nid, key):
        self.put(nid, key, 'tombstone', 'tombstone')

    def post(self, nid, obj):
        logger.info('Got a post: %s', obj)
        if type(obj) is not dict:
            return {'success' : False, 'error' : 'API request a json object'}
        if 'action' not in obj:
            return {'success' : False, 'error' : 'No action specified'}
        action = obj['action']
        if type(action) is not str:
            return {'success' : False, 'error' : 'Action must be a string'}
        if not hasattr(self, 'do_' + action):
            return {'success' : False, 'error' : 'Unknown action'}
        return getattr(self, 'do_' + action)(nid, obj)

    def do_create_app(self, nid, obj):
        if nid is not None:
            return {'success' : False, 'error' : 'create_app on nid not allowed'}
        if 'max_size' not in obj:
            return {'success' : False, 'error' : 'create_app requires a storage size'}
        max_size = obj['max_size']
        if type(max_size) is not int:
            return {'success' : False, 'error' : 'max_size must be an int'}
        if max_size < 0 or max_size > 1*1024*1024*1024:
            return {'success' : False, 'error' : 'max_size out of range'}
        tid = self.node.create_add(max_size)
        return {'success' : True, 'tid' : tid.encode('hex')}

    def do_join_app(self, nid, obj):
        if nid is not None:
            return {'success' : False, 'error' : 'join_app on nid not allowed'}
        if 'max_size' not in obj:
            return {'success' : False, 'error' : 'join_app requires a storage size'}
        max_size = obj['max_size']
        if type(max_size) is not int:
            return {'success' : False, 'error' : 'max_size must be an int'}
        if max_size < 0 or max_size > 1*1024*1024*1024:
            return {'success' : False, 'error' : 'max_size out of range'}
        if 'tid' not in obj:
            return {'success' : False, 'error' : 'join_app requires a tid'}
        tid = obj['tid']
        try:
            tid = tid.decode('hex')
        except TypeError:
            return {'success' : False, 'error' : 'join_app, unable to parse tid'}
        self.node.join_app(tid, max_size)
        return {'success' : True, 'tid' : tid.encode('hex')}

