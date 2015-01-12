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

    def get(self, tid, key):
        logger.info('Got a GET: tid = %s, key = %s', tid.encode('hex'), key)
        if tid not in self.node.stores:
            return None
        the_store = self.node.stores[tid]
        khash = hashlib.sha256(key).digest()
        (ctype, data) = the_store.get_data(record.RT_SIGNED, khash)
        if ctype == 'tombstone' and data == 'tombstone':
            return None
        if ctype == None:
            return None
        return (ctype, data)

    def put(self, tid, key, ctype, body):
        logger.info('Got a PUT: tid = %s, key = %s', tid.encode('hex'), key)
        if tid not in self.node.stores:
            return (404, 'Not Found')
        the_store = self.node.stores[tid]
        signer = the_store.signer
        if signer == None:
            return (403, 'Forbidden')
        (hid, summary, data) = record.make_signed_record(signer, key, ctype, body)
        if not the_store.on_record(record.RT_SIGNED, hid, summary, data):
            raise ValueError('unable to write')
        return (204, 'No Content')

    def delete(self, tid, key):
        logger.info('Got a DELETE: tid = %s, key = %s', tid.encode('hex'), key)
        self.put(tid, key, 'tombstone', 'tombstone')

    def post(self, tid, obj):
        logger.info('Got a POST: %s', obj)
        if type(obj) is not dict:
            return {'success' : False, 'error' : 'API request a json object'}
        if 'action' not in obj:
            return {'success' : False, 'error' : 'No action specified'}
        action = obj['action']
        if type(action) is not str:
            return {'success' : False, 'error' : 'Action must be a string'}
        if not hasattr(self, 'do_' + action):
            return {'success' : False, 'error' : 'Unknown action'}
        return getattr(self, 'do_' + action)(tid, obj)

    def do_create_app(self, tid, obj):
        if tid is not None:
            return {'success' : False, 'error' : 'create_app on tid not allowed'}
        if 'max_size' not in obj:
            return {'success' : False, 'error' : 'create_app requires a storage size'}
        max_size = obj['max_size']
        if type(max_size) is not int:
            return {'success' : False, 'error' : 'max_size must be an int'}
        if max_size < 0 or max_size > 1*1024*1024*1024:
            return {'success' : False, 'error' : 'max_size out of range'}
        tid = self.node.create_app(max_size)
        return {'success' : True, 'tid' : tid.encode('hex')}

    def do_join_app(self, tid, obj):
        if tid is not None:
            return {'success' : False, 'error' : 'join_app on tid not allowed'}
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

    def do_add_peer(self, tid, obj):
        if tid is None:
            return {'success' : False, 'error' : 'add_peer requires a tid'}
        if 'addr' not in obj:
            return {'success' : False, 'error' : 'add_peer requires a remote address'}
        if 'port' not in obj:
            return {'success' : False, 'error' : 'add_peer requires a port'}
        if type(obj['addr']) is not str:
            return {'success' : False, 'error' : 'add_peer remote address must be a string'}
        if type(obj['port']) is not int:
            return {'success' : False, 'error' : 'add_peer port must be an integer'}
        self.node.on_peer(tid, (obj['addr'], obj['port']))
        return {'success' : True}


