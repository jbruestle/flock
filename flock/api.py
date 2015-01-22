#!/usr/bin/env python
# pylint: disable=missing-docstring

import hashlib
import logging

import simplejson as json

from flock.http import HttpException
from flock import record
from flock import store

logger = logging.getLogger('api') # pylint: disable=invalid-name

class Api(object):
    def __init__(self, node):
        self.node = node

    def get(self, tid, key):
        logger.info('Got a GET: tid = %s, key = %s', tid.encode('hex'), key)
        the_store = self.node.get_store(tid)
        if the_store is None:
            raise HttpException(404, "Not Found")
        khash = hashlib.sha256(key).digest()
        (ctype, data) = the_store.get_data(record.RT_SIGNED, khash)
        if ctype == 'tombstone' and data == 'tombstone':
            raise HttpException(404, "Not Found")
        if ctype == None:
            raise HttpException(404, "Not Found")
        return (ctype, data)

    def put(self, tid, key, ctype, body):
        logger.info('Got a PUT: tid = %s, key = %s', tid.encode('hex'), key)
        the_store = self.node.get_store(tid)
        if the_store is None:
            raise HttpException(404, "Not Found")
        signer = the_store.signer
        if signer == None:
            raise HttpException(403, "Forbidden")
        (hid, summary, data) = record.make_signed_record(signer, key, ctype, body)
        if not the_store.on_record(record.RT_SIGNED, hid, summary, data):
            raise HttpException(500, "Unable to write record")
        self.node.poke(tid)

    def delete(self, tid, key):
        logger.info('Got a DELETE: tid = %s, key = %s', tid.encode('hex'), key)
        self.put(tid, key, 'tombstone', 'tombstone')
        self.node.poke(tid)

    def __optional(self, obj, field, default):
        _ = self
        if field not in obj:
            return default
        return obj[field]

    def __require(self, obj, field):
        _ = self
        if field not in obj:
            raise HttpException(400, "Action requires field: " + field)
        return obj[field]

    def __require_int(self, obj, field):
        val = self.__require(obj, field)
        if type(val) is not int:
            raise HttpException(400, "Field " + field + " not an integer")
        return val

    def __optional_int(self, obj, field, default):
        val = self.__optional(obj, field, default)
        if type(val) is not int:
            raise HttpException(400, "Field " + field + " not an integer")
        return val

    def __require_str(self, obj, field):
        val = self.__require(obj, field)
        if type(val) is not str:
            raise HttpException(400, "Field " + field + " not a string")
        return val

    def post(self, tid, action, obj):
        logger.info('Got a POST: action=%s, obj=%s', action, obj)
        if type(obj) is not dict:
            raise HttpException(400, "API request requires a json object")
        if hasattr(self, 'gact_' + action):
            if tid is not None:
                raise HttpException(400, "This action is global, no tid allowed")
            return getattr(self, 'gact_' + action)(obj)
        if hasattr(self, 'tact_' + action):
            if tid is None:
                raise HttpException(400, "This action is local, tid required")
            return getattr(self, 'tact_' + action)(tid, obj)
        raise HttpException(400, "Unknown action")

    def gact_create_app(self, obj):
        logger.info('create_app')
        tid = self.node.create_app()
        return {'success' : True, 'tid' : tid.encode('hex')}

    def tact_join_app(self, tid, obj):
        logger.info('join_app: tid = %s', tid.encode('hex'))
        self.node.join_app(tid)
        return {'success' : True}

    def tact_add_peer(self, tid, obj):
        addr = self.__require_str(obj, 'addr')
        port = self.__require_int(obj, 'port')
        logger.info('add_peer: tid = %s, addr = %s', tid.encode('hex'), (addr, port))
        self.node.on_peer(tid, (addr, port))
        return {'success' : True}

    def tact_add_record(self, tid, obj):
        logger.info('Got a add_record: tid = %s, val= %s', tid.encode('hex'), obj)
        the_store = self.node.get_store(tid)
        if the_store is None:
            raise HttpException(404, "Not Found")
        (hid, _, body) = record.make_worktoken_record('application/json', json.dumps(obj))
        (_, summary) = record.mine_worktoken(hid, 1000)
        the_store.on_record(record.RT_WORKTOKEN, hid, summary, body)
        self.node.poke(tid)
        return {'success' : True, 'id' : hid.encode('base64')[:-1]}

    def tact_query(self, tid, obj):
        logger.info('Got a query: tid = %s, val= %s', tid.encode('hex'), obj)
        the_store = self.node.get_store(tid)
        if the_store is None:
            raise HttpException(404, "Not Found")
        query = self.__require_str(obj, 'query')
        params = []
        if 'params' in obj:
            params = obj['params']
        results = the_store.run_query(query, params)
        return {'success' : True, 'results' : results}

