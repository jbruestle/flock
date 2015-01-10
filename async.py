#!/usr/bin/python
#pylint: disable=missing-docstring

import time
import asyncore
import asynchat
import bintrees
import multiprocessing
import collections
import struct
import logging
import sys
import traceback

logger = logging.getLogger('async')

class AsyncMgr(object):
    def __init__(self):
        self.async_map = {}
        self.timers = bintrees.RBTree()
        self.next_id = 0
        self.running = False

    def add_timer(self, when, callback):
        key = (when, self.next_id)
        self.next_id += 1
        self.timers[key] = callback
        return key

    def cancel(self, key):
        assert key in self.timers
        del self.timers[key]

    def step(self):
        now = time.time()
        while len(self.timers) > 0 and self.timers.min_key()[0] <= now:
            (_, callback) = self.timers.pop_min()
            callback()
        wait = 60
        if len(self.timers) > 0:
            wait = min(wait, self.timers.min_key()[0] - now)
        asyncore.loop(timeout=wait, map=self.async_map, count=1)

    def run(self, max_time=None):
        self.running = True
        if max_time is not None:
            self.add_timer(time.time() + max_time, self.__stop)
        while self.running:
            self.step()

    def __stop(self):
        self.running = False

class Connection(asynchat.async_chat):
    def __init__(self, sock, map=None):
        asynchat.async_chat.__init__(self, sock=sock, map=map)
        self.__term_callback = None
        self.__ibuffer = []
        self.__fmt = None

    def handle_error(self):
        logger.warning("%s: got error: %s", id(self), sys.exc_info()[1])
        logger.warning("%s", traceback.format_exc())
        self.close()

    def handle_close(self):
        logger.info("%s: Got a close", id(self))
        self.close()

    def collect_incoming_data(self, data):
        self.__ibuffer.append(data)

    def found_terminator(self):
        #pylint: disable=star-args
        if self.__fmt is None:
            self.__term_callback("".join(self.__ibuffer))
        else:
            params = struct.unpack(self.__fmt, "".join(self.__ibuffer))
            self.__term_callback(*params)

    def send_buffer(self, buf):
        self.push(buf)

    def send_struct(self, fmt, *t):
        buf = struct.pack(fmt, *t)
        self.push(buf)

    def recv_buffer(self, size, callback):
        self.__ibuffer = []
        self.__fmt = None
        self.__term_callback = callback
        self.set_terminator(size)

    def recv_struct(self, fmt, callback):
        self.__ibuffer = []
        self.__fmt = fmt
        self.__term_callback = callback
        self.set_terminator(struct.calcsize(fmt))

    def recv_until(self, term, callback):
        self.__ibuffer = []
        self.__fmt = None
        self.__term_callback = callback
        self.set_terminator(term)

