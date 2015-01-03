#!/usr/bin/python
#pylint: disable=missing-docstring

import time
import asyncore
import bintrees

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

