#!/usr/bin/python
#pylint: disable=missing-docstring

import struct
import hashlib
import math
import unittest
import time
import random

class WorkToken(object):
    halflife = 259200.0  # 3 days, measured in seconds
    overhead = 100
    def __init__(self, hid, wtime=int(time.time()), nonce=random.getrandbits(48)):
        # Makes a work token
        self.hid = hid
        self.time = wtime
        self.nonce = nonce
        self.score = self.compute_score(wtime, nonce)

    def compute_score(self, wtime, nonce):
        packed = struct.pack("!32sQQ", self.hid, wtime, nonce)
        digest1 = hashlib.sha256(packed).digest()
        rev_digest1 = digest1[::-1]
        digest2 = hashlib.sha256("0net" + rev_digest1 + "0net").digest()
        dint = struct.unpack("!L", digest2[0:4])[0]
        hardness = 4294967296.0 / (float(dint) + 1)
        hardness_po2 = math.log(hardness, 2) * WorkToken.halflife
        return float(wtime) + hardness_po2

    def mine(self, count):
        new_time = int(time.time())
        for _ in range(count):
            new_nonce = random.getrandbits(48)
            new_score = self.compute_score(new_time, new_nonce)
            if new_score > self.score:
                self.time = new_time
                self.nonce = new_nonce
                self.score = new_score

class TestWorkToken(unittest.TestCase):
    #pylint: disable=too-few-public-methods
    def test_basic(self):
        # Mine 1000 work tokens with 100 power
        avg_score_1 = 0
        for i in range(1000):
            hid = hashlib.sha256(str(i)).digest()
            wtok = WorkToken(hid)
            wtok.mine(100)
            avg_score_1 += wtok.score
        avg_score_1 /= 1000

        # Mine 1000 work tokens with 200 power
        avg_score_2 = 0
        for i in range(1000):
            wtok = WorkToken(hid)
            wtok.mine(200)
            avg_score_2 += wtok.score
        avg_score_2 /= 1000

        # Make sure the average score difference is about halflife
        diff = avg_score_2 - avg_score_1
        self.assertTrue(abs(diff - WorkToken.halflife) < WorkToken.halflife/3)

if __name__ == '__main__':
    unittest.main()


