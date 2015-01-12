#!/usr/bin/env python
# pylint: disable=missing-docstring
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-arguments

import hashlib
import struct
import time
import math
import random
import logging
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

RT_PUBKEY = 0
RT_WORKTOKEN = 1
RT_SIGNED = 2
WT_HALFLIFE = 259200.0  # 3 days, measured in seconds

logger = logging.getLogger('record') # pylint: disable=invalid-name

SEQ_NUM = 0

def worktoken_shared(flat, wtime):
    digest1 = hashlib.sha256(flat).digest()
    rev_digest1 = digest1[::-1]
    digest2 = hashlib.sha256("flock" + rev_digest1 + "flock").digest()
    dint = struct.unpack("!L", digest2[0:4])[0]
    hardness = 4294967296.0 / (float(dint) + 1)
    hardness_po2 = math.log(hardness, 2) * WT_HALFLIFE
    return float(wtime) + hardness_po2

def make_pubkey_record(pubkey):
    encoded = pubkey.exportKey('DER')
    hid = hashlib.sha256(encoded).digest()
    return (hid, '0', encoded)

def make_worktoken_record(ctype, data):
    assert len(ctype) < 256
    body = chr(len(ctype)) + ctype + data
    hid = hashlib.sha256(body).digest()
    summary = struct.pack("!LL", int(time.time()) - 2, 0)
    return (hid, summary, body)

def make_signed_record(signer, key, ctype, data):
    global SEQ_NUM # pylint: disable=global-statement
    assert len(ctype) < 256
    hid = hashlib.sha256(key).digest()
    summary = struct.pack("!LL", int(time.time()) - 2, SEQ_NUM)
    # Use of a global sequence number is a hack, but it's
    # a simple work-around for multiple updates to signed records in
    # a single second
    SEQ_NUM += 1
    # Need to use pycrypto's hashes for signatures
    sig_hash = SHA256.new()
    sig_hash.update(hid)
    sig_hash.update(summary)
    sig_hash.update(chr(len(ctype)))
    sig_hash.update(ctype)
    sig_hash.update(data)
    logger.debug("Signing data: %s", sig_hash.digest().encode('hex'))
    signature = signer.sign(sig_hash)
    body = signature + chr(len(ctype)) + ctype + data
    return (hid, summary, body)

def mine_worktoken(hid, count):
    best_score = 0
    best_summary = ''
    wtime = int(time.time())
    for _ in range(count):
        nonce = random.randint(0, 0xffffffff)
        summary = struct.pack("!LL", wtime, nonce)
        score = worktoken_shared(hid + summary, wtime)
        if score > best_score:
            best_score = score
            best_summary = summary
    return (best_score, best_summary)

def score_record(rtype, hid, summary):
    if rtype == RT_PUBKEY:
        if summary != '0':
            return -1
        return 2e9
    elif rtype == RT_WORKTOKEN:
        if len(summary) != 8:
            return -1
        (wtime, _) = struct.unpack("!LL", summary)
        return worktoken_shared(hid + summary, wtime)
    elif rtype == RT_SIGNED:
        if len(summary) != 8:
            return -1
        (wtime, _) = struct.unpack("!LL", summary)
        return 1e9 + float(wtime)
    else:
        return -1

def validate_pubkey(tid, hid, summary, body):
    if tid != hid[0:20]:
        logger.warning('pubkey doesnt match tid')
        return False
    if summary != '0':
        logger.warning('Summary is not 0')
        return False
    if hashlib.sha256(body).digest() != hid:
        logger.warning('pubkey failed digest check')
        return False
    try:
        pubkey = RSA.importKey(body)
    except Exception: # pylint: disable=broad-except
        logger.warning('pubkey not RSA key')
        return False
    if pubkey.has_private():
        logger.warning('pubkey is a private key')
        return False
    if pubkey.size() != 2047:
        logger.warning('pubkey is not 2048 bits')
        return False
    return True

def validate_worktoken(hid, summary, body):
    if len(summary) != 8:
        logger.warning('Worktoken summary size is wrong')
        return False
    (wtime, _) = struct.unpack("!LL", summary)
    if wtime > int(time.time()):
        logger.warning('Worktoken time in the future')
        return False
    if len(body) < 3:
        logger.warning('Worktoken body too small')
        return False
    ctypelen = ord(body[0])
    if ctypelen < 1:
        logger.warning('Worktoken ctype too small')
        return False
    if len(body) < (1 + ctypelen + 1):
        logger.warning('Worktoken body too small (2)')
        return False
    return hid == hashlib.sha256(body).digest()

def validate_signed(verify, hid, summary, body):
    if len(summary) != 8:
        logger.warning('Signed summary size is wrong')
        return False
    (wtime, _) = struct.unpack("!LL", summary)
    if wtime > int(time.time()):
        logger.warning('Signed time in the future')
        return False
    if verify is None:
        logger.warning('Signed no key to verify')
        return False
    if len(body) < 259:
        logger.warning('Signed body too small')
        return False
    ctypelen = ord(body[256])
    if ctypelen < 1:
        logger.warning('Signed ctype too small')
        return False
    if len(body) < (256 + 1 + ctypelen + 1):
        logger.warning('Signed body too small (2)')
        return False
    sig_hash = SHA256.new()
    sig_hash.update(hid)
    sig_hash.update(summary)
    sig_hash.update(body[256:])
    logger.debug("Verifying data: %s", sig_hash.digest().encode('hex'))
    if not verify.verify(sig_hash, body[0:256]):
        logger.warning('Signed record, signature failure')
        return False
    return True

def validate_record(rtype, tid, verify, hid, summary, body):
    if rtype == RT_PUBKEY:
        return validate_pubkey(tid, hid, summary, body)
    elif rtype == RT_WORKTOKEN:
        return hid == hashlib.sha256(body).digest()
    elif rtype == RT_SIGNED:
        return validate_signed(verify, hid, summary, body)
    else:
        return False

def get_record_content(rtype, body):
    if rtype == RT_PUBKEY:
        return ('application/octet-stream', body)
    elif rtype == RT_WORKTOKEN:
        ctypelen = ord(body[0])
        return (body[1:1+ctypelen], body[1+ctypelen:])
    elif rtype == RT_SIGNED:
        ctypelen = ord(body[256])
        return (body[257:257+ctypelen], body[257+ctypelen:])
    else:
        raise ValueError('Unknown record type')

