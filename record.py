
import hashlib
import struct
import time
import math
import random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

RT_PUBKEY = 0
RT_WORKTOKEN = 1
RT_SIGNED = 2
WT_HALFLIFE = 259200.0  # 3 days, measured in seconds

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
    return (hid, '0', body) 

def make_worktoken_record(ctype, data):
    assert len(ctype) < 256
    body = chr(len(ctype)) + ctype + data
    hid = hashlib.sha256(body).digest()
    summary = struct.pack("!LL", int(time.time()), 0)
    return (hid, summary, body)

def make_signed_record(signer, key, ctype, data):
    assert len(ctype) < 256
    hid = hashlib.sha256(key).digest()
    summary = struct.pack("!L", int(time.time()))
    sig_hash = hashlib.sha256()
    sig_hash.update(hid)
    sig_hash.update(summary)
    sig_hash.update(chr(len(ctype)))
    sig_hash.update(ctype)
    sig_hash.update(data)
    signature = signer.sign(sig_hash)
    body = signature + chr(len(ctype)) + ctype + '\n' + data 
    return (hid, summary, body)

def mine_worktoken(hid, count):
    best_score = 0
    best_summary = ''
    wtime = int(time.time())
    for i in range(count):
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
    elif rtype == WT_SIGNED:
        if len(summary) != 4:
            return -1
        (wtime,) = struct.unpack("!L", summary)
        return 1e9 + float(wtime) 
    else:
        return -1

def validate_pubkey(tid, hid, summary, body):
    if tid != hid[0:20]:
        return False
    if summary != '0':
        return False
    if hashlib.sha256(key).digest() != hid:
        return False
    try:
        pubkey = RSA.importKey(body)
    except Exception:
        return False
    if pubkey.has_private():
        return False
    if pubkey.size() != 2047:
        return False
    return True

def validate_worktoken(hid, summary, body):
    if len(body) < 3:
        return False
    ctypelen = ord(body[0])
    if ctypelen < 1:
        return False
    if len(body) < (1 + ctypelen + 1):
        return False
    return hid == hashlib.sha256(body).digest()
    
    
def validate_signed(verify, hid, summary, body):
    if verify is None:
        return False
    if len(body) < 259:
        return False
    ctypelen = ord(body[256])
    if ctypelen < 1:
        return False
    if len(body) < (256 + 1 + ctypelen + 1):
        return False
    summary = struct.pack("!L", int(time.time()))
    sig_hash = hashlib.sha256()
    sig_hash.update(hid)
    sig_hash.update(summary)
    sig_hash.update(body[256:])
    return verify.verify(sig_hash, body[0:256])


def validate_record(rtype, tid, verify, hid, summary, body):
    if rtype == RT_PUBKEY:
        return validate_pubkey(tid, hid, summary, body)
    elif rtype == RT_WORKTOKEN:
        return hid == hashlib.sha256(body).digest()
    elif rtype == WT_SIGNED:
        return validate_signed(verify, hid, summary, body)
    else:
        return False

def get_record_content(rtype, body):
    if rtype == RT_PUBKEY:
        return ('application/octet-stream', body)
    elif rtype == RT_WORKTOKEN:
        ctypelen = ord(body[0])
        return (body[1:1+ctypelen], body[1+ctypelen:])
    elif rtype == WT_SIGNED:
        ctypelen = ord(body[256])
        return (body[257:257+ctypelen], body[257+ctypelen:])
    else:
        raise ValueError('Unknown record type')

