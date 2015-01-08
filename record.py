
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

RT_PUBKEY = 0
RT_WORKTOKEN = 1
RT_SIGNED = 2

def worktoken_shared(flat, wtime):
    digest1 = hashlib.sha256(flat).digest()
    rev_digest1 = digest1[::-1]
    digest2 = hashlib.sha256("0net" + rev_digest1 + "0net").digest()
    dint = struct.unpack("!L", digest2[0:4])[0]
    hardness = 4294967296.0 / (float(dint) + 1)
    hardness_po2 = math.log(hardness, 2) * WorkToken.halflife
    return float(wtime) + hardness_po2

def make_pubkey_record(pubkey):
    body = pubkey.exportKey('DER')
    hid = hashlib.sha256(encoded).digest()
    return (hid, '0', body) 

def make_worktoken_record(ctype, data):
    body = ctype + '\n' + body
    hid = hashlib.sha256(body).digest()
    summary = struct.pack("!LL", int(time.time()), 0)
    return (hid, summary, body)

def make_signed_record(signer, key, ctype, data):
    hid = hashlib.sha256(key).digest()
    summary = struct.pack("!L", int(time.time()))
    sig_hash = hashlib.sha256()
    sig_hash.update(hid)
    sig_hash.update(summary)
    sig_hash.update(ctype + '\n')
    sig_hash.update(data)
    signature = signer.sign(sig_hash)
    body = signature + ctype + '\n' + data 
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
        return 2e9
    elif rtype == RT_WORKTOKEN:
        (wtime, _) = struct.unpack("!LL", summary)
        return worktoken_shared(hid + summary, wtime)
    elif rtype == WT_SIGNED:
        (wtime,) = struct.unpack("!L", summary)
        return 1e9 + float(wtime) 
    else:
        raise ValueError('Unknown record type')

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

def validate_signed(verify, hid, summary, body):
    if len(body) < 256:
        return False
    #TODO: Verify mimetype goo is proper?
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
        #TODO: Verify mimetype goo is proper?
        return hid == hashlib.sha256(data).digest()
    elif rtype == WT_SIGNED:
        return validate_signed(verify, hid, summary, body)
    else:
        return False

def get_record_content(rtype, body):
    if rtype == RT_PUBKEY:
        return ('application/octet-stream', body)
    elif rtype == RT_WORKTOKEN:
        return body.split('\n',1)
    elif rtype == WT_SIGNED:
        return body[256:].split('\n',1)
    else:
        raise ValueError('Unknown record type')

