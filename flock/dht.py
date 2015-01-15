#!/usr/bin/env python
# pylint: disable=missing-docstring
# pylint: disable=bad-continuation

import asyncore
import bencode
import struct
import socket
import errno
import time
import random
import bintrees
import collections
import logging

from flock import async

logger = logging.getLogger('dht') # pylint: disable=invalid-name

REQUEST_TIMEOUT = 3
GOOD_NODES = 8
POTENTIAL_NODES = 20
LOC_PEERS = 1000
GOOD_RETRY_MIN = 10*60
GOOD_RETRY_SLOP = 5*60
SEND_RATE = .05

class DhtRpc(asyncore.dispatcher):
    def __init__(self, dht, asm, port=6881):
        asyncore.dispatcher.__init__(self, map=asm.async_map)
        self.dht = dht
        self.asm = asm
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(('', port))
        self.tid = 0
        self.pending = {}
        self.handlers = {}

    # pylint: disable=too-many-arguments
    def send_request(self, addr, rtype, args, on_succ, on_fail):
        while self.tid in self.pending:
            self.tid = (self.tid + 1) & 0xffff
        tid = self.tid
        cancel_id = self.asm.add_timer(time.time() + REQUEST_TIMEOUT, lambda: self.__timeout(tid))
        self.pending[self.tid] = (on_succ, on_fail, cancel_id)
        req = {
            'y' : 'q',
            't' : struct.pack('!H', self.tid),
            'q' : rtype,
            'a' : args
        }
        raw = bencode.bencode(req)
        try:
            self.sendto(raw, addr)
        except socket.error as serr:
            if serr.errno != errno.EAGAIN:
                raise serr
            # Ignore EAGAIN and drop packets

    def add_handler(self, name, callback):
        self.handlers[name] = callback

    def handle_read(self):
        (raw, addr) = self.recvfrom(65000)
        try:
            wrapped = bencode.bdecode(raw)
        except bencode.BTL.BTFailure:
            logger.debug("%s: Packet did not decode", addr)
            return
        if 'y' not in wrapped:
            logger.debug("%s: Packet had no type field", addr)
            return
        if wrapped['y'] == 'r' or wrapped['y'] == 'e':
            self.__on_response(addr, wrapped)
            return
        if wrapped['y'] == 'q':
            self.__on_request(addr, wrapped)
            return
        logger.debug("%s: Packet invalid type field", addr)

    def __on_response(self, addr, wrapped):
        if 't' not in wrapped:
            logger.debug("%s:  Dropping response without tid", addr)
            return
        tstr = wrapped['t']
        if type(tstr) is not str or len(tstr) != 2:
            logger.debug("%s: Response with invalid tid", addr)
            return
        (tid,) = struct.unpack('!H', tstr)
        if tid not in self.pending:
            logger.debug("%s: Response not in pending", addr)
            return
        (on_succ, on_fail, cancel_id) = self.pending[tid]
        self.asm.cancel(cancel_id)
        del self.pending[tid]
        if wrapped['y'] == 'e' and 'e' in wrapped:
            on_fail(wrapped['e'])
            return
        if wrapped['y'] != 'r' or 'r' not in wrapped:
            on_fail([203, "No response"])
            return
        on_succ(wrapped['r'])

    def __on_request(self, addr, wrapped):
        if 'q' not in wrapped or wrapped['q'] not in self.handlers:
            resp = {'y' : 'e', 'e' : [204, "Method Unknown"]}
        elif 'a' not in wrapped:
            resp = {'y' : 'e', 'e' : [203, "Missing arguments"]}
        else:
            ret = self.handlers[wrapped['q']](wrapped['a'])
            if type(ret) is str:
                resp = {'y' : 'e', 'e' : [201, ret]}
            else:
                resp = {'y' : 'r', 'r' : ret}
        if 't' in wrapped:
            resp['t'] = wrapped['t']
        raw = bencode.bencode(resp)
        self.sendto(raw, addr)

    def __timeout(self, tid):
        assert tid in self.pending
        (_, on_fail, _) = self.pending[tid]
        del self.pending[tid]
        on_fail([205, "Timeout"])

# pylint: disable=too-few-public-methods
class DhtNode(object):
    def __init__(self, addr, nid):
        self.addr = addr
        self.nid = nid
        self.rand = random.random()
        self.timeout = None
        self.errors = 0
        self.responses = 0

    def key(self):
        return (-self.responses, self.rand, self.addr)

class DhtBucket(object):
    def __init__(self, dht, loc):
        self.dht = dht
        self.loc = loc
        self.all_nodes = {}
        self.good = bintrees.RBTree()
        self.potential = bintrees.RBTree()
        self.pending = 0

    def __shrink_potential(self):
        while len(self.potential) > POTENTIAL_NODES:
            (_, node) = self.potential.pop_max()
            del self.all_nodes[node.addr]

    def __shrink_good(self):
        while len(self.good) > GOOD_NODES:
            (_, node) = self.good.pop_max()
            self.dht.asm.cancel(node.timeout)
            self.potential[node.key()] = node
        self.__shrink_potential()

    def add_node(self, node):
        if node.addr in self.all_nodes:
            return
        self.all_nodes[node.addr] = node
        self.potential[node.key()] = node
        self.__shrink_potential()

    def try_send(self):
        if len(self.good) + self.pending >= 8:
            return False
        if len(self.potential) == 0:
            return False
        (_, node) = self.potential.pop_min()
        self.dht.rpc.send_request(node.addr, 'find_node',
            {'id' : self.dht.mid, 'target' : self.loc.tid},
            lambda resp: self.__find_node_success(node, resp),
            lambda err: self.__find_node_failure(node, err))
        self.pending += 1
        return True

    def __find_node_success(self, node, res):
        assert node.addr in self.all_nodes
        assert node.key() not in self.good
        assert node.key() not in self.potential
        # Not sure why nodes have invalid ids, maybe we should ignore it?
        if 'id' not in res or res['id'] != node.nid:
            self.__find_node_failure(node, (203, "Invalid node_id"))
            return
        if 'nodes' not in res or len(res['nodes']) % 26 != 0 or type(res['nodes']) is not str:
            self.__find_node_failure(node, (203, "Invalid nodes field"))
            return
        self.pending -= 1
        self.good[node.key()] = node
        good_retry = GOOD_RETRY_MIN + random.random() * GOOD_RETRY_SLOP
        node.timeout = self.dht.asm.add_timer(time.time() + good_retry,
            lambda: self.__good_node_timeout(node))
        self.__shrink_good()
        self.dht.rpc.send_request(node.addr, 'get_peers',
            {'id' : self.dht.mid, 'info_hash' : self.loc.tid},
            lambda resp: self.__get_peers_success(node, resp),
            lambda err: self.__get_peers_failure(node, err))
        slices = [res['nodes'][i:i+26] for i in range(0, len(res['nodes']), 26)]
        for flat in slices:
            nid = flat[0:20]
            ipaddr = socket.inet_ntoa(flat[20:24])
            port = struct.unpack('!H', flat[24:26])[0]
            self.dht.found_node((ipaddr, port), nid)

    def __find_node_failure(self, node, err):
        assert node.addr in self.all_nodes
        assert node.key() not in self.good
        assert node.key() not in self.potential
        self.pending -= 1
        logger.debug("%s: Find node failure: %s", node.addr, err)
        node.errors += 1
        if node.errors >= 3 or node.responses == 0:
            del self.all_nodes[node.addr]
        else:
            self.potential[node.key()] = node
            self.loc.start_timer()

    def __good_node_timeout(self, node):
        node.timeout = None
        assert node.addr in self.all_nodes
        assert node.key() in self.good
        del self.good[node.key()]
        self.potential[node.key()] = node
        self.loc.start_timer()

    def __get_peers_success(self, node, resp):
        if 'token' not in resp or type(resp['token']) is not str:
            logger.debug("%s: No token to echo", node.addr)
            return
        if self.loc.port is None:
            return
        self.dht.rpc.send_request(node.addr, 'announce_peer',
            {'id' : self.dht.mid,
             'implied_port' : 0, 'info_hash' : self.loc.tid,
             'port' : self.loc.port, 'token' : resp['token']},
             lambda resp: None,
             lambda err: self.__announce_failure(node, err))
        if 'values' not in resp:
            return
        if type(resp['values']) is not list:
            logger.debug("%s: Values is not a list", node.addr)
            return
        for peer in resp['values']:
            if type(peer) is not str or len(peer) != 6:
                continue
            ipaddr = socket.inet_ntoa(peer[0:4])
            port = struct.unpack('!H', peer[4:6])[0]
            self.loc.found_peer((ipaddr, port))

    def __get_peers_failure(self, node, err):
        _ = self
        logger.debug("%s: Get peers, got error: %s", node.addr, err)

    def __announce_failure(self, node, err):
        _ = self
        logger.debug("%s: Announce peer, got error: %s", node.addr, err)


class DhtLocation(object):
    def __init__(self, dht, tid, port, callback):
        self.dht = dht
        self.tid = tid
        self.port = port
        self.buckets = [DhtBucket(dht, self) for _ in range(160)]
        self.timer = None
        self.peers = collections.OrderedDict()
        self.on_found_peer = callback
        self.start_timer()

    def __shared_bits(self, nid1, nid2):
        _ = self
        shared = 0
        for ch1, ch2 in zip(nid1, nid2):
            xor = ord(ch1) ^ ord(ch2)
            if xor == 0:
                shared += 8
                continue
            if xor & 0xf0:
                xor >>= 4
            else:
                shared += 4
            if xor & 0x0c:
                xor >>= 2
            else:
                shared += 2
            if not xor & 0x02:
                shared += 1
            break
        return shared

    def find_nodes(self, nid):
        results = []
        for bucket in self.buckets:
            for (_, good) in bucket.good.items():
                results.append((-self.__shared_bits(nid, good.nid), good))
        results.sort()
        if len(results) > 8:
            results = results[:8]
        return [(x[1].nid, x[1].addr) for x in results]

    def start_timer(self):
        if self.timer is not None:
            return
        self.timer = self.dht.asm.add_timer(time.time() + SEND_RATE, self.try_send)

    def try_send(self):
        self.timer = None
        for level in range(159, -1, -1):
            sent = self.buckets[level].try_send()
            if sent:
                logger.debug("For %s, send on level %d", self.tid.encode('hex'), level)
                self.start_timer()
                return

    def add_node(self, addr, nid):
        shared = self.__shared_bits(self.tid, nid)
        if shared == 160:
            return
        node = DhtNode(addr, nid)
        self.buckets[shared].add_node(node)
        self.start_timer()

    def found_peer(self, addr):
        if addr in self.peers:
            return
        # pylint: disable=not-callable
        logger.info("Found new peer: %s", addr)
        if self.on_found_peer is not None:
            self.on_found_peer(addr)
        self.peers[addr] = 1
        while len(self.peers) > LOC_PEERS:
            self.peers.popitem(False)

class Dht(object):
    def __init__(self, asm, mid, cfg):
        self.asm = asm
        self.rpc = DhtRpc(self, self.asm, cfg.get('dht_port', 6881))
        self.mid = mid
        self.locations = {}
        self.add_location(mid, None, None)
        self.rpc.add_handler('ping', self.__ping_request)
        self.rpc.add_handler('find_node', self.__find_node_request)
        self.rpc.add_handler('get_peers', self.__get_peers_request)
        self.rpc.add_handler('announce', self.__announce_request)

    def add_location(self, tid, port, callback):
        logger.info("DHT: adding location %s", tid.encode('hex'))
        loc = DhtLocation(self, tid, port, callback)
        self.locations[tid] = loc
        for tid, loc in self.locations.iteritems():
            for bucket in loc.buckets:
                for _, node in bucket.all_nodes.iteritems():
                    loc.add_node(node.addr, node.nid)
        return loc

    def bootstrap_node(self, addr):
        addr = (socket.gethostbyname(addr[0]), addr[1])
        self.rpc.send_request(addr, 'ping', {'id' : self.mid},
            lambda resp: self.__ping_success(addr, resp),
            lambda err: self.__ping_failure(addr, err))

    def found_node(self, addr, nid):
        if nid == self.mid:
            return
        for (_, loc) in self.locations.iteritems():
            loc.add_node(addr, nid)

    def __ping_success(self, addr, resp):
        if 'id' not in resp or type(resp['id']) is not str or len(resp['id']) != 20:
            self.__ping_failure(addr, (203, "Invalid node id"))
            return
        for (_, loc) in self.locations.iteritems():
            loc.add_node(addr, resp['id'])

    def __ping_failure(self, addr, err):
        _ = self
        logger.debug("%s: Ping failure: %s", addr, err)

    def __ping_request(self, req):
        _ = req
        return {'id' : self.mid}

    def __find_node_request(self, req):
        logger.debug("Got find node request: %s", req)
        if 'target' not in req or type(req['target']) is not str or len(req['target']) != 20:
            return "Invalid request target"
        _ = self
        nodes = self.locations[self.mid].find_nodes(req['target'])
        flat = ''.join([x[0] + socket.inet_aton(x[1][0]) +
            struct.pack('!H', x[1][1]) for x in nodes])
        resp = {'id' : self.mid, 'nodes' : flat}
        logger.debug("Sending: %s", resp)
        return resp

    def __get_peers_request(self, req):
        if 'target' not in req or type(req['info_hash']) is not str or len(req['info_hash']) != 20:
            return "Invalid request info_hash"
        _ = self
        logger.debug("Got a get peers request, I guess I should answer it")
        return "Unimplemented"

    def __announce_request(self, req):
        _ = self
        _ = req
        logger.debug("Got an announce request, I guess I should answer it")
        return "Unimplemented"

def main():
    logging.basicConfig(level=logging.INFO)
    bootstrap = [
        ("dht.transmissionbt.com", 6881),
        ("router.bittorrent.com", 6881),
        ("cz.magnets.im", 6881),
        ("de.magnets.im", 6881),
    ]

    mid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
    asm = async.AsyncMgr()
    dht = Dht(asm, mid, {})
    dht.add_location('aaaabbbbeeeeffff000011112222333366667788'.decode('hex'), 6881, None)
    #dht.add_location('ef43d791e5be5f6a8a39c285cdbbd92a0c23870b'.decode('hex'), 8000)
    for addr in bootstrap:
        dht.bootstrap_node(addr)
    asm.run()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()


