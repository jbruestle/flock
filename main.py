#!/usr/bin/python
#pylint: disable=missing-docstring

import logging
import hashlib
import random
import ConfigParser
import argparse

from dht import Dht
from worktoken import WorkToken
from nat import autodetect_config
from async import AsyncMgr
from store import SyncStore
from sync import SyncPeer

def safe_found_peer(speer, self_addr, peer_addr):
    if self_addr == peer_addr:
        logging.info("Whoops, it's myself")
        return
    speer.add_peer(peer_addr)

def main():
    #parser = argparse.ArgumentParser()
    #parser.add_argument("-c", "--config", default="flock.json", help="Name of config file") 
    #args = parser.parse_args()
    
    #config = ConfigParser.RawConfigParser()
    #config.read(args.config)
    logging.basicConfig(level=logging.INFO)

    config = autodetect_config()
    if config is None:
        logging.error("Unable to find internet connection, bailing")
        return
    ext_addr = (config.ext_ip, config.ext_port)
    asm = AsyncMgr()
    nid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
    bootstrap = [
        ("dht.transmissionbt.com", 6881),
        ("router.bittorrent.com", 6881),
        ("cz.magnets.im", 6881),
        ("de.magnets.im", 6881),
    ]
    dht = Dht(asm, nid)
    for addr in bootstrap:
        dht.bootstrap_node(addr)
    store = SyncStore(":memory:", 100000)
    speer = SyncPeer(asm, nid, store, config.sock)
    loc = dht.add_location(hashlib.sha1("overnet test location").digest(), config.ext_port)
    loc.on_found_peer = lambda addr: safe_found_peer(speer, ext_addr, addr)
    asm.run()

main()


