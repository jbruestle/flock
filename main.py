#!/usr/bin/python
#pylint: disable=missing-docstring

import os
import logging
import hashlib
import random
import ConfigParser
import argparse

import dht
import nat
import async
import sync
import store
import http
import api

def safe_found_peer(speer, self_addr, tid, peer_addr):
    if self_addr == peer_addr:
        logging.info("Whoops, it's myself")
        return
    speer.add_peer(tid, peer_addr)

def main():
    # Parse some params
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", help="Storage directory")
    parser.add_argument("-p", "--port", default=58892, help="Local port #")
    parser.add_argument("-e", "--eport", default=55892, help="External port #")
    parser.add_argument("-a", "--aport", default=8000, help="API port #")
    args = parser.parse_args()

    # Logging system GO
    logging.basicConfig(level=logging.INFO)

    # Create/find path
    store_dir = args.dir
    if not os.path.exists(store_dir):
        os.makedirs(store_dir)

    # Create/load nid
    nid_file = os.path.join(store_dir, 'nid')
    if not os.path.exists(nid_file):
        nid = ''.join(chr(random.randint(0, 255)) for _ in range(20))
        with open(nid_file, 'w') as f:
            f.write(nid)
    with open(nid_file, 'r') as f:
        nid = f.read()
    if len(nid) != 20:
        raise(ValueError('Invalid nid'))
        
    # Load stores 
    stores = {}
    for bname in os.listdir(store_dir):
        if len(bname) != 40:
            continue
        try:
            tid = bname.decode('hex')
        except Exception:
            continue
        #TODO: Max size?
        nstore = store.SyncStore(tid, os.path.join(store_dir, bname), 1*1024*1024)
        stores[tid] = nstore

    # Nat punch out
    config = nat.autodetect_config(args.port, args.eport)
    if config is None:
        logging.error("Unable to find internet connection, bailing")
        return
    ext_addr = (config.ext_ip, config.ext_port)

    # Setup async goo
    asm = async.AsyncMgr()

    # Make sync system itself
    sync_peer = sync.SyncPeer(asm, nid, stores, config.sock)

    # Bootstrap DHT
    bootstrap = [
        ("dht.transmissionbt.com", 6881),
        ("router.bittorrent.com", 6881),
        ("cz.magnets.im", 6881),
        ("de.magnets.im", 6881),
    ]
    the_dht = dht.Dht(asm, nid)
    for addr in bootstrap:
        the_dht.bootstrap_node(addr)

    # Make a DHT location for each store
    for tid, _ in stores.iteritems():
        loc = the_dht.add_location(tid, config.ext_port)
        loc.on_found_peer = lambda addr: safe_found_peer(sync_peer, ext_addr, tid, addr)

    # Setup the http api
    the_api = api.Api(stores, store_dir)
    server = http.HttpServer(asm, the_api, args.aport)
    
    # Kick it all off
    asm.run()

main()


