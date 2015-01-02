#!/usr/bin/python
#pylint: disable=missing-docstring

import logging
import hashlib
import random

from dht import Dht
from nat import autodetect_config
from async import AsyncMgr

def main():
    logging.basicConfig(level=logging.INFO)
    config = autodetect_config()
    if config is None:
        logging.error("Unable to find internet connection, bailing")
        return
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
    dht.add_location(hashlib.sha1("overnet test location").digest(), config.ext_port)
    asm.run()

main()


