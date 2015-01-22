#!/usr/bin/env python
# pylint: disable=missing-docstring
# pylint: disable=too-few-public-methods

import time
import netifaces
import ipaddr
import miniupnpc
import socket
import threading
import logging
import select

logger = logging.getLogger('nat') # pylint: disable=invalid-name

UPNP_DESC = 'flock'

def get_ipv4_default_addr():
    # For some reason, netifaces doesn't seem to play nice
    # with pylint, so we disable no-member
    # pylint: disable=no-member
    # First, find the default gateway
    gws = netifaces.gateways()
    defaults = gws['default']
    if netifaces.AF_INET not in defaults:
        # No IPv4 gateway, give up
        return None
    # otherwise, get interface and addr
    (_, iface) = defaults[netifaces.AF_INET]
    # Get the local addresses
    addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET]
    # If there is more than one (or none), give up
    if len(addrs) != 1:
        return None
    logger.debug("Found ipv4 address: %s", addrs[0]['addr'])
    # Ok, found the 'primary' gateway facing address
    return ipaddr.IPAddress(addrs[0]['addr'])

def setup_upnp(local, eport):
    logger.info("Trying UPNP")
    upnp = miniupnpc.UPnP() # pylint: disable=no-member
    if not upnp.discover():
        logger.info("Failed to discover")
        return None
    upnp.selectigd()

    if upnp.lanaddr != local[0]:
        return None

    port = eport
    for _ in range(10):
        mapping = upnp.getspecificportmapping(port, 'TCP')
        logger.info("Checking port %d, mapping = %s", port, mapping)
        if mapping is None:
            # Looks like the port I want is free!
            logger.info("It's free, assigning to me")
            break
        (ihost, iport, desc, _, _) = mapping
        if desc != UPNP_DESC:
            # Some other service
            port += 1
            continue
        if ihost != upnp.lanaddr:
            # Some other device
            port += 1
            continue
        if iport == local[1]:
            # Looks like it's already set
            logger.info("Already mapped")
            return (upnp, port)
        # Hmm, clear out old version + break
        logger.info("Wrong local port, deleting mapping")
        upnp.deleteportmapping(port, 'TCP')
        break

    upnp.addportmapping(port, 'TCP', local[0], local[1], UPNP_DESC, '')
    return (upnp, port)

class BaseConfig(object):
    # pylint: disable=too-many-instance-attributes
    def __init__(self, sock, ext_ip, ext_port):
        # Set external variables
        self.sock = sock
        self.int_port = sock.getsockname()[1]
        self.ext_ip = ext_ip
        self.ext_port = ext_port
        (self.is_done, self.__make_done) = socket.socketpair()

        # Set default check timer
        self._check_time = 5

        # Kick off a check thread
        self.__stop_thread = False
        self.__thread = threading.Thread(target=self.__check_thread)
        self.__thread.daemon = True
        self.__thread.start()

    def stop(self):
        self.__stop_thread = True
        self.__thread.join()

    def __check_thread(self):
        try:
            while not self.__stop_thread:
                time.sleep(self._check_time)
                if not self._check():
                    break
        except: # pylint: disable = bare-except
            # Any failure in check thread shuts network down
            pass
        self.__make_done.close()

    def _check(self):
        _ = self
        return True

class ExtV4Config(BaseConfig):
    def __init__(self, sock, addr, port):
        BaseConfig.__init__(self, sock, str(addr), port)
        self.addr = addr

    def _check(self):
        new_addr = get_ipv4_default_addr()
        return new_addr == self.addr

class UPNPConfig(BaseConfig):
    def __init__(self, sock, local, upnp_res):
        (upnp, port) = upnp_res
        BaseConfig.__init__(self, sock, upnp.externalipaddress(), port)
        self.local_addr = local[0]
        self.local_port = local[1]
        self.upnp = upnp

    def _check(self):
        logger.debug("Checking UPNP mapping")
        ipv4 = get_ipv4_default_addr()
        if str(ipv4) != self.local_addr:
            return False
        mapping = self.upnp.getspecificportmapping(self.ext_port, 'TCP')
        if mapping is None:
            return False
        (ihost, iport, desc, _, _) = mapping
        if desc != UPNP_DESC or ihost != self.local_addr or iport != self.local_port:
            return False
        return True

def setup_network(cfg):
    logger.info("Doing network setup")
    if cfg.get('sync_local', False):
        ipv4 = '127.0.0.1'
    else:
        ipv4 = get_ipv4_default_addr()
        if ipv4 is None:
            # TODO: ipv6
            logger.warning("No external IPv4 found")
            return None

    iport = cfg.get('sync_port', 58892)

    # Make a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local = (str(ipv4), iport)
    sock.bind(local)

    if cfg.get('sync_local', False):
        return BaseConfig(sock, None, None)

    # Check if it's private
    if ipv4.is_private:
        # Yup, let's try upnp first
        eport = cfg.get('goal_ext_port', 58892)
        upnp_res = None
        try:
            upnp_res = setup_upnp(local, eport)
        except: # pylint: disable=bare-except
            pass
        if upnp_res:
            return UPNPConfig(sock, local, upnp_res)

        # TODO: Try NatPMP
        # Just give up and use a local setup
        return BaseConfig(sock, None, None)
    else:
        # Return simple external V4
        logger.info("Looks like an external IP")
        return ExtV4Config(sock, ipv4, iport)

def main():
    logging.basicConfig(level=logging.DEBUG)
    config = setup_network({})
    _ = select.select([config.is_done], [], [], 30)
    config.stop()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()


