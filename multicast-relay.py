#!/usr/bin/python

import argparse
import fcntl
import logging
import logging.handlers
import os
import select
import socket
import struct
import sys

def log():
    return logging.getLogger(__file__)

class MulticastRelay():
    def __init__(self, interfaces, verbose):
        self.interfaces = interfaces
        self.verbose = verbose
        self.transmitters = []
        self.receivers = []


    def addListener(self, addr, port):
        mac = 0x01005e000000
        mac |= self.ip2long(addr) & 0x7fffff
        self.mac = struct.pack('!Q', mac)[2:]
        self.ethertype = struct.pack('!h', 0x0800)

        # Receiving socket
        r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        for interface in self.interfaces:
            mac, ip, netmask = self.getInterface(interface)

            # Add this interface to the receiving socket's list.
            mreq = struct.pack('4s4s', socket.inet_aton(addr), socket.inet_aton(ip))
            r.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            # Sending socket
            tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            tx.bind((interface, 0))

            self.transmitters.append({'multicast': {'addr': addr, 'port': port}, 'interface': interface, 'addr': ip, 'mac': mac, 'netmask': netmask, 'socket': tx})

        r.bind((addr, port))
        self.receivers.append(r)

    def loop(self):
        recentChecksums = []
        while True:
            inputready, _, _ = select.select(self.receivers, [], [])
            for s in inputready:
                data, addr = s.recvfrom(10240)

                # Use IP checksum information to see if we have already seen this
                # packet, since once we have retransmitted it on an interface
                # we know that we will see it once again on that interface.
                #
                # If we were retransmitting via a UDP socket then we could
                # just disable IP_MULTICAST_LOOP but that won't work as we are
                # using an RAW socket.
                ipChecksum = data[10:12]
                if ipChecksum in recentChecksums:
                    continue
                recentChecksums.append(ipChecksum)
                if len(recentChecksums) > 16:
                    recentChecksums = recentChecksums[1:]

                maddr = socket.inet_ntoa(data[16:20])
                ipHeader = (struct.unpack('B', data[0])[0] & 0x0f) * 4
                mport = struct.unpack('!h', data[ipHeader+2:ipHeader+4])[0]

                receivingInterface = 'unknown'
                for tx in self.transmitters:
                    if maddr == tx['multicast']['addr'] and mport == tx['multicast']['port'] and self.onNetwork(addr[0], tx['addr'], tx['netmask']):
                        receivingInterface = tx['interface']

                for tx in self.transmitters:
                    # Re-transmit on all other interfaces than on the interface that we received this multicast packet from...
                    if maddr == tx['multicast']['addr'] and mport == tx['multicast']['port'] and not self.onNetwork(addr[0], tx['addr'], tx['netmask']):
                        packet = self.mac + tx['mac'] + self.ethertype+data
                        tx['socket'].send(packet)
                        if self.verbose:
                            log().info('Relayed %s byte%s from %s on %s to %s:%s via %s/%s.' % (len(data), len(data) != 1 and 's' or '', addr[0], receivingInterface, maddr, mport, tx['interface'], tx['addr']))

    @staticmethod
    def getInterface(ifname):
        """
        Truly horrible way to get the interface addresses, given an interface name.
        http://stackoverflow.com/questions/11735821/python-get-localhost-ip
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            arg = struct.pack('256s', ifname[:15])

            mac = fcntl.ioctl(s.fileno(), 0x8927, arg)[18:24]
            ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, arg)[20:24])
            netmask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, arg)[20:24])
            return (mac, ip, netmask)
        except IOError:
            print 'Error getting information about interface %s' % ifname
            sys.exit(1)

    @staticmethod
    def ip2long(ip):
        """
        Given an IP address (or netmask) turn it into an unsigned long.
        """
        packedIP = socket.inet_aton(ip)
        return struct.unpack('!L', packedIP)[0]

    @staticmethod
    def onNetwork(ip, network, netmask):
        """
        Given an IP address and a network/netmask tuple, work out
        if that IP address is on that network.
        """
        ipL = MulticastRelay.ip2long(ip)
        networkL = MulticastRelay.ip2long(network)
        netmaskL = MulticastRelay.ip2long(netmask)
        return (ipL & netmaskL) == (networkL & netmaskL)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interfaces', nargs='+', required=True,
                        help='Relay between these interfaces (minimum 2).')
    parser.add_argument('--relay', nargs='*',
                        help='Relay additional multicast address(es).')
    parser.add_argument('--noMDNS', action='store_true',
                        help='Do not relay mDNS packets.')
    parser.add_argument('--noSSDP', action='store_true',
                        help='Do not relay SSDP packets.')
    parser.add_argument('--foreground', action='store_true',
                        help='Do not background.')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output.')
    args = parser.parse_args()

    if len(args.interfaces) < 2:
        print 'You should specify at least two interfaces to relay between'
        return 1

    if not args.foreground:
        pid = os.fork()
        if pid != 0:
            return 0
        os.setsid()
        os.close(sys.stdin.fileno())

    logger = logging.getLogger()
    syslog_handler = logging.handlers.SysLogHandler()
    syslog_handler.setFormatter(logging.Formatter(fmt='%(name)s[%(process)d] %(levelname)s: %(message)s'))
    logger.addHandler(syslog_handler)

    if args.foreground:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s: %(message)s', datefmt='%b-%d %H:%M:%S'))
        logger.addHandler(stream_handler)

    if args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARN)

    relays = set()
    if not args.noMDNS:
        relays.add('224.0.0.251:5353')
    if not args.noSSDP:
        relays.add('239.255.255.250:1900')

    if args.relay:
        for relay in args.relay:
            relays.add(relay)

    multicastRelay = MulticastRelay(args.interfaces, args.verbose)
    for relay in relays:
        try:
            (addr, port) = relay.split(':')
            ip = MulticastRelay.ip2long(addr)
            port = int(port)
        except:
            log().warning('%s: Expecting --relay A.B.C.D:P, where A.B.C.D is a multicast IP address and P is a valid port number' % relay)
            return 1

        if ip < MulticastRelay.ip2long('224.0.0.0') or ip >= MulticastRelay.ip2long('239.255.255.255'):
            log().warning('IP address %s not a multicast address' % addr)
            return 1
        if port < 0 or port > 65535:
            log().warning('UDP port %s out of range' % port)
            return 1

        log().info('Adding multicast relay for %s:%s' % (addr, port))
        multicastRelay.addListener(addr, port)
    multicastRelay.loop()

if __name__ == '__main__':
    sys.exit(main())

