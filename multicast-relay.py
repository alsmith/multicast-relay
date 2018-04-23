#!/usr/bin/env python

import argparse
import binascii
import fcntl
import logging
import logging.handlers
import netifaces
import os
import select
import socket
import struct
import sys
import time

# Al Smith <ajs@aeschi.eu> January 2018
# https://github.com/alsmith/multicast-relay

def log():
    return logging.getLogger(__file__)

class MulticastRelay():
    def __init__(self, interfaces, verbose, waitForIP):
        self.interfaces = interfaces
        self.verbose = verbose
        self.wait = waitForIP

        self.transmitters = []
        self.receivers = []
        self.etherAddrs = {}
        self.etherType = struct.pack('!h', 0x0800)

    def addListener(self, addr, port, service):
        # Compute the MAC address that we will use to send
        # packets out to. Multicast MACs are derived from
        # the multicast IP address.
        multicastMac = 0x01005e000000
        multicastMac |= self.ip2long(addr) & 0x7fffff
        multicastMac = struct.pack('!Q', multicastMac)[2:]
        self.etherAddrs[addr] = multicastMac

        # Set up the receiving socket and corresponding IP and interface information.
        # One receiving socket is required per multicast address.
        rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        for interface in self.interfaces:
            (mac, ip, netmask) = self.getInterface(interface)

            # Add this interface to the receiving socket's list.
            packedAddress = struct.pack('4s4s', socket.inet_aton(addr), socket.inet_aton(ip))
            rx.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, packedAddress)

            # Also generate a transmitter socket. Each interface
            # requires its own transmitting socket.
            tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            tx.bind((interface, 0))

            self.transmitters.append({'multicast': {'addr': addr, 'port': port}, 'interface': interface, 'addr': ip, 'mac': mac, 'netmask': netmask, 'socket': tx, 'service': service})

        rx.bind((addr, port))
        self.receivers.append(rx)

    def loop(self):
        recentChecksums = []
        while True:
            (inputready, _, _) = select.select(self.receivers, [], [])
            for s in inputready:
                (data, addr) = s.recvfrom(10240)

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
                if len(recentChecksums) > 256:
                    recentChecksums = recentChecksums[1:]

                multicastAddress = socket.inet_ntoa(data[16:20])

                # Compute the length of the IP header so that we can then move
                # past it and delve into the UDP packet to find out what multicastPort
                # this packet was sent to. The length is encoded in the first least
                # significant nybble of the IP packet and is specified in nybbles.
                firstDataByte = data[0]
                if sys.version_info > (3, 0):
                    firstDataByte = bytes([data[0]])
                ipHeaderLength = (struct.unpack('B', firstDataByte)[0] & 0x0f) * 4
                multicastPort = struct.unpack('!h', data[ipHeaderLength+2:ipHeaderLength+4])[0]

                # Work out the name of the interface we received the packet
                # on.
                receivingInterface = 'unknown'
                for tx in self.transmitters:
                    if multicastAddress == tx['multicast']['addr'] and multicastPort == tx['multicast']['port'] and self.onNetwork(addr[0], tx['addr'], tx['netmask']):
                        receivingInterface = tx['interface']

                for tx in self.transmitters:
                    # Re-transmit on all other interfaces than on the interface that we received this multicast packet from...
                    if multicastAddress == tx['multicast']['addr'] and multicastPort == tx['multicast']['port'] and not self.onNetwork(addr[0], tx['addr'], tx['netmask']):
                        packet = self.etherAddrs[multicastAddress] + tx['mac'] + self.etherType + data
                        tx['socket'].send(packet)
                        if self.verbose:
                            log().info('%sRelayed %s byte%s from %s on %s to %s:%s via %s/%s' % (tx['service'] and '[%s] ' % tx['service'] or '', len(data), len(data) != 1 and 's' or '', addr[0], receivingInterface, multicastAddress, multicastPort, tx['interface'], tx['addr']))

    def getInterface(self, ifname):
        if ifname not in netifaces.interfaces():
            print('Interface %s does not exist.' % ifname)
            sys.exit(1)

        try:
            # Here we want to make sure that an interface has an
            # IPv4 address - but if we are running at boot time
            # it might be that we don't yet have an address assigned.
            while True:
                i = netifaces.ifaddresses(ifname)
                if netifaces.AF_INET in i:
                    break
                if not self.wait:
                    print('Interface %s does not have an IPv4 address assigned.' % ifname)
                    sys.exit(1)
                log().info('Waiting for IPv4 address on %s' % ifname)
                time.sleep(1)

            ip = i[netifaces.AF_INET][0]['addr']
            netmask = i[netifaces.AF_INET][0]['netmask']

            # If we've been given a virtual interface like eth0:0 then
            # netifaces might not be able to detect its MAC address so
            # lets at least try the parent interface and see if we can
            # find a MAC address there.
            if netifaces.AF_LINK not in i and ifname.find(':') != -1:
                i = netifaces.ifaddresses(ifname[:ifname.find(':')])
                
            if netifaces.AF_LINK not in i:
                print('Unable to detect MAC address for interface %s.' % ifname)
                sys.exit(1)

            mac = i[netifaces.AF_LINK][0]['addr']

            # These functions all return a value in string format, but our
            # only use for a MAC address later is when we concoct a packet
            # to send, and at that point we need as binary data. Lets do
            # that conversion here.
            return (binascii.unhexlify(mac.replace(':', '')), ip, netmask)
        except Exception as e:
            print('Error getting information about interface %s.' % ifname)
            print('Valid interfaces: %s' % ' '.join(netifaces.interfaces()))
            if self.verbose:
                raise
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
    parser.add_argument('--wait', action='store_true',
                        help='Wait for IPv4 address assignment.')
    parser.add_argument('--foreground', action='store_true',
                        help='Do not background.')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output.')
    args = parser.parse_args()

    if len(args.interfaces) < 2:
        print('You should specify at least two interfaces to relay between')
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
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s: %(message)s', datefmt='%b-%d %H:%M:%S'))
        logger.addHandler(stream_handler)

    if args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARN)

    relays = set()
    if not args.noMDNS:
        relays.add(('224.0.0.251:5353', 'mDNS'))
    if not args.noSSDP:
        relays.add(('239.255.255.250:1900', 'SSDP'))

    if args.relay:
        for relay in args.relay:
            relays.add((relay, None))

    multicastRelay = MulticastRelay(args.interfaces, args.verbose, args.wait)
    for relay in relays:
        try:
            (addr, port) = relay[0].split(':')
            ip = MulticastRelay.ip2long(addr)
            port = int(port)
        except:
            print('%s: Expecting --relay A.B.C.D:P, where A.B.C.D is a multicast IP address and P is a valid port number' % relay)
            return 1

        if ip < MulticastRelay.ip2long('224.0.0.0') or ip > MulticastRelay.ip2long('239.255.255.255'):
            print('IP address %s not a multicast address' % addr)
            return 1
        if port < 0 or port > 65535:
            print('UDP port %s out of range' % port)
            return 1

        log().info('Adding multicast relay for %s:%s%s' % (addr, port, relay[1] and ' (%s)' % relay[1] or ''))
        multicastRelay.addListener(addr, port, relay[1])
    multicastRelay.loop()

if __name__ == '__main__':
    sys.exit(main())

