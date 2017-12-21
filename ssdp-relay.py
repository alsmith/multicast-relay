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

def get_interface(ifname):
    """
    Truly horrible way to get the interface addresses, given an interface name.
    http://stackoverflow.com/questions/11735821/python-get-localhost-ip
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        arg = struct.pack('256s', ifname[:15])
        mac = fcntl.ioctl(s.fileno(), 0x8927, arg)[18:24]
        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, arg)[20:24])
        return (mac, ip)
    except IOError:
        print 'Error getting information about interface %s' % ifname
        sys.exit(1)

class SSDP():
    def __init__(self, interfaces, verbose):
        self.verbose = verbose
        self.interfaces = {}
        self.addr = '239.255.255.250'
        self.port = 1900
        self.mac = '\x01\x00\x5e\x7f\xff\xfa'
        self.ethertype = '\x08\x00'

        for interface in interfaces:
            (mac, ip) = get_interface(interface)

            # Inbound interface
            r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            mreq = struct.pack('4s4s', socket.inet_aton(self.addr), socket.inet_aton(ip))
            r.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            r.bind((self.addr, self.port))

            # Outbound interface
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((interface, 0))

            self.interfaces[interface] = {'addr': ip, 'mac': mac, 'recv': r, 'send': s}

    def loop(self):
        recentChecksums = []
        while True:
            inputready, _, _ = select.select(map(lambda interface: self.interfaces[interface]['recv'], self.interfaces), [], [])
            for s in inputready:
                data, addr = s.recvfrom(10240)

                # Use IP checksum information to see if we have already seen this
                # packet, since once we have retransmitted it on an interface
                # we know that we will see it once again on that interface.
                ipChecksum = data[10:11]
                if ipChecksum in recentChecksums:
                    continue
                recentChecksums.append(ipChecksum)
                if (len(recentChecksums) > 16):
                    recentChecksums = recentChecksums[1:]

                for interface in self.interfaces:
                    # Re-transmit on all other interfaces than on the interface that we received this multicast packet from...
                    if self.interfaces[interface]['recv'] != s:
                        packet = self.mac+self.interfaces[interface]['mac']+self.ethertype+data
                        self.interfaces[interface]['send'].send(packet)
                        if self.verbose:
                            log().info('Relayed %s byte%s from %s to %s.' % (len(data), len(data) != 1 and 's' or '', addr[0], interface))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interfaces', nargs='+', required=True,
                        help='Relay between interfaces.')
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

    ssdp = SSDP(args.interfaces, args.verbose)
    ssdp.loop()

if __name__ == '__main__':
    sys.exit(main())

