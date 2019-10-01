#!/usr/bin/env python

import argparse
import binascii
import os
import re
import select
import socket
import struct
import sys
import time

# Al Smith <ajs@aeschi.eu> January 2018
# https://github.com/alsmith/multicast-relay

class Logger():
    def __init__(self, foreground, verbose):
        self.verbose = verbose

        try:
            import logging
            import logging.handlers
            self.loggingAvailable = True

            logger = logging.getLogger()
            syslog_handler = logging.handlers.SysLogHandler()
            syslog_handler.setFormatter(logging.Formatter(fmt='%(name)s[%(process)d] %(levelname)s: %(message)s'))
            logger.addHandler(syslog_handler)

            if foreground:
                stream_handler = logging.StreamHandler(sys.stdout)
                stream_handler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s: %(message)s', datefmt='%b-%d %H:%M:%S'))
                logger.addHandler(stream_handler)

            if verbose:
                logger.setLevel(logging.INFO)
            else:
                logger.setLevel(logging.WARN)

        except ImportError:
            self.loggingAvailable = False

    def info(self, *args, **kwargs):
        if self.loggingAvailable:
            import logging
            logging.getLogger(__file__).info(*args, **kwargs)
        elif self.verbose:
            print(args, kwargs)

    def warning(self, *args, **kwargs):
        if self.loggingAvailable:
            import logging
            logging.getLogger(__file__).warning(*args, **kwargs)
        else:
            print(args, kwargs)

class Netifaces():
    def __init__(self, homebrewNetifaces, ifNameStructLen):
        self.homebrewNetifaces = homebrewNetifaces
        self.ifNameStructLen = ifNameStructLen
        if self.homebrewNetifaces:
            Netifaces.AF_LINK = 1
            Netifaces.AF_INET = 2
            self.interfaceAttrs = {}
        else:
            import netifaces
            Netifaces.AF_LINK = netifaces.AF_LINK
            Netifaces.AF_INET = netifaces.AF_INET

    def interfaces(self):
        if self.homebrewNetifaces:
            import array
            import fcntl

            maxInterfaces = 128
            bufsiz = maxInterfaces * 40
            nullByte = b'\0'

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifNames = array.array('B', nullByte * bufsiz)
            ifNameLen = struct.unpack('iL', fcntl.ioctl(
                s.fileno(),
                0x8912, # SIOCGIFCONF
                struct.pack('iL', bufsiz, ifNames.buffer_info()[0])
            ))[0]

            if ifNameLen % self.ifNameStructLen != 0:
                print 'Do you need to set --ifNameStructLen? %s/%s ought to have a remainder of zero.' % (ifNameLen, self.ifNameStructLen)
                sys.exit(1)

            ifNames = ifNames.tostring()
            for i in range(0, ifNameLen, self.ifNameStructLen):
                name      = ifNames[i:i+16].split(nullByte, 1)[0].decode()
                if not name:
                    print 'Cannot determine interface name: do you need to set --ifNameStructLen? %s/%s ought to have a remainder of zero.' % (ifNameLen, self.ifNameStructLen)
                    sys.exit(1)
                ip        = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8915, struct.pack('256s', str(name)))[20:24])
                netmask   = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x891b, struct.pack('256s', str(name)))[20:24])
                broadcast = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8919, struct.pack('256s', str(name)))[20:24])
                hwaddr    = ':'.join(['%02x' % ord(char) for char in fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8927, struct.pack('256s', str(name)))[18:24]])
                self.interfaceAttrs[name] = {Netifaces.AF_LINK: [{'addr': hwaddr}], Netifaces.AF_INET: [{'addr': ip, 'netmask': netmask, 'broadcast': broadcast}]}
            return self.interfaceAttrs.keys()
        else:
            import netifaces
            return netifaces.interfaces()

    def ifaddresses(self, interface):
        if self.homebrewNetifaces:
            return self.interfaceAttrs[interface]
        else:
            import netifaces
            return netifaces.ifaddresses(interface)

class PacketRelay():
    MULTICAST_MIN = '224.0.0.0'
    MULTICAST_MAX = '239.255.255.255'
    BROADCAST     = '255.255.255.255'
    SSDP_MCAST_ADDR = '239.255.255.250'
    SSDP_MCAST_PORT = 1900
    SSDP_UNICAST_PORT = 1901

    def __init__(self, interfaces, waitForIP, ttl, oneInterface, homebrewNetifaces, ifNameStructLen, allowNonEther, ssdpUnicastAddr, masquerade, logger):
        self.interfaces = interfaces
        self.ssdpUnicastAddr = ssdpUnicastAddr
        self.wait = waitForIP
        self.ttl = ttl
        self.oneInterface = oneInterface
        self.allowNonEther = allowNonEther
        self.masquerade = masquerade

        self.nif = Netifaces(homebrewNetifaces, ifNameStructLen)
        self.logger = logger

        self.transmitters = []
        self.receivers = []
        self.etherAddrs = {}
        self.etherType = struct.pack('!H', 0x0800)

    def addListener(self, addr, port, service):
        if self.isBroadcast(addr):
            self.etherAddrs[addr] = self.broadcastIpToMac(addr)
        elif self.isMulticast(addr):
            self.etherAddrs[addr] = self.multicastIpToMac(addr)
        else:
            # unicast -- we don't know yet which IP we'll want to send to
            self.etherAddrs[addr] = None

        # Set up the receiving socket and corresponding IP and interface information.
        # One receiving socket is required per multicast address.
        rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        for interface in self.interfaces:
            (ifname, mac, ip, netmask) = self.getInterface(interface)

            # Add this interface to the receiving socket's list.
            if self.isBroadcast(addr):
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            elif self.isMulticast(addr):
                packedAddress = struct.pack('4s4s', socket.inet_aton(addr), socket.inet_aton(ip))
                rx.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, packedAddress)

            # Generate a transmitter socket. Each interface
            # requires its own transmitting socket.
            tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            tx.bind((ifname, 0))

            self.transmitters.append({'relay': {'addr': addr, 'port': port}, 'interface': ifname, 'addr': ip, 'mac': mac, 'netmask': netmask, 'socket': tx, 'service': service})

        rx.bind((addr, port))
        self.receivers.append(rx)

    @staticmethod
    def net_checksum(data):
        """Calculate the IPv4 / UDP checksum of data as byte array.
        Data has a valid checksum if net_checksum(data) == 0
        Alternatively, to calculate the checksum of a header,
        set its checksum bytes (10 and 11 for IPv4, 6 and 7 for UDP, then
        run net_checksum(), e.g. for an IPv4 header:
        cksum = net_checksum(header[:10] + struct.pack('!H', 0) + header[12:])
        """
        # See https://en.wikipedia.org/wiki/IPv4_header_checksum for algorithm
        # Note: chose to implement with clarity over speed
        cksum = 0
        pointer = 0

        size = len(data)
        #The main loop adds up each set of 2 bytes. They are first converted to strings and then concatenated
        #together, converted to integers, and then added to the sum.
        while size > 1:
            val = struct.unpack('!H', data[pointer:pointer+2])[0]
            cksum += val
            size -= 2
            pointer += 2
        if size:
            # The data to checksum has an odd number of bytes, so one left to go through:
            cksum += struct.unpack('!H', data[pointer]+'\x00')[0]

        # Now sum the first 4 bits with the last 16:
        first4b = (cksum >> 16)
        last16b = cksum & 0x0FFFF

        cksum = first4b + last16b
        # Binary inversion:
        cksum = ~cksum
        # for some reason it does the right thing on the last 16 bits, but ends up adding bits at the front
        # so we have to only keep the last 16 bits
        cksum = cksum & 0xFFFF
        return cksum

    @staticmethod
    def unicast_ip2mac_str(ip_as_string, proc_net_arp_content=None):
        """Return the mac address (as a string) of ip_as_string
           If proc_net_arp_content is not None, then it will be used instead
           of reading /proc/net/arp (useful for unit tests).
        """
        if proc_net_arp_content:
            arp_table = proc_net_arp_content
        else:
            # The arp table should be fairly small -- read it all in one go
            with open('/proc/net/arp', 'r') as arp_file:
                arp_table = arp_file.read()
        # Format:
        # IP address       HW type     Flags       HW address            Mask     Device
        # 192.168.0.1      0x1         0x2         18:90:22:bf:3c:23     *        wlp2s0
        matches = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*\s(([a-fA-F\d]{1,2}\:){5}[a-fA-F\d]{1,2})",
                             arp_table)
        # We end up with tupes of 3 groups: (ip, mac, one_of_the_mac_sub_group)
        # We remove the 3rd one which allows us to create a dictionary:
        ip2mac = dict([t[0:2] for t in matches])

        # Default to None if key not in dict
        return ip2mac.get(ip_as_string, None)

    @staticmethod
    def modify_udp_packet(data, ipHeaderLength, newSrcAddr=None,
                          newSrcPort=None, newDstAddr=None, newDstPort=None):
        sourceAddress = newSrcAddr if newSrcAddr else socket.inet_ntoa(data[12:16])
        destinationAddress = newDstAddr if newDstAddr else socket.inet_ntoa(data[16:20])
        sourcePort = newSrcPort if newSrcPort \
            else struct.unpack('!H', data[ipHeaderLength+0:ipHeaderLength+2])[0]
        destinationPort = newDstPort if newDstPort \
            else struct.unpack('!H', data[ipHeaderLength+2:ipHeaderLength+4])[0]

        # recreate the packet with the right checksum:
        udp_data = data[ipHeaderLength+8:]
        udp_data_orig_len = len(udp_data)
        udp_length = 8 + len(udp_data)
        pseudo_header = socket.inet_aton(sourceAddress) + socket.inet_aton(destinationAddress)
        pseudo_header = pseudo_header + struct.pack('!BBH', 0, socket.IPPROTO_UDP, udp_length)
        # Set the checksum field to 0 to calculate the actual checksum
        udp_header = struct.pack('!4H', sourcePort, destinationPort, udp_length, 0)
        checksum = PacketRelay.net_checksum(pseudo_header + udp_header + udp_data)
        udp_header = struct.pack('!4H', sourcePort, destinationPort, udp_length, checksum)

        ip_header = data[:ipHeaderLength]
        # Put IP checksum at 0 to calculate correct checksum
        ip_header = ip_header[:10] + struct.pack('!H', 0) + socket.inet_aton(sourceAddress) \
            + socket.inet_aton(destinationAddress) + ip_header[20:]

        ip_cksum = PacketRelay.net_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_cksum) + ip_header[12:]
        modified_data = ip_header + udp_header + udp_data
        return modified_data

    def loop(self):
        recentChecksums = []
        # Record where the most recent Ssdp searches came from, to relay unicast answers
        # Note: ideally we'd be more clever and record multiple, but in practice
        #   recording the last one seems to be enough for a 'normal' home SSDP traffic
        #   (devices tend to retry SSDP queries multiple times anyway)
        recentSsdpSearchSrc = {}
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
                eighthDataByte = data[8]
                if sys.version_info > (3, 0):
                    eighthDataByte = bytes([data[8]])
                ttl = struct.unpack('B', eighthDataByte)[0]

                if self.ttl:
                    data = data[:8] + struct.pack('B', self.ttl) + data[9:]

                ipChecksum = struct.unpack('!H', data[10:12])[0]
                if ipChecksum in recentChecksums:
                    continue

                sourceAddress = socket.inet_ntoa(data[12:16])
                destinationAddress = socket.inet_ntoa(data[16:20])

                # Compute the length of the IP header so that we can then move past
                # it and delve into the UDP packet to find out what destination port
                # this packet was sent to. The length is encoded in the first least
                # significant nybble of the IP packet and is specified in nybbles.
                firstDataByte = data[0]
                if sys.version_info > (3, 0):
                    firstDataByte = bytes([data[0]])
                ipHeaderLength = (struct.unpack('B', firstDataByte)[0] & 0x0f) * 4
                sourcePort = struct.unpack('!H', data[ipHeaderLength+0:ipHeaderLength+2])[0]
                destinationPort = struct.unpack('!H', data[ipHeaderLength+2:ipHeaderLength+4])[0]

                origSourceAddress = sourceAddress  # str
                origSourcePort = sourcePort  # int
                origDestinationAddress = destinationAddress  # str
                origDestinationPort = destinationPort  # int

                # Record who sent the request
                # FIXME: record more than one?
                dest_mac = None
                modified_data = None
                if origDestinationAddress == PacketRelay.SSDP_MCAST_ADDR \
                        and origDestinationPort == PacketRelay.SSDP_MCAST_PORT and re.search(r'M-SEARCH', data):
                    recentSsdpSearchSrc = {'addr': origSourceAddress, 'port': origSourcePort}
                    self.logger.info('Last SSDP search source: %s:%d' % (origSourceAddress, origSourcePort))
                    # Modify the src IP and port to make it look like it comes from us
                    # so as we receive the unicast answers to a well known port (1901) and can relay them
                    sourceAddress = self.ssdpUnicastAddr
                    sourcePort = PacketRelay.SSDP_UNICAST_PORT
                    modified_data = PacketRelay.modify_udp_packet(data, ipHeaderLength,
                                                                  newSrcAddr=sourceAddress,
                                                                  newSrcPort=sourcePort)

                elif origDestinationAddress == self.ssdpUnicastAddr \
                        and origDestinationPort == PacketRelay.SSDP_UNICAST_PORT:
                    if 'addr' not in recentSsdpSearchSrc or 'port' not in recentSsdpSearchSrc:
                        # We probably haven't seen a SSDP multicast request yet
                        continue
                    # Relay SSDP unicast answer
                    destinationAddress = recentSsdpSearchSrc['addr']
                    destinationPort = recentSsdpSearchSrc['port']
                    self.logger.info("received SSDP Unicast - received from %s:%d on %s:%d, need to relay to %s:%d"
                                     % (origSourceAddress, origSourcePort, origDestinationAddress, origDestinationPort,
                                        destinationAddress, destinationPort))
                    modified_data = PacketRelay.modify_udp_packet(data, ipHeaderLength,
                                                                  newDstAddr=destinationAddress,
                                                                  newDstPort=destinationPort)

                    try:
                        dest_mac = binascii.unhexlify(PacketRelay.unicast_ip2mac_str(destinationAddress).replace(':', ''))
                    except e:
                        self.logger.info("DEBUG: exception while resolving mac of IP '%s'" % destinationAddress)
                        continue
                    # It's possible (though unlikely) we can't resolve the MAC if it's unicast.
                    # In that case, we can't relay the packet
                    if not dest_mac:
                        self.logger.info("DEBUG: could not resolve mac of IP '%s'" % destinationAddress)
                        continue

                # Work out the name of the interface we received the packet on.
                receivingInterface = 'unknown'
                for tx in self.transmitters:
                    if origDestinationAddress == tx['relay']['addr'] and origDestinationPort == tx['relay']['port'] \
                            and self.onNetwork(addr[0], tx['addr'], tx['netmask']):
                        receivingInterface = tx['interface']

                for tx in self.transmitters:
                    # Re-transmit on all other interfaces than on the interface that we received this packet from...
                    if origDestinationAddress == tx['relay']['addr'] and origDestinationPort == tx['relay']['port'] \
                            and (self.oneInterface or not self.onNetwork(addr[0], tx['addr'], tx['netmask'])):

                        dest_mac = dest_mac if dest_mac else self.etherAddrs[destinationAddress]
                        if modified_data and destinationAddress != self.ssdpUnicastAddr:
                            packet = dest_mac + tx['mac'] + self.etherType + modified_data
                            tx['socket'].send(packet)
                            self.logger.info('%sRelayed %s byte%s from %s(%s):%s on %s [ttl %s] to %s:%s via %s/%s'
                                             % (tx['service'] and '[%s] ' % tx['service'] or '', len(data),
                                                len(data) != 1 and 's' or '', addr[0], sourceAddress, sourcePort,
                                                receivingInterface, ttl, destinationAddress, destinationPort,
                                                tx['interface'], tx['addr']))
                        elif origDestinationAddress != self.ssdpUnicastAddr:
                            packet = dest_mac + tx['mac'] + self.etherType + data
                            tx['socket'].send(packet)
                            self.logger.info('%sRelayed %s byte%s from %s(%s):%s on %s [ttl %s] to %s:%s via %s/%s'
                                             % (tx['service'] and '[%s] ' % tx['service'] or '', len(data),
                                                len(data) != 1 and 's' or '', addr[0], origSourceAddress,
                                                origSourcePort, receivingInterface, ttl, origDestinationAddress,
                                                origDestinationPort, tx['interface'], tx['addr']))

                        if tx['interface'] in self.masquerade:
                            data = data[:12] + socket.inet_aton(tx['addr']) + data[16:]

                        # Zero out current checksum
                        data = data[:10] + struct.pack('!H', 0) + data[12:]

                        # Recompute the IP header checksum
                        checksum = 0
                        for i in range(0, ipHeaderLength, 2):
                            checksum += struct.unpack('!H', data[i:i+2])[0]

                        while checksum > 0xffff:
                            checksum = (checksum & 0xffff) + ((checksum - (checksum & 0xffff)) >> 16)

                        data = data[:10] + struct.pack('!H', ~checksum & 0xffff) + data[12:]

                        ipChecksum = struct.unpack('!H', data[10:12])[0]
                        recentChecksums.append(ipChecksum)
                        if len(recentChecksums) > 256:
                            recentChecksums = recentChecksums[1:]

                        packet = self.etherAddrs[destinationAddress] + tx['mac'] + self.etherType + data
                        tx['socket'].send(packet)
                        self.logger.info('%s%s %s byte%s from %s on %s [ttl %s] to %s:%s via %s/%s' % (tx['service'] and '[%s] ' % tx['service'] or '', tx['interface'] in self.masquerade and 'Masqueraded' or 'Relayed', len(data), len(data) != 1 and 's' or '', addr[0], receivingInterface, ttl, destinationAddress, destinationPort, tx['interface'], tx['addr']))

    def getInterface(self, interface):
        ifname = None

        # See if we got an interface name.
        if interface in self.nif.interfaces():
            ifname = interface

        # Maybe we got an network/netmask combination?
        elif re.match('\A\d+\.\d+\.\d+\.\d+\Z', interface):
            for i in self.nif.interfaces():
                addrs = self.nif.ifaddresses(i)
                if self.nif.AF_INET in addrs:
                    if self.nif.AF_INET in addrs and interface == addrs[self.nif.AF_INET][0]['addr']:
                        ifname = i
                        break

        # Or perhaps we got an IP address?
        elif re.match('\A\d+\.\d+\.\d+\.\d+/\d+\Z', interface):
            (network, netmask) = interface.split('/')
            netmask = '.'.join([str((0xffffffff << (32 - int(netmask)) >> i) & 0xff) for i in [24, 16, 8, 0]])

            for i in self.nif.interfaces():
                addrs = self.nif.ifaddresses(i)
                if self.nif.AF_INET in addrs:
                    if self.nif.AF_INET in addrs:
                        ip = addrs[self.nif.AF_INET][0]['addr']
                        if self.onNetwork(ip, network, netmask):
                            ifname = i
                            break

        if not ifname:
            print('Interface %s does not exist.' % interface)
            sys.exit(1)

        try:
            # Here we want to make sure that an interface has an
            # IPv4 address - but if we are running at boot time
            # it might be that we don't yet have an address assigned.
            #
            # --wait doesn't make sense in the situation where we
            # look for an IP# or net/mask combination, of course.
            while True:
                addrs = self.nif.ifaddresses(ifname)
                if self.nif.AF_INET in addrs:
                    break
                if not self.wait:
                    print('Interface %s does not have an IPv4 address assigned.' % ifname)
                    sys.exit(1)
                self.logger.info('Waiting for IPv4 address on %s' % ifname)
                time.sleep(1)

            ip = addrs[self.nif.AF_INET][0]['addr']
            netmask = addrs[self.nif.AF_INET][0]['netmask']

            # If we've been given a virtual interface like eth0:0 then
            # netifaces might not be able to detect its MAC address so
            # lets at least try the parent interface and see if we can
            # find a MAC address there.
            if self.nif.AF_LINK not in addrs and ifname.find(':') != -1:
                addrs = self.nif.ifaddresses(ifname[:ifname.find(':')])

            if self.nif.AF_LINK in addrs:
                mac = addrs[self.nif.AF_LINK][0]['addr']
            elif self.allowNonEther:
                mac = '00:00:00:00:00:00'
            else:
                print('Unable to detect MAC address for interface %s.' % ifname)
                sys.exit(1)

            # These functions all return a value in string format, but our
            # only use for a MAC address later is when we concoct a packet
            # to send, and at that point we need as binary data. Lets do
            # that conversion here.
            return (ifname, binascii.unhexlify(mac.replace(':', '')), ip, netmask)
        except Exception as e:
            print('Error getting information about interface %s.' % ifname)
            print('Valid interfaces: %s' % ' '.join(self.nif.interfaces()))
            self.logger.info(str(e))
            sys.exit(1)

    @staticmethod
    def isMulticast(ip):
        """
        Is this IP address a multicast address?
        """
        ipLong = PacketRelay.ip2long(ip)
        return ipLong >= PacketRelay.ip2long(PacketRelay.MULTICAST_MIN) and ipLong <= PacketRelay.ip2long(PacketRelay.MULTICAST_MAX)

    @staticmethod
    def isBroadcast(ip):
        """
        Is this IP address a broadcast address?
        """
        ipLong = PacketRelay.ip2long(ip)
        return ipLong == PacketRelay.ip2long(PacketRelay.BROADCAST)

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
        ipL = PacketRelay.ip2long(ip)
        networkL = PacketRelay.ip2long(network)
        netmaskL = PacketRelay.ip2long(netmask)
        return (ipL & netmaskL) == (networkL & netmaskL)

    @staticmethod
    def multicastIpToMac(addr):
        # Compute the MAC address that we will use to send
        # packets out to. Multicast MACs are derived from
        # the multicast IP address.
        multicastMac = 0x01005e000000
        multicastMac |= PacketRelay.ip2long(addr) & 0x7fffff
        return struct.pack('!Q', multicastMac)[2:]

    @staticmethod
    def broadcastIpToMac(addr):
        broadcastMac = 0xffffffffffff
        return struct.pack('!Q', broadcastMac)[2:]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interfaces', nargs='+', required=True,
                        help='Relay between these interfaces (minimum 2).')
    parser.add_argument('--ssdpUnicastAddr', required=False,
                        help='IP address to listen to SSDP unicast replies, which will be'
                             ' relayed to the IP that sent the SSDP multicast query.')
    parser.add_argument('--oneInterface', action='store_true',
                        help='Slightly dangerous: only one interface exists, connected to two networks.')
    parser.add_argument('--relay', nargs='*',
                        help='Relay additional multicast address(es).')
    parser.add_argument('--noMDNS', action='store_true',
                        help='Do not relay mDNS packets.')
    parser.add_argument('--noSSDP', action='store_true',
                        help='Do not relay SSDP packets.')
    parser.add_argument('--noSonosDiscovery', action='store_true',
                        help='Do not relay broadcast Sonos discovery packets.')
    parser.add_argument('--homebrewNetifaces', action='store_true',
                        help='Use self-contained netifaces-like package.')
    parser.add_argument('--ifNameStructLen', type=int, default=40,
                        help='Help the self-contained netifaces work out its ifName struct length.')
    parser.add_argument('--allowNonEther', action='store_true',
                        help='Allow non-ethernet interfaces to be configured.')
    parser.add_argument('--masquerade', nargs='+',
                        help='Masquerade outbound packets from these interface(s).')
    parser.add_argument('--wait', action='store_true',
                        help='Wait for IPv4 address assignment.')
    parser.add_argument('--ttl', type=int,
                        help='Set TTL on outbound packets.')
    parser.add_argument('--foreground', action='store_true',
                        help='Do not background.')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output.')
    args = parser.parse_args()

    if len(args.interfaces) < 2 and not args.oneInterface:
        print('You should specify at least two interfaces to relay between')
        return 1

    if args.ttl and (args.ttl < 0 or args.ttl > 255):
        print('Invalid TTL (must be between 1 and 255)')
        return 1

    if not args.foreground:
        pid = os.fork()
        if pid != 0:
            return 0
        os.setsid()
        os.close(sys.stdin.fileno())

    logger = Logger(args.foreground, args.verbose)

    relays = set()
    if not args.noMDNS:
        relays.add(('224.0.0.251:5353',            'mDNS'))
    if not args.noSSDP:
        relays.add(('%s:%d' % (PacketRelay.SSDP_MCAST_ADDR, PacketRelay.SSDP_MCAST_PORT),        'SSDP'))
    if not args.noSonosDiscovery:
        relays.add((PacketRelay.BROADCAST+':6969', 'Sonos Discovery'))

    if args.ssdpUnicastAddr:
        relays.add(('%s:%d' % (args.ssdpUnicastAddr, PacketRelay.SSDP_UNICAST_PORT), 'SSDPunicast'))

    if args.relay:
        for relay in args.relay:
            relays.add((relay, None))

    packetRelay = PacketRelay(args.interfaces, args.wait, args.ttl, args.oneInterface, args.homebrewNetifaces, args.ifNameStructLen, args.allowNonEther, args.ssdpUnicastAddr, args.masquerade, logger)
    for relay in relays:
        try:
            (addr, port) = relay[0].split(':')
            _ = PacketRelay.ip2long(addr)
            port = int(port)
        except:
            errorMessage = '%s: Expecting --relay A.B.C.D:P, where A.B.C.D is a multicast or broadcast IP address and P is a valid port number' % relay
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        if PacketRelay.isMulticast(addr):
            relayType = 'multicast'
        elif PacketRelay.isBroadcast(addr):
            relayType = 'broadcast'
        elif args.ssdpUnicastAddr:
            relayType = 'unicast'
        else:
            errorMessage = 'IP address %s is neither a multicast nor a broadcast address' % addr
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        if port < 0 or port > 65535:
            errorMessage = 'UDP port %s out of range' % port
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        logger.info('Adding %s relay for %s:%s%s' % (relayType, addr, port, relay[1] and ' (%s)' % relay[1] or ''))
        packetRelay.addListener(addr, port, relay[1])

    packetRelay.loop()

if __name__ == '__main__':
    sys.exit(main())
