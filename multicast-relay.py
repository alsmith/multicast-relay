#!/usr/bin/env python

import argparse
import binascii
import errno
import json
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
    def __init__(self, foreground, logfile, verbose):
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

            if logfile:
                file_handler = logging.FileHandler(logfile)
                file_handler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s: %(message)s', datefmt='%b-%d %H:%M:%S'))
                logger.addHandler(file_handler)

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
                print('Do you need to set --ifNameStructLen? %s/%s ought to have a remainder of zero.' % (ifNameLen, self.ifNameStructLen))
                sys.exit(1)

            ifNames = ifNames.tostring()
            for i in range(0, ifNameLen, self.ifNameStructLen):
                name      = ifNames[i:i+16].split(nullByte, 1)[0].decode()
                if not name:
                    print('Cannot determine interface name: do you need to set --ifNameStructLen? %s/%s ought to have a remainder of zero.' % (ifNameLen, self.ifNameStructLen))
                    sys.exit(1)
                ip        = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8915, struct.pack('256s', str(name)))[20:24]) # SIOCGIFADDR
                netmask   = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x891b, struct.pack('256s', str(name)))[20:24]) # SIOCGIFNETMASK
                broadcast = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8919, struct.pack('256s', str(name)))[20:24]) # SIOCGIFBRDADDR
                hwaddr    = ':'.join(['%02x' % ord(char) for char in fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8927, struct.pack('256s', str(name)))[18:24]]) # SIOCGIFHWADDR
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

class Cipher():
    def __init__(self, key):
        self.key = None
        if not key:
            return

        import Crypto.Cipher.AES
        import hashlib

        self.blockSize = Crypto.Cipher.AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    @staticmethod
    def strToInt(s):
        return int(binascii.hexlify(s), 16)

    def encrypt(self, plaintext):
        if not self.key:
            return plaintext

        import Crypto
        import Crypto.Random
        import Crypto.Util.Counter

        iv = Crypto.Random.new().read(self.blockSize)
        ctr = Crypto.Util.Counter.new(128, initial_value=self.strToInt(iv))
        aes = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        return iv + aes.encrypt(plaintext)

    def decrypt(self, ciphertext):
        if not self.key:
            return ciphertext

        import Crypto
        import Crypto.Util.Counter

        iv = ciphertext[:self.blockSize]
        ctr = Crypto.Util.Counter.new(128, initial_value=self.strToInt(iv))
        aes = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        return aes.decrypt(ciphertext[self.blockSize:])

class PacketRelay():
    MULTICAST_MIN     = '224.0.0.0'
    MULTICAST_MAX     = '239.255.255.255'
    BROADCAST         = '255.255.255.255'
    SSDP_MCAST_ADDR   = '239.255.255.250'
    SSDP_MCAST_PORT   = 1900
    SSDP_UNICAST_PORT = 1901
    MDNS_MCAST_ADDR   = '224.0.0.251'
    MDNS_MCAST_PORT   = 5353
    MAGIC             = b'MRLY'
    IPV4LEN           = len(socket.inet_aton('0.0.0.0'))

    def __init__(self, interfaces, noTransmitInterfaces, ifFilter, waitForIP, ttl,
                 oneInterface, homebrewNetifaces, ifNameStructLen, allowNonEther,
                 ssdpUnicastAddr, mdnsForceUnicast, masquerade, listen, remote,
                 remotePort, remoteRetry, noRemoteRelay, aes, logger):
        self.interfaces = interfaces
        self.noTransmitInterfaces = noTransmitInterfaces or []

        if ifFilter:
            with open(ifFilter) as fd:
                self.ifFilter = json.loads(fd.read().replace('\n', ' ').strip())
        else:
            self.ifFilter = {}
        self.ssdpUnicastAddr = ssdpUnicastAddr
        self.mdnsForceUnicast = mdnsForceUnicast
        self.wait = waitForIP
        self.ttl = ttl
        self.oneInterface = oneInterface
        self.allowNonEther = allowNonEther
        self.masquerade = masquerade or []

        self.nif = Netifaces(homebrewNetifaces, ifNameStructLen)
        self.logger = logger

        self.transmitters = []
        self.receivers = []
        self.etherAddrs = {}
        self.etherType = struct.pack('!H', 0x0800)
        self.udpMaxLength = 1458

        self.recentChecksums = []

        self.bindings = set()

        self.listenAddr = []
        if listen:
            for addr in listen:
                components = addr.split('/')
                if len(components) == 1:
                    components.append('32')
                if not components[1].isdigit():
                    raise ValueError('--listen netmask is not an integer')
                if int(components[1]) not in range(0, 33):
                    raise ValueError('--listen netmask specifies an invalid netmask')
                self.listenAddr.append(components)

        self.listenSock = None
        if remote:
            self.remoteAddrs = list(map(lambda remote: {'addr': remote, 'socket': None, 'connecting': False, 'connectFailure': None}, remote))
        else:
            self.remoteAddrs = []
        self.remotePort = remotePort
        self.remoteRetry = remoteRetry
        self.noRemoteRelay = noRemoteRelay
        self.aes = Cipher(aes)

        self.remoteConnections = []

        if self.listenAddr:
            self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listenSock.bind(('0.0.0.0', self.remotePort))
            self.listenSock.listen(0)
        elif self.remoteAddrs:
            self.connectRemotes()

    def connectRemotes(self):
        for remote in self.remoteAddrs:
            if remote['socket']:
                continue

            # Attempt reconnection at most once every N seconds
            if remote['connectFailure'] and remote['connectFailure'] > time.time()-self.remoteRetry:
                return

            remoteConnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remoteConnection.setblocking(0)
            self.logger.info('REMOTE: Connecting to remote %s' % remote['addr'])
            remote['connecting'] = True
            try:
                remoteConnection.connect((remote['addr'], self.remotePort))
            except socket.error as e:
                if e.errno == errno.EINPROGRESS:
                    remote['socket'] = remoteConnection
                else:
                    remote['connecting'] = False
                    remote['connectFailure'] = time.time()

    def removeConnection(self, s):
        if s in self.remoteConnections:
            self.remoteConnections.remove(s)
            return

        for remote in self.remoteAddrs:
            if remote['socket'] == s:
                remote['socket'] = None
                remote['connecting'] = False
                remote['connectFailure'] = time.time()

    def remoteSockets(self):
        return self.remoteConnections + list(map(lambda remote: remote['socket'], filter(lambda remote: remote['socket'], self.remoteAddrs)))

    def addListener(self, addr, port, service):
        if self.isBroadcast(addr):
            self.etherAddrs[addr] = self.broadcastIpToMac(addr)
        elif self.isMulticast(addr):
            self.etherAddrs[addr] = self.multicastIpToMac(addr)
        else:
            # unicast -- we don't know yet which IP we'll want to send to
            self.etherAddrs[addr] = None

            rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rx.bind((addr, port))
            self.receivers.append(rx)

        # Set up the receiving socket and corresponding IP and interface information.
        # One receiving socket is required per multicast address. But for extra
        # fun, one receiving socket for each network interface, if we're
        # intercepting broadcast packets.
        if self.isMulticast(addr):
            rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        for interface in self.interfaces:
            (ifname, mac, ip, netmask, broadcast) = self.getInterface(interface)

            # Add this interface to the receiving socket's list.
            if self.isBroadcast(addr):
                rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                if 'SO_BINDTODEVICE' not in dir(socket):
                    socket.SO_BINDTODEVICE = 25

                rx.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode('utf-8'))

                rx.bind(('0.0.0.0', port))

                self.receivers.append(rx)
                listenIP = '255.255.255.255'

            elif self.isMulticast(addr):
                packedAddress = struct.pack('4s4s', socket.inet_aton(addr), socket.inet_aton(ip))
                rx.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, packedAddress)
                listenIP = addr
            else:
                listenIP = addr

            # Generate a transmitter socket. Each interface
            # requires its own transmitting socket.
            if interface not in self.noTransmitInterfaces:
                tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                tx.bind((ifname, 0))

                self.transmitters.append({'relay': {'addr': listenIP, 'port': port}, 'interface': ifname, 'addr': ip, 'mac': mac, 'netmask': netmask, 'broadcast': broadcast, 'socket': tx, 'service': service})

        if self.isMulticast(addr):
            rx.bind((addr, port))
            self.receivers.append(rx)
        self.bindings.add((addr, port))

    @staticmethod
    def unicastIpToMac(ip, procNetArp=None):
        """
        Return the mac address (as a string) of ip
        If procNetArp is not None, then it will be used instead
        of reading /proc/net/arp (useful for unit tests).
        """
        if procNetArp:
            arpTable = procNetArp
        else:
            # The arp table should be fairly small -- read it all in one go
            with open('/proc/net/arp', 'r') as fd:
                arpTable = fd.read()

        # Format:
        # IP address       HW type     Flags       HW address            Mask     Device
        # 192.168.0.1      0x1         0x2         18:90:22:bf:3c:23     *        wlp2s0
        matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*\s(([a-fA-F\d]{1,2}\:){5}[a-fA-F\d]{1,2})', arpTable)

        # We end up with tuples of 3 groups: (ip, mac, one_of_the_mac_sub_group)
        # We remove the 3rd one which allows us to create a dictionary:
        ip2mac = dict([t[0:2] for t in matches])

        # Default to None if key not in dict
        return ip2mac.get(ip, None)

    @staticmethod
    def modifyUdpPacket(data, ipHeaderLength, srcAddr=None, srcPort=None, dstAddr=None, dstPort=None):
        srcAddr = srcAddr if srcAddr else socket.inet_ntoa(data[12:16])
        dstAddr = dstAddr if dstAddr else socket.inet_ntoa(data[16:20])

        srcPort = srcPort if srcPort else struct.unpack('!H', data[ipHeaderLength+0:ipHeaderLength+2])[0]
        dstPort = dstPort if dstPort else struct.unpack('!H', data[ipHeaderLength+2:ipHeaderLength+4])[0]

        # Recreate the packet
        ipHeader = data[:ipHeaderLength-8] + socket.inet_aton(srcAddr) + socket.inet_aton(dstAddr)

        udpData = data[ipHeaderLength+8:]
        udpLength = 8 + len(udpData)
        udpHeader = struct.pack('!4H', srcPort, dstPort, udpLength, 0)

        return ipHeader + udpHeader + udpData

    @staticmethod
    def mdnsSetUnicastBit(data, ipHeaderLength):
        headers = data[:ipHeaderLength+8]
        udpData = data[ipHeaderLength+8:]

        flags = struct.unpack('!H', udpData[2:4])[0]
        if flags & 0x8000 != 0:
            return data

        queries = struct.unpack('!H', udpData[4:6])[0]

        queryCount = 0
        ptr = 12
        while True:
            labelLength = struct.unpack('B', udpData[ptr:ptr+1])[0]
            if not labelLength & 0x3f:
                if labelLength & 0xc0:
                    ptr += 1
                queryCount += 1
                data = struct.unpack('!H', udpData[ptr+3:ptr+5])[0]
                udpData = udpData[:ptr+3] + struct.pack('!H', data | 0x8000) + udpData[ptr+5:]
                if queryCount == queries:
                    break
                ptr += 5
            else:
                ptr += labelLength+1

        return headers + udpData

    def computeIPChecksum(self, data, ipHeaderLength):
        # Zero out current checksum
        data = data[:10] + struct.pack('!H', 0) + data[12:]

        # Recompute the IP header checksum
        checksum = 0
        for i in range(0, ipHeaderLength, 2):
            checksum += struct.unpack('!H', data[i:i+2])[0]

        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + ((checksum - (checksum & 0xffff)) >> 16)

        checksum = ~checksum & 0xffff
        self.recentChecksums.append(checksum)
        if len(self.recentChecksums) > 256:
            self.recentChecksums = self.recentChecksums[1:]

        return data[:10] + struct.pack('!H', checksum) + data[12:]

    @staticmethod
    def computeUDPChecksum(ipHeader, udpHeader, data):
        pseudoIPHeader = ipHeader[12:20]+struct.pack('x')+ipHeader[9:10]+udpHeader[4:6]

        udpPacket = pseudoIPHeader+udpHeader[:6]+struct.pack('xx')+data
        if len(udpPacket) % 2:
            udpPacket += struct.pack('x')

        # Recompute the UDP header checksum
        checksum = 0
        for i in range(0, len(udpPacket), 2):
            checksum += struct.unpack('!H', udpPacket[i:i+2])[0]

        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + ((checksum - (checksum & 0xffff)) >> 16)

        checksum = ~checksum & 0xffff
        return udpHeader[:6]+struct.pack('!H', checksum)

    def transmitPacket(self, sock, srcMac, destMac, ipHeaderLength, ipPacket):
        ipHeader  = ipPacket[:ipHeaderLength]
        udpHeader = ipPacket[ipHeaderLength:ipHeaderLength+8]
        data      = ipPacket[ipHeaderLength+8:]
        dontFragment = ipPacket[6]
        if type(dontFragment) == str:
            dontFragment = ord(dontFragment)
        dontFragment = (dontFragment & 0x40) >> 6

        udpHeader = self.computeUDPChecksum(ipHeader, udpHeader, data)

        for boundary in range(0, len(data), self.udpMaxLength):
            dataFragment = data[boundary:boundary+self.udpMaxLength]
            totalLength = len(ipHeader) + len(udpHeader) + len(dataFragment)
            moreFragments = boundary+self.udpMaxLength < len(data)

            flagsOffset = boundary & 0x1fff
            if moreFragments:
                flagsOffset |= 0x2000
            elif dontFragment:
                flagsOffset |= 0x4000

            ipHeader = ipHeader[:2]+struct.pack('!H', totalLength)+ipHeader[4:6]+struct.pack('!H', flagsOffset)+ipHeader[8:]
            ipPacket = self.computeIPChecksum(ipHeader + udpHeader + dataFragment, ipHeaderLength)

            try:
                if srcMac != binascii.unhexlify('00:00:00:00:00:00'.replace(':', '')):
                    etherPacket = destMac + srcMac + self.etherType + ipPacket
                    sock.send(etherPacket)
                else:
                    sock.send(ipPacket)
            except Exception as e:
                if e.errno == errno.ENXIO:
                    raise
                else:
                    self.logger.info('Error sending packet: %s' % str(e))

    def match(self, addr, port):
        return ((addr, port)) in self.bindings

    def loop(self):
        # Record where the most recent SSDP searches came from, to relay unicast answers
        # Note: ideally we'd be more clever and record multiple, but in practice
        #   recording the last one seems to be enough for a 'normal' home SSDP traffic
        #   (devices tend to retry SSDP queries multiple times anyway)
        recentSsdpSearchSrc = {}
        while True:
            if self.remoteAddrs:
                self.connectRemotes()

            additionalListeners = []
            if self.listenSock:
                additionalListeners.append(self.listenSock)
            additionalListeners.extend(self.remoteSockets())

            try:
                (inputready, _, _) = select.select(additionalListeners + self.receivers, [], [], 1)
            except KeyboardInterrupt:
                break
            for s in inputready:
                if s == self.listenSock:
                    (remoteConnection, remoteAddr) = s.accept()
                    if not len(list(filter(lambda addr: PacketRelay.onNetwork(remoteAddr[0], addr[0], PacketRelay.cidrToNetmask(int(addr[1]))), self.listenAddr))):
                        self.logger.info('Refusing connection from %s - not in %s' % (remoteAddr[0], self.listenAddr))
                        remoteConnection.close()
                    else:
                        self.remoteConnections.append(remoteConnection)
                        self.logger.info('REMOTE: Accepted connection from %s' % remoteAddr[0])
                    continue
                else:
                    if s in self.remoteSockets():
                        receivingInterface = 'remote'
                        s.setblocking(1)
                        try:
                            (data, _) = s.recvfrom(2, socket.MSG_WAITALL)
                        except socket.error as e:
                            self.logger.info('REMOTE: Connection closed (%s)' % str(e))
                            self.removeConnection(s)
                            continue

                        if not data:
                            s.close()
                            self.logger.info('REMOTE: Connection closed')
                            self.removeConnection(s)
                            continue

                        size = struct.unpack('!H', data)[0]
                        try:
                            (packet, _) = s.recvfrom(size, socket.MSG_WAITALL)
                        except socket.error as e:
                            self.logger.info('REMOTE: Connection closed (%s)' % str(e))
                            self.removeConnection(s)
                            continue

                        packet = self.aes.decrypt(packet)

                        magic = packet[:len(self.MAGIC)]
                        addr = socket.inet_ntoa(packet[len(self.MAGIC):len(self.MAGIC)+self.IPV4LEN])
                        data = packet[len(self.MAGIC)+self.IPV4LEN:]

                        if magic != self.MAGIC:
                            self.logger.info('REMOTE: Garbage data received, closing connection.')
                            s.close()
                            self.remoteConnection(s)
                            continue

                    else:
                        receivingInterface = 'local'
                        (data, addr) = s.recvfrom(10240)
                        addr = addr[0]

                eighthDataByte = data[8]
                if sys.version_info > (3, 0):
                    eighthDataByte = bytes([data[8]])
                ttl = struct.unpack('B', eighthDataByte)[0]

                if self.ttl:
                    data = data[:8] + struct.pack('B', self.ttl) + data[9:]

                # Use IP checksum information to see if we have already seen this
                # packet, since once we have retransmitted it on an interface
                # we know that we will see it once again on that interface.
                #
                # If we were retransmitting via a UDP socket then we could
                # just disable IP_MULTICAST_LOOP but that won't work as we are
                # using an RAW socket.
                ipChecksum = struct.unpack('!H', data[10:12])[0]
                if ipChecksum in self.recentChecksums:
                    continue

                srcAddr = socket.inet_ntoa(data[12:16])
                dstAddr = socket.inet_ntoa(data[16:20])

                # Compute the length of the IP header so that we can then move past
                # it and delve into the UDP packet to find out what destination port
                # this packet was sent to. The length is encoded in the first least
                # significant nybble of the IP packet and is specified in nybbles.
                firstDataByte = data[0]
                if sys.version_info > (3, 0):
                    firstDataByte = bytes([data[0]])
                ipHeaderLength = (struct.unpack('B', firstDataByte)[0] & 0x0f) * 4
                srcPort = struct.unpack('!H', data[ipHeaderLength+0:ipHeaderLength+2])[0]
                dstPort = struct.unpack('!H', data[ipHeaderLength+2:ipHeaderLength+4])[0]

                # raw sockets cannot be bound to a specific port, so we receive all UDP packets with matching dstAddr
                if receivingInterface == 'local' and not self.match(dstAddr, dstPort):
                    continue

                if self.remoteSockets() and not (receivingInterface == 'remote' and self.noRemoteRelay) and srcAddr != self.ssdpUnicastAddr:
                    packet = self.aes.encrypt(self.MAGIC + socket.inet_aton(addr) + data)
                    for remoteConnection in self.remoteSockets():
                        if remoteConnection == s:
                            continue
                        try:
                            remoteConnection.sendall(struct.pack('!H', len(packet)) + packet)

                            for remote in self.remoteAddrs:
                                if remote['socket'] == remoteConnection and remote['connecting']:
                                    self.logger.info('REMOTE: Connection to %s established' % remote['addr'])
                                    remote['connecting'] = False
                        except socket.error as e:
                            if e.errno == errno.EAGAIN:
                                pass
                            else:
                                self.logger.info('REMOTE: Failed to connect to %s: %s' % (self.remoteAddr, str(e)))
                                self.removeConnection(remoteConnection)
                                continue

                origSrcAddr = srcAddr
                origSrcPort = srcPort
                origDstAddr = dstAddr
                origDstPort = dstPort

                # Record who sent the request
                # FIXME: record more than one?
                destMac = None
                modifiedData = None

                if self.mdnsForceUnicast and dstAddr == PacketRelay.MDNS_MCAST_ADDR and dstPort == PacketRelay.MDNS_MCAST_PORT:
                    data = PacketRelay.mdnsSetUnicastBit(data, ipHeaderLength)

                if self.ssdpUnicastAddr and dstAddr == PacketRelay.SSDP_MCAST_ADDR and dstPort == PacketRelay.SSDP_MCAST_PORT and (re.search(b'M-SEARCH', data) or re.search(b'NOTIFY', data)):
                    recentSsdpSearchSrc = {'addr': srcAddr, 'port': srcPort}
                    self.logger.info('Last SSDP search source: %s:%d' % (srcAddr, srcPort))

                    # Modify the src IP and port to make it look like it comes from us
                    # so as we receive the unicast answers to a well known port (1901)
                    # and can relay them
                    srcAddr = self.ssdpUnicastAddr
                    srcPort = PacketRelay.SSDP_UNICAST_PORT
                    data = PacketRelay.modifyUdpPacket(data, ipHeaderLength, srcAddr=srcAddr, srcPort=srcPort)

                elif self.ssdpUnicastAddr and origDstAddr == self.ssdpUnicastAddr and origDstPort == PacketRelay.SSDP_UNICAST_PORT:
                    if not recentSsdpSearchSrc:
                        # We haven't seen a SSDP multicast request yet
                        continue

                    # Relay the SSDP unicast answer back to the most recent source.
                    # On a network that has heavy SSDP usage, this probably won't
                    # really work as designed: if the unicast reply comes after
                    # another SSDP multicast packet comes in from a different srcAddr
                    # then the reply goes back to the wrong host.
                    dstAddr = recentSsdpSearchSrc['addr']
                    dstPort = recentSsdpSearchSrc['port']
                    self.logger.info('Received SSDP Unicast - received from %s:%d on %s:%d, need to relay to %s:%d' % (origSrcAddr, origSrcPort, origDstAddr, origDstPort, dstAddr, dstPort))
                    data = PacketRelay.modifyUdpPacket(data, ipHeaderLength, dstAddr=dstAddr, dstPort=dstPort)

                    try:
                        destMac = binascii.unhexlify(PacketRelay.unicastIpToMac(dstAddr).replace(':', ''))
                    except Exception as e:
                        self.logger.info('DEBUG: exception while resolving mac of IP %s: %s' % (dstAddr, str(e)))
                        continue

                    # It's possible (though unlikely) we can't resolve the MAC if it's unicast.
                    # In that case, we can't relay the packet.
                    if not destMac:
                        self.logger.info('DEBUG: could not resolve mac for %s' % dstAddr)
                        continue

                # Work out the name of the interface we received the packet on.
                broadcastPacket = False
                if receivingInterface == 'local':
                    for tx in self.transmitters:
                        if origDstAddr == tx['relay']['addr'] and origDstPort == tx['relay']['port'] \
                                and self.onNetwork(addr, tx['addr'], tx['netmask']):
                            receivingInterface = tx['interface']
                            broadcastPacket = (origDstAddr == tx['broadcast'])

                for tx in self.transmitters:
                    # Re-transmit on all other interfaces than on the interface that we received this packet from...
                    if receivingInterface == tx['interface']:
                        continue

                    transmit = True
                    for net in self.ifFilter:
                        (network, netmask) = '/' in net and net.split('/') or (net, '32')
                        if self.onNetwork(srcAddr, network, self.cidrToNetmask(int(netmask))) and tx['interface'] not in self.ifFilter[net]:
                            transmit = False
                            break
                    if not transmit:
                        continue

                    if srcAddr == self.ssdpUnicastAddr and not self.onNetwork(srcAddr, tx['addr'], tx['netmask']):
                        continue

                    if broadcastPacket:
                        dstAddr = tx['broadcast']
                        destMac = self.etherAddrs[PacketRelay.BROADCAST]
                        origDstAddr = tx['broadcast']
                        data = data[:16] + socket.inet_aton(tx['broadcast']) + data[20:]

                    if origDstAddr == tx['relay']['addr'] and origDstPort == tx['relay']['port'] and (self.oneInterface or not self.onNetwork(addr, tx['addr'], tx['netmask'])):
                        destMac = destMac if destMac else self.etherAddrs[dstAddr]

                        if tx['interface'] in self.masquerade:
                            data = data[:12] + socket.inet_aton(tx['addr']) + data[16:]
                            srcAddr = tx['addr']
                        asSrc = '' if srcAddr == origSrcAddr and srcPort == origSrcPort else ' (as %s:%s)' % (srcAddr, srcPort)
                        self.logger.info('%s%s %s byte%s from %s:%s on %s [ttl %s] to %s:%s via %s/%s%s' % (tx['service'] and '[%s] ' % tx['service'] or '',
                                                                                                          tx['interface'] in self.masquerade and 'Masqueraded' or 'Relayed',
                                                                                                          len(data),
                                                                                                          len(data) != 1 and 's' or '',
                                                                                                          origSrcAddr,
                                                                                                          origSrcPort,
                                                                                                          receivingInterface,
                                                                                                          ttl,
                                                                                                          dstAddr,
                                                                                                          dstPort,
                                                                                                          tx['interface'],
                                                                                                          tx['addr'],
                                                                                                          asSrc))

                        try:
                            self.transmitPacket(tx['socket'], tx['mac'], destMac, ipHeaderLength, data)
                        except Exception as e:
                            if e.errno == errno.ENXIO:
                                try:
                                    (ifname, mac, ip, netmask, broadcast) = self.getInterface(tx['interface'])
                                    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                                    s.bind((ifname, 0))
                                    tx['mac'] = mac
                                    tx['netmask'] = netmask
                                    tx['addr'] = ip
                                    tx['socket'] = s
                                    self.transmitPacket(tx['socket'], tx['mac'], destMac, ipHeaderLength, data)
                                except Exception as e:
                                    self.logger.info('Error sending packet: %s' % str(e))

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
            raise IOError('Interface %s does not exist.' % interface)

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

            ipLong = PacketRelay.ip2long(ip)
            netmaskLong = PacketRelay.ip2long(netmask)
            broadcastLong = ipLong | (~netmaskLong & 0xffffffff)
            broadcast = PacketRelay.long2ip(broadcastLong)

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
            return (ifname, binascii.unhexlify(mac.replace(':', '')), ip, netmask, broadcast)
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
        return ip == PacketRelay.BROADCAST

    @staticmethod
    def ip2long(ip):
        """
        Given an IP address (or netmask) turn it into an unsigned long.
        """
        packedIP = socket.inet_aton(ip)
        return struct.unpack('!L', packedIP)[0]

    @staticmethod
    def long2ip(ip):
        """
        Given an unsigned long turn it into an IP address
        """
        return socket.inet_ntoa(struct.pack('!I', ip))

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

    @staticmethod
    def cidrToNetmask(bits):
        return socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << (32 - bits))))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interfaces', nargs='+', required=True,
                        help='Relay between these interfaces (minimum 2).')
    parser.add_argument('--noTransmitInterfaces', nargs='+',
                        help='Do not relay packets via these interfaces, listen only.')
    parser.add_argument('--ifFilter',
                        help='JSON file specifying which interface(s) a particular source IP can relay to.')
    parser.add_argument('--ssdpUnicastAddr',
                        help='IP address to listen to SSDP unicast replies, which will be'
                             ' relayed to the IP that sent the SSDP multicast query.')
    parser.add_argument('--oneInterface', action='store_true',
                        help='Slightly dangerous: only one interface exists, connected to two networks.')
    parser.add_argument('--relay', nargs='*',
                        help='Relay additional multicast address(es).')
    parser.add_argument('--noMDNS', action='store_true',
                        help='Do not relay mDNS packets.')
    parser.add_argument('--mdnsForceUnicast', action='store_true',
                        help='Force mDNS packets to have the UNICAST-RESPONSE bit set.')
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
    parser.add_argument('--listen', nargs='+',
                        help='Listen for a remote connection from one or more remote addresses A.B.C.D.')
    parser.add_argument('--remote', nargs='+',
                        help='Relay packets to remote multicast-relay(s) on A.B.C.D.')
    parser.add_argument('--remotePort', type=int, default=1900,
                        help='Use this port to listen/connect to.')
    parser.add_argument('--remoteRetry', type=int, default=5,
                        help='If the remote connection is terminated, retry at least N seconds later.')
    parser.add_argument('--noRemoteRelay', action='store_true',
                        help='Only relay packets on local interfaces: don\'t relay packets out of --remote connected relays.')
    parser.add_argument('--aes',
                        help='Encryption key for the connection to the remote multicast-relay.')
    parser.add_argument('--foreground', action='store_true',
                        help='Do not background.')
    parser.add_argument('--logfile',
                        help='Save logs to this file.')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output.')
    args = parser.parse_args()

    if len(args.interfaces) < 2 and not args.oneInterface and not args.listen and not args.remote:
        print('You should specify at least two interfaces to relay between')
        return 1

    if args.remote and args.listen:
        print('Relay role should be either --listen or --remote (or neither) but not both')
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

    logger = Logger(args.foreground, args.logfile, args.verbose)

    relays = set()
    if not args.noMDNS:
        relays.add(('%s:%d' % (PacketRelay.MDNS_MCAST_ADDR, PacketRelay.MDNS_MCAST_PORT), 'mDNS'))
    if not args.noSSDP:
        relays.add(('%s:%d' % (PacketRelay.SSDP_MCAST_ADDR, PacketRelay.SSDP_MCAST_PORT), 'SSDP'))
    if not args.noSonosDiscovery:
        relays.add((PacketRelay.BROADCAST+':6969', 'Sonos Setup Discovery'))

    if args.ssdpUnicastAddr:
        relays.add(('%s:%d' % (args.ssdpUnicastAddr, PacketRelay.SSDP_UNICAST_PORT), 'SSDP Unicast'))

    if args.relay:
        for relay in args.relay:
            relays.add((relay, None))

    packetRelay = PacketRelay(interfaces           = args.interfaces,
                              noTransmitInterfaces = args.noTransmitInterfaces,
                              ifFilter             = args.ifFilter,
                              waitForIP            = args.wait,
                              ttl                  = args.ttl,
                              oneInterface         = args.oneInterface,
                              homebrewNetifaces    = args.homebrewNetifaces,
                              ifNameStructLen      = args.ifNameStructLen,
                              allowNonEther        = args.allowNonEther,
                              ssdpUnicastAddr      = args.ssdpUnicastAddr,
                              mdnsForceUnicast     = args.mdnsForceUnicast,
                              masquerade           = args.masquerade,
                              listen               = args.listen,
                              remote               = args.remote,
                              remotePort           = args.remotePort,
                              remoteRetry          = args.remoteRetry,
                              noRemoteRelay        = args.noRemoteRelay,
                              aes                  = args.aes,
                              logger               = logger)

    for relay in relays:
        try:
            (addr, port) = relay[0].split(':')
            _ = PacketRelay.ip2long(addr)
            port = int(port)
        except:
            errorMessage = '%s:%s: Expecting --relay A.B.C.D:P, where A.B.C.D is a multicast or broadcast IP address and P is a valid port number' % relay
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

