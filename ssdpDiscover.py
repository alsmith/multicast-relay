#!/usr/bin/env python

import argparse
import socket
import sys

"""
Simple script to send a SSDP M-SEARCH message out on a given interface.
"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ifAddr', help='Send out on the interface with the given address.')
    args = parser.parse_args()

    msearch = 'M-SEARCH * HTTP/1.1\r\n' \
              'HOST:239.255.255.250:1900\r\n' \
              'ST:upnp:rootdevice\r\n' \
              'MX:2\r\n' \
              'MAN:"ssdp:discover"\r\n' \
              '\r\n'

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if args.ifAddr:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.ifAddr))

    s.settimeout(2)
    s.sendto(msearch.encode('utf-8'), ('239.255.255.250', 1900))

    try:
        while True:
            data, addr = s.recvfrom(65535)
            try:
                print('%s [%s]' % (socket.gethostbyaddr(addr[0])[0], addr[0]))
            except socket.herror:
                print(addr[0])
            print(data)
    except socket.timeout:
        pass

if __name__ == '__main__':
    sys.exit(main())

