Relay broadcast and multicast packets between interfaces
--------------------------------------------------------

Useful, for example, if you have Sonos speakers on one interface, or VLAN,
and you want to be able to control them from devices on a different
interface/VLAN. Similar for Chromecast devices.

By default, SSDP multicast packets received on 239.255.255.250:1900 are
relayed to the other interfaces listed, as well as multicast DNS packets
received on 224.0.0.251:5353.

Broadcast UDP packets received on port 6969 are also relayed by default:
this is used by Sonos during the initial device-discovery phase, initiated
by pressing either the infinity button or the play+volume up buttons,
depending on your Sonos speaker.

Please note that even when your devices have discovered one another, at
least in the Sonos case, a unicast connection will be established from
the speakers back to the controlling-telephone. You will need to make sure
that IP forwarding is enabled (`echo 1 > /proc/sys/net/ipv4/ip_forward`) and
that no firewalling is in place that would prevent connections being
established.

`usage: multicast-relay.py [-h] --interfaces INTERFACE INTERFACE [INTERFACE ...] [--noTransmitInterfaces INTERFACE ...] [-ifFilter IFFILTER] [--relay BROADCAST_OR_MULTICAST:PORT [BROADCAST_OR_MULTICAST:PORT ...]] [--noMDNS] [--noSSDP] [--noSonosDiscovery] [--oneInterface] [--homebrewNetifaces] [--wait] [--listen REMOTE_ADDRESS [REMOTE_ADDRESS ...]] [--remote REMOTE_ADDRESS] [--remotePort PORT] [--remoteRetry SECS] [--foreground] [--logfile FILE] [--verbose]`

`--interfaces` specifies the >= 2 interfaces that you desire to listen to and
relay between. You can specify an interface by name, by IP address, or by
network/netmask combination (e.g. 10.0.0.0/24 in the last case). With certain
flags below, the minimum number of interfaces drops to >= 1.

`--noTransmitInterfaces` specifies interface(s) that are listen-only.

`--ifFilter` specifies a JSON file where one can state that a source address
A.B.C.D/M is only to be relayed to specific interfaces. This can be useful
in applications such as a hotel where relaying for one guest room may only
discover device(s) that are in the same guest room. See example file
`ifFilter.json`.

`--relay` specifies additional broadcast or multicast addresses to relay.

`--noMDNS` disables mDNS relaying.

`--noSSDP` disables SSDP relaying.

`--noSonosDiscovery` disables broadcast udp/6969 relaying.

`--oneInterface` support for one interface connected to two networks. Use with
caution - watch out for packet storms (although the IP checksum list ought
to still prevent such a thing from happening).

`--homebrewNetifaces` attempt to use our own netifaces implementation, probably
doesn't work on any other system than Linux but maybe useful for OpenWRT where
it's rather tricky to compile up netifaces.

`--allowNonEther` supports non-ethernet interfaces to be relayed [experimental].

`--wait` indicates that the relay should wait for an IPv4 address to be assigned
to each interface rather than bailing immediately if an interface is yet to be
assigned an address.

`--listen` for connections from the specified remote host(s) or network(s), for example `--listen 10.0.0.1 192.168.0.0/16`.

`--remote` connect to the specified remote host. If either --listen or --remote
are specified, then one can also specify just one local interface with --interfaces.

`--remotePort` use the specified port for remote communications (default: 1900).

`--remoteRetry` if the remote connection fails, wait at least this number of seconds before retrying (default: 5).

`--aes` use the specified string to encrypt/decrypt data packets.

`--foreground` stops the process forking itself off into the background. This
flag also encourages logging to stdout as well as to the syslog.

`--logfile` saves log data to the specified file.

`--verbose` steps up the logging.

multicast-relay.py requires the python 'netifaces' package. Install via
'easy_install netifaces' or 'pip install netifaces'. For ZeroShell users,
please review [README-ZeroShell](README-ZeroShell.md) for further instructions.

Al Smith <ajs@aeschi.eu>

