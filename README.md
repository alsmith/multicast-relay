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
that IP forwarding is enabled (echo 1 > /proc/sys/net/ipv4/ip_forward) and
that no firewalling is in place that would prevent connections being
established.

usage: multicast-relay.py [-h] --interfaces INTERFACE INTERFACE [INTERFACE ...] [--relay BROADCAST_OR_MULTICAST:PORT [BROADCAST_OR_MULTICAST:PORT ...]] [--noMDNS] [--noSSDP] [--noSonosDiscovery] [--wait] [--foreground] [--verbose]

--interfaces specifies the >= 2 interfaces that you desire to listen to and
relay between.

--relay specifies additional broadcast or multicast addresses to relay.

--noMDNS disables mDNS relaying.

--noSSDP disables SSDP relaying.

--noSonosDiscovery disables broadcast udp/6969 relaying.

--wait indicates that the relay should wait for an IPv4 address to be assigned
to each interface rather than bailing immediately if an interface is yet to be
assigned an address.

--foreground stops the process forking itself off into the background. This
flag also encourages logging to stdout as well as to the syslog.

--verbose steps up the logging.

multicast-relay.py requires the python 'netifaces' package. Install via
'easy_install netifaces' or 'pip install netifaces'. For ZeroShell users,
please review [README-ZeroShell](README-ZeroShell.md) for further instructions.

-- 
Al Smith <ajs@aeschi.eu>

