Relay multicast packets between interfaces
------------------------------------------

Useful, for example, if you have Sonos speakers on one interface, or VLAN,
and you want to be able to control them from devices on a different
interface/VLAN.

By default, SSDP multicast packets received on 239.255.255.250:1900 are
relayed other interfaces listed, as well as multicast DNS packets received
on 224.0.0.251:5353.

usage: multicast-relay.py [-h] --interfaces INTERFACES [INTERFACES ...] [--relay MULTICAST:PORT [MULTICAST:PORT ...] [--noMDNS] [--noSSDP] [--foreground] [--verbose]

--interfaces specifies the >= 2 interfaces that you desire to listen to and
relay between.

--relay specifies additional multicast addresses to relay.

--noMDNS disables mDNS relaying.

--noSSDP disables SSDP relaying.

--foreground stops the process forking itself off into the background. This
flag also encourages logging to stdout as well as to the syslog.

--verbose steps up the logging.


Al Smith <ajs@aeschi.eu>

