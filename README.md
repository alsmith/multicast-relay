Relay SSDP multicast packets between interfaces
-----------------------------------------------

Useful, for example, if you have Sonos speakers on one interface, or VLAN,
and you want to be able to control them from devices on a different
interface/VLAN. This relays SSDP multicast packets received on
239.255.255.250:1900 to other interfaces listed.

usage: ssdp.py [-h] --interfaces INTERFACES [INTERFACES ...] [--foreground] [--verbose]

--interfaces specifies the >= 2 interfaces that you desire to listen to and
relay between.

--foreground stops the process forking itself off into the background. This
flag also encourages logging to stdout as well as to the syslog.

--verbose steps up the logging.


-- 
Al Smith <ajs@aeschi.eu>

