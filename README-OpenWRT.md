OpenWRT installation notes
--------------------------

Required OpenWRT packages are 'python3-light' and 'python3-netifaces'.

Note that only interfaces that have IPv4 addresses configured may be used
as parameters to --interfaces. If you have bridges configured then you will
probably need to specify the bridge names and not the underlying interface
names.

