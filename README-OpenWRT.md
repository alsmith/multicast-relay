OpenWRT installation notes
--------------------------

Required OpenWRT package is 'python-light'.

However it is missing some prerequisites that argparse requires. Make
a directory called '/usr/lib/python2.7/encodings' and copy the contents
of 'openwrt-python-encodings' into it.

Two parameters are required for multicast-relay.py to run on OpenWRT
(currently 18.0.1 at the time of writing):

  --homebrewNetifaces
  --ifNameStructLen=32

Note that only interfaces that have IPv4 addresses configured may be used
as parameters to --interfaces. If you have bridges configured then you will
probably need to specify the bridge names and not the underlying interface
names.

