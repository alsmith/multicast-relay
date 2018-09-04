OpenWRT installation notes
--------------------------

Required OpenWRT package is 'python-light'.

However it is missing some prerequisites that argparse requires. Make
a directory called '/usr/lib/python2.7/encodings' and copy the contents
of 'openwrt-python-encodings' into it.

One parameter is required for multicast-relay.py to run on OpenWRT:

  --homebrewNetifaces

For certain OpenWRT architectures, you may also need to set --ifNameStructLen
for multicast-relay to be able to correctly determine interface names. The
default is 40, but you may have more luck setting it to a different value:

  --ifNameStructLen=32

Note that only interfaces that have IPv4 addresses configured may be used
as parameters to --interfaces. If you have bridges configured then you will
probably need to specify the bridge names and not the underlying interface
names.

