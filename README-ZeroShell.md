Installation on ZeroShell
-------------------------

Required ZeroShell packages are the C/C++ development environment
as well as the python interpreter.

Once these are installed, you can then install the netifaces python
package (at the time of writing, it is not installed by default).

From a ZS shell, first enter the development shell:

% develsh

Before you can fetch and install netifaces, you will need to make
the CA certificate for https://pypi.python.org available. Within
this distribution there is a file called 81b9768f.0 - drop that into
/etc/ssl/certs and keep the filename identical.

Now you can fetch and install netifaces:

develsh% easy_install-3.5 netifaces

And thereafter, multicast-relay.py will be able to run as follows:

% python ./multicast-relay.py

