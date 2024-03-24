# openconnect-gp-hip
CSD wrapper Python script compatible with Openconnect with PA Global Protect (globalprotect)

There are numerous CSD wrapper scripts for Palo Alto Networks Global Protect support in Openconnect. All of them seem to just spoof the data that the GP server needs. This script uses the PAN HIP generation tool and modifies the output to make it compatible with Openconnect.

The reason I need this is that the Globalprotect VPN client provided by PA coredumps whenever I attempt to use the command line, and the GUI requires a poorly supported library, Qt5WebKit which was removed from Qt around version 5.4. It has to be hacked up to even get it to compile, and my experience doing this is that it doesn't work. Qt5WebKit was replaced years ago with QtWebEngine. Since I don't run Ubuntu or Red Hat, PAN Globalprotect will not run on my distribution. PAN really should clean up their code mess. This currently works with OpenSUSE 15.5 and Global Protect 6.0.

To use it, when calling openconnect on the command line, add "--csd-wrapper=genhip.py"

Note that a front-end will also be required if OKTA is used.  I use gp-saml-gui https://github.com/dlenski/gp-saml-gui which I modified to pass-through --csd-wrapper.
