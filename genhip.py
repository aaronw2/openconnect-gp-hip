#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Copyright (C) 2024 by Aaron Williams
# This script is released under the GPL 2.0 license
#
# This script makes use of the Palo Alto Networks HIP tool to generate a
# HIP report for openconnect that is compatible with Global Protect 6.x.
# This requires that Global Protect 6.x is installed and defaults to
# /opt/paloaltonetworks/globalprotect
# This uses the PA HIP generation tool and modifies the XML to fill in
# a few missing fields.  Note that this does not work if PanGpHip is
# not installed.
#
# I wrote this because Global Protect VPN software crashes or otherwise does
# not work with my Linux distribution (OpenSUSE).  While I could just use
# one of the numerous scripts available and spoof the XML report, that is
# getting around the purpose of the report which is to report which
# anti-virus and other tools are installed without cheating.
#
# I'm no expert when it comes to XML manipulation and I'm sure there has
# to be some better method of importing and exporting the data without
# using files.  I use BytesIO streams instead of temporary files, but it
# would be nice if I could just feed in the output from HIP directly.

import os
import io
import sys
import argparse
import xml.etree.ElementTree as ET
import subprocess
import urllib.parse

DEBUG = os.getenv('HIPTOOL_DEBUG', None)

PA_PATH = os.getenv('PA_GP_PATH', '/opt/paloaltonetworks/globalprotect')
PA_HIP_TOOL = os.getenv('PA_GP_HIP', os.path.join(PA_PATH, 'PanGpHip'))
GENHIP_LOG_FILE = os.getenv('GENHIP_LOG_FILE', '/tmp/openconnect-hipreport.log')
OS_RELEASE_FILE = '/etc/os-release'

if DEBUG:
    LOGFILE = open(GENHIP_LOG_FILE, 'w', encoding='utf-8')
else:
    LOGFILE = None

def logprint(*args, **kwargs):
    if LOGFILE:
        print(*args, file=LOGFILE, **kwargs)

def get_release():
    '''Returns Linux OS release information'''
    logprint('Getting release...')
    name = None
    version = None
    pretty = None
    with open(OS_RELEASE_FILE, 'r', encoding='utf-8') as inf:
        lines = inf.readlines()
        for line in lines:
            line = line.strip()
            tokens = line.split('=')
            value = tokens[1].strip('"')
            if tokens[0] == 'NAME':
                name = value
            elif tokens[0] == 'VERSION':
                version = value
            elif tokens[0] == 'PRETTY_NAME':
                pretty = value

        if pretty:
            logprint(f'Release: {pretty}')
            return pretty
        if name and version:
            logprint(f'{name} {version}')
            return name + ' ' + version
    return None

def get_pa_hip_report(user, domain, computer, ipaddr, md5, client_os):
    """Returns an XML HIP report string as needed by openvpn"""
    logprint("Getting HIP report...")
    index = 1
    ips = ipaddr.split(',', 2)
    ip4 = ips[0]
    if len(ips) > 1:
        ip6 = ips[1]
    else:
        ip6 = None

    cmdline = [PA_HIP_TOOL]
    cwd = os.getcwd()
    os.chdir(PA_PATH)
    logprint('Running', cmdline)
    # The output of the PA HIP tool is actually two XML files.
    proc = subprocess.Popen(cmdline,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    os.chdir(cwd)
    # The first 10 characters appear to be a length
    stdout = stdout[10:]
    # The output is also two concatenated XML files, we only care about
    # the second one.
    logprint(f'HIP stderr:\n{stderr.decode()}')
    logprint(f'HIP output:\n{stdout.decode()}')

    root = ET.fromstring(stdout)
    tree = ET.ElementTree(root)
    tree = ET.ElementTree(root)
    biostream = io.BytesIO()
    tree.write(biostream, encoding='utf-8', method='xml')

    x_md5 = ET.Element('md5-sum')
    x_md5.text = md5
    root.insert(index, x_md5)
    index += 1
    x_username = ET.Element('user-name')
    x_username.text = user
    root.insert(index, x_username)
    index += 1
    x_domain = ET.Element('domain')
    x_domain.text = domain
    root.insert(index, x_domain)
    index += 1
    x_host = ET.Element('host-name')
    x_host.text = computer
    root.insert(index, x_host)
    index += 1
    x_ip = ET.Element('ip-address')
    x_ip.text = ip4
    root.insert(index, x_ip)
    index += 1
    if ip6:
        x_ip6 = ET.Element('ipv6-address')
        x_ip6.text = ip6
        root.insert(index, x_ip6)
        index += 1
    os_info = root.find("./categories/entry[@name='host-info']/os")
    os_info.text = get_release()
    biostream = io.BytesIO()
    tree.write(biostream, encoding='utf-8', method='xml')
    return biostream.getvalue().decode()

def main():
    parser = argparse.ArgumentParser(description="Generates a HIP report")
    parser.add_argument('--cookie', dest='cookie', help='Cookie to put in report')
    parser.add_argument('--client-ip', dest='ip', help='Client IP address')
    parser.add_argument('--md5', dest='md5', help='MD5 value to add')
    parser.add_argument('--client-os', dest='os', help='Client operating system')
    args = parser.parse_args()
    cookie = urllib.parse.parse_qs(args.cookie)
    user = cookie['user'][0]
    domain = cookie['domain'][0]
    computer = cookie['computer'][0]
    logprint(f'Decoded cookie: {cookie}')
    output = get_pa_hip_report(user, domain, computer, args.ip, args.md5, args.os)
    print(output)
    logprint(f'Output:\n{output}')
    return 0

if __name__ == '__main__':
    sys.exit(main())

# kate: indent-mode python; indent-width 4; space-indent on;
