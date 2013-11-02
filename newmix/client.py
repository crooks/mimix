#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# nymserv.py - A Basic Nymserver for delivering messages to a shared mailbox
# such as alt.anonymous.messages.
#
# Copyright (C) 2012 Steve Crook <steve@mixmin.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import mix
import sys
import keys
import requests

k = keys.Keystore()
m = mix.Message(k)
chain = keys.Chain()
parser = argparse.ArgumentParser(description='Newmix Client')
parser.add_argument('--file', type=str, dest='filename')
parser.add_argument('--stdout', dest='stdout', action='store_true')
parser.add_argument('--chain', type=str, dest='chainstr')
parser.add_argument('--fetch', type=str, dest='fetchurl')
args = parser.parse_args()

if args.fetchurl:
    k.conf_fetch(args.fetchurl)
    sys.exit(0)

# Chain creation
if args.chainstr:
    c = chain.create(chainstr=args.chainstr)
else:
    c = chain.create()

if args.filename:
    with open(args.filename, 'r') as f:
        m.new(f.read(), c)
else:
    sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
    m.new(sys.stdin.read(), c)

if args.stdout:
    sys.stdout.write(m.text())
else:
    payload = {'base64': m.text()}
    recipient = 'http://%s/collector.py/msg' % m.next_hop
    try:
        # Send the message to the first hop.
        r = requests.post(recipient, data=payload)
        if r.status_code == requests.codes.ok:
            sys.stdout.write("Message delivered to %s\n" % m.next_hop)
        else:
            sys.stderr.write("Delivery to %s failed with status code: %s.\n"
                             % (recipient, r.status_code))
    except requests.exceptions.ConnectionError:
        #TODO Mark down remailer statistics.
        sys.stderr.write("Unable to connect to %s.\n" % m.next_hop)
