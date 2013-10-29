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

m = mix.Message()
chain = keys.Chain()
parser = argparse.ArgumentParser(description='Newmix Client')
parser.add_argument('--file', type=str, dest='filename')
parser.add_argument('--stdout', dest='stdout', action='store_true')
args = parser.parse_args()
#TODO Proper chain handling
c = chain.create()
sys.stdout.write('Chain is %s\n' % c)
if args.filename:
    with open(args.filename, 'r') as f:
        m.encode(f.read(), c)
else:
    sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
    m.encode(sys.stdin.read(), c)

if args.stdout:
    sys.stdout.write(m.packet)
