#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# webcgi.py - CGI file for storing Mimix messages in a Pool
#
# Copyright (C) 2013 Steve Crook <steve@mixmin.net>
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

import sys
import os.path
from Crypto import Random

def msg(req, base64):
    if base64 is None:
        return "Invalid submission\n";
    if '-----BEGIN MIMIX MESSAGE-----' in base64:
        while True:
            fn = os.path.join('/home/crooks/mimix/inbound_pool',
                             'm' + Random.new().read(4).encode('hex'))
            if not os.path.isfile(fn):
                break
        with open(fn, 'w') as f:
            f.write(base64)
        return "Mimix message submitted";
    else:
        return "Invalid submission\n";
