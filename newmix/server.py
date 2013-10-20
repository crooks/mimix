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
import Pool
import logging
import requests
from Config import config

m = mix.Message()
pool = Pool.Pool()

def process():
    generator = pool.select()
    for filename in generator:
        with open(filename, 'r') as f:
            next_hop = f.readline().rstrip()
            expire = f.readline().rstrip()
            payload = {'newmix': f.read()}
            try:
                r = requests.post('http://%s/cgi-bin/webcgi.py' % next_hop,
                                  data=payload)
                print r.status_code
                if r.status_code == requests.codes.ok:
                    pool.delete(filename)
            except requests.exceptions.ConnectionError:
                log.info("Unable to connect to %s", next_hop)


log = logging.getLogger("newmix.%s" % __name__)
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                 'warn': logging.WARN, 'error': logging.ERROR}
    log = logging.getLogger("newmix")
    log.setLevel(loglevels[config.get('logging', 'level')])
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
    process()
