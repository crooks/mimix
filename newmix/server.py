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
import sys
import logging
import os.path
import requests
from Config import config
import mix
import Pool
import timing
from daemon import Daemon

m = mix.Message()
pool = Pool.Pool()

class Server(Daemon):
    def run(self):
        while True:
            self.process_inbound()
            if pool.outbound_trigger:
                self.process_outbound()
            timing.sleep(60)

    def process_inbound(self):
        generator = pool.inbound_select()
        for filename in generator:
            with open(filename, 'r') as f:
                m.decode(f.read().decode('base64'))
                pool.inbound_delete(filename)
                if m.is_exit:
                    print m.text

    def process_outbound(self):
        generator = pool.outbound_select()
        for filename in generator:
            with open(filename, 'r') as f:
                next_hop = f.readline().rstrip()
                expire = f.readline().rstrip()
                payload = {'newmix': f.read()}
            if expire < timing.epoch_days():
                log.warn("Giving up on sending msg to %s." % next_hop)
                pool.outbound_delete(filename)
                continue
            try:
                r = requests.post('http://%s/cgi-bin/webcgi.py' % next_hop,
                                  data=payload)
                if r.status_code == requests.codes.ok:
                    pool.outbound_delete(filename)
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
    filename = os.path.join(config.get('logging', 'path'), 'newmix.log')
    #handler = logging.StreamHandler()
    handler = logging.FileHandler(filename, mode='a')
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
    s = Server(config.get('general', 'pidfile'))
    s.run()
