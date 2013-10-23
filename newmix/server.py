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


class Server(Daemon):
    def run(self):
        while True:
            process_inbound()
            if out_pool.trigger():
                process_outbound()
            timing.sleep(60)

def process_inbound():
    generator = in_pool.select_all()
    for filename in generator:
        with open(filename, 'r') as f:
            try:
                packet_data = m.packet_read(f.read())
            except ValveError, e:
                log.debug("Newmix packet read failed with: %s", e)
                in_pool.delete(filename)
                continue
            m.decode(packet_data['binary'])
            in_pool.delete(filename)
            if m.is_exit:
                log.info("We got an exit message!!")

def process_outbound():
    generator = out_pool.select_subset()
    for filename in generator:
        with open(filename, 'r') as f:
            try:
                packet_data = m.packet_read(f.read())
            except ValveError, e:
                log.debug("Newmix packet read failed with: %s", e)
                out_pool.delete(filename)
                continue
        if packet_data['expire'] < timing.epoch_days():
            log.warn("Giving up on sending msg to %s.",
                     packet_data['next_hop'])
            out_pool.delete(filename)
            continue
        payload = {'newmix': packet_data['packet']}
        try:
            r = requests.post('http://%s/cgi-bin/webcgi.py'
                              % packet_data['next_hop'],
                              data=payload)
            if r.status_code == requests.codes.ok:
                out_pool.delete(filename)
        except requests.exceptions.ConnectionError:
            log.info("Unable to connect to %s", packet_data['next_hop'])


log = logging.getLogger("newmix.%s" % __name__)
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                 'warn': logging.WARN, 'error': logging.ERROR}
    log = logging.getLogger("newmix")
    log.setLevel(loglevels[config.get('logging', 'level')])
    filename = os.path.join(config.get('logging', 'path'), 'newmix.log')
    handler = logging.StreamHandler()
    #handler = logging.FileHandler(filename, mode='a')
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)

    m = mix.Message()
    in_pool = Pool.Pool(name = 'inpool',
                        pooldir = config.get('pool', 'indir'))
    out_pool = Pool.Pool(name = 'outpool',
                         pooldir = config.get('pool', 'outdir'),
                         interval = config.get('pool', 'interval'),
                         rate = config.getint('pool', 'rate'),
                         size = config.getint('pool', 'size'))
    s = Server(config.get('general', 'pidfile'),
               stderr='/home/crooks/newmix/log/err.log')

    if len(sys.argv) >= 1:
        cmd = sys.argv[1]
        if cmd == "--start":
            s.start()
        elif cmd == "--stop":
            s.stop()
        elif cmd == "--run":
            s.run()
