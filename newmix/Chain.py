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

from Crypto.PublicKey import RSA
from Config import config
import hashlib
import os.path
import timing
import sqlite3
import sys
import logging
import http
from Crypto import Random
from Crypto.Random import random


class ChainError(Exception):
    pass

class Chain(object):
    """
    """
    def __init__(self):
        filename = "directory.db"
        log.debug("Opening database: %s", filename)
        self.conn = sqlite3.connect(filename)
        self.conn.text_factory = str
        self.cur = self.conn.cursor()

    def count(self):
        self.cur.execute("SELECT COUNT(name) FROM keyring")
        return self.cur.fetchone()[0]

    def contenders(self, uptime=config.getint('chain', 'uptime'),
                         maxlat=config.getint('chain', 'maxlat'),
                         minlat=config.getint('chain', 'minlat'),
                         smtp=False):
        """
        Find all the known Remailers that meet the selection criteria of
        Uptime, Maximum Latency and Minimum Latency.  An additional criteria
        of SMTP-only nodes can also be stipulated.  Only the remailer address
        is returned as the valid key is cross-referenced during message
        compilation.
        """
        data = (uptime, maxlat, minlat, smtp)
        self.cur.execute("""SELECT name FROM keyring
                            WHERE uptime>=? AND latency<=? AND latency>=? AND
                            pubkey IS NOT NULL AND (SMTP or SMTP=?)""", data)
        return self.cur.fetchall()

    def create(self, chainstr=config.get('chain', 'chain')):
        # nodes is a list of each link in the chain.
        nodes = [n.lower() for n in chainstr.split(',')]
        exits = self.contenders(uptime=50, maxlat=2880, smtp=True)
        exit = nodes.pop()
        if exit == "*":
            exit = exits[random.randint(0, len(exits) - 1)]
        elif exit not in exits:
            log.error("%s: Invalid hardcoded exit remailer", exit)
            raise ChainError("Invalid exit node")
        chain = [exit]
        distance = [exit]
        return chain

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
    chain = Chain()
    print chain.create()
