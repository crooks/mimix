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
        filename = config.get('general', 'dbfile')
        log.debug("Opening database: %s", filename)
        self.conn = sqlite3.connect(filename)
        self.conn.text_factory = str
        self.cur = self.conn.cursor()

    def count(self):
        self.cur.execute("SELECT COUNT(name) FROM keyring")
        return self.cur.fetchone()[0]

    def all_remailers(self, smtp=False):
        """
        Return a list of all known remailers (with public keys).
        If smtp is True, only exit-type remailers will be included.
        """
        insert = (smtp,)
        self.cur.execute("""SELECT name FROM keyring
                            WHERE pubkey IS NOT NULL AND (smtp or smtp=?)""",
                            insert)
        data =  self.cur.fetchall()
        column = 0
        return [e[column] for e in data]

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
        insert = (uptime, maxlat, minlat, smtp)
        self.cur.execute("""SELECT name FROM keyring
                            WHERE uptime>=? AND latency<=? AND latency>=? AND
                            pubkey IS NOT NULL AND (smtp or smtp=?)""", insert)
        data =  self.cur.fetchall()
        column = 0
        return [e[column] for e in data]

    def create(self, chainstr=config.get('chain', 'chain')):
        """
        This function returns a remailer chain.  The first link in the chain
        being the entry-remailer and the last link, the exit-remailer.  As the
        exit node must meet specific criteria, it is selected first to ensure
        the availability of suiable exit-nodes isn't exhausted during chain
        creation (see 'distance' parameter).  From that point, the chain is
        constructed in reverse.
        """
        distance = config.get('chain', 'distance')
        # nodes is a list of each link in the chain.  Each link can either be
        # randomly selected (Depicted by an '*' or hardcoded (by remailer
        # address).
        nodes = [n.strip() for n in chainstr.split(',')]
        exits = self.contenders(uptime=70, maxlat=2880, smtp=True)
        # contenders is a list of exit remailers that don't conflict with any
        # hardcoded remailers within the proximity of "distance".  Without
        # this check, the exit remailer would be selected prior to
        # consideration of distance compliance.
        contenders = list(set(exits).difference(nodes[0 - distance:]))
        if len(contenders) == 0:
            raise ChainError("No exit remailers meet selection criteria")
        exit = nodes.pop()
        if exit == "*":
            exit = contenders[random.randint(0, len(exits) - 1)]
        elif exit not in exits:
            log.error("%s: Invalid hardcoded exit remailer", exit)
            raise ChainError("Invalid exit node")
        chain = [exit]
        # If the requested chain only contained a single remailer, bail out
        # at this point and save some cycles.
        if not nodes:
            return chain
        # distance_exclude is a list of the remailers in close proximity to
        # the node currently being selected.  It prevents a single remailer
        # from occupying two overly-proximate links.
        distance_exclude = [exit]
        # All remailers is used to check that hardcoded links are all known
        # remailers.
        all_remailers = self.all_remailers()
        remailers = self.contenders(uptime=50, maxlat=2880)
        # If processing reaches this point, at least one remailer (besides an
        # exit) is required.  If we have none to choose from, raise an error.
        if len(remailers) == 0:
            raise ChainError("Insufficient remailers meet selection criteria")
        # Loop until all the links have been popped off the nodes stack.
        while nodes:
            if len(distance_exclude) >= distance:
                distance_exclude.pop(0)
            remailer = nodes.pop()
            if remailer == "*":
                # During random selection, only nodes in the remailers list
                # and not in the distance list can be considered.
                contenders = list(set(remailers).difference(distance_exclude))
                num_contenders = len(contenders)
                if num_contenders == 0:
                    raise ChainError("Insufficient remailers to comply with "
                                     "distance criteria")
                # Pick a random remailer from the list of potential contenders
                remailer = contenders[random.randint(0, num_contenders - 1)]
            elif remailer not in all_remailers:
                log.error("%s: Invalid hardcoded remailer", remailer)
                raise ChainError("Invalid remailer")
            # The newly selected remailer becomes the first link in chain.
            chain.insert(0, remailer)
            distance_exclude.append(remailer)
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
    print chain.create(chainstr='*,*,test_15,*,*')
