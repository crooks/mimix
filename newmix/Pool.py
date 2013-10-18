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

import sys
import os.path
import logging
from Config import config
from Crypto.Random import random
from Crypto import Random
import timing


class Pool():
    def __init__(self):
        self.next_process = timing.future(mins=1)
        log.info("Initialised pool. Path=%s, Interval=%s, Rate=%s%%, "
                 "Size=%s.",
                 config.get('pool', 'path'),
                 config.get('pool', 'interval'),
                 config.getint('pool', 'rate'),
                 config.getint('pool', 'size'))
        log.debug("First pool process at %s",
                  timing.timestamp(self.next_process))

    def filename(self):
        """ Return a unique, fully-qualified, random filename within the pool
            folder.
        """
        fn = os.path.join(config.get('pool', 'path'),
                          'm' + Random.new().read(4).encode('hex'))
        while os.path.isfile(fn):
            fn = os.path.join(config.get('pool', 'path'),
                              'm' + Random.new().read(4).encode('hex'))
        return fn

    def store(self, msg):
        """ Store a Newmix encoded message as a pool file.
        """
        with open(self.filename(), 'w') as f:
            f.write(msg)

    def foo(self):
        for n in range(500):
            f = open(self.filename(), 'w')
            f.write("\n")
            f.close()
            

    def delete(self, fqfn):
        """Delete files from the Mixmaster Pool."""
        head, tail = os.path.split(fqfn)
        assert head == config.get('pool', 'path')
        os.remove(fqfn)
        log.debug("%s: Deleted", tail)

    def select(self):
        """Pick a random subset of filenames in the Pool and return them as a
        list.  If the Pool isn't sufficiently large, return an empty list.
        """
        poolfiles = os.listdir(config.get('pool', 'path'))
        poolsize = len(poolfiles)
        log.debug("Pool contains %s messages", poolsize)
        if poolsize < config.getint('pool', 'size'):
            # The pool is too small to send messages.
            log.info("Pool is insufficiently populated to trigger sending.")
            return []
        process_num = (poolsize * config.getint('pool', 'rate')) / 100
        log.debug("Attempting to send %s messages from the pool.", process_num)
        assert process_num <= poolsize
        # Shuffle the poolfiles into a random order
        random.shuffle(poolfiles)
        # Even though the list is shuffled, pick a random point in the list to
        # slice from/to.  It does no harm, might do some good and doesn't cost
        # a lot!
        startmax = poolsize - process_num
        if startmax <= 0:
            return poolfiles
        start = random.randint(0, startmax - 1)
        end = start + process_num
        return poolfiles[start:end]


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
    p = Pool()
    print len(p.select())
