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
from types import *
from Config import config
from Crypto.Random import random
from Crypto import Random
import timing


class Pool():
    def __init__(self, name, pooldir, interval='1m', rate=100, size=1,
                 expire=7):
        self.trigger_time = timing.future(mins=1)
        self.trigger_hour = timing.future(hours=1)
        assert type(interval) == StringType
        assert type(rate) == IntType
        assert type(size) == IntType
        assert type(expire) == IntType
        self.pooldir = pooldir
        self.interval = interval
        self.rate = rate
        self.size = size
        self.expire = expire
        self.log = logging.getLogger("mimix.%s" % name)

    def filename(self):
        """ Return a unique, fully-qualified, random filename within the pool
            folder.
        """
        while True:
            fn = os.path.join(self.pooldir,
                              'm' + Random.new().read(4).encode('hex'))
            if not os.path.isfile(fn):
                break
        return fn

    def packet_write(self, mixmsg):
        expire = timing.date_future(days=self.expire)
        with open(self.filename(), 'w') as f:
            f.write("Next Hop: %s\n" % mixmsg.next_hop)
            f.write("Expire: %s\n\n" % timing.datestamp(expire))
            f.write(mixmsg.text)

    def trigger(self):
        return timing.now() >= self.trigger_time

    def select_subset(self):
        """Pick a random subset of filenames in the Pool and return them as a
        list.  If the Pool isn't sufficiently large, return an empty list.
        """
        # Set a flag to indicate an hour has passed.
        if self.trigger_hour < timing.now():
            hourly = True
            self.trigger_hour = timing.future(hours=1)
        else:
            hourly = False

        files = os.listdir(self.pooldir)
        numfiles = len(files)
        if hourly:
            self.log.info("Pool contains %s messages", numfiles)
        else:
            self.log.debug("Pool contains %s messages", numfiles)

        if numfiles < self.size:
            # The pool is too small to send messages.
            self.log.debug("Pool is insufficiently populated to trigger "
                           "sending.")
            files = []
            numfiles = 0
        # Without adding the 0.5, a queue containing one message will never
        # send that message.
        process_num = int(numfiles * float(self.rate) / 100 + 0.5)
        if process_num > 0:
            self.log.debug("Attempting to send %s messages from the pool.",
                           process_num)
        assert process_num <= numfiles
        # Shuffle the poolfiles into a random order
        random.shuffle(files)
        # Even though the list is shuffled, pick a random point in the list to
        # slice from/to.  It does no harm, might do some good and doesn't cost
        # a lot!
        startmax = numfiles - process_num
        if startmax == 0:
            start = 0
        else:
            start = random.randint(0, startmax - 1)
        end = start + process_num
        for f in files[start:end]:
            yield os.path.join(self.pooldir, f)
        # Set the point in the future at which another outbound pool run will
        # occur.
        self.trigger_time = timing.dhms_future(self.interval)
        self.log.debug("Next pool run: %s",
                       timing.timestamp(self.trigger_time))

    def delete(self, fqfn):
        """Delete files from the Mixmaster Pool."""
        if os.path.isfile(fqfn):
            head, tail = os.path.split(fqfn)
            assert head == self.pooldir
            os.remove(fqfn)
            self.log.debug("%s: Deleted", tail)
        else:
            self.log.error("%s: File not found during msg deletion", fqfn)

    def select_all(self):
        files = os.listdir(self.pooldir)
        numfiles = len(files)
        if numfiles > 0:
            self.log.debug("Processing %s messages.", numfiles)
        for f in files:
            yield os.path.join(self.pooldir, f)


log = logging.getLogger("mimix.%s" % __name__)
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                 'warn': logging.WARN, 'error': logging.ERROR}
    log = logging.getLogger("mimix")
    log.setLevel(loglevels[config.get('logging', 'level')])
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
    p = Pool('testing', config.get('pool', 'outdir'))
    generator = p.select_subset()
    for f in generator:
        print f
