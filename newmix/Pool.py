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
        self.outbound_trigger_time = timing.future(mins=1)
        log.info("Initialised pool. Path=%s, Interval=%s, Rate=%s%%, "
                 "Size=%s.",
                 config.get('pool', 'outbound_pool'),
                 config.get('pool', 'interval'),
                 config.getint('pool', 'rate'),
                 config.getint('pool', 'size'))
        log.debug("First pool process at %s",
                  timing.timestamp(self.outbound_trigger_time))

    def filename(self):
        """ Return a unique, fully-qualified, random filename within the pool
            folder.
        """
        fn = os.path.join(config.get('pool', 'outbound_pool'),
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

    def outbound_trigger(self):
        return timing.now() >= self.outbound_trigger_time

    def outbound_select(self):
        """Pick a random subset of filenames in the Pool and return them as a
        list.  If the Pool isn't sufficiently large, return an empty list.
        """
        files = os.listdir(config.get('pool', 'outbound_pool'))
        size = len(files)
        log.debug("Pool contains %s messages", size)
        if size < config.getint('pool', 'size'):
            # The pool is too small to send messages.
            log.info("Pool is insufficiently populated to trigger sending.")
            files = []
            size = 0
        process_num = (size * config.getint('pool', 'rate')) / 100
        log.debug("Attempting to send %s messages from the pool.", process_num)
        assert process_num <= size
        # Shuffle the poolfiles into a random order
        Random.atfork()
        random.shuffle(files)
        # Even though the list is shuffled, pick a random point in the list to
        # slice from/to.  It does no harm, might do some good and doesn't cost
        # a lot!
        startmax = size - process_num
        if startmax == 0:
            start = 0
        else:
            start = random.randint(0, startmax - 1)
        end = start + process_num
        for f in files[start:end]:
            yield os.path.join(config.get('pool', 'outbound_pool'), f)
        # Set the point in the future at which another outbound pool run will
        # occur.
        next_outbound = timing.dhms_future(config.get('pool', 'interval'))
        self.outbound_trigger_time = next_outbound
        log.debug("Next outbound pool run: %s",
                  timing.timestamp(self.outbound_trigger_time))

    def outbound_delete(self, fqfn):
        """Delete files from the Mixmaster Pool."""
        if os.path.isfile(fqfn):
            head, tail = os.path.split(fqfn)
            assert head == config.get('pool', 'outbound_pool')
            os.remove(fqfn)
            log.debug("%s: Deleted", tail)
        else:
            log.error("%s: File not found during outbound msg deletion",
                      fqfn)

    def inbound_select(self):
        """Pick a random subset of filenames in the Pool and return them as a
        list.  If the Pool isn't sufficiently large, return an empty list.
        """
        files = os.listdir(config.get('pool', 'inbound_pool'))
        log.debug("Processing %s inbound messages in store.", len(files))
        for f in files:
            yield os.path.join(config.get('pool', 'inbound_pool'), f)

    def inbound_delete(self, fqfn):
        """Delete files from the Mixmaster Pool."""
        if os.path.isfile(fqfn):
            head, tail = os.path.split(fqfn)
            assert head == config.get('pool', 'inbound_pool')
            os.remove(fqfn)
            log.debug("%s: Deleted", tail)
        else:
            log.error("%s: File not found during inbound msg deletion",
                      fqfn)


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
    generator = p.outbound_select()
    for f in generator:
        print f
