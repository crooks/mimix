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
import sqlite3
import requests
from email.parser import Parser
from Config import config
import mix
import Pool
import timing
import keys
import Chain
import chunker
import sendmail
from daemon import Daemon
from Crypto import Random
from Crypto.Random import random


class Server(Daemon):

    def run(self, conlog=False):
        if not self.validity_check():
            sys.exit(1)
        # Initialize the logger.
        logfmt = config.get('logging', 'format')
        datefmt = config.get('logging', 'datefmt')
        loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                     'warn': logging.WARN, 'error': logging.ERROR}
        global log
        log = logging.getLogger("mimix")
        log.setLevel(loglevels[config.get('logging', 'level')])
        if conlog:
            handler = logging.StreamHandler()
        else:
            filename = os.path.join(config.get('logging', 'dir'),
                                    config.get('logging', 'file'))
            handler = logging.FileHandler(filename, mode='a')
        handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
        log.addHandler(handler)
        event = EventTimer()
        # The inbound pool always processes every message.
        in_pool = Pool.Pool(name='inpool',
                            pooldir=config.get('pool', 'indir'))
        out_pool = Pool.Pool(name='outpool',
                             pooldir=config.get('pool', 'outdir'),
                             interval=config.get('pool', 'interval'),
                             rate=config.getint('pool', 'rate'),
                             size=config.getint('pool', 'size'))
        Random.atfork()
        self.in_pool = in_pool
        self.out_pool = out_pool
        dbkeys = os.path.join(config.get('database', 'path'),
                              config.get('database', 'directory'))
        with sqlite3.connect(dbkeys) as conn:
            keyserv = keys.Server(conn)
            chunks = chunker.Chunker(conn)
            self.keyserv = keyserv
            self.chunks = chunks
            self.conn = conn
            # Loop until a SIGTERM or Ctrl-C is received.
            while True:
                # Every loop, check if it's yet time to perform daily
                # housekeeping actions.  This also clears the Secret Key cache.
                if event.daily_trigger():
                    keyserv.daily_events()
                    expired = chunks.expire()
                    if expired > 0:
                        log.info("Expired %s chunks from the Chunk DB",
                                 expired)
                # Process outbound messages first.  This ensures that no
                # message is received, processed and sent during the same
                # iteration.  Not sure if doing so would be a bad thing for
                # anonymity but not doing is it very unlikely to be bad.
                if out_pool.trigger():
                    self.process_outbound()
                self.process_inbound()
                # Some consideration should probably given to pool trigger
                # times rather than stubbornly looping every minute.
                timing.sleep(60)

    def process_inbound(self):
        """
        Messages from other remailers are stored in the inbound pool.  These
        are periodically processed and written to the outbound pool.  The
        exception to this rule is when we are the final hop in a remailer
        chain.  In this instance the message is delivered and not outbound
        queued.
        """
        self.inject_dummy(config.getint('pool', 'indummy'))
        generator = self.in_pool.select_all()
        for filename in generator:
            m = mix.Decode(self.keyserv)
            try:
                packet_data = m.packet_import(filename)
            except ValueError, e:
                # ValueError is returned when the packet being processed isn't
                # compliant with the specification.  These messages are
                # deleted without further consideration.
                log.debug("Mimix packet read failed with: %s", e)
                self.in_pool.delete(filename)
                continue
            # Process the Base64 component of the message.
            try:
                m.decode(packet_data['binary'])
            except mix.PacketError, e:
                log.info("Decoding failed with: %s", e)
                self.in_pool.delete(filename)
                continue
            if not m.is_exit:
                # Not an exit, write it to the outbound pool.
                self.out_pool.packet_write(m)
            else:
                log.debug("Exit Message: File=%s, MessageID=%s, ChunkNum=%s,"
                          " NumChunks=%s, ExitType=%s",
                          os.path.basename(filename),
                          m.packet_info.messageid.encode('hex'),
                          m.packet_info.chunknum,
                          m.packet_info.numchunks,
                          m.packet_info.exit_type)
                if m.packet_info.exit_type == 0:
                    # Exit and SMTP type: Email it.
                    if (m.packet_info.chunknum == 1 and
                            m.packet_info.numchunks == 1):
                        msg = Parser().parsestr(m.packet_info.payload)
                        sendmail.sendmsg(msg)
                    else:
                        log.debug("Multipart message. Doing chunk processing.")
                        self.chunks.insert(m.packet_info)
                        self.chunks.assemble()
                elif m.packet_info.exit_type == 1:
                    # It's a dummy
                    log.debug("Discarding dummy.")
                else:
                    log.warn("Unknown Exit_Type, discarding.")
            self.in_pool.delete(filename)

    def process_outbound(self):
        """
        Outbound messages are stored in a queue and a random subset of that
        queue is processed each time this function is called (providing there
        are sufficient messages queued to trigger sending.  No processing has
        to be done prior to transmission.  This happens as part of the inbound
        queue processing.
        """
        generator = self.out_pool.select_subset()
        self.inject_dummy(config.getint('pool', 'outdummy'))
        for filename in generator:
            m = mix.Decode(self.keyserv)
            try:
                packet_data = m.packet_import(filename)
            except ValueError, e:
                log.debug("Mimix packet read failed with: %s", e)
                self.out_pool.delete(filename)
                continue
            if not 'next_hop' in packet_data:
                log.error("Outbound pool file with no Next Hop header.")
                self.out_pool.delete(filename)
                continue
            if not 'expire' in packet_data:
                log.error("Outbound pool file with no Expire header.")
                self.out_pool.delete(filename)
                continue
            try:
                expire = timing.dateobj(packet_data['expire'])
            except ValueError, e:
                log.error("Invalid Expire: %s", e)
                self.out_pool.delete(filename)
                continue
            if expire < timing.today():
                # Remailers come and go.  They also fail from time to time.
                # When a message is written to the outbound queue, it's
                # stamped with an expiry date.  If it's still queued after
                # that date, we give up trying to send it.  Sadly, a
                # message is lost but messages can't be queued forever.
                log.warn("Giving up on sending msg to %s.",
                         packet_data['next_hop'])
                #TODO Statistically mark down this remailer.
                self.out_pool.delete(filename)
                continue

            # That's all the packet valdation completed.  From here on, it's
            # about trying to send the message.
            payload = {'base64': packet_data['packet']}
            try:
                # Actually try to send the message to the next_hop.  There are
                # probably a lot of failure conditions to handle at this point.
                recipient = '%s/collector.py/msg' % packet_data['next_hop']
                log.debug("Attempting delivery of %s to %s",
                          os.path.basename(filename), packet_data['next_hop'])
                r = requests.post(recipient, data=payload)
                if r.status_code == requests.codes.ok:
                    self.out_pool.delete(filename)
                else:
                    log.info("Delivery of %s to %s failed with status code: "
                             "%s.  Will keep trying to deliver it.",
                             filename, recipient, r.status_code)
            except requests.exceptions.ConnectionError:
                #TODO Mark down remailer statistics.
                log.info("Unable to connect to %s.  Will keep trying.",
                         recipient)

    def validity_check(self):
        if not config.has_option('general', 'name'):
            sys.stderr.write("Unable to start server: Remailer name is not "
                             "defined.\n")
            return False
        if not config.has_option('general', 'address'):
            sys.stderr.write("Unable to start server: Remailer address is "
                             "not defined.\n")
            return False
        return True

    def inject_dummy(self, odds):
        if random.randint(1, 100) <= odds:
            chain = Chain.Chain(self.conn)
            chain.create(config.get('pool', 'dummychain'))
            log.debug("Injecting Dummy with Chain: %s", chain.chainstr)
            # Encode the message
            exit = mix.ExitEncode()
            # chunks takes: MessageID, ChunkNum, NumChunks
            exit.set_chunks(Random.new().read(16), 1, 1)
            exit.set_exit_type(1)
            exit.set_payload("From: dummy@dummy\nTo: dummy@dummy\n\npayload")
            m = mix.Encode(self.conn)
            m.encode(exit, chain.chain)
            self.out_pool.packet_write(m)


class EventTimer(object):
    def __init__(self):
        self.daily_stamp = timing.today()

    def daily_trigger(self):
        if self.daily_stamp < timing.today():
            # Time to do things!
            self.daily_stamp = timing.today()
            return True
        return False


if (__name__ == "__main__"):
    pidfile = os.path.join(config.get('general', 'piddir'),
                           config.get('general', 'pidfile'))
    errlog = os.path.join(config.get('logging', 'dir'), 'err.log')
    s = Server(pidfile, stderr=errlog)

    # Handle command line args
    if len(sys.argv) >= 1:
        cmd = sys.argv[1]
        if cmd == "--start":
            s.start()
        elif cmd == "--stop":
            s.stop()
        elif cmd == "--run":
            s.run(conlog=True)
