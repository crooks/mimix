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
import requests
import libkeys
from Crypto.Random import random


class Server(object):
    """
    """
    def __init__(self, conn):
        self.conn = conn
        self.cursor = conn.cursor()
        self.exe = self.cursor.execute
        if 'idlog' not in libkeys.list_tables(conn):
            self.create_idlog()
        self.daily_events()

    def idcount(self):
        self.exe('SELECT COUNT(pid) FROM idlog')
        return self.cursor.fetchone()[0]

    def create_idlog(self):
        """
        Table Structure
        [ pid           Text                              Message ID ]
        [ date          Date                  Message processed date ]
        """
        log.info('Creating DB table "idlog"')
        self.exe('CREATE TABLE idlog (pid TEXT, date DATE)')
        self.conn.commit()

    def idlog(self, pid):
        b64pid = pid.encode('base64')
        criteria = (b64pid,)
        self.exe('SELECT pid FROM idlog WHERE pid = ?', criteria)
        if self.cursor.fetchone():
            log.warn("Packet ID Collision detected")
            return True
        insert = (b64pid, timing.today())
        self.exe('INSERT INTO idlog (pid, date) VALUES (?, ?)', insert)
        self.conn.commit()
        return False

    def idprune(self):
        numdays = config.getint('general', 'idage')
        criteria = (timing.date_past(days=numdays),)
        self.exe('DELETE FROM idlog WHERE date <= ?', criteria)
        self.conn.commit()
        return self.cursor.rowcount

    def unadvertise(self):
        # Stop advertising keys that expire in the next 28 days.
        criteria = (timing.date_future(days=28),)
        exe('''UPDATE keyring SET advertise = 0
               WHERE (? > validto OR uptime <= 0)
               AND advertise AND seckey IS NOT NULL''', criteria)
        return cur.rowcount

    def generate(self):
        log.info("Generating new RSA keys")
        seckey = RSA.generate(config.getint('general', 'keylen'))
        pubkey = seckey.publickey()
        pubpem = pubkey.exportKey(format='PEM')
        keyid = hashlib.md5(pubpem).hexdigest()
        expire = config.getint('general', 'keyvalid')

        insert = (keyid,
                  config.get('general', 'name'),
                  config.get('general', 'address'),
                  pubpem,
                  seckey.exportKey(format='PEM'),
                  timing.today(),
                  timing.date_future(days=expire),
                  1,
                  config.getboolean('general', 'smtp'),
                  100,
                  0)
        self.exe('''INSERT INTO keyring (keyid, name, address, pubkey, seckey,
                                         validfr, validto, advertise, smtp,
                                         uptime, latency)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)''', insert)
        self.conn.commit()
        return (str(keyid), seckey)

    def test_load(self):
        for n in range(0, 10):
            seckey = RSA.generate(1024)
            pubkey = seckey.publickey()
            pubpem = pubkey.exportKey(format='PEM')
            keyid = hashlib.md5(pubpem).hexdigest()
            expire = config.getint('general', 'keyvalid')
            insert = (keyid,
                      'exit_%s' % n,
                      'www.mixmin.net:8080',
                      seckey.exportKey(format='PEM'),
                      pubpem,
                      timing.today(),
                      timing.date_future(days=expire),
                      1,
                      1,
                      100,
                      random.randint(2, 120))
            exe('''INSERT INTO keyring (keyid, name, address, seckey, pubkey,
                                        validfr, validto, advertise, smtp,
                                        uptime, latency)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?)''', insert)
        con.commit()

    def daily_events(self):
        """
        Perform once per day events.
        """
        log.info("Running Keyserver daily housekeeping actions.")
        n = libkeys.unadvertise(self.conn)
        if n > 0:
            log.info("Stopped advertising %s secret keys", n)
        n = libkeys.delete_expired(self.conn)
        if n > 0:
            log.info("Deleted %s keys from the keyring", n)
        # Delete expired records from the Packet ID Log
        n = self.idprune()
        if n > 0:
            log.info("Pruning ID Log removed %s Packet IDs.", n)
        log.info("After pruning, Packet ID Log contains %s entries.",
                 self.idcount())
        # If any seckeys expired, it's likely a new key will be needed.  Check
        # what key should be advertised and advertise it.
        keyinfo = libkeys.server_key(self.conn)
        if keyinfo is None:
            log.info("No valid secret key found.  Generating a new one.")
            mykey = self.generate()
            log.info("Advertising newly generated KeyID: %s", mykey[0])
        else:
            mykey = (keyinfo[0], RSA.importKey(keyinfo[1]))
            log.info("Advertising current KeyID: %s", mykey[0])
        self.advertise(mykey)
        # Secret keys are cached when running as a remailer.  This is because
        # the key is required to decrypt every received message.  Clearing the
        # cache at this point ensures it doesn't become stale with expired
        # keys.
        self.sec_cache = {}
        # This is a list of known remailer addresses.  It's referenced each
        # time this remailer functions as an Intermediate Hop.  The message
        # contains the address of the next_hop and this list confirms that
        # address is a known remailer.
        self.known_addresses = libkeys.all_remailers_by_address(self.conn)
        # Reset the fetch cache.  This cache prevents repeated http GET
        # requests being sent to dead or never there remailers.
        self.fetch_cache = []

        # Set the daily trigger to today's date.
        self.daily_trigger = timing.today()

    def get_secret(self, keyid):
        """ Return the Secret Key object associated with the keyid provided.
            If no key is found, return None.  This function also maintains
            the Secret Key Cache.
        """
        if keyid in self.sec_cache:
            log.debug("Seckey cache hit for %s", keyid)
            return self.sec_cache[keyid]
        log.debug("Seckey cache miss for %s", keyid)
        self.exe('SELECT seckey FROM keyring WHERE keyid=?', (keyid,))
        data = self.cursor.fetchone()
        if data is None or data[0] is None:
            return None
        self.sec_cache[keyid] = RSA.importKey(data[0])
        log.info("%s: Got Secret Key from DB", keyid)
        return self.sec_cache[keyid]

    def advertise(self, mykey):
        # mykey is a tuple of (Keyid, BinarySecretKey)
        criteria = (mykey[0],)
        self.exe("""SELECT name,address,validfr,validto,smtp, pubkey
                 FROM keyring WHERE keyid=?""", criteria)
        name, address, fr, to, smtp, pub = self.cursor.fetchone()
        filename = os.path.join(config.get('http', 'wwwdir'),
                                'remailer-conf.txt')
        smtptxt = libkeys.booltext(smtp)
        f = open(filename, 'w')
        f.write("Name: %s\n" % name)
        f.write("Address: %s\n" % address)
        f.write("KeyID: %s\n" % mykey[0])
        f.write("Valid From: %s\n" % fr)
        f.write("Valid To: %s\n" % to)
        f.write("SMTP: %s\n" % smtptxt)
        f.write("\n%s\n\n" % pub)
        # Only the addresses of known remailers are advertised. It's up to the
        # third party to gather further details directly from the source.  The
        # query only grabs distinct addresses as we only expect to find a
        # single remailer per address, even if multiple keys may be current.
        self.exe('''SELECT DISTINCT address FROM keyring
               WHERE keyid != ? AND advertise''', criteria)
        data = self.cursor.fetchall()
        f.write("Known remailers:-\n")
        for row in data:
            f.write("%s\n" % row)
        f.close()

    def middle_spy(self, address, force_fetch=False):
        """
        An active remailer sees the addresses of next-hop remailers.  This
        function checks if each address is known to this remailer.  If not,
        steps are taken to find out about it.
        """
        # If the address is unknown, steps are taken to find out about it.
        if address in self.known_addresses and not force_fetch:
            return 0
        # Has there already been an attempt to retreive this address
        # today?
        if address in self.fetch_cache:
            log.info("Not trying to fetch remailer-conf for %s.  Already "
                     "attempted today", address)
            return 0
        # If we get to this point, an attempt to retrieve the remailer-conf
        # will be performed.
        self.fetch_cache.append(address)
        log.info("Middle spy attempting to fetch: %s", address)
        try:
            conf_keys = libkeys.fetch_remailer_conf(address)
        except libkeys.KeyImportError, e:
            log.info("Remailer-Conf retrieval failed for %s with error: %s",
                     address, e)
            return 0
        # Check how many records we currently have in the DB for this
        # address.  In theory it should never be more than one but
        # this is a good opportunity to make absolutely sure.
        count = libkeys.count_addresses(self.conn, conf_keys['address'])
        if count > 1:
            # If there is more than one record with the given address,
            # ambiguity wins.  We don't know which is correct so it's safest to
            # assume none and start with the supplied remailer-conf keys.
            self.delete_address(keys['address'])
            count = 0
        if count == 0:
            log.info("Inserting Remailer \"%s\" into our Directory.",
                     conf_keys['name'])
            libkeys.insert_remailer_conf(self.conn, conf_keys)
        elif count == 1:
            log.info("Refreshing Directory entry for Remailer \"%s\"",
                     conf_keys['name'])
            libkeys.update_remailer_conf(self.conn, conf_keys)
        self.known_addresses.append(address)


class Pinger(object):
    def decrement_uptime(address, step):
        criteria = (step, address)
        exe("""UPDATE keyring SET uptime = uptime - ?
               WHERE address = ? AND uptime > 0""", criteria)
        con.commit()

    def increment_uptime(address, step):
        criteria = (step, address)
        exe("""UPDATE keyring SET uptime = uptime + ?
               WHERE address = ? AND uptime < 100""", criteria)
        con.commit()


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
    #ks = Client()
    #print ks.list_remailers()
    dbkeys = os.path.join(config.get('database', 'path'),
                          config.get('database', 'directory'))
    with sqlite3.connect(dbkeys) as conn:
        s = Server(conn)
        s.middle_spy("http://www.mixmin.net:8080", force_fetch=True)
