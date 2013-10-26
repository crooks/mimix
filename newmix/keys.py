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

class KeyImportError(Exception):
    pass

class Keystore(object):
    """
    """
    def __init__(self):
        log.info("Initializing Keystore")
        exe("""SELECT name FROM sqlite_master
               WHERE type='table' AND name='keyring'""")
        if cur.fetchone() is None:
            self.create_keyring()
        # On startup, force a daily run
        self.daily_events(force=True)

    def create_keyring(self):
        """
        Database Structure
        [ keyid         Text                               Hex Keyid ]
        [ name          Text                      Friendly Shortname ]
        [ address       Text            Address (and port if not 80) ]
        [ pubkey        Text                        Public Key (PEM) ]
        [ seckey        Text                        Secret Key (PEM) ]
        [ validfr       Text (Date)                  Valid From Date ]
        [ validto       Text (Date)                    Valid To Date ]
        [ advertise     Int  (Bool)               Advertise (Yes/No) ]
        [ smtp          Int  (Bool)               SMTP Exit (Yes/No) ]
        [ uptime        Int  (%)                  Uptime Reliability ]
        [ latency       Int  (Mins)                          Latency ]
        """
        log.info('Creating DB table "keyring"')
        exe('''CREATE TABLE keyring (keyid text, name text, address text,
                                     pubkey text, seckey text, validfr text,
                                     validto text, advertise int, smtp int,
                                     uptime int, latency int,
                                     UNIQUE (keyid))''')
        con.commit()

    def generate(self):
        log.info("Generating new RSA keys")
        seckey = RSA.generate(config.getint('general', 'keylen'))
        pubkey = seckey.publickey()
        pubpem = pubkey.exportKey(format='PEM')
        keyid = hashlib.md5(pubpem).hexdigest()

        insert = (keyid,
                  config.get('general', 'name'),
                  config.get('general', 'address'),
                  pubpem,
                  seckey.exportKey(format='PEM'),
                  timing.today(),
                  timing.datestamp(timing.future(days=270)),
                  1,
                  config.getboolean('general', 'smtp'),
                  100,
                  0)
        exe('''INSERT INTO keyring (keyid, name, address, pubkey, seckey,
                                    validfr, validto, advertise, smtp,
                                    uptime, latency)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)''', insert)
        con.commit()
        return str(keyid)

    def test_load(self):
        for n in range(20,25):
            seckey = RSA.generate(1024)
            pubkey = seckey.publickey()
            pubpem = pubkey.exportKey(format='PEM')
            keyid = hashlib.md5(pubpem).hexdigest()
            insert = (keyid,
                      'exit_%s' % n,
                      'exit_%s.com' % n,
                      pubpem,
                      timing.today(),
                      timing.datestamp(timing.future(days=270)),
                      1,
                      1,
                      random.randint(0, 100),
                      random.randint(2, 10080))
            exe('''INSERT INTO keyring (keyid, name, address, pubkey, validfr,
                                        validto, advertise, smtp, uptime,
                                        latency)
                               VALUES (?,?,?,?,?,?,?,?,?,?)''', insert)
        con.commit()

    def key_to_advertise(self):
        while True:
            exe('''SELECT keyid,seckey FROM keyring
                                       WHERE seckey IS NOT NULL
                                       AND validfr <= datetime('now')
                                       AND datetime('now') <= validto
                                       AND advertise''')
            data = cur.fetchone()
            if data is None:
                self.generate()
            else:
                break
        self.mykey = (data[0], RSA.importKey(data[1]))
        log.info("Advertising KeyID: %s", data[0])
        self.advertise()

    def daily_events(self, force=False):
        """
        Perform once per day events.
        """
        # Bypass daily events unless forced to run them or it's actually a
        # new day.
        if not force and self.daily_trigger == timing.epoch_days():
            return None
        if force:
            log.info("Forced run of daily housekeeping actions.")
        else:
            log.info("Running routine daily housekeeping actions.")

        # Stop advertising keys that expire in the next 28 days.
        plus28 = timing.timestamp(timing.future(days=28))
        exe('''UPDATE keyring SET advertise=0
                              WHERE ?>validto AND advertise=1''', (plus28,))
        # Delete any keys that have expired.
        exe('DELETE FROM keyring WHERE datetime("now") > validto')
        con.commit()

        # If any seckeys expired, it's likely a new key will be needed.  Check
        # what key should be advertised and advertise it.
        self.key_to_advertise()
        self.advertise()

        self.sec_cache = {}

        # This is a list of known remailer addresses.  It's referenced each
        # time this remailer functions as an Intermediate Hop.  The message
        # contains the address of the next_hop and this list confirms that
        # is a known remailer.
        exe('SELECT address FROM keyring WHERE advertise')
        data = cur.fetchall()
        self.known_addresses = [c[0] for c in data]
        # Reset the fetch cache.  This cache prevents repeated http GET
        # requests being sent to dead or never there remailers.
        self.fetch_cache = []

        # Set the daily trigger to today's date.
        self.daily_trigger = timing.epoch_days()
        
    def get_public(self, name):
        """ Public keys are only used during encoding operations (client mode
            and random hops).  Performance is not important so no caching is
            performed.  The KeyID is required as it's encoded in the message
            so the recipient remailer knows which key to use for decryption.
        """
        exe("""SELECT keyid,address,pubkey FROM keyring
                                   WHERE name=? AND advertise""", (name,))
        data = cur.fetchone()
        if data is None:
            raise KeystoreError("%s: Unknown remailer name" % name)
        else:
            return (data[0], data[1], RSA.importKey(data[2]))

    def get_secret(self, keyid):
        """ Return the Secret Key object associated with the keyid provided.
            If no key is found, return None.
        """
        if keyid in self.sec_cache:
            log.debug("Seckey cache hit for %s", keyid)
            return self.sec_cache[keyid]
        log.debug("Seckey cache miss for %s", keyid)
        exe('SELECT seckey FROM keyring WHERE keyid=?', (keyid,))
        data = cur.fetchone()
        if data[0] is None:
            return None
        self.sec_cache[keyid] = RSA.importKey(data[0])
        log.debug("Got seckey from DB")
        return self.sec_cache[keyid]

    def advertise(self):
        exe("""SELECT name,address,validfr,validto,smtp, pubkey FROM keyring
                      WHERE keyid=?""", (self.mykey[0],))
        name, address, fr, to, smtp, pub = cur.fetchone()
        f = open("publish.txt", 'w')
        f.write("Name: %s\n" % name)
        f.write("Address: %s\n" % address)
        f.write("KeyID: %s\n" % self.mykey[0])
        f.write("Valid From: %s\n" % fr)
        f.write("Valid To: %s\n" % to)
        f.write("SMTP: %s\n" % smtp)
        f.write("\n%s\n\n" % pub)
        criteria = (self.mykey[0],)
        # Only the addresses of known remailers is advertised.  It's up to the
        # third party to gether further details directly from the source.
        exe('''SELECT address FROM keyring
               WHERE keyid != ? AND advertise''', criteria)
        data = cur.fetchall()
        f.write("Known remailers:-\n")
        for row in data:
            f.write("%s\n" % row)
        f.close()

    def conf_fetch(self, address):
        if address.startswith("http://"):
            log.warn('Address %s should not be prefixed with "http://"',
                     address)
            address = address[7:]
        # If the address is unknown, steps are taken to find out about it.
        if address in self.known_addresses:
            return 0
        # Has there already been an attempt to retreive this address
        # today?
        if address in self.fetch_cache:
            log.info("Not trying to fetch remailer-conf for %s.  Already "
                     "attempted today", address)
            raise KeyImportError("URL retrieval already attempted today")
        self.fetch_cache.append(address)

        #TODO At this point, fetch a URL
        log.debug("Attempting to fetch remailer-conf for %s", address)
        conf_page = http.get("http://%s/remailer-conf.txt" % address)
        if conf_page is None:
            raise KeyImportError("Could not retreive remailer-conf for %s"
                                 % address)
        keys = {}
        for line in conf_page.split("\n"):
            if ": " in line:
                key, val = line.split(": ", 1)
                if key == "Valid From":
                    key = "validfr"
                elif key == "Valid To":
                    key = "validto"
                keys[key.lower()] = val
        b = conf_page.rfind("-----BEGIN PUBLIC KEY-----")
        e = conf_page.rfind("-----END PUBLIC KEY-----")
        if b >= 0 and e >= 0:
            keys['pubkey'] = conf_page[b:e + 24]
        else:
            # Can't import a remailer without a pubkey
            raise KeyImportError("Public key not found")
        try:
            test = RSA.importKey(keys['pubkey'])
        except ValueError:
            raise KeyImportError("Public key is not valid")

        # Date validation section
        try:
            if not 'validfr' in keys or not 'validto' in keys:
                raise KeyImportError("Validity period not defined")
            if timing.dateobj(keys['validfr']) > timing.now():
                raise KeyImportError("Key is not yet valid")
            if timing.dateobj(keys['validto']) < timing.now():
                raise KeyImportError("Key has expired")
        except ValueError:
            raise KeyImportError("Invalid date format")
        # The KeyID should always be the MD5 hash of the Pubkey.
        if 'keyid' not in keys:
            raise KeyImportError("KeyID not published")
        if keys['keyid'] != hashlib.md5(keys['pubkey']).hexdigest():
            print hashlib.md5(keys['pubkey']).hexdigest()
            raise KeyImportError("Key digest error")
        # Convert keys to an ordered tuple, ready for a DB insert.
        try:
            insert = (keys['name'],
                      keys['address'],
                      keys['keyid'],
                      keys['validfr'],
                      keys['validto'],
                      bool(keys['smtp']),
                      keys['pubkey'],
                      1)
        except KeyError:
            # We need all the above keys to perform a valid import
            raise KeyImportError("Import Tuple construction failed")
        exe("""INSERT INTO keyring (name, address, keyid, validfr, validto,
                                    smtp, pubkey, advertise)
                           VALUES (?,?,?,?,?,?,?,?)""", insert)
        con.commit()
        self.known_addresses.append(address)
        return keys['keyid'], keys['pubkey']


    def chain(self):
        return self.known_addresses[0]

con = sqlite3.connect(config.get('general', 'dbfile'))
con.text_factory = str
cur = con.cursor()
exe = cur.execute
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
    ks = Keystore()
    #ks.test_load()
    #ks.conf_fetch("www.mixmin.net")
