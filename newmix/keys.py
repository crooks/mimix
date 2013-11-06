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
from Crypto.Random import random


class KeyImportError(Exception):
    pass


class ChainError(Exception):
    pass


class Client(object):
    def __init__(self):
        exe("SELECT name FROM sqlite_master WHERE type='table'")
        data = cur.fetchall()
        if data is None:
            tables = []
        else:
            tables = [e[0] for e in data]
        if 'keyring' not in tables:
            self.create_keyring()
        exe('DELETE FROM keyring WHERE datetime("now") > validto')
        con.commit()

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

    def booltext(self, boolean):
        if boolean:
            return "Yes"
        else:
            return "No"

    def textbool(self, text):
        if text.lower() == "yes":
            return True
        else:
            return False

    def count(self):
        exe("SELECT COUNT(name) FROM keyring WHERE advertise")
        return cur.fetchone()[0]

    def count_addresses(self, address):
        criteria = (address,)
        exe("""SELECT COUNT(address) FROM keyring
               WHERE address = ? AND advertise""", criteria)
        return int(cur.fetchone()[0])

    def all_remailers_by_name(self, smtp=False):
        """
        Return a list of all known remailers (with public keys).
        If smtp is True, only exit-type remailers will be included.
        """
        criteria = (smtp,)
        exe("""SELECT name FROM keyring
               WHERE pubkey IS NOT NULL AND (smtp OR smtp=?)
               AND advertise""", criteria)
        data = cur.fetchall()
        column = 0
        return [e[column] for e in data]

    def all_remailers_by_address(self, smtp=False):
        """
        Return a list of all known remailers (with public keys).
        If smtp is True, only exit-type remailers will be included.
        """
        criteria = (smtp,)
        exe("""SELECT address FROM keyring
               WHERE pubkey IS NOT NULL AND (smtp OR smtp=?)
               AND advertise""", criteria)
        data = cur.fetchall()
        column = 0
        return [e[column] for e in data]

    def list_remailers(self, smtp=False):
        criteria = (smtp,)
        exe("""SELECT name,address,keyid FROM keyring
               WHERE advertise AND (smtp OR smtp=?)""", criteria)
        return cur.fetchall()

    def list_stats(self, smtp=False):
        criteria = (smtp,)
        exe("""SELECT name,address,uptime,
               latency / 60,latency % 60 FROM keyring
               WHERE advertise AND (smtp OR smtp=?) AND
               uptime IS NOT NULL and latency IS NOT NULL
               ORDER BY uptime""", criteria)
        return cur.fetchall()

    def delete_keyid(self, keyid):
        criteria = (keyid,)
        exe("DELETE FROM keyring WHERE keyid = ?", criteria)
        con.commit()
        return cur.rowcount

    def delete_address(self, address):
        criteria = (address,)
        exe("DELETE FROM keyring WHERE address = ?", criteria)
        con.commit()
        return cur.rowcount

    def delete_name(self, name):
        criteria = (name,)
        exe("DELETE FROM keyring WHERE name = ?", criteria)
        con.commit()
        return cur.rowcount

    def toggle_exit(self, name):
        criteria = (name,)
        exe("UPDATE keyring SET smtp = NOT smtp WHERE name = ?", criteria)
        con.commit()
        return cur.rowcount

    def set_latency(self, name, latency):
        assert latency >= 0 and latency <= 60 * 24 * 28
        criteria = (latency, name)
        exe("UPDATE keyring SET latency = ? WHERE name = ?", criteria)
        con.commit()
        return cur.rowcount

    def set_uptime(self, name, uptime):
        assert uptime >= 0 and uptime <= 100
        criteria = (uptime, name)
        exe("UPDATE keyring SET uptime = ? WHERE name = ?", criteria)
        con.commit()
        return cur.rowcount

    def conf_fetch(self, address):
        if '://' in address:
            address = address.split('://', 1)[1]

        conf_page = http.get("http://%s/remailer-conf.txt" % address)
        if conf_page is None:
            raise KeyImportError("Could not retreive remailer-conf for %s"
                                 % address)
        keys = {}
        # Known Remailer List.  When processing reaches "Known remailers", the
        # subsequent lines should be known remailer addresses.
        krl = False
        known_remailers = {}
        for line in conf_page.split("\n"):
            if ": " in line:
                key, val = line.split(": ", 1)
                if key == "Valid From":
                    key = "validfr"
                elif key == "Valid To":
                    key = "validto"
                keys[key.lower()] = val
            elif krl and line not in known_remailers:
                known_remailers[line] = 0
            if line == 'Known remailers:-':
                krl = True
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
            raise KeyImportError("Key digest error")

        # Test we have all the required key components required to perform
        # the forthcoming DB updates.
        required_keys = ['name', 'address', 'keyid', 'validfr', 'validto',
                         'smtp', 'pubkey']
        while required_keys:
            key = required_keys.pop()
            if key not in keys:
                raise KeyImportError("%s: Not found" % key)

        # All checks on the received remailer details are now complete.  From
        # here we're concerned with updating our DB with those details.  The
        # address is used as the key field for inserts/updates as it defines
        # the uniqueness of the remailer to the client.
        while True:
            count = self.count_addresses(keys['address'])
            if count <= 1:
                break
            # If these is more than one record with the given address,
            # ambiguity wins.  We don't know which is correct so it's safest to
            # assume neither and start from scratch.
            self.delete_address(keys['address'])
        if count == 0:
            # If no record exists for this address, we need to perform an
            # insert operation.  This includes latency and uptime stats where
            # we're forced to make the assumption that this is a fast, reliable
            # remailer.
            values = (keys['name'],
                      keys['address'],
                      keys['keyid'],
                      keys['validfr'],
                      keys['validto'],
                      self.textbool(keys['smtp']),
                      keys['pubkey'],
                      1,
                      100,
                      0)
            exe("""INSERT INTO keyring (name, address, keyid, validfr,
                                        validto, smtp, pubkey, advertise,
                                        uptime, latency)
                               VALUES (?,?,?,?,?,?,?,?,?,?)""", values)
        elif count == 1:
            values = (keys['name'],
                      keys['keyid'],
                      keys['validfr'],
                      keys['validto'],
                      self.textbool(keys['smtp']),
                      keys['pubkey'],
                      1,
                      keys['address'])
            exe("""UPDATE keyring SET (name, keyid, validfr,
                                       validto, smtp, pubkey, advertise)
                                  VALUES (?,?,?,?,?,?,?)
                                  WHERE address = ?""", values)
        else:
            raise AssertionError("More than one record for supplied address")
        con.commit()
        return known_remailers


class Keystore(Client):
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

    def update(self):
        # Stop advertising keys that expire in the next 28 days.
        criteria = (timing.timestamp(timing.future(days=28)),)
        exe('''UPDATE keyring SET advertise = 0
               WHERE (? > validto OR uptime <= 0)
               AND advertise AND seckey IS NOT NULL''', criteria)
        # Delete any keys that have expired.
        exe('DELETE FROM keyring WHERE datetime("now") > validto')
        con.commit()
        return cur.rowcount

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
        for n in range(0, 10):
            seckey = RSA.generate(1024)
            pubkey = seckey.publickey()
            pubpem = pubkey.exportKey(format='PEM')
            keyid = hashlib.md5(pubpem).hexdigest()
            insert = (keyid,
                      'exit_%s' % n,
                      'www.mixmin.net:8080',
                      seckey.exportKey(format='PEM'),
                      pubpem,
                      timing.today(),
                      timing.datestamp(timing.future(days=270)),
                      1,
                      1,
                      100,
                      random.randint(2, 120))
            exe('''INSERT INTO keyring (keyid, name, address, seckey, pubkey,
                                        validfr, validto, advertise, smtp,
                                        uptime, latency)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?)''', insert)
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
        criteria = (timing.timestamp(timing.future(days=28)),)
        exe('''UPDATE keyring SET advertise = 0
               WHERE (? > validto OR uptime <= 0)
               AND advertise''', criteria)
        # Delete any keys that have expired.
        exe('DELETE FROM keyring WHERE datetime("now") > validto')
        con.commit()

        # If any seckeys expired, it's likely a new key will be needed.  Check
        # what key should be advertised and advertise it.
        self.key_to_advertise()

        self.sec_cache = {}

        # This is a list of known remailer addresses.  It's referenced each
        # time this remailer functions as an Intermediate Hop.  The message
        # contains the address of the next_hop and this list confirms that
        # is a known remailer.
        self.known_addresses = self.all_remailers_by_address()
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
        filename = os.path.join(config.get('http', 'wwwdir'),
                                'remailer-conf.txt')
        smtptxt = self.booltext(smtp)
        f = open(filename, 'w')
        f.write("Name: %s\n" % name)
        f.write("Address: %s\n" % address)
        f.write("KeyID: %s\n" % self.mykey[0])
        f.write("Valid From: %s\n" % fr)
        f.write("Valid To: %s\n" % to)
        f.write("SMTP: %s\n" % smtptxt)
        f.write("\n%s\n\n" % pub)
        criteria = (self.mykey[0],)
        # Only the addresses of known remailers are advertised. It's up to the
        # third party to gather further details directly from the source.  The
        # query only grabs distinct addresses as we only expect to find a
        # single remailer per address, even if multiple keys may be current.
        exe('''SELECT DISTINCT address FROM keyring
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
                      self.textbool(keys['smtp']),
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


class Chain(Client):
    """
    """
    def contenders(self,
                   uptime=config.getint('chain', 'uptime'),
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
        exe("""SELECT name FROM keyring
               WHERE uptime>=? AND latency<=? AND latency>=? AND
               pubkey IS NOT NULL AND (smtp or smtp=?)""", insert)
        data = cur.fetchall()
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
        exit = nodes.pop()
        if exit == "*":
            exits = self.contenders(uptime=70, maxlat=2880, smtp=True)
            # contenders is a list of exit remailers that don't conflict with
            # any hardcoded remailers within the proximity of "distance".
            # Without this check, the exit remailer would be selected prior to
            # consideration of distance compliance.
            contenders = list(set(exits).difference(nodes[0 - distance:]))
            if len(contenders) == 0:
                raise ChainError("No exit remailers meet selection criteria")
            exit = contenders[random.randint(0, len(exits) - 1)]
        elif exit not in self.all_remailers_by_name(smtp=True):
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
        all_remailers = self.all_remailers_by_name()
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


class Pinger(Client):
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

    def dead_remailers():
        criteria = (timing.timestamp(timing.future(days=28)),)
        exe("""SELECT address FROM keyring
               WHERE NOT advertise AND validto >= ?""", criteria)
        data = cur.fetchall()
        column = 0
        return [e[column] for e in data]


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
    print ks.list_remailers()
