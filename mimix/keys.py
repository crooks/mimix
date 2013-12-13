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
        self.tables = tables
        if 'keyring' not in tables:
            self.create_keyring()
        else:
            self.delete_expired()
        con.commit()

    def create_keyring(self):
        """
        Database Structure
        [ keyid         Text                               Hex Keyid ]
        [ name          Text                      Friendly Shortname ]
        [ address       Text            Address (and port if not 80) ]
        [ pubkey        Text                        Public Key (PEM) ]
        [ seckey        Text                        Secret Key (PEM) ]
        [ validfr       Date                         Valid From Date ]
        [ validto       Date                           Valid To Date ]
        [ advertise     Boolean                   Advertise (Yes/No) ]
        [ smtp          Boolean                   SMTP Exit (Yes/No) ]
        [ uptime        Int  (%)                  Uptime Reliability ]
        [ latency       Int  (Mins)                          Latency ]
        """
        log.info('Creating DB table "keyring"')
        exe('''CREATE TABLE keyring (keyid TEXT, name TEXT, address TEXT,
                                     pubkey TEXT, seckey TEXT, validfr DATE,
                                     validto DATE, advertise INT, smtp INT,
                                     uptime INT, latency INT,
                                     UNIQUE (keyid))''')
        con.commit()

    def delete_expired(self):
        """
        Delete keys that are no longer valid.  This applies to both local and
        remote remailers.  In the case of local, a new seckey will be
        auto-generated if one doesn't exist in the keyring.
        """
        exe('DELETE FROM keyring WHERE date("now") > validto')
        deleted = cur.rowcount
        if deleted > 0:
            log.info("Deleted %s remailer keys", deleted)
        con.commit()

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

    def walk(self, address):
        """
        Start with a single remailer-conf page and fetch the details of its
        local remailer.  This includes a list of other remailers known to that
        remailer.  Each of these is fetched, along with its list of known
        remailers.  Keep going until we no longer discover any new remailers.
        """
        all_remailers = {name: False for name in self.conf_fetch(address)}
        sys.stdout.write("%s: Knew about %s remailers.\n"
                         % (address, len(all_remailers)))
        # This loop will continue until a remailer-conf is fetched that
        # contains no remailers we don't already know about.
        while True:
            updated = False
            for ar in all_remailers.keys():
                if all_remailers[ar]:
                    continue
                # Regardless of success, we set this remailer as processed,
                # otherwise we might infinite loop if it's unavailable.
                all_remailers[ar] = True
                try:
                    remailers = self.conf_fetch(ar)
                except KeyImportError:
                    # During this phase, unavailable remailers can safely
                    # be ignored.
                    continue
                for r in remailers:
                    if r in all_remailers:
                        continue
                    # A new remailer is discovered.  This dictates another
                    # iteration of all remailers.
                    sys.stdout.write("%s reports unknown remailer at %s\n"
                                     % (ar, r))
                    updated = True
                    all_remailers[r] = False
            if not updated:
                # During the last iteration of all_remailers, no new nodes
                # were discovered.
                break
        sys.stdout.write("Walk complete. %s remailers found.\n"
                         % len(all_remailers))

    def conf_fetch(self, address):
        r = requests.get("%s/remailer-conf.txt" % address)
        if r.text is None:
            raise KeyImportError("Could not retreive remailer-conf for %s"
                                 % address)
        keys = {}
        # Known Remailer List.  When processing reaches "Known remailers", the
        # subsequent lines should be known remailer addresses.
        krl = False
        known_remailers = []
        for line in r.text.split("\n"):
            if not line:
                continue
            if not krl and ": " in line:
                key, val = line.split(": ", 1)
                if key == "Valid From":
                    key = "validfr"
                    try:
                        val = timing.dateobj(val)
                    except ValueError:
                        raise KeyImportError("Invalid date format")
                elif key == "Valid To":
                    key = "validto"
                    try:
                        val = timing.dateobj(val)
                    except ValueError:
                        raise KeyImportError("Invalid date format")
                keys[key.lower()] = val
            elif krl and line not in known_remailers:
                known_remailers.append(line)
            if line == 'Known remailers:-':
                krl = True
        b = r.text.rfind("-----BEGIN PUBLIC KEY-----")
        e = r.text.rfind("-----END PUBLIC KEY-----")
        if b >= 0 and e >= 0:
            keys['pubkey'] = r.text[b:e + 24]
        else:
            # Can't import a remailer without a pubkey
            raise KeyImportError("Public key not found")
        try:
            test = RSA.importKey(keys['pubkey'])
        except ValueError:
            raise KeyImportError("Public key is not valid")

        # Date validation section
        if not 'validfr' in keys or not 'validto' in keys:
            raise KeyImportError("Validity period not defined")
        if keys['validfr'] > timing.today():
            raise KeyImportError("Key is not yet valid")
        if keys['validto'] < timing.today():
            raise KeyImportError("Key has expired")
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
            # If there is more than one record with the given address,
            # ambiguity wins.  We don't know which is correct so it's safest to
            # assume neither and start from scratch.
            log.info("Multiple keys known for %s.  Deleting them all and "
                     "querying the remailer directly to ascertain correct "
                     "key.", keys['address'])
            self.delete_address(keys['address'])
        if count == 0:
            # If no record exists for this address, we need to perform an
            # insert operation.  This includes latency and uptime stats where
            # we're forced to make the assumption that this is a fast, reliable
            # remailer.
            log.info("Inserting new remailer: %s <%s>",
                     keys['name'], keys['address'])
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
            log.info("Updating details for %s <%s>",
                     keys['name'], keys['address'])
            values = (keys['name'],
                      keys['keyid'],
                      keys['validfr'],
                      keys['validto'],
                      self.textbool(keys['smtp']),
                      keys['pubkey'],
                      1,
                      keys['address'])
            exe("""UPDATE keyring SET name = ?,
                                      keyid = ?,
                                      validfr = ?,
                                      validto = ?,
                                      smtp = ?,
                                      pubkey = ?,
                                      advertise = ?
                                  WHERE address = ?""", values)
        else:
            raise AssertionError("More than one record for supplied address")
        con.commit()
        return known_remailers


class Server(Client):
    """
    """
    def __init__(self):
        super(Server, self).__init__()
        # On startup, force a daily run
        self.daily_trigger = timing.today()
        if 'idlog' not in self.tables:
            self.create_idlog()
        self.daily_events(force=True)

    def idcount(self):
        exe('SELECT COUNT(pid) FROM idlog')
        return cur.fetchone()[0]

    def create_idlog(self):
        """
        Table Structure
        [ pid           Text                              Message ID ]
        [ date          Date                  Message processed date ]
        """
        log.info('Creating DB table "idlog"')
        exe('CREATE TABLE idlog (pid TEXT, date DATE)')
        con.commit()

    def idlog(self, pid):
        b64pid = pid.encode('base64')
        criteria = (b64pid,)
        exe('SELECT pid FROM idlog WHERE pid = ?', criteria)
        if cur.fetchone():
            log.warn("Packet ID Collision detected")
            return True
        insert = (b64pid, timing.today())
        exe('INSERT INTO idlog (pid, date) VALUES (?, ?)', insert)
        con.commit()
        return False

    def idprune(self):
        numdays = config.getint('general', 'idage')
        criteria = (timing.date_past(days=numdays),)
        exe('DELETE FROM idlog WHERE date <= ?', criteria)
        con.commit()
        log.info("Post-pruning, Packet ID Log contains %s records.",
                 self.idcount())

    def unadvertise(self):
        # Stop advertising keys that expire in the next 28 days.
        criteria = (timing.date_future(days=28),)
        exe('''UPDATE keyring SET advertise = 0
               WHERE (? > validto OR uptime <= 0)
               AND advertise AND seckey IS NOT NULL''', criteria)
        expired = cur.rowcount
        if expired > 0:
            log.info("Expired %s remailer keys", expired)

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
        exe('''INSERT INTO keyring (keyid, name, address, pubkey, seckey,
                                    validfr, validto, advertise, smtp,
                                    uptime, latency)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)''', insert)
        con.commit()
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

    def key_to_advertise(self):
        exe('''SELECT keyid,seckey FROM keyring
                                   WHERE seckey IS NOT NULL
                                   AND validfr <= date("now")
                                   AND date("now") <= validto
                                   AND advertise''')
        data = cur.fetchone()
        if data is None:
            mykey = self.generate()
            log.info("Advertising new Key: %s", mykey[0])
        else:
            mykey = (data[0], RSA.importKey(data[1]))
            log.info("Advertising KeyID: %s", mykey[0])
        self.mykey = mykey
        self.advertise()

    def daily_events(self, force=False):
        """
        Perform once per day events.
        """
        # Bypass daily events unless forced to run them or it's actually a
        # new day.
        if not force and self.daily_trigger >= timing.today():
            return None
        if force:
            log.info("Forced run of daily housekeeping actions.")
        else:
            log.info("Running routine daily housekeeping actions.")
        # Unadvertise and delete expired keys.
        self.unadvertise()
        self.delete_expired()
        # Delete expired records from the Packet ID Log
        self.idprune()
        # If any seckeys expired, it's likely a new key will be needed.  Check
        # what key should be advertised and advertise it.
        self.key_to_advertise()
        # Secret keys are cached when running as a remailer.  This is because
        # the key is required to delete every received message.
        self.sec_cache = {}
        # This is a list of known remailer addresses.  It's referenced each
        # time this remailer functions as an Intermediate Hop.  The message
        # contains the address of the next_hop and this list confirms that
        # address is a known remailer.
        self.known_addresses = self.all_remailers_by_address()
        # Reset the fetch cache.  This cache prevents repeated http GET
        # requests being sent to dead or never there remailers.
        self.fetch_cache = []

        # Set the daily trigger to today's date.
        self.daily_trigger = timing.today()

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
        if data is None or data[0] is None:
            return None
        self.sec_cache[keyid] = RSA.importKey(data[0])
        log.info("%s: Got Secret Key from DB", keyid)
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

    def middle_spy(self, address):
        """
        An active remailer sees the addresses of next-hop remailers.  This
        function checks if each address is known to this remailer.  If not,
        steps are taken to find out about it.
        """
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
        log.debug("Middle spy attempting to fetch: %s", address)
        self.conf_fetch(address)
        self.known_addresses.append(address)


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

    def create(self, chainstr=None):
        """
        This function returns a remailer chain.  The first link in the chain
        being the entry-remailer and the last link, the exit-remailer.  As the
        exit node must meet specific criteria, it is selected first to ensure
        the availability of suitable exit-nodes isn't exhausted during chain
        creation (see 'distance' parameter).  From that point, the chain is
        constructed in reverse.
        """
        if chainstr is None:
            chainstr = config.get('chain', 'chain')
        distance = config.getint('chain', 'distance')
        # nodes is a list of each link in the chain.  Each link can either be
        # randomly selected (Depicted by an '*' or hardcoded (by remailer
        # address).
        nodes = [n.strip() for n in chainstr.split(',')]
        if len(nodes) > 10:
            raise ChainError("Maximum chain length exceeded")
        exit = nodes.pop()
        if exit == "*":
            exits = self.contenders(smtp=True)
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
        self.exit = exit
        # At this point, nodes is a list of the originally submitted chain
        # string, minus the exit.  In order to create chunked messages, that
        # chain must be repeatedly created but with a hardcoded exit node.  To
        # achieve that, the chainstr is reproduced with the exit hardcoded to
        # the exit node selected above.
        exitchain = list(nodes)
        exitchain.append(exit)
        self.exitchain = ",".join(exitchain)

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
        remailers = self.contenders()
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
        self.chain = chain
        self.chainstr = ",".join(chain)
        self.entry = chain[0]
        self.chainlen = len(chain)


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


dbfile = os.path.join(config.get('general', 'dbdir'),
                      config.get('general', 'dbfile'))
con = sqlite3.connect(dbfile)
con.text_factory = str
cur = con.cursor()
exe = cur.execute
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
    c = Chain()
    chain = "*,fleegle,*"
    c.create(chainstr=chain)
    print c.chain
    print c.chainstr
    print c.exit
    print c.chainlen
