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

from Config import config
import hashlib
import os.path
import timing
import sqlite3
import sys
import requests
from Crypto.Random import random
from Crypto.PublicKey import RSA


class KeyImportError(Exception):
    pass

def withconn(fn):
    def fn_wrap(*args, **kwargs):
        dbkeys = os.path.join(config.get('database', 'path'),
                              config.get('database', 'directory'))
        with sqlite3.connect(dbkeys) as conn:
            conn.text_factory = str
            retval = fn(conn, *args, **kwargs)
        return retval
    return fn_wrap


def list_tables(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    data = cursor.fetchall()
    if data is None:
        return []
    else:
        return [e[0] for e in data]

def create_keyring(conn):
    """
    Table Structure
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
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE keyring (keyid TEXT, name TEXT,
                   address TEXT, pubkey TEXT, seckey TEXT, validfr DATE,
                   validto DATE, advertise INT, smtp INT, uptime INT,
                   latency INT, UNIQUE (keyid))''')
    conn.commit()


def delete_expired(conn):
    """
    Delete remailer entries that are no longer valid.  This applies to both
    local and remote remailers and isn't specific to Public or Private keys.
    """
    cursor = conn.cursor()
    cursor.execute('DELETE FROM keyring WHERE date("now") > validto')
    conn.commit()
    return cursor.rowcount


def count(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(name) FROM keyring WHERE advertise")
    return cur.fetchone()[0]


def count_addresses(conn, address):
    cursor = conn.cursor()
    criteria = (address,)
    cursor.execute("""SELECT COUNT(address) FROM keyring
                   WHERE address = ? AND advertise""", criteria)
    return int(cursor.fetchone()[0])


def get_public(conn, name):
    """ Public keys are only used during encoding operations (client mode
        and random hops).  Performance is not important so no caching is
        performed.  The KeyID is required as it's encoded in the message
        so the recipient remailer knows which key to use for decryption.
    """
    cursor = conn.cursor()
    cursor.execute("""SELECT keyid,address,pubkey FROM keyring
                   WHERE name=? AND advertise""", (name,))
    data = cursor.fetchone()
    if data is None:
        raise KeystoreError("%s: Unknown remailer name" % name)
    else:
        return (data[0], data[1], RSA.importKey(data[2]))


def all_remailers_by_name(conn, smtp=False):
    """
    Return a list of all known remailers (with public keys).
    If smtp is True, only exit-type remailers will be included.
    """
    cursor = conn.cursor()
    criteria = (smtp,)
    cursor.execute("""SELECT name FROM keyring
                   WHERE pubkey IS NOT NULL AND (smtp OR smtp=?)
                   AND advertise""", criteria)
    data = cursor.fetchall()
    return [e[0] for e in data]


def all_remailers_by_address(conn, smtp=False):
    """
    Return a list of all known remailers (with public keys).
    If smtp is True, only exit-type remailers will be included.
    """
    cursor = conn.cursor()
    criteria = (smtp,)
    cursor.execute("""SELECT address FROM keyring
                   WHERE pubkey IS NOT NULL AND (smtp OR smtp=?)
                   AND advertise""", criteria)
    data = cursor.fetchall()
    return [e[0] for e in data]


def conf_fetch(conn, address):
    cursor = conn.cursor()
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

    # Test we have all the key components required to perform
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
        count = count_addresses(conn, keys['address'])
        if count <= 1:
            break
        # If there is more than one record with the given address,
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
        cursor.execute("""INSERT INTO keyring (name, address, keyid, validfr,
                                               validto, smtp, pubkey,
                                               advertise, uptime, latency)
                          VALUES (?,?,?,?,?,?,?,?,?,?)""", values)
    elif count == 1:
        values = (keys['name'],
                  keys['keyid'],
                  keys['validfr'],
                  keys['validto'],
                  textbool(keys['smtp']),
                  keys['pubkey'],
                  1,
                  keys['address'])
        cursor.execute("""UPDATE keyring SET name = ?,
                                             keyid = ?,
                                             validfr = ?,
                                             validto = ?,
                                             smtp = ?,
                                             pubkey = ?,
                                             advertise = ?
                          WHERE address = ?""", values)
    else:
        raise AssertionError("More than one record for supplied address")
    conn.commit()
    return known_remailers


def walk(conn, address):
    """
    Start with a single remailer-conf page and fetch the details of its
    local remailer.  This includes a list of other remailers known to that
    remailer.  Each of these is fetched, along with its list of known
    remailers.  Keep going until we no longer discover any new remailers.
    """
    cursor = conn.cursor()
    all_remailers = {name: False for name in conf_fetch(conn, address)}
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
                remailers = conf_fetch(conn, ar)
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


def contenders(conn, uptime=None, maxlat=None, minlat=None, smtp=False):
    """
    Find all the known Remailers that meet the selection criteria of
    Uptime, Maximum Latency and Minimum Latency.  An additional criteria
    of SMTP-only nodes can also be stipulated.  Only the remailer name
    is returned.
    """
    cursor = conn.cursor()
    if uptime is None:
        uptime = config.getint('chain', 'uptime')
    if maxlat is None:
        maxlat = config.getint('chain', 'maxlat')
    if minlat is None:
        minlat = config.getint('chain', 'minlat')
    criteria = (uptime, maxlat, minlat, smtp)
    cursor.execute("""SELECT name FROM keyring
                   WHERE uptime>=? AND latency<=? AND latency>=? AND
                   pubkey IS NOT NULL AND (smtp or smtp=?)""", criteria)
    data = cursor.fetchall()
    return [e[0] for e in data]


def unadvertise(conn):
    cursor = conn.cursor()
    # Stop advertising keys that expire in the next 28 days.
    criteria = (timing.date_future(days=28),)
    cursor.execute('''UPDATE keyring SET advertise = 0
                   WHERE (? > validto OR uptime <= 0)
                   AND advertise AND seckey IS NOT NULL''', criteria)
    conn.commit()
    return cursor.rowcount


def server_key(conn):
    """When running as a server, a secret key is required.  This function
       selects one from the DB based on validity criteria.  The return is a
       tuple of (keyid, secret_key).
    """
    cursor = conn.cursor()
    cursor.execute('''SELECT keyid,seckey FROM keyring
                             WHERE seckey IS NOT NULL
                             AND validfr <= date("now")
                             AND date("now") <= validto
                             AND advertise''')
    return cursor.fetchone()


def booltext(boolean):
    if boolean:
        return "Yes"
    else:
        return "No"


def textbool(text):
    if text.lower() == "yes":
        return True
    else:
        return False


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
            delete_expired(con)
        con.commit()


if (__name__ == "__main__"):
    all_remailers_by_address = withconn(all_remailers_by_address)
    print all_remailers_by_address(smtp=True)
