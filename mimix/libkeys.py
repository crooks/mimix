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


def secret_by_name(conn, name):
    cursor = conn.cursor()
    criteria = (name,)
    cursor.execute("""SELECT seckey FROM keyring
                   WHERE name=? AND seckey IS NOT NULL AND advertise""",
                   criteria)
    return cursor.fetchone()


def delete_by_address(conn, address):
    cursor = conn.cursor()
    criteria = (address,)
    cursor.execute("""DELETE FROM keyring
                      WHERE address = ? AND seckey IS NULL""", criteria)
    conn.commit()
    return cursor.rowcount


def fetch_remailer_conf(url):
    """
    fetch_remailer_conf takes a Remailer base-url and returns the elements of
    its associated remailer-conf as a dictionary.  Some validation of
    elements is performed and a KeyImportError raised if any validation test
    fails.
    """
    r = requests.get("%s/remailer-conf.txt" % url)
    if r.text is None:
        raise KeyImportError("Could not fetch URL")
    sections = r.text.split("\n\n")
    num_sections = len(sections)
    if num_sections < 2 or num_sections > 3:
        raise KeyImportError("Malformed remailer-conf")
    # keys will eventually be a dictionary of all remailer-conf elements but,
    # for now, it's initialized with just the SMTP default.
    keys = {'smtp': False}
    # The first section of the remailer-conf should be colon-spaced key/value
    # pairs.
    for line in sections[0].split("\n"):
        if not ": " in line:
            continue
        key, val = line.split(": ", 1)
        if key == "Valid From":
            key = "validfr"
            try:
                val = timing.dateobj(val)
            except ValueError:
                raise KeyImportError("Invalid date format")
            if val > timing.today():
                raise KeyImportError("Key is not valid yet")
        elif key == "Valid To":
            key = "validto"
            try:
                val = timing.dateobj(val)
            except ValueError:
                raise KeyImportError("Invalid date format")
            if val < timing.today():
                raise KeyImportError("Key has already expired")
        elif key == 'SMTP':
            val = textbool(val)
        keys[key.lower()] = val
    # Second section is the Public Key
    if (sections[1].startswith("-----BEGIN PUBLIC KEY-----") and
            sections[1].endswith("-----END PUBLIC KEY-----")):
        keys['pubkey'] = sections[1]
    else:
        raise KeyImportError("Public Key not found")
    if keys['keyid'] != hashlib.md5(keys['pubkey']).hexdigest():
        raise KeyImportError("Key digest error")
    # Third section is a list of other known remailers.  This section is
    # considered optional.
    if num_sections >= 3:
        known_remailers = sections[2].strip().split("\n")
        # Check that this remailer isn't listed in its own known remailers
        # section.
        if 'address' in keys and keys['address'] in known_remailers:
            known_remailers.remove(keys['address'])
        if known_remailers.pop(0).startswith("Known remailers"):
            keys['known'] = known_remailers
    return keys


def insert_remailer_conf(conn, keys):
    cursor = conn.cursor()
    # If no record exists for this address, we need to perform an
    # insert operation.  This includes latency and uptime stats where
    # we're forced to make the assumption that this is a fast, reliable
    # remailer.
    values = (keys['name'],
              keys['address'],
              keys['keyid'],
              keys['validfr'],
              keys['validto'],
              keys['smtp'],
              keys['pubkey'],
              1,
              100,
              0)
    cursor.execute("""INSERT INTO keyring (name, address, keyid, validfr,
                                           validto, smtp, pubkey,
                                           advertise, uptime, latency)
                      VALUES (?,?,?,?,?,?,?,?,?,?)""", values)
    conn.commit()


def update_remailer_conf(conn, keys):
    cursor = conn.cursor()
    values = (keys['name'],
              keys['keyid'],
              keys['validfr'],
              keys['validto'],
              keys['smtp'],
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
    conn.commit()


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


if (__name__ == "__main__"):
    print fetch_remailer_conf("http://www.mixmin.net:8080")
    sys.exit(0)
    dbkeys = os.path.join(config.get('database', 'path'),
                          config.get('database', 'directory'))
    with sqlite3.connect(dbkeys) as conn:
        pass
