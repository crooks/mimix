#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# mimix - A user interface for the Mimix Remailer
#
# Copyright (C) 2014 Steve Crook <steve@mixmin.net>
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
import os.path
import math
import sqlite3
import requests
import libmimix
import Chain
import mix
import server
from Crypto import Random
from email.parser import Parser
from Config import config


def send_msg(args):
    # The Database needs to be open to build Chains and for Mix to encode
    # messages.
    with sqlite3.connect(dbkeys()) as conn:
        conn.text_factory = str
        # Create a message object, either from file or stdin.
        if args.filename:
            with open(args.filename, 'r') as f:
                msg = Parser().parse(f)
        else:
            sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
            msg = Parser().parsestr(sys.stdin.read())

        # Create or override important headers
        if args.recipient:
            msg['To'] = args.recipient
        if args.sender:
            msg['From'] = args.sender
        if args.subject:
            msg['Subject'] = args.subject
        if 'To' not in msg:
            sys.stderr.write("Message has no recipient specified.\nUse "
                             "\"--recipient RECIPIENT_ADDRESS\" "
                             "to add one.\n")
            sys.exit(1)
        if 'From' not in msg:
            msg['From'] = config.get('general', 'sender')

        # Chain creation
        chain = Chain.Chain(conn)
        try:
            chain.create(chainstr=args.chainstr)
        except Chain.ChainError, e:
            sys.stderr.write("Chain Error: %s\n" % e)
            sys.exit(1)
        sys.stdout.write("Chain: \"%s\"\n" % chain.chainstr)

        messageid = Random.new().read(16)
        # Encode the message
        generator = libmimix.chunk(msg)
        # Here begins the loop for each message chunk.
        for c, n, t in generator:
            if c > 1:
                # After each chunk the chain needs to be recreated using the
                # same exit header as the previous pass.
                chain.create(chainstr=chain.exitstr)
            sys.stdout.write("Encoding chunk %s of %s\n" % (c, n))
            exit = mix.ExitEncode()
            exit.set_chunks(messageid, c, n)
            exit.set_exit_type(0)
            exit.set_payload(t)
            m = mix.Encode(conn)
            sys.stdout.write("Chain: %s\n" % chain.chain)
            m.encode(exit, chain.chain)

            if args.stdout:
                sys.stdout.write(m.text)
            else:
                payload = {'base64': m.text}
                url = '%s/collector.py/msg' % m.send_to_address
                try:
                    # Send the message to the first hop.
                    r = requests.post(url, data=payload)
                    if r.status_code == requests.codes.ok:
                        sys.stdout.write("Message delivered to %s\n"
                                         % m.send_to_address)
                    else:
                        sys.stderr.write("Delivery to %s failed with status "
                                         "code: %s.\n" % (url, r.status_code))
                except requests.exceptions.ConnectionError:
                    #TODO Mark down remailer statistics.
                    sys.stderr.write("Unable to connect to %s.\n"
                                     % m.send_to_address)


def keyring_update(args):
    with sqlite3.connect(dbkeys()) as conn:
        conn.text_factory = str
        if 'keyring' not in libmimix.list_tables(conn):
            libmimix.create_keyring(conn)
            sys.stdout.write("Created \"keyring\" table in %s\n" % dbkeys())
        cursor = conn.cursor()
        exe = cursor.execute
        if args.setexit:
            if not args.name:
                sys.stderr.write('Error: --setexit requires '
                                 '--name=remailer_name\n')
            else:
                criteria = (name,)
                exe("""UPDATE keyring SET smtp = NOT smtp
                       WHERE name = ?""", criteria)
                conn.commit()
                sys.stdout.write("Toggled %s exit status for remailer: %s\n"
                                 % (cur.rowcount, args.name))

        if args.latency:
            if not args.name:
                sys.stderr.write("Error: --latency requires "
                                 "--name=remailer_name\n")
            else:
                criteria = (args.latency, args.name)
                exe("UPDATE keyring SET latency = ? WHERE name = ?", criteria)
                conn.commit()
                if cur.rowcount > 0:
                    sys.stdout.write("%s: Latency=%s\n"
                                     % (args.name, args.latency))
                else:
                    sys.stderr.write("Latency not updated for any remailers\n")

        if args.uptime:
            if not args.name:
                sys.stderr.write("Error: --uptime requires "
                                 "--name=remailer_name\n")
            elif args.uptime < 0 or args.uptime > 100:
                sys.stderr.write("Uptime must be in the range 0-100\n")
            else:
                criteria = (args.uptime, args.name)
                exe("UPDATE keyring SET uptime = ? WHERE name = ?", criteria)
                con.commit()
                if cursor.rowcount > 0:
                    sys.stdout.write("%s: Uptime=%s\n"
                                     % (args.name, args.uptime))
                else:
                    sys.stderr.write("Uptime not updated for any remailers\n")

    if args.fetchurl:
        if args.walk:
            remailer_conf_walk(conn, args.fetchurl)
        else:
            remailer_conf(conn, args.fetchurl)

    if args.expire:
        n = libmimix.delete_expired(conn)
        sys.stdout.write("Expired %s remailers\n" % n)


def remailer_info(args):
    with sqlite3.connect(dbkeys()) as conn:
        cursor = conn.cursor()
        criteria = (args.exitonly,)
        if args.listkeys:
            cursor.execute("""SELECT name,address,keyid FROM keyring
                           WHERE advertise AND (smtp OR smtp=?)""", criteria)
            for row in cursor.fetchall():
                sys.stdout.write('%-14s %-30s %32s\n' % row)
        elif args.liststats:
            cursor.execute("""SELECT name,address,uptime,
                           latency / 60,latency % 60 FROM keyring
                           WHERE advertise AND (smtp OR smtp=?) AND
                           uptime IS NOT NULL and latency IS NOT NULL
                           ORDER BY uptime""", criteria)
            for row in cursor.fetchall():
                sys.stdout.write('%-14s %-30s %s%% %s:%02d\n' % row)

        elif args.secret:
            if args.name:
                sk = libmimix.secret_by_name(conn, args.name)
                if sk:
                    sys.stdout.write(sk[0] + "\n")
                else:
                    sys.stderr.write("No secret key found for %s\n"
                                     % args.name)


def remailer_delete(args):
    with sqlite3.connect(dbkeys()) as conn:
        cursor = conn.cursor()
        if args.keyid:
            criteria = (args.keyid,)
            cursor.execute("DELETE FROM keyring WHERE keyid = ?", criteria)
            conn.commit()
            sys.stdout.write("Deleted %s entries\n" % cur.rowcount)
        elif args.address:
            n = libmimix.delete_by_address(conn, args.address)
            sys.stdout.write("Deleted %s entries\n" % n)
        elif args.name:
            criteria = (args.name,)
            cursor.execute("DELETE FROM keyring WHERE name = ?", criteria)
            conn.commit()
            sys.stdout.write("Deleted %s entries\n" % cur.rowcount)


def server_mode(args):
    pidfile = os.path.join(config.get('general', 'piddir'),
                           config.get('general', 'pidfile'))
    errlog = os.path.join(config.get('logging', 'dir'), 'err.log')
    s = server.Server(pidfile, stderr=errlog)
    if args.start:
        s.start()
    elif args.stop:
        s.stop()
    elif args.run:
        s.run(conlog=True)


def dbkeys():
    """Shortcut the simply returns the fully-qualified DB filename.
    """
    return os.path.join(config.get('database', 'path'),
                        config.get('database', 'directory'))


def remailer_conf(conn, url):
    try:
        conf_keys = libmimix.fetch_remailer_conf(url)
    except libmimix.KeyImportError, e:
        sys.stderr.write("Remailer-Conf retrieval failed for %s with "
                         "error: %s\n" % (url, e))
        sys.exit(1)
    sys.stdout.write("Retrieved: %s (AKA %s).\n" % (url, conf_keys['name']))
    count = libmimix.count_addresses(conn, url)
    if count > 1:
        # If there is more than one record with the given address,
        # ambiguity wins.  We don't know which is correct so it's safest to
        # assume none and start with the supplied remailer-conf keys.
        sys.stderr.write("Oops! We have more than one key already on "
                         "file for %s.  Deleting them and using the "
                         "newly retrieved copy.\n" % url)
        n = libmimix.delete_by_address(conn, url)
        sys.stdout.write("Deleted %s records for %s\n" % (n, url))
        count = 0
    # At this point, count can only be 0 or 1.
    assert count == 0 or count == 1
    if count == 0:
        sys.stdout.write("Inserting new Remailer \"%s\" into our Directory.\n"
                         % conf_keys['name'])
        libmimix.insert_remailer_conf(conn, conf_keys)
    elif count == 1:
        sys.stdout.write("Refreshing existing Directory entry for Remailer "
                         "\"%s\"\n" % conf_keys['name'])
        libmimix.update_remailer_conf(conn, conf_keys)
    return conf_keys


def remailer_conf_walk(conn, url):
    conf_keys = remailer_conf(conn, url)
    if 'known' in conf_keys:
        num_known = len(conf_keys['known'])
        if num_known > 0:
            for u in conf_keys['known']:
                remailer_conf(conn, u)
        else:
            sys.stderr.write("%s: No other remailers known\n"
                             % conf_keys['name'])
            sys.exit(1)
    else:
        sys.stderr.write("%s: Has no Known Remailers section in its config."
                         % conf_keys['name'])
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Mimix Client')
    cmds = parser.add_subparsers(help='Commands')

    send = cmds.add_parser('send', help="Send a message")
    send.set_defaults(func=send_msg)
    send.add_argument('--file', type=str, dest='filename',
                      help="Read source message from a file")
    send.add_argument('--stdout', dest='stdout', action='store_true',
                      help=("Write a mimix message to stdout instead of "
                            "sending it to the first hop."))
    send.add_argument('--chain', type=str, dest='chainstr',
                      help="Define the Chain a message should use.")
    send.add_argument('--recipient', type=str, dest='recipient',
                      help="Specify a recipient address (To:)")
    send.add_argument('--sender', type=str, dest='sender',
                      help="Specify a sender address (From:)")
    send.add_argument('--subject', type=str, dest='subject',
                      help="Add a Subject header to the message.")

    update = cmds.add_parser('update', help="Perform keyring updates")
    update.set_defaults(func=keyring_update)
    update.add_argument('--fetch', type=str, dest='fetchurl',
                        help="Fetch a remailer-conf from the specified address")
    update.add_argument('--walk', dest='walk', action='store_true',
                        help=("Follow known_remailer trail to fetch all known "
                              "remailers"))
    update.add_argument('--expire', dest='expire', action='store_true',
                        help="Delete keys/stats for remailers that have expired")
    update.add_argument('--name', type=str, dest='name',
                        help="Specify a remailer name")
    update.add_argument('--setexit', dest='setexit', action='store_true',
                        help="Toggle the exit status for the given name")
    update.add_argument('--uptime', type=int, dest='uptime',
                        help=("Manually set the uptime stats for the specified "
                              "remailer name"))
    update.add_argument('--latency', type=int, dest='latency',
                        help=("Manually set the latency (in minutes) for the "
                              "specified remailer name"))

    info = cmds.add_parser('info', help="Remailer info")
    info.set_defaults(func=remailer_info)
    infogroup = info.add_mutually_exclusive_group(required=True)
    infogroup.add_argument('--keys', dest='listkeys', action='store_true',
                           help="List all known remailers and their keyids")
    infogroup.add_argument('--stats', dest='liststats', action='store_true',
                           help="List all known remailers and their stats")
    infogroup.add_argument('--secret', dest='secret', action='store_true',
                           help="Write a remailer's Secret Key to STDOUT")
    info.add_argument('--exit', dest='exitonly', action='store_true',
                      help="List only exit remailers")
    info.add_argument('--name', type=str, dest='name',
                      help="Pass a Remailer's name as an option")

    delete = cmds.add_parser('delete', help="Delete remailers")
    delete.set_defaults(func=remailer_delete)
    delgroup = delete.add_mutually_exclusive_group(required=True)
    delgroup.add_argument('--keyid', type=str, dest='keyid',
                          help="Delete remailers by keyid")
    delgroup.add_argument('--address', type=str, dest='address',
                          help="Delete remailers by address")
    delgroup.add_argument('--name', type=str, dest='name',
                          help="Delete remailers by short name")

    srvr = cmds.add_parser('server', help="Server mode options")
    srvr.set_defaults(func=server_mode)
    servgroup = srvr.add_mutually_exclusive_group(required=True)
    servgroup.add_argument('--start', dest='start', action='store_true',
                           help="Start the server daemon")
    servgroup.add_argument('--stop', dest='stop', action='store_true',
                           help="Stop the server daemon")
    servgroup.add_argument('--run', dest='run', action='store_true',
                           help="Start the server in a console")

    args = parser.parse_args()
    args.func(args)
    #if args.fetch:

if (__name__ == "__main__"):
    main()
