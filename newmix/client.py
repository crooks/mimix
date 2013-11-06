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
import mix
import sys
import keys
import requests


def send_msg(args):
    # Chain creation
    if args.chainstr:
        c = chain.create(chainstr=args.chainstr)
    else:
        c = chain.create()
    sys.stdout.write("Chain: %s\n" % ','.join(c))

    if args.filename:
        with open(args.filename, 'r') as f:
            msg = f.read()
    else:
        sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
        msg = sys.stdin.read()

    if args.recipient:
        tohead = "To: %s\n" % args.recipient
        msg = tohead + msg

    # Encode the message
    m = mix.Message(k)
    m.new(msg, c)

    if args.stdout:
        sys.stdout.write(m.text())
    else:
        payload = {'base64': m.text()}
        url = 'http://%s/collector.py/msg' % m.next_hop
        try:
            # Send the message to the first hop.
            r = requests.post(url, data=payload)
            if r.status_code == requests.codes.ok:
                sys.stdout.write("Message delivered to %s\n" % m.next_hop)
            else:
                sys.stderr.write("Delivery to %s failed with status code: %s."
                                 "\n" % (url, r.status_code))
        except requests.exceptions.ConnectionError:
            #TODO Mark down remailer statistics.
            sys.stderr.write("Unable to connect to %s.\n" % m.next_hop)


def keyring_update(args):
    if args.fetchurl:
        if args.walk:
            try:
                k.walk(args.fetchurl)
            except keys.KeyImportError, e:
                sys.stderr.write("%s\n" % e)
        else:
            try:
                k.conf_fetch(args.fetchurl)
            except keys.KeyImportError, e:
                sys.stderr.write("%s\n" % e)
    if args.setexit:
        if not args.name:
            sys.stderr.write('Error: --setexit requires '
                             '--name=remailer_name\n')
        else:
            sys.stdout.write("Toggled %s exit status for remailer: %s\n"
                             % (k.toggle_exit(args.name), args.name))
    if args.latency:
        if not args.name:
            sys.stderr.write("Error: --latency requires "
                             "--name=remailer_name\n")
        else:
            count = k.set_latency(args.name, args.latency)
            if count > 0:
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
            count = k.set_uptime(args.name, args.uptime)
            if count > 0:
                sys.stdout.write("%s: Uptime=%s\n"
                                 % (args.name, args.uptime))
            else:
                sys.stderr.write("Uptime not updated for any remailers\n")


def remailer_info(args):
    if args.listkeys:
        for row in k.list_remailers(smtp=args.exitonly):
            sys.stdout.write('%-14s %-30s %32s\n' % row)
    elif args.liststats:
        for row in k.list_stats(smtp=args.exitonly):
            sys.stdout.write('%-14s %-30s %s%% %s:%02d\n' % row)


def remailer_delete(args):
    if args.keyid:
        count = k.delete_keyid(args.keyid)
    elif args.address:
        count = k.delete_address(args.address)
    elif args.name:
        count = k.delete_name(args.name)

    sys.stdout.write("Deleted %s entries\n" % count)

k = keys.Client()
chain = keys.Chain()
parser = argparse.ArgumentParser(description='Newmix Client')
cmds = parser.add_subparsers(help='Commands')

send = cmds.add_parser('send', help="Send a message")
send.set_defaults(func=send_msg)
send.add_argument('--file', type=str, dest='filename',
                  help="Read source message from a file")
send.add_argument('--stdout', dest='stdout', action='store_true',
                  help=("Write a newmix message to stdout instead of "
                        "sending it to the first hop."))
send.add_argument('--chain', type=str, dest='chainstr',
                  help="Define the Chain a message should use.")
send.add_argument('--recipient', type=str, dest='recipient',
                  help="Specify a recipient address")

update = cmds.add_parser('update', help="Perform keyring updates")
update.set_defaults(func=keyring_update)
update.add_argument('--fetch', type=str, dest='fetchurl',
                    help="Fetch a remailer-conf from the specified address")
update.add_argument('--walk', dest='walk', action='store_true',
                    help="Follow known_remailer trail to fetch all known "
                         "remailers")
update.add_argument('--name', type=str, dest='name',
                    help="Specify a remailer name")
update.add_argument('--setexit', dest='setexit', action='store_true',
                    help="Toggle the exit status for the given name")
update.add_argument('--uptime', type=int, dest='uptime',
                    help=("Manually set the uptime stats for the specified "
                          "remailer name"))
update.add_argument('--latency', type=int, dest='latency',
                    help=("Manually set the latency time for the specified "
                          "remailer name"))

info = cmds.add_parser('info', help="Remailer info")
info.set_defaults(func=remailer_info)
infogroup = info.add_mutually_exclusive_group(required=True)
infogroup.add_argument('--keys', dest='listkeys', action='store_true',
                       help="List all known remailers and their keyids")
infogroup.add_argument('--stats', dest='liststats', action='store_true',
                       help="List all known remailers and their stats")
info.add_argument('--exit', dest='exitonly', action='store_true',
                  help="List only exit remailers")

delete = cmds.add_parser('delete', help="Delete remailers")
delete.set_defaults(func=remailer_delete)
delgroup = delete.add_mutually_exclusive_group(required=True)
delgroup.add_argument('--keyid', type=str, dest='keyid',
                      help="Delete remailers by keyid")
delgroup.add_argument('--address', type=str, dest='address',
                      help="Delete remailers by address")
delgroup.add_argument('--name', type=str, dest='name',
                      help="Delete remailers by short name")

args = parser.parse_args()
args.func(args)
#if args.fetch:
