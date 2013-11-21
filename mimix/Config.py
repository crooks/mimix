#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# Config.py - Configuration parser for the Mimix Remailer
#
# Copyright (C) 2013 Steve Crook <steve@mixmin.net>
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

import ConfigParser
import os
import sys


WRITE_DEFAULT_CONFIG = False


def mkdir(d):
    if not os.path.isdir(d):
        os.mkdir(d, 0700)
        sys.stdout.write("%s: Created directory\n" % d)


def dir_exists(d):
    if not os.path.isdir(d):
        sys.stderr.write("WARNING: %s does not exist\n" % d)


# Configure the Config Parser.
config = ConfigParser.RawConfigParser()

homedir = os.path.expanduser('~')
basedir = os.path.join(homedir, 'mimix')

config.add_section('general')
#config.set('general', 'name', 'noname')
#config.set('general', 'address', 'http://nothing.onion')
config.set('general', 'keylen', 1024)
config.set('general', 'smtp', 'no')
config.set('general', 'piddir', os.path.join(basedir, 'run'))
config.set('general', 'pidfile', 'mimix.pid')
config.set('general', 'dbdir', os.path.join(basedir, 'db'))
config.set('general', 'dbfile', 'directory.db')
config.set('general', 'idage', 28)
config.set('general', 'version', '0.1-alpha1')
config.set('general', 'keyvalid', 270)

config.add_section('chain')
config.set('chain', 'chain', "*,*,*")
config.set('chain', 'uptime', 90)
config.set('chain', 'maxlat', 120)
config.set('chain', 'minlat', 0)
config.set('chain', 'distance', 3)

config.add_section('logging')
config.set('logging', 'dir', os.path.join(basedir, 'log'))
config.set('logging', 'file', 'mimix.log')
config.set('logging', 'level', 'info')
config.set('logging', 'format',
           '%(asctime)s %(name)s %(levelname)s %(message)s')
config.set('logging', 'datefmt', '%Y-%m-%d %H:%M:%S')
config.set('logging', 'retain', 7)

config.add_section('pool')
config.set('pool', 'indir', os.path.join(basedir, 'inbound_pool'))
config.set('pool', 'outdir', os.path.join(basedir, 'outbound_pool'))
config.set('pool', 'size', 45)
config.set('pool', 'rate', 65)
config.set('pool', 'interval', '15m')
config.set('pool', 'expire', 7)
config.set('pool', 'indummy', 10)
config.set('pool', 'outdummy', 70)

config.add_section('http')
config.set('http', 'wwwdir', os.path.join(homedir, 'apache', 'www'))

if WRITE_DEFAULT_CONFIG:
    with open('sample.cfg', 'w') as c:
        config.write(c)
        sys.exit(0)

# Try and process the .mimixrc file.  If it doesn't exist, we
# bailout as some options are compulsory.
if 'MIMIX' in os.environ:
    configfile = os.environ['MIMIX']
else:
    configfile = os.path.join(homedir, '.mimixrc')
if os.path.isfile(configfile):
    config.read(configfile)

else:
    sys.stderr.write("No configuration file found.\nThe expected "
                     "location is %s.  This can be overridden by defining "
                     "the MIMIX environment variable.\n" % configfile)
    sys.exit(1)

if config.get('general', 'address').endswith('/'):
    config.set('general', 'address', config.get('general',
                                                'address').rstrip('/'))
# Make required directories
mkdir(basedir)
mkdir(config.get('general', 'dbdir'))
if config.has_option('general', 'address'):
    # If an address is set, the assumption is made that this node will run as
    # a server.
    mkdir(config.get('general', 'piddir'))
    mkdir(config.get('logging', 'dir'))
    mkdir(config.get('pool', 'indir'))
    mkdir(config.get('pool', 'outdir'))
    dir_exists(config.get('http', 'wwwdir'))
