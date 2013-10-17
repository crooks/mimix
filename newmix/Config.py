#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# pymaster.py - A Python version of the Mixmaster Remailer
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

# Configure the Config Parser.
config = ConfigParser.RawConfigParser()

homedir = os.path.expanduser('~')
config.add_section('general')
config.set('general', 'name', 'noname')
config.set('general', 'address', 'nothing.onion')
config.set('general', 'keylen', 1024)
config.set('general', 'smtp', 'no')
config.set('general', 'pooldir', os.path.join(homedir, 'pooldir'))

# Try and process the .pymasterrc file.  If it doesn't exist, we
# bailout as some options are compulsory.
#if options.rc:
#    configfile = options.rc
if 'NEWMIX' in os.environ:
    configfile = os.environ['NEWMIX']
else:
    configfile = os.path.join(homedir, '.newmixrc')
if os.path.isfile(configfile):
    config.read(configfile)

else:
    sys.stdout.write("No configuration file found.\nThe expected "
                     "location is %s.  This can be overridden by defining "
                     "the NEWMIX environment variable.\n" % configfile)
    sys.exit(1)

