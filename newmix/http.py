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

import requests
from wsgiref.simple_server import make_server

def get(url):
    try:
        r = requests.get(url)
    except requests.exceptions.ConnectionError:
        return None
    return r.text

def post(msg):
    payload = {'newmix': msg}
    r = requests.post('http://www.mixmin.net:8000/cgi-bin/webcgi.py',
                      data=payload)

if __name__ == '__main__':
    post("Test Message\n")
