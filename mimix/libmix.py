#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# mix.py - Packet encoder/decoder for Mimix
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

def split_headers(headbytes):
    assert len(headbytes) % 1024 == 0
    b = len(headbytes)
    return [headbytes[i:i+1024] for i in range(0, b, 1024)]

def split_ivs(ivs):
    assert len(ivs) % 16 == 0
    b = len(ivs)
    return [ivs[i:i+16] for i in range(0, b, 16)]
