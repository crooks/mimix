#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# sendmail.py - Email Agent for Mimix Remailer
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

import logging
import os.path
import smtplib
from Config import config
from email.parser import Parser
from email.mime.text import MIMEText


def sendmsg(msg):
    if msg['From'] and msg['To']:
        s = smtplib.SMTP('localhost')
        log.debug("Delivering message to: %s", msg['To'])
        try:
            s.sendmail(msg['From'], msg['To'], msg.as_string())
            return True
        except smtplib.SMTPRecipientsRefused, e:
            log.info("Email error: %s", e)
            return False
    else:
        if not 'From' in msg:
            log.info("Message has no From header")
        if not 'To' in msg:
            log.info("Message has no To header")
        return False

log = logging.getLogger("mimix.%s" % __name__)
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                 'warn': logging.WARN, 'error': logging.ERROR}
    log = logging.getLogger("mimix")
    log.setLevel(loglevels[config.get('logging', 'level')])
    filename = os.path.join(config.get('logging', 'path'), 'mimix.log')
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
