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
import os.path
import timing
import sqlite3
import sys
import logging
import sendmail
from email.parser import Parser

class Chunker(object):
    def __init__(self, conn):
        conn.text_factory = str
        cursor = conn.cursor()
        exe = cursor.execute
        self.conn = conn
        self.cursor = cursor
        self.exe = exe
        tables = self.list_tables()
        if 'chunker' not in tables:
            self.create_chunker()

    def list_tables(self):
        self.cursor.execute("""SELECT name FROM sqlite_master
                             WHERE type='table'""")
        data = self.cursor.fetchall()
        if data is None:
            return []
        else:
            return [e[0] for e in data]

    def delete_table(self):
        self.cursor.execute("DROP TABLE chunker")
        self.conn.commit()

    def create_chunker(self):
        """
        Database Structure
        [ msgid         Text                          Hex Message ID ]
        [ inserted      Date                       Date chunk stored ]
        [ chunknum      Int                             Chunk Number ]
        [ numchunks     Int                   Total number of chunks ]
        [ chunk         Text                           Message chunk ]
        """
        log.info('Creating DB table "chunker"')
        self.exe('''CREATE TABLE chunker (msgid TEXT, inserted TEXT,
                                          chunknum INT, numchunks INT,
                                          chunk TEXT)''')
        self.conn.commit()

    def insert(self, exit_info):
        insert = (exit_info.messageid.encode('hex'),
                  exit_info.chunknum,
                  exit_info.numchunks,
                  exit_info.payload,)
        self.exe('''INSERT into chunker (msgid, chunknum, numchunks,
                                         chunk, inserted)
                    VALUES (?,?,?,?,date("now"))''', insert)
        self.conn.commit() 
        return self.cursor.rowcount

    def delete(self, msgid):
        """
        """
        criteria = (msgid,)
        self.exe('DELETE FROM chunker WHERE msgid = ?', criteria)
        deleted = self.cursor.rowcount
        if deleted > 0:
            log.info("Deleted %s chunks for MsgID: %s", deleted, msgid)
        self.conn.commit()

    def expire(self):
        """
        Expire chunks in the DB that are more than 28 days old.  It's unlikely
        that missing chunks are going to turn up now.
        """
        criteria = (timing.date_past(days=28),)
        self.exe('DELETE FROM chunker WHERE inserted < ?', criteria)
        self.conn.commit()
        return self.cursor.rowcount

    def count(self, msgid):
        """
        """
        criteria = (msgid,)
        self.exe('SELECT COUNT(msgid) FROM chunker WHERE msgid = ?', criteria)
        return int(self.cursor.fetchone()[0])

    def chunk_check(self, msgid):
        criteria = (msgid,)
        self.exe('SELECT chunknum, numchunks FROM chunker WHERE msgid = ?',
                 criteria)
        data = self.cursor.fetchall()
        all_numchunks = [e[1] for e in data]
        if all_numchunks.count(all_numchunks[0]) != len(all_numchunks):
            log.warn("%s: Chunks disagree on number of chunks.  The client "
                     "may have a bug.")
            return False
        elif all_numchunks[0] > len(all_numchunks):
            log.debug("%s: Insufficient chunks available.", msgid)
            return False
        elif all_numchunks[0] < len(all_numchunks):
            log.warn("%s: Chunks all agree on numchunks(%s) but there are "
                     "%s chunks with this Message-ID.  Might be a client-"
                     "side bug.", msgid, all_numchunks[0],len(all_numchunks))
            return False
        numchunks = all_numchunks[0]
        chunknums = {n[0]:1 for n in data}
        for n in range(1, numchunks + 1):
            if n not in chunknums:
                log.warn("%s: Chunknum %s not found.", msgid, n)
                return False
        return True

    def assemble(self):
        for msgid in self.list_msgids():
            if self.chunk_check(msgid):
                criteria = (msgid,)
                self.exe('''SELECT chunk, chunknum FROM chunker
                            WHERE msgid=?
                            ORDER BY chunknum''', criteria)
                d = self.cursor.fetchall()
                msg = Parser().parsestr(''.join([e[0] for e in d]))
                sendmail.sendmsg(msg)
                self.delete(msgid)

    def list_msgids(self):
        self.exe('SELECT DISTINCT msgid FROM chunker')
        return [e[0] for e in self.cursor.fetchall()]

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
    
    dbkeys = os.path.join(config.get('database', 'path'),
                          config.get('database', 'directory'))
    with sqlite3.connect(dbkeys) as conn:
        c = Chunker(conn)
        #c.delete_table()
        c.assemble()
