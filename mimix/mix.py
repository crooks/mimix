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

import struct
import timing
import hashlib
import logging
import os.path
import sys
import libkeys
from Config import config
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random


class PacketError(Exception):
    pass


class IntermediateEncode(object):
    """
    Packet type 0 (intermediate hop):
    [ 9 Initialization vectors   144 bytes ]
    [ Next address                80 bytes ]
    [ Anti-tag digest             32 bytes ]
    """
    def __init__(self, next_hop):
        self.packet_type = "0"
        self.ivsstr = Random.new().read(9 * 16)
        self.ivs = [self.ivsstr[i:i+16] for i in range(0, 144, 16)]
        self.next_hop = next_hop
        self.next_hop_padded = next_hop + ('\x00' * (80 - len(next_hop)))

    def set_antitag(self, digest):
        """
        This is a digest of the next-hop header combined with the payload at
        the point in time at which they are presented to the remailer for
        processing this header.  The goal is to prevent tagging attacks by
        making this (honest) remailer drop tagged packets before they
        potentially reach the dishonest node that's watching for the tag.

        """
        self.antitag = digest

    def packetize(self):
        packet = struct.pack('144s80s32s', self.ivsstr,
                                           str(self.next_hop_padded),
                                           self.antitag)
        return packet


class IntermediateDecode(object):
    def __init__(self, packet):
        assert len(packet) == 256
        ivsstr = packet[:144]
        self.ivs = [ivsstr[i:i+16] for i in range(0, 144, 16)]
        self.next_hop = packet[144:144 + 80].rstrip('\x00')
        self.antitag = packet[144 + 80:]


class ExitEncode(object):
    """
    Packet type 1 (final hop):
    [ Chunk number                 1 byte  ]
    [ Number of chunks             1 byte  ]
    [ Message ID                  16 bytes ]
    [ Initialization vector       16 bytes ]
    [ Exit type                    1 byte  ]
    [ Payload (chunk) length       2 bytes ]
    [ Payload (chunk) digest      32 bytes ]
    [ Padding                    187 bytes ]
    """
    def __init__(self):
        self.packet_type = "1"
        self.iv = Random.new().read(16)

    def set_exit_type(self, exit_type):
        """
        [ SMTP message          0 ]
        [ Dummy message         1 ]
        """
        self.exit_type = exit_type

    def set_chunks(self, messageid, chunknum, numchunks):
        assert chunknum <= numchunks
        self.messageid = messageid
        self.chunknum = chunknum
        self.numchunks = numchunks

    def set_payload(self, payload):
        self.payload_length = len(payload)
        assert self.payload_length <= 10240
        self.payload = payload
        self.payload_digest = hashlib.sha256(payload).digest()

    def packetize(self):
        packet = struct.pack('<BB16s16sBH32s187s',
                             self.chunknum,
                             self.numchunks,
                             self.messageid,
                             self.iv,
                             self.exit_type,
                             self.payload_length,
                             self.payload_digest,
                             Random.new().read(187))
        assert len(packet) == 256
        return packet


class ExitDecode(object):
    def __init__(self, packet):
        assert len(packet) == 256
        (self.chunknum,
         self.numchunks,
         self.messageid,
         self.iv,
         self.exit_type,
         self.payload_length,
         self.payload_digest,
         _) = struct.unpack('<BB16s16sBH32s187s', packet)

    def set_payload(self, payload):
        self.payload = payload[:self.payload_length]
        payload_digest = hashlib.sha256(self.payload).digest()
        if payload_digest != self.payload_digest:
            log.warn("Payload digest does not match hash in packet_info.")
            raise PacketError("Content Digest Error")


class InnerEncode(object):
    """
    [ Packet ID                            16 bytes ]
    [ AES key                              32 bytes ]
    [ Packet type identifier                1 byte  ]
    [ Packet Info                         256 bytes ]
    [ Timestamp                             2 bytes ]
    [ Padding                              13 bytes ]
    [ Message digest                       64 bytes ]
    """

    def __init__(self, next_hop):
        self.packet_id = Random.new().read(16)
        # This AES key is used to encrypt the other header sections and the
        # Message Payload.
        self.aes = Random.new().read(32)
        if next_hop is not None:
            packet_info = IntermediateEncode(next_hop)
            self.packet_info = packet_info
        # Days since Epoch
        self.timestamp = timing.epoch_days()

    def packetize(self):
        packet = struct.pack('<16s32sc256sH13s',
                             self.packet_id,
                             self.aes,
                             self.packet_info.packet_type,
                             self.packet_info.packetize(),
                             self.timestamp,
                             Random.new().read(13))
        digest = hashlib.sha512(packet).digest()
        packet += digest
        assert len(packet) == 384
        return packet


class InnerDecode():
    def __init__(self, packet):
        assert len(packet) == 384
        (packet_id, aes, pkt_type, pi, timestamp, null,
         digest) = struct.unpack('<16s32sc256sH13s64s', packet)
        if digest != hashlib.sha512(packet[:320]).digest():
            raise PacketError("Digest mismatch on encrypted header")
        self.aes = aes
        if pkt_type == "0":
            packet_info = IntermediateDecode(pi)
        elif pkt_type == "1":
            packet_info = ExitDecode(pi)
        else:
            raise PacketError("Unknown packet type (%s)" % pkt_type)
        self.pkt_type = pkt_type
        self.packet_id = packet_id
        self.packet_info = packet_info


class Encode():
    """
    Headers:
    [ Public key ID                 16 bytes ]
    [ Length of RSA-encrypted data   2 bytes ]
    [ RSA-encrypted session key    512 bytes ]
    [ Initialization vector         16 bytes ]
    [ Encrypted header part        384 bytes ]
    [ Padding                       30 bytes ]
    [ Message digest                64 bytes ]

    Payload:
    [ Length                         2 bytes ]
    [ Content                    10238 bytes ]
    """

    def __init__(self, conn):
        # Encode and decode operations require the keystore so scoping it
        # in the Class kind of makes sense.
        self.conn = conn

    def encode(self, exit, chain):
        headers = []
        # next_hop is used to ascertain if this is a middle or exit encoding.
        # If there is no next_hop, the encoding must be an exit.
        next_hop = None
        # Headers are generated, exit first.  In each chain there will be a
        # single exit header and 0-9 intermediates.  During each iteration:
        # 1) A new header is created.
        # 2) Existing headers are encrypted using keys from Step.1.
        # 3) The payload is encrypted using keys from Step.1.
        for h in range(len(chain)):
            inner = InnerEncode(next_hop)
            # If next_hop is None, this is an Exit message.  This is only True
            # during the first iteration, after which next_hop contains the
            # address of the next hop.
            if next_hop is None:
                inner.packet_info = exit
                cipher = AES.new(inner.aes,
                                 AES.MODE_CFB,
                                 inner.packet_info.iv)
                msg = cipher.encrypt(inner.packet_info.payload)
                enclen = len(msg)
                if enclen < 10240:
                    pad_bytes = 10240 - enclen
                    msg += Random.new().read(pad_bytes)
                assert len(msg) == 10240
            else:
                for e in range(len(headers)):
                    cipher = AES.new(inner.aes, AES.MODE_CFB,
                                     inner.packet_info.ivs[e])
                    headers[e] = cipher.encrypt(headers[e])
                # The payload always gets encrypted with the final IV
                cipher = AES.new(inner.aes, AES.MODE_CFB,
                                 inner.packet_info.ivs[8])
                msg = cipher.encrypt(msg)
                antitag = hashlib.sha256()
                antitag.update(headers[0])
                antitag.update(msg)
                inner.packet_info.set_antitag(antitag.digest())

            # That's it for old header and payload encoding.  The following
            # section handles the header for this specific step.
            this_hop_name = chain.pop()
            # This is the AES key that will be RSA Encrypted.  It's used to
            # encrypt the 384 Byte inner header part.
            aes = Random.new().read(32)
            iv = Random.new().read(16)
            # get_public() returns a Tuple of (keyid, address, pubkey)
            rem_info = libkeys.get_public(self.conn, this_hop_name)
            cipher = PKCS1_OAEP.new(rem_info[2])
            rsa_data = cipher.encrypt(aes)
            len_rsa = len(rsa_data)
            # The RSA data size is dependent on the RSA key size.  The packet
            # format can accommodate 512 Bytes which results from a 4096 bit
            # keysize being used to encrypt the 32 Byte AES key.
            assert len_rsa <= 512
            # Pad RSA data
            rsa_data += Random.new().read(512 - len_rsa)
            cipher = AES.new(aes, AES.MODE_CFB, iv)
            newhead = struct.pack('<16sH512s16s384s30s',
                                  rem_info[0].decode('hex'),
                                  len_rsa,
                                  rsa_data,
                                  iv,
                                  cipher.encrypt(inner.packetize()),
                                  Random.new().read(30))
            digest = hashlib.sha512(newhead).digest()
            newhead += digest
            headers.insert(0, newhead)
            next_hop = rem_info[1]
        # The final step of encoding is to merge the headers (along with fake
        # headers for padding) with the body.
        binary = (''.join(headers) +
                  Random.new().read((10 - len(headers)) * 1024) +
                  msg)
        text = "-----BEGIN MIMIX MESSAGE-----\n"
        text += "Version: %s\n\n" % config.get('general', 'version')
        text += binary.encode('base64')
        text += "-----END MIMIX MESSAGE-----\n"
        self.text = text
        # Record the entry point into the chain.  This will be the address of
        # the remailer that the message is finally encrypted to.
        self.send_to_address = next_hop


class Decode():
    def __init__(self, keystore):
        # Encode and decode operations require the keystore so scoping it
        # in the Class kind of makes sense.
        self.keystore = keystore

    def decode(self):
        assert len(self.packet) == 20480
        self.is_exit = False
        # Split the header component into its 10 distinct headers.
        headers = [self.packet[i:i+1024] for i in range(0, 10240, 1024)]
        # The first header gets processed and removed at this hop.
        tophead = headers.pop(0)
        if hashlib.sha512(tophead[:960]).digest() != tophead[960:]:
            log.warn("Digest mismatch checking current header")
            raise PacketError("Digest mismatch")
        # Extract the keyid required to decrypt the message.
        keyid = tophead[0:16].encode('hex')
        secret_key = self.keystore.get_secret(keyid)
        if secret_key is None:
            raise PacketError("Unknown recipient secret key")
        cipher = PKCS1_OAEP.new(secret_key)
        len_rsa = struct.unpack('<H', tophead[16:18])[0]
        # Extract the AES key for the inner header.
        aes = cipher.decrypt(tophead[18:18 + len_rsa])
        assert len(aes) == 32
        iv = tophead[530:546]
        # Now the inner header can be decrypted.
        cipher = AES.new(aes, AES.MODE_CFB, iv)
        inner = InnerDecode(cipher.decrypt(tophead[546:546 + 384]))
        if self.keystore.idlog(inner.packet_id):
            raise PacketError("Packet ID collision")
        # If this is an intermediate message, the remaining 9 header sections
        # need to be decrypted using the AES key from the inner header and the
        # series of 9 IVs stored in the packet info.
        if inner.pkt_type == "0":
            # First, compare the Anti-Tagging Hash stored in the Packet-Info
            # against one calculated at this time.
            antitag = hashlib.sha256()
            antitag.update(headers[0])
            antitag.update(self.packet[10240:])
            if antitag.digest() != inner.packet_info.antitag:
                log.warn("Anti-tag digest failure.  This message might have "
                         "been tampered with.")
                raise PacketError("Anti-tag digest mismatch")
            if config.getboolean('general', 'hopspy'):
                self.keystore.middle_spy(inner.packet_info.next_hop)
            for h in range(9):
                cipher = AES.new(inner.aes, AES.MODE_CFB,
                                 inner.packet_info.ivs[h])
                headers[h] = cipher.decrypt(headers[h])
            # Use the final IV to decrypt the payload
            cipher = AES.new(inner.aes, AES.MODE_CFB,
                             inner.packet_info.ivs[8])
            binary = (''.join(headers) +
                      Random.new().read(1024) +
                      cipher.decrypt(self.packet[10240:20480]))
            text = "-----BEGIN MIMIX MESSAGE-----\n"
            text += "Version: %s\n\n" % config.get('general', 'version')
            text += binary.encode('base64')
            text += "-----END MIMIX MESSAGE-----\n"
            self.text = text
            self.send_to_address = inner.packet_info.next_hop
            self.is_exit = False

        elif inner.pkt_type == "1":
            cipher = AES.new(inner.aes, AES.MODE_CFB, inner.packet_info.iv)
            inner.packet_info.set_payload(cipher.decrypt(self.packet[10240:20480]))
            self.is_exit = True
        self.packet_info = inner.packet_info

    def set_packet(self, packet):
        self.packet = packet

    def file_to_packet(self, filename):
        with open(filename, 'r') as f:
            packet = ""
            packet_pos = 0
            for line in f:
                if (packet_pos == 0 and
                        line == '-----BEGIN MIMIX MESSAGE-----\n'):
                    packet_pos = 1
                    continue
                if packet_pos == 1 and line.startswith('Version: '):
                    version = line.split(': ')[1].strip()
                    packet_pos = 2
                if packet_pos == 2:
                    if len(line) < 70:
                       continue
                    else:
                        packet_pos = 3
                if packet_pos == 3:
                    if line.rstrip() == '-----END MIMIX MESSAGE-----':
                        packet_pos = 4
                        break
                    else:
                        packet += line
            if packet_pos != 4:
                raise PacketError("Invalid Mimix file:%s" % packet_pos)
            self.packet = packet.decode('base64')
            if len(self.packet) != 20480:
                raise PacketError("Incorrect packet size")
            self.version = version

    def packet_import(self, filename):
        """
        This function expects to receive a Base64 encoded Mimix message.
        When reading inbound messages, the message will contain just the
        Mimix packet.  For outbound messages, it will be prepended with
        a series of 'key: value' pairs.  These are never transmitted, they
        just provide instructions to the sending remailer.
        """
        with open(filename, 'r') as f:
            payload = f.read()
        data = {}
        packet_start = payload.index('-----BEGIN MIMIX MESSAGE-----\n')
        base64_end = payload.index('\n-----END MIMIX MESSAGE-----')
        packet_end = base64_end + 28
        double_nl = payload.index('\n\n', packet_start, packet_end)
        base64_start = double_nl + 2
        for line in payload[:packet_start].split('\n'):
            if ': ' in line:
                k, v = self._colonspace(line)
                data[k] = v
        version = payload[packet_start:packet_end].split("\n", 2)[1]
        if not version.startswith('Version: '):
            raise ValueError('Version header not found')
        k, v = self._colonspace(version)
        data[k] = v
        data['packet'] = payload[packet_start:packet_end]
        data['binary'] = payload[base64_start:base64_end].decode('base64')
        assert len(data['binary']) == 20480
        return data

    def _colonspace(self, data):
        key, value = data.split(': ', 1)
        key = key.strip().lower().replace(' ', '_')
        return key, value.strip()


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
    #import sqlite3
    #with sqlite3.connect(dbkeys) as conn:
    #    mix = Encode(conn)
    filename = '/home/crooks/mimix/inbound_pool/ma4e43f0c'
    decode = Decode(1)
    decode.file_to_packet(filename)
