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

import struct
import timing
import hashlib
import logging
import sys
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import keys

class PacketError(Exception):
    pass


class PacketInfo(object):
    """
    Packet type 0 (intermediate hop):
    [ 9 Initialization vectors   144 bytes ]
    [ Next address               112 bytes ]

    Packet type 1 (final hop):
    [ Chunk number                 1 byte  ]
    [ Number of chunks             1 byte  ]
    [ Message ID                  16 bytes ]
    [ Initialization vector       16 bytes ]
    [ Padding                    222 bytes ]
    """

    def encode_intermediate(self, next_hop):
        ivs = Random.new().read(9 * 16)
        next_hop_padded = next_hop + ('\x00' * (112 - len(next_hop)))
        self.ivs = ivs
        self.next_hop = next_hop
        packet = ivs + next_hop_padded
        assert len(packet) == 256
        self.packet = packet

    def decode_intermediate(self, packet):
        self.ivs = packet[:144]
        self.next_hop = packet[144:144 + 112].rstrip('\x00')

    def encode_exit(self, chunknum=1, numchunks=1):
        assert chunknum <= numchunks
        messageid = Random.new().read(16)
        iv = Random.new().read(16)
        packet = struct.pack('<BB16s16s222s', chunknum,
                                              numchunks,
                                              messageid,
                                              iv,
                                              Random.new().read(222))
        assert len(packet) == 256
        self.iv = iv
        self.packet = packet
        
    def decode_exit(self, packet):
        assert len(packet) == 256
        (self.chunknum,
         self.numchunks,
         self.messageid,
         self.iv
        ) = struct.unpack('<BB16s16s', packet[:34])


class Inner(object):
    """
    [ Packet ID                            16 bytes ]
    [ AES key                              32 bytes ]
    [ Packet type identifier                1 byte  ]
    [ Packet Info                         256 bytes ]
    [ Timestamp                             2 bytes ]
    [ Padding                              13 bytes ]
    [ Message digest                       64 bytes ]
    """

    def encode(self, next_hop):
        packet_id = Random.new().read(16)
        # This AES key is used to encrypt the other header sections and the
        # Message Payload.
        aes = Random.new().read(32)
        packet_info = PacketInfo()
        if next_hop == None:
            packet_info.encode_exit()
            pkt_type = "1"
        else:
            packet_info.encode_intermediate(next_hop)
            pkt_type = "0"
        # Days since Epoch
        timestamp = timing.epoch_days()
        packet = struct.pack('<16s32sc256sH13s', packet_id,
                                                aes,
                                                pkt_type,
                                                packet_info.packet,
                                                timestamp,
                                                Random.new().read(13))
        digest = hashlib.sha512(packet).digest()
        packet += digest
        assert len(packet) == 384
        self.aes = aes
        self.packet_info = packet_info
        self.packet = packet

    def decode(self, packet):
        assert len(packet) == 384
        (packet_id, aes, pkt_type, pi, timestamp, null,
         digest) = struct.unpack('<16s32sc256sH13s64s', packet)
        if digest != hashlib.sha512(packet[:320]).digest():
            raise PacketError("Digest mismatch on encrypted header")
        packet_info = PacketInfo()
        self.aes = aes
        if pkt_type == "0":
            packet_info.decode_intermediate(pi)
        elif pkt_type == "1":
            packet_info.decode_exit(pi)
        else:
            raise PacketError("Unknown packet type (%s)" % pkt_type)
        self.pkt_type = pkt_type
        self.packet_id = packet_id
        self.packet_info = packet_info


class Message():
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
    [ Digest                        64 bytes ]
    [ Content                    10174 bytes ]
    """

    def __init__(self):
        self.packet_size = 1024
        self.rsa_data_size = 512
        self.text = None
        self.keystore = keys.Keystore()

    def encode(self, msg, chain):
        headers = []
        # next_hop is used to ascertain is this is a middle or exit encoding.
        # If there is no next_hop, the encoding must be an exit.
        next_hop = None
        # Headers are generated, exit first.  In each chain there will be a
        # single exit header and 0-9 intermediates.  During each iteration:
        # 1) A new header is created.
        # 2) Existing headers are encrypted using keys from Step.1.
        # 3) The payload is encrypted using keys from Step.1.
        for h in range(len(chain)):
            this_hop = chain.pop()
            keyid, public_key = self.keystore.get_public(this_hop)
            if public_key is None:
                raise PacketError("Unknown recipient public key")
            # This is the AES key that will be RSA Encrypted.  It's used to
            # encrypt the 384 Byte inner header part.
            aes = Random.new().read(32)
            iv = Random.new().read(16)
            inner = Inner()
            inner.encode(next_hop)
            cipher = PKCS1_OAEP.new(public_key)
            rsa_data = cipher.encrypt(aes)
            len_rsa = len(rsa_data)
            # The RSA data size is dependent on the RSA key size.  The packet
            # format can accommodate 512 Bytes which results from a 4096 bit
            # keysize being used to encrypt the 32 Byte AES key.
            assert len_rsa <= 512
            rsa_data += Random.new().read(self.rsa_data_size - len_rsa)
            cipher = AES.new(aes, AES.MODE_CFB, iv)
            newhead = struct.pack('<16sH512s16s384s30s',
                                  keyid.decode('hex'),
                                  len_rsa,
                                  rsa_data,
                                  iv,
                                  cipher.encrypt(inner.packet),
                                  Random.new().read(30))
            digest = hashlib.sha512(newhead).digest()
            newhead += digest
            # If next_hop is None, this is an Exit message.  This is only True
            # during the first iteration, after which next_hop contains the
            # address of the next hop.
            if next_hop is None:
                digest = hashlib.sha512(msg).digest()
                length = len(msg)
                cipher = AES.new(inner.aes,
                                 AES.MODE_CFB,
                                 inner.packet_info.iv)
                body = struct.pack('<H64s', length, digest)
                body += msg
                body = cipher.encrypt(body)
                pad_bytes = 10240 - len(body)
                body += Random.new().read(pad_bytes)
                assert len(body) == 10240
            else:
                ivs = self._split_ivs(inner.packet_info.ivs)
                for e in range(len(headers)):
                    cipher = AES.new(inner.aes, AES.MODE_CFB, ivs[e])
                    headers[e] = cipher.encrypt(headers[e])
                cipher = AES.new(inner.aes, AES.MODE_CFB, ivs[8])
                body = cipher.encrypt(body)
            headers.insert(0, newhead)
            #TODO next_hop needs to be an address, not a keyid
            next_hop = this_hop
        # The final step of encoding is to merge the headers (along with fake
        # headers for padding) with the body.
        self.packet = (''.join(headers) +
                       Random.new().read((10 - len(headers)) * 1024) +
                       body).encode('base64')

    def decode(self, packet):
        self.text = None
        assert len(packet) == 20480
        # Split the header component into its 10 distinct headers.
        headers = self._split_headers(packet[:10240])
        # The first header gets processed and removed at this hop.
        tophead = headers.pop(0)
        if hashlib.sha512(tophead[:960]).digest() != tophead[960:]:
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
        inner = Inner()
        inner.decode(cipher.decrypt(tophead[546:546 + 384]))
        # If this is an intermediate message, the remaining 9 header sections
        # need to be decrypted using the AES key from the inner header and the
        # series of 9 IVs stored in the packet info.
        if inner.pkt_type == "0":
            ivs = self._split_ivs(inner.packet_info.ivs)
            try:
                self.keystore.conf_fetch(inner.packet_info.next_hop)
            except keystore.KeyImportError, e:
                log.info("Key import fail: %s", e)
            for h in range(9):
                cipher = AES.new(inner.aes, AES.MODE_CFB, ivs[h])
                headers[h] = cipher.decrypt(headers[h])
            cipher = AES.new(inner.aes, AES.MODE_CFB,ivs[8])
            self.packet = (''.join(headers) +
                           Random.new().read(1024) +
                           cipher.decrypt(packet[10240:20480]))
            assert len(self.packet) == 20480
        elif inner.pkt_type == "1":
            cipher = AES.new(inner.aes, AES.MODE_CFB,inner.packet_info.iv)
            length, digest, body = struct.unpack("<H64s10174s",
                                        cipher.decrypt(packet[10240:20480]))
            body = body[:length]
            if digest != hashlib.sha512(body).digest():
                raise PacketError("Content Digest Error")
            self.text = body

    def _split_headers(self, headbytes):
        assert len(headbytes) % 1024 == 0
        b = len(headbytes)
        return [headbytes[i:i+1024] for i in range(0, b, 1024)]

    def _split_ivs(self, ivs):
        assert len(ivs) % 16 == 0
        b = len(ivs)
        return [ivs[i:i+16] for i in range(0, b, 16)]

    def _debug(self, head):
        print "KeyId: %s" % head[:16].encode('hex')
        print "RSA Len: %s" % head[16:18].encode('hex')
        print "RSA Data: %s" % head[18:60].encode('hex')
        print "IV: %s" % head[530:546].encode('hex')
        print "Digest: %s" % head[960:990].encode('hex')
    

def new_msg():
    message = Message()
    test_rem = message.keystore.chain()
    chain = [test_rem, test_rem]
    plain_text = "This is a test message\n" * 10
    message.encode(plain_text, chain)
    while message.text is None:
        message.decode(message.packet)
    print message.text
    

log = logging.getLogger("newmix.%s" % __name__)
if (__name__ == "__main__"):
    log = logging.getLogger("newmix")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    log.addHandler(handler)
    new_msg()
