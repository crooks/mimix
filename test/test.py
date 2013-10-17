#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent

import mix
import http

def test():
    message = mix.Message()
    plain_text = "Nobody inspects the spammish repetition"
    message.text = None
    chain = ['no.onion', 'no.onion']
    message.encode(plain_text, chain)
    http.post(message.packet.encode('base64'))

if (__name__ == "__main__"):
    test()

