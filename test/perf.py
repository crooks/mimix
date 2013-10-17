#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent

import mix
import datetime

def perf():
    message = mix.Message()
    plain_text = "Nobody inspects the spammish repetition"


    start = datetime.datetime.now()
    for x in range(50):
        message.text = None
        chain = ['no.onion', 'no.onion']
        message.encode(plain_text, chain)
        while message.text is None:
            message.decode(message.packet)
    end = datetime.datetime.now()
    print message.text
    print end - start


if (__name__ == "__main__"):
    perf()

