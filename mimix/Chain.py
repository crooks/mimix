import os.path
import sqlite3
import libkeys
import logging
from Config import config
from Crypto.Random import random

class ChainError(Exception):
    pass


class Chain(object):
    """
    """
    def __init__(self, conn):
        self.conn = conn

    def create(self, chainstr=None):
        """
        This function generates a remailer chain.  The first link in the chain
        being the entry-remailer and the last link, the exit-remailer.  As the
        exit node must meet specific criteria, it is selected first to ensure
        the availability of suitable exit-nodes isn't exhausted during chain
        creation (see 'distance' parameter).  From that point, the chain is
        constructed in reverse.
        """
        if chainstr is None:
            chainstr = config.get('chain', 'chain')
        distance = config.getint('chain', 'distance')
        # nodes is a list of each link in the chain.  Each link can either be
        # randomly selected (depicted by an '*') or hardcoded (by remailer
        # address).
        nodes = [n.strip() for n in chainstr.split(',')]
        if len(nodes) > 10:
            raise ChainError("Maximum chain length exceeded")
        exit = nodes.pop()
        if exit == "*":
            exits = libkeys.contenders(self.conn, smtp=True)
            # contenders is a list of exit remailers that don't conflict with
            # any hardcoded remailers within the proximity of "distance".
            # Without this check, the exit remailer would be selected prior to
            # consideration of distance compliance.
            contenders = list(set(exits).difference(nodes[0 - distance:]))
            if len(contenders) == 0:
                raise ChainError("No exit remailers meet selection criteria")
            exit = contenders[random.randint(0, len(exits) - 1)]
        elif exit not in libkeys.all_remailers_by_name(self.conn):
            log.error("%s: Invalid hardcoded exit remailer", exit)
            raise ChainError("Invalid exit node")
        chain = [exit]
        self.exit = exit
        # At this point, nodes is a list of the originally submitted chain
        # string, minus the exit.  In order to create chunked messages, that
        # chain must be repeatedly created but with a hardcoded exit node.  To
        # achieve that, the chainstr is reproduced with the exit hardcoded to
        # the exit node selected above.
        exitchain = list(nodes)
        exitchain.append(exit)
        self.exitstr = ",".join(exitchain)

        # distance_exclude is a list of the remailers in close proximity to
        # the node currently being selected.  It prevents a single remailer
        # from occupying two overly-proximate links.
        distance_exclude = [exit]
        # All remailers is used to check that hardcoded links are all known
        # remailers.
        all_remailers = libkeys.all_remailers_by_name(self.conn)
        remailers = libkeys.contenders(self.conn)
        # If processing reaches this point, at least one remailer (besides an
        # exit) is required.  If we have none to choose from, raise an error.
        if len(remailers) == 0:
            raise ChainError("Insufficient remailers meet selection criteria")
        # Loop until all the links have been popped off the nodes stack.
        while nodes:
            if len(distance_exclude) >= distance:
                distance_exclude.pop(0)
            remailer = nodes.pop()
            if remailer == "*":
                # During random selection, only nodes in the remailers list
                # and not in the distance list can be considered.
                contenders = list(set(remailers).difference(distance_exclude))
                num_contenders = len(contenders)
                if num_contenders == 0:
                    raise ChainError("Insufficient remailers to comply with "
                                     "distance criteria")
                # Pick a random remailer from the list of potential contenders
                remailer = contenders[random.randint(0, num_contenders - 1)]
            elif remailer not in all_remailers:
                log.error("%s: Invalid hardcoded remailer", remailer)
                raise ChainError("Invalid remailer")
            # The newly selected remailer becomes the first link in chain.
            chain.insert(0, remailer)
            distance_exclude.append(remailer)
        self.chain = chain
        self.chainstr = ",".join(chain)
        self.entry = chain[0]
        self.chainlen = len(chain)

log = logging.getLogger("mimix.%s" % __name__)
if (__name__ == "__main__"):
    dbkeys = os.path.join(config.get('database', 'path'),
                          config.get('database', 'directory'))
    with sqlite3.connect(dbkeys) as conn:
        conn.text_factory = str
        c = Chain(conn)
        chain = "*,fleegle,*"
        c.create(chainstr=chain)
        print c.chain
        print c.chainstr
        print c.exitstr
