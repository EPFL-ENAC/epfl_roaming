#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
epfl_roaming extension for manage_cred

It has to implement :
+ FLAG_FILE : the file that flags it's epfl_roaming that sent USR1 signal to manage_cred
+ run(username, password) method that does the job
"""

import os
import sys

FLAG_FILE = "/var/run/epfl_roaming/manage_cred.flag"
FLAG_FILE = "/tmp/epfl_roaming.flag"  # TODO DEBUG

LOG_PAM = "/var/log/epfl_roaming.log"
LOG_PAM = "/tmp/epfl_roaming.log"  # TODO DEBUG
CONFIG_FILE = "/usr/local/etc/epfl_roaming.conf"

class IO(object):
    def __init__(self, filename):
        self.filename = filename

    def __enter__(self):
        IO.__open__(self.filename)
        try:
            for msg, eol in IO.previous_writes:
                IO.write(msg, eol)
        except AttributeError:
            pass

    def __exit__(self, typ, val, tb):
        IO.__close__()

    @classmethod
    def write(cls, msg, eol="\n"):
        pid = os.getpid()
        try:
            cls.f.write("\n".join(["(%s) %s" % (pid, s) for s in msg.split("\n")]) + eol)
        except AttributeError:
            try:
                cls.previous_writes.append((msg, eol))
            except AttributeError:
                cls.previous_writes = [(msg, eol),]

    @classmethod
    def __open__(cls, filename):
        cls.f = open(filename, "a", 1) # line buffered

    @classmethod
    def __close__(cls):
        cls.f.close()


def run(username, password):
    with IO(LOG_PAM):
        IO.write("Running epfl_roaming extension from manage_cred for %s!!" % username)

if __name__ == "__main__":
    print >> sys.stderr, "This is not to be run this way!"
    sys.exit(1)
