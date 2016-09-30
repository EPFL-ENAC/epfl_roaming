#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Bancal Samuel
# Created : 100831
# Updates : 110103

# Requisite :

# Description :
# - get username/password
# - encode it
# - store it to tmp file

import os
import sys
import pwd
import pickle
import ldap
import re

SERVICE = os.environ["PAM_SERVICE"]
TYPE = os.environ["PAM_TYPE"]

USERNAME = os.environ["PAM_USER"]

class UserIdentity():
    """
        Become user or back to root
    """
    def __init__(self):
        pass

    def __enter__(self):
        pw = pwd.getpwnam(USERNAME)
        os.seteuid(pw.pw_uid)

    def __exit__(self, type, value, traceback):
        os.seteuid(0)

#~ DOMAIN = get_domain()
#TTY = os.environ["PAM_TTY"]

print "USERNAME %s" % USERNAME
print "SERVICE %s" % SERVICE
print "TYPE %s" % TYPE

CRED_FILENAME = "/tmp/%s_epfl_cred" % USERNAME

if TYPE != "auth":
    sys.exit(0)

PASSWORD = sys.stdin.readline().rstrip(chr(0))

def save_credentials(username = USERNAME, password = PASSWORD):
    # Encode credential
    def encode(username, password):
        username = unicode(username, 'utf-8')
        password = unicode(password, 'utf-8')
        factor = len(password) / len(username) + 1
        key = username * factor
        enc_password = "".join([unichr(ord(password[i]) + ord(key[i])) for i in range(0, len(password)) ])
        return enc_password

    try:
        with open(CRED_FILENAME, "wb") as f:
            enc_password = encode(username, password)
            pickle.dump(enc_password, f)
    except IOError:
        print "Error: Could not write to file %s" % CRED_FILENAME
        sys.exit(1)

save_credentials(USERNAME, PASSWORD)

pw = pwd.getpwnam(USERNAME)
os.chown(CRED_FILENAME, pw.pw_uid, pw.pw_gid)
os.chmod(CRED_FILENAME, 0600)

sys.exit(0)
