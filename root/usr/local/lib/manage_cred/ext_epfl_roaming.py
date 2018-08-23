#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
epfl_roaming extension for manage_cred

It has to implement :
+ FLAG_FILE : the file that flags it's epfl_roaming that sent USR2 signal to manage_cred
+ run(username, password) method that does the job
"""

import os
import sys
import pwd
import subprocess

FLAG_FILE = "/var/run/epfl_roaming/manage_cred.flag"

EPFL_ROAMING_FOLDER = "/usr/local/bin"

sys.path.append(EPFL_ROAMING_FOLDER)
from epfl_roaming import IO, LOG_PAM, read_user, read_config, run_cmd, NameSpace, UserIdentity

def run(username, password):
    """
    Performs all mount for epfl_roaming
    """
    with IO(LOG_PAM):
        IO.write("Running epfl_roaming extension from manage_cred for user %s." % username)
        options = NameSpace()
        options.context = "pam"
        user = read_user(options, username)
        config = read_config(options, user)
        for mount_point, mount_instruction in config["mounts"].items():
            if not os.path.exists(mount_point):
                user = NameSpace()
                user.username = username
                pw = pwd.getpwnam(user.username)
                user.uid = str(pw.pw_uid)
                user.gid = str(pw.pw_gid)
                with UserIdentity(user):
                    run_cmd(
                        cmd=["mkdir", "-p", mount_point]
                    )
            # Mount
            os.environ['PASSWD'] = password
            run_cmd(
                cmd=mount_instruction,
                shell=True,
            )
            del os.environ['PASSWD']
        IO.write("Done running epfl_roaming extension from manage_cred for user %s." % username)

if __name__ == "__main__":
    print >> sys.stderr, "This is not to be run this way!"
    sys.exit(1)
