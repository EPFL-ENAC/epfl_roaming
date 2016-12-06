#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
manage_cred : receives user credentials during pam auth.
It keeps it until MANAGE_CRED_TIMEOUT.
Other applications (extensions) can ask it to do operations that need credentials.

The folder /usr/local/lib/manage_cred/ is the place where extensions have to be
installed. It has to be root:root 0x700.

Each extension file /usr/local/lib/manage_cred/*.py has to be root:root 0x600.
It has to implement :
+ FLAG_FILE : the file that flags it's epfl_roaming that sent USR1 signal to manage_cred
+ run(username, password) method that does the job
"""

import os
import sys
import time
import stat
import signal
import importlib

MANAGE_CRED_TIMEOUT = 20  # sec
EXT_FOLDER = "/usr/local/lib/manage_cred"

VAR_RUN = "/var/run/manage_cred"
PID_FILE = "/var/run/manage_cred/manage_cred_{username}.pid"

class PID():
    def __init__(self):
        self.pid_file = PID_FILE.format(username=USERNAME)

    def __enter__(self):
        with open(self.pid_file, "w") as f:
            f.write("%s\n" % os.getpid())

    def __exit__(self, typ, val, tb):
        os.unlink(self.pid_file)


def fork_and_wait():
    def signal_USR1_handler(signum, frame):
        an_ext_was_run = False
        for ext in extensions:
            if os.path.exists(extensions[ext].FLAG_FILE):
                an_ext_was_run = True
                print "Running extension %s." % ext
                extensions[ext].run(USERNAME, PASSWORD)
                try:
                    os.unlink(extensions[ext].FLAG_FILE)
                except:
                    pass
                print "done."
        if not an_ext_was_run:
            print "got USR1 signal, but no extension were run."

    def signal_KILL_handler(signum, frame):
        print "got TERM signal, gonna exit."
        sys.exit(0)

    if os.fork() != 0:
        return

    with PID():
        extensions = {}

        # SIGUSR1 and SIGTERM handling
        signal.signal(signal.SIGUSR1, signal_USR1_handler)
        signal.signal(signal.SIGTERM, signal_KILL_handler)

        # Check that Extension folder has correct rights : root:root 0x700
        ext_folder_stat = os.stat(EXT_FOLDER)
        if (ext_folder_stat.st_uid != 0 or
            ext_folder_stat.st_gid != 0 or
            ext_folder_stat.st_mode & (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO) != stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR):
            print "Error, extensions folder %s doesn't have correct rights : root:root 0x700.\nAborting." % EXT_FOLDER
            sys.exit(1)

        sys.path.insert(0, EXT_FOLDER)
        for f in os.listdir(EXT_FOLDER):
            if f == "__init__.py" or not f.endswith(".py"):
                continue

            # check extension has correct rights : root:root 0x600
            ext_path = os.path.join(EXT_FOLDER, f)
            ext_stat = os.stat(ext_path)
            if (ext_stat.st_uid != 0 or
                ext_stat.st_gid != 0 or
                ext_stat.st_mode & (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO) != stat.S_IRUSR | stat.S_IWUSR):
                print "Error, extensions %s doesn't have correct rights : root:root 0x600.\nSkipping." % ext_path
                continue

            try:
                ext_name = f[:-3]
                mod = importlib.import_module(ext_name)
                if ("FLAG_FILE" in dir(mod) and "run" in dir(mod) and
                    type(mod.FLAG_FILE) == str and callable(mod.run)):
                    extensions[ext_name] = mod
                else:
                    print "Error, %s doesn't implement required variables and functions; Skipping." % ext_name
            except Exception, e:
                print "Error, could not import %s; Skipping." % ext_name
                print e


        for i in range(MANAGE_CRED_TIMEOUT):
            time.sleep(1)
        print "Finished to wait for %i seconds; exiting." % MANAGE_CRED_TIMEOUT


if __name__ == "__main__":
    USERNAME = os.environ["PAM_USER"]
    SERVICE = os.environ["PAM_SERVICE"]
    TYPE = os.environ["PAM_TYPE"]

    print "USERNAME %s" % USERNAME
    print "SERVICE %s" % SERVICE
    print "TYPE %s" % TYPE

    if TYPE != "auth":
        sys.exit(0)

    PASSWORD = sys.stdin.readline().rstrip(chr(0))

    try:
        os.makedirs(VAR_RUN)
    except OSError:
        pass

    fork_and_wait()
    sys.exit(0)
