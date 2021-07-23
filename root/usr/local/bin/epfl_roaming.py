#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
epfl_roaming : Script to make application's preferences move along with the user.

+ It is called by PAM as root at session_open and session_close :
$ epfl_roaming.py --pam
    does :
      - mount & umount
      - files/folders ln -s & cp
      - rm -rf at session_close
      - DConf dump at session_close

+ It is called by an autostart ~/.config/autostart/epfl_roaming.desktop as username :
$ epfl_roaming.py --session
  does :
    - DConf load

+ It is called by a systemd service /etc/systemd/system/epfl_roaming_on_shutdown.service at shutdown|reboot as root :
$ epfl_roaming.py --on_halt
  does :
    - run roaming_close for every user still logged before network is turned off.

It requires packages:
$ sudo apt install python-lockfile

It requires to work with script manage_cred.py
"""

__version__ = "0.4.0"

import os
import sys
import re
import argparse
import pwd, grp
import ldap
import pickle
import subprocess
import lockfile
import shutil
import xml.dom.minidom
import datetime
import signal
import time
import traceback
import collections

### CONSTANTS
LOG_PAM = "/var/log/epfl_roaming.log"
LOG_SESSION = "/tmp/epfl_roaming_{username}.log" # username replaced during execution time

CONFIG_FILE = "/usr/local/etc/epfl_roaming.conf"

LDAP_SERVER = "ldap://ldap.epfl.ch"
LDAP_BASE_DN = "c=ch"
LDAP_SCOPE = ldap.SCOPE_SUBTREE
LDAP_NB_RETRY = 3

RM_MAX_ATTEMPT = 3
RM_SLEEP = 1
UMOUNT_MAX_ATTEMPT = 3
UMOUNT_SLEEP = 1

MANAGE_CRED_FLAG_FILE = "/var/run/epfl_roaming/manage_cred.flag"
MANAGE_CRED_PID_FILE = "/var/run/manage_cred/manage_cred_{username}.pid"
MANAGE_CRED_TIMEOUT = 3
MANAGE_CRED_TERM = True

VAR_RUN = "/var/run/epfl_roaming"
SEMAPHORE_LOCK_FILE = "/var/run/epfl_roaming/global_lock"
SESSIONS_COUNT_FILE = "/var/run/epfl_roaming/sessions_count"

class PreventInterrupt(object):
    def __init__(self):
        pass

    def __enter__(self):
        PreventInterrupt.__no_interrupt__()

    def __exit__(self, typ, val, tb):
        PreventInterrupt.__can_interrupt__()

    @classmethod
    def is_interruptible(cls):
        try:
            return cls.__can_interrupt
        except Exception:
            return True

    @classmethod
    def __no_interrupt__(cls):
        cls.__can_interrupt = False

    @classmethod
    def __can_interrupt__(cls):
        cls.__can_interrupt = True

class UserIdentity():
    def __init__(self, user):
        self.user = user

    def __enter__(self):
        os.setegid(int(self.user.gid))
        os.seteuid(int(self.user.uid))
        IO.write("ID changed : %s" % (os.getresuid(), ))

    def __exit__(self, typ, val, tb):
        os.seteuid(0)
        os.setegid(0)
        IO.write("ID changed : %s" % (os.getresuid(), ))

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

class NameSpace(object):
    def __repr__(self):
        type_name = type(self).__name__
        args_string = []
        for arg in self._get_args():
            args_string.append(repr(arg))
        for name, value in self._get_kwargs():
            args_string.append("%s=%r" % (name, value))
        return "%s(%s)" % (type_name, ", ".join(args_string))

    def _get_kwargs(self):
        return sorted(self.__dict__.items())

    def _get_args(self):
        return []

class Ldap(object):
    def __init__(self):
        success = False
        for _ in range(LDAP_NB_RETRY):
            try:
                self.l = ldap.initialize(LDAP_SERVER)
                success = True
            except Exception as e:
                time.sleep(1)
        if not success:
            raise e

    def search_s(self, l_filter, l_attrs):
        for _ in range(LDAP_NB_RETRY):
            try:
                return self.l.search_s(
                    base=LDAP_BASE_DN,
                    scope=LDAP_SCOPE,
                    filterstr=l_filter,
                    attrlist=l_attrs
                )
            except Exception as e:
                time.sleep(1)
        raise e

def run_cmd(cmd, s_cmd=None, env=None, stdin=None, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, s_input=None, shell=False):
    p = subprocess.Popen(
        cmd,
        env=env,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        shell=shell,
    )
    if s_cmd != None:
        IO.write("-> (%s) %s" % (p.pid, s_cmd))
    else:
        if shell:
            IO.write("-> (%s) %s" % (p.pid, cmd))
        else:
            IO.write("-> (%s) %s" % (p.pid, " ".join(cmd)))
    output = p.communicate(s_input)[0].decode()
    if output != "":
        IO.write("|  (%s) " % p.pid + re.sub(r"\n", "\n|  (%s) " % p.pid, output))

    if p.returncode == 0:
        IO.write("ok (%s)" % p.pid)
    else:
        IO.write("Error: Returned non-zero exit status %d (%s)" % (p.returncode, p.pid))
    return p.returncode == 0

def read_options():
    """
        Parse command line args
    """
    print(" ".join(sys.argv))
    parser = argparse.ArgumentParser(description="EPFL Roaming.")
    parser.add_argument(
        "--pam",
        help="PAM related actions (!=lightdm) : filers (u)mount, folders/files link/copy, DConf save",
        action="store_const",
        dest="context",
        default=None,
        const="pam",
    )
    parser.add_argument(
        "--session",
        help="Session (DConf load)",
        action="store_const",
        dest="context",
        const="session",
    )
    parser.add_argument(
        "--on_halt",
        help="Hold it's execution until all session have been cleaned by epfl_roaming.py (for shutdown/reboot).",
        action="store_const",
        dest="context",
        const="on_halt",
    )
    parser.add_argument(
        "--list_users",
        help="List users currently logged in and how many sessions they have.",
        action="store_const",
        dest="context",
        const="list_users",
    )
    parser.add_argument(
        "--test_load",
        help="Load DConf (test)",
        action="store_const",
        dest="context",
        const="test_load",
    )
    parser.add_argument(
        "--test_dump",
        help="Dump DConf (test)",
        action="store_const",
        dest="context",
        const="test_dump",
    )
    options = parser.parse_args()

    if options.context == None:
        parser.print_help()
        sys.exit(1)

    return options

def read_user(options, on_halt_username=None):
    """
        Extract all necessary info for the user
    """
    user = NameSpace()
    if options.context == "pam":
        user.username = os.environ.get("PAM_USER", None)
        # SERVICE : lightdm | sshd | login | gdm-password
        # other services (like slurm) are not taken in account in epfl_roaming
        user.conn_service = os.environ.get("PAM_SERVICE", None)
        # TTY : :0 | ssh
        user.conn_tty = os.environ.get("PAM_TTY", None)
        # TYPE : open_session | close_session
        user.conn_type = os.environ.get("PAM_TYPE", None)
    elif options.context == "on_halt":
        user.username = on_halt_username
    else:
        user.username = pwd.getpwuid(os.getuid())[0]
    user.username = user.username.split('@')[0]
    user.home_dir = os.path.expanduser("~%s" % user.username)

    # shortcuts
    if not user.home_dir.startswith("/home/"):
        return user

    try:
        pw = pwd.getpwnam(user.username)
    except (KeyError, TypeError):
        return user

    #~ if options.context in ("pam", "on_halt"):
    my_ldap = Ldap()
    try :
        ldap_res = my_ldap.search_s(
            # l_filter="uidNumber=%s" % pw.pw_uid,
            l_filter="uid=%s" % user.username,
            l_attrs=["uniqueIdentifier"]
        )
        unique_identifier = ldap_res[0][1]["uniqueIdentifier"][0].decode()
    except (KeyError, IndexError): # no pw_uid or not in ldap!
        return user

    # EPFL Guests
    if ldap_res[0][0].endswith("o=epfl-guests,c=ch"):
        user.epfl_account_type = "guest"
        return user

    # Normal EPFL account
    automount_informations = ("", "", "", "")
    ldap_res = my_ldap.search_s(
        l_filter="cn=%s" % user.username,
        l_attrs=["automountInformation"]
    )
    for entry in ldap_res:
        if entry[1].get("automountInformation") != None:
            automount_informations = entry[1]["automountInformation"][0].decode()
            automount_informations = re.findall(r'-fstype=(\w+),(.+) ([\w\.]+):(.+)$', automount_informations)[0]

    gr = grp.getgrgid(pw.pw_gid)
    user.epfl_account_type = "normal"
    user.uid = str(pw.pw_uid)
    user.gid = str(pw.pw_gid)
    user.groupname = gr.gr_name
    user.domain = "INTRANET"
    user.sciper = unique_identifier
    user.sciper_digit = unique_identifier[-1]
    user.automount_fstype = automount_informations[0]
    user.automount_options = automount_informations[1]
    user.automount_host = automount_informations[2]
    user.automount_path = automount_informations[3]

    return user

def check_options(options, user):
    """
        Performs all required checks
    """
    if options.context == "pam" and user.conn_service not in ("lightdm", "sshd", "login", "common-session", "gdm-password", "gdm-vmwcred"):
        IO.write("Not doing anything for PAM_SERVICE '%s'" % user.conn_service)
        sys.exit(0)
    if options.context in ("pam", "on_halt") and os.geteuid() != 0:
        IO.write("Error: this should be run as root.")
        sys.exit(1)
    if options.context == "session" and os.geteuid() == 0:
        IO.write("Error: this should not be running as root.")
        sys.exit(1)
    if user.username == None:
        if options.context == "pam":
            IO.write("Error: Could not read PAM_USER")
        else:
            IO.write("Error: Could not read USER")
        sys.exit(1)
    if not user.home_dir.startswith("/home/"):
        IO.write("Nothing to do for user %s (home dir: %s)" % (user.username, user.home_dir))
        sys.exit(0)
    if options.context == "pam":
        if user.conn_type == None:
            IO.write("Error: Could not read PAM_TYPE")
            sys.exit(1)
        if user.conn_type not in ("open_session", "close_session"):
            IO.write("Error: Unknown PAM_TYPE : %s" % user.conn_type)
            sys.exit(1)
    if options.context in ("pam", "on_halt"):
        try:
            user.epfl_account_type
        except AttributeError:
            IO.write("Warning: Incomplete user informations found in LDAP. Exiting.")
            sys.exit(0)

def apply_subst(name, user):
    """
      user.username forced in lowercase (VMware Horizon)
    """

    name = re.sub(r'_SCIPER_DIGIT_', user.sciper_digit, name)
    name = re.sub(r'_SCIPER_', user.sciper, name)
    name = re.sub(r'_USERNAME_', user.username.lower(), name)
    name = re.sub(r'_HOME_DIR_', user.home_dir, name)
    name = re.sub(r'_GROUPNAME_', user.groupname, name)
    name = re.sub(r'_DOMAIN_', user.domain, name)
    name = re.sub(r'_UID_', user.uid, name)
    name = re.sub(r'_GID_', user.gid, name)
    name = re.sub(r'_FSTYPE_', user.automount_fstype, name)
    name = re.sub(r'_HOST_', user.automount_host, name)
    name = re.sub(r'_PATH_', user.automount_path, name)
    name = re.sub(r'_OPTIONS_', user.automount_options, name)
    return name

def read_config(options, user):
    """
        Read and Parse config file
    """

    class ConfigLineException(Exception):
        def __init__(self, line, reason="syntax"):
            self.line = line
            self.reason = reason

    conf = {"mounts" : {}, "programmer" : [], "posixfs" : [], "posixmnt" : [], "links" : [], "su_links" : [], "dconf" : {},}

    dconf_file = ""

    # Au cas où programmer, posixfs (posixmnt) n'existent pas dans epfl_roaming.conf
    user.programmer = False
    user.posixfs = False
    user.posixovl = None

    try:
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                try:
                    line = re.sub(r'\s*#.*$', '', line).rstrip()
                    if line == "":
                        continue
                    try:
                        subject = re.findall(r'(\S+)', line)[0]
                    except IndexError as e:
                        raise ConfigLineException(line, reason="syntax")

                    ## Mounts
                    if subject == "mount":
                        if not options.context in ("pam", "on_halt"):
                            continue
                        line = apply_subst(line, user)
                        mount_point = get_mount_point(line)
                        conf["mounts"][mount_point] = line
                    ## Programmer
                    elif subject == "programmer":
                        try:
                            target, link_name = re.findall(r'"([^"]+)"', line)[0:2]
                            target = apply_subst(target, user)
                            link_name = apply_subst(link_name, user)
                            conf["programmer"].append((target, link_name))
                            # target = 1st parameter i.e. Desktop/myfiles/Programmation
                            # link_name = 2nd paramater i.e. YES or NO
                            if link_name.upper() == 'YES':
                              user.programmer = True
                              user.programmer_dir = target
                            else:
                              user.programmer = False
                            IO.write("Debug: programmer target " + target)
                            IO.write("Debug: programmer link_name " + link_name)
                        except IndexError as e:
                            raise ConfigLineException(line, reason="syntax")
                    ## posixfs
                    elif subject == "posixfs":
                        try:
                            target, link_name = re.findall(r'"([^"]+)"', line)[0:2]
                            target = apply_subst(target, user)
                            link_name = apply_subst(link_name, user)
                            conf["posixfs"].append((target, link_name))
                            # target = 1st parameter i.e. Desktop/myfiles/fs/posix-1G-disk.fs
                            # link_name = 2nd paramater i.e. 1024M or 1G
                            user.posixfs_size = link_name.upper()
                            user.posixfs_path = target
                            IO.write("Debug: posixfs size " + user.posixfs_size)
                            IO.write("Debug: posixfs path " + user.posixfs_path)
                        except IndexError as e:
                            raise ConfigLineException(line, reason="syntax")
                    ## posixmnt
                    elif subject == "posixmnt":
                        try:
                            target, link_name = re.findall(r'"([^"]+)"', line)[0:2]
                            target = apply_subst(target, user)
                            link_name = apply_subst(link_name, user)
                            conf["posixmnt"].append((target, link_name))
                            # target = 1st parameter i.e. Desktop/posixfs
                            # link_name = 2nd paramater i.e. YES or NO
                            if link_name.upper() == 'YES':
                              user.posixfs = True
                              user.posixmnt_path = target
                              IO.write("Debug: posixfs is set " + str(user.posixfs))
                              IO.write("Debug: posixmnt  path " + user.posixmnt_path)
                            else:
                              user.posixfs = False
                              IO.write("Debug: posixfs is set " + str(user.posixfs))
                        except IndexError as e:
                            raise ConfigLineException(line, reason="syntax")
                    ## posixovl
                    elif subject == "posixovl":
                        try:
                            lower, mountpoint = re.findall(r'"([^"]+)"', line)[0:2]
                            PosixOVLSettings = collections.namedtuple('PosixOVLSettings', ['lower', 'mountpoint'])
                            user.posixovl = PosixOVLSettings(
                                os.path.join(user.home_dir, apply_subst(lower, user)),
                                os.path.join(user.home_dir, apply_subst(mountpoint, user)))
                        except IndexError as e:
                            raise ConfigLineException(line, reason="syntax")

                    ## Links
                    elif subject == "link":
                        try:
                            target, link_name = re.findall(r'"([^"]+)"', line)[0:2]
                            target = apply_subst(target, user)
                            link_name = apply_subst(link_name, user)
                            conf["links"].append((target, link_name))
                        except IndexError as e:
                            raise ConfigLineException(line, reason="syntax")

                    ## Links
                    elif subject == "su_link":
                        try:
                            target, link_name = re.findall(r'"([^"]+)"', line)[0:2]
                            target = apply_subst(target, user)
                            link_name = apply_subst(link_name, user)
                            conf["su_links"].append((target, link_name))
                        except IndexError as e:
                            raise ConfigLineException(line, reason="syntax")

                    ## dconf file
                    elif subject == "dconf_file":
                        try:
                            dconf_file = re.findall(r'"(.+)"', line)[0]
                            dconf_file = apply_subst(dconf_file, user)
                        except IndexError as e:
                            raise ConfigLineException(line, reason="syntax")

                    ## dconf entry
                    elif subject == "dconf":
                        if dconf_file == "":
                            raise ConfigLineException(line, reason="dconf key before dconf_file instruction")
                        try:
                            dconf_entry = re.findall(r'"(.+)"', line)[0]
                            conf["dconf"].setdefault(dconf_file, []).append(dconf_entry)
                        except IndexError as e:
                            raise ConfigLineException(line, reason="syntax")
                    else:
                        raise ConfigLineException(line, reason="syntax")

                except ConfigLineException as e:
                    IO.write("Error: ", eol = "")
                    if e.reason == "syntax":
                        IO.write("Unrecognized line :\n%s" % e.line)
                    else:
                        IO.write("%s :\n%s" % (e.reason, e.line))
                    IO.write("Continuing ignoring that one.")

    except IOError:
        IO.write("Conf file %s not readable" % CONFIG_FILE)
        return conf

    ###
    # Clean DConf (remove englobing elements)
    for dconf_file in conf["dconf"]:
        indexes_to_drop = set()
        for i in range(len(conf["dconf"][dconf_file])):
            for j in range(len(conf["dconf"][dconf_file])):
                if i == j:
                    continue
                if conf["dconf"][dconf_file][i].startswith(conf["dconf"][dconf_file][j]):
                    indexes_to_drop.add(i)
        for i in reversed(sorted(list(indexes_to_drop))):
            del(conf["dconf"][dconf_file][i])

    return conf

def count_sessions(user, increment=0, clear_count=False):
    """
        Increments/decrements session count for current user
    """
    try:
        with open(SESSIONS_COUNT_FILE, "rb") as f:
            user_sessions = pickle.load(f)
    except:
        user_sessions = {}
    user_sessions.setdefault(user.username, 0)

    old_count = user_sessions[user.username]
    if clear_count:
        new_count = 0
        user_sessions.pop(user.username)
    else:
        new_count = max(user_sessions[user.username] + increment, 0)
        if new_count <= 0:
            user_sessions.pop(user.username)
        else:
            user_sessions[user.username] = new_count
    IO.write("%i -> %i" % (old_count, new_count))
    try:
        with open(SESSIONS_COUNT_FILE, "wb") as f:
            pickle.dump(user_sessions, f)
    except Exception as e:
        IO.write("Error : %s" % e)
        raise
    return old_count, new_count

def get_mount_point(mount_instruction):
    """
        Guess mointpoint from a mount instruction
    """
    line = mount_instruction
    line = re.sub(r'-o \S+\s*', '', line)
    line = re.sub(r'-t \S+\s*', '', line)
    line = re.sub(r'-[fnrsvw]\s*', '', line)
    m = re.search (r'(\S+)\s*$', line)
    if m:
        return m.group(1)
    else:
        IO.write("Error: Mount point not found in %s" % mount_instruction)
        IO.write("Aborting")
        sys.exit(1)

def ismount(path):
    """
        Replaces os.path.ismount which doesn't work for nfsv4 run from root
    """
    p = subprocess.Popen(["mount"], stdout=subprocess.PIPE)
    output = p.communicate()[0].decode()
    return path in re.findall(r' on (\S+)\s+', output)

def dconf_dump(config, user, test=False):
    if not os.path.exists(os.path.join(user.home_dir, ".config/dconf/user")):
        IO.write("dconf_dump : ~/.config/dconf/user not found -> Skipping.")
        return
    IO.write("dconf_dump")

    for dconf_file, keys_to_save in list(config["dconf"].items()):
        dconf_file = os.path.join(user.home_dir, dconf_file)
        IO.write("DConf to %s" % dconf_file)
        dir_save_to = os.path.dirname(dconf_file)
        if not os.path.exists(dir_save_to):
            IO.write("mkdir -p %s" % dir_save_to)
            os.makedirs(dir_save_to)

        dump_succeeded = True
        dump_dconf = ""
        for k in keys_to_save:
            IO.write("+ %s" % k)
            if k[-1] == "/":
                if test:
                    cmd = ["dconf", "dump", k]
                else:
                    cmd = ["sudo", "-u", user.username, "dconf", "dump", k]
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, env={})
                k_dumped = p.communicate()[0]

                for line in k_dumped.split("\n"):
                    try:
                        fold = re.findall(r'^\[(.*)\]$', line)[0]
                        if fold == "/":
                            dump_dconf += "[%s]\n" % k[1:-1]
                        else:
                            dump_dconf += "[%s]\n" % os.path.join(k[1:-1], fold)
                    except IndexError as e:
                        dump_dconf += line + "\n"
            else:
                if test:
                    cmd = ["dconf", "read", k]
                else:
                    cmd = ["sudo", "-u", user.username, "dconf", "read", k]
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                k_dumped = p.communicate()[0]
                if k_dumped != "":
                    dump_dconf += """
[%s]
%s=%s
""" % (os.path.dirname(k)[1:], os.path.basename(k), k_dumped)
            if p.returncode != 0:
                dump_succeeded = False
                break
        if dump_succeeded and dump_dconf != "":
            with open(dconf_file, "w") as f:
                f.write(dump_dconf)
        else:
            IO.write("DConf dump did not succeeded. Aborting this.")

def dconf_load(config, user, test=False):
    IO.write("dconf_load")
    for dconf_file in config["dconf"]:
        dconf_file = os.path.join(user.home_dir, dconf_file)
        if os.path.exists(dconf_file):
            with open(dconf_file, "r") as f:
                dconf_dumped = f.read()
                # "dbus-launch", "--exit-with-session",
                cmd = ["dconf", "load", "/"]
                run_cmd(
                    cmd=cmd,
                    s_cmd="cat %s | %s" % (dconf_file, " ".join(cmd)),
                    stdin=subprocess.PIPE,
                    s_input=dconf_dumped,
                )

def filers_mount(config, user):
    """
        Triggers manage_cred's extension to mount for us
    """
    try:
        with open(MANAGE_CRED_PID_FILE.format(username=user.username), "r") as f:
            manage_cred_pid = int(f.readline())
    except:
        IO.write("Warning, could not find manage_cred process. Not gonna mount filers.")
        return

    open(MANAGE_CRED_FLAG_FILE, "a").close()

    os.kill(manage_cred_pid, signal.SIGUSR2)

    manage_cred_finished = False
    for _ in range(MANAGE_CRED_TIMEOUT*10):
        time.sleep(0.1)
        if not os.path.exists(MANAGE_CRED_FLAG_FILE):
            manage_cred_finished = True
            break

    if not manage_cred_finished:
        IO.write("Warning, manage_cred didn't complete mount filers.")

    if MANAGE_CRED_TERM:
        os.kill(manage_cred_pid, signal.SIGTERM)

def umount_posixfs(user):
    success = True
    IO.write("Proceeding POSIX Filesystem umount!")
    run_cmd(cmd=['/bin/fusermount', '-u', os.path.join(user.home_dir, user.posixmnt_path)])
    return success

def filers_umount(config, user):
    """
        Performs all umount
        return True if all succeed
        return False if one failed
    """
    IO.write("Proceeding umount!")
    success = True
    for mount_point in list(config["mounts"].keys()) + [os.path.join(user.home_dir, ".gvfs"), os.path.join(user.home_dir, "freerds_client"),]:
        if not ismount(mount_point):
            IO.write("%s not mounted. Skip." % mount_point)
            continue
        for i in range(UMOUNT_MAX_ATTEMPT):
            if run_cmd(
                cmd=["umount", "-fl", mount_point],
            ):
                break
            time.sleep(UMOUNT_SLEEP)
        if ismount(mount_point):
            success = False
    return success

def make_homedir(user):
    if not os.path.exists(user.home_dir):
        IO.write("Make homedir")
        run_cmd(
            cmd=["cp", "-R", "/etc/skel", user.home_dir]
        )
        run_cmd(
            cmd=["chown", "-R", "%s:" % user.username, user.home_dir]
        )
    else:
        IO.write("homedir already exists.")

def make_progdir(user):
    progdir = user.home_dir + "/" + user.programmer_dir
    if not os.path.exists(progdir):
        IO.write("Make progdir to " + progdir)
        with UserIdentity(user):
            run_cmd(
                cmd=["mkdir", "-p", progdir]
            )
    else:
        IO.write("progdir already exists.")
    # ACLs appliqués à chaque fois !
    prog = str(progdir.split("/")[-1])
    with UserIdentity(user):
        run_cmd(
            cmd=["smbcacls", "//" + user.automount_host.split('.')[0] + ".intranet.epfl.ch/data", user.username + "/" + prog, "-k", "--add", "ACL:INTRANET\\" + user.username + ":ALLOWED/OI|CI/FULL"]
            # smbcacls //files9.intranet.epfl.ch/data fabbri/Programmation -k --add "ACL:INTRANET\\$USER:ALLOWED/OI|CI/FULL"
        )
    IO.write("ACLs to progdir applied.")

def obsolescent_mount_loopback_fuse_ext2(user):
    posixfs_path = os.path.join(user.home_dir, user.posixfs_path)
    posixmnt_path = os.path.join(user.home_dir, user.posixmnt_path)

    if not os.path.exists(posixfs_path):
        IO.write("No obsolescent ext2 image found at " + posixfs_path + ", skipping")
        return False

    with UserIdentity(user):
        run_cmd(
            cmd = ['/sbin/fsck.ext2', '-fy', posixfs_path]
        )
        IO.write("Check posix fs: " + posixfs_path)

        run_cmd(
            cmd=["mkdir", "-p", posixmnt_path]
        )

        IO.write("Now mounting: " + posixmnt_path)
        run_cmd(
            cmd = ['/usr/local/bin/fuse-ext2', '-o', 'rw+,allow_other,uid=' + str(user.uid) + ',gid=' + str(user.gid), posixfs_path, posixmnt_path]
        )
    # end of with UserIdentity

    IO.write("Mounted obsolescent loopback posix fs: " + posixfs_path + " to " + posixmnt_path)
    return True

def mount_posixovl(user):
    with UserIdentity(user):
        run_cmd(
            cmd=["mkdir", "-p", user.posixovl.mountpoint]
        )
        IO.write("Now mounting %s to %s" % (user.posixovl.lower, user.posixovl.mountpoint))
        run_cmd(
            cmd = ['mount.posixovl', '-S', user.posixovl.lower, user.posixovl.mountpoint]
        )
    IO.write("Mounted posixovl from %s to %s" % (user.posixovl.lower, user.posixovl.mountpoint))

def proceed_roaming_open(config, user):
    IO.write("Proceeding roaming 'open'!")
    folders_to_mkdir_as_root = []

    def mkdir(folder_name, as_root=False):
        IO.write("mkdir -p %s" % folder_name)
        try:
            os.makedirs(folder_name)
        except OSError:
            if not as_root:
                folders_to_mkdir_as_root.append(folder_name)
                IO.write("... failed. Will retry as root later!")
            else:
                IO.write("... failed.")
        if as_root:
            run_cmd(
                cmd=["chown", "-R", "%s:" % user.username, folder_name]
            )

    def prepare_link(target, link_name, user):
        if re.search(r'/$', target):
            target_is_dir = True
        else:
            target_is_dir = False
        if re.match(r'\+', target):
            force_link = True
            target = target[1:]
        else:
            force_link = False

        target = os.path.normpath(os.path.join(user.home_dir, target))
        link_name = os.path.normpath(os.path.join(user.home_dir, link_name))
        target_parent = os.path.normpath(target + "/..")
        link_name_parent = os.path.normpath(link_name + "/..")

        already_done = (os.path.islink(link_name) and
                        os.readlink(link_name) == target)
        if already_done:
            return

        if force_link:
            # create target if non existent
            if target_is_dir:
                if not os.path.exists(target):
                    mkdir(target)
            else:
                if not os.path.exists(target_parent):
                    mkdir(target_parent)
                open(target, "a").close()
        else:
            no_target = not os.path.exists(target)
            if no_target:
                return

        # Remove link_name if already exist
        if os.path.isdir(link_name) and not os.path.islink(link_name):
            shutil.rmtree(link_name)
        elif os.path.lexists(link_name):
            os.unlink(link_name)

        # Make the symlink
        if not os.path.exists(link_name_parent):
            mkdir(link_name_parent)
        IO.write("ln -s %s %s" % (target, link_name))
        os.symlink(target, link_name)

    ## Make homedir
    make_homedir(user)

    ## Mounts (sudo)
    filers_mount(config, user)

    ## Make progdir 2nd
    if user.programmer:
      make_progdir(user)
      IO.write("Debug: computer programmer.")

    ## Virtual File System in Userspace (POSIX compliant)
    has_obsolescent_posixfs = False
    if user.posixfs:
      if obsolescent_mount_loopback_fuse_ext2(user):
          IO.write("Debug: mounted (obsolete) loopback POSIX Filesystem.")
          has_obsolescent_posixfs = True

    if (not has_obsolescent_posixfs) and user.posixovl:
      mount_posixovl(user)

    with UserIdentity(user):
        ## Links
        for target, link_name in config["links"] + config["su_links"]:
            prepare_link(target, link_name, user)

    for folder_name in folders_to_mkdir_as_root:
        mkdir(folder_name, as_root=True)


def proceed_roaming_close(options, config, user):
    IO.write("Proceeding roaming 'close'!")

    ## Links
    with UserIdentity(user):
        for target, link_name in config["links"]:
            if re.match(r'\+', target):
                target = target[1:]
            target = os.path.normpath(os.path.join(user.home_dir, target))
            target_parent = os.path.normpath(target + "/..")
            link_name = os.path.normpath(os.path.join(user.home_dir, link_name))
            link_name_parent = os.path.normpath(link_name + "/..")
            if os.path.exists(link_name):
                if os.path.realpath(link_name) != os.path.realpath(target):
                    # link_name doesn't point to target -> new content -> rm old content.
                    run_cmd(
                        cmd=["rm", "-rf", "--one-file-system", target],
                    )
                if not os.path.exists(target):
                    if not os.path.lexists(target_parent):
                        IO.write("mkdir -p %s" % target_parent)
                        os.makedirs(target_parent)
                    if os.path.isdir(link_name):
                        run_cmd(
                            cmd=["cp", "-R", link_name, target],
                        )
                    else:
                        run_cmd(
                            cmd=["cp", link_name, target],
                        )
        dconf_dump(config, user)

    # Unmount POSIX Filesystem
    if not umount_posixfs(user):
        IO.write("Some trouble in unmonting POSIX Filesystem.")
        return

    # Umounts (sudo)
    if not filers_umount(config, user):
        IO.write("Skipping rm -rf.")
        return

    # RM
    for i in range(RM_MAX_ATTEMPT):
        success = run_cmd(
            cmd=["rm", "-rf", "--one-file-system", user.home_dir]
        )
        if success:
            break
        time.sleep(RM_SLEEP)

def proceed_guest_open(user):
    IO.write("Proceeding guest 'open'!")
    make_homedir(user)

def proceed_guest_close(user):
    IO.write("Proceeding guest 'close'!")
    IO.write("Nothing to be done ...")

def list_current_user_sessions(display=False):
    try:
        with open(SESSIONS_COUNT_FILE, "rb") as f:
            user_sessions = pickle.load(f)
    except:
        user_sessions = {}
    if display:
        if len(user_sessions) == 0:
            print("Currently, no user has an open session.")
        else:
            print("Currently, these users have an open session :")
            for username in user_sessions:
                print("%s: %i" % (username, user_sessions[username]))
    return user_sessions

def proceed_on_halt(options):
    with IO(LOG_PAM):
        IO.write("\n*** %s" % datetime.datetime.now())
        IO.write("Proceeding 'On Halt'!")
        try:
            with PreventInterrupt():
                with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                    for username in list_current_user_sessions():
                        IO.write("on_halt %s" % username)
                        user = read_user(options, username)
                        count_sessions(user, clear_count=True)
                        if user.epfl_account_type == "guest":
                            proceed_guest_close(user)
                        else:
                            config = read_config(options, user)
                            proceed_roaming_close(options, config, user)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            IO.write("\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
        IO.write("done.")

def signal_handler(signum, frame):
    IO.write("received signal %s" % signum)
    if PreventInterrupt.is_interruptible():
        IO.write("exit.")
        sys.exit(1)
    else:
        IO.write("not interruptible yet. Continuing...")


if __name__ == '__main__':
    try:
        os.makedirs(VAR_RUN)
    except OSError:
        pass

    # Manage the kill -TERM  ... unfortunately not kill -9
    signal.signal(signal.SIGTERM, signal_handler)
    #~ signal.signal(signal.SIGKILL, signal_handler)

    options = read_options()
    if options.context == "on_halt":
        proceed_on_halt(options)
        sys.exit(0)
    if options.context == "list_users":
        list_current_user_sessions(display=True)
        sys.exit(0)

    user = read_user(options)

    if options.context in ("pam",):
        logfile_name = LOG_PAM
    else:
        logfile_name = LOG_SESSION.format(username=user.username)

    with IO(logfile_name):
        try:
            IO.write("\n*** %s" % datetime.datetime.now())
            operation = options.context
            if options.context == "pam":
                operation += "_%s" % user.conn_type

            IO.write("%s %s (uid=%s euid=%s)" % (operation, user.username, os.getuid(), os.geteuid()))
            check_options(options, user)

            # EPFL Guests shortcut
            if user.epfl_account_type == "guest":
                if options.context == "pam":
                    if user.conn_type == "open_session":
                        with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                            if count_sessions(user, increment=+1) == (0, 1):
                                proceed_guest_open(user)
                    elif user.conn_type == "close_session":
                        with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                            if count_sessions(user, increment=-1) == (1, 0):
                                proceed_guest_close(user)
                sys.exit(0)

            config = read_config(options, user)

            if options.context == "pam":
                if user.conn_type == "open_session":
                    with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                        if count_sessions(user, increment=+1) == (0, 1):
                            proceed_roaming_open(config, user)
                elif user.conn_type == "close_session":
                    with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                        if count_sessions(user, increment=-1) == (1, 0):
                            with PreventInterrupt():
                                proceed_roaming_close(options, config, user)

            elif options.context == "session":
                dconf_load(config, user)

            elif options.context == "test_load":
                dconf_load(config, user, test=True)
            elif options.context == "test_dump":
                dconf_dump(config, user, test=True)

            IO.write("Everything complete.")
            sys.exit(0)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            IO.write("\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
