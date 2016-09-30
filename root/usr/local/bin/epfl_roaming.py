#!/usr/bin/env python
# -*- coding: utf-8 -*-

###
# Bancal Samuel
# 121002

# 121105 :
# GConf can't make it work! Giving up for now.

###
# Usage :
#
# - epfl_roaming.py --pam
#     trigged by PAM at session_open & session_close
#     run as root
#     does :
#       - mount & umount
#       - files/folders ln -s & cp
#       - rm -rf at session_close
#       - GConf dump (Disabled) at session_close
#       - DConf dump at session_close
#
# - epfl_roaming.py --session
#   trigged at Gnome/Unity new session
#   as user
#   does :
#     - GConf load (Disabled)
#     - DConf load
#
# - epfl_roaming.py --on_halt
#   trigged by /etc/init/epfl_roaming.conf at shutdown/reboot
#   does :
#     - run roaming_close for every user still logged
#
# - epfl_roaming.py --torque_prologue
#   trigged by /var/spool/torque/mom_priv/prologue
#   does :
#     - empty home dir for user
#
# - epfl_roaming.py --torque_epilogue
#   trigged by /var/spool/torque/mom_priv/epilogue
#   does :
#     - simple remove home dir if not other session for that user
#

###
# Requires :
# sudo apt install python-lockfile

import os
import sys
import re
import argparse
import pwd, grp
import ldap
import pickle
import subprocess
# import pprint
import lockfile
import shutil
import xml.dom.minidom
import datetime
import signal
import time
import traceback

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

UNLINK_CRED_FILE = True

SEMAPHORE_LOCK_FILE = "/tmp/epfl_roaming_global_lock"

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
        for _ in xrange(LDAP_NB_RETRY):
            try:
                self.l = ldap.initialize(LDAP_SERVER)
                success = True
            except Exception, e:
                time.sleep(1)
        if not success:
            raise e

    def search_s(self, l_filter, l_attrs):
        for _ in xrange(LDAP_NB_RETRY):
            try:
                return self.l.search_s(
                    base=LDAP_BASE_DN,
                    scope=LDAP_SCOPE,
                    filterstr=l_filter,
                    attrlist=l_attrs
                )
            except Exception, e:
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
    output = p.communicate(s_input)[0]
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
    print " ".join(sys.argv)
    parser = argparse.ArgumentParser(description="EPFL Roaming.")
    parser.add_argument(
        "--pam",
        help="PAM related actions (!=lightdm) : filers (u)mount, folders/files link/copy, GConf/DConf save",
        action="store_const",
        dest="context",
        default=None,
        const="pam",
    )
    parser.add_argument(
        "--session",
        help="Session (GConf/DConf load)",
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
        "--test_load",
        help="Load GConf and DConf (test)",
        action="store_const",
        dest="context",
        const="test_load",
    )
    parser.add_argument(
        "--test_dump",
        help="Dump GConf and DConf (test)",
        action="store_const",
        dest="context",
        const="test_dump",
    )
    parser.add_argument(
        "--torque_prologue",
        help="Prepare home dir for Torque job",
        action="store_const",
        dest="context",
        const="torque_prologue",
    )
    parser.add_argument(
        "--torque_epilogue",
        help="Close home dir after Torque job",
        action="store_const",
        dest="context",
        const="torque_epilogue",
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
        # SERVICE : lightdm | sshd | login
        # other services (like slurm) are not taken in account in epfl_roaming
        user.conn_service = os.environ.get("PAM_SERVICE", None)
        # TTY : :0 | ssh
        user.conn_tty = os.environ.get("PAM_TTY", None)
        # TYPE : open_session | close_session
        user.conn_type = os.environ.get("PAM_TYPE", None)
    elif options.context in ("torque_prologue", "torque_epilogue"):
        user.username = os.environ.get("USER", None)
    elif options.context == "on_halt":
        user.username = on_halt_username
    else:
        user.username = pwd.getpwuid(os.getuid())[0]
    user.home_dir = os.path.expanduser("~%s" % user.username)

    # shortcuts
    if (options.context in ("torque_prologue", "torque_epilogue")) or \
       (not user.home_dir.startswith("/home/")):
        return user

    try:
        pw = pwd.getpwnam(user.username)
    except (KeyError, TypeError):
        return user

    #~ if options.context in ("pam", "on_halt"):
    my_ldap = Ldap()
    try :
        ldap_res = my_ldap.search_s(
            l_filter="uidNumber=%s" % pw.pw_uid,
            l_attrs=["uniqueIdentifier"]
        )
        unique_identifier = ldap_res[0][1]["uniqueIdentifier"][0]
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
            automount_informations = entry[1]["automountInformation"][0]
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
    #~ if options.context == "pam" and user.conn_service == "lightdm":
        #~ IO.write("Not doing things for lightdm sessions trigged by PAM")
        #~ sys.exit(0)
    if options.context == "pam" and user.conn_service not in ("lightdm", "sshd", "login"):
        IO.write("Not doing anything for PAM_SERVICE '%s'" % user.conn_service)
        sys.exit(0)
    if options.context in ("pam", "on_halt", "torque_prologue", "torque_epilogue") and os.geteuid() != 0:
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
            IO.write("Warning: Incomplete user informations found. Exiting.")
            sys.exit(1)

def apply_subst(name, user):
    name = re.sub(r'_SCIPER_DIGIT_', user.sciper_digit, name)
    name = re.sub(r'_SCIPER_', user.sciper, name)
    name = re.sub(r'_USERNAME_', user.username, name)
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

    conf = {"mounts" : {}, "links" : [], "su_links" : [], "gconf" : {}, "dconf" : {},}

    if options.context in ("torque_prologue", "torque_epilogue"):
        return conf

    gconf_file = ""
    dconf_file = ""

    try:
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                try:
                    line = re.sub(r'\s*#.*$', '', line).rstrip()
                    if line == "":
                        continue
                    try:
                        subject = re.findall(r'(\S+)', line)[0]
                    except IndexError, e:
                        raise ConfigLineException(line, reason="syntax")

                    ## Mounts
                    if subject == "mount":
                        if not options.context in ("pam", "on_halt"):
                            continue
                        line = apply_subst(line, user)
                        mount_point = get_mount_point(line)
                        conf["mounts"][mount_point] = line

                    ## Links
                    elif subject == "link":
                        try:
                            target, link_name = re.findall(r'"([^"]+)"', line)[0:2]
                            target = apply_subst(target, user)
                            link_name = apply_subst(link_name, user)
                            conf["links"].append((target, link_name))
                        except IndexError, e:
                            raise ConfigLineException(line, reason="syntax")

                    ## Links
                    elif subject == "su_link":
                        try:
                            target, link_name = re.findall(r'"([^"]+)"', line)[0:2]
                            target = apply_subst(target, user)
                            link_name = apply_subst(link_name, user)
                            conf["su_links"].append((target, link_name))
                        except IndexError, e:
                            raise ConfigLineException(line, reason="syntax")

                    ## gconf file
                    elif subject == "gconf_file":
                        try:
                            gconf_file = re.findall(r'"(.+)"', line)[0]
                            gconf_file = apply_subst(gconf_file, user)
                        except IndexError, e:
                            raise ConfigLineException(line, reason="syntax")

                    ## gconf entry
                    elif subject == "gconf":
                        if gconf_file == "":
                            raise ConfigLineException(line, reason="gconf key before gconf_file instruction")
                        try:
                            gconf_entry = re.findall(r'"(.+)"', line)[0]
                            conf["gconf"].setdefault(gconf_file, []).append(gconf_entry)
                        except IndexError, e:
                            raise ConfigLineException(line, reason="syntax")

                    ## dconf file
                    elif subject == "dconf_file":
                        try:
                            dconf_file = re.findall(r'"(.+)"', line)[0]
                            dconf_file = apply_subst(dconf_file, user)
                        except IndexError, e:
                            raise ConfigLineException(line, reason="syntax")

                    ## dconf entry
                    elif subject == "dconf":
                        if dconf_file == "":
                            raise ConfigLineException(line, reason="dconf key before dconf_file instruction")
                        try:
                            dconf_entry = re.findall(r'"(.+)"', line)[0]
                            conf["dconf"].setdefault(dconf_file, []).append(dconf_entry)
                        except IndexError, e:
                            raise ConfigLineException(line, reason="syntax")
                    else:
                        raise ConfigLineException(line, reason="syntax")

                except ConfigLineException, e:
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
        for i in xrange(len(conf["dconf"][dconf_file])):
            for j in xrange(len(conf["dconf"][dconf_file])):
                if i == j:
                    continue
                if conf["dconf"][dconf_file][i].startswith(conf["dconf"][dconf_file][j]):
                    indexes_to_drop.add(i)
        for i in reversed(sorted(list(indexes_to_drop))):
            del(conf["dconf"][dconf_file][i])

    return conf

def count_sessions(user, increment):
    """
        Increments/decrements session count for current user
    """
    user_count_file = "/tmp/epfl_count_%s" % user.username
    IO.write("session counter :", eol="")
    counter = 0 # default
    try:
        with open(user_count_file, "r") as f:
            counter = int(f.readline())
    except (IOError, ValueError):
        pass

    IO.write("%i -> %i" % (counter, counter + increment))
    counter += increment
    if counter > 0:
        with open(user_count_file, "w") as f:
            f.write("%i\n" % counter)
    else:
        try:
            os.unlink(user_count_file)
        except OSError:
            pass
    return counter

def get_mount_point(mount_instruction):
    """
        Guess mointpoint from a mount instruction
    """
    line = mount_instruction
    line = re.sub(r'-o \S+\s*', '', line)
    line = re.sub(r'-t \S+\s*', '', line)
    line = re.sub(r'-[fnrsvw]\s*', '', line)
    m = re.search ('(\S+)\s*$', line)
    if m:
        return m.group(1)
    else:
        IO.write("Error: Mount point not found in %s" % mount_instruction)
        IO.write("Aborting")
        sys.exit(1)

def get_credentials(username):
    cred_filename = "/tmp/%s_epfl_cred" % username

    # Decode credential
    def decode(username, enc_password):
        username = unicode(username, 'utf-8')
        factor = len(enc_password) / len(username) + 1
        key = username * factor
        password = "".join([unichr(ord(enc_password[i]) - ord(key[i])) for i in range(0, len(enc_password)) ])
        return password.encode('utf-8')

    try:
        with open(cred_filename, "rb") as f:
            enc_password = pickle.load(f)
    except Exception:
        IO.write("Warning: could not load file %s, skipping." % cred_filename)
        return None
    if UNLINK_CRED_FILE:
        os.unlink(cred_filename)
    return decode(username, enc_password)

def ismount(path):
    """
        Replaces os.path.ismount which doesn't work for nfsv4 run from root
    """
    p = subprocess.Popen(["mount"], stdout=subprocess.PIPE)
    output = p.communicate()[0]
    return path in re.findall(r' on (\S+)\s+', output)

def gconf_dump(config, user, test=False):
    return # NOTE : We had no success with GConf and 12.04 ...
    IO.write("gconf_dump")
    try:
        gconf_work_dir = os.path.join(user.home_dir, ".gconf")
        for gconf_file in config["gconf"]:
            gconf_dirs = {}

            # extract expected dirs (if keys, then add key entry in a list)
            for i in xrange(len(config["gconf"][gconf_file])):
                # check that there are no englobing other
                skip_this = False
                path = config["gconf"][gconf_file][i]
                for j in xrange(len(config["gconf"][gconf_file])):
                    if i == j:
                        continue
                    if path.startswith(config["gconf"][gconf_file][j]):
                        skip_this = True
                        break
                if skip_this:
                    continue
                # Store dir
                if path[-1] == "/":
                    gconf_dirs[path] = []
                else:
                    dirname = os.path.dirname(path)
                    if dirname[-1] != "/":
                        dirname += "/"
                    keyname = os.path.basename(path)
                    if len(gconf_dirs.get(dirname, [1])) == 0:
                        continue # already included as a dir
                    gconf_dirs.setdefault(dirname, []).append(keyname)

            #~ IO.write("gconf_dirs :")
            #~ pprint.pprint(gconf_dirs)

            if len(gconf_dirs) != 0:
                # Dump gconf dirs
                # "dbus-launch", "--exit-with-session",
                # "sudo", "-u", user.username,
                # "--config-source=xml:readwrite:%s" % (gconf_work_dir),
                if test:
                    cmd = ["gconftool-2", "--config-source=xml:readwrite:%s" % (gconf_work_dir), "--dump"]
                else:
                    cmd = ["sudo", "-u", user.username, "dbus-launch", "--exit-with-session", "gconftool-2", "--dump"]
                for gconf_dir in gconf_dirs:
                    if gconf_dir == "/":
                        cmd += (gconf_dir,)
                    else:
                        cmd += (gconf_dir[:-1],)
                IO.write(" ".join(cmd))
                if test:
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
                complete_dump, stderr = p.communicate()
                if stderr != "":
                    IO.write("Error :\n" + "\n".join(["EE %s" % line for line in stderr.split("\n")]))

                # Filter with xml.dom.minidom
                dom = xml.dom.minidom.parseString(complete_dump)
                saved_keys = []
                for entrylist in dom.getElementsByTagName("entrylist"):
                    base = entrylist.getAttribute("base")
                    for entry in entrylist.getElementsByTagName("entry"):
                        key_name = entry.getElementsByTagName("key")[0].childNodes[0].toxml()
                        key_path = os.path.join(base, key_name)
                        # Drop entry if not expected
                        drop_entry = True
                        for gconf_dir in gconf_dirs:
                            if key_path.startswith(gconf_dir):
                                if gconf_dirs[gconf_dir] == []:
                                    drop_entry = False
                                else:
                                    for key in gconf_dirs[gconf_dir]:
                                        if key_path == os.path.join(gconf_dir, key):
                                            drop_entry = False
                                            continue
                        if drop_entry:
                            entrylist.removeChild(entry)
                        else:
                            saved_keys.append(key_path)

                # Save
                gconf_file = os.path.join(user.home_dir, gconf_file)
                IO.write("Saving to %s keys:\n%s" % (gconf_file, "\n".join(saved_keys)))
                dir_save_to = os.path.dirname(gconf_file)
                if not os.path.exists(dir_save_to):
                    IO.write("mkdir -p %s" % dir_save_to)
                    os.makedirs(dir_save_to)
                f = open(gconf_file, "w")
                #~ dom.writexml(f)
                f.write(dom.toxml(encoding="utf-8"))
                f.close()
            else:
                if os.path.exists(gconf_file) and os.path.isfile(gconf_file):
                    os.unlink(gconf_file)
    except Exception, e:
        IO.write("Unexpected exception : %s" % e)

def gconf_load(config, user, test=False):
    return # NOTE : We had no success with GConf and 12.04 ...
    IO.write("gconf_load")
    user_gconf_dir = os.path.join(user.home_dir, ".gconf")
    for gconf_file in config["gconf"]:
        gconf_file = os.path.join(user.home_dir, gconf_file)
        if os.path.exists(gconf_file):
            # "--direct", "--config-source=xml:readwrite:%s" % user_gconf_dir ,
            run_cmd(
                cmd=["gconftool-2", "--load", gconf_file],
            )

def dconf_dump(config, user, test=False):
    if not os.path.exists(os.path.join(user.home_dir, ".config/dconf/user")):
        IO.write("dconf_dump : ~/.config/dconf/user not found -> Skipping.")
        return
    IO.write("dconf_dump")

    for dconf_file, keys_to_save in config["dconf"].items():
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
                #
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
                    except IndexError, e:
                        dump_dconf += line + "\n"
            else:
                #
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
        Performs all mount
        return True if all succeed
        return False if one failed
    """
    IO.write("Proceeding mount!")
    success = True
    if PASSWORD != None:
        os.environ['PASSWD'] = PASSWORD # For CIFS mounts
    for mount_point, mount_instruction in config["mounts"].items():
        if not os.path.exists(mount_point):
            #~ os.makedirs(mount_point)
            run_cmd(
                cmd=["mkdir", "-p", mount_point]
            )
            run_cmd(
                cmd=["chown", "%s:" % user.username, mount_point]
            )
            # chown parents also
            parent_dir = os.path.dirname(mount_point)
            while parent_dir.startswith("/home/%s" % user.username):
                run_cmd(
                    cmd=["chown", "%s:" % user.username, parent_dir]
                )
                parent_dir = os.path.dirname(parent_dir)
        run_cmd(
            cmd=mount_instruction,
            shell=True,
        )
        if not ismount(mount_point):
            success = False
    if PASSWORD != None:
        del os.environ['PASSWD']
    return success

def filers_umount(config, user):
    """
        Performs all umount
        return True if all succeed
        return False if one failed
    """
    IO.write("Proceeding umount!")
    success = True
    for mount_point in config["mounts"].keys() + [os.path.join(user.home_dir, ".gvfs"),]:
        if not ismount(mount_point):
            IO.write("%s not mounted. Skip." % mount_point)
            continue
        for i in xrange(UMOUNT_MAX_ATTEMPT):
            if run_cmd(
                cmd=["umount", "-fl", mount_point],
            ):
                break
            time.sleep(UMOUNT_SLEEP)
        if ismount(mount_point):
            success = False
    return success

def make_homedir(user):
    ## Make homedir
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

def proceed_roaming_open(config, user):
    IO.write("Proceeding roaming 'open'!")

    ## Make homedir
    make_homedir(user)

    ## Mounts (sudo)
    filers_mount(config, user)

    ## Links
    with UserIdentity(user):
        for target, link_name in config["links"]:
            target_is_dir = False
            force_target = False
            if re.search(r'/$', target):
                target_is_dir = True
            if re.match(r'\+', target):
                force_target = True
                target = target[1:]

            target = os.path.normpath(os.path.join(user.home_dir, target))
            target_parent = os.path.normpath(target + "/..")
            link_name = os.path.normpath(os.path.join(user.home_dir, link_name))
            link_name_parent = os.path.normpath(link_name + "/..")

            if not os.path.lexists(target):
                if force_target:
                    if target_is_dir:
                        os.makedirs(target)       # mkdir target
                    else:
                        if not os.path.lexists(target_parent):
                            os.makedirs(target_parent)
                        open(target, "a").close() # touch target
                else:
                    continue
            if os.path.lexists(link_name):
                if os.path.exists(target): # link_name and target exists -> use target
                    if os.path.isdir(link_name) and not os.path.islink(link_name):
                        shutil.rmtree(link_name)
                    else:
                        os.unlink(link_name)
                else:
                    continue
            if not os.path.exists(link_name_parent):
                os.makedirs(link_name_parent)

            IO.write("ln -s %s %s" % (target, link_name))
            os.symlink(target, link_name)

    ## su_Links (links done as root and chown afterward)
    for target, link_name in config["su_links"]:
        target_is_dir = False
        force_target = False
        if re.search(r'/$', target):
            target_is_dir = True
        if re.match(r'\+', target):
            force_target = True
            target = target[1:]

        target = os.path.normpath(os.path.join(user.home_dir, target))
        target_parent = os.path.normpath(target + "/..")
        link_name = os.path.normpath(os.path.join(user.home_dir, link_name))
        link_name_parent = os.path.normpath(link_name + "/..")

        if not os.path.lexists(target):
            if force_target:
                if target_is_dir:
                    os.makedirs(target)       # mkdir target
                else:
                    if not os.path.lexists(target_parent):
                        os.makedirs(target_parent)
                    open(target, "a").close() # touch target
                run_cmd(
                    cmd=["chown", "%s:" % user.username, target]
                )
            else:
                continue
        if os.path.lexists(link_name):
            if os.path.exists(target): # link_name and target exists -> use target
                if os.path.isdir(link_name) and not os.path.islink(link_name):
                    shutil.rmtree(link_name)
                else:
                    os.unlink(link_name)
            else:
                continue
        if not os.path.exists(link_name_parent):
            os.makedirs(link_name_parent)

        IO.write("ln -s %s %s" % (target, link_name))
        os.symlink(target, link_name)
        run_cmd(
            cmd=["chown", "-h", "%s:" % user.username, link_name]
        )

def proceed_roaming_close(options, config, user):
    IO.write("Proceeding roaming 'close'!")

    ## Links
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
                #~ run_cmd(
                    #~ cmd=["sync"]
                #~ )
    gconf_dump(config, user)
    dconf_dump(config, user)

    ## Umounts (sudo)
    if not filers_umount(config, user):
        IO.write("Skipping rm -rf.")
        return

    ## RM
    for i in xrange(RM_MAX_ATTEMPT):
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

    IO.write("Nothing done ...")

def proceed_torque_prologue(config, user):
    IO.write("Proceeding Torque Prolog!")

    ## Make Home dir
    if not os.path.exists(user.home_dir):
        IO.write("Make homedir")
        run_cmd(
            cmd=["cp", "-R", "/etc/skel", user.home_dir]
        )
        run_cmd(
            cmd=["chown", "-R", "%s:" % user.username, user.home_dir]
        )
    else:
        IO.write("Home dir already exists: nothing to do.")

def proceed_torque_epilogue(config, user):
    IO.write("Proceeding Torque Epilog!")

    ## Remove Home dir
    if os.path.exists(user.home_dir):
        for i in xrange(RM_MAX_ATTEMPT):
            success = run_cmd(
                cmd=["rm", "-rf", "--one-file-system", user.home_dir]
            )
            if success:
                break
            time.sleep(RM_SLEEP)
    else:
        IO.write("Home dir doesn't exists: nothing to do.")

def proceed_on_halt(options):
    def list_current_users():
        return [f[11:] for f in os.listdir("/tmp") if f.startswith("epfl_count")]

    with IO(LOG_PAM):
        IO.write("\n*** %s" % datetime.datetime.now())
        IO.write("Proceeding 'On Halt'!")
        try:
            with PreventInterrupt():
                with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                    for username in list_current_users():
                        IO.write("on_halt %s" % username)
                        user = read_user(options, username)
                        config = read_config(options, user)
                        proceed_roaming_close(options, config, user)
        except Exception, e:
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

### MAIN
if __name__ == '__main__':
    username = os.environ.get("PAM_USER", None)
    if username is not None:
        PASSWORD = get_credentials(username)

    # Manage the kill -TERM  ... unfortunately not kill -9
    signal.signal(signal.SIGTERM, signal_handler)
    #~ signal.signal(signal.SIGKILL, signal_handler)

    options = read_options()
    if options.context == "on_halt":
        proceed_on_halt(options)
        sys.exit(0)

    user = read_user(options)

    if options.context in ("pam", "torque_prologue", "torque_epilogue"):
        logfile_name = LOG_PAM
    else:
        logfile_name = LOG_SESSION.format(username=user.username)

    EPFL_ROAMING_DONE_FILE = os.path.join("/tmp/epfl_roaming_{}_done".format(user.username))

    with IO(logfile_name):
        # IO.write(pprint.pformat(user))
        #~ IO.write("ENV :")
        #~ IO.write(pprint.pformat(os.environ))
        #~ IO.write("\n")
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
                        proceed_guest_open(user)
                    elif user.conn_type == "close_session":
                        proceed_guest_close(user)
                sys.exit(0)

            config = read_config(options, user)

            #~ IO.write("options")
            #~ IO.write(pprint.pformat(options))
            #~ IO.write("user")
            #~ IO.write(pprint.pformat(user))
            #~ IO.write("config")
            #~ IO.write(pprint.pformat(config))
            #~ sys.exit(0)

            if options.context == "pam":
                if user.conn_type == "open_session":
                    with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                        count_sessions(user, +1)
                        if PASSWORD is not None and not os.path.exists(EPFL_ROAMING_DONE_FILE):
                            proceed_roaming_open(config, user)
                            with open(EPFL_ROAMING_DONE_FILE, "w"):
                                pass
                elif user.conn_type == "close_session":
                    time.sleep(0.5) # Give on_halt the chance to be the 1st!
                    with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                        if count_sessions(user, -1) == 0:
                            with PreventInterrupt():
                                proceed_roaming_close(options, config, user)
                            os.unlink(EPFL_ROAMING_DONE_FILE)

            elif options.context == "session":
                gconf_load(config, user)
                dconf_load(config, user)

            elif options.context == "torque_prologue":
                with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                    proceed_torque_prologue(config, user)
            elif options.context == "torque_epilogue":
                with lockfile.FileLock(SEMAPHORE_LOCK_FILE):
                    if count_sessions(user, 0) == 0:
                        proceed_torque_epilogue(config, user)
                    else:
                        IO.write("Sessions still opened for user %s. Nothing to do." % user.username)

            elif options.context == "test_load":
                gconf_load(config, user, test=True)
                dconf_load(config, user, test=True)
            elif options.context == "test_dump":
                gconf_dump(config, user, test=True)
                dconf_dump(config, user, test=True)

            IO.write("Everything complete.")
            sys.exit(0)
        except Exception, e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            IO.write("\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
