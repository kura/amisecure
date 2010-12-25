#!/usr/bin/python
import re
import sys

def write_to_shell(message, yes_no, status):
    if status:
        colour = "\x1b[01;32m"
    else:
        colour = "\x1b[01;31m"
    sys.stdout.write("%s ... " % (message))
    sys.stdout.write(colour + yes_no.upper() + "\x1b[00m" + "\n")

class ssh(object):

    def __init__(self):
        self.content = open("/etc/ssh/sshd_config", "r").read()

    def check_root_logins(self):
        if re.search("PermitRootLogin+\s+yes", self.content):
            value = "yes"
            good = False
        else:
            value = "no"
            good = True

        write_to_shell("Permit root logins", value, good)

    def use_privilege_separation(self):
        if re.search("UsePrivilegeSeparation+\s+yes", self.content):
            value = "yes"
            good = True
        else:
            value = "no"
            good = False

        write_to_shell("Use privilege separation", value, good)

ssh = ssh()
ssh.check_root_logins()
ssh.use_privilege_separation()