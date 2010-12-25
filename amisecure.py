#!/usr/bin/python
import re
import sys

def write_to_shell(message, yes_no, status):
    u"""Output response to shell"""
    if status:
        colour = "\x1b[01;32m"
    else:
        colour = "\x1b[01;31m"
    sys.stdout.write("- %s ... " % (message))
    sys.stdout.write(colour + yes_no.upper() + "\x1b[00m" + "\n")

def check(regex, match_is_secure, message, content):
    u"""Test method for doing entire check without code replication"""
    rx = re.compile(regex)
    if rx.search(content):
        if match_is_secure:
            secure = True
        else:
            secure = False
    write_to_shell(message, rx.search(content).group(1), secure)

class ssh(object):
    u"""SSH security class"""

    def __init__(self):
        sys.stdout.write("Checking SSHD configuration\n")
        self.content = open("/etc/ssh/sshd_config", "r").read()

    def root_logins(self):
        u"""Old basic test for root logins being enabled"""
        if re.search("PermitRootLogin+\s+(yes)", self.content):
            value = "yes"
            good = False
        else:
            value = "no"
            good = True

        write_to_shell("Permit root logins", value, good)

    def privilege_separation(self):
        u"""Old basic test for privilege being enabled"""
        if re.search("UsePrivilegeSeparation+\s+yes", self.content):
            value = "yes"
            good = True
        else:
            value = "no"
            good = False

        write_to_shell("Use privilege separation", value, good)

    def strict_modes(self):
        u"""Old basic test for strict modes being enabled"""
        if re.search("StrictModes+\s+yes", self.content):
            value = "yes"
            good = True
        else:
            value = "no"
            good = False

        write_to_shell("Use strict modes", value, good)

    def permit_empty_passwords(self):
        u"""Old basic test for empty passwords being enabled"""
        if re.search("PermitEmptyPasswords+\s+yes", self.content):
            value = "yes"
            good = False
        else:
            value = "no"
            good = True

        write_to_shell("Permit empty passwords", value, good)

sys.stdout.write("Checking system security features\n\n")

ssh = ssh()
ssh.root_logins()
ssh.privilege_separation()
ssh.strict_modes()
ssh.permit_empty_passwords()
