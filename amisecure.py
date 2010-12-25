#!/usr/bin/python
import re
import sys
from os import EX_OK

checks = (
    {
        "name": "ssh",
        "file": "/etc/ssh/sshd_config",
        "tests": (
            ("PermitRootLogin+\s+(yes|no)", "no", "Permit root logins"),
            ("UsePrivilegeSeparation+\s+(yes|no)", "yes", "Use privilege separation"),
            ("StrictModes+\s+(yes|no)", "yes", "Use strict modes"),
            ("PermitEmptyPasswords+\s+(yes|no)", "no", "Permit empty passwords"),
        ),
    },
)

def write_to_shell(message, value, status):
    u"""Output response to shell"""
    if status:
        colour = "\x1b[01;32m"
        value = value + " (secure)"
    else:
        colour = "\x1b[01;31m"
        value = value + " (not secure)"
    sys.stdout.write("- %s ... " % (message))
    sys.stdout.write(colour + value.upper() + "\x1b[00m" + "\n")

def check(regex, secure_value, message, content):
    u"""Test method for doing entire check without code replication"""
    rx = re.compile(regex)
    if rx.search(content):
        value = rx.search(content).group(1)
        if secure_value == value:
            secure = True
        else:
            secure = False
    write_to_shell(message, value, secure)

for system in checks:
    sys.stdout.write("Checking: %s\n" % (system['name']))
    content = open(system['file'], "r").read()
    for test in system['tests']:
        check(test[0], test[1], test[2], content)

sys.exit(EX_OK)
