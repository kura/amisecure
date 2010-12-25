#!/usr/bin/python
import re
import sys
import os

config_checks = (
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

def write_to_shell(message, value, colour):
    u"""Output response to shell"""
    if colour == "green":
        colour = "\x1b[01;32m"
    elif colour == "red":
        colour = "\x1b[01;31m"
    else:
        colour = "\x1b[01;33m"
    sys.stdout.write("- %s ... " % (message))
    sys.stdout.write(colour + value.upper() + "\x1b[00m" + "\n")

def check_config_value(regex, secure_value, message, content):
    u"""Test method for doing entire check without code replication"""
    rx = re.compile(regex)
    if rx.search(content):
        value = rx.search(content).group(1)
        if secure_value == value:
            colour = "green"
            value = value + " (secure)"
        else:
            colour = "red"
            value = value + " (not secure)"
    else:
        colour = "yellow"
        value = "unknown"
        
    write_to_shell(message, value, colour)

for system in config_checks:
    sys.stdout.write("Checking: %s\n" % (system['name']))
    content = open(system['file'], "r").read()
    for test in system['tests']:
        check_config_value(test[0], test[1], test[2], content)

sys.exit(os.EX_OK)
