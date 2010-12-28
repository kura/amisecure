#!/usr/bin/python
import re
import sys
import os

config_checks = (
    {
        "name": "ssh",
        "files": (
            "/etc/ssh/sshd_config",
        ),
        "tests": (
            (re.compile(r"PermitRootLogin+\s+(?P<value>yes|no)"), "no", "Permit root logins"),
            (re.compile(r"UsePrivilegeSeparation+\s+(?P<value>yes|no)"), "yes", "Use privilege separation"),
            (re.compile(r"StrictModes+\s+(?P<value>yes|no)"), "yes", "Use strict modes"),
            (re.compile(r"PermitEmptyPasswords+\s+(?P<value>yes|no)"), "no", "Permit empty passwords"),
        ),
    },
    {
        "name": "apache",
        "files": (
            "/etc/apache2/httpd.conf",
            "/etc/apache2/ports.conf",
            "/etc/apache2/apache2.conf",
            "/etc/apache2/conf.d/*",
        ),
        "tests": (
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
    if regex.search(content):
        value = regex.findall(content)[-1]
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
    content = ""
    for file in system['files']:
        if re.search(r"\*$", file):
            (path, asterix) = os.path.split(file)
            for extra_file in os.listdir(path):
                content = content + "\n" + open(extra_file, "r").read()
        elif os.path.exists(file):
            content = content + "\n" + open(file, "r").read()

    for (regex, secure_value, message) in system['tests']:
        check_config_value(regex, secure_value, message, content)

sys.exit(os.EX_OK)
