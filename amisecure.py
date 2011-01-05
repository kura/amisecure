#!/usr/bin/env python
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
            (re.compile(r"[^#]+PermitRootLogin+\s+(?P<value>yes|no)"), ("equal_to", "no"), "Permit root logins"),
            (re.compile(r"[^#]+UsePrivilegeSeparation+\s+(?P<value>yes|no)"), ("equal_to", "yes"), "Use privilege separation"),
            (re.compile(r"[^#]+StrictModes+\s+(?P<value>yes|no)"), ("equal_to", "yes"), "Use strict modes"),
            (re.compile(r"[^#]+PermitEmptyPasswords+\s+(?P<value>yes|no)"), ("equal_to", "no"), "Permit empty passwords"),
        ),
    },
    {
        "name": "apache2",
        "files": (
            "/etc/apache2/httpd.conf",
            "/etc/apache2/ports.conf",
            "/etc/apache2/apache2.conf",
            "/etc/apache2/conf.d/*",
            "/etc/apache2/sites-enabled/*",
        ),
        "tests": (
            (re.compile(r"[^#a-zA-Z0-9]+Timeout+\s+(?P<value>[0-9]*)"), ("less_than", 6), "Timeout"),
            (re.compile(r"[^#a-zA-Z0-9]+KeepAliveTimeout+\s+(?P<value>[0-9]*)"), ("less_than", 4), "Keep alive timeout"),
            (re.compile(r"[^#a-zA-Z0-9]+ServerTokens+\s+(?P<value>OS|Full|Minimal)"), ("equal_to", "OS"), "Server tokens"),
        ),
    },
    {
        "name": "nginx",
        "files": (
            "/etc/nginx/nginx.conf",
            "/etc/nginx/conf.d/*",
            "/etc/nginx/sites-enabled/*",
        ),
        "tests": (
            (re.compile(r"[^#a-zA-Z0-9]+server_tokens+\s+(?P<value>on|off)"), ("equal_to", "off"), "Server tokens"),
        ),
    },
    {
        "name": "php5",
        "files": (
            "/etc/php5/apache2/php.ini",
            "/etc/php5/cli/php.ini",
            "/etc/php5/conf.d/*",
        ),
        "tests": (
            (re.compile(r"[^#a-zA-Z0-9]+expose_php+\s=\s+(?P<value>On|Off)"), ("equal_to", "Off"), "Expose PHP"),
        ),
    },
)


def is_root():
    if os.geteuid() == 0:
        return True
    return False

def equal_to(this, that):
    if str(this) == str(that):
        return True
    return False

def greater_than(this, that):
    if int(this) > int(that):
        return True
    return False

def less_than(this, that):
    if int(this) < int(that):
        return True
    return False

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
    (value_test, secure_value) = secure_value
    if regex.search(content):
        value = regex.findall(content)[-1]
        if globals()[value_test](value, secure_value):
            colour = "green"
            value = value + " (secure)"
        else:
            colour = "red"
            value = value + " (not secure)"
    else:
        colour = "yellow"
        value = "unknown"

    write_to_shell(message, value, colour)

def get_content(system):
    content = ""
    for file in system['files']:
        if re.search(r"\*$", file):
            (path, asterix) = os.path.split(file)
            for extra_file in os.listdir(path):
                content = content + "\n" + open(os.path.join(path, extra_file), "r").read()
        elif os.path.exists(file):
            content = content + "\n" + open(file, "r").read()
    return content

if not is_root():
    sys.stdout.write("Only root may run this command\n")
    sys.exit(os.EX_NOUSER)

for system in config_checks:
    sys.stdout.write("Checking: %s\n" % (system['name']))
    content = get_content(system)

    for (regex, secure_value, message) in system['tests']:
        check_config_value(regex, secure_value, message, content)

sys.exit(os.EX_OK)
