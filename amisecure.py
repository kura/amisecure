#!/usr/bin/env python
import re
import sys
import os

config_checks = (
    {
        "name": "ssh",
        "content_function": "get_file_content",
        "check_function": "check_value",
        "files": (
            "/etc/ssh/sshd_config",
        ),
        "tests": (
            (
                re.compile(r"[^#]+PermitRootLogin+\s+(?P<value>yes|no)", re.IGNORECASE),
                ("equal_to", "no"),
                "Permit root logins"
            ),
            (
                re.compile(r"[^#]+UsePrivilegeSeparation+\s+(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "yes"), 
                "Use privilege separation"
            ),
            (
                re.compile(r"[^#]+StrictModes+\s+(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "yes"), 
                "Use strict modes"
            ),
            (
                re.compile(r"[^#]+PermitEmptyPasswords+\s+(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "no"), 
                "Permit empty passwords"
            ),
        ),
    },
    {
        "name": "apache2",
        "content_function": "get_file_content",
        "check_function": "check_value",
        "files": (
            "/etc/apache2/httpd.conf",
            "/etc/apache2/ports.conf",
            "/etc/apache2/apache2.conf",
            "/etc/apache2/conf.d/*",
            "/etc/apache2/sites-enabled/*",
        ),
        "tests": (
            (
                re.compile(r"[^#a-z0-9]+Timeout+\s+(?P<value>[0-9]*)", re.IGNORECASE), 
                ("less_than", 6), 
                "Timeout"
            ),
            (
                re.compile(r"[^#a-z0-9]+KeepAliveTimeout+\s+(?P<value>[0-9]*)", re.IGNORECASE), 
                ("less_than", 4), 
                "Keep alive timeout"
            ),
            (
                re.compile(r"[^#a-z0-9]+ServerTokens+\s+(?P<value>OS|Full|Minimal)", re.IGNORECASE), 
                ("equal_to", "os"), 
                "Server tokens"
            ),
            (
                re.compile(r"[^#a-z0-9]+ServerSignature+\s+(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"),
                "Server signature"
            ),

        ),
    },
    {
        "name": "nginx",
        "content_function": "get_file_content",
        "check_function": "check_value",
        "files": (
            "/etc/nginx/nginx.conf",
            "/etc/nginx/conf.d/*",
            "/etc/nginx/sites-enabled/*",
        ),
        "tests": (
            (
                re.compile(r"[^#a-z0-9]+server_tokens+\s+(?P<value>on|off)", re.IGNORECASE), 
                ("equal_to", "off"), 
                "Server tokens"
            ),
        ),
    },
    {
        "name": "php5",
        "content_function": "get_file_content",
        "check_function": "check_value",
        "files": (
            "/etc/php5/apache2/php.ini",
            "/etc/php5/cli/php.ini",
            "/etc/php5/conf.d/*",
        ),
        "tests": (
            (
                re.compile(r"[^#a-z0-9]+expose_php+\s=\s+(?P<value>on|off)", re.IGNORECASE), 
                ("equal_to", "Off"), 
                "Expose PHP"
            ),
            (
                re.compile(r"[^#a-z0-9]+session.use_only_cookies+\s=\s+(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "1"),
                "Use only cookies"
            ),
            (
                re.compile(r"[^#a-z0-9]+session.cookie_httponly+\s=\s+(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "1"),
                "HTTPOnly cookies"
            ),
            (
                re.compile(r"[^#a-z0-9]+session.use_trans_sid+\s=\s+(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "0"),
                "Session trans SID"
            ),
        ),
    },
    {
        "name": "denyhosts",
        "content_function": "get_shell_output",
        "check_function": "check_value",
        "files": (
        ),
        "shell_command": "ps aux | grep denyhosts | grep -v grep",
        "tests": (
            (
                re.compile(r"denyhosts", re.IGNORECASE),
                ("like", re.compile(r"denyhosts", re.IGNORECASE)),
                "DenyHosts running"
            ),
        ),
    },
)


def is_root():
    u""" Check if user is super user"""
    if os.geteuid() == 0:
        return True
    return False

def like(this, regex):
    u"""Check content against a regex"""
    if regex.match(this):
       return True
    return False

def equal_to(this, that):
    u"""Convert values to strings and check if they match"""
    if str(this).lower() == str(that).lower():
        return True
    return False

def greater_than(this, that):
    u"""Convert values to integers and check if the first is greater than the second"""
    if int(this) > int(that):
        return True
    return False

def less_than(this, that):
    u"""Convert values to integers and check if the first is less than the second"""
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

def check_value(regex, secure_value, message, content):
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

def get_file_content(system):
    u"""Open up all listed config files and cat their content together"""
    content = ""
    for file in system['files']:
        if re.search(r"\*$", file):
            (path, asterix) = os.path.split(file)
            for extra_file in os.listdir(path):
                content = content + "\n" + open(os.path.join(path, extra_file), "r").read()
        elif os.path.exists(file):
            content = content + "\n" + open(file, "r").read()
    return content

def get_shell_output(system):
    u"""Get content output from a shell command"""
    return os.popen(system['shell_command']).read()

if not is_root():
    sys.stdout.write("Only root may run this command\n")
    sys.exit(os.EX_NOUSER)

for system in config_checks:
    sys.stdout.write("Checking: %s\n" % (system['name']))
    content = globals()[system['content_function']](system)

    for (regex, secure_value, message) in system['tests']:
        globals()[system['check_function']](regex, secure_value, message, content)

sys.exit(os.EX_OK)
