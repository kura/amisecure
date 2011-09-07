#!/usr/bin/env python

"""
Runs multiple checks across the system to check for secureness

Checks are done on system config files, running security processes,
firewall rules and more.
"""

import re
import sys
import os

__author__ = "Kura"
__copyright__ = "None"
__credits__ = ["Kura"]
__license__ = "Free"
__version__ = "0 Alpha"
__maintainer__ = "Kura"
__email__ = "kura@deviling.net"
__status__ = "Alpha/Test"

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
                re.compile(r"[^.*]PermitRootLogin\s(?P<value>yes|no)", re.IGNORECASE),
                ("equal_to", "no"),
                "Permit root logins"
            ),
            (
                re.compile(r"[^.*]UsePrivilegeSeparation\s(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "yes"), 
                "Use privilege separation"
            ),
            (
                re.compile(r"[^.*]StrictModes\s(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "yes"), 
                "Use strict modes"
            ),
            (
                re.compile(r"[^.*]PermitEmptyPasswords\s(?P<value>yes|no)", re.IGNORECASE), 
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
                re.compile(r"[^.*]Timeout\s(?P<value>[0-9]*)", re.IGNORECASE), 
                ("less_than", 6), 
                "Timeout"
            ),
            (
                re.compile(r"[^.*]KeepAliveTimeout\s(?P<value>[0-9]*)", re.IGNORECASE), 
                ("less_than", 4), 
                "Keep alive timeout"
            ),
            (
                re.compile(r"[^.*]ServerTokens\s(?P<value>OS|Full|Minimal)", re.IGNORECASE), 
                ("equal_to", "os"), 
                "Server tokens"
            ),
            (
                re.compile(r"[^.*]ServerSignature\s(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"),
                "Server signature"
            ),
            (
                re.compile(r"[^.*]traceenable\s(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"),
                "Trace Enable"
            ),
            (
                re.compile(r"[^.*]Options\s.*?(?P<value>Indexes).*", re.IGNORECASE),
                ("equal_to", ""),
                "Directory Listing"
            ),
            (
                re.compile(r"[^.*]ScriptAlias\s(?P<value>/cgi-bin/).*", re.IGNORECASE),
                ("equal_to", ""),
                "cgi-bin alias"
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
                re.compile(r"[^.*]server_tokens\s(?P<value>on|off)", re.IGNORECASE), 
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
                re.compile(r"[^.*]expose_php\s=\s(?P<value>on|off)", re.IGNORECASE), 
                ("equal_to", "off"), 
                "Expose PHP"
            ),
            (
                re.compile(r"[^.*]session.use_only_cookies\s=\s(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "1"),
                "Use only cookies"
            ),
            (
                re.compile(r"[^.*]session.cookie-httponly\s=\s(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "1"),
                "HTTPOnly cookies"
            ),
            (
                re.compile(r"[^.*]session.use_trans_sid\s=\s(?P<value>1|0)", re.IGNORECASE),
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
    """ Check if user is super user"""
    if os.geteuid() == 0:
        return True
    return False

def like(this, regex):
    """Check content against a regex"""
    if regex.match(this):
       return True
    return False

def equal_to(this, that):
    """Convert values to strings and check if they match"""
    if str(this).lower() == str(that).lower():
        return True
    return False

def greater_than(this, that):
    """Convert values to integers and check if the first is greater than the second"""
    if int(this) > int(that):
        return True
    return False

def less_than(this, that):
    """Convert values to integers and check if the first is less than the second"""
    if int(this) < int(that):
        return True
    return False

def write_to_shell(message, value, colour):
    """Output response to shell"""
    if colour == "green":
        colour = "\x1b[01;32m"
    elif colour == "red":
        colour = "\x1b[01;31m"
    else:
        colour = "\x1b[01;33m"
    sys.stdout.write("- %s ... " % (message))
    sys.stdout.write(colour + value.upper() + "\x1b[00m" + "\n")

def check_value(regex, secure_value, message, content):
    """Test method for doing entire check without code replication"""
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

def check_multi_value(regex, secure_value, message, content):
    (value_test, secure_value) = secure_value
    if regex.search(content):
        values = regex.findall(content)
        for value in values:
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
    """Open up all listed config files and cat their content together"""
    content = ""
    for file in system['files']:
        if re.search(r"\*$", file):
            (path, asterix) = os.path.split(file)
            if os.path.exists(path):
                for extra_file in os.listdir(path):
                    file_path = os.path.join(path, extra_file)
                    if os.path.exists(file_path):
                        content += "\n" + open(file_path, "r").read()
        elif os.path.exists(file):
            content = content + "\n" + open(file, "r").read()
    return clean(content)

def clean(content):
    stripped_content = ""
    for line in content.split("\n"):
        line = line.lstrip()
        line = re.sub(r"\s+", " ", line)
        if not re.match(r"[^.*]#", line) and not re.match(r"#", line):
            stripped_content += line + "\n"
    return stripped_content

def get_shell_output(system):
    """Get content output from a shell command"""
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
