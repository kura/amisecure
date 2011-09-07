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
                ("equal_to", "no"), True,
                "Permit root logins", ""
            ),
            (
                re.compile(r"[^.*]UsePrivilegeSeparation\s(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "yes"), True,
                "Use privilege separation", ""
            ),
            (
                re.compile(r"[^.*]StrictModes\s(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "yes"), True,
                "Use strict modes", ""
            ),
            (
                re.compile(r"[^.*]PermitEmptyPasswords\s(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "no"), True,
                "Permit empty passwords", ""
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
                ("less_than", 6), True,
                "Timeout", "Less than 5 seconds is good"
            ),
            (
                re.compile(r"[^.*]KeepAliveTimeout\s(?P<value>[0-9]*)", re.IGNORECASE), 
                ("less_than", 4), True,
                "Keep alive timeout", "Less than 3 seconds is good"
            ),
            (
                re.compile(r"[^.*]ServerTokens\s(?P<value>OS|Full|Minimal)", re.IGNORECASE), 
                ("equal_to", "os"), True,
                "Server tokens", "OS or Minimal are considered 'secure'"
            ),
            (
                re.compile(r"[^.*]ServerSignature\s(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"), True,
                "Server signature", ""
            ),
            (
                re.compile(r"[^.*]traceenable\s(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"), True,
                "Trace Enable", ""
            ),
            (
                re.compile(r"[^.*]Options\s.*?(?P<value>Indexes).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "Directory Listing", "Enabling this allows people to browse you web-filesystem"
            ),
            (
                re.compile(r"[^.*]ScriptAlias\s(?P<value>/cgi-bin/).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "cgi-bin alias", "Always disable unless required"
            ),
            (
                re.compile(r"[^.*]Alias\s(?P<value>/doc/).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "Docs alias", "Always disable unless required"
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
                ("equal_to", "off"), True,
                "Server tokens", "Off is considered 'secure'"
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
                ("equal_to", "off"), True,
                "Expose PHP", ""
            ),
            (
                re.compile(r"[^.*]session.use_only_cookies\s=\s(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "1"), True,
                "Use only cookies", ""
            ),
            (
                re.compile(r"[^.*]session.cookie-httponly\s=\s(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "1"), True,
                "HTTPOnly cookies", ""
            ),
            (
                re.compile(r"[^.*]session.use_trans_sid\s=\s(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "0"), True,
                "Session trans SID", ""
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
                ("like", re.compile(r"denyhosts", re.IGNORECASE)), True,
                "DenyHosts running", ""
            ),
        ),
    },
)


GREEN =  "\x1b[01;32m"
RED = "\x1b[01;31m"
YELLOW = "\x1b[01;33m"
BLUE = "\x1b[01;34m"
PURPLE = "\x1b[01;35m"
RESET = "\x1b[00m"


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

def write_to_shell(message, additional, value, colour):
    """Output response to shell"""
    colour = globals()[colour.upper()]
    sys.stdout.write("- %s ... " % (message))
    sys.stdout.write(colour + value.upper() + RESET)
    sys.stdout.write("\n")
    if additional:
        sys.stdout.write("  %s%s%s"% (BLUE, additional, RESET))
        sys.stdout.write("\n")

def check_value(regex, secure_value, display_value, message, additional, content):
    """Test method for doing entire check without code replication"""
    (value_test, secure_value) = secure_value
    if regex.search(content):
        value = regex.findall(content)[-1]
        if display_value is not True:
            value = display_value
        if globals()[value_test](value, secure_value):
            colour = "green"
            value = value + " (secure)"
        else:
            colour = "red"
            value = value + " (not secure)"
    else:
        colour = "yellow"
        value = "unknown"
    write_to_shell(message, additional, value, colour)

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

sys.stdout.write("%sChecking your system ...%s" % (GREEN, RESET))
sys.stdout.write("\n\n")

for system in config_checks:
    sys.stdout.write("%sChecking: %s%s\n" % (PURPLE, system['name'], RESET))
    content = globals()[system['content_function']](system)
    for (regex, secure_value, display_value, message, additional) in system['tests']:
        globals()[system['check_function']](regex, secure_value, display_value, message, additional, content)
    sys.stdout.write("\n")

sys.stdout.write("%s ... Done%s" % (GREEN, RESET))
sys.stdout.write("\n")
sys.exit(os.EX_OK)
