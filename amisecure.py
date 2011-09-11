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
__version__ = "0.0.1 (Alpha)"
__maintainer__ = "Kura"
__email__ = "kura@deviling.net"
__status__ = "Alpha/Test"
__url__ = "https://github.com/kura/amisecure"

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
                re.compile(r"[^a-z]PermitRootLogin\s(?P<value>yes|no)", re.IGNORECASE),
                ("equal_to", "no"), True,
                "Permit root logins", "Always disable this option"
            ),
            (
                re.compile(r"[^a-z]UsePrivilegeSeparation\s(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "yes"), True,
                "Use privilege separation", "Always enable this option"
            ),
            (
                re.compile(r"[^a-z]StrictModes\s(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "yes"), True,
                "Use strict modes", "Always enable this option"
            ),
            (
                re.compile(r"[^a-z]PermitEmptyPasswords\s(?P<value>yes|no)", re.IGNORECASE), 
                ("equal_to", "no"), True,
                "Permit empty passwords", "Always disable this option"
            ),
        ),
    },
    {
        "name": "apache2",
        "content_function": "get_file_content",
        "check_function": "check_value",
        "files": (
            "/etc/apache2/apache2.conf",
            "/etc/apache2/mods-enabled/*",
            "/etc/apache2/httpd.conf",
            "/etc/apache2/ports.conf",
            "/etc/apache2/conf.d/*",
            "/etc/apache2/sites-enabled/*",
        ),
        "tests": (
            (
                re.compile(r"[^a-z]Timeout\s(?P<value>[0-9]*)", re.IGNORECASE), 
                ("less_than", 6), True,
                "Timeout", "Less than 5 seconds is good"
            ),
            (
                re.compile(r"[^a-z]KeepAliveTimeout\s(?P<value>[0-9]*)", re.IGNORECASE), 
                ("less_than", 4), True,
                "Keep alive timeout", "Less than 3 seconds is good"
            ),
            (
                re.compile(r"[^a-z]ServerTokens\s(?P<value>Prod|Major|Minor|Minimal|OS|Full)", re.IGNORECASE), 
                ("equal_to", ("prod", "major")), True,
                "Server tokens", "Prod and Major are considered 'secure' but both are the same"
            ),
            (
                re.compile(r"[^a-z]ServerSignature\s(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"), True,
                "Server signature", "Off is considered 'secure'"
            ),
            (
                re.compile(r"[^a-z]traceenable\s(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"), True,
                "Trace Enable", "Always disable unless required"
            ),
            (
                re.compile(r"[^a-z]Options\s.*?(?P<value>\+?Includes).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "ServerSide includes", "Only enable when required"
            ),
                        (
                re.compile(r"[^a-z]Options\s.*?(?P<value>\+?ExecCGI).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "CGI execution", "Only enable when if you're using CGI"
            ),
            (
                re.compile(r"[^a-z]Options\s.*?(?P<value>\+?Indexes).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "Directory Listing", "Enabling this allows people to browse your web-filesystem"
            ),
            (
                re.compile(r"[^a-z]ScriptAlias\s(?P<value>/cgi-bin/).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "cgi-bin alias", "Controls cgi-bin aliasing"
            ),
            (
                re.compile(r"[^a-z]Alias\s(?P<value>/doc/).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "Docs alias", "Controls Apache doc aliasing"
            ),
            (
                re.compile(r"[^a-z]Alias\s(?P<value>/icons/).*", re.IGNORECASE),
                ("equal_to", ""), "Found",
                "Icons alias", "Controls Apache icon aliasing"
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
                re.compile(r"[^a-z]server_tokens\s(?P<value>on|off)", re.IGNORECASE), 
                ("equal_to", "off"), True,
                "Server tokens", "Hides or shows nginx version information"
            ),
            (
                re.compile(r"[^a-z]autoindex\s(?P<value>on|off)", re.IGNORECASE), 
                ("equal_to", ""), "Found",
                "Directory Listing", "Enabling this allows people to browse your web-filesystem"
            ),
            (
                re.compile(r"[^a-z]location\s(?P<value>/doc).*", re.IGNORECASE), 
                ("equal_to", ""), "Found",
                "Docs alias", "Controls nginx doc aliasing"
            ),
            (
                re.compile(r"[^a-z]autoindex\s(?P<value>/images).*", re.IGNORECASE), 
                ("equal_to", ""), "Found",
                "Images alias", "Controls nginx image aliasing"
            ),
        ),
    },
    {
        "name": "php5",
        "content_function": "get_file_content",
        "check_function": "check_value",
        "files": (
            "/etc/php5/apache2/php.ini",
            "/etc/php5/conf.d/*",
        ),
        "tests": (
            (
                re.compile(r"[^a-z]expose_php\s?=\s?(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"), True,
                "Expose PHP", "Controls PHP exposing itself via HTTP headers etc"
            ),
            (
                re.compile(r"[^a-z]register_globals\s?=\s?(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"), True,
                "Register globals", "Controls whether GET, POST, etc variables are globally registered"
            ),
            (
                re.compile(r"[^a-z]display_errors\s?=\s?(?P<value>on|off)", re.IGNORECASE),
                ("equal_to", "off"), True,
                "Display errors", "Controls whether PHP prints errors"
            ),
            (
                re.compile(r"[^a-z]session.use_only_cookies\?s=\s?(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "1"), True,
                "Use only cookies", "Prevents attacks involving passing session ids in URLs"
            ),
            (
                re.compile(r"[^a-z]session.cookie_httponly\s?=\s?(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "1"), True,
                "HTTPOnly cookies", "Cookies set by the server can only be read by the client"
            ),
            (
                re.compile(r"[^a-z]session.use_trans_sid\s=\s(?P<value>1|0)", re.IGNORECASE),
                ("equal_to", "0"), True,
                "Session trans SID", "Enables or disables URL-based session ids"
            ),
            (
                re.compile(r"[^a-z]extension\s?=\s?(?P<value>suhosin.so)", re.IGNORECASE),
                ("equal_to", "suhosin.so"), True,
                "Suhosin", "PHP hardening - http://www.hardened-php.net/suhosin/"
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
                "DenyHosts running", "When running, DenyHosts will help protect your server from SSH bruteforcing"
            ),
        ),
    },
)


START = "\x1b["
GREEN =  "32m"
RED = "31m"
YELLOW = "33m"
BLUE = "34m"
PURPLE = "35m"
BOLD = "01;"
UNDERLINE = "04;"
RESET = "\x1b[00m"

SUCCESS = START+BOLD+GREEN
FAILURE = START+BOLD+RED
UNKNOWN = START+BOLD+YELLOW
TITLE = START+BOLD+UNDERLINE+PURPLE
MESSAGE = START+BOLD+BLUE


class AmISecure():
    TOTAL_SECURE = 0
    TOTAL_UNSECURE = 0
    TOTAL_UNKNOWN = 0
    content = ""

    def __init__(self):
        sys.stdout.write("%samisecure %s - %s%s" % (MESSAGE, __version__, __url__, RESET))
        sys.stdout.write("\n\n")
        self.is_root()
        sys.stdout.write("Please remember that this program helps show possible security holes, but it is just a basic tool.")
        sys.stdout.write("\n\n")
        sys.stdout.write("%sScanning your system ...%s" % (SUCCESS, RESET))
        sys.stdout.write("\n\n")
        self.run()
        sys.stdout.write("%s... Done%s" % (SUCCESS, RESET))
        sys.stdout.write("\n\n")
        self.totals()
        sys.exit(os.EX_OK)

    def is_root(self):
        """Check if user is super user"""
        if os.geteuid() == 0:
            return True
        sys.stdout.write("You need to be a superuser to run this program\n")
        sys.exit(os.EX_NOUSER)
        
    def run(self):
        """Go go go"""
        for system in config_checks:
            sys.stdout.write("%sChecking: %s%s\n" % (TITLE, system['name'], RESET))
            self.content = getattr(self, system['content_function'])(system)
            for (regex, secure_value, display_value, message, additional) in system['tests']:
                getattr(self, system['check_function'])(regex, secure_value, display_value, message, additional)
            sys.stdout.write("\n")
            
    def totals(self):
        sys.stdout.write("%sTotals%s\n" % (TITLE, RESET))
        sys.stdout.write("%sSecure:   %s%s\n" % (SUCCESS, self.TOTAL_SECURE, RESET))
        sys.stdout.write("%sUnsecure: %s%s\n" % (FAILURE, self.TOTAL_UNSECURE, RESET))
        sys.stdout.write("%sUnknown:  %s%s\n" % (UNKNOWN, self.TOTAL_UNKNOWN, RESET))
        sys.stdout.write("\n")

    def like(self, this, regex):
        """Check content against a regex"""
        if regex.match(this):
            return True
        return False
    
    def equal_to(self, this, that):
        """Convert values to strings and check if they match"""
        if isinstance(that, (tuple)):
            for v in that:
                if str(this).lower() == str(v).lower():
                    return True
        if str(this).lower() == str(that).lower():
            return True
        return False
    
    def greater_than(self, this, that):
        """Convert values to integers and check if the first is greater than the second"""
        if int(this) > int(that):
            return True
        return False
    
    def less_than(self, this, that):
        """Convert values to integers and check if the first is less than the second"""
        if int(this) < int(that):
            return True
        return False
    
    def write_to_shell(self, message, additional, value, colour):
        """Output response to shell"""
        sys.stdout.write("- %s ... " % (message,))
        sys.stdout.write(colour + value.upper() + RESET)
        sys.stdout.write("\n")
        sys.stdout.write("  %s%s%s"% (MESSAGE, additional, RESET))
        sys.stdout.write("\n")
    
    def check_value(self, regex, secure_value, display_value, message, additional):
        """Test method for doing entire check without code replication"""
        (value_test, secure_value) = secure_value
        if regex.search(self.content):
            value = regex.findall(self.content)[-1]
            if display_value is not True:
                value = display_value
            if getattr(self, value_test)(value, secure_value):
                colour = SUCCESS
                value = value + " (secure)"
                self.TOTAL_SECURE += 1
            else:
                colour = FAILURE
                value = value + " (not secure)"
                self.TOTAL_UNSECURE += 1
        elif secure_value == "":
            colour = SUCCESS
            value = "Not found (secure)"
            self.TOTAL_SECURE += 1
        else:
            colour = UNKNOWN
            value = "unknown"
            self.TOTAL_UNKNOWN += 1
        self.write_to_shell(message, additional, value, colour)
    
    def get_file_content(self, system):
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
        return self.clean(content)
    
    def clean(self, content):
        """Clean up the file contents, remove extra spaces and commented lines"""
        stripped_content = ""
        for line in content.split("\n"):
            line = line.lstrip()
            line = re.sub(r"\s+", " ", line)
            if not re.match(r"[^a-z]#", line) and not re.match(r"#", line) \
            and not re.match(r"[^a-z];", line) and not re.match(r";", line):
                stripped_content += line + "\n"
        return stripped_content
    
    def get_shell_output(self, system):
        """Get content output from a shell command"""
        return os.popen(system['shell_command']).read()


if __name__ == "__main__":
    obj = AmISecure()
    obj.run()