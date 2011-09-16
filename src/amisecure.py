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
__version__ = "0.0.2 (Alpha)"
__maintainer__ = "Kura"
__email__ = "kura@deviling.net"
__status__ = "Alpha/Test"
__url__ = "https://github.com/kura/amisecure"

TOTAL_SECURE = 0
TOTAL_UNSECURE = 0
TOTAL_UNKNOWN = 0

config_checks = (
    {
        "name": "ssh",
        "content_function": "get_file_content",
        "check_function": "check_value",
        "files": (
            "/etc/ssh/sshd_config",
        ),
        "tests": (
            {
                'regex': re.compile(r"[^a-z]PermitRootLogin\s(?P<value>yes|no)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("no"),
                'display_value': True,
                'test_name': "Permit root logins",
                'additional_text': "Always disable this option"
            },
            {
                'regex': re.compile(r"[^a-z]UsePrivilegeSeparation\s(?P<value>yes|no)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("yes"),
                'display_value': True,
                'test_name': "Use privilege separation",
                'additional_text': "Always enable this option"
            },
            {
                'regex': re.compile(r"[^a-z]StrictModes\s(?P<value>yes|no)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("yes"),
                'display_value': True,
                'test_name': "Use strict modes",
                'additional_text': "Always enable this option"
            },
            {
                'regex': re.compile(r"[^a-z]PermitEmptyPasswords\s(?P<value>yes|no)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("no"),
                'display_value': True,
                'test_name': "Permit empty passwords",
                'additional_text': "Always disable this option"
            },
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
            {
                'regex': re.compile(r"[^a-z]Timeout\s(?P<value>[0-9]*)", re.IGNORECASE), 
                'method': "less_than",
                'secure_values': (6),
                'display_value': True,
                'test_name': "Timeout",
                'additional_text': "5 seconds or less is good"
            },
            {
                'regex': re.compile(r"[^a-z]KeepAliveTimeout\s(?P<value>[0-9]*)", re.IGNORECASE), 
                'method': "less_than",
                'secure_values': (4),
                'display_value': True,
                'test_name': "Keep alive timeout",
                'additional_text': "3 seconds or less is good"
            },
            {
                'regex': re.compile(r"[^a-z]ServerTokens\s(?P<value>Prod|Major|Minor|Minimal|OS|Full)", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("prod", "major"),
                'display_value': True,
                'test_name': "Server tokens",
                'additional_text': "Prod and Major are considered 'secure' but both are the same"
            },
            {
                'regex': re.compile(r"[^a-z]ServerSignature\s(?P<value>on|off)", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("off"),
                'display_value': True,
                'test_name': "Server signature",
                'additional_text': "Off is considered 'secure'"
            },
            {
                'regex': re.compile(r"[^a-z]traceenable\s(?P<value>on|off)", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("off"),
                'display_value': True,
                'test_name': "Trace Enable",
                'additional_text': "Always disable unless required"
            },
            {
                'regex': re.compile(r"[^a-z]SSLCipherSuite\s[a-z0-9\:\!\+]*?(?P<value>\+?[^\-\!]?SSLv2)[a-z0-9\:\!\+]*?", re.IGNORECASE), #ssl2
                'method': "equal_to",
                'secure_values': ("", "!SSLv2"),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "SSLv2 cipher",
                'additional_text': "Always disable, SSLv2 is not secure"
            },
            {
                'regex': re.compile(r"[^a-z]SSLProtocol\s[a-z0-9\s]*?(?P<value>\+?[^\-\!]?SSLv2)[a-z0-9\s]*?", re.IGNORECASE),  #ssl2
                'method': "equal_to",
                'secure_values': ("", "!SSLv2"),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "SSLv2 protocol",
                'additional_text': "Always disable, SSLv2 is not secure"
            },
            {
                'regex': re.compile(r"[^a-z]Options\s.*?[^\-Includes].*?(?P<value>\+?Includes).*", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("", "-Includes"),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "ServerSide includes",
                'additional_text': "Only enable when required"
            },
            {
                'regex': re.compile(r"[^a-z]Options\s.*?[^\-ExecCGI].*?(?P<value>\+?ExecCGI).*", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("", "-ExecCGI"),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "CGI execution",
                'additional_text': "Only enable when if you're using CGI"
            },
            {
                'regex': re.compile(r"[^a-z]Options\s.*?[^\-Indexes].*?(?P<value>\+?Indexes).*", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("", "-Indexes"),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "Directory Listing",
                'additional_text': "Enabling this allows people to browse your web-filesystem"
            },
            {
                'regex': re.compile(r"[^a-z]ScriptAlias\s(?P<value>/cgi-bin/).*", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': (""),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "cgi-bin alias",
                'additional_text': "Controls cgi-bin aliasing"
            },
            {
                'regex': re.compile(r"[^a-z]Alias\s(?P<value>/doc/).*", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': (""),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "Docs alias",
                'additional_text': "Controls Apache doc aliasing"
            },
            {
                'regex': re.compile(r"[^a-z]Alias\s(?P<value>/icons/).*", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': (""),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "Icons alias",
                'additional_text': "Controls Apache icon aliasing"
            },
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
            {
                'regex': re.compile(r"[^a-z]server_tokens\s(?P<value>on|off)", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("off"),
                'display_value': True,
                'test_name': "Server tokens",
                'additional_text': "Display nginx version information"
            },
            {
                'regex': re.compile(r"[^a-z]autoindex\s(?P<value>on|off)", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("", "off"),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "Directory Listing",
                'additional_text': "Enabling this allows people to browse your web-filesystem"
            },
            {
                'regex': re.compile(r"[^a-z]location\s(?P<value>/doc).*", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': (""),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "Docs alias",
                'additional_text': "Controls nginx doc aliasing"
            },
            {
                'regex': re.compile(r"[^a-z]location\s(?P<value>/images).*", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("", "off"),
                'display_value': False,
                'display_text': {'success': "Not Found", 'failure': "Found"},
                'secure_on_empty': True,
                'test_name': "Images alias",
                'additional_text': "Controls nginx image aliasing"
            },
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
            {
                'regex': re.compile(r"[^a-z]expose_php\s?=\s?(?P<value>on|off)", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("off"),
                'display_value': True,
                'test_name': "Expose PHP",
                'additional_text': "Controls PHP exposing itself via HTTP headers etc"
            },
            {
                'regex': re.compile(r"[^a-z]register_globals\s?=\s?(?P<value>on|off)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("off"),
                'display_value': True,
                'test_name': "Register globals",
                'additional_text': "Controls whether GET, POST, etc variables are globally registered"
            },
            {
                'regex': re.compile(r"[^a-z]display_errors\s?=\s?(?P<value>on|off)", re.IGNORECASE), 
                'method': "equal_to",
                'secure_values': ("off"),
                'display_value': True,
                'test_name': "Display errors",
                'additional_text': "Controls whether PHP prints errors"
            },
            {
                'regex': re.compile(r"[^a-z]session\.use_only_cookies\s?=\s?(?P<value>1|0)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("1"),
                'display_value': True,
                'test_name': "Use only cookies",
                'additional_text': "Prevents attacks involving passing session ids in URLs"
            },
            {
                'regex': re.compile(r"[^a-z]session\.cookie_httponly\s?=\s?(?P<value>1|0)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("1"),
                'display_value': True,
                'test_name': "HTTPOnly cookies",
                'additional_text': "Cookies set by the server can only be read by the client"
            },
            {
                'regex': re.compile(r"[^a-z]session\.use_trans_sid\s=\s(?P<value>1|0)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("0"),
                'display_value': True,
                'test_name': "Session trans SID",
                'additional_text': "Enables or disables URL-based session ids"
            },
            {
                'regex': re.compile(r"[^a-z]extension\s?=\s?(?P<value>suhosin.so)", re.IGNORECASE),
                'method': "equal_to",
                'secure_values': ("suhosin.so"),
                'display_value': False,
                'display_text': {'success': "Found", 'failure': "Not Found"},
                'secure_on_empty': False,
                'test_name': "Suhosin",
                'additional_text': "PHP hardening - http://www.hardened-php.net/suhosin/"
            },
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
            {
                'regex': re.compile(r"denyhosts", re.IGNORECASE),
                'method': "like",
                'secure_values': (re.compile(r"denyhosts", re.IGNORECASE)),
                'display_value': True,
                'display_text': {'success': "Found", 'failure': "Not Found"},
                'secure_on_empty': False,
                'test_name': "DenyHosts running",
                'additional_text': "When running, DenyHosts will help protect your server from SSH bruteforcing"
            },
        ),
    },
)

dont_exclude = ('denyhosts',)


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
            if self.installed is False and system['name'] not in dont_exclude:
                sys.stdout.write("%sNot installed. Skipping%s\n" % (MESSAGE, RESET))
            else:
                for test in system['tests']:
                    self.test = test
                    getattr(self, system['check_function'])()
            sys.stdout.write("\n")
            
    def totals(self):
        """Grab totals and output them"""
        all = (self.TOTAL_SECURE+self.TOTAL_UNSECURE+self.TOTAL_UNKNOWN)
        sys.stdout.write("%sResults%s\n" % (TITLE, RESET))
        sys.stdout.write("%sScanned:  %s%s\n" % (MESSAGE, all, RESET))
        sys.stdout.write("%sSecure:   %s%s\n" % (SUCCESS, self.TOTAL_SECURE, RESET))
        sys.stdout.write("%sUnsecure: %s%s\n" % (FAILURE, self.TOTAL_UNSECURE, RESET))
        sys.stdout.write("%sUnknown:  %s%s\n" % (UNKNOWN, self.TOTAL_UNKNOWN, RESET))
        sys.stdout.write("\n")

    def like(self, this, regex):
        """Check content against a regex"""
        if isinstance(regex, (tuple)):
            for r in regex:
                if r.match(this):
                    return True
        else:
            if regex.match(this):
                return True
        return False
    
    def equal_to(self, this, that):
        """Convert values to strings and check if they match"""
        if isinstance(that, (tuple)):
            if this.lower() in [x.lower() for x in that]:
                return True
        if isinstance(that, (str)):
            if this.lower() == that.lower():
                return True
        return False
    
    def greater_than(self, this, that):
        """Convert values to integers and check if the first is greater than the second"""
        if isinstance(that, (tuple)):
            if int(this) > [int(x) for x in that]:
                return True
        if isinstance(that, (int)):
            if int(this) > int(that):
                return True
        return False
    
    def less_than(self, this, that):
        """Convert values to integers and check if the first is less than the second"""
        if isinstance(that, (tuple)):
            if int(this) < [int(x) for x in that]:
                return True
        if isinstance(that, (int)):
            if int(this) < int(that):
                return True
        return False
    
    def write_to_shell(self, value, colour):
        """Output response to shell"""
        sys.stdout.write("- %s ... " % (self.test['test_name'],))
        sys.stdout.write(colour + value.upper() + RESET)
        sys.stdout.write("\n")
        sys.stdout.write("  %s%s%s"% (MESSAGE, self.test['additional_text'], RESET))
        sys.stdout.write("\n")
    
    def check_value(self):
        """Value testing method"""
        secure_on_empty_set = True
        try:
            a = self.test['secure_on_empty']
        except KeyError:
            secure_on_empty_set = False
        
        if self.test['regex'].search(self.content):
            value = self.test['regex'].findall(self.content)[-1]
            if getattr(self, self.test['method'])(value, self.test['secure_values']):
                success = True
                colour = SUCCESS
                display_value = value + " (secure)"
                self.TOTAL_SECURE += 1
            else:
                success = False
                colour = FAILURE
                display_value = value + " (not secure)"
                self.TOTAL_UNSECURE += 1
        elif secure_on_empty_set is True:
            if self.test['secure_on_empty'] is True:
                success = True
                colour = SUCCESS
                display_value = self.test['display_text']['success']
                self.TOTAL_SECURE += 1
            elif self.test['secure_on_empty'] is False:
                success = False
                colour = FAILURE
                display_value = "%s (not secure)" % self.test['display_text']['failure']
                self.TOTAL_UNSECURE += 1
        else:
            colour = UNKNOWN
            display_value = "unknown"
            self.TOTAL_UNKNOWN += 1
        # override
        if self.test['display_value'] is not True:
            if success is True:
                display_value = "%s (secure)" % self.test['display_text']['success']
            else:
                display_value = "%s (not secure)" % self.test['display_text']['failure']
        self.write_to_shell(display_value, colour)
    
    def get_file_content(self, system):
        """Open up all listed config files and cat their content together"""
        content = ""
        self.installed = False
        for file in system['files']:
            if re.search(r"\*$", file):
                (path, asterix) = os.path.split(file)
                if os.path.exists(path):
                    for extra_file in os.listdir(path):
                        file_path = os.path.join(path, extra_file)
                        if os.path.exists(file_path):
                            self.installed = True
                            content += "\n" + open(file_path, "r").read()
            elif os.path.exists(file):
                self.installed = True
                content += "\n" + open(file, "r").read()
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
    sys.exit(os.EX_OK)
