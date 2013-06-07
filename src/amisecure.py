from functools import wraps
import os
import re
import unittest
import warnings


_MAX_LENGTH = 80


class SkipTest(Exception):
    pass


def _id(obj):
    return obj

def skip(reason):
    """
    Unconditionally skip a test.
    """
    def decorator(test_item):
        if not (isinstance(test_item, type) and issubclass(test_item, unittest.TestCase)):
            @wraps(test_item)
            def skip_wrapper(*args, **kwargs):
                raise SkipTest(reason)
            test_item = skip_wrapper

        test_item.__unittest_skip__ = True
        test_item.__unittest_skip_why__ = reason
        return test_item
    return decorator


def skipIf(condition, reason):
    """
    Skip a test if the condition is true.
    """
    if condition:
        return skip(reason)
    return _id


def safe_repr(obj, short=False):
    try:
        result = repr(obj)
    except Exception:
        result = object.__repr__(obj)
    if not short or len(result) < _MAX_LENGTH:
        return result
    return result[:_MAX_LENGTH] + ' [truncated]...'


def safe_str(obj):
    try:
        return str(obj)
    except Exception:
        return object.__str__(obj)


class _Outcome(object):
    def __init__(self):
        self.success = True
        self.skipped = None
        self.unexpectedSuccess = None
        self.expectedFailure = None
        self.errors = []
        self.failures = []

setattr(unittest.TestResult, 'skipped', [])

def addSkip(self, test, reason):
    self.skipped.append((test, reason))
    if self.showAll:
        self.stream.writeln("skipped %r" % (reason,))
    elif self.dots:
        self.stream.write("s")
    self.stream.flush()

setattr(unittest.TestResult, 'addSkip', addSkip)

class Base(unittest.TestCase):

    def get_file_content(self, files):
        """Open up all listed config files and cat their content together"""
        content = ""
        self.installed = False
        for afile in files:
            if re.search(r"\*$", afile):
                (path, asterix) = os.path.split(afile)
                if os.path.exists(path):
                    for extra_file in os.listdir(path):
                        file_path = os.path.join(path, extra_file)
                        if os.path.exists(file_path):
                            content += "\n" + open(file_path, "r").read()
            elif os.path.exists(afile):
                content += "\n" + open(afile, "r").read()
        return self.clean(content)

    def get_shell_content(self, command):
        return os.popen(command).read()

    def clean(self, content):
        """Clean up the file contents, remove extra spaces and commented lines"""
        stripped_content = ""
        for line in content.split("\n"):
            line = line.lstrip()
            line = re.sub(r"\s+", " ", line)
            if not re.match(r"[^a-z]#", line) and not re.match(r"#", line) \
            and not re.match(r"[^a-z];", line) and not re.match(r";", line):
                stripped_content += line + "\n"
        return re.sub(r"^\n$", "", stripped_content)

    def last_value(self, regex):
        vals = regex.findall(self.content)
        if len(vals) == 0:
            return ""
        if len(vals) == 1:
            return vals[0]
        return regex.findall(self.content)[-1]

    def assertLess(self, a, b, msg=None):
        """Just like self.assertTrue(a < b), but with a nicer default message."""
        if not a < b:
            standardMsg = '%s not less than %s' % (safe_repr(a), safe_repr(b))
            self.fail(self._formatMessage(msg, standardMsg))

    def assertLessEqual(self, a, b, msg=None):
        """Just like self.assertTrue(a <= b), but with a nicer default message."""
        if not a <= b:
            standardMsg = '%s not less than or equal to %s' % (safe_repr(a), safe_repr(b))
            self.fail(self._formatMessage(msg, standardMsg))

    def assertGreater(self, a, b, msg=None):
        """Just like self.assertTrue(a > b), but with a nicer default message."""
        if not a > b:
            standardMsg = '%s not greater than %s' % (safe_repr(a), safe_repr(b))
            self.fail(self._formatMessage(msg, standardMsg))

    def assertGreaterEqual(self, a, b, msg=None):
        """Just like self.assertTrue(a >= b), but with a nicer default message."""
        if not a >= b:
            standardMsg = '%s not greater than or equal to %s' % (safe_repr(a), safe_repr(b))
            self.fail(self._formatMessage(msg, standardMsg))

    def assertIn(self, member, container, msg=None):
        """Just like self.assertTrue(a in b), but with a nicer default message."""
        if member not in container:
            standardMsg = '%s not found in %s' % (safe_repr(member),
                                                  safe_repr(container))
            self.fail(self._formatMessage(msg, standardMsg))

    def assertNotIn(self, member, container, msg=None):
        """Just like self.assertTrue(a not in b), but with a nicer default message."""
        if member in container:
            standardMsg = '%s unexpectedly found in %s' % (safe_repr(member),
                                                           safe_repr(container))
            self.fail(self._formatMessage(msg, standardMsg))

    def assertIs(self, expr1, expr2, msg=None):
        """Just like self.assertTrue(a is b), but with a nicer default message."""
        if expr1 is not expr2:
            standardMsg = '%s is not %s' % (safe_repr(expr1), safe_repr(expr2))
            self.fail(self._formatMessage(msg, standardMsg))

    def assertIsNot(self, expr1, expr2, msg=None):
        """Just like self.assertTrue(a is not b), but with a nicer default message."""
        if expr1 is expr2:
            standardMsg = 'unexpectedly identical: %s' % (safe_repr(expr1),)
            self.fail(self._formatMessage(msg, standardMsg))

    def assertRegex(self, text, expected_regex, msg=None):
        """Fail the test unless the text matches the regular expression."""
        if isinstance(expected_regex, basestring):
            expected_regex = re.compile(expected_regex)
        if not expected_regex.search(text):
            msg = msg or "Regex didn't match"
            msg = '%s: %r not found in %r' % (msg, expected_regex.pattern, text)
            raise self.failureException(msg)

    def _formatMessage(self, msg, standardMsg):
        """Honour the longMessage attribute when generating failure messages.
        If longMessage is False this means:
        * Use only an explicit message if it is provided
        * Otherwise use the standard message for the assert

        If longMessage is True:
        * Use the standard message
        * If an explicit message is provided, plus ' : ' and the explicit message
        """
        if msg is None:
            return standardMsg
        try:
            return '%s : %s' % (standardMsg, msg)
        except UnicodeDecodeError:
            return '%s : %s' % (safe_str(standardMsg), safe_str(msg))

    def _addSkip(self, result, reason):
        addSkip = getattr(result, 'addSkip', None)
        if addSkip is not None:
            addSkip(self, reason)
        else:
            warnings.warn("TestResult has no addSkip method, skips not reported",
                          RuntimeWarning, 2)
            result.addSuccess(self)


    def run(self, result=None):
        orig_result = result
        if result is None:
            result = self.defaultTestResult()
            startTestRun = getattr(result, 'startTestRun', None)
            if startTestRun is not None:
                startTestRun()

        result.startTest(self)

        testMethod = getattr(self, self._testMethodName)
        if (getattr(self.__class__, "__unittest_skip__", False) or
            getattr(testMethod, "__unittest_skip__", False)):
            # If the class or method was skipped.
            try:
                skip_why = (getattr(self.__class__, '__unittest_skip_why__', '')
                            or getattr(testMethod, '__unittest_skip_why__', ''))
                self._addSkip(result, skip_why)
            finally:
                result.stopTest(self)
            return
            try:
                outcome = _Outcome()
                self._outcomeForDoCleanups = outcome

                self._executeTestPart(self.setUp, outcome)
                if outcome.success:
                    self._executeTestPart(testMethod, outcome, isTest=True)
                    self._executeTestPart(self.tearDown, outcome)

                self.doCleanups()
                if outcome.success:
                    result.addSuccess(self)
                else:
                    if outcome.skipped is not None:
                        self._addSkip(result, outcome.skipped)
                    for exc_info in outcome.errors:
                        result.addError(self, exc_info)
                    for exc_info in outcome.failures:
                        result.addFailure(self, exc_info)
                    if outcome.unexpectedSuccess is not None:
                        addUnexpectedSuccess = getattr(result, 'addUnexpectedSuccess', None)
                        if addUnexpectedSuccess is not None:
                            addUnexpectedSuccess(self)
                        else:
                            warnings.warn("TestResult has no addUnexpectedSuccess method, reporting as failures",
                                          RuntimeWarning)
                            result.addFailure(self, outcome.unexpectedSuccess)

                    if outcome.expectedFailure is not None:
                        addExpectedFailure = getattr(result, 'addExpectedFailure', None)
                        if addExpectedFailure is not None:
                            addExpectedFailure(self, outcome.expectedFailure)
                        else:
                            warnings.warn("TestResult has no addExpectedFailure method, reporting as passes",
                                          RuntimeWarning)
                            result.addSuccess(self)
                return result
            finally:
                result.stopTest(self)
                if orig_result is None:
                    stopTestRun = getattr(result, 'stopTestRun', None)
                    if stopTestRun is not None:
                        stopTestRun()


@skipIf(os.path.exists('etc/ssh') is False, "Skipped. SSH Not installed/found")
class SSH(Base):
    files = ('/etc/ssh/sshd_config', )

    def setUp(self):
        self.content = self.get_file_content(self.files)

    def tearDown(self):
        del self.content

    def test_permit_root_login(self):
        regex = re.compile(r"[^a-z]PermitRootLogin\s(?P<value>yes|no)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'no')

    def test_use_privilege_separation(self):
        regex = re.compile(r"[^a-z]UsePrivilegeSeparation\s(?P<value>yes|no)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'yes')

    def test_strict_modes(self):
        regex = re.compile(r"[^a-z]StrictModes\s(?P<value>yes|no)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'yes')

    def test_permit_empty_passwords(self):
        regex = re.compile(r"[^a-z]PermitEmptyPasswords\s(?P<value>yes|no)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'no')


@skipIf(os.path.exists('/etc/apache2') is False, "Skipped. Apache 2 not installed/found")
class Apache2(Base):
    files = ('/etc/apache2/apache2.conf',
             '/etc/apache2/mods-enabled/*',
             '/etc/apache2/httpd.conf',
             '/etc/apache2/ports.conf',
             '/etc/apache2/conf.d/*',
             '/etc/apache2/sites-enabled/*', )

    def setUp(self):
        self.content = self.get_file_content(self.files)

    def tearDown(self):
        del self.content

    def test_timeout(self):
        regex = re.compile(r"[^a-z]Timeout\s(?P<value>[0-9]*)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertLessEqual(value, 5)

    def test_keep_alive_timeout(self):
        regex = re.compile(r"[^a-z]KeepAliveTimeout\s(?P<value>[0-9]*)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertLessEqual(value, 3)

    def test_server_tokens(self):
        regex = re.compile(r"[^a-z]ServerTokens\s(?P<value>Prod|Major|Minor|Minimal|OS|Full)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertIn(value, ('prod', 'major', ))

    def test_server_signature(self):
        regex = re.compile(r"[^a-z]ServerSignature\s(?P<value>on|off)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'off')

    def test_trace_enable(self):
        regex = re.compile(r"[^a-z]TraceEnable\s(?P<value>on|off)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'off')

    def test_ssl_cipher_suite(self):
        regex = re.compile(r"[^a-z]SSLCipherSuite\s[a-z0-9\:\!\+]*?(?P<value>\+?[^\-\!]?SSLv2)[a-z0-9\:\!\+]*?", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertIn(value, ('', '!SSLv2', ))

    def test_ssl_protocol(self):
        regex = re.compile(r"[^a-z]SSLProtocol\s[a-z0-9\s]*?(?P<value>\+?[^\-\!]?SSLv2)[a-z0-9\s]*?", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertIn(value, ('', '!SSLv2', ))

    def test_includes(self):
        regex = re.compile(r"[^a-z]Options\s.*?[^\-Includes].*?(?P<value>\+?Includes).*", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertIn(value, ('', '-Includes'))

    def test_exec_cgi(self):
        regex = re.compile(r"[^a-z]Options\s.*?[^\-ExecCGI].*?(?P<value>\+?Includes).*", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertIn(value, ('', '-ExecCGI'))

    def test_indexes(self):
        regex = re.compile(r"[^a-z]Options\s.*?[^\-Indexes].*?(?P<value>\+?Includes).*", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertIn(value, ('', '-Indexes'))

    def test_script_alias(self):
        regex = re.compile(r"[^a-z]ScriptAlias\s(?P<value>/cgi-bin/).*", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, '')

    def test_doc_alias(self):
        regex = re.compile(r"[^a-z]Alias\s(?P<value>/doc/).*", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, '')

    def test_icons_alias(self):
        regex = re.compile(r"[^a-z]Alias\s(?P<value>/icons/).*", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, '')


@skipIf(os.path.exists('/etc/nginx') is False, "Skipped. Nginx not installed/found")
class Nginx(Base):
    files = ('/etc/nginx/nginx.conf',
             '/etc/nginx/conf.d/*',
             '/etc/nginx/sites-enabled/*', )

    def setUp(self):
        self.content = self.get_file_content(self.files)

    def tearDown(self):
        del self.content

    def test_server_tokens(self):
        regex = re.compile(r"[^a-z]server_tokens\s(?P<value>on|off)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertLessEqual(value, 'off')

    def test_auto_index(self):
        regex = re.compile(r"[^a-z]autoindex\s(?P<value>on|off)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertIn(value, ('', 'off', ))

    def test_doc_location(self):
        regex = re.compile(r"[^a-z]location\s(?P<value>/doc).*", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertLessEqual(value, '')

    def test_images_location(self):
        regex = re.compile(r"[^a-z]location\s(?P<value>/images).*", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertLessEqual(value, '')


@skipIf(os.path.exists('/etc/php5') is False, "Skipped. PHP is not installed/found")
class PHP(Base):
    files = ('/etc/php5/apache2/php.ini',
             '/etc/php5/conf.d/*')

    def setUp(self):
        self.content = self.get_file_content(self.files)

    def tearDown(self):
        del self.content

    def test_expose_php(self):
        regex = re.compile(r"[^a-z]expose_php\s?=\s?(?P<value>on|off)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'off')

    def test_register_globals(self):
        regex = re.compile(r"[^a-z]register_globals\s?=\s?(?P<value>on|off)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'off')

    def test_display_errors(self):
        regex = re.compile(r"[^a-z]display_errors\s?=\s?(?P<value>on|off)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'off')

    def test_use_only_cookies(self):
        regex = re.compile(r"[^a-z]session\.use_only_cookies\s?=\s?(?P<value>1|0)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, '1')

    def test_cookie_http_only(self):
        regex = re.compile(r"[^a-z]session\.cookie_httponly\s?=\s?(?P<value>1|0)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, '1')

    def test_use_trans_sid(self):
        regex = re.compile(r"[^a-z]session\.use_trans_sid\s=\s(?P<value>1|0)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, '0')

    def test_suhosin(self):
        regex = re.compile(r"[^a-z]extension\s?=\s?(?P<value>suhosin.so)", re.IGNORECASE)
        value = self.last_value(regex)
        self.assertEqual(value, 'suhosin.so')


class DenyHosts(Base):
    shell_command = 'ps aux | grep denyhosts | grep -v grep'

    def setUp(self):
        self.content = self.get_shell_content(self.shell_command)

    def tearDown(self):
        del self.content

    def test_denyhosts_running(self):
        regex = re.compile(r"denyhosts", re.IGNORECASE)
        self.assertRegex(self.content, regex)


if __name__ == '__main__':
    unittest.main()
