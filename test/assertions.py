#!/usr/bin/python

import re

class BoothAssertions:
    def configFileMissingMyIP(self, config_file=None, lock_file=None):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_file=config_file, lock_file=lock_file,
                           expected_exitcode=1)

        expected_error = "ERROR: can't find myself in config file"
        self.assertRegexpMatches(self.read_log(), expected_error)

    def assertLockFileError(self, config_file=None, config_text=None,
                            lock_file=True, args=[]):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=config_text, config_file=config_file,
                           lock_file=lock_file, args=args, expected_exitcode=1)
        expected_error = 'lockfile open error %s: Permission denied' % runner.lock_file_used()
        self.assertRegexpMatches(self.read_log(), expected_error)

    ######################################################################
    # backported from 2.7 just in case we're running on an older Python
    def assertRegexpMatches(self, text, expected_regexp, msg=None):
        """Fail the test unless the text matches the regular expression."""
        if isinstance(expected_regexp, basestring):
            expected_regexp = re.compile(expected_regexp)
        if not expected_regexp.search(text):
            msg = msg or "Regexp didn't match"
            msg = '%s: %r not found in %r' % (msg, expected_regexp.pattern, text)
            raise self.failureException(msg)

    def assertNotRegexpMatches(self, text, unexpected_regexp, msg=None):
        """Fail the test if the text matches the regular expression."""
        if isinstance(unexpected_regexp, basestring):
            unexpected_regexp = re.compile(unexpected_regexp)
        match = unexpected_regexp.search(text)
        if match:
            msg = msg or "Regexp matched"
            msg = '%s: %r matches %r in %r' % (msg,
                                               text[match.start():match.end()],
                                               unexpected_regexp.pattern,
                                               text)
            raise self.failureException(msg)
    ######################################################################
