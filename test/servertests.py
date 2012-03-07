#!/usr/bin/python

import copy
from   pprint    import pprint, pformat
import re
import string

from   serverenv import ServerTestEnvironment

class ServerTests(ServerTestEnvironment):
    # We don't know enough about the build/test system to rely on the
    # existence, permissions, contents of the default config file.  So
    # we can't predict (and hence test) how booth will behave when -c
    # is not specified.
    #
    # def test_no_args(self):
    #     # If do_server() called lockfile() first then this would be
    #     # the appropriate test:
    #     #self.assertLockFileError(lock_file=False)
    #
    #     # If do_server() called setup() first, and the default
    #     # config file was readable non-root, then this would be the
    #     # appropriate test:
    #     self.configFileMissingMyIP(lock_file=False)
    #
    # def test_custom_lock_file(self):
    #     (pid, ret, stdout, stderr, runner) = self.run_booth(expected_exitcode=1)
    #     self.assertRegexpMatches(
    #         stderr,
    #         'failed to open %s: ' % runner.config_file_used(),
    #         'should fail to read default config file'
    #     )

    def test_example_config(self):
        self.configFileMissingMyIP(config_file=self.example_config_path)

    def test_config_file_buffer_overflow(self):
        # https://bugzilla.novell.com/show_bug.cgi?id=750256
        longfile = (string.lowercase * 5)[:127]
        expected_error = "'%s' exceeds maximum config file length" % longfile
        self._test_buffer_overflow(expected_error, config_file=longfile)

    def test_lock_file_buffer_overflow(self):
        # https://bugzilla.novell.com/show_bug.cgi?id=750256
        longfile = (string.lowercase * 5)[:127]
        expected_error = "'%s' exceeds maximum lock file length" % longfile
        self._test_buffer_overflow(expected_error, lock_file=longfile)

    def test_working_config(self):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=self.working_config)

    def test_missing_quotes(self):
        orig_lines = self.working_config.split("\n")
        for i in xrange(len(orig_lines)):
            new_lines = copy.copy(orig_lines)
            new_lines[i] = new_lines[i].replace('"', '')
            new_config = "\n".join(new_lines)

            line_contains_IP = re.search('=.+\.', orig_lines[i])
            if line_contains_IP:
                # IP addresses need to be surrounded by quotes
                expected_exitcode = 1
            else:
                expected_exitcode = 0

            (pid, ret, stdout, stderr, runner) = \
                self.run_booth(config_text=new_config,
                               expected_exitcode=expected_exitcode)

            if line_contains_IP:
                self.assertRegexpMatches(
                    self.read_log(),
                    "ERROR: invalid config file format: unquoted '.'",
                    'IP addresses need to be quoted'
                )

    def test_debug_mode(self):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=self.working_config, debug=True,
                           expected_exitcode=None)

    def test_missing_transport(self):
        config = re.sub('transport=.+\n', '', self.typical_config)
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=config, expected_exitcode=1)
        self.assertRegexpMatches(
            self.read_log(),
            'config file was missing transport line'
        )

    def test_invalid_transport_protocol(self):
        config = re.sub('transport=.+', 'transport=SNEAKERNET', self.typical_config)
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=config, expected_exitcode=1)
        self.assertRegexpMatches(
            self.read_log(),
            'invalid transport protocol'
        )
