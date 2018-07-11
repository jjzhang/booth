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
    #     (pid, ret, stdout, stderr, runner) = \
    #         self.run_booth(expected_exitcode=1, expected_daemon=False)
    #     self.assertRegexpMatches(
    #         stderr,
    #         'failed to open %s: ' % runner.config_file_used(),
    #         'should fail to read default config file'
    #     )

    def test_example_config(self):
        self.configFileMissingMyIP(config_file=self.example_config_path)

    def test_config_file_buffer_overflow(self):
        # https://bugzilla.novell.com/show_bug.cgi?id=750256
        longfile = (string.ascii_lowercase * 5)[:127]
        expected_error = "'%s' exceeds maximum config name length" % longfile
        self._test_buffer_overflow(expected_error, config_file=longfile)

    def test_lock_file_buffer_overflow(self):
        # https://bugzilla.novell.com/show_bug.cgi?id=750256
        longfile = (string.ascii_lowercase * 5)[:127]
        expected_error = "'%s' exceeds maximum lock file length" % longfile
        self._test_buffer_overflow(expected_error, lock_file=longfile)

    def test_working_config(self):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(expected_exitcode=0, expected_daemon=True,
                           config_text=self.working_config)

    def test_missing_quotes(self):
        # quotes no longer required
        return True
        orig_lines = self.working_config.split("\n")
        for (i, line) in enumerate(orig_lines):
            new_lines = copy.copy(orig_lines)
            new_lines[i] = line.replace('"', '')
            new_config = "\n".join(new_lines)

            line_contains_IP = re.search('^\s*(site|arbitrator)=.*[0-9]\.', line)
            if line_contains_IP:
                # IP addresses need to be surrounded by quotes,
                # so stripping them should cause it to fail
                expected_exitcode = 1
                expected_daemon   = False
            else:
                expected_exitcode = 0
                expected_daemon   = True

            (pid, ret, stdout, stderr, runner) = \
                self.run_booth(config_text=new_config,
                               expected_exitcode=expected_exitcode,
                               expected_daemon=expected_daemon)

            if line_contains_IP:
                self.assertRegexpMatches(
                    self.read_log(),
                    "(ERROR|error): invalid config file format: unquoted '.'",
                    'IP addresses need to be quoted'
                )

    def test_debug_mode(self):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=self.working_config, debug=True,
                           expected_exitcode=0, expected_daemon=True)

    def test_foreground_mode(self):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=self.working_config, foreground=True,
                           expected_exitcode=None, expected_daemon=True)

    def test_debug_and_foreground_mode(self):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=self.working_config, debug=True, foreground=True,
                           expected_exitcode=None, expected_daemon=True)

    def test_missing_transport(self):
        # UDP is default -- TODO?
        return True
        config = re.sub('transport=.+\n', '', self.typical_config)
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=config, expected_exitcode=1, expected_daemon=False)
        self.assertRegexpMatches(
            self.read_log(),
            'config file was missing transport line'
        )

    def test_invalid_transport_protocol(self):
        config = re.sub('transport=.+', 'transport=SNEAKERNET', self.typical_config)
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=config, expected_exitcode=1, expected_daemon=False)
        self.assertRegexpMatches(stderr, 'invalid transport protocol')

    def test_missing_final_newline(self):
        config = re.sub('\n$', '', self.working_config)
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(config_text=config, expected_exitcode=0, expected_daemon=True)

    def test_a_few_trailing_whitespaces(self):
        for ws in (' ', '  '):
            new_config = self.working_config.replace("\n", ws + "\n", 3)
            (pid, ret, stdout, stderr, runner) = \
                self.run_booth(config_text=new_config,
                               expected_exitcode=0, expected_daemon=True)

    def test_trailing_space_everywhere(self):
        for ws in (' ', '  '):
            new_config = self.working_config.replace("\n", ws + "\n")
            (pid, ret, stdout, stderr, runner) = \
                self.run_booth(config_text=new_config,
                               expected_exitcode=0, expected_daemon=True)

    def test_unquoted_space(self):
        for ticket in ('unquoted space', 'unquoted space man'):
            new_config = re.sub('ticket=.+', 'ticket=' + ticket,
                                self.working_config, 1)
            (pid, ret, stdout, stderr, runner) = \
                self.run_booth(config_text=new_config, expected_exitcode=1, expected_daemon=False)
            self.assertRegexpMatches(stderr, 'ticket name "' + ticket + '" invalid')

    def test_unreachable_peer(self):
        # what should this test do? daemon not expected, but no exitcode either?
        # booth would now just run, and try to reach that peer...
        # TCP reachability is not required during startup anymore.
        return True
        config = re.sub('#(.+147.+)', lambda m: m.group(1), self.working_config)
        self.run_booth(config_text=config,
                       expected_exitcode=None, expected_daemon=False)
