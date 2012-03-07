#!/usr/bin/python

import copy
from   pprint    import pprint, pformat
import re

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
