#!/usr/bin/python

from boothtestenv import BoothTestEnvironment
from boothrunner  import BoothRunner

class ClientTestEnvironment(BoothTestEnvironment):
    mode = 'client'

    def run_booth(self, config_text=None, config_file=None, lock_file=True, args=[],
                  expected_exitcode=0, debug=False):
        '''
        Runs boothd.

        Returns a (pid, return_code, stdout, stderr, runner) tuple,
        where return_code/stdout/stderr are None iff pid is still running.
        '''
        self.init_log()

        runner = BoothRunner(self.boothd_path, self.mode, args)
        runner.show_args()
        (pid, return_code, stdout, stderr) = runner.run()
        self.check_return_code(pid, return_code, expected_exitcode)

        return (pid, return_code, stdout, stderr, runner)

    def _test_buffer_overflow(self, expected_error, **args):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(expected_exitcode=1, **args)
        self.assertRegexpMatches(stderr, expected_error)
