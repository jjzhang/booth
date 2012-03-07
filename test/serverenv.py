#!/usr/bin/python

import os
import re
import time
import unittest

from assertions   import BoothAssertions
from boothrunner  import BoothRunner
from boothtestenv import BoothTestEnvironment
from utils        import get_IP

class ServerTestEnvironment(BoothTestEnvironment):
    typical_config = """\
# This is like the config in the manual
transport="UDP"
port="6666"
# Here's another comment
arbitrator="147.2.207.14"
site="147.4.215.19"
site="147.18.2.1"
ticket="ticketA"
ticket="ticketB"
"""
    working_config = re.sub('site=".+"', 'site="%s"' % get_IP(), typical_config, 1)

    def run_booth(self, config_text=None, config_file=None, lock_file=True, args=[],
                  expected_exitcode=0, debug=False):
        '''
        Runs boothd.  Defaults to using a temporary lock file and
        the standard config file path.

        Returns a (pid, return_code, stdout, stderr, runner) tuple,
        where return_code/stdout/stderr are None iff pid is still running.
        '''
        self.init_log()

        runner = BoothRunner(self.boothd_path, self.mode, args)

        if config_text:
            config_file = self.write_config_file(config_text)
        if config_file:
            runner.set_config_file(config_file)

        if lock_file is True:
            lock_file = os.path.join(self.test_path, 'boothd-lock.pid')
        if lock_file:
            runner.set_lock_file(lock_file)

        if debug:
            runner.set_debug()

        runner.show_args()
        (pid, return_code, stdout, stderr) = runner.run()
        self.check_return_code(pid, return_code, expected_exitcode)

        expected_daemon = expected_exitcode == 0 or expected_exitcode is None
        got_daemon      = return_code       == 0 or return_code       is None

        if got_daemon:
            self.check_daemon_handling(runner, expected_daemon)

        return (pid, return_code, stdout, stderr, runner)

    def write_config_file(self, config_text):
        config_file = self.get_tempfile('config')
        c = open(config_file, 'w')
        c.write(config_text)
        c.close()
        return config_file

    def check_daemon_handling(self, runner, expected_daemon):
        '''
        Check that the lock file contains a pid referring to a running
        daemon.  Then kill the daemon, and ensure that the lock file
        vanishes (bnc#749763).
        '''
        daemon_pid = self.get_daemon_pid_from_lock_file(runner.lock_file)
        err = "lock file should contain pid"
        if not expected_daemon:
            err += ", even though we didn't expect a daemon"
        self.assertTrue(daemon_pid is not None, err)

        daemon_running = self.is_pid_running_daemon(daemon_pid)
        err = "pid in lock file should referred to a running daemon"
        self.assertTrue(daemon_running, err)

        if daemon_running:
            print "killing %s ..." % daemon_pid
            os.kill(int(daemon_pid), 15)
            print "killed"
            time.sleep(1)
            daemon_pid = self.get_daemon_pid_from_lock_file(runner.lock_file)
            self.assertTrue(daemon_pid is not None,
                            'bnc#749763: lock file should vanish after daemon is killed')

    def get_daemon_pid_from_lock_file(self, lock_file):
        '''
        Returns the pid contained in lock_file, or None if it doesn't exist.
        '''
        if not os.path.exists(lock_file):
            print "%s does not exist" % lock_file
            return None

        l = open(lock_file)
        lines = l.readlines()
        l.close()
        self.assertEqual(len(lines), 1, "Lock file should contain one line")
        pid = lines[0].rstrip()
        print "lockfile contains: %s" % pid
        return pid

    def is_pid_running_daemon(self, pid):
        '''
        Returns true iff the given pid refers to a running boothd process.
        '''

        path = "/proc/%s" % pid
        pid_running = os.path.isdir(path)

        # print "======"
        # import subprocess
        # print subprocess.check_output(['lsof', '-p', pid])
        # print subprocess.check_output(['ls', path])
        # print subprocess.check_output(['cat', "/proc/%s/cmdline" % pid])
        # print "======"

        if not pid_running:
            return False

        c = open("/proc/%s/cmdline" % pid)
        cmdline = "".join(c.readlines())
        print cmdline
        c.close()

        if cmdline.find('boothd') == -1:
            print 'no boothd in cmdline:', cmdline
            return False

        # self.assertRegexpMatches(
        #     cmdline,
        #     'boothd',
        #     "lock file should refer to pid of running boothd"
        # )

        return True
