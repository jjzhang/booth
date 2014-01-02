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
    '''
    boothd site/arbitrator will hang in setup phase while attempting to connect
    to an unreachable peer during ticket_catchup().  In a test environment we don't
    have any reachable peers.  Fortunately, we can still successfully launch a
    daemon by only listing our own IP in the config file.
    '''
    typical_config = """\
# This is like the config in the manual
transport="UDP"
port="6666"
# Here's another comment
#arbitrator="147.2.207.14"
site="147.4.215.19"
#site="147.18.2.1"
ticket="ticketA"
ticket="ticketB"
"""
    site_re = re.compile('^site=".+"', re.MULTILINE)
    working_config = re.sub(site_re, 'site="%s"' % get_IP(), typical_config, 1)

    def run_booth(self, expected_exitcode, expected_daemon,
                  config_text=None, config_file=None, lock_file=True,
                  args=[], debug=False):
        '''
        Runs boothd.  Defaults to using a temporary lock file and the
        standard config file path.  There are four possible types of
        outcome:

            - boothd exits non-zero without launching a daemon (setup phase failed,
              e.g. due to invalid configuration file)
            - boothd exits zero after launching a daemon (successful operation)
            - boothd does not exit (running in foreground / debug mode)
            - boothd does not exit (setup phase hangs, e.g. while attempting
              to connect to peer during ticket_catchup())

        Arguments:
            config_text
                a string containing the contents of a configuration file to use
            config_file
                path to a configuration file to use
            lock_file
                False: don't pass a lockfile parameter to booth via -l
                True: pass a temporary lockfile parameter to booth via -l
                string: pass the given lockfile path to booth via -l
            args
                array of extra args to pass to booth
            expected_exitcode
                an integer, or False if booth is not expected to terminate
                within the timeout
            expected_daemon
                True iff a daemon is expected to be launched (this includes
                running the server in debug / foreground mode via -D; even
                though in this case the server's not technically not a daemon,
                we still want to treat it like one by checking the lockfile
                before and after we kill it)
            debug
                True means pass the -D parameter

        Returns a (pid, return_code, stdout, stderr, runner) tuple,
        where return_code/stdout/stderr are None iff pid is still running.
        '''
        if expected_daemon and expected_exitcode is not None and expected_exitcode != 0:
            raise RuntimeError, \
                "Shouldn't ever expect daemon to start and then failure"

        if not expected_daemon and expected_exitcode == 0:
            raise RuntimeError, \
                "Shouldn't ever expect success without starting daemon"

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

        if expected_daemon:
            self.check_daemon_handling(runner, expected_daemon)
        elif return_code is None:
            # This isn't strictly necessary because we ensure no
            # daemon is running from within test setUp(), but it's
            # probably a good idea to tidy up after ourselves anyway.
            self.kill_pid(pid)

        return (pid, return_code, stdout, stderr, runner)

    def write_config_file(self, config_text):
        config_file = self.get_tempfile('config')
        c = open(config_file, 'w')
        c.write(config_text)
        c.close()
        return config_file

    def kill_pid(self, pid):
        print "killing %d ..." % pid
        os.kill(pid, 15)
        print "killed"

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
            self.kill_pid(int(daemon_pid))
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
        pid = re.search('\\bbooth_pid="?(\\d+)"?', lines[0]).group(1)
        print "lockfile contains: <%s>" % pid
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

    def _test_buffer_overflow(self, expected_error, **args):
        (pid, ret, stdout, stderr, runner) = \
            self.run_booth(expected_exitcode=1, expected_daemon=False, **args)
        self.assertRegexpMatches(stderr, expected_error)
