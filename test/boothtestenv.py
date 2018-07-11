import os
import subprocess
import time
import tempfile
import unittest

from assertions  import BoothAssertions
from boothrunner import BoothRunner

class BoothTestEnvironment(unittest.TestCase, BoothAssertions):
    test_src_path       = os.path.abspath(os.path.dirname(__file__))
    dist_path           = os.path.join(test_src_path, '..'    )
    src_path            = os.path.join(dist_path,     'src'   )
    boothd_path         = os.path.join(src_path,      'boothd')
    conf_path           = os.path.join(dist_path,     'conf'  )
    example_config_path = os.path.join(conf_path, 'booth.conf.example')

    def setUp(self):
        if not self._testMethodName.startswith('test_'):
            raise RuntimeError("unexpected test method name: " + self._testMethodName)
        self.test_name = self._testMethodName[5:]
        self.test_path = os.path.join(self.test_run_path, self.test_name)
        os.makedirs(self.test_path)
        self.ensure_boothd_not_running()

    def ensure_boothd_not_running(self):
        # Need to redirect STDERR in case we're not root, in which
        # case netstat's -p option causes a warning.  However we only
        # want to kill boothd processes which we own; -p will list the
        # pid for those and only those, which is exactly what we want
        # here.
        subprocess.call("netstat -tpln 2>&1 | perl -lne 'm,LISTEN\s+(\d+)/boothd, and kill 15, $1'", shell=True)

    def get_tempfile(self, identity):
        tf = tempfile.NamedTemporaryFile(
            prefix='%s.%d.' % (identity, time.time()),
            dir=self.test_path,
            delete=False
        )
        return tf.name

    def init_log(self):
        self.log_file = self.get_tempfile('log')
        os.putenv('HA_debugfile', self.log_file) # See cluster-glue/lib/clplumbing/cl_log.c

    def read_log(self):
        if not os.path.exists(self.log_file):
            return ''

        l = open(self.log_file)
        msgs = ''.join(l.readlines())
        l.close()
        return msgs

    def check_return_code(self, pid, return_code, expected_exitcode):
        if return_code is None:
            print("pid %d still running" % pid)
            if expected_exitcode is not None:
                self.fail("expected exit code %d, not long-running process" % expected_exitcode)
        else:
            print("pid %d exited with code %d" % (pid, return_code))
            if expected_exitcode is None:
                msg = "should not exit"
            else:
                msg = "should exit with code %s" % expected_exitcode
            msg += "\nLog follows (see %s)" % self.log_file
            msg += "\nN.B. expect mlockall/setscheduler errors when running tests non-root"
            msg += "\n-----------\n%s" % self.read_log()
            self.assertEqual(return_code, expected_exitcode, msg)
