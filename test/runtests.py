#!/usr/bin/python

import os
import re
import shutil
import sys
import tempfile
import time
import unittest

from clienttests import ClientConfigTests
from sitetests   import SiteConfigTests
from arbtests    import ArbitratorConfigTests

if __name__ == '__main__':
    if os.geteuid() == 0:
        sys.stderr.write("Must be run non-root; aborting.\n")
        sys.exit(1)

    tmp_path            = '/tmp/booth-tests'
    if not os.path.exists(tmp_path):
        os.makedirs(tmp_path)
    test_run_path       = tempfile.mkdtemp(prefix='%d.' % time.time(), dir=tmp_path)

    suite = unittest.TestSuite()
    testclasses = [
        SiteConfigTests,
        #ArbitratorConfigTests,
        ClientConfigTests,
    ]
    for testclass in testclasses:
        testclass.test_run_path = test_run_path
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(testclass))

    runner_args = {
        #'verbosity' : 2,
    }
    major, minor, micro, releaselevel, serial = sys.version_info
    if major > 2 or (major == 2 and minor >= 7):
        # New in 2.7
        runner_args['buffer'] = True
        runner_args['failfast'] = True
        pass

    runner = unittest.TextTestRunner(**runner_args)
    result = runner.run(suite)

    if result.wasSuccessful():
        shutil.rmtree(test_run_path)
        sys.exit(0)
    else:
        print "Left %s for debugging" % test_run_path
        sys.exit(1)
