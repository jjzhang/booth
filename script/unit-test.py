#!/usr/bin/python

import os
import re
import shutil
import sys
import time
import pexpect

binary = sys.argv[1]
test_base = sys.argv[2] + "/"


class Common():
    gdb = None
    booth = None
    prompt = "CUSTOM-GDB-PROMPT-%d-%d" % (os.getpid(), time.time())

    def sync(timeout=-1):
        gdb.expect(prompt, timeout)

    def __init__(self):
        booth = pexpect.spawn(binary, args=["daemon", "-D", "-c", test_base + "/booth.conf"])
        booth.expect("o") # TODO

        gdb = pexpect.spawn("gdb",
                args=["-quiet", "-p", booth.pid],
                timeout=30,
                maxread=32768)
        gdb.expect("(gdb)")
        gdb.sendline("set pagination off\n")
        gdb.sendline("set prompt " + prompt + "\n");
        self.sync(2000)

    def send_cmd(stg):
        gdb.sendline(stg + "\n")
        gdb.sync()

    def set_val(name, value, numeric_conv=None):
        # string value?
        if re.match('^"', value):
            send_cmd("print strcpy(" + name + ", " + value + ")")
        # numeric
        elif numeric_conv:
            send_cmd("set variable " + name + " = " + numeric_conv + "(" + value + ")")
        else:
            send_cmd("set variable " + name + " = " + value)


class Message(Common):
    def set_break():
        "message_recv"

    def send_vals(data):
        for (n, v) in data:
            set_val("msg->" + n, v, "htonl")

class Ticket(Common):
    def send_vals(data):
        for (n, v) in data:
            set_val(n, v)

def read_test_input(file, state=None):
    fo = open(file, "r")
    m = { "ticket": {}, "message" : {} }
    for line in fo.readlines():
        # comment?
        if re.match("^\\s*#", line):
            continue

        # message resp. ticket
        res = re.match("^\\s*(\\w+)\\s*:\\s*$", line)
        if res:
            state = res.group(1)
            continue

        res = re.match("^\\s*(\\S+)\\s*(.*)\\s*$", line)
        if res:
            assert(state)
            if not m[state]:
                m[state] = {}
            m[state][ res.group(1) ] = res.group(2)
    return m

if __name__ == '__main__':
    if os.geteuid() == 0:
        sys.stderr.write("Must be run non-root; aborting.\n")
        sys.exit(1)

    defaults = read_test_input(test_base + "_defaults.txt", state="ticket")
    print defaults
    sys.exit(0)


##
##name value
##
##value.match
##
##function void():
##    tmp_path            = '/tmp/booth-tests'
##    if not os.path.exists(tmp_path):
##        os.makedirs(tmp_path)
##    test_run_path       = tempfile.mkdtemp(prefix='%d.' % time.time(), dir=tmp_path)
##
##    suite = unittest.TestSuite()
##    testclasses = [
##        SiteConfigTests,
##        #ArbitratorConfigTests,
##        ClientConfigTests,
##    ]
##    for testclass in testclasses:
##        testclass.test_run_path = test_run_path
##        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(testclass))
##
##    runner_args = {
##        'verbosity' : 4,
##    }
##    major, minor, micro, releaselevel, serial = sys.version_info
##    if major > 2 or (major == 2 and minor >= 7):
##        # New in 2.7
##        runner_args['buffer'] = True
##        runner_args['failfast'] = True
##        pass
##
##    # not root anymore, so safe
##    # needed because old instances might still use the UDP port.
##    os.system("killall boothd")
##
##    runner = unittest.TextTestRunner(**runner_args)
##    result = runner.run(suite)
##
##    if result.wasSuccessful():
##        shutil.rmtree(test_run_path)
##        sys.exit(0)
##    else:
##        print "Left %s for debugging" % test_run_path
##        s
##
