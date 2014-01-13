#!/usr/bin/python
# vim: fileencoding=utf-8
# see http://stackoverflow.com/questions/728891/correct-way-to-define-python-source-code-encoding

import os, sys, time, signal, tempfile, socket
import re, shutil, pexpect, logging
import random, copy, glob


# Don't make that much sense - function/line is write().
# Would have to use traceback.extract_stack() manually.
#   %(funcName)10.10s:%(lineno)3d  %(levelname)8s 
default_log_format = '%(asctime)s: %(message)s'
default_log_datefmt = '%b %d %H:%M:%S'


# {{{ pexpect-logging glue
# needed for use as pexpect.logfile, to relay into existing logfiles
class expect_logging():
    prefix = ""
    test = None

    def __init__(self, pre, inst):
        self.prefix = pre
        self.test = inst

    def flush(self, *arg):
        pass
    def write(self, stg):
        if self.test.dont_log_expect == 0:
            # TODO: split by input/output, give program
            for line in re.split(r"[\r\n]+", stg):
                if line == self.test.prompt:
                    continue
                if line == "":
                    continue
                logging.debug("  " + self.prefix + "  " + line)
# }}}


class UT():
# {{{ Members
    binary = None
    test_base = None
    lockfile = None

    defaults = None

    this_port = None
    this_site = "127.0.0.1"
    this_site_id = None

    gdb = None
    booth = None
    prompt = "CUSTOM-GDB-PROMPT-%d-%d" % (os.getpid(), time.time())

    dont_log_expect = 0

    udp_sock = None
# }}}


# {{{ setup functions
    @classmethod
    def _filename(cls, desc):
        return "/tmp/booth-unittest.%s" % desc
        return "/tmp/booth-unittest.%d.%s" % (os.getpid(), desc)


    def __init__(self, bin, dir):
        self.binary = os.path.realpath(bin)
        self.test_base = os.path.realpath(dir) + "/"
        self.defaults = self.read_test_input(self.test_base + "_defaults.txt", state="ticket")
        self.lockfile = UT._filename("lock")
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


    def read_test_input(self, file, state=None, m={ "ticket": {}, "message": {} } ):
        fo = open(file, "r")
        for line in fo.readlines():
            # comment?
            if re.match(r"^\s*#", line):
                continue
            # empty line
            if re.match(r"^\s*$", line):
                continue

            # message resp. ticket
            res = re.match(r"^\s*(\w+)\s*:\s*$", line)
            if res:
                state = res.group(1)
                if not m.has_key(state):
                    m[state] = {}
                continue

            assert(state)

            res = re.match(r"^\s*(\S+)\s*(.*)\s*$", line)
            if res:
                assert(state)
                if not m[state]:
                    m[state] = {}
                m[state][ res.group(1) ] = res.group(2)
        return m


    def setup_log(self, **args):
        global default_log_format
        global default_log_datefmt

        this_test_log = logging.FileHandler( mode = "w", **args )
        this_test_log.setFormatter(
                logging.Formatter(fmt = default_log_format,
                    datefmt = default_log_datefmt) )
        
        this_test_log.emit(
                logging.makeLogRecord( { 
                    "msg": "## vim: set ft=messages : ##",
                    "lineno": 0,
                    "levelname": "None",
                    "level": None,} ) )

        # in the specific files we want ALL information
        this_test_log.setLevel(logging.DEBUG)

        logging.getLogger('').addHandler(this_test_log)
        return this_test_log


    # We want shorthand in descriptions, ie. "state"
    # instead of "booth_conf->ticket[0].state".
    def translate_shorthand(self, name, context):
        if context == 'ticket':
            return "booth_conf->ticket[0]." + name
        if context == 'message':
            return "msg->" + name
        assert(False)




    def stop_processes(self):
        if os.access(self.lockfile, os.F_OK):
            os.unlink(self.lockfile)
        # In case the boothd process is already dead, isalive() would still return True
        # (because GDB still has it), but terminate() does fail.
        # So we just quit GDB, and that might take the boothd with it -
        # if not, we terminate it ourselves.
        if self.gdb:
            self.gdb.close( force=True );
        if self.booth:
            self.booth.close( force=self.booth.isalive() )



    def start_processes(self):
        self.booth = pexpect.spawn(self.binary,
                args = [ "daemon", "-D",
                    "-c", self.test_base + "/booth.conf",
                    "-s", "127.0.0.1",
                    "-l", self.lockfile,
                    ],
                env = dict( os.environ.items() +
                    [('PATH',
                        self.test_base + "/bin/:" +
                        os.getenv('PATH'))] ),
                #logfile = expect_logging("?? boothd", self),
                timeout = 30,
                maxread = 32768)
        self.booth.setecho(False)
        self.booth.logfile_read = expect_logging("<-  boothd", self)
        self.booth.logfile_send = expect_logging(" -> boothd", self)
        logging.info("started booth with PID %d, lockfile %s" % (self.booth.pid, self.lockfile))
        self.booth.expect(self.this_site, timeout=2)
        #print self.booth.before; exit

        self.gdb = pexpect.spawn("gdb",
                args=["-quiet",
                    "-p", str(self.booth.pid),
                    "-nx", "-nh",   # don't use .gdbinit
                    ],
                timeout = 30,
                #logfile = expect_logging("?? gdb", self),
                maxread = 32768)
        self.gdb.setecho(False)
        self.gdb.logfile_read = expect_logging("<-  gdb", self)
        self.gdb.logfile_send = expect_logging(" -> gdb", self)
        logging.info("started GDB with PID %d" % self.gdb.pid)
        self.gdb.expect("(gdb)")
        self.gdb.sendline("set pagination off\n")
        self.gdb.sendline("set verbose off\n") ## sadly to late for the initial "symbol not found" messages
        self.gdb.sendline("set prompt " + self.prompt + "\\n\n");
        self.sync(2000)

        self.this_site_id = self.query_value("local->site_id")
        self.this_port = self.query_value("boothd_config->port")

        # do a self-test
        self.check_value("local->site_id", self.this_site_id);
        
        # Now we're set up.
        self.send_cmd("break booth_udp_send")
        self.send_cmd("break booth_udp_broadcast")
        self.send_cmd("break process_recv")
# }}}


# {{{ GDB communication
    def sync(self, timeout=-1):
        self.gdb.expect(self.prompt, timeout)

        answer = self.gdb.before

        self.dont_log_expect += 1
        # be careful not to use RE characters like +*.[] etc.
        r = str(random.randint(2**19, 2**20))
        self.gdb.sendline("print " + r)
        self.gdb.expect(r, timeout)
        self.gdb.expect(self.prompt, timeout)
        self.dont_log_expect -= 1
        return answer    # send a command to GDB, returning the GDB answer as string.

    def send_cmd(self, stg, timeout=-1):
        # avoid logging the echo of our command 
        self.gdb.sendline(stg + "\n")
        return self.sync()

    def _query_value(self, which):
        val = self.send_cmd("print " + which)
        cleaned = re.search(r"^\$\d+ = (.*\S)\s*$", val, re.MULTILINE)
        assert cleaned,val
        return cleaned.group(1)

    def query_value(self, which):
        res = self._query_value(which)
        logging.debug("query_value: «%s» evaluates to «%s»" % (which, res))
        return res

    def check_value(self, which, value):
        val = self._query_value("(" + which + ") == (" + value + ")")
        logging.debug("check_value: «%s» is «%s»: %s" % (which, value, val))
        assert val == "1", val # TODO: return?

    # Send data to GDB, to inject them into the binary.
    # Handles different data types
    def set_val(self, name, value, numeric_conv=None):
        logging.debug("setting value «%s» to «%s» (num_conv %s)" %(name, value, numeric_conv))
        # string value?
        if re.match(r'^"', value):
            self.send_cmd("print strcpy(" + name + ", " + value + ")")
        # numeric
        elif numeric_conv:
            self.send_cmd("set variable " + name + " = " + numeric_conv + "(" + value + ")")
        else:
            self.send_cmd("set variable " + name + " = " + value)
# }}} GDB communication


    # there has to be some event waiting, so that boothd stops again.
    def continue_debuggee(timeout=30):
        self.gdb.send_cmd("continue", timeout)


# {{{ High-level functions
    def set_state(self, kv):
        for n, v in kv.iteritems():
            self.set_val( self.translate_shorthand(n, "ticket"), v)
        logging.info("set state")

    def send_message(self, msg):
        udp_sock.sendto('a', (self.this_site, self.this_port))
        self.continue_debuggee(timeout=2)

    def wait_outgoing(self, msg):
        pass

    def loop(self, data):
        matches = map(lambda k: re.match(r"^(outgoing|message)(\d+)$", k), data.iterkeys())
        valid_matches = filter(None, matches)
        nums = map(lambda m: int(m.group(2)), valid_matches)
        loop_max = max(nums)
        for counter in range(0, loop_max+1):    # incl. last message
            logging.info("Part " + str(counter))
            msg = 'message%d' % counter
            if data.has_key(msg):
                self.send_message(data[msg])
            out = 'outgoing%d' % counter
            if data.has_key(msg):
                self.wait_outgoing(data[msg])

    def run(self):
        os.chdir(self.test_base)
        # TODO: sorted, random order
        for f in filter( (lambda f: re.match(r"^\d\d\d_.*\.txt$", f)), glob.glob("*")):
            log = None
            try:
                log = self.setup_log(filename = UT._filename(f))

                log.setLevel(logging.DEBUG)
                logging.warn("running test %s" % f)
                self.start_processes()

                test = self.read_test_input(f, m=copy.deepcopy(self.defaults))
                self.set_state(test["ticket"])
                self.loop(test)
            finally:
                self.stop_processes()
                if log:
                    log.close()
            return
# }}}


##
##class Message(UT):
##    def set_break():
##        "message_recv"
##
##    # set data, with automatic htonl() for network messages.
##    def send_vals(self, data):
##        for n, v in data.iteritems():
##            self.set_val("msg->" + n, v, "htonl")
##
##class Ticket(UT):
##    # set ticket data - 
##    def send_vals(self, data):
##        for (n, v) in data:
##            self.set_val(n, v)


# {{{ main 
if __name__ == '__main__':
    if os.geteuid() == 0:
        sys.stderr.write("Must be run non-root; aborting.\n")
        sys.exit(1)


    ut = UT(sys.argv[1], sys.argv[2] + "/")

    # "master" log object needs max level
    logging.basicConfig(level = logging.DEBUG,
            format = default_log_format,
            datefmt = default_log_datefmt)


    overview_log = ut.setup_log( filename = UT._filename('seq') )
    overview_log.setLevel(logging.WARN)

    # http://stackoverflow.com/questions/9321741/printing-to-screen-and-writing-to-a-file-at-the-same-time
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('%(levelname)-8s: %(message)s'))
    logging.getLogger('').addHandler(console)
    console.setLevel(logging.WARN)

 
    logging.info("Starting boothd unit tests.")

    ret = ut.run()
    sys.exit(ret)
# }}}
