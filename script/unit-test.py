#!/usr/bin/python
# vim: fileencoding=utf-8
# see http://stackoverflow.com/questions/728891/correct-way-to-define-python-source-code-encoding

import os, sys, time, signal, tempfile, socket, posix, time
import re, shutil, pexpect, logging, pprint
import random, copy, glob, traceback


# Don't make that much sense - function/line is write().
# Would have to use traceback.extract_stack() manually.
#   %(funcName)10.10s:%(lineno)3d  %(levelname)8s 
# The second ":" is to get correct syntax highlightning,
# eg. messages with ERROR etc. are red in vim.
default_log_format = '%(asctime)s: : %(message)s'
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


# {{{ dictionary plus second hash
class dict_plus(dict):
    def __init__(self):
        self.aux = dict()

#    def aux(self):
#        return self.aux
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
    running = False

    gdb = None
    booth = None
    prompt = "CUSTOM-GDB-PROMPT-%d-%d" % (os.getpid(), time.time())

    dont_log_expect = 0
    current_nr = None

    udp_sock = None

    # http://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
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


    def read_test_input(self, file, state=None, m = dict()):
        fo = open(file, "r")
        state = None
        line_nr = 0
        for line in fo.readlines():
            line_nr += 1

            # comment?
            if re.match(r"^\s*#", line):
                continue
            # empty line
            if re.match(r"^\s*$", line):
                continue

            # message resp. ticket
            # We allow a comment to have something to write out to screen
            res = re.match(r"^\s*(\w+)\s*:(?:\s*(#.*?\S))?\s*$", line)
            if res:
                state = res.group(1)
                if not m.has_key(state):
                    m[state] = dict_plus()
                if res.group(2):
                    m[state].aux["comment"] = res.group(2)
                m[state].aux["line"] = line_nr
                continue

            assert(state)

            res = re.match(r"^\s*(\S+)\s*(.*)\s*$", line)
            if res:
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


    def running_on_console(self):
        return sys.stdout.isatty()


    def colored_string(self, stg, color):
        if self.running_on_console():
            return  "\033[%dm%s\033[0m" % (30+color, stg)
        return stg


    # We want shorthand in descriptions, ie. "state"
    # instead of "booth_conf->ticket[0].state".
    def translate_shorthand(self, name, context):
        if context == 'ticket':
            return "booth_conf->ticket[0]." + name
        if context == 'message':
            return "msg->" + name
        if context == 'inject':
            return "ntohl(((struct boothc_ticket_msg *)buf)->" + name + ")"
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


    def start_a_process(self, bin, env_add=[], **args):
        name = re.sub(r".*/", "", bin)
        # How to get stderr, too?
        expct = pexpect.spawn(bin,
                env = dict( os.environ.items() +
                    [('PATH',
                        self.test_base + "/bin/:" +
                        os.getenv('PATH')),
                    ('UNIT_TEST_PATH', self.test_base),
                    ('LC_ALL', 'C'),
                    ('LANG', 'C')] +
                    env_add ),
                timeout = 30,
                maxread = 32768,
                **args)
        expct.setecho(False)
        expct.logfile_read = expect_logging("<-  %s" % name, self)
        expct.logfile_send = expect_logging(" -> %s" % name, self)
        return expct


    def start_processes(self, test):
        self.booth = self.start_a_process(self.binary,
                args = [ "daemon", "-D",
                    "-c", self.test_base + "/booth.conf",
                    "-s", "127.0.0.1",
                    "-l", self.lockfile, 
                    ],
                env_add=[ ('UNIT_TEST', test),
                    ('UNIT_TEST_FILE', os.path.realpath(test)),
                    # provide some space, so that strcpy(getenv()) works
                    ('UNIT_TEST_AUX', "".zfill(1024)),
                    ]);

        logging.info("started booth with PID %d, lockfile %s" % (self.booth.pid, self.lockfile))
        self.booth.expect("BOOTH site daemon is starting", timeout=2)
        #print self.booth.before; exit

        self.gdb = self.start_a_process("gdb",
                args=["-quiet",
                    "-p", str(self.booth.pid),
                    "-nx", "-nh",   # don't use .gdbinit
                    ])
        logging.info("started GDB with PID %d" % self.gdb.pid)
        self.gdb.expect("(gdb)")
        self.gdb.sendline("set pagination off\n")
        self.gdb.sendline("set interactive-mode off\n")
        self.gdb.sendline("set verbose off\n") ## sadly to late for the initial "symbol not found" messages
        self.gdb.sendline("set prompt " + self.prompt + "\\n\n");
        self.sync(2000)
        #os.system("strace -o /tmp/sfdgs -f -tt -s 2000 -p %d &" % self.gdb.pid)

        self.this_site_id = self.query_value("local->site_id")
        self.this_port = int(self.query_value("booth_conf->port"))

        # do a self-test
        assert(self.check_value("local->site_id", self.this_site_id))
        
        # Now we're set up.
        self.send_cmd("break ticket_cron")
        self.send_cmd("break booth_udp_send if to == &(booth_conf->site[1])")
        self.send_cmd("break recvfrom")

        self.running = False
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

    def drain_booth_log(self):
        try:
            self.booth.read_nonblocking(64*1024, 0)
        except pexpect.TIMEOUT:
            pass
        finally:
            pass

    def send_cmd(self, stg, timeout=-1):
        # give booth a chance to get its messages out
        self.drain_booth_log()

        self.gdb.sendline(stg)
        return self.sync(timeout=timeout)

    def _query_value(self, which):
        val = self.send_cmd("print " + which)
        cleaned = re.search(r"^\$\d+ = (.*\S)\s*$", val, re.MULTILINE)
        if not cleaned:
            self.user_debug("query failed")
        return cleaned.group(1)

    def query_value(self, which):
        res = self._query_value(which)
        logging.debug("query_value: «%s» evaluates to «%s»" % (which, res))
        return res

    def check_value(self, which, value):
        val = self._query_value("(" + which + ") == (" + value + ")")
        logging.debug("check_value: «%s» is «%s»: %s" % (which, value, val))
        if val == "1":
            return True
        # for easier (test) debugging we'll show the _real_ value, too.
        want = self._query_value(value)
        # Order is important, so that next query works!!
        has = self._query_value(which)
        # for informational purposes
        self._query_value('state_to_string($$)')
        logging.error("«%s»: got «%s», expected «%s». ERROR." % (which, has, want))
        return False

    # Send data to GDB, to inject them into the binary.
    # Handles different data types
    def set_val(self, name, value, numeric_conv=None):
        logging.debug("setting value «%s» to «%s» (num_conv %s)" %(name, value, numeric_conv))
        res = None
        # string value?
        if re.match(r'^"', value):
            res = self.send_cmd("print strcpy(" + name + ", " + value + ")")
        # numeric
        elif numeric_conv:
            res = self.send_cmd("set variable " + name + " = " + numeric_conv + "(" + value + ")")
        else:
            res = self.send_cmd("set variable " + name + " = " + value)
        for r in [r"There is no member named",
                r"Structure has no component named",
                r"No symbol .* in current context", ]:
            assert(not re.search(r, res, re.MULTILINE))
        logging.debug("set_val %s done" % name)
# }}} GDB communication


    # there has to be some event waiting, so that boothd stops again.
    def continue_debuggee(self, timeout=30):
        res = None
        if not self.running:
            res = self.send_cmd("continue", timeout)
        self.drain_booth_log()
        return res


# {{{ High-level functions.
# Generally, GDB is attached to BOOTHD, and has it stopped.
    def set_state(self, kv):
        if not kv:
            return

        self.current_nr = kv.aux.get("line")
        #os.system("strace -f -tt -s 2000 -e write -p" + str(self.gdb.pid) + " &")
        for n, v in kv.iteritems():
            self.set_val( self.translate_shorthand(n, "ticket"), v)
        logging.info("set state")


    def user_debug(self, txt):
        logging.error("Problem detected: %s", txt)
        logging.info(self.gdb.buffer)
        if not sys.stdin.isatty():
            logging.error("Not a terminal, stopping.")
        else:
            print "\n\nEntering interactive mode.\n\n"
            self.gdb.sendline("set prompt GDB> \n")
            self.gdb.setecho(True)
            # can't use send_cmd, doesn't reply with expected prompt anymore.
            self.gdb.interact()
            #while True:
            #    sys.stdout.write("GDB> ")
            #    sys.stdout.flush()
            #    x = sys.stdin.readline()
            #    if not x:
            #        break
            #    self.send_cmd(x)
        self.stop_processes()
        sys.exit(1)
 

    def wait_for_function(self, fn, timeout=20):
        until = time.time() + timeout
        while True:
            stopped_at = self.continue_debuggee(timeout=3)
            if not stopped_at:
                self.user_debug("Not stopped at any breakpoint?")
            if re.search(r"^Program received signal SIGSEGV,", stopped_at, re.MULTILINE):
                self.user_debug("Segfault")
            if re.search(r"^Breakpoint \d+, (0x\w+ in )?%s " % fn, stopped_at, re.MULTILINE):
                break
            if time.time() > until:
                self.user_debug("Didn't stop in function %s" % fn)
        logging.info("Now in %s" % fn)

    # We break, change the data, and return the correct size.
    def send_message(self, msg):
        self.udp_sock.sendto('a', (socket.gethostbyname(self.this_site), self.this_port))

        self.wait_for_function("recvfrom")
        # drain input, but stop afterwards for changing data
        self.send_cmd("finish")
        # step over length assignment
        self.send_cmd("next")
        
        # push message.
        for (n, v) in msg.iteritems():
            self.set_val( self.translate_shorthand(n, "message"), v, "htonl")

        # set "received" length
        self.set_val("rv", "msg->header.length", "ntohl")

        # the next thing should run continue via wait_for_function
 
    def wait_outgoing(self, msg):
        self.wait_for_function("booth_udp_send")
        ok = True
        for (n, v) in msg.iteritems():
            if re.search(r"\.", n):
                ok = self.check_value( self.translate_shorthand(n, "inject"), v) and ok
            else:
                ok = self.check_value( self.translate_shorthand(n, "ticket"), v) and ok

        if not ok:
            sys.exit(1)
        logging.info("out gone")
        #stopped_at = self.sync() 

    def merge_dicts(self, base, overlay):
        return dict(base.items() + overlay.items())
       

    def loop(self, fn, data):
        matches = map(lambda k: re.match(r"^(outgoing|message)(\d+)$", k), data.iterkeys())
        valid_matches = filter(None, matches)
        nums = map(lambda m: int(m.group(2)), valid_matches)
        loop_max = max(nums)
        for counter in range(0, loop_max+1):    # incl. last message

            kmsg = 'message%d' % counter
            msg  = data.get(kmsg)

            ktkt = 'ticket%d' % counter
            tkt  = data.get(ktkt)

            kout = 'outgoing%d' % counter
            out  = data.get(kout)

            kgdb = 'gdb%d' % counter
            gdb  = data.get(kgdb)


            if not any([msg, out, tkt]):
                continue

            logging.info("Part %d" % counter)
            if tkt:
                self.current_nr = tkt.aux.get("line")
                comment = tkt.aux.get("comment", "")
                logging.info("ticket change %s  (%s:%d)  %s" % (ktkt, fn, self.current_nr, comment))
                self.set_state(tkt)
            if msg:
                self.current_nr = msg.aux.get("line")
                comment = msg.aux.get("comment", "")
                logging.info("sending %s  (%s:%d)  %s" % (kmsg, fn, self.current_nr, comment))
                self.send_message(self.merge_dicts(data["message"], msg))
            if gdb:
                for (k, v) in gdb.iteritems():
                    self.send_cmd(k + " " + v.replace("§", "\n"))
            if data.has_key(kgdb) and len(gdb) == 0:
                self.user_debug("manual override")
            if out:
                self.current_nr = out.aux.get("line")
                comment = out.aux.get("comment", "")
                logging.info("waiting for %s  (%s:%d)  %s" % (kout, fn, self.current_nr, comment))
                self.wait_outgoing(out)
        logging.info("loop ends")


    def let_booth_go_a_bit(self):
        self.drain_booth_log()
        logging.debug("running: %d" % self.running)

        if not self.running:
            self.gdb.sendline("continue")
        time.sleep(1)
        self.drain_booth_log()
        # stop it
        posix.kill(self.booth.pid, signal.SIGINT)
        posix.kill(self.gdb.pid, signal.SIGINT)
        self.running = False
        self.sync(2000)


    def do_finally(self, data):
        if not data:
            return

        self.current_nr = data.aux.get("line")
        # Allow debuggee to reach a stable state
        self.let_booth_go_a_bit()

        ok = True
        for (n, v) in data.iteritems():
            ok = self.check_value( self.translate_shorthand(n, "ticket"), v) and ok
        if not ok:
            sys.exit(1)
        

    def run(self, start_from="000"):
        os.chdir(self.test_base)
        # TODO: sorted, random order
        tests = filter( (lambda f: re.match(r"^\d\d\d_.*\.txt$", f)), glob.glob("*"))
        tests.sort()
        for f in tests:
            if f < start_from:
                continue
            log = None
            logfn = UT._filename(f)
            if self.running_on_console():
                sys.stdout.write("\n")
            try:
                log = self.setup_log(filename = logfn)

                log.setLevel(logging.DEBUG)
                logging.error(self.colored_string("Starting test '%s'" % f, self.BLUE) + ", logfile " + logfn)
                self.start_processes(f)

                test = self.read_test_input(f, m=copy.deepcopy(self.defaults))
                logging.debug("data: %s" % pprint.pformat(test, width = 200))

                self.set_state(test.get("ticket"))
                self.loop(f, test)
                self.do_finally(test.get("finally"))

                self.current_nr = None
                logging.warn(self.colored_string("Finished test '%s' - OK" % f, self.GREEN))
            except:
                logging.error(self.colored_string("Broke in %s:%d %s" % (f, self.current_nr, sys.exc_info()), self.RED))
                for frame in traceback.format_tb(sys.exc_traceback):
                    logging.info("  -  %s " % frame.rstrip())
            finally:
                self.stop_processes()
                if log:
                    log.close()
                    logging.getLogger("").removeHandler(log)
        if self.running_on_console():
            sys.stdout.write("\n")
        return
# }}}


#def traceit(frame, event, arg):
#     if event == "line":
#         lineno = frame.f_lineno
#         print frame.f_code.co_filename, ":", "line", lineno
#     return traceit


# {{{ main 
if __name__ == '__main__':
    if os.geteuid() == 0:
        sys.stderr.write("Must be run non-root; aborting.\n")
        sys.exit(1)


    ut = UT(sys.argv[1], sys.argv[2] + "/")

    # "master" log object needs max level
    logging.basicConfig(level = logging.DEBUG,
            filename = "/dev/null",
            filemode = "a",
            format = default_log_format,
            datefmt = default_log_datefmt)


    # make sure no old processes are active anymore
    os.system("killall boothd > /dev/null 2> /dev/null")

    overview_log = ut.setup_log( filename = UT._filename('seq') )
    overview_log.setLevel(logging.WARN)

    # http://stackoverflow.com/questions/9321741/printing-to-screen-and-writing-to-a-file-at-the-same-time
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(' #  %(message)s'))
    console.setLevel(logging.WARN)
    logging.getLogger('').addHandler(console)

 
    logging.info("Starting boothd unit tests.")

    #sys.settrace(traceit)

    starting = "0"
    if len(sys.argv) > 3:
        starting = sys.argv[3]
    ret = ut.run(starting)
    sys.exit(ret)
# }}}
