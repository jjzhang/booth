#!/usr/bin/python

import os
import subprocess
import time
import unittest

class BoothRunner:
    default_config_file = '/etc/booth/booth.conf'
    default_lock_file   = '/var/run/booth.pid'

    def __init__(self, boothd_path, mode, args):
        self.boothd_path = boothd_path
        self.args        = [ mode ]
        self.final_args  = args # will be appended to self.args
        self.mode        = mode
        self.config_file = None
        self.lock_file   = None

    def set_config_file_arg(self):
        self.args += [ '-c', self.config_file ]

    def set_config_file(self, config_file):
        self.config_file = config_file
        self.set_config_file_arg()

    def set_lock_file(self, lock_file):
        self.lock_file = lock_file
        self.args += [ '-l', self.lock_file ]

    def set_debug(self):
        self.args += [ '-D' ]

    def all_args(self):
        return [ self.boothd_path ] + self.args + self.final_args

    def show_output(self, stdout, stderr):
        if stdout:
            print "STDOUT:"
            print "------"
            print stdout,
        if stderr:
            print "STDERR: (N.B. crm_ticket failures indicate daemon started correctly)"
            print "------"
            print stderr,
        print "-" * 70

    def subproc_completed_within(self, p, timeout):
        start = time.time()
        wait = 0.1
        while True:
            if p.poll() is not None:
                return True
            elapsed = time.time() - start
            if elapsed + wait > timeout:
                wait = timeout - elapsed
            print "Waiting on %d for %.1fs ..." % (p.pid, wait)
            time.sleep(wait)
            elapsed = time.time() - start
            if elapsed >= timeout:
                return False
            wait *= 2

    def lock_file_used(self):
        return self.lock_file or self.default_lock_file

    def config_file_used(self):
        return self.config_file or self.default_config_file

    def config_text_used(self):
        config_file = self.config_file_used()
        try:
            c = open(config_file)
        except:
            return None
        text = "".join(c.readlines())
        c.close()

        text = text.replace('\t', '<TAB>')
        text = text.replace('\n', '|\n')

        return text

    def show_args(self):
        print "\n"
        print "-" * 70
        print "Running", ' '.join(self.all_args())
        msg = "with config from %s" % self.config_file_used()
        config_text = self.config_text_used()
        if config_text is not None:
            msg += ": [%s]" % config_text
        print msg

    def run(self):
        p = subprocess.Popen(self.all_args(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not p:
            raise RuntimeError, "failed to start subprocess"

        print "Started subprocess pid %d" % p.pid

        completed = self.subproc_completed_within(p, 2)

        if completed:
            (stdout, stderr) = p.communicate()
            self.show_output(stdout, stderr)
            return (p.pid, p.returncode, stdout, stderr)

        return (p.pid, None, None, None)
