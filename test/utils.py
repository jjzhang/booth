#!/usr/bin/python

import subprocess
import re

def run_cmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = p.communicate()
    return (stdout, stderr, p.returncode)

def get_IP():
    (stdout, stderr, returncode) = run_cmd(['hostname', '-i'])
    if returncode != 0:
        raise RuntimeError, "Failed to run hostname -i:\n" + stderr
    # in case multiple IP addresses are returned, use only the first.
    return re.sub(r'\s.*', '', stdout)
