#!/usr/bin/python

import subprocess

def run_cmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = p.communicate()
    return (stdout, stderr, p.returncode)

def get_IP():
    (stdout, stderr, returncode) = run_cmd(['hostname', '-i'])
    if returncode != 0:
        raise RuntimeError, "Failed to run hostname -i:\n" + stderr
    return stdout.replace('\n', '')
