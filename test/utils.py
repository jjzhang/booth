import subprocess
import re
import sys

def run_cmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = p.communicate()
    return (stdout, stderr, p.returncode)

def get_IP():
    (stdout, stderr, returncode) = run_cmd(['hostname', '-i'])
    if returncode != 0:
        raise RuntimeError("Failed to run hostname -i:\n" + stderr)
    # in case multiple IP addresses are returned, use only the first
    # and also strip '%<device>' part possibly present with IPv6 address;
    # in Python 3 context, only expect ASCII/UTF-8 encodings for the
    # obtained input bytes
    ret = re.sub(r'\s.*', '',
                 stdout if sys.version_info[0] < 3 else str(stdout, 'UTF-8'))
    return "::1" if '%' in ret else ret
