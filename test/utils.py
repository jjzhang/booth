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
    # in case multiple IP addresses are returned, use only the first
    # and also strip '%<device>' part possibly present with IPv6 address
    ret = re.sub(r'\s.*', '', stdout)
    return "::1" if '%' in ret else ret
