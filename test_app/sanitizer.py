import shlex
import subprocess


def unsafe_func(cmd):
    # This should MATCH
    subprocess.call(cmd, shell=True)


def safe_func(cmd):
    # This should NOT MATCH because of shlex.quote sanitizer
    safe_cmd = shlex.quote(cmd)
    subprocess.call(safe_cmd, shell=True)
