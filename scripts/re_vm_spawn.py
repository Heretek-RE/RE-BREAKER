"""re_vm_spawn.py — launch a Windows-side process fully-detached.

Written to be run via SSH. Launches `cmd /c <args>` as a process with
DETACHED_PROCESS + CREATE_NEW_PROCESS_GROUP flags (0x00000008 | 0x00000200 = 0x208).
The Python script exits immediately after spawning, leaving the child
process to run independently of the SSH session.

Usage:
    python re_vm_spawn.py <command-line>
"""
import subprocess
import sys

if len(sys.argv) < 2:
    print("usage: re_vm_spawn.py <cmd> <args...>", file=sys.stderr)
    sys.exit(2)

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB

cmd = sys.argv[1:]
p = subprocess.Popen(
    cmd,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
    creationflags=flags,
)
print(p.pid)
