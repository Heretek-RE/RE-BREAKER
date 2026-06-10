"""re_vm_spawn_ida.py — launch idalib-mcp in the guest, fully detached."""
import os
import subprocess
import sys

UV = r"C:\Users\john\AppData\Local\Programs\Python\Python312\Scripts\uv.exe"
LOG = r"C:\re-mcps\idalib-mcp.log"
WORKDIR = r"C:\re-mcps\ida-pro-mcp"
PATH_EXT = r"C:\Users\john\AppData\Local\Programs\Python\Python312\Scripts;"

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB

# Use cmd /c to set PATH then run uv, redirect to LOG
cmd = ["cmd", "/c",
       f"set PATH={PATH_EXT}%PATH% && "
       f"cd /d {WORKDIR} && "
       f"\"{UV}\" run idalib-mcp --host 127.0.0.1 --port 8744 "
       f"> {LOG} 2>&1"]

env = os.environ.copy()
env["PATH"] = PATH_EXT + env.get("PATH", "")

# Use cmd.exe directly so the PATH set + redirection work
p = subprocess.Popen(
    ["cmd.exe", "/c"] + cmd[2:],
    stdin=subprocess.DEVNULL,
    stdout=open(LOG, "wb"),
    stderr=subprocess.STDOUT,
    cwd=WORKDIR,
    env=env,
    close_fds=True,
    creationflags=flags,
)
print(f"started: pid={p.pid}")
