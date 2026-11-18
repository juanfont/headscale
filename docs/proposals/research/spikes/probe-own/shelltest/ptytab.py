"""Drive a real interactive shell in a pty: type a line, press Tab, report the
edited line and what the shell listed.

usage: python3 -I ptytab.py bash|zsh|fish LINE [TABS]
Needs SHELL_BIN, SETUP (shell code run first) in the environment.
"""

import os
import pty
import re
import select
import sys
import time

shell, line = sys.argv[1], sys.argv[2]
tabs = int(sys.argv[3]) if len(sys.argv) > 3 else 1
binp, setup = os.environ["SHELL_BIN"], os.environ["SETUP"]

argv = {
    "bash": [binp, "--norc", "--noprofile", "-i"],
    "zsh": [binp, "-f", "-i"],
    "fish": [binp, "--no-config", "-i"],
}[shell]
env = dict(os.environ, TERM="dumb", PS1="$ ", INPUTRC="/dev/null")

pid, fd = pty.fork()
if pid == 0:
    os.execve(argv[0], argv, env)


def read(t):
    out, end = b"", time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                out += os.read(fd, 65536)
            except OSError:
                break
    return out.decode(errors="replace")


def send(s):
    os.write(fd, s.encode())


read(1.0)
send(setup + "\n")
read(2.0)
send(line + "\t" * tabs)
listed = read(2.0)
# Wrap the edited buffer in a quote and print it, to see trailing spaces.
pre, post = ("set X '", "'; printf '[%s]\\n' $X\n") if shell == "fish" else ("X='", "'; printf '[%s]\\n' \"$X\"\n")
send("\x01" + pre + "\x05" + post)  # Ctrl-A, open quote, Ctrl-E, close, print
final = read(1.0)
os.kill(pid, 9)

ansi = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\r")
print("LISTED:", ansi.sub("", listed).replace("\x07", "<BEL>"))
print("FINAL:", ansi.sub("", final))
