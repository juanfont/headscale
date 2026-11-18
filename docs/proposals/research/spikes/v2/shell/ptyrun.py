"""Drive one interactive shell in a pty through many lines: type the line,
press Tab once, record what the shell listed and the edited line.

usage: python3 -I ptyrun.py bash|zsh|fish LINESFILE
env:   SHELL_BIN, SETUP (shell code run once first)
Prints one block per line: LINE, LISTED (cleaned screen output), FINAL [buffer].
The buffer is printed by wrapping it in quotes and echoing it, so a trailing
space added by the completion is visible inside the brackets.
"""

import os
import pty
import re
import select
import sys
import time

shell, linesfile = sys.argv[1], sys.argv[2]
lines = [l.rstrip("\n") for l in open(linesfile) if l.strip() and not l.startswith("#")]
binp, setup = os.environ["SHELL_BIN"], os.environ["SETUP"]
argv = {
    "bash": [binp, "--norc", "--noprofile", "-i"],
    "zsh": [binp, "-f", "-i"],
    "fish": [binp, "--no-config", "-i"],
}[shell]
env = dict(os.environ, TERM="dumb", PS1="$ ", INPUTRC="/dev/null", COLUMNS="200", LINES="50")

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


ansi = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\r")
read(1.5)
send(setup + "\n")
read(3.0)
for line in lines:
    line = line.replace("\\t", "")
    send(line + "\t")
    listed = read(2.0)
    if shell == "fish":
        pre, post = "set X '", "'; printf '[%s]\\n' $X\n"
    else:
        pre, post = "X='", "'; printf '[%s]\\n' \"$X\"\n"
    send("\x01" + pre + "\x05" + post)
    final = read(1.0)
    m = re.findall(r"^\[.*\]$", ansi.sub("", final), re.M)
    print("LINE:", line)
    print("LISTED:", ansi.sub("", listed).replace("\x07", "<BEL>").replace("\n", " / "))
    print("FINAL:", m[-1] if m else "?? " + ansi.sub("", final).replace("\n", " / "))
    print()
    sys.stdout.flush()
os.kill(pid, 9)
