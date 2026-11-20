"""Drive one interactive shell in a pseudo-terminal through many lines:
type the line, press Tab once, and record what the shell listed and the
edited line.

usage: python3 -I ptyrun.py bash|zsh|fish LINESFILE
env:   SHELL_BIN, SETUP (shell code run once first)

LINESFILE holds one line per row, ending in "|" where the cursor stands.
Prints one block per line: LINE, LISTED (the screen after Tab, cleaned),
FINAL (the edited line, echoed between brackets so that a space added by
the completion shows).
"""

import os
import pty
import re
import select
import sys
import time

shell, linesfile = sys.argv[1], sys.argv[2]
lines = [l.rstrip("\n")[:-1] for l in open(linesfile) if l.strip()]
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

ansi = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\r")
final = re.compile(r"^\[.*\]$", re.M)


def read(quiet, until=None, most=15.0):
    """Read until no byte came for quiet seconds, or until the cleaned
    output matches until; give up after most seconds."""
    out, end, last = b"", time.time() + most, time.time()
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                out += os.read(fd, 65536)
            except OSError:
                break
            last = time.time()
            if until and until.search(ansi.sub("", out.decode(errors="replace"))):
                break
        elif not until and time.time() - last > quiet:
            break
    return ansi.sub("", out.decode(errors="replace"))


def send(s):
    os.write(fd, s.encode())


read(1.5)
send(setup + "\n")
read(2.0)
for n, line in enumerate(lines):
    send(line + "\t")
    # The completion answers within the quiet time; the shell then waits.
    listed = read(1.5)
    if shell == "fish":
        pre, post = "set X '", "'; printf '[%s]\\n' $X\n"
    else:
        pre, post = "X='", "'; printf '[%s]\\n' \"$X\"\n"
    send("\x01" + pre + "\x05" + post)
    m = final.findall(read(0, until=final))
    # The prompt follows the printf; let it come before the next line.
    read(0.3)
    if n:
        print()
    print("LINE: " + line + "|")
    print("LISTED: [" + listed.replace("\x07", "<BEL>").replace("\n", " / ") + "]")
    print("FINAL: " + (m[-1] if m else "??"))
    sys.stdout.flush()
# A shell that died on the way leaves "??" above; fail too.
if os.waitpid(pid, os.WNOHANG) != (0, 0):
    sys.exit(shell + " exited before the last line")
os.kill(pid, 9)
