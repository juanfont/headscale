"""Build the line x shell x candidate table from out/.

usage: python3 -I summarize.py OUTDIR SET   (SET is "" for delivered, "-fix" for fixed)

Cell legend:
  word␣      Tab completed the word and added a space
  word       Tab completed the word, no space
  {a b}      Tab listed these candidates (bash/zsh screen; fish/pwsh candidate list)
  files      the shell offered the files of the test directory (other.json policy.hujson)
  ∅          nothing
  ERR        the shell printed an error
zsh removes its own auto-inserted space when the driver presses Ctrl-A, so for
zsh the space is read from the echo of the line instead of the final buffer.
"""

import re
import sys

cands = ["cobra", "urfave", "kong", "creachadair", "own-grammar", "own-pflag"]
outdir, tag = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
FILES = {"other.json", "policy.hujson", "./other.json", "./policy.hujson"}


def pty_blocks(path):
    out, cur = {}, {}
    for l in open(path, errors="replace"):
        l = l.rstrip("\n")
        if l.startswith("LINE: "):
            cur = {"line": l[6:]}
        elif l.startswith("LISTED: "):
            cur["listed"] = l[8:]
        elif l.startswith("FINAL: "):
            cur["final"] = l[7:]
            out[cur["line"]] = cur
    return out


def list_blocks(path):
    out, line = {}, None
    for l in open(path, errors="replace"):
        l = l.rstrip("\n")
        if l.startswith("LINE: "):
            line = l[6:]
            out[line] = []
        elif line is not None:
            out[line].append(l[2:] if l.startswith("  ") else l)
    return out


def fmt_list(words):
    words = [w for w in words if w]
    if set(words) and set(words) <= FILES:
        return "files"
    if len(words) > 4:
        return "{" + " ".join(words[:3]) + f" …{len(words)}}}"
    return "{" + " ".join(words) + "}"


def pty_cell(shell, b):
    line, listed, final = b["line"], b.get("listed", ""), b.get("final", "")
    m = re.match(r"^\[(.*)\]$", final)
    if not m:
        return "??"
    buf = m.group(1)
    if "unknown option" in listed or "string split" in listed:
        return "ERR"
    if shell == "zsh" and buf == line.rstrip() and line.endswith(" "):
        buf = line
    if shell == "zsh" and not buf.endswith(" "):
        first = listed.split(" / ")[0].replace("<BEL>", "")
        if first.endswith(buf + " "):
            buf += " "
    ins = buf[len(line):] if buf.startswith(line) else None
    parts = listed.split(" / ")
    lst = fmt_list(parts[1].split()) if len(parts) >= 3 else ""
    word = ""
    if ins:
        last = buf.rstrip(" ").split(" ")[-1]
        word = last + ("␣" if buf.endswith(" ") else "")
    elif ins is None:
        word = "~" + buf.rstrip(" ").split(" ")[-1] + ("␣" if buf.endswith(" ") else "")
    s = (word + " " + lst).strip()
    return s or "∅"


def fish_cell(fishlist, b):
    words = fishlist
    if any("unknown option" in w or "string split" in w for w in words):
        return "ERR"
    words = [w.split("\t")[0] for w in words if w.strip()]
    pty = pty_cell("fish", b) if b else ""
    if len(words) == 1 or (len(words) == 2 and words[1] == words[0] + "."):
        return pty if pty not in ("∅", "??") else words[0]
    if not words:
        return "∅"
    return fmt_list(words)


def pwsh_cell(lines):
    txt = " ".join(lines)
    if "THROWS" in txt:
        return "THROWS"
    words = re.findall(r"\[([^\]]*)\]", txt)
    words = [w.rstrip() + ("␣" if w.endswith(" ") and w.strip() and len(w.rstrip()) + 1 == len(w) else "") for w in words]
    words = [w for w in words if w.strip()]
    if not words:
        return "∅"
    if len(words) == 1:
        return words[0]
    return fmt_list([w.rstrip("␣") for w in words])


data = {}
for c in cands:
    for sh in ("bash", "zsh", "fish"):
        try:
            for line, b in pty_blocks(f"{outdir}/pty{tag}-{c}-{sh}.txt").items():
                data.setdefault(line, {})[(c, sh + "-pty")] = b
        except FileNotFoundError:
            pass
    for line, ws in list_blocks(f"{outdir}/fishc{tag}-{c}.txt").items():
        data.setdefault(line, {})[(c, "fishc")] = ws
    for line, ws in list_blocks(f"{outdir}/pwsh{tag}-{c}.txt").items():
        data.setdefault(line, {})[(c, "pwsh")] = ws

print("| Line + Tab | Shell | " + " | ".join(cands) + " |")
print("| --- | --- |" + " --- |" * len(cands))
for line, d in data.items():
    for sh in ("bash", "zsh", "fish", "pwsh"):
        cells = []
        for c in cands:
            if sh in ("bash", "zsh"):
                b = d.get((c, sh + "-pty"))
                cells.append(pty_cell(sh, b) if b else "-")
            elif sh == "fish":
                cells.append(fish_cell(d.get((c, "fishc"), []), d.get((c, "fish-pty"))))
            else:
                cells.append(pwsh_cell(d.get((c, "pwsh"), [])))
        shown = "`" + line + "`" if sh == "bash" else ""
        print(f"| {shown} | {sh} | " + " | ".join("`" + x + "`" for x in cells) + " |")
