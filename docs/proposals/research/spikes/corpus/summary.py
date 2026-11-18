#!/usr/bin/env python3
"""Counts for edge-corpus.md: inventory IN/OUT by reason, and per adapter the
verdicts of results.tsv (written by `go run . -tsv results.tsv cases/*.jsonl`)
split by what `why` says. Run: python3 -I summary.py <corpus dir>"""
import collections, csv, glob, json, os, sys

d = sys.argv[1]
inv = collections.Counter()
reasons = collections.Counter()
per_src = collections.defaultdict(collections.Counter)
for p in sorted(glob.glob(os.path.join(d, "inventory", "*.tsv"))):
    src = os.path.basename(p)[:-4]
    for r in csv.DictReader(open(p), delimiter="\t"):
        v = r["verdict"].strip()
        inv[v] += 1
        per_src[src][v] += 1
        if v == "OUT":
            reason = r["reason"].strip()
            reasons[reason.split(":")[0] if reason.startswith("other") else reason] += 1
print("## inventory")
print(f"rows {sum(inv.values())}: IN {inv['IN']}, OUT {inv['OUT']}")
for s, c in per_src.items():
    print(f"  {s:10} IN {c['IN']:4}  OUT {c['OUT']:4}")
print("OUT by reason:")
for r, n in reasons.most_common():
    print(f"  {n:4}  {r}")
other = collections.Counter()
for p in sorted(glob.glob(os.path.join(d, "inventory", "*.tsv"))):
    for r in csv.DictReader(open(p), delimiter="\t"):
        if r["verdict"].strip() == "OUT" and r["reason"].startswith("other"):
            other[r["reason"].strip()] += 1
for r, n in other.most_common():
    print(f"        {n:4}  {r}")

cases = {}
for p in sorted(glob.glob(os.path.join(d, "cases", "*.jsonl"))):
    for l in open(p):
        if l.strip():
            c = json.loads(l)
            cases[c["id"]] = c
print(f"\n## cases {len(cases)}: run {sum(c['kind'] == 'run' for c in cases.values())}, complete {sum(c['kind'] == 'complete' for c in cases.values())}")
by = collections.Counter(c["id"].split("-")[0] for c in cases.values())
print("  by source file:", dict(by))


def wcat(c):
    w = c.get("why", "")
    if not w:
        return "-"
    if w.startswith("quirk"):
        return "quirk"
    if w.startswith("undecided"):
        return "undecided"
    return "decided"


print("  cases with ours:", collections.Counter(wcat(c) for c in cases.values() if "ours" in c))
res = os.path.join(d, "results.tsv")
if os.path.exists(res):
    rows = list(csv.DictReader(open(res), delimiter="\t"))
    t = collections.defaultdict(collections.Counter)
    for r in rows:
        c = cases[r["id"]]
        v = r["verdict"]
        if v == "up" and "ours" in c:
            v = "up (" + wcat(c) + ")"
        if v == "ours":
            v = "ours (" + wcat(c) + ")"
        t[r["adapter"]][(r["kind"], v)] += 1
    print("\n## results by adapter (kind, verdict)")
    for a, cnt in t.items():
        print(a)
        for k in sorted(cnt):
            print(f"   {k[0]:8} {k[1]:22} {cnt[k]}")
