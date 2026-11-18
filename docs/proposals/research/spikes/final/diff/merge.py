"""Merges results/final/*.json into results/final/summary.md: one table per
mode and grammar, one row per cause, one column per pair (≈ lines)."""
import collections, glob, json, os

here = os.path.dirname(os.path.abspath(__file__))
out = []
for mode in ("run", "tab"):
    for g in ("delivered", "fixed"):
        files = sorted(glob.glob(f"{here}/results/final/{mode}-{g}*.json"))
        if not files:
            continue
        pat, comp, dif, sev, shr = (collections.Counter() for _ in range(5))
        rows = {}
        for f in files:
            d = json.load(open(f))
            for k, c in (("patterns", pat), ("compared", comp), ("differ", dif), ("severity", sev), ("shrunk", shr)):
                c.update(d[k])
            for b in d["buckets"]:
                r = rows.setdefault(b["Cause"], {"est": collections.Counter(), "shr": collections.Counter(), "ex": None})
                r["est"][b["Pair"]] += b["Est"]
                r["shr"][b["Pair"]] += b["Shrunk"]
                ex = " ".join(b["Example"])
                if r["ex"] is None or len(ex) < len(r["ex"][0]):
                    r["ex"] = (ex, b["Pair"], b["Outcomes"])
        pairs = sorted(comp)
        out.append(f"## {mode} / {g}: {len(files)} file(s)\n")
        out.append("| pattern | lines |\n| --- | --- |")
        for k, v in sorted(pat.items()):
            out.append(f"| {k} | {v} |")
        out.append("\n| pair | compared | differ | semantic | acceptance | report | shrunk |\n| --- | --- | --- | --- | --- | --- | --- |")
        for p in pairs:
            out.append(f"| {p} | {comp[p]} | {dif[p]} | {sev[p+'|semantic']} | {sev[p+'|acceptance']} | {sev[p+'|report']} | {shr[p]} |")
        out.append("\n| cause | " + " | ".join(pairs) + " | smallest |\n| --- | " + " --- |" * (len(pairs) + 1))
        for cause, r in sorted(rows.items(), key=lambda kv: -sum(kv[1]["est"].values())):
            cells = " | ".join(f"{r['est'][p]:.0f} ({r['shr'][p]})" if r["shr"][p] else "" for p in pairs)
            ex, p, o = r["ex"]
            out.append(f"| {cause.replace('|', '\\|')} | {cells} | `{ex[:60]}` ({p}: `{o[0][:50]}` / `{o[1][:50]}`) |")
        out.append("")
open(f"{here}/results/final/summary.md", "w").write("\n".join(out))
print("\n".join(out))
