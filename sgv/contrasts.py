"""Per-version accuracies and the matched contrasts of an evidence run.

    python -m sgv.contrasts results/evidence_pilot_a [results/evidence_pilot_b ...]

* recall    = accuracy on vulnerable versions (verdict VULNERABLE)
* specificity = accuracy on patched versions (verdict SAFE)
Matched contrasts compare conditions on the *same* functions:
  C4 vs C2 on vulnerable versions: false reassurance vs the true facts about the same operations
  C5 vs C2 on patched versions:    false alarm vs the true facts about the same operations
  C2 vs C0 / C1 vs C0:             effect of (true) notes at all
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .stats import bootstrap_diff, mcnemar_exact

CONTRASTS = [("C1", "C0", None), ("C2", "C0", None), ("C3", "C0", None),
             ("C4", "C2", 1), ("C4", "C0", 1), ("C5", "C2", 0), ("C5", "C0", 0)]


def load(run_dirs: list[str]) -> list[dict]:
    recs = []
    for d in run_dirs:
        with open(os.path.join(d, "records.jsonl"), encoding="utf-8") as fh:
            recs += [json.loads(line) for line in fh]
    return [r for r in recs if not r.get("error")]  # API failures are missing data, not wrong answers


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dirs", nargs="+")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    recs = load(args.run_dirs)
    R = {(r["model"], r["condition"], r["pair_id"], r["target"]): r for r in recs}
    models = sorted({r["model"] for r in recs})

    print("Per-version accuracy (n): recall = vulnerable versions judged VULNERABLE, "
          "specificity = patched versions judged SAFE")
    print("| model | cond | recall (n) | specificity (n) | share judged VULNERABLE |")
    print("|---|---|---|---|---|")
    for m in models:
        for c in ("C0", "C1", "C2", "C3", "C4", "C5"):
            rows = [r for r in recs if r["model"] == m and r["condition"] == c]
            if not rows:
                continue
            vul = [r for r in rows if r["target"] == 1]
            pat = [r for r in rows if r["target"] == 0]
            rec = f"{sum(r['correct'] for r in vul) / len(vul):.2f} ({len(vul)})" if vul else "-"
            spe = f"{sum(r['correct'] for r in pat) / len(pat):.2f} ({len(pat)})" if pat else "-"
            share = sum(r["verdict"] == "VULNERABLE" for r in rows) / len(rows)
            print(f"| {m} | {c} | {rec} | {spe} | {share:.2f} |")

    print("\nMatched contrasts on the same functions (accuracy A vs B, B-only correct / A-only correct, McNemar p, "
          "bootstrap 95% CI of A-B):")
    print("| model | A vs B | versions | n | acc A | acc B | B-only / A-only | p | A-B (95% CI) |")
    print("|---|---|---|---|---|---|---|---|---|")
    for m in models:
        for a, b, target in CONTRASTS:
            keys = [(p, t) for (mm, c, p, t) in R if mm == m and c == a and (target is None or t == target)
                    and (m, b, p, t) in R]
            if not keys:
                continue
            xa = [bool(R[(m, a, p, t)]["correct"]) for p, t in keys]
            xb = [bool(R[(m, b, p, t)]["correct"]) for p, t in keys]
            b_only = sum(1 for u, v in zip(xa, xb) if v and not u)
            a_only = sum(1 for u, v in zip(xa, xb) if u and not v)
            lo, hi = bootstrap_diff(xb, xa)
            which = {None: "both", 1: "vulnerable", 0: "patched"}[target]
            print(f"| {m} | {a} vs {b} | {which} | {len(keys)} | {sum(xa) / len(keys):.2f} | {sum(xb) / len(keys):.2f} | "
                  f"{b_only} / {a_only} | {mcnemar_exact(b_only, a_only):.3f} | "
                  f"{(sum(xa) - sum(xb)) / len(keys):+.2f} ({lo:+.2f}, {hi:+.2f}) |")


if __name__ == "__main__":
    main()
