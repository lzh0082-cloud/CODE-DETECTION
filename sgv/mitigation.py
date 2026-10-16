"""Compare note presentations (plain / quote / alarms) on the same functions.

    python -m sgv.mitigation results/evidence_full_a results/mitig_quote results/mitig_alarms --model flash

For every condition: accuracy per presentation on the functions all presentations share, with a paired
McNemar test against `plain`. The key quantity is the deference gap: accuracy under C4 (false reassurance)
minus accuracy under C2 (true facts about the same operations) on vulnerable versions. A mitigation works
if it shrinks that gap without lowering accuracy under the true-evidence conditions C1/C2.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .deference import disputes
from .stats import bootstrap_diff, mcnemar_exact

ROWS = [("C1", None, "all true notes, both versions"), ("C2", None, "patch-relevant true notes, both versions"),
        ("C2", 1, "patch-relevant true notes, vulnerable versions"), ("C4", 1, "false reassurance, vulnerable"),
        ("C2", 0, "patch-relevant true notes, patched versions"), ("C5", 0, "false alarm, patched")]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dirs", nargs="+")
    ap.add_argument("--model", default="flash")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    R = {}
    for d in args.run_dirs:
        with open(os.path.join(d, "records.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                if r["model"] == args.model and not r.get("error"):  # API failures are missing data
                    R[(r.get("presentation", "plain"), r["condition"], r["pair_id"], r["target"])] = r
    pres = [p for p in ("plain", "quote", "alarms", "reframe", "provenance", "verify", "verify-show", "commit",
                        "commit-verify") if any(k[0] == p for k in R)]

    print(f"model {args.model}; presentations {pres}\n")
    print("| condition | n | " + " | ".join(f"acc {p}" for p in pres) + " | " +
          " | ".join(f"{p} vs plain: lost/gained, p, diff (95% CI)" for p in pres[1:]) + " |")
    print("|---|---|" + "---|" * len(pres) + "---|" * (len(pres) - 1))
    for cond, target, label in ROWS:
        keys = sorted({(k[2], k[3]) for k in R if k[1] == cond and (target is None or k[3] == target)})
        keys = [k for k in keys if all((p, cond) + k in R for p in pres)]
        if not keys:
            continue
        acc = {p: [bool(R[(p, cond) + k]["correct"]) for k in keys] for p in pres}
        cells = [f"{sum(acc[p]) / len(keys):.2f}" for p in pres]
        tests = []
        for p in pres[1:]:
            lost = sum(1 for a, b in zip(acc["plain"], acc[p]) if a and not b)
            gained = sum(1 for a, b in zip(acc["plain"], acc[p]) if b and not a)
            lo, hi = bootstrap_diff(acc["plain"], acc[p])
            tests.append(f"{lost}/{gained}, p={mcnemar_exact(lost, gained):.3f}, "
                         f"{(sum(acc[p]) - sum(acc['plain'])) / len(keys):+.2f} ({lo:+.2f}, {hi:+.2f})")
        print(f"| {cond} {label} | {len(keys)} | " + " | ".join(cells) + " | " + " | ".join(tests) + " |")

    # Primary test, decided before the results: does the mitigation raise C4 accuracy on vulnerable versions
    # relative to `plain` on the same functions? Holm-corrected over all mitigations tried.
    primary = []
    keys = sorted({(k[2], k[3]) for k in R if k[1] == "C4" and k[3] == 1})
    for p in pres[1:]:
        common = [k for k in keys if ("plain", "C4") + k in R and (p, "C4") + k in R]
        if not common:
            continue
        lost = sum(1 for k in common if R[("plain", "C4") + k]["correct"] and not R[(p, "C4") + k]["correct"])
        gained = sum(1 for k in common if R[(p, "C4") + k]["correct"] and not R[("plain", "C4") + k]["correct"])
        primary.append((p, len(common), lost, gained, mcnemar_exact(lost, gained)))
    if primary:
        print("\nPrimary test: C4 accuracy vs plain on vulnerable versions, Holm-corrected:")
        ordered = sorted(primary, key=lambda x: x[4])
        running = 0.0
        for rank, (p, n, lost, gained, pv) in enumerate(ordered):
            running = max(running, min(1.0, pv * (len(ordered) - rank)))
            print(f"  {p:11s} n={n} lost/gained {lost}/{gained}  p={pv:.4f}  Holm-adjusted p={running:.4f}")

    print("\nDeference gap on vulnerable versions (C4 accuracy - C2 accuracy, same functions):")
    for p in pres:
        keys = [(pid, 1) for (pp, c, pid, t) in R if pp == p and c == "C4" and t == 1 and (p, "C2", pid, 1) in R]
        if not keys:
            continue
        c4 = [bool(R[(p, "C4") + k]["correct"]) for k in keys]
        c2 = [bool(R[(p, "C2") + k]["correct"]) for k in keys]
        b = sum(1 for x, y in zip(c2, c4) if x and not y)
        g = sum(1 for x, y in zip(c2, c4) if y and not x)
        lo, hi = bootstrap_diff(c2, c4)
        dispute = sum(disputes(R[(p, "C4") + k]["reasoning"]) for k in keys)
        print(f"  {p:7s} n={len(keys)}  C2 {sum(c2) / len(keys):.2f} -> C4 {sum(c4) / len(keys):.2f}  "
              f"gap {(sum(c4) - sum(c2)) / len(keys):+.2f} ({lo:+.2f}, {hi:+.2f}), McNemar p={mcnemar_exact(b, g):.3f}; "
              f"lexical dispute cue in C4 answers {dispute}/{len(keys)}")


if __name__ == "__main__":
    main()
