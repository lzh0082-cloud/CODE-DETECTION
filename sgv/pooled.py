"""Post-hoc pooled analysis of deference (H2) across the three disjoint sets, and dataset descriptives.

    python -m sgv.pooled

Labelled post hoc in the paper: H2 was registered for the test set only. The three sets share no pair, so
pooling concatenates disjoint functions; the McNemar test and bootstrap CI are computed on the pooled pairs.
"""
from __future__ import annotations

import collections
import json
import os
import sys

from .stats import bootstrap_diff, mcnemar_exact

SETS = {"flash": [("study", "results/evidence_full_a"), ("held-out", "results/confirm_plain"),
                  ("test", "results/test_flash_plain")],
        "qwen-plus": [("study", "results/qwen_study_c245"), ("test", "results/test_qwen_plain")]}


def records(d: str) -> list[dict]:
    with open(os.path.join(d, "records.jsonl"), encoding="utf-8") as fh:
        return [r for r in map(json.loads, fh) if not r.get("error") and r.get("presentation", "plain") == "plain"]


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    for model, sets in SETS.items():
        c2_all, c4_all = [], []
        for name, d in sets:
            R = {(r["condition"], r["pair_id"], r["target"]): r for r in records(d) if r["model"] == model}
            keys = [(p, t) for (c, p, t) in R if c == "C4" and t == 1 and ("C2", p, t) in R]
            c2 = [bool(R[("C2", *k)]["correct"]) for k in keys]
            c4 = [bool(R[("C4", *k)]["correct"]) for k in keys]
            c2_all += [(name, x) for x in c2]
            c4_all += [(name, x) for x in c4]
            b = sum(x and not y for x, y in zip(c2, c4))
            g = sum(y and not x for x, y in zip(c2, c4))
            print(f"{model} {name}: n={len(keys)} C2 {sum(c2) / len(keys):.2f} -> C4 {sum(c4) / len(keys):.2f}, "
                  f"lost/gained {b}/{g}, p={mcnemar_exact(b, g):.3f}")
        x2 = [v for _, v in c2_all]
        x4 = [v for _, v in c4_all]
        b = sum(x and not y for x, y in zip(x2, x4))
        g = sum(y and not x for x, y in zip(x2, x4))
        lo, hi = bootstrap_diff(x2, x4)
        print(f"{model} POOLED (post hoc): n={len(x2)} C2 {sum(x2) / len(x2):.2f} -> C4 {sum(x4) / len(x4):.2f}, "
              f"diff {(sum(x4) - sum(x2)) / len(x2):+.3f} ({lo:+.3f}, {hi:+.3f}), lost/gained {b}/{g}, "
              f"McNemar p={mcnemar_exact(b, g):.4f}\n")

    recs = records("results/evidence_full_a")
    pairs = {r["pair_id"]: (r["project"], r["cwe"]) for r in recs}
    print(f"study set: {len(pairs)} pairs from {len({p for p, _ in pairs.values()})} projects")
    print("projects:", collections.Counter(p for p, _ in pairs.values()).most_common(8))
    print("CWEs:", collections.Counter(str(c) for _, c in pairs.values()).most_common(12))


if __name__ == "__main__":
    main()
