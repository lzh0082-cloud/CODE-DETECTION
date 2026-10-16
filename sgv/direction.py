"""Directional deference: how far false evidence moves verdicts towards what it claims (H3).

    python -m sgv.direction results/evidence_full_a results/evidence_pilot_b ... [--models a,b] [--pooled]

For every model, on the pairs where both conditions exist:
  assurance shift = share SAFE under C4 - share SAFE under C2, on vulnerable versions
                    (C4 claims a check exists, so SAFE is the direction of its claim)
  alarm shift     = share VULNERABLE under C5 - share VULNERABLE under C2, on patched versions
                    (C5 claims a check is missing, so VULNERABLE is the direction of its claim)
  asymmetry       = assurance shift - alarm shift
Both shifts are measured against true notes about the same operations, so they are net of the model's leaning
(a model that flags everything cannot be moved towards VULNERABLE, but that limits both directions the same way
only if we compare against the same baseline). 95% CIs: bootstrap over pairs (2,000 resamples, seed 0).
`--pooled` adds the registered H3 test: the mean asymmetry over the listed models, with a bootstrap that resamples
pairs jointly for all models (the same functions are audited by every model), and a one-sided bootstrap p-value.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from math import comb

ITERS = 2000


def load(run_dirs: list[str]) -> dict:
    R = {}
    for d in run_dirs:
        with open(os.path.join(d, "records.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                if not r.get("error") and r.get("presentation", "plain") == "plain":
                    R[(r["model"], r["condition"], r["pair_id"], r["target"])] = r["verdict"]
    return R


def units(R: dict, model: str) -> dict[int, dict]:
    """Per pair: the assurance and/or alarm shift of that pair (+1, 0 or -1)."""
    out: dict[int, dict] = {}
    for (m, c, pid, t), verdict in R.items():
        if m != model or c not in ("C4", "C5"):
            continue
        base = R.get((model, "C2", pid, t))
        if base is None:
            continue
        if c == "C4":  # vulnerable version; claim direction SAFE
            out.setdefault(pid, {})["a"] = (verdict == "SAFE") - (base == "SAFE")
        else:  # patched version; claim direction VULNERABLE
            out.setdefault(pid, {})["l"] = (verdict == "VULNERABLE") - (base == "VULNERABLE")
    return out


def stat(u: dict[int, dict], pids: list[int]) -> tuple[float, float, float]:
    a = [u[p]["a"] for p in pids if p in u and "a" in u[p]]
    l = [u[p]["l"] for p in pids if p in u and "l" in u[p]]
    sa = sum(a) / len(a) if a else float("nan")
    sl = sum(l) / len(l) if l else float("nan")
    return sa, sl, sa - sl


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dirs", nargs="+")
    ap.add_argument("--models", help="comma-separated; default: every model in the runs")
    ap.add_argument("--pooled", action="store_true", help="registered H3 test over the listed models")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    R = load(args.run_dirs)
    models = args.models.split(",") if args.models else sorted({k[0] for k in R})
    U = {m: units(R, m) for m in models}
    rng = random.Random(0)

    print("| model | n C4 | assurance shift (95% CI) | n C5 | alarm shift (95% CI) | asymmetry (95% CI) |")
    print("|---|---|---|---|---|---|")
    for m in models:
        u = U[m]
        pids = sorted(u)
        if not pids:
            continue
        sa, sl, d = stat(u, pids)
        boots = [stat(u, [rng.choice(pids) for _ in pids]) for _ in range(ITERS)]
        ci = [sorted(b[i] for b in boots) for i in range(3)]
        lo, hi = int(0.025 * ITERS), int(0.975 * ITERS) - 1
        na = sum("a" in u[p] for p in pids)
        nl = sum("l" in u[p] for p in pids)
        print(f"| {m} | {na} | {sa:+.2f} ({ci[0][lo]:+.2f}, {ci[0][hi]:+.2f}) | {nl} | {sl:+.2f} "
              f"({ci[1][lo]:+.2f}, {ci[1][hi]:+.2f}) | {d:+.2f} ({ci[2][lo]:+.2f}, {ci[2][hi]:+.2f}) |")

    if args.pooled:
        pids = sorted(set().union(*(U[m] for m in models)))

        def pooled(sample):
            return sum(stat(U[m], sample)[2] for m in models) / len(models)

        est = pooled(pids)
        boots = sorted(pooled([rng.choice(pids) for _ in pids]) for _ in range(ITERS))
        p_one = (sum(b <= 0 for b in boots) + 1) / (ITERS + 1)
        positive = sum(stat(U[m], sorted(U[m]))[2] > 0 for m in models)
        k = len(models)
        p_sign = sum(comb(k, i) for i in range(positive, k + 1)) / 2 ** k
        print(f"\nH3 pooled over {k} models: mean asymmetry {est:+.3f}, 95% CI ({boots[int(0.025 * ITERS)]:+.3f}, "
              f"{boots[int(0.975 * ITERS) - 1]:+.3f}), one-sided bootstrap p={p_one:.4f}")
        print(f"Secondary: asymmetry > 0 in {positive}/{k} models, one-sided sign test p={p_sign:.4f}")


if __name__ == "__main__":
    main()
