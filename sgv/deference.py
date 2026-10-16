"""Inspect how models treat false evidence (conditions C4/C5) in an evidence run.

    python -m sgv.deference results/evidence_pilot [--show 5]

For every function under C4 (false reassurance) or C5 (false alarm) it reports
  * deference: C0 was correct and the verdict now follows the false evidence;
  * scrutiny: the reasoning explicitly disputes the static-analysis notes (lexical cue,
    meant for triage and checked by hand on a sample).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict

_DISPUTE = re.compile(
    r"(notes?|analysis|analy[sz]er|tool|static)[^.\n]{0,120}\b(incorrect|wrong|mistaken|inaccurate|false|misleading|"
    r"not (actually|present|true|accurate|correct)|does(n't| not) (match|hold|exist|appear)|contradict)"
    r"|\b(no such|there is no) (check|guard)[^.\n]{0,80}(line \d+)"
    r"|(contrary to|despite) (the )?(notes?|analysis|claim)"
    r"|line \d+ (is|contains) (actually |just |only )?(a |the )?`?(return|goto|break|\})", re.I)


def disputes(reasoning: str) -> bool:
    return bool(_DISPUTE.search(reasoning or ""))


def _excerpt(reasoning: str, width: int = 900) -> str:
    m = _DISPUTE.search(reasoning or "")
    start = max(0, (m.start() if m else 0) - 300)
    return reasoning[start:start + width]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    ap.add_argument("--show", type=int, default=0, help="print N deferring examples per model and condition")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    with open(os.path.join(args.run_dir, "records.jsonl"), encoding="utf-8") as fh:
        recs = [json.loads(line) for line in fh]
    R = {(r["model"], r["condition"], r["pair_id"], r["target"]): r for r in recs}
    with open(os.path.join(args.run_dir, "evidence.jsonl"), encoding="utf-8") as fh:
        source = {json.loads(line)["pair_id"]: json.loads(line)["info"].get("c5_source") for line in fh}

    for model in sorted({r["model"] for r in recs}):
        for cond in ("C4", "C5"):
            rows = [r for r in recs if r["model"] == model and r["condition"] == cond]
            if not rows:
                continue
            stats = defaultdict(int)
            deferring = []
            for r in rows:
                base = R.get((model, "C0", r["pair_id"], r["target"]))
                if base is None:
                    continue
                d = disputes(r["reasoning"])
                stats["n"] += 1
                stats["disputed"] += d
                if base["correct"]:
                    stats["c0_correct"] += 1
                    if not r["correct"]:
                        stats["deferred"] += 1
                        stats["deferred_disputed"] += d
                        deferring.append(r)
                    else:
                        stats["resisted_disputed"] += d
            resisted = stats["c0_correct"] - stats["deferred"]
            print(f"\n[{model} {cond}] functions={stats['n']} disputed-notes={stats['disputed']} | C0 correct="
                  f"{stats['c0_correct']} -> deferred={stats['deferred']} (disputed {stats['deferred_disputed']}), "
                  f"resisted={resisted} (disputed {stats['resisted_disputed']})")
            if cond == "C5":
                by_src = defaultdict(lambda: [0, 0])
                for r in rows:
                    base = R.get((model, "C0", r["pair_id"], r["target"]))
                    if base is not None and base["correct"]:
                        by_src[source.get(r["pair_id"])][0] += 1
                        by_src[source.get(r["pair_id"])][1] += not r["correct"]
                print("   deference by C5 source:", {k: f"{v[1]}/{v[0]}" for k, v in by_src.items()})
            for r in deferring[:args.show]:
                print(f"   --- pair {r['pair_id']} ({r['project']}, {','.join(r['cwe'])}) -> {r['verdict']}")
                print("   " + _excerpt(r["reasoning"]).replace("\n", "\n   "))


if __name__ == "__main__":
    main()
