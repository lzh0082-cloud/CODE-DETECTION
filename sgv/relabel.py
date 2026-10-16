"""Re-label the claims of an existing run with the current labelling rules and
traces, then rewrite its summary. No LLM calls.

    python -m sgv.relabel results/pilot1c
"""
from __future__ import annotations

import argparse
import json
import os

from .analysis import analyze_program
from .data import load_cruxeval
from .labeling import label_record
from .methods import METHODS
from .reval import load_reval_humaneval
from .stats import summarize, to_markdown
from .trace import TraceCache


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    args = ap.parse_args(argv)

    with open(os.path.join(args.run_dir, "config.json"), encoding="utf-8") as fh:
        cfg = json.load(fh)
    dataset = cfg.get("dataset", "cruxeval")
    if dataset == "cruxeval":
        samples = load_cruxeval(cfg.get("data") or "data/cruxeval.jsonl")
    else:
        samples = load_reval_humaneval(cfg.get("data") or "data/reval", cfg.get("inputs_per_program", 1))
    by_id = {s.id: s for s in samples}
    traces = TraceCache(os.path.join("data", "traces", f"{dataset}.jsonl"))

    records_path = os.path.join(args.run_dir, "records.jsonl")
    with open(records_path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh]
    analyses = {}
    for r in records:
        if not r.get("rounds"):
            continue
        sample = by_id[r["id"]]
        if sample.id not in analyses:
            analyses[sample.id] = analyze_program(sample.code, sample.entry)
        label_record(r, analyses[sample.id], traces.get(sample))

    with open(records_path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    summary = summarize(records, order=list(METHODS))
    with open(os.path.join(args.run_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    table = to_markdown(summary)
    with open(os.path.join(args.run_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(table + "\n")
    print(table)


if __name__ == "__main__":
    main()
