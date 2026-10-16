"""Run selected methods on a benchmark subset, then summarise.

    python -m sgv.run --n 50 --methods B0,B1,B4,SGV
    python -m sgv.run --dataset reval-he --n 0 --methods B1,SGV --label
    python -m sgv.run --mock --n 5          # dry run without an API

--label runs each program on its input in an isolated interpreter to record an
execution trace, and uses it to label the claims SGV extracted (evaluation only).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .analysis import analyze_program
from .data import load_cruxeval
from .labeling import label_record
from .llm import ScriptedLLM, client_from_env
from .methods import METHODS, run_method
from .reval import load_reval_humaneval
from .stats import summarize, to_markdown
from .trace import TraceCache


def _mock_handler(kind, messages, sample):
    return "[]" if kind == "extract" else "Mock reasoning.\n[ANSWER] None"


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", choices=["cruxeval", "reval-he"], default="cruxeval")
    ap.add_argument("--data", default=None, help="dataset file (cruxeval) or directory (reval-he)")
    ap.add_argument("--inputs-per-program", type=int, default=1, help="reval-he: inputs used per program")
    ap.add_argument("--label", action="store_true", help="label SGV claims with execution traces")
    ap.add_argument("--n", type=int, default=50, help="number of samples (0 = all)")
    ap.add_argument("--seed", type=int, default=0, help="seed for drawing the sample subset")
    ap.add_argument("--methods", default="B0,B1,B4,SGV", help=f"comma-separated, from {','.join(METHODS)}")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", default=None, help="output directory (default results/<timestamp>)")
    ap.add_argument("--cache", default="results/llm_cache.sqlite")
    ap.add_argument("--mock", action="store_true", help="use a scripted LLM (no API calls)")
    args = ap.parse_args(argv)

    methods = [METHODS[m.strip()] for m in args.methods.split(",") if m.strip()]
    if args.dataset == "cruxeval":
        samples = load_cruxeval(args.data or "data/cruxeval.jsonl")
    else:
        samples = load_reval_humaneval(args.data or "data/reval", args.inputs_per_program)
    if args.n and args.n < len(samples):
        order = {s.id: i for i, s in enumerate(samples)}
        samples = sorted(random.Random(args.seed).sample(samples, args.n), key=lambda s: order[s.id])
    traces = TraceCache(os.path.join("data", "traces", f"{args.dataset}.jsonl")) if args.label else None
    llm = ScriptedLLM(_mock_handler) if args.mock else client_from_env(args.cache)
    out_dir = args.out or os.path.join("results", time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "config.json"), "w", encoding="utf-8") as fh:
        json.dump({**vars(args), "model": getattr(llm, "model", "mock"),
                   "sample_ids": [s.id for s in samples]}, fh, indent=2)

    records: list[dict] = []
    lock = threading.Lock()
    records_path = os.path.join(out_dir, "records.jsonl")

    def work(sample):
        pa = analyze_program(sample.code, sample.entry)
        # Methods run sequentially per sample so B1 and SGV share the cached CoT response.
        recs = [run_method(cfg, sample, pa, llm) for cfg in methods]
        if traces is not None:
            trace = traces.get(sample)
            for r in recs:
                if r.get("rounds"):
                    label_record(r, pa, trace)
        return recs

    with open(records_path, "w", encoding="utf-8") as fh, ThreadPoolExecutor(args.workers) as pool:
        futures = [pool.submit(work, s) for s in samples]
        for done, fut in enumerate(as_completed(futures), 1):
            recs = fut.result()
            with lock:
                records.extend(recs)
                for r in recs:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                fh.flush()
            print(f"[{done}/{len(samples)}] {recs[0]['id']}: "
                  + " ".join(f"{r['method']}={'ok' if r['correct'] else 'x'}" for r in recs), flush=True)

    summary = summarize(records, order=list(METHODS))
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    table = to_markdown(summary)
    with open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(table + "\n")
    print("\n" + table + f"\n\nResults written to {out_dir}")


if __name__ == "__main__":
    main()
