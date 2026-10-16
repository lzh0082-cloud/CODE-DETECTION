"""REval (ICSE 2025) loader: the HumanEval part as output-prediction samples.

REval's data holds programs, inputs and outputs; its intermediate-state ground
truth is obtained by running the programs (see `trace.py`).
"""
from __future__ import annotations

import argparse
import json
import os
import re

import requests

from .data import Sample

REVAL_URL = "https://raw.githubusercontent.com/r-eval/REval/main/data/"
REVAL_FILES = ("DREval_data.jsonl", "DREval_tasks.jsonl")
HUMANEVAL_RANGE = range(0, 85)  # DREval/0..84 come from HumanEval, 85..153 from ClassEval


def download_reval(dest_dir: str) -> None:
    os.makedirs(dest_dir, exist_ok=True)
    for name in REVAL_FILES:
        resp = requests.get(REVAL_URL + name, timeout=60)
        resp.raise_for_status()
        with open(os.path.join(dest_dir, name), "w", encoding="utf-8") as fh:
            fh.write(resp.text)


def _rows(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_reval_humaneval(data_dir: str, inputs_per_program: int = 1) -> list[Sample]:
    """One sample per (program, input), using the inputs REval selected for its tasks."""
    data = _rows(os.path.join(data_dir, "DREval_data.jsonl"))
    tasks = {row["idx"]: row for row in _rows(os.path.join(data_dir, "DREval_tasks.jsonl"))}
    samples = []
    for idx in HUMANEVAL_RANGE:
        row = data[idx]
        chosen = [t["input_idx"] for t in tasks[idx]["tasks"]][:inputs_per_program]
        for k in chosen:
            args = row["inputs"][k]
            call = row["entry_point"] + re.sub(r",\s*\)\s*$", ")", args.strip())
            samples.append(Sample(id=f"reval_{idx}_{k}", code=row["code"], input=args, output=row["outputs"][k],
                                  entry=row["entry_point"], call=call))
    return samples


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Download REval data")
    ap.add_argument("--dest", default="data/reval")
    args = ap.parse_args()
    download_reval(args.dest)
    print(f"saved {len(load_reval_humaneval(args.dest, 5))} HumanEval-part samples to {args.dest}")
