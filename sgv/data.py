"""CRUXEval-O loading, answer parsing and scoring.

Dataset code is parsed by the analyzer but never executed; gold outputs and
predictions are compared as safely evaluated literals.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass

import requests

from .literals import safe_literal

CRUXEVAL_URL = "https://raw.githubusercontent.com/facebookresearch/cruxeval/main/data/cruxeval.jsonl"


@dataclass(frozen=True)
class Sample:
    id: str
    code: str
    input: str
    output: str
    entry: str = "f"
    call: str | None = None  # full call expression; defaults to `{entry}({input})`

    @property
    def call_expr(self) -> str:
        return self.call or f"{self.entry}({self.input})"


def load_cruxeval(path: str) -> list[Sample]:
    samples = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                samples.append(Sample(row["id"], row["code"], row["input"], row["output"]))
    return samples


def download_cruxeval(dest: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    resp = requests.get(CRUXEVAL_URL, timeout=60)
    resp.raise_for_status()
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(resp.text)


def parse_answer(text: str | None) -> str | None:
    """Extract the value after the last `[ANSWER]` marker."""
    if not text:
        return None
    idx = text.rfind("[ANSWER]")
    if idx == -1:
        return None
    answer = text[idx + len("[ANSWER]"):].strip()
    answer = re.sub(r"^```(?:python)?\s*|\s*```$", "", answer).strip().strip("`").strip()
    if answer.startswith("f(") and "==" in answer:
        answer = answer.split("==", 1)[1].strip()
    if "\n" in answer and not safe_literal(answer)[0]:
        answer = answer.splitlines()[0].strip()
    return answer or None


def is_correct(pred: str | None, gold: str) -> bool:
    if pred is None:
        return False
    ok_p, val_p = safe_literal(pred)
    ok_g, val_g = safe_literal(gold)
    if ok_p and ok_g:
        try:
            return bool(val_p == val_g)
        except Exception:
            return False
    return " ".join(pred.split()) == " ".join(gold.split())


def canonical(answer: str | None) -> str | None:
    """Key for majority voting: equal values map to the same key."""
    if answer is None:
        return None
    ok, value = safe_literal(answer)
    return repr(value) if ok else " ".join(answer.split())


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Download CRUXEval")
    ap.add_argument("--dest", default="data/cruxeval.jsonl")
    args = ap.parse_args()
    download_cruxeval(args.dest)
    print(f"saved {len(load_cruxeval(args.dest))} samples to {args.dest}")
