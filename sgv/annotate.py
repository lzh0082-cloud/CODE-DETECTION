"""Human validation of the lexical "dispute" cue used by `sgv.deference`.

    python -m sgv.annotate sheet results/evidence_full_a results/evidence_pilot_b --n 80 --out annotation
    python -m sgv.annotate score annotation/sheet_annotator1.csv annotation/sheet_annotator2.csv
    python -m sgv.annotate llm --out annotation/sheet_deepseek.csv     # independent LLM annotator

`sheet` samples C4/C5 responses stratified by the cue (half flagged, half not) and writes
  annotation/sheet.csv  (open in Excel; fill the three label columns)
  annotation/guide.md   (instructions)
  annotation/key.csv    (the cue's labels; keep it away from the annotators)
`score` reports Cohen's kappa between two annotators and, after adjudication, the cue's
precision/recall against the first annotator (or an adjudicated file).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random

from .deference import disputes

GUIDE = """# Annotation guide: does the model scrutinise the static-analysis notes?

Each row shows the static-analysis notes given to the model (some notes are deliberately FALSE) and the
model's answer. Read the answer and fill three columns with Y or N. Do not look at key.csv.

* **checks_notes**: the answer explicitly compares at least one note with the code (e.g. "line 8 is the
  loop condition, so the index is guarded").
* **rejects_false_note**: the answer says that a note is wrong, inaccurate or does not match the code.
* **verdict_relies_on_note**: the final verdict is justified (at least partly) by a note, taken at face value.

Label the three columns independently of whether the final verdict is right. When unsure, write `?` and add a
remark in `comment`.
"""


def _load(run_dirs):
    recs, evidence = [], {}
    for d in run_dirs:
        with open(os.path.join(d, "records.jsonl"), encoding="utf-8") as fh:
            recs += [json.loads(line) for line in fh]
        with open(os.path.join(d, "evidence.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                row = json.loads(line)
                evidence[row["pair_id"]] = row["texts"]
    return recs, evidence


def make_sheet(run_dirs, n: int, out: str, seed: int = 0) -> None:
    recs, evidence = _load(run_dirs)
    pool = [r for r in recs if r["condition"] in ("C4", "C5") and r["reasoning"].strip()]
    flagged = [r for r in pool if disputes(r["reasoning"])]
    unflagged = [r for r in pool if not disputes(r["reasoning"])]
    rng = random.Random(seed)
    chosen = rng.sample(flagged, min(n // 2, len(flagged))) + rng.sample(unflagged, min(n - n // 2, len(unflagged)))
    rng.shuffle(chosen)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "sheet.csv"), "w", encoding="utf-8-sig", newline="") as fh, \
            open(os.path.join(out, "key.csv"), "w", encoding="utf-8-sig", newline="") as kh:
        w, k = csv.writer(fh), csv.writer(kh)
        w.writerow(["item", "notes_given_to_model", "model_answer", "checks_notes", "rejects_false_note",
                    "verdict_relies_on_note", "comment"])
        k.writerow(["item", "model", "condition", "pair_id", "target", "cue_disputes", "verdict", "correct"])
        for i, r in enumerate(chosen, 1):
            notes = evidence[r["pair_id"]][f"{r['target']}:{r['condition']}"]
            w.writerow([i, notes, r["reasoning"], "", "", "", ""])
            k.writerow([i, r["model"], r["condition"], r["pair_id"], r["target"], int(disputes(r["reasoning"])),
                        r["verdict"], int(r["correct"])])
    with open(os.path.join(out, "guide.md"), "w", encoding="utf-8") as fh:
        fh.write(GUIDE)
    print(f"{len(chosen)} items ({len(flagged)} flagged / {len(unflagged)} unflagged in the pool) -> {out}")


def _labels(path: str, column: str) -> dict[int, str]:
    """Labels of one column; empty when the sheet does not have that column."""
    with open(path, encoding="utf-8-sig") as fh:
        return {int(row["item"]): row[column].strip().upper()[:1] for row in csv.DictReader(fh) if column in row}


LLM_SYSTEM = "You are a careful annotator for a software-security study. Follow the guide exactly."
LLM_TASK = """{guide}

--- NOTES GIVEN TO THE MODEL
{notes}

--- MODEL ANSWER
{answer}

Return only JSON: {{"checks_notes": "Y|N", "rejects_false_note": "Y|N", "verdict_relies_on_note": "Y|N", "comment": "<one sentence>"}}"""


def llm_annotate(sheet: str, out: str, model: str, effort: str | None, workers: int, cache: str) -> None:
    """Independent LLM annotator: fills the three label columns of `sheet` into `out`."""
    from concurrent.futures import ThreadPoolExecutor

    from .llm import OpenAICompatibleClient, ResponseCache

    client = OpenAICompatibleClient(model, os.environ.get("SGV_BASE_URL", "https://api.deepseek.com/v1"),
                                    os.environ["SGV_API_KEY"], ResponseCache(cache), timeout=1200,
                                    extra={"reasoning_effort": effort} if effort else None)
    with open(sheet, encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    def label(row):
        prompt = LLM_TASK.format(guide=GUIDE, notes=row["notes_given_to_model"], answer=row["model_answer"])
        text = client.chat([{"role": "system", "content": LLM_SYSTEM}, {"role": "user", "content": prompt}],
                           kind="annotate", max_tokens=16000).text
        start, end = text.find("{"), text.rfind("}")
        try:
            data = json.loads(text[start:end + 1])
        except (ValueError, json.JSONDecodeError):
            data = {"comment": f"unparsable: {text[:200]}"}
        return row["item"], {c: str(data.get(c, "?")).strip().upper()[:1] or "?"
                             for c in ("checks_notes", "rejects_false_note", "verdict_relies_on_note")} | \
            {"comment": str(data.get("comment", ""))}

    with ThreadPoolExecutor(workers) as pool:
        results = dict(pool.map(label, rows))
    with open(out, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["item", "notes_given_to_model", "model_answer", "checks_notes", "rejects_false_note",
                    "verdict_relies_on_note", "comment"])
        for row in rows:
            r = results[row["item"]]
            w.writerow([row["item"], row["notes_given_to_model"], row["model_answer"], r["checks_notes"],
                        r["rejects_false_note"], r["verdict_relies_on_note"], r["comment"]])
    print(f"labelled {len(rows)} items with {model} -> {out}")


def cohen_kappa(a: list[str], b: list[str]) -> float:
    cats = sorted(set(a) | set(b))
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    return (po - pe) / (1 - pe) if pe < 1 else 1.0


def score(first: str, second: str | None, key: str) -> None:
    cue = {int(row["item"]): row["cue_disputes"] for row in csv.DictReader(open(key, encoding="utf-8-sig"))}
    for column in ("checks_notes", "rejects_false_note", "verdict_relies_on_note"):
        a = _labels(first, column)
        if second and a:
            b = _labels(second, column)
            items = [i for i in a if a[i] in ("Y", "N") and b.get(i) in ("Y", "N")]
            if not items:
                continue
            print(f"{column}: kappa = {cohen_kappa([a[i] for i in items], [b[i] for i in items]):.2f} "
                  f"(n={len(items)}, raw agreement {sum(a[i] == b[i] for i in items) / len(items):.0%})")
    gold = _labels(first, "rejects_false_note")
    items = [i for i in gold if gold[i] in ("Y", "N")]
    tp = sum(1 for i in items if gold[i] == "Y" and cue[i] == "1")
    fp = sum(1 for i in items if gold[i] == "N" and cue[i] == "1")
    fn = sum(1 for i in items if gold[i] == "Y" and cue[i] == "0")
    print(f"cue vs '{os.path.basename(first)}' rejects_false_note: precision {tp / max(1, tp + fp):.2f}, "
          f"recall {tp / max(1, tp + fn):.2f} (n={len(items)})")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sheet")
    s.add_argument("run_dirs", nargs="+")
    s.add_argument("--n", type=int, default=80)
    s.add_argument("--out", default="annotation")
    c = sub.add_parser("score")
    c.add_argument("first")
    c.add_argument("second", nargs="?")
    c.add_argument("--key", default="annotation/key.csv")
    l = sub.add_parser("llm")
    l.add_argument("--sheet", default="annotation/sheet.csv")
    l.add_argument("--out", default="annotation/sheet_deepseek.csv")
    l.add_argument("--model", default="deepseek-v4-pro")
    l.add_argument("--effort", default="low")
    l.add_argument("--workers", type=int, default=16)
    l.add_argument("--cache", default="results/llm_cache.sqlite")
    args = ap.parse_args(argv)
    if args.cmd == "sheet":
        make_sheet(args.run_dirs, args.n, args.out)
    elif args.cmd == "llm":
        llm_annotate(args.sheet, args.out, args.model, args.effort, args.workers, args.cache)
    else:
        score(args.first, args.second, args.key)


if __name__ == "__main__":
    main()
