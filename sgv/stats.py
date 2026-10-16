"""Summary statistics for a run: accuracy with Wilson CIs, paired comparison
against a reference method (exact McNemar test, bootstrap CI of the
difference) and SGV verification diagnostics."""
from __future__ import annotations

import math
import random
from collections import Counter, defaultdict

from .verifier import CONTRADICTED, INVALID, SUPPORTED, UNVERIFIABLE


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def bootstrap_diff(ref: list[bool], new: list[bool], iters: int = 2000, seed: int = 0) -> tuple[float, float]:
    n = len(ref)
    if n == 0:
        return 0.0, 0.0
    rng = random.Random(seed)
    diffs = []
    for _ in range(iters):
        idx = [rng.randrange(n) for _ in range(n)]
        diffs.append(sum(new[i] - ref[i] for i in idx) / n)
    diffs.sort()
    return diffs[int(0.025 * iters)], diffs[int(0.975 * iters) - 1]


def _mean(xs) -> float:
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def _sgv_diagnostics(recs: list[dict]) -> dict | None:
    with_rounds = [r for r in recs if r.get("rounds")]
    if not with_rounds:
        return None
    first = [r["rounds"][0] for r in with_rounds]
    statuses = Counter(v["status"] for rd in first for v in rd["verdicts"])
    total = sum(statuses.values())
    checked_views = Counter(v["view"] for rd in first for v in rd["verdicts"] if v["status"] in (SUPPORTED, CONTRADICTED))
    flagged_first = [r for r in with_rounds if any(v["status"] == CONTRADICTED for v in r["rounds"][0]["verdicts"])]
    final_flagged = [r for r in with_rounds if any(v["status"] == CONTRADICTED for v in r["rounds"][-1]["verdicts"])]
    final_clean = [r for r in with_rounds if r not in final_flagged]
    return {
        "claims_per_sample": total / len(with_rounds),
        "dynamic_share": sum(1 for rd in first for v in rd["verdicts"] if v.get("dynamic")) / total if total else 0.0,
        "status_share": {s: statuses[s] / total if total else 0.0
                         for s in (SUPPORTED, CONTRADICTED, UNVERIFIABLE, INVALID)},
        "decided_by_view": dict(checked_views),
        "extract_failures": sum(1 for rd in first if rd["extract_error"]),
        "flagged_rate": len(flagged_first) / len(with_rounds),
        "initial_acc_flagged": _mean(r["initial_correct"] for r in flagged_first),
        "initial_acc_clean": _mean(r["initial_correct"] for r in with_rounds if r not in flagged_first),
        "repaired": sum(1 for r in with_rounds if r.get("repaired")),
        "wrong_to_right": sum(1 for r in with_rounds if not r["initial_correct"] and r["correct"]),
        "right_to_wrong": sum(1 for r in with_rounds if r["initial_correct"] and not r["correct"]),
        "final_acc_clean": _mean(r["correct"] for r in final_clean),
        "final_acc_flagged": _mean(r["correct"] for r in final_flagged),
        "final_clean_n": len(final_clean),
        "final_flagged_n": len(final_flagged),
    }


def _rate(num: int, den: int) -> float | None:
    return num / den if den else None


def _hallucination(recs: list[dict]) -> dict | None:
    """Claim-level hallucination metrics from labelled SGV records (round 0 = the initial CoT)."""
    rs = [r for r in recs if r.get("rounds") and r.get("trace_status") is not None]
    if not rs:
        return None
    first = [v for r in rs for v in r["rounds"][0]["verdicts"]]
    labeled = [v for v in first if v.get("truth") is not None]
    hall = [v for v in labeled if v["hallucinated"]]
    flagged = [v for v in labeled if v["status"] == CONTRADICTED]
    tp = [v for v in flagged if v["hallucinated"]]
    dyn_l = [v for v in labeled if v.get("dynamic")]
    dyn_h = [v for v in dyn_l if v["hallucinated"]]
    st_l = [v for v in labeled if not v.get("dynamic")]
    st_h = [v for v in st_l if v["hallucinated"]]
    has_h = {id(r): any(v.get("hallucinated") for v in r["rounds"][0]["verdicts"]) for r in rs}
    right = [r for r in rs if r["initial_correct"]]
    wrong = [r for r in rs if not r["initial_correct"]]
    final = [v for r in rs for v in r["rounds"][-1]["verdicts"] if v.get("truth") is not None]
    return {
        "samples": len(rs),
        "traced": sum(1 for r in rs if r["trace_status"] == "ok"),
        "claims": len(first),
        "labeled": len(labeled),
        "hallucination_rate": _rate(len(hall), len(labeled)),
        "static_rate": _rate(len(st_h), len(st_l)), "static_n": len(st_l),
        "dynamic_rate": _rate(len(dyn_h), len(dyn_l)), "dynamic_n": len(dyn_l),
        "samples_with_hallucination": _rate(sum(has_h.values()), len(rs)),
        "right_answer_hallucinated_reasoning": _rate(sum(has_h[id(r)] for r in right), len(right)),
        "wrong_answer_hallucinated_reasoning": _rate(sum(has_h[id(r)] for r in wrong), len(wrong)),
        "detect_precision": _rate(len(tp), len(flagged)),
        "detect_recall": _rate(len(tp), len(hall)),
        "detect_recall_dynamic": _rate(sum(1 for v in tp if v.get("dynamic")), len(dyn_h)),
        "final_hallucination_rate": _rate(sum(1 for v in final if v["hallucinated"]), len(final)),
    }


def summarize(records: list[dict], order: list[str], reference: str = "B1") -> dict:
    by_method: dict[str, dict[str, dict]] = defaultdict(dict)
    for r in records:
        by_method[r["method"]][r["id"]] = r
    ref = by_method.get(reference)
    rows = []
    for method in sorted(by_method, key=lambda m: order.index(m) if m in order else len(order)):
        recs = by_method[method]
        ids = sorted(recs)
        k = sum(recs[i]["correct"] for i in ids)
        row = {
            "method": method, "n": len(ids), "accuracy": k / len(ids), "ci95": wilson(k, len(ids)),
            "errors": sum(1 for i in ids if recs[i].get("error")),
            "calls": _mean(recs[i]["calls"] for i in ids),
            "prompt_tokens": _mean(recs[i]["prompt_tokens"] for i in ids),
            "completion_tokens": _mean(recs[i]["completion_tokens"] for i in ids),
        }
        if ref is not None and method != reference:
            common = [i for i in ids if i in ref]
            x = [bool(ref[i]["correct"]) for i in common]
            y = [bool(recs[i]["correct"]) for i in common]
            b = sum(1 for a, c in zip(x, y) if a and not c)
            c = sum(1 for a, c_ in zip(x, y) if not a and c_)
            row["vs_reference"] = {
                "reference": reference, "n": len(common), "delta": _mean(y) - _mean(x),
                "ci95": bootstrap_diff(x, y), "reference_only_correct": b, "method_only_correct": c,
                "mcnemar_p": mcnemar_exact(b, c),
            }
        diag = _sgv_diagnostics([recs[i] for i in ids])
        if diag:
            row["sgv"] = diag
        hall = _hallucination([recs[i] for i in ids])
        if hall:
            row["hallucination"] = hall
        rows.append(row)
    return {"reference": reference, "methods": rows}


def to_markdown(summary: dict) -> str:
    ref = summary["reference"]
    out = [f"| Method | n | Acc (95% CI) | Δ vs {ref} (95% CI) | {ref}-only / method-only | McNemar p | "
           "calls | tokens in | tokens out | errors |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for r in summary["methods"]:
        lo, hi = r["ci95"]
        vs = r.get("vs_reference")
        delta = f"{vs['delta']:+.3f} ({vs['ci95'][0]:+.3f}, {vs['ci95'][1]:+.3f})" if vs else "-"
        disc = f"{vs['reference_only_correct']} / {vs['method_only_correct']}" if vs else "-"
        p = f"{vs['mcnemar_p']:.3f}" if vs else "-"
        out.append(f"| {r['method']} | {r['n']} | {r['accuracy']:.3f} ({lo:.3f}, {hi:.3f}) | {delta} | {disc} | {p} | "
                   f"{r['calls']:.1f} | {r['prompt_tokens']:.0f} | {r['completion_tokens']:.0f} | {r['errors']} |")

    diag_rows = [r for r in summary["methods"] if "sgv" in r]
    if diag_rows:
        out += ["", "Verification diagnostics (first round = verifying the initial CoT):", "",
                "| Method | claims/sample | dynamic | supported | contradicted | unverifiable | invalid | flagged samples | "
                "init acc flagged / clean | repaired | wrong→right | right→wrong | final acc clean (n) / flagged (n) |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in diag_rows:
            d = r["sgv"]
            s = d["status_share"]
            out.append(
                f"| {r['method']} | {d['claims_per_sample']:.1f} | {d['dynamic_share']:.0%} | {s[SUPPORTED]:.0%} | "
                f"{s[CONTRADICTED]:.0%} | "
                f"{s[UNVERIFIABLE]:.0%} | {s[INVALID]:.0%} | {d['flagged_rate']:.0%} | "
                f"{d['initial_acc_flagged']:.2f} / {d['initial_acc_clean']:.2f} | {d['repaired']} | "
                f"{d['wrong_to_right']} | {d['right_to_wrong']} | "
                f"{d['final_acc_clean']:.2f} ({d['final_clean_n']}) / {d['final_acc_flagged']:.2f} ({d['final_flagged_n']}) |")

    hall_rows = [r for r in summary["methods"] if "hallucination" in r]
    if hall_rows:
        def pct(x):
            return "-" if x is None else f"{x:.1%}"

        out += ["", "Claim-level hallucination (labels: execution trace for dynamic claims, program facts for static "
                "claims; round 0 = initial CoT):", "",
                "| Method | traced / samples | labeled / claims | halluc. rate | static (n) | dynamic (n) | "
                "samples w/ halluc. | right answer + halluc. | wrong answer + halluc. | detect P | detect R (dynamic R) | "
                "final halluc. rate |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in hall_rows:
            h = r["hallucination"]
            out.append(
                f"| {r['method']} | {h['traced']} / {h['samples']} | {h['labeled']} / {h['claims']} | "
                f"{pct(h['hallucination_rate'])} | {pct(h['static_rate'])} ({h['static_n']}) | "
                f"{pct(h['dynamic_rate'])} ({h['dynamic_n']}) | {pct(h['samples_with_hallucination'])} | "
                f"{pct(h['right_answer_hallucinated_reasoning'])} | {pct(h['wrong_answer_hallucinated_reasoning'])} | "
                f"{pct(h['detect_precision'])} | {pct(h['detect_recall'])} ({pct(h['detect_recall_dynamic'])}) | "
                f"{pct(h['final_hallucination_rate'])} |")
    return "\n".join(out)
