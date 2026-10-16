"""Task T1: LLM vulnerability judgments with explanations on PrimeVul paired
data (vulnerable function + its patched version).

    python -m sgv.vuln --pairs 30 --methods cot,facts,og --out results/vuln_og1

Methods:
  cot     the model audits the function and reasons step by step
  facts   the same, with the static obligations of `cfront` attached as notes
  og      obligation-guided: the model must rule on every obligation before its verdict
  refine  unconstrained CoT first (shared with `cot`), then a re-check against the obligations

With --extract the structural claims of the reasoning are extracted with a
C/security predicate set and exported for a manual audit.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import random
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass

from .cfront import FunctionFacts, language_for, render_obligations
from .claims import parse_claims
from .llm import client_from_env
from .serialize import numbered
from .stats import mcnemar_exact

STRUCTURAL_CWES = frozenset({
    "CWE-787", "CWE-125", "CWE-119", "CWE-120", "CWE-122",  # out-of-bounds access
    "CWE-476",                                              # NULL dereference
    "CWE-416", "CWE-415", "CWE-401",                        # use after free, double free, leak
    "CWE-369", "CWE-190", "CWE-191",                        # divide by zero, integer over/underflow
    "CWE-835",                                              # infinite loop
})


@dataclass(frozen=True)
class VulnFunc:
    idx: str
    pair_id: int
    project: str
    file_name: str
    func: str
    target: int  # 1 = vulnerable version, 0 = patched version
    cwe: tuple[str, ...]
    cve: str


def load_pairs(path: str) -> list[tuple[VulnFunc, VulnFunc]]:
    """(vulnerable, patched) pairs: consecutive rows of the same commit with targets 1 and 0."""
    with open(path, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    pairs = []
    for i in range(0, len(rows) - 1, 2):
        a, b = rows[i], rows[i + 1]
        if a["commit_id"] != b["commit_id"] or {int(a["target"]), int(b["target"])} != {0, 1}:
            continue
        funcs = []
        for r in (a, b):
            cwe = r["cwe"] if isinstance(r["cwe"], list) else json.loads(r["cwe"] or "[]")
            funcs.append(VulnFunc(str(r["idx"]), len(pairs), r["project"], r["file_name"], r["func"],
                                  int(r["target"]), tuple(cwe), r.get("cve") or ""))
        funcs.sort(key=lambda f: -f.target)
        pairs.append((funcs[0], funcs[1]))
    return pairs


def select_pairs(pairs, n: int, seed: int = 0, max_lines: int = 150):
    eligible = [p for p in pairs
                if set(p[0].cwe) & STRUCTURAL_CWES
                and max(len(f.func.splitlines()) for f in p) <= max_lines
                and p[0].func.strip() != p[1].func.strip()]
    return sorted(random.Random(seed).sample(eligible, min(n, len(eligible))), key=lambda p: p[0].pair_id)


# -- prompts ---------------------------------------------------------------

AUDIT_SYSTEM = "You are an expert C/C++ security auditor who reasons precisely about code."
_AUDIT_TASK = (
    "Reason step by step, citing line numbers: identify untrusted or externally controlled values, trace how "
    "they flow into memory accesses, pointer dereferences, frees, arithmetic and calls, and state which checks "
    "guard each of them. Then finish with a final line:\n[VERDICT] VULNERABLE  or  [VERDICT] SAFE")
_OBLIGATION_LEGEND = (
    "'holds here' lists conditions guaranteed on every path that reaches the operation; 'concern' states what "
    "this function itself does not guarantee. The analysis is exact for this function's code but does not look "
    "into callers or called functions.")


def _header(f: VulnFunc) -> str:
    return (f"Decide whether the following function (project `{f.project}`, file `{f.file_name}`) contains a "
            "security vulnerability. Line numbers are shown for reference only.\n\n"
            f"```c\n{numbered(f.func)}\n```\n\n")


def obligations_text(f: VulnFunc) -> str:
    return render_obligations(FunctionFacts(f.func, language_for(f.file_name)).obligations())


def audit_prompt(f: VulnFunc) -> list[dict]:
    return [{"role": "system", "content": AUDIT_SYSTEM}, {"role": "user", "content": _header(f) + _AUDIT_TASK}]


def facts_prompt(f: VulnFunc) -> list[dict]:
    return [{"role": "system", "content": AUDIT_SYSTEM}, {"role": "user", "content": (
        _header(f) + f"Static analysis notes for reference. {_OBLIGATION_LEGEND}\n\n{obligations_text(f)}\n\n"
        + _AUDIT_TASK)}]


def og_prompt(f: VulnFunc) -> list[dict]:
    return [{"role": "system", "content": AUDIT_SYSTEM}, {"role": "user", "content": (
        _header(f) + "Static analysis has listed the sensitive operations of this function as proof obligations. "
        f"{_OBLIGATION_LEGEND} A concern is a vulnerability only if values that actually reach the operation can "
        "violate it; callers, called functions or the meaning of the data may already rule it out, so judge each "
        "concern on its merits instead of counting them.\n\n"
        f"{obligations_text(f)}\n\n"
        "First, for every obligation write one line `O<i>: violable` or `O<i>: safe` with a short justification "
        "grounded in the facts and the code. Then consider risks the list does not cover (what called functions "
        "do, pointer arithmetic, integer types, error paths). Finish with a final line:\n"
        "[VERDICT] VULNERABLE  or  [VERDICT] SAFE")}]


def refine_followup(f: VulnFunc) -> str:
    return (f"Static analysis of this function lists its sensitive operations below. {_OBLIGATION_LEGEND}\n\n"
            f"{obligations_text(f)}\n\n"
            "Re-check your analysis above against these facts. For each obligation, say in one line whether it "
            "changes your assessment and why. Keep every problem you found earlier that the list does not cover, "
            "and correct any statement of yours that the facts contradict. Finish with a final line:\n"
            "[VERDICT] VULNERABLE  or  [VERDICT] SAFE")


PROMPTS = {"cot": audit_prompt, "facts": facts_prompt, "og": og_prompt, "refine": audit_prompt}


C_CATALOGUE = """Static facts about the function text (true for every execution):
- is_parameter(var): `var` is a parameter of the function
- var_defined(var): `var` is declared or assigned somewhere in the function
- calls(name, line?): the code contains a call of `name` [in the statement at `line`]
- in_loop(line, loop_line?): the statement at `line` is inside the body of a loop [the loop at `loop_line`]
- in_branch(line, if_line, branch): the statement at `line` is inside the true (`branch`: true) or false/else arm of the if at `if_line`
- condition_uses(line, var): the condition at `line` (if/while/for/ternary) reads `var`
- def_reaches(var, def_line, use_line): the value written to `var` at `def_line` can be the value read at `use_line`
- flows_to(var, line): the value of `var` (directly or through assignments) can reach an expression in the statement at `line`
- checked_before(var, line): on every path to the statement at `line`, a condition that tests `var` (NULL, bounds, length, zero) has been evaluated
- freed_at(var, line): the statement at `line` frees/releases `var`
- used_after(var, line): `var` can be read or dereferenced after the statement at `line` executes
- modified_after(var, line): `var` can be reassigned after the statement at `line`
- returns_at(line): the statement at `line` is a return statement
- early_exit_before(line): some return/goto/break can leave before the statement at `line` is reached

Other:
- free(): judgments that need semantics beyond the code text (whether a value is attacker-controlled, whether a size is large enough, whether an overflow is exploitable, the final verdict)"""


def extract_prompt(f: VulnFunc, reasoning: str, max_claims: int = 20) -> list[dict]:
    return [{"role": "system", "content": (
        "You convert free-text reasoning about a C function into atomic claims in a fixed predicate language. "
        "You never judge whether a claim is true; you only record what the reasoning asserts.")},
        {"role": "user", "content": (
            f"Function (line numbers for reference):\n```c\n{numbered(f.func)}\n```\n\n"
            f"Reasoning to convert:\n\"\"\"\n{reasoning}\n\"\"\"\n\n"
            f"Predicates:\n{C_CATALOGUE}\n\n"
            "Instructions:\n"
            "- Record each assertion about the code that the reasoning makes or clearly relies on, especially those "
            "the verdict depends on (missing or present checks, where data flows, frees, loop/branch structure).\n"
            "- Use holds=false for negated assertions (\"len is never checked before line 40\" is "
            "checked_before(var=len, line=40) with holds=false).\n"
            "- Line numbers refer to the listing above and must point at a statement. Never correct the reasoning.\n"
            f"- At most {max_claims} claims; prefer the ones the verdict depends on.\n\n"
            "Return only a JSON array, no prose:\n"
            '[{"text": "<short quote or paraphrase>", "predicate": "<name>", "args": {...}, "holds": true}]')}]


def parse_verdict(text: str) -> str | None:
    m = re.findall(r"\[VERDICT\]\s*\**\s*(VULNERABLE|SAFE)", text or "", re.I)
    return m[-1].upper() if m else None


def changed_lines(vuln: VulnFunc, patched: VulnFunc) -> tuple[list[int], list[int]]:
    """Lines of each version touched by the patch (1-based)."""
    a, b = vuln.func.splitlines(), patched.func.splitlines()
    va, pb = [], []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag != "equal":
            va += range(i1 + 1, i2 + 1)
            pb += range(j1 + 1, j2 + 1)
    return va, pb


# -- pilot run --------------------------------------------------------------

def run_function(f: VulnFunc, llm, method: str = "cot", extract: bool = False) -> dict:
    first = llm.chat(PROMPTS[method](f), kind=f"audit_{method}", max_tokens=3000).text
    reasoning = first
    if method == "refine":  # unconstrained CoT first (shared with `cot`), then a check against the facts
        followup = audit_prompt(f) + [{"role": "assistant", "content": first},
                                      {"role": "user", "content": refine_followup(f)}]
        reasoning = llm.chat(followup, kind="refine", max_tokens=3000).text
    verdict = parse_verdict(reasoning)
    claims, error = [], None
    if extract:
        raw = llm.chat(extract_prompt(f, reasoning), kind="extract", max_tokens=3000).text
        try:
            claims = [c.to_dict() for c in parse_claims(raw, 20)]
        except ValueError as e:
            error = str(e)
    predicted = None if verdict is None else int(verdict == "VULNERABLE")
    return {**asdict(f), "method": method, "verdict": verdict, "correct": predicted == f.target,
            "reasoning": reasoning, "initial_verdict": parse_verdict(first), "claims": claims,
            "extract_error": error}


def pair_metrics(recs: list[dict]) -> dict:
    """PrimeVul paired metrics: P-C both right, P-V both 'vulnerable', P-B both 'safe', P-R both wrong."""
    by_pair: dict[int, dict[int, dict]] = {}
    for r in recs:
        by_pair.setdefault(r["pair_id"], {})[r["target"]] = r
    out = Counter()
    for pair in by_pair.values():
        if set(pair) != {0, 1}:
            continue
        v, p = pair[1]["verdict"], pair[0]["verdict"]
        out["pairs"] += 1
        out["P-C"] += v == "VULNERABLE" and p == "SAFE"
        out["P-V"] += v == "VULNERABLE" and p == "VULNERABLE"
        out["P-B"] += v == "SAFE" and p == "SAFE"
        out["P-R"] += v == "SAFE" and p == "VULNERABLE"
    return dict(out)


def pair_correct(recs: list[dict]) -> dict[int, bool]:
    by_pair: dict[int, dict[int, dict]] = {}
    for r in recs:
        by_pair.setdefault(r["pair_id"], {})[r["target"]] = r
    return {pid: p[1]["verdict"] == "VULNERABLE" and p[0]["verdict"] == "SAFE"
            for pid, p in by_pair.items() if set(p) == {0, 1}}


def write_audit_sheet(recs: list[dict], pairs, path: str) -> None:
    """Markdown sheet for manually labelling claims (code, patch lines, reasoning excerpt, claims)."""
    diffs = {}
    for vuln, patched in pairs:
        va, pb = changed_lines(vuln, patched)
        diffs[(vuln.pair_id, 1)], diffs[(vuln.pair_id, 0)] = va, pb
    with open(path, "w", encoding="utf-8") as fh:
        for r in sorted(recs, key=lambda r: (r["pair_id"], -r["target"])):
            version = "VULNERABLE version" if r["target"] else "PATCHED version"
            fh.write(f"\n\n## pair {r['pair_id']} / {version} / {r['project']}:{r['file_name']} / "
                     f"{','.join(r['cwe'])} / verdict {r['verdict']} ({'correct' if r['correct'] else 'WRONG'})\n")
            fh.write(f"patch-touched lines: {diffs[(r['pair_id'], r['target'])]}\n\n```c\n{numbered(r['func'])}\n```\n")
            fh.write("\n### claims\n")
            for c in r["claims"]:
                neg = "" if c["holds"] else "NOT "
                fh.write(f"- [{c['id']}] {neg}{c['predicate']}({json.dumps(c['args'], ensure_ascii=False)})"
                         f"  <- {c['text']}\n")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data/primevul/primevul_test_paired.jsonl")
    ap.add_argument("--pairs", type=int, default=30)
    ap.add_argument("--max-lines", type=int, default=150)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--methods", default="cot", help=f"comma-separated, from {','.join(PROMPTS)}")
    ap.add_argument("--extract", action="store_true", help="extract claims (cot reasoning) for auditing")
    ap.add_argument("--cache", default="results/llm_cache.sqlite")
    ap.add_argument("--out", default="results/vuln_pilot")
    args = ap.parse_args(argv)

    methods = [m.strip() for m in args.methods.split(",") if m.strip()]
    pairs = select_pairs(load_pairs(args.data), args.pairs, args.seed, args.max_lines)
    funcs = [f for pair in pairs for f in pair]
    llm = client_from_env(args.cache)
    os.makedirs(args.out, exist_ok=True)
    jobs = [(f, m) for m in methods for f in funcs]
    recs = []
    with ThreadPoolExecutor(args.workers) as pool:
        futures = [pool.submit(run_function, f, llm, m, args.extract and m == "cot") for f, m in jobs]
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            recs.append(r)
            print(f"[{i}/{len(jobs)}] {r['method']} pair {r['pair_id']} target={r['target']} "
                  f"verdict={r['verdict']}", flush=True)

    with open(os.path.join(args.out, "records.jsonl"), "w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    if args.extract:
        write_audit_sheet([r for r in recs if r["method"] == "cot"], pairs,
                          os.path.join(args.out, "audit_sheet.md"))

    summary = {"pairs": len(pairs), "methods": {}}
    ref = pair_correct([r for r in recs if r["method"] == methods[0]])
    for m in methods:
        mine = [r for r in recs if r["method"] == m]
        pc = pair_correct(mine)
        b = sum(1 for p in pc if ref[p] and not pc[p])
        c = sum(1 for p in pc if pc[p] and not ref[p])
        summary["methods"][m] = {
            "accuracy": sum(r["correct"] for r in mine) / len(mine),
            "no_verdict": sum(r["verdict"] is None for r in mine),
            "paired": pair_metrics(mine),
            f"vs_{methods[0]}": {"lost": b, "gained": c, "mcnemar_p": mcnemar_exact(b, c)},
        }
        if args.extract and m == "cot":
            summary["methods"][m]["predicates"] = dict(Counter(c["predicate"] for r in mine for c in r["claims"]))
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
