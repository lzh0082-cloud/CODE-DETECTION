"""Controlled study: how LLMs use static-analysis evidence in vulnerability reasoning.

For each PrimeVul pair the evidence shown to the model is manipulated:

  C0  none                       plain audit (chain of thought)
  C1  all true obligations       what the static front end reports
  C2  patch-relevant true facts  only obligations at the code the patch touches ("precise tool")
  C3  irrelevant true facts      only obligations away from the patch
  C4  false reassurance          vulnerable version: relevant concerns replaced by fabricated checks
  C5  false alarm                patched version: the vulnerable version's concerns transplanted onto
                                 the fixed operation, with the contradicting facts removed

    python -m sgv.evidence --pairs 60 --models flash,flash-think,pro-think --out results/evidence_pilot

Relevance uses the patch (diff) only to *build* conditions C2-C5; the model never sees the patch.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import random
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace

from .cfront import FunctionFacts, Obligation, language_for, render_obligations
from .llm import OpenAICompatibleClient, ResponseCache
from .serialize import numbered
from .stats import mcnemar_exact, wilson
from .vuln import (AUDIT_SYSTEM, _AUDIT_TASK, _OBLIGATION_LEGEND, VulnFunc, _header, load_pairs, parse_verdict,
                   select_pairs)

DEEPSEEK = ("https://api.deepseek.com/v1", "SGV_API_KEY", r"~\.sgv_deepseek_key")
DASHSCOPE = ("https://dashscope.aliyuncs.com/compatible-mode/v1", "SGV_QWEN_KEY", r"~\.sgv_qwen_key")
MODELS = {  # name -> (API model, max_tokens, extra request fields, (base URL, key env var, key file))
    # Thinking models count reasoning tokens against max_tokens; both run at the same (low) effort, which
    # keeps a 75-line function at ~10k (flash) / ~24k (pro) tokens instead of exhausting 32k.
    "flash": ("deepseek-chat", 8000, {}, DEEPSEEK),                                   # deepseek-flash, non-thinking
    "flash-think": ("deepseek-flash", 32000, {"reasoning_effort": "low"}, DEEPSEEK),  # deepseek-flash, thinking
    "pro-think": ("deepseek-v4-pro", 32000, {"reasoning_effort": "low"}, DEEPSEEK),   # deepseek-v4-pro, thinking
    "qwen-plus": ("qwen-plus-2025-12-01", 8000, {}, DASHSCOPE),                       # pinned snapshot, non-thinking
    # Multi-vendor replication (H3), all on Bailian with thinking switched off; snapshots pinned where offered.
    "glm-5.2": ("glm-5.2", 8000, {"enable_thinking": False}, DASHSCOPE),                      # Zhipu
    "kimi-k2.6": ("kimi-k2.6", 8000, {"enable_thinking": False}, DASHSCOPE),                  # Moonshot
    "kimi-k3": ("kimi-k3", 8000, {"enable_thinking": False}, DASHSCOPE),                      # Moonshot
    "qwen3.7-plus": ("qwen3.7-plus-2026-05-26", 8000, {"enable_thinking": False}, DASHSCOPE),  # Alibaba
    "qwen3.7-max": ("qwen3.7-max-2026-06-08", 8000, {"enable_thinking": False}, DASHSCOPE),    # Alibaba
    "qwen3.7-flash": ("qwen3.7-flash-2026-07-15", 8000, {"enable_thinking": False}, DASHSCOPE),  # Alibaba
    "ds-v4.1-flash": ("deepseek-v4.1-flash", 8000, {"enable_thinking": False}, DASHSCOPE),    # DeepSeek
}


def api_key(env_var: str, key_file: str) -> str:
    """The key from the environment, else from a file kept outside the repository."""
    key = os.environ.get(env_var)
    path = os.path.expanduser(key_file)
    if not key and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            key = fh.read().strip()
    if not key:
        raise SystemExit(f"Set {env_var} or put the key in {path}")
    return key
CONDITIONS = ("C0", "C1", "C2", "C3", "C4", "C5")
_IDENT = re.compile(r"[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*")
_C_WORDS = frozenset("""if else for while do switch case default return goto break continue sizeof struct union
enum typedef static const volatile unsigned signed int long short char void float double bool true false NULL
inline extern register auto unlikely likely""".split())


# -- relevance to the patch ------------------------------------------------

def _hunks(vuln: VulnFunc, patched: VulnFunc) -> list[tuple[int, int, int, int]]:
    a, b = vuln.func.splitlines(), patched.func.splitlines()
    return [(i1, i2, j1, j2) for tag, i1, i2, j1, j2 in
            difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes() if tag != "equal"]


def _patch_vars(vuln: VulnFunc, patched: VulnFunc, hunks) -> set[str]:
    a, b = vuln.func.splitlines(), patched.func.splitlines()
    text = "\n".join(line for i1, i2, j1, j2 in hunks for line in a[i1:i2] + b[j1:j2])
    out = set()
    for m in _IDENT.finditer(text):
        path = re.sub(r"\s+", "", m.group(0))
        for part in [path] + re.split(r"->|\.", path):
            if part and part not in _C_WORDS and not re.fullmatch(r"[A-Z][A-Z0-9_]*", part) and len(part) > 1:
                out.add(part)
    return out


def _windows(hunks, version: int) -> list[tuple[int, int]]:
    """1-based line windows around the patch in the vulnerable (1) or patched (0) version."""
    out = []
    for i1, i2, j1, j2 in hunks:
        lo, hi = (i1, i2) if version == 1 else (j1, j2)
        out.append((lo + 1 - 3, max(hi, lo + 1) + 8))
    return out


def _mentions(ob: Obligation, names: set[str]) -> bool:
    text = " ".join([ob.expr] + ob.concerns + ob.facts)
    return any(re.search(rf"(?<![\w>.]){re.escape(n)}(?!\w)", text) for n in names)


def _near(ob: Obligation, windows) -> bool:
    """The operation, or a line its concerns point at (e.g. "the return at line 17"), lies near the patch."""
    lines = [ob.line] + [int(x) for c in ob.concerns for x in re.findall(r"\b(\d+)\b", c)]
    return any(lo <= x <= hi for x in lines for lo, hi in windows)


def split_relevant(obs: list[Obligation], windows, names) -> tuple[list[Obligation], list[Obligation]]:
    rel = [o for o in obs if _near(o, windows) and _mentions(o, names)]
    return rel, [o for o in obs if o not in rel]


# -- fabricated evidence ------------------------------------------------------

_REASSURE = [
    (r"no upper-bound check on `([^`]+)` dominates this (\w[\w ]*)",
     lambda m, k: f"`{m.group(1)}` is checked against its upper bound before this {m.group(2)} (line {k})"),
    (r"`([^`]+)` is signed .*no lower-bound .*dominates this (\w[\w ]*)",
     lambda m, k: f"`{m.group(1)} >= 0` is checked before this {m.group(2)} (line {k})"),
    (r"`([^`]+)` \(.*\) may be NULL and no NULL check dominates this dereference",
     lambda m, k: f"`{m.group(1)} != NULL` is checked before this dereference (line {k})"),
    (r"no check that `([^`]+)` != 0 dominates this division",
     lambda m, k: f"`{m.group(1)} != 0` is checked before this division (line {k})"),
    (r"the return at line (\d+) neither frees nor returns `([^`]+)`",
     lambda m, k: f"`{m.group(2)}` is released before the return at line {m.group(1)}"),
    (r"`([^`]+)` can be freed again",
     lambda m, k: f"`{m.group(1)}` is set to NULL right after this free (line {k + 1}), so it cannot be freed twice"),
    (r"`([^`]+)` is mentioned at line\(s\) .* after this free",
     lambda m, k: f"`{m.group(1)}` is not used after this free"),
    (r"`([^`]+)` .*(overflow|wrap)",
     lambda m, k: f"`{m.group(1)}` is range-checked before use, so it cannot {m.group(2)} (line {k})"),
    (r"`(\w+)` copies without a destination size limit",
     lambda m, k: f"the destination of `{m.group(1)}` is checked to be large enough (line {k})"),
]


def reassure(ob: Obligation) -> Obligation:
    """C4: the same operation, its concerns replaced by fabricated guarantees."""
    k = max(1, ob.line - 1)
    fake = []
    for concern in ob.concerns:
        for pattern, make in _REASSURE:
            m = re.search(pattern, concern)
            if m:
                fake.append(make(m, k))
                break
        else:
            fake.append(f"`{ob.expr}` is fully validated before this operation (line {k})")
    return replace(ob, facts=ob.facts + list(dict.fromkeys(fake)), concerns=[])


def _shape(concern: str) -> str:
    return re.sub(r"\d+", "#", concern)


def alarm(ob: Obligation, donor: list[Obligation], fixed: set[str], transplant_only: bool) -> Obligation | None:
    """C5 false alarm on a patched-version operation, with its guarding facts removed:
    * transplant: the concerns the patch removed (vulnerable-version concerns of the same kind of
      operation that the patched version no longer has);
    * negation (unless `transplant_only`): each true guard is declared not to protect the operation.
    None when neither applies."""
    removed = [c for d in donor if d.kind == ob.kind for c in d.concerns if _shape(c) in fixed]
    if removed:
        return replace(ob, facts=[], concerns=list(dict.fromkeys(removed)))
    if transplant_only:
        return None
    negated = []
    for fact in ob.facts:
        m = re.match(r"`(.+)` \((.+), line (\d+)\)$", fact)
        if m:
            negated.append(f"`{m.group(1)}` does not hold here: the check at line {m.group(3)} does not guard "
                           f"this {ob.kind}")
    return replace(ob, facts=[], concerns=negated) if negated else None


# -- per-pair evidence ----------------------------------------------------------

@dataclass
class PairEvidence:
    vuln: VulnFunc
    patched: VulnFunc
    texts: dict[tuple[int, str], str]  # (target, condition) -> evidence text (None = condition not applicable)
    info: dict


def build_evidence(vuln: VulnFunc, patched: VulnFunc) -> PairEvidence:
    hunks = _hunks(vuln, patched)
    names = _patch_vars(vuln, patched, hunks)
    obs, rel, irr = {}, {}, {}
    for f in (vuln, patched):
        obs[f.target] = FunctionFacts(f.func, language_for(f.file_name)).obligations()
        rel[f.target], irr[f.target] = split_relevant(obs[f.target], _windows(hunks, f.target), names)
    texts: dict[tuple[int, str], str | None] = {}
    for t in (1, 0):
        texts[(t, "C0")] = ""
        texts[(t, "C1")] = render_obligations(obs[t])
        texts[(t, "C2")] = render_obligations(rel[t]) if rel[t] else None
        texts[(t, "C3")] = render_obligations([o for o in irr[t] if o.concerns]) \
            if any(o.concerns for o in irr[t]) else None
    vuln_rel_concerned = [o for o in rel[1] if o.concerns]
    texts[(1, "C4")] = render_obligations([reassure(o) for o in rel[1]]) if vuln_rel_concerned else None
    texts[(0, "C4")] = None
    fixed = {_shape(c) for o in obs[1] for c in o.concerns} - {_shape(c) for o in obs[0] for c in o.concerns}
    c5_source = None
    for source, pool, transplant_only in (("transplant", rel[0], True), ("negated-relevant", rel[0], False),
                                          ("negated-any", obs[0], False)):
        alarms = [(o, alarm(o, rel[1], fixed, transplant_only)) for o in pool]
        if any(a for _, a in alarms):
            texts[(0, "C5")] = render_obligations([a or o for o, a in alarms])
            c5_source = source
            break
    else:
        texts[(0, "C5")] = None
    texts[(1, "C5")] = None
    info = {"relevant": (len(rel[1]), len(rel[0])), "patch_vars": sorted(names)[:20], "c5_source": c5_source,
            "discriminative": bool({re.sub(r"\d+", "#", c) for o in obs[1] for c in o.concerns}
                                   - {re.sub(r"\d+", "#", c) for o in obs[0] for c in o.concerns})}
    return PairEvidence(vuln, patched, texts, info)


# How the notes are presented (mitigations of deference to false notes):
#   plain       the notes as reference (the setting of the main study)
#   quote       verify-before-trust: every note must be checked against a quoted code line before it is used
#   alarms      only concerns are shown; positive "holds here" assurances are withheld
#   reframe     assurances are recast as claims to verify ("to verify: the tool reports ...")
#   provenance  every line number a note cites is followed by that line's source code
#   verify      verify-then-audit: a separate call checks every note against the code; the audit sees only
#               confirmed notes (unconfirmed ones marked), refuted ones are withheld
#   verify-show as verify, but refuted notes are listed separately as contradicted by the code
#   commit      cognitive forcing (two turns): the model audits without notes first, then sees the notes and
#               may change its verdict only on the strength of a note it confirms in quoted code
#   commit-verify  both: independent audit first, then the notes after a separate verification step
#               (refuted claims listed as contradicted by the code)
PRESENTATIONS = ("plain", "quote", "alarms", "reframe", "provenance", "verify", "verify-show", "commit",
                 "commit-verify")
_VERIFYING = ("verify", "verify-show", "commit-verify")
_VERIFIED_LEGEND = (" Every claim below was checked against the code in a separate verification step; claims the "
                    "code did not confirm are marked.")
_COMMIT_FOLLOWUP = (
    "A static analysis tool, which is sometimes wrong, produced these notes about the function. {legend}\n\n"
    "{notes}\n\n"
    "Reconsider your analysis as a careful reviewer would treat advice from such a tool. For every note that bears "
    "on your verdict, quote the code it refers to and say whether the code confirms or contradicts it. Keep your "
    "earlier verdict unless a note that you confirmed in the code gives a concrete reason to change it. Finish with a "
    "final line:\n[VERDICT] VULNERABLE  or  [VERDICT] SAFE")
_CLAIM = re.compile(r"^\s*(holds here|concern): (?!\(no relevant check\))")


def claim_lines(text: str) -> list[int]:
    """Indexes of the note lines that make a checkable claim."""
    return [i for i, line in enumerate(text.splitlines()) if _CLAIM.match(line)]


def verify_prompt(f: VulnFunc, text: str) -> list[dict]:
    lines = text.splitlines()
    claims = "\n".join(f"[{k}] {lines[i].strip()}  (about {_operation_of(lines, i)})"
                       for k, i in enumerate(claim_lines(text), 1))
    return [{"role": "system", "content": "You check claims made by a static analyzer against C/C++ source code."},
            {"role": "user", "content": (
                f"```c\n{numbered(f.func)}\n```\n\nA static analyzer made these claims about the function above. "
                "'holds here' claims that a condition is guaranteed on every path to the operation; 'concern' claims "
                "that something is not guaranteed there.\n\n" + claims + "\n\n"
                "Check every claim against the code only. Quote the code line(s) that decide it. A claim is CONFIRMED if "
                "the code shows it is true, REFUTED if the code shows it is false (for example the cited line does not "
                "contain the claimed check), UNCLEAR if this function's code cannot decide it.\n"
                'Return only a JSON array: [{"id": 1, "status": "CONFIRMED|REFUTED|UNCLEAR", "quote": "..."}]')}]


def _operation_of(lines: list[str], i: int) -> str:
    for j in range(i, -1, -1):
        m = re.match(r"^O\d+ \[(.+?)\] line (\d+): (.*)$", lines[j])
        if m:
            return f"the {m.group(1)} at line {m.group(2)}: {m.group(3)}"
    return "the function"


def parse_verification(reply: str) -> dict[int, str]:
    start, end = reply.find("["), reply.rfind("]")
    try:
        items = json.loads(reply[start:end + 1])
    except (ValueError, json.JSONDecodeError):
        return {}
    out = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and str(item.get("status", "")).upper() in ("CONFIRMED", "REFUTED", "UNCLEAR"):
            try:
                out[int(item["id"])] = str(item["status"]).upper()
            except (KeyError, TypeError, ValueError):
                pass
    return out


def verified_notes(text: str, statuses: dict[int, str], show_refuted: bool) -> str:
    """Notes after verification: confirmed claims kept, unconfirmed ones marked, refuted ones withheld
    (or, with `show_refuted`, listed separately)."""
    lines = text.splitlines()
    claim_at = {i: k for k, i in enumerate(claim_lines(text), 1)}
    kept, refuted = [], []
    for i, line in enumerate(lines):
        k = claim_at.get(i)
        status = statuses.get(k, "UNCLEAR") if k else None
        if status == "REFUTED":
            refuted.append(f"- {_operation_of(lines, i)} -- {line.strip()}")
        elif status == "UNCLEAR":
            kept.append(f"{line}  (not confirmed by the code)")
        else:
            kept.append(line)
    out = "\n".join(kept)
    if show_refuted and refuted:
        out += ("\n\nClaims of the analyzer that verification found CONTRADICTED by the code (do not rely on them):\n"
                + "\n".join(refuted))
    return out
_QUOTE_RULE = (
    "Treat every note as an unverified claim, not as a fact. Before you rely on any 'holds here' or 'concern' "
    "line, quote the exact code it refers to and say whether that code confirms the claim. Do not rely on a note "
    "that you could not confirm in the code; reason from the code instead.")


def alarms_only(text: str) -> str:
    """Drop the positive assurances, keep the operations and their concerns."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("holds here:"))


def reframe(text: str) -> str:
    """Recast assurances as claims to verify, the form models already scrutinise."""
    return "\n".join(re.sub(r"^(\s*)holds here: (.*)$", r"\1to verify: the tool reports \2", line)
                     for line in text.splitlines())


def with_provenance(text: str, code: str) -> str:
    """Append the source of every cited line, so a claim can be checked against the code at a glance."""
    source = code.splitlines()

    def cite(m: re.Match) -> str:
        n = int(m.group(2))
        snippet = " ".join(source[n - 1].split()) if 1 <= n <= len(source) else "(no such line)"
        return f"{m.group(0)} [line {n} is: `{snippet[:120]}`]"

    out = []
    for line in text.splitlines():
        if line.lstrip().startswith(("holds here:", "concern:")):
            line = re.sub(r"(line|at line) (\d+)\)?", cite, line)
        out.append(line)
    return "\n".join(out)


STUDY_MAX_LINES = 150  # the study set: structural CWEs, both versions <= 150 lines


def select_heldout(pairs, max_lines: int) -> list:
    """Confirmatory pairs: disjoint from the study set, any CWE, both versions <= max_lines."""
    study = {v.pair_id for v, _ in select_pairs(pairs, 10 ** 6, 0, STUDY_MAX_LINES)}
    return [p for p in pairs if p[0].pair_id not in study and p[0].func.strip() != p[1].func.strip()
            and max(len(f.func.splitlines()) for f in p) <= max_lines]


def evidence_prompt(f: VulnFunc, text: str, presentation: str = "plain") -> list[dict]:
    if not text:  # C0: identical to vuln.audit_prompt, so earlier CoT responses are reused from the cache
        return [{"role": "system", "content": AUDIT_SYSTEM}, {"role": "user", "content": _header(f) + _AUDIT_TASK}]
    legend = _OBLIGATION_LEGEND
    if presentation == "alarms":
        text = alarms_only(text)
        legend = ("Each 'concern' states what this function itself does not guarantee at that operation. The analysis "
                  "is exact for this function's code but does not look into callers or called functions.")
    elif presentation == "reframe":
        text = reframe(text)
        legend = ("'to verify' lists conditions the tool reports as guaranteed on every path to the operation; check "
                  "each against the code before relying on it. 'concern' states what this function itself does not "
                  "guarantee. The analysis does not look into callers or called functions.")
    elif presentation == "provenance":
        text = with_provenance(text, f.func)
    elif presentation in ("verify", "verify-show"):
        legend = _OBLIGATION_LEGEND + _VERIFIED_LEGEND
    rule = f"{_QUOTE_RULE}\n\n" if presentation == "quote" else ""
    return [{"role": "system", "content": AUDIT_SYSTEM}, {"role": "user", "content": (
        _header(f) + f"Static analysis notes for reference. {legend}\n\n{text}\n\n" + rule + _AUDIT_TASK)}]


# -- running ----------------------------------------------------------------------

# Errors that will repeat for every remaining job (no balance, no quota, bad key): stop instead of
# filling the results with failures. Completed calls are cached, so a rerun after topping up resumes.
_FATAL = re.compile(r"HTTP (401|402|403)|insufficient|balance|quota|arrearage|exceeded your current|"
                    r"invalid api key|authentication|free ?tier|exhausted|access ?denied|overdue", re.I)


def run_job(client, max_tokens: int, model: str, cond: str, f: VulnFunc, text: str,
            presentation: str = "plain") -> dict:
    statuses = None
    try:
        tokens = 0
        if presentation in _VERIFYING and claim_lines(text):
            check = client.chat(verify_prompt(f, text), kind=f"verify_{cond}", max_tokens=max_tokens)
            statuses = parse_verification(check.text)
            tokens += check.completion_tokens
            text = verified_notes(text, statuses, presentation != "verify")
        if presentation in ("commit", "commit-verify"):
            # turn 1 is the C0 audit (shared with the cache); turn 2 brings the notes
            first = client.chat(evidence_prompt(f, ""), kind="evidence_C0", max_tokens=max_tokens)
            statuses = {"initial_verdict": parse_verdict(first.text), "verification": statuses}
            legend = _OBLIGATION_LEGEND + (_VERIFIED_LEGEND if presentation == "commit-verify" else "")
            followup = _COMMIT_FOLLOWUP.format(legend=legend, notes=text)
            messages = evidence_prompt(f, "") + [{"role": "assistant", "content": first.text},
                                                 {"role": "user", "content": followup}]
            reply = client.chat(messages, kind=f"evidence_{cond}", max_tokens=max_tokens)
        else:
            reply = client.chat(evidence_prompt(f, text, presentation), kind=f"evidence_{cond}",
                                max_tokens=max_tokens)
        verdict, error = parse_verdict(reply.text), None
        reasoning, tokens = reply.text, tokens + reply.completion_tokens
    except Exception as e:  # keep the study running; failures are reported
        verdict, error, reasoning, tokens = None, f"{type(e).__name__}: {e}", "", 0
    predicted = None if verdict is None else int(verdict == "VULNERABLE")
    return {"model": model, "condition": cond, "presentation": presentation, "pair_id": f.pair_id,
            "target": f.target, "project": f.project,
            "cwe": list(f.cwe), "verdict": verdict, "correct": predicted == f.target, "reasoning": reasoning,
            "completion_tokens": tokens, "truncated": tokens >= max_tokens, "error": error,
            "verification": statuses}


def summarize(records: list[dict], evidence: dict[int, PairEvidence]) -> dict:
    # API failures are missing data, not wrong answers
    R = {(r["model"], r["condition"], r["pair_id"], r["target"]): r for r in records if not r.get("error")}
    models = sorted({r["model"] for r in records}, key=list(MODELS).index)
    out = {}
    for m in models:
        rows = {}
        for c in CONDITIONS:
            funcs = [(p, t) for p in evidence for t in (1, 0) if (m, c, p, t) in R]
            if not funcs:
                continue
            base = [(p, t) for p, t in funcs if (m, "C0", p, t) in R]
            correct = sum(R[(m, c, p, t)]["correct"] for p, t in funcs)
            row = {"functions": len(funcs), "accuracy": correct / len(funcs),
                   "accuracy_ci": wilson(correct, len(funcs)),
                   "no_verdict": sum(R[(m, c, p, t)]["verdict"] is None for p, t in funcs),
                   "truncated": sum(bool(R[(m, c, p, t)].get("truncated")) for p, t in funcs)}
            pairs = [p for p in evidence if (m, c, p, 1) in R and (m, c, p, 0) in R]
            if pairs:
                pc = [R[(m, c, p, 1)]["verdict"] == "VULNERABLE" and R[(m, c, p, 0)]["verdict"] == "SAFE"
                      for p in pairs]
                row["pairs"], row["pair_correct"] = len(pairs), sum(pc)
                row["both_vulnerable"] = sum(R[(m, c, p, 1)]["verdict"] == "VULNERABLE"
                                             and R[(m, c, p, 0)]["verdict"] == "VULNERABLE" for p in pairs)
                row["both_safe"] = sum(R[(m, c, p, 1)]["verdict"] == "SAFE"
                                       and R[(m, c, p, 0)]["verdict"] == "SAFE" for p in pairs)
            if c != "C0" and base:
                flips = Counter()
                for p, t in base:
                    before, after = R[(m, "C0", p, t)], R[(m, c, p, t)]
                    if before["verdict"] != after["verdict"]:
                        flips["to_right" if after["correct"] else "to_wrong"] += 1
                b = sum(1 for p, t in base if R[(m, "C0", p, t)]["correct"] and not R[(m, c, p, t)]["correct"])
                g = sum(1 for p, t in base if not R[(m, "C0", p, t)]["correct"] and R[(m, c, p, t)]["correct"])
                row["vs_C0"] = {"functions": len(base), "C0_accuracy": sum(R[(m, "C0", p, t)]["correct"]
                                                                         for p, t in base) / len(base),
                                "flips_to_right": flips["to_right"], "flips_to_wrong": flips["to_wrong"],
                                "mcnemar_p": mcnemar_exact(b, g)}
                if c in ("C4", "C5"):
                    # deference: share of functions C0 judged correctly whose verdict follows the false evidence
                    was_right = [(p, t) for p, t in base if R[(m, "C0", p, t)]["correct"]]
                    followed = sum(1 for p, t in was_right if not R[(m, c, p, t)]["correct"])
                    row["deference"] = {"C0_correct": len(was_right), "followed_false_evidence": followed,
                                        "rate": followed / len(was_right) if was_right else None}
            rows[c] = row
        out[m] = rows
    return out


def to_markdown(summary: dict) -> str:
    lines = ["| model | cond | functions | no verdict | accuracy (95% CI) | pair-correct / pairs | both V / both S | "
             "vs C0: acc C0 -> cond, flips right/wrong, McNemar p | deference to false evidence |",
             "|---|---|---|---|---|---|---|---|---|"]
    for m, rows in summary.items():
        for c, r in rows.items():
            lo, hi = r["accuracy_ci"]
            pc = f"{r['pair_correct']} / {r['pairs']}" if "pairs" in r else "-"
            bb = f"{r['both_vulnerable']} / {r['both_safe']}" if "pairs" in r else "-"
            vs = r.get("vs_C0")
            vs_text = (f"{vs['C0_accuracy']:.2f} -> {r['accuracy']:.2f}, {vs['flips_to_right']}/"
                       f"{vs['flips_to_wrong']}, p={vs['mcnemar_p']:.3f}") if vs else "-"
            d = r.get("deference")
            d_text = f"{d['followed_false_evidence']}/{d['C0_correct']} ({d['rate']:.0%})" if d and d["rate"] is not None \
                else "-"
            lines.append(f"| {m} | {c} | {r['functions']} | {r['no_verdict']} | {r['accuracy']:.2f} ({lo:.2f}, "
                         f"{hi:.2f}) | {pc} | {bb} | {vs_text} | {d_text} |")
    return "\n".join(lines)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data/primevul/primevul_test_paired.jsonl")
    ap.add_argument("--pairs", type=int, default=60, help="0 = all eligible pairs")
    ap.add_argument("--max-lines", type=int, default=150)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--models", default="flash")
    ap.add_argument("--conditions", default=",".join(CONDITIONS))
    ap.add_argument("--presentation", choices=PRESENTATIONS, default="plain")
    ap.add_argument("--heldout", action="store_true",
                    help="confirmatory set: all pairs disjoint from the study set (any CWE, up to --max-lines)")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--cache", default="results/llm_cache.sqlite")
    ap.add_argument("--out", default="results/evidence_pilot")
    ap.add_argument("--dry-run", action="store_true", help="build and save the evidence only")
    args = ap.parse_args(argv)

    all_pairs = load_pairs(args.data)
    n = args.pairs or len(all_pairs)
    if args.heldout:
        pairs = select_heldout(all_pairs, args.max_lines)
    else:
        pairs = select_pairs(all_pairs, n, args.seed, args.max_lines)
    evidence = {v.pair_id: build_evidence(v, p) for v, p in pairs}
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "evidence.jsonl"), "w", encoding="utf-8") as fh:
        for pid, ev in evidence.items():
            fh.write(json.dumps({"pair_id": pid, "info": ev.info,
                                 "texts": {f"{t}:{c}": x for (t, c), x in ev.texts.items()}},
                                ensure_ascii=False) + "\n")
    coverage = {c: sum(1 for ev in evidence.values() for t in (1, 0) if ev.texts.get((t, c)) is not None)
                for c in CONDITIONS}
    print(f"pairs: {len(pairs)}; functions with evidence per condition: {coverage}")
    if args.dry_run:
        return

    conds = [c.strip() for c in args.conditions.split(",") if c.strip()]
    cache = ResponseCache(args.cache)
    jobs = []
    for m in [x.strip() for x in args.models.split(",") if x.strip()]:
        api_model, max_tokens, extra, (base_url, key_env, key_file) = MODELS[m]
        client = OpenAICompatibleClient(api_model, base_url, api_key(key_env, key_file), cache, timeout=1200,
                                        extra=extra)
        for c in conds:
            for ev in evidence.values():
                for f in (ev.vuln, ev.patched):
                    text = ev.texts.get((f.target, c))
                    if text is not None and (text or args.presentation == "plain"):
                        jobs.append((client, max_tokens, m, c, f, text, args.presentation))
    print(f"jobs: {len(jobs)}", flush=True)
    records = []
    path = os.path.join(args.out, "records.jsonl")
    fatal = None
    with open(path, "w", encoding="utf-8") as fh, ThreadPoolExecutor(args.workers) as pool:
        futures = [pool.submit(run_job, *job) for job in jobs]
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            if r["error"] and _FATAL.search(r["error"]):
                fatal = r["error"]
                for other in futures:
                    other.cancel()
                continue  # failed jobs are not recorded; a rerun picks them up
            records.append(r)
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            fh.flush()
            if i % 50 == 0 or i == len(jobs):
                print(f"[{i}/{len(jobs)}] done", flush=True)
    if fatal:
        raise SystemExit(f"Stopped: the API refused further calls ({fatal[:200]}). {len(records)} results were "
                         f"saved and every completed call is cached; top up / fix the key and rerun the same "
                         f"command to resume.")
    summary = summarize(records, evidence)
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    table = to_markdown(summary)
    with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(table + "\n")
    print(table)


if __name__ == "__main__":
    main()
