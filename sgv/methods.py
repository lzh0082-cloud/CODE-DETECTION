"""The compared methods: baselines B0-B4 and SGV with its ablations A1-A7."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace

from . import prompts
from .analysis import ProgramAnalysis
from .claims import ALL_VIEWS, parse_claims
from .data import Sample, canonical, is_correct, parse_answer
from .serialize import program_context, program_dump
from .verifier import CONTRADICTED, verify

GEN_TOKENS = 2048
EXTRACT_TOKENS = 2048


@dataclass(frozen=True)
class MethodConfig:
    name: str
    kind: str                  # direct | cot | self_consistency | self_refine | fullstruct | sgv
    description: str = ""
    max_rounds: int = 2        # SGV: maximum number of repair rounds
    repair: bool = True        # SGV: repair contradicted claims (False = detect only)
    router: bool = True        # SGV: repair context only from the views the claims were routed to
    slicing: bool = True       # SGV: restrict repair context to the backward slice around cited lines
    repair_cot: bool = True    # SGV: repair by re-tracing step by step
    views: frozenset = ALL_VIEWS
    sc_samples: int = 5
    sc_temperature: float = 0.7
    max_claims: int = 15


_SGV = MethodConfig("SGV", "sgv", "extract -> route -> verify -> sliced repair (full method)")

METHODS = {m.name: m for m in [
    MethodConfig("B0", "direct", "direct answer"),
    MethodConfig("B1", "cot", "chain of thought"),
    MethodConfig("B2", "self_consistency", "CoT, 5 samples at T=0.7, majority vote"),
    MethodConfig("B3", "self_refine", "CoT + one self-review/revise round"),
    MethodConfig("B4", "fullstruct", "CoT with AST+CFG+DFG dump in the prompt"),
    _SGV,
    replace(_SGV, name="A1", router=False, description="SGV without router (all views in repair context)"),
    replace(_SGV, name="A2", slicing=False, description="SGV without slicing (whole-function views)"),
    replace(_SGV, name="A3", repair=False, description="SGV detect only (no repair)"),
    replace(_SGV, name="A4", repair_cot=False, description="SGV repair without step-by-step re-tracing"),
    replace(_SGV, name="A5", views=frozenset({"ast"}), description="SGV, AST view only"),
    replace(_SGV, name="A6", views=frozenset({"cfg"}), description="SGV, CFG view only"),
    replace(_SGV, name="A7", views=frozenset({"dfg"}), description="SGV, DFG view only"),
]}


class _Trace:
    """Counts calls and tokens of one method run."""

    def __init__(self, llm):
        self.llm = llm
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    def chat(self, messages, kind, **kwargs) -> str:
        r = self.llm.chat(messages, kind=kind, **kwargs)
        self.calls += 1
        self.prompt_tokens += r.prompt_tokens
        self.completion_tokens += r.completion_tokens
        return r.text


def _direct(cfg, sample, fa, t):
    text = t.chat(prompts.direct(sample), "direct", max_tokens=512)
    return parse_answer(text), {"response": text}


def _cot(cfg, sample, fa, t):
    text = t.chat(prompts.cot(sample), "cot", max_tokens=GEN_TOKENS)
    return parse_answer(text), {"response": text}


def _self_consistency(cfg, sample, fa, t):
    answers = [parse_answer(t.chat(prompts.cot(sample), "cot_sample", temperature=cfg.sc_temperature, sample=i,
                                   max_tokens=GEN_TOKENS))
               for i in range(cfg.sc_samples)]
    votes = Counter(canonical(a) for a in answers if a is not None)
    if not votes:
        return None, {"votes": answers}
    top = votes.most_common(1)[0][0]
    return next(a for a in answers if a is not None and canonical(a) == top), {"votes": answers}


def _self_refine(cfg, sample, fa, t):
    first = t.chat(prompts.cot(sample), "cot", max_tokens=GEN_TOKENS)
    second = t.chat(prompts.self_refine(sample, first), "refine", max_tokens=GEN_TOKENS)
    initial = parse_answer(first)
    return parse_answer(second) or initial, {
        "initial_answer": initial, "initial_correct": is_correct(initial, sample.output), "response": second}


def _fullstruct(cfg, sample, fa, t):
    text = t.chat(prompts.fullstruct(sample, program_dump(fa)), "cot_struct", max_tokens=GEN_TOKENS)
    return parse_answer(text), {"response": text}


def _check(cfg, sample, fa, t, reasoning):
    """Extract claims from `reasoning` and verify them. Returns (round record, verdicts)."""
    raw = t.chat(prompts.extract(sample, reasoning, cfg.max_claims), "extract", max_tokens=EXTRACT_TOKENS)
    try:
        claims = parse_claims(raw, cfg.max_claims)
        error = None
    except ValueError as e:
        claims, error = [], str(e)
    verdicts = [verify(c, fa, cfg.views) for c in claims]
    return {"reasoning": reasoning, "answer": parse_answer(reasoning), "extract_error": error,
            "verdicts": [v.to_dict() for v in verdicts]}, verdicts


def _sgv(cfg, sample, fa, t):
    reasoning = t.chat(prompts.cot(sample), "cot", max_tokens=GEN_TOKENS)  # identical to B1
    initial = parse_answer(reasoning)
    answer = initial
    rounds = []
    for r in range(cfg.max_rounds + 1):
        record, verdicts = _check(cfg, sample, fa, t, reasoning)
        rounds.append(record)
        contradicted = [v for v in verdicts if v.status == CONTRADICTED]
        if not contradicted or not cfg.repair or r == cfg.max_rounds:
            break
        context = program_context(fa, [v.claim for v in contradicted], router=cfg.router, slicing=cfg.slicing,
                                  views=cfg.views)
        reasoning = t.chat(prompts.repair(sample, reasoning, contradicted, context, cfg.repair_cot), "repair",
                           max_tokens=GEN_TOKENS)
        answer = parse_answer(reasoning) or answer
    return answer, {"initial_answer": initial, "initial_correct": is_correct(initial, sample.output),
                    "repaired": len(rounds) > 1, "rounds": rounds}


_RUNNERS = {"direct": _direct, "cot": _cot, "self_consistency": _self_consistency, "self_refine": _self_refine,
            "fullstruct": _fullstruct, "sgv": _sgv}


def run_method(cfg: MethodConfig, sample: Sample, fa: ProgramAnalysis, llm) -> dict:
    t = _Trace(llm)
    record = {"id": sample.id, "method": cfg.name, "gold": sample.output}
    try:
        answer, extra = _RUNNERS[cfg.kind](cfg, sample, fa, t)
        record.update(answer=answer, correct=is_correct(answer, sample.output), **extra)
    except Exception as e:  # keep the run going; the error is reported in the summary
        record.update(answer=None, correct=False, error=f"{type(e).__name__}: {e}")
    record.update(calls=t.calls, prompt_tokens=t.prompt_tokens, completion_tokens=t.completion_tokens)
    return record
