"""All prompts. Each builder returns an OpenAI-style message list.

SGV's first generation uses exactly the `cot` prompt, so it shares the B1
(CoT) response through the cache and the comparison is paired.
"""
from __future__ import annotations

from .claims import catalogue
from .serialize import numbered

SOLVER_SYSTEM = "You are an expert Python programmer who reasons precisely about program execution."
EXTRACTOR_SYSTEM = (
    "You convert free-text reasoning about a Python function into atomic claims in a fixed predicate "
    "language. You never judge whether a claim is true; you only record what the reasoning asserts."
)
ANSWER_FORMAT = "[ANSWER] <the return value as a Python literal>"


def _task(sample) -> str:
    return (
        "Line numbers are shown for reference only; they are not part of the code.\n\n"
        f"```python\n{numbered(sample.code)}\n```\n\n"
        f"Call: {sample.call_expr}"
    )


def _messages(user: str, system: str = SOLVER_SYSTEM) -> list[dict]:
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def direct(sample) -> list[dict]:
    return _messages(
        f"Predict the exact value returned by the call below.\n\n{_task(sample)}\n\n"
        f"Reply with a single line:\n{ANSWER_FORMAT}"
    )


_COT_INSTRUCTIONS = (
    "Think step by step: trace the execution statement by statement, citing line numbers (e.g. 'line 4') "
    "and stating the values of variables as they change. Then finish with a final line:\n" + ANSWER_FORMAT
)


def cot(sample) -> list[dict]:
    return _messages(f"Predict the exact value returned by the call below.\n\n{_task(sample)}\n\n{_COT_INSTRUCTIONS}")


def fullstruct(sample, dump: str) -> list[dict]:
    return _messages(
        f"Predict the exact value returned by the call below.\n\n{_task(sample)}\n\n"
        f"Static analysis of the function (syntax tree, control-flow and data-flow views):\n{dump}\n\n"
        f"{_COT_INSTRUCTIONS}"
    )


SELF_REFINE = (
    "Review your reasoning above line by line against the code. Look for misread statements, wrong control "
    "flow (which statements are inside which loop or branch), wrong data flow (which assignment a variable's "
    "value comes from) and wrong values. Then write corrected step-by-step reasoning and finish with a final "
    "line:\n" + ANSWER_FORMAT
)


def self_refine(sample, first_response: str) -> list[dict]:
    return cot(sample) + [{"role": "assistant", "content": first_response},
                          {"role": "user", "content": SELF_REFINE}]


def extract(sample, reasoning: str, max_claims: int) -> list[dict]:
    return _messages(
        f"Function (line numbers for reference):\n```python\n{numbered(sample.code)}\n```\n\n"
        f"Call being traced: {sample.call_expr}\n\n"
        f"Reasoning to convert:\n\"\"\"\n{reasoning}\n\"\"\"\n\n"
        f"Predicates (arguments in parentheses; `?` = optional):\n{catalogue()}\n\n"
        "Instructions:\n"
        "- Record each assertion the reasoning makes, or clearly relies on, about the program or this call. Use a "
        "predicate whenever the assertion (or part of it) can be expressed by one.\n"
        "- Static predicates are only for facts about the code that hold for every input, e.g. \"after the loop "
        "finishes, line 5 sorts the list\" asserts in_loop(line=5) with holds=false.\n"
        "- What happens in this particular call uses dynamic predicates, e.g. \"the list is empty so the loop "
        "body never runs\" is loop_iterations(loop_line=3, count=0); \"we skip the else branch\" is "
        "branch_taken(if_line=2, branch=false) with holds=false; \"line 6 is not reached\" is executes(line=6) "
        "with holds=false; \"now total is 5\" after line 4 is state_after(var=total, line=4, value=5).\n"
        "- Use holds=false for negated assertions (\"x is not changed after line 4\").\n"
        "- Line numbers refer to the listing above and must point at a statement (not at the `def` line or at a "
        "bare `else:`). Use the line the reasoning refers to; never correct the reasoning.\n"
        "- Parameter values at the call, library behaviour and the final result go to `free`.\n"
        "- Write every `value` as a Python literal inside a JSON string, e.g. \"value\": \"[(1, 3), 'a']\".\n"
        f"- At most {max_claims} claims; skip repetitions.\n\n"
        "Return only a JSON array, no prose:\n"
        '[{"text": "<short quote or paraphrase>", "predicate": "<name>", "args": {...}, "holds": true}]',
        system=EXTRACTOR_SYSTEM,
    )


def repair(sample, reasoning: str, verdicts, context: str, step_by_step: bool = True) -> list[dict]:
    flagged = []
    for i, v in enumerate(verdicts, 1):
        args = ", ".join(f"{k}={val}" for k, val in v.claim.args.items())
        negation = "" if v.claim.holds else "NOT "
        flagged.append(f"{i}. You claimed: \"{v.claim.text}\"  [{negation}{v.claim.predicate}({args})]\n"
                       f"   Program fact: {v.evidence}")
    if step_by_step:
        instructions = (
            "Trace the execution again from the start, step by step, citing line numbers and correcting the errors "
            "above. The analyzer only reasons about program structure and may have misread what you meant; if you "
            "are sure a flagged statement was correct, say why and keep it. Finish with a final line:\n"
            + ANSWER_FORMAT
        )
    else:
        instructions = f"Taking these facts into account, give the corrected return value. Reply with a single line:\n{ANSWER_FORMAT}"
    return _messages(
        f"You predicted the return value of this call:\n\n{_task(sample)}\n\n"
        f"Your previous reasoning:\n\"\"\"\n{reasoning}\n\"\"\"\n\n"
        "A static analyzer checked the structural claims in your reasoning against the program's syntax tree, "
        "control-flow graph and data-flow graph. These claims contradict the program:\n"
        + "\n".join(flagged)
        + f"\n\nRelevant program structure:\n{context}\n\n{instructions}"
    )
