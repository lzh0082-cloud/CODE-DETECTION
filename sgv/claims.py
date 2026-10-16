"""The claim language: a fixed set of predicates that free-text reasoning about
a function is normalised into, so that each claim can be checked mechanically.

Each predicate belongs to exactly one structural view (ast / cfg / dfg); the
verifier routes a claim to that view. Static predicates state facts about the
program text that hold for every input; dynamic predicates state what happens
during the traced call. The static verifier decides dynamic claims only where
the structure settles them on every execution, otherwise they stay
UNVERIFIABLE (execution traces can label them for evaluation). `free` collects
everything else (API semantics, the final result, ...).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

VIEWS = ("ast", "cfg", "dfg")
ALL_VIEWS = frozenset(VIEWS)


@dataclass(frozen=True)
class Predicate:
    name: str
    view: str              # ast | cfg | dfg | none
    args: tuple[str, ...]  # a trailing `?` marks an optional argument
    meaning: str
    dynamic: bool = False  # about the traced call rather than the program text

    @property
    def required(self) -> list[str]:
        return [a for a in self.args if not a.endswith("?")]


PREDICATES = {p.name: p for p in [
    Predicate("is_parameter", "ast", ("var",), "`var` is a parameter of the function"),
    Predicate("var_defined", "ast", ("var",),
              "`var` is a parameter or is assigned/bound somewhere in the function"),
    Predicate("calls", "ast", ("name", "line?"),
              "the code contains a call of the function or method `name` (e.g. 'sorted', 'append', 'nums.count') "
              "[in the statement at `line`]; whether it runs in this call is `invokes`"),
    Predicate("method_exists", "ast", ("type", "method"),
              "the built-in type `type` (str/list/dict/set/tuple/int/float/bytes) has a method `method`"),
    Predicate("loop_iterates_over", "ast", ("loop_line", "var"),
              "the for-loop header at `loop_line` iterates over an expression that uses `var`"),
    Predicate("condition_uses", "ast", ("line", "var"), "the if/while condition at `line` reads `var`"),
    Predicate("in_loop", "cfg", ("line", "loop_line?"),
              "the statement at `line` is inside the body of a loop [the loop whose header is at `loop_line`]"),
    Predicate("in_branch", "cfg", ("line", "if_line", "branch"),
              "the statement at `line` is inside the true arm (`branch`: true) or the false/else arm "
              "(`branch`: false) of the if/elif at `if_line`"),
    Predicate("reachable", "cfg", ("line",), "the statement at `line` can be reached at all (false = dead code)"),
    Predicate("can_follow", "cfg", ("line", "after_line"),
              "control can flow from the statement at `after_line` to the statement at `line`"),
    Predicate("returns_at", "cfg", ("line",), "the statement at `line` is a return statement"),
    Predicate("loop_has_early_exit", "cfg", ("loop_line",),
              "the loop at `loop_line` contains a break/return/raise that can leave it early"),
    Predicate("def_reaches", "dfg", ("var", "def_line", "use_line"),
              "the value written to `var` at `def_line` can be the value read at `use_line`"),
    Predicate("modified_in_loop", "dfg", ("var", "loop_line"),
              "`var` is reassigned or modified in place inside the loop at `loop_line`"),
    Predicate("modified_after", "dfg", ("var", "line"),
              "`var` can be reassigned or modified in place after the statement at `line` executes"),
    Predicate("mutated_at", "dfg", ("var", "line"), "the statement at `line` reassigns or modifies `var` in place"),
    Predicate("affects_return", "dfg", ("var",), "the value of `var` can influence the returned value"),
    Predicate("value_at", "dfg", ("var", "line", "value"),
              "right after the statement at `line` first executes, `var` equals the Python literal `value`"),
    Predicate("executes", "cfg", ("line",), "during this call, the statement at `line` executes", dynamic=True),
    Predicate("branch_taken", "cfg", ("if_line", "branch"),
              "during this call, the if/elif at `if_line` takes its true (`branch`: true) or false arm",
              dynamic=True),
    Predicate("loop_iterations", "cfg", ("loop_line", "count"),
              "during this call, the body of the loop at `loop_line` runs `count` times (for a nested loop: in "
              "the execution the reasoning talks about)", dynamic=True),
    Predicate("next_line", "cfg", ("line", "next"),
              "during this call, right after the statement at `line` executes, the next statement executed is "
              "at line `next` (use 0 for leaving the function)", dynamic=True),
    Predicate("invokes", "cfg", ("name",),
              "during this call, the function `name` defined in this code is actually called at least once",
              dynamic=True),
    Predicate("state_after", "dfg", ("var", "line", "value"),
              "during this call, right after the statement at `line` executes, `var` equals the Python literal "
              "`value` (at least once)", dynamic=True),
    Predicate("free", "none", (),
              "any other assertion (parameter values at the call, library behaviour, final result, ...)"),
]}


def catalogue() -> str:
    static = [p for p in PREDICATES.values() if not p.dynamic and p.view != "none"]
    dynamic = [p for p in PREDICATES.values() if p.dynamic]
    other = [p for p in PREDICATES.values() if p.view == "none"]

    def fmt(ps):
        return "\n".join(f"- {p.name}({', '.join(p.args)}): {p.meaning}" for p in ps)

    return (f"Static (true of the program text for every input):\n{fmt(static)}\n\n"
            f"Dynamic (what happens during this particular call):\n{fmt(dynamic)}\n\n"
            f"Other:\n{fmt(other)}")


@dataclass
class Claim:
    id: int
    text: str
    predicate: str
    args: dict = field(default_factory=dict)
    holds: bool = True

    @property
    def view(self) -> str:
        p = PREDICATES.get(self.predicate)
        return p.view if p else "none"

    @property
    def dynamic(self) -> bool:
        p = PREDICATES.get(self.predicate)
        return bool(p and p.dynamic)

    def to_dict(self) -> dict:
        return {"id": self.id, "text": self.text, "predicate": self.predicate, "args": self.args,
                "holds": self.holds, "view": self.view, "dynamic": self.dynamic}


def _json_array(text: str) -> list:
    candidates = [m.group(1) for m in re.finditer(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.S)]
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        candidates.append(text[start:end + 1])
    for cand in candidates:
        try:
            value = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            return value
    raise ValueError("no JSON array found in extractor output")


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("false", "0", "no", "f")


def parse_claims(text: str, max_claims: int = 30) -> list[Claim]:
    """Parse the extractor's JSON output. Raises ValueError if it is not a JSON array."""
    claims = []
    for item in _json_array(text)[:max_claims]:
        if not isinstance(item, dict):
            continue
        predicate = str(item.get("predicate", "free")).strip()
        args = item.get("args") if isinstance(item.get("args"), dict) else {}
        claims.append(Claim(id=len(claims), text=str(item.get("text", "")).strip(), predicate=predicate,
                            args=args, holds=_as_bool(item.get("holds", True))))
    return claims
