"""Route each claim to the structural view that can decide it and check it.

Statuses:
  SUPPORTED     - the static facts agree with the claim
  CONTRADICTED  - the static facts refute the claim (triggers repair)
  UNVERIFIABLE  - the program text cannot decide it, or its view is disabled
  INVALID       - the claim is malformed or cites a line/construct that does not
                  exist (most often an extraction slip, so it does not trigger repair)

Checks are one-directional where the program text alone cannot settle a claim:
CONTRADICTED is only reported when the claim is false on every execution.
"""
from __future__ import annotations

import ast
import keyword
from dataclasses import dataclass

from .analysis import FunctionAnalysis, Node
from .claims import ALL_VIEWS, PREDICATES, Claim
from .literals import claimed_matches

SUPPORTED, CONTRADICTED, UNVERIFIABLE, INVALID = "SUPPORTED", "CONTRADICTED", "UNVERIFIABLE", "INVALID"

_BUILTIN_TYPES = {"str": str, "list": list, "dict": dict, "set": set, "tuple": tuple, "int": int,
                  "float": float, "bytes": bytes, "frozenset": frozenset, "bool": bool}


@dataclass
class Verdict:
    claim: Claim
    status: str
    view: str
    evidence: str

    def to_dict(self) -> dict:
        return {**self.claim.to_dict(), "status": self.status, "evidence": self.evidence}


class _Invalid(Exception):
    pass


# -- argument helpers ----------------------------------------------------

def _int(args: dict, key: str, optional: bool = False) -> int | None:
    value = args.get(key)
    if value is None or value == "":
        if optional:
            return None
        raise _Invalid(f"missing argument `{key}`")
    try:
        return int(str(value).strip().lstrip("Ll"))
    except ValueError:
        raise _Invalid(f"`{key}` is not a line number: {value!r}") from None


def _str(args: dict, key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _Invalid(f"missing argument `{key}`")
    return value.strip().strip("`")


def _bool(args: dict, key: str) -> bool:
    value = args.get(key)
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "t", "yes", "if", "then", "1"):
        return True
    if text in ("false", "f", "no", "else", "0"):
        return False
    raise _Invalid(f"`{key}` must be true or false, got {value!r}")


def _at(fa: FunctionAnalysis, line: int) -> list[Node]:
    nodes = fa.nodes_at(line)
    if not nodes:
        raise _Invalid(f"line {line} holds no statement of `{fa.name}`")
    return nodes


def _header(fa: FunctionAnalysis, line: int, kinds: set[str], what: str) -> Node:
    nodes = _at(fa, line)
    for n in nodes:
        if n.kind in kinds:
            return n
    raise _Invalid(f"line {line} is not {what} (it is `{nodes[0].text}`)")


def _labels(fa: FunctionAnalysis, ids) -> str:
    lines = fa.lines_of(ids)
    return ", ".join(f"L{x}" for x in lines) if lines else "nowhere"


def _describe_enclosing(fa: FunctionAnalysis, node: Node) -> str:
    parts = [f"loop at L{fa.nodes[h].line}" for h in node.loops]
    parts += [f"{'true' if arm else 'false'} arm of `{fa.nodes[i].text}` (L{fa.nodes[i].line})"
              for i, arm in node.branches]
    return "; ".join(parts) if parts else "top level of the function body (not inside any loop or branch)"


# -- checks: each returns (truth or None, evidence) -----------------------

def _is_parameter(fa, a):
    var = _str(a, "var")
    return var in fa.params, f"parameters of `{fa.name}`: {', '.join(fa.params) or 'none'}"


def _var_defined(fa, a):
    var = _str(a, "var")
    bound = fa.bound_names
    if var in bound:
        where = _labels(fa, [n.id for n in fa.statements if var in n.defs])
        return True, f"`{var}` is {'a parameter' if var in fa.params else 'bound at ' + where}"
    return False, f"`{var}` is never bound in `{fa.name}`; bound names: {', '.join(sorted(bound))}"


def _calls(fa, a):
    name = _str(a, "name").rstrip("()")
    if keyword.iskeyword(name.split(".")[-1]):
        raise _Invalid(f"`{name}` is a keyword, not a callable")
    line = _int(a, "line", optional=True)
    nodes = _at(fa, line) if line is not None else fa.statements
    called = set().union(*(fa.calls(n) for n in nodes)) if nodes else set()
    attr = name.split(".")[-1]
    prefix = name.rsplit(".", 1)[0] if "." in name else None
    truth = name in called or (prefix in _BUILTIN_TYPES and attr in called) or (prefix is None and attr in called)
    scope = f"the statement at L{line}" if line is not None else f"`{fa.name}`"
    return truth, f"calls made in {scope}: {', '.join(sorted(called)) or 'none'}"


def _method_exists(fa, a):
    type_name, method = _str(a, "type"), _str(a, "method").rstrip("()")
    t = _BUILTIN_TYPES.get(type_name)
    if t is None:
        return None, f"`{type_name}` is not a built-in type the verifier knows"
    truth = hasattr(t, method)
    return truth, f"`{type_name}` {'has' if truth else 'has no'} method `{method}`"


def _loop_iterates_over(fa, a):
    h = _header(fa, _int(a, "loop_line"), {"for"}, "a for-loop header")
    var = _str(a, "var")
    if var in h.defs:
        return None, f"`{var}` is the loop variable of `{h.text}`"  # "for i in ..." read as iterating over i
    return var in h.uses, f"L{h.line}: `{h.text}`"


def _condition_uses(fa, a):
    h = _header(fa, _int(a, "line"), {"if", "while"}, "an if/while condition")
    var = _str(a, "var")
    return var in h.uses, f"L{h.line}: `{h.text}` reads {', '.join(sorted(h.uses)) or 'nothing'}"


def _deepest(nodes: list[Node]) -> Node:
    """On a line holding several statements (e.g. `for x in xs: total += x`), the innermost one."""
    return max(nodes, key=lambda n: len(n.loops) + len(n.branches))


def _in_loop(fa, a):
    nodes = _at(fa, _int(a, "line"))
    node = _deepest(nodes)
    loop_line = _int(a, "loop_line", optional=True)
    where = f"L{node.line} `{node.text}` is at: {_describe_enclosing(fa, node)}"
    if loop_line is None:
        return any(n.loops for n in nodes), where
    h = _header(fa, loop_line, {"for", "while"}, "a loop header")
    return any(h.id in n.loops for n in nodes), where


def _in_branch(fa, a):
    nodes = _at(fa, _int(a, "line"))
    h = _header(fa, _int(a, "if_line"), {"if"}, "an if/elif")
    arm = _bool(a, "branch")
    node = _deepest(nodes)
    return any((h.id, arm) in n.branches for n in nodes), \
        f"L{node.line} `{node.text}` is at: {_describe_enclosing(fa, node)}"


def _reachable(fa, a):
    nodes = _at(fa, _int(a, "line"))
    truth = any(n.id in fa.reachable for n in nodes)
    return truth, f"L{nodes[0].line} is {'reachable' if truth else 'unreachable (dead code)'} in the CFG"


def _can_follow(fa, a):
    srcs = _at(fa, _int(a, "after_line"))
    dsts = _at(fa, _int(a, "line"))
    truth = any(d.id in fa.after(s.id) for s in srcs for d in dsts)
    successors = ", ".join(sorted({fa.nodes[d].label for s in srcs for d in fa.succ[s.id]}))
    return truth, (f"there is {'a' if truth else 'no'} control-flow path from L{srcs[0].line} to L{dsts[0].line}; "
                   f"L{srcs[0].line} is directly followed by {successors}")


def _returns_at(fa, a):
    nodes = _at(fa, _int(a, "line"))
    truth = any(n.kind == "return" for n in nodes)
    returns = _labels(fa, [n.id for n in fa.return_nodes])
    return truth, f"L{nodes[0].line} is `{nodes[0].text}`; return statements are at {returns}"


def _loop_has_early_exit(fa, a):
    h = _header(fa, _int(a, "loop_line"), {"for", "while"}, "a loop header")
    exits = [m for m in fa.loop_members.get(h.id, ())
             if fa.nodes[m].kind in ("return", "raise")
             or (fa.nodes[m].kind == "break" and fa.nodes[m].break_target == h.id)]
    if exits:
        return True, f"the loop at L{h.line} can be left early at {_labels(fa, exits)}"
    return False, f"the loop at L{h.line} has no break/return/raise; it always runs to completion"


def _def_reaches(fa, a):
    var = _str(a, "var")
    def_line, use_line = _int(a, "def_line"), _int(a, "use_line")
    defs = [n for n in _at(fa, def_line) if var in n.writes]
    if not defs:
        return False, f"L{def_line} (`{fa.nodes_at(def_line)[0].text}`) does not write `{var}`"
    uses = [n for n in _at(fa, use_line) if var in n.uses | n.mutates]
    if not uses:
        return False, f"L{use_line} (`{fa.nodes_at(use_line)[0].text}`) does not read `{var}`"
    def_ids = {d.id for d in defs}
    truth = any(src in def_ids for u in uses for src, v in fa.dfg_in[u.id] if v == var)
    reaching = _labels(fa, [src for u in uses for src, v in fa.dfg_in[u.id] if v == var])
    return truth, f"the values of `{var}` read at L{use_line} can come from: {reaching}"


def _writers(fa, var, ids):
    return [i for i in ids if var in fa.nodes[i].writes]


def _modified_in_loop(fa, a):
    var = _str(a, "var")
    h = _header(fa, _int(a, "loop_line"), {"for", "while"}, "a loop header")
    writers = _writers(fa, var, fa.loop_members.get(h.id, ()))
    if var in h.defs:
        writers.append(h.id)
    return bool(writers), f"inside the loop at L{h.line}, `{var}` is written at {_labels(fa, writers)}"


def _modified_after(fa, a):
    var = _str(a, "var")
    line = _int(a, "line")
    later = set().union(*(fa.after(n.id) for n in _at(fa, line)))
    writers = _writers(fa, var, later)
    return bool(writers), f"after L{line}, `{var}` can be written at {_labels(fa, writers)}"


def _mutated_at(fa, a):
    var = _str(a, "var")
    nodes = _at(fa, _int(a, "line"))
    truth = any(var in n.writes for n in nodes)
    writes = set().union(*(n.writes for n in nodes))
    return truth, f"L{nodes[0].line} (`{nodes[0].text}`) writes: {', '.join(sorted(writes)) or 'nothing'}"


def _affects_return(fa, a):
    var = _str(a, "var")
    rets = fa.return_nodes
    if not rets:
        return False, f"`{fa.name}` has no reachable return statement; it returns None"
    sl = fa.backward_slice([r.id for r in rets])
    truth = any(var in fa.nodes[i].writes for i in sl)
    return truth, f"the returned value depends on {_labels(fa, sl)} (backward slice from {_labels(fa, [r.id for r in rets])})"


def _literal_assignment(fa, a):
    """Decide `var == value` after `line` when that statement assigns `var` a literal."""
    var = _str(a, "var")
    line = _int(a, "line")
    raw = a.get("value")
    for n in _at(fa, line):
        stmt = n.stmt
        if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == var for t in stmt.targets):
            value_node = stmt.value
        elif (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
              and stmt.target.id == var and stmt.value is not None):
            value_node = stmt.value
        else:
            continue
        try:
            actual = ast.literal_eval(value_node)
        except (ValueError, SyntaxError, TypeError):
            return None, f"L{line} assigns `{var}` a computed value"
        return claimed_matches(raw, actual), f"L{line} sets `{var}` to the literal {actual!r}"
    return None, f"L{line} does not assign `{var}` a literal"


# Dynamic claims: decided only where the structure settles them for every input.

def _executes(fa, a):
    nodes = _at(fa, _int(a, "line"))
    if not any(n.id in fa.reachable for n in nodes):
        return False, f"L{nodes[0].line} is dead code; it never executes"
    return None, f"whether L{nodes[0].line} executes depends on the input"


def _branch_taken(fa, a):
    h = _header(fa, _int(a, "if_line"), {"if"}, "an if/elif")
    _bool(a, "branch")
    return None, f"the arm taken at L{h.line} is decided by `{h.text}` at run time"


def _loop_iterations(fa, a):
    h = _header(fa, _int(a, "loop_line"), {"for", "while"}, "a loop header")
    return None, f"the iteration count of `{h.text}` depends on the input"


def _invokes(fa, a):
    name = _str(a, "name").rstrip("()").split(".")[-1]
    referenced = set()
    for n in fa.statements:
        for expr in n.exprs:
            referenced |= {x.id for x in ast.walk(expr) if isinstance(x, ast.Name)}
            referenced |= {x.attr for x in ast.walk(expr) if isinstance(x, ast.Attribute)}
    if name not in referenced:
        return False, f"`{fa.name}` never refers to `{name}`, so it cannot call it"
    return None, f"whether `{name}` runs depends on the input"


def _next_line(fa, a):
    line, nxt = _int(a, "line"), _int(a, "next")
    nodes = _at(fa, line)
    successors = set()
    for n in nodes:
        for d in fa.succ[n.id]:
            successors.add(0 if fa.nodes[d].kind == "exit" else fa.nodes[d].line)
    listed = ", ".join("leaving the function" if s == 0 else f"L{s}" for s in sorted(successors))
    evidence = f"after L{line} control can only continue at: {listed}"
    if nxt in successors and successors == {nxt} and nxt != 0 and not fa.irregular_flow:
        return True, evidence  # the only possible continuation
    if nxt == 0 or nxt == line or nxt in successors or nxt in fa.nested_lines:
        return None, evidence
    if fa.irregular_flow and fa.def_line <= nxt <= fa.end_line:
        return None, evidence  # try/with/match emit line events the CFG does not model
    span = range(nodes[0].line, (getattr(nodes[0].stmt, "end_lineno", None) or nodes[0].line) + 1)
    if nxt in span:
        return None, evidence  # multi-line statement
    return False, evidence


_CHECKS = {
    "is_parameter": _is_parameter, "var_defined": _var_defined, "calls": _calls,
    "method_exists": _method_exists, "loop_iterates_over": _loop_iterates_over,
    "condition_uses": _condition_uses, "in_loop": _in_loop, "in_branch": _in_branch,
    "reachable": _reachable, "can_follow": _can_follow, "returns_at": _returns_at,
    "loop_has_early_exit": _loop_has_early_exit, "def_reaches": _def_reaches,
    "modified_in_loop": _modified_in_loop, "modified_after": _modified_after,
    "mutated_at": _mutated_at, "affects_return": _affects_return, "value_at": _literal_assignment,
    "executes": _executes, "branch_taken": _branch_taken, "loop_iterations": _loop_iterations,
    "next_line": _next_line, "state_after": _literal_assignment, "invokes": _invokes,
}


_LINE_ARGS = ("line", "loop_line", "if_line", "def_line", "use_line", "after_line")


def resolve_function(claim: Claim, analysis) -> FunctionAnalysis:
    """The function a claim is about: the one holding the first line it cites."""
    if isinstance(analysis, FunctionAnalysis):
        return analysis
    for key in _LINE_ARGS:
        try:
            fa = analysis.function_at(int(claim.args[key]))
        except (KeyError, TypeError, ValueError):
            continue
        if fa is not None:
            return fa
    return analysis.entry


def verify(claim: Claim, analysis, views=ALL_VIEWS) -> Verdict:
    """Check `claim` against a FunctionAnalysis or ProgramAnalysis.

    A claim that cites no line (e.g. "n is a parameter") may be about any function
    of the program: it is supported if it holds for one of them and contradicted
    only if every function refutes it."""
    if not isinstance(analysis, FunctionAnalysis) and not any(k in claim.args for k in _LINE_ARGS):
        entry = _verify_in(claim, analysis.entry, views)
        verdicts = [entry] + [_verify_in(claim, fa, views) for fa in analysis.functions.values()
                              if fa is not analysis.entry]
        supported = [v for v in verdicts if v.status == SUPPORTED]
        if supported:
            return supported[0]
        if all(v.status == CONTRADICTED for v in verdicts):
            return entry
        return next(v for v in verdicts if v.status != CONTRADICTED)
    return _verify_in(claim, resolve_function(claim, analysis), views)


def _verify_in(claim: Claim, fa: FunctionAnalysis, views) -> Verdict:
    pred = PREDICATES.get(claim.predicate)
    if pred is None:
        return Verdict(claim, INVALID, "none", f"unknown predicate `{claim.predicate}`")
    if pred.view == "none":
        return Verdict(claim, UNVERIFIABLE, "none", "not decidable from the program structure")
    if pred.view not in views:
        return Verdict(claim, UNVERIFIABLE, pred.view, f"{pred.view} view disabled")
    try:
        truth, evidence = _CHECKS[pred.name](fa, claim.args)
    except _Invalid as e:
        return Verdict(claim, INVALID, pred.view, str(e))
    if truth is None:
        return Verdict(claim, UNVERIFIABLE, pred.view, evidence)
    return Verdict(claim, SUPPORTED if truth == claim.holds else CONTRADICTED, pred.view, evidence)
