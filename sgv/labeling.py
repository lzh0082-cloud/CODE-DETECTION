"""Ground-truth labels for extracted claims (evaluation only).

* Static claims are labelled by the program facts themselves (all views on).
* Dynamic claims are labelled by the execution trace of the call.
* `free` claims and claims the evidence cannot settle stay unlabelled (None).

A claim is hallucinated when its label disagrees with what it asserts.
Labelling is conservative: whenever a claim's wording and the predicate it was
mapped to may diverge (a line with no statement, a line that never ran, a
one-line `if`), the claim is left unlabelled rather than counted as wrong.
"""
from __future__ import annotations

from collections import defaultdict

from .claims import ALL_VIEWS, PREDICATES, Claim
from .literals import claimed_matches, safe_literal
from .verifier import CONTRADICTED, SUPPORTED, resolve_function, verify


class TraceIndex:
    """Trace events grouped by (function qualname, line) and by frame, in execution order.
    Filtering by qualname keeps lambda/genexpr frames on the same line out."""

    def __init__(self, trace: dict):
        self.usable = bool(trace) and "skipped" not in trace and not trace.get("truncated")
        self._at: dict[tuple[str, int], list[dict]] = defaultdict(list)
        self.frames: dict[int, list[dict]] = defaultdict(list)
        self.funcs: set[str] = set()
        for ev in trace.get("events", []) if self.usable else []:
            self._at[(ev["func"], ev["line"])].append(ev)
            self.frames[ev["frame"]].append(ev)
            self.funcs.add(ev["func"])

    def at(self, fa, line: int) -> list[dict]:
        return self._at[(fa.qualname, line)]

    def loop_runs(self, fa, header_line: int, body_lines: set[int]) -> list[int]:
        """Iteration count of every separate execution of the loop."""
        runs = []
        for frame_events in self.frames.values():
            if not frame_events or frame_events[0]["func"] != fa.qualname:
                continue
            current = None
            prev_line = None
            for ev in frame_events:
                if ev["line"] == header_line and not ev.get("entry"):
                    if current is not None and prev_line not in body_lines:
                        runs.append(current)  # left earlier by break/return; this is a fresh entry
                        current = None
                    if current is None:
                        current = 0
                    if ev.get("next") in body_lines:
                        current += 1
                    else:  # the loop condition ended this execution
                        runs.append(current)
                        current = None
                prev_line = ev["line"]
            if current is not None:
                runs.append(current)
        return runs


def _span(stmts) -> set[int]:
    """Every source line of a statement block."""
    return set(range(stmts[0].lineno, stmts[-1].end_lineno + 1)) if stmts else set()


def _static_truth(claim: Claim, analysis) -> bool | None:
    v = verify(claim, analysis, ALL_VIEWS)
    if v.status == SUPPORTED:
        return claim.holds
    if v.status == CONTRADICTED:
        return not claim.holds
    return None


def _statement_line(fa, line: int) -> bool:
    return bool(fa.nodes_at(line))


def _dynamic_truth(claim: Claim, analysis, idx: TraceIndex) -> bool | None:
    if not idx.usable:
        return None
    a, p = claim.args, claim.predicate
    fa = resolve_function(claim, analysis)

    if p == "invokes":
        name = str(a["name"]).rstrip("()").split(".")[-1]
        defined = [q for q in getattr(analysis, "functions", {fa.qualname: fa}) if q.split(".")[-1] == name]
        if not defined:
            return None  # a builtin or library function: frames are not traced
        return any(q in idx.funcs for q in defined)

    if p == "executes":
        line = int(a["line"])
        return bool(idx.at(fa, line)) if _statement_line(fa, line) else None

    if p == "next_line":
        line, nxt = int(a["line"]), int(a["next"])
        if not _statement_line(fa, line):
            return None
        events = idx.at(fa, line)
        return any(ev["next"] == nxt for ev in events if "next" in ev) if events else None

    if p == "branch_taken":
        if_line = int(a["if_line"])
        headers = [n for n in fa.nodes_at(if_line) if n.kind == "if"]
        if not headers:
            return None
        true_lines = _span(headers[0].stmt.body)
        if if_line in true_lines:
            return None  # one-line `if c: stmt`: the arm runs without a line event of its own
        events = [ev for ev in idx.at(fa, if_line) if "next" in ev]
        if not events:
            return None
        arm = str(a["branch"]).strip().lower() in ("true", "t", "yes", "if", "then", "1")
        return arm in {ev["next"] in true_lines for ev in events}

    if p == "loop_iterations":
        loop_line = int(a["loop_line"])
        headers = [n for n in fa.nodes_at(loop_line) if n.kind in ("for", "while")]
        if not headers:
            return None
        body_lines = _span(headers[0].stmt.body)
        if loop_line in body_lines:
            return None  # one-line loop: header and body share a line
        runs = idx.loop_runs(fa, loop_line, body_lines)
        return int(a["count"]) in runs if runs else None

    if p == "state_after":
        var, line = str(a["var"]).strip("`"), int(a["line"])
        if line != fa.def_line and not _statement_line(fa, line):
            return None
        events = [ev for ev in idx.at(fa, line) if "post" in ev]
        reprs = [ev["post"][var] for ev in events if var in ev["post"]]
        if not reprs:
            return None  # the line never ran or `var` is not a plain local there
        values = []
        for r in reprs:
            ok, value = safe_literal(r)
            values.append(value if ok else r)
        return any(claimed_matches(a.get("value"), v) for v in values)
    return None


def claim_truth(claim: Claim, analysis, idx: TraceIndex) -> bool | None:
    pred = PREDICATES.get(claim.predicate)
    if pred is None or pred.view == "none":
        return None
    try:
        if claim.predicate == "state_after":
            # a literal assignment settles it statically; otherwise ask the trace
            static = _static_truth(claim, analysis)
            return static if static is not None else _dynamic_truth(claim, analysis, idx)
        if pred.dynamic:
            return _dynamic_truth(claim, analysis, idx)
        return _static_truth(claim, analysis)
    except (KeyError, TypeError, ValueError):
        return None


def label_record(record: dict, analysis, trace: dict) -> None:
    """Add `truth` and `hallucinated` to every verdict of an SGV record, in place."""
    idx = TraceIndex(trace)
    record["trace_status"] = "ok" if idx.usable else trace.get("skipped", "truncated")
    for rd in record.get("rounds", []):
        for v in rd["verdicts"]:
            claim = Claim(v["id"], v["text"], v["predicate"], v["args"], v["holds"])
            truth = claim_truth(claim, analysis, idx)
            v["truth"] = truth
            v["hallucinated"] = None if truth is None else truth != v["holds"]
