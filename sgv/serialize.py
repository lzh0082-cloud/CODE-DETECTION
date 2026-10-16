"""Render the structural views as text for prompts.

`full_dump` is the "dump every structure" baseline (B4). `routed_context` is
SGV's repair context: only the views the contradicted claims were routed to
(router) restricted to the backward slice around the cited lines (slicing).
"""
from __future__ import annotations

from .analysis import ENTRY, FunctionAnalysis
from .claims import ALL_VIEWS, Claim

_LINE_ARGS = ("line", "loop_line", "if_line", "def_line", "use_line", "after_line")


def numbered(code: str) -> str:
    return "\n".join(f"{i:>3} | {text}" for i, text in enumerate(code.splitlines(), 1))


def _names(names) -> str:
    return ", ".join(sorted(names))


def ast_view(fa: FunctionAnalysis, lines=None) -> str:
    out = [f"[AST] statements of `{fa.name}` (parameters: {', '.join(fa.params) or 'none'}); "
           "indentation = nesting depth"]
    for n in fa.statements:
        if lines is not None and n.line not in lines:
            continue
        facts = []
        if n.defs:
            facts.append(f"binds {_names(n.defs)}")
        if n.mutates:
            facts.append(f"modifies in place {_names(n.mutates)}")
        if n.uses:
            facts.append(f"reads {_names(n.uses)}")
        calls = fa.calls(n)
        if calls:
            facts.append(f"calls {_names(calls)}")
        indent = "  " * (len(n.loops) + len(n.branches))
        out.append(f"{indent}L{n.line} [{n.kind}] {n.text}" + (f"  -- {'; '.join(facts)}" if facts else ""))
    return "\n".join(out)


def cfg_view(fa: FunctionAnalysis, lines=None) -> str:
    out = ["[CFG] control-flow edges (T/F = condition true/false or loop continues/ends, "
           "exc = exception, break/continue/return as labelled)"]
    for n in [fa.nodes[ENTRY]] + fa.statements:
        if lines is not None and n.id != ENTRY and n.line not in lines:
            continue
        succ = ", ".join(fa.nodes[d].label + (f" ({lab})" if lab else "") for d, lab in fa.succ_labeled[n.id])
        out.append(f"{n.label} [{n.kind}] -> {succ or 'nothing'}")
    for header, members in sorted(fa.loop_members.items()):
        h = fa.nodes[header]
        if lines is not None and h.line not in lines and not set(fa.lines_of(members)) & set(lines):
            continue
        out.append(f"loop {h.label} `{h.text}` body: {', '.join(f'L{x}' for x in fa.lines_of(members))}")
    dead = [n for n in fa.statements if n.id not in fa.reachable]
    if dead and lines is None:
        out.append(f"unreachable: {', '.join(n.label for n in dead)}")
    return "\n".join(out)


def dfg_view(fa: FunctionAnalysis, variables=None) -> str:
    out = ["[DFG] per variable: where it is bound, modified in place and read; "
           "`A -> B` = the value written at A can be the one read at B"]
    bound = fa.bound_names
    names = sorted(bound if variables is None else set(variables) & bound)
    for var in names:
        binds = [n.label for n in fa.nodes if var in n.defs]
        mutations = [n.label for n in fa.nodes if var in n.mutates]
        reads = [n.label for n in fa.nodes if var in n.uses]
        flows = sorted({(fa.nodes[src].label, fa.nodes[dst].label)
                        for dst, deps in fa.dfg_in.items() for src, v in deps if v == var},
                       key=lambda p: (p[0], p[1]))
        parts = [f"bound at {', '.join(binds) or '-'}"]
        if mutations:
            parts.append(f"modified in place at {', '.join(mutations)}")
        parts.append(f"read at {', '.join(reads) or '-'}")
        if flows:
            parts.append("flows " + ", ".join(f"{a} -> {b}" for a, b in flows))
        out.append(f"{var}: " + "; ".join(parts))
    rets = fa.return_nodes
    if rets and variables is None:
        sl = fa.backward_slice([r.id for r in rets])
        out.append(f"returned value depends on lines: {', '.join(f'L{x}' for x in fa.lines_of(sl))}")
    return "\n".join(out)


def full_dump(fa: FunctionAnalysis) -> str:
    return "\n\n".join([ast_view(fa), cfg_view(fa), dfg_view(fa)])


def program_dump(pa) -> str:
    """Full dump of every function; a single-function program renders exactly like `full_dump`."""
    if len(pa.functions) == 1:
        return full_dump(pa.entry)
    return "\n\n".join(f"=== {name} ===\n{full_dump(fa)}" for name, fa in pa.functions.items())


def program_context(pa, claims: list[Claim], **kwargs) -> str:
    """`routed_context` per function the claims are about."""
    from .verifier import resolve_function

    groups: dict[int, tuple[FunctionAnalysis, list[Claim]]] = {}
    for c in claims:
        fa = resolve_function(c, pa)
        groups.setdefault(id(fa), (fa, []))[1].append(c)
    if len(groups) == 1:
        fa, cs = next(iter(groups.values()))
        return routed_context(fa, cs, **kwargs)
    return "\n\n".join(f"=== {fa.name} ===\n{routed_context(fa, cs, **kwargs)}" for fa, cs in groups.values())


def routed_context(fa: FunctionAnalysis, claims: list[Claim], router: bool = True, slicing: bool = True,
                   views=ALL_VIEWS) -> str:
    """Structural context for repairing the given contradicted claims."""
    wanted = {c.view for c in claims} & set(views) if router else set(views)
    lines: set[int] = set()
    variables: set[str] = set()
    for c in claims:
        for key in _LINE_ARGS:
            try:
                lines.add(int(c.args[key]))
            except (KeyError, TypeError, ValueError):
                pass
        if isinstance(c.args.get("var"), str):
            variables.add(c.args["var"].strip("`"))
        if c.predicate == "affects_return":
            lines |= set(fa.lines_of(r.id for r in fa.return_nodes))

    line_filter = var_filter = None
    if slicing:
        seeds = [n.id for line in lines for n in fa.nodes_at(line)]
        sliced = fa.backward_slice(seeds)
        for i in seeds:  # keep the enclosing loop/if headers so nesting stays visible
            sliced |= set(fa.nodes[i].loops) | {b for b, _ in fa.nodes[i].branches}
        line_filter = lines | set(fa.lines_of(sliced))
        var_filter = variables or None

    parts = []
    if "ast" in wanted:
        parts.append(ast_view(fa, line_filter))
    if "cfg" in wanted:
        parts.append(cfg_view(fa, line_filter))
    if "dfg" in wanted:
        parts.append(dfg_view(fa, var_filter))
    return "\n\n".join(parts)
