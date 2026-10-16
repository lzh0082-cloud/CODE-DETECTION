"""Static analysis of a single Python function.

Provides the three structural views that SGV routes claims to:

* AST view - parameters, bound names, calls and statement text.
* CFG view - statement-level control-flow graph; every node records the loops
  and if-arms that enclose it.
* DFG view - reaching-definition def-use edges, control dependence and
  backward slices. In-place mutation (``xs.append(..)``, ``d[k] = v``) is a
  non-killing definition, so both the original binding and the mutation reach
  later reads.

The target program is only parsed, never executed.
"""
from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import dataclass, field

ENTRY, EXIT = 0, 1

MUTATING_METHODS = frozenset({
    "append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse",
    "update", "add", "discard", "setdefault", "popitem",
    "difference_update", "intersection_update", "symmetric_difference_update",
    "appendleft", "popleft", "extendleft", "rotate",
})

_HEADER_KINDS = frozenset({"if", "while", "for", "with", "match", "case", "except"})


@dataclass
class Node:
    id: int
    kind: str  # entry/exit/stmt/if/while/for/return/break/continue/raise/except/with/match/case
    line: int | None
    text: str
    stmt: ast.AST | None = None
    exprs: list[ast.AST] = field(default_factory=list)
    defs: set[str] = field(default_factory=set)      # rebinding (kills earlier definitions)
    mutates: set[str] = field(default_factory=set)   # in-place modification (does not kill)
    uses: set[str] = field(default_factory=set)
    loops: tuple[int, ...] = ()                      # enclosing loop headers, outermost first
    branches: tuple[tuple[int, bool], ...] = ()      # enclosing (if node, arm) pairs
    break_target: int | None = None

    @property
    def writes(self) -> set[str]:
        return self.defs | self.mutates

    @property
    def label(self) -> str:
        if self.kind in ("entry", "exit"):
            return self.kind.upper()
        return f"L{self.line}"


def function_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = func.args
    names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    names += [x.arg for x in (a.vararg, a.kwarg) if x]
    return names


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _bind(target: ast.AST, node: Node) -> None:
    if isinstance(target, ast.Name):
        node.defs.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _bind(elt, node)
    elif isinstance(target, ast.Starred):
        _bind(target.value, node)
    elif isinstance(target, (ast.Attribute, ast.Subscript)):
        root = _root_name(target)
        if root:
            node.mutates.add(root)


class _Effects(ast.NodeVisitor):
    """Collects the names an expression reads, its walrus bindings and the
    variables it mutates in place, respecting comprehension/lambda scopes."""

    def __init__(self, node: Node):
        self.node = node
        self.scopes: list[set[str]] = []

    def _local(self, name: str) -> bool:
        return any(name in scope for scope in self.scopes)

    def visit_Name(self, n: ast.Name) -> None:
        if isinstance(n.ctx, ast.Load) and not self._local(n.id):
            self.node.uses.add(n.id)

    def visit_NamedExpr(self, n: ast.NamedExpr) -> None:
        self.visit(n.value)
        self.node.defs.add(n.target.id)

    def visit_Call(self, n: ast.Call) -> None:
        f = n.func
        if isinstance(f, ast.Attribute) and f.attr in MUTATING_METHODS:
            root = _root_name(f.value)
            if root and not self._local(root):
                self.node.mutates.add(root)
        self.generic_visit(n)

    def _comprehension(self, n) -> None:
        gens = n.generators
        self.visit(gens[0].iter)  # the first iterable is evaluated in the enclosing scope
        bound = set()
        for g in gens:
            bound |= {x.id for x in ast.walk(g.target) if isinstance(x, ast.Name)}
        self.scopes.append(bound)
        for i, g in enumerate(gens):
            if i:
                self.visit(g.iter)
            for cond in g.ifs:
                self.visit(cond)
        for part in (n.key, n.value) if isinstance(n, ast.DictComp) else (n.elt,):
            self.visit(part)
        self.scopes.pop()

    visit_ListComp = visit_SetComp = visit_GeneratorExp = visit_DictComp = _comprehension

    def visit_Lambda(self, n: ast.Lambda) -> None:
        a = n.args
        for default in a.defaults + [d for d in a.kw_defaults if d is not None]:
            self.visit(default)
        params = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
        params |= {x.arg for x in (a.vararg, a.kwarg) if x}
        self.scopes.append(params)
        self.visit(n.body)
        self.scopes.pop()


Frontier = list[tuple[int, str | None]]  # dangling (source node, edge label) pairs


class _Builder:
    """Builds the statement-level CFG of one function."""

    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef, source: str):
        self.source = source
        self.nodes: list[Node] = []
        self.succ: dict[int, list[tuple[int, str | None]]] = defaultdict(list)
        self.loop_members: dict[int, set[int]] = defaultdict(set)
        entry = self._new("entry", None, "ENTRY", (), ())
        self._new("exit", None, "EXIT", (), ())
        entry.defs.update(function_params(func))
        frontier = self._block(func.body, [(ENTRY, None)], (), (), None)
        self._connect(frontier, EXIT)

    def _new(self, kind, line, text, loops, branches, stmt=None) -> Node:
        node = Node(len(self.nodes), kind, line, text, stmt=stmt, loops=loops, branches=branches)
        self.nodes.append(node)
        for header in loops:
            self.loop_members[header].add(node.id)
        return node

    def _edge(self, src: int, dst: int, label: str | None = None) -> None:
        if (dst, label) not in self.succ[src]:
            self.succ[src].append((dst, label))

    def _connect(self, frontier: Frontier, dst: int) -> None:
        for src, label in frontier:
            self._edge(src, dst, label)

    def _seg(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.source, node) or ast.unparse(node)

    def _first_line(self, stmt: ast.AST) -> str:
        text = self._seg(stmt).splitlines()[0].strip()
        return text if len(text) <= 100 else text[:97] + "..."

    def _node(self, kind, stmt, text, frontier, loops, branches, exprs=(), targets=()) -> Node:
        node = self._new(kind, stmt.lineno, text, loops, branches, stmt)
        self._connect(frontier, node.id)
        effects = _Effects(node)
        for expr in exprs:
            if expr is not None:
                effects.visit(expr)
                node.exprs.append(expr)
        for target in targets:
            effects.visit(target)  # reads inside subscripts, e.g. `i` in `a[i] = v`
            _bind(target, node)
            node.exprs.append(target)
        return node

    def _block(self, stmts, frontier: Frontier, loops, branches, loop) -> Frontier:
        for stmt in stmts:
            frontier = self._stmt(stmt, frontier, loops, branches, loop)
        return frontier

    def _stmt(self, s, frontier: Frontier, loops, branches, loop) -> Frontier:
        if isinstance(s, ast.If):
            node = self._node("if", s, f"if {self._seg(s.test)}", frontier, loops, branches, exprs=[s.test])
            arm_true = self._block(s.body, [(node.id, "T")], loops, branches + ((node.id, True),), loop)
            if s.orelse:
                arm_false = self._block(s.orelse, [(node.id, "F")], loops, branches + ((node.id, False),), loop)
            else:
                arm_false = [(node.id, "F")]
            return arm_true + arm_false

        if isinstance(s, (ast.For, ast.AsyncFor, ast.While)):
            if isinstance(s, ast.While):
                node = self._node("while", s, f"while {self._seg(s.test)}", frontier, loops, branches,
                                  exprs=[s.test])
                endless = isinstance(s.test, ast.Constant) and bool(s.test.value)
            else:
                node = self._node("for", s, f"for {self._seg(s.target)} in {self._seg(s.iter)}", frontier,
                                  loops, branches, exprs=[s.iter], targets=[s.target])
                endless = False
            breaks: list[int] = []
            body = self._block(s.body, [(node.id, "T")], loops + (node.id,), branches, (node.id, breaks))
            self._connect(body, node.id)
            done: Frontier = [] if endless else [(node.id, "F")]
            if s.orelse:
                done = self._block(s.orelse, done, loops, branches, loop)
            return done + [(b, "break") for b in breaks]

        if isinstance(s, ast.Break):
            node = self._node("break", s, "break", frontier, loops, branches)
            if loop is not None:
                node.break_target = loop[0]
                loop[1].append(node.id)
            return []

        if isinstance(s, ast.Continue):
            node = self._node("continue", s, "continue", frontier, loops, branches)
            if loop is not None:
                self._edge(node.id, loop[0], "continue")
            return []

        if isinstance(s, ast.Return):
            node = self._node("return", s, self._first_line(s), frontier, loops, branches, exprs=[s.value])
            self._edge(node.id, EXIT, "return")
            return []

        if isinstance(s, ast.Raise):
            node = self._node("raise", s, self._first_line(s), frontier, loops, branches, exprs=[s.exc, s.cause])
            self._edge(node.id, EXIT, "raise")
            return []

        if isinstance(s, (ast.Try, ast.TryStar)):
            # Approximation: any statement of the try body may transfer to any handler;
            # return/raise inside try bypass `finally`.
            first = len(self.nodes)
            done = self._block(s.body, frontier, loops, branches, loop)
            body_ids = range(first, len(self.nodes))
            handled: Frontier = []
            for h in s.handlers:
                text = "except" + (f" {self._seg(h.type)}" if h.type else "") + (f" as {h.name}" if h.name else "")
                node = self._node("except", h, text, [], loops, branches, exprs=[h.type])
                if h.name:
                    node.defs.add(h.name)
                for i in body_ids:
                    self._edge(i, node.id, "exc")
                handled += self._block(h.body, [(node.id, None)], loops, branches, loop)
            if s.orelse:
                done = self._block(s.orelse, done, loops, branches, loop)
            done = done + handled
            if s.finalbody:
                done = self._block(s.finalbody, done, loops, branches, loop)
            return done

        if isinstance(s, (ast.With, ast.AsyncWith)):
            items = ", ".join(self._seg(i.context_expr) + (f" as {self._seg(i.optional_vars)}" if i.optional_vars
                                                          else "") for i in s.items)
            node = self._node("with", s, f"with {items}", frontier, loops, branches,
                              exprs=[i.context_expr for i in s.items],
                              targets=[i.optional_vars for i in s.items if i.optional_vars])
            return self._block(s.body, [(node.id, None)], loops, branches, loop)

        if isinstance(s, ast.Match):
            node = self._node("match", s, f"match {self._seg(s.subject)}", frontier, loops, branches,
                              exprs=[s.subject])
            done: Frontier = []
            exhaustive = False
            for case in s.cases:
                cnode = self._node("case", case.pattern, f"case {self._seg(case.pattern)}", [(node.id, "case")],
                                   loops, branches, exprs=[case.guard])
                for p in ast.walk(case.pattern):
                    for attr in ("name", "rest"):
                        name = getattr(p, attr, None)
                        if isinstance(name, str):
                            cnode.defs.add(name)
                done += self._block(case.body, [(cnode.id, None)], loops, branches, loop)
                if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None:
                    exhaustive = True
            if not exhaustive:
                done.append((node.id, "F"))
            return done

        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node = self._node("stmt", s, self._first_line(s), frontier, loops, branches)
            node.defs.add(s.name)
            return [(node.id, None)]

        if isinstance(s, ast.Assign):
            node = self._node("stmt", s, self._first_line(s), frontier, loops, branches,
                              exprs=[s.value], targets=s.targets)
        elif isinstance(s, ast.AugAssign):
            node = self._node("stmt", s, self._first_line(s), frontier, loops, branches,
                              exprs=[s.value], targets=[s.target])
            if isinstance(s.target, ast.Name):
                node.uses.add(s.target.id)
        elif isinstance(s, ast.AnnAssign):
            node = self._node("stmt", s, self._first_line(s), frontier, loops, branches,
                              exprs=[s.value], targets=[s.target] if s.value is not None else [])
        elif isinstance(s, ast.Delete):
            node = self._node("stmt", s, self._first_line(s), frontier, loops, branches, exprs=s.targets)
            for t in s.targets:
                _bind(t, node)
        elif isinstance(s, (ast.Import, ast.ImportFrom)):
            node = self._node("stmt", s, self._first_line(s), frontier, loops, branches)
            node.defs.update((a.asname or a.name).split(".")[0] for a in s.names)
        else:  # Expr, Assert, Pass, Global, Nonlocal, ...
            node = self._node("stmt", s, self._first_line(s), frontier, loops, branches, exprs=[s])
        return [(node.id, None)]


class FunctionAnalysis:
    """CFG, reaching definitions, control dependence and slicing for one function."""

    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef, source: str):
        built = _Builder(func, source)
        self.name = func.name
        self.qualname = func.name  # `Class.method` for methods; matches frame co_qualname in traces
        self.params = function_params(func)
        self.def_line = func.lineno
        self.end_line = func.end_lineno
        # Lines run by nested functions/lambdas (a trace can jump there from a call) and
        # whether the body uses constructs whose line events the CFG does not model exactly.
        self.nested_lines: set[int] = set()
        self.irregular_flow = False
        for sub in ast.walk(func):
            if sub is func:
                continue
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                self.nested_lines.update(range(sub.lineno, sub.end_lineno + 1))
            elif isinstance(sub, (ast.Try, ast.TryStar, ast.With, ast.AsyncWith, ast.Match)):
                self.irregular_flow = True
        self.nodes = built.nodes
        self.loop_members = {h: frozenset(m) for h, m in built.loop_members.items()}
        self.succ_labeled = {n.id: list(built.succ.get(n.id, [])) for n in self.nodes}
        self.succ = {i: [d for d, _ in edges] for i, edges in self.succ_labeled.items()}
        self.pred: dict[int, list[int]] = {n.id: [] for n in self.nodes}
        for src, dsts in self.succ.items():
            for dst in dsts:
                self.pred[dst].append(src)

        self.line_nodes: dict[int, list[int]] = defaultdict(list)
        for n in self.statements:
            simple = n.kind not in _HEADER_KINDS and not isinstance(
                n.stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            last = getattr(n.stmt, "end_lineno", None) if simple else None
            for line in range(n.line, (last or n.line) + 1):
                self.line_nodes[line].append(n.id)

        self.reachable = self.reach_from([ENTRY])
        self._reaching_definitions()
        self._control_dependence()

    # -- queries ---------------------------------------------------------

    @property
    def statements(self) -> list[Node]:
        return self.nodes[2:]

    def nodes_at(self, line: int) -> list[Node]:
        return [self.nodes[i] for i in self.line_nodes.get(line, [])]

    def reach_from(self, starts) -> set[int]:
        seen = set(starts)
        work = deque(seen)
        while work:
            for nxt in self.succ[work.popleft()]:
                if nxt not in seen:
                    seen.add(nxt)
                    work.append(nxt)
        return seen

    def after(self, node_id: int) -> set[int]:
        """Nodes reachable through at least one edge from `node_id`."""
        return self.reach_from(self.succ[node_id])

    @property
    def return_nodes(self) -> list[Node]:
        return [n for n in self.statements if n.kind == "return" and n.id in self.reachable]

    @property
    def bound_names(self) -> set[str]:
        names = set(self.params)
        for n in self.statements:
            names |= n.defs
        return names

    def calls(self, node: Node) -> set[str]:
        out = set()
        for expr in node.exprs:
            for c in ast.walk(expr):
                if not isinstance(c, ast.Call):
                    continue
                f = c.func
                if isinstance(f, ast.Name):
                    out.add(f.id)
                elif isinstance(f, ast.Attribute):
                    out.add(f.attr)
                    if isinstance(f.value, ast.Name):
                        out.add(f"{f.value.id}.{f.attr}")
                    elif isinstance(f.value, ast.Constant):
                        out.add(f"{type(f.value.value).__name__}.{f.attr}")
        return out

    def backward_slice(self, criteria) -> set[int]:
        seen = set(criteria)
        work = deque(seen)
        while work:
            n = work.popleft()
            deps = [src for src, _ in self.dfg_in[n]] + list(self.control_deps[n])
            for dep in deps:
                if dep not in seen:
                    seen.add(dep)
                    work.append(dep)
        return seen

    def lines_of(self, ids) -> list[int]:
        return sorted({self.nodes[i].line for i in ids if self.nodes[i].line is not None})

    # -- dataflow --------------------------------------------------------

    def _reaching_definitions(self) -> None:
        gen = {n.id: {(v, n.id) for v in n.writes} for n in self.nodes}
        out: dict[int, set] = {n.id: set() for n in self.nodes}
        rd_in: dict[int, set] = {n.id: set() for n in self.nodes}
        changed = True
        while changed:
            changed = False
            for n in self.nodes:
                inn = set().union(*(out[p] for p in self.pred[n.id])) if self.pred[n.id] else set()
                new_out = {d for d in inn if d[0] not in n.defs} | gen[n.id]
                if inn != rd_in[n.id] or new_out != out[n.id]:
                    rd_in[n.id], out[n.id] = inn, new_out
                    changed = True
        self.rd_in = rd_in
        # A mutation also reads the object it modifies.
        self.dfg_in: dict[int, list[tuple[int, str]]] = {
            n.id: sorted((src, v) for v, src in rd_in[n.id] if v in n.uses | n.mutates) for n in self.nodes
        }

    def _control_dependence(self) -> None:
        ids = {n.id for n in self.nodes}
        pdom = {i: set(ids) for i in ids}
        pdom[EXIT] = {EXIT}
        changed = True
        while changed:
            changed = False
            for i in ids - {EXIT}:
                succs = self.succ[i]
                new = {i} | (set.intersection(*(pdom[s] for s in succs)) if succs else set())
                if new != pdom[i]:
                    pdom[i] = new
                    changed = True
        self.pdom = pdom
        self.control_deps: dict[int, set[int]] = {i: set() for i in ids}
        for a in ids:
            for b in self.succ[a]:
                if b in pdom[a] and b != a:
                    continue  # b post-dominates a: the edge decides nothing
                for n in pdom[b] - (pdom[a] - {a}):
                    self.control_deps[n].add(a)


def analyze_function(source: str, name: str | None = "f") -> FunctionAnalysis:
    """Analyse the top-level function `name` (or the first one if absent)."""
    tree = ast.parse(source)
    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not funcs:
        raise ValueError("no top-level function in source")
    chosen = next((f for f in funcs if f.name == name), funcs[0])
    return FunctionAnalysis(chosen, source)


class ProgramAnalysis:
    """Every top-level function and class method of a module. A claim is checked
    against the function whose body holds the line it cites (the entry function
    when it cites none)."""

    def __init__(self, source: str, entry: str = "f"):
        tree = ast.parse(source)
        self.functions: dict[str, FunctionAnalysis] = {}
        self._collect(tree.body, "", source)
        if not self.functions:
            raise ValueError("no function in source")
        self.entry = self.functions.get(entry) or next(iter(self.functions.values()))

    def _collect(self, body, prefix: str, source: str) -> None:
        """Functions, methods and nested functions, keyed by their frame `co_qualname`."""
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fa = FunctionAnalysis(node, source)
                fa.qualname = prefix + node.name
                self.functions[fa.qualname] = fa
                self._collect(node.body, f"{fa.qualname}.<locals>.", source)
            elif isinstance(node, ast.ClassDef):
                self._collect(node.body, f"{prefix}{node.name}.", source)
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                for block in ("body", "orelse", "finalbody"):
                    self._collect(getattr(node, block, []), prefix, source)

    def function_at(self, line: int) -> FunctionAnalysis | None:
        """The innermost function whose definition spans `line`."""
        spanning = [fa for fa in self.functions.values() if fa.def_line <= line <= fa.end_line]
        return min(spanning, key=lambda fa: fa.end_line - fa.def_line) if spanning else None


def analyze_program(source: str, entry: str = "f") -> ProgramAnalysis:
    return ProgramAnalysis(source, entry)
