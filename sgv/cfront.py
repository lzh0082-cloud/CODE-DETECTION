"""C/C++ front end for vulnerability analysis: sensitive operations in a function
and the exact structural facts that guard them ("proof obligations").

Intraprocedural and syntax-directed (tree-sitter). A fact is a condition that
holds on every path reaching an operation, derived from
  * the enclosing if/else arms, loop conditions, ternaries and && / || operands;
  * earlier early-exit checks in enclosing blocks: after `if (c) return/goto/...;`
    the negation of `c` holds.
A *concern* states what is not guaranteed inside this function (a missing
bound, NULL or zero check, a use after free, a return that drops an
allocation). Whether callers or callees rule it out is left to the model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Node, Parser

_LANGS = {"c": Language(tree_sitter_c.language()), "cpp": Language(tree_sitter_cpp.language())}
_CPP_EXT = (".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".c++")

SIZE_ARG = {"memcpy": 2, "memmove": 2, "memset": 2, "memcmp": 2, "bcopy": 2, "strncpy": 2, "strncat": 2,
            "snprintf": 1, "vsnprintf": 1, "copy_from_user": 2, "copy_to_user": 2, "skb_put": 1, "skb_pull": 1,
            "skb_push": 1, "fread": 2, "read": 2, "recv": 2, "memcpy_s": 3, "strlcpy": 2, "strlcat": 2,
            "__copy_from_user": 2, "copy_in_user": 2, "memdup_user": 1, "kmemdup": 1}
UNBOUNDED = {"strcpy", "strcat", "sprintf", "vsprintf", "gets", "stpcpy", "wcscpy"}
EXIT_CALLS = {"exit", "abort", "_exit", "panic", "BUG", "longjmp", "siglongjmp", "__builtin_unreachable",
              "mrb_raise", "mrb_raisef", "mrb_name_error", "rb_raise", "croak", "zend_error_noreturn", "g_error"}
_ALLOC = re.compile(r"(alloc|^strn?dup$|^g_new0?$|^emalloc$|^xmalloc$|^av_malloc|^kmemdup$|^memdup)", re.I)
_FREE = re.compile(r"free|_destroy$|^g_object_unref$", re.I)
_POOL = re.compile(r"pool|arena|talloc|ALLOCA|alloca", re.I)  # region allocations are released wholesale
_UNSIGNED = re.compile(r"\b(unsigned|size_t|u_?int\w*|u8|u16|u32|u64|__u\d+|ut\d+|usize|uint\w*|DWORD|WORD|BYTE|"
                       r"UINT\w*|ULONG\w*|USHORT|uintptr_t|\w*_size_t|gsize|guint\w*|uInt|uLong|Py_UCS\d)\b")
_SIGNED = re.compile(r"\b(int|long|short|char|signed|s8|s16|s32|s64|__s\d+|int\d+_t|ssize_t|off_t|ptrdiff_t|"
                     r"st\d+|gint\w*|\w*_ssize_t|i32|i64|Sint\w*|LONG|INT\w*|Py_ssize_t|zend_long|mrb_int)\b")
_NEGATE = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
_MIRROR = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
_BLOCKS = {"compound_statement", "case_statement", "preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif",
           "labeled_statement", "translation_unit"}


_LENGTH_NAME = re.compile(r"(len|length|size|sz|count|cnt|num|nbytes|bytes|nelem|nmemb)$", re.I)
_ATTRIBUTE_MACROS = re.compile(r"\b(UNUSED|__unused|__maybe_unused|MAYBE_UNUSED|G_GNUC_UNUSED|__user|__iomem|"
                               r"__rcu|__force|__must_check|__init|__exit|noinline|__always_inline)\b"
                               r"|__attribute__\s*\(\((?:[^()]|\([^()]*\))*\)\)")


def language_for(file_name: str | None) -> str:
    return "cpp" if (file_name or "").lower().endswith(_CPP_EXT) else "c"


def _blank(match: re.Match) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))  # keep line and column positions


def _text(n: Node) -> str:
    return " ".join(n.text.decode("utf-8", "replace").split())


def _line(n: Node) -> int:
    return n.start_point[0] + 1


def _op(n: Node) -> str:
    op = n.child_by_field_name("operator")
    return op.type if op is not None else ""


def _callee(call: Node) -> str:
    fn = call.child_by_field_name("function")
    return re.split(r"->|\.|::", _text(fn))[-1] if fn is not None else ""


def _args(call: Node) -> list[Node]:
    al = call.child_by_field_name("arguments")
    return list(al.named_children) if al is not None else []


def _strip(n: Node | None) -> Node | None:
    """Drop parentheses, casts, likely()/unlikely() and `&x` around an expression."""
    while n is not None:
        if n.type == "parenthesized_expression" and n.named_child_count == 1:
            n = n.named_children[0]
        elif n.type == "cast_expression":
            n = n.child_by_field_name("value")
        elif n.type == "call_expression" and _callee(n) in ("likely", "unlikely", "__builtin_expect") and _args(n):
            n = _args(n)[0]
        elif n.type == "assignment_expression" and _op(n) == "=":
            n = n.child_by_field_name("left")  # `(p = alloc(...)) == NULL` tests p
        else:
            return n
    return None


def _is_zero(n: Node | None) -> bool:
    n = _strip(n)
    return n is not None and _text(n) in ("0", "NULL", "nullptr", "0L", "0U", "'\\0'", "false")


def _varlike(n: Node | None) -> bool:
    if n is None:
        return False
    if n.type in ("identifier", "field_expression", "qualified_identifier"):
        return not _const_name(_text(n))
    if n.type == "subscript_expression":
        return True
    return n.type == "pointer_expression" and _op(n) == "*"


def _const_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", name))  # macro constants such as MAX_LEN


def _subjects(n: Node | None) -> list[str]:
    """Maximal variable-like sub-expressions (constants, callees and sizeof operands excluded)."""
    n = _strip(n)
    if n is None or n.type in ("number_literal", "string_literal", "char_literal", "sizeof_expression"):
        return []
    if _varlike(n):
        return [_text(n)]
    if n.type == "call_expression":
        return [s for a in _args(n) for s in _subjects(a)]
    out = []
    for c in n.named_children:
        out += _subjects(c)
    return list(dict.fromkeys(out))


def _descendants(n: Node, types: set[str]):
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur.type in types:
            yield cur
        stack.extend(reversed(cur.children))


@dataclass(frozen=True)
class Fact:
    subject: str
    kind: str      # upper | lower | equal | nonzero | zero
    source: str    # the condition as written
    holds: bool    # whether `source` is true or false at the operation
    how: str       # "inside if", "inside else", "loop condition", "early exit", ...
    line: int

    def render(self) -> str:
        cond = self.source if self.holds else f"!({self.source})"
        return f"`{cond}` ({self.how}, line {self.line})"


def _facts(cond: Node | None, holds: bool, how: str, line: int, source: str | None = None) -> list[Fact]:
    cond = _strip(cond)
    if cond is None:
        return []
    source = source or _text(cond)
    t = cond.type
    if t == "unary_expression" and _op(cond) == "!":
        return _facts(cond.child_by_field_name("argument"), not holds, how, line, source)
    if t == "binary_expression":
        op = _op(cond)
        left, right = cond.child_by_field_name("left"), cond.child_by_field_name("right")
        if op == "&&":
            return _facts(left, True, how, line, source) + _facts(right, True, how, line, source) if holds else []
        if op == "||":
            return _facts(left, False, how, line, source) + _facts(right, False, how, line, source) if not holds else []
        if op in _NEGATE:
            eff = op if holds else _NEGATE[op]
            out = []
            for side, other, sop in ((left, right, eff), (right, left, _MIRROR[eff])):
                s = _strip(side)
                if not _varlike(s):
                    continue
                if sop in ("<", "<="):
                    kinds = ["upper"]
                elif sop in (">", ">="):
                    kinds = ["lower"]
                    if (sop == ">" and _is_zero(other)) or (sop == ">=" and _text(_strip(other)) == "1"):
                        kinds.append("nonzero")  # x > 0 or x >= 1
                elif sop == "==":
                    kinds = ["zero"] if _is_zero(other) else ["equal"]
                else:
                    kinds = ["nonzero"] if _is_zero(other) else []
                out += [Fact(_text(s), k, source, holds, how, line) for k in kinds]
            return out
        return []
    if t == "call_expression" and _callee(cond) in ("IS_ERR", "IS_ERR_OR_NULL", "IS_ERR_VALUE") and _args(cond):
        arg = _strip(_args(cond)[0])
        return [Fact(_text(arg), "nonzero", source, holds, how, line)] if not holds and _varlike(arg) else []
    if _varlike(cond):
        return [Fact(_text(cond), "nonzero" if holds else "zero", source, holds, how, line)]
    return []


def _exits(stmt: Node | None) -> bool:
    """Whether control never falls through `stmt` to the next statement."""
    if stmt is None:
        return False
    t = stmt.type
    if t in ("return_statement", "goto_statement", "break_statement", "continue_statement", "throw_statement"):
        return True
    if t == "expression_statement" and stmt.named_child_count:
        call = _strip(stmt.named_children[0])
        return call is not None and call.type == "call_expression" and _callee(call) in EXIT_CALLS
    if t == "compound_statement":
        return any(_exits(c) for c in stmt.named_children)
    if t == "labeled_statement":
        return bool(stmt.named_children) and _exits(stmt.named_children[-1])
    if t == "if_statement":
        alt = stmt.child_by_field_name("alternative")
        return alt is not None and _exits(stmt.child_by_field_name("consequence")) and _exits(_else_body(alt))
    return False


def _else_body(alt: Node | None) -> Node | None:
    if alt is not None and alt.type == "else_clause" and alt.named_children:
        return alt.named_children[-1]
    return alt


def path_facts(node: Node) -> list[Fact]:
    """Conditions that hold on every path reaching `node` (within its function)."""
    out: list[Fact] = []
    child, anc = node, node.parent
    while anc is not None and anc.type != "function_definition":
        t = anc.type
        if t == "if_statement":
            cond = anc.child_by_field_name("condition")
            cons, alt = anc.child_by_field_name("consequence"), anc.child_by_field_name("alternative")
            if cons is not None and child.id == cons.id:
                out += _facts(cond, True, "inside if", _line(anc))
            elif alt is not None and child.id == alt.id:
                out += _facts(cond, False, "inside else", _line(anc))
        elif t in ("while_statement", "for_statement") and child.id == getattr(
                anc.child_by_field_name("body"), "id", None):
            out += _facts(anc.child_by_field_name("condition"), True, "loop condition", _line(anc))
            if t == "for_statement":
                out += _loop_lower_bound(anc)
        elif t == "binary_expression" and child.id == getattr(anc.child_by_field_name("right"), "id", None):
            if _op(anc) == "&&":
                out += _facts(anc.child_by_field_name("left"), True, "left of &&", _line(anc))
            elif _op(anc) == "||":
                out += _facts(anc.child_by_field_name("left"), False, "left of ||", _line(anc))
        elif t == "conditional_expression":
            cond = anc.child_by_field_name("condition")
            if child.id == getattr(anc.child_by_field_name("consequence"), "id", None):
                out += _facts(cond, True, "?: true arm", _line(anc))
            elif child.id == getattr(anc.child_by_field_name("alternative"), "id", None):
                out += _facts(cond, False, "?: false arm", _line(anc))
        elif t in _BLOCKS:
            for sib in anc.named_children:
                if sib.id == child.id:
                    break
                if sib.type != "if_statement":
                    continue
                cons, alt = sib.child_by_field_name("consequence"), sib.child_by_field_name("alternative")
                cond = sib.child_by_field_name("condition")
                if _exits(cons) and (alt is None or not _exits(_else_body(alt))):
                    out += _facts(cond, False, "early exit", _line(sib))
                elif alt is not None and _exits(_else_body(alt)) and not _exits(cons):
                    out += _facts(cond, True, "early exit in else", _line(sib))
        child, anc = anc, anc.parent
    return out


def _loop_lower_bound(loop: Node) -> list[Fact]:
    """`for (i = 0; ...; i++)` keeps i >= 0."""
    init, update = loop.child_by_field_name("initializer"), loop.child_by_field_name("update")
    if init is None or update is None:
        return []
    m = re.fullmatch(r"(?:\w[\w\s\*]*\s)?(\w+)\s*=\s*(\d+)", _text(init).rstrip(";"))
    if not m or not re.search(rf"(\+\+\s*{m.group(1)}\b|\b{m.group(1)}\s*\+\+|\b{m.group(1)}\s*\+=)", _text(update)):
        return []
    return [Fact(m.group(1), "lower", _text(init).rstrip(";"), True, "loop starts at a constant and increases",
                 _line(loop))]


@dataclass
class Obligation:
    kind: str
    line: int
    expr: str
    facts: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)

    def render(self, i: int) -> str:
        lines = [f"O{i} [{self.kind}] line {self.line}: `{self.expr}`"]
        lines += [f"   holds here: {f}" for f in self.facts] or ["   holds here: (no relevant check)"]
        lines += [f"   concern: {c}" for c in self.concerns]
        return "\n".join(lines)


class FunctionFacts:
    """Sensitive operations of one C/C++ function and their obligations."""

    def __init__(self, code: str, lang: str = "c"):
        self.code = code
        cleaned = _ATTRIBUTE_MACROS.sub(_blank, code)
        # PrimeVul drops a return type written on its own line (`static int\nfoo(...)`): add a
        # placeholder on the first line so the definition parses with unchanged line numbers.
        self.func, self.parse_errors = None, True
        for source in (cleaned, "int " + cleaned):
            tree = Parser(_LANGS[lang]).parse(source.encode("utf-8"))
            funcs = list(_descendants(tree.root_node, {"function_definition"}))
            if funcs and funcs[0].child_by_field_name("body") is not None:
                self.tree, self.func, self.parse_errors = tree, funcs[0], tree.root_node.has_error
                break
        self.types: dict[str, tuple[str, bool]] = {}
        if self.func is not None:
            self._collect_types()

    # -- declarations ---------------------------------------------------

    def _collect_types(self) -> None:
        for decl in _descendants(self.func, {"parameter_declaration", "declaration"}):
            type_node = decl.child_by_field_name("type")
            type_text = _text(type_node) if type_node is not None else ""
            prefix = " ".join(_text(c) for c in decl.named_children if c.type == "type_qualifier")
            for i, c in enumerate(decl.children):
                if decl.field_name_for_child(i) != "declarator":
                    continue
                pointer, d = False, c
                while d is not None and d.type != "identifier":
                    if d.type in ("pointer_declarator", "array_declarator", "reference_declarator"):
                        pointer = True
                    d = d.child_by_field_name("declarator") or (d.named_children[0] if d.named_children else None)
                if d is not None:
                    self.types[_text(d)] = (f"{prefix} {type_text}".strip(), pointer)

    def _signed(self, name: str) -> str | None:
        """The declared type if `name` is a signed integer variable."""
        type_text, pointer = self.types.get(name, ("", True))
        if pointer or _UNSIGNED.search(type_text) or not _SIGNED.search(type_text):
            return None
        return type_text

    # -- obligations -------------------------------------------------------

    def obligations(self) -> list[Obligation]:
        if self.func is None:
            return []
        obs = self._index() + self._sizes() + self._divisions() + self._frees() + self._nullable_derefs() + \
            self._leaks() + self._pointer_offsets()
        seen, unique = set(), []
        for ob in sorted(obs, key=lambda o: (o.line, o.kind)):
            key = (ob.kind, ob.line, ob.expr)
            if key not in seen:
                seen.add(key)
                unique.append(ob)
        return unique

    @staticmethod
    def _relevant(facts: list[Fact], subjects: list[str], kinds: set[str]) -> list[Fact]:
        return [f for f in facts if f.kind in kinds and f.subject in subjects]

    def _bound_obligation(self, kind: str, node: Node, value: Node, what: str) -> Obligation | None:
        subjects = _subjects(value)
        if not subjects:
            return None
        facts = path_facts(node)
        rel = [f for f in facts if f.subject in subjects]
        ob = Obligation(kind, _line(node), _text(node)[:160], list(dict.fromkeys(f.render() for f in rel)))
        vtext = _text(_strip(value))
        masked = _strip(value).type == "binary_expression" and _op(_strip(value)) in ("&", "%")
        for s in subjects:
            mine = [f for f in rel if f.subject == s]
            if not masked and not any(f.kind in ("upper", "equal") for f in mine):
                ob.concerns.append(f"no upper-bound check on `{s}` dominates this {what}")
            signed = self._signed(s)
            if signed and not any(f.kind in ("lower", "equal") for f in mine):
                ob.concerns.append(f"`{s}` is signed (`{signed}`) and no lower-bound (>= 0) check dominates this {what}")
        if re.search(r"(?<![-=<>!])-(?![->=])", vtext) and not any(f.kind == "lower" for f in rel):
            ob.concerns.append(f"`{vtext}` involves a subtraction that can wrap below zero (no lower-bound check)")
        if kind == "copy size" and re.search(r"[\*\+]", vtext) and not any(f.kind == "upper" for f in rel):
            ob.concerns.append(f"`{vtext}` involves arithmetic that can overflow")
        return ob

    def _index(self) -> list[Obligation]:
        out = []
        for n in _descendants(self.func, {"subscript_expression"}):
            if _in_sizeof(n) or any(a.type == "array_declarator" for a in _ancestors(n)):
                continue
            idx = n.child_by_field_name("index")
            if idx is None:
                idx = n.named_children[-1] if n.named_child_count > 1 else None
            if idx is not None and idx.type == "subscript_argument_list" and idx.named_children:
                idx = idx.named_children[0]
            core = _strip(idx)
            if core is not None and ((core.type == "unary_expression" and _op(core) == "!")
                                     or (core.type == "binary_expression" and _op(core) in _NEGATE)):
                continue  # boolean index: 0 or 1
            ob = self._bound_obligation("array index", n, idx, "access") if idx is not None else None
            if ob is not None:
                out.append(ob)
        return out

    def _sizes(self) -> list[Obligation]:
        out = []
        for call in _descendants(self.func, {"call_expression"}):
            name, args = _callee(call), _args(call)
            if name in UNBOUNDED:
                out.append(Obligation("unbounded copy", _line(call), _text(call)[:160],
                                      concerns=[f"`{name}` copies without a destination size limit"]))
            elif name in SIZE_ARG and len(args) > SIZE_ARG[name]:
                ob = self._bound_obligation("copy size", call, args[SIZE_ARG[name]], "copy")
                if ob is not None:
                    out.append(ob)
            elif not _ALLOC.search(name) and not _FREE.search(name) and name not in SIZE_ARG:
                for arg in args:  # a computed length or size passed to any other call
                    subjects = _subjects(arg)
                    lengthy = [s for s in subjects if _LENGTH_NAME.search(re.split(r"->|\.", s)[-1])]
                    product = _has_variable_product(arg)
                    if (lengthy and re.search(r"[\*\+\-/]", _text(arg))) or product:
                        ob = self._bound_obligation("length argument", call, arg, "length")
                        if ob is not None and product and not any("overflow" in c for c in ob.concerns):
                            rel = self._relevant(path_facts(call), subjects, {"upper", "equal"})
                            if not rel:
                                ob.concerns.append(f"`{_text(_strip(arg))}` multiplies unbounded values and can "
                                                   "overflow before it is used as a size")
                        if ob is not None and ob.concerns:
                            out.append(ob)
            if _ALLOC.search(name) and args:
                size = max(args, key=lambda a: len(_text(a)))
                if re.search(r"[\*\+]", _text(size)) and _subjects(size):
                    rel = self._relevant(path_facts(call), _subjects(size), {"upper", "equal"})
                    ob = Obligation("allocation size", _line(call), _text(call)[:160],
                                    list(dict.fromkeys(f.render() for f in rel)))
                    if not rel:
                        ob.concerns.append(f"allocation size `{_text(size)}` can overflow: no upper bound on "
                                           f"{', '.join(f'`{s}`' for s in _subjects(size))}")
                    out.append(ob)
        return out

    def _pointer_offsets(self) -> list[Obligation]:
        """`p + e`, `p - e`, `p += e` on a declared pointer/array with a non-constant offset."""
        out = []
        for n in _descendants(self.func, {"binary_expression", "assignment_expression"}):
            if _op(n) not in ("+", "-", "+=", "-="):
                continue
            left, right = _strip(n.child_by_field_name("left")), _strip(n.child_by_field_name("right"))
            if left is None or right is None or left.type != "identifier":
                continue
            if not self.types.get(_text(left), ("", False))[1] or not _subjects(right):
                continue
            if right.type == "identifier" and self.types.get(_text(right), ("", False))[1]:
                continue  # pointer difference
            ob = self._bound_obligation("pointer offset", n, right, "pointer offset")
            if ob is not None and ob.concerns:
                out.append(ob)
        return out

    def _divisions(self) -> list[Obligation]:
        out = []
        for n in _descendants(self.func, {"binary_expression", "assignment_expression"}):
            op = _op(n)
            if op not in ("/", "%", "/=", "%="):
                continue
            divisor = _strip(n.child_by_field_name("right"))
            subjects = _subjects(divisor)
            if not subjects or divisor.type == "number_literal":
                continue
            rel = [f for f in path_facts(n) if f.subject in subjects and f.kind in ("nonzero", "lower", "equal")]
            ob = Obligation("division", _line(n), _text(n)[:160], list(dict.fromkeys(f.render() for f in rel)))
            if not rel:
                ob.concerns.append(f"no check that `{_text(divisor)}` != 0 dominates this division")
            out.append(ob)
        return out

    def _calls_named(self, pattern) -> list[tuple[Node, str]]:
        out = []
        for call in _descendants(self.func, {"call_expression"}):
            name = _callee(call)
            if pattern.search(name) and _args(call):
                arg = _strip(_args(call)[0])
                if arg is not None and arg.type == "pointer_expression" and _op(arg) == "&":
                    arg = _strip(arg.child_by_field_name("argument"))
                if _varlike(arg):
                    out.append((call, _text(arg)))
        return out

    def _mentions(self, var: str) -> list[Node]:
        """Expressions that read `var` (the variable itself or a member access through it)."""
        return [n for n in _descendants(self.func, {"identifier", "field_expression", "subscript_expression",
                                                    "pointer_expression"}) if _text(n) == var]

    def _assigned_at(self, var: str) -> list[int]:
        lines = []
        for n in _descendants(self.func, {"assignment_expression", "init_declarator"}):
            target = n.child_by_field_name("left") or n.child_by_field_name("declarator")
            if target is not None and _text(_strip(target)).lstrip("*") == var:
                lines.append(_line(n))
        return lines

    def _cut_off(self, src: Node, dst: Node) -> bool:
        """Whether `dst` is unreachable from `src` because the block holding `src` exits first
        (`free(p); return;` or `free(p); goto out;` with `dst` before the label)."""
        stmt = src
        while stmt.parent is not None and stmt.parent.type not in _BLOCKS:
            stmt = stmt.parent
        block = stmt.parent
        if block is None:
            return False
        seen = False
        for sib in block.named_children:
            if sib.id == stmt.id:
                seen = True
                continue
            if not seen or not _exits(sib):
                continue
            if _inside(dst, block) and _line(dst) < _line(sib):
                return False  # reached before the exit
            if sib.type in ("return_statement", "throw_statement", "expression_statement"):
                return True   # return, throw or a no-return call: nothing after it follows `src`
            if sib.type == "goto_statement":
                label = _text(sib.child_by_field_name("label"))
                targets = [_line(l) for l in _descendants(self.func, {"labeled_statement"})
                           if _text(l.child_by_field_name("label")) == label]
                return bool(targets) and _line(dst) < min(targets)
            return False  # break/continue or a nested exit: stay conservative
        return False

    def _frees(self) -> list[Obligation]:
        out = []
        frees = self._calls_named(_FREE)
        for call, var in frees:
            line = _line(call)
            reassigned = sorted(x for x in self._assigned_at(var) if x > line)
            limit = reassigned[0] if reassigned else 10 ** 9
            later = sorted({_line(m) for m in self._mentions(var)
                            if line < _line(m) < limit and not _exclusive(call, m) and not _inside(m, call)
                            and not self._cut_off(call, m)})
            ob = Obligation("free", line, _text(call)[:160])
            if reassigned and reassigned[0] in (line, line + 1):
                ob.facts.append(f"`{var}` is reassigned right after the free (line {reassigned[0]})")
            others = sorted({_line(c) for c, v in frees if v == var and _line(c) > line and _line(c) < limit
                             and not _exclusive(call, c) and not self._cut_off(call, c)})
            if others:
                ob.concerns.append(f"`{var}` can be freed again at line(s) {others} without being reassigned")
            uses = [x for x in later if x not in others]
            if uses:
                ob.concerns.append(f"`{var}` is mentioned at line(s) {uses} after this free, before any reassignment")
            out.append(ob)
        return out

    def _nullable_derefs(self) -> list[Obligation]:
        """Dereferences of pointers that come from a call or are NULL-checked elsewhere."""
        nullable: dict[str, str] = {}
        for n in _descendants(self.func, {"assignment_expression", "init_declarator"}):
            target = n.child_by_field_name("left") or n.child_by_field_name("declarator")
            value = _strip(n.child_by_field_name("right") or n.child_by_field_name("value"))
            if target is None or value is None or value.type != "call_expression":
                continue
            name = _text(_strip(target)).lstrip("*").strip()
            if _POOL.search(_callee(value)):
                continue
            if self.types.get(name, ("", False))[1] or _ALLOC.search(_callee(value)):
                nullable.setdefault(name, f"assigned from `{_callee(value)}()` at line {_line(n)}")
        out = []
        for var, origin in nullable.items():
            for n in _descendants(self.func, {"field_expression", "pointer_expression", "subscript_expression"}):
                base = n.child_by_field_name("argument")
                if n.type == "field_expression" and _op(n) != "->":
                    continue
                if n.type == "pointer_expression" and _op(n) != "*":
                    continue
                if base is None or _text(_strip(base)) != var or _in_sizeof(n):
                    continue
                facts = [f for f in path_facts(n) if f.subject == var and f.kind in ("nonzero", "equal")]
                ob = Obligation("dereference", _line(n), _text(n)[:160], [f.render() for f in facts])
                if not facts:
                    ob.concerns.append(f"`{var}` ({origin}) may be NULL and no NULL check dominates this dereference")
                out.append(ob)
                break  # the first dereference of each nullable pointer is the informative one
        return out

    def _leaks(self) -> list[Obligation]:
        out = []
        returns = list(_descendants(self.func, {"return_statement"}))
        frees = self._calls_named(_FREE)
        for n in _descendants(self.func, {"assignment_expression", "init_declarator"}):
            target = n.child_by_field_name("left") or n.child_by_field_name("declarator")
            value = _strip(n.child_by_field_name("right") or n.child_by_field_name("value"))
            if target is None or value is None or value.type != "call_expression" or not _ALLOC.search(_callee(value)):
                continue
            if _POOL.search(_callee(value)):
                continue
            var, start = _text(_strip(target)).lstrip("*").strip(), _line(n)
            dropped = []
            for ret in returns:
                rline = _line(ret)
                if rline <= start or var in _text(ret):
                    continue
                if any(f.subject == var and f.kind == "zero" for f in path_facts(ret)):
                    continue  # the allocation failed on this path
                if any(start < _line(c) < rline and not _exclusive(c, ret) for c, v in frees if v == var):
                    continue
                passed = sorted({_line(c) for c in _descendants(self.func, {"call_expression"})
                                 if start < _line(c) < rline and not _FREE.search(_callee(c))
                                 and any(_text(_strip(a)) == var for a in _args(c))})
                dropped.append((rline, passed))
            if dropped:
                ob = Obligation("allocation", start, _text(n)[:160])
                for rline, passed in dropped:
                    note = f"; `{var}` was passed to calls at line(s) {passed} before it (ownership may move)" \
                        if passed else ""
                    ob.concerns.append(f"the return at line {rline} neither frees nor returns `{var}`{note}")
                out.append(ob)
        return out


def _ancestors(n: Node):
    p = n.parent
    while p is not None:
        yield p
        p = p.parent


def _has_variable_product(n: Node | None) -> bool:
    """A multiplication with a non-constant operand, outside sizeof (e.g. `width * height * 4`)."""
    if n is None:
        return False
    for b in _descendants(n, {"binary_expression"}):
        if _op(b) == "*" and not _in_sizeof(b) and _subjects(b):
            return True
    return False


def _in_sizeof(n: Node) -> bool:
    """`sizeof(*p)` or `sizeof(a[i])` is evaluated at compile time: no access happens."""
    return any(a.type in ("sizeof_expression", "alignof_expression") for a in _ancestors(n))


def _inside(n: Node, outer: Node) -> bool:
    return outer.start_byte <= n.start_byte and n.end_byte <= outer.end_byte


def _exclusive(a: Node, b: Node) -> bool:
    """Whether `a` and `b` lie in different arms of the same if (never both on one path)."""
    a_ancestors = {x.id for x in _ancestors(a)}
    for anc in _ancestors(b):
        if anc.id not in a_ancestors:
            continue
        if anc.type != "if_statement":
            return False  # the innermost common ancestor is not an if
        cons, alt = anc.child_by_field_name("consequence"), anc.child_by_field_name("alternative")
        in_cons = cons is not None and _inside(a, cons), cons is not None and _inside(b, cons)
        in_alt = alt is not None and _inside(a, alt), alt is not None and _inside(b, alt)
        return (in_cons[0] and in_alt[1]) or (in_alt[0] and in_cons[1])
    return False


def render_obligations(obs: list[Obligation], limit: int = 12) -> str:
    """Concerns first, then fully guarded operations, capped at `limit`."""
    if not obs:
        return "(the analysis found no sensitive operations in this function)"
    ranked = sorted(obs, key=lambda o: (not o.concerns, o.line))
    shown = ranked[:limit]
    text = "\n".join(o.render(i) for i, o in enumerate(sorted(shown, key=lambda o: o.line), 1))
    if len(ranked) > limit:
        text += f"\n(+{len(ranked) - limit} more operations without concerns omitted)"
    return text
