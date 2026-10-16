"""Safe evaluation of Python value literals written by models or datasets.

Accepts everything ``ast.literal_eval`` does plus a few constructor calls that
appear in reprs (``set()``, ``frozenset({1})``, ``float('inf')``). Anything else
is rejected; nothing is executed beyond building these values.
"""
from __future__ import annotations

import ast
import math

_CONSTRUCTORS = {"set": set, "frozenset": frozenset, "tuple": tuple, "list": list, "dict": dict,
                 "float": float, "complex": complex}
_ALLOWED = (ast.Expression, ast.Constant, ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Load,
            ast.UnaryOp, ast.USub, ast.UAdd, ast.BinOp, ast.Add, ast.Sub)


def _loose(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b if isinstance(a, bool) and isinstance(b, bool) else a == b
    if isinstance(a, float) or isinstance(b, float):
        try:
            return math.isclose(float(a), float(b), rel_tol=1e-9, abs_tol=1e-12)
        except (TypeError, ValueError):
            return False
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_loose(x, y) for x, y in zip(a, b))
    sets = (set, frozenset)
    if (isinstance(a, sets) and isinstance(b, (list, tuple, *sets))) or (
            isinstance(b, sets) and isinstance(a, (list, tuple))):
        try:
            return set(a) == set(b)  # JSON has no sets: a set is often written as a list
        except TypeError:
            return False
    if isinstance(a, dict) and isinstance(b, dict):
        ka, kb = {str(k): v for k, v in a.items()}, {str(k): v for k, v in b.items()}
        return ka.keys() == kb.keys() and all(_loose(ka[k], kb[k]) for k in ka)
    try:
        return bool(a == b)
    except Exception:
        return False


def claimed_matches(claimed, actual) -> bool:
    """Whether a value a model wrote (JSON value or literal text) denotes `actual`.

    Lenient where the claim format, not the model, is ambiguous: JSON has no
    tuples and only string keys, models write `0.2` for 0.20000000000000018, and
    a JSON string "2" may mean the literal 2 or the text '2'.
    """
    candidates = [claimed]
    if isinstance(claimed, str):
        ok, parsed = safe_literal(claimed)
        candidates = ([parsed] if ok else []) + [claimed]
    return any(_loose(c, actual) for c in candidates)


def safe_literal(text: str) -> tuple[bool, object]:
    """Return (True, value) if `text` is a safe Python literal, else (False, None)."""
    text = text.strip()
    try:
        return True, ast.literal_eval(text)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        pass
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError:
        return False, None
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            if not (isinstance(n.func, ast.Name) and n.func.id in _CONSTRUCTORS) or n.keywords:
                return False, None
        elif isinstance(n, ast.Name):
            if n.id not in _CONSTRUCTORS:
                return False, None
        elif not isinstance(n, _ALLOWED):
            return False, None
    try:
        return True, eval(compile(tree, "<literal>", "eval"), {"__builtins__": {}}, dict(_CONSTRUCTORS))
    except Exception:
        return False, None
