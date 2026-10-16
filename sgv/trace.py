"""Execution traces that label dynamic claims. Used for evaluation only: SGV
itself never runs the program it reasons about.

A trace is the sequence of line events of every frame of the target module
(`<sgv-target>`), each with the locals right after the line executed and the
line executed next in the same frame (0 = the frame returned).

Programs are scanned before running: anything importing outside a small
allowlist or calling file/process/introspection builtins is refused. Accepted
programs run in a separate isolated interpreter (`python -I`) with a timeout
and an empty temporary working directory.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import threading

SAFE_IMPORTS = frozenset({
    "typing", "math", "cmath", "collections", "itertools", "functools", "re", "string", "heapq", "bisect",
    "datetime", "decimal", "fractions", "operator", "statistics", "copy", "random", "hashlib", "numbers",
    "dataclasses", "enum", "abc", "array", "textwrap", "unicodedata",
})
BLOCKED_CALLS = frozenset({"open", "exec", "compile", "__import__", "input", "breakpoint", "exit", "quit",
                           "globals", "locals", "vars", "getattr", "setattr", "delattr", "memoryview"})

_RUNNER = r'''
import json, sys
payload = json.loads(sys.stdin.read())
MAX_EVENTS, MAX_REPR = payload["max_events"], payload["max_repr"]
events, pending, frame_ids = [], {}, {}
state = {"truncated": False}

def snapshot(frame):
    out = {}
    for name, value in list(frame.f_locals.items()):
        if name.startswith("__"):
            continue
        try:
            text = repr(value)
        except Exception:
            continue
        if len(text) <= MAX_REPR:
            out[name] = text
        if name == "self" and hasattr(value, "__dict__"):
            for attr, attr_value in list(vars(value).items()):
                try:
                    text = repr(attr_value)
                except Exception:
                    continue
                if len(text) <= MAX_REPR:
                    out["self." + attr] = text
    return out

def close(frame, nxt):
    ev = pending.pop(id(frame), None)
    if ev is not None:
        ev["post"] = snapshot(frame)
        ev["next"] = nxt

def local_trace(frame, event, arg):
    if event == "line":
        close(frame, frame.f_lineno)
        if len(events) >= MAX_EVENTS:
            state["truncated"] = True
            return local_trace
        fid = frame_ids.setdefault(id(frame), len(frame_ids))
        ev = {"frame": fid, "func": frame.f_code.co_qualname, "line": frame.f_lineno}
        events.append(ev)
        pending[id(frame)] = ev
    elif event == "return":
        close(frame, 0)
        frame_ids.pop(id(frame), None)
    return local_trace

def global_trace(frame, event, arg):
    if frame.f_code.co_filename != "<sgv-target>":
        return None
    if event == "call" and len(events) < MAX_EVENTS:
        # The `def` line stands for parameter binding: its post-state holds the arguments.
        fid = frame_ids.setdefault(id(frame), len(frame_ids))
        ev = {"frame": fid, "func": frame.f_code.co_qualname, "line": frame.f_code.co_firstlineno, "entry": True}
        events.append(ev)
        pending[id(frame)] = ev
    return local_trace

namespace = {"__name__": "__sgv_target__"}
exec(compile(payload["code"], "<sgv-target>", "exec"), namespace)
result = {}
sys.setrecursionlimit(3000)
sys.settrace(global_trace)
try:
    value = eval(payload["call"], namespace)
    result["return"] = repr(value)
except BaseException as e:
    result["exception"] = type(e).__name__ + ": " + str(e)
finally:
    sys.settrace(None)
result["events"] = events
result["truncated"] = state["truncated"]
sys.stdout.write(json.dumps(result))
'''


def unsafe_reason(code: str) -> str | None:
    """Why `code` must not be run, or None if it passes the scan."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return f"syntax error: {e}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bad = [a.name for a in node.names if a.name.split(".")[0] not in SAFE_IMPORTS]
            if bad:
                return f"imports {', '.join(bad)}"
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in SAFE_IMPORTS:
                return f"imports from {node.module}"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in BLOCKED_CALLS:
            return f"calls {node.func.id}()"
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr not in (
                "__init__", "__name__", "__class__", "__len__", "__dict__"):
            return f"uses {node.attr}"
    return None


def run_trace(code: str, call: str, timeout: float = 10.0, max_events: int = 20000, max_repr: int = 400) -> dict:
    """Run `call` against `code` in an isolated interpreter and return its trace."""
    reason = unsafe_reason(code)
    if reason:
        return {"skipped": reason}
    payload = json.dumps({"code": code, "call": call, "max_events": max_events, "max_repr": max_repr})
    with tempfile.TemporaryDirectory(prefix="sgv-trace-") as cwd:
        try:
            proc = subprocess.run([sys.executable, "-I", "-c", _RUNNER], input=payload, capture_output=True,
                                  text=True, encoding="utf-8", timeout=timeout, cwd=cwd,
                                  env={"PYTHONHASHSEED": "0", "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")})
        except subprocess.TimeoutExpired:
            return {"skipped": f"timeout after {timeout}s"}
    if proc.returncode != 0:
        return {"skipped": f"runner failed: {proc.stderr.strip()[-300:]}"}
    return json.loads(proc.stdout)


class TraceCache:
    """Traces stored per sample id in a JSONL file, computed on first use."""

    def __init__(self, path: str):
        self.path = path
        self.traces: dict[str, dict] = {}
        self._lock = threading.Lock()
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    row = json.loads(line)
                    self.traces[row["id"]] = row["trace"]

    def get(self, sample) -> dict:
        if sample.id not in self.traces:
            trace = run_trace(sample.code, sample.call_expr)
            with self._lock:
                self.traces[sample.id] = trace
                os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"id": sample.id, "trace": trace}) + "\n")
        return self.traces[sample.id]
