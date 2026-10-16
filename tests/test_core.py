import json
import unittest

from sgv.analysis import analyze_function, analyze_program
from sgv.claims import Claim, parse_claims
from sgv.data import Sample, is_correct, parse_answer
from sgv.labeling import TraceIndex, claim_truth, label_record
from sgv.literals import safe_literal
from sgv.llm import ScriptedLLM
from sgv.methods import METHODS, run_method
from sgv.serialize import full_dump, routed_context
from sgv.trace import run_trace, unsafe_reason
from sgv.verifier import CONTRADICTED, INVALID, SUPPORTED, UNVERIFIABLE, verify

# CRUXEval sample_0
SORT_CODE = """def f(nums):
    output = []
    for n in nums:
        output.append((nums.count(n), n))
    output.sort(reverse=True)
    return output"""

BRANCH_CODE = """def f(xs, k):
    total = 0
    for x in xs:
        if x > k:
            break
        elif x == k:
            continue
        else:
            total += x
    return total
    print("dead")"""


def check(code, predicate, holds=True, **args):
    return verify(Claim(0, "", predicate, args, holds), analyze_function(code)).status


class AnalysisTest(unittest.TestCase):
    def test_loop_membership_and_mutation_flow(self):
        fa = analyze_function(SORT_CODE)
        header = fa.nodes_at(3)[0]
        self.assertIn(header.id, fa.nodes_at(4)[0].loops)
        self.assertEqual(fa.nodes_at(5)[0].loops, ())
        self.assertEqual(fa.nodes_at(4)[0].mutates, {"output"})
        ret = fa.nodes_at(6)[0]
        # the binding at L2 and the in-place mutations at L4/L5 all reach the return
        self.assertEqual({fa.nodes[s].line for s, v in fa.dfg_in[ret.id] if v == "output"}, {2, 4, 5})

    def test_branches_dead_code_and_slice(self):
        fa = analyze_function(BRANCH_CODE)
        if4, if6 = fa.nodes_at(4)[0].id, fa.nodes_at(6)[0].id
        self.assertEqual(fa.nodes_at(9)[0].branches, ((if4, False), (if6, False)))
        self.assertNotIn(fa.nodes_at(11)[0].id, fa.reachable)
        sl = fa.backward_slice([n.id for n in fa.return_nodes])
        self.assertTrue({2, 3, 4, 6, 9, 10} <= set(fa.lines_of(sl)))

    def test_comprehension_and_lambda_scopes(self):
        fa = analyze_function("def f(a):\n    b = [x * a for x in range(3)]\n    c = sorted(b, key=lambda y: -y)\n    return c")
        self.assertEqual(fa.nodes_at(2)[0].uses, {"a", "range"})
        self.assertEqual(fa.nodes_at(3)[0].uses, {"sorted", "b"})


class VerifierTest(unittest.TestCase):
    def test_structural_claims(self):
        cases = [
            ("in_loop", True, dict(line=5, loop_line=3), CONTRADICTED),   # sort is after the loop
            ("in_loop", False, dict(line=5), SUPPORTED),
            ("in_loop", True, dict(line=4, loop_line=3), SUPPORTED),
            ("calls", True, dict(name="nums.count"), SUPPORTED),
            ("calls", True, dict(name="sorted"), CONTRADICTED),
            ("var_defined", True, dict(var="result"), CONTRADICTED),        # fabricated variable
            ("method_exists", True, dict(type="str", method="append"), CONTRADICTED),
            ("method_exists", True, dict(type="list", method="append"), SUPPORTED),
            ("value_at", True, dict(var="output", line=2, value="[]"), SUPPORTED),
            ("value_at", True, dict(var="output", line=2, value="[1]"), CONTRADICTED),
            ("returns_at", True, dict(line=5), CONTRADICTED),
            ("modified_after", False, dict(var="output", line=5), SUPPORTED),
            ("modified_in_loop", True, dict(var="output", loop_line=3), SUPPORTED),
            ("def_reaches", True, dict(var="output", def_line=2, use_line=6), SUPPORTED),
            ("affects_return", True, dict(var="nums"), SUPPORTED),
            ("loop_has_early_exit", True, dict(loop_line=3), CONTRADICTED),
            ("in_loop", True, dict(line=40), INVALID),
            ("free", True, {}, UNVERIFIABLE),
        ]
        for predicate, holds, args, expected in cases:
            with self.subTest(predicate=predicate, args=args):
                self.assertEqual(check(SORT_CODE, predicate, holds, **args), expected)

    def test_branch_claims(self):
        cases = [
            ("in_branch", True, dict(line=9, if_line=6, branch=False), SUPPORTED),
            ("in_branch", True, dict(line=9, if_line=4, branch=True), CONTRADICTED),
            ("loop_has_early_exit", True, dict(loop_line=3), SUPPORTED),
            ("reachable", True, dict(line=11), CONTRADICTED),
            ("condition_uses", True, dict(line=6, var="total"), CONTRADICTED),
            ("def_reaches", True, dict(var="total", def_line=9, use_line=9), SUPPORTED),  # loop-carried
            ("can_follow", True, dict(line=2, after_line=10), CONTRADICTED),
            ("affects_return", True, dict(var="k"), SUPPORTED),                         # via control dependence
        ]
        for predicate, holds, args, expected in cases:
            with self.subTest(predicate=predicate, args=args):
                self.assertEqual(check(BRANCH_CODE, predicate, holds, **args), expected)

    def test_one_line_loop_body(self):
        code = "def f(n):\n    b = list(str(n))\n    for i in range(2, len(b)): b[i] += '+'\n    return b"
        self.assertEqual(check(code, "in_loop", True, line=3, loop_line=3), SUPPORTED)

    def test_dynamic_claims(self):
        cases = [
            ("executes", False, dict(line=6), UNVERIFIABLE),       # pilot false positive: run-specific
            ("executes", True, dict(line=11), CONTRADICTED),        # dead code never runs
            ("branch_taken", False, dict(if_line=4, branch=True), UNVERIFIABLE),
            ("loop_iterations", True, dict(loop_line=3, count=0), UNVERIFIABLE),
            ("next_line", True, dict(line=2, next=3), SUPPORTED),   # only successor
            ("next_line", True, dict(line=4, next=5), UNVERIFIABLE),  # one of two arms
            ("next_line", True, dict(line=9, next=10), CONTRADICTED),  # loop body returns to the header
            ("next_line", True, dict(line=5, next=3), CONTRADICTED),   # break leaves the loop
            ("state_after", True, dict(var="total", line=2, value="1"), CONTRADICTED),
        ]
        for predicate, holds, args, expected in cases:
            with self.subTest(predicate=predicate, args=args):
                self.assertEqual(check(BRANCH_CODE, predicate, holds, **args), expected)

    def test_views_can_be_disabled(self):
        fa = analyze_function(SORT_CODE)
        v = verify(Claim(0, "", "in_loop", {"line": 5}, True), fa, frozenset({"ast"}))
        self.assertEqual(v.status, UNVERIFIABLE)


class LiteralAndAnswerTest(unittest.TestCase):
    def test_safe_literal(self):
        self.assertEqual(safe_literal("set()"), (True, set()))
        self.assertEqual(safe_literal("{1: None}"), (True, {1: None}))
        self.assertEqual(safe_literal("float('inf')")[1], float("inf"))
        self.assertFalse(safe_literal("__import__('os').getcwd()")[0])
        self.assertFalse(safe_literal("(1).__class__")[0])

    def test_parse_and_score(self):
        self.assertEqual(parse_answer("reasoning\n[ANSWER] [(4, 1), (2, 3)]"), "[(4, 1), (2, 3)]")
        self.assertEqual(parse_answer("[ANSWER] `f([1]) == 'ab'`"), "'ab'")
        self.assertIsNone(parse_answer("no marker"))
        self.assertTrue(is_correct("{2: None, 1: None}", "{1: None, 2: None}"))
        self.assertFalse(is_correct("[1, 2]", "[2, 1]"))

    def test_parse_claims_tolerates_fences(self):
        claims = parse_claims('Here:\n```json\n[{"text": "t", "predicate": "in_loop", "args": {"line": 5}, '
                              '"holds": "false"}]\n```')
        self.assertEqual((claims[0].predicate, claims[0].holds), ("in_loop", False))


class PipelineTest(unittest.TestCase):
    GOLD = "[(4, 1), (4, 1), (4, 1), (4, 1), (2, 3), (2, 3)]"

    def setUp(self):
        self.sample = Sample("sample_0", SORT_CODE, "[1, 1, 3, 1, 3, 1]", self.GOLD)
        self.fa = analyze_program(SORT_CODE)

        def handler(kind, messages, sample_idx):
            user = messages[-1]["content"]
            if kind == "extract":
                if "sorts the output inside the loop" in user:
                    return json.dumps([{"text": "line 5 sorts inside the loop", "predicate": "in_loop",
                                        "args": {"line": 5, "loop_line": 3}, "holds": True}])
                return json.dumps([{"text": "sort happens after the loop", "predicate": "in_loop",
                                    "args": {"line": 5}, "holds": False}])
            if kind == "repair":
                assert "Program fact" in user and "[CFG]" in user
                return f"Line 5 runs once after the loop.\n[ANSWER] {self.GOLD}"
            # wrong initial CoT: believes the list is sorted on every iteration
            return "Line 5 sorts the output inside the loop each time...\n[ANSWER] [(4, 1), (2, 3)]"

        self.llm = ScriptedLLM(handler)

    def test_sgv_repairs_contradicted_reasoning(self):
        rec = run_method(METHODS["SGV"], self.sample, self.fa, self.llm)
        self.assertFalse(rec["initial_correct"])
        self.assertTrue(rec["correct"])
        self.assertTrue(rec["repaired"])
        self.assertEqual([v["status"] for v in rec["rounds"][0]["verdicts"]], [CONTRADICTED])
        self.assertEqual([v["status"] for v in rec["rounds"][-1]["verdicts"]], [SUPPORTED])

    def test_detect_only_keeps_answer_and_b1_shares_prompt(self):
        b1 = run_method(METHODS["B1"], self.sample, self.fa, self.llm)
        a3 = run_method(METHODS["A3"], self.sample, self.fa, self.llm)
        self.assertEqual(a3["answer"], b1["answer"])
        self.assertFalse(a3["repaired"])
        cot_prompts = [m for kind, m in self.llm.calls if kind == "cot"]
        self.assertEqual(cot_prompts[0], cot_prompts[1])  # identical -> cached once in real runs

    def test_routed_context_is_smaller_than_full_dump(self):
        claim = Claim(0, "", "in_loop", {"line": 5, "loop_line": 3}, True)
        routed = routed_context(self.fa.entry, [claim])
        self.assertIn("[CFG]", routed)
        self.assertNotIn("[DFG]", routed)
        self.assertLess(len(routed), len(full_dump(self.fa.entry)))

    def test_all_methods_run(self):
        for name, cfg in METHODS.items():
            with self.subTest(method=name):
                rec = run_method(cfg, self.sample, self.fa, self.llm)
                self.assertNotIn("error", rec)


class ProgramAnalysisTest(unittest.TestCase):
    CODE = ("def helper(x):\n    return x * 2\n\n\nclass Box:\n    def __init__(self, v):\n        self.v = v\n\n"
            "    def get(self):\n        for i in range(3):\n            self.v += i\n        return self.v\n\n\n"
            "def f(n):\n    return helper(n) + 1")

    def test_claims_resolve_to_the_function_holding_the_line(self):
        pa = analyze_program(self.CODE, "f")
        self.assertEqual(set(pa.functions), {"helper", "Box.__init__", "Box.get", "f"})
        self.assertEqual(verify(Claim(0, "", "in_loop", {"line": 11, "loop_line": 10}, True), pa).status, SUPPORTED)
        self.assertEqual(verify(Claim(0, "", "returns_at", {"line": 2}, True), pa).status, SUPPORTED)
        self.assertEqual(verify(Claim(0, "", "is_parameter", {"var": "n"}, True), pa).status, SUPPORTED)


class TraceLabelingTest(unittest.TestCase):
    def test_scan_blocks_unsafe_programs(self):
        self.assertIsNone(unsafe_reason(BRANCH_CODE))
        self.assertIn("os", unsafe_reason("import os\ndef f():\n    return os.getcwd()"))
        self.assertIn("open", unsafe_reason("def f(p):\n    return open(p).read()"))
        self.assertIn("skipped", run_trace("import socket\ndef f():\n    pass", "f()"))

    def test_trace_labels_dynamic_claims(self):
        trace = run_trace(BRANCH_CODE, "f([1, 2, 5, 9], 4)")
        self.assertEqual(trace["return"], "3")
        pa, idx = analyze_program(BRANCH_CODE), TraceIndex(trace)
        cases = [
            ("executes", dict(line=5), True),                          # break at x=5
            ("executes", dict(line=7), False),                         # x == k never holds
            ("branch_taken", dict(if_line=4, branch=True), True),
            ("loop_iterations", dict(loop_line=3, count=3), True),     # 1, 2, then 5 breaks
            ("next_line", dict(line=5, next=10), True),
            ("state_after", dict(var="total", line=9, value="3"), True),
            ("state_after", dict(var="total", line=9, value="4"), False),
            ("state_after", dict(var="k", line=1, value="4"), True),   # parameter binding at the def line
            ("state_after", dict(var="xs", line=1, value=[1, 2, 5, 9]), True),
            ("in_loop", dict(line=9, loop_line=3), True),              # static claim, program facts
            ("free", {}, None),
        ]
        for predicate, args, expected in cases:
            with self.subTest(predicate=predicate, args=args):
                self.assertEqual(claim_truth(Claim(0, "", predicate, args, True), pa, idx), expected)

    def test_nested_loops_one_line_ifs_and_lambdas(self):
        code = ("def g(xs):\n    total = 0\n    for x in xs:\n        for _ in range(x):\n            total += 1\n"
                "    pairs = sorted([(1, 'b'), (0, 'a')], key=lambda p: p[0])\n"
                "    for x in xs:\n        if x > 1: total += x\n    return total, pairs")
        trace = run_trace(code, "g([2, 0, 3])")
        pa, idx = analyze_program(code, "g"), TraceIndex(trace)
        cases = [
            ("loop_iterations", dict(loop_line=4, count=0), True),   # inner loop when x == 0
            ("loop_iterations", dict(loop_line=4, count=3), True),
            ("loop_iterations", dict(loop_line=4, count=5), False),  # 5 is the total, not one execution
            ("loop_iterations", dict(loop_line=3, count=3), True),
            ("branch_taken", dict(if_line=8, branch=True), None),    # one-line if
            ("state_after", dict(var="pairs", line=6, value=[[0, "a"], [1, "b"]]), True),  # JSON lists vs tuples
            ("next_line", dict(line=6, next=7), True),
            ("next_line", dict(line=6, next=0), False),              # lambda frames on L6 are not g's
        ]
        for predicate, args, expected in cases:
            with self.subTest(predicate=predicate, args=args):
                self.assertEqual(claim_truth(Claim(0, "", predicate, args, True), pa, idx), expected)

    def test_nested_functions_and_loose_values(self):
        code = ("def outer(xs):\n    def digits(n):\n        neg = 1\n        if n < 0: n, neg = -n, -1\n"
                "        return [int(c) for c in str(n)][0] * neg\n"
                "    def unused(v):\n        return v\n"
                "    ratio = 1 / 5\n    names = {1: 'One'}\n    return sorted(xs, key=digits), ratio, names")
        trace = run_trace(code, "outer([-12, 3])")
        pa, idx = analyze_program(code, "outer"), TraceIndex(trace)
        self.assertIn("outer.<locals>.digits", pa.functions)
        cases = [
            ("state_after", dict(var="neg", line=3, value=1), True),        # inside the nested function
            ("is_parameter", dict(var="n"), True),                          # parameter of the nested function
            ("invokes", dict(name="digits"), True),                         # called via key=, no call syntax
            ("invokes", dict(name="unused"), False),
            ("state_after", dict(var="ratio", line=8, value="0.2"), True),  # 0.2 vs 0.2000...
            ("state_after", dict(var="names", line=9, value={"1": "One"}), True),  # JSON keys are strings
            ("state_after", dict(var="neg", line=1, value=1), None),        # wrong function's def line: no events
        ]
        for predicate, args, expected in cases:
            with self.subTest(predicate=predicate, args=args):
                self.assertEqual(claim_truth(Claim(0, "", predicate, args, True), pa, idx), expected)

    def test_label_record_marks_hallucinations(self):
        trace = run_trace(BRANCH_CODE, "f([1, 2, 5, 9], 4)")
        record = {"rounds": [{"verdicts": [
            {"id": 0, "text": "", "predicate": "executes", "args": {"line": 7}, "holds": True},
            {"id": 1, "text": "", "predicate": "executes", "args": {"line": 5}, "holds": True},
        ]}]}
        label_record(record, analyze_program(BRANCH_CODE), trace)
        self.assertEqual([v["hallucinated"] for v in record["rounds"][0]["verdicts"]], [True, False])


if __name__ == "__main__":
    unittest.main()
