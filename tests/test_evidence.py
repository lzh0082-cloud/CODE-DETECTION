import unittest

from sgv.cfront import Obligation
from sgv.evidence import (_near, alarm, build_evidence, claim_lines, evidence_prompt, parse_verification,
                          reassure, verified_notes, verify_prompt)
from sgv.vuln import VulnFunc

VULN = """static s32 parse(GF_BitStream *bs, AVCState *avc, AVCSliceInfo *si)
{
\ts32 pps_id = read_ue(bs);
\tif (pps_id > 255)
\t\treturn -1;
\tsi->pps = &avc->pps[pps_id];
\treturn 0;
}"""
PATCHED = VULN.replace("if (pps_id > 255)", "if ((pps_id < 0) || (pps_id > 255))")


def func(code, target):
    return VulnFunc("x", 0, "proj", "a.c", code, target, ("CWE-787",), "")


class EvidenceTest(unittest.TestCase):
    def test_reassurance_replaces_concerns_with_fabricated_checks(self):
        ob = Obligation("array index", 6, "avc->pps[pps_id]", ["`!(pps_id > 255)` (early exit, line 4)"],
                        ["`pps_id` is signed (`s32`) and no lower-bound (>= 0) check dominates this access"])
        fake = reassure(ob)
        self.assertEqual(fake.concerns, [])
        self.assertIn("`pps_id >= 0` is checked before this access (line 5)", fake.facts)

    def test_alarm_transplants_removed_concerns_or_negates_guards(self):
        donor = [Obligation("array index", 6, "a[i]", [], ["no upper-bound check on `i` dominates this access"])]
        fixed_op = Obligation("array index", 7, "a[i]", ["`i < n` (inside if, line 6)"], [])
        moved = alarm(fixed_op, donor, {"no upper-bound check on `i` dominates this access"}, True)
        self.assertEqual((moved.facts, moved.concerns), ([], donor[0].concerns))
        self.assertIsNone(alarm(fixed_op, donor, set(), True))
        negated = alarm(fixed_op, donor, set(), False)
        self.assertIn("does not hold here", negated.concerns[0])

    def test_concerns_pointing_at_the_patch_count_as_near(self):
        ob = Obligation("allocation", 6, "skb = alloc()", [], ["the return at line 17 neither frees nor returns `skb`"])
        self.assertTrue(_near(ob, [(14, 25)]))
        self.assertFalse(_near(ob, [(30, 40)]))

    def test_presentations(self):
        f = func(VULN, 1)
        notes = "O1 [array index] line 6: `a[i]`\n   holds here: `i < n` (inside if, line 5)\n   concern: no check"
        plain = evidence_prompt(f, notes)[1]["content"]
        self.assertNotIn("unverified claim", plain)
        self.assertIn("holds here", plain)
        self.assertIn("unverified claim", evidence_prompt(f, notes, "quote")[1]["content"])
        alarms = evidence_prompt(f, notes, "alarms")[1]["content"]
        self.assertNotIn("holds here", alarms)
        self.assertIn("concern: no check", alarms)
        self.assertEqual(evidence_prompt(f, "", "quote"), evidence_prompt(f, ""))  # C0 is unaffected
        reframed = evidence_prompt(f, notes, "reframe")[1]["content"]
        self.assertIn("to verify: the tool reports `i < n`", reframed)
        self.assertNotIn("holds here:", reframed)
        cited = evidence_prompt(f, notes, "provenance")[1]["content"]
        self.assertIn("(inside if, line 5) [line 5 is: `return -1;`]", cited)  # line 5 of VULN

    def test_verify_then_audit_helpers(self):
        notes = ("O1 [array index] line 6: `a[i]`\n   holds here: `i < n` (inside if, line 5)\n"
                 "   holds here: `i >= 0` is checked before this access (line 4)\n"
                 "O2 [free] line 9: `free(p)`\n   holds here: (no relevant check)\n   concern: `p` used later")
        self.assertEqual(claim_lines(notes), [1, 2, 5])  # "(no relevant check)" is not a claim
        statuses = parse_verification('Here: [{"id": 1, "status": "confirmed"}, {"id": 2, "status": "REFUTED"}]')
        self.assertEqual(statuses, {1: "CONFIRMED", 2: "REFUTED"})
        hidden = verified_notes(notes, statuses, show_refuted=False)
        self.assertIn("`i < n`", hidden)
        self.assertNotIn("i >= 0", hidden)                               # refuted claim withheld
        self.assertIn("`p` used later  (not confirmed by the code)", hidden)  # no status -> unconfirmed
        shown = verified_notes(notes, statuses, show_refuted=True)
        self.assertIn("CONTRADICTED by the code", shown)
        self.assertIn("the array index at line 6", shown)
        self.assertIn("1 | static s32", verify_prompt(func(VULN, 1), notes)[1]["content"])

    def test_pair_evidence(self):
        ev = build_evidence(func(VULN, 1), func(PATCHED, 0))
        self.assertIn("signed", ev.texts[(1, "C2")])
        self.assertNotIn("concern", ev.texts[(0, "C2")])           # the patch added the lower bound
        self.assertIn("pps_id >= 0", ev.texts[(1, "C4")])           # fabricated reassurance
        self.assertIn("lower-bound", ev.texts[(0, "C5")])           # the removed concern transplanted back
        self.assertEqual(ev.info["c5_source"], "transplant")
        self.assertIsNone(ev.texts[(0, "C4")])


if __name__ == "__main__":
    unittest.main()
