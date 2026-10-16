import unittest

from sgv.cfront import FunctionFacts, render_obligations


def obligations(code: str, lang: str = "c"):
    return FunctionFacts(code, lang).obligations()


def concerns(code: str, kind: str) -> list[str]:
    return [c for o in obligations(code) if o.kind == kind for c in o.concerns]


class GuardFactsTest(unittest.TestCase):
    VULN = """static s32 parse(GF_BitStream *bs, AVCState *avc, AVCSliceInfo *si)
{
\ts32 pps_id = read_ue(bs);
\tif (pps_id > 255)
\t\treturn -1;
\tsi->pps = &avc->pps[pps_id];
\treturn 0;
}"""
    PATCHED = VULN.replace("if (pps_id > 255)", "if ((pps_id < 0) || (pps_id > 255))")

    def test_early_exit_gives_upper_bound_only(self):
        found = concerns(self.VULN, "array index")
        self.assertEqual(len(found), 1)
        self.assertIn("signed", found[0])            # missing lower bound on a signed index
        self.assertEqual(concerns(self.PATCHED, "array index"), [])

    def test_conditions_inside_branches_and_short_circuit(self):
        code = """int f(int *a, int n, int i, char *p)
{
    if (i >= 0 && i < n)
        return a[i];
    if (p && p[0] == 'x')
        return 1;
    for (int k = 0; k < n; k++)
        a[k] = 0;
    return a[i];
}"""
        obs = {o.line: o for o in obligations(code) if o.kind == "array index"}
        self.assertEqual(obs[4].concerns, [])        # inside `if (i >= 0 && i < n)`
        self.assertEqual(obs[8].concerns, [])        # loop variable: k < n, starts at 0, increases
        self.assertTrue(obs[9].concerns)             # after the if: no guarantee

    def test_missing_return_type_line_still_parses(self):
        code = "yank(struct bd *bd, long y_idx)\n{\n    return bd->arr[y_idx];\n}"
        self.assertTrue(any(o.kind == "array index" for o in obligations(code)))


class ResourceTest(unittest.TestCase):
    LEAK = """static int send_beacon(struct common *c)
{
\tstruct sk_buff *skb = NULL;
\tskb = dev_alloc_skb(SIZE);
\tif (!skb)
\t\treturn -ENOMEM;
\tif (prepare(c, skb)) {
\t\treturn -EINVAL;
\t}
\tqueue_tail(&c->q, skb);
\treturn 0;
}"""

    def test_error_path_leak(self):
        found = concerns(self.LEAK, "allocation")
        self.assertTrue(any("line 8" in c for c in found))       # the error return drops skb
        self.assertFalse(any("line 6" in c for c in found))      # allocation failed on that path

    def test_free_followed_by_return_is_not_a_use_after_free(self):
        patched = self.LEAK.replace("\t\treturn -EINVAL;", "\t\tdev_kfree_skb(skb);\n\t\treturn -EINVAL;")
        self.assertEqual(concerns(patched, "free"), [])
        self.assertFalse(any("line 8" in c for c in concerns(patched, "allocation")))

    def test_use_and_double_free(self):
        code = "void f(char *s)\n{\n    char *p = malloc(10);\n    free(p);\n    p[0] = 1;\n    free(p);\n}"
        found = " ".join(concerns(code, "free"))
        self.assertIn("freed again", found)
        self.assertIn("mentioned at line(s) [5]", found)

    def test_render_puts_concerns_first_and_caps(self):
        text = render_obligations(obligations(self.LEAK), limit=1)
        self.assertIn("allocation", text)


if __name__ == "__main__":
    unittest.main()
