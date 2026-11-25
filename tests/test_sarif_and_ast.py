"""Unit and adversarial tests for SARIF v2.1.0 export (BMP/SMP UTF-16) and Python AST gate."""
from __future__ import annotations

import unittest

from proofgate import (
    ASTGateResult,
    check_python_source,
    compute_partial_fingerprints,
    export_sarif,
    findings_from_gate_result,
    span_to_utf16_region,
    utf16_len,
    utf16_offset_for_line_col,
)


class TestSarifAndAst(unittest.TestCase):
    def test_utf16_bmp_and_smp_offsets(self) -> None:
        # '🚀' (U+1F680) and '𝕏' (U+1D54F) are SMP (2 UTF-16 code units each); '→' is BMP (1).
        src = "x = '🚀'\ny = eval('1')\n"
        self.assertEqual(utf16_len("🚀"), 2)
        self.assertEqual(utf16_len("𝕏"), 2)
        self.assertEqual(utf16_len("→"), 1)

        idx = src.index("eval")
        reg = span_to_utf16_region(src, idx, idx + 4)
        # Line 1: "x = '🚀'\n" has 7 BMP chars + 1 SMP char (2 UTF-16 units) = 9 UTF-16 units
        self.assertEqual(reg["startLine"], 2)
        self.assertEqual(reg["startColumn"], 5)
        self.assertEqual(reg["char_utf16"], 9 + 4)
        self.assertEqual(reg["charOffset"], 13)
        self.assertEqual(reg["char_length_utf16"], 4)

        off2, col2 = utf16_offset_for_line_col("𝕏a\n", 1, 2)
        self.assertEqual(off2, 2)
        self.assertEqual(col2, 3)

    def test_sarif_v21_schema_and_deterministic_fingerprints(self) -> None:
        src = "# header 🚀\ndef f():\n    return eval('2+2')\n"
        res = check_python_source(src)
        self.assertEqual(res.verdict, "REJECT")
        findings = findings_from_gate_result(res, artifact_uri="./pkg/mod.py", source=src)
        sarif = export_sarif(findings)

        self.assertEqual(sarif[chr(36) + "schema"], "https://json.schemastore.org/sarif-2.1.0.json")
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["columnKind"], "utf16CodeUnits")
        self.assertEqual(run["tool"]["driver"]["name"], "ProofGate")
        self.assertGreaterEqual(len(run["results"]), 1)

        r0 = run["results"][0]
        self.assertTrue(r0["ruleId"].startswith("PG-AST-"))
        loc = r0["locations"][0]["physicalLocation"]
        self.assertEqual(loc["region"]["startLine"], 3)
        self.assertEqual(loc["region"]["startColumn"], 12)
        self.assertIn("char_utf16", loc["region"]["properties"])
        self.assertEqual(
            loc["region"]["charOffset"],
            loc["region"]["properties"]["char_utf16"],
        )

        fp1 = r0["partialFingerprints"]
        fp2 = compute_partial_fingerprints(
            r0["ruleId"],
            loc["artifactLocation"]["uri"],
            loc["region"]["startLine"],
            loc["region"]["startColumn"],
            loc["region"]["snippet"]["text"],
        )
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1["proofgateSha256"]), 64)

    def test_ast_gate_rejects_aliased_imports_async_stub_and_range_limit(self) -> None:
        samples = [
            ("import os as harmless\nx = 1\n", "REJECT_AST_FORBIDDEN_IMPORT"),
            ("from urllib.request import urlopen\n", "REJECT_AST_FORBIDDEN_IMPORT"),
            ("def f():\n    return getattr(object, 'x')\n", "REJECT_AST_FORBIDDEN_BUILTIN"),
            ("x = ().__class__.__mro__\n", "REJECT_AST_DUNDER_ESCAPE"),
            ("for i in range(10001):\n    pass\n", "REJECT_AST_SAFE_RANGE_LIMIT_EXCEEDED"),
            ("while 1:\n    x = 1\n", "REJECT_AST_UNBOUNDED_LOOP_DOS"),
            ("async def spoof(a, b):\n    return 42\n", "REJECT_AST_TRIVIAL_CONSTANT_ORACLE_SPOOF"),
            ("def broken(:\n    pass\n", "REJECT_AST_SYNTAX_ERROR"),
        ]
        for code, expected in samples:
            res = check_python_source(code)
            self.assertIsInstance(res, ASTGateResult)
            self.assertEqual(res.verdict, "REJECT", code)
            self.assertIn(expected, res.violations, code)

    def test_ast_gate_accepts_bounded_loops_and_pure_functions(self) -> None:
        clean = (
            "def dot(xs, ys):\n"
            "    total = 0\n"
            "    i = 0\n"
            "    while True:\n"
            "        if i >= len(xs) or i >= len(ys):\n"
            "            break\n"
            "        total += xs[i] * ys[i]\n"
            "        i += 1\n"
            "    return total\n"
        )
        res = check_python_source(clean)
        self.assertEqual(res.verdict, "ACCEPT")
        self.assertEqual(res.primary_code, "AST_SAFE_ACCEPT")
        self.assertEqual(res.findings, [])

    def test_sarif_export_from_lean_and_diff_gates_with_smp_chars(self) -> None:
        from proofgate import check_lean_source, diff_lean_sources

        lean_src = "-- 𝕏\ntheorem bad (x : Int) (h1 : x < 0) (h2 : x > 5) : False := by omega\n#print axioms bad\n"
        lres = check_lean_source(lean_src)
        l_findings = findings_from_gate_result(lres, artifact_uri="formal/Bad.lean", source=lean_src)
        sarif_l = export_sarif(l_findings)
        self.assertEqual(sarif_l["runs"][0]["results"][0]["ruleId"], "PG-LEAN-011")
        self.assertEqual(sarif_l["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 2)

        dres = diff_lean_sources("theorem keep (n : Nat) : n = n := rfl\n", "")
        d_findings = findings_from_gate_result(dres, artifact_uri="formal/Head.lean", source="")
        sarif_d = export_sarif(d_findings)
        self.assertEqual(sarif_d["runs"][0]["results"][0]["ruleId"], "PG-DIFF-001")

    def test_ast_gate_rejects_range_limit_and_allows_exact_bound(self) -> None:
        ok_src = "def f():\n    return list(range(10000))\n"
        bad_src = "def f():\n    return list(range(10001))\n"
        self.assertEqual(check_python_source(ok_src, max_range_bound=10_000).verdict, "ACCEPT")
        self.assertEqual(check_python_source(bad_src, max_range_bound=10_000).primary_code, "REJECT_AST_SAFE_RANGE_LIMIT_EXCEEDED")


if __name__ == "__main__":
    unittest.main()
