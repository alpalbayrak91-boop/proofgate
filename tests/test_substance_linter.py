"""Tests for ProofGate v1.4.0 Lean 4 mathematical substance & non-tautology linter."""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from proofgate.cli import main as cli_main
from proofgate.substance_linter import audit_lean_substance

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestSubstanceLinter(unittest.TestCase):
    def test_accepts_canonical_omnigate_formal_spec(self) -> None:
        src = (REPO_ROOT / "formal" / "ProofGateV1OmniGateSoundness.lean").read_text(encoding="utf-8")
        res = audit_lean_substance(src, strict=True)
        self.assertEqual(res["verdict"], "ACCEPT", res)
        self.assertGreaterEqual(res["substantive_count"], 14)
        self.assertLessEqual(res["trivial_count"], 2)
        self.assertGreaterEqual(res["substance_bps"], 8000)

    def test_detects_closed_ground_decide_filler(self) -> None:
        src = (
            "set_option autoImplicit false\n"
            "theorem t1 : 2 + 2 = 4 := by decide\n"
            "theorem t2 : 10 < 20 := by omega\n"
            "theorem t3 : 3 * 3 = 9 := rfl\n"
        )
        res = audit_lean_substance(src, strict=True)
        self.assertEqual(res["verdict"], "REJECT_VACUOUS_SUITE")
        self.assertEqual(res["substantive_count"], 0)
        self.assertEqual(res["trivial_count"], 3)
        self.assertEqual(res["substance_bps"], 0)
        codes = {f["rule_id"] for f in res["findings"]}
        self.assertEqual(codes, {"PG-LEAN-016"})

    def test_certificate_helper_referenced_by_quantified_theorem_not_penalized(self) -> None:
        src = (
            "set_option autoImplicit false\n"
            "def chk (n : Nat) : Bool := n < 16\n"
            "theorem chk_batch_dec : chk 0 = true ∧ chk 5 = true := by decide\n"
            "theorem chk_quantified (n : Nat) (h : n = 0 ∨ n = 5) : chk n = true := by\n"
            "  rcases h with rfl | rfl\n"
            "  · exact chk_batch_dec.1\n"
            "  · exact chk_batch_dec.2\n"
        )
        res = audit_lean_substance(src, strict=True)
        self.assertEqual(res["verdict"], "ACCEPT", res)
        self.assertEqual(res["certificate_helper_count"], 1)
        self.assertEqual(res["substantive_count"], 1)
        self.assertEqual(res["trivial_count"], 0)
        self.assertEqual(res["substance_bps"], 10000)

    def test_detects_trivial_local_def_unfold_wrapper(self) -> None:
        src = (
            "set_option autoImplicit false\n"
            "def gateScore (x : Nat) : Nat := x + 1\n"
            "theorem gate_wrap (x : Nat) : gateScore x = x + 1 := by unfold gateScore; rfl\n"
        )
        res = audit_lean_substance(src, strict=False)
        self.assertEqual(res["verdict"], "WARN_LOW_SUBSTANCE")
        self.assertEqual(res["trivial_count"], 1)
        self.assertEqual(res["findings"][0]["rule_id"], "PG-LEAN-017")

    def test_detects_literal_true_and_hypothesis_echo_tautologies(self) -> None:
        src = (
            "theorem taut_true (n : Nat) : True := trivial\n"
            "theorem taut_echo (h : 1 = 1) : 1 = 1 := h\n"
        )
        res = audit_lean_substance(src, strict=True)
        self.assertEqual(res["verdict"], "REJECT_VACUOUS_SUITE")
        self.assertEqual(res["trivial_count"], 2)
        self.assertTrue(all(f["rule_id"] == "PG-LEAN-018" for f in res["findings"]))

    def test_comments_and_strings_do_not_trigger_false_positives(self) -> None:
        src = (
            "/- theorem fake_taut : True := trivial -/\n"
            "def txt : String := \"theorem s : 1 = 1 := rfl\"\n"
            "theorem real_add_zero (n : Nat) : n + 0 = n := by\n"
            "  induction n with\n"
            "  | zero => rfl\n"
            "  | succ k ih => simp [ih]\n"
        )
        res = audit_lean_substance(src, strict=True)
        self.assertEqual(res["verdict"], "ACCEPT")
        self.assertEqual(res["total_theorems"], 1)
        self.assertEqual(res["substantive_count"], 1)

    def test_mixed_suite_threshold_and_summary_ratio(self) -> None:
        src = (
            "theorem r1 (n : Nat) (h : n > 0) : n >= 1 := by omega\n"
            "theorem r2 (a b : Nat) : a + b = b + a := by induction a with | zero => simp | succ k ih => simp [Nat.succ_add, ih]\n"
            "theorem t_lit : 5 = 5 := rfl\n"
        )
        res_pass = audit_lean_substance(src, min_substance_bps=6000, strict=True)
        self.assertEqual(res_pass["verdict"], "ACCEPT")
        self.assertEqual(res_pass["summary_ratio"], "2/3 substantive")
        self.assertEqual(res_pass["substance_bps"], 6666)

        res_fail = audit_lean_substance(src, min_substance_bps=7000, strict=True)
        self.assertEqual(res_fail["verdict"], "REJECT_VACUOUS_SUITE")

    def test_cli_check_substance_json_and_sarif_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "Filler.lean"
            p.write_text(
                "theorem bad1 : 1 = 1 := rfl\ntheorem bad2 : True := trivial\n",
                encoding="utf-8",
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["check-substance", str(p), "--strict-substance", "--format", "sarif"])
            self.assertEqual(rc, 1)
            sarif = json.loads(buf.getvalue())
            rules = sorted(r["ruleId"] for r in sarif["runs"][0]["results"])
            self.assertEqual(rules, ["PG-LEAN-016", "PG-LEAN-018"])

    def test_empty_file_fails_closed(self) -> None:
        res = audit_lean_substance("-- empty\n", strict=True)
        self.assertEqual(res["verdict"], "REJECT_VACUOUS_SUITE")
        self.assertEqual(res["total_theorems"], 0)
        self.assertEqual(res["substance_bps"], 0)

    def test_quantified_bridge_over_non_helper_still_substantive(self) -> None:
        src = (
            "theorem all_pos (n : Nat) (h : n >= 1) : 2 * n >= 2 := by omega\n"
            "theorem two_gt_zero : 2 * 1 >= 2 := all_pos 1 (by omega)\n"
        )
        res = audit_lean_substance(src, min_substance_bps=5000, strict=True)
        self.assertEqual(res["verdict"], "ACCEPT")
        self.assertGreaterEqual(res["substance_bps"], 5000)


if __name__ == "__main__":
    unittest.main()
