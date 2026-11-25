"""Unit and adversarial tests for strengthened Lean 4 gate, vacuity detector, and PR diff gate."""
from __future__ import annotations

import pathlib
import unittest

from proofgate import check_lean_source, diff_lean_sources

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestLeanAndDiffGate(unittest.TestCase):
    def test_lean_lexer_handles_nested_comments_raw_strings_and_interp_evasion(self) -> None:
        clean = (
            "set_option autoImplicit false\n"
            "/- outer /- inner sorry admit -/ still comment axiom x : False -/\n"
            'def rawTxt : String := r#"sorry admit native_decide"#\n'
            'def interpOk (n : Nat) : String := s!"val={{n}}"\n'
            "theorem ok (n : Nat) : n + 0 = n := by omega\n"
            "#print axioms ok\n"
        )
        res_clean = check_lean_source(clean, strict=True)
        self.assertEqual(res_clean.verdict, "ACCEPT")
        self.assertEqual(res_clean.cov_bps, 10_000)
        self.assertTrue(res_clean.has_auto_implicit_false)

        evasion1 = (
            "set_option autoImplicit false\n"
            'def s : String := s! /- comment -/ "{(by sorry : Nat)}"\n'
            "theorem t (n : Nat) : n = n := rfl\n"
            "#print axioms t\n"
        )
        r1 = check_lean_source(evasion1, strict=True)
        self.assertEqual(r1.verdict, "REJECT")
        self.assertIn("REJECT_LEAN_SORRY", r1.violations)

        evasion2 = (
            "set_option autoImplicit false\n"
            "structure B where v : Nat\n"
            'def s : String := s!"{{ v := (by sorry : Nat) : B }.v}"\n'
            "theorem t (n : Nat) : n = n := rfl\n"
            "#print axioms t\n"
        )
        r2 = check_lean_source(evasion2, strict=True)
        self.assertEqual(r2.verdict, "REJECT")
        self.assertIn("REJECT_LEXER_INTERP_SORRY_EVASION", r2.violations)

    def test_lean_rejects_kernel_bypasses_chained_axioms_and_trust_compiler(self) -> None:
        vectors = [
            ("set_option debug.skipKernelTC true\ntheorem t (n : Nat) : n = n := rfl\n#print axioms t\n", "REJECT_SKIP_KERNEL_TC"),
            ("def bad : Nat := Meta.mkSorry\ntheorem t (n : Nat) : n = n := rfl\n#print axioms t\n", "REJECT_METAPROG_MKSORRY_ELAB"),
            ("def x := addDecl axiomDecl\ntheorem t (n : Nat) : n = n := rfl\n#print axioms t\n", "REJECT_METAPROG_ADDDECL_AXIOM"),
            ("def a : Nat := 0 axiom b : False\ntheorem t : 1 = 2 := False.elim b\n#print axioms t\n", "REJECT_NONSTANDARD_AXIOM"),
            ("@[extern \"c_fn\"] def f (n : Nat) : Nat := n\ntheorem t (n : Nat) : n = n := rfl\n#print axioms t\n", "REJECT_UNSAFE_LEAN_ATTRIBUTE"),
        ]
        for src, expected in vectors:
            res = check_lean_source(src)
            self.assertEqual(res.verdict, "REJECT")
            self.assertIn(expected, res.violations)

        res_trust = check_lean_source(
            "theorem t (n : Nat) : n = n := rfl\n#print axioms t\n",
            printed_axioms=["Lean.trustCompiler"],
        )
        self.assertEqual(res_trust.verdict, "REJECT")
        self.assertIn("REJECT_NATIVE_DECIDE_OFREDUCEBOOL", res_trust.violations)

        # Trojan Source BiDi character must reject
        trojan = "set_option autoImplicit false\n-- \u202e\ntheorem t (n : Nat) : n = n := rfl\n#print axioms t\n"
        res_trojan = check_lean_source(trojan)
        self.assertEqual(res_trojan.verdict, "REJECT")
        self.assertIn("REJECT_UNTERMINATED_LEXER", res_trojan.violations)

    def test_lean_strict_auto_implicit_and_print_axioms_coverage(self) -> None:
        partial_src = (
            "theorem t1 (a : Nat) : a = a := rfl\n"
            "theorem t2 (b : Nat) : b = b := rfl\n"
            "#print axioms t1\n"
        )
        res_default = check_lean_source(partial_src)
        self.assertEqual(res_default.verdict, "ACCEPT")
        self.assertEqual(res_default.cov_bps, 5000)

        res_strict = check_lean_source(partial_src, strict=True)
        self.assertEqual(res_strict.verdict, "REJECT")
        self.assertIn("REJECT_MISSING_AUTO_IMPLICIT_FALSE", res_strict.violations)
        self.assertIn("REJECT_LOW_PRINT_AXIOMS_COVERAGE", res_strict.violations)

    def test_lean_vacuity_detector_catches_contradictions_and_avoids_false_positives(self) -> None:
        vacuous_cases = [
            "theorem v1 (x : Int) (h1 : x < 0) (h2 : x > 5) : 1 = 2 := by omega\n#print axioms v1\n",
            "theorem v2 (x : Int) (h1 : x <= 3) (h2 : 3 < x) : False := by omega\n#print axioms v2\n",
            "theorem v3 (x : Nat) (h : x < 0) : False := by omega\n#print axioms v3\n",
            "theorem v4 (x : Int) (h1 : x = 7) (h2 : x ≠ 7) : False := by contradiction\n#print axioms v4\n",
            "theorem v5 (P : Prop) (h1 : P) (h2 : ¬ P) : 1 = 2 := absurd h1 h2\n#print axioms v5\n",
            "theorem v6 (h : False) : 1 = 2 := False.elim h\n#print axioms v6\n",
        ]
        for src in vacuous_cases:
            res = check_lean_source(src)
            self.assertEqual(res.verdict, "REJECT", src)
            self.assertIn("REJECT_VACUOUS_HYPOTHESIS", res.violations, src)
            self.assertEqual(len(res.vacuous_theorems), 1)

        non_vacuous = (
            "set_option autoImplicit false\n"
            "theorem nv1 (x : Int) (h1 : x > 0) (h2 : x < 5) : 0 ≤ x := by omega\n"
            "theorem nv2 (x : Int) (h : x < 0 ∨ x > 5) : x ≠ 2 := by omega\n"
            "#print axioms nv1\n"
            "#print axioms nv2\n"
        )
        res_ok = check_lean_source(non_vacuous, strict=True)
        self.assertEqual(res_ok.verdict, "ACCEPT")
        self.assertEqual(res_ok.vacuous_theorems, [])

    def test_lean_gate_accepts_formal_omnigate_soundness_file_strictly(self) -> None:
        lean_path = REPO_ROOT / "formal" / "ProofGateV1OmniGateSoundness.lean"
        src = lean_path.read_text(encoding="utf-8")
        res = check_lean_source(src, strict=True)
        self.assertEqual(res.verdict, "ACCEPT", res.violations)
        self.assertEqual(res.cov_bps, 10_000)
        self.assertGreaterEqual(res.theorem_count, 16)
        self.assertEqual(res.vacuous_theorems, [])

    def test_diff_gate_detects_alpha_moves_renames_drops_and_mutations(self) -> None:
        base = (
            "namespace Core\n"
            "theorem add_comm_spec (a b : Nat) : a + b = b + a := by omega\n"
            "theorem pos_bound (n : Nat) (hn : n > 0) : n ≥ 1 := by omega\n"
            "end Core\n"
        )
        # Alpha-rename + move across namespaces + ∀ form
        head_equiv = (
            "namespace CoreV2\n"
            "-- refactored comment\n"
            "theorem add_comm_renamed : ∀ (x y : Nat), x + y = y + x := by intro x y; omega\n"
            "theorem pos_bound (k : Nat) (hk : k > 0) : k ≥ 1 := by omega\n"
            "end CoreV2\n"
        )
        res_equiv = diff_lean_sources(base, head_equiv)
        self.assertEqual(res_equiv.verdict, "ACCEPT")
        self.assertEqual(len(res_equiv.renamed), 1)
        self.assertEqual(len(res_equiv.moved), 1)
        self.assertEqual(res_equiv.dropped, [])

        # Disallow renames strictly
        res_strict_ren = diff_lean_sources(base, head_equiv, allow_renames=False)
        self.assertEqual(res_strict_ren.verdict, "REJECT")
        self.assertIn("REJECT_THEOREM_RENAMED", res_strict_ren.violations)

        # Theorem drop
        head_drop = (
            "namespace Core\n"
            "theorem add_comm_spec (a b : Nat) : a + b = b + a := by omega\n"
            "end Core\n"
        )
        res_drop = diff_lean_sources(base, head_drop)
        self.assertEqual(res_drop.verdict, "REJECT")
        self.assertIn("REJECT_THEOREM_DROPPED", res_drop.violations)
        self.assertEqual(len(res_drop.dropped), 1)

        # Statement mutation
        head_mutated = (
            "namespace Core\n"
            "theorem add_comm_spec (a b : Nat) : a + b = a + b := by rfl\n"
            "theorem pos_bound (n : Nat) (hn : n > 0) : n ≥ 1 := by omega\n"
            "end Core\n"
        )
        res_mut = diff_lean_sources(base, head_mutated)
        self.assertEqual(res_mut.verdict, "REJECT")
        self.assertIn("REJECT_THEOREM_STATEMENT_CHANGED", res_mut.violations)

    def test_lean_vacuity_flipped_bounds_and_multibinder_soundness(self) -> None:
        # Multi-variable binder should NOT trigger TRIVIAL_ISPAT
        multi = (
            "set_option autoImplicit false\n"
            "theorem multi_ok (p0 p1 q1 q2 : Nat) : p0 + p1 + q1 + q2 = q2 + q1 + p1 + p0 := by omega\n"
            "#print axioms multi_ok\n"
        )
        self.assertEqual(check_lean_source(multi, strict=True).verdict, "ACCEPT")

        # Flipped interval bounds (5 < x) and (0 > x) must still trigger vacuity
        flipped = (
            "theorem vac_flip (x : Int) (h1 : 5 < x) (h2 : 0 > x) : False := by omega\n"
            "#print axioms vac_flip\n"
        )
        res_f = check_lean_source(flipped)
        self.assertEqual(res_f.verdict, "REJECT")
        self.assertIn("REJECT_VACUOUS_HYPOTHESIS", res_f.violations)

    def test_diff_gate_private_theorem_filtering(self) -> None:
        base = "private theorem helper (n : Nat) : n = n := rfl\ntheorem pub (n : Nat) : n = n := rfl\n"
        head = "theorem pub (m : Nat) : m = m := rfl\n"
        self.assertEqual(diff_lean_sources(base, head, include_private=False).verdict, "ACCEPT")
        self.assertEqual(diff_lean_sources(base, head, include_private=True).primary_code, "REJECT_THEOREM_DROPPED")


if __name__ == "__main__":
    unittest.main()
