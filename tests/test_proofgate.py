"""Unit tests for ProofGate Lean 4 gate, Python AST gate, and RFC 6962 Merkle proofs."""
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from proofgate import (
    MerkleTree,
    canonical_json_bytes,
    check_lean_source,
    check_python_source,
    verify_inclusion_proof,
)
from proofgate.cli import main as cli_main


class TestProofGate(unittest.TestCase):
    def test_lean_accepts_clean_theorem_with_print_axioms(self) -> None:
        src = (
            "theorem add_comm_ok (a b : Nat) : a + b = b + a := by omega\n"
            "theorem mul_comm_ok (a b : Nat) : a * b = b * a := by simp [Nat.mul_comm]\n"
            "#print axioms add_comm_ok\n"
        )
        res = check_lean_source(src, printed_axioms=["propext", "Classical.choice"])
        self.assertEqual(res.verdict, "ACCEPT")
        self.assertEqual(res.primary_code, "QED_ACCEPT")
        self.assertEqual(res.theorem_count, 2)

    def test_lean_rejects_sorry_and_axiom_smuggling_even_beyond_comments(self) -> None:
        comment_only = (
            "/-- comment mentioning sorry safely -/\n"
            "-- single line sorry\n"
            "theorem t_ok (n : Nat) : n = n := by rfl\n"
            "#print axioms t_ok\n"
        )
        self.assertEqual(check_lean_source(comment_only).verdict, "ACCEPT")

        real_sorry = "theorem bad (n : Nat) : n = n := by sorry\n#print axioms bad\n"
        res_s = check_lean_source(real_sorry)
        self.assertEqual(res_s.verdict, "REJECT")
        self.assertIn("REJECT_LEAN_SORRY", res_s.violations)

        native_dec = "theorem bad2 : 1 = 1 := by native_decide\n#print axioms bad2\n"
        res_n = check_lean_source(native_dec, printed_axioms=["Lean.ofReduceBool"])
        self.assertEqual(res_n.verdict, "REJECT")
        self.assertIn("REJECT_NATIVE_DECIDE_OFREDUCEBOOL", res_n.violations)

    def test_ast_gate_accepts_pure_and_rejects_unsafe(self) -> None:
        clean = "def sq_sum(xs):\n    return sum(x * x for x in xs)\n"
        self.assertEqual(check_python_source(clean).verdict, "ACCEPT")

        bad = "import subprocess\ndef run():\n    return eval('1+1')\n"
        res = check_python_source(bad)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("REJECT_AST_FORBIDDEN_IMPORT", res.violations)
        self.assertIn("REJECT_AST_FORBIDDEN_BUILTIN", res.violations)

    def test_rfc6962_merkle_tree_and_inclusion_proof(self) -> None:
        records = [{"id": i, "cost_micro_usd": 100 * i} for i in range(1, 8)]
        tree = MerkleTree.from_json_records(records)
        for idx, rec in enumerate(records):
            proof = tree.inclusion_proof(idx)
            raw = canonical_json_bytes(rec)
            self.assertTrue(
                verify_inclusion_proof(
                    raw,
                    proof["leaf_index"],
                    proof["tree_size"],
                    proof["audit_path"],
                    proof["root"],
                )
            )
            tampered = canonical_json_bytes({"id": idx + 1, "cost_micro_usd": 999999})
            self.assertFalse(
                verify_inclusion_proof(
                    tampered,
                    proof["leaf_index"],
                    proof["tree_size"],
                    proof["audit_path"],
                    proof["root"],
                )
            )

    def test_cli_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = pathlib.Path(tmp)
            py_ok = tpath / "ok.py"
            py_ok.write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
            j1 = tpath / "r1.json"
            j2 = tpath / "r2.json"
            j1.write_text(json.dumps({"b": 2, "a": 1}), encoding="utf-8")
            j2.write_text(json.dumps({"a": 3}), encoding="utf-8")

            self.assertEqual(cli_main(["check-ast", str(py_ok)]), 0)
            self.assertEqual(cli_main(["merkle-root", str(j1), str(j2)]), 0)


if __name__ == "__main__":
    unittest.main()
