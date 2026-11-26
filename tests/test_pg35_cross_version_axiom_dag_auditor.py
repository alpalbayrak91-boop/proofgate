#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 AlpLab Research
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for ProofGate PG-35 Cross-Version Lean 4 & Mathlib Axiom-Dependency Auditor."""
from __future__ import annotations

import pathlib
import unittest

from proofgate.pg35_cross_version_axiom_dag_auditor import evaluate_pg35_benchmark


class TestPg35CrossVersionAuditor(unittest.TestCase):
    def test_m5_zero_fp_zero_fn_across_all_48_transitions(self) -> None:
        rep = evaluate_pg35_benchmark()
        self.assertEqual(rep["total_transitions"], 48)
        m5 = rep["methods"]["M5_PROOFGATE_PG35_HYBRID"]
        self.assertEqual(m5["overall"]["fp"], 0)
        self.assertEqual(m5["overall"]["fn"], 0)
        self.assertEqual(m5["overall"]["f1"], 1.0)
        for cat in ("ALLOWED_AXIOM_SHIFT", "TRANSITIVE_DEP_VIOLATION", "RENAME_ONLY", "DIRECT_OR_STEALTH_VIOLATION"):
            self.assertEqual(m5["by_category"][cat]["fp"], 0)
            self.assertEqual(m5["by_category"][cat]["fn"], 0)
            self.assertEqual(m5["by_category"][cat]["correct"], 12)

    def test_baselines_exhibit_documented_failure_modes(self) -> None:
        rep = evaluate_pg35_benchmark()
        m1 = rep["methods"]["M1_V32_SOURCE_REGEX"]
        m2 = rep["methods"]["M2_NAIVE_PRINT_AXIOMS"]
        m3 = rep["methods"]["M3_ALLOWLIST_AXIOMS"]
        m4 = rep["methods"]["M4_ISOLATED_LEAN4CHECKER"]
        # M1 misses transitive DAG violations completely
        self.assertEqual(m1["by_category"]["TRANSITIVE_DEP_VIOLATION"]["fn"], 12)
        # M2 triggers false alarms on allowed axiom shifts
        self.assertEqual(m2["by_category"]["ALLOWED_AXIOM_SHIFT"]["fp"], 12)
        # M3 misses #8840 axiom-type chains, runtime attrs, and stealth source escapes
        self.assertGreater(m3["by_category"]["TRANSITIVE_DEP_VIOLATION"]["fn"], 0)
        self.assertGreater(m3["by_category"]["RENAME_ONLY"]["fp"], 0)
        # M4 accepts custom axioms and sorryAx
        self.assertGreaterEqual(m4["by_category"]["TRANSITIVE_DEP_VIOLATION"]["fn"], 9)

    def test_zero_chr36_hygiene(self) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        for rel in (
            "proofgate/pg35_cross_version_axiom_dag_auditor.py",
            "tests/test_pg35_cross_version_axiom_dag_auditor.py",
        ):
            raw = (root / rel).read_text(encoding="utf-8")
            self.assertNotIn(chr(36), raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
