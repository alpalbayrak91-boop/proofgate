"""Unit, PBT, and CLI tests for non-compensatory agent evaluation, Wilson LCB, Page-CUSUM, and CLI."""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import random
import tempfile
import unittest
import xml.etree.ElementTree as ET

from proofgate import (
    PageCusumDetector,
    evaluate_agent_run,
    evaluate_fleet_runs,
    export_junit_xml,
    export_promptfoo_json,
    lexicographic_4gate_bps,
    lexicographic_6tier_score,
    wilson_ci_bps,
    wilson_lcb_bps,
)
from proofgate.cli import main as cli_main


class TestAgentEvalAndCli(unittest.TestCase):
    def test_linear_compensation_paradox_eliminated(self) -> None:
        # Agent submits clean prose (quality=10000) but fabricates 1 missing file (P0)
        leak_run = {
            "run_id": "run-paradox-1",
            "agent": "demo-agent",
            "p0_missing_file": 1,
            "quality_bps": 10_000,
        }
        ev = evaluate_agent_run(leak_run)
        self.assertEqual(ev["linear_baseline_score"], 85)
        self.assertTrue(ev["linear_baseline_passed"])
        self.assertTrue(ev["linear_compensation_leak"])
        self.assertFalse(ev["passed"])
        self.assertEqual(ev["score_4gate_bps"], -25_000)
        self.assertEqual(ev["score_6tier"], 0)

        ev_triv = evaluate_agent_run({"run_id": "run-paradox-2", "p0_trivial_proof": 1, "quality_bps": 10_000})
        self.assertEqual(ev_triv["linear_baseline_score"], 80)
        self.assertEqual(ev_triv["score_6tier"], 2)

    def test_pbt_2000_trials_lex6tier_and_4gate_non_compensatory_dominance(self) -> None:
        rng = random.Random(20261125)
        min_gap = 10**9
        for _ in range(2000):
            q_bad = rng.randint(0, 20_000)
            q_clean = rng.randint(0, 10_000)
            ws = rng.choice([True, False])
            cap = rng.choice([True, False])
            prov = rng.choice([True, False])
            live = rng.choice([True, False])
            bud = rng.choice([True, False])
            p1 = rng.randint(0, 4)
            if ws and cap and prov and live and bud and p1 == 0:
                ws = False  # ensure at least one hard/P1 failure
            s_fail = lexicographic_6tier_score(
                workspace_ok=ws,
                capability_ok=cap,
                provenance_ok=prov,
                liveness_ok=live,
                budget_ok=bud,
                p1_total=p1,
                quality_bps=q_bad,
            )
            s_pass = lexicographic_6tier_score(
                workspace_ok=True,
                capability_ok=True,
                provenance_ok=True,
                liveness_ok=True,
                budget_ok=True,
                p1_total=0,
                quality_bps=q_clean,
            )
            self.assertLessEqual(s_fail, 10_004)
            self.assertGreaterEqual(s_pass, 10_005)
            min_gap = min(min_gap, s_pass - s_fail)

            # 4-gate veto check on random P0 > 0
            s4 = lexicographic_4gate_bps(p0_missing_file=rng.randint(1, 5), quality_bps=q_clean)
            self.assertEqual(s4, -25_000)
        self.assertGreaterEqual(min_gap, 1)

    def test_wilson_lcb_bps_edge_cases_and_monotonicity(self) -> None:
        self.assertEqual(wilson_lcb_bps(0, 0), 0)
        self.assertEqual(wilson_lcb_bps(0, 100), 0)
        self.assertGreater(wilson_lcb_bps(100, 100), 9500)
        self.assertLess(wilson_lcb_bps(100, 100), 10_000)
        for n in (1, 5, 20, 100):
            prev = -1
            for s in range(0, n + 1):
                lcb, ucb = wilson_ci_bps(s, n)
                self.assertGreaterEqual(lcb, prev)
                self.assertLessEqual(lcb, ucb)
                self.assertLessEqual(lcb, (10_000 * s) // n)
                prev = lcb

    def test_page_cusum_drift_quarantine(self) -> None:
        det = PageCusumDetector(target=0.05, slack=0.05, threshold=1.5)
        clean_rep = det.evaluate_series([0.0] * 20)
        self.assertFalse(clean_rep["quarantined"])
        self.assertEqual(clean_rep["final_cusum"], 0.0)

        drift_rep = det.evaluate_series([0.0, 0.0, 1.0, 1.0, 1.0])
        self.assertTrue(drift_rep["quarantined"])
        self.assertEqual(drift_rep["first_alarm_step"], 4)

    def test_fleet_eval_junit_and_promptfoo_exports(self) -> None:
        runs = [{"run_id": f"ok-{i}", "agent": "argon"} for i in range(18)]
        runs.append({"run_id": "bad-1", "agent": "flash", "p0_trivial_proof": 1, "quality_bps": 10_000})
        runs.append({"run_id": "bad-2", "agent": "flash", "referee_distinct_family": False})

        report = evaluate_fleet_runs(runs, min_wilson_lcb_bps=7000, cusum_threshold=1.5)
        self.assertEqual(report["verdict"], "REJECT")
        self.assertEqual(report["total_runs"], 20)
        self.assertEqual(report["passed_runs"], 18)
        self.assertEqual(report["failed_runs"], 2)
        self.assertEqual(report["linear_compensation_leaks"], 2)
        self.assertTrue(report["cusum_quarantined"])

        xml_str = export_junit_xml(report)
        root = ET.fromstring(xml_str)
        ts = root.find("testsuite")
        self.assertIsNotNone(ts)
        self.assertEqual(ts.attrib["tests"], "20")
        self.assertEqual(ts.attrib["failures"], "2")

        pf = export_promptfoo_json(report)
        self.assertEqual(pf["results"]["version"], 3)
        self.assertEqual(pf["results"]["stats"]["successes"], 18)
        self.assertEqual(pf["results"]["stats"]["failures"], 2)
        self.assertEqual(len(pf["results"]["results"]), 20)

    def test_cli_all_v1_subcommands_and_output_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tdir = pathlib.Path(tmp)
            lean_ok = tdir / "ok.lean"
            lean_ok.write_text(
                "set_option autoImplicit false\ntheorem ok (a : Nat) : a = a := rfl\n#print axioms ok\n",
                encoding="utf-8",
            )
            lean_bad = tdir / "bad.lean"
            lean_bad.write_text("theorem vac (x : Int) (h1 : x < 0) (h2 : x > 5) : False := by omega\n#print axioms vac\n", encoding="utf-8")

            py_bad = tdir / "bad.py"
            py_bad.write_text("def g():\n    return eval('1')\n", encoding="utf-8")

            runs_json = tdir / "runs.json"
            runs_json.write_text(json.dumps([{"run_id": f"r{i}", "agent": "argon"} for i in range(15)]), encoding="utf-8")

            # check-lean sarif
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["check-lean", str(lean_bad), "--format", "sarif"])
            self.assertEqual(rc, 1)
            sarif_doc = json.loads(buf.getvalue())
            self.assertEqual(sarif_doc["version"], "2.1.0")
            self.assertEqual(sarif_doc["runs"][0]["results"][0]["ruleId"], "PG-LEAN-011")

            # check-ast junit
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["check-ast", str(py_bad), "--format", "junit"])
            self.assertEqual(rc, 1)
            ET.fromstring(buf.getvalue())

            # diff-lean
            lean_renamed = tdir / "ok_renamed.lean"
            lean_renamed.write_text(
                "set_option autoImplicit false\ntheorem ok_v2 (z : Nat) : z = z := rfl\n#print axioms ok_v2\n",
                encoding="utf-8",
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["diff-lean", str(lean_ok), str(lean_renamed)])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(buf.getvalue())["verdict"], "ACCEPT")

            # merkle-root with proof-index + consistency-old
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["merkle-root", str(lean_ok), str(lean_renamed), "--proof-index", "0", "--consistency-old", "1"])
            self.assertEqual(rc, 0)
            mk = json.loads(buf.getvalue())
            self.assertIn("inclusion_proof", mk)
            self.assertIn("consistency_proof", mk)

            # slsa-attest
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["slsa-attest", str(lean_ok), "--ephemeral-key", "--merkle", "--verify"])
            self.assertEqual(rc, 0)
            slsa = json.loads(buf.getvalue())
            self.assertEqual(slsa["verification"]["verdict"], "ACCEPT")

            # eval-agents promptfoo
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["eval-agents", str(runs_json), "--format", "promptfoo"])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(buf.getvalue())["results"]["version"], 3)

    def test_cli_eval_agents_rejects_failing_fleet_and_exports_sarif_and_junit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs_json = pathlib.Path(tmp) / "bad_runs.json"
            runs_json.write_text(
                json.dumps({"runs": [{"run_id": "bad", "p0_axiom_bypass": 1, "quality_bps": 10_000}]}),
                encoding="utf-8",
            )
            for fmt in ("json", "sarif", "junit"):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = cli_main(["eval-agents", str(runs_json), "--format", fmt])
                self.assertEqual(rc, 1)
                if fmt == "junit":
                    ET.fromstring(buf.getvalue())
                else:
                    json.loads(buf.getvalue())

    def test_lex4gate_rejects_malformed_domain_and_same_family_referee(self) -> None:
        self.assertEqual(lexicographic_4gate_bps(quality_bps=10_001), -26_000)
        self.assertEqual(lexicographic_4gate_bps(p0_fake_commit=-1), -26_000)
        self.assertEqual(lexicographic_4gate_bps(git_sha_present=False), -24_000)
        self.assertEqual(lexicographic_4gate_bps(referee_distinct_family=False), -23_000)
        self.assertEqual(lexicographic_4gate_bps(referee_approved=False), -22_000)


if __name__ == "__main__":
    unittest.main()
