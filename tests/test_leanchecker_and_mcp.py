"""Tests for ProofGate v1.2.0 official Lean C++ leanchecker bridge and optional FastMCP server."""
from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import proofgate
from proofgate.cli import main as cli_main
from proofgate.leanchecker_bridge import (
    LeanToolchain,
    discover_lean_toolchain,
    replay_lean_kernel,
)
from proofgate.mcp_server import (
    create_fastmcp_server,
    proofgate_audit_spec_diff,
    proofgate_check_lean,
    proofgate_check_substance,
    proofgate_export_sarif,
    proofgate_replay_kernel,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _require_lean_tests() -> bool:
    return os.environ.get("PROOFGATE_REQUIRE_LEAN_TESTS", "").strip() == "1"


def _require_mcp_tests() -> bool:
    return os.environ.get("PROOFGATE_REQUIRE_MCP_TESTS", "").strip() == "1"


class TestLeancheckerAndMcp(unittest.TestCase):
    def _ensure_lean_or_skip(self) -> LeanToolchain:
        tc = discover_lean_toolchain()
        if tc is None:
            if _require_lean_tests():
                self.fail("Expected Lean 4 + leanchecker toolchain (PROOFGATE_REQUIRE_LEAN_TESTS=1)")
            self.skipTest("Lean 4 + leanchecker toolchain not installed in this environment")
        return tc

    def test_real_leanchecker_replay_accepts_formal_omnigate_or_valid_sample(self) -> None:
        self._ensure_lean_or_skip()
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "ValidCheck.lean"
            p.write_text(
                "set_option autoImplicit false\nset_option warningAsError true\n"
                "theorem add_comm_nat (a b : Nat) : a + b = b + a := Nat.add_comm a b\n"
                "#print axioms add_comm_nat\n",
                encoding="utf-8",
            )
            res = replay_lean_kernel(p, fresh=False, require_toolchain=True)
            self.assertEqual(res.verdict, "ACCEPT", res.stderr_excerpt)
            self.assertEqual(res.lean_rc, 0)
            self.assertEqual(res.leanchecker_rc, 0)

    def test_leanchecker_rejects_sorry_and_emits_sarif_pg_lean_014(self) -> None:
        self._ensure_lean_or_skip()
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "BadProof.lean"
            p.write_text("set_option autoImplicit false\ntheorem bad : 1 = 2 := by sorry\n", encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["check-kernel", str(p), "--require-toolchain", "--format", "sarif"])
            self.assertEqual(rc, 1)
            sarif = json.loads(buf.getvalue())
            rules = [r["ruleId"] for r in sarif["runs"][0]["results"]]
            self.assertIn("PG-LEAN-014", rules)

    def test_mocked_leanchecker_nonzero_exit_triggers_pg_lean_015(self) -> None:
        fake_tc = LeanToolchain("lean", "leanchecker", "/tmp", "fake")
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "Tampered.lean"
            p.write_text("theorem t : True := trivial\n", encoding="utf-8")

            def fake_run(cmd, **kwargs):
                if pathlib.Path(cmd[0]).name == "lean":
                    out_idx = cmd.index("-o") + 1
                    pathlib.Path(cmd[out_idx]).write_bytes(b"FAKE_OLEAN")
                    return mock.Mock(returncode=0, stdout="", stderr="")
                return mock.Mock(returncode=1, stdout="", stderr="kernel rejected tampered olean environment")

            with mock.patch("proofgate.leanchecker_bridge.discover_lean_toolchain", return_value=fake_tc):
                with mock.patch("proofgate.leanchecker_bridge.subprocess.run", side_effect=fake_run):
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        rc = cli_main(["check-kernel", str(p), "--format", "sarif"])
            self.assertEqual(rc, 1)
            sarif = json.loads(buf.getvalue())
            rules = [r["ruleId"] for r in sarif["runs"][0]["results"]]
            self.assertIn("PG-LEAN-015", rules)

    def test_missing_toolchain_graceful_skip_vs_strict_reject(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "Smoke.lean"
            p.write_text("theorem x : True := trivial\n", encoding="utf-8")
            with mock.patch("proofgate.leanchecker_bridge.discover_lean_toolchain", return_value=None):
                skip_res = replay_lean_kernel(p, require_toolchain=False)
                self.assertEqual(skip_res.verdict, "SKIPPED_NO_TOOLCHAIN")
                req_res = replay_lean_kernel(p, require_toolchain=True)
                self.assertEqual(req_res.verdict, "REJECT")
                self.assertEqual(req_res.primary_code, "REJECT_LEANCHECKER_REPLAY")

    def test_cli_check_kernel_with_also_static_gate_on_formal_spec(self) -> None:
        self._ensure_lean_or_skip()
        spec = REPO_ROOT / "formal" / "ProofGateV1OmniGateSoundness.lean"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli_main(["check-kernel", str(spec), "--also-static-gate", "--require-toolchain"])
        self.assertEqual(rc, 0, buf.getvalue())
        data = json.loads(buf.getvalue())
        self.assertEqual(data["verdict"], "ACCEPT")
        self.assertEqual(data["static_gate"]["verdict"], "ACCEPT")

    def test_fastmcp_server_registers_and_executes_5_tools(self) -> None:
        if importlib.util.find_spec("mcp") is None:
            if _require_mcp_tests():
                self.fail("Expected optional [mcp] extra installed (PROOFGATE_REQUIRE_MCP_TESTS=1)")
            self.skipTest("Optional [mcp] extra not installed (pip install 'proofgate[mcp]')")
        srv = create_fastmcp_server()
        tools = asyncio.run(srv.list_tools())
        names = sorted(t.name for t in tools)
        self.assertEqual(
            names,
            [
                "check_trajectory_difc",
                "proofgate_audit_spec_diff",
                "proofgate_check_lean",
                "proofgate_check_substance",
                "proofgate_export_sarif",
                "proofgate_replay_kernel",
            ],
        )
        ok_src = "set_option autoImplicit false\ntheorem p (n : Nat) : n + 0 = n := rfl\n#print axioms p\n"
        self.assertEqual(proofgate_check_lean(ok_src)["verdict"], "ACCEPT")
        self.assertEqual(proofgate_check_substance(ok_src)["verdict"], "ACCEPT")
        sarif = proofgate_export_sarif("theorem bad : 1 = 2 := by sorry")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "PG-LEAN-001")
        diff_ok = proofgate_audit_spec_diff(
            "theorem p (x : Nat) : x = x := by sorry",
            "theorem p (x : Nat) : x = x := rfl",
        )
        self.assertEqual(diff_ok["verdict"], "FAITHFUL_PASS")
        spec = REPO_ROOT / "formal" / "ProofGateV1OmniGateSoundness.lean"
        k_out = proofgate_replay_kernel(str(spec), fresh=False, also_static_gate=True)
        expected_verdict = (
            "ACCEPT"
            if (discover_lean_toolchain() is not None or _require_lean_tests())
            else "SKIPPED_NO_TOOLCHAIN"
        )
        self.assertEqual(k_out["verdict"], expected_verdict)


if __name__ == "__main__":
    unittest.main()
