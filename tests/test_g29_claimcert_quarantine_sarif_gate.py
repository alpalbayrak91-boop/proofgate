"""Unit, CLI, SARIF v2.1.0, and PBT tests for ProofGate Gate 2.9 CLI integration.

Runs offline with zero external dependencies under both unittest and pytest.
KURAL-3 compliant: 0 occurrences of chr(36).
"""
from __future__ import annotations

import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout

from proofgate import cli
from proofgate.g29_claimcert_quarantine_sarif_gate import (
    audit_g29_claimcert_bundle,
    build_g29_quarantine_demo_bundle,
    build_g29_selftest_bundle,
    export_g29_claimcert_sarif_v210,
    gate_g29_bps,
    lattice_join,
    normalize_g29_sarif_uri,
    strict_json_loads_g29,
)


class EvilInt(int):
    pass


class TestG29ClaimCertQuarantineSarifGate(unittest.TestCase):
    def test_selftest_bundle_accepts_and_meets_vendi_floor(self) -> None:
        res = audit_g29_claimcert_bundle(build_g29_selftest_bundle())
        self.assertEqual(res["verdict"], "ACCEPT")
        self.assertTrue(res["passed"])
        self.assertEqual(res["findings_count"], 0)
        self.assertFalse(res["raw_leak_detected"])
        self.assertGreaterEqual(res["vs2"], 3.0)
        self.assertGreaterEqual(res["gate_bps"], 4000)
        self.assertTrue(res["kural3_zero_chr36"])
        self.assertEqual(len(res["merkle_root_sha256"]), 64)
        self.assertEqual(res["aws_oss_program"], "AWS-OSS-NOV30-2026")

    def test_quarantine_demo_rejects_with_zero_raw_leak(self) -> None:
        res = audit_g29_claimcert_bundle(build_g29_quarantine_demo_bundle())
        self.assertEqual(res["verdict"], "REJECT")
        self.assertFalse(res["passed"])
        self.assertFalse(res["raw_leak_detected"])
        self.assertEqual(res["quarantined_claim_count"], 5)
        self.assertEqual(res["gate_bps"], -28000)
        for rule in (
            "PG-G29-KERNEL-SORRY",
            "PG-G29-DBM-VACUOUS",
            "PG-G29-JUNK-DIVZERO",
            "PG-G29-JUNK-NATSUB-ZERO",
            "PG-G29-QUARANTINE-PROPAGATED",
            "PG-G29-VENDI-BELOW-FLOOR",
        ):
            self.assertIn(rule, res["violations"])

    def test_sarif_v210_export_and_uri_traversal_guard(self) -> None:
        res = audit_g29_claimcert_bundle(build_g29_quarantine_demo_bundle())
        sarif = export_g29_claimcert_sarif_v210(res)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["columnKind"], "utf16CodeUnits")
        self.assertGreaterEqual(len(run["results"]), 5)
        self.assertNotIn(chr(36), json.dumps(sarif))

        bad_uris = [
            "/etc/passwd",
            "../secret.lean",
            "foo/%2e%2e/bar.lean",
            "foo\\..\\bar.lean",
            "https://evil.example/a.lean",
            "a\x00b.lean",
            "cost_" + chr(36) + "10.lean",
        ]
        for u in bad_uris:
            norm, err = normalize_g29_sarif_uri(u)
            self.assertIsNone(norm)
            self.assertIsNotNone(err)
            bad_res = audit_g29_claimcert_bundle({"artifact_uri": u, "lean_source": "theorem ok : 1 = 1 := rfl"})
            self.assertEqual(bad_res["verdict"], "REJECT")
            self.assertEqual(bad_res["primary_code"], "PG-G29-SARIF-URI")

    def test_strict_json_loads_rejects_dup_keys_and_nan(self) -> None:
        with self.assertRaises(ValueError):
            strict_json_loads_g29('{"a": 1, "a": 2}')
        with self.assertRaises(ValueError):
            strict_json_loads_g29('{"a": NaN}')
        with self.assertRaises(ValueError):
            strict_json_loads_g29('{"a": Infinity}')

    def test_strict_type_fail_closed(self) -> None:
        self.assertEqual(gate_g29_bps(EvilInt(1), 1, 1, 1, 1, 40000), -29000)
        self.assertEqual(gate_g29_bps(True, 1, 1, 1, 1, 40000), -29000)
        self.assertEqual(lattice_join(EvilInt(1), 2), 4)

    def test_cli_check_g29_claimcert_selftest_demo_and_sarif_out(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["check-g29-claimcert", "--self-test", "--format", "json"])
        self.assertEqual(rc, 0)
        obj = json.loads(buf.getvalue())
        self.assertEqual(obj["verdict"], "ACCEPT")

        with tempfile.TemporaryDirectory() as td:
            sarif_path = pathlib.Path(td) / "g29_demo.sarif"
            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                rc2 = cli.main([
                    "check-g29-claimcert",
                    "--quarantine-demo",
                    "--format",
                    "sarif",
                    "--sarif-out",
                    str(sarif_path),
                ])
            self.assertEqual(rc2, 1)
            sarif_disk = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertEqual(sarif_disk["version"], "2.1.0")
            self.assertEqual(sarif_disk["runs"][0]["properties"]["verdict"], "REJECT")
            self.assertFalse(sarif_disk["runs"][0]["properties"]["raw_leak_detected"])

        buf3 = io.StringIO()
        with redirect_stdout(buf3):
            rc3 = cli.main(["check-g29-claimcert", "--self-test", "--format", "junit"])
        self.assertEqual(rc3, 0)
        self.assertIn("ProofGate.G29ClaimCertQuarantineGate", buf3.getvalue())


if __name__ == "__main__":
    unittest.main()
