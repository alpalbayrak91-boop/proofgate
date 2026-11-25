"""Unit, exhaustive, PBT, and adversarial tests for RFC 8785 JCS, RFC 6962 proofs, and SLSA/DSSE."""
from __future__ import annotations

import copy
import math
import random
import unittest

from proofgate import (
    MerkleTree,
    build_consistency_proof,
    build_in_toto_slsa_statement,
    canonical_json_bytes,
    canonical_json_dumps,
    dsse_pae,
    dsse_sign_hmac_sha256,
    dsse_verify_hmac_sha256,
    hash_leaf,
    hash_node,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_slsa_provenance,
)


class TestMuhurAndSlsa(unittest.TestCase):
    def test_strict_rfc8785_jcs_numbers_and_utf16_key_sort(self) -> None:
        self.assertEqual(canonical_json_dumps(-0.0), "0")
        self.assertEqual(canonical_json_dumps(0.0), "0")
        self.assertEqual(canonical_json_dumps(1.0), "1")
        self.assertEqual(canonical_json_dumps(100000.0), "100000")
        self.assertEqual(canonical_json_dumps(1e20), "100000000000000000000")
        self.assertEqual(canonical_json_dumps(1e21), "1e+21")
        self.assertEqual(canonical_json_dumps(1e-6), "0.000001")
        self.assertEqual(canonical_json_dumps(1e-7), "1e-7")
        self.assertEqual(canonical_json_dumps({"z": -0.0, "a": 3.5}), '{"a":3.5,"z":0}')

        # UTF-16-BE key sorting: U+10000 (0xD800 0xDC00) MUST sort before U+E000 (0xE000)
        obj = {"\uE000": 1, "\U00010000": 2}
        self.assertEqual(canonical_json_dumps(obj), '{"\U00010000":2,"\uE000":1}')

        for bad_num in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                canonical_json_bytes({"bad": bad_num})
        with self.assertRaises(TypeError):
            canonical_json_bytes({1: "non_string_key"})  # type: ignore[dict-item]

    def test_rfc6962_domain_separation_and_exhaustive_consistency_0_to_16(self) -> None:
        a = b"alpha"
        b = b"beta"
        self.assertNotEqual(hash_leaf(b"\x01" + a + b), hash_node(a, b))

        payloads = [f"leaf-{i}".encode("utf-8") for i in range(16)]
        tree = MerkleTree(payloads)

        for n in range(0, 17):
            sub = MerkleTree(payloads[:n])
            for m in range(0, n + 1):
                old_root = sub.root_at_size(m)
                new_root = sub.root_hex
                cproof = sub.consistency_proof(m)
                self.assertEqual(cproof["old_root"], old_root)
                self.assertEqual(cproof["new_root"], new_root)
                self.assertTrue(
                    verify_consistency_proof(m, n, cproof["consistency_path"], old_root, new_root),
                    f"Failed valid consistency for m={m}, n={n}",
                )
                self.assertEqual(cproof["consistency_path"], build_consistency_proof(m, payloads[:n]))

                # Negative: wrong new_root or old_root must fail when tree sizes commit to a non-empty prefix
                if 0 < m or n == 0:
                    bad_root = ("0" if new_root[0] != "0" else "1") + new_root[1:]
                    self.assertFalse(verify_consistency_proof(m, n, cproof["consistency_path"], old_root, bad_root))
                if 0 < m < n:
                    bad_old = ("0" if old_root[0] != "0" else "1") + old_root[1:]
                    self.assertFalse(verify_consistency_proof(m, n, cproof["consistency_path"], bad_old, new_root))

        # Verify tampering single element in consistency proof fails
        c37 = tree.consistency_proof(3, 7)
        tampered_path = list(c37["consistency_path"])
        tampered_path[0] = ("f" if tampered_path[0][0] != "f" else "0") + tampered_path[0][1:]
        self.assertFalse(
            verify_consistency_proof(3, 7, tampered_path, c37["old_root"], c37["new_root"])
        )
        # Reject invalid sizes / bools / malformed hex
        self.assertFalse(verify_consistency_proof(5, 3, [], c37["old_root"], c37["new_root"]))
        self.assertFalse(verify_consistency_proof(True, 3, [], c37["old_root"], c37["new_root"]))  # type: ignore[arg-type]
        self.assertFalse(verify_consistency_proof(3, 7, ["not-hex"], c37["old_root"], c37["new_root"]))

    def test_pbt_500_randomized_merkle_inclusion_and_consistency(self) -> None:
        rng = random.Random(20261125)
        for trial in range(500):
            n = rng.randint(1, 25)
            records = [{"seq": i, "trial": trial, "v": rng.randint(-1000, 1000)} for i in range(n)]
            tree = MerkleTree.from_json_records(records)
            idx = rng.randrange(n)
            inc = tree.inclusion_proof(idx)
            self.assertTrue(
                verify_inclusion_proof(
                    canonical_json_bytes(records[idx]),
                    inc["leaf_index"],
                    inc["tree_size"],
                    inc["audit_path"],
                    inc["root"],
                )
            )
            m = rng.randint(1, n)
            cons = tree.consistency_proof(m)
            self.assertTrue(
                verify_consistency_proof(m, n, cons["consistency_path"], cons["old_root"], cons["new_root"])
            )

    def test_dsse_pae_framing_and_slsa_v1_provenance_verify_and_tamper(self) -> None:
        # Framing boundary ambiguity resistance: ("ab", b"c") vs ("a", b"bc")
        self.assertNotEqual(dsse_pae("ab", b"c"), dsse_pae("a", b"bc"))

        digest_a = "a" * 64
        stmt = build_in_toto_slsa_statement(
            [{"name": "artifact.whl", "digest": {"sha256": digest_a}}],
            external_parameters={"merkle_root": "b" * 64},
            builder_version={"proofgate": "1.0.0"},
        )
        key = b"proofgate-test-hmac-secret-key-32b"
        env = dsse_sign_hmac_sha256(canonical_json_bytes(stmt), key)

        raw = dsse_verify_hmac_sha256(env, key)
        self.assertIsNotNone(raw)
        self.assertIsNone(dsse_verify_hmac_sha256(env, b"wrong-key"))

        res_ok = verify_slsa_provenance(
            env,
            key,
            expected_subjects={"artifact.whl": digest_a},
        )
        self.assertEqual(res_ok.verdict, "ACCEPT")
        self.assertEqual(res_ok.primary_code, "SLSA_PROVENANCE_VERIFIED")

        # Adversarial: wrong subject digest
        res_bad_sub = verify_slsa_provenance(
            env,
            key,
            expected_subjects={"artifact.whl": "c" * 64},
        )
        self.assertEqual(res_bad_sub.verdict, "REJECT")
        self.assertIn("REJECT_SLSA_SUBJECT_DIGEST_MISMATCH", res_bad_sub.violations)

        # Adversarial: tampered envelope signature
        forged_env = copy.deepcopy(env)
        forged_env["signatures"][0]["sig"] = "AAAA" + forged_env["signatures"][0]["sig"][4:]
        res_bad_sig = verify_slsa_provenance(forged_env, key)
        self.assertEqual(res_bad_sig.verdict, "REJECT")
        self.assertIn("REJECT_SLSA_DSSE_SIGNATURE", res_bad_sig.violations)

        # Adversarial: signed statement with wrong predicateType
        bad_stmt = copy.deepcopy(stmt)
        bad_stmt["predicateType"] = "https://example.invalid/v0"
        bad_env = dsse_sign_hmac_sha256(canonical_json_bytes(bad_stmt), key)
        res_bad_pred = verify_slsa_provenance(bad_env, key)
        self.assertEqual(res_bad_pred.verdict, "REJECT")
        self.assertIn("REJECT_SLSA_PREDICATE_TYPE", res_bad_pred.violations)

    def test_jcs_control_escapes_booleans_null_and_negative_floats(self) -> None:
        obj = {"flag": True, "none": None, "neg": -0.0, "small": -1e-7, "txt": "line1\n\t\"q\""}
        out = canonical_json_dumps(obj)
        self.assertEqual(out, '{"flag":true,"neg":0,"none":null,"small":-1e-7,"txt":"line1\\n\\t\\"q\\""}')

    def test_slsa_rejects_malformed_envelope_and_mismatched_builder_id(self) -> None:
        digest = "d" * 64
        stmt = build_in_toto_slsa_statement([{"name": "app.py", "digest": {"sha256": digest}}], builder_id="builder-a")
        key = b"secret-k"
        env = dsse_sign_hmac_sha256(canonical_json_bytes(stmt), key)
        self.assertEqual(verify_slsa_provenance(env, key, expected_builder_id="builder-b").primary_code, "REJECT_SLSA_BUILDER_ID_MISMATCH")
        self.assertEqual(verify_slsa_provenance({"payloadType": "bad", "payload": "e30=", "signatures": []}, key).primary_code, "REJECT_SLSA_DSSE_SIGNATURE")


if __name__ == "__main__":
    unittest.main()
