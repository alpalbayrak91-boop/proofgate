"""CLI entrypoint for ProofGate v2.0.0 Omni-Gate."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
from typing import Any, Dict, List, Optional, Sequence

from .agent_eval import evaluate_fleet_runs, export_junit_xml, export_promptfoo_json
from .ast_gate import check_python_source
from .diff_gate import diff_lean_sources
from .lean_gate import check_lean_source
from .leanchecker_bridge import replay_lean_kernel
from .muhur_rfc6962 import MerkleTree, canonical_json_bytes, verify_inclusion_proof
from .sarif_export import export_sarif, findings_from_gate_result
from .slsa_provenance import build_in_toto_slsa_statement, dsse_sign_hmac_sha256, verify_slsa_provenance
from .substance_linter import audit_lean_substance
from .trajectory_difc_gate import evaluate_trajectory_difc, mint_macaroon


def _emit_gate_output(
    result_dict: Dict[str, Any],
    *,
    fmt: str,
    artifact_uri: str,
    source: str = "",
    suite_name: str = "ProofGate.OmniGate",
) -> None:
    if fmt == "sarif":
        findings = findings_from_gate_result(result_dict, artifact_uri=artifact_uri, source=source)
        print(json.dumps(export_sarif(findings), indent=2, ensure_ascii=False))
    elif fmt == "junit":
        print(export_junit_xml(result_dict, suite_name=suite_name))
    else:
        print(json.dumps(result_dict, indent=2, ensure_ascii=False))


def run_cli_self_test() -> Dict[str, Any]:
    """Deterministic offline self-test exercising all 6 ProofGate verification layers."""
    lean_ok = check_lean_source(
        "set_option autoImplicit false\ntheorem id_nat (n : Nat) : n + 0 = n := rfl\n#print axioms id_nat\n",
        strict=True,
    )
    lean_bad = check_lean_source("theorem bad : 1 = 2 := by sorry\n", strict=True)
    ast_ok = check_python_source("def add(a, b):\n    return a + b\n")
    ast_bad = check_python_source("import subprocess\n")
    diff_ok = diff_lean_sources(
        "theorem t (a : Nat) : a = a := rfl\n",
        "theorem t_moved (b : Nat) : b = b := rfl\n",
    )
    sub_ok = audit_lean_substance("theorem t (n : Nat) (h : n > 0) : n >= 1 := by omega\n", strict=True)

    mac_key = b"proofgate-selftest-macaroon-key"
    root_mac = mint_macaroon(
        mac_key,
        identifier="selftest-mac",
        nonce="selftest-nonce-1",
        root_scopes=["read", "network"],
    )
    traj_clean = evaluate_trajectory_difc(
        {
            "trajectory_id": "selftest-clean",
            "root_macaroon": root_mac.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "doc_read",
                    "action_kind": "read_resource",
                    "required_scope": "read",
                    "source_integrity": "USER_EXPLICIT",
                    "tool_schema": {"name": "doc_read", "description": "Read public doc"},
                }
            ],
        },
        macaroon_key=mac_key,
    )
    traj_trifecta = evaluate_trajectory_difc(
        {
            "trajectory_id": "selftest-trifecta",
            "root_macaroon": root_mac.to_dict(),
            "steps": [
                {
                    "step_index": 0,
                    "tool_name": "env_read",
                    "action_kind": "read_resource",
                    "required_scope": "read",
                    "source_secrecy_tags": ["SECRET_ENV"],
                    "source_integrity": "USER_EXPLICIT",
                },
                {
                    "step_index": 1,
                    "tool_name": "web_fetch",
                    "action_kind": "read_resource",
                    "required_scope": "read",
                    "source_integrity": "UNTRUSTED_EXTERNAL",
                },
                {
                    "step_index": 2,
                    "tool_name": "http_post",
                    "action_kind": "http_post",
                    "required_scope": "network",
                    "target_domain": "exfil.invalid",
                },
            ],
        },
        macaroon_key=mac_key,
    )
    leaf0 = canonical_json_bytes(traj_trifecta.step_traces[0])
    proof0 = traj_trifecta.receipt["inclusion_proofs"][0]
    merkle_ok = verify_inclusion_proof(
        leaf0,
        leaf_index=0,
        tree_size=traj_trifecta.receipt["tree_size"],
        audit_path_hex=proof0["audit_path"],
        expected_root_hex=traj_trifecta.receipt["merkle_root"],
    )

    checks = {
        "lean_gate": lean_ok.verdict == "ACCEPT" and lean_bad.verdict == "REJECT",
        "ast_gate": ast_ok.verdict == "ACCEPT" and ast_bad.verdict == "REJECT",
        "diff_gate": diff_ok.verdict == "ACCEPT",
        "substance_gate": sub_ok["verdict"] == "ACCEPT",
        "trajectory_difc_accept": traj_clean.verdict == "ACCEPT",
        "trajectory_difc_trifecta_reject": (
            traj_trifecta.verdict == "REJECT"
            and "PG-TRAJ-001" in traj_trifecta.triggered_rule_ids
        ),
        "rfc6962_trajectory_receipt": merkle_ok,
    }
    return {
        "version": "2.0.0",
        "all_pass": all(checks.values()),
        "checks": checks,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="proofgate", description="ProofGate v2.0.0 Omni-Gate Verifier")
    parser.add_argument("--self-test", action="store_true", help="Run built-in 6-layer deterministic self-test")
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_lean = sub.add_parser("check-lean", help="Audit a Lean 4 file")
    p_lean.add_argument("path", type=pathlib.Path)
    p_lean.add_argument("--no-print-axioms", action="store_true")
    p_lean.add_argument("--strict", action="store_true")
    p_lean.add_argument("--auto-implicit-false", action="store_true")
    p_lean.add_argument("--no-vacuity", action="store_true")
    p_lean.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    p_ast = sub.add_parser("check-ast", help="Audit a Python file statically")
    p_ast.add_argument("path", type=pathlib.Path)
    p_ast.add_argument("--max-range-bound", type=int, default=10_000)
    p_ast.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    p_diff = sub.add_parser("diff-lean", help="Compare base and head Lean 4 revisions")
    p_diff.add_argument("base_path", type=pathlib.Path)
    p_diff.add_argument("head_path", type=pathlib.Path)
    p_diff.add_argument("--include-private", action="store_true")
    p_diff.add_argument("--allow-drops", action="store_true")
    p_diff.add_argument("--disallow-renames", action="store_true")
    p_diff.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    p_merkle = sub.add_parser("merkle-root", help="Compute RFC 6962 SHA-256 Merkle root over files")
    p_merkle.add_argument("paths", nargs="+", type=pathlib.Path)
    p_merkle.add_argument("--proof-index", type=int, default=None)
    p_merkle.add_argument("--consistency-old", type=int, default=None)
    p_merkle.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    p_slsa = sub.add_parser("slsa-attest", help="Build in-toto SLSA v1.0 Provenance & DSSEv1 envelope")
    p_slsa.add_argument("paths", nargs="+", type=pathlib.Path)
    p_slsa.add_argument("--hmac-key", default=None, help="HMAC signing secret string (avoid in shell history; prefer --hmac-key-env)")
    p_slsa.add_argument("--hmac-key-env", default="PROOFGATE_HMAC_KEY", help="Env var holding HMAC signing secret")
    p_slsa.add_argument("--ephemeral-key", action="store_true", help="Generate random ephemeral HMAC key for local test envelopes")
    p_slsa.add_argument("--merkle", action="store_true", help="Include RFC 6962 Merkle root in externalParameters")
    p_slsa.add_argument("--verify", action="store_true", help="Self-verify generated DSSE envelope")
    p_slsa.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    p_eval = sub.add_parser("eval-agents", help="Evaluate multi-agent trajectory ledger JSON")
    p_eval.add_argument("input_json", type=pathlib.Path)
    p_eval.add_argument("--min-wilson-lcb-bps", type=int, default=7000)
    p_eval.add_argument("--cusum-threshold", type=float, default=1.5)
    p_eval.add_argument("--format", choices=("json", "sarif", "junit", "promptfoo"), default="json")

    p_kern = sub.add_parser("check-kernel", help="Compile Lean 4 with --trust=0 and replay via C++ leanchecker")
    p_kern.add_argument("path", type=pathlib.Path)
    p_kern.add_argument("--fresh", action="store_true", help="Pass --fresh to leanchecker (full stdlib replay, higher timeout)")
    p_kern.add_argument("--require-toolchain", action="store_true", help="Fail closed if lean/leanchecker binaries are unavailable")
    p_kern.add_argument("--also-static-gate", action="store_true", help="Run ProofGate static Lean faithfulness gate in addition to kernel replay")
    p_kern.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    p_sub = sub.add_parser("check-substance", help="Audit Lean 4 theorems for mathematical substance vs trivial filler")
    p_sub.add_argument("path", type=pathlib.Path)
    p_sub.add_argument("--min-substance-bps", type=int, default=5000)
    p_sub.add_argument("--strict-substance", action="store_true")
    p_sub.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    p_traj = sub.add_parser(
        "check-trajectory",
        help="Verify multi-step agent trajectory via Layer 6 DIFC + Macaroon + Schema Epoch gate",
    )
    p_traj.add_argument("trajectory_json", type=pathlib.Path)
    p_traj.add_argument("--sarif", type=pathlib.Path, default=None, help="Optional path to write SARIF v2.1.0 output")
    p_traj.add_argument("--receipt", type=pathlib.Path, default=None, help="Optional path to write RFC 6962 Merkle receipt JSON")
    p_traj.add_argument("--macaroon-key-hex", default=None, help="Optional hex HMAC root key for Macaroon verification")
    p_traj.add_argument("--endorsement-key-hex", default=None, help="Optional hex HMAC key for human declassification endorsements")
    p_traj.add_argument("--fail-fast", action="store_true", help="Stop evaluation on first rule violation")
    p_traj.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    args = parser.parse_args(argv)

    if args.self_test:
        st = run_cli_self_test()
        print(json.dumps(st, indent=2, ensure_ascii=False))
        return 0 if st["all_pass"] else 1

    if not args.cmd:
        parser.error("the following arguments are required: cmd")

    if args.cmd == "check-lean":
        src = args.path.read_text(encoding="utf-8")
        res = check_lean_source(
            src,
            require_print_axioms=not args.no_print_axioms,
            require_auto_implicit_false=args.auto_implicit_false,
            check_vacuity=not args.no_vacuity,
            strict=args.strict,
        )
        _emit_gate_output(res.to_dict(), fmt=args.format, artifact_uri=str(args.path), source=src, suite_name="ProofGate.LeanGate")
        return 0 if res.verdict == "ACCEPT" else 1

    if args.cmd == "check-ast":
        src = args.path.read_text(encoding="utf-8")
        res = check_python_source(src, max_range_bound=args.max_range_bound)
        _emit_gate_output(res.to_dict(), fmt=args.format, artifact_uri=str(args.path), source=src, suite_name="ProofGate.ASTGate")
        return 0 if res.verdict == "ACCEPT" else 1

    if args.cmd == "diff-lean":
        base_src = args.base_path.read_text(encoding="utf-8")
        head_src = args.head_path.read_text(encoding="utf-8")
        res = diff_lean_sources(
            base_src,
            head_src,
            include_private=args.include_private,
            allow_drops=args.allow_drops,
            allow_renames=not args.disallow_renames,
        )
        _emit_gate_output(res.to_dict(), fmt=args.format, artifact_uri=str(args.head_path), source=head_src, suite_name="ProofGate.DiffGate")
        return 0 if res.verdict == "ACCEPT" else 1

    if args.cmd == "merkle-root":
        payloads: List[bytes] = []
        for p in args.paths:
            raw = p.read_bytes()
            if p.suffix.lower() == ".json":
                raw = canonical_json_bytes(json.loads(raw.decode("utf-8")))
            payloads.append(raw)
        tree = MerkleTree(payloads)
        out: Dict[str, Any] = {"tree_size": tree.size, "root": tree.root_hex}
        if args.proof_index is not None:
            out["inclusion_proof"] = tree.inclusion_proof(args.proof_index)
        if args.consistency_old is not None:
            out["consistency_proof"] = tree.consistency_proof(args.consistency_old)
        if args.format == "junit":
            print(export_junit_xml({"verdict": "ACCEPT", "primary_code": "MERKLE_ROOT", "violations": []}, suite_name="ProofGate.Merkle"))
        elif args.format == "sarif":
            print(json.dumps(export_sarif([]), indent=2))
        else:
            print(json.dumps(out, indent=2))
        return 0

    if args.cmd == "slsa-attest":
        subjects: List[Dict[str, Any]] = []
        raw_payloads: List[bytes] = []
        for p in args.paths:
            raw = p.read_bytes()
            raw_payloads.append(raw)
            subjects.append({
                "name": p.name,
                "digest": {"sha256": hashlib.sha256(raw).hexdigest()},
            })
        ext_params: Dict[str, Any] = {"inputs": [str(p) for p in args.paths]}
        if args.merkle:
            tree = MerkleTree(raw_payloads)
            ext_params["rfc6962_merkle_root"] = tree.root_hex
            ext_params["rfc6962_tree_size"] = tree.size

        stmt = build_in_toto_slsa_statement(subjects, external_parameters=ext_params)
        stmt_bytes = canonical_json_bytes(stmt)

        key_bytes: Optional[bytes] = None
        if args.hmac_key is not None:
            key_bytes = args.hmac_key.encode("utf-8")
        elif args.hmac_key_env and os.environ.get(args.hmac_key_env):
            key_bytes = os.environ[args.hmac_key_env].encode("utf-8")
        elif args.ephemeral_key:
            key_bytes = os.urandom(32)

        if key_bytes is not None:
            envelope = dsse_sign_hmac_sha256(stmt_bytes, key_bytes)
            out_obj: Dict[str, Any] = {"statement": stmt, "dsse": envelope}
            if args.verify:
                v_res = verify_slsa_provenance(
                    envelope,
                    key_bytes,
                    expected_subjects={s["name"]: s["digest"]["sha256"] for s in subjects},
                )
                out_obj["verification"] = v_res.to_dict()
                rc = 0 if v_res.verdict == "ACCEPT" else 1
            else:
                rc = 0
        else:
            out_obj = {"statement": stmt, "dsse": None}
            rc = 0

        if args.format == "junit":
            gate = {"verdict": "ACCEPT" if rc == 0 else "REJECT", "primary_code": "SLSA_ATTEST", "violations": []}
            print(export_junit_xml(gate, suite_name="ProofGate.SLSA"))
        elif args.format == "sarif":
            print(json.dumps(export_sarif([]), indent=2))
        else:
            print(json.dumps(out_obj, indent=2, ensure_ascii=False))
        return rc

    if args.cmd == "eval-agents":
        loaded = json.loads(args.input_json.read_text(encoding="utf-8"))
        runs_list = loaded["runs"] if isinstance(loaded, dict) and "runs" in loaded else loaded
        if not isinstance(runs_list, list):
            raise ValueError("eval-agents input must be a JSON array or an object with a 'runs' list")
        res = evaluate_fleet_runs(
            runs_list,
            min_wilson_lcb_bps=args.min_wilson_lcb_bps,
            cusum_threshold=args.cusum_threshold,
        )
        if args.format == "promptfoo":
            print(json.dumps(export_promptfoo_json(res), indent=2, ensure_ascii=False))
        else:
            _emit_gate_output(res, fmt=args.format, artifact_uri=str(args.input_json), suite_name="ProofGate.AgentEval")
        return 0 if res["verdict"] == "ACCEPT" else 1

    if args.cmd == "check-kernel":
        res_obj = replay_lean_kernel(
            args.path,
            fresh=args.fresh,
            require_toolchain=args.require_toolchain,
        )
        out_dict = res_obj.to_dict()
        src = args.path.read_text(encoding="utf-8") if args.path.is_file() else ""
        if args.also_static_gate and args.path.is_file():
            s_res = check_lean_source(
                src,
                require_print_axioms=True,
                require_auto_implicit_false=True,
                check_vacuity=True,
                strict=True,
            ).to_dict()
            out_dict["static_gate"] = s_res
            if s_res.get("verdict") != "ACCEPT":
                out_dict["verdict"] = "REJECT"
                out_dict["primary_code"] = str(s_res.get("primary_code") or out_dict["primary_code"])
                out_dict["violations"] = list(dict.fromkeys([*out_dict.get("violations", []), *s_res.get("violations", [])]))
                out_dict["findings"] = [*out_dict.get("findings", []), *s_res.get("findings", [])]
        _emit_gate_output(
            out_dict,
            fmt=args.format,
            artifact_uri=str(args.path),
            source=src,
            suite_name="ProofGate.KernelReplay",
        )
        return 0 if out_dict["verdict"] in ("ACCEPT", "SKIPPED_NO_TOOLCHAIN") else 1

    if args.cmd == "check-substance":
        src = args.path.read_text(encoding="utf-8")
        res_dict = audit_lean_substance(
            src,
            min_substance_bps=args.min_substance_bps,
            strict=args.strict_substance,
        )
        _emit_gate_output(
            res_dict,
            fmt=args.format,
            artifact_uri=str(args.path),
            source=src,
            suite_name="ProofGate.SubstanceLinter",
        )
        return 0 if res_dict["verdict"] == "ACCEPT" else 1

    if args.cmd == "check-trajectory":
        raw_text = args.trajectory_json.read_text(encoding="utf-8")
        traj_doc = json.loads(raw_text)
        m_key = bytes.fromhex(args.macaroon_key_hex) if args.macaroon_key_hex else None
        e_key = bytes.fromhex(args.endorsement_key_hex) if args.endorsement_key_hex else None
        t_res = evaluate_trajectory_difc(
            traj_doc,
            macaroon_key=m_key,
            endorsement_key=e_key,
            fail_fast=args.fail_fast,
            source_text=raw_text,
        )
        t_dict = t_res.to_dict()
        if args.sarif is not None:
            sarif_obj = t_res.to_sarif(artifact_uri=str(args.trajectory_json), source=raw_text)
            args.sarif.parent.mkdir(parents=True, exist_ok=True)
            args.sarif.write_text(json.dumps(sarif_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if args.receipt is not None:
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(json.dumps(t_res.receipt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        _emit_gate_output(
            t_dict,
            fmt=args.format,
            artifact_uri=str(args.trajectory_json),
            source=raw_text,
            suite_name="ProofGate.TrajectoryDIFC",
        )
        return 0 if t_res.verdict == "ACCEPT" else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
