"""CLI entrypoint for ProofGate v1.0.0 Omni-Gate."""
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
from .muhur_rfc6962 import MerkleTree, canonical_json_bytes
from .sarif_export import export_sarif, findings_from_gate_result
from .slsa_provenance import build_in_toto_slsa_statement, dsse_sign_hmac_sha256, verify_slsa_provenance


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


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="proofgate", description="ProofGate v1.0.0 Omni-Gate Verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

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


    p_g29 = sub.add_parser(
        "check-g29-claimcert",
        help="Audit Lean 4 COC DAG, Swarm Quarantine Redaction, Exposure Predictor & Vendi VS_2/VAS_2 (SARIF v2.1.0)",
    )
    p_g29.add_argument("path", nargs="?", default=None, type=pathlib.Path)
    p_g29.add_argument("--self-test", action="store_true", help="Run canonical clean Gate 2.9 COC + Vendi self-test")
    p_g29.add_argument("--quarantine-demo", action="store_true", help="Run adversarial quarantine redaction demo returning exit code 1")
    p_g29.add_argument("--min-vs2", type=float, default=3.0, help="Minimum canonical Vendi VS_2 floor for AST portfolios")
    p_g29.add_argument("--sarif-out", type=pathlib.Path, default=None, help="Optional OASIS SARIF v2.1.0 output file path")
    p_g29.add_argument("--format", choices=("json", "sarif", "junit"), default="json")

    args = parser.parse_args(argv)

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


    if args.cmd == "check-g29-claimcert":
        from .g29_claimcert_quarantine_sarif_gate import (
            audit_g29_claimcert_bundle,
            build_g29_quarantine_demo_bundle,
            build_g29_selftest_bundle,
            export_g29_claimcert_sarif_v210,
            strict_json_loads_g29,
        )

        if args.quarantine_demo:
            g29_obj = build_g29_quarantine_demo_bundle()
            g29_uri = "formal/g29_quarantine_demo.lean"
        elif args.self_test or args.path is None:
            g29_obj = build_g29_selftest_bundle()
            g29_uri = "formal/g29_selftest_coc.lean"
        else:
            raw_g29 = args.path.read_text(encoding="utf-8")
            if args.path.suffix.lower() == ".json":
                g29_obj = strict_json_loads_g29(raw_g29)
                g29_uri = str(g29_obj.get("artifact_uri", args.path.name))
            else:
                g29_obj = {"lean_source": raw_g29, "artifact_uri": args.path.name}
                g29_uri = args.path.name
        res_g29 = audit_g29_claimcert_bundle(
            g29_obj,
            default_uri=g29_uri,
            min_vs2=args.min_vs2,
        )
        sarif_g29 = export_g29_claimcert_sarif_v210(res_g29, artifact_uri=g29_uri)
        if args.sarif_out is not None:
            args.sarif_out.parent.mkdir(parents=True, exist_ok=True)
            sarif_txt = json.dumps(sarif_g29, indent=2, ensure_ascii=False)
            args.sarif_out.write_text(sarif_txt + "\n", encoding="utf-8")
        if args.format == "sarif":
            print(json.dumps(sarif_g29, indent=2, ensure_ascii=False))
        elif args.format == "junit":
            print(export_junit_xml(res_g29, suite_name="ProofGate.G29ClaimCertQuarantineGate"))
        else:
            print(json.dumps(res_g29, indent=2, ensure_ascii=False))
        return 0 if res_g29.get("verdict") == "ACCEPT" else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
