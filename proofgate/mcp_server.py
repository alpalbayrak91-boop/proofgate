"""Optional FastMCP v2.0.0 server exposing ProofGate verification gates cleanly to AI agents."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
from typing import Any, Dict, Mapping, Optional, Sequence

from .lean_gate import check_lean_source
from .leanchecker_bridge import replay_lean_kernel
from .sarif_export import export_sarif, findings_from_gate_result
from .spec_diff_reward_hack_gate import audit_spec_vs_candidate_submission
from .substance_linter import audit_lean_substance
from .trajectory_difc_gate import evaluate_trajectory_difc


def proofgate_check_lean(
    lean_source: str,
    strict: bool = True,
    auto_implicit_false: bool = True,
) -> Dict[str, Any]:
    """Run static Lean 4 faithfulness, vacuity, escape, and axiom-coverage audit."""
    return check_lean_source(
        lean_source,
        require_print_axioms=True,
        require_auto_implicit_false=auto_implicit_false,
        check_vacuity=True,
        strict=strict,
    ).to_dict()


def proofgate_replay_kernel(
    lean_path: str,
    fresh: bool = False,
    also_static_gate: bool = True,
    require_toolchain: bool = False,
) -> Dict[str, Any]:
    """Compile a Lean file with --trust=0 and replay its .olean via official C++ leanchecker."""
    path_obj = pathlib.Path(lean_path)
    k_res = replay_lean_kernel(path_obj, fresh=fresh, require_toolchain=require_toolchain).to_dict()
    if also_static_gate and path_obj.is_file():
        s_res = check_lean_source(path_obj.read_text(encoding="utf-8"), strict=True).to_dict()
        k_res["static_gate"] = s_res
        if s_res.get("verdict") != "ACCEPT":
            k_res["verdict"] = "REJECT"
            k_res["primary_code"] = str(s_res.get("primary_code") or k_res["primary_code"])
            k_res["violations"] = list(dict.fromkeys([*k_res.get("violations", []), *s_res.get("violations", [])]))
    return k_res


def proofgate_audit_spec_diff(base_source: str, head_source: str) -> Dict[str, Any]:
    """Verify candidate Lean proof faithfully matches baseline specification without reward hacking."""
    return audit_spec_vs_candidate_submission(base_source, head_source)


def proofgate_export_sarif(
    lean_source: str,
    artifact_uri: str = "Spec.lean",
    strict: bool = True,
) -> Dict[str, Any]:
    """Audit Lean 4 source and return GitHub Code Scanning / VS Code compatible SARIF v2.1.0 JSON."""
    res = check_lean_source(lean_source, strict=strict).to_dict()
    findings = findings_from_gate_result(res, artifact_uri=artifact_uri, source=lean_source)
    return export_sarif(findings)


def proofgate_check_substance(
    lean_source: str,
    min_substance_bps: int = 5000,
    strict_substance: bool = False,
) -> Dict[str, Any]:
    """Audit Lean 4 theorems for mathematical substance vs binderless decide/unfold/tautology filler."""
    return audit_lean_substance(
        lean_source,
        min_substance_bps=min_substance_bps,
        strict=strict_substance,
    )


def check_trajectory_difc(
    trajectory: Mapping[str, Any],
    macaroon_key_hex: str = "",
    endorsement_key_hex: str = "",
    fail_fast: bool = False,
    emit_sarif: bool = False,
) -> Dict[str, Any]:
    """Verify multi-step agent trajectory via Layer 6 DIFC lattice, Macaroon caveats, and schema epoch pinning."""
    env_m = (os.environ.get("PROOFGATE_MACAROON_KEY_HEX") or "").strip()
    env_e = (os.environ.get("PROOFGATE_ENDORSEMENT_KEY_HEX") or "").strip()
    eff_m_hex = env_m or macaroon_key_hex.strip()
    eff_e_hex = env_e or endorsement_key_hex.strip()
    m_key = bytes.fromhex(eff_m_hex) if eff_m_hex else None
    e_key = bytes.fromhex(eff_e_hex) if eff_e_hex else None
    res = evaluate_trajectory_difc(
        trajectory,
        macaroon_key=m_key,
        endorsement_key=e_key,
        fail_fast=fail_fast,
    )
    out = res.to_dict()
    if emit_sarif:
        out["sarif"] = res.to_sarif()
    return out


proofgate_check_trajectory_difc = check_trajectory_difc


def create_fastmcp_server() -> Any:
    """Instantiate FastMCP server with ProofGate v2.0.0 tools (lazy-imports `mcp` optional extra)."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        try:
            from mcp.server.mcpserver import MCPServer as FastMCP
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Optional dependency `mcp` is required; install via `pip install proofgate[mcp]`") from exc

    server = FastMCP("proofgate-v2.0")
    server.tool()(proofgate_check_lean)
    server.tool()(proofgate_replay_kernel)
    server.tool()(proofgate_audit_spec_diff)
    server.tool()(proofgate_export_sarif)
    server.tool()(proofgate_check_substance)
    server.tool()(check_trajectory_difc)
    return server


async def _self_test() -> Dict[str, Any]:
    srv = create_fastmcp_server()
    tools = await srv.list_tools()
    tool_names = sorted(t.name for t in tools)
    sample = "set_option autoImplicit false\ntheorem ok_thm (n : Nat) : n + 0 = n := rfl\n#print axioms ok_thm\n"
    chk = proofgate_check_lean(sample)
    sub = proofgate_check_substance(sample)
    sarif = proofgate_export_sarif("theorem bad : 1 = 1 := by sorry")
    traj = check_trajectory_difc(
        {
            "trajectory_id": "mcp-selftest",
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
                    "target_domain": "evil.invalid",
                },
            ],
        }
    )
    return {
        "all_pass": (
            len(tool_names) == 6
            and chk["verdict"] == "ACCEPT"
            and sub["verdict"] == "ACCEPT"
            and len(sarif["runs"][0]["results"]) >= 1
            and traj["verdict"] == "REJECT"
            and "PG-TRAJ-001" in traj["triggered_rule_ids"]
        ),
        "tool_count": len(tool_names),
        "tools": tool_names,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ProofGate v2.0.0 FastMCP Verification Server")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        res = asyncio.run(_self_test())
        print(json.dumps(res, indent=2))
        return 0 if res["all_pass"] else 1
    create_fastmcp_server().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
