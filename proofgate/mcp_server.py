"""Optional FastMCP v1.2.0 server exposing ProofGate verification gates cleanly to AI agents."""
from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
from typing import Any, Dict, Optional, Sequence

from .lean_gate import check_lean_source
from .leanchecker_bridge import replay_lean_kernel
from .sarif_export import export_sarif, findings_from_gate_result
from .spec_diff_reward_hack_gate import audit_spec_vs_candidate_submission
from .substance_linter import audit_lean_substance


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


def create_fastmcp_server() -> Any:
    """Instantiate FastMCP server with ProofGate tools (lazy-imports `mcp` optional extra)."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        try:
            from mcp.server.mcpserver import MCPServer as FastMCP
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Optional dependency `mcp` is required; install via `pip install proofgate[mcp]`") from exc

    server = FastMCP("proofgate-v1.4")
    server.tool()(proofgate_check_lean)
    server.tool()(proofgate_replay_kernel)
    server.tool()(proofgate_audit_spec_diff)
    server.tool()(proofgate_export_sarif)
    server.tool()(proofgate_check_substance)
    return server


async def _self_test() -> Dict[str, Any]:
    srv = create_fastmcp_server()
    tools = await srv.list_tools()
    tool_names = sorted(t.name for t in tools)
    sample = "set_option autoImplicit false\ntheorem ok_thm (n : Nat) : n + 0 = n := rfl\n#print axioms ok_thm\n"
    chk = proofgate_check_lean(sample)
    sub = proofgate_check_substance(sample)
    sarif = proofgate_export_sarif("theorem bad : 1 = 1 := by sorry")
    return {
        "all_pass": (
            len(tool_names) == 5
            and chk["verdict"] == "ACCEPT"
            and sub["verdict"] == "ACCEPT"
            and len(sarif["runs"][0]["results"]) >= 1
        ),
        "tool_count": len(tool_names),
        "tools": tool_names,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ProofGate v1.2.0 FastMCP Verification Server")
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
