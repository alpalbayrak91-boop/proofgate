"""SARIF v2.1.0 exporter compatible with GitHub Code Scanning and VS Code SARIF Viewer."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_URI = "https://github.com/alpalbayrak91-boop/proofgate"


@dataclass(frozen=True)
class SarifFinding:
    rule_id: str
    violation_code: str
    message: str
    artifact_uri: str
    start_line: int = 1
    start_column: int = 1
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    char_utf16: int = 0
    char_length_utf16: int = 0
    level: str = "error"
    snippet: str = ""


_RULE_CATALOG: Dict[str, Tuple[str, str, str, str]] = {
    "REJECT_LEAN_SORRY": ("PG-LEAN-001", "Incomplete proof via sorry", "error", "ProofGate detected a live sorry placeholder in Lean 4 code."),
    "REJECT_LEAN_SORRY_WARNING": ("PG-LEAN-001", "Incomplete proof via sorry", "error", "Lean compiler emitted a sorry declaration warning."),
    "REJECT_LEAN_ADMIT": ("PG-LEAN-002", "Incomplete proof via admit", "error", "ProofGate detected a live admit placeholder in Lean 4 code."),
    "REJECT_LEXER_INTERP_SORRY_EVASION": ("PG-LEAN-003", "Interpolated string sorry evasion", "error", "Lean interpolated string s!\"...\" contains or conceals sorry evasion."),
    "REJECT_SKIP_KERNEL_TC": ("PG-LEAN-004", "Lean kernel type-checker bypass", "error", "Dangerous debug.skipKernelTC or proofAsSorry/byAsSorry option detected."),
    "REJECT_METAPROG_MKSORRY_ELAB": ("PG-LEAN-005", "Metaprogramming sorry or axiom injection", "error", "Metaprogramming helper Meta.mkSorry or elab sorry injection detected."),
    "REJECT_METAPROG_ADDDECL_AXIOM": ("PG-LEAN-005", "Metaprogramming sorry or axiom injection", "error", "Metaprogramming addDecl/axiomDecl axiom smuggling detected."),
    "REJECT_NATIVE_DECIDE_OFREDUCEBOOL": ("PG-LEAN-006", "Compiler-trust native_decide / ofReduceBool", "error", "Proof relies on native_decide, bv_decide, or Lean.ofReduceBool/Lean.trustCompiler."),
    "REJECT_NONSTANDARD_AXIOM": ("PG-LEAN-007", "Custom or non-standard axiom", "error", "Custom axiom declaration or non-standard axiom outside {propext, Classical.choice, Quot.sound}."),
    "REJECT_NONSTANDARD_AXIOM_WHITELIST": ("PG-LEAN-007", "Custom or non-standard axiom", "error", "Printed axioms contain an entry outside standard Lean 4 kernel axioms."),
    "REJECT_MISSING_PRINT_AXIOMS": ("PG-LEAN-008", "Missing #print axioms audit coverage", "error", "Public theorem is missing #print axioms verification receipt."),
    "REJECT_LOW_PRINT_AXIOMS_COVERAGE": ("PG-LEAN-008", "Missing #print axioms audit coverage", "error", "Public theorem #print axioms coverage is below 10000 bps."),
    "REJECT_MISSING_AUTO_IMPLICIT_FALSE": ("PG-LEAN-009", "Missing set_option autoImplicit false", "error", "Module does not enforce set_option autoImplicit false."),
    "REJECT_FREE_VAR_DECIDE": ("PG-LEAN-010", "Trivial or free-variable decide padding", "error", "Bound theorem uses bare decide or >50% trivial constant-tactic padding."),
    "REJECT_TRIVIAL_ISPAT": ("PG-LEAN-010", "Trivial or free-variable decide padding", "error", "More than 50% of theorems are binderless single-tactic trivial proofs."),
    "REJECT_VACUOUS_HYPOTHESIS": ("PG-LEAN-011", "Vacuous theorem with contradictory hypotheses", "error", "Theorem hypotheses are mutually contradictory (e.g. x < 0 and x > 5 or P and not P)."),
    "REJECT_UNTERMINATED_LEXER": ("PG-LEAN-012", "Unterminated comment/string or Trojan Unicode", "error", "Unterminated block comment/string or invisible bidirectional Unicode character detected."),
    "REJECT_UNSAFE_LEAN_ATTRIBUTE": ("PG-LEAN-013", "Unsafe Lean attribute or opaque/unsafe decl", "error", "Unsafe declaration, @[extern], @[implemented_by], @[csimp], or core typeclass hijack detected."),
    "REJECT_AST_SYNTAX_ERROR": ("PG-AST-001", "Python syntax error in AST gate", "error", "Python source failed ast.parse verification."),
    "REJECT_AST_FORBIDDEN_IMPORT": ("PG-AST-002", "Forbidden Python module import", "error", "Restricted system/IO/FFI module imported inside sandboxed Python operator."),
    "REJECT_AST_FORBIDDEN_BUILTIN": ("PG-AST-003", "Forbidden dynamic Python builtin", "error", "Dynamic code execution or reflection builtin (eval/exec/open/getattr) detected."),
    "REJECT_AST_DUNDER_ESCAPE": ("PG-AST-004", "Python dunder attribute escape", "error", "Dunder attribute access (__class__, __subclasses__, etc.) rejected."),
    "REJECT_AST_SAFE_RANGE_LIMIT_EXCEEDED": ("PG-AST-005", "Bounded range limit exceeded", "error", "Static range(...) bound exceeds configured deterministic limit."),
    "REJECT_AST_UNBOUNDED_LOOP_DOS": ("PG-AST-006", "Unbounded while loop DoS risk", "error", "Constant-true while loop without break statement rejected."),
    "REJECT_AST_TRIVIAL_CONSTANT_ORACLE_SPOOF": ("PG-AST-007", "Trivial constant-return stub oracle", "error", "Multi-argument function immediately returns a constant literal."),
    "REJECT_THEOREM_DROPPED": ("PG-DIFF-001", "Public theorem dropped across revision", "error", "A theorem from base revision was dropped without an alpha-equivalent counterpart."),
    "REJECT_THEOREM_STATEMENT_CHANGED": ("PG-DIFF-002", "Theorem specification statement mutated", "error", "Theorem kept its name but changed its alpha-normalized proposition."),
    "REJECT_THEOREM_RENAMED": ("PG-DIFF-003", "Theorem renamed under strict diff mode", "warning", "Theorem was alpha-equivalently renamed while rename policy is strict."),
    "REJECT_EVAL_P0_INTEGRITY": ("PG-EVAL-001", "Hard P0 integrity defect veto", "error", "Multi-agent run failed lexicographic P0 integrity gate (non-compensatory)."),
    "REJECT_EVAL_PROVENANCE": ("PG-EVAL-002", "Missing provenance or Lean hygiene failure", "error", "Multi-agent run lacked Git SHA, root sync, or Lean kernel clearance."),
    "REJECT_EVAL_REFEREE": ("PG-EVAL-003", "Cross-family referee gate rejection", "error", "Referee was unreachable, same-family, stale, or rejected the candidate."),
    "REJECT_EVAL_WILSON_LCB": ("PG-EVAL-004", "Fleet Wilson 95% LCB below gate floor", "error", "Aggregate fleet Wilson 95% lower confidence bound fell below policy minimum."),
    "REJECT_EVAL_CUSUM_QUARANTINE": ("PG-EVAL-005", "Page-CUSUM sequential drift quarantine", "error", "Sequential defect/failure drift triggered Page-CUSUM quarantine alarm."),
}


def utf16_len(text: str) -> int:
    """Return length of text in UTF-16 code units (BMP = 1, SMP = 2)."""
    return len(text.encode("utf-16-le")) // 2


def utf16_offset_for_line_col(source: str, line_1based: int, col_1based_codepoint: int = 1) -> Tuple[int, int]:
    """Compute (char_utf16, line_col_utf16_1based) from 1-based line and 1-based codepoint column."""
    if not source:
        return 0, max(1, col_1based_codepoint)
    lines = source.splitlines(keepends=True)
    target_line = max(1, min(line_1based, len(lines)))
    prefix_utf16 = sum(utf16_len(ln) for ln in lines[: target_line - 1])
    line_str = lines[target_line - 1]
    col_idx = max(0, min(col_1based_codepoint - 1, len(line_str)))
    in_line_utf16 = utf16_len(line_str[:col_idx])
    return prefix_utf16 + in_line_utf16, in_line_utf16 + 1


def utf16_offset_from_utf8_col(source: str, line_1based: int, col_0based_utf8: int) -> Tuple[int, int]:
    """Convert Python ast (lineno, UTF-8 byte col_offset) to (char_utf16, start_column_utf16_1based)."""
    if not source:
        return 0, 1
    lines = source.splitlines(keepends=True)
    target_line = max(1, min(line_1based, len(lines)))
    prefix_utf16 = sum(utf16_len(ln) for ln in lines[: target_line - 1])
    line_bytes = lines[target_line - 1].encode("utf-8")
    clamped = max(0, min(col_0based_utf8, len(line_bytes)))
    line_prefix_str = line_bytes[:clamped].decode("utf-8", errors="replace")
    in_line_utf16 = utf16_len(line_prefix_str)
    return prefix_utf16 + in_line_utf16, in_line_utf16 + 1


def span_to_utf16_region(source: str, start_idx: int, end_idx: int) -> Dict[str, int]:
    """Convert Python character slice [start_idx, end_idx) to SARIF line/col and UTF-16 offsets."""
    n = len(source)
    s = max(0, min(start_idx, n))
    e = max(s, min(end_idx, n))

    prefix = source[:s]
    start_line = prefix.count("\n") + 1
    last_nl = prefix.rfind("\n")
    start_line_prefix = prefix[last_nl + 1 :] if last_nl != -1 else prefix
    start_col_utf16 = utf16_len(start_line_prefix) + 1
    char_utf16 = utf16_len(prefix)

    end_prefix = source[:e]
    end_line = end_prefix.count("\n") + 1
    end_last_nl = end_prefix.rfind("\n")
    end_line_prefix = end_prefix[end_last_nl + 1 :] if end_last_nl != -1 else end_prefix
    end_col_utf16 = utf16_len(end_line_prefix) + 1
    char_length_utf16 = utf16_len(source[s:e])

    return {
        "startLine": start_line,
        "startColumn": start_col_utf16,
        "endLine": end_line,
        "endColumn": end_col_utf16,
        "charOffset": char_utf16,
        "charLength": char_length_utf16,
        "char_utf16": char_utf16,
        "char_length_utf16": char_length_utf16,
    }


def rule_id_for_violation(violation_code: str) -> str:
    if violation_code in _RULE_CATALOG:
        return _RULE_CATALOG[violation_code][0]
    if "AST" in violation_code:
        return "PG-AST-999"
    if "THEOREM" in violation_code or "DIFF" in violation_code:
        return "PG-DIFF-999"
    if "EVAL" in violation_code or "CUSUM" in violation_code or "WILSON" in violation_code:
        return "PG-EVAL-999"
    return "PG-LEAN-999"


def compute_partial_fingerprints(
    rule_id: str,
    artifact_uri: str,
    start_line: int,
    start_col_utf16: int,
    snippet: str = "",
) -> Dict[str, str]:
    """Deterministic SHA-256 partialFingerprints for GitHub Code Scanning / VS Code deduplication."""
    norm_uri = artifact_uri.replace("\\", "/").lstrip("./")
    line_key = f"{rule_id}|{norm_uri}|{start_line}|{snippet.strip()}"
    exact_key = f"{rule_id}|{norm_uri}|{start_line}|{start_col_utf16}|{snippet.strip()}"
    return {
        "primaryLocationLineHash": hashlib.sha256(line_key.encode("utf-8")).hexdigest()[:32] + ":1",
        "proofgateSha256": hashlib.sha256(exact_key.encode("utf-8")).hexdigest(),
    }


def findings_from_gate_result(
    gate_result: Any,
    *,
    artifact_uri: str,
    source: str = "",
) -> List[SarifFinding]:
    """Convert any ProofGate result object or dict into structured SarifFinding items."""
    if isinstance(gate_result, Mapping):
        raw_findings = gate_result.get("findings") or []
        violations = gate_result.get("violations") or []
    else:
        raw_findings = getattr(gate_result, "findings", None) or []
        violations = getattr(gate_result, "violations", None) or []

    out: List[SarifFinding] = []
    if raw_findings:
        for item in raw_findings:
            code = str(item.get("code", "REJECT_UNKNOWN"))
            rid = rule_id_for_violation(code)
            msg = str(item.get("message") or _RULE_CATALOG.get(code, (rid, code, "error", code))[3])
            line = int(item.get("line", 1) or 1)
            if "start_offset" in item and source:
                reg = span_to_utf16_region(
                    source,
                    int(item["start_offset"]),
                    int(item.get("end_offset", item["start_offset"])),
                )
                sline = reg["startLine"]
                scol = reg["startColumn"]
                eline = reg["endLine"]
                ecol = reg["endColumn"]
                c_off = reg["char_utf16"]
                c_len = reg["char_length_utf16"]
            elif "col_offset_utf8" in item and source:
                c_off, scol = utf16_offset_from_utf8_col(source, line, int(item["col_offset_utf8"]))
                sline = line
                eline = int(item.get("end_line") or line)
                if "end_col_offset_utf8" in item:
                    end_c_off, ecol = utf16_offset_from_utf8_col(source, eline, int(item["end_col_offset_utf8"]))
                    c_len = max(0, end_c_off - c_off)
                else:
                    ecol = scol
                    c_len = 0
            else:
                col_cp = int(item.get("column", 1) or 1)
                c_off, scol = utf16_offset_for_line_col(source, line, col_cp)
                sline = line
                eline = int(item.get("end_line") or line)
                end_col_cp = int(item.get("end_column") or col_cp)
                end_off, ecol = utf16_offset_for_line_col(source, eline, end_col_cp)
                c_len = max(0, end_off - c_off)
            snippet = str(item.get("snippet", ""))
            if not snippet and source:
                lines = source.splitlines()
                if 1 <= sline <= len(lines):
                    snippet = lines[sline - 1].strip()
            out.append(
                SarifFinding(
                    rule_id=rid,
                    violation_code=code,
                    message=msg,
                    artifact_uri=artifact_uri,
                    start_line=sline,
                    start_column=scol,
                    end_line=eline,
                    end_column=ecol,
                    char_utf16=c_off,
                    char_length_utf16=c_len,
                    level=str(item.get("level", _RULE_CATALOG.get(code, (rid, code, "error", code))[2])),
                    snippet=snippet,
                )
            )
        return out

    for code in violations:
        code_s = str(code)
        rid = rule_id_for_violation(code_s)
        meta = _RULE_CATALOG.get(code_s, (rid, code_s, "error", f"ProofGate rule violation: {code_s}"))
        out.append(
            SarifFinding(
                rule_id=rid,
                violation_code=code_s,
                message=meta[3],
                artifact_uri=artifact_uri,
                start_line=1,
                start_column=1,
                end_line=1,
                end_column=1,
                char_utf16=0,
                char_length_utf16=0,
                level=meta[2],
            )
        )
    return out


def export_sarif(
    findings: Sequence[SarifFinding],
    *,
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """Export findings as a GitHub Code Scanning / VS Code compliant SARIF v2.1.0 dictionary."""
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    for code, (rid, short_desc, default_lvl, full_desc) in _RULE_CATALOG.items():
        if rid not in rules_by_id:
            rules_by_id[rid] = {
                "id": rid,
                "name": code,
                "shortDescription": {"text": short_desc},
                "fullDescription": {"text": full_desc},
                "defaultConfiguration": {"level": default_lvl},
                "properties": {"tags": ["security", "formal-verification", "proofgate"]},
            }

    results: List[Dict[str, Any]] = []
    for f in findings:
        if f.rule_id not in rules_by_id:
            rules_by_id[f.rule_id] = {
                "id": f.rule_id,
                "name": f.violation_code,
                "shortDescription": {"text": f.violation_code},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {"level": f.level},
            }
        norm_uri = f.artifact_uri.replace("\\", "/")
        region: Dict[str, Any] = {
            "startLine": max(1, int(f.start_line)),
            "startColumn": max(1, int(f.start_column)),
            "charOffset": max(0, int(f.char_utf16)),
            "charLength": max(0, int(f.char_length_utf16)),
            "properties": {
                "char_utf16": max(0, int(f.char_utf16)),
                "char_length_utf16": max(0, int(f.char_length_utf16)),
            },
        }
        if f.end_line is not None and f.end_line >= region["startLine"]:
            region["endLine"] = int(f.end_line)
        if f.end_column is not None and f.end_column >= 1:
            region["endColumn"] = int(f.end_column)
        if f.snippet:
            region["snippet"] = {"text": f.snippet}

        results.append(
            {
                "ruleId": f.rule_id,
                "level": f.level,
                "message": {"text": f"{f.violation_code}: {f.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": norm_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": region,
                        }
                    }
                ],
                "partialFingerprints": compute_partial_fingerprints(
                    f.rule_id,
                    norm_uri,
                    region["startLine"],
                    region["startColumn"],
                    f.snippet,
                ),
            }
        )

    ordered_rules = [rules_by_id[k] for k in sorted(rules_by_id)]
    return {
        chr(36) + "schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ProofGate",
                        "semanticVersion": tool_version,
                        "informationUri": TOOL_URI,
                        "rules": ordered_rules,
                    }
                },
                "columnKind": "utf16CodeUnits",
                "results": results,
            }
        ],
    }
