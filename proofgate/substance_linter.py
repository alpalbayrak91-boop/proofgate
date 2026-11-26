"""Deterministic Lean 4 mathematical substance & non-tautology linter (ProofGate v1.4.0)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .lean_gate import lex_lean_source

_DECL_START_RE = re.compile(
    r"(?m)^[ \t]*(?:(private|protected)\s+)?(theorem|lemma)\s+([A-Za-z_][A-Za-z0-9_'.]*)\b"
)
_BOUNDARY_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:private|protected|noncomputable|unsafe|partial)\s+)*"
    r"(?:theorem|lemma|def|abbrev|inductive|structure|class|instance|axiom|opaque|"
    r"section|end|namespace|#print|set_option|open)\b"
)
_DEF_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:private|protected|noncomputable)\s+)*(?:def|abbrev)\s+([A-Za-z_][A-Za-z0-9_']*)\b"
)

_QUANT_OR_IMP_RE = re.compile(r"(∀|→|->|\bforall\b|∃|\bExists\b)")
_NONTRIVIAL_PROOF_TOKENS_RE = re.compile(
    r"\b(?:induction|cases|rcases|by_cases|match|omega|linarith|nlinarith|ring|field_simp|"
    r"rw|rewrite|have|obtain|refine|apply|exact|ext|funext|calc|contradiction|absurd|simpa)\b"
)
_SIMPLE_CLOSED_STEP_RE = re.compile(
    r"\A(?:decide(?:\s+\+\s*kernel)?|rfl|trivial|norm_num|simp(?:\s+only)?|omega|exact\s+trivial)\Z"
)
_UNFOLD_ONLY_RE = re.compile(
    r"\A(?:unfold|dsimp(?:\s+only)?|simp(?:\s+only)?)\s+(?:\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_'.]*))\Z"
)


@dataclass(frozen=True)
class SubstanceAuditResult:
    verdict: str
    primary_code: str
    violations: List[str]
    total_theorems: int
    substantive_count: int
    certificate_helper_count: int
    trivial_count: int
    substance_bps: int
    summary_ratio: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    declarations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _split_sig_and_body(decl_slice: str, name_end_offset: int) -> Tuple[str, str]:
    """Split a declaration tail after its name into signature text and proof body at top-level `:=`."""
    depth_p = depth_b = depth_c = 0
    in_guil = False
    i = name_end_offset
    n = len(decl_slice)
    while i < n:
        ch = decl_slice[i]
        if in_guil:
            if ch == "\u00bb":
                in_guil = False
            i += 1
            continue
        if ch == "\u00ab":
            in_guil = True
        elif ch == "(":
            depth_p += 1
        elif ch == ")":
            depth_p = max(0, depth_p - 1)
        elif ch == "[":
            depth_b += 1
        elif ch == "]":
            depth_b = max(0, depth_b - 1)
        elif ch == "{":
            depth_c += 1
        elif ch == "}":
            depth_c = max(0, depth_c - 1)
        elif depth_p == 0 and depth_b == 0 and depth_c == 0 and decl_slice[i : i + 2] == ":=":
            return decl_slice[name_end_offset:i], decl_slice[i + 2 :]
        i += 1
    return decl_slice[name_end_offset:], ""


def _split_binders_and_type(sig_text: str) -> Tuple[str, str]:
    """Split theorem signature at the first top-level `:` separating binders from proposition."""
    depth_p = depth_b = depth_c = 0
    in_guil = False
    for i, ch in enumerate(sig_text):
        if in_guil:
            if ch == "\u00bb":
                in_guil = False
            continue
        if ch == "\u00ab":
            in_guil = True
        elif ch == "(":
            depth_p += 1
        elif ch == ")":
            depth_p = max(0, depth_p - 1)
        elif ch == "[":
            depth_b += 1
        elif ch == "]":
            depth_b = max(0, depth_b - 1)
        elif ch == "{":
            depth_c += 1
        elif ch == "}":
            depth_c = max(0, depth_c - 1)
        elif ch == ":" and depth_p == 0 and depth_b == 0 and depth_c == 0:
            return sig_text[:i], sig_text[i + 1 :]
    return "", sig_text


def _normalize_ws(text: str) -> str:
    return " ".join(text.split())


def _proof_steps(body_text: str) -> List[str]:
    stripped = body_text.strip()
    if re.match(r"^by\b", stripped):
        stripped = stripped[2:].strip()
    steps: List[str] = []
    for raw_ln in stripped.splitlines():
        for part in raw_ln.split(";"):
            s = part.strip().lstrip("\u00b7").strip()
            if s:
                steps.append(s)
    return steps


def _extract_hyp_types(binders_part: str) -> List[Tuple[str, str]]:
    hyps: List[Tuple[str, str]] = []
    for m in re.finditer(r"\(\s*([A-Za-z_][A-Za-z0-9_']*)\s*:\s*([^()]+)\)", binders_part):
        hyps.append((m.group(1), _normalize_ws(m.group(2))))
    return hyps


def audit_lean_substance(
    source: str,
    *,
    min_substance_bps: int = 5000,
    strict: bool = False,
) -> Dict[str, Any]:
    """Audit Lean 4 declarations for non-vacuity and mathematical substance vs trivial filler."""
    lexed = lex_lean_source(source)
    code = lexed["code_only"]
    local_defs: Set[str] = {m.group(1) for m in _DEF_DECL_RE.finditer(code)}

    matches = list(_DECL_START_RE.finditer(code))
    boundaries = sorted(m.start() for m in _BOUNDARY_RE.finditer(code))

    parsed: List[Dict[str, Any]] = []
    for m in matches:
        decl_start = m.start()
        end_idx = len(code)
        for b in boundaries:
            if b > decl_start:
                end_idx = b
                break
        decl_slice = code[decl_start:end_idx]
        sig_text, body_text = _split_sig_and_body(decl_slice, m.end() - decl_start)
        binders_part, type_part = _split_binders_and_type(sig_text)
        line_no = source[:decl_start].count("\n") + 1
        full_name = m.group(3)
        short_name = full_name.rsplit(".", 1)[-1]
        parsed.append({
            "visibility": m.group(1) or "public",
            "kind": m.group(2),
            "name": full_name,
            "short_name": short_name,
            "line": line_no,
            "binders": binders_part,
            "type_part": type_part,
            "body": body_text,
            "steps": _proof_steps(body_text),
        })

    all_bodies = [d["body"] for d in parsed]
    findings: List[Dict[str, Any]] = []
    decl_reports: List[Dict[str, Any]] = []
    substantive_count = 0
    certificate_helper_count = 0
    trivial_count = 0

    for idx, decl in enumerate(parsed):
        short_name = decl["short_name"]
        binders = decl["binders"]
        type_part = decl["type_part"]
        steps = decl["steps"]
        norm_type = _normalize_ws(type_part)

        has_binders = bool(re.search(r"[({\[]", binders))
        has_quant_or_imp = bool(_QUANT_OR_IMP_RE.search(type_part))
        is_closed_ground = (not has_binders) and (not has_quant_or_imp)

        # Check PG-LEAN-018: literal True conclusion or syntactic restatement of a named hypothesis
        classification = "SUBSTANTIVE"
        violation_code: Optional[str] = None
        rule_id: Optional[str] = None
        reason = "Quantified or structured mathematical proof."

        hyps = _extract_hyp_types(binders)
        single_step = steps[0] if len(steps) == 1 else ""
        matched_hyp = any(
            htype == norm_type and single_step in (hname, f"exact {hname}", "assumption")
            for hname, htype in hyps
        )
        if norm_type == "True" or matched_hyp:
            classification = "TRIVIAL_TAUTOLOGY"
            violation_code = "REJECT_TRIVIAL_TAUTOLOGY"
            rule_id = "PG-LEAN-018"
            reason = f"Theorem `{decl['name']}` proves literal `True` or immediately echoes a hypothesis."

        # Check PG-LEAN-017: proof unfolds only a local def and closes immediately without reasoning
        elif steps and len(steps) <= 2:
            m_unfold = _UNFOLD_ONLY_RE.match(steps[0])
            uses_other_structure = any(_NONTRIVIAL_PROOF_TOKENS_RE.search(st) for st in steps)
            if m_unfold and not uses_other_structure:
                ident_blob = m_unfold.group(1) or m_unfold.group(2) or ""
                refs = [tok.strip().rsplit(".", 1)[-1] for tok in re.split(r"[\s,]+", ident_blob) if tok.strip()]
                if refs and all(r in local_defs for r in refs):
                    tail_ok = len(steps) == 1 or bool(_SIMPLE_CLOSED_STEP_RE.match(steps[1]))
                    if tail_ok:
                        classification = "TRIVIAL_DEF_UNFOLD"
                        violation_code = "REJECT_TRIVIAL_DEF_UNFOLD"
                        rule_id = "PG-LEAN-017"
                        reason = f"Theorem `{decl['name']}` only unfolds local def(s) `{', '.join(refs)}` without substantive proof."

        # Check PG-LEAN-016: closed ground assertion dispatched solely via decide/rfl/trivial/norm_num
        if classification == "SUBSTANTIVE" and is_closed_ground and steps:
            if all(_SIMPLE_CLOSED_STEP_RE.match(st) for st in steps):
                is_helper_name = short_name.endswith("_batch_dec") or short_name.endswith("_cert")
                referenced_by_substantive = False
                if is_helper_name:
                    pat_ref = re.compile(rf"\b{re.escape(short_name)}\b")
                    for jdx, other_body in enumerate(all_bodies):
                        if jdx != idx and pat_ref.search(other_body):
                            referenced_by_substantive = True
                            break
                if referenced_by_substantive:
                    classification = "CERTIFICATE_HELPER"
                    reason = f"Closed batch certificate helper `{decl['name']}` consumed by quantified theorem."
                else:
                    classification = "TRIVIAL_CLOSED_DECIDE"
                    violation_code = "REJECT_TRIVIAL_CLOSED_DECIDE"
                    rule_id = "PG-LEAN-016"
                    reason = f"Closed ground assertion `{decl['name']}` is proved solely by constant-tactic evaluation without universal scope."

        if classification == "SUBSTANTIVE":
            substantive_count += 1
        elif classification == "CERTIFICATE_HELPER":
            certificate_helper_count += 1
        else:
            trivial_count += 1
            findings.append({
                "rule_id": rule_id,
                "code": violation_code,
                "violation_code": violation_code,
                "theorem": decl["name"],
                "line": decl["line"],
                "column": 1,
                "level": "error" if strict else "warning",
                "message": reason,
            })

        decl_reports.append({
            "name": decl["name"],
            "line": decl["line"],
            "classification": classification,
            "is_closed_ground": is_closed_ground,
            "step_count": len(steps),
            "reason": reason,
        })

    total_theorems = len(parsed)
    denom = substantive_count + trivial_count
    if total_theorems == 0 or denom == 0:
        substance_bps = 0
    else:
        substance_bps = (substantive_count * 10000) // denom

    violations: List[str] = []
    if total_theorems == 0 or substantive_count == 0 or substance_bps < min_substance_bps:
        verdict = "REJECT_VACUOUS_SUITE" if strict else "WARN_LOW_SUBSTANCE"
        primary_code = "REJECT_VACUOUS_SUBSTANCE_SUITE" if strict else "WARN_LOW_SUBSTANCE"
        for f in findings:
            vc = str(f["violation_code"])
            if vc not in violations:
                violations.append(vc)
        if not violations:
            violations.append(primary_code)
    else:
        verdict = "ACCEPT"
        primary_code = "SUBSTANCE_ACCEPT"

    return SubstanceAuditResult(
        verdict=verdict,
        primary_code=primary_code,
        violations=violations,
        total_theorems=total_theorems,
        substantive_count=substantive_count,
        certificate_helper_count=certificate_helper_count,
        trivial_count=trivial_count,
        substance_bps=substance_bps,
        summary_ratio=f"{substantive_count}/{total_theorems} substantive",
        findings=findings,
        declarations=decl_reports,
    ).to_dict()
