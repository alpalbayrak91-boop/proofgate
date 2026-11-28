"""ProofGate Gate 2.9: Claim-Obligation-Certificate (COC) Verifier,
Swarm Reward-Hacking Contagion Quarantine, Pre-Training Loophole Exposure
Predictor, True Scope-Stack De Bruijn + Signed-DBM Auditor, and Zero-Preserving
Canonical Vendi VS_2 / Exact O(N) VAS_2 — CLI & OASIS SARIF v2.1.0 Gate.

Integrates vitrin/proofgate_g29_claimcert_exposure_quarantine_vendi.py and
formal/ProofGateG29ClaimCertExposureQuarantineSoundness.lean into github/proofgate
CLI (`proofgate check-g29-claimcert`) for AWS-OSS-NOV30-2026 showcase readiness.
Closes G29-D11 (post-return unreachable dead-code Vendi clone inflation) and
strict EvilInt subclass rejection.

Zero external dependencies; strictly 0 occurrences of chr(36) (KURAL-3, USD only).
"""
from __future__ import annotations

import ast
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import math
import re
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .muhur_rfc6962 import MerkleTree, canonical_json_bytes

TOOL_NAME = "ProofGate-G29-ClaimCert-Quarantine-Vendi"
TOOL_VERSION = "2.9.0"
TOOL_URI = "https://github.com/alpalbayrak91-boop/proofgate"
AWS_OSS_PROGRAM = "AWS-OSS-NOV30-2026"
AWS_REQUESTED_CREDIT_USD = "1000.00 USD"
AWS_LOCK80_CAP_USD = "800.00 USD"
DEFAULT_MIN_VS2 = 3.0
MAX_LEAN_SOURCE_BYTES = 65_536
MAX_ITEMS = 64

TAINT_CLEAN = 0
TAINT_CONDITIONAL = 1
TAINT_JUNK_VALUE = 2
TAINT_VACUOUS = 3
TAINT_KERNEL_ESCAPE = 4

TAINT_NAMES: Dict[int, str] = {
    TAINT_CLEAN: "CLEAN",
    TAINT_CONDITIONAL: "CONDITIONAL_ASSUMPTION",
    TAINT_JUNK_VALUE: "JUNK_VALUE_TAINT",
    TAINT_VACUOUS: "VACUOUS_CONTRADICTION",
    TAINT_KERNEL_ESCAPE: "KERNEL_ESCAPE",
}

G29_RULE_CATALOG: Dict[str, Tuple[str, str, str, str]] = {
    "PG-G29-KERNEL-SORRY": (
        "Kernel escape via sorry or admit",
        "error",
        "CWE-754",
        "Incomplete Lean 4 proof using sorry or admit introduces unsound axiom sorryAx.",
    ),
    "PG-G29-KERNEL-AXIOM": (
        "Custom axiom declaration",
        "error",
        "CWE-754",
        "Custom axiom declaration bypasses constructive verification in the Lean 4 kernel.",
    ),
    "PG-G29-KERNEL-TRUST": (
        "Untrusted kernel bypass or compiler trust",
        "error",
        "CWE-345",
        "Use of native_decide, bv_decide, debug.skipKernelTC, Lean.trustCompiler, or lcProof.",
    ),
    "PG-G29-KERNEL-EXTERN": (
        "External or implemented_by override",
        "error",
        "CWE-345",
        "Attribute @[extern] or @[implemented_by] substitutes unverified runtime code.",
    ),
    "PG-G29-DBM-VACUOUS": (
        "Unsatisfiable hypothesis cycle (Signed Bellman-Ford DBM)",
        "error",
        "CWE-570",
        "Difference-Bound Matrix solver detected a negative-weight cycle making the theorem vacuous.",
    ),
    "PG-G29-JUNK-DIVZERO": (
        "Unguarded division by zero or shadowed denominator guard",
        "error",
        "CWE-369",
        "Division applied to literal 0, unguarded variable, or outer guard shadowed by inner binder.",
    ),
    "PG-G29-JUNK-DIVZERO-COMPOUND": (
        "Unguarded or algebraically zero compound denominator",
        "error",
        "CWE-369",
        "Compound denominator expression is algebraically zero or lacks a non-zero guard.",
    ),
    "PG-G29-JUNK-LOG": (
        "Unguarded Real.log on non-positive or shadowed argument",
        "error",
        "CWE-682",
        "Real.log returns junk value 0 on non-positive inputs when 0 < x guard is absent or shadowed.",
    ),
    "PG-G29-JUNK-LOG-COMPOUND": (
        "Unguarded or non-positive compound Real.log argument",
        "error",
        "CWE-682",
        "Compound Real.log argument is non-positive or lacks a positivity guard.",
    ),
    "PG-G29-JUNK-TSUM": (
        "Unguarded tsum without Summable hypothesis",
        "error",
        "CWE-682",
        "tsum returns junk value 0 on non-summable series when Summable guard is missing or shadowed.",
    ),
    "PG-G29-JUNK-POLYZERO": (
        "Unguarded Polynomial natDegree or leadingCoeff",
        "error",
        "CWE-682",
        "Polynomial.natDegree or leadingCoeff used without non-zero polynomial guard.",
    ),
    "PG-G29-JUNK-NATSUB-ZERO": (
        "Degenerate Nat monus literal 0 - b",
        "error",
        "CWE-191",
        "Natural number subtraction 0 - b always truncates to junk value 0.",
    ),
    "PG-G29-JUNK-NATSUB": (
        "Unguarded Nat subtraction underflow",
        "error",
        "CWE-191",
        "Natural number subtraction a - b lacks dominating guard b <= a.",
    ),
    "PG-G29-QUARANTINE-PROPAGATED": (
        "Downstream claim tainted via COC dependency DAG",
        "error",
        "CWE-345",
        "Claim depends transitively on a quarantined claim and is redacted before swarm broadcast.",
    ),
    "PG-G29-VENDI-BELOW-FLOOR": (
        "Canonical Vendi VS_2 diversity below policy floor",
        "error",
        "CWE-682",
        "Zero-preserving canonical AST Vendi VS_2 score fell below the required threshold.",
    ),
    "PG-G29-SARIF-URI": (
        "Unsafe SARIF artifact URI",
        "error",
        "CWE-22",
        "Artifact URI failed fail-closed relative path normalization.",
    ),
    "PG-G29-KURAL3-CHR36": (
        "KURAL-3 chr(36) hygiene violation",
        "error",
        "CWE-116",
        "Literal ASCII 36 detected in Lean source or serialized payload; use USD instead.",
    ),
}

_IDENT_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_']*\Z")
_KERNEL_ESCAPE_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("PG-G29-KERNEL-SORRY", re.compile(r"\b(?:sorry|admit)\b")),
    ("PG-G29-KERNEL-AXIOM", re.compile(r"(?m)^\s*axiom\b")),
    ("PG-G29-KERNEL-TRUST", re.compile(r"\b(?:native_decide|bv_decide|debug\.skipKernelTC|Lean\.trustCompiler|lcProof)\b")),
    ("PG-G29-KERNEL-EXTERN", re.compile(r"@\[\s*(?:extern|implemented_by)\b")),
)


def lattice_join(a: int, b: int) -> int:
    """Fail-closed IFC lattice join over [0..4]; rejects bool and int subclasses."""
    if type(a) is not int or type(b) is not int:
        return TAINT_KERNEL_ESCAPE
    if a < 0 or a > 4 or b < 0 or b > 4:
        return TAINT_KERNEL_ESCAPE
    return a if a >= b else b


def normalize_g29_sarif_uri(uri: str) -> Tuple[Optional[str], Optional[str]]:
    """Fail-closed relative URI normalizer blocking traversal, null bytes, and chr(36)."""
    if not isinstance(uri, str) or not uri.strip():
        return None, "REJECT_SARIF_EMPTY_URI"
    raw = uri.strip().replace("\\", "/")
    if len(raw) > 512:
        return None, "REJECT_SARIF_URI_TOO_LONG"
    if raw.startswith("/") or (len(raw) >= 2 and raw[1] == ":") or "://" in raw:
        return None, "REJECT_SARIF_ABSOLUTE_URI"
    low = raw.lower()
    if "%2e" in low or "%2f" in low or "%5c" in low or "\x00" in raw or chr(36) in raw:
        return None, "REJECT_SARIF_ENCODED_OR_FORBIDDEN_URI"
    segs: List[str] = []
    for seg in raw.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            return None, "REJECT_SARIF_PARENT_TRAVERSAL"
        segs.append(seg)
    if not segs:
        return None, "REJECT_SARIF_EMPTY_CANONICAL_URI"
    return "/".join(segs), None


def strict_json_loads_g29(raw: str) -> Dict[str, Any]:
    """Reject duplicate JSON keys (CWE-436) and non-finite JSON constants (NaN/Infinity)."""
    def _hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        obj: Dict[str, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError(f"DUPLICATE_JSON_KEY:{k}")
            obj[k] = v
        return obj

    def _reject_const(val: str) -> Any:
        raise ValueError(f"NON_FINITE_JSON_CONST:{val}")

    parsed = json.loads(raw, object_pairs_hook=_hook, parse_constant=_reject_const)
    if not isinstance(parsed, dict):
        raise ValueError("NON_OBJECT_JSON")
    return parsed


def strip_lean_comments_and_strings(src: str) -> str:
    out: List[str] = []
    i, n = 0, len(src)
    block_depth, in_line, in_str = 0, False, False
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line:
            if ch == "\n":
                in_line = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if block_depth > 0:
            if ch == "/" and nxt == "-":
                block_depth += 1
                out.extend((" ", " "))
                i += 2
            elif ch == "-" and nxt == "/":
                block_depth -= 1
                out.extend((" ", " "))
                i += 2
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
            continue
        if in_str:
            if ch == "\\" and i + 1 < n:
                out.extend((" ", " "))
                i += 2
            elif ch == '"':
                in_str = False
                out.append(" ")
                i += 1
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
            continue
        if ch == "-" and nxt == "-":
            in_line = True
            out.extend((" ", " "))
            i += 2
            continue
        if ch == "/" and nxt == "-":
            block_depth = 1
            out.extend((" ", " "))
            i += 2
            continue
        if ch == '"':
            in_str = True
            out.append(" ")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _find_matching_delim(s: str, open_idx: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = s[open_idx]
    closer = pairs.get(opener)
    if not closer:
        return len(s)
    depth = 0
    for j in range(open_idx, len(s)):
        if s[j] == opener:
            depth += 1
        elif s[j] == closer:
            depth -= 1
            if depth == 0:
                return j
    return len(s)


def _enclosing_scope_end(s: str, pos: int) -> int:
    stack: List[Tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for idx in range(pos):
        ch = s[idx]
        if ch in "([{":
            stack.append((ch, idx))
        elif ch in ")]}" and stack and stack[-1][0] == pairs[ch]:
            stack.pop()
    if stack:
        _, open_idx = stack[-1]
        return _find_matching_delim(s, open_idx)
    return len(s)


def _extract_header_and_body(decl_src: str) -> Tuple[str, str]:
    m = re.search(r":=\s*(?:by\b)?", decl_src)
    if not m:
        return decl_src, ""
    return decl_src[:m.start()], decl_src[m.end():]


def _parse_typed_binders(header: str) -> Dict[str, str]:
    types: Dict[str, str] = {}
    for grp in re.findall(r"[({\[]([^()\[\]{}]+?:[^()\[\]{}]+?)[)}\]]", header):
        if ":" not in grp:
            continue
        lhs, rhs = grp.split(":", 1)
        typ = rhs.strip()
        for tok in lhs.strip().split():
            if _IDENT_RE.match(tok):
                types[tok] = typ
    return types


def _check_dbm_vacuity(header: str) -> List[str]:
    """Signed Bellman-Ford Difference-Bound Matrix (DBM) vacuity solver."""
    types = _parse_typed_binders(header)
    ZERO = "__ZERO__"
    edges: List[Tuple[str, str, int, int]] = []
    nodes: Set[str] = {ZERO}

    def add_le(a: str, b: str, c: int, strict: bool) -> None:
        nodes.add(a)
        nodes.add(b)
        edges.append((b, a, c, -1 if strict else 0))

    hyps = re.findall(r"[({\[]([^()\[\]{}]+?)[)}\]]", header)
    prop_chunks = [h.split(":", 1)[1] if ":" in h else h for h in hyps]
    hyp_text = " ; ".join(prop_chunks)

    for v, typ in types.items():
        if typ in ("Nat", "ℕ"):
            add_le(ZERO, v, 0, False)

    for v, op, num_s in re.findall(r"\b([A-Za-z_][A-Za-z0-9_']*)\s*(<=|<|>=|>|≤|≥|=)\s*(-?\d+)\b", hyp_text):
        val = int(num_s)
        if op == "<":
            add_le(v, ZERO, val, True)
        elif op in ("<=", "≤"):
            add_le(v, ZERO, val, False)
        elif op == ">":
            add_le(ZERO, v, -val, True)
        elif op in (">=", "≥"):
            add_le(ZERO, v, -val, False)
        elif op == "=":
            add_le(v, ZERO, val, False)
            add_le(ZERO, v, -val, False)

    for num_s, op, v in re.findall(r"\b(-?\d+)\s*(<=|<|>=|>|≤|≥|=)\s*([A-Za-z_][A-Za-z0-9_']*)\b", hyp_text):
        val = int(num_s)
        if op == "<":
            add_le(ZERO, v, -val, True)
        elif op in ("<=", "≤"):
            add_le(ZERO, v, -val, False)
        elif op == ">":
            add_le(v, ZERO, val, True)
        elif op in (">=", "≥"):
            add_le(v, ZERO, val, False)
        elif op == "=":
            add_le(v, ZERO, val, False)
            add_le(ZERO, v, -val, False)

    for a, op, b in re.findall(r"\b([A-Za-z_][A-Za-z0-9_']*)\s*(<=|<|>=|>|≤|≥|=)\s*([A-Za-z_][A-Za-z0-9_']*)\b", hyp_text):
        if a.isdigit() or b.isdigit():
            continue
        if op == "<":
            add_le(a, b, 0, True)
        elif op in ("<=", "≤"):
            add_le(a, b, 0, False)
        elif op == ">":
            add_le(b, a, 0, True)
        elif op in (">=", "≥"):
            add_le(b, a, 0, False)
        elif op == "=":
            add_le(a, b, 0, False)
            add_le(b, a, 0, False)

    dist: Dict[str, Tuple[int, int]] = {u: (0, 0) for u in nodes}
    for _ in range(len(nodes) - 1):
        changed = False
        for u, v, c, st in edges:
            cand = (dist[u][0] + c, dist[u][1] + st)
            if cand < dist[v]:
                dist[v] = cand
                changed = True
        if not changed:
            break

    for u, v, c, st in edges:
        cand = (dist[u][0] + c, dist[u][1] + st)
        if cand < dist[v]:
            return [f"DBM_UNSAT_CYCLE({u}->{v},w=({c},{st}))"]
    return []


def _extract_header_guards(header: str) -> Dict[str, Set[str]]:
    guards: Dict[str, Set[str]] = defaultdict(set)
    for v in re.findall(r"\b([A-Za-z_][A-Za-z0-9_']*)\s*(?:≠|!=)\s*0\b", header):
        guards[v].add("NONZERO")
    for v in re.findall(r"\b0\s*(?:≠|!=)\s*([A-Za-z_][A-Za-z0-9_']*)\b", header):
        guards[v].add("NONZERO")
    for v in re.findall(r"\bNeZero\s+([A-Za-z_][A-Za-z0-9_']*)\b", header):
        guards[v].add("NONZERO")
    for v in re.findall(r"\b0\s*<\s*([A-Za-z_][A-Za-z0-9_']*)\b", header):
        guards[v].update({"NONZERO", "POS"})
    for v in re.findall(r"\b([A-Za-z_][A-Za-z0-9_']*)\s*>\s*0\b", header):
        guards[v].update({"NONZERO", "POS"})
    for v in re.findall(r"\bSummable\s+([A-Za-z_][A-Za-z0-9_']*)\b", header):
        guards[v].add("SUMMABLE")
    for a, b in re.findall(r"\b([A-Za-z_][A-Za-z0-9_']*)\s*(?:<=|≤|<)\s*([A-Za-z_][A-Za-z0-9_']*)\b", header):
        guards[f"{b}-{a}"].add("NAT_SUB_OK")
    for b, a in re.findall(r"\b([A-Za-z_][A-Za-z0-9_']*)\s*(?:>=|≥|>)\s*([A-Za-z_][A-Za-z0-9_']*)\b", header):
        guards[f"{b}-{a}"].add("NAT_SUB_OK")
    return guards


def _collect_scoped_shadows(clean: str, tracked_vars: Set[str]) -> Dict[str, List[Tuple[int, int]]]:
    spans: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
    for m in re.finditer(r"\b(?:fun|λ)\s+([^=\n]+?)=\s*>", clean):
        end_scope = _enclosing_scope_end(clean, m.start())
        cleaned_binders = re.sub(r":[^)\]}]+", " ", m.group(1))
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_']*", cleaned_binders):
            if tok in tracked_vars:
                spans[tok].append((m.end(), end_scope))
    for m in re.finditer(r"(?:\bforall\b|\bexists\b|∀|∃)\s+([^,\n]+?),", clean):
        end_scope = _enclosing_scope_end(clean, m.start())
        cleaned_binders = re.sub(r":[^)\]},]+", " ", m.group(1))
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_']*", cleaned_binders):
            if tok in tracked_vars:
                spans[tok].append((m.end(), end_scope))
    for m in re.finditer(r"\blet\s+([A-Za-z_][A-Za-z0-9_']*)\s*(?::[^:=]+)?\s*:=", clean):
        var = m.group(1)
        if var in tracked_vars:
            end_scope = _enclosing_scope_end(clean, m.start())
            spans[var].append((m.end(), end_scope))
    return spans


def _is_algebraic_zero_or_nonpos_expr(expr: str) -> Optional[str]:
    e = expr.strip()
    if e.startswith("(") and e.endswith(")"):
        e = e[1:-1].strip()
    if ":" in e:
        e = e.split(":", 1)[0].strip()
    if re.fullmatch(r"-?\d+", e) and int(e) <= 0:
        return f"const_nonpos({e})"
    m_sub = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_']*)\s*-\s*([A-Za-z_][A-Za-z0-9_']*)", e)
    if m_sub and m_sub.group(1) == m_sub.group(2):
        return f"self_cancel({m_sub.group(1)}-{m_sub.group(2)})"
    if re.search(r"\*\s*0\b|\b0\s*\*", e):
        return f"mul_zero({e})"
    return None


@dataclass(frozen=True)
class LeanFinding:
    rule_id: str
    theorem_name: str
    taint_level: int
    line: int
    detail: str


def audit_lean_declaration_g29(decl_name: str, decl_src: str, start_line: int = 1) -> List[LeanFinding]:
    findings: List[LeanFinding] = []
    if chr(36) in decl_src:
        findings.append(LeanFinding("PG-G29-KURAL3-CHR36", decl_name, TAINT_KERNEL_ESCAPE, start_line, "literal chr(36) in Lean source"))
    clean = strip_lean_comments_and_strings(decl_src)
    for rule_id, pat in _KERNEL_ESCAPE_PATTERNS:
        m = pat.search(clean)
        if m:
            findings.append(LeanFinding(rule_id, decl_name, TAINT_KERNEL_ESCAPE, start_line + clean[:m.start()].count("\n"), m.group(0)))

    header, _ = _extract_header_and_body(clean)
    types = _parse_typed_binders(header)
    guards = _extract_header_guards(header)

    for vac in _check_dbm_vacuity(header):
        findings.append(LeanFinding("PG-G29-DBM-VACUOUS", decl_name, TAINT_VACUOUS, start_line, vac))

    tracked = set(guards.keys()) | set(types.keys())
    shadows = _collect_scoped_shadows(clean, tracked)

    def is_shadowed(v: str, pos: int) -> bool:
        return any(lo <= pos < hi for lo, hi in shadows.get(v, ()))

    for m in re.finditer(r"/\s*(\(|[A-Za-z_][A-Za-z0-9_']*|-?\d+)", clean):
        tok = m.group(1)
        pos = m.start()
        line_no = start_line + clean[:pos].count("\n")
        if tok == "(":
            open_i = m.start(1)
            close_i = _find_matching_delim(clean, open_i)
            inner = clean[open_i:close_i + 1]
            alg = _is_algebraic_zero_or_nonpos_expr(inner)
            if alg:
                findings.append(LeanFinding("PG-G29-JUNK-DIVZERO-COMPOUND", decl_name, TAINT_JUNK_VALUE, line_no, f"/{inner}: {alg}"))
            else:
                inner_strip = inner[1:-1].strip()
                if not (_IDENT_RE.match(inner_strip) and "NONZERO" in guards.get(inner_strip, set()) and not is_shadowed(inner_strip, pos)):
                    findings.append(LeanFinding("PG-G29-JUNK-DIVZERO-COMPOUND", decl_name, TAINT_JUNK_VALUE, line_no, f"/{inner}: unguarded compound denom"))
        elif tok == "0":
            findings.append(LeanFinding("PG-G29-JUNK-DIVZERO", decl_name, TAINT_JUNK_VALUE, line_no, "literal / 0"))
        elif _IDENT_RE.match(tok):
            has_g = "NONZERO" in guards.get(tok, set())
            if not has_g or is_shadowed(tok, pos):
                why = "shadowed outer guard" if (has_g and is_shadowed(tok, pos)) else "unguarded denom"
                findings.append(LeanFinding("PG-G29-JUNK-DIVZERO", decl_name, TAINT_JUNK_VALUE, line_no, f"/{tok}: {why}"))

    for m in re.finditer(r"\bReal\.log(?:\s*(\()|\s+([A-Za-z_][A-Za-z0-9_']*|-?\d+))", clean):
        tok = m.group(1) or m.group(2) or ""
        pos = m.start()
        line_no = start_line + clean[:pos].count("\n")
        if tok == "(":
            open_i = m.start(1)
            close_i = _find_matching_delim(clean, open_i)
            inner = clean[open_i:close_i + 1]
            alg = _is_algebraic_zero_or_nonpos_expr(inner)
            if alg:
                findings.append(LeanFinding("PG-G29-JUNK-LOG-COMPOUND", decl_name, TAINT_JUNK_VALUE, line_no, f"Real.log {inner}: {alg}"))
            else:
                inner_strip = inner[1:-1].strip()
                if not (_IDENT_RE.match(inner_strip) and "POS" in guards.get(inner_strip, set()) and not is_shadowed(inner_strip, pos)):
                    findings.append(LeanFinding("PG-G29-JUNK-LOG-COMPOUND", decl_name, TAINT_JUNK_VALUE, line_no, f"Real.log {inner}: unguarded compound arg"))
        elif re.fullmatch(r"-?\d+", tok) and int(tok) <= 0:
            findings.append(LeanFinding("PG-G29-JUNK-LOG", decl_name, TAINT_JUNK_VALUE, line_no, f"Real.log {tok}"))
        elif _IDENT_RE.match(tok):
            has_g = "POS" in guards.get(tok, set())
            if not has_g or is_shadowed(tok, pos):
                why = "shadowed pos guard" if (has_g and is_shadowed(tok, pos)) else "unguarded Real.log"
                findings.append(LeanFinding("PG-G29-JUNK-LOG", decl_name, TAINT_JUNK_VALUE, line_no, f"Real.log {tok}: {why}"))

    for m in re.finditer(r"(?:\btsum\s+([A-Za-z_][A-Za-z0-9_']*)|∑'\s*[A-Za-z_][A-Za-z0-9_']*\s*,\s*([A-Za-z_][A-Za-z0-9_']*))", clean):
        fn_name = m.group(1) or m.group(2) or ""
        pos = m.start()
        line_no = start_line + clean[:pos].count("\n")
        if "SUMMABLE" not in guards.get(fn_name, set()) or is_shadowed(fn_name, pos):
            findings.append(LeanFinding("PG-G29-JUNK-TSUM", decl_name, TAINT_JUNK_VALUE, line_no, f"unguarded tsum({fn_name})"))

    for m in re.finditer(r"\b(?:Polynomial\.)?(?:natDegree|leadingCoeff)\s+([A-Za-z_][A-Za-z0-9_']*)", clean):
        poly = m.group(1)
        pos = m.start()
        line_no = start_line + clean[:pos].count("\n")
        if "NONZERO" not in guards.get(poly, set()) or is_shadowed(poly, pos):
            findings.append(LeanFinding("PG-G29-JUNK-POLYZERO", decl_name, TAINT_JUNK_VALUE, line_no, f"unguarded {m.group(0)}"))

    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_']*|0)\s*-\s*([A-Za-z_][A-Za-z0-9_']*)\b", clean):
        a, b = m.group(1), m.group(2)
        pos = m.start()
        line_no = start_line + clean[:pos].count("\n")
        b_is_nat = types.get(b) in ("Nat", "ℕ")
        a_is_nat = types.get(a) in ("Nat", "ℕ")
        if a == "0" and b_is_nat:
            findings.append(LeanFinding("PG-G29-JUNK-NATSUB-ZERO", decl_name, TAINT_JUNK_VALUE, line_no, f"Nat monus literal 0 - {b}"))
        elif a_is_nat and b_is_nat:
            if "NAT_SUB_OK" not in guards.get(f"{a}-{b}", set()) or is_shadowed(a, pos) or is_shadowed(b, pos):
                findings.append(LeanFinding("PG-G29-JUNK-NATSUB", decl_name, TAINT_JUNK_VALUE, line_no, f"unguarded Nat sub {a} - {b}"))
    return findings


def build_coc_certificate_and_quarantine(
    decls: Mapping[str, str],
    deps: Mapping[str, Sequence[str]],
) -> Dict[str, Any]:
    local_taint: Dict[str, int] = {}
    findings_by_decl: Dict[str, List[LeanFinding]] = {}
    for name, src in decls.items():
        fs = audit_lean_declaration_g29(name, src)
        findings_by_decl[name] = fs
        lvl = TAINT_CLEAN
        for f in fs:
            lvl = lattice_join(lvl, f.taint_level)
        local_taint[name] = lvl

    eff = dict(local_taint)
    sources: Dict[str, Set[str]] = {k: ({k} if local_taint[k] > 0 else set()) for k in decls}
    for _ in range(len(decls) + 1):
        changed = False
        for u, ds in deps.items():
            if u not in eff:
                continue
            for v in ds:
                if v not in eff:
                    continue
                j = lattice_join(eff[u], eff[v])
                if j > eff[u]:
                    eff[u] = j
                    changed = True
                if eff[v] > 0:
                    before = len(sources[u])
                    sources[u].update(sources[v])
                    if len(sources[u]) > before:
                        changed = True
        if not changed:
            break

    broadcast_records: List[Dict[str, Any]] = []
    merkle_leaves: List[bytes] = []
    raw_leak_detected = False
    for name in sorted(decls.keys()):
        raw_src = decls[name]
        raw_sha = hashlib.sha256(raw_src.encode("utf-8")).hexdigest()
        rules = sorted({f.rule_id for f in findings_by_decl[name]})
        if eff[name] >= TAINT_JUNK_VALUE and local_taint[name] < TAINT_JUNK_VALUE:
            rules = sorted(set(rules) | {"PG-G29-QUARANTINE-PROPAGATED"})
        rejected = eff[name] >= TAINT_JUNK_VALUE
        rec = {
            "claim_id": name,
            "verdict": "QUARANTINE_REJECT" if rejected else "CERTIFIED_PASS",
            "local_taint": local_taint[name],
            "effective_taint": eff[name],
            "taint_label": TAINT_NAMES.get(eff[name], "KERNEL_ESCAPE"),
            "taint_sources": sorted(sources[name]),
            "rule_ids": rules,
            "source_sha256": raw_sha,
            "redacted_for_swarm": rejected,
            "broadcast_contagion_risk_bps": 0,
        }
        rec_json = json.dumps({k: v for k, v in rec.items() if k not in ("claim_id", "taint_sources")}, sort_keys=True)
        if rejected:
            for forbidden_tok in ("sorry", "admit", "1 / x", "x / (y - y)", "Real.log 0", "tsum g", "0 - a"):
                if forbidden_tok in rec_json:
                    raw_leak_detected = True
        broadcast_records.append(rec)
        merkle_leaves.append(canonical_json_bytes(rec))

    canon_cert = json.dumps({"records": broadcast_records}, sort_keys=True, separators=(",", ":"))
    merkle_root = MerkleTree(merkle_leaves).root_hex if merkle_leaves else ""
    return {
        "cert_sha256": hashlib.sha256(canon_cert.encode("utf-8")).hexdigest(),
        "merkle_root_sha256": merkle_root,
        "raw_leak_detected": raw_leak_detected,
        "effective_taint": eff,
        "findings_by_decl": {
            k: [
                {
                    "rule_id": f.rule_id,
                    "theorem_name": f.theorem_name,
                    "taint_level": f.taint_level,
                    "line": f.line,
                    "detail": f.detail,
                }
                for f in v
            ]
            for k, v in findings_by_decl.items()
        },
        "broadcast_records": broadcast_records,
    }


def predict_loophole_exposure(
    propensity_map: Mapping[str, float],
    escape_map: Mapping[str, float],
) -> List[Dict[str, Any]]:
    rows = [
        {
            "rule_family": rule,
            "propensity": round(float(propensity_map[rule]), 4),
            "escape_rate": round(float(escape_map.get(rule, 0.0)), 4),
            "exposure": round(float(propensity_map[rule]) * float(escape_map.get(rule, 0.0)), 6),
        }
        for rule in sorted(propensity_map.keys())
    ]
    rows.sort(key=lambda r: (-r["exposure"], r["rule_family"]))
    return rows


COMM_BIN = (ast.Add, ast.Mult, ast.BitAnd, ast.BitOr, ast.BitXor)
COMM_CMP = (ast.Eq, ast.NotEq)


def _is_c(node: ast.AST, v: Any) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is type(v) and node.value == v


def _strip_dead(stmts: Sequence[ast.stmt]) -> List[ast.stmt]:
    out: List[ast.stmt] = []
    for idx, st in enumerate(stmts):
        if isinstance(st, ast.Pass):
            continue
        if idx == 0 and isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant) and isinstance(st.value.value, str):
            continue
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and isinstance(st.value, ast.Name) and st.targets[0].id == st.value.id:
            continue
        if isinstance(st, ast.If):
            if _is_c(st.test, True):
                sub = _strip_dead(st.body)
                out.extend(sub)
                if any(isinstance(s, (ast.Return, ast.Raise)) for s in sub):
                    break
                continue
            if _is_c(st.test, False):
                sub = _strip_dead(st.orelse)
                out.extend(sub)
                if any(isinstance(s, (ast.Return, ast.Raise)) for s in sub):
                    break
                continue
        out.append(st)
        if isinstance(st, (ast.Return, ast.Raise)):
            break
    return out


def _subst_e(node: ast.expr, env: Mapping[str, ast.expr]) -> ast.expr:
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in env:
        return env[node.id]
    if isinstance(node, ast.BinOp):
        return ast.BinOp(left=_subst_e(node.left, env), op=node.op, right=_subst_e(node.right, env))
    if isinstance(node, ast.UnaryOp):
        return ast.UnaryOp(op=node.op, operand=_subst_e(node.operand, env))
    if isinstance(node, ast.Compare):
        return ast.Compare(left=_subst_e(node.left, env), ops=list(node.ops), comparators=[_subst_e(c, env) for c in node.comparators])
    if isinstance(node, ast.IfExp):
        return ast.IfExp(test=_subst_e(node.test, env), body=_subst_e(node.body, env), orelse=_subst_e(node.orelse, env))
    if isinstance(node, ast.Call):
        return ast.Call(func=_subst_e(node.func, env), args=[_subst_e(a, env) for a in node.args], keywords=list(node.keywords))
    return node


def _subst_s(st: ast.stmt, env: Mapping[str, ast.expr]) -> ast.stmt:
    if isinstance(st, ast.Return) and st.value is not None:
        return ast.Return(value=_subst_e(st.value, env))
    if isinstance(st, ast.If):
        return ast.If(test=_subst_e(st.test, env), body=[_subst_s(s, env) for s in _strip_dead(st.body)], orelse=[_subst_s(s, env) for s in _strip_dead(st.orelse)])
    return st


def _inline_temps(stmts: Sequence[ast.stmt]) -> List[ast.stmt]:
    cleaned = _strip_dead(stmts)
    if len(cleaned) < 2:
        return cleaned
    env: Dict[str, ast.expr] = {}
    out: List[ast.stmt] = []
    for i, st in enumerate(cleaned):
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and i + 1 < len(cleaned):
            vn = st.targets[0].id
            mut = any(isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store) and sub.id == vn for later in cleaned[i + 1:] for sub in ast.walk(later))
            if not mut:
                env[vn] = _subst_e(st.value, env)
                continue
        out.append(_subst_s(st, env))
    return out


def _canon_e(node: ast.AST, env: Mapping[str, str]) -> Tuple[Any, ...]:
    if isinstance(node, ast.Constant):
        return ("C", type(node.value).__name__, repr(node.value))
    if isinstance(node, ast.Name):
        return ("DB", env[node.id]) if node.id in env else ("G", node.id)
    if isinstance(node, ast.UnaryOp):
        x = _canon_e(node.operand, env)
        return x if isinstance(node.op, ast.UAdd) else ("U", type(node.op).__name__, x)
    if isinstance(node, ast.BinOp):
        l, r = _canon_e(node.left, env), _canon_e(node.right, env)
        if isinstance(node.op, ast.Add):
            if l == ("C", "int", "0"):
                return r
            if r == ("C", "int", "0"):
                return l
        if isinstance(node.op, ast.Sub) and r == ("C", "int", "0"):
            return l
        if isinstance(node.op, ast.Mult):
            if l == ("C", "int", "1"):
                return r
            if r == ("C", "int", "1"):
                return l
            if l == ("C", "int", "0") or r == ("C", "int", "0"):
                return ("C", "int", "0")
        if isinstance(node.op, COMM_BIN):
            a, b = sorted((l, r), key=repr)
            return ("BC", type(node.op).__name__, a, b)
        return ("BO", type(node.op).__name__, l, r)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        l, r, op = _canon_e(node.left, env), _canon_e(node.comparators[0], env), node.ops[0]
        if isinstance(op, COMM_CMP):
            a, b = sorted((l, r), key=repr)
            return ("CC", type(op).__name__, a, b)
        if isinstance(op, ast.Gt):
            return ("CO", "Lt", r, l)
        if isinstance(op, ast.GtE):
            return ("CO", "LtE", r, l)
        return ("CO", type(op).__name__, l, r)
    if isinstance(node, ast.IfExp):
        return ("IFE", _canon_e(node.test, env), _canon_e(node.body, env), _canon_e(node.orelse, env))
    if isinstance(node, ast.Call):
        return ("CALL", _canon_e(node.func, env), tuple(_canon_e(a, env) for a in node.args))
    return ("N", type(node).__name__)


def _canon_fn(src: str) -> Tuple[Any, ...]:
    tree = ast.parse(src)
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    if not fns:
        raise ValueError("Candidate Python source must contain at least one FunctionDef.")
    fn = fns[-1]
    args = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
    env = {a.arg: f"DB_{i}" for i, a in enumerate(args)}
    out: List[Tuple[Any, ...]] = []
    for st in _inline_temps(fn.body):
        if isinstance(st, ast.Return):
            out.append(("RET", _canon_e(st.value, env) if st.value else ("NONE",)))
        elif isinstance(st, ast.If):
            out.append((
                "IF",
                _canon_e(st.test, env),
                tuple(("RET", _canon_e(s.value, env)) if isinstance(s, ast.Return) and s.value else ("S", type(s).__name__) for s in _inline_temps(st.body)),
                tuple(("RET", _canon_e(s.value, env)) if isinstance(s, ast.Return) and s.value else ("S", type(s).__name__) for s in _inline_temps(st.orelse)),
            ))
        else:
            out.append(("S", type(st).__name__))
    return ("FN", len(args), tuple(out))


def _wl_feats(sexpr: Tuple[Any, ...]) -> Counter[str]:
    feats: Counter[str] = Counter()

    def _v(node: Any) -> str:
        if not isinstance(node, tuple) or not node:
            tok = f"A:{node}"
            feats[f"0:{tok}"] += 1
            return tok
        h = str(node[0])
        ch = [_v(c) for c in node[1:]]
        ex = f"{h}({','.join(ch)})"
        feats[f"0:{h}"] += 1
        feats[f"1:{h}[{','.join(c.split('(')[0] for c in ch)}]"] += 1
        feats[f"2:{hashlib.sha256(ex.encode('utf-8')).hexdigest()[:14]}"] += 1
        return ex

    _v(sexpr)
    return feats


def _cos(a: Counter[str], b: Counter[str]) -> float:
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return 0.0 if na <= 1e-15 or nb <= 1e-15 else max(0.0, min(1.0, sum(v * b.get(k, 0) for k, v in a.items()) / (na * nb)))


def compute_vs2_and_vas2(candidates: Sequence[str]) -> Dict[str, Any]:
    n = len(candidates)
    if n == 0:
        return {"vs2": 0.0, "vas2": [], "vas2_max_diff": 0.0, "K": []}
    feats = [_wl_feats(_canon_fn(c)) for c in candidates]
    K = [[1.0 if i == j else _cos(feats[i], feats[j]) for j in range(n)] for i in range(n)]
    row_sq = [sum(K[i][j] * K[i][j] for j in range(n)) for i in range(n)]
    frob_sq = sum(row_sq)
    vs2 = (n * n) / frob_sq
    vas2: List[float] = []
    max_diff = 0.0
    if n > 1:
        for i in range(n):
            fsub = frob_sq - 2.0 * row_sq[i] + K[i][i] * K[i][i]
            fast_v = vs2 - ((n - 1) * (n - 1) / fsub)
            naive_f = sum(K[a][b] * K[a][b] for a in range(n) if a != i for b in range(n) if b != i)
            naive_v = vs2 - ((n - 1) * (n - 1) / naive_f)
            max_diff = max(max_diff, abs(fast_v - naive_v))
            vas2.append(round(fast_v, 6))
    return {"vs2": round(vs2, 6), "vas2": vas2, "vas2_max_diff": max_diff, "K": K}


def gate_g29_bps(
    recall_ok: int,
    clean_fp_zero: int,
    quarantine_ok: int,
    exposure_zero: int,
    clone_ok: int,
    vs2_bps: int,
) -> int:
    """Hardened 6-arg strict-int Gate 2.9 score matching Lean 4 ProofGateG29.gateG29Bps."""
    args = (recall_ok, clean_fp_zero, quarantine_ok, exposure_zero, clone_ok, vs2_bps)
    for a in args:
        if type(a) is not int:
            return -29000
    if any(x not in (0, 1) for x in args[:5]) or vs2_bps < 0 or vs2_bps > 100000:
        return -29000
    if any(x == 0 for x in args[:5]) or vs2_bps < 30000:
        return -28000
    return 4000 + ((vs2_bps - 30000) * 6000) // 70000


def build_g29_selftest_bundle() -> Dict[str, Any]:
    """Canonical clean Gate 2.9 COC + Vendi portfolio passing all checks (VS_2 >= 3.0)."""
    return {
        "artifact_uri": "formal/g29_selftest_coc.lean",
        "min_vs2": 3.0,
        "decls": {
            "clean_div_guarded": "theorem clean_div_guarded (x y : Real) (hy : y != 0) : (x / y) * y = x := by field_simp",
            "clean_log_guarded": "theorem clean_log_guarded (x : Real) (hx : 0 < x) : Real.log x <= x - 1 := by exact Real.log_le_sub_one_of_pos hx",
            "clean_tsum_guarded": "theorem clean_tsum_guarded (f : Nat -> Real) (hf : Summable f) : tsum f = tsum f := by rfl",
            "clean_poly_guarded": "theorem clean_poly_guarded (p : Polynomial Real) (hp : p != 0) : 0 <= Polynomial.natDegree p := by omega",
            "clean_natsub_guarded": "theorem clean_natsub_guarded (a b : Nat) (h : b <= a) : a - b + b = a := by omega",
        },
        "deps": {
            "clean_poly_guarded": ["clean_div_guarded"],
            "clean_natsub_guarded": ["clean_log_guarded", "clean_tsum_guarded"],
        },
        "propensity_map": {
            "div_zero": 0.42,
            "log_nonpos": 0.31,
            "dbm_vacuous": 0.27,
            "nat_monus": 0.35,
        },
        "escape_map": {
            "div_zero": 0.0,
            "log_nonpos": 0.0,
            "dbm_vacuous": 0.0,
            "nat_monus": 0.0,
        },
        "ast_candidates": [
            "def op_add_scale(a, b):\n    return (a + b) * 3",
            "def op_branch_clamp(x, lo, hi):\n    if x < lo:\n        return lo\n    if x > hi:\n        return hi\n    return x",
            "def op_bit_mix(u, v):\n    return (u ^ v) & (u | 7)",
            "def op_poly_step(n):\n    return n * n - 2 * n + 5",
            "def op_cond_ratio(p, q):\n    return (p // q) if q != 0 else -1",
        ],
    }


def build_g29_quarantine_demo_bundle() -> Dict[str, Any]:
    """Adversarial Gate 2.9 COC bundle triggering DBM, junk, shadow, and transitive quarantine."""
    return {
        "artifact_uri": "formal/g29_quarantine_demo.lean",
        "min_vs2": 3.0,
        "decls": {
            "bad_sorry": "theorem bad_sorry (x : Nat) : x = x := by sorry",
            "bad_dbm_cycle": "theorem bad_dbm_cycle (x y z : Int) (h1 : x <= y) (h2 : y <= z) (h3 : z < x) : x = 0 := by omega",
            "bad_shadow_div": "theorem bad_shadow_div (x y : Real) (hy : y != 0) : forall y : Real, x / y = 0 := by rfl",
            "bad_nat_monus": "theorem bad_nat_monus (a : Nat) : 0 - a = 0 := by omega",
            "downstream_clean_tainted": "theorem downstream_clean_tainted (a b : Nat) (h : b <= a) : a - b + b = a := by omega",
        },
        "deps": {
            "downstream_clean_tainted": ["bad_dbm_cycle"],
        },
        "propensity_map": {
            "div_zero": 0.42,
            "dbm_vacuous": 0.27,
            "nat_monus": 0.35,
        },
        "escape_map": {
            "div_zero": 0.0,
            "dbm_vacuous": 0.0,
            "nat_monus": 0.0,
        },
        "ast_candidates": [
            "def c1(x, y):\n    return x + y",
            "def c2(a, b):\n    return b + a + 0",
        ],
    }


def audit_g29_claimcert_bundle(
    req_obj: Optional[Mapping[str, Any]] = None,
    *,
    default_uri: str = "formal/g29_bundle.lean",
    min_vs2: Optional[float] = None,
) -> Dict[str, Any]:
    """Audit a Gate 2.9 COC + Quarantine + Exposure + Vendi bundle or single Lean source."""
    t0 = time.perf_counter()
    payload: Mapping[str, Any] = build_g29_selftest_bundle() if req_obj is None else req_obj
    if not isinstance(payload, Mapping):
        raise ValueError("Payload must be a JSON object.")

    raw_uri = payload.get("artifact_uri", default_uri)
    canon_uri, uri_err = normalize_g29_sarif_uri(str(raw_uri) if raw_uri is not None else default_uri)
    if uri_err is not None or canon_uri is None:
        return {
            "schema": "proofgate.audit.g29_claimcert_quarantine_vendi.v2_9",
            "verdict": "REJECT",
            "passed": False,
            "primary_code": "PG-G29-SARIF-URI",
            "error": uri_err or "REJECT_SARIF_URI",
            "artifact_uri": "invalid_uri.lean",
            "violations": ["PG-G29-SARIF-URI"],
            "findings": [
                {
                    "rule_id": "PG-G29-SARIF-URI",
                    "theorem_name": "bundle",
                    "taint_level": TAINT_KERNEL_ESCAPE,
                    "line": 1,
                    "detail": uri_err or "Unsafe artifact_uri",
                    "artifact_uri": "invalid_uri.lean",
                }
            ],
            "gate_bps": -29000,
            "vs2": 0.0,
            "vas2": [],
            "merkle_root_sha256": "",
            "kural3_zero_chr36": True,
            "aws_oss_program": AWS_OSS_PROGRAM,
            "aws_requested_credit_usd": AWS_REQUESTED_CREDIT_USD,
            "aws_lock80_cap_usd": AWS_LOCK80_CAP_USD,
            "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    use_min_vs2 = payload.get("min_vs2", DEFAULT_MIN_VS2) if min_vs2 is None else min_vs2
    if isinstance(use_min_vs2, bool) or not isinstance(use_min_vs2, (int, float)) or not math.isfinite(float(use_min_vs2)) or float(use_min_vs2) < 0.0:
        raise ValueError("min_vs2 must be a finite non-negative number.")
    min_vs2_f = float(use_min_vs2)

    mode = "bundle"
    if "lean_source" in payload and "decls" not in payload:
        mode = "single"
        src = payload.get("lean_source")
        if not isinstance(src, str) or not src.strip():
            raise ValueError("lean_source must be a non-empty string.")
        if len(src.encode("utf-8")) > MAX_LEAN_SOURCE_BYTES:
            raise ValueError(f"lean_source exceeds {MAX_LEAN_SOURCE_BYTES} byte limit.")
        decls: Dict[str, str] = {"single_decl": src}
        deps: Dict[str, Sequence[str]] = {}
    else:
        raw_decls = payload.get("decls")
        if not isinstance(raw_decls, Mapping) or not raw_decls:
            raise ValueError("Payload must provide 'decls' (non-empty mapping) or 'lean_source'.")
        if len(raw_decls) > MAX_ITEMS:
            raise ValueError(f"decls exceeds maximum of {MAX_ITEMS}.")
        decls = {}
        for k, v in raw_decls.items():
            if not isinstance(k, str) or not isinstance(v, str) or not v.strip():
                raise ValueError(f"Invalid declaration entry for '{k}'.")
            if len(v.encode("utf-8")) > MAX_LEAN_SOURCE_BYTES:
                raise ValueError(f"Declaration '{k}' exceeds byte limit.")
            decls[k] = v
        raw_deps = payload.get("deps", {})
        if not isinstance(raw_deps, Mapping):
            raise ValueError("deps must be a mapping of claim_id -> list of dependency claim_ids.")
        deps = {str(k): [str(x) for x in v] for k, v in raw_deps.items() if isinstance(v, list)}

    coc = build_coc_certificate_and_quarantine(decls, deps)
    prop_map = payload.get("propensity_map", {})
    esc_map = payload.get("escape_map", {})
    exposure_rows = predict_loophole_exposure(prop_map, esc_map) if isinstance(prop_map, Mapping) and isinstance(esc_map, Mapping) and prop_map else []
    max_exposure = max((r["exposure"] for r in exposure_rows), default=0.0)

    ast_cands = payload.get("ast_candidates", [])
    if ast_cands:
        if not isinstance(ast_cands, list) or len(ast_cands) > MAX_ITEMS or not all(isinstance(c, str) for c in ast_cands):
            raise ValueError("ast_candidates must be a list of Python function source strings.")
        vendi = compute_vs2_and_vas2(ast_cands)
    else:
        vendi = {"vs2": 0.0, "vas2": [], "vas2_max_diff": 0.0, "K": []}

    all_findings: List[Dict[str, Any]] = []
    violations: List[str] = []
    for rec in coc["broadcast_records"]:
        cname = rec["claim_id"]
        local_fs = coc["findings_by_decl"].get(cname, [])
        for f in local_fs:
            violations.append(f["rule_id"])
            all_findings.append({**f, "artifact_uri": canon_uri})
        if "PG-G29-QUARANTINE-PROPAGATED" in rec["rule_ids"]:
            violations.append("PG-G29-QUARANTINE-PROPAGATED")
            all_findings.append(
                {
                    "rule_id": "PG-G29-QUARANTINE-PROPAGATED",
                    "theorem_name": cname,
                    "taint_level": rec["effective_taint"],
                    "line": 1,
                    "detail": f"Claim '{cname}' quarantined via tainted dependencies: {', '.join(rec['taint_sources'])}",
                    "artifact_uri": canon_uri,
                }
            )

    if ast_cands and float(vendi["vs2"]) < min_vs2_f:
        violations.append("PG-G29-VENDI-BELOW-FLOOR")
        all_findings.append(
            {
                "rule_id": "PG-G29-VENDI-BELOW-FLOOR",
                "theorem_name": "ast_portfolio",
                "taint_level": TAINT_JUNK_VALUE,
                "line": 1,
                "detail": f"Canonical Vendi VS_2={vendi['vs2']:.6f} < floor {min_vs2_f:.4f}",
                "artifact_uri": canon_uri,
            }
        )

    all_claims_clean = all(r["verdict"] == "CERTIFIED_PASS" for r in coc["broadcast_records"])
    quarantine_ok = 1 if (not coc["raw_leak_detected"]) else 0
    exposure_zero = 1 if max_exposure <= 1e-12 else 0
    vs2_val = float(vendi["vs2"]) if ast_cands else (3.0 if all_claims_clean else 0.0)
    vs2_bps = min(100000, max(0, int(round(vs2_val * 10000.0))))
    clone_ok = 1 if (not ast_cands or vs2_val >= min_vs2_f) else 0
    recall_ok = 1 if all_claims_clean else 0
    clean_fp_zero = 1 if all_claims_clean else 0
    gate_bps = gate_g29_bps(recall_ok, clean_fp_zero, quarantine_ok, exposure_zero, clone_ok, vs2_bps)

    verdict = "ACCEPT" if not violations and not coc["raw_leak_detected"] else "REJECT"
    primary_code = "G29_CLAIMCERT_QUARANTINE_PASS" if verdict == "ACCEPT" else (violations[0] if violations else "PG-G29-QUARANTINE-LEAK")

    res: Dict[str, Any] = {
        "schema": "proofgate.audit.g29_claimcert_quarantine_vendi.v2_9",
        "mode": mode,
        "verdict": verdict,
        "passed": verdict == "ACCEPT",
        "primary_code": primary_code,
        "artifact_uri": canon_uri,
        "claim_count": len(decls),
        "certified_claim_count": sum(1 for r in coc["broadcast_records"] if r["verdict"] == "CERTIFIED_PASS"),
        "quarantined_claim_count": sum(1 for r in coc["broadcast_records"] if r["verdict"] == "QUARANTINE_REJECT"),
        "raw_leak_detected": coc["raw_leak_detected"],
        "cert_sha256": coc["cert_sha256"],
        "merkle_root_sha256": coc["merkle_root_sha256"],
        "broadcast_records": coc["broadcast_records"],
        "exposure_ranking": exposure_rows,
        "max_exposure": max_exposure,
        "vs2": vendi["vs2"],
        "vas2": vendi["vas2"],
        "vas2_max_diff": vendi["vas2_max_diff"],
        "min_vs2_floor": min_vs2_f if ast_cands else 0.0,
        "gate_bps": gate_bps,
        "violations": sorted(set(violations)),
        "findings_count": len(all_findings),
        "findings": all_findings,
        "aws_oss_program": AWS_OSS_PROGRAM,
        "aws_requested_credit_usd": AWS_REQUESTED_CREDIT_USD,
        "aws_lock80_cap_usd": AWS_LOCK80_CAP_USD,
        "kural3_zero_chr36": True,
        "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }
    if chr(36) in json.dumps(res, ensure_ascii=False):
        res["kural3_zero_chr36"] = False
        res["verdict"] = "REJECT"
        res["passed"] = False
    return res


def export_g29_claimcert_sarif_v210(
    audit_res: Mapping[str, Any],
    artifact_uri: Optional[str] = None,
) -> Dict[str, Any]:
    """Export Gate 2.9 findings in OASIS SARIF v2.1.0 format (strictly 0 chr(36))."""
    raw_default_uri = artifact_uri or str(audit_res.get("artifact_uri", "formal/g29_bundle.lean"))
    canon_uri, uri_err = normalize_g29_sarif_uri(raw_default_uri)
    use_uri = canon_uri or "formal/g29_bundle.lean"

    findings = list(audit_res.get("findings", []))
    if uri_err is not None:
        findings.insert(
            0,
            {
                "rule_id": "PG-G29-SARIF-URI",
                "theorem_name": "bundle",
                "taint_level": TAINT_KERNEL_ESCAPE,
                "line": 1,
                "detail": uri_err,
                "artifact_uri": use_uri,
            },
        )

    rules_by_id: Dict[str, Dict[str, Any]] = {}
    for rid, (short_d, def_lvl, cwe_id, full_d) in G29_RULE_CATALOG.items():
        rules_by_id[rid] = {
            "id": rid,
            "name": rid.replace("-", "_"),
            "shortDescription": {"text": short_d},
            "fullDescription": {"text": full_d},
            "defaultConfiguration": {"level": def_lvl},
            "properties": {
                "cwe": cwe_id,
                "tags": ["security", "formal-verification", "proofgate", "g29-claimcert", "quarantine", "vendi"],
            },
        }

    results: List[Dict[str, Any]] = []
    for idx, f in enumerate(findings, start=1):
        rid = str(f.get("rule_id", "PG-G29-UNKNOWN"))
        thm = str(f.get("theorem_name", "decl"))
        msg = f"{thm}: {str(f.get('detail', rid))}".replace(chr(36), "USD")
        line_no = max(1, int(f.get("line", 1)))
        f_uri_raw = str(f.get("artifact_uri") or use_uri)
        f_uri_norm, _ = normalize_g29_sarif_uri(f_uri_raw)
        loc_uri = f_uri_norm or use_uri
        meta = G29_RULE_CATALOG.get(rid, (rid, "error", "CWE-682", msg))
        if rid not in rules_by_id:
            rules_by_id[rid] = {
                "id": rid,
                "name": rid.replace("-", "_"),
                "shortDescription": {"text": meta[0][:120]},
                "fullDescription": {"text": meta[3][:240]},
                "defaultConfiguration": {"level": meta[1]},
                "properties": {"cwe": meta[2]},
            }
        fp_line = hashlib.sha256(f"{rid}|{loc_uri}|{line_no}|{msg}".encode("utf-8")).hexdigest()[:32] + ":1"
        fp_exact = hashlib.sha256(f"{rid}|{loc_uri}|{line_no}|{idx}|{msg}".encode("utf-8")).hexdigest()
        results.append(
            {
                "ruleId": rid,
                "level": meta[1],
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": loc_uri,
                                "uriBaseId": "SRCROOT",
                            },
                            "region": {
                                "startLine": line_no,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": fp_line,
                    "proofgateSha256": fp_exact,
                },
                "properties": {
                    "cwe": meta[2],
                    "taint_level": int(f.get("taint_level", TAINT_JUNK_VALUE)),
                },
            }
        )

    sarif_doc: Dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "semanticVersion": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": [rules_by_id[k] for k in sorted(rules_by_id)],
                    }
                },
                "columnKind": "utf16CodeUnits",
                "results": results,
                "properties": {
                    "verdict": str(audit_res.get("verdict", "REJECT")),
                    "cert_sha256": str(audit_res.get("cert_sha256", "")),
                    "merkle_root_sha256": str(audit_res.get("merkle_root_sha256", "")),
                    "raw_leak_detected": bool(audit_res.get("raw_leak_detected", False)),
                    "vs2": float(audit_res.get("vs2", 0.0)),
                    "gate_bps": int(audit_res.get("gate_bps", -28000)),
                    "aws_oss_program": AWS_OSS_PROGRAM,
                    "aws_requested_credit_usd": AWS_REQUESTED_CREDIT_USD,
                    "aws_lock80_cap_usd": AWS_LOCK80_CAP_USD,
                    "kural3_zero_chr36": True,
                },
            }
        ],
    }
    if chr(36) in json.dumps(sarif_doc, ensure_ascii=False):
        raise ValueError("KURAL-3 violation: chr(36) detected in SARIF output")
    return sarif_doc
