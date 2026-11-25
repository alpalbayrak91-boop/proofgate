"""Lean 4 PR specification diff gate detecting alpha-equivalent moves/renames and theorem drops."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple

from .lean_gate import _extract_binder_groups, _find_top_level_assign, _split_top_level_arrows, _strip_outer_parens, lex_lean_source

_IDENT_SEG_RE = r"(?:\u00ab[^\u00bb\n]+\u00bb|[A-Za-z_][A-Za-z0-9_']*)"
_IDENT_QUAL_RE = rf"{_IDENT_SEG_RE}(?:\.{_IDENT_SEG_RE})*"

_LEAN_NON_BOUND_TOKENS: frozenset[str] = frozenset({
    "Nat", "Int", "Bool", "Prop", "Type", "Sort", "String", "Char", "Float",
    "True", "False", "List", "Option", "Fin", "BitVec", "Unit", "Empty",
    "And", "Or", "Not", "Iff", "Eq", "Ne", "LE", "LT", "Add", "Sub", "Mul", "Div",
    "forall", "exists", "let", "have", "in", "fun", "if", "then", "else", "match", "with",
})


@dataclass(frozen=True)
class TheoremSpec:
    fqn: str
    short_name: str
    namespace: str
    is_private: bool
    line: int
    start_offset: int
    end_offset: int
    canonical_prop: str
    raw_signature: str


@dataclass(frozen=True)
class LeanDiffResult:
    verdict: str
    primary_code: str
    violations: List[str]
    unchanged: List[Dict[str, Any]]
    moved: List[Dict[str, Any]]
    renamed: List[Dict[str, Any]]
    dropped: List[Dict[str, Any]]
    added: List[Dict[str, Any]]
    statement_changed: List[Dict[str, Any]]
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _canonicalize_ops(text: str) -> str:
    s = text.strip()
    s = s.replace("->", "→")
    s = re.sub(r"\bforall\b", "∀", s)
    s = s.replace("/\\", "∧")
    s = s.replace("\\/", "∨")
    s = s.replace("<=", "≤").replace(">=", "≥").replace("!=", "≠")
    s = re.sub(r"\bNot\s+", "¬", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def _parse_leading_forall(expr: str) -> Tuple[List[Tuple[str, str]], str]:
    """Consume leading `∀ (x : T), ...` or `∀ x : T, ...` binders into binder items."""
    s = _canonicalize_ops(expr)
    extracted: List[Tuple[str, str]] = []
    while s.startswith("∀"):
        rest = s[1:].lstrip()
        depth = 0
        comma_idx = -1
        for idx, ch in enumerate(rest):
            if ch in "([{⦃":
                depth += 1
            elif ch in ")]}⦄":
                depth = max(0, depth - 1)
            elif depth == 0 and ch == ",":
                comma_idx = idx
                break
        if comma_idx == -1:
            break
        binder_chunk = rest[:comma_idx].strip()
        body_chunk = rest[comma_idx + 1 :].strip()
        # Handle `(a b : T) (c : U)` or plain `a b : T`
        if binder_chunk.startswith("(") or binder_chunk.startswith("{") or binder_chunk.startswith("["):
            sub_binders, rem = _extract_binder_groups(binder_chunk + " :")
            if sub_binders and not rem:
                for kind, inner in sub_binders:
                    extracted.append((kind, inner))
            else:
                extracted.append(("(", binder_chunk))
        else:
            extracted.append(("(", binder_chunk))
        s = _canonicalize_ops(body_chunk)
    return extracted, s


def _alpha_normalize_expr(expr: str, env: Dict[str, str]) -> str:
    """Replace bound variable identifiers with canonical `_vK` names using word boundaries."""
    tok_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_']*\b")

    def _sub(m: re.Match[str]) -> str:
        tok = m.group(0)
        return env.get(tok, tok)

    norm = _canonicalize_ops(_strip_outer_parens(expr))
    norm = tok_re.sub(_sub, norm)
    # Normalize spacing around operators & delimiters for invariant formatting
    norm = re.sub(r"\s*([→∧∨=≠≤≥<>+\-*/,:()\[\]{}])\s*", r"\1", norm)
    return norm


def alpha_canonicalize_signature(raw_sig: str) -> str:
    """Alpha-normalize a Lean 4 theorem signature so bound-variable renames and ∀/binder forms match."""
    binders, ret_type = _extract_binder_groups(raw_sig)
    leading_binders, clean_ret = _parse_leading_forall(ret_type)
    all_binders = list(binders) + leading_binders

    env: Dict[str, str] = {}
    counter = 0
    parts: List[str] = []

    for kind, inner in all_binders:
        clean_inner = _canonicalize_ops(inner)
        if ":" in clean_inner:
            lhs, rhs = clean_inner.split(":", 1)
            rhs_norm = _alpha_normalize_expr(rhs, env)
            names = [t for t in lhs.strip().split() if re.match(r"^[A-Za-z_][A-Za-z0-9_']*\Z", t)]
            if not names:
                parts.append(f"{kind}{_alpha_normalize_expr(clean_inner, env)}")
                continue
            for nm in names:
                if nm == "_":
                    parts.append(f"{kind}_:{rhs_norm}")
                    continue
                canon_var = f"_v{counter}"
                counter += 1
                env[nm] = canon_var
                # Distinguish implicit/instance binders while equating `(h : P)` vs `∀ h : P`
                tag = "(" if kind in ("(", "⦃") else kind
                parts.append(f"{tag}{canon_var}:{rhs_norm}")
        else:
            # Bare binder `[DecidableEq α]` or bare type
            parts.append(f"{kind}{_alpha_normalize_expr(clean_inner, env)}")

    # Split remaining top-level arrow premises in return type
    arrows = _split_top_level_arrows(clean_ret)
    norm_arrows = [_alpha_normalize_expr(a, env) for a in arrows if a.strip()]
    # Collapse unused hypothesis names in parts when comparing `(h : P)` vs unnamed `P -> ...`
    # by checking whether `_vK` appears in subsequent parts or return type!
    tail_joined = "→".join(norm_arrows)
    collapsed_parts: List[str] = []
    for idx, p in enumerate(parts):
        if p.startswith("(_v") and ":" in p:
            var_nm, typ_part = p[1:].split(":", 1)
            later = " ".join(parts[idx + 1 :]) + " " + tail_joined
            if not re.search(rf"\b{re.escape(var_nm)}\b", later):
                collapsed_parts.append(typ_part)
                continue
        collapsed_parts.append(p)

    all_chain = collapsed_parts + ([tail_joined] if tail_joined else [])
    return "→".join(all_chain)


def extract_theorem_specs(lean_source: str) -> List[TheoremSpec]:
    """Extract namespace-resolved, alpha-canonicalized TheoremSpec items from Lean 4 source."""
    lex = lex_lean_source(lean_source or "")
    code = lex["code_only"]
    lines = code.splitlines(keepends=True)
    line_starts: List[int] = []
    acc = 0
    for ln in lines:
        line_starts.append(acc)
        acc += len(ln)

    ns_stack: List[Tuple[str, str]] = []
    ns_re = re.compile(rf"^\s*namespace\s+({_IDENT_QUAL_RE})\s*\Z")
    sec_re = re.compile(rf"^\s*(?:(?:public|meta|noncomputable)\s+)?(?:section|mutual)(?:\s+({_IDENT_QUAL_RE}))?\s*\Z")
    end_re = re.compile(rf"^\s*end(?:\s+({_IDENT_QUAL_RE}))?\s*\Z")
    thm_re = re.compile(
        rf"^\s*(?P<mods>(?:(?:private|protected|public|noncomputable|meta|scoped|local)\s+)*)(?P<kind>theorem|lemma)\s+(?P<name>{_IDENT_QUAL_RE})\b"
    )

    def _unwrap(s: str) -> str:
        return re.sub(r"\u00ab([^\u00bb\n]+)\u00bb", r"\1", s)

    specs: List[TheoremSpec] = []
    for idx, raw_ln in enumerate(lines):
        ln = raw_ln.rstrip("\r\n")
        m_ns = ns_re.match(ln)
        if m_ns:
            for seg in _unwrap(m_ns.group(1)).split("."):
                ns_stack.append(("ns", seg))
            continue
        m_sec = sec_re.match(ln)
        if m_sec:
            ns_stack.append(("sec", _unwrap(m_sec.group(1)) if m_sec.group(1) else ""))
            continue
        m_end = end_re.match(ln)
        if m_end:
            ename = _unwrap(m_end.group(1)) if m_end.group(1) else ""
            pops = len(ename.split(".")) if ename else 1
            for _ in range(pops):
                if ns_stack:
                    ns_stack.pop()
            continue
        m_thm = thm_re.match(ln)
        if m_thm:
            name_end = line_starts[idx] + m_thm.end("name")
            assign_pos = _find_top_level_assign(code, name_end)
            sig = code[name_end:assign_pos] if assign_pos != -1 else ""
            raw_nm = _unwrap(m_thm.group("name"))
            cur_ns = [seg for k, seg in ns_stack if k == "ns"]
            ns_str = "" if raw_nm.startswith("_root_.") else ".".join(cur_ns)
            fqn = raw_nm[7:] if raw_nm.startswith("_root_.") else (".".join(cur_ns + [raw_nm]) if cur_ns else raw_nm)
            is_priv = bool(re.search(r"\bprivate\b", m_thm.group("mods") or ""))
            specs.append(
                TheoremSpec(
                    fqn=fqn,
                    short_name=fqn.split(".")[-1],
                    namespace=ns_str,
                    is_private=is_priv,
                    line=idx + 1,
                    start_offset=line_starts[idx] + m_thm.start("kind"),
                    end_offset=line_starts[idx] + m_thm.end("name"),
                    canonical_prop=alpha_canonicalize_signature(sig),
                    raw_signature=sig.strip(),
                )
            )
    return specs


def diff_lean_sources(
    base_source: str,
    head_source: str,
    *,
    include_private: bool = False,
    allow_drops: bool = False,
    allow_renames: bool = True,
) -> LeanDiffResult:
    """Compare two Lean 4 revisions, detecting alpha-equivalent moves/renames, statement edits, and drops."""
    base_specs = [t for t in extract_theorem_specs(base_source) if include_private or not t.is_private]
    head_specs = [t for t in extract_theorem_specs(head_source) if include_private or not t.is_private]

    head_by_fqn = {t.fqn: t for t in head_specs}

    unchanged: List[Dict[str, Any]] = []
    moved: List[Dict[str, Any]] = []
    renamed: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    added: List[Dict[str, Any]] = []
    statement_changed: List[Dict[str, Any]] = []
    violations: List[str] = []
    findings: List[Dict[str, Any]] = []

    matched_head_fqns: set[str] = set()
    unmatched_base: List[TheoremSpec] = []

    for b in base_specs:
        h = head_by_fqn.get(b.fqn)
        if h is not None:
            matched_head_fqns.add(h.fqn)
            if b.canonical_prop == h.canonical_prop:
                entry = {"fqn": b.fqn, "base_line": b.line, "head_line": h.line, "canonical_prop": b.canonical_prop}
                if b.line != h.line:
                    moved.append({**entry, "kind": "LINE_SHIFT"})
                else:
                    unchanged.append(entry)
            else:
                statement_changed.append({
                    "fqn": b.fqn,
                    "base_line": b.line,
                    "head_line": h.line,
                    "base_prop": b.canonical_prop,
                    "head_prop": h.canonical_prop,
                })
                violations.append("REJECT_THEOREM_STATEMENT_CHANGED")
                findings.append({
                    "code": "REJECT_THEOREM_STATEMENT_CHANGED",
                    "message": f"Theorem '{b.fqn}' changed proposition from '{b.canonical_prop}' to '{h.canonical_prop}'",
                    "line": h.line,
                    "start_offset": h.start_offset,
                    "end_offset": h.end_offset,
                })
        else:
            unmatched_base.append(b)

    unmatched_head = [h for h in head_specs if h.fqn not in matched_head_fqns]
    used_head_idx: set[int] = set()

    for b in unmatched_base:
        # 1) Prefer same short_name + alpha-equivalent proposition (namespace move)
        match_idx: Optional[int] = None
        is_ns_move = False
        for idx, h in enumerate(unmatched_head):
            if idx in used_head_idx:
                continue
            if h.canonical_prop == b.canonical_prop and h.short_name == b.short_name:
                match_idx = idx
                is_ns_move = True
                break
        # 2) Otherwise any unmatched head theorem with identical alpha-canonicalized proposition (rename)
        if match_idx is None:
            for idx, h in enumerate(unmatched_head):
                if idx in used_head_idx:
                    continue
                if h.canonical_prop == b.canonical_prop:
                    match_idx = idx
                    is_ns_move = False
                    break

        if match_idx is not None:
            used_head_idx.add(match_idx)
            h = unmatched_head[match_idx]
            rec = {
                "base_fqn": b.fqn,
                "head_fqn": h.fqn,
                "base_line": b.line,
                "head_line": h.line,
                "canonical_prop": b.canonical_prop,
                "kind": "NAMESPACE_MOVE" if is_ns_move else "ALPHA_RENAME",
            }
            if is_ns_move:
                moved.append(rec)
            else:
                renamed.append(rec)
                if not allow_renames:
                    violations.append("REJECT_THEOREM_RENAMED")
                    findings.append({
                        "code": "REJECT_THEOREM_RENAMED",
                        "message": f"Theorem '{b.fqn}' alpha-renamed to '{h.fqn}'",
                        "line": h.line,
                        "start_offset": h.start_offset,
                        "end_offset": h.end_offset,
                    })
        else:
            dropped.append({
                "fqn": b.fqn,
                "base_line": b.line,
                "canonical_prop": b.canonical_prop,
            })
            if not allow_drops:
                violations.append("REJECT_THEOREM_DROPPED")
                findings.append({
                    "code": "REJECT_THEOREM_DROPPED",
                    "message": f"Public theorem '{b.fqn}' from base revision was dropped without alpha-equivalent replacement",
                    "line": b.line,
                    "start_offset": b.start_offset,
                    "end_offset": b.end_offset,
                })

    for idx, h in enumerate(unmatched_head):
        if idx not in used_head_idx:
            added.append({"fqn": h.fqn, "head_line": h.line, "canonical_prop": h.canonical_prop})

    unique_v = sorted(set(violations))
    if unique_v:
        return LeanDiffResult(
            verdict="REJECT",
            primary_code=unique_v[0],
            violations=unique_v,
            unchanged=unchanged,
            moved=moved,
            renamed=renamed,
            dropped=dropped,
            added=added,
            statement_changed=statement_changed,
            findings=findings,
        )
    return LeanDiffResult(
        verdict="ACCEPT",
        primary_code="DIFF_EQUIV_ACCEPT",
        violations=[],
        unchanged=unchanged,
        moved=moved,
        renamed=renamed,
        dropped=[],
        added=added,
        statement_changed=[],
        findings=[],
    )
