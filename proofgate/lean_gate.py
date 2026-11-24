"""Deterministic Lean 4 specification-faithfulness and soundness gate."""
from __future__ import annotations

from dataclasses import dataclass, asdict
import re
from typing import Dict, Iterable, List, Optional, Tuple

STANDARD_AXIOMS: frozenset[str] = frozenset({
    "propext",
    "Classical.choice",
    "Quot.sound",
})

_THEOREM_HEADER_RE = re.compile(
    r"(?m)^\s*(?:private\s+|protected\s+)?(?:theorem|lemma)\s+([^\s:({\[<]+)(.*?):=\s*by\s+([^\n]*)",
    re.S,
)


@dataclass(frozen=True)
class LeanGateResult:
    verdict: str
    primary_code: str
    violations: List[str]
    theorem_count: int

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def strip_lean_comments_and_strings(src: str) -> Tuple[str, str]:
    """Strip nested block comments and line comments; return (with_strings, code_only)."""
    n = len(src)
    i = 0
    block_depth = 0
    with_strings: List[str] = []
    code_only: List[str] = []

    while i < n:
        ch = src[i]
        nxt = src[i + 1] if (i + 1) < n else ""

        if block_depth > 0:
            if ch == "/" and nxt == "-":
                block_depth += 1
                i += 2
                continue
            if ch == "-" and nxt == "/":
                block_depth -= 1
                i += 2
                continue
            if ch == "\n":
                with_strings.append("\n")
                code_only.append("\n")
            i += 1
            continue

        if ch == "/" and nxt == "-":
            block_depth = 1
            i += 2
            continue
        if ch == "-" and nxt == "-":
            while i < n and src[i] != "\n":
                i += 1
            continue

        if ch == "'":
            j = i + 1
            if j < n and src[j] == "\\":
                j += 2
            elif j < n:
                j += 1
            if j < n and src[j] == "'":
                lit = src[i : j + 1]
                with_strings.append(lit)
                code_only.append(" 'c' ")
                i = j + 1
                continue

        if ch == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            lit = src[i:j]
            with_strings.append(lit)
            code_only.append(' "" ')
            i = j
            continue

        with_strings.append(ch)
        code_only.append(ch)
        i += 1

    return "".join(with_strings), "".join(code_only)


def _extract_theorems(code_only: str) -> List[Tuple[bool, str]]:
    found: List[Tuple[bool, str]] = []
    for m in _THEOREM_HEADER_RE.finditer(code_only):
        sig = m.group(2)
        tactic = m.group(3).strip().split()[0] if m.group(3).strip() else ""
        has_binders = ("forall" in sig) or ("∀" in sig) or any(c in sig for c in "({[")
        found.append((has_binders, tactic))
    return found


def check_lean_source(
    lean_source: str,
    *,
    printed_axioms: Optional[Iterable[str]] = None,
    compiler_warnings: Optional[Iterable[str]] = None,
    require_print_axioms: bool = True,
) -> LeanGateResult:
    """Audit Lean 4 source for proof loopholes, kernel bypasses, and trivial padding."""
    axioms = [str(a).strip() for a in (printed_axioms or ()) if str(a).strip()]
    warnings = [str(w) for w in (compiler_warnings or ())]
    violations: List[str] = []

    with_strings, code_only = strip_lean_comments_and_strings(lean_source or "")

    if re.search(r's!\s*"[^"]*\bsorry\b', with_strings):
        violations.append("REJECT_LEXER_INTERP_SORRY_EVASION")
    if re.search(r"\bdebug\.skipKernelTC\b\s+true\b", with_strings):
        violations.append("REJECT_SKIP_KERNEL_TC")
    if re.search(r"\bmkSorry\b", code_only) or (re.search(r"\belab\b", code_only) and "Meta.mkSorry" in code_only):
        violations.append("REJECT_METAPROG_MKSORRY_ELAB")
    if re.search(r"\baddDecl\b", code_only) and re.search(r"\baxiomDecl\b", code_only):
        violations.append("REJECT_METAPROG_ADDDECL_AXIOM")
    if re.search(r"\bnative_decide\b", code_only) or any(
        ax in {"Lean.ofReduceBool", "Lean.trustCompiler"} for ax in axioms
    ):
        violations.append("REJECT_NATIVE_DECIDE_OFREDUCEBOOL")
    if re.search(r"(?m)^\s*axiom\s+", code_only):
        violations.append("REJECT_NONSTANDARD_AXIOM")
    if re.search(r"\badmit\b", code_only):
        violations.append("REJECT_LEAN_ADMIT")
    if re.search(r"\bsorry\b", code_only):
        violations.append("REJECT_LEAN_SORRY")
    if any(re.search(r"\bsorry\b", w, re.I) for w in warnings):
        violations.append("REJECT_LEAN_SORRY_WARNING")
    if any(ax not in STANDARD_AXIOMS for ax in axioms):
        violations.append("REJECT_NONSTANDARD_AXIOM_WHITELIST")

    theorems = _extract_theorems(code_only)
    if theorems:
        if require_print_axioms and "#print axioms" not in code_only:
            violations.append("REJECT_MISSING_PRINT_AXIOMS")
        for has_binders, tactic in theorems:
            if has_binders and tactic == "decide":
                violations.append("REJECT_FREE_VAR_DECIDE")
        closed_trivial = sum(
            1 for has_binders, tactic in theorems if (not has_binders) and tactic in {"decide", "omega", "rfl", "trivial"}
        )
        if (closed_trivial / float(len(theorems))) > 0.50:
            violations.append("REJECT_TRIVIAL_ISPAT")

    unique_v = sorted(set(violations))
    if unique_v:
        return LeanGateResult(
            verdict="REJECT",
            primary_code=unique_v[0],
            violations=unique_v,
            theorem_count=len(theorems),
        )
    return LeanGateResult(
        verdict="ACCEPT",
        primary_code="QED_ACCEPT",
        violations=[],
        theorem_count=len(theorems),
    )
