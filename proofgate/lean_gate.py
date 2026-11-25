"""Deterministic Lean 4 specification-faithfulness, hygiene, and vacuity gate."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

STANDARD_AXIOMS: frozenset[str] = frozenset({
    "propext",
    "Classical.choice",
    "Quot.sound",
})

_TRIVIAL_TACTICS: frozenset[str] = frozenset({
    "decide",
    "omega",
    "rfl",
    "trivial",
    "simp",
    "norm_num",
})

_IDENT_SEG_RE = r"(?:\u00ab[^\u00bb\n]+\u00bb|[A-Za-z_][A-Za-z0-9_']*)"
_IDENT_QUAL_RE = rf"{_IDENT_SEG_RE}(?:\.{_IDENT_SEG_RE})*"


@dataclass(frozen=True)
class LeanGateResult:
    verdict: str
    primary_code: str
    violations: List[str]
    theorem_count: int
    cov_bps: int = 10000
    has_auto_implicit_false: bool = False
    printed_theorem_count: int = 0
    vacuous_theorems: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def lex_lean_source(src: str) -> Dict[str, Any]:
    """Offset-preserving Lean 4 lexer handling nested /- -/, --, r#\"...\"#, and s!\"...{...}\"."""
    n = len(src)
    i = 0
    block_depth = 0
    # Frame stack for interpolated strings: [in_string_lit: bool, brace_depth: int]
    frames: List[List[Any]] = []
    with_strings: List[str] = []
    code_only: List[str] = []
    unterminated = 0
    invisible_unicode: List[str] = []

    for ch in src:
        cp = ord(ch)
        if cp in (0x00AD, 0x034F, 0x061C, 0x180E, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF):
            invisible_unicode.append(f"U+{cp:04X}")
        elif 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            invisible_unicode.append(f"BIDI_U+{cp:04X}")
        elif 0xFE00 <= cp <= 0xFE0F or 0xE0000 <= cp <= 0xE007F:
            invisible_unicode.append(f"TAG_U+{cp:05X}")

    def _emit_both(ws_text: str, code_text: str) -> None:
        with_strings.append(ws_text)
        code_only.append(code_text)

    while i < n:
        ch = src[i]
        nxt = src[i + 1] if (i + 1) < n else ""

        if block_depth > 0:
            if ch == "/" and nxt == "-":
                block_depth += 1
                _emit_both("  ", "  ")
                i += 2
                continue
            if ch == "-" and nxt == "/":
                block_depth -= 1
                _emit_both("  ", "  ")
                i += 2
                continue
            nl = "\n" if ch == "\n" else " "
            _emit_both(nl, nl)
            i += 1
            continue

        if frames and frames[-1][0]:
            if ch == "\\" and i + 1 < n:
                esc_c = "\n" if src[i + 1] == "\n" else " "
                _emit_both(src[i : i + 2], " " + esc_c)
                i += 2
                continue
            if ch == "{" and nxt == "{":
                _emit_both("{{", "  ")
                i += 2
                continue
            if ch == "{":
                frames[-1][0] = False
                frames[-1][1] = 1
                _emit_both("{", "{")
                i += 1
                continue
            if ch == '"':
                frames.pop()
                _emit_both('"', '"')
                i += 1
                continue
            _emit_both(ch, "\n" if ch == "\n" else " ")
            i += 1
            continue

        if ch == "/" and nxt == "-":
            block_depth = 1
            _emit_both("  ", "  ")
            i += 2
            continue

        if ch == "-" and nxt == "-":
            while i < n and src[i] != "\n":
                _emit_both(" ", " ")
                i += 1
            continue

        if ch == "\u00ab":
            j = i + 1
            while j < n and src[j] != "\u00bb" and src[j] != "\n":
                j += 1
            if j < n and src[j] == "\u00bb":
                seg = src[i : j + 1]
                _emit_both(seg, seg)
                i = j + 1
            else:
                unterminated += 1
                seg = src[i:j]
                _emit_both(seg, seg)
                i = j
            continue

        prev_ch = src[i - 1] if i > 0 else " "
        if (ch.isalpha() or ch == "_") and not (prev_ch.isalnum() or prev_ch in "_'"):
            k_id = i
            while k_id < n and (src[k_id].isalnum() or src[k_id] in "_'"):
                k_id += 1
            if k_id < n and src[k_id] == "!":
                k = k_id + 1
                mid_ws: List[str] = []
                while k < n:
                    if src[k].isspace():
                        mid_ws.append(src[k])
                        k += 1
                    elif src[k] == "-" and k + 1 < n and src[k + 1] == "-":
                        while k < n and src[k] != "\n":
                            mid_ws.append(" ")
                            k += 1
                    elif src[k] == "/" and k + 1 < n and src[k + 1] == "-":
                        cbd = 1
                        mid_ws.append("  ")
                        k += 2
                        while k < n and cbd > 0:
                            if src[k] == "/" and k + 1 < n and src[k + 1] == "-":
                                cbd += 1
                                mid_ws.append("  ")
                                k += 2
                            elif src[k] == "-" and k + 1 < n and src[k + 1] == "/":
                                cbd -= 1
                                mid_ws.append("  ")
                                k += 2
                            else:
                                mid_ws.append("\n" if src[k] == "\n" else " ")
                                k += 1
                        if cbd > 0:
                            unterminated += 1
                    else:
                        break
                if k < n and src[k] == '"':
                    prefix = src[i : k_id + 1] + "".join(mid_ws) + '"'
                    _emit_both(prefix, "".join("\n" if x == "\n" else " " for x in prefix))
                    frames.append([True, 0])
                    i = k + 1
                    continue

        if ch == "r" and nxt == "#" and not (prev_ch.isalnum() or prev_ch in "_'"):
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                j += 1
                closing = '"' + ("#" * hashes)
                ep = src.find(closing, j)
                if ep == -1:
                    unterminated += 1
                    rest = src[i:]
                    _emit_both(rest, "".join("\n" if x == "\n" else " " for x in rest))
                    break
                seg = src[i : ep + len(closing)]
                masked = '"' + "".join("\n" if x == "\n" else " " for x in seg[1:-1]) + '"'
                _emit_both(seg, masked)
                i = ep + len(closing)
                continue

        if ch == "'" and not (prev_ch.isalnum() or prev_ch in "_)'"):
            m_ch = re.match(
                r"^'(?:\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]{1,6}\}|.)|[^'\\\n])'",
                src[i:],
            )
            if m_ch:
                lit = m_ch.group(0)
                _emit_both(lit, "'" + (" " * (len(lit) - 2)) + "'")
                i += len(lit)
                continue

        if ch == '"':
            j = i + 1
            closed = False
            while j < n:
                if src[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    closed = True
                    break
                j += 1
            if not closed:
                unterminated += 1
            seg = src[i:j]
            masked = '"' + "".join("\n" if x == "\n" else " " for x in seg[1 : (-1 if closed else None)]) + ('"' if closed else "")
            _emit_both(seg, masked)
            i = j
            continue

        if frames:
            if ch == "{":
                frames[-1][1] += 1
                _emit_both(ch, ch)
                i += 1
                continue
            if ch == "}":
                frames[-1][1] -= 1
                if frames[-1][1] == 0:
                    frames[-1][0] = True
                    _emit_both("}", "}")
                    i += 1
                    continue
                _emit_both(ch, ch)
                i += 1
                continue

        _emit_both(ch, ch)
        i += 1

    if frames or block_depth > 0:
        unterminated += 1

    return {
        "with_strings": "".join(with_strings),
        "code_only": "".join(code_only),
        "unterminated": unterminated,
        "invisible_unicode": sorted(set(invisible_unicode)),
    }


def strip_lean_comments_and_strings(src: str) -> Tuple[str, str]:
    """Strip nested block comments and line comments; return (with_strings, code_only)."""
    res = lex_lean_source(src)
    return res["with_strings"], res["code_only"]


def _unwrap_guillemets(text: str) -> str:
    return re.sub(r"\u00ab([^\u00bb\n]+)\u00bb", r"\1", text)


def _find_top_level_assign(code: str, start: int) -> int:
    """Find top-level `:=` starting at `start` outside parens/brackets/braces."""
    depth = 0
    i = start
    n = len(code)
    while i < n:
        ch = code[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0 and ch == ":" and i + 1 < n and code[i + 1] == "=":
            return i
        i += 1
    return -1


def _split_top_level_arrows(expr: str) -> List[str]:
    """Split `P -> Q -> R` / `P → Q → R` at bracket depth 0."""
    parts: List[str] = []
    depth = 0
    buf: List[str] = []
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if ch in "([{":
            depth += 1
            buf.append(ch)
            i += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
            i += 1
        elif depth == 0 and ch == "→":
            parts.append("".join(buf).strip())
            buf = []
            i += 1
        elif depth == 0 and ch == "-" and i + 1 < n and expr[i + 1] == ">":
            parts.append("".join(buf).strip())
            buf = []
            i += 2
        else:
            buf.append(ch)
            i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _split_top_level_conjuncts(expr: str) -> List[str]:
    """Split top-level `P ∧ Q` or `P /\\ Q` conjuncts inside a hypothesis proposition."""
    parts: List[str] = []
    depth = 0
    buf: List[str] = []
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if ch in "([{":
            depth += 1
            buf.append(ch)
            i += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
            i += 1
        elif depth == 0 and ch == "∧":
            parts.append("".join(buf).strip())
            buf = []
            i += 1
        elif depth == 0 and ch == "/" and i + 1 < n and expr[i + 1] == "\\":
            parts.append("".join(buf).strip())
            buf = []
            i += 2
        else:
            buf.append(ch)
            i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _extract_binder_groups(sig: str) -> Tuple[List[Tuple[str, str]], str]:
    """Split theorem signature into list of (binder_kind, inner_text) and return_type after top-level ':'."""
    binders: List[Tuple[str, str]] = []
    i = 0
    n = len(sig)
    while i < n:
        while i < n and sig[i].isspace():
            i += 1
        if i >= n:
            break
        ch = sig[i]
        if ch == ":":
            return binders, sig[i + 1 :].strip()
        if ch in "({[⦃":
            close = {"(": ")", "{": "}", "[": "]", "⦃": "⦄"}[ch]
            depth = 1
            j = i + 1
            while j < n and depth > 0:
                if sig[j] == ch:
                    depth += 1
                elif sig[j] == close:
                    depth -= 1
                j += 1
            binders.append((ch, sig[i + 1 : j - 1].strip()))
            i = j
            continue
        # Unexpected token before ':' (skip safely)
        i += 1
    return binders, ""


def _strip_outer_parens(expr: str) -> str:
    s = expr.strip()
    while len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        depth = 0
        matched = True
        for idx, c in enumerate(s):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0 and idx < len(s) - 1:
                    matched = False
                    break
        if matched and depth == 0:
            s = s[1:-1].strip()
        else:
            break
    return s


def _normalize_prop(prop: str) -> str:
    s = _strip_outer_parens(prop)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def _detect_vacuous_hypotheses(sig: str) -> Optional[str]:
    """Detect contradictory hypotheses in theorem binders / arrow premises."""
    binders, ret_type = _extract_binder_groups(sig)

    nat_vars: Set[str] = set()
    # var -> {"low": (val, strict) | None, "high": (val, strict) | None, "eq": Set[int], "ne": Set[int]}
    bounds: Dict[str, Dict[str, Any]] = {}
    positive_props: Set[str] = set()
    negative_props: Set[str] = set()
    eq_pairs: Set[Tuple[str, str]] = set()
    ne_pairs: Set[Tuple[str, str]] = set()

    def _var_bounds(v: str) -> Dict[str, Any]:
        return bounds.setdefault(v, {"low": None, "high": None, "eq": set(), "ne": set()})

    def _update_low(v: str, val: int, strict: bool) -> None:
        b = _var_bounds(v)
        cur = b["low"]
        if cur is None or val > cur[0] or (val == cur[0] and strict and not cur[1]):
            b["low"] = (val, strict)

    def _update_high(v: str, val: int, strict: bool) -> None:
        b = _var_bounds(v)
        cur = b["high"]
        if cur is None or val < cur[0] or (val == cur[0] and strict and not cur[1]):
            b["high"] = (val, strict)

    hyps: List[str] = []
    for _, inner in binders:
        if ":" in inner:
            lhs, rhs = inner.split(":", 1)
            rhs_clean = rhs.strip()
            if rhs_clean in {"Nat", "ℕ"}:
                for tok in lhs.split():
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_']*\Z", tok):
                        nat_vars.add(tok)
                        _update_low(tok, 0, False)
            else:
                hyps.append(rhs_clean)
        elif inner:
            hyps.append(inner.strip())

    if ret_type:
        arrows = _split_top_level_arrows(ret_type)
        if len(arrows) > 1:
            for prem in arrows[:-1]:
                if ":" in prem and not any(op in prem.split(":", 1)[0] for op in ("<", ">", "=", "≤", "≥", "≠")):
                    # Named or typed premise like (h : P) -> Q
                    lhs_p, rhs_p = prem.split(":", 1)
                    if rhs_p.strip() in {"Nat", "ℕ"}:
                        for tok in lhs_p.strip("() ").split():
                            if re.match(r"^[A-Za-z_][A-Za-z0-9_']*\Z", tok):
                                nat_vars.add(tok)
                                _update_low(tok, 0, False)
                    else:
                        hyps.append(rhs_p.strip())
                else:
                    hyps.append(prem)

    # Expand top-level conjunctions inside hypotheses (never disjunctions!)
    atomic_hyps: List[str] = []
    for h in hyps:
        h_clean = _strip_outer_parens(h)
        atomic_hyps.extend(_split_top_level_conjuncts(h_clean))

    # Do not check inequalities inside 'or' / '∨'
    cmp_var_lit = re.compile(
        r"^(?:\(\s*)?([A-Za-z_][A-Za-z0-9_']*)(?:\s*:\s*(?:Nat|Int|ℕ|ℤ)\s*)?(?:\s*\))?\s*(<=|>=|!=|<|>|=|≤|≥|≠)\s*(-?\d+)\Z"
    )
    cmp_lit_var = re.compile(
        r"^(-?\d+)\s*(<=|>=|!=|<|>|=|≤|≥|≠)\s*(?:\(\s*)?([A-Za-z_][A-Za-z0-9_']*)(?:\s*:\s*(?:Nat|Int|ℕ|ℤ)\s*)?(?:\s*\))?\Z"
    )
    lit_eq_lit = re.compile(r"^(-?\d+)\s*(=|!=|≠|<|>|<=|>=|≤|≥)\s*(-?\d+)\Z")
    sym_eq_ne = re.compile(r"^([A-Za-z_][A-Za-z0-9_']*)\s*(=|!=|≠)\s*([A-Za-z_][A-Za-z0-9_']*)\Z")

    for raw_atom in atomic_hyps:
        atom = _normalize_prop(raw_atom)
        if not atom or "∨" in atom or r"\/" in atom or "→" in atom or "->" in atom:
            continue

        if atom == "False":
            return "direct False hypothesis"
        if atom in {"True = False", "False = True", "true = false", "false = true"}:
            return f"contradictory literal equality ({atom})"

        m_ll = lit_eq_lit.match(atom)
        if m_ll:
            a, op, b = int(m_ll.group(1)), m_ll.group(2), int(m_ll.group(3))
            ok = (
                (op == "=" and a == b)
                or (op in {"!=", "≠"} and a != b)
                or (op == "<" and a < b)
                or (op == ">" and a > b)
                or (op in {"<=", "≤"} and a <= b)
                or (op in {">=", "≥"} and a >= b)
            )
            if not ok:
                return f"unsatisfiable numeric literal hypothesis ({atom})"

        m_vl = cmp_var_lit.match(atom)
        if m_vl:
            v, op, num = m_vl.group(1), m_vl.group(2), int(m_vl.group(3))
            if op == "<":
                _update_high(v, num, True)
            elif op in {"<=", "≤"}:
                _update_high(v, num, False)
            elif op == ">":
                _update_low(v, num, True)
            elif op in {">=", "≥"}:
                _update_low(v, num, False)
            elif op == "=":
                _var_bounds(v)["eq"].add(num)
            elif op in {"!=", "≠"}:
                _var_bounds(v)["ne"].add(num)
            continue

        m_lv = cmp_lit_var.match(atom)
        if m_lv:
            num, op, v = int(m_lv.group(1)), m_lv.group(2), m_lv.group(3)
            if op == "<":
                _update_low(v, num, True)
            elif op in {"<=", "≤"}:
                _update_low(v, num, False)
            elif op == ">":
                _update_high(v, num, True)
            elif op in {">=", "≥"}:
                _update_high(v, num, False)
            elif op == "=":
                _var_bounds(v)["eq"].add(num)
            elif op in {"!=", "≠"}:
                _var_bounds(v)["ne"].add(num)
            continue

        m_se = sym_eq_ne.match(atom)
        if m_se:
            lhs, op, rhs = m_se.group(1), m_se.group(2), m_se.group(3)
            pair = (min(lhs, rhs), max(lhs, rhs))
            if op == "=":
                eq_pairs.add(pair)
            else:
                if lhs == rhs:
                    return f"irreflexive self-inequality ({atom})"
                ne_pairs.add(pair)

        if atom.startswith("¬"):
            negative_props.add(_normalize_prop(atom[1:]))
        elif atom.startswith("Not "):
            negative_props.add(_normalize_prop(atom[4:]))
        else:
            positive_props.add(atom)

    for v, b in bounds.items():
        low = b["low"]
        high = b["high"]
        eqs = b["eq"]
        nes = b["ne"]
        if len(eqs) > 1:
            return f"conflicting equalities on '{v}': {sorted(eqs)}"
        if eqs & nes:
            return f"variable '{v}' forced equal and unequal to {sorted(eqs & nes)}"
        if low is not None and high is not None:
            lv, l_strict = low
            hv, h_strict = high
            if lv > hv or (lv == hv and (l_strict or h_strict)):
                tag = f"{v} : Nat, " if v in nat_vars else ""
                return f"empty interval on '{v}' ({tag}lower=({lv}, strict={l_strict}), upper=({hv}, strict={h_strict}))"
        if eqs:
            ev = next(iter(eqs))
            if low is not None:
                lv, l_strict = low
                if ev < lv or (l_strict and ev == lv):
                    return f"'{v} = {ev}' violates lower bound ({lv}, strict={l_strict})"
            if high is not None:
                hv, h_strict = high
                if ev > hv or (h_strict and ev == hv):
                    return f"'{v} = {ev}' violates upper bound ({hv}, strict={h_strict})"

    if positive_props & negative_props:
        prop_dup = sorted(positive_props & negative_props)[0]
        return f"contradictory proposition '{prop_dup}' and '¬{prop_dup}'"
    if eq_pairs & ne_pairs:
        p = sorted(eq_pairs & ne_pairs)[0]
        return f"contradictory equality '{p[0]} = {p[1]}' and '{p[0]} ≠ {p[1]}'"
    return None


def _analyze_structure(code_only: str) -> Dict[str, Any]:
    """Extract theorems, namespaces, #print axioms coverage, and vacuity info with exact offsets."""
    lines = code_only.splitlines(keepends=True)
    line_starts: List[int] = []
    acc = 0
    for ln in lines:
        line_starts.append(acc)
        acc += len(ln)

    ns_stack: List[Tuple[str, str]] = []
    ns_re = re.compile(rf"^\s*namespace\s+({_IDENT_QUAL_RE})\s*\Z")
    sec_re = re.compile(rf"^\s*(?:(?:public|meta|noncomputable)\s+)?(?:section|mutual)(?:\s+({_IDENT_QUAL_RE}))?\s*\Z")
    end_re = re.compile(rf"^\s*end(?:\s+({_IDENT_QUAL_RE}))?\s*\Z")
    pa_re = re.compile(rf"^\s*#print\s+axioms\s+({_IDENT_QUAL_RE})")
    thm_re = re.compile(
        rf"^\s*(?P<mods>(?:(?:private|protected|public|noncomputable|meta|scoped|local)\s+)*)(?P<kind>theorem|lemma)\s+(?P<name>{_IDENT_QUAL_RE})\b"
    )

    def _cur_ns() -> List[str]:
        return [seg for k, seg in ns_stack if k == "ns"]

    theorems: List[Dict[str, Any]] = []
    print_calls: List[Tuple[List[str], str]] = []

    for idx, raw_ln in enumerate(lines):
        ln = raw_ln.rstrip("\r\n")
        m_ns = ns_re.match(ln)
        if m_ns:
            for seg in _unwrap_guillemets(m_ns.group(1)).split("."):
                ns_stack.append(("ns", seg))
            continue
        m_sec = sec_re.match(ln)
        if m_sec:
            sname = _unwrap_guillemets(m_sec.group(1)) if m_sec.group(1) else ""
            ns_stack.append(("sec", sname))
            continue
        m_end = end_re.match(ln)
        if m_end:
            ename = _unwrap_guillemets(m_end.group(1)) if m_end.group(1) else ""
            pops = len(ename.split(".")) if ename else 1
            for _ in range(pops):
                if ns_stack:
                    ns_stack.pop()
            continue
        m_pa = pa_re.match(ln)
        if m_pa:
            print_calls.append((_cur_ns(), _unwrap_guillemets(m_pa.group(1))))
            continue
        m_thm = thm_re.match(ln)
        if m_thm:
            name_end = line_starts[idx] + m_thm.end("name")
            assign_pos = _find_top_level_assign(code_only, name_end)
            sig = code_only[name_end:assign_pos] if assign_pos != -1 else ""
            tactic_tail = ""
            if assign_pos != -1:
                after_assign = code_only[assign_pos + 2 :].lstrip()
                if after_assign.startswith("by"):
                    rest_by = after_assign[2:].lstrip()
                    tactic_tail = rest_by.split()[0] if rest_by.split() else ""
            raw_nm = _unwrap_guillemets(m_thm.group("name"))
            cns = _cur_ns()
            if raw_nm.startswith("_root_."):
                fqn = raw_nm[7:]
            else:
                fqn = ".".join(cns + [raw_nm]) if cns else raw_nm
            mods = m_thm.group("mods") or ""
            is_private = bool(re.search(r"\bprivate\b", mods))
            sig_binders, sig_ret = _extract_binder_groups(sig)
            has_binders = (
                bool(sig_binders)
                or ("forall" in sig_ret)
                or ("∀" in sig_ret)
                or ("→" in sig_ret)
                or ("->" in sig_ret)
            )
            theorems.append({
                "fqn": fqn,
                "short_name": raw_nm,
                "is_private": is_private,
                "has_binders": has_binders,
                "tactic": tactic_tail,
                "sig": sig,
                "line": idx + 1,
                "start_offset": line_starts[idx] + m_thm.start("kind"),
                "end_offset": line_starts[idx] + m_thm.end("name"),
                "vacuity_reason": _detect_vacuous_hypotheses(sig) if sig else None,
            })

    all_thms = {t["fqn"] for t in theorems}
    resolved_prints: Set[str] = set()
    for cns, raw_target in print_calls:
        if raw_target.startswith("_root_."):
            resolved_prints.add(raw_target[7:])
            continue
        matched: Optional[str] = None
        for k in range(len(cns), -1, -1):
            cand = ".".join(cns[:k] + [raw_target]) if k > 0 else raw_target
            if cand in all_thms:
                matched = cand
                break
        resolved_prints.add(matched if matched is not None else (".".join(cns + [raw_target]) if cns else raw_target))

    pub_thms = [t for t in theorems if not t["is_private"]]
    printed_pub = [t for t in pub_thms if t["fqn"] in resolved_prints]
    if pub_thms:
        cov_bps = (10_000 * len(printed_pub)) // len(pub_thms)
    elif theorems:
        cov_bps = (10_000 * sum(1 for t in theorems if t["fqn"] in resolved_prints)) // len(theorems)
    else:
        cov_bps = 10_000

    return {
        "theorems": theorems,
        "public_theorems": pub_thms,
        "printed_pub_count": len(printed_pub),
        "resolved_prints": resolved_prints,
        "has_any_print_axioms": bool(print_calls),
        "cov_bps": cov_bps,
    }


def check_lean_source(
    lean_source: str,
    *,
    printed_axioms: Optional[Iterable[str]] = None,
    compiler_warnings: Optional[Iterable[str]] = None,
    require_print_axioms: bool = True,
    require_all_print_axioms: bool = False,
    require_auto_implicit_false: bool = False,
    check_vacuity: bool = True,
    strict: bool = False,
) -> LeanGateResult:
    """Audit Lean 4 source for proof loopholes, kernel bypasses, trivial padding, and vacuity."""
    if strict:
        require_print_axioms = True
        require_all_print_axioms = True
        require_auto_implicit_false = True
        check_vacuity = True

    src = lean_source or ""
    axioms = [str(a).strip() for a in (printed_axioms or ()) if str(a).strip()]
    warnings = [str(w) for w in (compiler_warnings or ())]
    violations: List[str] = []
    findings: List[Dict[str, Any]] = []

    def _add_span(code: str, message: str, start_idx: int = 0, end_idx: int = 0) -> None:
        violations.append(code)
        prefix = src[:start_idx]
        line = prefix.count("\n") + 1
        snippet = src.splitlines()[line - 1].strip() if src.splitlines() and 1 <= line <= len(src.splitlines()) else ""
        findings.append({
            "code": code,
            "message": message,
            "line": line,
            "start_offset": start_idx,
            "end_offset": max(start_idx, end_idx),
            "snippet": snippet,
        })

    lex = lex_lean_source(src)
    with_strings = lex["with_strings"]
    code_only = lex["code_only"]

    if lex["unterminated"] > 0 or lex["invisible_unicode"]:
        _add_span(
            "REJECT_UNTERMINATED_LEXER",
            f"Unterminated comment/string ({lex['unterminated']}) or invisible Unicode {lex['invisible_unicode']}",
        )

    m_interp = re.search(r's!\s*"[^"]*\bsorry\b', with_strings)
    if m_interp:
        _add_span("REJECT_LEXER_INTERP_SORRY_EVASION", "Interpolated s!\"...\" string contains sorry evasion", m_interp.start(), m_interp.end())

    m_skip = re.search(
        r"\bset_option\s+(?:weak\s*\.\s*)?debug\s*\.\s*(?:skipKernelTC|proofAsSorry|byAsSorry)\b(?:\s*\(?\s*true\s*\)?)?|\bdebug\.skipKernelTC\b\s+true\b",
        with_strings,
    )
    if m_skip:
        _add_span("REJECT_SKIP_KERNEL_TC", "Dangerous debug kernel bypass option detected", m_skip.start(), m_skip.end())

    m_mk = re.search(r"\b(?:mkSorry|mkSyntheticSorry|Meta\.mkSorry)\b", code_only)
    if m_mk:
        _add_span("REJECT_METAPROG_MKSORRY_ELAB", "Metaprogramming mkSorry injection detected", m_mk.start(), m_mk.end())

    m_add = re.search(r"\baddDecl\b", code_only)
    if m_add and re.search(r"\baxiomDecl\b", code_only):
        _add_span("REJECT_METAPROG_ADDDECL_AXIOM", "Metaprogramming addDecl/axiomDecl smuggling detected", m_add.start(), m_add.end())

    m_nat = re.search(r"(?<![\w'])(?:native_decide|bv_decide|bv_check)(?![\w'])", code_only)
    if m_nat or any(ax in {"Lean.ofReduceBool", "Lean.trustCompiler", "Lean.ofReduceNat"} for ax in axioms):
        _add_span(
            "REJECT_NATIVE_DECIDE_OFREDUCEBOOL",
            "native_decide or Lean.ofReduceBool / Lean.trustCompiler dependency detected",
            m_nat.start() if m_nat else 0,
            m_nat.end() if m_nat else 0,
        )

    m_ax = re.search(
        r"(?<![.\w'])axiom(?![\w'])",
        re.sub(r"\u00ab[^\u00bb\n]+\u00bb", "_GUIL_", code_only),
    )
    if m_ax:
        _add_span("REJECT_NONSTANDARD_AXIOM", "Explicit custom axiom declaration detected", m_ax.start(), m_ax.end())

    m_ext = re.search(r"\b(?:implemented_by|csimp)\b|@\[[^\]]*\b(?:extern|implemented_by|csimp)\b[^\]]*\]", code_only)
    if m_ext:
        _add_span("REJECT_UNSAFE_LEAN_ATTRIBUTE", "Unsafe extern/implemented_by/csimp attribute detected", m_ext.start(), m_ext.end())

    m_admit = re.search(r"(?<![\w'])admit(?![\w'])", code_only)
    if m_admit:
        _add_span("REJECT_LEAN_ADMIT", "Incomplete proof via admit detected", m_admit.start(), m_admit.end())

    m_sorry = re.search(r"(?<![\w'])(?:sorry|sorryAx)(?![\w'])", code_only)
    if m_sorry:
        _add_span("REJECT_LEAN_SORRY", "Incomplete proof via sorry detected", m_sorry.start(), m_sorry.end())

    if any(re.search(r"\bsorry\b", w, re.I) for w in warnings):
        _add_span("REJECT_LEAN_SORRY_WARNING", "Compiler warning references sorry")

    if any(ax not in STANDARD_AXIOMS for ax in axioms):
        bad_ax = [ax for ax in axioms if ax not in STANDARD_AXIOMS]
        _add_span("REJECT_NONSTANDARD_AXIOM_WHITELIST", f"Non-standard axioms used: {bad_ax}")

    has_auto_implicit_false = bool(re.search(r"(?m)^\s*set_option\s+autoImplicit\s+false\b", code_only))
    has_auto_implicit_true = bool(re.search(r"\bset_option\s+(?:weak\s*\.\s*)?(?:autoImplicit|relaxedAutoImplicit)\s+true\b", code_only))
    if require_auto_implicit_false and (not has_auto_implicit_false or has_auto_implicit_true):
        _add_span("REJECT_MISSING_AUTO_IMPLICIT_FALSE", "Missing 'set_option autoImplicit false' or autoImplicit re-enabled")

    struct = _analyze_structure(code_only)
    theorems = struct["theorems"]
    cov_bps = int(struct["cov_bps"])
    printed_count = int(struct["printed_pub_count"])
    vacuous_theorems: List[str] = []

    if theorems:
        if require_print_axioms and not struct["has_any_print_axioms"]:
            _add_span("REJECT_MISSING_PRINT_AXIOMS", "Public theorems present without any #print axioms command")
        if require_all_print_axioms and cov_bps < 10_000:
            missing_names = [t["fqn"] for t in struct["public_theorems"] if t["fqn"] not in struct["resolved_prints"]]
            _add_span(
                "REJECT_LOW_PRINT_AXIOMS_COVERAGE",
                f"#print axioms coverage is {cov_bps} bps (< 10000); missing: {missing_names}",
            )
            if "REJECT_MISSING_PRINT_AXIOMS" not in violations:
                violations.append("REJECT_MISSING_PRINT_AXIOMS")

        for thm in theorems:
            if thm["has_binders"] and thm["tactic"] == "decide":
                _add_span(
                    "REJECT_FREE_VAR_DECIDE",
                    f"Theorem '{thm['fqn']}' uses bare decide on bound hypotheses",
                    thm["start_offset"],
                    thm["end_offset"],
                )
            if check_vacuity and thm["vacuity_reason"]:
                vacuous_theorems.append(thm["fqn"])
                _add_span(
                    "REJECT_VACUOUS_HYPOTHESIS",
                    f"Theorem '{thm['fqn']}' has vacuous/contradictory hypotheses: {thm['vacuity_reason']}",
                    thm["start_offset"],
                    thm["end_offset"],
                )

        closed_trivial = sum(
            1 for thm in theorems if (not thm["has_binders"]) and thm["tactic"] in _TRIVIAL_TACTICS
        )
        if (closed_trivial / float(len(theorems))) > 0.50:
            _add_span(
                "REJECT_TRIVIAL_ISPAT",
                f"{closed_trivial}/{len(theorems)} theorems (>50%) are binderless constant-tactic proofs",
            )

    unique_v = sorted(set(violations))
    if unique_v:
        return LeanGateResult(
            verdict="REJECT",
            primary_code=unique_v[0],
            violations=unique_v,
            theorem_count=len(theorems),
            cov_bps=cov_bps,
            has_auto_implicit_false=has_auto_implicit_false,
            printed_theorem_count=printed_count,
            vacuous_theorems=vacuous_theorems,
            findings=findings,
        )
    return LeanGateResult(
        verdict="ACCEPT",
        primary_code="QED_ACCEPT",
        violations=[],
        theorem_count=len(theorems),
        cov_bps=cov_bps,
        has_auto_implicit_false=has_auto_implicit_false,
        printed_theorem_count=printed_count,
        vacuous_theorems=[],
        findings=[],
    )
