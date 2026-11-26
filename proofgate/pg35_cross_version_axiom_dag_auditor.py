#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 AlpLab Research
# SPDX-License-Identifier: Apache-2.0
"""ProofGate PG-35 — Cross-Version Lean 4 & Mathlib Axiom-Dependency DAG + Source Auditor.

Implements and benchmarks 5 auditing methods (M1..M5) across 48 synthetic cross-version
theorem transitions (12 ALLOWED_AXIOM_SHIFT, 12 TRANSITIVE_DEP_VIOLATION, 12 RENAME_ONLY,
12 DIRECT_OR_STEALTH_VIOLATION), measuring False Positives (FP) and False Negatives (FN)
separately per class, with OASIS SARIF 2.1.0 and RFC 8785 JCS SHA-256 export.
"""
from __future__ import annotations

import dataclasses
import json
import re
import sys
import time
from typing import Any

from proofgate.spec_diff_sarif_v33 import (
    audit_spec_vs_candidate_v33,
    compute_vendi_scores,
    jcs_sha256,
    to_sarif_v210,
    v32_audit_spec_vs_candidate,
)

STANDARD_LEAN_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})
COMPILER_RUNTIME_ATTRS = frozenset({"implemented_by", "extern", "csimp"})


@dataclasses.dataclass(frozen=True)
class ConstNode:
    """Serialized kernel/export declaration node from a Lean .olean / Comparator snapshot."""
    name: str
    kind: str  # theorem | def | abbrev | axiom | opaque
    type_expr: str
    value_deps: tuple[str, ...] = ()
    type_deps: tuple[str, ...] = ()
    attrs: tuple[str, ...] = ()
    is_public: bool = True
    deprecated_target: str | None = None


@dataclasses.dataclass(frozen=True)
class ArchiveSnapshot:
    """Represents one Lean/Mathlib version snapshot (e.g. v4.21.0, v4.28.0, v4.36.0)."""
    toolchain: str
    nodes: dict[str, ConstNode]
    align_map: dict[str, str]
    source_files: dict[str, str]


@dataclasses.dataclass(frozen=True)
class AuditPolicy:
    name: str
    allowed_axioms: frozenset[str] = STANDARD_LEAN_AXIOMS
    allow_native_eval: bool = False
    forbid_runtime_attrs_in_transitive_closure: bool = True


POLICY_STANDARD_MATHLIB = AuditPolicy(
    name="STANDARD_MATHLIB",
    allowed_axioms=STANDARD_LEAN_AXIOMS,
    allow_native_eval=False,
)

POLICY_ALLOW_TRUSTED_BV = AuditPolicy(
    name="ALLOW_TRUSTED_BV_DECIDE",
    allowed_axioms=STANDARD_LEAN_AXIOMS,
    allow_native_eval=True,
)

# Supports grouped Lean 4 binders like (a b c : Nat) and {x y : Type}
_GROUPED_BINDER_RE = re.compile(r"([\(\{])\s*([A-Za-z_][A-Za-z0-9_'\s]*?)\s*:\s*([^)\}]+)([)\}])")
_RESERVED_TYPES = frozenset({"Nat", "Int", "Prop", "Type", "Sort", "Bool", "Real", "Rat", "String"})


def canonicalize_type_alpha(type_expr: str, align_map: dict[str, str] | None = None) -> str:
    """Alpha-normalize single and grouped Lean 4 binders and apply verified #align renames."""
    expr = " ".join(type_expr.split())
    if align_map:
        for old_k, new_k in sorted(align_map.items(), key=lambda kv: -len(kv[0])):
            expr = re.sub(rf"\b{re.escape(old_k)}\b", new_k, expr)
    mapping: dict[str, str] = {}
    counter = 0
    for m in _GROUPED_BINDER_RE.finditer(expr):
        for var in m.group(2).split():
            if var not in mapping and var not in _RESERVED_TYPES:
                mapping[var] = f"_b{counter}"
                counter += 1
    for orig, repl in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
        expr = re.sub(rf"\b{re.escape(orig)}\b", repl, expr)
    return expr


def collect_axioms_pre_8842(snap: ArchiveSnapshot, root: str) -> set[str]:
    """Simulates pre-Jul-2025 Lean.collectAxioms (value-edges only; misses axiom-type edges #8840)."""
    seen: set[str] = set()
    axioms: set[str] = set()
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in snap.nodes:
            continue
        seen.add(cur)
        node = snap.nodes[cur]
        if node.kind == "axiom":
            axioms.add(node.name)
            continue
        stack.extend(node.value_deps)
    return axioms


def collect_full_kernel_dag(snap: ArchiveSnapshot, root: str) -> dict[str, Any]:
    """Walks BOTH value_deps AND type_deps across all reachable constants, including axiom types."""
    seen: set[str] = set()
    axioms: set[str] = set()
    runtime_attrs: list[str] = []
    visited_order: list[str] = []
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in snap.nodes:
            continue
        seen.add(cur)
        visited_order.append(cur)
        node = snap.nodes[cur]
        if node.kind == "axiom":
            axioms.add(node.name)
        for attr in node.attrs:
            if attr in COMPILER_RUNTIME_ATTRS:
                runtime_attrs.append(f"{attr}@{node.name}")
        stack.extend(node.value_deps)
        stack.extend(node.type_deps)
    return {
        "axioms": axioms,
        "runtime_attrs": sorted(set(runtime_attrs)),
        "reachable_count": len(visited_order),
    }


def _normalize_axiom_token(ax: str, allow_native: bool) -> str:
    if allow_native and (
        ax == "Lean.trustCompiler"
        or ax == "Lean.ofReduceBool"
        or ax.endswith("_native")
        or "._native." in ax
    ):
        return "<NATIVE_TRUST_AXIOM>"
    return ax


def _split_ns(qual_name: str) -> tuple[str, str]:
    if "." not in qual_name:
        return ("", qual_name)
    ns, short = qual_name.rsplit(".", 1)
    return (ns, short)


def resolve_target_name(old_name: str, old_snap: ArchiveSnapshot, new_snap: ArchiveSnapshot) -> str | None:
    """Resolve target via exact match, @[deprecated] alias, #align manifest, or same-namespace prime suffix."""
    if old_name in new_snap.nodes:
        node = new_snap.nodes[old_name]
        if node.deprecated_target and node.deprecated_target in new_snap.nodes:
            return node.deprecated_target
        return old_name
    if old_name in new_snap.align_map:
        mapped = new_snap.align_map[old_name]
        if mapped in new_snap.nodes:
            return mapped
    # Same-namespace prime-suffix rename ONLY (never cross-namespace without explicit #align/deprecated!)
    old_node = old_snap.nodes[old_name]
    old_ns, old_short = _split_ns(old_name)
    old_canon = canonicalize_type_alpha(old_node.type_expr, new_snap.align_map)
    candidates = [
        k for k, v in new_snap.nodes.items()
        if v.kind == old_node.kind
        and _split_ns(k)[0] == old_ns
        and _split_ns(k)[1].rstrip("'") == old_short.rstrip("'")
        and canonicalize_type_alpha(v.type_expr, new_snap.align_map) == old_canon
    ]
    return candidates[0] if len(candidates) == 1 else None


def run_m1_v32_source_diff(old_snap: ArchiveSnapshot, new_snap: ArchiveSnapshot, target: str) -> bool:
    """M1: Source-only v3.2 regex diff."""
    base_src = old_snap.source_files.get(target, "")
    if target not in new_snap.source_files:
        return True
    cand_src = new_snap.source_files[target]
    return v32_audit_spec_vs_candidate(base_src, cand_src)["verdict"] != "FAITHFUL_PASS"


def run_m2_naive_print_axioms_eq(old_snap: ArchiveSnapshot, new_snap: ArchiveSnapshot, target: str) -> bool:
    """M2: Naive #print axioms exact set equality."""
    if target not in new_snap.nodes:
        return True
    ax_old = (
        collect_axioms_pre_8842(old_snap, target)
        if old_snap.toolchain <= "v4.21.0"
        else collect_full_kernel_dag(old_snap, target)["axioms"]
    )
    ax_new = collect_full_kernel_dag(new_snap, target)["axioms"]
    return ax_old != ax_new


def run_m3_allowlist_print_axioms(
    old_snap: ArchiveSnapshot, new_snap: ArchiveSnapshot, target: str, policy: AuditPolicy
) -> bool:
    """M3: Standard allowlist-filtered #print axioms without rename resolution or runtime-attr/lexer audit."""
    if target not in new_snap.nodes:
        return True
    ax_new = collect_axioms_pre_8842(new_snap, target)
    for ax in ax_new:
        norm = _normalize_axiom_token(ax, policy.allow_native_eval)
        if norm != "<NATIVE_TRUST_AXIOM>" and norm not in policy.allowed_axioms:
            return True
    return False


def run_m4_isolated_lean4checker(old_snap: ArchiveSnapshot, new_snap: ArchiveSnapshot, target: str) -> bool:
    """M4: Isolated module replay (lean4checker): rejects native eval & missing target, accepts custom axioms/sorryAx."""
    if target not in new_snap.nodes:
        return True
    dag = collect_full_kernel_dag(new_snap, target)
    for ax in dag["axioms"]:
        if ax in {"Lean.trustCompiler", "Lean.ofReduceBool"} or ax.endswith("_native") or "._native." in ax:
            return True
    return False


def run_m5_proofgate_pg35_hybrid(
    old_snap: ArchiveSnapshot,
    new_snap: ArchiveSnapshot,
    target: str,
    policy: AuditPolicy,
) -> dict[str, Any]:
    """M5: ProofGate PG-35 Hybrid Kernel-DAG (value+type) + Canonical Rename + Stateful v3.3 Lexer."""
    reasons: list[str] = []
    resolved = resolve_target_name(target, old_snap, new_snap)
    if resolved is None:
        return {"alarm": True, "resolved_target": None, "reasons": [f"MISSING_OR_UNAUTHENTICATED_NAMESPACE_MOVE:{target}"]}

    old_node = old_snap.nodes[target]
    new_node = new_snap.nodes[resolved]

    old_canon = canonicalize_type_alpha(old_node.type_expr, new_snap.align_map)
    new_canon = canonicalize_type_alpha(new_node.type_expr, new_snap.align_map)
    if old_node.kind != new_node.kind or old_canon != new_canon:
        reasons.append(f"TYPE_SIGNATURE_DRIFT:{target}->{resolved}")

    if old_node.is_public and not new_node.is_public:
        reasons.append(f"PUBLIC_VISIBILITY_DOWNGRADE:{resolved}")

    dag_new = collect_full_kernel_dag(new_snap, resolved)
    for ax in sorted(dag_new["axioms"]):
        norm = _normalize_axiom_token(ax, policy.allow_native_eval)
        if norm == "<NATIVE_TRUST_AXIOM>":
            continue
        if norm not in policy.allowed_axioms:
            reasons.append(f"UNPERMITTED_AXIOM:{ax}")

    if policy.forbid_runtime_attrs_in_transitive_closure and dag_new["runtime_attrs"]:
        for rattr in dag_new["runtime_attrs"]:
            reasons.append(f"TRANSITIVE_RUNTIME_REPLACEMENT:{rattr}")

    for node_name, src_text in new_snap.source_files.items():
        res_v33 = audit_spec_vs_candidate_v33(src_text, src_text)
        for r in res_v33["reasons"]:
            if policy.allow_native_eval and r.startswith("REJECT_NATIVE_EVAL:"):
                continue
            reasons.append(f"SOURCE_HYGIENE({node_name}):{r}")

    return {
        "alarm": len(reasons) > 0,
        "resolved_target": resolved,
        "reasons": reasons,
        "reachable_nodes": dag_new["reachable_count"],
    }


def build_48_transitions() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    allowed_specs = [
        ("ALLOW-01", "v4.28.0", "v4.36.0", POLICY_STANDARD_MATHLIB, (), ("Classical.choice",), "Constructive to classical choice refactor"),
        ("ALLOW-02", "v4.28.0", "v4.36.0", POLICY_STANDARD_MATHLIB, ("propext",), ("propext", "Quot.sound"), "Added Quot.sound quotient lemma"),
        ("ALLOW-03", "v4.28.0", "v4.36.0", POLICY_STANDARD_MATHLIB, ("propext", "Classical.choice"), ("propext",), "Constructive strengthening removed Classical.choice"),
        ("ALLOW-04", "v4.28.0", "v4.36.0", POLICY_STANDARD_MATHLIB, ("Classical.choice", "Quot.sound"), (), "Eliminated all axioms via pure kernel proof"),
        ("ALLOW-05", "v4.21.0", "v4.36.0", POLICY_STANDARD_MATHLIB, ("propext",), ("propext", "Quot.sound"), "Pre-8842 benign Quot.sound surfaced"),
        ("ALLOW-06", "v4.28.0", "v4.36.0", POLICY_ALLOW_TRUSTED_BV, ("Lean.trustCompiler",), ("ThmA06._native.1",), "Lean 4.28 trustCompiler -> 4.36 _native under BV policy"),
        ("ALLOW-07", "v4.35.0", "v4.36.0", POLICY_STANDARD_MATHLIB, (), ("propext",), "Simp rewrite using propositional extensionality"),
        ("ALLOW-08", "v4.35.0", "v4.36.0", POLICY_STANDARD_MATHLIB, ("Quot.sound",), ("propext", "Classical.choice", "Quot.sound"), "Full standard triad"),
        ("ALLOW-09", "v4.28.0", "v4.36.0", POLICY_STANDARD_MATHLIB, ("Classical.choice",), ("propext",), "Replaced choice with propext"),
        ("ALLOW-10", "v4.35.0", "v4.37.0-rc1", POLICY_ALLOW_TRUSTED_BV, ("ThmA10._native.1",), ("ThmA10._native.2",), "Re-numbered _native computation axiom under BV policy"),
        ("ALLOW-11", "v4.28.0", "v4.36.0", POLICY_STANDARD_MATHLIB, ("propext", "Quot.sound"), ("Quot.sound",), "Dropped propext"),
        ("ALLOW-12", "v4.36.0", "v4.37.0-rc1", POLICY_STANDARD_MATHLIB, (), ("Quot.sound",), "Quotient lift refactor"),
    ]
    for cid, v_old, v_new, pol, ax_old, ax_new, desc in allowed_specs:
        tname = f"Thm_{cid.replace('-', '_')}"
        old_nodes = {tname: ConstNode(tname, "theorem", "(n : Nat) : n = n", value_deps=ax_old)}
        for ax in ax_old:
            old_nodes[ax] = ConstNode(ax, "axiom", "Prop")
        new_nodes = {tname: ConstNode(tname, "theorem", "(n : Nat) : n = n", value_deps=ax_new)}
        for ax in ax_new:
            new_nodes[ax] = ConstNode(ax, "axiom", "Prop")
        src = f"theorem {tname} (n : Nat) : n = n := rfl\n"
        cases.append({
            "case_id": cid,
            "category": "ALLOWED_AXIOM_SHIFT",
            "expected_alarm": False,
            "policy": pol,
            "target": tname,
            "desc": desc,
            "vec": [1, 0, 0, 0, len(ax_new), int(pol.allow_native_eval), 0, 1],
            "old": ArchiveSnapshot(v_old, old_nodes, {}, {tname: src}),
            "new": ArchiveSnapshot(v_new, new_nodes, {}, {tname: src}),
        })

    trans_specs = [
        ("TRANS-01", "3-hop sorryAx in helper lemma L2", "sorryAx", (), False, ""),
        ("TRANS-02", "3-hop custom unsound axiom in L2", "Finance.customRoundingAxiom", (), False, ""),
        ("TRANS-03", "Axiom-in-axiom-type (#8840) hidden behind benign-looking wrapper axiom", "WrapperAx", (), True, ""),
        ("TRANS-04", "Transitive @[implemented_by] runtime swap on helper def", None, ("implemented_by",), False, ""),
        ("TRANS-05", "Transitive @[extern] C FFI hook in upstream arithmetic def", None, ("extern",), False, ""),
        ("TRANS-06", "Transitive @[csimp] compiler rewrite theorem on fee function", None, ("csimp",), False, ""),
        ("TRANS-07", "Unpermitted bv_decide (_native axiom) in L2 under STRICT_KERNEL_ONLY", "HelperL2._native.1", (), False, ""),
        ("TRANS-08", "Unpermitted Lean.ofReduceBool in L3 under STRICT_KERNEL_ONLY", "Lean.ofReduceBool", (), False, ""),
        ("TRANS-09", "Cross-package 'import all' exposing private axiom in helper module", "Vault.privAxiom", (), False, "module\nimport all Vault.Secret\n"),
        ("TRANS-10", "4-hop sorryAx injected via type_deps of helper definition", "sorryAx_via_type", (), False, ""),
        ("TRANS-11", "Transitive custom classical-looking spoof axiom 'Classical.fastChoice'", "Classical.fastChoice", (), False, ""),
        ("TRANS-12", "Dual transitive violation: @[csimp] + custom axiom in L2", "Oracle.unverifiedAx", ("csimp",), False, ""),
    ]
    for cid, desc, bad_ax, bad_attrs, is_8840_type_chain, extra_helper_src in trans_specs:
        tname = f"Thm_{cid.replace('-', '_')}"
        src_thm = f"theorem {tname} (x : Nat) : x <= x + 1 := HelperL1 x\n"
        old_nodes = {
            tname: ConstNode(tname, "theorem", "(x : Nat) : x <= x + 1", value_deps=("HelperL1",)),
            "HelperL1": ConstNode("HelperL1", "theorem", "(x : Nat) : x <= x + 1", value_deps=("HelperL2",)),
            "HelperL2": ConstNode("HelperL2", "def", "Nat -> Nat", value_deps=("propext",)),
            "propext": ConstNode("propext", "axiom", "Prop"),
        }
        new_nodes = {
            tname: ConstNode(tname, "theorem", "(x : Nat) : x <= x + 1", value_deps=("HelperL1",)),
            "HelperL1": ConstNode("HelperL1", "theorem", "(x : Nat) : x <= x + 1", value_deps=("HelperL2",)),
        }
        if is_8840_type_chain:
            new_nodes["HelperL2"] = ConstNode("HelperL2", "def", "Nat -> Nat", value_deps=("WrapperAx",))
            new_nodes["WrapperAx"] = ConstNode("WrapperAx", "axiom", "HiddenType", type_deps=("HiddenUnsoundAx",))
            new_nodes["HiddenUnsoundAx"] = ConstNode("HiddenUnsoundAx", "axiom", "False")
        elif bad_ax == "sorryAx_via_type":
            new_nodes["HelperL2"] = ConstNode("HelperL2", "def", "Nat -> Nat", type_deps=("sorryAx",))
            new_nodes["sorryAx"] = ConstNode("sorryAx", "axiom", "False")
        else:
            deps = (bad_ax,) if bad_ax else ("propext",)
            new_nodes["HelperL2"] = ConstNode("HelperL2", "def", "Nat -> Nat", value_deps=deps, attrs=bad_attrs)
            if bad_ax:
                new_nodes[bad_ax] = ConstNode(bad_ax, "axiom", "False")
            else:
                new_nodes["propext"] = ConstNode("propext", "axiom", "Prop")

        helper_files = {tname: src_thm}
        if extra_helper_src:
            helper_files["HelperL2"] = extra_helper_src + "public def HelperL2 (x : Nat) : Nat := x\n"
        cases.append({
            "case_id": cid,
            "category": "TRANSITIVE_DEP_VIOLATION",
            "expected_alarm": True,
            "policy": POLICY_STANDARD_MATHLIB,
            "target": tname,
            "desc": desc,
            "vec": [0, 1, int(bool(bad_attrs)), int(is_8840_type_chain), 1, 0, int(bool(extra_helper_src)), 0],
            "old": ArchiveSnapshot("v4.21.0", old_nodes, {}, {tname: src_thm}),
            "new": ArchiveSnapshot("v4.36.0", new_nodes, {}, helper_files),
        })

    rename_specs = [
        ("REN-01", "OldDivLe", "NewDivLe", "(a b : Nat) : a <= a + b", "(a b : Nat) : a <= a + b", "via_deprecated", POLICY_STANDARD_MATHLIB, "theorem NewDivLe (a b : Nat) : a <= a + b := Nat.le_add_right a b\n"),
        ("REN-02", "Group.mul_id", "Mathlib.Algebra.Group.mul_id", "(x : Int) : x + 0 = x", "(x : Int) : x + 0 = x", "via_align", POLICY_STANDARD_MATHLIB, "theorem Mathlib.Algebra.Group.mul_id (x : Int) : x + 0 = x := Int.add_zero x\n"),
        ("REN-03", "AlphaThm", "AlphaThm", "(a b : Nat) : a + b = b + a", "(x y : Nat) : x + y = y + x", "same_name", POLICY_STANDARD_MATHLIB, "theorem AlphaThm (x y : Nat) : x + y = y + x := Nat.add_comm x y\n"),
        ("REN-04", "sorry_free_lemma", "sorry_free_lemma_v2", "(n : Nat) : 0 <= n", "(n : Nat) : 0 <= n", "via_align", POLICY_STANDARD_MATHLIB, "theorem sorry_free_lemma_v2 (n : Nat) : 0 <= n := Nat.zero_le n\n"),
        ("REN-05", "admit_valid_bound", "admit_valid_bound", "(k : Nat) : k = k", "(m : Nat) : m = m", "same_name", POLICY_STANDARD_MATHLIB, "theorem admit_valid_bound (m : Nat) : m = m := rfl\n"),
        ("REN-06", "BvCheckOld", "BvCheckNew", "(x : Nat) : x = x", "(x : Nat) : x = x", "via_align_bv", POLICY_ALLOW_TRUSTED_BV, "theorem BvCheckNew (x : Nat) : x = x := by bv_decide\n"),
        ("REN-07", "HelperCallThm", "HelperCallThm", "(n : Nat) : n = n", "(n : Nat) : n = n", "helper_renamed", POLICY_STANDARD_MATHLIB, 'def note : String := "no sorry here"\ntheorem HelperCallThm (n : Nat) : n = n := rfl\n'),
        ("REN-08", "Order.le_refl_ext", "Std.Order.le_refl_ext", "(u : Nat) : u <= u", "(v : Nat) : v <= v", "via_deprecated", POLICY_STANDARD_MATHLIB, "theorem Std.Order.le_refl_ext (v : Nat) : v <= v := Nat.le_refl v\n"),
        ("REN-09", "FinLedgerEq", "Alpess.Ledger.FinLedgerEq", "(c : Int) : c - c = 0", "(d : Int) : d - d = 0", "via_align", POLICY_STANDARD_MATHLIB, "theorem Alpess.Ledger.FinLedgerEq (d : Int) : d - d = 0 := Int.sub_self d\n"),
        ("REN-10", "UniqueCanonMatch", "UniqueCanonMatch'", "(n : Nat) : n + 1 = 1 + n", "(k : Nat) : k + 1 = 1 + k", "type_heuristic", POLICY_STANDARD_MATHLIB, "theorem UniqueCanonMatch' (k : Nat) : k + 1 = 1 + k := Nat.add_comm k 1\n"),
        ("REN-11", "NestedCommentThm", "NestedCommentThm", "(n : Nat) : n = n", "(n : Nat) : n = n", "same_name", POLICY_STANDARD_MATHLIB, "/- outer /- inner axiom sorry -/ end -/\ntheorem NestedCommentThm (n : Nat) : n = n := rfl\n"),
        ("REN-12", "TypeAlignedThm", "TypeAlignedThm", "(x : OldAlias) : x = x", "(y : NewAlias) : y = y", "type_align", POLICY_STANDARD_MATHLIB, "theorem TypeAlignedThm (y : NewAlias) : y = y := rfl\n"),
    ]
    for cid, old_n, new_n, t_old, t_new, mode, pol, cand_src in rename_specs:
        ax_old = ("BvCheckOld._native.1",) if mode == "via_align_bv" else ("propext",)
        ax_new = ("BvCheckNew._native.1",) if mode == "via_align_bv" else ("propext",)
        old_nodes = {
            old_n: ConstNode(old_n, "theorem", t_old, value_deps=ax_old),
            ax_old[0]: ConstNode(ax_old[0], "axiom", "Prop"),
        }
        new_nodes = {
            new_n: ConstNode(new_n, "theorem", t_new, value_deps=ax_new),
            ax_new[0]: ConstNode(ax_new[0], "axiom", "Prop"),
        }
        align_map: dict[str, str] = {}
        if mode == "via_deprecated":
            new_nodes[old_n] = ConstNode(old_n, "theorem", t_old, value_deps=(new_n,), deprecated_target=new_n)
        elif mode in {"via_align", "via_align_bv"}:
            align_map[old_n] = new_n
        elif mode == "type_align":
            align_map["OldAlias"] = "NewAlias"
        base_src = f"theorem {old_n} {t_old} := rfl\n"
        cases.append({
            "case_id": cid,
            "category": "RENAME_ONLY",
            "expected_alarm": False,
            "policy": pol,
            "target": old_n,
            "desc": f"Rename mode={mode}: {old_n} -> {new_n}",
            "vec": [0, 0, 1, 0, int(old_n != new_n), int(t_old != t_new), 1, 0],
            "old": ArchiveSnapshot("v4.28.0", old_nodes, {}, {old_n: base_src}),
            "new": ArchiveSnapshot("v4.36.0", new_nodes, align_map, {new_n: cand_src}),
        })

    stealth_specs = [
        ("STL-01", "String-desync '/-' ... axiom ... '-/' smuggling", 'def d1 : String := "/-"\naxiom smuggled : False\ndef d2 : String := "-/"\ntheorem T (n : Nat) : n = n := False.elim smuggled\n', True, ()),
        ("STL-02", "Tab-separated 'axiom\\t' escape", "axiom\ttabAx : False\ntheorem T (n : Nat) : n = n := False.elim tabAx\n", True, ()),
        ("STL-03", "Newline-separated '@[extern\\n...]' FFI hook", '@[extern\n"c_zero"]\nopaque hook : Nat\ntheorem T (n : Nat) : n = n := rfl\n', True, ("extern",)),
        ("STL-04", "Lowercase 'abbrev mynat := Nat' + [LE mynat] local instance hijack", "abbrev mynat := Nat\ntheorem T (n : mynat) [LE mynat] : n <= n := le_refl n\n", True, ()),
        ("STL-05", "Lean 4.37 module public visibility downgrade", "module\ntheorem T (n : Nat) : n = n := rfl\n", False, ()),
        ("STL-06", "In-file 'set_option warningAsError false' CLI flag override", "set_option warningAsError false\ntheorem T (n : Nat) : n = n := rfl\n", True, ()),
        ("STL-07", "In-file 'set_option debug.skipKernelTC true' kernel bypass", "set_option debug.skipKernelTC true\ntheorem T (n : Nat) : n = n := rfl\n", True, ()),
        ("STL-08", "Cross-module 'import all' private scope leak", "module\nimport all Mathlib.Internal.Private\npublic theorem T (n : Nat) : n = n := rfl\n", True, ()),
        ("STL-09", "Guillemet «sorry» token escape", "theorem T (n : Nat) : n = n := \u00absorry\u00bb\n", True, ("sorryAx",)),
        ("STL-10", "Decide +native under STRICT_KERNEL_ONLY", "theorem T (n : Nat) : n = n := by decide +native\n", True, ("T._native.1",)),
        ("STL-11", "Namespace Sandbox shadowing of root theorem", "namespace Sandbox\ntheorem T (n : Nat) : n = n := rfl\nend Sandbox\n", True, ()),
        ("STL-12", "Statement weakening to True := trivial", "theorem T (n : Nat) : True := trivial\n", True, ()),
    ]
    for cid, desc, cand_src, is_pub, extra_items in stealth_specs:
        tname = "T"
        base_t_expr = "(n : mynat) : n <= n" if cid == "STL-04" else "(n : Nat) : n = n"
        cand_t_expr = "(n : Nat) : True" if cid == "STL-12" else base_t_expr
        old_nodes = {tname: ConstNode(tname, "theorem", base_t_expr, value_deps=(), is_public=True)}
        if cid == "STL-11":
            new_nodes = {"Sandbox.T": ConstNode("Sandbox.T", "theorem", cand_t_expr, is_public=True)}
        else:
            ax_deps = tuple(x for x in extra_items if x not in COMPILER_RUNTIME_ATTRS)
            at_deps = tuple(x for x in extra_items if x in COMPILER_RUNTIME_ATTRS)
            new_nodes = {tname: ConstNode(tname, "theorem", cand_t_expr, value_deps=ax_deps, attrs=at_deps, is_public=is_pub)}
            for ax in ax_deps:
                new_nodes[ax] = ConstNode(ax, "axiom", "False")
        base_src = f"module\npublic theorem T {base_t_expr} := sorry\n" if cid == "STL-05" else f"theorem T {base_t_expr} := sorry\n"
        cases.append({
            "case_id": cid,
            "category": "DIRECT_OR_STEALTH_VIOLATION",
            "expected_alarm": True,
            "policy": POLICY_STANDARD_MATHLIB,
            "target": tname,
            "desc": desc,
            "vec": [0, 0, 0, 1, int(not is_pub), len(extra_items), 1, 1],
            "old": ArchiveSnapshot("v4.35.0", old_nodes, {}, {tname: base_src}),
            "new": ArchiveSnapshot("v4.37.0-rc1", new_nodes, {}, {tname: cand_src}),
        })

    return cases


def evaluate_pg35_benchmark() -> dict[str, Any]:
    t0 = time.perf_counter()
    cases = build_48_transitions()
    methods = (
        "M1_V32_SOURCE_REGEX",
        "M2_NAIVE_PRINT_AXIOMS",
        "M3_ALLOWLIST_AXIOMS",
        "M4_ISOLATED_LEAN4CHECKER",
        "M5_PROOFGATE_PG35_HYBRID",
    )
    categories = (
        "ALLOWED_AXIOM_SHIFT",
        "TRANSITIVE_DEP_VIOLATION",
        "RENAME_ONLY",
        "DIRECT_OR_STEALTH_VIOLATION",
    )

    stats: dict[str, dict[str, Any]] = {
        m: {
            "overall": {"tp": 0, "fn": 0, "tn": 0, "fp": 0},
            "by_category": {cat: {"n": 0, "fp": 0, "fn": 0, "correct": 0} for cat in categories},
        }
        for m in methods
    }

    sarif_sample_count = 0
    for c in cases:
        old_s, new_s, tgt, pol = c["old"], c["new"], c["target"], c["policy"]
        exp_alarm: bool = c["expected_alarm"]
        cat = c["category"]

        m5_detail = run_m5_proofgate_pg35_hybrid(old_s, new_s, tgt, pol)
        verdicts = {
            "M1_V32_SOURCE_REGEX": run_m1_v32_source_diff(old_s, new_s, tgt),
            "M2_NAIVE_PRINT_AXIOMS": run_m2_naive_print_axioms_eq(old_s, new_s, tgt),
            "M3_ALLOWLIST_AXIOMS": run_m3_allowlist_print_axioms(old_s, new_s, tgt, pol),
            "M4_ISOLATED_LEAN4CHECKER": run_m4_isolated_lean4checker(old_s, new_s, tgt),
            "M5_PROOFGATE_PG35_HYBRID": m5_detail["alarm"],
        }

        if tgt in new_s.source_files:
            v33_res = audit_spec_vs_candidate_v33(old_s.source_files.get(tgt, ""), new_s.source_files[tgt])
            sarif_doc = to_sarif_v210(v33_res, new_s.source_files[tgt], artifact_uri=f"pg35/{c['case_id']}.lean")
            sarif_sample_count += len(sarif_doc["runs"][0]["results"])

        for m_name, got_alarm in verdicts.items():
            st_all = stats[m_name]["overall"]
            st_cat = stats[m_name]["by_category"][cat]
            st_cat["n"] += 1
            if exp_alarm:
                if got_alarm:
                    st_all["tp"] += 1
                    st_cat["correct"] += 1
                else:
                    st_all["fn"] += 1
                    st_cat["fn"] += 1
            else:
                if not got_alarm:
                    st_all["tn"] += 1
                    st_cat["correct"] += 1
                else:
                    st_all["fp"] += 1
                    st_cat["fp"] += 1

    for m_name in methods:
        ov = stats[m_name]["overall"]
        tp, fn, tn, fp = ov["tp"], ov["fn"], ov["tn"], ov["fp"]
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        ov["fpr_pct"] = round(100.0 * fp / 24.0, 2)
        ov["fnr_pct"] = round(100.0 * fn / 24.0, 2)
        ov["f1"] = round(f1, 4)

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    vendi = compute_vendi_scores([c["vec"] for c in cases])
    result = {
        "task_id": "DR-KONU-PG-35-202611251235",
        "total_transitions": len(cases),
        "benign_transitions": 24,
        "violation_transitions": 24,
        "sarif_emitted_findings": sarif_sample_count,
        "vendi_shannon": vendi["vendi_shannon"],
        "vendi_renyi2": vendi["vendi_renyi2"],
        "elapsed_ms": elapsed_ms,
        "methods": stats,
    }
    result["jcs_sha256"] = jcs_sha256(result)
    return result


def main() -> int:
    rep = evaluate_pg35_benchmark()
    m5 = rep["methods"]["M5_PROOFGATE_PG35_HYBRID"]["overall"]
    assert m5["fp"] == 0 and m5["fn"] == 0, f"Expected 0 FP and 0 FN for M5, got {m5}"
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
