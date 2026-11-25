"""Static Python AST safety and constant-oracle gate for bounded verification code."""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

FORBIDDEN_MODULES: frozenset[str] = frozenset({
    "os",
    "sys",
    "subprocess",
    "socket",
    "shutil",
    "pathlib",
    "ctypes",
    "importlib",
    "builtins",
    "pickle",
    "marshal",
    "urllib",
    "http",
    "ftplib",
    "telnetlib",
    "tempfile",
    "glob",
    "pty",
    "resource",
})

FORBIDDEN_BUILTINS: frozenset[str] = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "breakpoint",
})


@dataclass(frozen=True)
class ASTGateResult:
    verdict: str
    primary_code: str
    violations: List[str]
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _node_span(node: ast.AST, lines: List[str]) -> Dict[str, Any]:
    line = int(getattr(node, "lineno", 1) or 1)
    col_utf8 = int(getattr(node, "col_offset", 0) or 0)
    end_line = int(getattr(node, "end_lineno", line) or line)
    end_col_utf8 = int(getattr(node, "end_col_offset", col_utf8) or col_utf8)
    snippet = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
    return {
        "line": line,
        "col_offset_utf8": col_utf8,
        "end_line": end_line,
        "end_col_offset_utf8": end_col_utf8,
        "snippet": snippet,
    }


def _call_target_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def check_python_source(python_source: str, *, max_range_bound: int = 10_000) -> ASTGateResult:
    """Statically inspect Python code without executing it."""
    src = python_source or ""
    lines = src.splitlines()
    violations: List[str] = []
    findings: List[Dict[str, Any]] = []

    def _add(code: str, message: str, node: Optional[ast.AST] = None, line_override: Optional[int] = None) -> None:
        violations.append(code)
        if node is not None:
            span = _node_span(node, lines)
        else:
            ln = int(line_override or 1)
            span = {
                "line": ln,
                "col_offset_utf8": 0,
                "end_line": ln,
                "end_col_offset_utf8": 0,
                "snippet": lines[ln - 1].strip() if 1 <= ln <= len(lines) else "",
            }
        findings.append({"code": code, "message": message, **span})

    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        ln = int(exc.lineno or 1)
        col = max(0, int((exc.offset or 1) - 1))
        snippet = lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""
        return ASTGateResult(
            verdict="REJECT",
            primary_code="REJECT_AST_SYNTAX_ERROR",
            violations=["REJECT_AST_SYNTAX_ERROR"],
            findings=[
                {
                    "code": "REJECT_AST_SYNTAX_ERROR",
                    "message": f"SyntaxError: {exc.msg}",
                    "line": ln,
                    "col_offset_utf8": col,
                    "end_line": ln,
                    "end_col_offset_utf8": col + 1,
                    "snippet": snippet,
                }
            ],
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".")[0]
                if root_mod in FORBIDDEN_MODULES:
                    _add("REJECT_AST_FORBIDDEN_IMPORT", f"Forbidden module import: {alias.name}", node)
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in FORBIDDEN_MODULES:
                _add("REJECT_AST_FORBIDDEN_IMPORT", f"Forbidden module import: {node.module}", node)
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                _add("REJECT_AST_DUNDER_ESCAPE", f"Dunder attribute access rejected: {node.attr}", node)
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_BUILTINS and isinstance(node.ctx, ast.Load):
                _add("REJECT_AST_FORBIDDEN_BUILTIN", f"Reference to restricted builtin: {node.id}", node)
        elif isinstance(node, ast.Call):
            func_name = _call_target_name(node)
            if func_name in FORBIDDEN_BUILTINS:
                _add("REJECT_AST_FORBIDDEN_BUILTIN", f"Call to restricted builtin: {func_name}", node)
            if func_name == "range":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value > max_range_bound:
                        _add(
                            "REJECT_AST_SAFE_RANGE_LIMIT_EXCEEDED",
                            f"range({arg.value}) exceeds max_range_bound={max_range_bound}",
                            node,
                        )
        elif isinstance(node, ast.While):
            is_const_true = isinstance(node.test, ast.Constant) and bool(node.test.value)
            has_break = any(isinstance(sub, (ast.Break, ast.Return, ast.Raise)) for sub in ast.walk(node))
            if is_const_true and not has_break:
                _add("REJECT_AST_UNBOUNDED_LOOP_DOS", "Unbounded constant-true while loop without break/return", node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            total_args = len(node.args.posonlyargs) + len(node.args.args) + len(node.args.kwonlyargs)
            if (
                total_args >= 2
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Return)
                and isinstance(node.body[0].value, ast.Constant)
            ):
                _add(
                    "REJECT_AST_TRIVIAL_CONSTANT_ORACLE_SPOOF",
                    f"Multi-argument function '{node.name}' returns only a constant literal",
                    node,
                )

    unique_v = sorted(set(violations))
    if unique_v:
        return ASTGateResult(
            verdict="REJECT",
            primary_code=unique_v[0],
            violations=unique_v,
            findings=findings,
        )
    return ASTGateResult(
        verdict="ACCEPT",
        primary_code="AST_SAFE_ACCEPT",
        violations=[],
        findings=[],
    )
