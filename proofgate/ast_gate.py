"""Static Python AST safety and constant-oracle gate for bounded verification code."""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from typing import Dict, List

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
})


@dataclass(frozen=True)
class ASTGateResult:
    verdict: str
    primary_code: str
    violations: List[str]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def check_python_source(python_source: str, *, max_range_bound: int = 10_000) -> ASTGateResult:
    """Statically inspect Python code without executing it."""
    violations: List[str] = []
    try:
        tree = ast.parse(python_source or "")
    except SyntaxError:
        return ASTGateResult(
            verdict="REJECT",
            primary_code="REJECT_AST_SYNTAX_ERROR",
            violations=["REJECT_AST_SYNTAX_ERROR"],
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    violations.append("REJECT_AST_FORBIDDEN_IMPORT")
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in FORBIDDEN_MODULES:
                violations.append("REJECT_AST_FORBIDDEN_IMPORT")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                violations.append("REJECT_AST_DUNDER_ESCAPE")
        elif isinstance(node, ast.Call):
            func_name = node.func.id if isinstance(node.func, ast.Name) else ""
            if func_name in FORBIDDEN_BUILTINS:
                violations.append("REJECT_AST_FORBIDDEN_BUILTIN")
            if func_name == "range":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value > max_range_bound:
                        violations.append("REJECT_AST_SAFE_RANGE_LIMIT_EXCEEDED")
        elif isinstance(node, ast.While):
            is_const_true = isinstance(node.test, ast.Constant) and bool(node.test.value)
            has_break = any(isinstance(sub, ast.Break) for sub in ast.walk(node))
            if is_const_true and not has_break:
                violations.append("REJECT_AST_UNBOUNDED_LOOP_DOS")
        elif isinstance(node, ast.FunctionDef):
            if (
                len(node.args.args) >= 2
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Return)
                and isinstance(node.body[0].value, ast.Constant)
            ):
                violations.append("REJECT_AST_TRIVIAL_CONSTANT_ORACLE_SPOOF")

    unique_v = sorted(set(violations))
    if unique_v:
        return ASTGateResult(verdict="REJECT", primary_code=unique_v[0], violations=unique_v)
    return ASTGateResult(verdict="ACCEPT", primary_code="AST_SAFE_ACCEPT", violations=[])
