"""Official Lean 4 C++ independent kernel replay bridge (lean -R + leanchecker).

Combines static AST/spec-faithfulness verification with Lean's external C++ .olean
kernel checker (`leanchecker`, equivalent to SafeVerify / lean4checker replay defense)
while preserving ProofGate's zero-dependency runtime core and zero-chr(36) standard.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class LeanToolchain:
    lean_bin: str
    leanchecker_bin: str
    stdlib_dir: str
    toolchain_name: str


@dataclass(frozen=True)
class KernelReplayResult:
    verdict: str  # 'ACCEPT' | 'REJECT' | 'SKIPPED_NO_TOOLCHAIN'
    primary_code: str
    violations: List[str]
    lean_rc: Optional[int]
    leanchecker_rc: Optional[int]
    fresh: bool
    toolchain: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    static_gate: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _version_sort_key(path: pathlib.Path) -> Tuple[int, Tuple[int, ...]]:
    is_stable = 0 if re.search(r"-(rc|alpha|beta)\d*", path.name, re.I) else 1
    nums = [int(x) for x in re.findall(r"\d+", path.name)]
    return (is_stable, tuple(nums) if nums else (0,))


def discover_lean_toolchain() -> Optional[LeanToolchain]:
    """Auto-discover matching Lean 4 `lean`, `leanchecker`, and stdlib directory."""
    env_lean = os.environ.get("LEAN_BIN")
    env_chk = os.environ.get("LEANCHECKER_BIN")
    if env_lean and env_chk and pathlib.Path(env_lean).is_file() and pathlib.Path(env_chk).is_file():
        tc_root = pathlib.Path(env_lean).resolve().parent.parent
        stdlib = os.environ.get("LEAN_STDLIB_DIR") or str(tc_root / "lib" / "lean")
        if pathlib.Path(stdlib).is_dir():
            return LeanToolchain(str(env_lean), str(env_chk), stdlib, tc_root.name)

    which_lean = shutil.which("lean")
    which_chk = shutil.which("leanchecker")
    if which_lean and which_chk:
        lp = pathlib.Path(which_lean).resolve()
        stdlib_cand = lp.parent.parent / "lib" / "lean"
        if stdlib_cand.is_dir():
            return LeanToolchain(str(lp), str(pathlib.Path(which_chk).resolve()), str(stdlib_cand), lp.parent.parent.name)

    elan_root = pathlib.Path(os.environ.get("ELAN_HOME") or (pathlib.Path.home() / ".elan"))
    toolchains_dir = elan_root / "toolchains"
    if toolchains_dir.is_dir():
        candidates = sorted(toolchains_dir.iterdir(), key=_version_sort_key, reverse=True)
        for tc in candidates:
            lb = tc / "bin" / "lean"
            cb = tc / "bin" / "leanchecker"
            sd = tc / "lib" / "lean"
            if lb.is_file() and cb.is_file() and sd.is_dir():
                return LeanToolchain(str(lb), str(cb), str(sd), tc.name)
    return None


def replay_lean_kernel(
    lean_path: pathlib.Path,
    *,
    fresh: bool = False,
    require_toolchain: bool = False,
    timeout_sec: Optional[int] = None,
    trust_level: int = 0,
    warning_as_error: bool = True,
) -> KernelReplayResult:
    """Compile a standalone Lean 4 file into .olean and replay it through C++ `leanchecker`."""
    src_path = pathlib.Path(lean_path)
    if not src_path.is_file():
        msg = f"Lean source file not found: {src_path}"
        return KernelReplayResult(
            verdict="REJECT",
            primary_code="REJECT_LEAN_COMPILE",
            violations=["REJECT_LEAN_COMPILE"],
            lean_rc=None,
            leanchecker_rc=None,
            fresh=fresh,
            findings=[{"code": "REJECT_LEAN_COMPILE", "line": 1, "col": 1, "message": msg}],
            stderr_excerpt=msg,
        )

    tc = discover_lean_toolchain()
    if tc is None:
        if require_toolchain:
            msg = "Lean 4 toolchain / leanchecker binary not found while require_toolchain=True."
            return KernelReplayResult(
                verdict="REJECT",
                primary_code="REJECT_LEANCHECKER_REPLAY",
                violations=["REJECT_LEANCHECKER_REPLAY"],
                lean_rc=None,
                leanchecker_rc=None,
                fresh=fresh,
                findings=[{"code": "REJECT_LEANCHECKER_REPLAY", "line": 1, "col": 1, "message": msg}],
                stderr_excerpt=msg,
            )
        return KernelReplayResult(
            verdict="SKIPPED_NO_TOOLCHAIN",
            primary_code="SKIPPED_NO_TOOLCHAIN",
            violations=[],
            lean_rc=None,
            leanchecker_rc=None,
            fresh=fresh,
            toolchain=None,
            findings=[],
            stderr_excerpt="Lean 4 / leanchecker not installed; kernel replay skipped.",
        )

    eff_timeout = timeout_sec if timeout_sec is not None else (240 if fresh else 90)
    src_text = src_path.read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmpdir:
        mod_name = "PgTarget"
        tmp_path = pathlib.Path(tmpdir)
        target_lean = tmp_path / f"{mod_name}.lean"
        target_olean = tmp_path / f"{mod_name}.olean"
        target_lean.write_text(src_text, encoding="utf-8")

        env = dict(os.environ)
        existing_lp = env.get("LEAN_PATH", "")
        env["LEAN_PATH"] = f"{tmpdir}{os.pathsep}{tc.stdlib_dir}" + (f"{os.pathsep}{existing_lp}" if existing_lp else "")
        tc_bin_dir = str(pathlib.Path(tc.lean_bin).parent)
        existing_path = env.get("PATH", "")
        env["PATH"] = f"{tc_bin_dir}{os.pathsep}{existing_path}" if existing_path else tc_bin_dir

        compile_cmd = [
            tc.lean_bin,
            "-M",
            "1024",
            "-j",
            "1",
            "-R",
            tmpdir,
            "-o",
            str(target_olean),
            f"--trust={int(trust_level)}",
        ]
        if warning_as_error:
            compile_cmd.append("-DwarningAsError=true")
        compile_cmd.append(str(target_lean))

        try:
            c_proc = subprocess.run(
                compile_cmd,
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=eff_timeout,
            )
        except subprocess.TimeoutExpired:
            msg = f"Lean --trust={trust_level} compilation timed out after {eff_timeout}s."
            return KernelReplayResult(
                verdict="REJECT",
                primary_code="REJECT_LEAN_COMPILE",
                violations=["REJECT_LEAN_COMPILE"],
                lean_rc=None,
                leanchecker_rc=None,
                fresh=fresh,
                toolchain=tc.toolchain_name,
                findings=[{"code": "REJECT_LEAN_COMPILE", "line": 1, "col": 1, "message": msg}],
                stderr_excerpt=msg,
            )

        if c_proc.returncode != 0 or not target_olean.is_file():
            err_msg = (c_proc.stderr or c_proc.stdout or "Lean compiler returned non-zero exit status.").strip()
            line_num = 1
            col_num = 1
            m_pos = re.search(r":(\d+):(\d+):", err_msg)
            if m_pos:
                line_num = max(1, int(m_pos.group(1)))
                col_num = max(1, int(m_pos.group(2)))
            return KernelReplayResult(
                verdict="REJECT",
                primary_code="REJECT_LEAN_COMPILE",
                violations=["REJECT_LEAN_COMPILE"],
                lean_rc=c_proc.returncode,
                leanchecker_rc=None,
                fresh=fresh,
                toolchain=tc.toolchain_name,
                findings=[{"code": "REJECT_LEAN_COMPILE", "line": line_num, "col": col_num, "message": err_msg[:500]}],
                stdout_excerpt=(c_proc.stdout or "")[:800],
                stderr_excerpt=err_msg[:800],
            )

        chk_cmd = [tc.leanchecker_bin]
        if fresh:
            chk_cmd.append("--fresh")
        chk_cmd.append(mod_name)

        try:
            k_proc = subprocess.run(
                chk_cmd,
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=eff_timeout,
            )
        except subprocess.TimeoutExpired:
            msg = f"leanchecker replay timed out after {eff_timeout}s (fresh={fresh})."
            return KernelReplayResult(
                verdict="REJECT",
                primary_code="REJECT_LEANCHECKER_REPLAY",
                violations=["REJECT_LEANCHECKER_REPLAY"],
                lean_rc=c_proc.returncode,
                leanchecker_rc=None,
                fresh=fresh,
                toolchain=tc.toolchain_name,
                findings=[{"code": "REJECT_LEANCHECKER_REPLAY", "line": 1, "col": 1, "message": msg}],
                stderr_excerpt=msg,
            )

        if k_proc.returncode != 0:
            err_msg = (k_proc.stderr or k_proc.stdout or "leanchecker returned non-zero exit status.").strip()
            return KernelReplayResult(
                verdict="REJECT",
                primary_code="REJECT_LEANCHECKER_REPLAY",
                violations=["REJECT_LEANCHECKER_REPLAY"],
                lean_rc=c_proc.returncode,
                leanchecker_rc=k_proc.returncode,
                fresh=fresh,
                toolchain=tc.toolchain_name,
                findings=[{"code": "REJECT_LEANCHECKER_REPLAY", "line": 1, "col": 1, "message": err_msg[:500]}],
                stdout_excerpt=(k_proc.stdout or "")[:800],
                stderr_excerpt=err_msg[:800],
            )

    return KernelReplayResult(
        verdict="ACCEPT",
        primary_code="KERNEL_REPLAY_ACCEPT",
        violations=[],
        lean_rc=c_proc.returncode,
        leanchecker_rc=0,
        fresh=fresh,
        toolchain=tc.toolchain_name,
        findings=[],
        stdout_excerpt=(c_proc.stdout or "")[:800],
        stderr_excerpt="",
    )
