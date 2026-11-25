"""Docker GitHub Action entrypoint for ProofGate (zero chr(36) environment interface)."""
from __future__ import annotations

import json
import os
import pathlib
import sys
from typing import List, Optional, Sequence

from .cli import main as cli_main
from .spec_diff_reward_hack_gate import audit_spec_vs_candidate_submission


def run_from_env(argv: Optional[Sequence[str]] = None) -> int:
    if argv is not None:
        return cli_main(list(argv))

    mode = (os.environ.get("INPUT_MODE") or "check-lean").strip()
    target = (os.environ.get("INPUT_TARGET") or "").strip()
    base_path = (os.environ.get("INPUT_BASE_PATH") or "").strip()
    fmt = (os.environ.get("INPUT_FORMAT") or "json").strip()
    strict = (os.environ.get("INPUT_STRICT") or "true").strip().lower() in ("1", "true", "yes")

    if not target:
        print(json.dumps({"verdict": "REJECT", "error": "INPUT_TARGET is required"}))
        return 1

    if mode == "spec-diff":
        if not base_path:
            print(json.dumps({"verdict": "REJECT", "error": "INPUT_BASE_PATH is required for spec-diff"}))
            return 1
        base_src = pathlib.Path(base_path).read_text(encoding="utf-8")
        cand_src = pathlib.Path(target).read_text(encoding="utf-8")
        res = audit_spec_vs_candidate_submission(base_src, cand_src)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res.get("verdict") == "FAITHFUL_PASS" else 1

    args: List[str] = [mode]
    if mode in ("diff-lean",):
        if not base_path:
            print(json.dumps({"verdict": "REJECT", "error": "INPUT_BASE_PATH is required for diff-lean"}))
            return 1
        args.extend([base_path, target])
    else:
        args.append(target)

    if mode == "check-lean" and strict:
        args.append("--strict")
    args.extend(["--format", fmt])
    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(run_from_env())
