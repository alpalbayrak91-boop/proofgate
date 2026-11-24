"""CLI entrypoint for ProofGate."""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Optional, Sequence

from .ast_gate import check_python_source
from .lean_gate import check_lean_source
from .muhur_rfc6962 import MerkleTree, canonical_json_bytes


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="proofgate", description="ProofGate & RFC 6962 Merkle Verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_lean = sub.add_parser("check-lean", help="Audit a Lean 4 file")
    p_lean.add_argument("path", type=pathlib.Path)
    p_lean.add_argument("--no-print-axioms", action="store_true")

    p_ast = sub.add_parser("check-ast", help="Audit a Python file statically")
    p_ast.add_argument("path", type=pathlib.Path)

    p_merkle = sub.add_parser("merkle-root", help="Compute RFC 6962 SHA-256 Merkle root over files")
    p_merkle.add_argument("paths", nargs="+", type=pathlib.Path)

    args = parser.parse_args(argv)
    if args.cmd == "check-lean":
        src = args.path.read_text(encoding="utf-8")
        res = check_lean_source(src, require_print_axioms=not args.no_print_axioms)
        print(json.dumps(res.to_dict(), indent=2))
        return 0 if res.verdict == "ACCEPT" else 1

    if args.cmd == "check-ast":
        src = args.path.read_text(encoding="utf-8")
        res = check_python_source(src)
        print(json.dumps(res.to_dict(), indent=2))
        return 0 if res.verdict == "ACCEPT" else 1

    if args.cmd == "merkle-root":
        payloads = []
        for p in args.paths:
            raw = p.read_bytes()
            if p.suffix.lower() == ".json":
                raw = canonical_json_bytes(json.loads(raw.decode("utf-8")))
            payloads.append(raw)
        tree = MerkleTree(payloads)
        print(json.dumps({"tree_size": tree.size, "root": tree.root_hex}, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
