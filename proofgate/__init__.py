"""ProofGate: Lean 4 specification-faithfulness gate, Python AST verifier, and RFC 6962 Merkle receipt toolkit."""
from __future__ import annotations

from .ast_gate import ASTGateResult, check_python_source
from .lean_gate import LeanGateResult, check_lean_source
from .muhur_rfc6962 import (
    MerkleTree,
    canonical_json_bytes,
    hash_leaf,
    hash_node,
    verify_inclusion_proof,
)

__version__ = "0.1.0"

__all__ = [
    "ASTGateResult",
    "LeanGateResult",
    "MerkleTree",
    "__version__",
    "canonical_json_bytes",
    "check_lean_source",
    "check_python_source",
    "hash_leaf",
    "hash_node",
    "verify_inclusion_proof",
]
