"""RFC 6962 domain-separated SHA-256 Merkle tree and deterministic JSON canonicalizer (RFC 8785 subset)."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Sequence


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize JSON deterministically with sorted object keys and minimal whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def hash_leaf(data: bytes) -> bytes:
    """RFC 6962 Section 2.1 leaf hash: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """RFC 6962 Section 2.1 interior node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def _mth(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hash_leaf(leaves[0])
    k = _largest_power_of_two_less_than(n)
    return hash_node(_mth(leaves[:k]), _mth(leaves[k:]))


def _audit_path(m: int, leaves: Sequence[bytes]) -> List[bytes]:
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if m < k:
        path = _audit_path(m, leaves[:k])
        path.append(_mth(leaves[k:]))
        return path
    path = _audit_path(m - k, leaves[k:])
    path.append(_mth(leaves[:k]))
    return path


class MerkleTree:
    """RFC 6962 Merkle tree over arbitrary byte payloads or canonical JSON records."""

    def __init__(self, payloads: Sequence[bytes]) -> None:
        self._payloads: List[bytes] = [bytes(p) for p in payloads]

    @classmethod
    def from_json_records(cls, records: Sequence[Any]) -> "MerkleTree":
        return cls([canonical_json_bytes(rec) for rec in records])

    @property
    def size(self) -> int:
        return len(self._payloads)

    @property
    def root_hex(self) -> str:
        return _mth(self._payloads).hex()

    def inclusion_proof(self, index: int) -> Dict[str, Any]:
        if index < 0 or index >= len(self._payloads):
            raise IndexError(f"leaf index {index} out of range [0, {len(self._payloads)})")
        path = _audit_path(index, self._payloads)
        return {
            "leaf_index": index,
            "tree_size": len(self._payloads),
            "root": self.root_hex,
            "audit_path": [h.hex() for h in path],
        }


def verify_inclusion_proof(payload: bytes, leaf_index: int, tree_size: int, audit_path_hex: Sequence[str], expected_root_hex: str) -> bool:
    """Verify an RFC 6962 Merkle audit path against an expected root hash."""
    if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
        return False
    if tree_size == 1 and not audit_path_hex:
        return hash_leaf(payload).hex() == expected_root_hex.lower()

    def _rec(m: int, n: int, path: List[bytes]) -> bytes:
        if n == 1:
            if len(path) != 0:
                raise ValueError("unexpected extra proof nodes")
            return hash_leaf(payload)
        k = _largest_power_of_two_less_than(n)
        if not path:
            raise ValueError("insufficient proof nodes")
        sibling = path[-1]
        rest = path[:-1]
        if m < k:
            return hash_node(_rec(m, k, rest), sibling)
        return hash_node(sibling, _rec(m - k, n - k, rest))

    try:
        computed = _rec(leaf_index, tree_size, [bytes.fromhex(h) for h in audit_path_hex])
    except ValueError:
        return False
    return computed.hex() == expected_root_hex.lower()
