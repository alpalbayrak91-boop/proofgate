"""RFC 6962 domain-separated SHA-256 Merkle tree and strict RFC 8785 JSON canonicalizer."""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, List, Sequence, Tuple

EMPTY_TREE_ROOT_HEX: str = hashlib.sha256(b"").hexdigest()


def _format_jcs_float(val: float) -> str:
    """Serialize an IEEE-754 float strictly per RFC 8785 Section 3.2.2.3 (ECMAScript)."""
    if not math.isfinite(val):
        raise ValueError("RFC 8785 JCS forbids NaN and Infinity")
    if val == 0.0:
        return "0"

    sign = "-" if val < 0.0 else ""
    av = abs(val)
    raw = repr(av)
    if "e" in raw or "E" in raw:
        mant, exp_str = raw.lower().split("e", 1)
        exp10 = int(exp_str)
    else:
        mant = raw
        exp10 = 0

    if "." in mant:
        int_part, frac_part = mant.split(".", 1)
        digits = int_part + frac_part
        exp10 -= len(frac_part)
    else:
        digits = mant

    digits = digits.lstrip("0") or "0"
    stripped = digits.rstrip("0")
    exp10 += len(digits) - len(stripped)
    digits = stripped or "0"

    k = len(digits)
    n = exp10 + k

    if k <= n <= 21:
        return sign + digits + ("0" * (n - k))
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + ("0" * (-n)) + digits

    exp_val = n - 1
    exp_sign = "+" if exp_val >= 0 else "-"
    if k == 1:
        return sign + digits + "e" + exp_sign + str(abs(exp_val))
    return sign + digits[0] + "." + digits[1:] + "e" + exp_sign + str(abs(exp_val))


def canonical_json_dumps(obj: Any) -> str:
    """Serialize Python JSON values strictly per RFC 8785 (JCS): UTF-16-BE key sort and -0.0 -> 0."""
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return _format_jcs_float(obj)
    if isinstance(obj, str):
        obj.encode("utf-8")
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json_dumps(item) for item in obj) + "]"
    if isinstance(obj, dict):
        entries: List[Tuple[bytes, str, Any]] = []
        for key, val in obj.items():
            if not isinstance(key, str):
                raise TypeError(f"RFC 8785 JCS requires string object keys, got {type(key).__name__}")
            entries.append((key.encode("utf-16-be"), key, val))
        entries.sort(key=lambda item: item[0])
        return (
            "{"
            + ",".join(
                f"{canonical_json_dumps(k)}:{canonical_json_dumps(v)}"
                for _, k, v in entries
            )
            + "}"
        )
    raise TypeError(f"Unsupported type for RFC 8785 JCS serialization: {type(obj).__name__}")


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize JSON deterministically as UTF-8 bytes strictly per RFC 8785 (JCS)."""
    return canonical_json_dumps(obj).encode("utf-8")


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


def _subproof(m: int, leaves: Sequence[bytes], complete_subtree: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete_subtree else [_mth(leaves)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        path = _subproof(m, leaves[:k], complete_subtree)
        path.append(_mth(leaves[k:]))
        return path
    path = _subproof(m - k, leaves[k:], False)
    path.append(_mth(leaves[:k]))
    return path


def build_consistency_proof(old_size: int, payloads: Sequence[bytes]) -> List[str]:
    """Generate an RFC 6962 Section 2.1.2 consistency proof path from old_size to len(payloads)."""
    n = len(payloads)
    if old_size < 0 or old_size > n:
        raise ValueError(f"old_size {old_size} out of valid range [0, {n}]")
    if old_size == 0 or old_size == n:
        return []
    return [h.hex() for h in _subproof(old_size, payloads, True)]


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

    def root_at_size(self, tree_size: int) -> str:
        """Compute the RFC 6962 Merkle Tree Hash for the prefix of size tree_size."""
        if tree_size < 0 or tree_size > len(self._payloads):
            raise ValueError(f"tree_size {tree_size} out of range [0, {len(self._payloads)}]")
        return _mth(self._payloads[:tree_size]).hex()

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

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> Dict[str, Any]:
        """Generate an RFC 6962 Section 2.1.2 consistency proof between two append-only tree sizes."""
        target_size = len(self._payloads) if new_size is None else new_size
        if target_size < 0 or target_size > len(self._payloads):
            raise ValueError(f"new_size {target_size} out of range [0, {len(self._payloads)}]")
        if old_size < 0 or old_size > target_size:
            raise ValueError(f"old_size {old_size} out of range [0, {target_size}]")
        prefix = self._payloads[:target_size]
        return {
            "old_size": old_size,
            "new_size": target_size,
            "old_root": _mth(prefix[:old_size]).hex(),
            "new_root": _mth(prefix).hex(),
            "consistency_path": build_consistency_proof(old_size, prefix),
        }


def _decode_sha256_hex(hex_str: str) -> bytes | None:
    if not isinstance(hex_str, str) or len(hex_str) != 64:
        return None
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def verify_inclusion_proof(
    payload: bytes,
    leaf_index: int,
    tree_size: int,
    audit_path_hex: Sequence[str],
    expected_root_hex: str,
) -> bool:
    """Verify an RFC 6962 Merkle audit path against an expected root hash."""
    if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
        return False
    expected_root = _decode_sha256_hex(expected_root_hex)
    if expected_root is None:
        return False
    if tree_size == 1 and not audit_path_hex:
        return hash_leaf(payload) == expected_root

    decoded_path: List[bytes] = []
    for item in audit_path_hex:
        raw = _decode_sha256_hex(item)
        if raw is None:
            return False
        decoded_path.append(raw)

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
        computed = _rec(leaf_index, tree_size, decoded_path)
    except ValueError:
        return False
    return computed == expected_root


def verify_consistency_proof(
    old_size: int,
    new_size: int,
    consistency_path_hex: Sequence[str],
    old_root_hex: str,
    new_root_hex: str,
) -> bool:
    """Verify an RFC 6962 Section 2.1.2 Merkle consistency proof between old_size and new_size."""
    if isinstance(old_size, bool) or isinstance(new_size, bool):
        return False
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False

    old_root = _decode_sha256_hex(old_root_hex)
    new_root = _decode_sha256_hex(new_root_hex)
    if old_root is None or new_root is None:
        return False

    empty_root = hashlib.sha256(b"").digest()
    if old_size == 0:
        if len(consistency_path_hex) != 0 or old_root != empty_root:
            return False
        if new_size == 0:
            return new_root == empty_root
        return True

    if old_size == new_size:
        return len(consistency_path_hex) == 0 and old_root == new_root

    proof: List[bytes] = []
    for item in consistency_path_hex:
        raw = _decode_sha256_hex(item)
        if raw is None:
            return False
        proof.append(raw)

    if not proof:
        return False

    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    idx = 0
    if fn == 0:
        fr = old_root
        sr = old_root
    else:
        fr = proof[0]
        sr = proof[0]
        idx = 1

    while sn != 0:
        if idx >= len(proof):
            return False
        node = proof[idx]
        idx += 1
        if (fn & 1) or fn == sn:
            fr = hash_node(node, fr)
            sr = hash_node(node, sr)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = hash_node(sr, node)
        fn >>= 1
        sn >>= 1

    return idx == len(proof) and fn == 0 and fr == old_root and sr == new_root
