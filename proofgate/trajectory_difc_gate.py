"""Layer 6 Trajectory Security Gate: DIFC Lattice + Macaroon Capabilities + Schema Epoch Firewall.

Implements a deterministic, zero-dependency multi-step trajectory verifier for autonomous AI agents,
combining Decentralized Information-Flow Control (DIFC), HMAC-SHA256 Macaroon capability attenuation,
RFC 8785 JCS tool-schema epoch pinning, multi-dimensional knapsack horizon budgets, SARIF 2.1.0
reporting, and RFC 6962 Merkle trajectory receipts.

Primary Literature Grounding:
  - Denning, D. E. (1976). A Lattice Model of Secure Information Flow.
    Communications of the ACM, 19(5), 236-243.
  - Biba, K. J. (1977). Integrity Considerations for Secure Computer Systems.
    Technical Report ESD-TR-76-372, MITRE Corp.
  - Myers, A. C., & Liskov, B. (1997). A Decentralized Model for Information Flow Control.
    Proceedings of the 16th ACM Symposium on Operating Systems Principles (SOSP '97), 129-142.
  - Birgisson, A., Politz, J. G., Erlingsson, U., Taly, A., Vrable, M., & Lentczner, M. (2014).
    Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud.
    NDSS 2014.
  - Debenedetti, E., et al. (2025). Defeating Prompt Injections by Design (CaMeL).
    arXiv:2503.18813.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import hashlib
import hmac
import json
import math
import os
import posixpath
import re
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union
import urllib.parse

from .muhur_rfc6962 import (
    MerkleTree,
    canonical_json_bytes,
    canonical_json_dumps,
    hash_leaf,
)
from .sarif_export import export_sarif, findings_from_gate_result


class IntegrityLevel(IntEnum):
    """Total-order Biba integrity lattice levels (meet = min)."""

    UNTRUSTED_EXTERNAL = 0
    VERIFIED_TOOL = 1
    USER_EXPLICIT = 2
    TRUSTED_SYSTEM = 3


STANDARD_SECRECY_TAGS: FrozenSet[str] = frozenset({
    "SECRET_ENV",
    "CREDENTIAL_STORE",
    "PRIVATE_REPO",
    "PII_RECORD",
    "FINANCIAL_LEDGER",
})

EXTERNAL_SINK_ACTIONS: FrozenSet[str] = frozenset({
    "http_post",
    "webhook_send",
    "email_send",
    "dns_lookup_untrusted",
    "markdown_external_image",
    "git_push_public",
})

HIGH_INTEGRITY_MUTATION_ACTIONS: FrozenSet[str] = frozenset({
    "shell_exec",
    "ci_workflow_write",
    "iam_policy_update",
    "payment_transfer",
    "production_deploy",
})

PATH_BEARING_ACTIONS: FrozenSet[str] = frozenset({
    "file_write",
    "write_file",
    "ci_workflow_write",
    "delete_resource",
    "git_commit",
})

WRITE_OR_MUTATING_ACTIONS: FrozenSet[str] = (
    EXTERNAL_SINK_ACTIONS
    | HIGH_INTEGRITY_MUTATION_ACTIONS
    | PATH_BEARING_ACTIONS
    | frozenset({"db_write"})
)

SUPPORTED_CAVEAT_TYPES: FrozenSet[str] = frozenset({
    "scopes_subset",
    "allowed_tools",
    "path_prefixes",
    "domain_allowlist",
    "max_calls",
    "read_only",
})

DEFAULT_HORIZON_BUDGETS: Dict[str, float] = {
    "risk_score": 100.0,
    "external_bytes": 65536.0,
    "tool_calls": 64.0,
}

TRAJECTORY_RULE_IDS: Dict[str, str] = {
    "LETHAL_TRIFECTA_EXFIL": "PG-TRAJ-001",
    "BIBA_CONFUSED_DEPUTY_MUTATION": "PG-TRAJ-002",
    "MACAROON_CAPABILITY_VIOLATION": "PG-TRAJ-003",
    "MID_TRAJECTORY_SCHEMA_RUGPULL": "PG-TRAJ-004",
    "KNAPSACK_HORIZON_BUDGET_EXCEEDED": "PG-TRAJ-005",
}

_PATH_ARG_KEYS: FrozenSet[str] = frozenset({
    "path",
    "file",
    "filepath",
    "file_path",
    "filename",
    "dest",
    "destination",
    "cwd",
})

_HOST_ARG_KEYS: FrozenSet[str] = frozenset({
    "url",
    "uri",
    "endpoint",
    "webhook",
    "domain",
    "host",
    "hostname",
    "remote",
})

_RFC1123_HOST_RE = re.compile(
    r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z"
)
_MARKDOWN_EXT_IMG_RE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)")
_SECRET_PATH_RE = re.compile(
    r"(?:^|/)(?:\.env(?:\.[A-Za-z0-9_.-]+)?|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|secrets\.[A-Za-z0-9]+)\Z"
)
_CI_WORKFLOW_PATH_RE = re.compile(
    r"(?:^|/)(?:\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml|Jenkinsfile)\Z"
)
_STATELESS_BAD_CMD_RE = re.compile(
    r"(?:\brm\s+-rf\s+/|\bmkfs\b|\bcurl\b[^\n|]*\|\s*(?:sh|bash)\b|"
    r"\bignore\s+(?:all\s+)?previous\s+instructions\b|"
    r"-----BEGIN\s+(?:RSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----)",
    re.IGNORECASE,
)


def _parse_nonneg_finite_float(val: Any) -> Optional[float]:
    """Return finite float >= 0.0, rejecting bool, NaN, Infinity, negatives, and non-numbers."""
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None
    fval = float(val)
    if not math.isfinite(fval) or fval < 0.0:
        return None
    return fval


def parse_integrity_level(val: Union[int, str, IntegrityLevel]) -> IntegrityLevel:
    """Parse an IntegrityLevel from enum, integer 0..3, or canonical string name."""
    if isinstance(val, IntegrityLevel):
        return val
    if isinstance(val, bool):
        raise ValueError("IntegrityLevel cannot be a boolean")
    if isinstance(val, int):
        return IntegrityLevel(val)
    if isinstance(val, str):
        cleaned = val.strip().upper()
        if cleaned.isdigit():
            return IntegrityLevel(int(cleaned))
        try:
            return IntegrityLevel[cleaned]
        except KeyError as exc:
            raise ValueError(f"Unknown IntegrityLevel: {val!r}") from exc
    raise TypeError(f"Unsupported IntegrityLevel type: {type(val).__name__}")


def secrecy_join(left: Iterable[str], right: Iterable[str]) -> FrozenSet[str]:
    """Join operator on the secrecy tag semilattice (set union)."""
    out: Set[str] = set()
    for item in left:
        s = str(item).strip()
        if s:
            out.add(s)
    for item in right:
        s = str(item).strip()
        if s:
            out.add(s)
    return frozenset(out)


def integrity_meet(left: IntegrityLevel, right: IntegrityLevel) -> IntegrityLevel:
    """Meet operator on the Biba integrity total order (min)."""
    return IntegrityLevel(min(int(left), int(right)))


def _normalize_posix_path(raw_path: str) -> str:
    """Canonicalize a POSIX resource path to prevent `..` prefix-escape bypasses."""
    cleaned = raw_path.strip().replace("\\", "/")
    if not cleaned or "\x00" in cleaned:
        return ""
    leading_slash = cleaned.startswith("/")
    normed = posixpath.normpath(cleaned)
    if leading_slash and not normed.startswith("/"):
        normed = "/" + normed
    return normed


def _path_matches_prefix(norm_target: str, raw_prefix: str) -> bool:
    norm_pref = _normalize_posix_path(raw_prefix)
    if not norm_pref or not norm_target:
        return False
    # Relative or tilde-prefixed paths cannot satisfy an absolute directory prefix
    if norm_pref.startswith("/") and not norm_target.startswith("/"):
        return False
    if norm_pref == "/":
        return norm_target.startswith("/")
    return norm_target == norm_pref or norm_target.startswith(norm_pref + "/")


def _extract_host(url_or_domain: str) -> str:
    """Strictly extract and validate an RFC-1123 hostname; return '' fail-closed on ambiguity."""
    if not isinstance(url_or_domain, str):
        return ""
    val = url_or_domain.strip()
    if not val:
        return ""
    # Reject userinfo '@', backslashes, whitespace, and ASCII control / non-ASCII codepoints
    if "@" in val or "\\" in val or any(ord(ch) <= 0x20 or ord(ch) >= 0x7F for ch in val):
        return ""
    if "://" in val:
        parts = urllib.parse.urlsplit(val)
        if not parts.scheme or "@" in parts.netloc:
            return ""
        netloc = parts.netloc
    else:
        # Strip '?' and '#' BEFORE '/' and ':' so query/fragment suffixes never masquerade as host
        before_qf = val.split("?", 1)[0].split("#", 1)[0]
        netloc = before_qf.split("/", 1)[0]
    if not netloc or "@" in netloc:
        return ""
    if ":" in netloc:
        host_part, port_part = netloc.split(":", 1)
        if not port_part.isdigit():
            return ""
    else:
        host_part = netloc
    host = host_part.lower().rstrip(".")
    if not host or len(host) > 253:
        return ""
    if not _RFC1123_HOST_RE.fullmatch(host):
        return ""
    return host


def _domain_matches(host: str, allowed_domain: str) -> bool:
    h = _extract_host(host)
    dom = _extract_host(allowed_domain)
    if not h or not dom:
        return False
    return h == dom or h.endswith("." + dom)


def compute_secrecy_tags_hash(tags: Iterable[str]) -> str:
    """Deterministic SHA-256 over RFC 8785 JCS sorted secrecy tag array."""
    ordered = sorted({str(t).strip() for t in tags if str(t).strip()})
    return hashlib.sha256(canonical_json_bytes(ordered)).hexdigest()


def compute_tool_schema_digest(schema_obj: Mapping[str, Any]) -> str:
    """Compute RFC 8785 JCS SHA-256 digest of an MCP tool descriptor / prompt schema."""
    if not isinstance(schema_obj, Mapping):
        raise TypeError("tool_schema must be a JSON object mapping")
    return hashlib.sha256(canonical_json_bytes(dict(schema_obj))).hexdigest()


@dataclass(frozen=True)
class ArtifactTaintLabel:
    """DIFC security label attached to an intermediate scratchpad cell or local artifact."""

    secrecy_tags: FrozenSet[str] = frozenset()
    integrity_level: IntegrityLevel = IntegrityLevel.USER_EXPLICIT
    hop_count: int = 0
    lineage: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secrecy_tags": sorted(self.secrecy_tags),
            "integrity_level": self.integrity_level.name,
            "hop_count": self.hop_count,
            "lineage": list(self.lineage),
        }


@dataclass(frozen=True)
class MacaroonToken:
    """HMAC-SHA256 chained capability token with monotonic contextual caveat attenuation."""

    identifier: str
    nonce: str
    root_scopes: Tuple[str, ...]
    caveats: Tuple[Dict[str, Any], ...]
    signature_hex: str

    def attenuate(self, caveat: Mapping[str, Any]) -> "MacaroonToken":
        """Append a contextual caveat without needing the root key: sig' = HMAC(sig, JCS(caveat))."""
        if not isinstance(caveat, Mapping):
            raise TypeError("Macaroon caveat must be a mapping")
        cav_dict = json.loads(canonical_json_dumps(dict(caveat)))
        prev_sig = bytes.fromhex(self.signature_hex)
        next_sig = hmac.new(prev_sig, canonical_json_bytes(cav_dict), hashlib.sha256).hexdigest()
        return MacaroonToken(
            identifier=self.identifier,
            nonce=self.nonce,
            root_scopes=self.root_scopes,
            caveats=self.caveats + (cav_dict,),
            signature_hex=next_sig,
        )

    def effective_scopes(self) -> FrozenSet[str]:
        """Compute monotonically attenuated effective scopes (can only shrink from root_scopes)."""
        eff: Set[str] = set(self.root_scopes)
        for cav in self.caveats:
            ctype = str(cav.get("type", ""))
            if ctype == "scopes_subset":
                allowed = {str(s) for s in cav.get("scopes", ()) if isinstance(s, str)}
                eff &= allowed
            elif ctype == "read_only" and bool(cav.get("value", True)):
                eff &= {"read", "inspect", "search", "summarize", "verify"}
        return frozenset(eff)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "nonce": self.nonce,
            "root_scopes": list(self.root_scopes),
            "caveats": [dict(c) for c in self.caveats],
            "signature_hex": self.signature_hex,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MacaroonToken":
        if not isinstance(data, Mapping):
            raise TypeError("MacaroonToken data must be a JSON object")
        root_scopes_raw = data.get("root_scopes")
        caveats_raw = data.get("caveats", ())
        sig_hex = str(data.get("signature_hex", "")).strip().lower()
        if not isinstance(root_scopes_raw, (list, tuple)):
            raise ValueError("MacaroonToken root_scopes must be a list")
        if not isinstance(caveats_raw, (list, tuple)):
            raise ValueError("MacaroonToken caveats must be a list")
        if len(sig_hex) != 64:
            raise ValueError("MacaroonToken signature_hex must be a 64-char SHA-256 hex digest")
        bytes.fromhex(sig_hex)
        return cls(
            identifier=str(data.get("identifier", "")),
            nonce=str(data.get("nonce", "")),
            root_scopes=tuple(sorted({str(s) for s in root_scopes_raw})),
            caveats=tuple(json.loads(canonical_json_dumps(dict(c))) for c in caveats_raw),
            signature_hex=sig_hex,
        )


@dataclass(frozen=True)
class MacaroonVerificationResult:
    valid: bool
    effective_scopes: FrozenSet[str]
    scope_trace: Tuple[FrozenSet[str], ...]
    reason: str = "OK"


def _macaroon_root_sig_bytes(
    root_key: bytes,
    identifier: str,
    nonce: str,
    root_scopes: Sequence[str],
) -> bytes:
    derived_key = hmac.new(
        root_key,
        b"proofgate-macaroon-v2:" + identifier.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    root_header = {
        "id": identifier,
        "nonce": nonce,
        "root_scopes": sorted({str(s) for s in root_scopes}),
    }
    return hmac.new(derived_key, canonical_json_bytes(root_header), hashlib.sha256).digest()


def mint_macaroon(
    root_key: bytes,
    *,
    identifier: str,
    nonce: str,
    root_scopes: Iterable[str],
    caveats: Sequence[Mapping[str, Any]] = (),
) -> MacaroonToken:
    """Mint a root HMAC-SHA256 Macaroon token and apply any initial contextual caveats."""
    if not root_key:
        raise ValueError("Macaroon root_key must be non-empty")
    if not identifier or not nonce:
        raise ValueError("Macaroon identifier and nonce must be non-empty")
    ordered_scopes = tuple(sorted({str(s) for s in root_scopes if str(s).strip()}))
    sig0 = _macaroon_root_sig_bytes(root_key, identifier, nonce, ordered_scopes).hex()
    tok = MacaroonToken(
        identifier=identifier,
        nonce=nonce,
        root_scopes=ordered_scopes,
        caveats=(),
        signature_hex=sig0,
    )
    for cav in caveats:
        tok = tok.attenuate(cav)
    return tok


def verify_macaroon(root_key: bytes, token: MacaroonToken) -> MacaroonVerificationResult:
    """Verify full HMAC-SHA256 chain integrity and monotonic scope attenuation."""
    if not root_key or not token.identifier or not token.nonce:
        return MacaroonVerificationResult(False, frozenset(), (), "MACAROON_EMPTY_METADATA")
    try:
        claimed_sig = bytes.fromhex(token.signature_hex)
    except ValueError:
        return MacaroonVerificationResult(False, frozenset(), (), "MACAROON_MALFORMED_HEX")
    if len(claimed_sig) != 32:
        return MacaroonVerificationResult(False, frozenset(), (), "MACAROON_SIG_LEN_MISMATCH")

    cur_sig = _macaroon_root_sig_bytes(root_key, token.identifier, token.nonce, token.root_scopes)
    cur_scopes: FrozenSet[str] = frozenset(token.root_scopes)
    trace: List[FrozenSet[str]] = [cur_scopes]

    for idx, cav in enumerate(token.caveats):
        if not isinstance(cav, Mapping):
            return MacaroonVerificationResult(False, frozenset(), tuple(trace), f"MACAROON_INVALID_CAVEAT_AT_{idx}")
        cur_sig = hmac.new(cur_sig, canonical_json_bytes(dict(cav)), hashlib.sha256).digest()
        ctype = str(cav.get("type", ""))
        if ctype not in SUPPORTED_CAVEAT_TYPES:
            return MacaroonVerificationResult(
                False,
                frozenset(),
                tuple(trace),
                f"MACAROON_UNSUPPORTED_OR_ESCALATING_CAVEAT:{ctype}",
            )
        if ctype == "scopes_subset":
            raw_sc = cav.get("scopes")
            if not isinstance(raw_sc, (list, tuple)):
                return MacaroonVerificationResult(False, frozenset(), tuple(trace), "MACAROON_BAD_SCOPES_CAVEAT")
            next_scopes = frozenset(cur_scopes & {str(s) for s in raw_sc})
        elif ctype == "read_only" and bool(cav.get("value", True)):
            next_scopes = frozenset(cur_scopes & {"read", "inspect", "search", "summarize", "verify"})
        else:
            next_scopes = cur_scopes

        if not next_scopes.issubset(cur_scopes):  # pragma: no cover - defensive invariant
            return MacaroonVerificationResult(False, frozenset(), tuple(trace), "MACAROON_NON_MONOTONIC_SCOPE")
        cur_scopes = next_scopes
        trace.append(cur_scopes)

    if not hmac.compare_digest(cur_sig, claimed_sig):
        return MacaroonVerificationResult(False, frozenset(), tuple(trace), "MACAROON_HMAC_CHAIN_TAMPERED")

    return MacaroonVerificationResult(True, cur_scopes, tuple(trace), "OK")


def check_macaroon_step_authorization(
    token: MacaroonToken,
    *,
    tool_name: str,
    action_kind: str,
    required_scope: str,
    target_path: str = "",
    target_domain: str = "",
    call_count_1based: int = 1,
    candidate_paths: Optional[Sequence[str]] = None,
    candidate_hosts: Optional[Sequence[str]] = None,
    has_invalid_path: bool = False,
    has_invalid_host: bool = False,
) -> Tuple[bool, str]:
    """Evaluate all active Macaroon scopes and contextual caveats against ALL step targets."""
    eff_scopes = token.effective_scopes()
    if required_scope and required_scope not in eff_scopes:
        return False, f"MACAROON_MISSING_SCOPE:{required_scope}"

    all_paths: List[str] = []
    if candidate_paths is not None:
        for p in candidate_paths:
            np = _normalize_posix_path(p) if p else ""
            if np and np not in all_paths:
                all_paths.append(np)
    elif target_path:
        np = _normalize_posix_path(target_path)
        if np:
            all_paths.append(np)

    all_hosts: List[str] = []
    invalid_host_flag = has_invalid_host
    if candidate_hosts is not None:
        for h in candidate_hosts:
            nh = _extract_host(h)
            if not nh:
                invalid_host_flag = True
            elif nh not in all_hosts:
                all_hosts.append(nh)
    elif target_domain:
        nh = _extract_host(target_domain)
        if not nh:
            invalid_host_flag = True
        else:
            all_hosts.append(nh)

    is_path_action = (action_kind in PATH_BEARING_ACTIONS) or (
        action_kind == "read_resource" and not all_hosts and not invalid_host_flag
    )
    is_net_action = action_kind in EXTERNAL_SINK_ACTIONS

    for idx, cav in enumerate(token.caveats):
        ctype = str(cav.get("type", ""))
        if ctype not in SUPPORTED_CAVEAT_TYPES:
            return False, f"MACAROON_UNKNOWN_CAVEAT:{ctype}"

        if ctype == "allowed_tools":
            tools = cav.get("tools")
            if not isinstance(tools, (list, tuple)) or tool_name not in {str(t) for t in tools}:
                return False, f"MACAROON_TOOL_DENIED:{tool_name}@caveat[{idx}]"

        elif ctype == "path_prefixes":
            prefixes = cav.get("prefixes")
            if not isinstance(prefixes, (list, tuple)) or not prefixes:
                return False, f"MACAROON_INVALID_PATH_PREFIXES@caveat[{idx}]"
            if has_invalid_path:
                return False, f"MACAROON_MALFORMED_PATH_CANDIDATE@caveat[{idx}]"
            if all_paths or is_path_action:
                if not all_paths:
                    return False, f"MACAROON_MISSING_REQUIRED_PATH:{action_kind}@caveat[{idx}]"
                for cp in all_paths:
                    if not any(_path_matches_prefix(cp, str(p)) for p in prefixes):
                        return False, f"MACAROON_PATH_OUTSIDE_ALLOWLIST:{cp}@caveat[{idx}]"

        elif ctype == "domain_allowlist":
            domains = cav.get("domains")
            if not isinstance(domains, (list, tuple)) or not domains:
                return False, f"MACAROON_INVALID_DOMAIN_ALLOWLIST@caveat[{idx}]"
            if invalid_host_flag:
                return False, f"MACAROON_INVALID_OR_SPOOFED_HOST@caveat[{idx}]"
            if all_hosts or is_net_action:
                if not all_hosts:
                    return False, f"MACAROON_EXTERNAL_SINK_MISSING_HOST@caveat[{idx}]"
                for ch in all_hosts:
                    if not any(_domain_matches(ch, str(d)) for d in domains):
                        return False, f"MACAROON_DOMAIN_OUTSIDE_ALLOWLIST:{ch}@caveat[{idx}]"

        elif ctype == "max_calls":
            limit = cav.get("limit")
            if isinstance(limit, bool) or not isinstance(limit, int) or call_count_1based > limit:
                return False, f"MACAROON_MAX_CALLS_EXCEEDED:{call_count_1based}>{limit}@caveat[{idx}]"

        elif ctype == "read_only":
            if bool(cav.get("value", True)) and action_kind in WRITE_OR_MUTATING_ACTIONS:
                return False, f"MACAROON_READ_ONLY_BLOCKS:{action_kind}@caveat[{idx}]"

    return True, "OK"


def mint_declassification_endorsement(
    endorsement_key: bytes,
    *,
    trajectory_id: str,
    step_index: int,
    action_kind: str,
    sink_target: str,
    secrecy_tags: Iterable[str] = (),
    nonce: str,
    endorse_lethal_trifecta: bool = True,
    endorse_biba_mutation: bool = False,
) -> Dict[str, Any]:
    """Mint a single-use, step-bound human declassification / Biba integrity endorsement."""
    if not endorsement_key:
        raise ValueError("endorsement_key must be non-empty")
    if not nonce or not str(nonce).strip():
        raise ValueError("endorsement nonce must be non-empty")
    tags_hash = compute_secrecy_tags_hash(secrecy_tags)
    body = {
        "domain": "ProofGate-DIFC-Endorsement-v2",
        "trajectory_id": str(trajectory_id),
        "step_index": int(step_index),
        "action_kind": str(action_kind),
        "sink_target": str(sink_target),
        "secrecy_tags_hash": tags_hash,
        "nonce": str(nonce),
        "endorse_lethal_trifecta": bool(endorse_lethal_trifecta),
        "endorse_biba_mutation": bool(endorse_biba_mutation),
    }
    sig = hmac.new(endorsement_key, canonical_json_bytes(body), hashlib.sha256).hexdigest()
    return {**body, "hmac_sha256": sig}


def verify_declassification_endorsement(
    endorsement_key: Optional[bytes],
    endorsement: Mapping[str, Any],
    *,
    trajectory_id: str,
    step_index: int,
    action_kind: str,
    sink_target: str,
    active_secrecy_tags: Iterable[str],
    used_nonces: FrozenSet[str],
    require_trifecta: bool = False,
    require_biba: bool = False,
    all_sink_urls: Sequence[str] = (),
    all_hosts: Sequence[str] = (),
    all_paths: Sequence[str] = (),
    all_explicit_targets: Sequence[str] = (),
    has_ambiguous_target: bool = False,
) -> Tuple[bool, str, str]:
    """Verify HMAC-SHA256 human endorsement, anti-split-brain target consistency, and nonce freshness."""
    if not endorsement_key:
        return False, "", "ENDORSEMENT_KEY_UNCONFIGURED"
    if not isinstance(endorsement, Mapping):
        return False, "", "ENDORSEMENT_NOT_OBJECT"
    if has_ambiguous_target:
        return False, "", "ENDORSEMENT_AMBIGUOUS_STEP_TARGET"

    nonce = str(endorsement.get("nonce", "")).strip()
    if not nonce:
        return False, "", "ENDORSEMENT_EMPTY_NONCE"
    if nonce in used_nonces:
        return False, nonce, "ENDORSEMENT_NONCE_REPLAYED"

    claimed_sig_hex = str(endorsement.get("hmac_sha256", "")).strip().lower()
    try:
        claimed_sig = bytes.fromhex(claimed_sig_hex)
    except ValueError:
        return False, nonce, "ENDORSEMENT_MALFORMED_HMAC_HEX"
    if len(claimed_sig) != 32:
        return False, nonce, "ENDORSEMENT_BAD_HMAC_LEN"

    body = {
        "domain": str(endorsement.get("domain", "")),
        "trajectory_id": str(endorsement.get("trajectory_id", "")),
        "step_index": endorsement.get("step_index"),
        "action_kind": str(endorsement.get("action_kind", "")),
        "sink_target": str(endorsement.get("sink_target", "")),
        "secrecy_tags_hash": str(endorsement.get("secrecy_tags_hash", "")),
        "nonce": nonce,
        "endorse_lethal_trifecta": bool(endorsement.get("endorse_lethal_trifecta", False)),
        "endorse_biba_mutation": bool(endorsement.get("endorse_biba_mutation", False)),
    }
    if body["domain"] != "ProofGate-DIFC-Endorsement-v2":
        return False, nonce, "ENDORSEMENT_WRONG_DOMAIN"
    if isinstance(body["step_index"], bool) or not isinstance(body["step_index"], int):
        return False, nonce, "ENDORSEMENT_INVALID_STEP_INDEX"

    expected_sig = hmac.new(endorsement_key, canonical_json_bytes(body), hashlib.sha256).digest()
    if not hmac.compare_digest(expected_sig, claimed_sig):
        return False, nonce, "ENDORSEMENT_HMAC_MISMATCH"

    if body["trajectory_id"] != str(trajectory_id):
        return False, nonce, "ENDORSEMENT_TRAJECTORY_ID_MISMATCH"
    if body["step_index"] != int(step_index):
        return False, nonce, "ENDORSEMENT_STEP_INDEX_MISMATCH"
    if body["action_kind"] != str(action_kind):
        return False, nonce, "ENDORSEMENT_ACTION_KIND_MISMATCH"

    endorsed_sink = body["sink_target"].strip()
    if endorsed_sink != str(sink_target).strip():
        return False, nonce, "ENDORSEMENT_SINK_TARGET_MISMATCH"

    # Anti-split-brain verification: EVERY extracted URL/host/path/target on the step must match endorsed_sink
    for exp_t in all_explicit_targets:
        if exp_t.strip() and exp_t.strip() != endorsed_sink:
            return False, nonce, f"ENDORSEMENT_SPLIT_BRAIN_TARGET_MISMATCH:{exp_t.strip()}"
    for url_cand in all_sink_urls:
        if url_cand.strip() and url_cand.strip() != endorsed_sink:
            return False, nonce, f"ENDORSEMENT_SPLIT_BRAIN_URL_MISMATCH:{url_cand.strip()}"
    if all_hosts:
        endorsed_host = _extract_host(endorsed_sink)
        if not endorsed_host or any(h != endorsed_host for h in all_hosts):
            return False, nonce, "ENDORSEMENT_SPLIT_BRAIN_HOST_MISMATCH"
    if all_paths and (action_kind in PATH_BEARING_ACTIONS or endorsed_sink.startswith("/") or endorsed_sink.startswith(".")):
        norm_endorsed = _normalize_posix_path(endorsed_sink)
        if any(p != norm_endorsed for p in all_paths):
            return False, nonce, "ENDORSEMENT_SPLIT_BRAIN_PATH_MISMATCH"
    elif all_paths and action_kind in HIGH_INTEGRITY_MUTATION_ACTIONS:
        norm_endorsed = _normalize_posix_path(endorsed_sink)
        if any(p != norm_endorsed for p in all_paths):
            return False, nonce, "ENDORSEMENT_SPLIT_BRAIN_MUTATION_PATH_MISMATCH"

    if require_trifecta:
        if not body["endorse_lethal_trifecta"]:
            return False, nonce, "ENDORSEMENT_NOT_AUTHORIZED_FOR_TRIFECTA"
        active_hash = compute_secrecy_tags_hash(active_secrecy_tags)
        if body["secrecy_tags_hash"] != active_hash:
            return False, nonce, "ENDORSEMENT_SECRECY_TAGS_HASH_MISMATCH"

    if require_biba and not body["endorse_biba_mutation"]:
        return False, nonce, "ENDORSEMENT_NOT_AUTHORIZED_FOR_BIBA"

    return True, nonce, "OK"


@dataclass(frozen=True)
class TrajectoryLatticeState:
    """Product security lattice state maintained across an autonomous agent trajectory."""

    secrecy_tags: FrozenSet[str]
    integrity_level: IntegrityLevel
    capability_macaroon: MacaroonToken
    pinned_tool_digests: Dict[str, str]
    cumulative_cost: Dict[str, float]
    schema_epoch: int = 0
    artifact_labels: Dict[str, ArtifactTaintLabel] = field(default_factory=dict)
    used_endorsement_nonces: FrozenSet[str] = field(default_factory=frozenset)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secrecy_tags": sorted(self.secrecy_tags),
            "integrity_level": self.integrity_level.name,
            "integrity_rank": int(self.integrity_level),
            "capability_macaroon": self.capability_macaroon.to_dict(),
            "effective_scopes": sorted(self.capability_macaroon.effective_scopes()),
            "pinned_tool_digests": dict(sorted(self.pinned_tool_digests.items())),
            "cumulative_cost": {k: round(float(v), 6) for k, v in sorted(self.cumulative_cost.items())},
            "schema_epoch": self.schema_epoch,
            "artifact_labels": {k: v.to_dict() for k, v in sorted(self.artifact_labels.items())},
            "used_endorsement_nonces_count": len(self.used_endorsement_nonces),
        }


@dataclass(frozen=True)
class TrajectoryGateResult:
    """Complete result of ProofGate Layer 6 TrajectoryDIFCGate evaluation."""

    trajectory_id: str
    verdict: str
    primary_code: str
    violations: List[str]
    triggered_rule_ids: List[str]
    steps_evaluated: int
    findings: List[Dict[str, Any]]
    step_traces: List[Dict[str, Any]]
    final_state: Dict[str, Any]
    receipt: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trajectory_id": self.trajectory_id,
            "verdict": self.verdict,
            "primary_code": self.primary_code,
            "violations": list(self.violations),
            "triggered_rule_ids": list(self.triggered_rule_ids),
            "steps_evaluated": self.steps_evaluated,
            "findings": list(self.findings),
            "step_traces": list(self.step_traces),
            "final_state": dict(self.final_state),
            "receipt": dict(self.receipt),
        }

    def to_sarif(
        self,
        *,
        artifact_uri: str = "trajectory.json",
        source: str = "",
        tool_version: str = "2.0.0",
    ) -> Dict[str, Any]:
        sarif_findings = findings_from_gate_result(
            self.to_dict(),
            artifact_uri=artifact_uri,
            source=source,
        )
        return export_sarif(sarif_findings, tool_version=tool_version)


def _locate_step_lines_in_json_source(source: str, step_count: int) -> List[int]:
    """Locate 1-based line numbers of `"step_index"` or `"step_id"` entries in raw JSON text."""
    if not source:
        return [idx + 1 for idx in range(step_count)]
    hits: List[int] = []
    for line_no, raw_line in enumerate(source.splitlines(), start=1):
        if '"step_index"' in raw_line or '"step_id"' in raw_line:
            hits.append(line_no)
    if len(hits) >= step_count:
        return hits[:step_count]
    return [hits[i] if i < len(hits) else (i + 1) for i in range(step_count)]


def _looks_like_path(val: str, action_kind: str) -> bool:
    s = val.strip()
    if not s or "://" in s:
        return False
    if s.startswith(("/", "./", "../", "~")):
        return True
    return action_kind in PATH_BEARING_ACTIONS


@dataclass(frozen=True)
class _ExtractedStepTargets:
    effective_action: str
    primary_sink_target: str
    candidate_paths: Tuple[str, ...]
    candidate_hosts: Tuple[str, ...]
    candidate_urls: Tuple[str, ...]
    explicit_targets: Tuple[str, ...]
    inferred_secrecy: FrozenSet[str]
    has_invalid_path: bool
    has_invalid_host: bool


def _extract_all_step_targets(step: Mapping[str, Any]) -> _ExtractedStepTargets:
    """Extract ALL paths, hosts, URLs, covert Markdown sinks, and implicit taint across step & arguments."""
    raw_action = str(step.get("action_kind") or step.get("tool_name") or "tool_call").strip()
    effective_action = raw_action

    raw_paths: List[str] = []
    raw_net_targets: List[str] = []
    raw_urls: List[str] = []
    explicit_targets: List[str] = []
    has_invalid_path = False
    has_invalid_host = False

    def _add_path_raw(val: Any) -> None:
        nonlocal has_invalid_path
        if val is None:
            return
        if not isinstance(val, str):
            has_invalid_path = True
            return
        s = val.strip()
        if not s:
            return
        normed = _normalize_posix_path(s)
        if not normed:
            has_invalid_path = True
        elif normed not in raw_paths:
            raw_paths.append(normed)

    def _add_net_raw(val: Any, is_full_url: bool = False) -> None:
        nonlocal has_invalid_host
        if val is None:
            return
        if not isinstance(val, str):
            has_invalid_host = True
            return
        s = val.strip()
        if not s:
            return
        raw_net_targets.append(s)
        if is_full_url or "://" in s:
            if s not in raw_urls:
                raw_urls.append(s)

    if step.get("target_path") is not None:
        _add_path_raw(step.get("target_path"))
    if step.get("target_domain") is not None:
        td = step.get("target_domain")
        if isinstance(td, str) and td.strip():
            _add_net_raw(td)
        elif not isinstance(td, str):
            has_invalid_host = True

    for top_key in ("sink_target", "target"):
        tval = step.get(top_key)
        if isinstance(tval, str) and tval.strip():
            st = tval.strip()
            if st not in explicit_targets:
                explicit_targets.append(st)
            if "://" in st or effective_action in EXTERNAL_SINK_ACTIONS:
                _add_net_raw(st, is_full_url=("://" in st))
            elif _looks_like_path(st, effective_action):
                _add_path_raw(st)

    args = step.get("arguments")
    rendered_blobs: List[str] = []
    if isinstance(step.get("rendered_markdown"), str):
        rendered_blobs.append(str(step["rendered_markdown"]))

    def _walk_args(obj: Any) -> None:
        if isinstance(obj, Mapping):
            for k, v in obj.items():
                kl = str(k).strip().lower()
                if kl in _PATH_ARG_KEYS and v is not None:
                    _add_path_raw(v)
                elif kl in _HOST_ARG_KEYS and v is not None:
                    is_u = kl in ("url", "uri", "endpoint", "webhook")
                    _add_net_raw(v, is_full_url=is_u)
                elif kl == "target" and isinstance(v, str) and v.strip():
                    vs = v.strip()
                    if vs not in explicit_targets:
                        explicit_targets.append(vs)
                    if "://" in vs or effective_action in EXTERNAL_SINK_ACTIONS:
                        _add_net_raw(vs, is_full_url=("://" in vs))
                    elif _looks_like_path(vs, effective_action) or effective_action in HIGH_INTEGRITY_MUTATION_ACTIONS:
                        if vs.startswith(("/", "./", "../", "~")):
                            _add_path_raw(vs)
                if isinstance(v, str) and "![" in v:
                    rendered_blobs.append(v)
                elif isinstance(v, (Mapping, list, tuple)):
                    _walk_args(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                if isinstance(item, str) and "![" in item:
                    rendered_blobs.append(item)
                elif isinstance(item, (Mapping, list, tuple)):
                    _walk_args(item)

    if isinstance(args, Mapping):
        _walk_args(args)

    # Extract covert Markdown external image URLs across ALL string arguments and rendered_markdown
    for blob in rendered_blobs:
        for m_img in _MARKDOWN_EXT_IMG_RE.finditer(blob):
            img_url = m_img.group(1)
            _add_net_raw(img_url, is_full_url=True)
            if effective_action not in EXTERNAL_SINK_ACTIONS:
                effective_action = "markdown_external_image"

    # Evaluate secret path taint & CI workflow elevation across ALL candidate paths
    inferred_secrecy: Set[str] = set()
    for p in raw_paths:
        if _SECRET_PATH_RE.search(p):
            if "id_rsa" in p or "id_ed25519" in p or "credentials" in p or ".npmrc" in p:
                inferred_secrecy.add("CREDENTIAL_STORE")
            else:
                inferred_secrecy.add("SECRET_ENV")
        if effective_action in ("file_write", "write_file") and _CI_WORKFLOW_PATH_RE.search(p):
            effective_action = "ci_workflow_write"

    candidate_hosts: List[str] = []
    for net_raw in raw_net_targets:
        parsed_h = _extract_host(net_raw)
        if not parsed_h:
            has_invalid_host = True
        elif parsed_h not in candidate_hosts:
            candidate_hosts.append(parsed_h)

    primary_sink = (
        str(step.get("sink_target") or step.get("target") or "").strip()
        or (raw_urls[0] if raw_urls else "")
        or (candidate_hosts[0] if candidate_hosts else "")
        or (raw_paths[0] if raw_paths else "")
        or str(step.get("tool_name") or "")
    )

    return _ExtractedStepTargets(
        effective_action=effective_action,
        primary_sink_target=primary_sink,
        candidate_paths=tuple(raw_paths),
        candidate_hosts=tuple(candidate_hosts),
        candidate_urls=tuple(raw_urls),
        explicit_targets=tuple(explicit_targets),
        inferred_secrecy=frozenset(inferred_secrecy),
        has_invalid_path=has_invalid_path,
        has_invalid_host=has_invalid_host,
    )


class TrajectoryDIFCGate:
    """Stateful Layer 6 verifier enforcing DIFC, Macaroon attenuation, schema pinning, and budgets."""

    def __init__(
        self,
        *,
        macaroon_key: Optional[bytes] = None,
        endorsement_key: Optional[bytes] = None,
        horizon_budgets: Optional[Mapping[str, float]] = None,
        fail_fast: bool = False,
    ) -> None:
        self._macaroon_key = macaroon_key
        self._endorsement_key = endorsement_key
        self._horizon_budgets = dict(DEFAULT_HORIZON_BUDGETS)
        if horizon_budgets:
            for k, v in horizon_budgets.items():
                fv = _parse_nonneg_finite_float(v)
                if fv is None:
                    raise ValueError(f"Configured horizon_budgets[{k!r}] must be a non-negative finite float")
                self._horizon_budgets[str(k)] = fv
        self._fail_fast = fail_fast

    def evaluate(
        self,
        trajectory: Mapping[str, Any],
        *,
        source_text: str = "",
    ) -> TrajectoryGateResult:
        return evaluate_trajectory_difc(
            trajectory,
            macaroon_key=self._macaroon_key,
            endorsement_key=self._endorsement_key,
            horizon_budgets=self._horizon_budgets,
            fail_fast=self._fail_fast,
            source_text=source_text,
        )


def _resolve_trusted_key_bytes(
    explicit_key: Optional[bytes],
    env_var_name: str,
    default_dev_seed: Optional[bytes] = None,
) -> Optional[bytes]:
    """Resolve HMAC verification key strictly from trusted parameter or environment — NEVER from trajectory."""
    if explicit_key is not None:
        return explicit_key
    env_hex = (os.environ.get(env_var_name) or "").strip()
    if env_hex:
        return bytes.fromhex(env_hex)
    return default_dev_seed


def evaluate_trajectory_difc(
    trajectory: Mapping[str, Any],
    *,
    macaroon_key: Optional[bytes] = None,
    endorsement_key: Optional[bytes] = None,
    horizon_budgets: Optional[Mapping[str, float]] = None,
    fail_fast: bool = False,
    source_text: str = "",
) -> TrajectoryGateResult:
    """Evaluate a multi-step agent trajectory against PG-TRAJ-001 .. PG-TRAJ-005."""
    if not isinstance(trajectory, Mapping):
        raise TypeError("trajectory must be a JSON object mapping")

    traj_id = str(trajectory.get("trajectory_id") or "traj-unnamed")
    steps_raw = trajectory.get("steps")
    if not isinstance(steps_raw, list):
        raise ValueError("trajectory['steps'] must be a list of step objects")

    # Security invariant: NEVER read verification keys from untrusted trajectory dict!
    eff_macaroon_key = _resolve_trusted_key_bytes(
        macaroon_key,
        "PROOFGATE_MACAROON_KEY_HEX",
        b"proofgate-default-macaroon-verification-key-v2",
    )
    assert eff_macaroon_key is not None

    eff_endorsement_key = _resolve_trusted_key_bytes(
        endorsement_key,
        "PROOFGATE_ENDORSEMENT_KEY_HEX",
        None,
    )

    budgets: Dict[str, float] = dict(DEFAULT_HORIZON_BUDGETS)
    if horizon_budgets:
        for k, v in horizon_budgets.items():
            fv = _parse_nonneg_finite_float(v)
            if fv is None:
                raise ValueError(f"horizon_budgets[{k!r}] must be a non-negative finite float")
            budgets[str(k)] = fv

    findings: List[Dict[str, Any]] = []
    violations: List[str] = []
    triggered_rules: List[str] = []

    def _record_violation(
        code: str,
        message: str,
        step_idx: int,
        line_no: int,
        snippet: str,
    ) -> None:
        rid = TRAJECTORY_RULE_IDS[code]
        if code not in violations:
            violations.append(code)
        if rid not in triggered_rules:
            triggered_rules.append(rid)
        findings.append({
            "code": code,
            "rule_id": rid,
            "message": message,
            "step_index": step_idx,
            "line": line_no,
            "column": 1,
            "snippet": snippet,
        })

    # Untrusted trajectory["horizon_budgets"] can ONLY monotonically tighten existing limits!
    raw_traj_budgets = trajectory.get("horizon_budgets")
    if raw_traj_budgets is not None:
        if not isinstance(raw_traj_budgets, Mapping):
            _record_violation(
                "KNAPSACK_HORIZON_BUDGET_EXCEEDED",
                "Trajectory header horizon_budgets must be a JSON object.",
                0,
                1,
                "trajectory.horizon_budgets",
            )
        else:
            for k, raw_val in raw_traj_budgets.items():
                k_str = str(k)
                parsed_b = _parse_nonneg_finite_float(raw_val)
                if parsed_b is None:
                    _record_violation(
                        "KNAPSACK_HORIZON_BUDGET_EXCEEDED",
                        f"Invalid non-finite, boolean, or negative trajectory horizon_budgets[{k_str!r}]={raw_val!r}.",
                        0,
                        1,
                        f"horizon_budgets[{k_str}]",
                    )
                elif k_str in budgets:
                    budgets[k_str] = min(budgets[k_str], parsed_b)
                else:
                    budgets[k_str] = parsed_b

    eff_fail_fast = bool(fail_fast or trajectory.get("fail_fast", False))

    init_sec = secrecy_join(trajectory.get("initial_secrecy_tags") or (), ())
    init_int = parse_integrity_level(trajectory.get("initial_integrity", "USER_EXPLICIT"))

    if isinstance(trajectory.get("root_macaroon"), Mapping):
        init_mac = MacaroonToken.from_dict(trajectory["root_macaroon"])
    else:
        default_scopes = trajectory.get("root_scopes") or [
            "read",
            "write",
            "network",
            "exec",
            "ci",
            "deploy",
            "iam",
            "payment",
        ]
        init_mac = mint_macaroon(
            eff_macaroon_key,
            identifier=f"mac:{traj_id}",
            nonce=f"nonce:{traj_id}",
            root_scopes=default_scopes,
            caveats=trajectory.get("root_caveats") or (),
        )

    pinned_digests: Dict[str, str] = {}
    if isinstance(trajectory.get("initial_tool_schemas"), Mapping):
        for tname, tschema in trajectory["initial_tool_schemas"].items():
            if isinstance(tschema, Mapping):
                pinned_digests[str(tname)] = compute_tool_schema_digest(tschema)

    cum_cost: Dict[str, float] = {k: 0.0 for k in budgets}
    artifact_labels: Dict[str, ArtifactTaintLabel] = {}
    used_nonces: Set[str] = set()
    schema_epoch = int(trajectory.get("initial_schema_epoch", 0))

    state = TrajectoryLatticeState(
        secrecy_tags=init_sec,
        integrity_level=init_int,
        capability_macaroon=init_mac,
        pinned_tool_digests=pinned_digests,
        cumulative_cost=cum_cost,
        schema_epoch=schema_epoch,
        artifact_labels=artifact_labels,
        used_endorsement_nonces=frozenset(),
    )

    step_lines = _locate_step_lines_in_json_source(source_text, len(steps_raw))
    step_traces: List[Dict[str, Any]] = []
    merkle_step_leaves: List[Dict[str, Any]] = []

    for idx, raw_step in enumerate(steps_raw):
        if not isinstance(raw_step, Mapping):
            raise ValueError(f"Step at index {idx} must be a JSON object")

        step_index = idx
        step_id = str(raw_step.get("step_id") or f"step-{step_index}")
        tool_name = str(raw_step.get("tool_name") or "unknown_tool").strip()
        line_no = step_lines[idx] if idx < len(step_lines) else (idx + 1)
        step_violations_here: List[str] = []

        pre_sec = state.secrecy_tags
        pre_int = state.integrity_level
        active_mac = state.capability_macaroon
        cur_digests = dict(state.pinned_tool_digests)
        cur_cost = dict(state.cumulative_cost)
        cur_artifacts = dict(state.artifact_labels)
        cur_epoch = state.schema_epoch

        extracted = _extract_all_step_targets(raw_step)
        effective_action = extracted.effective_action
        sink_target = extracted.primary_sink_target
        required_scope = str(raw_step.get("required_scope") or "").strip()
        snippet_txt = f"step[{step_index}] {tool_name} ({effective_action}) -> {sink_target}"

        # 0. Strict monotonic step_index == idx sequence check (blocks endorsement step_index replay)
        if "step_index" in raw_step and raw_step["step_index"] is not None:
            declared_idx = raw_step["step_index"]
            if isinstance(declared_idx, bool) or not isinstance(declared_idx, int) or declared_idx != idx:
                msg = (
                    f"Step {idx} ({tool_name}): declared step_index={declared_idx!r} does not match "
                    f"canonical trajectory position {idx}."
                )
                _record_violation("MACAROON_CAPABILITY_VIOLATION", msg, step_index, line_no, snippet_txt)
                step_violations_here.append("PG-TRAJ-003")

        # Parse actor_integrity once for authenticated reset & schema epoch checks
        actor_raw = raw_step.get("actor_integrity")
        actor_int = (
            parse_integrity_level(actor_raw)
            if actor_raw is not None
            else IntegrityLevel.UNTRUSTED_EXTERNAL
        )

        # Authenticated sub-agent ambient context isolation reset:
        # Unattested steps can NEVER raise integrity above pre_int or wipe ambient secrecy!
        if bool(raw_step.get("context_isolation_reset", False)):
            raw_reset_int = parse_integrity_level(raw_step.get("reset_integrity", "USER_EXPLICIT"))
            capped_reset_int = (
                raw_reset_int
                if actor_int == IntegrityLevel.TRUSTED_SYSTEM
                else integrity_meet(raw_reset_int, IntegrityLevel.USER_EXPLICIT)
            )
            attested_reset = (raw_step.get("orchestrator_attested_reset") is True) or (
                actor_int == IntegrityLevel.TRUSTED_SYSTEM
            )
            if attested_reset:
                work_sec: FrozenSet[str] = frozenset()
                work_int: IntegrityLevel = capped_reset_int
            else:
                work_sec = pre_sec
                work_int = integrity_meet(pre_int, capped_reset_int)
        else:
            work_sec = pre_sec
            work_int = pre_int

        # 1. PG-TRAJ-004: Tool-Schema Epoch Firewall (RFC 8785 JCS SHA-256)
        raw_schema = raw_step.get("tool_schema")
        if raw_schema is not None:
            if not isinstance(raw_schema, Mapping):
                msg = f"Step {step_index} ({tool_name}): malformed non-object tool_schema."
                _record_violation("MID_TRAJECTORY_SCHEMA_RUGPULL", msg, step_index, line_no, snippet_txt)
                step_violations_here.append("PG-TRAJ-004")
            else:
                new_digest = compute_tool_schema_digest(raw_schema)
                if tool_name not in cur_digests:
                    cur_digests[tool_name] = new_digest
                elif cur_digests[tool_name] != new_digest:
                    bump_flag = bool(raw_step.get("schema_epoch_bump", False))
                    cand_epoch_raw = raw_step.get("schema_epoch", cur_epoch)
                    cand_epoch = (
                        cand_epoch_raw
                        if (not isinstance(cand_epoch_raw, bool) and isinstance(cand_epoch_raw, int))
                        else cur_epoch
                    )
                    if bump_flag and actor_int == IntegrityLevel.TRUSTED_SYSTEM and cand_epoch > cur_epoch:
                        cur_digests[tool_name] = new_digest
                        cur_epoch = cand_epoch
                    else:
                        msg = (
                            f"Step {step_index} ({tool_name}): tool schema JCS SHA-256 mutated mid-trajectory "
                            f"({cur_digests[tool_name][:12]} -> {new_digest[:12]}) without TRUSTED_SYSTEM epoch bump."
                        )
                        _record_violation("MID_TRAJECTORY_SCHEMA_RUGPULL", msg, step_index, line_no, snippet_txt)
                        step_violations_here.append("PG-TRAJ-004")

        # 2. PG-TRAJ-003: Macaroon HMAC-SHA256 Attenuation & Split-Brain-Proof Caveat Verification
        mac_failed = False
        for att_cav in raw_step.get("attenuate_caveats") or ():
            if not isinstance(att_cav, Mapping):
                mac_failed = True
                _record_violation(
                    "MACAROON_CAPABILITY_VIOLATION",
                    f"Step {step_index}: malformed Macaroon caveat attenuation entry.",
                    step_index,
                    line_no,
                    snippet_txt,
                )
                step_violations_here.append("PG-TRAJ-003")
                break
            active_mac = active_mac.attenuate(att_cav)

        if not mac_failed and raw_step.get("step_macaroon") is not None:
            try:
                cand_mac = MacaroonToken.from_dict(raw_step["step_macaroon"])
            except (TypeError, ValueError) as exc:
                mac_failed = True
                _record_violation(
                    "MACAROON_CAPABILITY_VIOLATION",
                    f"Step {step_index}: invalid step_macaroon encoding ({exc}).",
                    step_index,
                    line_no,
                    snippet_txt,
                )
                step_violations_here.append("PG-TRAJ-003")
            else:
                prefix_len = len(active_mac.caveats)
                if (
                    cand_mac.identifier != active_mac.identifier
                    or cand_mac.nonce != active_mac.nonce
                    or cand_mac.root_scopes != active_mac.root_scopes
                    or len(cand_mac.caveats) < prefix_len
                    or cand_mac.caveats[:prefix_len] != active_mac.caveats
                ):
                    mac_failed = True
                    _record_violation(
                        "MACAROON_CAPABILITY_VIOLATION",
                        f"Step {step_index}: Macaroon caveat-stripping or root-escalation rollback detected.",
                        step_index,
                        line_no,
                        snippet_txt,
                    )
                    step_violations_here.append("PG-TRAJ-003")
                else:
                    active_mac = cand_mac

        if not mac_failed:
            v_mac = verify_macaroon(eff_macaroon_key, active_mac)
            if not v_mac.valid:
                mac_failed = True
                _record_violation(
                    "MACAROON_CAPABILITY_VIOLATION",
                    f"Step {step_index}: Macaroon cryptographic check failed ({v_mac.reason}).",
                    step_index,
                    line_no,
                    snippet_txt,
                )
                step_violations_here.append("PG-TRAJ-003")
            else:
                next_call_count = int(cur_cost.get("tool_calls", 0.0)) + 1
                auth_ok, auth_reason = check_macaroon_step_authorization(
                    active_mac,
                    tool_name=tool_name,
                    action_kind=effective_action,
                    required_scope=required_scope,
                    call_count_1based=next_call_count,
                    candidate_paths=extracted.candidate_paths,
                    candidate_hosts=extracted.candidate_hosts,
                    has_invalid_path=extracted.has_invalid_path,
                    has_invalid_host=extracted.has_invalid_host,
                )
                if not auth_ok:
                    _record_violation(
                        "MACAROON_CAPABILITY_VIOLATION",
                        f"Step {step_index}: Macaroon contextual caveat rejected step ({auth_reason}).",
                        step_index,
                        line_no,
                        snippet_txt,
                    )
                    step_violations_here.append("PG-TRAJ-003")

        # 3. DIFC Lattice Join (Secrecy) & Meet (Integrity) across Ambient + Scratchpad Channels
        max_hops = 0
        lineage_acc: List[str] = []
        for r_art in raw_step.get("read_artifacts") or ():
            art_key = str(r_art)
            lbl = cur_artifacts.get(art_key)
            if lbl is not None:
                work_sec = secrecy_join(work_sec, lbl.secrecy_tags)
                work_int = integrity_meet(work_int, lbl.integrity_level)
                max_hops = max(max_hops, lbl.hop_count)
                for origin in lbl.lineage:
                    if origin not in lineage_acc:
                        lineage_acc.append(origin)

        explicit_sec = raw_step.get("source_secrecy_tags") or ()
        post_sec = secrecy_join(work_sec, list(explicit_sec) + sorted(extracted.inferred_secrecy))
        if explicit_sec or extracted.inferred_secrecy:
            if step_id not in lineage_acc:
                lineage_acc.append(step_id)

        if raw_step.get("source_integrity") is not None:
            src_int = parse_integrity_level(raw_step["source_integrity"])
            post_int = integrity_meet(work_int, src_int)
        else:
            post_int = work_int

        raw_endorsement = raw_step.get("endorsement")
        has_ambiguous_target = extracted.has_invalid_host or extracted.has_invalid_path

        # 4. PG-TRAJ-001: Lethal Trifecta & Multi-Hop / Split-Payload Taint Laundering Gate
        if effective_action in EXTERNAL_SINK_ACTIONS and len(post_sec) > 0 and post_int <= IntegrityLevel.UNTRUSTED_EXTERNAL:
            endorsed_ok = False
            endorse_err = "NO_HUMAN_DECLASSIFICATION_ENDORSEMENT"
            if raw_endorsement is not None:
                endorsed_ok, nonce_used, endorse_err = verify_declassification_endorsement(
                    eff_endorsement_key,
                    raw_endorsement,
                    trajectory_id=traj_id,
                    step_index=step_index,
                    action_kind=effective_action,
                    sink_target=sink_target,
                    active_secrecy_tags=post_sec,
                    used_nonces=frozenset(used_nonces),
                    require_trifecta=True,
                    require_biba=(effective_action in HIGH_INTEGRITY_MUTATION_ACTIONS),
                    all_sink_urls=extracted.candidate_urls,
                    all_hosts=extracted.candidate_hosts,
                    all_paths=extracted.candidate_paths,
                    all_explicit_targets=extracted.explicit_targets,
                    has_ambiguous_target=has_ambiguous_target,
                )
                if endorsed_ok and nonce_used:
                    used_nonces.add(nonce_used)
            if not endorsed_ok:
                hop_note = f" via {max_hops}-hop scratchpad laundering" if max_hops > 0 else ""
                msg = (
                    f"Step {step_index} ({tool_name}): Lethal Trifecta exfiltration blocked on sink "
                    f"'{effective_action}' -> '{sink_target}' with secrecy={sorted(post_sec)}, "
                    f"integrity={post_int.name}{hop_note} ({endorse_err})."
                )
                _record_violation("LETHAL_TRIFECTA_EXFIL", msg, step_index, line_no, snippet_txt)
                step_violations_here.append("PG-TRAJ-001")

        # 5. PG-TRAJ-002: Biba Confused-Deputy High-Integrity Mutation Gate
        if effective_action in HIGH_INTEGRITY_MUTATION_ACTIONS and post_int < IntegrityLevel.USER_EXPLICIT:
            endorsed_biba = False
            biba_err = "NO_HUMAN_BIBA_ENDORSEMENT"
            if raw_endorsement is not None:
                endorsed_biba, nonce_used, biba_err = verify_declassification_endorsement(
                    eff_endorsement_key,
                    raw_endorsement,
                    trajectory_id=traj_id,
                    step_index=step_index,
                    action_kind=effective_action,
                    sink_target=sink_target,
                    active_secrecy_tags=post_sec,
                    used_nonces=frozenset(used_nonces),
                    require_trifecta=False,
                    require_biba=True,
                    all_sink_urls=extracted.candidate_urls,
                    all_hosts=extracted.candidate_hosts,
                    all_paths=extracted.candidate_paths,
                    all_explicit_targets=extracted.explicit_targets,
                    has_ambiguous_target=has_ambiguous_target,
                )
                if endorsed_biba and nonce_used:
                    used_nonces.add(nonce_used)
            if not endorsed_biba:
                msg = (
                    f"Step {step_index} ({tool_name}): Biba confused-deputy high-integrity mutation "
                    f"'{effective_action}' -> '{sink_target}' blocked at integrity={post_int.name} "
                    f"< USER_EXPLICIT ({biba_err})."
                )
                _record_violation("BIBA_CONFUSED_DEPUTY_MUTATION", msg, step_index, line_no, snippet_txt)
                step_violations_here.append("PG-TRAJ-002")

        # Propagate DIFC label into written intermediate scratchpad / memory artifacts
        for w_art in raw_step.get("write_artifacts") or ():
            w_key = str(w_art)
            prior = cur_artifacts.get(w_key)
            merged_sec = secrecy_join(prior.secrecy_tags, post_sec) if prior else post_sec
            merged_int = integrity_meet(prior.integrity_level, post_int) if prior else post_int
            next_hop = max(max_hops, prior.hop_count if prior else 0) + (
                1 if (merged_sec or merged_int < IntegrityLevel.USER_EXPLICIT) else 0
            )
            merged_lin = tuple(dict.fromkeys([*(prior.lineage if prior else ()), *lineage_acc, step_id]))
            cur_artifacts[w_key] = ArtifactTaintLabel(
                secrecy_tags=merged_sec,
                integrity_level=merged_int,
                hop_count=next_hop,
                lineage=merged_lin,
            )

        # 6. PG-TRAJ-005: Multi-Dimensional Knapsack Horizon Budget Gate (strict finite float hygiene)
        budget_exceeded_dims: List[str] = []
        raw_cost = raw_step.get("cost")
        if raw_cost is not None and not isinstance(raw_cost, Mapping):
            budget_exceeded_dims.append(f"cost:non_object({type(raw_cost).__name__})")
            cost_map: Dict[str, Any] = {}
        else:
            cost_map = dict(raw_cost) if isinstance(raw_cost, Mapping) else {}

        if "tool_calls" not in cost_map:
            cost_map["tool_calls"] = 1.0
        if "external_bytes" not in cost_map:
            cost_map["external_bytes"] = raw_step.get("external_bytes", 0.0)
        if "risk_score" not in cost_map:
            cost_map["risk_score"] = raw_step.get("risk_score", 1.0)

        for dim, delta_raw in cost_map.items():
            dim_key = str(dim)
            delta = _parse_nonneg_finite_float(delta_raw)
            if delta is None:
                budget_exceeded_dims.append(f"{dim_key}:invalid_cost({delta_raw!r})")
                continue
            new_total = cur_cost.get(dim_key, 0.0) + delta
            if not math.isfinite(new_total):
                budget_exceeded_dims.append(f"{dim_key}:float_overflow")
                continue
            cur_cost[dim_key] = new_total

        for dim, limit_val in budgets.items():
            actual_val = cur_cost.get(dim, 0.0)
            if actual_val > limit_val + 1e-9:
                budget_exceeded_dims.append(f"{dim}={actual_val:.2f}>{limit_val:.2f}")

        if budget_exceeded_dims:
            msg = (
                f"Step {step_index} ({tool_name}): cumulative trajectory horizon budget violation "
                f"({', '.join(budget_exceeded_dims)})."
            )
            _record_violation("KNAPSACK_HORIZON_BUDGET_EXCEEDED", msg, step_index, line_no, snippet_txt)
            step_violations_here.append("PG-TRAJ-005")

        state = TrajectoryLatticeState(
            secrecy_tags=post_sec,
            integrity_level=post_int,
            capability_macaroon=active_mac,
            pinned_tool_digests=cur_digests,
            cumulative_cost=cur_cost,
            schema_epoch=cur_epoch,
            artifact_labels=cur_artifacts,
            used_endorsement_nonces=frozenset(used_nonces),
        )

        step_verdict = "ACCEPT" if not step_violations_here else "REJECT"
        step_leaf = {
            "trajectory_id": traj_id,
            "step_index": step_index,
            "step_id": step_id,
            "tool_name": tool_name,
            "action_kind": effective_action,
            "sink_target": sink_target,
            "pre_secrecy": sorted(pre_sec),
            "post_secrecy": sorted(post_sec),
            "pre_integrity": pre_int.name,
            "post_integrity": post_int.name,
            "macaroon_sig_prefix": active_mac.signature_hex[:16],
            "effective_scopes": sorted(active_mac.effective_scopes()),
            "schema_epoch": cur_epoch,
            "cumulative_cost": {k: round(float(v), 6) for k, v in sorted(cur_cost.items())},
            "step_verdict": step_verdict,
            "triggered_rules": sorted(set(step_violations_here)),
        }
        step_traces.append(step_leaf)
        merkle_step_leaves.append(step_leaf)

        if step_violations_here and eff_fail_fast:
            break

    raw_leaf_bytes = [canonical_json_bytes(leaf) for leaf in merkle_step_leaves]
    tree = MerkleTree(raw_leaf_bytes)
    merkle_root = tree.root_hex
    inclusion_proofs = [
        {
            "leaf_index": i,
            "leaf_hash": hash_leaf(raw_leaf_bytes[i]).hex(),
            "audit_path": tree.inclusion_proof(i)["audit_path"],
        }
        for i in range(len(raw_leaf_bytes))
    ]
    consistency = (
        tree.consistency_proof(1, len(raw_leaf_bytes))
        if len(raw_leaf_bytes) >= 1
        else {"old_size": 0, "new_size": 0, "old_root": merkle_root, "new_root": merkle_root, "consistency_path": []}
    )

    overall_verdict = "ACCEPT" if not violations else "REJECT"
    primary_code = "TRAJECTORY_DIFC_ACCEPT" if not violations else violations[0]

    receipt_core = {
        "spec": "ProofGate-TrajectoryDIFC-Receipt-v2.0",
        "jcs_spec": "RFC-8785",
        "merkle_spec": "RFC-6962-Section-2.1",
        "trajectory_id": traj_id,
        "verdict": overall_verdict,
        "primary_code": primary_code,
        "triggered_rule_ids": triggered_rules,
        "tree_size": tree.size,
        "merkle_root": merkle_root,
        "consistency_from_step_1": consistency,
        "inclusion_proofs": inclusion_proofs,
    }
    receipt_jcs_sha256 = hashlib.sha256(canonical_json_bytes(receipt_core)).hexdigest()
    receipt = {
        **receipt_core,
        "receipt_id": "PGTRAJ-" + merkle_root[:12].upper(),
        "receipt_jcs_sha256": receipt_jcs_sha256,
    }

    return TrajectoryGateResult(
        trajectory_id=traj_id,
        verdict=overall_verdict,
        primary_code=primary_code,
        violations=violations,
        triggered_rule_ids=triggered_rules,
        steps_evaluated=len(step_traces),
        findings=findings,
        step_traces=step_traces,
        final_state=state.to_dict(),
        receipt=receipt,
    )


def evaluate_stateless_baseline(trajectory: Mapping[str, Any]) -> Dict[str, Any]:
    """Stateless per-step pattern/allowlist guardrail baseline (memoryless across trajectory steps).

    Models standard single-step pre-tool guardrails that inspect each tool invocation `(tool_name,
    arguments, single-step payload)` in isolation without cross-step DIFC lattice state, pinned
    historical tool-schema digests, Macaroon chain history, or cumulative horizon budgets.
    """
    steps = trajectory.get("steps") or []
    flagged_steps: List[int] = []
    reasons: List[str] = []

    for idx, raw_step in enumerate(steps):
        if not isinstance(raw_step, Mapping):
            continue
        extracted = _extract_all_step_targets(raw_step)
        args_blob = canonical_json_dumps(raw_step.get("arguments") or {})

        # 1. Single-step destructive command / literal private key / prompt-override regex in outbound args
        if _STATELESS_BAD_CMD_RE.search(args_blob):
            flagged_steps.append(idx)
            reasons.append("STATELESS_REGEX_MATCH")
            continue

        # 2. Single-step simultaneous secret-path read + external network sink in the exact same call
        if extracted.effective_action in EXTERNAL_SINK_ACTIONS and any(
            _SECRET_PATH_RE.search(p) for p in extracted.candidate_paths
        ):
            flagged_steps.append(idx)
            reasons.append("STATELESS_SAME_STEP_SECRET_SINK")
            continue

        # 3. Single-step oversize payload (> 32 KiB in a single call)
        cost_obj = raw_step.get("cost")
        raw_ext = (
            cost_obj.get("external_bytes", 0.0)
            if isinstance(cost_obj, Mapping)
            else raw_step.get("external_bytes", 0.0)
        )
        ext_b = _parse_nonneg_finite_float(raw_ext)
        if ext_b is None or ext_b > 32768.0:
            flagged_steps.append(idx)
            reasons.append("STATELESS_SINGLE_STEP_BYTES")
            continue

    verdict = "ACCEPT" if not flagged_steps else "REJECT"
    return {
        "trajectory_id": str(trajectory.get("trajectory_id") or "traj-unnamed"),
        "verdict": verdict,
        "flagged_steps": flagged_steps,
        "reasons": sorted(set(reasons)),
    }
