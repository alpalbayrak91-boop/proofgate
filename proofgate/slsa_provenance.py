"""in-toto Statement v1, SLSA Provenance v1.0, and DSSEv1 PAE HMAC-SHA256 attestation toolkit."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import datetime as _dt
import hashlib
import hmac
import json
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .muhur_rfc6962 import canonical_json_bytes

IN_TOTO_STATEMENT_V1_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1_TYPE = "https://slsa.dev/provenance/v1"
DSSE_IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
DEFAULT_BUILD_TYPE = "https://alpalbayrak91-boop.github.io/proofgate/build/v1"
DEFAULT_BUILDER_ID = "https://alpalbayrak91-boop.github.io/proofgate/builder/v1"


@dataclass(frozen=True)
class SLSAVerificationResult:
    verdict: str
    primary_code: str
    violations: List[str]
    payload_type: str
    subject_count: int
    statement_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_sha256_hex(digest: str) -> bool:
    if not isinstance(digest, str) or len(digest) != 64:
        return False
    try:
        raw = bytes.fromhex(digest)
    except ValueError:
        return False
    return len(raw) == 32


def build_in_toto_slsa_statement(
    subjects: Sequence[Mapping[str, Any]],
    *,
    build_type: str = DEFAULT_BUILD_TYPE,
    builder_id: str = DEFAULT_BUILDER_ID,
    builder_version: Optional[Mapping[str, str]] = None,
    external_parameters: Optional[Mapping[str, Any]] = None,
    internal_parameters: Optional[Mapping[str, Any]] = None,
    resolved_dependencies: Optional[Sequence[Mapping[str, Any]]] = None,
    byproducts: Optional[Sequence[Mapping[str, Any]]] = None,
    invocation_id: Optional[str] = None,
    started_on: Optional[str] = None,
    finished_on: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct a strict in-toto Statement v1 carrying a SLSA Provenance v1.0 predicate."""
    if not subjects:
        raise ValueError("in-toto Statement v1 requires at least one subject")

    norm_subjects: List[Dict[str, Any]] = []
    for sub in subjects:
        name = str(sub.get("name", "")).strip()
        digest_map = sub.get("digest") or {}
        sha256_hex = str(digest_map.get("sha256", "")).lower().strip()
        if not name:
            raise ValueError("each subject must define a non-empty 'name'")
        if not _validate_sha256_hex(sha256_hex):
            raise ValueError(f"subject '{name}' must define a valid 64-hex digest.sha256")
        norm_subjects.append({"name": name, "digest": {"sha256": sha256_hex}})

    now_iso = _utc_now_iso()
    start_ts = started_on or now_iso
    finish_ts = finished_on or now_iso
    inv_id = invocation_id or hashlib.sha256(
        canonical_json_bytes({"subjects": norm_subjects, "started_on": start_ts})
    ).hexdigest()[:24]

    build_def: Dict[str, Any] = {
        "buildType": str(build_type),
        "externalParameters": dict(external_parameters or {}),
        "internalParameters": dict(internal_parameters or {}),
        "resolvedDependencies": [dict(d) for d in (resolved_dependencies or ())],
    }

    builder_obj: Dict[str, Any] = {"id": str(builder_id)}
    if builder_version:
        builder_obj["version"] = {str(k): str(v) for k, v in builder_version.items()}

    run_details: Dict[str, Any] = {
        "builder": builder_obj,
        "metadata": {
            "invocationId": inv_id,
            "startedOn": start_ts,
            "finishedOn": finish_ts,
        },
        "byproducts": [dict(b) for b in (byproducts or ())],
    }

    return {
        "_type": IN_TOTO_STATEMENT_V1_TYPE,
        "subject": norm_subjects,
        "predicateType": SLSA_PROVENANCE_V1_TYPE,
        "predicate": {
            "buildDefinition": build_def,
            "runDetails": run_details,
        },
    }


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Compute DSSEv1 Pre-Authentication Encoding (PAE) bytes."""
    if not isinstance(payload_type, str) or not payload_type:
        raise ValueError("payload_type must be a non-empty string")
    pt_bytes = payload_type.encode("utf-8")
    raw_payload = bytes(payload)
    return b"DSSEv1 %d %b %d %b" % (len(pt_bytes), pt_bytes, len(raw_payload), raw_payload)


def dsse_sign_hmac_sha256(
    payload: bytes,
    key: bytes,
    *,
    payload_type: str = DSSE_IN_TOTO_PAYLOAD_TYPE,
    keyid: str = "",
) -> Dict[str, Any]:
    """Wrap raw payload bytes in a DSSEv1 envelope signed with HMAC-SHA256 over PAE."""
    if not key:
        raise ValueError("HMAC signing key must be non-empty")
    raw_payload = bytes(payload)
    pae_bytes = dsse_pae(payload_type, raw_payload)
    sig_bytes = hmac.new(bytes(key), pae_bytes, hashlib.sha256).digest()
    effective_keyid = keyid or ("sha256:" + hashlib.sha256(bytes(key)).hexdigest()[:16])
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(raw_payload).decode("ascii"),
        "signatures": [
            {
                "keyid": effective_keyid,
                "sig": base64.b64encode(sig_bytes).decode("ascii"),
            }
        ],
    }


def dsse_verify_hmac_sha256(
    envelope: Mapping[str, Any],
    key: bytes,
    *,
    expected_payload_type: Optional[str] = None,
    expected_keyid: Optional[str] = None,
) -> Optional[bytes]:
    """Verify a DSSEv1 HMAC-SHA256 envelope fail-closed; returns decoded payload bytes or None."""
    if not key or not isinstance(envelope, Mapping):
        return None
    payload_type = envelope.get("payloadType")
    payload_b64 = envelope.get("payload")
    sigs = envelope.get("signatures")
    if not isinstance(payload_type, str) or not payload_type:
        return None
    if expected_payload_type is not None and payload_type != expected_payload_type:
        return None
    if not isinstance(payload_b64, str) or not isinstance(sigs, list) or not sigs:
        return None

    try:
        raw_payload = base64.b64decode(payload_b64.encode("ascii"), validate=True)
    except Exception:
        return None

    pae_bytes = dsse_pae(payload_type, raw_payload)
    expected_mac = hmac.new(bytes(key), pae_bytes, hashlib.sha256).digest()

    for entry in sigs:
        if not isinstance(entry, Mapping):
            continue
        kid = entry.get("keyid", "")
        sig_b64 = entry.get("sig")
        if expected_keyid is not None and kid != expected_keyid:
            continue
        if not isinstance(sig_b64, str):
            continue
        try:
            sig_bytes = base64.b64decode(sig_b64.encode("ascii"), validate=True)
        except Exception:
            continue
        if len(sig_bytes) == 32 and hmac.compare_digest(sig_bytes, expected_mac):
            return raw_payload
    return None


def verify_slsa_provenance(
    envelope: Mapping[str, Any],
    key: bytes,
    *,
    expected_subjects: Optional[Mapping[str, str]] = None,
    expected_builder_id: Optional[str] = None,
    expected_keyid: Optional[str] = None,
) -> SLSAVerificationResult:
    """Fail-closed verifier for DSSEv1-signed in-toto Statement v1 + SLSA Provenance v1.0."""
    violations: List[str] = []
    raw_payload = dsse_verify_hmac_sha256(
        envelope,
        key,
        expected_payload_type=DSSE_IN_TOTO_PAYLOAD_TYPE,
        expected_keyid=expected_keyid,
    )
    if raw_payload is None:
        return SLSAVerificationResult(
            verdict="REJECT",
            primary_code="REJECT_SLSA_DSSE_SIGNATURE",
            violations=["REJECT_SLSA_DSSE_SIGNATURE"],
            payload_type=str(envelope.get("payloadType", "")) if isinstance(envelope, Mapping) else "",
            subject_count=0,
            statement_sha256="",
        )

    stmt_sha = hashlib.sha256(raw_payload).hexdigest()
    try:
        stmt = json.loads(raw_payload.decode("utf-8"))
    except Exception:
        return SLSAVerificationResult(
            verdict="REJECT",
            primary_code="REJECT_SLSA_INVALID_JSON",
            violations=["REJECT_SLSA_INVALID_JSON"],
            payload_type=DSSE_IN_TOTO_PAYLOAD_TYPE,
            subject_count=0,
            statement_sha256=stmt_sha,
        )

    if not isinstance(stmt, dict) or stmt.get("_type") != IN_TOTO_STATEMENT_V1_TYPE:
        violations.append("REJECT_SLSA_STATEMENT_TYPE")
    if not isinstance(stmt, dict) or stmt.get("predicateType") != SLSA_PROVENANCE_V1_TYPE:
        violations.append("REJECT_SLSA_PREDICATE_TYPE")

    subjects = stmt.get("subject") if isinstance(stmt, dict) else None
    actual_subjects: Dict[str, str] = {}
    if not isinstance(subjects, list) or not subjects:
        violations.append("REJECT_SLSA_EMPTY_SUBJECTS")
    else:
        for item in subjects:
            if not isinstance(item, Mapping):
                violations.append("REJECT_SLSA_MALFORMED_SUBJECT")
                continue
            nm = item.get("name")
            dig = item.get("digest")
            sha_hex = dig.get("sha256") if isinstance(dig, Mapping) else None
            if not isinstance(nm, str) or not nm or not isinstance(sha_hex, str) or not _validate_sha256_hex(sha_hex):
                violations.append("REJECT_SLSA_MALFORMED_SUBJECT")
                continue
            actual_subjects[nm] = sha_hex.lower()

    if expected_subjects is not None:
        for exp_name, exp_sha in expected_subjects.items():
            got = actual_subjects.get(exp_name)
            if got is None or got != exp_sha.lower():
                violations.append("REJECT_SLSA_SUBJECT_DIGEST_MISMATCH")
                break

    pred = stmt.get("predicate") if isinstance(stmt, dict) else None
    if not isinstance(pred, Mapping):
        violations.append("REJECT_SLSA_MALFORMED_PREDICATE")
    else:
        bdef = pred.get("buildDefinition")
        rdet = pred.get("runDetails")
        if not isinstance(bdef, Mapping) or not isinstance(bdef.get("buildType"), str) or not bdef.get("buildType"):
            violations.append("REJECT_SLSA_MISSING_BUILD_DEFINITION")
        if not isinstance(rdet, Mapping) or not isinstance(rdet.get("builder"), Mapping):
            violations.append("REJECT_SLSA_MISSING_RUN_DETAILS")
        else:
            got_bid = rdet["builder"].get("id")
            if not isinstance(got_bid, str) or not got_bid:
                violations.append("REJECT_SLSA_MISSING_BUILDER_ID")
            elif expected_builder_id is not None and got_bid != expected_builder_id:
                violations.append("REJECT_SLSA_BUILDER_ID_MISMATCH")

    unique_v = sorted(set(violations))
    if unique_v:
        return SLSAVerificationResult(
            verdict="REJECT",
            primary_code=unique_v[0],
            violations=unique_v,
            payload_type=DSSE_IN_TOTO_PAYLOAD_TYPE,
            subject_count=len(actual_subjects),
            statement_sha256=stmt_sha,
        )
    return SLSAVerificationResult(
        verdict="ACCEPT",
        primary_code="SLSA_PROVENANCE_VERIFIED",
        violations=[],
        payload_type=DSSE_IN_TOTO_PAYLOAD_TYPE,
        subject_count=len(actual_subjects),
        statement_sha256=stmt_sha,
    )
