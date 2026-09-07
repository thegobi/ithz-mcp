"""Operator-pinned attestations for memory, not model-generated authority.

The runtime may load a trust policy from ITHZ_MEMORY_TRUST_POLICY. The file,
process environment and signing keys MUST be outside the proposing agent's
write authority. No MCP method installs keys or issues signatures. An optional
cryptography dependency verifies Ed25519; missing configuration/dependency
leaves activation disabled. Signatures attest an identified review, not truth.
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical_json import dumps
from .hashing import stable_json_hash

TRUST_SCHEMA = "ithz_memory_trust_policy_v1"
SUPPORT_SCHEMA = "ithz_memory_support_receipt_v1"
AUTHORIZATION_SCHEMA = "ithz_memory_activation_authorization_v1"


def candidate_content_hash(record: dict[str, Any]) -> str:
    # Lifecycle state and receipts are envelopes. Every other field is bound,
    # including scope, evidence references, validity and supersession targets.
    return stable_json_hash({key: value for key, value in record.items() if key not in {
        "record_hash", "verification_state", "support_receipt", "activation_authorization",
    }})


def load_runtime_trust_policy() -> dict[str, Any] | None:
    path = os.environ.get("ITHZ_MEMORY_TRUST_POLICY", "")
    if not path:
        return None
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return policy if isinstance(policy, dict) and policy.get("schema") == TRUST_SCHEMA else None


def _signed_body(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "signature"}


def _verify_receipt(receipt: Any, policy: dict[str, Any], role: str,
                    record: dict[str, Any], now: datetime) -> tuple[dict[str, Any] | None, str]:
    from .memory_integrity import timestamp_instant

    if not isinstance(receipt, dict):
        return None, role + "_receipt_missing"
    schema = SUPPORT_SCHEMA if role == "support" else AUTHORIZATION_SCHEMA
    if receipt.get("schema") != schema:
        return None, role + "_receipt_schema_invalid"
    keys = policy.get("keys", {})
    key = keys.get(receipt.get("key_id")) if isinstance(keys, dict) else None
    if not isinstance(key, dict) or key.get("revoked") or role not in key.get("roles", []):
        return None, role + "_signer_untrusted"
    if record["scope"] not in key.get("scopes", []) or record["policy_class"] not in key.get("policy_classes", []):
        return None, role + "_signer_scope_forbidden"
    proposer = policy.get("proposer_principal")
    if not isinstance(proposer, str) or not proposer or record["created_by"] != proposer:
        return None, "runtime_proposer_binding_invalid"
    if not key.get("principal") or key["principal"] == proposer:
        return None, role + "_self_approval_forbidden"
    if receipt.get("candidate_hash") != candidate_content_hash(record) or receipt.get("scope") != record["scope"]:
        return None, role + "_candidate_binding_invalid"
    if receipt.get("rules_version") != policy.get("rules_version") or not policy.get("rules_version"):
        return None, role + "_rules_version_invalid"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None, "signature_verifier_unavailable"
    try:
        if not (timestamp_instant(receipt.get("issued_at")) <= now < timestamp_instant(receipt.get("expires_at"))):
            return None, role + "_receipt_not_current"
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key"], validate=True))
        public.verify(base64.b64decode(receipt["signature"], validate=True), dumps(_signed_body(receipt)).encode("utf-8"))
    except (ValueError, TypeError, KeyError, InvalidSignature):
        return None, role + "_signature_or_time_invalid"
    return key, ""


def verify_candidate_support(record: dict[str, Any], source_contents: dict[str, Any],
                             policy: dict[str, Any] | None, *, now: datetime | None = None) -> dict[str, Any]:
    try:
        return _verify_candidate_support(record, source_contents, policy, now=now)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return {"support_verdict": "insufficient", "activation_authorized": False,
                "independence_verified": False, "reasons": ["malformed_support_or_trust_policy"]}


def _verify_candidate_support(record: dict[str, Any], source_contents: dict[str, Any],
                             policy: dict[str, Any] | None, *, now: datetime | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"support_verdict": "insufficient", "activation_authorized": False,
                              "independence_verified": False, "reasons": []}
    if not isinstance(policy, dict) or policy.get("schema") != TRUST_SCHEMA:
        result["reasons"] = ["runtime_trust_policy_not_configured"]
        return result
    now = now or datetime.now(timezone.utc)
    support = record.get("support_receipt")
    signer, error = _verify_receipt(support, policy, "support", record, now)
    if error:
        result["reasons"].append(error)
        return result
    expected = {"event:" + value for value in record["source_event_ids"]} | {
        "artifact:" + value for value in record["source_artifact_hashes"]}
    bindings = support.get("evidence")
    if not isinstance(bindings, list) or not bindings or any(not isinstance(row, dict) for row in bindings):
        result["reasons"].append("support_evidence_required")
        return result
    if {row.get("id") for row in bindings} != expected or len(bindings) != len(expected):
        result["reasons"].append("support_evidence_binding_invalid")
    for row in bindings:
        source_id = row.get("id")
        content = source_contents.get(source_id)
        # Artifact content must be resolved by the runtime. A mentioned digest
        # or caller-supplied blob is never a substitute for available content.
        if content is None or row.get("sha256") != stable_json_hash(content):
            result["reasons"].append("support_source_content_missing_or_changed:" + str(source_id))
    if support.get("verification_method") not in {"human_evidence_review", "bounded_model_review", "deterministic_test_run"}:
        result["reasons"].append("support_verification_method_invalid")
    if support.get("verification_method") == "human_evidence_review" and signer.get("authority") != "human":
        result["reasons"].append("support_human_identity_required")
    if support.get("verification_method") == "deterministic_test_run":
        claim = record.get("claim")
        if not isinstance(claim, dict) or claim.get("type") != "test_run_passed":
            result["reasons"].append("deterministic_claim_type_invalid")
        else:
            evidence = source_contents.get("event:" + str(claim.get("event_id")), {})
            run = evidence.get("metadata", {}).get("test_run", {}) if isinstance(evidence, dict) else {}
            bound_fields = ("run_id", "revision", "suite", "output_sha256")
            valid = (all(isinstance(claim.get(k), str) and claim[k] and claim[k] == run.get(k) for k in bound_fields)
                     and type(run.get("exit_code")) is int and run["exit_code"] == 0
                     and type(run.get("failed")) is int and run["failed"] == 0
                     and type(run.get("passed")) is int and run["passed"] > 0
                     and record["statement"] == f"Test run {claim.get('run_id')} passed suite {claim.get('suite')} at revision {claim.get('revision')}."
                     and "event:" + str(claim.get("event_id")) in expected)
            if not valid:
                result["reasons"].append("deterministic_test_run_not_supported")
    relation = support.get("relation")
    if relation not in {"supports", "contradicts", "insufficient"}:
        result["reasons"].append("support_relation_invalid")
    if result["reasons"]:
        return result
    result["support_verdict"] = relation
    result["support_receipt_hash"] = stable_json_hash(support)
    if relation != "supports":
        result["reasons"].append("support_" + relation)
        return result
    authorization = record.get("activation_authorization")
    approver, error = _verify_receipt(authorization, policy, "activation", record, now)
    if error:
        result["reasons"].append(error)
        return result
    if authorization.get("support_receipt_hash") != result["support_receipt_hash"] or authorization.get("decision") != "activate":
        result["reasons"].append("activation_support_binding_invalid")
    if approver["principal"] == signer["principal"]:
        result["reasons"].append("activation_independent_approver_required")
    if record["policy_class"] == "hard" and (approver.get("authority") != "human" or authorization.get("approval_id") not in record["human_approval_ids"]):
        result["reasons"].append("hard_policy_verified_human_approval_required")
    if not result["reasons"]:
        result.update(activation_authorized=True, independence_verified=True,
                      authorization_receipt_hash=stable_json_hash(authorization))
    return result
