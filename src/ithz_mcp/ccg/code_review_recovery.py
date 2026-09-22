"""Explicit, one-use operator recovery. Never changes accepted model verdicts."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from . import code_review as cr
from .models import BackendError, safe_backend_diagnostic

AUTH = "recovery.json"
USED = "recovery-used.json"
FAILED = "recovery-failure.json"
CONSUMED = "recovery-consumed.attempt"


def read_sealed(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("receipt_hash") != cr.digest({key: item for key, item in value.items() if key != "receipt_hash"}):
            raise ValueError("recovery_chain_integrity_invalid")
        return value
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("recovery_chain_integrity_invalid") from exc


def chain(directory: Path, packet: dict[str, Any], planned: dict[str, Any]) -> dict[str, Any] | None:
    """Revalidate every original and new link, including deleted-link detection."""
    authorization = directory / AUTH
    if not authorization.exists():
        if any((directory / name).exists() for name in (USED, FAILED, CONSUMED)):
            raise ValueError("recovery_authorization_missing")
        # A recovered receipt must never be accepted after authorization deletion.
        for path in directory.glob("part-*.json"):
            if path.name.endswith(".failure.json"):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError, UnicodeError):
                continue
            if isinstance(data, dict) and data.get("recovery_hash"):
                raise ValueError("recovery_authorization_missing")
        integration = directory / "integration.json"
        if integration.exists():
            try:
                data = json.loads(integration.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("recovery_hash"):
                    raise ValueError("recovery_authorization_missing")
            except (json.JSONDecodeError, OSError, UnicodeError) as exc:
                raise ValueError("recovery_chain_integrity_invalid") from exc
        return None
    value = read_sealed(authorization)
    keys = {"schema", "packet_hash", "manifest_hash", "target", "request_hash", "authorization_id", "reason",
            "original_marker", "original_marker_hash", "original_failure", "diagnostic", "prior_receipts",
            "maximum_additional_attempts", "receipt_hash"}
    if (set(value) != keys or type(value.get("maximum_additional_attempts")) is not int
            or value["maximum_additional_attempts"] != 1 or not isinstance(value.get("prior_receipts"), dict)
            or any(not isinstance(value.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", value[key])
                   for key in ("packet_hash", "manifest_hash", "request_hash", "original_marker_hash"))
            or not isinstance(value.get("authorization_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value["authorization_id"])
            or not isinstance(value.get("reason"), str) or not 1 <= len(value["reason"].strip()) <= 500
            or value.get("diagnostic") != safe_backend_diagnostic(BackendError("diagnostic", diagnostic=value.get("diagnostic")))):
        raise ValueError("recovery_authorization_shape_invalid")
    if (value.get("schema") != cr.VERSION or value.get("packet_hash") != cr.digest(packet)
            or value.get("manifest_hash") != planned["manifest_hash"]
            or not re.fullmatch(r"(?:part-\d{4}|integration)\.json", str(value.get("target", "")))):
        raise ValueError("recovery_binding_invalid")
    target = directory / value["target"]
    if target.exists() and (directory / FAILED).exists():
        raise ValueError("recovery_multiple_outcomes")
    try:
        marker = target.with_suffix(".attempt").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError("recovery_original_marker_missing") from exc
    if marker != value.get("original_marker") or cr.digest(marker) != value.get("original_marker_hash") or marker != value.get("request_hash"):
        raise ValueError("recovery_original_marker_changed")
    failure = target.with_suffix(".failure.json")
    if value.get("original_failure") is not None:
        if read_sealed(failure) != value["original_failure"]:
            raise ValueError("recovery_original_failure_changed")
    elif failure.exists():
        raise ValueError("recovery_original_failure_changed")
    names = [f"part-{part['index']:04d}.json" for part in planned["parts"]] + ["integration.json"]
    if value["target"] not in names:
        raise ValueError("recovery_binding_invalid")
    index = names.index(value["target"])
    if set(value["prior_receipts"]) != set(names[:index]):
        raise ValueError("recovery_prior_receipt_changed")
    prior = []
    for name, expected_hash in value["prior_receipts"].items():
        receipt = read_sealed(directory / name)
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or receipt.get("receipt_hash") != expected_hash:
            raise ValueError("recovery_prior_receipt_changed")
        prior.append(receipt)
    from . import code_review_parts as parts
    if value["target"] == "integration.json":
        if any(not isinstance(item.get("review"), dict) or not isinstance(item["review"].get("data"), dict) for item in prior):
            raise ValueError("recovery_prior_receipt_changed")
        requests = parts.integration_request(packet, planned, [parts.report_for(read_sealed(directory / name), i) for i, name in enumerate(names[:-1])])
    else:
        requests = planned["parts"][index]
    if cr.digest(requests) != value["request_hash"]:
        raise ValueError("recovery_binding_invalid")
    used = directory / USED
    consumed = directory / CONSUMED
    if used.exists():
        try:
            if consumed.read_text(encoding="utf-8") != value["receipt_hash"]:
                raise ValueError("recovery_consumption_invalid")
        except (OSError, UnicodeError) as exc:
            raise ValueError("recovery_consumption_missing") from exc
        usage = read_sealed(used)
        if (set(usage) != {"schema", "authorization_hash", "request_hash", "receipt_hash"}
                or usage.get("schema") != cr.VERSION
                or usage.get("authorization_hash") != value["receipt_hash"] or usage.get("request_hash") != value["request_hash"]):
            raise ValueError("recovery_consumption_invalid")
    elif target.exists() or (directory / FAILED).exists() or consumed.exists():
        raise ValueError("recovery_consumption_missing")
    if target.exists():
        receipt = read_sealed(target)
        if receipt.get("recovery_hash") != value["receipt_hash"]:
            raise ValueError("recovery_result_binding_invalid")
    if (directory / FAILED).exists():
        failed = read_sealed(directory / FAILED)
        if (set(failed) != {"schema", "packet_hash", "manifest_hash", "request_hash", "diagnostic", "authorization_hash", "receipt_hash"}
                or failed.get("schema") != cr.VERSION or failed.get("packet_hash") != cr.digest(packet)
                or failed.get("manifest_hash") != planned["manifest_hash"]
                or failed.get("diagnostic") != safe_backend_diagnostic(BackendError("diagnostic", diagnostic=failed.get("diagnostic")))
                or failed.get("authorization_hash") != value["receipt_hash"] or failed.get("request_hash") != value["request_hash"]):
            raise ValueError("recovery_failure_binding_invalid")
    return value


def authorize_recovery(project: Path, packet: dict[str, Any], snapshot: Callable[[], dict[str, Any]], *,
                       expected_manifest_hash: str, request_hash: str, authorization_id: str, reason: str) -> dict[str, Any]:
    """Operator-only entry point; does not call a model or consume authorization."""
    from . import code_review_parts as parts
    if not isinstance(authorization_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", authorization_id):
        raise ValueError("invalid_recovery_authorization_id")
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
        raise ValueError("invalid_recovery_reason")
    cr.safe_text("operator-authorization.json", parts.encoded({"authorization_id": authorization_id, "reason": reason}))
    planned = parts.plan(packet)
    if planned["manifest_hash"] != expected_manifest_hash or snapshot() != packet:
        raise ValueError("recovery_evidence_changed")
    directory = parts.directory_for(project, planned)
    lock = directory / "review.lock"
    try:
        with lock.open("x"):
            pass
    except FileExistsError as exc:
        raise ValueError("review_in_progress_or_interrupted") from exc
    try:
        if any((directory / name).exists() for name in (AUTH, USED, FAILED, CONSUMED)):
            raise ValueError("recovery_already_authorized_or_consumed")
        if json.loads((directory / "manifest.json").read_text(encoding="utf-8")) != planned["manifest"]:
            raise ValueError("manifest_integrity_invalid")
        prior, reports = {}, []
        requests = [(f"part-{part['index']:04d}.json", part) for part in planned["parts"]]
        selected = None
        for index in range(len(requests) + 1):
            name, request = requests[index] if index < len(requests) else ("integration.json", parts.integration_request(packet, planned, reports))
            path = directory / name
            if cr.digest(request) == request_hash:
                if path.exists():
                    raise ValueError("accepted_response_cannot_be_recovered")
                selected = (name, request)
                break
            receipt, errors = parts.read_receipt(path, packet, request, planned)
            if errors:
                raise ValueError("prior_review_missing_or_blocking")
            prior[name] = receipt["receipt_hash"]
            reports.append(parts.report_for(receipt, index))
        if selected is None:
            raise ValueError("recovery_request_not_in_manifest")
        name, request = selected
        target = directory / name
        try:
            original = target.with_suffix(".attempt").read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValueError("recovery_original_marker_missing") from exc
        if original != request_hash:
            raise ValueError("recovery_original_marker_changed")
        failure_path = target.with_suffix(".failure.json")
        original_failure = read_sealed(failure_path) if failure_path.exists() else None
        if original_failure and (original_failure.get("request_hash") != request_hash or original_failure.get("manifest_hash") != planned["manifest_hash"]):
            raise ValueError("recovery_failure_binding_invalid")
        value = {"schema": cr.VERSION, "packet_hash": cr.digest(packet), "manifest_hash": planned["manifest_hash"],
                 "target": name, "request_hash": request_hash, "authorization_id": authorization_id, "reason": reason,
                 "original_marker": original, "original_marker_hash": cr.digest(original), "original_failure": original_failure,
                 "diagnostic": original_failure["diagnostic"] if original_failure else {"category": "legacy_failure_diagnostic_unavailable"},
                 "prior_receipts": prior, "maximum_additional_attempts": 1}
        if snapshot() != packet:
            raise ValueError("recovery_evidence_changed")
        parts.atomic_write(directory / AUTH, value)
        return {"authorized": True, "authorization_hash": read_sealed(directory / AUTH)["receipt_hash"],
                "request_hash": request_hash, "model_runs": 0, "diagnostic": value["diagnostic"]}
    finally:
        lock.unlink(missing_ok=True)
