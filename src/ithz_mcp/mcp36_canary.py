from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty
from .hashing import stable_json_hash


CANARY_VERSION = "mcp36.4-opt-in-canary-v1"
CONFIG_SCHEMA = "mcp36_canary_config_v1"
RECEIPT_SCHEMA = "mcp36_canary_case_receipt_v1"
RESERVATION_SCHEMA = "mcp36_canary_slot_reservation_v1"
MAX_CANARY_CASES = 25
MAX_CANARY_HOURS = 168


class CanaryGateError(ValueError):
    """Raised before model execution when the opt-in canary is not admissible."""


def _utc_now(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CanaryGateError("canary_config_invalid_expiry") from exc
    if parsed.tzinfo is None:
        raise CanaryGateError("canary_config_invalid_expiry")
    return parsed.astimezone(timezone.utc)


def _control_dir(project: Path) -> Path:
    return project.resolve() / ".ccg" / "mcp36-canary"


def _config_path(project: Path) -> Path:
    return _control_dir(project) / "config.json"


def _config_hash(config: dict[str, Any]) -> str:
    material = {key: value for key, value in config.items() if key != "config_hash"}
    return stable_json_hash(material)


def _rollout_hash(config: dict[str, Any]) -> str:
    return stable_json_hash(
        {
            key: config.get(key)
            for key in (
                "schema",
                "version",
                "mode",
                "rollout_id",
                "enabled_at",
                "expires_at",
                "max_cases",
                "allowed_capabilities",
                "allowed_risks",
                "require_cross_lab",
                "provider_usage_required",
                "fresh_case_required",
                "capability_tokens_forbidden",
                "ithz_mirror",
                "external_writes",
            )
        }
    )


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(dump_pretty(value), encoding="utf-8")
    os.replace(temporary, path)


def _load_config(project: Path) -> dict[str, Any] | None:
    path = _config_path(project)
    if not path.exists():
        return None
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CanaryGateError("canary_config_unreadable") from exc
    if not isinstance(config, dict) or config.get("schema") != CONFIG_SCHEMA:
        raise CanaryGateError("canary_config_schema_invalid")
    if config.get("version") != CANARY_VERSION:
        raise CanaryGateError("canary_config_version_invalid")
    if config.get("config_hash") != _config_hash(config):
        raise CanaryGateError("canary_config_hash_mismatch")
    if config.get("rollout_hash") != _rollout_hash(config):
        raise CanaryGateError("canary_rollout_hash_mismatch")
    if config.get("state") not in {"active", "paused"}:
        raise CanaryGateError("canary_config_state_invalid")
    if config.get("allowed_capabilities") != ["analysis.read"]:
        raise CanaryGateError("canary_config_capability_scope_invalid")
    if (
        config.get("mode") != "shadow-read-only"
        or config.get("ithz_mirror") is not False
        or config.get("external_writes") is not False
        or config.get("capability_tokens_forbidden") is not True
    ):
        raise CanaryGateError("canary_config_write_boundary_invalid")
    if (
        config.get("require_cross_lab") is not True
        or config.get("provider_usage_required") is not True
        or config.get("fresh_case_required") is not True
    ):
        raise CanaryGateError("canary_config_review_boundary_invalid")
    if config.get("allowed_risks") != ["low", "medium", "high", "critical"]:
        raise CanaryGateError("canary_config_risk_scope_invalid")
    max_cases = config.get("max_cases")
    if not isinstance(max_cases, int) or isinstance(max_cases, bool) or not 1 <= max_cases <= MAX_CANARY_CASES:
        raise CanaryGateError("canary_config_max_cases_invalid")
    _parse_iso(str(config.get("expires_at", "")))
    return config


def enable_canary(
    project: Path,
    *,
    max_cases: int = 5,
    expires_hours: int = 24,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Explicitly opt a local project into one bounded MCP36.4 rollout."""

    if isinstance(max_cases, bool) or not isinstance(max_cases, int) or not 1 <= max_cases <= MAX_CANARY_CASES:
        raise CanaryGateError(f"canary_max_cases_must_be_1_to_{MAX_CANARY_CASES}")
    if isinstance(expires_hours, bool) or not isinstance(expires_hours, int) or not 1 <= expires_hours <= MAX_CANARY_HOURS:
        raise CanaryGateError(f"canary_expires_hours_must_be_1_to_{MAX_CANARY_HOURS}")
    current = _utc_now(now)
    config: dict[str, Any] = {
        "schema": CONFIG_SCHEMA,
        "version": CANARY_VERSION,
        "state": "active",
        "mode": "shadow-read-only",
        "rollout_id": f"canary-{current.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}",
        "enabled_at": _iso(current),
        "expires_at": _iso(current + timedelta(hours=expires_hours)),
        "max_cases": max_cases,
        "allowed_capabilities": ["analysis.read"],
        "allowed_risks": ["low", "medium", "high", "critical"],
        "require_cross_lab": True,
        "provider_usage_required": True,
        "fresh_case_required": True,
        "capability_tokens_forbidden": True,
        "ithz_mirror": False,
        "external_writes": False,
    }
    config["rollout_hash"] = _rollout_hash(config)
    config["config_hash"] = _config_hash(config)
    _atomic_write(_config_path(project), config)
    return canary_status(project, now=current)


def pause_canary(project: Path, *, now: datetime | None = None) -> dict[str, Any]:
    config = _load_config(project)
    if config is None:
        raise CanaryGateError("canary_not_configured")
    config = dict(config)
    config["state"] = "paused"
    config["paused_at"] = _iso(_utc_now(now))
    config["config_hash"] = _config_hash(config)
    _atomic_write(_config_path(project), config)
    return canary_status(project, now=now)


def _rollout_dir(project: Path, rollout_id: str) -> Path:
    if not rollout_id.startswith("canary-") or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-TZ" for char in rollout_id):
        raise CanaryGateError("canary_rollout_id_invalid")
    return _control_dir(project) / "rollouts" / rollout_id


def _read_slot(path: Path, expected_schema: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CanaryGateError("canary_telemetry_unreadable") from exc
    if not isinstance(value, dict) or value.get("schema") != expected_schema:
        raise CanaryGateError("canary_telemetry_schema_invalid")
    hash_key = "reservation_hash" if expected_schema == RESERVATION_SCHEMA else "receipt_hash"
    expected_hash = stable_json_hash({key: item for key, item in value.items() if key != hash_key})
    if value.get(hash_key) != expected_hash:
        raise CanaryGateError("canary_telemetry_hash_mismatch")
    return value


def _slot_status(project: Path, config: dict[str, Any]) -> dict[str, Any]:
    slots = _rollout_dir(project, str(config["rollout_id"])) / "slots"
    reservations: list[dict[str, Any]] = []
    completed: list[dict[str, Any]] = []
    if slots.exists():
        for slot in sorted(slots.glob("slot-*")):
            reservation_path = slot / "reservation.json"
            if not reservation_path.exists():
                raise CanaryGateError("canary_slot_missing_reservation")
            reservation = _read_slot(reservation_path, RESERVATION_SCHEMA)
            if reservation.get("rollout_id") != config["rollout_id"] or reservation.get("rollout_hash") != config["rollout_hash"]:
                raise CanaryGateError("canary_slot_config_binding_mismatch")
            reservations.append(reservation)
            receipt_path = slot / "receipt.json"
            if receipt_path.exists():
                receipt = _read_slot(receipt_path, RECEIPT_SCHEMA)
                if receipt.get("reservation_hash") != reservation["reservation_hash"]:
                    raise CanaryGateError("canary_receipt_reservation_binding_mismatch")
                completed.append(receipt)
    return {
        "reserved_cases": len(reservations),
        "completed_cases": len(completed),
        "indeterminate_cases": len(reservations) - len(completed),
        "remaining_slots": max(0, int(config["max_cases"]) - len(reservations)),
        "latest_receipt_hash": completed[-1]["receipt_hash"] if completed else None,
    }


def canary_status(project: Path, *, now: datetime | None = None) -> dict[str, Any]:
    current = _utc_now(now)
    base: dict[str, Any] = {
        "schema": "mcp36_canary_status_v1",
        "version": CANARY_VERSION,
        "project": str(project.resolve()),
        "configured": False,
        "active": False,
        "eligible": False,
        "default_off": True,
        "mode": "shadow-read-only",
        "allowed_capabilities": ["analysis.read"],
        "capability_tokens_forbidden": True,
        "ithz_mirror": False,
        "external_writes": False,
        "telemetry_valid": True,
    }
    try:
        config = _load_config(project)
        if config is None:
            return {**base, "reason": "canary_not_configured", "remaining_slots": 0}
        slots = _slot_status(project, config)
        expired = current >= _parse_iso(str(config["expires_at"]))
        active = config["state"] == "active" and not expired and slots["remaining_slots"] > 0
        reason = (
            "canary_paused"
            if config["state"] == "paused"
            else "canary_expired"
            if expired
            else "canary_case_limit_reached"
            if slots["remaining_slots"] == 0
            else "canary_active"
        )
        return {
            **base,
            **slots,
            "configured": True,
            "active": active,
            "eligible": active,
            "reason": reason,
            "state": config["state"],
            "rollout_id": config["rollout_id"],
            "enabled_at": config["enabled_at"],
            "expires_at": config["expires_at"],
            "max_cases": config["max_cases"],
            "require_cross_lab": True,
            "provider_usage_required": True,
            "fresh_case_required": True,
            "config_hash": config["config_hash"],
            "rollout_hash": config["rollout_hash"],
        }
    except CanaryGateError as exc:
        return {
            **base,
            "configured": _config_path(project).exists(),
            "reason": str(exc),
            "telemetry_valid": False,
            "remaining_slots": 0,
        }


def canary_admission(
    project: Path,
    *,
    risk: str,
    capability: str,
    cross_lab_provider: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    status = canary_status(project, now=now)
    if not status["telemetry_valid"]:
        raise CanaryGateError(str(status["reason"]))
    if not status["configured"]:
        raise CanaryGateError("canary_not_configured")
    if not status["active"]:
        raise CanaryGateError(str(status["reason"]))
    if capability != "analysis.read":
        raise CanaryGateError("canary_capability_must_be_analysis_read")
    if risk not in {"low", "medium", "high", "critical"}:
        raise CanaryGateError("canary_risk_invalid")
    if cross_lab_provider not in {"gemini", "grok"}:
        raise CanaryGateError("canary_cross_lab_provider_must_be_gemini_or_grok")
    return {
        "schema": "mcp36_canary_admission_v1",
        "admitted": True,
        "rollout_id": status["rollout_id"],
        "config_hash": status["config_hash"],
        "rollout_hash": status["rollout_hash"],
        "risk": risk,
        "capability": capability,
        "cross_lab_provider": cross_lab_provider,
        "mode": "shadow-read-only",
        "ithz_mirror": False,
        "capability_tokens_forbidden": True,
    }


def reserve_canary_slot(project: Path, admission: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    current = _utc_now(now)
    refreshed = canary_admission(
        project,
        risk=str(admission["risk"]),
        capability=str(admission["capability"]),
        cross_lab_provider=str(admission["cross_lab_provider"]),
        now=current,
    )
    if refreshed["config_hash"] != admission["config_hash"]:
        raise CanaryGateError("canary_config_changed_before_reservation")
    config = _load_config(project)
    assert config is not None
    slots = _rollout_dir(project, str(config["rollout_id"])) / "slots"
    slots.mkdir(parents=True, exist_ok=True)
    for number in range(1, int(config["max_cases"]) + 1):
        slot = slots / f"slot-{number:03d}"
        try:
            slot.mkdir()
        except FileExistsError:
            continue
        reservation: dict[str, Any] = {
            "schema": RESERVATION_SCHEMA,
            "version": CANARY_VERSION,
            "rollout_id": config["rollout_id"],
            "config_hash": config["config_hash"],
            "rollout_hash": config["rollout_hash"],
            "slot": number,
            "reserved_at": _iso(current),
            "admission_hash": stable_json_hash(admission),
        }
        reservation["reservation_hash"] = stable_json_hash(reservation)
        _atomic_write(slot / "reservation.json", reservation)
        return {**admission, **reservation, "slot_path": str(slot)}
    raise CanaryGateError("canary_case_limit_reached")


def record_canary_receipt(project: Path, reservation: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    if result.get("capability_token") is not None or result.get("authorization") is not None:
        raise CanaryGateError("canary_postflight_authorization_present")
    if result.get("advisory_only") is not True:
        raise CanaryGateError("canary_postflight_not_advisory")
    if result.get("model_runs") != 5:
        raise CanaryGateError("canary_postflight_model_run_count_invalid")
    if result.get("cross_lab_quorum") is not True:
        raise CanaryGateError("canary_postflight_cross_lab_quorum_missing")
    usage = result.get("provider_usage")
    if not isinstance(usage, dict) or usage.get("complete") is not True or usage.get("metered_model_calls") != 5:
        raise CanaryGateError("canary_postflight_provider_usage_incomplete")
    mirror = result.get("ithz_mirror")
    if not isinstance(mirror, dict) or mirror.get("mirrored") is not False or mirror.get("reason") != "mcp36_canary_read_only":
        raise CanaryGateError("canary_postflight_ithz_mirror_boundary_failed")
    diversity = result.get("evidence_diversity_receipt")
    # A canary may honestly complete a metered process with an evidence gap; the
    # court must then return REQUEST_EVIDENCE.  Reject only a malformed or leaky
    # evidence-view process here, and preserve sufficiency in the receipt.
    if not isinstance(diversity, dict) or diversity.get("structurally_valid") is not True:
        raise CanaryGateError("canary_postflight_evidence_diversity_invalid")
    slot_path = Path(str(reservation.get("slot_path", ""))).resolve()
    expected_parent = (_rollout_dir(project, str(reservation["rollout_id"])) / "slots").resolve()
    if slot_path.parent != expected_parent or not slot_path.exists():
        raise CanaryGateError("canary_reservation_path_invalid")
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "version": CANARY_VERSION,
        "rollout_id": reservation["rollout_id"],
        "config_hash": reservation["config_hash"],
        "rollout_hash": reservation["rollout_hash"],
        "slot": reservation["slot"],
        "reservation_hash": reservation["reservation_hash"],
        "case_id": result["case_id"],
        "evidence_hash": result["evidence_hash"],
        "decision_material_hash": result["decision_material_hash"],
        "evidence_diversity_receipt_hash": stable_json_hash(diversity),
        "evidence_sufficient": diversity.get("evidence_sufficient") is True,
        "final_verdict": result["final_verdict"],
        "cross_lab_quorum": True,
        "provider_usage_hash": stable_json_hash(usage),
        "provider_usage_complete": True,
        "model_runs": 5,
        "advisory_only": True,
        "capability_token_issued": False,
        "ithz_mirrored": False,
        "external_write_performed": False,
    }
    receipt["receipt_hash"] = stable_json_hash(receipt)
    receipt_path = slot_path / "receipt.json"
    try:
        with receipt_path.open("x", encoding="utf-8") as handle:
            handle.write(dump_pretty(receipt))
    except FileExistsError as exc:
        raise CanaryGateError("canary_receipt_already_exists") from exc
    return receipt


def run_canary_control_selftest() -> dict[str, Any]:
    """Pure local control-plane test. Court integration is covered by unit tests."""

    import tempfile

    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory)
        rows.append({"test": "default_off", "passed": canary_status(project)["reason"] == "canary_not_configured"})
        enabled = enable_canary(project, max_cases=1, expires_hours=1)
        rows.append({"test": "explicit_enable", "passed": enabled["active"] and enabled["remaining_slots"] == 1})
        admission = canary_admission(
            project,
            risk="high",
            capability="analysis.read",
            cross_lab_provider="gemini",
        )
        reservation = reserve_canary_slot(project, admission)
        rows.append({"test": "atomic_slot_reservation", "passed": reservation["slot"] == 1})
        rows.append({"test": "case_limit_fail_closed", "passed": canary_status(project)["reason"] == "canary_case_limit_reached"})
        paused = pause_canary(project)
        rows.append({"test": "kill_switch", "passed": paused["state"] == "paused" and not paused["active"]})
    return {
        "schema": "mcp36_4_canary_control_selftest_v1",
        "version": CANARY_VERSION,
        "rows": rows,
        "passed": all(bool(row["passed"]) for row in rows),
        "external_model_calls": 0,
        "external_writes": 0,
    }
