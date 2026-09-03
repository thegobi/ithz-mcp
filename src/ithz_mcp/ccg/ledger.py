from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..canonical_json import dump_pretty, dumps
from ..hashing import stable_json_hash
from ..safety import redaction_block_reason


LEDGER_SCHEMA = "ccg_ithz_evidence_ledger_v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ccg_root(project: Path) -> Path:
    return project.resolve() / ".ithz-ccg"


def new_case_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"ccg_{stamp}_{uuid.uuid4().hex[:10]}"


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(dump_pretty(value), encoding="utf-8")
    os.replace(tmp, path)


@contextmanager
def _exclusive_lock(path: Path, timeout_seconds: float = 8.0) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    descriptor: int | None = None
    while descriptor is None:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(descriptor, dumps({"pid": os.getpid(), "created_at": utc_now()}).encode("utf-8"))
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"ccg_ledger_lock_timeout:{path}")
            time.sleep(0.05)
        except PermissionError:
            # Windows may report an O_EXCL race as EACCES while the competing
            # handle is not yet observable through Path.exists(). Treat it as
            # transient contention only on Windows; real persistent denial still
            # fails closed as a bounded lock timeout.
            if os.name != "nt":
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(f"ccg_ledger_lock_timeout:{path}")
            time.sleep(0.05)
    try:
        yield
    finally:
        os.close(descriptor)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _validate_safe_payload(payload: Any) -> None:
    reason = redaction_block_reason(dumps(payload))
    if reason:
        raise ValueError(f"ccg_payload_redaction_blocked:{reason}")


class EvidenceLedger:
    """Append-only, hash-linked local evidence store for CCG court cases."""

    def __init__(self, project: Path) -> None:
        self.project = project.resolve()
        self.root = ccg_root(self.project)

    def initialize(self) -> dict[str, Any]:
        for relative in ("cases", "private", "chambers"):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        return {"schema": LEDGER_SCHEMA, "root": str(self.root), "exists": True}

    def case_dir(self, case_id: str) -> Path:
        if not case_id.startswith("ccg_") or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in case_id):
            raise ValueError("invalid_case_id")
        return self.root / "cases" / case_id

    def create_case(
        self,
        evidence: dict[str, Any],
        constitution: dict[str, Any],
        role_plan: dict[str, Any],
        case_id: str | None = None,
    ) -> str:
        self.initialize()
        selected = case_id or new_case_id()
        directory = self.case_dir(selected)
        with _exclusive_lock(self.root / ".create.lock"):
            if directory.exists():
                raise ValueError("case_already_exists")
            directory.mkdir(parents=True)
            _validate_safe_payload(evidence)
            _validate_safe_payload(constitution)
            _atomic_json(directory / "evidence.json", evidence)
            _atomic_json(directory / "constitution.json", constitution)
            _atomic_json(
                directory / "manifest.json",
                {
                    "schema": LEDGER_SCHEMA,
                    "case_id": selected,
                    "created_at": utc_now(),
                    "status": "OPEN",
                    "evidence_hash": evidence["evidence_hash"],
                    "constitution_hash": evidence["constitution_hash"],
                    "decision_material_hash": evidence.get("decision_material_hash", ""),
                    "case_family_hash": evidence.get("case_family_hash", ""),
                    "template_set_hash": evidence.get("template_set_hash", ""),
                    "role_plan": role_plan,
                },
            )
        self.append(
            selected,
            "case_opened",
            {
                "role_plan": role_plan,
                "evidence_hash": evidence["evidence_hash"],
                "decision_material_hash": evidence.get("decision_material_hash", ""),
            },
        )
        with (self.root / "index.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(
                dumps(
                    {
                        "case_id": selected,
                        "created_at": utc_now(),
                        "status": "OPEN",
                        "evidence_hash": evidence["evidence_hash"],
                        "decision_material_hash": evidence.get("decision_material_hash", ""),
                    }
                )
                + "\n"
            )
        return selected

    def append(self, case_id: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        directory = self.case_dir(case_id)
        if not directory.exists():
            raise ValueError("unknown_case")
        _validate_safe_payload(payload)
        path = directory / "events.jsonl"
        with _exclusive_lock(directory / ".events.lock"):
            rows = self.events(case_id)
            previous = rows[-1]["event_hash"] if rows else "0" * 64
            event = {
                "schema": LEDGER_SCHEMA,
                "sequence": len(rows) + 1,
                "timestamp": utc_now(),
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous,
            }
            event["event_hash"] = stable_json_hash(event)
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(dumps(event) + "\n")
        return event

    def events(self, case_id: str) -> list[dict[str, Any]]:
        path = self.case_dir(case_id) / "events.jsonl"
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"corrupt_ccg_ledger_line:{line_number}:{exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"corrupt_ccg_ledger_event:{line_number}")
            rows.append(value)
        return rows

    def store_role_result(self, case_id: str, result: dict[str, Any]) -> None:
        role = str(result["role"])
        _validate_safe_payload(result)
        path = self.case_dir(case_id) / "roles" / f"{role}.json"
        _atomic_json(path, result)
        self.append(
            case_id,
            "role_completed",
            {
                "role": role,
                "provider": result["provider"],
                "model": result["model"],
                "thread_id": result["thread_id"],
                "duration_ms": result["duration_ms"],
                "usage": result.get("usage", {}),
                "result_hash": stable_json_hash(result["data"]),
                "evidence_hash": result["data"].get("evidence_hash", ""),
                "template_hash": result.get("template_hash", ""),
            },
        )

    def finalize(self, case_id: str, final: dict[str, Any]) -> None:
        _validate_safe_payload(final)
        directory = self.case_dir(case_id)
        _atomic_json(directory / "final.json", final)
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        manifest["status"] = final["final_verdict"]
        manifest["completed_at"] = utc_now()
        manifest["final_hash"] = stable_json_hash(final)
        _atomic_json(directory / "manifest.json", manifest)
        self.append(
            case_id,
            "case_finalized",
            {
                "final_verdict": final["final_verdict"],
                "final_hash": manifest["final_hash"],
                "cross_lab_quorum": final["cross_lab_quorum"],
                "authorization_issued": bool(final.get("authorization")),
            },
        )

    def read_case(self, case_id: str, include_events: bool = True) -> dict[str, Any]:
        directory = self.case_dir(case_id)
        if not directory.exists():
            raise ValueError("unknown_case")
        result: dict[str, Any] = {}
        for name in ("manifest", "evidence", "constitution", "final"):
            path = directory / f"{name}.json"
            if path.exists():
                result[name] = json.loads(path.read_text(encoding="utf-8"))
        roles: dict[str, Any] = {}
        for path in sorted((directory / "roles").glob("*.json")) if (directory / "roles").exists() else []:
            roles[path.stem] = json.loads(path.read_text(encoding="utf-8"))
        result["roles"] = roles
        if include_events:
            result["events"] = self.events(case_id)
        return result

    def list_cases(self, limit: int = 20) -> list[dict[str, Any]]:
        if not (self.root / "cases").exists():
            return []
        rows = []
        for directory in sorted((self.root / "cases").iterdir(), key=lambda item: item.name, reverse=True):
            manifest = directory / "manifest.json"
            if manifest.is_file():
                rows.append(json.loads(manifest.read_text(encoding="utf-8")))
            if len(rows) >= limit:
                break
        return rows

    def find_reusable_case(self, decision_material_hash: str) -> dict[str, Any] | None:
        """Find a verified original decision that issued no executable authorization."""
        if not decision_material_hash:
            return None
        for manifest in self.list_cases(500):
            if manifest.get("decision_material_hash") != decision_material_hash:
                continue
            case_id = str(manifest.get("case_id", ""))
            try:
                case = self.read_case(case_id, include_events=False)
                final = case.get("final") or {}
                if final.get("reused_decision") or final.get("authorization"):
                    continue
                verification = self.verify(case_id)
                if not verification["valid"]:
                    continue
                return {
                    "case_id": case_id,
                    "manifest": case.get("manifest", {}),
                    "final": final,
                    "verification": verification,
                }
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        return None

    def verify(self, case_id: str) -> dict[str, Any]:
        errors: list[str] = []
        previous = "0" * 64
        rows = self.events(case_id)
        for expected_sequence, event in enumerate(rows, start=1):
            if event.get("sequence") != expected_sequence:
                errors.append(f"sequence_mismatch:{expected_sequence}")
            if event.get("previous_hash") != previous:
                errors.append(f"previous_hash_mismatch:{expected_sequence}")
            body = {key: value for key, value in event.items() if key != "event_hash"}
            expected_hash = stable_json_hash(body)
            if event.get("event_hash") != expected_hash:
                errors.append(f"event_hash_mismatch:{expected_sequence}")
            previous = str(event.get("event_hash", ""))
        case = self.read_case(case_id, include_events=False)
        manifest = case.get("manifest", {})
        evidence = case.get("evidence", {})
        if evidence:
            body = {key: value for key, value in evidence.items() if key != "evidence_hash"}
            if evidence.get("evidence_hash") != stable_json_hash(body):
                errors.append("evidence_hash_mismatch")
        for role, result in case.get("roles", {}).items():
            if result.get("data", {}).get("evidence_hash") != evidence.get("evidence_hash"):
                errors.append(f"role_evidence_hash_mismatch:{role}")
        if manifest:
            if manifest.get("evidence_hash") != evidence.get("evidence_hash"):
                errors.append("manifest_evidence_hash_mismatch")
            material_hash = evidence.get("decision_material_hash", "")
            if manifest.get("decision_material_hash", "") != material_hash:
                errors.append("manifest_decision_material_hash_mismatch")
        final = case.get("final", {})
        if final and manifest.get("final_hash") != stable_json_hash(final):
            errors.append("final_hash_mismatch")
        if final.get("reused_decision"):
            source_case_id = str(final.get("source_case_id", ""))
            if not source_case_id or source_case_id == case_id:
                errors.append("reuse_source_invalid")
            else:
                try:
                    source = self.read_case(source_case_id, include_events=False)
                    source_final = source.get("final", {})
                    source_verification = self.verify(source_case_id)
                    if not source_verification["valid"]:
                        errors.append("reuse_source_ledger_invalid")
                    if source.get("evidence", {}).get("decision_material_hash") != evidence.get("decision_material_hash"):
                        errors.append("reuse_material_hash_mismatch")
                    if final.get("source_final_hash") != stable_json_hash(source_final):
                        errors.append("reuse_source_final_hash_mismatch")
                    if final.get("authorization") or final.get("approved_action"):
                        errors.append("reuse_must_not_copy_authorization")
                except (OSError, ValueError, json.JSONDecodeError):
                    errors.append("reuse_source_unreadable")
        return {
            "schema": LEDGER_SCHEMA,
            "case_id": case_id,
            "valid": not errors,
            "event_count": len(rows),
            "head_hash": previous,
            "errors": errors,
        }
