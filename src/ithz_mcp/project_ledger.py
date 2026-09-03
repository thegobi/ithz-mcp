from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .canonical_json import sanitize_json_value, sanitize_text
from .hashing import stable_json_hash
from .native_archive_store import (
    BLOCKED_CLAIM_LOG_PATH,
    CLAIM_LOG_PATH,
    PROJECT_LEDGER_SUMMARY_PATH,
    REPLICATION_PACK_LOG_PATH,
    REVIEWER_NOTE_LOG_PATH,
    archive_append_event,
    build_native_archive,
    extract_archive_file_bytes,
    project_archive_path,
)
from .safety import redaction_block_reason


def _load_jsonl(project: Path, inner_path: str, native_exe: str | None = None) -> list[dict[str, Any]]:
    try:
        data = extract_archive_file_bytes(project, inner_path, native_exe)
    except (FileNotFoundError, RuntimeError):
        return []
    rows = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            import json

            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _load_json(project: Path, inner_path: str, native_exe: str | None = None) -> dict[str, Any]:
    try:
        data = extract_archive_file_bytes(project, inner_path, native_exe)
    except (FileNotFoundError, RuntimeError):
        return {}
    try:
        import json

        loaded = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _ensure_archive(project: Path, native_exe: str | None = None) -> None:
    if not project_archive_path(project).exists():
        build_native_archive(project, native_exe)


def _clean_list(values: list[str] | None) -> list[str]:
    return sorted({sanitize_text(str(value)).strip() for value in (values or []) if str(value).strip()})


def _require_safe_text(text: str, field: str = "text") -> str:
    clean = sanitize_text(str(text)).strip()
    if not clean:
        raise ValueError(f"{field}_required")
    block = redaction_block_reason(clean)
    if block:
        raise ValueError(f"secret_like_{field}_blocked:{block}")
    return clean


def _slug(value: str, prefix: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    if not cleaned:
        cleaned = stable_json_hash(value)[:12]
    return f"{prefix}_{cleaned[:80]}"


def add_claim(
    project: Path,
    text: str,
    claim_id: str | None = None,
    scope: str = "project",
    supporting_gates: list[str] | None = None,
    status: str = "allowed_scoped",
    source: str = "project_ledger",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    _ensure_archive(project, native_exe)
    clean_text = _require_safe_text(text)
    clean_scope = sanitize_text(scope or "project")
    clean_status = sanitize_text(status or "allowed_scoped")
    clean_claim_id = sanitize_text(claim_id or _slug(clean_text, "claim"))
    metadata = {
        "type": "claim",
        "claim_id": clean_claim_id,
        "text": clean_text,
        "scope": clean_scope,
        "supporting_gates": _clean_list(supporting_gates),
        "status": clean_status,
    }
    event = archive_append_event(
        project,
        "claim",
        f"Claim: {clean_text}",
        source,
        ["claim", clean_status, clean_scope],
        native_exe,
        memory_zone,
        memory_zone_path,
        include_git,
        metadata,
    )
    return {"added": True, "claim_id": clean_claim_id, "record": metadata, "append": event}


def block_claim(
    project: Path,
    text: str,
    reason: str,
    claim_id: str | None = None,
    blocking_gates: list[str] | None = None,
    status: str = "blocked",
    source: str = "project_ledger",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    _ensure_archive(project, native_exe)
    clean_text = _require_safe_text(text)
    clean_reason = _require_safe_text(reason, "reason")
    clean_claim_id = sanitize_text(claim_id or _slug(clean_text, "blocked"))
    clean_status = sanitize_text(status or "blocked")
    metadata = {
        "type": "blocked_claim",
        "claim_id": clean_claim_id,
        "text": clean_text,
        "reason": clean_reason,
        "blocking_gates": _clean_list(blocking_gates),
        "status": clean_status,
    }
    event = archive_append_event(
        project,
        "blocked_claim",
        f"Blocked claim: {clean_text}. Reason: {clean_reason}",
        source,
        ["blocked_claim", clean_status],
        native_exe,
        memory_zone,
        memory_zone_path,
        include_git,
        metadata,
    )
    return {"blocked": True, "claim_id": clean_claim_id, "record": metadata, "append": event}


def create_replication_pack_record(
    project: Path,
    pack_id: str,
    witnesses: int = 0,
    positive: int = 0,
    negative_stop: int = 0,
    manifest_path: str = "",
    public_safe: bool = False,
    status: str = "recorded",
    source: str = "project_ledger",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    _ensure_archive(project, native_exe)
    clean_pack_id = _require_safe_text(pack_id, "pack_id")
    clean_manifest = sanitize_text(manifest_path or "")
    if clean_manifest and redaction_block_reason(clean_manifest):
        raise ValueError("secret_like_manifest_path_blocked")
    metadata = {
        "type": "replication_pack",
        "pack_id": clean_pack_id,
        "witnesses": int(witnesses),
        "positive": int(positive),
        "negative_stop": int(negative_stop),
        "manifest_path": clean_manifest,
        "public_safe": bool(public_safe),
        "status": sanitize_text(status or "recorded"),
    }
    text = (
        f"Replication pack {clean_pack_id}: witnesses={metadata['witnesses']} "
        f"positive={metadata['positive']} negative_stop={metadata['negative_stop']} status={metadata['status']}"
    )
    event = archive_append_event(project, "replication_pack", text, source, ["replication_pack", metadata["status"]], native_exe, memory_zone, memory_zone_path, include_git, metadata)
    return {"created": True, "pack_id": clean_pack_id, "record": metadata, "append": event}


def add_reviewer_note(
    project: Path,
    text: str,
    target: str,
    note_id: str | None = None,
    severity: str = "guidance",
    source: str = "project_ledger",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    _ensure_archive(project, native_exe)
    clean_text = _require_safe_text(text)
    clean_target = _require_safe_text(target, "target")
    clean_note_id = sanitize_text(note_id or _slug(f"{clean_target} {clean_text}", "reviewer"))
    metadata = {
        "type": "reviewer_note",
        "note_id": clean_note_id,
        "target": clean_target,
        "text": clean_text,
        "severity": sanitize_text(severity or "guidance"),
    }
    event = archive_append_event(project, "reviewer_note", f"Reviewer note for {clean_target}: {clean_text}", source, ["reviewer_note", metadata["severity"]], native_exe, memory_zone, memory_zone_path, include_git, metadata)
    return {"added": True, "note_id": clean_note_id, "record": metadata, "append": event}


def list_allowed_claims(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    rows = _load_jsonl(project, CLAIM_LOG_PATH, native_exe)
    return {"schema": "ithz_mcp_allowed_claims_v1", "claim_count": len(rows), "rows": rows}


def list_blocked_claims(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    rows = _load_jsonl(project, BLOCKED_CLAIM_LOG_PATH, native_exe)
    return {"schema": "ithz_mcp_blocked_claims_v1", "blocked_claim_count": len(rows), "rows": rows}


def project_ledger_summary(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    summary = _load_json(project, PROJECT_LEDGER_SUMMARY_PATH, native_exe)
    if not summary:
        summary = {
            "schema": "ithz_mcp_project_ledger_summary_v1",
            "claim_count": len(_load_jsonl(project, CLAIM_LOG_PATH, native_exe)),
            "blocked_claim_count": len(_load_jsonl(project, BLOCKED_CLAIM_LOG_PATH, native_exe)),
            "replication_pack_count": len(_load_jsonl(project, REPLICATION_PACK_LOG_PATH, native_exe)),
            "reviewer_note_count": len(_load_jsonl(project, REVIEWER_NOTE_LOG_PATH, native_exe)),
        }
    return summary


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9_]+", text.lower()) if len(token) > 2}


def _overlap(query: str, text: str) -> float:
    qt = _tokens(query)
    tt = _tokens(text)
    if not qt or not tt:
        return 0.0
    return len(qt & tt) / max(1, len(qt))


def _best_match(query: str, rows: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, float]:
    best: dict[str, Any] | None = None
    best_score = 0.0
    q_lower = query.lower()
    for row in rows:
        hay = " ".join(str(row.get(k, "")) for k in ("claim_id", "text", "reason", "scope", "status"))
        score = 1.0 if str(row.get("claim_id", "")).lower() in q_lower and row.get("claim_id") else _overlap(query, hay)
        if score > best_score:
            best = row
            best_score = score
    return best, best_score


def get_claim_evidence(project: Path, query: str, native_exe: str | None = None) -> dict[str, Any]:
    clean_query = _require_safe_text(query, "query")
    claims = _load_jsonl(project, CLAIM_LOG_PATH, native_exe)
    blocked = _load_jsonl(project, BLOCKED_CLAIM_LOG_PATH, native_exe)
    allowed_match, allowed_score = _best_match(clean_query, claims)
    blocked_match, blocked_score = _best_match(clean_query, blocked)
    return sanitize_json_value(
        {
            "query": clean_query,
            "allowed_match": allowed_match,
            "allowed_match_score": round(allowed_score, 4),
            "blocked_match": blocked_match,
            "blocked_match_score": round(blocked_score, 4),
            "supporting_gates": allowed_match.get("supporting_gates", []) if allowed_match else [],
            "blocking_gates": blocked_match.get("blocking_gates", []) if blocked_match else [],
        }
    )


def can_i_claim(project: Path, query: str, native_exe: str | None = None) -> dict[str, Any]:
    evidence = get_claim_evidence(project, query, native_exe)
    blocked = evidence.get("blocked_match")
    allowed = evidence.get("allowed_match")
    blocked_score = float(evidence.get("blocked_match_score", 0.0))
    allowed_score = float(evidence.get("allowed_match_score", 0.0))
    if isinstance(blocked, dict) and blocked_score >= max(0.35, allowed_score):
        return {
            "query": evidence["query"],
            "can_claim": False,
            "status": "blocked",
            "reason": blocked.get("reason", "blocked_claim_match"),
            "blocked_by": blocked.get("blocking_gates", []),
            "blocked_claim": blocked,
            "allowed_alternative": allowed,
        }
    if isinstance(allowed, dict) and allowed_score >= 0.35:
        return {
            "query": evidence["query"],
            "can_claim": True,
            "status": allowed.get("status", "allowed_scoped"),
            "supporting_gates": allowed.get("supporting_gates", []),
            "allowed_claim": allowed,
        }
    return {
        "query": evidence["query"],
        "can_claim": False,
        "status": "not_found_needs_evidence",
        "reason": "No deterministic allowed claim was found in project.ithz.",
        "allowed_alternative": allowed,
        "blocked_claim": blocked,
    }
