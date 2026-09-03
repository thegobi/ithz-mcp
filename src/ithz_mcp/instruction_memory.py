from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty
from .hashing import stable_json_hash
from .native_archive_store import archive_append_events, build_native_archive, extract_archive_file_bytes, project_archive_path, resolve_memory_zone
from .safety import redaction_block_reason


INSTRUCTION_LOG_PATHS = {
    "workflow_rule": "instructions/workflow_rules.jsonl",
    "project_decision": "instructions/project_decisions.jsonl",
    "gate_rule": "instructions/gate_rules.jsonl",
    "risk_rule": "instructions/risk_rules.jsonl",
}
INSTRUCTION_INDEX_PATH = "instructions/instruction_index.json"
EVENT_KIND_BY_TYPE = {
    "workflow_rule": "workflow_rule",
    "project_decision": "decision",
    "gate_rule": "gate",
    "risk_rule": "risk",
}
ID_PREFIX_BY_TYPE = {
    "workflow_rule": "wr",
    "project_decision": "dec",
    "gate_rule": "gate",
    "risk_rule": "risk",
}


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        for row in rows
    )


def _load_jsonl(project: Path, inner_path: str, native_exe: str | None = None) -> list[dict[str, Any]]:
    try:
        data = extract_archive_file_bytes(project, inner_path, native_exe)
    except RuntimeError as exc:
        if "path not found" in str(exc):
            return []
        raise
    return [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]


def _classify_instruction(text: str) -> str:
    lower = text.lower()
    if re.search(r"\b(decision|rozhodnutie|rozhodni|pouzijeme|pouzivame|use .* as|project uses)\b", lower):
        return "project_decision"
    if re.search(r"\b(gate|test|tests|prejde|passed|failed|run-ci|self-test|pred commitom|before commit|validat)\b", lower):
        return "gate_rule"
    if re.search(r"\b(risk|rizik|nesmie|neskladuj|neukladaj|must not|do not|secret|token|password|private key|ssh key|ssh kluc|ssh kluce|ssh kľúč|credential)\b", lower):
        return "risk_rule"
    return "workflow_rule"


def _split_instruction_text(text: str) -> list[str]:
    rows: list[str] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        line = re.sub(r"^[-*]\s+", "", line)
        line = re.sub(r"^\d+[.)]\s+", "", line)
        if line:
            rows.append(line)
    return rows or [text.strip()]


def _instruction_index(all_rows: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    searchable = []
    counts = {}
    latest = {}
    for instruction_type in sorted(all_rows):
        rows = sorted(all_rows[instruction_type], key=lambda r: r.get("instruction_id", ""))
        counts[instruction_type] = len(rows)
        if rows:
            latest[instruction_type] = rows[-1].get("instruction_id", "")
        for row in rows:
            searchable.append(
                {
                    "instruction_id": row.get("instruction_id", ""),
                    "instruction_type": instruction_type,
                    "profile": row.get("profile", ""),
                    "scope": row.get("scope", ""),
                    "text": str(row.get("text", ""))[:1000],
                    "source": row.get("source", ""),
                    "tags": row.get("tags", []),
                    "semantic_instruction_hash": row.get("semantic_instruction_hash", ""),
                }
            )
    index = {
        "schema": "ithz_mcp_durable_instruction_index_v1",
        "counts_by_type": dict(sorted(counts.items())),
        "latest_by_type": dict(sorted(latest.items())),
        "searchable_units": searchable,
    }
    index["instruction_index_hash"] = stable_json_hash(index)
    return index


def record_durable_instruction(
    project: Path,
    instruction_type: str,
    text: str,
    profile: str = "default",
    scope: str = "project",
    source: str = "user_instruction",
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    return record_durable_instructions(
        project,
        [
            {
                "instruction_type": instruction_type,
                "text": text,
                "profile": profile,
                "scope": scope,
                "source": source,
                "tags": tags or [],
                "metadata": metadata or {},
            }
        ],
        native_exe=native_exe,
        memory_zone=memory_zone,
        memory_zone_path=memory_zone_path,
        include_git=include_git,
    )


def record_durable_instructions(
    project: Path,
    instructions: list[dict[str, Any]],
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    if not instructions:
        raise ValueError("at_least_one_instruction_required")
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    if not project_archive_path(active_root).exists():
        build_native_archive(active_root, native_exe)
    all_rows = {
        instruction_type: _load_jsonl(active_root, path, native_exe)
        for instruction_type, path in INSTRUCTION_LOG_PATHS.items()
    }
    records: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for spec in instructions:
        instruction_type = str(spec.get("instruction_type", "workflow_rule"))
        if instruction_type not in INSTRUCTION_LOG_PATHS:
            raise ValueError(f"unsupported_instruction_type:{instruction_type}")
        text = str(spec.get("text", "")).strip()
        if not text:
            raise ValueError("instruction text is required")
        block_reason = redaction_block_reason(text)
        if block_reason:
            raise ValueError(f"secret_like_instruction_blocked:{block_reason}")
        profile = str(spec.get("profile", "default"))
        scope = str(spec.get("scope", "project"))
        source = str(spec.get("source", "user_instruction"))
        tags = sorted(str(t) for t in spec.get("tags", []) if str(t))
        metadata = spec.get("metadata") if isinstance(spec.get("metadata"), dict) else {}
        semantic_hash = stable_json_hash(
            {
                "instruction_type": instruction_type,
                "profile": profile,
                "scope": scope,
                "source": source,
                "tags": tags,
                "text": text,
                "metadata": metadata,
            }
        )
        existing = [row for row in all_rows[instruction_type] if row.get("semantic_instruction_hash") == semantic_hash]
        if existing:
            records.append({**existing[0], "deduplicated": True})
            continue
        prefix = ID_PREFIX_BY_TYPE[instruction_type]
        instruction_id = f"{prefix}_{len(all_rows[instruction_type]) + 1:06d}"
        record = {
            "schema": "ithz_mcp_durable_instruction_v1",
            "instruction_id": instruction_id,
            "instruction_type": instruction_type,
            "profile": profile,
            "scope": scope,
            "source": source,
            "tags": tags,
            "text": text,
            "metadata": metadata,
            "semantic_instruction_hash": semantic_hash,
        }
        all_rows[instruction_type].append(record)
        records.append(record)
        events.append(
            {
                "kind": EVENT_KIND_BY_TYPE[instruction_type],
                "text": text,
                "source": source,
                "tags": sorted({*tags, instruction_type, profile}),
                "metadata": {
                    "instruction_id": instruction_id,
                    "instruction_type": instruction_type,
                    "profile": profile,
                    "scope": scope,
                    "semantic_instruction_hash": semantic_hash,
                },
            }
        )
    index = _instruction_index(all_rows)
    extra_updates = {
        path: _jsonl_bytes(all_rows[instruction_type])
        for instruction_type, path in INSTRUCTION_LOG_PATHS.items()
    }
    extra_updates[INSTRUCTION_INDEX_PATH] = dump_pretty(index).encode("utf-8")
    if events:
        append = archive_append_events(
            active_root,
            events,
            native_exe=native_exe,
            memory_zone="current",
            include_git=include_git,
            extra_updates=extra_updates,
            manifest_extra={
                "durable_instruction_count": sum(len(rows) for rows in all_rows.values()),
                "instruction_index_hash": index["instruction_index_hash"],
            },
        )
    else:
        append = {"appended": False, "active_memory_zone": active_zone.active_memory_zone, "events": [], "event_count": None, "update": None}
    return {
        "recorded": True,
        "active_memory_zone": active_zone.active_memory_zone,
        "records": records,
        "new_record_count": len(events),
        "deduplicated_count": sum(1 for r in records if r.get("deduplicated")),
        "instruction_index_hash": index["instruction_index_hash"],
        "append": append,
    }


def ingest_user_instruction(
    project: Path,
    text: str,
    profile: str = "default",
    scope: str = "project",
    source: str = "user_instruction",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    instructions = []
    for line in _split_instruction_text(text):
        instructions.append(
            {
                "instruction_type": _classify_instruction(line),
                "text": line,
                "profile": profile,
                "scope": scope,
                "source": source,
                "tags": ["ingested_user_instruction"],
                "metadata": {"classifier": "deterministic_patterns_v1"},
            }
        )
    return record_durable_instructions(
        project,
        instructions,
        native_exe=native_exe,
        memory_zone=memory_zone,
        memory_zone_path=memory_zone_path,
        include_git=include_git,
    )


def durable_instruction_status(project: Path, native_exe: str | None = None, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> dict[str, Any]:
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    if not project_archive_path(active_root).exists():
        return {"active_memory_zone": active_zone.active_memory_zone, "exists": False, "counts_by_type": {}, "instruction_index_hash": ""}
    all_rows = {
        instruction_type: _load_jsonl(active_root, path, native_exe)
        for instruction_type, path in INSTRUCTION_LOG_PATHS.items()
    }
    index = _instruction_index(all_rows)
    return {
        "active_memory_zone": active_zone.active_memory_zone,
        "exists": True,
        "counts_by_type": index["counts_by_type"],
        "latest_by_type": index["latest_by_type"],
        "instruction_index_hash": index["instruction_index_hash"],
    }
