from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty, sanitize_json_value, sanitize_text
from .hashing import stable_json_hash
from .native_archive_store import archive_append_events, archive_create_snapshot, extract_archive_file_bytes, native_archive_record_prompt_response, project_archive_path, build_native_archive
from .prompt_memory import redact_text
from .safety import ignore_reason, normalize_rel, redaction_block_reason

MAX_SOURCE_BYTES = 256 * 1024
ASYNC_ARCHIVE_BYTES_THRESHOLD = 900_000
ASYNC_EVENT_COUNT_THRESHOLD = 500


def _safe_text(text: str) -> dict[str, Any]:
    text = sanitize_text(str(text))
    redacted = redact_text(text)
    safe = redacted["text"]
    replacements = {
        ".env": "[DOTENV_FILE]",
        "-----BEGIN": "[PRIVATE_KEY_BLOCK_BEGIN]",
        "-----END": "[PRIVATE_KEY_BLOCK_END]",
    }
    for needle, repl in replacements.items():
        safe = safe.replace(needle, repl)
    blocked = redaction_block_reason(safe)
    if blocked:
        safe = re.sub(r"(?i)(secret|credential|password|passwd|pwd|token|access_token|refresh_token|bearer|api_key|private_key)\s*[:=]\s*\S+", r"\1=[REDACTED]", safe)
        safe = re.sub(r"\b[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b", "[REDACTED:jwt_like]", safe)
        safe = re.sub(r"\b(?:sk|pk|ghp|github_pat|xox[baprs])-?[A-Za-z0-9_=-]{20,}\b", "[REDACTED:provider_key]", safe, flags=re.I)
    return {
        "text": safe,
        "redaction_hits": sorted(set(redacted.get("hits", []))),
        "redaction_status": "redacted" if redacted.get("redacted") or safe != text else "clean",
        "blocked_after_redaction": redaction_block_reason(safe),
    }


def _kind_for_line(line: str) -> str | None:
    lowered = line.lower()
    if re.search(r"\b(accepted|decision|rozhodnutie|dohodnute|accepted:)\b", lowered):
        return "decision"
    if re.search(r"\b(gate|gates|test|tests|passed|failed|prešlo|zlyhalo|validation|validate|php -l|run-ci|self-test)\b", lowered):
        return "gate"
    if re.search(r"\b(risk|risks|known risk|common risk|rizik|limitation|limity|nesmie|must not|non-negotiable|forbidden)\b", lowered):
        return "risk"
    if re.search(r"\b(next|todo|current focus|finish checklist|ďalší|dalsi|nasledny)\b", lowered):
        return "next"
    if re.search(r"\b(workflow|deploy|deployment|git|commit|push|ssh|scp|domain|doména|remote path|read order|docs-first|documentation impact|memory impact)\b", lowered):
        return "note"
    return None


def _event_text_from_line(source_name: str, line_no: int, line: str) -> str:
    compact = re.sub(r"\s+", " ", line.strip())
    return f"{source_name}:{line_no}: {compact[:900]}"


def _source_allowed(path: Path) -> tuple[bool, str | None]:
    if not path.exists():
        return False, "missing_source"
    if not path.is_file():
        return False, "not_a_file"
    try:
        size = path.stat().st_size
    except OSError:
        return False, "stat_failed"
    rel = path.name
    reason = ignore_reason(rel, size)
    if reason:
        return False, reason
    if size > MAX_SOURCE_BYTES:
        return False, "source_too_large"
    return True, None


def extract_workflow_events_from_text(source_name: str, text: str, default_source: str = "workflow_intake") -> dict[str, Any]:
    safe = _safe_text(text)
    if safe["blocked_after_redaction"]:
        raise ValueError("source_contains_unredactable_secret_like_content")
    events: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    in_relevant_section = False
    for line_no, raw in enumerate(safe["text"].splitlines(), start=1):
        line = raw.strip(" \t-*#")
        if not line:
            continue
        if raw.lstrip().startswith("#"):
            in_relevant_section = bool(_kind_for_line(line) or re.search(r"\b(read order|workflow|deployment|git|memory|risk|decision|architecture|validation|finish)\b", line, re.I))
        kind = _kind_for_line(line)
        if kind is None and in_relevant_section and len(line) <= 220:
            kind = "note"
        if kind is None:
            continue
        text_line = _event_text_from_line(source_name, line_no, line)
        key = (kind, text_line.lower())
        if key in seen:
            continue
        seen.add(key)
        events.append(
            {
                "kind": kind,
                "text": text_line,
                "source": default_source,
                "tags": ["project_intake", source_name],
                "metadata": {"source_file": source_name, "line": line_no, "redaction_status": safe["redaction_status"]},
            }
        )
        if len(events) >= 120:
            break
    return {
        "events": events,
        "redaction_status": safe["redaction_status"],
        "redaction_hits": safe["redaction_hits"],
        "source_hash": stable_json_hash({"source": source_name, "safe_text": safe["text"]}),
    }


def archive_ingest_project_memory(
    project: Path,
    sources: list[Path],
    note: str = "",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    project = project.resolve()
    if not project_archive_path(project).exists():
        build_native_archive(project, native_exe)
    rows: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for source in sources:
        path = source if source.is_absolute() else project / source
        allowed, reason = _source_allowed(path)
        if not allowed:
            rows.append({"source": str(source), "indexed": False, "reason": reason, "event_count": 0})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = normalize_rel(path.relative_to(project)) if path.resolve().is_relative_to(project) else path.name
        extracted = extract_workflow_events_from_text(rel, text)
        rows.append(
            {
                "source": rel,
                "indexed": True,
                "reason": "",
                "event_count": len(extracted["events"]),
                "redaction_status": extracted["redaction_status"],
                "redaction_hits": ",".join(extracted["redaction_hits"]),
                "source_hash": extracted["source_hash"],
            }
        )
        events.extend(extracted["events"])
    if note.strip():
        safe_note = _safe_text(note)
        if safe_note["blocked_after_redaction"]:
            raise ValueError("note_contains_unredactable_secret_like_content")
        events.append({"kind": "note", "text": f"Project intake note: {safe_note['text'][:900]}", "source": "workflow_intake", "tags": ["project_intake"], "metadata": {"redaction_status": safe_note["redaction_status"]}})
    if not events:
        return {"ingested": False, "project": str(project), "rows": rows, "reason": "no_durable_events_found"}
    append = archive_append_events(project, events, native_exe, memory_zone, memory_zone_path, include_git)
    return {
        "ingested": True,
        "project": str(project),
        "rows": rows,
        "event_count": len(events),
        "append": append,
        "intake_hash": stable_json_hash({"rows": rows, "events": [{k: e.get(k) for k in ("kind", "text", "source", "tags")} for e in events]}),
    }


def _list_event(kind: str, label: str, values: list[str], tags: list[str]) -> list[dict[str, Any]]:
    events = []
    for value in values:
        safe = _safe_text(value)
        if safe["blocked_after_redaction"]:
            raise ValueError(f"{label}_contains_unredactable_secret_like_content")
        events.append({"kind": kind, "text": f"{label}: {safe['text'][:900]}", "source": "end_task_checkpoint", "tags": tags, "metadata": {"redaction_status": safe["redaction_status"]}})
    return events


def _job_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) / "ITHZ" / "mcp-jobs" if base else Path(tempfile.gettempdir()) / "ithz_mcp_jobs"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _checkpoint_archive_signal(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    archive = project_archive_path(project)
    signal: dict[str, Any] = {
        "archive_exists": archive.exists(),
        "archive_bytes": archive.stat().st_size if archive.exists() else 0,
        "memory_event_count": None,
    }
    if not archive.exists():
        return signal
    try:
        manifest = json.loads(extract_archive_file_bytes(project, "manifest.json", native_exe).decode("utf-8", errors="replace"))
        signal["memory_event_count"] = manifest.get("memory_event_count")
    except Exception:
        signal["memory_event_count"] = None
    return signal


def should_queue_checkpoint(project: Path, native_exe: str | None = None, async_mode: str = "auto") -> tuple[bool, str, dict[str, Any]]:
    mode = sanitize_text(str(async_mode or "auto")).lower()
    signal = _checkpoint_archive_signal(project, native_exe)
    if mode in {"never", "sync", "false", "off"}:
        return False, "sync_requested", signal
    if mode in {"always", "async", "queued", "true"}:
        return True, "async_requested", signal
    event_count = signal.get("memory_event_count")
    if isinstance(event_count, int) and event_count >= ASYNC_EVENT_COUNT_THRESHOLD:
        return True, "large_event_count", signal
    if int(signal.get("archive_bytes") or 0) >= ASYNC_ARCHIVE_BYTES_THRESHOLD:
        return True, "large_archive_bytes", signal
    return False, "small_archive_sync", signal


def archive_finalize_task_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    payload = sanitize_json_value(payload)
    return archive_finalize_task(
        project=Path(str(payload["project"])),
        task=str(payload["task"]),
        summary=str(payload.get("summary", "")),
        summary_file=Path(str(payload["summary_file"])) if payload.get("summary_file") else None,
        decisions=[str(v) for v in payload.get("decisions", [])],
        gates=[str(v) for v in payload.get("gates", [])],
        risks=[str(v) for v in payload.get("risks", [])],
        next_steps=[str(v) for v in payload.get("next_steps", [])],
        changed_files=[str(v) for v in payload.get("changed_files", [])],
        commands=[str(v) for v in payload.get("commands", [])],
        docs_impact=str(payload.get("docs_impact", "unknown")),
        memory_impact=str(payload.get("memory_impact", "unknown")),
        prompt_file=Path(str(payload["prompt_file"])) if payload.get("prompt_file") else None,
        response_file=Path(str(payload["response_file"])) if payload.get("response_file") else None,
        prompt_mode=str(payload.get("prompt_mode", "summary")),
        create_snapshot=bool(payload.get("create_snapshot", False)),
        snapshot_mode=str(payload.get("snapshot_mode", "auto")),
        native_exe=str(payload["native_exe"]) if payload.get("native_exe") else None,
        memory_zone=str(payload.get("memory_zone", "nearest")),
        memory_zone_path=str(payload["memory_zone_path"]) if payload.get("memory_zone_path") else None,
        include_git=bool(payload.get("include_git", False)),
    )


def _compact_checkpoint_result(result: dict[str, Any]) -> dict[str, Any]:
    append = result.get("append") if isinstance(result.get("append"), dict) else {}
    update = append.get("update") if isinstance(append.get("update"), dict) else {}
    return {
        "finalized": bool(result.get("finalized")),
        "queued": False,
        "project": result.get("project"),
        "task": result.get("task"),
        "checkpoint_hash": result.get("checkpoint_hash"),
        "event_count": result.get("event_count"),
        "active_memory_zone": append.get("active_memory_zone"),
        "archive_sha256_after": update.get("archive_sha256_after"),
        "archive_bytes": update.get("archive_bytes"),
    }


def run_archive_finalize_task_worker(input_path: Path) -> dict[str, Any]:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    log_path = Path(str(payload.get("_job_log") or (input_path.with_suffix(".log.json"))))
    try:
        result = archive_finalize_task_from_payload(payload)
        compact = _compact_checkpoint_result(result)
        log_path.write_text(dump_pretty({"status": "completed", "result": compact}), encoding="utf-8")
        try:
            input_path.unlink()
        except OSError:
            pass
        return compact
    except Exception as exc:
        failure = {"status": "failed", "error": str(exc), "input": str(input_path)}
        log_path.write_text(dump_pretty(failure), encoding="utf-8")
        raise


def queue_archive_finalize_task(payload: dict[str, Any], reason: str, signal: dict[str, Any]) -> dict[str, Any]:
    payload = sanitize_json_value(payload)
    request_hash = stable_json_hash({k: v for k, v in payload.items() if not str(k).startswith("_")})
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    root = _job_root()
    input_path = root / f"checkpoint-{stamp}-{request_hash[:12]}.json"
    log_path = root / f"checkpoint-{stamp}-{request_hash[:12]}.log.json"
    payload["_job_log"] = str(log_path)
    input_path.write_text(dump_pretty(payload), encoding="utf-8")
    cmd = [sys.executable, "-m", "ithz_mcp", "archive-finalize-task-worker", "--input", str(input_path)]
    flags = 0
    if os.name == "nt":
        flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
        flags |= getattr(subprocess, "DETACHED_PROCESS", 0)
    with log_path.open("ab") as log:
        proc = subprocess.Popen(
            cmd,
            cwd=str(Path(payload["project"])),
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
            creationflags=flags,
            start_new_session=(os.name != "nt"),
        )
    return {
        "finalized": False,
        "queued": True,
        "queue_reason": reason,
        "project": str(payload["project"]),
        "task": payload.get("task"),
        "request_hash": request_hash,
        "pid": proc.pid,
        "job_input": str(input_path),
        "job_log": str(log_path),
        "archive_signal": signal,
    }


def archive_finalize_task(
    project: Path,
    task: str,
    summary: str = "",
    summary_file: Path | None = None,
    decisions: list[str] | None = None,
    gates: list[str] | None = None,
    risks: list[str] | None = None,
    next_steps: list[str] | None = None,
    changed_files: list[str] | None = None,
    commands: list[str] | None = None,
    docs_impact: str = "unknown",
    memory_impact: str = "unknown",
    prompt_file: Path | None = None,
    response_file: Path | None = None,
    prompt_mode: str = "summary",
    create_snapshot: bool = False,
    snapshot_mode: str = "auto",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    project = project.resolve()
    task = sanitize_text(task)
    docs_impact = sanitize_text(docs_impact)
    memory_impact = sanitize_text(memory_impact)
    if not project_archive_path(project).exists():
        build_native_archive(project, native_exe)
    summary_text = summary
    if summary_file:
        path = summary_file if summary_file.is_absolute() else project / summary_file
        allowed, reason = _source_allowed(path)
        if not allowed:
            raise ValueError(f"summary_file_not_allowed:{reason}")
        summary_text = path.read_text(encoding="utf-8", errors="replace")
    safe_summary = _safe_text(summary_text or task)
    if safe_summary["blocked_after_redaction"]:
        raise ValueError("summary_contains_unredactable_secret_like_content")
    tags = ["end_task", "checkpoint"]
    events: list[dict[str, Any]] = [
        {
            "kind": "note",
            "text": f"Task checkpoint: {task}. Summary: {safe_summary['text'][:1200]}",
            "source": "end_task_checkpoint",
            "tags": tags,
            "metadata": {
                "docs_impact": docs_impact,
                "memory_impact": memory_impact,
                "redaction_status": safe_summary["redaction_status"],
                "changed_files": sorted(sanitize_text(str(v)) for v in (changed_files or [])),
                "commands": sorted(sanitize_text(str(v)) for v in (commands or [])),
            },
        },
        {"kind": "gate", "text": f"Documentation impact: {docs_impact}", "source": "end_task_checkpoint", "tags": tags + ["documentation_impact"]},
        {"kind": "gate", "text": f"Memory impact: {memory_impact}", "source": "end_task_checkpoint", "tags": tags + ["memory_impact"]},
    ]
    events.extend(_list_event("decision", "Decision", decisions or [], tags))
    events.extend(_list_event("gate", "Gate", gates or [], tags))
    events.extend(_list_event("risk", "Risk", risks or [], tags))
    events.extend(_list_event("next", "Next step", next_steps or [], tags))
    if changed_files:
        events.append({"kind": "note", "text": "Changed files: " + ", ".join(sorted(sanitize_text(str(v)) for v in changed_files))[:900], "source": "end_task_checkpoint", "tags": tags + ["changed_files"]})
    if commands:
        events.append({"kind": "gate", "text": "Commands run: " + " ; ".join(sorted(sanitize_text(str(v)) for v in commands))[:900], "source": "end_task_checkpoint", "tags": tags + ["commands"]})
    prompt_record = None
    if prompt_file and response_file:
        prompt_record = native_archive_record_prompt_response(project, prompt_file, response_file, task, prompt_mode, native_exe, memory_zone, memory_zone_path)
        prompt_record_body = prompt_record.get("record", {}) if isinstance(prompt_record, dict) else {}
        events.append(
            {
                "kind": "note",
                "text": f"Prompt memory linked: prompt_id={prompt_record_body.get('prompt_id')} response_id={prompt_record_body.get('response_id')} mode={prompt_record_body.get('mode')}",
                "source": "end_task_checkpoint",
                "tags": tags + ["prompt_memory"],
                "metadata": {
                    "prompt_id": prompt_record_body.get("prompt_id"),
                    "response_id": prompt_record_body.get("response_id"),
                    "redaction_status": prompt_record_body.get("redaction_status"),
                    "prompt_memory_mode": prompt_record_body.get("mode"),
                },
            }
        )
    append = archive_append_events(project, events, native_exe, memory_zone, memory_zone_path, include_git)
    snapshot = archive_create_snapshot(project, f"after-task-{task[:40]}", native_exe, memory_zone, memory_zone_path, snapshot_mode) if create_snapshot else None
    return sanitize_json_value({
        "finalized": True,
        "project": str(project),
        "task": task,
        "event_count": len(events),
        "prompt_record": prompt_record,
        "append": append,
        "snapshot": snapshot,
        "checkpoint_hash": stable_json_hash({"task": task, "summary": safe_summary["text"], "events": [{k: e.get(k) for k in ("kind", "text", "tags")} for e in events]}),
    })
