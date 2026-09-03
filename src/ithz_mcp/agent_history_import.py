from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty
from .hashing import stable_json_hash
from .native_archive_store import (
    PROMPT_LOG_PATH,
    PROMPT_SUMMARY_INDEX_PATH,
    _derive_prompt_summary_index,
    _jsonl_bytes,
    _load_archive_jsonl_optional,
    archive_append_events,
    build_native_archive,
    locate_native_ithz,
    project_archive_path,
)
from .prompt_memory import _summarize_text, redact_text, redaction_status
from .safety import redaction_block_reason

SUPPORTED_AGENT_SOURCES = ("codex", "claude", "cursor", "antigravity", "generic")
MAX_HISTORY_RECORDS = 100
MAX_HISTORY_FILES = 500
MAX_TEXT_CHARS = 20000
UNKNOWN_AUTHOR = "unknown"


def _home() -> Path:
    return Path.home()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_time(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        # Most local history formats use either seconds or milliseconds.
        seconds = float(value) / 1000.0 if value > 10_000_000_000 else float(value)
        try:
            return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except (OSError, OverflowError, ValueError):
            return ""
    if not isinstance(value, str):
        return ""
    raw = value.strip()
    if not raw:
        return ""
    if raw.isdigit():
        return _normalize_time(int(raw))
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return value.strip()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _extract_time(obj: Any) -> str:
    if not isinstance(obj, dict):
        return ""
    for key in ("timestamp", "created_at", "createdAt", "time", "date", "ts"):
        normalized = _normalize_time(obj.get(key))
        if normalized:
            return normalized
    for key in ("payload", "response_item", "session_meta"):
        child = obj.get(key)
        if isinstance(child, dict):
            normalized = _extract_time(child)
            if normalized:
                return normalized
    return ""


def _file_mtime_utc(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except OSError:
        return ""


def detect_history_author(project: Path, explicit: str | None = None) -> dict[str, str]:
    if explicit and explicit.strip():
        return {"author": explicit.strip(), "author_source": "explicit", "author_id": stable_json_hash({"author": explicit.strip()})[:16]}

    try:
        name = subprocess.run(["git", "-C", str(project), "config", "user.name"], capture_output=True, text=True, timeout=5, check=False).stdout.strip()
        email = subprocess.run(["git", "-C", str(project), "config", "user.email"], capture_output=True, text=True, timeout=5, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        name = ""
        email = ""
    if name or email:
        author = f"{name} <{email}>".strip() if email else name
        return {"author": author, "author_source": "git_config", "author_id": stable_json_hash({"author": author})[:16]}

    for key in ("GIT_AUTHOR_NAME", "USERNAME", "USER"):
        value = os.environ.get(key, "").strip()
        if value:
            return {"author": value, "author_source": f"env_{key}", "author_id": stable_json_hash({"author": value})[:16]}
    return {"author": UNKNOWN_AUTHOR, "author_source": "unknown", "author_id": stable_json_hash({"author": UNKNOWN_AUTHOR})[:16]}


def default_history_roots(source: str) -> list[Path]:
    appdata = Path(os.environ.get("APPDATA", ""))
    localappdata = Path(os.environ.get("LOCALAPPDATA", ""))
    roots: dict[str, list[Path]] = {
        "codex": [_home() / ".codex" / "sessions"],
        "claude": [_home() / ".claude" / "projects", _home() / ".claude"],
        "cursor": [appdata / "Cursor" / "User" / "workspaceStorage", appdata / "Cursor" / "User" / "globalStorage"],
        "antigravity": [appdata / "Antigravity", localappdata / "Antigravity", _home() / ".antigravity"],
        "generic": [],
    }
    return [p for p in roots.get(source, []) if str(p) and p.exists()]


def _iter_candidate_files(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        candidates: list[Path] = []
        if root.is_file():
            candidates.append(root)
        elif root.exists():
            for pattern in ("*.jsonl", "*.json", "*.md", "*.txt"):
                candidates.extend(root.rglob(pattern))
        for path in sorted(candidates, key=lambda p: str(p).lower()):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(resolved)
            if len(files) >= MAX_HISTORY_FILES:
                return files
    return files


def _project_markers(project: Path) -> list[str]:
    resolved = project.resolve()
    markers = {str(resolved), str(resolved).replace("\\", "/"), resolved.name}
    return [m.lower() for m in markers if m]


def _file_mentions_project(path: Path, markers: list[str]) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


def _extract_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item.get("content"), str):
                    parts.append(item["content"])
                else:
                    parts.append(_extract_text(item))
            else:
                parts.append(_extract_text(item))
        return "\n".join(p for p in parts if p)
    if isinstance(value, dict):
        for key in ("text", "content", "message", "body"):
            if key in value:
                text = _extract_text(value.get(key))
                if text:
                    return text
        return ""
    return ""


def _role_from_obj(obj: dict[str, Any]) -> str | None:
    candidates = [obj.get("role"), obj.get("author"), obj.get("type")]
    if isinstance(obj.get("payload"), dict):
        candidates.append(obj["payload"].get("role"))
    if isinstance(obj.get("response_item"), dict):
        candidates.append(obj["response_item"].get("role"))
    for raw in candidates:
        if isinstance(raw, dict):
            raw = raw.get("role") or raw.get("name")
        if not isinstance(raw, str):
            continue
        value = raw.lower()
        if value in {"user", "human"}:
            return "user"
        if value in {"assistant", "agent", "model"}:
            return "assistant"
    return None


def _text_from_obj(obj: dict[str, Any]) -> str:
    if isinstance(obj.get("response_item"), dict):
        text = _extract_text(obj["response_item"].get("content"))
        if text:
            return text
        return _extract_text(obj["response_item"])
    if isinstance(obj.get("payload"), dict):
        text = _extract_text(obj["payload"].get("content"))
        if text:
            return text
    return _extract_text(obj)


def _parse_json_lines(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        role = _role_from_obj(obj)
        text = _text_from_obj(obj)
        if role and text:
            rows.append({"role": role, "text": text[:MAX_TEXT_CHARS], "line": str(line_no), "time": _extract_time(obj)})
    return rows


def _parse_json_file(path: Path) -> list[dict[str, str]]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return []
    rows: list[dict[str, str]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            role = _role_from_obj(value)
            text = _text_from_obj(value)
            if role and text:
                rows.append({"role": role, "text": text[:MAX_TEXT_CHARS], "line": "0", "time": _extract_time(value)})
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(obj)
    return rows


def _parse_markdown_or_text(path: Path) -> list[dict[str, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    chunks = re.split(r"(?im)^#{1,3}\s*(user|assistant|prompt|response)\b.*$", text)
    rows: list[dict[str, str]] = []
    if len(chunks) >= 3:
        for idx in range(1, len(chunks), 2):
            role_raw = chunks[idx].lower()
            role = "user" if role_raw in {"user", "prompt"} else "assistant"
            body = chunks[idx + 1].strip()
            if body:
                rows.append({"role": role, "text": body[:MAX_TEXT_CHARS], "line": "0", "time": ""})
    return rows


def _parse_history_file(path: Path) -> list[dict[str, str]]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return _parse_json_lines(path)
    if suffix == ".json":
        return _parse_json_file(path)
    if suffix in {".md", ".txt"}:
        return _parse_markdown_or_text(path)
    return []


def _pair_turns(rows: list[dict[str, str]], source_path: Path, source_name: str, author_info: dict[str, str]) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    pending_user: dict[str, str] | None = None
    source_mtime_utc = _file_mtime_utc(source_path)
    for row in rows:
        if row["role"] == "user":
            pending_user = row
            continue
        if row["role"] == "assistant" and pending_user:
            prompt_text = pending_user["text"]
            response_text = row["text"]
            prompt_redaction = redact_text(prompt_text)
            response_redaction = redact_text(response_text)
            prompt_safe = prompt_redaction["text"]
            response_safe = response_redaction["text"]
            if redaction_block_reason(prompt_safe) or redaction_block_reason(response_safe):
                prompt_safe = re.sub(r"(?i)(secret|credential|password|passwd|pwd|token|access_token|refresh_token|bearer|api_key|private_key)\s*[:=]\s*\S+", r"\1=[REDACTED]", prompt_safe)
                response_safe = re.sub(r"(?i)(secret|credential|password|passwd|pwd|token|access_token|refresh_token|bearer|api_key|private_key)\s*[:=]\s*\S+", r"\1=[REDACTED]", response_safe)
            record_seed = {
                "author_id": author_info["author_id"],
                "source": source_name,
                "source_path": str(source_path),
                "prompt_hash": stable_json_hash({"prompt": prompt_text}),
                "response_hash": stable_json_hash({"response": response_text}),
            }
            history_time = pending_user.get("time") or row.get("time") or source_mtime_utc
            pairs.append(
                {
                    "source": source_name,
                    "source_path": str(source_path),
                    "source_line": pending_user.get("line", "0"),
                    "author": author_info["author"],
                    "author_source": author_info["author_source"],
                    "author_id": author_info["author_id"],
                    "history_time": history_time,
                    "source_mtime_utc": source_mtime_utc,
                    "prompt_summary": _summarize_text(prompt_safe, "prompt"),
                    "response_summary": _summarize_text(response_safe, "response"),
                    "prompt_hash": stable_json_hash({"prompt": prompt_text}),
                    "response_hash": stable_json_hash({"response": response_text}),
                    "semantic_prompt_hash": stable_json_hash(record_seed),
                    "redaction_status": redaction_status(prompt_redaction, response_redaction),
                    "redaction_hits": sorted(set(prompt_redaction["hits"] + response_redaction["hits"])),
                }
            )
            pending_user = None
    return pairs


def discover_agent_history(
    project: Path,
    sources: list[str] | None = None,
    roots: list[Path] | None = None,
    max_records: int = MAX_HISTORY_RECORDS,
    author: str | None = None,
) -> dict[str, Any]:
    project = project.resolve()
    sources = sources or ["codex", "claude", "cursor", "antigravity"]
    author_info = detect_history_author(project, author)
    markers = _project_markers(project)
    explicit_roots = [p for p in (roots or []) if p.exists()]
    discovered_roots: list[Path] = list(explicit_roots)
    if not discovered_roots:
        for source in sources:
            discovered_roots.extend(default_history_roots(source))
    files = _iter_candidate_files(discovered_roots)
    records: list[dict[str, Any]] = []
    file_rows = []
    for path in files:
        if not _file_mentions_project(path, markers):
            continue
        source_name = sources[0] if len(sources) == 1 else next((s for s in sources if s in str(path).lower()), "generic")
        pairs = _pair_turns(_parse_history_file(path), path, source_name, author_info)
        file_rows.append({"path": str(path), "source": source_name, "pair_count": len(pairs)})
        records.extend(pairs)
        if len(records) >= max_records:
            records = records[:max_records]
            break
    records.sort(key=lambda r: (r["source"], r["source_path"], r["source_line"], r["semantic_prompt_hash"]))
    return {
        "project": str(project),
        "sources": sources,
        "author": author_info["author"],
        "author_source": author_info["author_source"],
        "author_id": author_info["author_id"],
        "roots": [str(p) for p in discovered_roots],
        "file_count": len(file_rows),
        "record_count": len(records),
        "files": file_rows,
        "records": records,
        "history_discovery_hash": stable_json_hash(
            {
                "project": str(project),
                "author_id": author_info["author_id"],
                "records": [{k: r.get(k) for k in ("source", "source_path", "semantic_prompt_hash", "history_time")} for r in records],
            }
        ),
    }


def archive_import_agent_history(
    project: Path,
    sources: list[str] | None = None,
    roots: list[Path] | None = None,
    max_records: int = MAX_HISTORY_RECORDS,
    apply: bool = False,
    native_exe: str | None = None,
    author: str | None = None,
    imported_at: str | None = None,
) -> dict[str, Any]:
    project = project.resolve()
    discovery = discover_agent_history(project, sources, roots, max_records, author)
    imported_at_utc = _normalize_time(imported_at) or _utc_now_iso()
    archive_preexisting = project_archive_path(project).exists()
    if not apply:
        return {**discovery, "applied": False, "dry_run": True, "archive_preexisting": archive_preexisting, "imported_at_utc": imported_at_utc}
    if not archive_preexisting:
        build_native_archive(project, native_exe)
    exe = str(locate_native_ithz(native_exe))
    existing = _load_archive_jsonl_optional(project, PROMPT_LOG_PATH, exe)
    seen = {str(row.get("semantic_prompt_hash")) for row in existing}
    rows = list(existing)
    imported: list[dict[str, Any]] = []
    for record in discovery["records"]:
        if record["semantic_prompt_hash"] in seen:
            continue
        record_id = f"pr_{len(rows) + 1:06d}"
        prompt_id = f"prompt_{record_id[3:]}"
        response_id = f"response_{record_id[3:]}"
        row = {
            "schema": "ithz_prompt_memory_record_v1",
            "record_id": record_id,
            "prompt_id": prompt_id,
            "response_id": response_id,
            "task": f"Imported {record['source']} agent history",
            "mode": "summary",
            "local_only": False,
            "imported_from_agent_history": True,
            "source": record["source"],
            "source_path_hash": stable_json_hash({"source_path": record["source_path"]}),
            "source_line": record.get("source_line", "0"),
            "source_mtime_utc": record.get("source_mtime_utc", ""),
            "history_time": record.get("history_time", ""),
            "imported_at_utc": imported_at_utc,
            "author": record.get("author", UNKNOWN_AUTHOR),
            "author_source": record.get("author_source", "unknown"),
            "author_id": record.get("author_id", stable_json_hash({"author": UNKNOWN_AUTHOR})[:16]),
            "archive_preexisting": archive_preexisting,
            "prompt_hash": record["prompt_hash"],
            "response_hash": record["response_hash"],
            "semantic_prompt_hash": record["semantic_prompt_hash"],
            "prompt_summary": record["prompt_summary"],
            "response_summary": record["response_summary"],
            "redaction_status": record["redaction_status"],
            "redaction_hits": record["redaction_hits"],
            "team_sync_allowed": True,
        }
        rows.append(row)
        seen.add(record["semantic_prompt_hash"])
        imported.append(row)
    if not imported:
        return {
            **discovery,
            "applied": True,
            "dry_run": False,
            "archive_preexisting": archive_preexisting,
            "imported_at_utc": imported_at_utc,
            "imported_count": 0,
            "reason": "no_new_history_records",
        }
    prompt_index = _derive_prompt_summary_index(rows)
    extra_updates = {
        PROMPT_LOG_PATH: _jsonl_bytes(rows),
        PROMPT_SUMMARY_INDEX_PATH: dump_pretty(prompt_index).encode("utf-8"),
    }
    event_specs = [
        {
            "kind": "note",
            "source": "agent_history_import",
            "tags": ["agent_history", str(row.get("source", "generic"))],
            "text": f"Agent history imported: {row['source']} {row['prompt_id']} by {row.get('author', UNKNOWN_AUTHOR)} at {row.get('history_time') or row.get('imported_at_utc', '')}. {row['prompt_summary']} {row['response_summary']}",
            "metadata": {
                "prompt_id": row["prompt_id"],
                "response_id": row["response_id"],
                "author": row.get("author", UNKNOWN_AUTHOR),
                "author_id": row.get("author_id", ""),
                "author_source": row.get("author_source", ""),
                "source": row["source"],
                "history_time": row.get("history_time", ""),
                "imported_at_utc": row.get("imported_at_utc", ""),
                "redaction_status": row["redaction_status"],
                "source_path_hash": row["source_path_hash"],
            },
        }
        for row in imported
    ]
    append = archive_append_events(
        project,
        event_specs,
        native_exe,
        "current",
        None,
        False,
        extra_updates=extra_updates,
        manifest_extra={
            "prompt_record_count": len(rows),
            "prompt_summary_index_hash": prompt_index["prompt_summary_index_hash"],
            "agent_history_import_count": len(imported),
            "agent_history_sources": sorted(set(str(r.get("source")) for r in imported)),
            "agent_history_last_import_author": discovery.get("author", UNKNOWN_AUTHOR),
            "agent_history_last_imported_at_utc": imported_at_utc,
        },
    )
    return {
        **discovery,
        "applied": True,
        "dry_run": False,
        "archive_preexisting": archive_preexisting,
        "imported_at_utc": imported_at_utc,
        "imported_count": len(imported),
        "prompt_record_count": len(rows),
        "prompt_summary_index_hash": prompt_index["prompt_summary_index_hash"],
        "append": append,
    }
