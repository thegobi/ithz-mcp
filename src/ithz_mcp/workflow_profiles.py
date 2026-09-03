from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty, dumps, sanitize_text
from .hashing import sha256_file, stable_json_hash
from .native_archive_store import (
    WORKFLOW_INDEX_PATH,
    WORKFLOW_PROMPT_LOG_PATH,
    archive_append_events,
    build_native_archive,
    ensure_project_bootstrap,
    extract_archive_file_bytes,
    locate_native_ithz,
    native_archive_context_pack,
    native_archive_search,
    project_archive_path,
)
from .prompt_memory import _summarize_text, redact_text
from .safety import ignore_reason, normalize_rel, redaction_block_reason

WORKFLOW_SCHEMA = "ithz_mcp_workflow_profile_v1"
WORKFLOW_INDEX_SCHEMA = "ithz_mcp_workflow_profile_index_v1"
MAX_WORKFLOW_SOURCE_BYTES = 256 * 1024


def safe_workflow_id(value: str | None) -> str:
    raw = (value or "default").strip().lower()
    raw = re.sub(r"[^a-z0-9_.-]+", "-", raw)
    raw = raw.strip(".-")
    return raw or "default"


def workflow_profile_path(profile_id: str) -> str:
    return f"workflows/profiles/{safe_workflow_id(profile_id)}.json"


def _workflow_safe_text(text: str) -> dict[str, Any]:
    redacted = redact_text(text)
    safe = redacted["text"]
    safe = safe.replace(".env", "[DOTENV_FILE]")
    safe = safe.replace("-----BEGIN", "[PRIVATE_KEY_BLOCK_BEGIN]")
    safe = safe.replace("-----END", "[PRIVATE_KEY_BLOCK_END]")
    safe = re.sub(
        r"(?i)(secret|credential|password|passwd|pwd|token|access_token|refresh_token|bearer|api_key|private_key)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        safe,
    )
    return {
        "text": safe,
        "redaction_status": "redacted" if redacted.get("redacted") or safe != text else "clean",
        "redaction_hits": sorted(set(redacted.get("hits", []))),
        "blocked_after_redaction": redaction_block_reason(safe),
    }


def _source_allowed(path: Path) -> tuple[bool, str | None]:
    if not path.exists():
        return False, "missing_source"
    if not path.is_file():
        return False, "not_a_file"
    size = path.stat().st_size
    reason = ignore_reason(path.name, size)
    if reason:
        return False, reason
    if size > MAX_WORKFLOW_SOURCE_BYTES:
        return False, "source_too_large"
    return True, None


def discover_markdown_workflow_sources(project: Path) -> list[Path]:
    project = project.resolve()
    priority = [
        "AI_PROJECT_BRIEF.md",
        "PROJECT_BRIEF.md",
        "PROJECT_CONTEXT.md",
        "ARCHITECTURE.md",
        "WORKFLOW_RULES.md",
        "DECISIONS_LOG.md",
        "repo.md",
        "README.md",
        "AGENTS.md",
        "ITHZ_CONTEXT.md",
        "project.md",
    ]
    found: list[Path] = []
    seen: set[Path] = set()
    for name in priority:
        path = project / name
        if path.exists() and path.resolve() not in seen:
            found.append(path)
            seen.add(path.resolve())
    for path in sorted(project.rglob("*.md"), key=lambda p: normalize_rel(p.relative_to(project)).lower()):
        if path.resolve() in seen:
            continue
        rel = normalize_rel(path.relative_to(project))
        parts = {part.lower() for part in Path(rel).parts}
        if parts.intersection({".git", ".ithz-install", ".ithz-context", ".ithz_mcp", ".antigravity", ".claude", ".cursor", ".mempalace-capture", ".mempalace-pilot", ".mempalace-seed", "dist", "build", "node_modules", "vendor", "source_package"}):
            continue
        found.append(path)
        seen.add(path.resolve())
        if len(found) >= 40:
            break
    return found


def _bucket_for_line(line: str) -> str | None:
    hay = line.lower()
    if re.search(r"\b(read order|docs-first|bootstrap|project\.md|source of truth|markdown)\b", hay):
        return "source_of_truth"
    if re.search(r"\b(documentation impact|docs impact|project_brief|architecture|workflow_rules|decisions_log)\b", hay):
        return "documentation_policy"
    if re.search(r"\b(memory impact|handoff|mempalace|project\.ithz|ithz-mcp|context pack|checkpoint)\b", hay):
        return "memory_policy"
    if re.search(r"\b(git|commit|push|pull|merge|branch|checkout|stage)\b", hay):
        return "git_policy"
    if re.search(r"\b(test|tests|smoke|gate|run-ci|pytest|unittest|php -l|verify)\b", hay):
        return "testing_policy"
    if re.search(r"\b(deploy|deployment|ssh|scp|server|domain|ip address|doména|produkcia|prod|dev)\b", hay):
        return "deployment_policy"
    if re.search(r"\b(secret|token|password|private key|credential|\.env|risk|nesmie|must not|safety)\b", hay):
        return "safety_policy"
    if re.search(r"\b(done|end-of-task|checklist|definition of done|finish)\b", hay):
        return "end_of_task"
    return None


def _extract_workflow_rules(source_name: str, text: str) -> dict[str, Any]:
    safe = _workflow_safe_text(text)
    if safe["blocked_after_redaction"]:
        raise ValueError("workflow_source_contains_unredactable_secret_like_content")
    buckets: dict[str, list[dict[str, Any]]] = {
        "source_of_truth": [],
        "documentation_policy": [],
        "memory_policy": [],
        "git_policy": [],
        "testing_policy": [],
        "deployment_policy": [],
        "safety_policy": [],
        "end_of_task": [],
        "other_workflow_notes": [],
    }
    active_heading = ""
    for line_no, raw in enumerate(safe["text"].splitlines(), start=1):
        stripped = re.sub(r"\s+", " ", raw.strip(" \t-*")).strip()
        if not stripped:
            continue
        if raw.lstrip().startswith("#"):
            active_heading = stripped.lstrip("#").strip()
        bucket = _bucket_for_line(stripped)
        if bucket is None and active_heading:
            bucket = _bucket_for_line(active_heading)
        if bucket is None:
            continue
        row = {"source": source_name, "line": line_no, "text": stripped[:500]}
        buckets.setdefault(bucket, []).append(row)
    return {
        "source": source_name,
        "rules": {k: v[:40] for k, v in buckets.items() if v},
        "redaction_status": safe["redaction_status"],
        "redaction_hits": safe["redaction_hits"],
        "source_hash": stable_json_hash({"source": source_name, "safe_text": safe["text"]}),
        "summary": _summarize_text(safe["text"], source_name),
    }


def _merge_rule_buckets(extracted: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    merged: dict[str, list[dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    for item in extracted:
        rules = item.get("rules") if isinstance(item.get("rules"), dict) else {}
        for bucket, rows in rules.items():
            for row in rows:
                key = (bucket, str(row.get("text", "")).lower())
                if key in seen:
                    continue
                seen.add(key)
                merged.setdefault(bucket, []).append(row)
    return {k: v[:80] for k, v in sorted(merged.items())}


def _load_json_optional(project: Path, inner_path: str, default: Any, native_exe: str | None = None) -> Any:
    try:
        data = extract_archive_file_bytes(project, inner_path, native_exe)
    except RuntimeError as exc:
        if "path not found" in str(exc):
            return default
        raise
    return __import__("json").loads(data.decode("utf-8-sig"))


def _load_jsonl_optional(project: Path, inner_path: str, native_exe: str | None = None) -> list[dict[str, Any]]:
    try:
        data = extract_archive_file_bytes(project, inner_path, native_exe)
    except RuntimeError as exc:
        if "path not found" in str(exc):
            return []
        raise
    return [__import__("json").loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return "".join(dumps(row) + "\n" for row in rows).encode("utf-8")


def _profile_index(profiles: dict[str, dict[str, Any]], default_profile: str) -> dict[str, Any]:
    rows = []
    for profile_id, profile in sorted(profiles.items()):
        rows.append(
            {
                "profile_id": profile_id,
                "owner": profile.get("owner", ""),
                "revision": profile.get("revision", 0),
                "profile_hash": profile.get("profile_hash", ""),
                "source_count": len(profile.get("source_docs", [])),
                "prompt_update_count": int(profile.get("prompt_update_count", 0)),
            }
        )
    doc = {"schema": WORKFLOW_INDEX_SCHEMA, "default_profile": default_profile, "profiles": rows}
    doc["workflow_index_hash"] = stable_json_hash({"default_profile": default_profile, "profiles": rows})
    return doc


def _write_project_bootstrap_if_missing(project: Path, profile_id: str) -> dict[str, Any]:
    result = ensure_project_bootstrap(project)
    path = project / "project.md"
    if result.get("created") and path.exists():
        text = path.read_text(encoding="utf-8")
        text += (
            "\n## Workflow profiles\n\n"
            f"- Default workflow profile: `{profile_id}`\n"
            "- User- or team-specific workflow changes are stored in `project.ithz` under `workflows/`.\n"
            "- Use `workflow-ingest-prompt` to update a workflow profile from a prompt.\n"
        )
        path.write_text(text, encoding="utf-8", newline="\n")
    return result


def archive_update_workflow_profile(
    project: Path,
    profile_id: str = "default",
    owner: str = "",
    prompt_file: Path | None = None,
    source_files: list[Path] | None = None,
    note: str = "",
    native_exe: str | None = None,
    set_default: bool = False,
) -> dict[str, Any]:
    project = project.resolve()
    profile_id = safe_workflow_id(profile_id)
    _write_project_bootstrap_if_missing(project, profile_id)
    if not project_archive_path(project).exists():
        build_native_archive(project, native_exe)
    exe = str(locate_native_ithz(native_exe))
    existing_index = _load_json_optional(project, WORKFLOW_INDEX_PATH, {"schema": WORKFLOW_INDEX_SCHEMA, "default_profile": "default", "profiles": []}, exe)
    profiles: dict[str, dict[str, Any]] = {}
    for row in existing_index.get("profiles", []) if isinstance(existing_index, dict) else []:
        pid = safe_workflow_id(str(row.get("profile_id", "")))
        profiles[pid] = _load_json_optional(project, workflow_profile_path(pid), {}, exe)
    old_profile = profiles.get(profile_id, {})
    source_files = source_files or []
    extracted: list[dict[str, Any]] = []
    source_rows: list[dict[str, Any]] = []
    for source in source_files:
        path = source if source.is_absolute() else project / source
        allowed, reason = _source_allowed(path)
        rel = normalize_rel(path.relative_to(project)) if path.exists() and path.resolve().is_relative_to(project) else str(source)
        if not allowed:
            source_rows.append({"source": rel, "indexed": False, "reason": reason})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            item = _extract_workflow_rules(rel, text)
        except ValueError as exc:
            source_rows.append({"source": rel, "indexed": False, "reason": str(exc)})
            continue
        extracted.append(item)
        source_rows.append({"source": rel, "indexed": True, "reason": "", "source_hash": item["source_hash"], "redaction_status": item["redaction_status"]})
    prompt_update = None
    if prompt_file:
        prompt_path = prompt_file if prompt_file.is_absolute() else project / prompt_file
        allowed, reason = _source_allowed(prompt_path)
        if not allowed:
            raise ValueError(f"prompt_file_not_allowed:{reason}")
        prompt_rel = normalize_rel(prompt_path.relative_to(project)) if prompt_path.resolve().is_relative_to(project) else prompt_path.name
        try:
            item = _extract_workflow_rules(prompt_rel, prompt_path.read_text(encoding="utf-8", errors="replace"))
        except ValueError as exc:
            item = None
            prompt_update = {
                "profile_id": profile_id,
                "owner": owner,
                "prompt_source": prompt_rel,
                "prompt_summary": f"Prompt source skipped: {exc}",
                "prompt_hash": stable_json_hash({"prompt_source": prompt_rel, "skipped_reason": str(exc)}),
                "redaction_status": "skipped",
                "skipped_reason": str(exc),
            }
        if item is not None:
            extracted.append(item)
            prompt_update = {
                "profile_id": profile_id,
                "owner": owner,
                "prompt_source": prompt_rel,
                "prompt_summary": item["summary"],
                "prompt_hash": item["source_hash"],
                "redaction_status": item["redaction_status"],
            }
    if note.strip():
        item = _extract_workflow_rules("manual_note", note)
        extracted.append(item)
    rules = _merge_rule_buckets(extracted)
    previous_hash = old_profile.get("profile_hash") if isinstance(old_profile, dict) else None
    revision = int(old_profile.get("revision", 0) or 0) + 1 if old_profile else 1
    source_docs = sorted({row["source"] for row in source_rows if row.get("indexed")})
    prompt_log = _load_jsonl_optional(project, WORKFLOW_PROMPT_LOG_PATH, exe)
    if prompt_update:
        prompt_update["revision"] = revision
        prompt_update["previous_profile_hash"] = previous_hash
        prompt_update["workflow_prompt_hash"] = stable_json_hash(prompt_update)
        prompt_log.append(prompt_update)
    profile = {
        "schema": WORKFLOW_SCHEMA,
        "profile_id": profile_id,
        "owner": owner,
        "revision": revision,
        "previous_profile_hash": previous_hash,
        "source_docs": source_docs,
        "source_rows": source_rows,
        "rules": rules,
        "note": note[:500],
        "prompt_update_count": len([row for row in prompt_log if row.get("profile_id") == profile_id]),
    }
    profile["profile_hash"] = stable_json_hash({k: v for k, v in profile.items() if k != "profile_hash"})
    profiles[profile_id] = profile
    default_profile = profile_id if set_default or not existing_index.get("default_profile") else safe_workflow_id(str(existing_index.get("default_profile")))
    index = _profile_index(profiles, default_profile)
    event_text = f"Workflow profile updated: profile_id={profile_id} owner={owner or 'unspecified'} revision={revision} profile_hash={profile['profile_hash']}"
    extra_updates = {
        WORKFLOW_INDEX_PATH: dump_pretty(index).encode("utf-8"),
        WORKFLOW_PROMPT_LOG_PATH: _jsonl_bytes(prompt_log),
        workflow_profile_path(profile_id): dump_pretty(profile).encode("utf-8"),
    }
    append = archive_append_events(
        project,
        [
            {
                "kind": "note",
                "source": "workflow_profile",
                "tags": ["workflow_profile", profile_id],
                "text": event_text,
                "metadata": {
                    "profile_id": profile_id,
                    "owner": owner,
                    "revision": revision,
                    "profile_hash": profile["profile_hash"],
                    "source_docs": source_docs,
                },
            }
        ],
        native_exe,
        "current",
        None,
        False,
        extra_updates=extra_updates,
        manifest_extra={
            "workflow_profile_count": len(profiles),
            "workflow_default_profile": default_profile,
            "workflow_index_hash": index["workflow_index_hash"],
        },
    )
    return {
        "updated": True,
        "profile": profile,
        "workflow_index": index,
        "source_rows": source_rows,
        "prompt_update": prompt_update,
        "append": append,
    }


def archive_adopt_project_workflow(
    project: Path,
    profile_id: str = "default",
    owner: str = "",
    prompt_file: Path | None = None,
    include_existing_md: bool = True,
    native_exe: str | None = None,
) -> dict[str, Any]:
    project = project.resolve()
    _write_project_bootstrap_if_missing(project, safe_workflow_id(profile_id))
    sources = discover_markdown_workflow_sources(project) if include_existing_md else []
    result = archive_update_workflow_profile(project, profile_id, owner, prompt_file, sources, "Initial workflow profile adoption.", native_exe, set_default=True)
    return {
        "adopted": True,
        "project": str(project),
        "project_md": str(project / "project.md"),
        "project_ithz": str(project_archive_path(project)),
        "source_count": len(sources),
        **result,
    }


def workflow_profile_status(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    project = project.resolve()
    if not project_archive_path(project).exists():
        return {"exists": False, "project": str(project), "profile_count": 0, "profiles": []}
    exe = str(locate_native_ithz(native_exe))
    index = _load_json_optional(project, WORKFLOW_INDEX_PATH, {"schema": WORKFLOW_INDEX_SCHEMA, "default_profile": "", "profiles": []}, exe)
    return {
        "exists": True,
        "project": str(project),
        "project_ithz": str(project_archive_path(project)),
        "default_profile": index.get("default_profile", "") if isinstance(index, dict) else "",
        "profile_count": len(index.get("profiles", [])) if isinstance(index, dict) else 0,
        "profiles": index.get("profiles", []) if isinstance(index, dict) else [],
        "workflow_index_hash": index.get("workflow_index_hash", "") if isinstance(index, dict) else "",
    }


def workflow_context_pack(project: Path, profile_id: str, query: str, max_bytes: int = 20000, native_exe: str | None = None) -> dict[str, Any]:
    project = project.resolve()
    profile_id = safe_workflow_id(profile_id)
    enriched = f"{query} workflow_profile {profile_id}"
    pack = native_archive_context_pack(project, enriched, max_bytes, native_exe, "current")
    profile = _load_json_optional(project, workflow_profile_path(profile_id), {}, native_exe)
    if not isinstance(profile, dict) or profile.get("schema") != WORKFLOW_SCHEMA:
        return {
            **pack,
            "profile_id": profile_id,
            "workflow_profile_found": False,
            "fallback_required": True,
            "recommended_working_set": [],
        }

    lines = [
        "# ITHZ Workflow Profile",
        "",
        f"- profile: {profile_id}",
        f"- owner: {profile.get('owner', '')}",
        f"- revision: {profile.get('revision', 0)}",
        f"- profile_hash: {profile.get('profile_hash', '')}",
        "",
        "## Recommended Working Set",
    ]
    source_docs = [str(item) for item in profile.get("source_docs", []) if isinstance(item, str)]
    lines.extend(f"- `{source}`" for source in source_docs)
    rules = profile.get("rules") if isinstance(profile.get("rules"), dict) else {}
    if rules:
        lines.extend(["", "## Workflow Rules"])
        for bucket, rows in sorted(rules.items()):
            lines.append(f"### {str(bucket).replace('_', ' ').title()}")
            for row in rows[:4] if isinstance(rows, list) else []:
                if isinstance(row, dict):
                    lines.append(f"- `{row.get('source', '')}:{row.get('line', '')}` {row.get('text', '')}")
    profile_text = sanitize_text("\n".join(lines) + "\n\n")
    archive_text = str(pack.get("text", ""))
    combined = profile_text + archive_text
    if len(combined.encode("utf-8")) > max_bytes:
        marker = "\n\n[truncated deterministically]\n"
        budget = max(0, max_bytes - len(marker.encode("utf-8")))
        combined = combined.encode("utf-8")[:budget].decode("utf-8", errors="ignore") + marker
    return {
        **pack,
        "text": combined,
        "bytes": len(combined.encode("utf-8")),
        "context_pack_hash": stable_json_hash(
            {
                "query": enriched,
                "text": combined,
                "profile_hash": profile.get("profile_hash", ""),
                "archive_context_pack_hash": pack.get("context_pack_hash", ""),
            }
        ),
        "profile_id": profile_id,
        "workflow_profile_found": True,
        "workflow_profile_hash": profile.get("profile_hash", ""),
        "fallback_required": False,
        "recommended_working_set": source_docs,
    }
