from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .canonical_json import sanitize_text
from .hashing import stable_json_hash
from .safety import redaction_block_reason
from .store_layout import ensure_context_store, preferred_state_dir
from .storage import append_jsonl, read_json, read_jsonl, write_json

PROMPT_MEMORY_MODES = ("off", "summary", "full-redacted", "full-local-only")
DEFAULT_PROMPT_MEMORY_MODE = "summary"


def prompt_store(project: Path, create: bool = True) -> Path:
    if create:
        ensure_context_store(project)
    return preferred_state_dir(project)


def prompt_memory_status(project: Path) -> dict[str, Any]:
    store = prompt_store(project, create=False)
    exists = store.exists()
    config = read_json(store / "config.json", {}) if exists else {}
    prompt_records = sorted((store / "conversations").glob("pr_*.json")) if exists else []
    return {
        "project": str(project.resolve()),
        "store": str(store),
        "store_exists": exists,
        "prompt_memory_default": config.get("prompt_memory", DEFAULT_PROMPT_MEMORY_MODE),
        "supported_modes": list(PROMPT_MEMORY_MODES),
        "prompt_record_count": len(prompt_records),
        "raw_prompt_response_auto_capture": False,
        "team_sync_pushes_local_only": False,
    }


def _next_record_id(store: Path) -> str:
    return f"pr_{len(list((store / 'conversations').glob('pr_*.json'))) + 1:06d}"


def _summarize_text(text: str, label: str) -> str:
    text = sanitize_text(text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    selected = []
    for line in lines:
        if re.search(r"\b(decision|gate|risk|todo|next|summary|test|failed|passed|implement|fix)\b", line, re.I):
            selected.append(line)
    if not selected:
        selected = lines[:4]
    summary = " ".join(selected[:6])
    return f"{label}: {summary[:900]}" if summary else f"{label}: empty"


def redact_text(text: str) -> dict[str, Any]:
    text = sanitize_text(text)
    redacted = text
    hits: list[str] = []
    patterns = [
        ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
        ("env_assignment", r"(?im)^\s*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*\s*=\s*.+$"),
        ("password_field", r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|api_key|private_key)\s*[:=]\s*[^\s,;]+"),
        ("jwt_like", r"\b[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
        ("provider_key", r"\b(?:sk|pk|ghp|github_pat|xox[baprs])-?[A-Za-z0-9_=-]{20,}\b"),
    ]
    for name, pattern in patterns:
        new = re.sub(pattern, f"[REDACTED:{name}]", redacted, flags=re.S)
        if new != redacted:
            hits.append(name)
            redacted = new
    return {"text": redacted, "hits": sorted(set(hits)), "redacted": bool(hits)}


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sanitize_text(text), encoding="utf-8")


def record_prompt_response(project: Path, prompt_file: Path, response_file: Path, task: str, mode: str = DEFAULT_PROMPT_MEMORY_MODE) -> dict[str, Any]:
    if mode not in PROMPT_MEMORY_MODES:
        raise ValueError("unsupported_prompt_memory_mode")
    if mode == "off":
        return {"recorded": False, "mode": mode, "reason": "prompt_memory_off"}
    prompt_text = prompt_file.read_text(encoding="utf-8")
    response_text = response_file.read_text(encoding="utf-8")
    prompt_text = sanitize_text(prompt_text)
    response_text = sanitize_text(response_text)
    task = sanitize_text(task)
    store = prompt_store(project)
    record_id = _next_record_id(store)
    prompt_id = f"prompt_{record_id[3:]}"
    response_id = f"response_{record_id[3:]}"
    prompt_redaction = redact_text(prompt_text)
    response_redaction = redact_text(response_text)
    local_only = mode == "full-local-only"
    if local_only and (redaction_block_reason(prompt_text) or redaction_block_reason(response_text)):
        raise ValueError("local_only_prompt_memory_secret_like_content_blocked")
    stored_prompt_text = ""
    stored_response_text = ""
    prompt_summary = _summarize_text(prompt_redaction["text"], "prompt")
    response_summary = _summarize_text(response_redaction["text"], "response")
    if mode == "summary":
        stored_prompt_path = None
        stored_response_path = None
    elif mode == "full-redacted":
        stored_prompt_text = prompt_redaction["text"]
        stored_response_text = response_redaction["text"]
        stored_prompt_path = f"prompts/{prompt_id}.md"
        stored_response_path = f"responses/{response_id}.md"
        _write_text(store / stored_prompt_path, stored_prompt_text)
        _write_text(store / stored_response_path, stored_response_text)
    else:
        stored_prompt_text = prompt_text
        stored_response_text = response_text
        stored_prompt_path = f"prompts/{prompt_id}.local.md"
        stored_response_path = f"responses/{response_id}.local.md"
        _write_text(store / stored_prompt_path, stored_prompt_text)
        _write_text(store / stored_response_path, stored_response_text)
    summary_path = f"prompt-summaries/{record_id}.md"
    summary_text = "\n".join(
        [
            f"# Prompt Memory Summary {record_id}",
            "",
            f"- task: {task}",
            f"- mode: {mode}",
            f"- prompt_id: {prompt_id}",
            f"- response_id: {response_id}",
            f"- local_only: {str(local_only).lower()}",
            f"- redaction_status: {redaction_status(prompt_redaction, response_redaction)}",
            "",
            "## Prompt Summary",
            prompt_summary,
            "",
            "## Response Summary",
            response_summary,
            "",
        ]
    )
    _write_text(store / summary_path, summary_text)
    semantic = {
        "task": task,
        "mode": mode,
        "prompt_hash": stable_json_hash({"prompt": prompt_text}),
        "response_hash": stable_json_hash({"response": response_text}),
        "prompt_summary": prompt_summary,
        "response_summary": response_summary,
    }
    record = {
        "schema": "ithz_prompt_memory_record_v1",
        "record_id": record_id,
        "prompt_id": prompt_id,
        "response_id": response_id,
        "task": task,
        "mode": mode,
        "local_only": local_only,
        "prompt_hash": semantic["prompt_hash"],
        "response_hash": semantic["response_hash"],
        "semantic_prompt_hash": stable_json_hash(semantic),
        "prompt_summary": prompt_summary,
        "response_summary": response_summary,
        "prompt_path": stored_prompt_path,
        "response_path": stored_response_path,
        "summary_path": summary_path,
        "redaction_status": redaction_status(prompt_redaction, response_redaction),
        "redaction_hits": sorted(set(prompt_redaction["hits"] + response_redaction["hits"])),
        "team_sync_allowed": not local_only,
    }
    write_json(store / "conversations" / f"{record_id}.json", record)
    append_jsonl(store / "prompt_memory_events.jsonl", {"type": "prompt_memory_record", "record_id": record_id, "semantic_prompt_hash": record["semantic_prompt_hash"], "mode": mode})
    return record


def redaction_status(prompt_redaction: dict[str, Any], response_redaction: dict[str, Any]) -> str:
    return "redacted" if prompt_redaction["redacted"] or response_redaction["redacted"] else "clean"


def prompt_log(project: Path) -> list[dict[str, Any]]:
    store = prompt_store(project, create=False)
    if not store.exists():
        return []
    rows = []
    for path in sorted((store / "conversations").glob("pr_*.json")):
        rows.append(read_json(path))
    return rows


def prompt_search(project: Path, query: str, limit: int = 20) -> list[dict[str, Any]]:
    terms = [t.lower() for t in re.findall(r"[A-Za-z0-9_./:-]+", query)]
    rows = []
    for record in prompt_log(project):
        hay = (record.get("task", "") + "\n" + record.get("prompt_summary", "") + "\n" + record.get("response_summary", "")).lower()
        score = sum(1 for term in terms if term and term in hay)
        if score:
            rows.append({**record, "score": score})
    rows.sort(key=lambda r: (-r["score"], r["record_id"]))
    return rows[:limit]


def prompt_context_pack(project: Path, query: str, max_bytes: int = 20000) -> dict[str, Any]:
    matches = prompt_search(project, query, 30)
    lines = [
        "# ITHZ-MCP Prompt Context Pack",
        "",
        f"- query: {query}",
        f"- record_count: {len(matches)}",
        "",
        "## Prompt / Response Summaries",
    ]
    if not matches:
        lines.append("- Not enough prompt-memory evidence found.")
    for row in matches:
        lines += [
            f"### {row['record_id']} ({row['mode']})",
            f"- task: {row['task']}",
            f"- prompt_id: {row['prompt_id']}",
            f"- response_id: {row['response_id']}",
            f"- redaction_status: {row['redaction_status']}",
            f"- local_only: {row['local_only']}",
            f"- prompt_summary: {row['prompt_summary']}",
            f"- response_summary: {row['response_summary']}",
        ]
    lines += [
        "",
        "## Decisions and Gates",
        "- Prompt memory complements context commits. Use context-log for the commit DAG and gate history.",
        "",
        "## Safety Notes",
        "- Raw prompt/response text is not captured automatically.",
        "- Local-only prompt memory is skipped by team sync.",
    ]
    text = "\n".join(lines).rstrip() + "\n"
    if len(text.encode("utf-8")) > max_bytes:
        marker = "\n[truncated]\n"
        text = text.encode("utf-8")[: max(0, max_bytes - len(marker))].decode("utf-8", errors="ignore") + marker
    return {"text": text, "bytes": len(text.encode("utf-8")), "context_pack_hash": stable_json_hash({"query": query, "matches": matches})}


def validate_prompt_memory(project: Path) -> dict[str, Any]:
    errors = []
    try:
        store = prompt_store(project, create=False)
        if not store.exists():
            return {"valid": True, "errors": [], "store_exists": False}
        for event in read_jsonl(store / "prompt_memory_events.jsonl"):
            if not isinstance(event, dict) or event.get("type") != "prompt_memory_record":
                errors.append({"scope": "event", "error": "invalid_prompt_memory_event"})
    except Exception as exc:
        errors.append({"scope": "event", "error": "corrupt_prompt_memory_events", "detail": str(exc)})
    for path in sorted((store / "conversations").glob("pr_*.json")):
        try:
            record = read_json(path)
        except Exception as exc:
            errors.append({"scope": "record", "path": path.name, "error": "corrupt_prompt_record", "detail": str(exc)})
            continue
        for field in ("record_id", "prompt_id", "response_id", "mode", "semantic_prompt_hash"):
            if field not in record:
                errors.append({"scope": "record", "path": path.name, "error": f"missing_{field}"})
        if record.get("mode") not in PROMPT_MEMORY_MODES:
            errors.append({"scope": "record", "path": path.name, "error": "invalid_mode"})
    return {"valid": not errors, "errors": errors}
