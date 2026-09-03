from __future__ import annotations

from contextlib import contextmanager
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty, dumps
from .hashing import sha256_file, stable_json_hash
from .native_archive_store import (
    ARCHIVE_NAME,
    BRANCH_MAIN_PATH,
    CONTEXT_COMMIT_INDEX_PATH,
    DECISION_LOG_PATH,
    EVENT_LOG_PATH,
    PROMPT_LOG_PATH,
    REF_HEAD_PATH,
    REF_INDEX_PATH,
    REF_MAIN_PATH,
    WORKFLOW_INDEX_PATH,
    WORKFLOW_PROMPT_LOG_PATH,
    _event_semantic_key,
    _jsonl_bytes,
    _layer_update_bytes,
    _load_archive_json_optional,
    _load_archive_jsonl_optional,
    _prompt_semantic_key,
    _run_native,
    _text_bytes,
    extract_archive_file_bytes,
    locate_native_ithz,
    native_archive_status,
    project_archive_path,
    update_archive_files_bytes,
)
from .safety import redaction_block_reason
from .workflow_profiles import workflow_profile_path


@contextmanager
def _archive_project(archive: Path):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "project"
        project.mkdir()
        shutil.copy2(archive, project / ARCHIVE_NAME)
        yield project


def _read_text_optional(project: Path, inner_path: str, default: str = "") -> str:
    try:
        return extract_archive_file_bytes(project, inner_path).decode("utf-8-sig").strip()
    except RuntimeError as exc:
        if "path not found" in str(exc):
            return default
        raise


def _archive_layers(archive: Path) -> dict[str, Any]:
    with _archive_project(archive) as project:
        status = native_archive_status(project)
        events = _load_archive_jsonl_optional(project, EVENT_LOG_PATH)
        prompts = _load_archive_jsonl_optional(project, PROMPT_LOG_PATH)
        decisions = _load_archive_jsonl_optional(project, DECISION_LOG_PATH)
        manifest = _load_archive_json_optional(project, "manifest.json", {})
        commit_index = _load_archive_json_optional(project, CONTEXT_COMMIT_INDEX_PATH, {})
        ref_index = _load_archive_json_optional(project, REF_INDEX_PATH, {})
        workflow_index = _load_archive_json_optional(project, WORKFLOW_INDEX_PATH, {"profiles": [], "default_profile": ""})
        workflow_prompts = _load_archive_jsonl_optional(project, WORKFLOW_PROMPT_LOG_PATH)
        workflow_profiles = {}
        if isinstance(workflow_index, dict):
            for row in workflow_index.get("profiles", []):
                profile_id = str(row.get("profile_id", ""))
                if profile_id:
                    workflow_profiles[profile_id] = _load_archive_json_optional(project, workflow_profile_path(profile_id), {})
        return {
            "archive": str(archive),
            "status": status,
            "manifest": manifest,
            "events": events,
            "prompts": prompts,
            "decisions": decisions,
            "commit_index": commit_index,
            "ref_index": ref_index,
            "workflow_index": workflow_index,
            "workflow_profiles": workflow_profiles,
            "workflow_prompts": workflow_prompts,
            "HEAD": _read_text_optional(project, REF_HEAD_PATH),
            "main": _read_text_optional(project, REF_MAIN_PATH),
            "archive_sha256": sha256_file(archive),
        }


def git_diff_ithz(archive: Path) -> str:
    layers = _archive_layers(archive)
    manifest = layers["manifest"]
    ref_index = layers["ref_index"] if isinstance(layers["ref_index"], dict) else {}
    prompts = [p for p in layers["prompts"] if not p.get("local_only")]
    private_count = len(layers["prompts"]) - len(prompts)
    lines = [
        "ITHZ project memory archive",
        f"archive: {archive}",
        f"archive_sha256: {layers['archive_sha256']}",
        f"schema: {manifest.get('schema')}",
        f"archive_semantic_hash: {manifest.get('archive_semantic_hash')}",
        f"project_semantic_hash: {manifest.get('project_semantic_hash')}",
        f"context_commit_count: {layers['commit_index'].get('commit_count', 0) if isinstance(layers['commit_index'], dict) else 0}",
        f"latest_context_commit: {layers.get('HEAD') or ref_index.get('HEAD', '')}",
        f"event_count: {len(layers['events'])}",
        f"decision_count: {len([e for e in layers['events'] if e.get('kind') == 'decision'])}",
        f"gate_result_count: {len([e for e in layers['events'] if e.get('kind') == 'gate'])}",
        f"risk_count: {len([e for e in layers['events'] if e.get('kind') in {'risk', 'must_not_break'}])}",
        f"prompt_summary_count: {len(prompts)}",
        f"private_local_only_count: {private_count}",
        f"workflow_profile_count: {len(layers['workflow_profiles'])}",
        f"workflow_default_profile: {layers['workflow_index'].get('default_profile', '') if isinstance(layers['workflow_index'], dict) else ''}",
        f"refs: {dumps(ref_index.get('refs', {}) if isinstance(ref_index, dict) else {})}",
        f"branches: {dumps(ref_index.get('branches', {}) if isinstance(ref_index, dict) else {})}",
    ]
    for event in layers["events"]:
        lines.append(f"- {event.get('event_id')} [{event.get('kind')}] {str(event.get('text', ''))[:160]}")
    return "\n".join(lines) + "\n"


def _validate_layer_payloads(name: str, layers: dict[str, Any]) -> list[str]:
    errors = []
    if not layers["status"].get("safe_verify_ok"):
        errors.append(f"{name}:archive_verify_failed")
    for event in layers["events"]:
        if redaction_block_reason(dumps(event)):
            errors.append(f"{name}:secret_like_event:{event.get('event_id')}")
    for prompt in layers["prompts"]:
        if prompt.get("local_only"):
            continue
        if redaction_block_reason(dumps(prompt)):
            errors.append(f"{name}:secret_like_prompt:{prompt.get('record_id')}")
    return errors


def _merge_events(base: list[dict[str, Any]], ours: list[dict[str, Any]], theirs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    conflicts: list[str] = []
    base_by_id = {str(e.get("event_id")): _event_semantic_key(e) for e in base if e.get("event_id")}
    for side_name, side in (("ours", ours), ("theirs", theirs)):
        for event in side:
            eid = str(event.get("event_id", ""))
            key = _event_semantic_key(event)
            if eid in base_by_id and base_by_id[eid] != key:
                conflicts.append(f"{side_name}:historical_event_modified:{eid}")
    if conflicts:
        return [], conflicts
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for event in base:
        key = _event_semantic_key(event)
        if key not in seen:
            merged.append(dict(event))
            seen.add(key)
    new_events = []
    for event in [*ours, *theirs]:
        key = _event_semantic_key(event)
        if key not in seen:
            new_events.append(dict(event))
            seen.add(key)
    new_events.sort(key=lambda e: (_event_semantic_key(e), str(e.get("source", "")), str(e.get("text", ""))))
    next_id = len(merged) + 1
    for event in new_events:
        original = event.get("event_id")
        event["merged_from_event_id"] = original
        event["event_id"] = f"evt_{next_id:06d}"
        next_id += 1
        merged.append(event)
    return merged, []


def _merge_prompts(base: list[dict[str, Any]], ours: list[dict[str, Any]], theirs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str], int]:
    conflicts: list[str] = []
    skipped_private = 0
    base_by_id = {str(p.get("record_id")): _prompt_semantic_key(p) for p in base if p.get("record_id")}
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for prompt in base:
        if prompt.get("local_only"):
            skipped_private += 1
            continue
        key = _prompt_semantic_key(prompt)
        merged.append(dict(prompt))
        seen.add(key)
    new_prompts = []
    for side_name, side in (("ours", ours), ("theirs", theirs)):
        for prompt in side:
            if prompt.get("local_only"):
                skipped_private += 1
                continue
            rid = str(prompt.get("record_id", ""))
            key = _prompt_semantic_key(prompt)
            if rid in base_by_id and base_by_id[rid] != key:
                conflicts.append(f"{side_name}:historical_prompt_modified:{rid}")
            elif key not in seen:
                new_prompts.append(dict(prompt))
                seen.add(key)
    if conflicts:
        return [], conflicts, skipped_private
    new_prompts.sort(key=lambda p: (_prompt_semantic_key(p), str(p.get("task", ""))))
    next_id = len(merged) + 1
    for prompt in new_prompts:
        original = prompt.get("record_id")
        prompt["merged_from_record_id"] = original
        prompt["record_id"] = f"pr_{next_id:06d}"
        prompt["prompt_id"] = f"prompt_{next_id:06d}"
        prompt["response_id"] = f"response_{next_id:06d}"
        next_id += 1
        merged.append(prompt)
    return merged, [], skipped_private


def _workflow_hash(profile: dict[str, Any]) -> str:
    existing = profile.get("profile_hash")
    if isinstance(existing, str) and existing:
        return existing
    return stable_json_hash(profile)


def _workflow_prompt_hash(row: dict[str, Any]) -> str:
    existing = row.get("workflow_prompt_hash")
    if isinstance(existing, str) and existing:
        return existing
    return stable_json_hash(row)


def _merge_default_ref(base_default: str, ours_default: str, theirs_default: str) -> tuple[str, list[str]]:
    if ours_default == theirs_default:
        return ours_default, []
    if ours_default == base_default:
        return theirs_default, []
    if theirs_default == base_default:
        return ours_default, []
    return base_default, [f"workflow_default_profile_diverged:ours={ours_default}:theirs={theirs_default}"]


def _merge_workflows(base_layers: dict[str, Any], ours_layers: dict[str, Any], theirs_layers: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, Any], list[dict[str, Any]], list[str]]:
    conflicts: list[str] = []
    base_profiles = base_layers.get("workflow_profiles", {}) if isinstance(base_layers.get("workflow_profiles"), dict) else {}
    ours_profiles = ours_layers.get("workflow_profiles", {}) if isinstance(ours_layers.get("workflow_profiles"), dict) else {}
    theirs_profiles = theirs_layers.get("workflow_profiles", {}) if isinstance(theirs_layers.get("workflow_profiles"), dict) else {}
    merged: dict[str, dict[str, Any]] = {pid: dict(profile) for pid, profile in base_profiles.items()}
    all_ids = sorted(set(base_profiles) | set(ours_profiles) | set(theirs_profiles))
    for pid in all_ids:
        base = base_profiles.get(pid)
        ours = ours_profiles.get(pid)
        theirs = theirs_profiles.get(pid)
        base_hash = _workflow_hash(base) if base else ""
        ours_hash = _workflow_hash(ours) if ours else ""
        theirs_hash = _workflow_hash(theirs) if theirs else ""
        if base is None:
            if ours and theirs and ours_hash != theirs_hash:
                conflicts.append(f"workflow_profile_added_differently:{pid}")
            elif ours:
                merged[pid] = dict(ours)
            elif theirs:
                merged[pid] = dict(theirs)
            continue
        if ours_hash == theirs_hash and ours:
            merged[pid] = dict(ours)
        elif ours_hash == base_hash and theirs:
            merged[pid] = dict(theirs)
        elif theirs_hash == base_hash and ours:
            merged[pid] = dict(ours)
        elif ours_hash != base_hash and theirs_hash != base_hash:
            conflicts.append(f"workflow_profile_diverged:{pid}")
    base_default = str((base_layers.get("workflow_index") or {}).get("default_profile", ""))
    ours_default = str((ours_layers.get("workflow_index") or {}).get("default_profile", base_default))
    theirs_default = str((theirs_layers.get("workflow_index") or {}).get("default_profile", base_default))
    default_profile, default_conflicts = _merge_default_ref(base_default, ours_default, theirs_default)
    conflicts.extend(default_conflicts)
    prompt_rows: list[dict[str, Any]] = []
    seen_prompts: set[str] = set()
    for row in [*(base_layers.get("workflow_prompts") or []), *(ours_layers.get("workflow_prompts") or []), *(theirs_layers.get("workflow_prompts") or [])]:
        key = _workflow_prompt_hash(row)
        if key not in seen_prompts:
            prompt_rows.append(dict(row))
            seen_prompts.add(key)
    prompt_rows.sort(key=lambda row: (_workflow_prompt_hash(row), str(row.get("profile_id", ""))))
    profile_rows = [
        {
            "profile_id": pid,
            "owner": profile.get("owner", ""),
            "revision": profile.get("revision", 0),
            "profile_hash": _workflow_hash(profile),
            "source_count": len(profile.get("source_docs", [])),
            "prompt_update_count": int(profile.get("prompt_update_count", 0)),
        }
        for pid, profile in sorted(merged.items())
    ]
    index = {"schema": "ithz_mcp_workflow_profile_index_v1", "default_profile": default_profile, "profiles": profile_rows}
    index["workflow_index_hash"] = stable_json_hash({"default_profile": default_profile, "profiles": profile_rows})
    return merged, index, prompt_rows, conflicts


def git_merge_ithz(base: Path, ours: Path, theirs: Path, out: Path, report: Path | None = None) -> dict[str, Any]:
    base_layers = _archive_layers(base)
    ours_layers = _archive_layers(ours)
    theirs_layers = _archive_layers(theirs)
    conflicts = []
    conflicts.extend(_validate_layer_payloads("base", base_layers))
    conflicts.extend(_validate_layer_payloads("ours", ours_layers))
    conflicts.extend(_validate_layer_payloads("theirs", theirs_layers))
    merged_events, event_conflicts = _merge_events(base_layers["events"], ours_layers["events"], theirs_layers["events"])
    conflicts.extend(event_conflicts)
    merged_prompts, prompt_conflicts, skipped_private = _merge_prompts(base_layers["prompts"], ours_layers["prompts"], theirs_layers["prompts"])
    conflicts.extend(prompt_conflicts)
    merged_workflows, workflow_index, workflow_prompts, workflow_conflicts = _merge_workflows(base_layers, ours_layers, theirs_layers)
    conflicts.extend(workflow_conflicts)
    result = {
        "schema": "ithz_mcp_git_merge_result_v1",
        "base": str(base),
        "ours": str(ours),
        "theirs": str(theirs),
        "out": str(out),
        "merge_needed": bool(conflicts),
        "conflicts": conflicts,
        "event_count": len(merged_events),
        "prompt_summary_count": len(merged_prompts),
        "workflow_profile_count": len(merged_workflows),
        "private_local_only_skipped": skipped_private,
    }
    report_lines = [
        "# ITHZ Merge Report",
        "",
        f"- merge_needed: {str(bool(conflicts)).lower()}",
        f"- conflicts: {len(conflicts)}",
        f"- merged_events: {len(merged_events)}",
        f"- merged_prompt_summaries: {len(merged_prompts)}",
        f"- merged_workflow_profiles: {len(merged_workflows)}",
        f"- private_local_only_skipped: {skipped_private}",
        "",
    ]
    if conflicts:
        report_lines.extend(["## Conflicts", *[f"- {c}" for c in conflicts], ""])
    if report is None:
        report = out.with_suffix(out.suffix + ".merge_report.md")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(report_lines), encoding="utf-8")
    result["report"] = str(report)
    if conflicts:
        return result
    with _archive_project(ours) as project:
        manifest = _load_archive_json_optional(project, "manifest.json", {})
        manifest["memory_event_count"] = len(merged_events)
        manifest["prompt_record_count"] = len(merged_prompts)
        manifest["workflow_profile_count"] = len(merged_workflows)
        manifest["workflow_default_profile"] = workflow_index.get("default_profile", "")
        manifest["workflow_index_hash"] = workflow_index.get("workflow_index_hash", "")
        manifest["merge_driver"] = {
            "schema": "ithz_mcp_git_merge_driver_v1",
            "base_sha256": sha256_file(base),
            "ours_sha256": sha256_file(ours),
            "theirs_sha256": sha256_file(theirs),
            "merged_event_count": len(merged_events),
            "merged_prompt_summary_count": len(merged_prompts),
            "merged_workflow_profile_count": len(merged_workflows),
            "private_local_only_skipped": skipped_private,
        }
        layer_updates = _layer_update_bytes(merged_events, merged_prompts)
        layer_updates[PROMPT_LOG_PATH] = _jsonl_bytes(merged_prompts)
        layer_updates[WORKFLOW_INDEX_PATH] = dump_pretty(workflow_index).encode("utf-8")
        layer_updates[WORKFLOW_PROMPT_LOG_PATH] = _jsonl_bytes(workflow_prompts)
        for pid, profile in merged_workflows.items():
            layer_updates[workflow_profile_path(pid)] = dump_pretty(profile).encode("utf-8")
        layer_updates["manifest.json"] = dump_pretty(manifest).encode("utf-8")
        update_archive_files_bytes(project, layer_updates, expected_archive_sha256=sha256_file(project_archive_path(project)))
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(project_archive_path(project), out)
    result["archive_sha256"] = sha256_file(out)
    return result


def install_git_drivers(repo: Path, dry_run: bool = False) -> dict[str, Any]:
    repo = repo.resolve()
    attrs = repo / ".gitattributes"
    attr_line = "*.ithz merge=ithz diff=ithz binary"
    existing = attrs.read_text(encoding="utf-8") if attrs.exists() else ""
    actions = []
    if attr_line not in existing.splitlines():
        actions.append({"action": "append_gitattributes", "line": attr_line})
        if not dry_run:
            attrs.write_text((existing.rstrip("\n") + "\n" + attr_line + "\n").lstrip("\n"), encoding="utf-8")
    merge_driver = "python -m ithz_mcp git-merge-ithz --base %O --ours %A --theirs %B --out %A"
    diff_driver = "python -m ithz_mcp git-diff-ithz --archive"
    actions.extend(
        [
            {"action": "git_config", "key": "merge.ithz.name", "value": "ITHZ semantic merge driver"},
            {"action": "git_config", "key": "merge.ithz.driver", "value": merge_driver},
            {"action": "git_config", "key": "diff.ithz.textconv", "value": diff_driver},
        ]
    )
    if not dry_run:
        subprocess.run(["git", "config", "merge.ithz.name", "ITHZ semantic merge driver"], cwd=str(repo), check=True)
        subprocess.run(["git", "config", "merge.ithz.driver", merge_driver], cwd=str(repo), check=True)
        subprocess.run(["git", "config", "diff.ithz.textconv", diff_driver], cwd=str(repo), check=True)
    return {"repo": str(repo), "dry_run": dry_run, "actions": actions}


def git_driver_status(repo: Path) -> dict[str, Any]:
    repo = repo.resolve()
    attrs = repo / ".gitattributes"
    attr_present = attrs.exists() and "*.ithz merge=ithz diff=ithz binary" in attrs.read_text(encoding="utf-8").splitlines()

    def cfg(key: str) -> str:
        result = subprocess.run(["git", "config", "--get", key], cwd=str(repo), text=True, capture_output=True, check=False)
        return result.stdout.strip()

    return {
        "repo": str(repo),
        "gitattributes_present": attr_present,
        "merge_driver": cfg("merge.ithz.driver"),
        "diff_textconv": cfg("diff.ithz.textconv"),
    }
