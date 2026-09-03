from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from .context_index import build_index, load_or_build_index
from .hashing import sha256_file, stable_json_hash
from .prompt_memory import prompt_log
from .safety import redaction_block_reason
from .storage import append_jsonl, ensure_state, read_json, read_jsonl, state_dir, write_json


def _commit_files(project: Path) -> list[Path]:
    return sorted((state_dir(project) / "commits").glob("ctx_*.json"))


def next_commit_id(project: Path) -> str:
    return f"ctx_{len(_commit_files(project)) + 1:06d}"


def latest_commit_id(project: Path) -> str | None:
    files = _commit_files(project)
    return files[-1].stem if files else None


def record_task_summary(project: Path, summary_file: Path) -> dict[str, Any]:
    ensure_state(project)
    text = summary_file.read_text(encoding="utf-8")
    if redaction_block_reason(text):
        raise ValueError("summary contains secret-like content")
    out = state_dir(project) / "logs" / f"task_summary_{len(list((state_dir(project) / 'logs').glob('task_summary_*.md'))) + 1:06d}.md"
    out.write_text(text, encoding="utf-8")
    event = {"type": "task_summary", "path": str(out.relative_to(state_dir(project))), "summary_hash": stable_json_hash({"text": text})}
    append_jsonl(state_dir(project) / "events.jsonl", event)
    return event


def context_commit(
    project: Path,
    task: str,
    summary_file: Path | None = None,
    include_git: bool = False,
    private: bool = False,
    prompt_ids: list[str] | None = None,
    response_ids: list[str] | None = None,
) -> dict[str, Any]:
    ensure_state(project)
    index = build_index(project)
    cid = next_commit_id(project)
    parent = latest_commit_id(project)
    summary = summary_file.read_text(encoding="utf-8") if summary_file and summary_file.exists() else ""
    if redaction_block_reason(summary):
        raise ValueError("summary contains secret-like content")
    prompt_records = prompt_log(project)
    selected_prompt_ids = prompt_ids or []
    selected_response_ids = response_ids or []
    linked_records = []
    if selected_prompt_ids or selected_response_ids:
        wanted_prompts = set(selected_prompt_ids)
        wanted_responses = set(selected_response_ids)
        linked_records = [r for r in prompt_records if r.get("prompt_id") in wanted_prompts or r.get("response_id") in wanted_responses]
    elif prompt_records:
        syncable_records = [r for r in prompt_records if not r.get("local_only")]
        linked_records = syncable_records[-1:] if syncable_records else []
    syncable_linked_records = [r for r in linked_records if not r.get("local_only")]
    if syncable_linked_records:
        selected_prompt_ids = [linked_records[0]["prompt_id"]]
        selected_response_ids = [linked_records[0]["response_id"]]
    commit: dict[str, Any] = {
        "type": "context_commit",
        "context_commit_id": cid,
        "parent": parent,
        "parents": [parent] if parent else [],
        "task": task,
        "agent": "Codex",
        "context_pack_hash": "",
        "project_tree_hash_before": index["project_semantic_hash"],
        "project_tree_hash_after": index["project_semantic_hash"],
        "changed_files": [],
        "commands": [],
        "gate_results": [],
        "decisions": extract_decisions(summary),
        "known_risks": extract_lines(summary, ("risk", "limitation")),
        "next_steps": extract_lines(summary, ("next", "todo")),
        "semantic_project_state_hash": index["project_semantic_hash"],
        "summary_hash": stable_json_hash({"summary": summary}),
        "private": bool(private),
        "prompt_ids": selected_prompt_ids,
        "response_ids": selected_response_ids,
        "prompt_summary": "\n".join(r.get("prompt_summary", "") for r in syncable_linked_records)[:2000],
        "response_summary": "\n".join(r.get("response_summary", "") for r in syncable_linked_records)[:2000],
        "prompt_memory_mode": ",".join(sorted({r.get("mode", "") for r in linked_records if r.get("mode")})),
        "redaction_status": ",".join(sorted({r.get("redaction_status", "") for r in linked_records if r.get("redaction_status")})),
    }
    if include_git:
        commit["git"] = git_status(project)
    commit["semantic_context_hash"] = stable_json_hash({k: v for k, v in commit.items() if k != "context_commit_id"})
    write_json(state_dir(project) / "commits" / f"{cid}.json", commit)
    append_jsonl(state_dir(project) / "events.jsonl", {"type": "context_commit", "id": cid, "semantic_context_hash": commit["semantic_context_hash"]})
    write_ref(project, "latest", cid)
    main_branch = state_dir(project) / "branches" / "main"
    if not main_branch.exists():
        write_json(main_branch, {"name": "main", "head": cid})
    else:
        data = read_json(main_branch, {})
        data["head"] = cid
        write_json(main_branch, data)
    return commit


def extract_decisions(text: str) -> list[str]:
    return extract_lines(text, ("decision", "rozhodnutie"))


def extract_lines(text: str, terms: tuple[str, ...]) -> list[str]:
    rows = []
    for line in text.splitlines():
        lowered = line.lower()
        if any(t in lowered for t in terms):
            rows.append(line.strip())
    return rows


def context_log(project: Path) -> list[dict[str, Any]]:
    rows = []
    for p in _commit_files(project):
        rows.append(read_json(p))
    return rows


def validate_dag(project: Path) -> dict[str, Any]:
    commits = {c["context_commit_id"]: c for c in context_log(project)}
    missing = []
    for c in commits.values():
        for parent in c.get("parents", []):
            if parent and parent not in commits:
                missing.append({"commit": c["context_commit_id"], "missing_parent": parent})
    return {"valid": not missing, "missing": missing, "commit_count": len(commits)}


def validate_context_integrity(project: Path) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    commits: dict[str, dict[str, Any]] = {}
    try:
        for event in read_jsonl(state_dir(project) / "events.jsonl"):
            if not isinstance(event, dict) or "type" not in event:
                errors.append({"scope": "events", "error": "missing_required_field"})
    except Exception as exc:
        errors.append({"scope": "events", "error": "corrupt_events_jsonl", "detail": str(exc)})
    seen: set[str] = set()
    for path in _commit_files(project):
        try:
            commit = read_json(path)
        except Exception as exc:
            errors.append({"scope": "commit", "path": path.name, "error": "corrupt_commit_json", "detail": str(exc)})
            continue
        cid = commit.get("context_commit_id")
        if not cid:
            errors.append({"scope": "commit", "path": path.name, "error": "missing_context_commit_id"})
            continue
        if cid in seen:
            errors.append({"scope": "commit", "path": path.name, "error": "duplicate_context_commit_id", "id": cid})
        seen.add(cid)
        commits[cid] = commit
        if "task" not in commit:
            errors.append({"scope": "commit", "path": path.name, "error": "missing_task"})
        if not isinstance(commit.get("changed_files", []), list):
            errors.append({"scope": "commit", "path": path.name, "error": "invalid_changed_files_type"})
        expected_hash = stable_json_hash({k: v for k, v in commit.items() if k not in {"context_commit_id", "semantic_context_hash"}})
        if commit.get("semantic_context_hash") and commit.get("semantic_context_hash") != expected_hash:
            errors.append({"scope": "commit", "path": path.name, "error": "invalid_semantic_hash"})
    for cid, commit in commits.items():
        for parent in commit.get("parents", []):
            if parent and parent not in commits:
                errors.append({"scope": "dag", "commit": cid, "error": "missing_parent", "parent": parent})
    for folder in ("refs", "branches", "tags"):
        base = state_dir(project) / folder
        if not base.exists():
            continue
        for ref in sorted(base.iterdir(), key=lambda p: p.name):
            if not ref.is_file():
                continue
            try:
                data = read_json(ref)
            except Exception as exc:
                errors.append({"scope": folder, "path": ref.name, "error": "corrupt_ref", "detail": str(exc)})
                continue
            head = data.get("head")
            if head and head not in commits:
                errors.append({"scope": folder, "path": ref.name, "error": "ref_points_to_missing_commit", "head": head})
    return {"valid": not errors, "errors": errors, "commit_count": len(commits)}


def context_diff(project: Path, a: str, b: str) -> dict[str, Any]:
    commits = {c["context_commit_id"]: c for c in context_log(project)}
    ca, cb = commits.get(a), commits.get(b)
    if not ca or not cb:
        raise ValueError("unknown context commit")
    return {
        "from": a,
        "to": b,
        "decisions_added": [d for d in cb.get("decisions", []) if d not in ca.get("decisions", [])],
        "hash_from": ca.get("semantic_context_hash"),
        "hash_to": cb.get("semantic_context_hash"),
    }


def write_ref(project: Path, name: str, commit_id: str) -> None:
    write_json(state_dir(project) / "refs" / name, {"ref": name, "head": commit_id})


def context_branch(project: Path, name: str) -> dict[str, Any]:
    ensure_state(project)
    head = latest_commit_id(project)
    data = {"name": name, "head": head}
    write_json(state_dir(project) / "branches" / name, data)
    return data


def context_tag(project: Path, name: str, force: bool = False) -> dict[str, Any]:
    ensure_state(project)
    path = state_dir(project) / "tags" / name
    if path.exists() and not force:
        raise ValueError("tag exists; use force to replace")
    data = {"name": name, "head": latest_commit_id(project), "immutable": not force}
    write_json(path, data)
    return data


def git_status(project: Path) -> dict[str, Any]:
    def run(args: list[str]) -> str:
        return subprocess.check_output(["git", *args], cwd=str(project), text=True, stderr=subprocess.STDOUT).strip()
    try:
        root = run(["rev-parse", "--show-toplevel"])
        branch = run(["branch", "--show-current"])
        commit = run(["rev-parse", "HEAD"])
        short_commit = run(["rev-parse", "--short=12", "HEAD"])
        subject = run(["log", "-1", "--format=%s"])
        ref_names = run(["log", "-1", "--format=%D"])
        porcelain = run(["status", "--porcelain=v1"])
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    dirty = sorted(line[3:] for line in porcelain.splitlines() if line)
    return {
        "available": True,
        "root": root,
        "git_branch": branch,
        "git_commit_hash": commit,
        "git_commit_short_hash": short_commit,
        "git_commit_subject": subject,
        "git_commit_subject_hash": stable_json_hash({"git_commit_subject": subject}),
        "git_commit_ref_names": ref_names,
        "git_dirty_files": dirty,
        "git_status_porcelain_hash": stable_json_hash({"status": porcelain}),
    }


def decisions_between_git(project: Path, a: str, b: str) -> dict[str, Any]:
    rows = []
    for c in context_log(project):
        git = c.get("git") or {}
        h = git.get("git_commit_hash")
        if h in {a, b} or h:
            rows.extend(c.get("decisions", []))
    return {"from": a, "to": b, "decisions": sorted(set(rows))}


def remote_config(project: Path) -> dict[str, Any]:
    return read_json(state_dir(project) / "remotes.json", {"remotes": {}})


def add_remote(project: Path, name: str, path: Path) -> dict[str, Any]:
    ensure_state(project)
    cfg = remote_config(project)
    cfg["remotes"][name] = str(path.resolve())
    write_json(state_dir(project) / "remotes.json", cfg)
    return cfg


def push_context(project: Path, remote_name: str) -> dict[str, Any]:
    cfg = remote_config(project)
    if remote_name not in cfg["remotes"]:
        raise ValueError("unknown remote")
    remote = Path(cfg["remotes"][remote_name])
    remote.mkdir(parents=True, exist_ok=True)
    payload = ""
    for p in list((state_dir(project) / "commits").glob("*.json")) + [state_dir(project) / "events.jsonl"]:
        if p.exists():
            payload += p.read_text(encoding="utf-8", errors="ignore")
    prompt_store = project / ".ithz-context"
    if (prompt_store / "conversations").exists():
        for p in sorted((prompt_store / "conversations").glob("pr_*.json")):
            record = read_json(p, {})
            if record.get("local_only"):
                continue
            payload += p.read_text(encoding="utf-8", errors="ignore")
    reason = redaction_block_reason(payload)
    if reason:
        raise ValueError(f"redaction_blocked:{reason}")
    dst = remote / "context"
    local_commits = {p.name: sha256_file(p) for p in (state_dir(project) / "commits").glob("*.json")}
    local_commit_names = set(local_commits)
    if dst.exists():
        remote_commits = {p.name: sha256_file(p) for p in (dst / "commits").glob("*.json")} if (dst / "commits").exists() else {}
        remote_commit_names = set(remote_commits)
        unknown_remote = sorted(remote_commit_names - local_commit_names)
        changed_remote = sorted(name for name in remote_commit_names & local_commit_names if remote_commits[name] != local_commits[name])
        if unknown_remote or changed_remote:
            write_json(remote / "merge_needed.json", {"remote": remote_name, "reason": "remote_has_commits_not_in_local_or_hash_mismatch", "unknown_commits": unknown_remote, "changed_commits": changed_remote})
            return {"remote": remote_name, "pushed": False, "conflict": True, "merge_needed": True, "source_files_pushed": False}
        integrity = validate_remote_context(dst)
        if not integrity["valid"]:
            raise ValueError("corrupted_remote_manifest")
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(state_dir(project), dst, ignore=shutil.ignore_patterns("index", "packs"))
    for commit_file in list((dst / "commits").glob("*.json")):
        commit = read_json(commit_file, {})
        if commit.get("private"):
            commit_file.unlink()
    prompt_src = project / ".ithz-context"
    if (prompt_src / "conversations").exists():
        prompt_dst = remote / "prompt-memory"
        if prompt_dst.exists():
            shutil.rmtree(prompt_dst)
        for rel in ("conversations", "prompt-summaries", "prompts", "responses"):
            (prompt_dst / rel).mkdir(parents=True, exist_ok=True)
        for record_file in sorted((prompt_src / "conversations").glob("pr_*.json")):
            record = read_json(record_file, {})
            if record.get("local_only"):
                continue
            shutil.copy2(record_file, prompt_dst / "conversations" / record_file.name)
            summary_path = record.get("summary_path")
            if summary_path and (prompt_src / summary_path).exists():
                target = prompt_dst / summary_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(prompt_src / summary_path, target)
            for key in ("prompt_path", "response_path"):
                rel_path = record.get(key)
                if rel_path and (prompt_src / rel_path).exists():
                    target = prompt_dst / rel_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(prompt_src / rel_path, target)
    return {"remote": remote_name, "pushed": True, "source_files_pushed": False}


def pull_context(project: Path, remote_name: str) -> dict[str, Any]:
    cfg = remote_config(project)
    if remote_name not in cfg["remotes"]:
        raise ValueError("unknown remote")
    src = Path(cfg["remotes"][remote_name]) / "context"
    if not src.exists():
        raise ValueError("remote context missing")
    integrity = validate_remote_context(src)
    if not integrity["valid"]:
        raise ValueError("corrupted_remote_manifest")
    ensure_state(project)
    imported = 0
    for p in (src / "commits").glob("*.json"):
        dst = state_dir(project) / "commits" / p.name
        if not dst.exists():
            shutil.copy2(p, dst)
            imported += 1
    return {"remote": remote_name, "imported_commits": imported, "source_tree_changed": False}


def validate_remote_context(context_dir: Path) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    if (context_dir / "events.jsonl").exists():
        try:
            rows = []
            for i, line in enumerate((context_dir / "events.jsonl").read_text(encoding="utf-8").splitlines(), start=1):
                if line.strip():
                    rows.append((i, line))
                    event = __import__("json").loads(line)
                    if not isinstance(event, dict) or "type" not in event:
                        errors.append({"scope": "events", "line": i, "error": "missing_type"})
        except Exception as exc:
            errors.append({"scope": "events", "error": "corrupt_events_jsonl", "detail": str(exc)})
    commit_names = {p.stem for p in (context_dir / "commits").glob("*.json")} if (context_dir / "commits").exists() else set()
    for folder in ("refs", "branches", "tags"):
        base = context_dir / folder
        if not base.exists():
            continue
        for ref in base.iterdir():
            if not ref.is_file():
                continue
            data = read_json(ref, {})
            head = data.get("head")
            if head and head not in commit_names:
                errors.append({"scope": folder, "path": ref.name, "error": "missing_remote_commit", "head": head})
    return {"valid": not errors, "errors": errors}

