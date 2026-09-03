from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from .agent_history_import import archive_import_agent_history, detect_history_author
from .agent_intake import first_project_agent_intake
from .git_merge_driver import install_git_drivers
from .hashing import sha256_file, stable_json_hash
from .host_install import write_host_install_bundle
from .native_archive_store import INDEX_MODE_COMPACT, build_native_archive, native_archive_status, project_archive_path
from .workflow_profiles import archive_adopt_project_workflow


PROJECT_GITIGNORE_HEADER = "# ITHZ-MCP local artifacts"
PROJECT_GITIGNORE_HEADER_ALIASES = (
    PROJECT_GITIGNORE_HEADER,
    "# Local agent/MCP host setup artifacts.",
    "# Native ITHZ diagnostic plan artifacts; project.ithz is the memory zone.",
)
PROJECT_GITIGNORE_ENTRIES = (
    ".ithz-install/",
    ".ithz-context/",
    ".antigravity/",
    ".claude/",
    ".cursor/",
    "project.ithz.lock",
    "*.auto_mixed_plan.json",
    "auto_mixed_plan_summary.md",
    "native_ithz_p9_auto_mixed_plan_matrix.csv",
)
GITATTRIBUTES_LINE = "*.ithz merge=ithz diff=ithz binary"
GIT_CONFIG_KEYS = (
    "merge.ithz.name",
    "merge.ithz.driver",
    "diff.ithz.textconv",
)


def _git_value(project: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(["git", "-C", str(project), *args], text=True, capture_output=True, check=False)
    except (FileNotFoundError, OSError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def detect_git(project: Path) -> dict[str, Any]:
    inside = _git_value(project, ["rev-parse", "--is-inside-work-tree"]) == "true"
    root = _git_value(project, ["rev-parse", "--show-toplevel"]) if inside else ""
    branch = _git_value(project, ["branch", "--show-current"]) if inside else ""
    return {
        "inside_git": inside,
        "git_root": root,
        "project_root_policy": "current_directory_not_git_root",
        "branch": branch,
    }


def ensure_project_gitignore(project: Path, apply: bool) -> dict[str, Any]:
    path = project / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    existing_lines = {line.strip() for line in existing.splitlines()}
    missing_entries = [entry for entry in PROJECT_GITIGNORE_ENTRIES if entry not in existing_lines]
    needs_header = bool(missing_entries) and PROJECT_GITIGNORE_HEADER not in existing_lines
    added_lines = ([PROJECT_GITIGNORE_HEADER] if needs_header else []) + missing_entries
    if not added_lines:
        return {
            "action": "project_gitignore_already_covered",
            "path": str(path),
            "changed": False,
            "added_entries": [],
        }
    if not apply:
        return {
            "action": "would_update_project_gitignore" if path.exists() else "would_create_project_gitignore",
            "path": str(path),
            "changed": True,
            "added_entries": added_lines,
        }
    prefix = existing
    if prefix and not prefix.endswith(("\n", "\r\n")):
        prefix += "\n"
    if prefix and not prefix.endswith(("\n\n", "\r\n\r\n")):
        prefix += "\n"
    path.write_text(prefix + "\n".join(added_lines) + "\n", encoding="utf-8")
    return {
        "action": "updated_project_gitignore" if existing else "created_project_gitignore",
        "path": str(path),
        "changed": True,
        "added_entries": added_lines,
    }


def cleanup_install_artifacts(project: Path, install_hash: str | None = None) -> dict[str, Any]:
    root = project / ".ithz-install"
    removed: list[str] = []
    if root.exists():
        for target in sorted(root.iterdir(), key=lambda p: p.name.lower()):
            if target.name == "install.log":
                continue
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            removed.append(str(target))
    root.mkdir(parents=True, exist_ok=True)
    log = root / "install.log"
    lines = [
        "ITHZ-MCP install completed.",
        f"project={project.resolve()}",
    ]
    if install_hash:
        lines.append(f"install_hash={install_hash}")
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    removed_root = False
    if not removed and root.exists():
        removed_root = False
    return {
        "action": "cleaned_install_artifacts",
        "path": str(root),
        "removed": removed,
        "remaining": [str(p) for p in sorted(root.iterdir(), key=lambda p: p.name.lower())] if root.exists() else [],
        "removed_root": removed_root,
    }


def cleanup_native_diagnostics(project: Path) -> dict[str, Any]:
    targets = [
        project / f"{project_archive_path(project).name}.lock",
        project / f"{project_archive_path(project).name}.auto_mixed_plan.json",
        project / "auto_mixed_plan_summary.md",
        project / "native_ithz_p9_auto_mixed_plan_matrix.csv",
    ]
    removed: list[str] = []
    for target in targets:
        try:
            if target.exists() and target.is_file():
                target.unlink()
                removed.append(str(target))
        except FileNotFoundError:
            pass
    return {"action": "cleaned_native_diagnostics", "removed": removed}


def cleanup_empty_context_store(project: Path) -> dict[str, Any]:
    root = project / ".ithz-context"
    if root.exists():
        files = [p for p in root.rglob("*") if p.is_file()]
        non_empty_files = [p for p in files if p.stat().st_size > 0 and p.name not in {"config.json", "index.json"}]
        if not non_empty_files:
            shutil.rmtree(root)
            return {"action": "removed_empty_context_store", "path": str(root), "removed": True}
        return {"action": "kept_context_store", "path": str(root), "removed": False, "reason": "contains_non_empty_files"}
    return {"action": "context_store_absent", "path": str(root), "removed": False}


def _write_lines_or_remove(path: Path, lines: list[str], apply: bool) -> dict[str, Any]:
    if not apply:
        return {"path": str(path), "would_remove_file": not lines, "remaining_line_count": len(lines)}
    if lines:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"path": str(path), "removed_file": False, "remaining_line_count": len(lines)}
    path.unlink()
    return {"path": str(path), "removed_file": True, "remaining_line_count": 0}


def remove_gitignore_block(project: Path, apply: bool) -> dict[str, Any]:
    path = project / ".gitignore"
    if not path.exists():
        return {"action": "gitignore_missing", "path": str(path), "changed": False}
    lines = path.read_text(encoding="utf-8").splitlines()
    stripped = [line.strip() for line in lines]
    if not any(header in stripped for header in PROJECT_GITIGNORE_HEADER_ALIASES):
        return {
            "action": "gitignore_manual_review",
            "path": str(path),
            "changed": False,
            "reason": "ithz_header_not_found",
        }
    remove_set = {*PROJECT_GITIGNORE_HEADER_ALIASES, *PROJECT_GITIGNORE_ENTRIES}
    kept = [line for line in lines if line.strip() not in remove_set]
    changed = kept != lines
    if changed and apply:
        path.write_text("\n".join(kept).rstrip() + ("\n" if kept else ""), encoding="utf-8")
    return {
        "action": "updated_gitignore_remove_ithz_block" if changed else "gitignore_no_ithz_entries",
        "path": str(path),
        "changed": changed,
        "removed_entries": [line for line in lines if line.strip() in remove_set],
    }


def remove_gitattributes_line(project: Path, apply: bool) -> dict[str, Any]:
    path = project / ".gitattributes"
    if not path.exists():
        return {"action": "gitattributes_missing", "path": str(path), "changed": False}
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.strip() != GITATTRIBUTES_LINE]
    changed = kept != lines
    details = _write_lines_or_remove(path, kept, apply) if changed else {"path": str(path), "remaining_line_count": len(lines)}
    return {
        "action": "removed_ithz_gitattributes_line" if changed else "gitattributes_no_ithz_line",
        "path": str(path),
        "changed": changed,
        **details,
    }


def unset_git_driver_config(project: Path, apply: bool) -> dict[str, Any]:
    git = detect_git(project)
    if not git["inside_git"]:
        return {"action": "git_config_skipped", "changed": False, "reason": "not_inside_git"}
    actions = []
    for key in GIT_CONFIG_KEYS:
        existing = _git_value(project, ["config", "--local", "--get", key])
        if existing:
            actions.append({"key": key, "had_value": True})
            if apply:
                try:
                    subprocess.run(["git", "-C", str(project), "config", "--local", "--unset-all", key], text=True, capture_output=True, check=False)
                except (FileNotFoundError, OSError):
                    pass
        else:
            actions.append({"key": key, "had_value": False})
    return {"action": "unset_git_driver_config", "changed": any(a["had_value"] for a in actions), "keys": actions}


def remove_host_config_files(project: Path, apply: bool) -> dict[str, Any]:
    candidates = [
        project / ".antigravity" / "mcp.json",
        project / ".cursor" / "mcp.json",
        project / ".claude" / "mcp.json",
        project / ".mcp.json",
        project / "mcp.json",
    ]
    rows = []
    for path in candidates:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "ithz" not in text.lower():
            rows.append({"path": str(path), "removed": False, "reason": "no_ithz_marker"})
            continue
        if apply:
            path.unlink()
            parent = path.parent
            if parent.name in {".antigravity", ".cursor", ".claude"}:
                try:
                    parent.rmdir()
                except OSError:
                    pass
        rows.append({"path": str(path), "removed": apply, "reason": "ithz_marker_present"})
    return {"action": "remove_host_config_files", "changed": any(row.get("removed") for row in rows), "files": rows}


def uninstall_project(
    project: Path,
    apply: bool = False,
    keep_project_md: bool = False,
    keep_host_configs: bool = False,
) -> dict[str, Any]:
    project = project.resolve()
    targets = [
        project_archive_path(project),
        project / "project.ithz.lock",
        project / ".ithz-install",
        project / ".ithz-context",
    ]
    if not keep_project_md:
        targets.insert(0, project / "project.md")
    actions: list[dict[str, Any]] = []
    for target in targets:
        exists = target.exists()
        action = {
            "action": "remove_path",
            "path": str(target),
            "exists": exists,
            "removed": False,
            "is_dir": target.is_dir() if exists else False,
        }
        if exists and apply:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            action["removed"] = True
        actions.append(action)
    actions.append(remove_gitattributes_line(project, apply))
    actions.append(remove_gitignore_block(project, apply))
    actions.append(unset_git_driver_config(project, apply))
    if keep_host_configs:
        actions.append({"action": "host_config_cleanup_skipped", "changed": False, "reason": "keep_host_configs"})
    else:
        actions.append(remove_host_config_files(project, apply))
    return {
        "schema": "ithz_mcp_uninstall_project_v1",
        "project": str(project),
        "apply": apply,
        "keep_project_md": keep_project_md,
        "keep_host_configs": keep_host_configs,
        "actions": actions,
        "source_files_modified": False,
        "git_commit_is_automatic": False,
    }


def _install_codex_config(snippet_path: Path, config_path: Path | None = None) -> dict[str, Any]:
    config_path = config_path or (Path.home() / ".codex" / "config.toml")
    snippet = snippet_path.read_text(encoding="utf-8")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    already_present = "[mcp_servers.ithz_mcp]" in existing and "[mcp_servers.ithz_mcp_write]" in existing
    if already_present:
        return {"config_path": str(config_path), "installed": False, "reason": "profiles_already_present"}
    backup = ""
    if config_path.exists():
        backup_path = config_path.with_suffix(config_path.suffix + ".bak-ithz-mcp23")
        backup_path.write_text(existing, encoding="utf-8")
        backup = str(backup_path)
    config_path.write_text(existing.rstrip() + "\n\n" + snippet.strip() + "\n", encoding="utf-8")
    return {"config_path": str(config_path), "installed": True, "backup": backup}


def install_project(
    project: Path,
    apply: bool = False,
    profile: str = "default",
    owner: str | None = None,
    native_exe: str | None = None,
    include_child_zones: bool = False,
    import_agent_history: bool = False,
    history_sources: list[str] | None = None,
    history_roots: list[Path] | None = None,
    install_codex_config: bool = False,
    install_git_driver: bool = True,
    index_mode: str = INDEX_MODE_COMPACT,
    keep_install_artifacts: bool = False,
    agent_intake: str = "auto",
) -> dict[str, Any]:
    project = project.resolve()
    author = detect_history_author(project, owner)
    owner_name = owner or author["author"]
    git = detect_git(project)
    install_root = project / ".ithz-install"
    host_out = (install_root / "host_installers") if keep_install_artifacts else (install_root / "tmp" / "host_installers")
    archive_path = project_archive_path(project)
    archive_preexists = archive_path.exists()
    result: dict[str, Any] = {
        "schema": "ithz_mcp_install_project_v1",
        "project": str(project),
        "apply": apply,
        "root_policy": "current_directory",
        "author": author,
        "git": git,
        "index_mode": index_mode,
        "actions": [],
    }
    if not apply:
        archive_action = (
            {"action": "would_reuse_existing_project_ithz", "path": str(archive_path)}
            if archive_preexists
            else {"action": "would_build_project_ithz", "path": str(archive_path), "index_mode": index_mode}
        )
        result["actions"].extend(
            [
                archive_action,
                {"action": "would_adopt_workflow_profile", "profile": profile, "owner": owner_name},
                {
                    "action": "would_run_first_install_agent_intake" if not archive_preexists and agent_intake != "off" else "would_skip_first_install_agent_intake",
                    "mode": agent_intake,
                    "reason": "new_archive" if not archive_preexists else "existing_project_ithz_reused",
                },
                ensure_project_gitignore(project, apply=False),
            ]
        )
        if install_codex_config or keep_install_artifacts:
            result["actions"].append(
                {
                    "action": "would_generate_host_installers",
                    "out": str(host_out),
                    "keep_install_artifacts": keep_install_artifacts,
                }
            )
        else:
            result["actions"].append({"action": "would_skip_host_installer_artifacts", "reason": "not_needed_for_default_install"})
        if git["inside_git"] and install_git_driver:
            result["actions"].append({"action": "would_install_git_driver", "scope": str(project)})
        result["recommended_apply"] = "python -m ithz_mcp install-project --apply"
        return result

    gitignore = ensure_project_gitignore(project, apply=True)
    result["actions"].append(gitignore)
    if archive_preexists:
        existing_status = native_archive_status(project, native_exe)
        if not existing_status.get("safe_verify_ok"):
            raise RuntimeError(f"existing_project_ithz_failed_safe_verify: {archive_path}")
        result["actions"].append(
            {
                "action": "reused_existing_project_ithz",
                "archive": str(archive_path),
                "archive_bytes": existing_status.get("archive_bytes", archive_path.stat().st_size),
                "archive_sha256": existing_status.get("archive_sha256", sha256_file(archive_path)),
            }
        )
    else:
        archive = build_native_archive(project, native_exe, "safe", include_child_zones, index_mode)
        result["actions"].append({"action": "built_project_ithz", "archive": archive["archive"], "archive_bytes": archive["archive_bytes"], "index_mode": index_mode})
    if archive_preexists:
        result["actions"].append({"action": "skipped_workflow_profile_adoption", "reason": "existing_project_ithz_reused", "profile": profile})
    else:
        adopted = archive_adopt_project_workflow(project, profile, owner_name, project / "project.md", include_existing_md=True, native_exe=native_exe)
        result["actions"].append({"action": "adopted_workflow_profile", "profile": adopted["profile"]["profile_id"], "source_count": adopted["source_count"]})
    history_result = None
    if import_agent_history:
        history_result = archive_import_agent_history(
            project,
            history_sources,
            history_roots,
            apply=True,
            author=owner_name,
            max_records=100,
            native_exe=native_exe,
        )
        result["actions"].append({"action": "imported_agent_history", "imported_count": history_result.get("imported_count", 0)})
    if archive_preexists:
        result["actions"].append({"action": "skipped_first_install_agent_intake", "reason": "existing_project_ithz_reused", "mode": agent_intake})
    elif agent_intake == "off":
        result["actions"].append({"action": "skipped_first_install_agent_intake", "reason": "disabled", "mode": agent_intake})
    else:
        intake = first_project_agent_intake(project, owner_name, profile, agent_intake, native_exe)
        result["actions"].append(
            {
                "action": "ran_first_install_agent_intake" if intake.get("ran") else "skipped_first_install_agent_intake",
                "mode": agent_intake,
                "analysis_source": intake.get("analysis_source"),
                "codex_cli_available": intake.get("codex_cli_available"),
                "codex_cli_passed": intake.get("codex_cli_passed"),
                "manual_host_intake_required": intake.get("manual_host_intake_required"),
                "repo_scale": intake.get("repo_scale"),
                "repo_intake_strategy": intake.get("repo_intake_strategy"),
                "repo_intake_candidate_count": intake.get("repo_intake_candidate_count"),
                "repo_intake_excerpt_count": intake.get("repo_intake_excerpt_count"),
                "repo_intake_prompt_bytes": intake.get("repo_intake_prompt_bytes"),
                "instruction_count": intake.get("memory", {}).get("instruction_count") if isinstance(intake.get("memory"), dict) else 0,
                "event_count": intake.get("memory", {}).get("event_count") if isinstance(intake.get("memory"), dict) else 0,
                "intake_hash": intake.get("intake_hash"),
                "reason": intake.get("reason") or intake.get("fallback_reason", ""),
            }
        )
    if install_codex_config or keep_install_artifacts:
        host = write_host_install_bundle(project, host_out)
        result["actions"].append(
            {
                "action": "generated_host_installers",
                "out": host["out_dir"],
                "rows": len(host["rows"]),
                "keep_install_artifacts": keep_install_artifacts,
            }
        )
    else:
        result["actions"].append({"action": "skipped_host_installer_artifacts", "reason": "not_needed_for_default_install"})
    if install_codex_config:
        codex = _install_codex_config(host_out / "codex_config_snippet.toml")
        result["actions"].append({"action": "installed_codex_config", **codex})
    if git["inside_git"] and install_git_driver:
        driver = install_git_drivers(project, dry_run=False)
        result["actions"].append({"action": "installed_git_driver", "scope": str(project), "driver_actions": driver["actions"]})
    status = native_archive_status(project, native_exe)
    result["status"] = {
        "archive": status.get("archive"),
        "archive_bytes": status.get("archive_bytes"),
        "archive_sha256": status.get("archive_sha256"),
        "project_semantic_hash": status.get("project_semantic_hash"),
        "safe_verify_ok": status.get("safe_verify_ok"),
        "index_mode": status.get("index_mode"),
        "source_snapshot_included": status.get("source_snapshot_included", False),
        "source_file_count": status.get("source_file_count", 0),
    }
    result["install_hash"] = stable_json_hash({"project": str(project), "actions": result["actions"], "status": result["status"]})
    result["actions"].append(cleanup_native_diagnostics(project))
    result["actions"].append(cleanup_empty_context_store(project))
    if not keep_install_artifacts:
        result["actions"].append(cleanup_install_artifacts(project, result["install_hash"]))
    result["recommended_git_add"] = ["project.md", "project.ithz"]
    if gitignore.get("changed"):
        result["recommended_git_add"].append(".gitignore")
    if git["inside_git"] and install_git_driver:
        result["recommended_git_add"].append(".gitattributes")
    result["commit_is_automatic"] = False
    result["project_ithz_sha256"] = sha256_file(project_archive_path(project))
    return result
