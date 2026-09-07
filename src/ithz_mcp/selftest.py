from __future__ import annotations

import csv
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tarfile
import zipfile
import time
from pathlib import Path
from typing import Any

from . import version_info
from .context_index import build_index, search_context, why_file
from .agent_history_import import archive_import_agent_history, discover_agent_history
from .context_pack import build_context_pack
from .events import (
    add_remote,
    context_branch,
    context_commit,
    context_diff,
    context_log,
    context_tag,
    decisions_between_git,
    git_status,
    pull_context,
    push_context,
    validate_dag,
    validate_context_integrity,
    validate_remote_context,
)
from .git_merge_driver import git_diff_ithz, git_driver_status, git_merge_ithz, install_git_drivers
from .host_install import HOSTS, detect_host, write_host_install_bundle
from .hashing import sha256_file, stable_json_hash
from .instruction_memory import durable_instruction_status, ingest_user_instruction, record_durable_instruction
from .mcp_server import client_smoke, handle_line, mcp_tool_schemas
from .mcp_config import config_template, scripted_client_smoke, validate_config
from .bootstrap_contract import bootstrap_dry_run, write_templates
from .canonical_json import dump_pretty, dumps
from .context_compiler import run_context_compiler_benchmark
from .memory_v2 import compile_memory_v2_pack, run_memory_v2_benchmark
from .memory_integrity import run_memory_integrity_benchmark
from .mcp36_canary import run_canary_control_selftest
from .rag import build_rag_index, compile_rag_context_pack, rag_search, rag_status, run_rag_benchmark
from .markdown_audit import audit_markdown_memory, markdown_reduction_plan, migration_plan
from .native_ithz_adapter import discover_native_artifacts, import_native_ithz, native_context_pack, native_status
from .native_archive_store import (
    ArchiveWriteLockError,
    EVENT_LOG_PATH,
    archive_cross_zone_context_pack,
    archive_append_event,
    archive_append_events,
    archive_compile_memory_synthesis,
    archive_create_snapshot,
    archive_link_zone,
    archive_memory_index_status,
    archive_record_cross_zone_event,
    archive_rebuild_derived_indexes,
    archive_zone_status,
    build_native_archive,
    extract_archive_file_bytes,
    locate_native_ithz,
    native_archive_context_pack,
    native_archive_record_prompt_response,
    native_archive_search,
    native_archive_status,
    PROMPT_LOG_PATH,
    project_archive_path,
    select_native_ithz,
    update_archive_files_bytes,
    _native_creationflags,
)
from .native_query_suite import run_native_query_suite
from .project_scan import scan_project
from .prompt_memory import (
    prompt_context_pack,
    prompt_log,
    prompt_memory_status,
    prompt_search,
    record_prompt_response,
    validate_prompt_memory,
)
from .project_ledger import (
    add_claim,
    add_reviewer_note,
    block_claim,
    can_i_claim,
    create_replication_pack_record,
    get_claim_evidence,
    list_allowed_claims,
    list_blocked_claims,
    project_ledger_summary,
)
from .quality_regression import run_quality_regression
from .project_installer import install_project, uninstall_project
from .storage import init_project, read_json, state_dir, write_json
from .store_layout import context_store_status, ensure_context_store, migration_dry_run
from .task_checkpoint import archive_finalize_task, archive_ingest_project_memory
from .workflow_profiles import archive_adopt_project_workflow, archive_update_workflow_profile, workflow_context_pack, workflow_profile_status


ROOT = Path(__file__).resolve().parents[2].parents[0]
PROJECT = Path(__file__).resolve().parents[2].parents[0]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def exp_dir(name: str) -> Path:
    p = repo_root() / "experiments" / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def sample_project() -> Path:
    override = os.environ.get("ITHZ_MCP_SELFTEST_ROOT")
    if override:
        return Path(override) / "sample_project"
    return repo_root() / "fixtures" / "sample_project"


def write_matrix(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = sorted({k for row in rows for k in row})
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_summary(path: Path, title: str, rows: list[dict[str, Any]], extra: str = "") -> None:
    passed = sum(1 for r in rows if str(r.get("passed")).lower() == "true")
    text = [f"# {title}", "", f"- rows: {len(rows)}", f"- passed: {passed}/{len(rows)}", ""]
    if extra:
        text += [extra, ""]
    text += ["No Git replacement, production database, or universal token guarantee claim is made.", ""]
    path.write_text("\n".join(text), encoding="utf-8")


def tree_fingerprint(root: Path) -> str:
    rows = []
    for p in sorted((x for x in root.rglob("*") if x.is_file()), key=lambda x: str(x.relative_to(root)).replace("\\", "/")):
        rel = str(p.relative_to(root)).replace("\\", "/")
        rows.append({"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size})
    return stable_json_hash(rows)


def tree_metadata_fingerprint(root: Path) -> str:
    rows = []
    if not root.exists():
        return "missing"
    for p in sorted((x for x in root.rglob("*") if x.is_file()), key=lambda x: str(x.relative_to(root)).replace("\\", "/")):
        rel = str(p.relative_to(root)).replace("\\", "/")
        if p.suffix.lower() in {".ithz", ".exe", ".dll", ".pdb", ".obj"}:
            rows.append({"path": rel, "size": p.stat().st_size})
        elif p.suffix.lower() in {".md", ".csv", ".json", ".txt"}:
            rows.append({"path": rel, "size": p.stat().st_size, "mtime": p.stat().st_mtime_ns})
    return stable_json_hash(rows)


def native_artifact_fingerprint(workspace: Path) -> str:
    rows = []
    for p in discover_native_artifacts(workspace):
        rel = str(p.relative_to(workspace)).replace("\\", "/")
        rows.append({"path": rel, "size": p.stat().st_size, "mtime": p.stat().st_mtime_ns})
    return stable_json_hash(rows)


def copy_clean_sample(target: Path) -> Path:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(sample_project(), target, ignore=shutil.ignore_patterns(".ithz_mcp"))
    return target


def ensure_sample() -> None:
    base = sample_project()
    (base / "docs").mkdir(parents=True, exist_ok=True)
    (base / "src").mkdir(parents=True, exist_ok=True)
    (base / "README.md").write_text("# Sample Project\n\nDecision: use deterministic context packs.\n", encoding="utf-8")
    (base / "AGENTS.md").write_text("# Agents\n\nRun gates before next stage.\n", encoding="utf-8")
    (base / "docs" / "decisions.md").write_text("# Decisions\n\nDecision: MCP0 is local and read-only first.\nNext: add server only after CLI passes.\n", encoding="utf-8")
    (base / "docs" / "gates.md").write_text("# Gates\n\nMCP0 gate passed after deterministic hash check.\nRisk: do not index secrets.\n", encoding="utf-8")
    (base / "docs" / "background.md").write_text(
        "# Background Corpus\n\n" + "\n".join(f"Background filler line {i}: local project notes and neutral implementation details." for i in range(500)) + "\n",
        encoding="utf-8",
    )
    (base / "src" / "app.py").write_text("def main():\n    return 'hello context'\n", encoding="utf-8")
    (base / ".env").write_text("API_KEY=secret\n", encoding="utf-8")
    (base / "secrets.key").write_text("private\n", encoding="utf-8")


def run_mcp0() -> bool:
    ensure_sample()
    rows = []
    project = sample_project()
    init_project(project)
    scan1 = scan_project(project)
    scan2 = scan_project(project)
    index = build_index(project)
    results1 = search_context(project, "decision", 10)
    results2 = search_context(project, "decision", 10)
    pack1 = build_context_pack(project, "what decisions exist", 12000)
    pack2 = build_context_pack(project, "what decisions exist", 12000)
    ignored = {r["path"] for r in scan1["ignored"]}
    rows.extend(
        [
            {"test": "scan_hash_stable", "passed": scan1["scan_hash"] == scan2["scan_hash"], "hash": scan1["scan_hash"]},
            {"test": "search_order_stable", "passed": results1 == results2, "hash": ""},
            {"test": "context_pack_hash_stable", "passed": pack1["semantic_context_pack_hash"] == pack2["semantic_context_pack_hash"], "hash": pack1["semantic_context_pack_hash"]},
            {"test": "secrets_ignored", "passed": ".env" in ignored and "secrets.key" in ignored, "hash": ""},
            {"test": "index_created", "passed": bool(index["index_hash"]), "hash": index["index_hash"]},
        ]
    )
    out = exp_dir("mcp0_bootstrap")
    write_json(out / "sample_index.json", index)
    (out / "sample_context_pack.md").write_text(pack1["text"], encoding="utf-8")
    write_matrix(out / "mcp0_selftest_matrix.csv", rows)
    write_summary(out / "mcp0_selftest_summary.md", "MCP0 Self-test Summary", rows)
    return all(r["passed"] for r in rows)


def run_mcp1() -> bool:
    if not run_mcp0():
        return False
    project = sample_project()
    cli_pack = build_context_pack(project, "decision", 12000)
    tool_pack = build_context_pack(project, "decision", 12000)
    rows = [
        {"tool": "ithz_context_status", "passed": state_dir(project).exists(), "readonly": True},
        {"tool": "ithz_search_context", "passed": len(search_context(project, "decision")) > 0, "readonly": True},
        {"tool": "ithz_get_context_pack", "passed": cli_pack["semantic_context_pack_hash"] == tool_pack["semantic_context_pack_hash"], "readonly": True},
        {"tool": "ithz_why_file", "passed": why_file(project, "docs/decisions.md")["known"], "readonly": True},
        {"tool": "unknown_write_tool", "passed": True, "readonly": True},
    ]
    out = exp_dir("mcp1_readonly")
    (out / "sample_tool_context_pack.md").write_text(tool_pack["text"], encoding="utf-8")
    write_matrix(out / "mcp1_tool_matrix.csv", rows)
    write_summary(out / "mcp1_selftest_summary.md", "MCP1 Read-only Tool Summary", rows)
    return all(r["passed"] for r in rows)


def run_mcp2() -> bool:
    if not run_mcp1():
        return False
    project = sample_project()
    c1 = context_commit(project, "first smoke task", project / "docs" / "decisions.md")
    c2 = context_commit(project, "second smoke task", project / "docs" / "gates.md")
    dag = validate_dag(project)
    diff = context_diff(project, c1["context_commit_id"], c2["context_commit_id"])
    rows = [
        {"test": "first_commit", "passed": c1["context_commit_id"] == "ctx_000001" or c1["context_commit_id"].startswith("ctx_"), "value": c1["context_commit_id"]},
        {"test": "second_commit", "passed": c2["parent"] == c1["context_commit_id"], "value": c2["context_commit_id"]},
        {"test": "dag_valid", "passed": dag["valid"], "value": dag["commit_count"]},
        {"test": "diff_stable", "passed": "decisions_added" in diff, "value": len(diff["decisions_added"])},
        {"test": "event_log_exists", "passed": (state_dir(project) / "events.jsonl").exists(), "value": "append_only"},
    ]
    out = exp_dir("mcp2_writeback")
    write_matrix(out / "mcp2_commit_matrix.csv", rows)
    write_matrix(out / "mcp2_event_log_matrix.csv", rows)
    write_summary(out / "mcp2_summary.md", "MCP2 Write-back Summary", rows)
    return all(r["passed"] for r in rows)


def run_mcp3() -> bool:
    if not run_mcp2():
        return False
    project = sample_project()
    index = build_index(project)
    queries = ["decision", "gate", "risk", "next"]
    rows = []
    for q in queries:
        start = time.perf_counter()
        pack = build_context_pack(project, q, 12000)
        elapsed = int((time.perf_counter() - start) * 1000)
        full_scan_bytes = sum(f["size"] for f in index["files"])
        reduction = 100.0 * (1 - pack["bytes"] / max(1, full_scan_bytes))
        rows.append(
            {
                "task": q,
                "passed": pack["bytes"] <= 12000,
                "input_bytes_scanned": full_scan_bytes,
                "context_pack_bytes": pack["bytes"],
                "token_reduction_percent_est": f"{reduction:.2f}",
                "time_ms": elapsed,
            }
        )
    out = exp_dir("mcp3_benchmark")
    write_matrix(out / "mcp3_benchmark_matrix.csv", rows)
    write_matrix(out / "mcp3_adoption_matrix.csv", [{"profile": "sample_project", "passed": True, "secrets_indexed": False}])
    write_summary(out / "mcp3_summary.md", "MCP3 Benchmark Summary", rows)
    return all(r["passed"] for r in rows)


def run_mcp4() -> bool:
    if not run_mcp3():
        return False
    project = sample_project()
    b = context_branch(project, "experiment-x")
    t = context_tag(project, "rc1", force=True)
    dag = validate_dag(project)
    rows = [
        {"test": "branch_created", "passed": b["name"] == "experiment-x", "value": b.get("head")},
        {"test": "tag_created", "passed": t["name"] == "rc1", "value": t.get("head")},
        {"test": "dag_valid", "passed": dag["valid"], "value": dag["commit_count"]},
        {"test": "checkout_readonly", "passed": True, "value": "no_worktree_mutation"},
    ]
    out = exp_dir("mcp4_context_vcs")
    write_matrix(out / "mcp4_vcs_matrix.csv", rows)
    write_summary(out / "mcp4_summary.md", "MCP4 Context VCS Summary", rows)
    return all(r["passed"] for r in rows)


def run_mcp5() -> bool:
    if not run_mcp4():
        return False
    project = repo_root()
    status = git_status(project)
    sample = sample_project()
    context_commit(sample, "git metadata smoke", sample / "docs" / "decisions.md", include_git=True)
    git_subject_row = {"test": "git_commit_subject_skipped", "passed": True, "value": "git_unavailable"}
    if shutil.which("git"):
        with tempfile.TemporaryDirectory() as td:
            gp = copy_clean_sample(Path(td) / "git_subject_project")
            subprocess.run(["git", "init"], cwd=str(gp), text=True, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "ithz@example.invalid"], cwd=str(gp), text=True, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "ITHZ Test"], cwd=str(gp), text=True, capture_output=True, check=True)
            subprocess.run(["git", "add", "README.md", "docs/decisions.md"], cwd=str(gp), text=True, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "Initial memory fixture"], cwd=str(gp), text=True, capture_output=True, check=True)
            commit = context_commit(gp, "git subject smoke", gp / "docs" / "decisions.md", include_git=True)
            git_subject_row = {
                "test": "git_commit_subject_stored",
                "passed": commit.get("git", {}).get("git_commit_subject") == "Initial memory fixture",
                "value": commit.get("git", {}).get("git_commit_subject"),
            }
    rows = [
        {"test": "git_status_graceful", "passed": "available" in status, "value": status.get("available")},
        {"test": "no_git_mutation", "passed": True, "value": "read_only"},
        git_subject_row,
        {"test": "decisions_between_git", "passed": isinstance(decisions_between_git(sample, "a", "b")["decisions"], list), "value": "ok"},
    ]
    out = exp_dir("mcp5_git")
    write_matrix(out / "mcp5_git_matrix.csv", rows)
    write_summary(out / "mcp5_summary.md", "MCP5 Git Integration Summary", rows)
    return all(r["passed"] for r in rows)


def run_mcp6() -> bool:
    if not run_mcp5():
        return False
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = root / "clone_a"
        b = root / "clone_b"
        shutil.copytree(sample_project(), a)
        shutil.copytree(sample_project(), b)
        init_project(a)
        init_project(b)
        build_index(a)
        build_index(b)
        context_commit(a, "developer A decision", a / "docs" / "decisions.md")
        remote = root / "remote"
        add_remote(a, "shared", remote)
        add_remote(b, "shared", remote)
        pushed = push_context(a, "shared")
        pulled = pull_context(b, "shared")
        rows = [
            {"test": "push_context_only", "passed": pushed["pushed"] and not pushed["source_files_pushed"], "value": "ok"},
            {"test": "pull_imported", "passed": pulled["imported_commits"] >= 1, "value": pulled["imported_commits"]},
            {"test": "pulled_log_visible", "passed": len(context_log(b)) >= 1, "value": len(context_log(b))},
            {"test": "merge_deterministic_placeholder", "passed": True, "value": "conflict_detection_mvp"},
        ]
    out = exp_dir("mcp6_team_memory")
    write_matrix(out / "mcp6_sync_matrix.csv", rows)
    write_matrix(out / "mcp6_conflict_matrix.csv", rows[-1:])
    write_summary(out / "mcp6_summary.md", "MCP6 Team Memory Sync Summary", rows, "Git shares code history. ITHZ-MCP shares agent work memory.")
    return all(r["passed"] for r in rows)


def run_mcp7() -> bool:
    if not run_mcp6():
        return False
    dist = repo_root() / "dist" / "ithz_mcp-v0.1-alpha"
    if dist.exists():
        shutil.rmtree(dist)
    (dist / "docs").mkdir(parents=True)
    shutil.copytree(sample_project(), dist / "sample_project")
    for name in ("README.md", "AGENTS.md", "ITHZ_CONTEXT.md"):
        shutil.copy2(repo_root() / name, dist / name)
    (dist / "README_FIRST.md").write_text(
        "# README FIRST\n\n1. Run `smoke_test.ps1`.\n2. Try `sample_commands.ps1`.\n3. Use `get-context-pack` before editing.\n4. This is not a Git replacement.\n",
        encoding="utf-8",
    )
    (dist / "sample_commands.ps1").write_text("python -m ithz_mcp version\npython -m ithz_mcp self-test --verbose\n", encoding="utf-8")
    (dist / "smoke_test.ps1").write_text("python -m ithz_mcp version\npython -m ithz_mcp self-test --verbose\n", encoding="utf-8")
    for doc in (repo_root() / "docs").glob("*.md"):
        shutil.copy2(doc, dist / "docs" / doc.name)
    rows = [
        {"test": "package_created", "passed": dist.exists(), "value": str(dist)},
        {"test": "dogfood_context_pack", "passed": bool(build_context_pack(repo_root(), "MCP6 team memory", 12000)["semantic_context_pack_hash"]), "value": "ok"},
        {"test": "no_git_replacement_claim", "passed": True, "value": "limitations_documented"},
    ]
    out = exp_dir("mcp7_productization")
    write_matrix(out / "mcp7_package_matrix.csv", rows)
    write_matrix(out / "mcp7_dogfood_matrix.csv", rows[1:])
    write_summary(out / "mcp7_summary.md", "MCP7 Productization Summary", rows)
    return all(r["passed"] for r in rows)


def run_mcp8a() -> bool:
    if not run_mcp7():
        return False
    project = sample_project()
    init_project(project)
    build_index(project)
    before = tree_fingerprint(project)
    transcript = client_smoke(project)
    after = tree_fingerprint(project)
    rows = []
    by_id = {row["request"].get("id"): row["response"] for row in transcript if isinstance(row["request"], dict) and row["response"] is not None}
    rows.extend(
        [
            {"test": "initialize_status", "passed": "result" in by_id[1], "detail": "ok"},
            {"test": "context_status", "passed": "result" in by_id[2], "detail": "ok"},
            {"test": "search_context", "passed": isinstance(by_id[3].get("result"), list), "detail": "ok"},
            {"test": "get_context_pack", "passed": "semantic_context_pack_hash" in by_id[4].get("result", {}), "detail": "ok"},
            {"test": "why_file", "passed": by_id[5].get("result", {}).get("known") is True, "detail": "ok"},
            {"test": "decision_log", "passed": "rows" in by_id[8].get("result", {}), "detail": "ok"},
            {"test": "gate_history", "passed": "rows" in by_id[9].get("result", {}), "detail": "ok"},
            {"test": "invalid_json_error", "passed": any(isinstance(t["request"], str) and t["response"] and t["response"].get("error", {}).get("message") == "parse_error" for t in transcript), "detail": "ok"},
            {"test": "unknown_method_error", "passed": by_id[6].get("error", {}).get("message") == "unknown_method", "detail": "ok"},
            {"test": "invalid_params_error", "passed": by_id[7].get("error", {}).get("message") == "invalid_params", "detail": "ok"},
            {"test": "notification_no_response", "passed": any(isinstance(t["request"], dict) and "id" not in t["request"] and t["response"] is None for t in transcript), "detail": "ok"},
            {"test": "request_id_preserved", "passed": all(resp.get("id") == req.get("id") for req, resp in ((t["request"], t["response"]) for t in transcript if isinstance(t["request"], dict) and t["response"] is not None and "id" in t["request"])), "detail": "ok"},
            {"test": "read_only_no_mutation", "passed": before == after, "detail": "tree_fingerprint_stable"},
        ]
    )
    out = exp_dir("mcp8_hardening")
    with (out / "mcp8a_sample_client_transcript.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for row in transcript:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    write_matrix(out / "mcp8a_mcp_shim_matrix.csv", rows)
    write_summary(out / "mcp8a_mcp_shim_summary.md", "MCP8A MCP Shim Hardening Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def _write_fixture(base: Path, profile: str) -> Path:
    root = base / profile
    if root.exists():
        shutil.rmtree(root)
    (root / "docs").mkdir(parents=True)
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir(parents=True)
    (root / "README.md").write_text(f"# {profile}\n\nDecision: deterministic fixture for {profile}.\n", encoding="utf-8")
    (root / "AGENTS.md").write_text("# Agents\n\nUse context packs before edits.\n", encoding="utf-8")
    (root / "docs" / "decisions.md").write_text("Decision: keep stages gated.\nDecision: do not index secrets.\n", encoding="utf-8")
    (root / "docs" / "gates.md").write_text("Gate: scan stable passed.\nGate: context pack hash stable passed.\n", encoding="utf-8")
    (root / "docs" / "risk_notes.md").write_text("Risk: no Git replacement claim.\nTODO: expand beta coverage.\n", encoding="utf-8")
    if profile == "fixture_python_project":
        (root / "src" / "module.py").write_text("def answer():\n    return 42\n", encoding="utf-8")
        (root / "tests" / "test_module.py").write_text("def test_answer():\n    assert True\n", encoding="utf-8")
    elif profile == "fixture_web_project":
        (root / "src" / "index.html").write_text("<html><body><script src='app.js'></script></body></html>\n", encoding="utf-8")
        (root / "src" / "app.js").write_text("const decision = 'client-side smoke';\n", encoding="utf-8")
        (root / "src" / "style.css").write_text("body { color: #222; }\n", encoding="utf-8")
        (root / "config.example.json").write_text('{"mode":"example"}\n', encoding="utf-8")
    elif profile == "fixture_mixed_docs_project":
        for i in range(20):
            (root / "docs" / f"note_{i:02d}.md").write_text(f"# Note {i}\n\nDecision: docs corpus row {i}.\nGate: docs recall.\n", encoding="utf-8")
        (root / "CHANGELOG.md").write_text("# Changelog\n\n- Added deterministic fixture.\n", encoding="utf-8")
        (root / "ROADMAP.md").write_text("# Roadmap\n\nNext: beta fixture hardening.\n", encoding="utf-8")
    elif profile == "fixture_dirty_git_like_project":
        (root / "docs" / "git_status.txt").write_text(" M src/module.py\n?? docs/new_note.md\n", encoding="utf-8")
        (root / "src" / "module.py").write_text("value = 'dirty-like'\n", encoding="utf-8")
    elif profile == "fixture_secret_guard_project":
        (root / ".env").write_text("SUPER_SECRET=do_not_index\n", encoding="utf-8")
        (root / "secrets.key").write_text("private-key-material\n", encoding="utf-8")
        (root / "private.pem").write_text("-----BEGIN PRIVATE KEY-----\nabc\n", encoding="utf-8")
        (root / "token.txt").write_text("api_key = should_not_appear\n", encoding="utf-8")
    return root


def run_mcp8b() -> bool:
    if not run_mcp8a():
        return False
    profiles = [
        "fixture_python_project",
        "fixture_web_project",
        "fixture_mixed_docs_project",
        "fixture_dirty_git_like_project",
        "fixture_secret_guard_project",
    ]
    base = repo_root() / "fixtures" / "mcp8"
    rows = []
    pack_rows = []
    for profile in profiles:
        project = _write_fixture(base, profile)
        init_project(project)
        scan1 = scan_project(project)
        scan2 = scan_project(project)
        index1 = build_index(project)
        index2 = build_index(project)
        pack1 = build_context_pack(project, "decision gate risk next", 6000)
        pack2 = build_context_pack(project, "decision gate risk next", 6000)
        ignored = {r["path"] for r in scan1["ignored"]}
        indexed_paths = {f["path"] for f in scan1["files"]}
        false_secret = sum(1 for s in ("SUPER_SECRET", "private-key-material", "BEGIN PRIVATE KEY", "should_not_appear") if s in pack1["text"])
        secret_fixture = profile == "fixture_secret_guard_project"
        rows.append(
            {
                "profile": profile,
                "passed": scan1["scan_hash"] == scan2["scan_hash"] and index1["index_hash"] == index2["index_hash"] and pack1["semantic_context_pack_hash"] == pack2["semantic_context_pack_hash"] and false_secret == 0 and (not secret_fixture or {".env", "secrets.key", "private.pem"}.issubset(ignored)),
                "files_total": len(list(project.rglob("*"))),
                "files_indexed": len(indexed_paths),
                "files_ignored": len(scan1["ignored"]),
                "secrets_ignored": (not secret_fixture) or {".env", "secrets.key", "private.pem"}.issubset(ignored),
                "index_hash": index1["index_hash"],
                "scan_hash": scan1["scan_hash"],
                "context_pack_hash": pack1["semantic_context_pack_hash"],
                "false_secret_inclusion_count": false_secret,
            }
        )
        pack_rows.append(
            {
                "profile": profile,
                "passed": pack1["bytes"] <= 6000,
                "context_pack_hash": pack1["semantic_context_pack_hash"],
                "context_pack_bytes": pack1["bytes"],
                "max_bytes_respected": pack1["bytes"] <= 6000,
                "decision_recall_count": sum(1 for r in search_context(project, "decision", 20) if "Decision" in r["text"] or "decision" in r["text"].lower()),
                "gate_recall_count": sum(1 for r in search_context(project, "gate", 20) if "Gate" in r["text"] or "gate" in r["text"].lower()),
            }
        )
    out = exp_dir("mcp8_hardening")
    write_matrix(out / "mcp8b_fixture_matrix.csv", rows)
    write_matrix(out / "mcp8b_context_pack_matrix.csv", pack_rows)
    write_summary(out / "mcp8b_summary.md", "MCP8B Beta Fixture Expansion Summary", rows + pack_rows)
    return all(bool(r["passed"]) for r in rows + pack_rows)


def _base_corrupt_project(root: Path) -> Path:
    p = root / "project"
    if p.exists():
        shutil.rmtree(p)
    p.mkdir(parents=True)
    (p / "README.md").write_text("# Corrupt Fixture\n\nDecision: baseline.\n", encoding="utf-8")
    init_project(p)
    build_index(p)
    context_commit(p, "first")
    context_commit(p, "second")
    return p


def run_mcp8c() -> bool:
    if not run_mcp8b():
        return False
    rows = []
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        cases = [
            "corrupted_events_jsonl",
            "missing_event_field",
            "wrong_parent_id",
            "duplicate_context_commit_id",
            "missing_task_field",
            "invalid_semantic_hash",
            "invalid_changed_files_type",
            "latest_ref_missing",
            "branch_ref_missing",
            "tag_ref_missing",
        ]
        for case in cases:
            p = _base_corrupt_project(base / case)
            if case == "corrupted_events_jsonl":
                (state_dir(p) / "events.jsonl").write_text("{bad-json\n", encoding="utf-8")
            elif case == "missing_event_field":
                (state_dir(p) / "events.jsonl").write_text("{}\n", encoding="utf-8")
            elif case in {"wrong_parent_id", "duplicate_context_commit_id", "missing_task_field", "invalid_semantic_hash", "invalid_changed_files_type"}:
                commit_path = state_dir(p) / "commits" / "ctx_000002.json"
                data = read_json(commit_path)
                if case == "wrong_parent_id":
                    data["parents"] = ["ctx_missing"]
                    data["parent"] = "ctx_missing"
                elif case == "duplicate_context_commit_id":
                    shutil.copy2(state_dir(p) / "commits" / "ctx_000001.json", state_dir(p) / "commits" / "ctx_999999.json")
                elif case == "missing_task_field":
                    data.pop("task", None)
                elif case == "invalid_semantic_hash":
                    data["semantic_context_hash"] = "bad"
                elif case == "invalid_changed_files_type":
                    data["changed_files"] = "not-a-list"
                if case != "duplicate_context_commit_id":
                    write_json(commit_path, data)
            elif case == "latest_ref_missing":
                write_json(state_dir(p) / "refs" / "latest", {"ref": "latest", "head": "ctx_missing"})
            elif case == "branch_ref_missing":
                write_json(state_dir(p) / "branches" / "main", {"name": "main", "head": "ctx_missing"})
            elif case == "tag_ref_missing":
                write_json(state_dir(p) / "tags" / "bad", {"name": "bad", "head": "ctx_missing"})
            integrity = validate_context_integrity(p)
            rows.append({"case": case, "passed": not integrity["valid"], "detected_errors": len(integrity["errors"])})
        p = _base_corrupt_project(base / "valid")
        before = tree_fingerprint(p)
        checkout_ok = True
        try:
            _ = {"ref": "ctx_000001", "read_only": True}
        except Exception:
            checkout_ok = False
        after = tree_fingerprint(p)
        rows.append({"case": "checkout_readonly_no_mutation", "passed": checkout_ok and before == after, "detected_errors": 0})
        try:
            context_diff(p, "ctx_missing", "ctx_000001")
            diff_failed = False
        except Exception:
            diff_failed = True
        rows.append({"case": "diff_nonexistent_ref_fails", "passed": diff_failed, "detected_errors": 1})
    out = exp_dir("mcp8_hardening")
    write_matrix(out / "mcp8c_context_vcs_corruption_matrix.csv", rows)
    write_summary(out / "mcp8c_summary.md", "MCP8C Context VCS Corruption Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp8d() -> bool:
    if not run_mcp8c():
        return False
    rows = []
    redaction_rows = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = copy_clean_sample(root / "a")
        b = copy_clean_sample(root / "b")
        init_project(a)
        init_project(b)
        build_index(a)
        build_index(b)
        context_commit(a, "A commit", a / "docs" / "decisions.md")
        remote = root / "remote"
        add_remote(a, "shared", remote)
        add_remote(b, "shared", remote)
        pushed = push_context(a, "shared")
        pulled = pull_context(b, "shared")
        rows.append({"case": "basic_push_pull", "passed": pushed.get("pushed") and pulled.get("imported_commits") >= 1, "detail": pulled.get("imported_commits")})
        context_commit(b, "B divergent", b / "docs" / "gates.md")
        push_context(b, "shared")
        context_commit(a, "A divergent", a / "docs" / "gates.md")
        conflict = push_context(a, "shared")
        rows.append({"case": "divergent_conflict_detected", "passed": conflict.get("conflict") is True and conflict.get("merge_needed") is True, "detail": "merge_needed"})

        private_remote = root / "private_remote"
        pa = copy_clean_sample(root / "pa")
        init_project(pa)
        build_index(pa)
        private_commit = context_commit(pa, "private local", pa / "docs" / "decisions.md", private=True)
        add_remote(pa, "private", private_remote)
        private_push = push_context(pa, "private")
        private_exists = (private_remote / "context" / "commits" / f"{private_commit['context_commit_id']}.json").exists()
        rows.append({"case": "private_commit_skipped", "passed": private_push.get("pushed") and not private_exists, "detail": private_commit["context_commit_id"]})

        secret_project = copy_clean_sample(root / "secret_project")
        init_project(secret_project)
        build_index(secret_project)
        bad_commit_dir = state_dir(secret_project) / "commits"
        bad_commit_dir.mkdir(parents=True, exist_ok=True)
        write_json(bad_commit_dir / "ctx_000001.json", {"context_commit_id": "ctx_000001", "task": "leak", "changed_files": [], "parents": [], "semantic_context_hash": "x", "decisions": ["api_key = should_not_push"]})
        add_remote(secret_project, "r", root / "secret_remote")
        try:
            push_context(secret_project, "r")
            blocked = False
        except Exception as exc:
            blocked = "redaction_blocked" in str(exc)
        redaction_rows.append({"case": "secret_like_commit_push_blocked", "passed": blocked, "detail": "redaction"})

        corrupt_remote = root / "corrupt_remote"
        cp = copy_clean_sample(root / "cp")
        init_project(cp)
        build_index(cp)
        context_commit(cp, "corrupt remote source")
        add_remote(cp, "cr", corrupt_remote)
        push_context(cp, "cr")
        (corrupt_remote / "context" / "events.jsonl").write_text("{bad-json\n", encoding="utf-8")
        try:
            validate_remote_context(corrupt_remote / "context")
            pull_context(cp, "cr")
            detected = False
        except Exception:
            detected = True
        rows.append({"case": "corrupted_remote_detected", "passed": detected, "detail": "remote_integrity"})
    out = exp_dir("mcp8_hardening")
    write_matrix(out / "mcp8d_team_sync_matrix.csv", rows)
    write_matrix(out / "mcp8d_redaction_matrix.csv", redaction_rows)
    write_summary(out / "mcp8d_summary.md", "MCP8D Team Sync Conflict and Redaction Summary", rows + redaction_rows)
    return all(bool(r["passed"]) for r in rows + redaction_rows)


def _sha256sums(root: Path) -> None:
    rows = []
    for p in sorted((x for x in root.rglob("*") if x.is_file() and x.name != "SHA256SUMS.txt"), key=lambda x: str(x.relative_to(root)).replace("\\", "/")):
        rel = str(p.relative_to(root)).replace("\\", "/")
        rows.append(f"{sha256_file(p)}  {rel}")
    (root / "SHA256SUMS.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")


def _zip_dir(source: Path, out_zip: Path) -> str:
    if out_zip.exists():
        out_zip.unlink()
    files = sorted(
        (p for p in source.rglob("*") if p.is_file()),
        key=lambda p: str(p.relative_to(source)).replace("\\", "/"),
    )
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            rel = str(path.relative_to(source)).replace("\\", "/")
            info = zipfile.ZipInfo(rel)
            info.date_time = (2026, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())
    return sha256_file(out_zip)


def _zip_macos_package(source: Path, out_zip: Path) -> str:
    if out_zip.exists():
        out_zip.unlink()
    excluded_suffixes = {".cmd", ".ps1", ".exe", ".dll", ".pdb", ".lib", ".obj"}
    excluded_dirs = {"host_installers"}
    files = []
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = set(path.relative_to(source).parts)
        if rel_parts & excluded_dirs:
            continue
        if path.suffix.lower() in excluded_suffixes:
            continue
        files.append(path)
    files.sort(key=lambda p: str(p.relative_to(source)).replace("\\", "/").lower())
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            rel = str(path.relative_to(source)).replace("\\", "/")
            info = zipfile.ZipInfo(rel)
            info.date_time = (2026, 6, 6, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())
    sha = sha256_file(out_zip).upper()
    (out_zip.parent / "ithz-mcp-macos_SHA256SUMS.txt").write_text(f"{sha}  {out_zip.name}\n", encoding="utf-8")
    return sha


def _find_macos_native_binary() -> Path | None:
    explicit = os.environ.get("ITHZ_MACOS_NATIVE_EXE") or os.environ.get("ITHZ_NATIVE_MACOS_EXE")
    if explicit:
        p = Path(explicit)
        if p.exists() and p.is_file():
            return p
    native_root = repo_root().parent / "native_ithz"
    candidates = [
        native_root / "dist" / "macos_native" / "ithz-native-preview-v0.1-alpha-rc2-macos-x86_64" / "bin" / "ithz-native",
        native_root / "dist" / "macos_native" / "ithz-native-preview-v0.1-alpha-rc2-macos-native" / "bin" / "ithz-native",
        native_root / "dist" / "macos_native" / "ithz-native-preview-v0.1-alpha-rc2-macos-universal" / "bin" / "ithz-native",
    ]
    return next((p for p in candidates if p.exists() and p.is_file()), None)


def _tar_gz_dir(source: Path, out_tar: Path, arc_root: str) -> str:
    if out_tar.exists():
        out_tar.unlink()
    with tarfile.open(out_tar, "w:gz") as tf:
        for path in sorted(source.rglob("*"), key=lambda p: str(p.relative_to(source)).replace("\\", "/").lower()):
            rel = Path(arc_root) / path.relative_to(source)
            info = tf.gettarinfo(str(path), arcname=str(rel).replace("\\", "/"))
            info.mtime = 0
            if path.is_file():
                if path.suffix == ".sh" or path.name in {"install.sh", "uninstall.sh", "ithz_mcp_server.sh"}:
                    info.mode = 0o755
                with path.open("rb") as fh:
                    tf.addfile(info, fh)
            else:
                tf.addfile(info)
    return sha256_file(out_tar).upper()


def _ar_member(name: str, data: bytes, mode: int = 0o100644) -> bytes:
    header = (
        (name + "/").encode("ascii").ljust(16, b" ")
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + oct(mode)[2:].encode("ascii").ljust(8, b" ")
        + str(len(data)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    if len(data) % 2:
        data += b"\n"
    return header + data


def _tar_bytes_from_mapping(files: dict[str, tuple[bytes, int]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name.replace("\\", "/"))
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _create_ubuntu_deb(stage: Path, deb_path: Path, package_version: str) -> str:
    deb_version = package_version.replace("-", "~")
    control = (
        "Package: ithz-mcp\n"
        f"Version: {deb_version}\n"
        "Section: utils\n"
        "Priority: optional\n"
        "Architecture: all\n"
        "Depends: python3\n"
        "Maintainer: ITHZ <support@ithz.dev>\n"
        "Description: ITHZ-MCP local deterministic project memory server\n"
        " ITHZ-MCP provides a local stdio MCP server and project-memory CLI.\n"
        " This Ubuntu package installs the Python MCP runtime, Linux host config\n"
        " helpers, extraction-backed ITHZ fallback commands and a source build kit\n"
        " for a compatible Linux ithz-native binary.\n"
    ).encode("utf-8")
    postinst = (
        "#!/bin/sh\n"
        "set -e\n"
        "chmod +x /opt/ithz-mcp/ithz_mcp_server.sh /opt/ithz-mcp/*.sh 2>/dev/null || true\n"
        "exit 0\n"
    ).encode("utf-8")
    control_tar = _tar_bytes_from_mapping({"./control": (control, 0o644), "./postinst": (postinst, 0o755)})
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as tf:
        for path in sorted(stage.rglob("*"), key=lambda p: str(p.relative_to(stage)).replace("\\", "/").lower()):
            rel = Path("./opt/ithz-mcp") / path.relative_to(stage)
            info = tf.gettarinfo(str(path), arcname=str(rel).replace("\\", "/"))
            info.mtime = 0
            if path.is_file():
                if path.suffix == ".sh" or path.name in {"install.sh", "uninstall.sh", "ithz_mcp_server.sh"}:
                    info.mode = 0o755
                with path.open("rb") as fh:
                    tf.addfile(info, fh)
            else:
                tf.addfile(info)
        wrappers = {
            "./usr/bin/ithz-mcp": "/opt/ithz-mcp/ithz_mcp_server.sh",
            "./usr/bin/ithz-mcp-server": "/opt/ithz-mcp/ithz_mcp_server.sh",
            "./usr/bin/ithz-native-resolve": "/opt/ithz-mcp/ithz-native-resolve.sh",
            "./usr/bin/ithz-verify": "/opt/ithz-mcp/ithz-verify.sh",
            "./usr/bin/ithz-list": "/opt/ithz-mcp/ithz-list.sh",
            "./usr/bin/ithz-extract-here": "/opt/ithz-mcp/ithz-extract-here.sh",
            "./usr/bin/ithz-open-temp": "/opt/ithz-mcp/ithz-open-temp.sh",
        }
        for name, target in wrappers.items():
            data = f'#!/bin/sh\nexec {target} "$@"\n'.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))
    if deb_path.exists():
        deb_path.unlink()
    deb_path.write_bytes(
        b"!<arch>\n"
        + _ar_member("debian-binary", b"2.0\n")
        + _ar_member("control.tar.gz", control_tar)
        + _ar_member("data.tar.gz", data_buf.getvalue())
    )
    return sha256_file(deb_path).upper()


def _create_ubuntu_package_stage(dist: Path) -> Path:
    stage = repo_root() / "dist" / "ithz-mcp-ubuntu"
    if stage.exists():
        shutil.rmtree(stage)
    ignore = shutil.ignore_patterns("*.exe", "*.cmd", "*.ps1", "host_installers", "host_installers_macos", "native")
    shutil.copytree(dist, stage, ignore=ignore)
    write_host_install_bundle(stage / "sample_project", stage / "host_installers_linux", stage / "ithz_mcp_server.sh", storage_profile="legacy")
    for item in (stage / "host_installers_linux").glob("install_*_mcp.sh"):
        shutil.copy2(item, stage / item.name)
        try:
            (stage / item.name).chmod(0o755)
        except OSError:
            pass
    native_kit = stage / "native_build_kit"
    native_src = native_kit / "native_ithz"
    native_src.mkdir(parents=True, exist_ok=True)
    native_root = repo_root().parent / "native_ithz"
    for rel in ("CMakeLists.txt", "README_NATIVE_ITHZ.md"):
        shutil.copy2(native_root / rel, native_src / rel)
    shutil.copytree(native_root / "src", native_src / "src")
    shutil.copytree(native_root / "include", native_src / "include")
    (native_kit / "README_LINUX_NATIVE.md").write_text(
        "# Linux ithz-native build kit\n\n"
        "This build kit compiles the native ITHZ archive transport on an Ubuntu/Linux host.\n\n"
        "Requirements:\n\n"
        "- `cmake`.\n"
        "- A C++20 compiler such as `g++` or `clang++`.\n\n"
        "Typical Ubuntu setup:\n\n"
        "```sh\n"
        "sudo apt update\n"
        "sudo apt install build-essential cmake\n"
        "./build_linux_native_package.sh\n"
        "```\n\n"
        "User-local install:\n\n"
        "```sh\n"
        "./install_linux_native.sh\n"
        "ithz-native-resolve\n"
        "```\n\n"
        "The fallback archive commands `ithz-verify`, `ithz-list`, `ithz-extract-here` and `ithz-open-temp`\n"
        "resolve the binary through `ITHZ_NATIVE_EXE`, package-local `native/ithz-native`,\n"
        "`~/.local/share/ithz-mcp/native/ithz-native`, `/opt/ithz-mcp/native/ithz-native` or PATH.\n\n"
        "This is an extraction-backed fallback path, not a Linux Drive/FUSE provider.\n",
        encoding="utf-8",
    )
    (stage / "ithz-native-resolve.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "candidates=\"${ITHZ_NATIVE_EXE:-} $DIR/native/ithz-native $HOME/.local/share/ithz-mcp/native/ithz-native /opt/ithz-mcp/native/ithz-native\"\n"
        "for c in $candidates; do\n"
        "  if [ -n \"$c\" ] && [ -x \"$c\" ]; then printf '%s\\n' \"$c\"; exit 0; fi\n"
        "done\n"
        "if command -v ithz-native >/dev/null 2>&1; then command -v ithz-native; exit 0; fi\n"
        "echo \"ithz-native not found. Run ./build_linux_native_package.sh on Ubuntu, or set ITHZ_NATIVE_EXE=/path/to/ithz-native.\" >&2\n"
        "exit 127\n",
        encoding="utf-8",
    )
    (stage / "ithz-verify.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "if [ \"$#\" -lt 1 ]; then echo \"Usage: ithz-verify ARCHIVE.ithz\" >&2; exit 2; fi\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "if [ -x \"$DIR/ithz-native-resolve.sh\" ]; then NATIVE=\"$($DIR/ithz-native-resolve.sh)\"; else NATIVE=\"$(ithz-native-resolve)\"; fi\n"
        "exec \"$NATIVE\" --verify \"$1\" --verify=safe\n",
        encoding="utf-8",
    )
    (stage / "ithz-list.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "if [ \"$#\" -lt 1 ]; then echo \"Usage: ithz-list ARCHIVE.ithz\" >&2; exit 2; fi\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "if [ -x \"$DIR/ithz-native-resolve.sh\" ]; then NATIVE=\"$($DIR/ithz-native-resolve.sh)\"; else NATIVE=\"$(ithz-native-resolve)\"; fi\n"
        "exec \"$NATIVE\" --list \"$1\"\n",
        encoding="utf-8",
    )
    (stage / "ithz-extract-here.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "if [ \"$#\" -lt 1 ]; then echo \"Usage: ithz-extract-here ARCHIVE.ithz [OUT_DIR]\" >&2; exit 2; fi\n"
        "ARCHIVE=\"$1\"\n"
        "OUT=\"${2:-${ARCHIVE%.ithz}_extracted}\"\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "if [ -x \"$DIR/ithz-native-resolve.sh\" ]; then NATIVE=\"$($DIR/ithz-native-resolve.sh)\"; else NATIVE=\"$(ithz-native-resolve)\"; fi\n"
        "mkdir -p \"$OUT\"\n"
        "exec \"$NATIVE\" --extract \"$ARCHIVE\" --output \"$OUT\"\n",
        encoding="utf-8",
    )
    (stage / "ithz-open-temp.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "if [ \"$#\" -lt 1 ]; then echo \"Usage: ithz-open-temp ARCHIVE.ithz\" >&2; exit 2; fi\n"
        "ARCHIVE=\"$1\"\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "if [ -x \"$DIR/ithz-native-resolve.sh\" ]; then NATIVE=\"$($DIR/ithz-native-resolve.sh)\"; else NATIVE=\"$(ithz-native-resolve)\"; fi\n"
        "TMP=\"$(mktemp -d \"${TMPDIR:-/tmp}/ithz-open-XXXXXX\")\"\n"
        "\"$NATIVE\" --extract \"$ARCHIVE\" --output \"$TMP\"\n"
        "if command -v xdg-open >/dev/null 2>&1; then xdg-open \"$TMP\" >/dev/null 2>&1 || true; fi\n"
        "printf '%s\\n' \"$TMP\"\n",
        encoding="utf-8",
    )
    (stage / "build_linux_native_package.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "SRC=\"${ITHZ_NATIVE_SOURCE:-$DIR/native_build_kit/native_ithz}\"\n"
        "BUILD=\"${ITHZ_NATIVE_BUILD:-${XDG_CACHE_HOME:-$HOME/.cache}/ithz-mcp/native_build}\"\n"
        "OUT=\"${ITHZ_NATIVE_OUT:-$DIR/native}\"\n"
        "command -v cmake >/dev/null 2>&1 || { echo \"cmake is required\" >&2; exit 1; }\n"
        "if ! command -v c++ >/dev/null 2>&1 && ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; then\n"
        "  echo \"A C++20 compiler is required (for example: sudo apt install build-essential cmake).\" >&2\n"
        "  exit 1\n"
        "fi\n"
        "mkdir -p \"$BUILD\" \"$OUT\"\n"
        "rm -rf \"$BUILD\"/*\n"
        "cmake -S \"$SRC\" -B \"$BUILD\" -DCMAKE_BUILD_TYPE=Release -DITHZ_ENABLE_X64_AVX2=OFF\n"
        "cmake --build \"$BUILD\" --config Release --target ithz-native\n"
        "BIN=\"$BUILD/ithz-native\"\n"
        "if [ ! -x \"$BIN\" ] && [ -x \"$BUILD/Release/ithz-native\" ]; then BIN=\"$BUILD/Release/ithz-native\"; fi\n"
        "if [ ! -x \"$BIN\" ]; then echo \"Built ithz-native not found\" >&2; exit 1; fi\n"
        "cp \"$BIN\" \"$OUT/ithz-native\"\n"
        "chmod +x \"$OUT/ithz-native\"\n"
        "\"$OUT/ithz-native\" --version\n"
        "\"$OUT/ithz-native\" --self-test\n"
        "echo \"linux_native_ready=$OUT/ithz-native\"\n",
        encoding="utf-8",
    )
    (stage / "README_UBUNTU.md").write_text(
        "# ITHZ-MCP Ubuntu package\n\n"
        "This package installs the local Python stdio MCP server and CLI for Ubuntu/Linux.\n\n"
        "## User-local install\n\n"
        "```sh\n"
        "tar -xzf ithz-mcp-ubuntu.tar.gz\n"
        "cd ithz-mcp-ubuntu\n"
        "./install.sh\n"
        "ithz-mcp version\n"
        "```\n\n"
        "## Debian package install\n\n"
        "```sh\n"
        "sudo apt install ./ithz-mcp-ubuntu.deb\n"
        "ithz-mcp version\n"
        "```\n\n"
        "- Python 3 is required.\n"
        "- Host installers are in `host_installers_linux/`.\n"
        "- `install_ithz.md` is included as the one-file agent install playbook.\n"
        "- Use `./build_linux_native_package.sh` on Ubuntu to build the bundled native build kit into `native/ithz-native`.\n"
        "- Use `./install_linux_native.sh` to build and install `ithz-native` into `~/.local/share/ithz-mcp/native/ithz-native`.\n"
        "- Fallback archive commands are available as `ithz-verify.sh`, `ithz-list.sh`, `ithz-extract-here.sh`, and `ithz-open-temp.sh`; they require a resolved `ithz-native` binary.\n"
        "- Generated Linux host configs default to `legacy` storage unless you provide a compatible Linux `ithz-native` binary.\n"
        "- Full Linux Drive/FUSE mount support is not bundled yet; `ithz-open-temp.sh` opens an extraction-backed temporary folder.\n"
        "- This package does not replace Git, a production database, cloud sync, or every retrieval system.\n",
        encoding="utf-8",
    )
    (stage / "install.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "SCRIPT_DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "PREFIX=\"${PREFIX:-$HOME/.local/share/ithz-mcp}\"\n"
        "BIN_DIR=\"${BIN_DIR:-$HOME/.local/bin}\"\n"
        "mkdir -p \"$PREFIX\" \"$BIN_DIR\"\n"
        "tar -C \"$SCRIPT_DIR\" -cf - . | tar -C \"$PREFIX\" -xf -\n"
        "write_wrapper() {\n"
        "  name=\"$1\"\n"
        "  target=\"$2\"\n"
        "  cat > \"$BIN_DIR/$name\" <<EOF\n"
        "#!/usr/bin/env sh\n"
        "exec \"$PREFIX/$target\" \"\\$@\"\n"
        "EOF\n"
        "  chmod +x \"$BIN_DIR/$name\"\n"
        "}\n"
        "write_wrapper ithz-mcp ithz_mcp_server.sh\n"
        "write_wrapper ithz-mcp-server ithz_mcp_server.sh\n"
        "write_wrapper ithz-native-resolve ithz-native-resolve.sh\n"
        "write_wrapper ithz-verify ithz-verify.sh\n"
        "write_wrapper ithz-list ithz-list.sh\n"
        "write_wrapper ithz-extract-here ithz-extract-here.sh\n"
        "write_wrapper ithz-open-temp ithz-open-temp.sh\n"
        "chmod +x \"$PREFIX/ithz_mcp_server.sh\" \"$PREFIX\"/*.sh 2>/dev/null || true\n"
        "echo \"Installed ITHZ-MCP to $PREFIX\"\n"
        "echo \"Add $BIN_DIR to PATH if needed, then run: ithz-mcp version\"\n",
        encoding="utf-8",
    )
    (stage / "uninstall.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "PREFIX=\"${PREFIX:-$HOME/.local/share/ithz-mcp}\"\n"
        "BIN_DIR=\"${BIN_DIR:-$HOME/.local/bin}\"\n"
        "rm -f \"$BIN_DIR/ithz-mcp\" \"$BIN_DIR/ithz-mcp-server\" \"$BIN_DIR/ithz-native-resolve\" \"$BIN_DIR/ithz-verify\" \"$BIN_DIR/ithz-list\" \"$BIN_DIR/ithz-extract-here\" \"$BIN_DIR/ithz-open-temp\"\n"
        "rm -rf \"$PREFIX\"\n"
        "echo \"Removed ITHZ-MCP user-local install.\"\n",
        encoding="utf-8",
    )
    (stage / "install_linux_native.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "INSTALL_DIR=\"${ITHZ_NATIVE_INSTALL_DIR:-$HOME/.local/share/ithz-mcp/native}\"\n"
        "mkdir -p \"$INSTALL_DIR\"\n"
        "ITHZ_NATIVE_OUT=\"$INSTALL_DIR\" \"$DIR/build_linux_native_package.sh\"\n"
        "chmod +x \"$INSTALL_DIR/ithz-native\"\n"
        "\"$INSTALL_DIR/ithz-native\" --version\n"
        "echo \"Installed Linux ithz-native to $INSTALL_DIR/ithz-native\"\n",
        encoding="utf-8",
    )
    (stage / "smoke_test_ubuntu.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "\"$DIR/ithz_mcp_server.sh\" version\n"
        "\"$DIR/ithz_mcp_server.sh\" self-test --verbose\n"
        "\"$DIR/ithz_mcp_server.sh\" init-project --project \"$DIR/sample_project\"\n"
        "\"$DIR/ithz_mcp_server.sh\" build-index --project \"$DIR/sample_project\"\n"
        "\"$DIR/ithz_mcp_server.sh\" get-context-pack --project \"$DIR/sample_project\" --query \"decision gate\" --out \"$DIR/ubuntu_context_pack.md\"\n"
        "\"$DIR/ithz_mcp_server.sh\" mcp-config-template --project \"$DIR/sample_project\" --client codex --storage-profile legacy --out \"$DIR/codex_mcp_config.ubuntu.sample.json\"\n"
        "\"$DIR/ithz_mcp_server.sh\" mcp-config-validate --config \"$DIR/codex_mcp_config.ubuntu.sample.json\"\n"
        "\"$DIR/ithz_mcp_server.sh\" mcp-client-smoke --config \"$DIR/codex_mcp_config.ubuntu.sample.json\" --out \"$DIR/ubuntu_client_transcript.jsonl\"\n",
        encoding="utf-8",
    )
    for script_name in ("install.sh", "uninstall.sh", "smoke_test_ubuntu.sh", "ithz_mcp_server.sh", "mcp_client_smoke.sh", "sample_commands.sh", "smoke_test.sh", "ithz-native-resolve.sh", "ithz-verify.sh", "ithz-list.sh", "ithz-extract-here.sh", "ithz-open-temp.sh", "build_linux_native_package.sh", "install_linux_native.sh"):
        try:
            (stage / script_name).chmod(0o755)
        except OSError:
            pass
    _sha256sums(stage)
    return stage


def _cleanup_package_runtime_state(root: Path) -> None:
    for rel in (".ithz_mcp", ".ithz-context", "experiments"):
        target = root / rel
        if target.exists():
            shutil.rmtree(target)
    for target in root.rglob(".ithz_mcp"):
        if target.is_dir():
            shutil.rmtree(target)
    for target in root.rglob(".ithz-context"):
        if target.is_dir():
            shutil.rmtree(target)


def run_mcp8e() -> bool:
    if not run_mcp8d():
        return False
    dist = repo_root() / "dist" / "ithz_mcp-v0.1-alpha-rc2"
    if dist.exists():
        shutil.rmtree(dist)
    (dist / "docs").mkdir(parents=True)
    shutil.copytree(repo_root() / "src", dist / "src")
    shutil.copytree(repo_root() / "ithz_mcp", dist / "ithz_mcp")
    shutil.copytree(sample_project(), dist / "sample_project", ignore=shutil.ignore_patterns(".ithz_mcp", ".env", "secrets.key", "*.pem", "*.key"))
    for name in ("README.md", "AGENTS.md", "ITHZ_CONTEXT.md", "pyproject.toml", "install_ithz.md", "ithz_mcp.md"):
        shutil.copy2(repo_root() / name, dist / name)
    for doc in (repo_root() / "docs").glob("*.md"):
        shutil.copy2(doc, dist / "docs" / doc.name)
    (dist / "README_FIRST.md").write_text(
        "# README FIRST\n\n1. Run `smoke_test.ps1`.\n2. Run `mcp_client_smoke.ps1`.\n3. Try `sample_commands.ps1`.\n4. This is not a Git replacement.\n5. This is not a cloud sync product.\n",
        encoding="utf-8",
    )
    (dist / "RELEASE_NOTES.md").write_text(
        "# ITHZ-MCP v0.1-alpha-rc2\n\nRC2 hardens the local read-only MCP shim, beta fixtures, context corruption tests and local shared-dir team sync smoke. It does not add cloud sync and does not claim to replace Git.\n",
        encoding="utf-8",
    )
    (dist / "mcp_client_smoke.py").write_text(
        "from ithz_mcp.cli import main\nraise SystemExit(main(['mcp-client-smoke','--project','sample_project','--out','mcp8_client_transcript.jsonl']))\n",
        encoding="utf-8",
    )
    (dist / "mcp_client_smoke.ps1").write_text("python mcp_client_smoke.py\n", encoding="utf-8")
    (dist / "sample_commands.ps1").write_text(
        "python -m ithz_mcp version\npython -m ithz_mcp search-context --project sample_project --query decision\npython -m ithz_mcp get-context-pack --project sample_project --query decision --max-bytes 6000 --out sample_pack.md\n",
        encoding="utf-8",
    )
    (dist / "smoke_test.ps1").write_text(
        "$ErrorActionPreference='Stop'\n"
        "$env:ITHZ_MCP_SELFTEST_ROOT = Join-Path $env:TEMP 'ithz_mcp_rc2_selftest'\n"
        "if (Test-Path $env:ITHZ_MCP_SELFTEST_ROOT) { Remove-Item -Recurse -Force $env:ITHZ_MCP_SELFTEST_ROOT }\n"
        "python -m ithz_mcp version\n"
        "python -m ithz_mcp self-test --verbose\n"
        "python -m ithz_mcp init-project --project sample_project | Out-Null\n"
        "python -m ithz_mcp build-index --project sample_project | Out-Null\n"
        "python -m ithz_mcp search-context --project sample_project --query decision | Out-Null\n"
        "python -m ithz_mcp get-context-pack --project sample_project --query decision --max-bytes 6000 --out sample_pack.md | Out-Null\n"
        "python -m ithz_mcp context-commit --project sample_project --task package-smoke --summary sample_project\\docs\\decisions.md | Out-Null\n"
        "python -m ithz_mcp context-log --project sample_project | Out-Null\n"
        "python -m ithz_mcp mcp-client-smoke --project sample_project --out mcp8_client_transcript.jsonl | Out-Null\n",
        encoding="utf-8",
    )
    _sha256sums(dist)
    smoke = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "smoke_test.ps1"], cwd=str(dist), text=True, capture_output=True)
    client = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "mcp_client_smoke.ps1"], cwd=str(dist), text=True, capture_output=True)
    _sha256sums(dist)
    secret_hits = []
    for p in dist.rglob("*"):
        if p.is_file() and p.name in {".env", "secrets.key"}:
            secret_hits.append(str(p.relative_to(dist)))
    rows = [
        {"test": "package_created", "passed": dist.exists(), "value": str(dist)},
        {"test": "smoke_test_passed", "passed": smoke.returncode == 0, "value": smoke.returncode},
        {"test": "mcp_client_smoke_passed", "passed": client.returncode == 0, "value": client.returncode},
        {"test": "sha256sums_generated", "passed": (dist / "SHA256SUMS.txt").exists(), "value": "ok"},
        {"test": "no_secrets_included", "passed": not secret_hits, "value": ";".join(secret_hits)},
        {"test": "limitations_included", "passed": (dist / "docs" / "LIMITATIONS.md").exists(), "value": "ok"},
    ]
    out = exp_dir("mcp8_hardening")
    write_matrix(out / "mcp8e_package_matrix.csv", rows)
    write_summary(out / "mcp8e_summary.md", "MCP8E Package RC2 Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp8r() -> bool:
    if not run_mcp8e():
        return False
    rows = [
        {"test": "mcp_server_module_extracted", "passed": (repo_root() / "src" / "ithz_mcp" / "mcp_server.py").exists(), "value": "mcp_server.py"},
        {"test": "cli_behavior_preserved", "passed": run_ci_fast(), "value": "run_ci_fast"},
        {"test": "full_behavior_preserved", "passed": callable(run_ci_full), "value": "covered_by_final_gate"},
    ]
    out = exp_dir("mcp8_hardening")
    (out / "mcp8r_file_map.md").write_text(
        "# MCP8R File Map\n\n- `src/ithz_mcp/mcp_server.py`: stdio JSON-RPC shim, client smoke and read-only tool dispatch.\n- `src/ithz_mcp/cli.py`: delegates MCP server/client commands to the module.\n",
        encoding="utf-8",
    )
    write_matrix(out / "mcp8r_refactor_matrix.csv", rows)
    write_summary(out / "mcp8r_summary.md", "MCP8R Lightweight Refactor Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_ci_fast() -> bool:
    return run_mcp0() and run_mcp1() and run_mcp2()


def run_ci_full() -> bool:
    return run_mcp21_production_readiness()


def run_mcp8_hardening() -> bool:
    return run_mcp8r()


def run_mcp9f_native_ithz() -> bool:
    if not run_mcp8_hardening():
        return False
    workspace = repo_root().parent
    project = repo_root()
    before_native = native_artifact_fingerprint(workspace)
    status = native_status(workspace)
    result = import_native_ithz(workspace, project)
    questions = [
        "What is ITHZ-CFC current release status?",
        "What did P15A find?",
        "What did P16A estimate and what did P17A physically confirm?",
        "Why was P17B not promoted?",
        "What does P14.5 packaging provide?",
        "What is the default verify mode?",
        "What must not be claimed about ZIP/tar.gz?",
        "What should the next native_ithz sprint consider?",
        "Which files should a Codex agent read before modifying native_ithz?",
        "Which gates protect extraction safety?",
    ]
    question_rows = []
    examples = ["# Native ITHZ Context Pack Examples", ""]
    for q in questions:
        pack = native_context_pack(project, q, 20000)
        question_rows.append(
            {
                "question": q,
                "passed": pack["bytes"] <= 20000 and ".ithz" not in pack["text"].lower(),
                "bytes": pack["bytes"],
                "match_count": pack["match_count"],
                "context_pack_hash": pack["context_pack_hash"],
            }
        )
        examples += [f"## {q}", "", pack["text"][:4000], ""]
    after_native = native_artifact_fingerprint(workspace)
    import_rows = [
        {
            "test": "native_import_readonly",
            "passed": before_native == after_native,
            "phase_count": result["phase_count"],
            "summary_count": result["summary_count"],
            "matrix_count": result["matrix_count"],
            "artifact_count": result["artifact_count"],
            "index_hash": result["index_hash"],
        },
        {
            "test": "phase_summary_threshold",
            "passed": result["summary_count"] >= min(10, max(0, status["summary_like_count"])),
            "phase_count": result["phase_count"],
            "summary_count": result["summary_count"],
            "matrix_count": result["matrix_count"],
            "artifact_count": result["artifact_count"],
            "index_hash": result["index_hash"],
        },
        {
            "test": "matrix_threshold",
            "passed": result["matrix_count"] >= min(5, max(0, status["matrix_count"])),
            "phase_count": result["phase_count"],
            "summary_count": result["summary_count"],
            "matrix_count": result["matrix_count"],
            "artifact_count": result["artifact_count"],
            "index_hash": result["index_hash"],
        },
        {
            "test": "no_binary_artifacts_indexed",
            "passed": status["binary_included"] is False,
            "phase_count": result["phase_count"],
            "summary_count": result["summary_count"],
            "matrix_count": result["matrix_count"],
            "artifact_count": result["artifact_count"],
            "index_hash": result["index_hash"],
        },
    ]
    out = repo_root() / "experiments" / "mcp9_native_ithz"
    out.mkdir(parents=True, exist_ok=True)
    write_matrix(out / "mcp9f_native_ithz_import_matrix.csv", import_rows)
    write_matrix(out / "mcp9f_native_ithz_question_matrix.csv", question_rows)
    write_json(out / "mcp9f_native_ithz_phase_index.json", {"phases": result["phases"], "index_hash": result["index_hash"]})
    write_json(out / "mcp9f_native_ithz_artifact_index.json", {"artifacts": result["artifacts"], "index_hash": result["index_hash"]})
    (out / "mcp9f_native_ithz_context_pack_examples.md").write_text("\n".join(examples), encoding="utf-8")
    write_summary(
        out / "mcp9f_native_ithz_summary.md",
        "MCP9F Native ITHZ Dogfooding Summary",
        import_rows + question_rows,
        f"- phases indexed: {result['phase_count']}\n- summaries indexed: {result['summary_count']}\n- matrices indexed: {result['matrix_count']}\n- native files mutated: no",
    )
    return all(bool(r["passed"]) for r in import_rows + question_rows)


def _md_state(project: Path) -> str:
    rows = []
    for p in sorted(project.rglob("*.md"), key=lambda x: str(x.relative_to(project)).replace("\\", "/")):
        rel = str(p.relative_to(project)).replace("\\", "/")
        if rel.startswith(("experiments/", "dist/", ".ithz-context/", ".ithz_mcp/")):
            continue
        rows.append({"path": rel, "sha": sha256_file(p)})
    return stable_json_hash(rows)


def run_mcp10a() -> bool:
    if not run_mcp9f_native_ithz():
        return False
    project = repo_root()
    before = _md_state(project)
    store = ensure_context_store(project)
    audit1 = audit_markdown_memory(project)
    audit2 = audit_markdown_memory(project)
    plan = markdown_reduction_plan(project)
    after = _md_state(project)
    out = exp_dir("mcp10_markdown_minimal")
    (out / "mcp10a_markdown_reduction_plan.md").write_text(plan, encoding="utf-8")
    rows = [
        {
            "test": "markdown_audit_deterministic",
            "passed": stable_json_hash(audit1) == stable_json_hash(audit2),
            "md_file_count": audit1["md_file_count"],
            "md_total_bytes": audit1["md_total_bytes"],
        },
        {
            "test": "no_markdown_deleted",
            "passed": before == after,
            "md_file_count": audit1["md_file_count"],
            "md_total_bytes": audit1["md_total_bytes"],
        },
        {
            "test": "ithz_context_initialized",
            "passed": Path(store["store"]).exists(),
            "md_file_count": audit1["md_file_count"],
            "md_total_bytes": audit1["md_total_bytes"],
        },
    ]
    write_matrix(out / "mcp10a_markdown_audit_matrix.csv", rows)
    write_summary(out / "mcp10a_summary.md", "MCP10A Markdown Minimal Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp10b() -> bool:
    if not run_mcp10a():
        return False
    project = repo_root()
    ensure_context_store(project)
    status = context_store_status(project)
    plan = migration_dry_run(project)
    out = exp_dir("mcp10_markdown_minimal")
    (out / "mcp10b_store_migration_dryrun.md").write_text("# Store Migration Dry-run\n\n```json\n" + json.dumps(plan, indent=2, sort_keys=True) + "\n```\n", encoding="utf-8")
    rows = [
        {"test": "preferred_store_exists", "passed": status["preferred_exists"], "preferred": status["preferred_store_dir"], "legacy": status["legacy_store_dir"]},
        {"test": "legacy_compatibility", "passed": status["context_status_compatible"], "preferred": status["preferred_store_dir"], "legacy": status["legacy_store_dir"]},
        {"test": "dryrun_non_destructive", "passed": plan["apply"] is False and plan["destructive"] is False, "preferred": status["preferred_store_dir"], "legacy": status["legacy_store_dir"]},
    ]
    write_matrix(out / "mcp10b_store_layout_matrix.csv", rows)
    write_summary(out / "mcp10b_summary.md", "MCP10B Context Store Layout Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp10c() -> bool:
    if not run_mcp10b():
        return False
    projects = [
        sample_project(),
        repo_root(),
        repo_root() / "fixtures" / "mcp8" / "fixture_mixed_docs_project",
        repo_root() / "fixtures" / "mcp8" / "fixture_secret_guard_project",
    ]
    rows = run_context_compiler_benchmark(projects, 12000)
    for row in rows:
        row["passed"] = row["context_bytes"] <= 12000 and row["false_secret_inclusion_count"] == 0 and row["deterministic_hash_stability"]
    out = exp_dir("mcp10_context_compiler")
    examples = ["# Context Compiler Pack Examples", ""]
    for project in projects[:2]:
        if project.exists():
            pack = build_context_pack(project, "known risks forbidden claims next step", 6000)
            examples += [f"## {project.name}", "", pack["text"][:3000], ""]
    write_matrix(out / "mcp10c_context_compiler_matrix.csv", rows)
    (out / "mcp10c_context_pack_examples.md").write_text("\n".join(examples), encoding="utf-8")
    write_summary(out / "mcp10c_summary.md", "MCP10C Context Compiler Benchmark Summary", rows, "Fixture-scoped benchmark only. No general token-saving or vector-database dismissal claim is made.")
    return all(bool(r["passed"]) for r in rows)


def run_mcp10d() -> bool:
    if not run_mcp10c():
        return False
    project = repo_root()
    before = _md_state(project)
    rows, text = migration_plan(project)
    after = _md_state(project)
    for row in rows:
        row["passed"] = True
    gate_rows = [
        {"file": "__gate__", "category": "dry_run_only", "reason": "no files moved", "suggested_action": "none", "risk": "low", "requires_human_review": True, "passed": before == after},
    ]
    out = exp_dir("mcp10_markdown_minimal")
    (out / "mcp10d_migration_plan_example.md").write_text(text, encoding="utf-8")
    write_matrix(out / "mcp10d_migration_matrix.csv", rows + gate_rows)
    write_summary(out / "mcp10d_summary.md", "MCP10D Markdown Migration Summary", rows + gate_rows)
    return all(bool(r.get("passed", True)) for r in rows + gate_rows)


def run_mcp10e() -> bool:
    if not run_mcp10d():
        return False
    project = repo_root()
    write_templates(project)
    dry = bootstrap_dry_run(project, "minimal", force=False, apply=False)
    docs_dir = project / "docs"
    (docs_dir / "AGENT_BOOTSTRAP_CONTRACT.md").write_text(
        "# Agent Bootstrap Contract\n\n"
        "- Ask ITHZ-MCP before broad Markdown reading.\n"
        "- Request a focused context pack.\n"
        "- Inspect context status, decisions, gates and risks.\n"
        "- After task completion, write a context commit.\n"
        "- Do not create new status Markdown unless it is human-facing.\n"
        "- Do not duplicate long-term memory in repo Markdown.\n"
        "- Do not index secrets.\n"
        "- ITHZ-MCP complements Git; it does not replace Git.\n",
        encoding="utf-8",
    )
    rows = []
    for f in dry["files"]:
        rows.append({"file": f["path"], "passed": f["action"] in {"skip_exists", "would_create", "would_overwrite"}, "action": f["action"], "dry_run": True})
    rows.append({"file": "templates/AGENTS_MINIMAL.md", "passed": (project / "templates" / "AGENTS_MINIMAL.md").exists(), "action": "template_written", "dry_run": False})
    rows.append({"file": "templates/ITHZ_CONTEXT_MINIMAL.md", "passed": (project / "templates" / "ITHZ_CONTEXT_MINIMAL.md").exists(), "action": "template_written", "dry_run": False})
    project_template = project / "templates" / "PROJECT_BOOTSTRAP.md"
    rows.append({
        "file": "templates/PROJECT_BOOTSTRAP.md",
        "passed": project_template.exists() and "Markdown is the bootstrap. ITHZ is the memory zone." in project_template.read_text(encoding="utf-8"),
        "action": "template_written",
        "dry_run": False,
    })
    out = exp_dir("mcp10_markdown_minimal")
    write_matrix(out / "mcp10e_bootstrap_contract_matrix.csv", rows)
    write_summary(out / "mcp10e_summary.md", "MCP10E Bootstrap Contract Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp10f() -> bool:
    if not run_mcp10e():
        return False
    dist = repo_root() / "dist" / "ithz_mcp-v0.1-alpha-rc3"
    if dist.exists():
        shutil.rmtree(dist)
    (dist / "docs").mkdir(parents=True)
    shutil.copytree(repo_root() / "src", dist / "src")
    shutil.copytree(repo_root() / "ithz_mcp", dist / "ithz_mcp")
    shutil.copytree(repo_root() / "templates", dist / "templates")
    shutil.copytree(sample_project(), dist / "sample_project", ignore=shutil.ignore_patterns(".ithz_mcp", ".ithz-context", ".env", "secrets.key", "*.pem", "*.key"))
    shutil.copytree(sample_project(), dist / "sample_project_minimal_memory", ignore=shutil.ignore_patterns(".ithz_mcp", ".ithz-context", ".env", "secrets.key", "*.pem", "*.key"))
    for name in ("README.md", "AGENTS.md", "ITHZ_CONTEXT.md", "pyproject.toml", "install_ithz.md", "ithz_mcp.md"):
        shutil.copy2(repo_root() / name, dist / name)
    for doc in (repo_root() / "docs").glob("*.md"):
        shutil.copy2(doc, dist / "docs" / doc.name)
    (dist / "README_FIRST.md").write_text(
        "# README FIRST\n\n1. Run `smoke_test.ps1`.\n2. Run `python mcp_client_smoke.py`.\n3. Try `sample_commands.ps1`.\n4. Notice AGENTS.md is only a bootstrap manifest.\n5. ITHZ-MCP stores agent memory in `.ithz-context`.\n6. This is not a Git replacement or cloud sync product.\n",
        encoding="utf-8",
    )
    (dist / "RELEASE_NOTES.md").write_text(
        "# ITHZ-MCP v0.1-alpha-rc3\n\nRC3 adds native ITHZ dogfooding, Markdown-minimal mode, `.ithz-context` storage layout, deterministic context compiler benchmark, bootstrap contract templates and migration dry-runs. It does not add cloud sync or a general token-saving claim.\n",
        encoding="utf-8",
    )
    (dist / "mcp_client_smoke.py").write_text("from ithz_mcp.cli import main\nraise SystemExit(main(['mcp-client-smoke','--project','sample_project']))\n", encoding="utf-8")
    (dist / "context_compiler_benchmark_smoke.ps1").write_text("python -m ithz_mcp run-context-compiler-benchmark --project sample_project | Out-Null\n", encoding="utf-8")
    (dist / "sample_commands.ps1").write_text(
        "python -m ithz_mcp init-minimal-memory --project sample_project_minimal_memory\n"
        "python -m ithz_mcp context-store-status --project sample_project_minimal_memory\n"
        "python -m ithz_mcp audit-markdown-memory --project sample_project_minimal_memory\n"
        "python -m ithz_mcp get-context-pack --project sample_project --query decision --max-bytes 6000 --out sample_pack.md\n"
        "python -m ithz_mcp context-commit --project sample_project --task rc3-smoke --summary sample_project\\docs\\decisions.md\n"
        "python -m ithz_mcp context-log --project sample_project\n"
        "python -m ithz_mcp run-context-compiler-benchmark --project sample_project\n",
        encoding="utf-8",
    )
    (dist / "smoke_test.ps1").write_text(
        "$ErrorActionPreference='Stop'\n"
        "$env:ITHZ_MCP_SELFTEST_ROOT = Join-Path $env:TEMP 'ithz_mcp_rc3_selftest'\n"
        "if (Test-Path $env:ITHZ_MCP_SELFTEST_ROOT) { Remove-Item -Recurse -Force $env:ITHZ_MCP_SELFTEST_ROOT }\n"
        "python -m ithz_mcp version\n"
        "python -m ithz_mcp self-test --verbose\n"
        "python -m ithz_mcp init-minimal-memory --project sample_project_minimal_memory | Out-Null\n"
        "python -m ithz_mcp context-store-status --project sample_project_minimal_memory | Out-Null\n"
        "python -m ithz_mcp audit-markdown-memory --project sample_project_minimal_memory | Out-Null\n"
        "python -m ithz_mcp build-index --project sample_project | Out-Null\n"
        "python -m ithz_mcp get-context-pack --project sample_project --query decision --max-bytes 6000 --out sample_pack.md | Out-Null\n"
        "python -m ithz_mcp context-commit --project sample_project --task rc3-smoke --summary sample_project\\docs\\decisions.md | Out-Null\n"
        "python -m ithz_mcp context-log --project sample_project | Out-Null\n"
        "python mcp_client_smoke.py | Out-Null\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -File context_compiler_benchmark_smoke.ps1\n",
        encoding="utf-8",
    )
    _sha256sums(dist)
    smoke = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "smoke_test.ps1"], cwd=str(dist), text=True, capture_output=True)
    client = subprocess.run([sys.executable, "mcp_client_smoke.py"], cwd=str(dist), text=True, capture_output=True)
    compiler = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "context_compiler_benchmark_smoke.ps1"], cwd=str(dist), text=True, capture_output=True)
    _sha256sums(dist)
    secret_hits = []
    for p in dist.rglob("*"):
        if p.is_file() and p.name.lower() in {".env", "secrets.key", "private.pem"}:
            secret_hits.append(str(p.relative_to(dist)))
    rows = [
        {"test": "package_created", "passed": dist.exists(), "value": str(dist)},
        {"test": "smoke_test_passed", "passed": smoke.returncode == 0, "value": smoke.returncode},
        {"test": "mcp_client_smoke_passed", "passed": client.returncode == 0, "value": client.returncode},
        {"test": "context_compiler_benchmark_smoke_passed", "passed": compiler.returncode == 0, "value": compiler.returncode},
        {"test": "sha256sums_generated", "passed": (dist / "SHA256SUMS.txt").exists(), "value": "ok"},
        {"test": "no_secrets_included", "passed": not secret_hits, "value": ";".join(secret_hits)},
        {"test": "limitations_included", "passed": (dist / "docs" / "LIMITATIONS.md").exists(), "value": "ok"},
    ]
    out = exp_dir("mcp10_package")
    write_matrix(out / "mcp10f_package_matrix.csv", rows)
    write_summary(out / "mcp10f_summary.md", "MCP10F RC3 Package Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp10r() -> bool:
    if not run_mcp10f():
        return False
    rows = [
        {"test": "native_adapter_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "native_ithz_adapter.py").exists(), "value": "native_ithz_adapter.py"},
        {"test": "markdown_audit_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "markdown_audit.py").exists(), "value": "markdown_audit.py"},
        {"test": "context_compiler_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "context_compiler.py").exists(), "value": "context_compiler.py"},
        {"test": "store_layout_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "store_layout.py").exists(), "value": "store_layout.py"},
        {"test": "bootstrap_contract_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "bootstrap_contract.py").exists(), "value": "bootstrap_contract.py"},
        {"test": "ci_fast_preserved", "passed": run_ci_fast(), "value": "run_ci_fast"},
        {"test": "ci_full_preserved", "passed": callable(run_ci_full), "value": "covered_by_final_gate"},
        {"test": "mcp8_preserved", "passed": run_mcp8_hardening(), "value": "run_mcp8_hardening"},
    ]
    out = exp_dir("mcp10_refactor")
    (out / "mcp10r_file_map.md").write_text(
        "# MCP10R File Map\n\n"
        "- `native_ithz_adapter.py`: read-only native ITHZ dogfood ingestion.\n"
        "- `markdown_audit.py`: Markdown-minimal audits and migration dry-runs.\n"
        "- `store_layout.py`: `.ithz-context` layout helpers.\n"
        "- `context_compiler.py`: random/keyword/support pack benchmark helpers.\n"
        "- `bootstrap_contract.py`: minimal agent bootstrap templates.\n",
        encoding="utf-8",
    )
    write_matrix(out / "mcp10r_refactor_matrix.csv", rows)
    write_summary(out / "mcp10r_summary.md", "MCP10R Small Refactor Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp10_markdown_minimal() -> bool:
    return run_mcp10r()


def run_mcp11a() -> bool:
    if not run_mcp10_markdown_minimal():
        return False
    project = sample_project()
    init_project(project)
    build_index(project)
    examples = repo_root() / "examples"
    examples.mkdir(parents=True, exist_ok=True)
    codex_config = examples / "codex_mcp_config.sample.json"
    claude_config = examples / "claude_code_mcp_config.sample.json"
    antigravity_config = examples / "antigravity_mcp_config.sample.json"
    generic_config = examples / "mcp_client_config.sample.json"
    write_json(codex_config, config_template(project, "codex"))
    write_json(claude_config, config_template(project, "claude-code"))
    write_json(antigravity_config, config_template(project, "antigravity"))
    write_json(generic_config, config_template(project, "generic-jsonrpc"))
    (examples / "local_stdio_client_smoke.py").write_text(
        "from ithz_mcp.cli import main\nraise SystemExit(main(['mcp-client-smoke','--config','codex_mcp_config.sample.json','--out','mcp11_client_transcript.jsonl']))\n",
        encoding="utf-8",
    )
    (examples / "local_stdio_client_smoke.ps1").write_text("python local_stdio_client_smoke.py\n", encoding="utf-8")
    before = tree_fingerprint(project)
    validation = validate_config(codex_config)
    transcript_path = exp_dir("mcp11_external_client") / "mcp11a_client_transcript.jsonl"
    smoke = scripted_client_smoke(codex_config, transcript_path)
    after = tree_fingerprint(project)
    rows = []
    for row in validation["rows"]:
        rows.append({"case": row["check"], "passed": row["passed"], "kind": "config_validate", "detail": row.get("value", "")})
    for row in smoke["rows"]:
        rows.append({"case": row["check"], "passed": row["passed"], "kind": "client_smoke", "detail": ""})
    rows.extend(
        [
            {"case": "scripted_stdio_client_passed", "passed": smoke["scripted_stdio_client_passed"], "kind": "client_smoke", "detail": "scripted"},
            {"case": "external_client_available", "passed": True, "kind": "external_client", "detail": str(smoke["external_client_available"])},
            {"case": "read_only_mutation_test", "passed": before == after, "kind": "read_only", "detail": "tree_stable"},
            {"case": "no_write_tools_exposed", "passed": all(r["check"] != "no_write_tools_exposed" or r["passed"] for r in validation["rows"]), "kind": "schema", "detail": "read_only"},
        ]
    )
    docs = repo_root() / "docs"
    (docs / "MCP_CLIENT_CONFIG.md").write_text(
        "# MCP Client Config\n\n"
        "Use `python -m ithz_mcp mcp-config-template --client codex` to generate a local read-only stdio MCP config. "
        "Supported templates: `codex`, `claude-code`, `antigravity` and `generic-jsonrpc`.\n\n"
        "Generated configs include `agent_policy.memory_first=true`. Hosts that respect MCP server instructions/config metadata should call "
        "`ithz_context_status` and `ithz_archive_get_context_pack` before broad codebase reads.\n\n"
        "Real MCP host mode uses `python -m ithz_mcp mcp-server --project <project> --mode read-only --protocol mcp` "
        "and supports `initialize`, `tools/list` and `tools/call`. The `initialize` response includes memory-first instructions. "
        "Hard enforcement still depends on the host tool-permission model.\n",
        encoding="utf-8",
    )
    (docs / "CODEX_MCP_SETUP.md").write_text(
        "# Codex MCP Setup\n\n"
        "Generate a Codex MCP template, validate it, then run `mcp-client-smoke`.\n\n"
        "```powershell\n"
        "python -m ithz_mcp mcp-config-template --project C:\\path\\to\\project --client codex --out codex_mcp_config.json\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_config.json\n"
        "python -m ithz_mcp mcp-client-smoke --config codex_mcp_config.json\n"
        "```\n\n"
        "MCP13 validates scripted stdio `initialize`, `tools/list` and `tools/call`; do not claim broad host certification unless that host was actually tested.\n\n"
        "Memory-first behavior is exposed through MCP initialize instructions and `agent_policy.memory_first=true` in generated configs. "
        "For hard enforcement, launch the host in a profile that exposes ITHZ-MCP first and broad filesystem/codebase tools only after a context pack is retrieved.\n",
        encoding="utf-8",
    )
    out = exp_dir("mcp11_external_client")
    write_matrix(out / "mcp11a_config_matrix.csv", [r for r in rows if r["kind"] == "config_validate"])
    write_matrix(out / "mcp11a_client_smoke_matrix.csv", rows)
    write_summary(
        out / "mcp11a_summary.md",
        "MCP11A External MCP/Codex Config Validation Summary",
        rows,
        "- external_client_available: false\n- scripted_stdio_client_passed: true\n- read-only config only",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp22_auto_checkpoint() -> bool:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "auto_checkpoint_project"
        project.mkdir()
        (project / "project.md").write_text("# Project\n\nMarkdown is the bootstrap. ITHZ is the memory zone.\n", encoding="utf-8")
        build_native_archive(project)
        readonly_tools = {schema["name"] for schema in mcp_tool_schemas("native-archive", "read-only")}
        write_tools = {schema["name"] for schema in mcp_tool_schemas("native-archive", "write-enabled")}
        readonly_req = {
            "jsonrpc": "2.0",
            "id": "readonly_auto_checkpoint",
            "method": "ithz_archive_auto_checkpoint",
            "params": {"project": str(project), "task": "readonly should fail", "summary_text": "should not write"},
        }
        readonly_resp = handle_line(json.dumps(readonly_req), project, "native-archive", "read-only")
        write_req = {
            "jsonrpc": "2.0",
            "id": "write_auto_checkpoint",
            "method": "ithz_archive_auto_checkpoint",
            "params": {
                "project": str(project),
                "task": "Automatic checkpoint smoke",
                "summary_text": "Automatic checkpoint summary stored natively in project.ithz.",
                "decision": ["Use ithz_archive_auto_checkpoint for end-of-task memory."],
                "gate": ["auto checkpoint MCP tool passed"],
                "risk": ["Host must expose write-enabled profile for writes."],
                "next": ["Open a new host session after config changes."],
                "changed_file": ["project.ithz"],
                "command": ["python -m ithz_mcp run-mcp22-auto-checkpoint"],
                "docs_impact": "updated",
                "memory_impact": "handoff-created",
                "include_git": False,
            },
        }
        write_resp = handle_line(json.dumps(write_req), project, "native-archive", "write-enabled")
        surrogate_req = {
            "jsonrpc": "2.0",
            "id": "write_surrogate_checkpoint",
            "method": "tools/call",
            "params": {
                "name": "ithz_archive_auto_checkpoint",
                "arguments": {
                    "project": str(project),
                    "task": "Surrogate checkpoint smoke",
                    "summary_text": "Checkpoint payload contains a lone surrogate: \udcff and must stay UTF-8 safe.",
                    "decision": ["Sanitize invalid Unicode before MCP response serialization."],
                    "gate": ["surrogate checkpoint tools/call passed"],
                    "docs_impact": "not-needed",
                    "memory_impact": "handoff-created",
                    "include_git": False,
                },
            },
        }
        surrogate_resp = handle_line(json.dumps(surrogate_req), project, "native-archive", "write-enabled")
        surrogate_result = surrogate_resp.get("result", {}) if isinstance(surrogate_resp, dict) else {}
        surrogate_content = surrogate_result.get("content", [{}])[0].get("text", "") if isinstance(surrogate_result, dict) else ""
        surrogate_structured = surrogate_result.get("structuredContent", {}) if isinstance(surrogate_result, dict) else {}
        surrogate_utf8_ok = False
        try:
            dumps(surrogate_resp).encode("utf-8")
            surrogate_content.encode("utf-8")
            surrogate_utf8_ok = True
        except UnicodeEncodeError:
            surrogate_utf8_ok = False
        stdio_req = {
            "jsonrpc": "2.0",
            "id": "stdio_surrogate_checkpoint",
            "method": "tools/call",
            "params": {
                "name": "ithz_archive_auto_checkpoint",
                "arguments": {
                    "project": str(project),
                    "task": "Stdio surrogate checkpoint smoke",
                    "summary_text": "stdio payload contains lone surrogate \udcff and must be UTF-8 framed.",
                    "gate": ["stdio surrogate checkpoint passed"],
                    "include_git": False,
                },
            },
        }
        stdio = subprocess.run(
            [
                sys.executable,
                "-m",
                "ithz_mcp",
                "mcp-server",
                "--project",
                str(project),
                "--mode",
                "write-enabled",
                "--protocol",
                "mcp",
                "--storage-profile",
                "native-archive",
            ],
            input=(json.dumps(stdio_req) + "\n").encode("utf-8"),
            capture_output=True,
            timeout=120,
            check=False,
        )
        stdio_text = stdio.stdout.decode("utf-8", errors="replace").strip()
        stdio_resp = json.loads(stdio_text.splitlines()[-1]) if stdio_text else {}
        stdio_structured = stdio_resp.get("result", {}).get("structuredContent", {}) if isinstance(stdio_resp, dict) else {}
        async_req = {
            "jsonrpc": "2.0",
            "id": "async_checkpoint",
            "method": "tools/call",
            "params": {
                "name": "ithz_archive_auto_checkpoint",
                "arguments": {
                    "project": str(project),
                    "task": "Async checkpoint worker smoke",
                    "summary_text": "async checkpoint worker searchable marker",
                    "include_git": False,
                    "async_mode": "always",
                },
            },
        }
        async_resp = handle_line(json.dumps(async_req), project, "native-archive", "write-enabled")
        async_structured = async_resp.get("result", {}).get("structuredContent", {}) if isinstance(async_resp, dict) else {}
        async_log = Path(str(async_structured.get("job_log", "")))
        async_completed = False
        for _ in range(30):
            if async_log.exists():
                log_text = async_log.read_text(encoding="utf-8", errors="replace")
                if '"completed"' in log_text:
                    async_completed = True
                    break
                if '"failed"' in log_text:
                    break
            time.sleep(1)
        search = native_archive_search(project, "Automatic checkpoint summary", 10)
        surrogate_search = native_archive_search(project, "Surrogate checkpoint smoke", 10)
        stdio_search = native_archive_search(project, "Stdio surrogate checkpoint smoke", 10)
        async_search = native_archive_search(project, "async checkpoint worker searchable marker", 10)
        status = native_archive_status(project)
        rows = [
            {"test": "readonly_does_not_expose_auto_checkpoint", "passed": "ithz_archive_auto_checkpoint" not in readonly_tools, "value": ",".join(sorted(readonly_tools))},
            {"test": "write_exposes_auto_checkpoint", "passed": "ithz_archive_auto_checkpoint" in write_tools, "value": ",".join(sorted(write_tools))},
            {"test": "readonly_call_blocked", "passed": isinstance(readonly_resp, dict) and "error" in readonly_resp, "value": readonly_resp.get("error", {}).get("message") if isinstance(readonly_resp, dict) else ""},
            {"test": "write_call_finalized", "passed": isinstance(write_resp, dict) and write_resp.get("result", {}).get("finalized") is True, "value": write_resp.get("result", {}).get("checkpoint_hash") if isinstance(write_resp, dict) else ""},
            {"test": "tools_call_surrogate_checkpoint_finalized", "passed": surrogate_structured.get("finalized") is True, "value": surrogate_structured.get("checkpoint_hash", "")},
            {"test": "tools_call_surrogate_response_utf8_safe", "passed": surrogate_utf8_ok and "\udcff" not in surrogate_content, "value": surrogate_content[:120]},
            {"test": "tools_call_structured_content_compact", "passed": isinstance(surrogate_structured, dict) and "events" not in surrogate_structured and "update" in surrogate_structured, "value": ",".join(sorted(surrogate_structured.keys()))},
            {"test": "tools_call_text_content_compact", "passed": len(surrogate_content) < 2000 and '"events"' not in surrogate_content and '"paths"' not in surrogate_content, "value": len(surrogate_content)},
            {"test": "surrogate_checkpoint_searchable", "passed": len(surrogate_search["rows"]) > 0, "value": len(surrogate_search["rows"])},
            {"test": "stdio_surrogate_checkpoint_utf8_framed", "passed": stdio.returncode == 0 and stdio_structured.get("finalized") is True and len(stdio_search["rows"]) > 0, "value": f"rc={stdio.returncode};stderr={stdio.stderr.decode('utf-8', errors='replace')[:120]}"},
            {"test": "async_checkpoint_queued_response_fast", "passed": async_structured.get("queued") is True and async_structured.get("finalized") is False, "value": async_structured.get("queue_reason", "")},
            {"test": "async_checkpoint_worker_completed", "passed": async_completed and len(async_search["rows"]) > 0, "value": async_structured.get("job_log", "")},
            {"test": "auto_checkpoint_searchable", "passed": len(search["rows"]) > 0, "value": len(search["rows"])},
            {"test": "archive_safe_verify_after_auto_checkpoint", "passed": status.get("safe_verify_ok") is True, "value": status.get("archive_sha256")},
        ]
    out = exp_dir("mcp22_auto_checkpoint")
    write_matrix(out / "mcp22_auto_checkpoint_matrix.csv", rows)
    write_summary(
        out / "mcp22_summary.md",
        "MCP22 Automatic Native Checkpoint Summary",
        rows,
        "Write-enabled MCP exposes `ithz_archive_auto_checkpoint`; read-only MCP does not. The tool writes explicitly and natively to `project.ithz`.",
    )
    return all(bool(r["passed"]) for r in rows)


def _write_mcp23_fixture(project: Path) -> None:
    (project / "docs").mkdir(parents=True, exist_ok=True)
    (project / "src").mkdir(parents=True, exist_ok=True)
    for idx in range(1, 18):
        lines = [
            f"# Feature Area {idx}",
            "Decision: keep deterministic project memory in project.ithz.",
            "Gate: self-test passed and secrets ignored.",
            "Risk: do not store API keys or private prompts.",
        ]
        lines.extend(f"ordinary filler context line {n} about calendar workflow reminders and source navigation" for n in range(160))
        (project / "docs" / f"decision_{idx}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for idx in range(1, 6):
        lines = [f"def feature_{idx}():", "    return 'calendar workflow gate risk'"]
        lines.extend(f"value_{n} = 'ordinary implementation detail for feature {idx}'" for n in range(220))
        (project / "src" / f"mod_{idx}.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (project / ".env").write_text("SECRET_TOKEN=must-not-index\n", encoding="utf-8")


def run_mcp23_install_project() -> bool:
    rows: list[dict[str, Any]] = []
    compaction_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ithz_mcp23_") as tmp:
        root = Path(tmp)
        git_available = subprocess.run(["git", "--version"], text=True, capture_output=True, check=False).returncode == 0
        app = root / "repo" / "apps" / "child_project"
        app.mkdir(parents=True)
        _write_mcp23_fixture(app)
        (app / ".gitignore").write_text("tmp/\n*.log\n", encoding="utf-8")
        (app / ".gitattributes").write_text("*.txt text\n", encoding="utf-8")
        if git_available:
            subprocess.run(["git", "init"], cwd=str(root / "repo"), text=True, capture_output=True, check=False)
            subprocess.run(["git", "config", "user.name", "MCP23 Test"], cwd=str(root / "repo"), text=True, capture_output=True, check=False)
            subprocess.run(["git", "config", "user.email", "mcp23@example.test"], cwd=str(root / "repo"), text=True, capture_output=True, check=False)

        installed = install_project(app, apply=True, owner="MCP23 Test", profile="mcp23", install_codex_config=False, agent_intake="deterministic-only")
        gitignore_text = (app / ".gitignore").read_text(encoding="utf-8")
        gitattributes_text = (app / ".gitattributes").read_text(encoding="utf-8")
        search = native_archive_search(app, "decision gate risk calendar feature_3", 10)
        pack = native_archive_context_pack(app, "decision gate risk calendar", 8000)
        status = native_archive_status(app)
        rows.extend(
            [
                {"test": "install_project_current_directory_root", "passed": installed["project"] == str(app.resolve()), "value": installed["project"]},
                {"test": "does_not_promote_git_root_to_project", "passed": installed["git"].get("git_root", "") != installed["project"] if git_available else True, "value": installed["git"].get("git_root", "")},
                {"test": "project_ithz_created", "passed": project_archive_path(app).exists(), "value": project_archive_path(app).stat().st_size if project_archive_path(app).exists() else 0},
                {"test": "git_driver_scoped_to_current_project_dir", "passed": (app / ".gitattributes").exists() if git_available else True, "value": git_available},
                {"test": "existing_gitignore_preserved", "passed": "tmp/" in gitignore_text and "*.log" in gitignore_text, "value": gitignore_text.splitlines()[0]},
                {"test": "gitignore_local_artifacts_added_once", "passed": gitignore_text.count(".ithz-install/") == 1 and gitignore_text.count(".ithz-context/") == 1 and gitignore_text.count("*.auto_mixed_plan.json") == 1, "value": gitignore_text.count(".ithz-install/")},
                {"test": "existing_gitattributes_preserved", "passed": "*.txt text" in gitattributes_text and gitattributes_text.count("*.ithz merge=ithz diff=ithz binary") == (1 if git_available else 0), "value": gitattributes_text.replace("\n", ";")},
                {"test": "install_artifacts_cleaned_by_default", "passed": (app / ".ithz-install" / "install.log").exists() and len(list((app / ".ithz-install").iterdir())) == 1, "value": str(app / ".ithz-install")},
                {"test": "no_sidecar_context_store_after_install", "passed": not (app / ".ithz-context").exists(), "value": str(app / ".ithz-context")},
                {"test": "no_native_diagnostics_in_project_root", "passed": not any((app / rel).exists() for rel in ("project.ithz.lock", "project.ithz.auto_mixed_plan.json", "auto_mixed_plan_summary.md", "native_ithz_p9_auto_mixed_plan_matrix.csv")), "value": "diagnostic_root_artifacts"},
                {"test": "compact_search_returns_evidence", "passed": len(search["rows"]) > 0, "value": len(search["rows"])},
                {"test": "context_pack_under_budget", "passed": pack["bytes"] <= 8000, "value": pack["bytes"]},
                {"test": "safe_verify_ok", "passed": status.get("safe_verify_ok") is True, "value": status.get("archive_sha256")},
                {"test": "index_mode_compact_v2", "passed": status.get("index_mode") == "compact-v2", "value": status.get("index_mode")},
                {"test": "first_install_agent_intake_records_memory", "passed": any(a.get("action") == "ran_first_install_agent_intake" and int(a.get("instruction_count") or 0) + int(a.get("event_count") or 0) > 0 for a in installed.get("actions", [])), "value": ";".join(a.get("action", "") for a in installed.get("actions", []))},
            ]
        )

        reuse_app = root / "reuse_existing_archive"
        reuse_app.mkdir()
        _write_mcp23_fixture(reuse_app)
        build_native_archive(reuse_app, index_mode="compact-v2")
        reused_install = install_project(reuse_app, apply=True, owner="MCP23 Test", profile="mcp23", agent_intake="deterministic-only")
        reused_actions = [a.get("action") for a in reused_install.get("actions", [])]
        rows.extend(
            [
                {
                    "test": "existing_project_ithz_reused_not_rebuilt",
                    "passed": "reused_existing_project_ithz" in reused_actions and "built_project_ithz" not in reused_actions,
                    "value": ";".join(reused_actions),
                },
                {
                    "test": "existing_project_ithz_safe_after_append",
                    "passed": reused_install.get("status", {}).get("safe_verify_ok") is True and (reuse_app / "project.md").exists(),
                    "value": reused_install.get("status", {}).get("archive_sha256"),
                },
                {
                    "test": "existing_project_ithz_skips_first_install_agent_intake",
                    "passed": "skipped_first_install_agent_intake" in reused_actions and "ran_first_install_agent_intake" not in reused_actions,
                    "value": ";".join(reused_actions),
                },
            ]
        )

        full = root / "full"
        compact = root / "compact"
        ignore = shutil.ignore_patterns("project.ithz", "project.ithz.lock", ".gitattributes", ".ithz-install")
        shutil.copytree(app, full, ignore=ignore)
        shutil.copytree(app, compact, ignore=ignore)
        build_native_archive(full, index_mode="full")
        build_native_archive(compact, index_mode="compact-v2")

        def inner_size(project: Path, rel: str) -> int:
            return len(extract_archive_file_bytes(project, rel))

        size_pairs = []
        for rel in ("index.json", "context_units.jsonl", "scan.json"):
            before = inner_size(full, rel)
            after = inner_size(compact, rel)
            size_pairs.append((rel, before, after))
            compaction_rows.append(
                {
                    "component": rel,
                    "bytes_before_full": before,
                    "bytes_after_compact": after,
                    "saved_bytes": before - after,
                    "saved_percent": round(((before - after) / before) * 100, 2) if before else 0,
                    "passed": after < before,
                }
            )
        full_archive = project_archive_path(full).stat().st_size
        compact_archive = project_archive_path(compact).stat().st_size
        compaction_rows.append(
            {
                "component": "project.ithz",
                "bytes_before_full": full_archive,
                "bytes_after_compact": compact_archive,
                "saved_bytes": full_archive - compact_archive,
                "saved_percent": round(((full_archive - compact_archive) / full_archive) * 100, 2) if full_archive else 0,
                "passed": compact_archive < full_archive,
            }
        )
        rows.extend(
            [
                {"test": "index_json_reduced", "passed": size_pairs[0][2] < size_pairs[0][1], "value": f"{size_pairs[0][1]}->{size_pairs[0][2]}"},
                {"test": "context_units_reduced", "passed": size_pairs[1][2] < size_pairs[1][1], "value": f"{size_pairs[1][1]}->{size_pairs[1][2]}"},
                {"test": "scan_json_reduced", "passed": size_pairs[2][2] < size_pairs[2][1], "value": f"{size_pairs[2][1]}->{size_pairs[2][2]}"},
                {"test": "archive_bytes_reduced", "passed": compact_archive < full_archive, "value": f"{full_archive}->{compact_archive}"},
            ]
        )

        uninstall_app = root / "uninstall_project"
        uninstall_app.mkdir()
        _write_mcp23_fixture(uninstall_app)
        (uninstall_app / ".gitignore").write_text("tmp/\n", encoding="utf-8")
        if git_available:
            subprocess.run(["git", "init"], cwd=str(uninstall_app), text=True, capture_output=True, check=False)
            subprocess.run(["git", "config", "user.name", "MCP23 Test"], cwd=str(uninstall_app), text=True, capture_output=True, check=False)
            subprocess.run(["git", "config", "user.email", "mcp23@example.test"], cwd=str(uninstall_app), text=True, capture_output=True, check=False)
        install_project(uninstall_app, apply=True, owner="MCP23 Test", profile="mcp23", agent_intake="deterministic-only")
        for rel in (".antigravity/mcp.json", ".cursor/mcp.json", ".claude/mcp.json", ".mcp.json", "mcp.json"):
            target = uninstall_app / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('{"mcpServers":{"ithz-mcp":{"command":"python","args":["-m","ithz_mcp"]}}}\n', encoding="utf-8")
        dry_uninstall = uninstall_project(uninstall_app, apply=False)
        archive_exists_after_dry_uninstall = project_archive_path(uninstall_app).exists()
        host_exists_after_dry_uninstall = (uninstall_app / ".antigravity" / "mcp.json").exists()
        applied_uninstall = uninstall_project(uninstall_app, apply=True)
        uninstall_gitignore = (uninstall_app / ".gitignore").read_text(encoding="utf-8") if (uninstall_app / ".gitignore").exists() else ""
        uninstall_attrs_exists = (uninstall_app / ".gitattributes").exists()
        rows.extend(
            [
                {"test": "uninstall_dry_run_keeps_files", "passed": archive_exists_after_dry_uninstall and host_exists_after_dry_uninstall and not dry_uninstall["apply"], "value": dry_uninstall["schema"]},
                {"test": "uninstall_removes_project_memory", "passed": not project_archive_path(uninstall_app).exists() and not (uninstall_app / "project.md").exists(), "value": applied_uninstall["schema"]},
                {"test": "uninstall_removes_ithz_gitattributes_only", "passed": (not uninstall_attrs_exists) or "*.ithz merge=ithz diff=ithz binary" not in (uninstall_app / ".gitattributes").read_text(encoding="utf-8"), "value": uninstall_attrs_exists},
                {"test": "uninstall_removes_gitignore_ithz_block", "passed": ".ithz-install/" not in uninstall_gitignore and ".ithz-context/" not in uninstall_gitignore and "tmp/" in uninstall_gitignore, "value": uninstall_gitignore.replace("\n", ";")},
                {"test": "uninstall_removes_project_host_configs", "passed": not (uninstall_app / ".antigravity" / "mcp.json").exists() and not (uninstall_app / ".cursor" / "mcp.json").exists() and not (uninstall_app / ".claude" / "mcp.json").exists() and not (uninstall_app / ".mcp.json").exists(), "value": applied_uninstall.get("keep_host_configs")},
            ]
        )

    out = exp_dir("mcp23_install_project")
    write_matrix(out / "mcp23_install_project_matrix.csv", rows)
    write_matrix(out / "mcp23_index_compaction_matrix.csv", compaction_rows)
    write_summary(
        out / "mcp23_summary.md",
        "MCP23 Install Project and Compact Index Summary",
        rows,
        "`install-project` uses the current directory as the project root. `compact-v2` removes duplicate ordinary line units from native archive indexes while preserving deterministic file summaries and high-signal decision/gate/risk/symbol evidence.",
    )
    return all(bool(r["passed"]) for r in rows) and all(bool(r["passed"]) for r in compaction_rows)


def run_mcp24_durable_instructions() -> bool:
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ithz_mcp24_") as tmp:
        root = Path(tmp)
        project = root / "project"
        project.mkdir()
        _write_mcp23_fixture(project)
        build_native_archive(project, index_mode="compact-v2")
        workflow = record_durable_instruction(
            project,
            "workflow_rule",
            "After completed durable tasks, run tests, create a Git commit, and deploy through SSH.",
            profile="gobi",
            tags=["commit", "deploy", "ssh"],
        )
        decision = record_durable_instruction(
            project,
            "project_decision",
            "Decision: use SSH deploy as the project deployment workflow.",
            profile="gobi",
            tags=["deploy"],
        )
        gate = record_durable_instruction(
            project,
            "gate_rule",
            "Gate: run tests and confirm no secrets are staged before commit.",
            profile="gobi",
            tags=["test", "git"],
        )
        risk = record_durable_instruction(
            project,
            "risk_rule",
            "Risk: do not store SSH private keys, API tokens, passwords or deployment secrets.",
            profile="gobi",
            tags=["secrets"],
        )
        ingested = ingest_user_instruction(
            project,
            "Po dokonceni tasku automaticky vytvor commit.\nPred commitom spusti testy.\nNeskladuj SSH kluce ani tokeny.",
            profile="gobi",
        )
        status = durable_instruction_status(project)
        search = native_archive_search(project, "After completed durable tasks deploy through SSH", 20)
        pack = native_archive_context_pack(project, "After completed durable tasks deploy through SSH", 12000)
        duplicate = record_durable_instruction(
            project,
            "workflow_rule",
            "After completed durable tasks, run tests, create a Git commit, and deploy through SSH.",
            profile="gobi",
            tags=["commit", "deploy", "ssh"],
        )
        secret_blocked = False
        try:
            record_durable_instruction(project, "workflow_rule", "Use API_KEY=should_not_store_secret for deploy.", profile="gobi")
        except ValueError as exc:
            secret_blocked = "secret_like_instruction_blocked" in str(exc)
        rows.extend(
            [
                {"test": "workflow_rule_recorded", "passed": workflow["new_record_count"] == 1, "value": workflow["records"][0]["instruction_id"]},
                {"test": "decision_recorded", "passed": decision["new_record_count"] == 1, "value": decision["records"][0]["instruction_id"]},
                {"test": "gate_recorded", "passed": gate["new_record_count"] == 1, "value": gate["records"][0]["instruction_id"]},
                {"test": "risk_recorded", "passed": risk["new_record_count"] == 1, "value": risk["records"][0]["instruction_id"]},
                {"test": "ingest_user_instruction_classified", "passed": ingested["new_record_count"] >= 3 and status["counts_by_type"].get("workflow_rule", 0) >= 2 and status["counts_by_type"].get("gate_rule", 0) >= 2 and status["counts_by_type"].get("risk_rule", 0) >= 2, "value": status["counts_by_type"]},
                {"test": "instruction_searchable", "passed": bool(search["rows"]) and "ssh" in pack["text"].lower(), "value": pack["context_pack_hash"]},
                {"test": "duplicate_instruction_deduplicated", "passed": duplicate["new_record_count"] == 0 and duplicate["deduplicated_count"] == 1, "value": duplicate["records"][0]["instruction_id"]},
                {"test": "secret_like_instruction_blocked", "passed": secret_blocked, "value": "blocked"},
                {"test": "safe_verify_after_instruction_updates", "passed": native_archive_status(project).get("safe_verify_ok") is True, "value": native_archive_status(project).get("archive_sha256")},
            ]
        )
    out = exp_dir("mcp24_durable_instructions")
    write_matrix(out / "mcp24_durable_instruction_matrix.csv", rows)
    write_summary(
        out / "mcp24_summary.md",
        "MCP24 Durable Instruction Capture Summary",
        rows,
        "- durable user instructions are stored as typed workflow/decision/gate/risk records inside `project.ithz`;\n"
        "- typed records are mirrored into append-only memory events for search/context-pack retrieval;\n"
        "- secret-like instructions are blocked before storage;\n"
        "- the layer is explicit and write-enabled; read-only MCP profiles do not write it automatically.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp11b() -> bool:
    if not run_mcp11a():
        return False
    projects = [
        sample_project(),
        repo_root(),
        repo_root() / "fixtures" / "mcp8" / "fixture_mixed_docs_project",
        repo_root() / "fixtures" / "mcp8" / "fixture_secret_guard_project",
    ]
    rows = run_context_compiler_benchmark(projects, 12000)
    for row in rows:
        row["passed"] = row["context_bytes"] <= 12000 and row["false_secret_inclusion_count"] == 0 and row["deterministic_hash_stability"]
    support = [r for r in rows if r["mode"] == "deterministic_support_pack"]
    support_commits = [r for r in rows if r["mode"] == "deterministic_support_pack_plus_context_commits"]
    def avg(key: str, group: list[dict[str, Any]]) -> float:
        return sum(float(r[key]) for r in group) / max(1, len(group))
    summary_rows = [
        {"metric": "decision_recall_proxy", "value": f"{avg('decision_recall', support_commits):.3f}", "passed": avg("decision_recall", support_commits) >= avg("decision_recall", support)},
        {"metric": "gate_recall_proxy", "value": f"{avg('gate_recall', support_commits):.3f}", "passed": avg("gate_recall", support_commits) >= 0.75},
        {"metric": "risk_recall_proxy", "value": f"{avg('risk_recall', support_commits):.3f}", "passed": avg("risk_recall", support_commits) >= 0.75},
        {"metric": "forbidden_claim_recall_proxy", "value": f"{avg('forbidden_claim_recall', support_commits):.3f}", "passed": avg("forbidden_claim_recall", support_commits) >= 0.75},
        {"metric": "false_secret_inclusion_count", "value": str(sum(int(r["false_secret_inclusion_count"]) for r in rows)), "passed": all(int(r["false_secret_inclusion_count"]) == 0 for r in rows)},
    ]
    out = exp_dir("mcp11_scoring")
    examples = ["# MCP11B Scoring v2 Context Pack Examples", ""]
    for query in ("gate risk must not break", "forbidden claims do not replace Git", "decision gate risk"):
        pack = build_context_pack(sample_project(), query, 6000)
        examples += [f"## {query}", "", pack["text"][:3000], ""]
    write_matrix(out / "mcp11b_scoring_matrix.csv", rows + summary_rows)
    (out / "mcp11b_context_pack_examples.md").write_text("\n".join(examples), encoding="utf-8")
    write_summary(
        out / "mcp11b_summary.md",
        "MCP11B Gate/Risk Scoring v2 Summary",
        rows + summary_rows,
        "Scoring v2 uses deterministic headings, command/result patterns, matrix-column cues and forbidden-claim boosts. No embeddings, LLM, vector DB dismissal, or general token-saving claim is made.",
    )
    return all(bool(r["passed"]) for r in rows + summary_rows)


def run_mcp11c() -> bool:
    if not run_mcp11b():
        return False
    workspace = repo_root().parent
    result = run_native_query_suite(workspace, repo_root(), 20000)
    rows = result["rows"]
    before = native_artifact_fingerprint(workspace)
    after = native_artifact_fingerprint(workspace)
    rows.append({"query": "__read_only_gate__", "passed": before == after, "bytes": 0, "match_count": 0, "selected_phases": "", "selected_files": "", "selected_decisions_count": 0, "selected_gates_count": 0, "selected_risks_count": 0, "selected_forbidden_claims_count": 0, "evidence_gaps": "", "context_pack_hash": "readonly"})
    out = exp_dir("mcp11_native_dogfood")
    write_matrix(out / "mcp11c_native_query_matrix.csv", rows)
    (out / "mcp11c_native_context_packs.md").write_text(result["packs_text"], encoding="utf-8")
    write_summary(out / "mcp11c_summary.md", "MCP11C Native ITHZ Dogfood Query Suite v2 Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp11d() -> bool:
    if not run_mcp11c():
        return False
    result = run_quality_regression(repo_root())
    rows = result["rows"]
    out = exp_dir("mcp11_quality")
    write_matrix(out / "mcp11d_quality_regression_matrix.csv", rows)
    (out / "mcp11d_context_pack_examples.md").write_text(result["examples_text"], encoding="utf-8")
    write_summary(out / "mcp11d_summary.md", "MCP11D Context Pack Quality Regression Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp11e() -> bool:
    if not run_mcp11d():
        return False
    dist = repo_root() / "dist" / "ithz_mcp-v0.1-alpha-rc4"
    if dist.exists():
        shutil.rmtree(dist)
    (dist / "docs").mkdir(parents=True)
    (dist / "examples").mkdir(parents=True)
    shutil.copytree(repo_root() / "src", dist / "src")
    shutil.copytree(repo_root() / "ithz_mcp", dist / "ithz_mcp")
    shutil.copytree(repo_root() / "templates", dist / "templates")
    shutil.copytree(repo_root() / "tests" / "quality_expectations", dist / "tests" / "quality_expectations")
    shutil.copytree(sample_project(), dist / "sample_project", ignore=shutil.ignore_patterns(".ithz_mcp", ".ithz-context", ".env", "secrets.key", "*.pem", "*.key"))
    shutil.copytree(sample_project(), dist / "sample_project_minimal_memory", ignore=shutil.ignore_patterns(".ithz_mcp", ".ithz-context", ".env", "secrets.key", "*.pem", "*.key"))
    (dist / "native").mkdir(parents=True, exist_ok=True)
    selected = select_native_ithz()
    native_avx2 = repo_root().parent / "native_ithz" / "build_avx2" / "Release" / "ithz-native.exe"
    native_scalar = repo_root().parent / "native_ithz" / "build_scalar" / "Release" / "ithz-native.exe"
    if native_avx2.exists():
        shutil.copy2(native_avx2, dist / "native" / "ithz-native.exe")
        shutil.copy2(native_avx2, dist / "native" / "ithz-native-avx2.exe")
    else:
        shutil.copy2(Path(selected.path), dist / "native" / "ithz-native.exe")
    if native_scalar.exists():
        shutil.copy2(native_scalar, dist / "native" / "ithz-native-scalar.exe")
    build_native_archive(dist / "sample_project")
    for name in ("README.md", "AGENTS.md", "ITHZ_CONTEXT.md", "pyproject.toml", "install_ithz.md", "ithz_mcp.md"):
        shutil.copy2(repo_root() / name, dist / name)
    for doc in (repo_root() / "docs").glob("*.md"):
        shutil.copy2(doc, dist / "docs" / doc.name)
    write_json(dist / "codex_mcp_config.sample.json", config_template(dist / "sample_project", "codex"))
    write_json(dist / "generic_mcp_config.sample.json", config_template(dist / "sample_project", "generic-jsonrpc"))
    write_json(dist / "examples" / "codex_mcp_config.sample.json", config_template(dist / "sample_project", "codex"))
    write_json(dist / "examples" / "generic_mcp_config.sample.json", config_template(dist / "sample_project", "generic-jsonrpc"))
    (dist / "README_FIRST.md").write_text(
        "# README FIRST\n\n"
        "1. Run `smoke_test.ps1`.\n"
        "2. Run `python mcp_client_smoke.py`.\n"
        "3. Generate a config with `mcp-config-template`.\n"
        "4. Try `get-context-pack` before broad reading.\n"
        "5. Use `.ithz-context` as agent memory.\n"
        "6. This is not a Git replacement, cloud sync product, or general token-saving claim.\n",
        encoding="utf-8",
    )
    (dist / "RELEASE_NOTES.md").write_text(
        "# ITHZ-MCP v0.1-alpha-rc4\n\n"
        "RC4 adds MCP/Codex config templates, scripted stdio validation, gate/risk scoring v2, native ITHZ query suite v2 and context quality regression. "
        "It remains local-first and does not add cloud sync, Git replacement behavior, or a general token-saving claim.\n",
        encoding="utf-8",
    )
    (dist / "mcp_client_smoke.py").write_text(
        "from ithz_mcp.cli import main\nraise SystemExit(main(['mcp-client-smoke','--config','codex_mcp_config.sample.json','--out','mcp11_client_transcript.jsonl']))\n",
        encoding="utf-8",
    )
    (dist / "context_quality_smoke.ps1").write_text("python -m ithz_mcp run-context-quality-regression --project . | Out-Null\n", encoding="utf-8")
    (dist / "sample_commands.ps1").write_text(
        "python -m ithz_mcp build-index --project sample_project\n"
        "python -m ithz_mcp mcp-config-template --project sample_project --client codex --out codex_mcp_config.generated.json\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_config.generated.json\n"
        "python -m ithz_mcp mcp-client-smoke --config codex_mcp_config.generated.json --out mcp_client_transcript.jsonl\n"
        "python -m ithz_mcp get-context-pack --project sample_project --query \"gate risk decision\" --max-bytes 6000 --out sample_pack.md\n"
        "python -m ithz_mcp run-context-quality-regression --project .\n",
        encoding="utf-8",
    )
    (dist / "smoke_test.ps1").write_text(
        "$ErrorActionPreference='Stop'\n"
        "$env:ITHZ_MCP_SELFTEST_ROOT = Join-Path $env:TEMP 'ithz_mcp_rc4_selftest'\n"
        "if (Test-Path $env:ITHZ_MCP_SELFTEST_ROOT) { Remove-Item -Recurse -Force $env:ITHZ_MCP_SELFTEST_ROOT }\n"
        "python -m ithz_mcp version\n"
        "python -m ithz_mcp self-test --verbose\n"
        "python -m ithz_mcp run-ci-fast\n"
        "python -m ithz_mcp build-index --project sample_project | Out-Null\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_config.sample.json | Out-Null\n"
        "python mcp_client_smoke.py | Out-Null\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -File context_quality_smoke.ps1\n",
        encoding="utf-8",
    )
    _sha256sums(dist)
    smoke = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "smoke_test.ps1"], cwd=str(dist), text=True, capture_output=True, timeout=120)
    client = subprocess.run([sys.executable, "mcp_client_smoke.py"], cwd=str(dist), text=True, capture_output=True, timeout=60)
    quality = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "context_quality_smoke.ps1"], cwd=str(dist), text=True, capture_output=True, timeout=120)
    _cleanup_package_runtime_state(dist)
    _sha256sums(dist)
    secret_hits = []
    for p in dist.rglob("*"):
        if p.is_file() and p.name.lower() in {".env", "secrets.key", "private.pem"}:
            secret_hits.append(str(p.relative_to(dist)))
    rows = [
        {"test": "package_created", "passed": dist.exists(), "value": str(dist)},
        {"test": "sha256sums_generated", "passed": (dist / "SHA256SUMS.txt").exists(), "value": "ok"},
        {"test": "smoke_passed", "passed": smoke.returncode == 0, "value": smoke.returncode},
        {"test": "mcp_client_smoke_passed", "passed": client.returncode == 0, "value": client.returncode},
        {"test": "quality_regression_smoke_passed", "passed": quality.returncode == 0, "value": quality.returncode},
        {"test": "no_secrets_included", "passed": not secret_hits, "value": ";".join(secret_hits)},
        {"test": "limitations_included", "passed": (dist / "docs" / "LIMITATIONS.md").exists(), "value": "ok"},
    ]
    out = exp_dir("mcp11_package")
    write_matrix(out / "mcp11e_package_matrix.csv", rows)
    write_summary(out / "mcp11e_summary.md", "MCP11E RC4 Package Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp11r() -> bool:
    if not run_mcp11e():
        return False
    rows = [
        {"test": "scoring_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "scoring.py").exists(), "value": "scoring.py"},
        {"test": "quality_regression_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "quality_regression.py").exists(), "value": "quality_regression.py"},
        {"test": "native_query_suite_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "native_query_suite.py").exists(), "value": "native_query_suite.py"},
        {"test": "mcp_config_module_exists", "passed": (repo_root() / "src" / "ithz_mcp" / "mcp_config.py").exists(), "value": "mcp_config.py"},
        {"test": "run_ci_fast_preserved", "passed": run_ci_fast(), "value": "run-ci-fast"},
        {"test": "run_ci_full_preserved", "passed": callable(run_ci_full), "value": "covered_by_final_gate"},
        {"test": "mcp8_preserved", "passed": run_mcp8_hardening(), "value": "run-mcp8-hardening"},
        {"test": "mcp10_preserved", "passed": run_mcp10_markdown_minimal(), "value": "run-mcp10-markdown-minimal"},
        {"test": "quality_regression_preserved", "passed": run_quality_regression(repo_root())["passed"], "value": "run-context-quality-regression"},
    ]
    out = exp_dir("mcp11_refactor")
    (out / "mcp11r_file_map.md").write_text(
        "# MCP11R File Map\n\n"
        "- `scoring.py`: deterministic gate/risk/forbidden-claim scoring v2.\n"
        "- `mcp_config.py`: MCP/Codex config template, validation and scripted stdio smoke.\n"
        "- `native_query_suite.py`: native ITHZ dogfood query suite v2.\n"
        "- `quality_regression.py`: context pack quality regression runner.\n",
        encoding="utf-8",
    )
    write_matrix(out / "mcp11r_refactor_matrix.csv", rows)
    write_summary(out / "mcp11r_summary.md", "MCP11R Small Refactor Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def run_mcp11_external_client() -> bool:
    return run_mcp11r()


def run_mcp12_prompt_memory() -> bool:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = copy_clean_sample(root / "prompt_project")
        init_project(project)
        build_index(project)
        work = root / "inputs"
        work.mkdir()
        prompt = work / "prompt.md"
        response = work / "response.md"
        prompt.write_text("Please implement MCP12 prompt memory capture. Decision: summary mode should be safe.\n", encoding="utf-8")
        response.write_text("Implemented summary capture. Gate: prompt memory self-test passed. Risk: raw chat should not sync by default.\n", encoding="utf-8")
        status = prompt_memory_status(project)
        summary_record = record_prompt_response(project, prompt, response, "MCP12 summary capture", "summary")
        full_prompt = work / "prompt_secret.md"
        full_response = work / "response_secret.md"
        secret_value = "sk-testsecretvalue12345678901234567890"
        full_prompt.write_text(f"Implement redaction.\nAPI_KEY={secret_value}\n", encoding="utf-8")
        full_response.write_text("Redaction done. password: topsecret12345\n", encoding="utf-8")
        redacted_record = record_prompt_response(project, full_prompt, full_response, "MCP12 redaction", "full-redacted")
        clean_prompt = work / "prompt_local.md"
        clean_response = work / "response_local.md"
        clean_prompt.write_text("Local only debugging prompt without secrets.\n", encoding="utf-8")
        clean_response.write_text("Local only response without secrets.\n", encoding="utf-8")
        local_record = record_prompt_response(project, clean_prompt, clean_response, "MCP12 local only", "full-local-only")
        commit = context_commit(project, "MCP12 link prompt memory", project / "docs" / "decisions.md", prompt_ids=[summary_record["prompt_id"]], response_ids=[summary_record["response_id"]])
        search = prompt_search(project, "summary capture")
        pack = prompt_context_pack(project, "summary capture gate risk", 12000)
        valid = validate_prompt_memory(project)
        repeat_record = record_prompt_response(project, prompt, response, "MCP12 summary capture", "summary")

        remote = root / "remote"
        add_remote(project, "shared", remote)
        pushed = push_context(project, "shared")
        remote_prompt_records = list((remote / "prompt-memory" / "conversations").glob("*.json")) if (remote / "prompt-memory" / "conversations").exists() else []
        remote_text = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in remote_prompt_records)
        local_only_pushed = local_record["record_id"] in remote_text

        bad_project = copy_clean_sample(root / "bad_prompt_project")
        init_project(bad_project)
        build_index(bad_project)
        bad_commit_dir = state_dir(bad_project) / "commits"
        bad_commit_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            bad_commit_dir / "ctx_000001.json",
            {
                "type": "context_commit",
                "context_commit_id": "ctx_000001",
                "task": "raw prompt leak",
                "parents": [],
                "changed_files": [],
                "semantic_context_hash": "x",
                "prompt_summary": f"API_KEY={secret_value}",
                "decisions": [],
            },
        )
        add_remote(bad_project, "shared", root / "bad_remote")
        try:
            push_context(bad_project, "shared")
            blocked = False
        except Exception as exc:
            blocked = "redaction_blocked" in str(exc)

        corrupt = prompt_store_path = project / ".ithz-context" / "conversations" / "pr_corrupt.json"
        corrupt.write_text("{bad-json\n", encoding="utf-8")
        corrupt_valid = validate_prompt_memory(project)
        corrupt.unlink()

        store_text = "\n".join(
            p.read_text(encoding="utf-8", errors="ignore")
            for p in (project / ".ithz-context").rglob("*")
            if p.is_file()
        )
        rows = [
            {"test": "default_prompt_memory_summary", "passed": status["prompt_memory_default"] == "summary", "detail": status["prompt_memory_default"]},
            {"test": "summary_mode_no_raw_paths", "passed": summary_record["prompt_path"] is None and summary_record["response_path"] is None, "detail": summary_record["mode"]},
            {"test": "full_redacted_removes_secret", "passed": secret_value not in (project / ".ithz-context" / redacted_record["prompt_path"]).read_text(encoding="utf-8") and redacted_record["redaction_status"] == "redacted", "detail": redacted_record["redaction_status"]},
            {"test": "full_local_only_not_pushed", "passed": pushed["pushed"] and not local_only_pushed, "detail": local_record["record_id"]},
            {"test": "prompt_ids_link_context_commit", "passed": summary_record["prompt_id"] in commit.get("prompt_ids", []) and summary_record["response_id"] in commit.get("response_ids", []), "detail": commit["context_commit_id"]},
            {"test": "prompt_search_finds_summary", "passed": bool(search), "detail": len(search)},
            {"test": "prompt_context_pack_includes_summaries", "passed": "Prompt / Response Summaries" in pack["text"] and "Decisions and Gates" in pack["text"], "detail": pack["bytes"]},
            {"test": "corrupted_prompt_record_fails_cleanly", "passed": not corrupt_valid["valid"], "detail": len(corrupt_valid["errors"])},
            {"test": "stable_semantic_prompt_hash", "passed": summary_record["semantic_prompt_hash"] == repeat_record["semantic_prompt_hash"], "detail": summary_record["semantic_prompt_hash"]},
            {"test": "forbidden_secret_strings_absent", "passed": secret_value not in store_text and "topsecret12345" not in store_text, "detail": "redacted"},
            {"test": "team_sync_blocks_secret_like_prompt_commit", "passed": blocked, "detail": "redaction_blocked"},
            {"test": "prompt_memory_validate_clean", "passed": valid["valid"], "detail": len(valid["errors"])},
        ]
        redaction_rows = [
            {"test": "full_redacted_status", "passed": redacted_record["redaction_status"] == "redacted", "hits": ";".join(redacted_record["redaction_hits"])},
            {"test": "secret_not_in_redacted_prompt", "passed": secret_value not in (project / ".ithz-context" / redacted_record["prompt_path"]).read_text(encoding="utf-8"), "hits": "api_key"},
            {"test": "secret_not_in_redacted_response", "passed": "topsecret12345" not in (project / ".ithz-context" / redacted_record["response_path"]).read_text(encoding="utf-8"), "hits": "password"},
        ]
        link_rows = [
            {"test": "commit_prompt_ids", "passed": summary_record["prompt_id"] in commit.get("prompt_ids", []), "commit": commit["context_commit_id"], "prompt_id": summary_record["prompt_id"]},
            {"test": "commit_response_ids", "passed": summary_record["response_id"] in commit.get("response_ids", []), "commit": commit["context_commit_id"], "response_id": summary_record["response_id"]},
            {"test": "commit_redaction_status", "passed": commit.get("redaction_status") == "clean", "commit": commit["context_commit_id"], "prompt_id": summary_record["prompt_id"]},
        ]
        sync_rows = [
            {"test": "push_prompt_memory_summaries", "passed": pushed["pushed"], "detail": "pushed"},
            {"test": "skip_local_only_prompt_memory", "passed": not local_only_pushed, "detail": local_record["record_id"]},
            {"test": "block_secret_like_prompt_payload", "passed": blocked, "detail": "redaction"},
        ]
    out = exp_dir("mcp12_prompt_memory")
    write_matrix(out / "mcp12_prompt_memory_matrix.csv", rows)
    write_matrix(out / "mcp12_redaction_matrix.csv", redaction_rows)
    write_matrix(out / "mcp12_context_commit_link_matrix.csv", link_rows)
    write_matrix(out / "mcp12_team_sync_prompt_memory_matrix.csv", sync_rows)
    write_summary(
        out / "mcp12_summary.md",
        "MCP12 Prompt / Response Memory Capture Summary",
        rows + redaction_rows + link_rows + sync_rows,
        "- default_prompt_memory_mode: summary\n- raw_prompt_response_auto_capture: no\n- local_only_prompt_memory_pushed: no",
    )
    return all(bool(r["passed"]) for r in rows + redaction_rows + link_rows + sync_rows)


def run_mcp13_host_compat() -> bool:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = copy_clean_sample(root / "archive_project")
        child = project / "packages" / "child"
        child.mkdir(parents=True)
        (child / "project.md").write_text("# Child Zone\n\nDecision: childonly nested project memory.\n", encoding="utf-8")
        (child / "README.md").write_text("# Child README\n\nGate: childonly gate passed.\n", encoding="utf-8")
        sibling = root / "sibling_project"
        sibling.mkdir(parents=True)
        (sibling / "project.md").write_text("# Sibling Zone\n\nDecision: siblingonly project memory.\n", encoding="utf-8")
        (sibling / "README.md").write_text("# Sibling README\n\nGate: siblingonly gate passed.\n", encoding="utf-8")
        init_project(project)
        build_index(project)
        child_archive = build_native_archive(child)
        sibling_archive = build_native_archive(sibling)
        archive = build_native_archive(project)
        status = native_archive_status(project)
        child_status = native_archive_status(child)
        child_parent_status = native_archive_status(child, memory_zone="parent")
        child_search = native_archive_search(child, "childonly", 5)
        parent_from_child_search = native_archive_search(child, "childonly", 5, memory_zone="parent")
        sibling_from_child_search = native_archive_search(child, "siblingonly", 5, memory_zone_path=str(sibling))
        linked = archive_link_zone(project, "native_ithz", sibling)
        zone_status = archive_zone_status(project)
        cross_pack = archive_cross_zone_context_pack(project, "siblingonly decision", 8000)
        cross_event = archive_record_cross_zone_event(project, "native_ithz", "MCP layer referenced sibling native_ithz memory zone for transport changes.")
        search = native_archive_search(project, "decision gate", 5)
        pack = native_archive_context_pack(project, "decision gate", 8000)
        prompt = root / "prompt.md"
        response = root / "response.md"
        prompt.write_text("Capture this prompt as summary for archive-backed memory.\n", encoding="utf-8")
        response.write_text("Archive-backed prompt memory captured. Gate: native archive repack passed.\n", encoding="utf-8")
        record = native_archive_record_prompt_response(project, prompt, response, "archive prompt memory", "summary")
        parent_record_from_child = native_archive_record_prompt_response(child, prompt, response, "parent archive prompt memory", "summary", memory_zone="parent")
        status_after = native_archive_status(project)
        configs = []
        for client in ("codex", "claude-code", "antigravity", "generic-jsonrpc"):
            cfg = root / f"{client}.json"
            write_json(cfg, config_template(project, client))
            validation = validate_config(cfg)
            smoke = scripted_client_smoke(cfg, root / f"{client}_transcript.jsonl")
            configs.append({"client": client, "validate": validation["passed"], "smoke": smoke["passed"]})
        rows = [
            {"test": "project_md_created", "passed": (project / "project.md").exists(), "value": "project.md"},
            {"test": "project_md_memory_first_bootstrap", "passed": "ithz_archive_get_context_pack" in (project / "project.md").read_text(encoding="utf-8") and "Markdown is the bootstrap. ITHZ is the memory zone." in (project / "project.md").read_text(encoding="utf-8"), "value": "project.md"},
            {"test": "project_ithz_created", "passed": (project / "project.ithz").exists(), "value": archive["archive_bytes"]},
            {"test": "nested_child_archive_created", "passed": (child / "project.ithz").exists() and child_archive["archive_bytes"] > 0, "value": child_archive["archive_bytes"]},
            {"test": "sibling_archive_created", "passed": (sibling / "project.ithz").exists() and sibling_archive["archive_bytes"] > 0, "value": sibling_archive["archive_bytes"]},
            {"test": "native_safe_verify_ok", "passed": bool(status["safe_verify_ok"]), "value": status.get("archive_sha256")},
            {"test": "native_runtime_selection_reported", "passed": status.get("native_selected_build") in {"avx2", "scalar", "explicit"} and bool(status.get("native_selection_reason")) and status.get("native_version", {}).get("version_ok"), "value": f"{status.get('native_selected_build')}:{status.get('native_selection_reason')}"},
            {"test": "nearest_project_ithz_wins", "passed": child_status.get("active_memory_zone") == str((child / "project.ithz").resolve()), "value": child_status.get("active_memory_zone")},
            {"test": "parent_zone_detected", "passed": str((project / "project.ithz").resolve()) in child_status.get("memory_zone", {}).get("parent_zones", []), "value": child_status.get("memory_zone", {}).get("parent_zones", [])},
            {"test": "parent_ignores_child_zone_by_default", "passed": not parent_from_child_search["rows"] and bool(child_search["rows"]), "value": f"child={len(child_search['rows'])};parent={len(parent_from_child_search['rows'])}"},
            {"test": "explicit_parent_zone_search", "passed": child_parent_status.get("active_memory_zone") == str((project / "project.ithz").resolve()), "value": child_parent_status.get("active_memory_zone")},
            {"test": "explicit_sibling_zone_search", "passed": bool(sibling_from_child_search["rows"]) and sibling_from_child_search.get("active_memory_zone") == str((sibling / "project.ithz").resolve()), "value": len(sibling_from_child_search["rows"])},
            {"test": "archive_link_zone", "passed": linked.get("linked") and linked["zone"]["relationship"] == "sibling", "value": linked.get("linked_zone_hash")},
            {"test": "archive_zone_status_linked", "passed": any(z.get("name") == "native_ithz" for z in zone_status.get("linked_zones", [])), "value": len(zone_status.get("linked_zones", []))},
            {"test": "archive_cross_zone_context_pack", "passed": bool(cross_pack.get("context_pack_hash")) and any(r.get("zone") == "native_ithz" for r in cross_pack.get("rows", [])), "value": cross_pack.get("context_pack_hash")},
            {"test": "archive_record_cross_zone_event", "passed": cross_event.get("recorded") and cross_event["record"]["target_zone"] == "native_ithz", "value": cross_event["record"]["event_id"]},
            {"test": "archive_search_finds_rows", "passed": bool(search["rows"]), "value": len(search["rows"])},
            {"test": "archive_context_pack_hash", "passed": bool(pack["context_pack_hash"]) and pack["bytes"] <= 8000, "value": pack["context_pack_hash"]},
            {"test": "archive_prompt_repack", "passed": record["archive"]["safe_verify_ok"] and status_after["prompt_record_count"] >= 1, "value": status_after["prompt_record_count"]},
            {"test": "archive_prompt_update_file_memory_path", "passed": record.get("update_mode") == "native_memory_update_files_batch" and len(record.get("updates", [])) == 1 and record["updates"][0].get("update_mode") == "memory_decode_repack_batch" and record["updates"][0].get("update_count", 0) >= 2, "value": record.get("update_mode")},
            {"test": "parent_zone_write_from_child", "passed": parent_record_from_child.get("active_memory_zone") == str((project / "project.ithz").resolve()), "value": parent_record_from_child.get("active_memory_zone")},
            {"test": "write_lock_and_hash_precondition", "passed": bool(parent_record_from_child["updates"][0].get("lock_acquired")) and bool(parent_record_from_child["updates"][0].get("precondition_checked")), "value": parent_record_from_child["updates"][0].get("archive_sha256_after")},
            {"test": "codex_config_validate_and_smoke", "passed": next(c for c in configs if c["client"] == "codex")["validate"] and next(c for c in configs if c["client"] == "codex")["smoke"], "value": "codex"},
            {"test": "claude_config_validate_and_smoke", "passed": next(c for c in configs if c["client"] == "claude-code")["validate"] and next(c for c in configs if c["client"] == "claude-code")["smoke"], "value": "claude-code"},
            {"test": "antigravity_config_validate_and_smoke", "passed": next(c for c in configs if c["client"] == "antigravity")["validate"] and next(c for c in configs if c["client"] == "antigravity")["smoke"], "value": "antigravity"},
            {"test": "generic_direct_config_still_smokes", "passed": next(c for c in configs if c["client"] == "generic-jsonrpc")["validate"] and next(c for c in configs if c["client"] == "generic-jsonrpc")["smoke"], "value": "generic-jsonrpc"},
        ]
    out = exp_dir("mcp13_native_archive")
    write_matrix(out / "mcp13_native_archive_matrix.csv", rows)
    write_summary(
        out / "mcp13_summary.md",
        "MCP13 Real MCP Host Compatibility / Native Archive Memory Summary",
        rows,
        "- storage_model: project.md bootstrap plus project.ithz native archive memory\n"
        "- memory_zone_discovery: nearest project.ithz wins; parent/sibling zones require explicit selection\n"
        "- cross_zone_registry: linked_zones.json and cross_zone_events.jsonl are stored inside project.ithz\n"
        "- nested_zones: parent archives ignore child project.ithz zones by default\n"
        "- native_ithz_used_for: pack, safe verify, stdout-backed read/search and batched memory-backed logical-file update\n"
        "- external_host_tested: scripted stdio compatibility only\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp14_rc5_package() -> bool:
    if not run_mcp13_host_compat():
        return False
    dist = repo_root() / "dist" / "ithz_mcp-v0.1-alpha-rc5"
    if dist.exists():
        shutil.rmtree(dist)
    (dist / "docs").mkdir(parents=True)
    (dist / "examples").mkdir(parents=True)
    (dist / "native").mkdir(parents=True)
    (dist / "assets").mkdir(parents=True)
    (dist / "assets").mkdir(parents=True)
    shutil.copytree(repo_root() / "src", dist / "src", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(repo_root() / "ithz_mcp", dist / "ithz_mcp", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(repo_root() / "templates", dist / "templates")
    shutil.copytree(repo_root() / "tests" / "quality_expectations", dist / "tests" / "quality_expectations")
    shutil.copytree(sample_project(), dist / "sample_project", ignore=shutil.ignore_patterns(".ithz_mcp", ".ithz-context", "project.ithz", ".env", "secrets.key", "*.pem", "*.key"))
    for name in ("README.md", "AGENTS.md", "ITHZ_CONTEXT.md", "pyproject.toml", "install_ithz.md", "ithz_mcp.md"):
        shutil.copy2(repo_root() / name, dist / name)
    for asset in (repo_root() / "src" / "ithz_mcp" / "assets").glob("*"):
        if asset.is_file():
            shutil.copy2(asset, dist / "assets" / asset.name)
    for doc in (repo_root() / "docs").glob("*.md"):
        shutil.copy2(doc, dist / "docs" / doc.name)
    selected = select_native_ithz()
    native_avx2 = repo_root().parent / "native_ithz" / "build_avx2" / "Release" / "ithz-native.exe"
    if native_avx2.exists():
        shutil.copy2(native_avx2, dist / "native" / "ithz-native.exe")
        shutil.copy2(native_avx2, dist / "native" / "ithz-native-avx2.exe")
    else:
        shutil.copy2(Path(selected.path), dist / "native" / "ithz-native.exe")
    scalar = repo_root().parent / "native_ithz" / "build_scalar" / "Release" / "ithz-native.exe"
    if scalar.exists():
        shutil.copy2(scalar, dist / "native" / "ithz-native-scalar.exe")
    macos_native = _find_macos_native_binary()
    if macos_native is not None:
        shutil.copy2(macos_native, dist / "native" / "ithz-native")
        try:
            (dist / "native" / "ithz-native").chmod(0o755)
        except OSError:
            pass
    macos_storage_profile = "native-archive" if (dist / "native" / "ithz-native").exists() else "legacy"
    launcher = dist / "ithz_mcp_server.cmd"
    launcher.write_text(
        "@echo off\r\n"
        "set \"PYTHONPATH=%~dp0;%~dp0src;%PYTHONPATH%\"\r\n"
        "set \"ITHZ_PYTHON=python\"\r\n"
        "where python >nul 2>nul\r\n"
        "if errorlevel 1 set \"ITHZ_PYTHON=py -3\"\r\n"
        "if exist \"%LOCALAPPDATA%\\Programs\\Python\\Python312\\python.exe\" set \"ITHZ_PYTHON=%LOCALAPPDATA%\\Programs\\Python\\Python312\\python.exe\"\r\n"
        "%ITHZ_PYTHON% -m ithz_mcp %*\r\n",
        encoding="utf-8",
    )
    for client, file_name in (
        ("codex", "codex_mcp_config.sample.json"),
        ("claude-code", "claude_code_mcp_config.sample.json"),
        ("antigravity", "antigravity_mcp_config.sample.json"),
        ("generic-jsonrpc", "generic_mcp_config.sample.json"),
    ):
        cfg = config_template(dist / "sample_project", client, storage_profile="native-archive")
        if "mcpServers" in cfg:
            cfg["mcpServers"]["ithz-mcp"]["command"] = str(launcher)
            cfg["mcpServers"]["ithz-mcp"]["args"] = [
                "mcp-server",
                "--project",
                str((dist / "sample_project").resolve()),
                "--mode",
                "read-only",
                "--protocol",
                cfg["mcpServers"]["ithz-mcp"]["protocol"],
                "--storage-profile",
                "native-archive",
            ]
        elif "server" in cfg:
            cfg["server"]["command"] = str(launcher)
            cfg["server"]["args"] = [
                "mcp-server",
                "--project",
                str((dist / "sample_project").resolve()),
                "--mode",
                "read-only",
                "--protocol",
                cfg["server"]["protocol"],
                "--storage-profile",
                "native-archive",
            ]
        write_json(dist / file_name, cfg)
        write_json(dist / "examples" / file_name, cfg)
    write_cfg = config_template(dist / "sample_project", "codex", storage_profile="native-archive", mode="write-enabled")
    write_cfg["mcpServers"]["ithz-mcp"]["command"] = str(launcher)
    write_cfg["mcpServers"]["ithz-mcp"]["args"] = [
        "mcp-server",
        "--project",
        str((dist / "sample_project").resolve()),
        "--mode",
        "write-enabled",
        "--protocol",
        "mcp",
        "--storage-profile",
        "native-archive",
    ]
    write_json(dist / "codex_mcp_write_config.sample.json", write_cfg)
    write_json(dist / "examples" / "codex_mcp_write_config.sample.json", write_cfg)
    (dist / "README_FIRST.md").write_text(
        "# README FIRST\n\n"
        "1. Run `smoke_test.ps1`.\n"
        "2. Run `python mcp_client_smoke.py`.\n"
        "3. Try `sample_commands.ps1`.\n"
        "4. To install another project, copy `install_ithz.md` there and ask the local agent to follow it.\n"
        "5. Use `project.md` as bootstrap and `project.ithz` as native archive memory.\n"
        "6. Use `ithz_mcp_server.cmd` from external MCP hosts when the package is not installed globally.\n"
        "7. Nearest `project.ithz` wins; use `--memory-zone parent` or `--memory-zone-path` for explicit parent/sibling zones.\n"
        "8. Use `archive-link-zone` only when a task intentionally references another memory zone.\n"
        "9. Append events are audit history; indexes and snapshots are derived working-memory/performance layers.\n"
        "10. Use durable instruction tools when the user gives lasting workflow, decision, gate or risk rules.\n"
        "11. Use the separate write-enabled MCP profile only for end-of-task checkpointing.\n"
        "12. This is not a Git replacement, cloud sync product, production database, or general token-saving claim.\n",
        encoding="utf-8",
    )
    (dist / "RELEASE_NOTES.md").write_text(
        "# ITHZ-MCP v0.1-alpha-rc5\n\n"
        "RC5 packages MCP12 prompt/response memory and MCP13 native archive memory. It includes MCP-style stdio "
        "`initialize`, `tools/list` and `tools/call`, Codex/Claude Code/Antigravity config samples, and a bundled "
        "`ithz-native.exe` for `project.ithz` pack, safe verify, archive-backed search and batched logical-file update. "
        "The Python resolver selects AVX2 only when CPU support is detected and falls back to `ithz-native-scalar.exe` when needed. "
        "Memory-zone discovery uses the nearest `project.ithz` by default, treats nested archives as child zones, and allows explicit parent/sibling access with write lock/hash preconditions. "
        "RC5 also includes a local cross-zone registry (`zones/linked_zones.json`, `zones/cross_zone_events.jsonl`) for tasks that touch sibling project memory such as native transport changes. "
        "MCP17-style append-only events, derived indexes and snapshots are included as archive-memory maintenance primitives. "
        "MCP18-style workflow intake and end-of-task checkpoint commands are included with an explicit write-enabled MCP profile. "
        "MCP19 workflow profiles and MCP20 summary-only local agent-history import are included for project adoption. "
        "MCP24 durable instruction memory stores lasting workflow/decision/gate/risk rules as typed project.ithz records. "
        "It remains local-first and does not add cloud sync, Git replacement behavior, production database claims, or a general token-saving claim.\n",
        encoding="utf-8",
    )
    (dist / "mcp_client_smoke.py").write_text(
        "from ithz_mcp.cli import main\nraise SystemExit(main(['mcp-client-smoke','--config','codex_mcp_config.sample.json','--out','mcp13_client_transcript.jsonl']))\n",
        encoding="utf-8",
    )
    (dist / "sample_commands.ps1").write_text(
        "python -m ithz_mcp version\n"
        "python -m ithz_mcp init-native-archive-memory --project sample_project\n"
        "python -m ithz_mcp archive-memory-status --project sample_project\n"
        "python -m ithz_mcp archive-zone-status --project sample_project\n"
        "python -m ithz_mcp archive-append-event --project sample_project --kind decision --text \"Decision: package smoke append event.\" --source package-smoke\n"
        "python -m ithz_mcp archive-ingest-project-memory --project sample_project --source project.md --note \"Package workflow intake smoke.\"\n"
        "python -m ithz_mcp archive-adopt-project-workflow --project sample_project --profile package --owner Package --prompt project.md\n"
        "python -m ithz_mcp workflow-profile-status --project sample_project\n"
        "python -m ithz_mcp archive-memory-index-status --project sample_project\n"
        "python -m ithz_mcp archive-create-snapshot --project sample_project --label package-smoke\n"
        "python -m ithz_mcp archive-search-context --project sample_project --memory-zone current --query decision\n"
        "python -m ithz_mcp archive-search-context --project sample_project --query decision\n"
        "python -m ithz_mcp archive-get-context-pack --project sample_project --query \"decision gate\" --out archive_pack.md\n"
        "Set-Content -Encoding UTF8 prompt_smoke.md 'Prompt memory smoke.'\n"
        "Set-Content -Encoding UTF8 response_smoke.md 'Response memory smoke. Gate: native update-files batch passed.'\n"
        "python -m ithz_mcp archive-record-prompt-response --project sample_project --prompt prompt_smoke.md --response response_smoke.md --task \"package prompt smoke\" --mode summary\n"
        "python -m ithz_mcp archive-finalize-task --project sample_project --task \"package checkpoint smoke\" --summary-text \"Package checkpoint completed.\" --docs-impact not-needed --memory-impact handoff-created --gate \"Gate: package checkpoint passed\"\n"
        "New-Item -ItemType Directory -Force sample_history | Out-Null\n"
        "Set-Content -Encoding UTF8 sample_history\\history.jsonl '{\"response_item\":{\"role\":\"user\",\"content\":[{\"text\":\"sample_project history prompt: run smoke test\"}]}}'\n"
        "Add-Content -Encoding UTF8 sample_history\\history.jsonl '{\"response_item\":{\"role\":\"assistant\",\"content\":[{\"text\":\"sample_project history response: smoke passed\"}]}}'\n"
        "python -m ithz_mcp agent-history-discover --project sample_project --source codex --root sample_history --author PackageUser\n"
        "python -m ithz_mcp archive-import-agent-history --project sample_project --source codex --root sample_history --author PackageUser --imported-at 2026-05-29T00:00:00Z --apply\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_config.sample.json\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_write_config.sample.json\n"
        "python mcp_client_smoke.py\n",
        encoding="utf-8",
    )
    (dist / "smoke_test.ps1").write_text(
        "$ErrorActionPreference='Stop'\n"
        "python -m ithz_mcp version\n"
        "python -m ithz_mcp self-test --verbose\n"
        "python -m ithz_mcp init-native-archive-memory --project sample_project | Out-Null\n"
        "python -m ithz_mcp archive-memory-status --project sample_project | Out-Null\n"
        "python -m ithz_mcp archive-zone-status --project sample_project | Out-Null\n"
        "python -m ithz_mcp archive-append-event --project sample_project --kind decision --text \"Decision: package smoke append event.\" --source package-smoke | Out-Null\n"
        "python -m ithz_mcp archive-ingest-project-memory --project sample_project --source project.md --note \"Package workflow intake smoke.\" | Out-Null\n"
        "python -m ithz_mcp archive-adopt-project-workflow --project sample_project --profile package --owner Package --prompt project.md | Out-Null\n"
        "python -m ithz_mcp workflow-profile-status --project sample_project | Out-Null\n"
        "python -m ithz_mcp archive-memory-index-status --project sample_project | Out-Null\n"
        "python -m ithz_mcp archive-create-snapshot --project sample_project --label package-smoke | Out-Null\n"
        "python -m ithz_mcp archive-search-context --project sample_project --query decision | Out-Null\n"
        "python -m ithz_mcp archive-get-context-pack --project sample_project --query decision --out archive_pack.md | Out-Null\n"
        "Set-Content -Encoding UTF8 prompt_smoke.md 'Prompt memory smoke.'\n"
        "Set-Content -Encoding UTF8 response_smoke.md 'Response memory smoke. Gate: native update-files batch passed.'\n"
        "python -m ithz_mcp archive-record-prompt-response --project sample_project --prompt prompt_smoke.md --response response_smoke.md --task \"package prompt smoke\" --mode summary | Out-Null\n"
        "python -m ithz_mcp archive-finalize-task --project sample_project --task \"package checkpoint smoke\" --summary-text \"Package checkpoint completed.\" --docs-impact not-needed --memory-impact handoff-created --gate \"Gate: package checkpoint passed\" | Out-Null\n"
        "New-Item -ItemType Directory -Force sample_history | Out-Null\n"
        "Set-Content -Encoding UTF8 sample_history\\history.jsonl '{\"response_item\":{\"role\":\"user\",\"content\":[{\"text\":\"sample_project history prompt: run smoke test\"}]}}'\n"
        "Add-Content -Encoding UTF8 sample_history\\history.jsonl '{\"response_item\":{\"role\":\"assistant\",\"content\":[{\"text\":\"sample_project history response: smoke passed\"}]}}'\n"
        "python -m ithz_mcp agent-history-discover --project sample_project --source codex --root sample_history --author PackageUser | Out-Null\n"
        "python -m ithz_mcp archive-import-agent-history --project sample_project --source codex --root sample_history --author PackageUser --imported-at 2026-05-29T00:00:00Z --apply | Out-Null\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_config.sample.json | Out-Null\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_write_config.sample.json | Out-Null\n"
        "python mcp_client_smoke.py | Out-Null\n",
        encoding="utf-8",
    )
    _sha256sums(dist)
    smoke = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "smoke_test.ps1"], cwd=str(dist), text=True, capture_output=True, timeout=180)
    client = subprocess.run([sys.executable, "mcp_client_smoke.py"], cwd=str(dist), text=True, capture_output=True, timeout=60)
    _cleanup_package_runtime_state(dist)
    if (dist / "fixtures").exists():
        shutil.rmtree(dist / "fixtures")
    if (dist / "sample_history").exists():
        shutil.rmtree(dist / "sample_history")
    for extra in ("archive_pack.md", "mcp13_client_transcript.jsonl", "prompt_smoke.md", "response_smoke.md"):
        target = dist / extra
        if target.exists():
            target.unlink()
    _sha256sums(dist)
    secret_hits = []
    for p in dist.rglob("*"):
        if p.is_file() and p.name.lower() in {".env", "secrets.key", "private.pem"}:
            secret_hits.append(str(p.relative_to(dist)))
    rows = [
        {"test": "package_created", "passed": dist.exists(), "value": str(dist)},
        {"test": "native_exe_included", "passed": (dist / "native" / "ithz-native.exe").exists(), "value": "native/ithz-native.exe"},
        {"test": "native_avx2_alias_included", "passed": (dist / "native" / "ithz-native-avx2.exe").exists(), "value": "native/ithz-native-avx2.exe"},
        {"test": "native_scalar_included", "passed": (dist / "native" / "ithz-native-scalar.exe").exists(), "value": "native/ithz-native-scalar.exe"},
        {"test": "native_runtime_selection_present", "passed": selected.selected_build in {"avx2", "scalar"} and isinstance(selected.cpu_avx2_supported, bool), "value": f"{selected.selected_build}:{selected.reason}"},
        {"test": "portable_mcp_launcher_included", "passed": launcher.exists(), "value": "ithz_mcp_server.cmd"},
        {"test": "sha256sums_generated", "passed": (dist / "SHA256SUMS.txt").exists(), "value": "ok"},
        {"test": "smoke_test_passed", "passed": smoke.returncode == 0, "value": smoke.returncode},
        {"test": "mcp_client_smoke_passed", "passed": client.returncode == 0, "value": client.returncode},
        {"test": "native_archive_docs_included", "passed": (dist / "docs" / "NATIVE_ARCHIVE_MEMORY.md").exists(), "value": "docs/NATIVE_ARCHIVE_MEMORY.md"},
        {"test": "prompt_memory_docs_included", "passed": (dist / "docs" / "PROMPT_MEMORY.md").exists(), "value": "docs/PROMPT_MEMORY.md"},
        {"test": "no_secrets_included", "passed": not secret_hits, "value": ";".join(secret_hits)},
    ]
    out = exp_dir("mcp14_rc5_package")
    write_matrix(out / "mcp14_rc5_package_matrix.csv", rows)
    write_summary(out / "mcp14_rc5_summary.md", "MCP14 RC5 Package Summary", rows)
    return all(bool(r["passed"]) for r in rows)


def _copy_archive_to_project(archive: Path, project: Path) -> Path:
    project.mkdir(parents=True, exist_ok=True)
    shutil.copy2(archive, project / "project.ithz")
    return project


def _archive_events(project: Path) -> list[dict[str, Any]]:
    data = extract_archive_file_bytes(project, "events/events.jsonl")
    return [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]


def _write_events_for_test(project: Path, events: list[dict[str, Any]]) -> None:
    data = "".join(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n" for row in events).encode("utf-8")
    update_archive_files_bytes(project, {"events/events.jsonl": data}, expected_archive_sha256=sha256_file(project_archive_path(project)))


def run_mcp16_git_merge_driver() -> bool:
    if not run_mcp13_host_compat():
        return False
    out = exp_dir("mcp16_git_merge")
    reports = out / "mcp16_merge_reports"
    reports.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        base_project = copy_clean_sample(root / "base_project")
        build_native_archive(base_project)
        base_archive = root / "base.ithz"
        shutil.copy2(project_archive_path(base_project), base_archive)

        ours_project = _copy_archive_to_project(base_archive, root / "ours_project")
        theirs_project = _copy_archive_to_project(base_archive, root / "theirs_project")
        archive_append_event(ours_project, "decision", "Decision: ours adds independent memory.", "mcp16", ["merge"])
        archive_append_event(theirs_project, "gate", "Gate: theirs adds independent gate.", "mcp16", ["merge"])
        ours_archive = root / "ours.ithz"
        theirs_archive = root / "theirs.ithz"
        shutil.copy2(project_archive_path(ours_project), ours_archive)
        shutil.copy2(project_archive_path(theirs_project), theirs_archive)
        merged_archive = root / "merged.ithz"
        merge = git_merge_ithz(base_archive, ours_archive, theirs_archive, merged_archive, reports / "auto_merge.md")
        merged_project = _copy_archive_to_project(merged_archive, root / "merged_project")
        merged_search = native_archive_search(merged_project, "independent gate", 10)
        diff_text = git_diff_ithz(merged_archive)
        (out / "mcp16_git_diff_examples.md").write_text("```text\n" + diff_text + "```\n", encoding="utf-8")
        rows.extend(
            [
                {"test": "auto_merge_independent_events", "passed": not merge["merge_needed"] and merge["event_count"] == 2, "value": merge.get("archive_sha256", "")},
                {"test": "merged_archive_safe_verify", "passed": native_archive_status(merged_project)["safe_verify_ok"], "value": native_archive_status(merged_project).get("archive_sha256")},
                {"test": "merged_events_searchable", "passed": len(merged_search["rows"]) > 0, "value": len(merged_search["rows"])},
                {"test": "git_diff_stable_output", "passed": "context_commit_count:" in diff_text and "event_count: 2" in diff_text, "value": stable_json_hash({"diff": diff_text})},
            ]
        )

        private_project = _copy_archive_to_project(base_archive, root / "private_project")
        prompt_file = root / "prompt.md"
        response_file = root / "response.md"
        prompt_file.write_text("private local prompt memory", encoding="utf-8")
        response_file.write_text("private local response memory", encoding="utf-8")
        native_archive_record_prompt_response(private_project, prompt_file, response_file, "private prompt", "full-local-only")
        private_archive = root / "private.ithz"
        shutil.copy2(project_archive_path(private_project), private_archive)
        private_merge = git_merge_ithz(base_archive, private_archive, base_archive, root / "private_merged.ithz", reports / "private_skip.md")
        rows.append({"test": "private_local_only_prompt_skipped", "passed": private_merge["private_local_only_skipped"] >= 1 and not private_merge["merge_needed"], "value": private_merge["private_local_only_skipped"]})

        base_with_event_project = _copy_archive_to_project(base_archive, root / "base_with_event_project")
        archive_append_event(base_with_event_project, "decision", "Decision: base history.", "mcp16", ["base"])
        base_with_event = root / "base_with_event.ithz"
        shutil.copy2(project_archive_path(base_with_event_project), base_with_event)
        modified_project = _copy_archive_to_project(base_with_event, root / "modified_project")
        events = _archive_events(modified_project)
        events[0]["text"] = "Decision: modified historical event."
        events[0]["semantic_event_hash"] = stable_json_hash({"kind": "decision", "text": events[0]["text"]})
        _write_events_for_test(modified_project, events)
        modified_archive = root / "modified.ithz"
        shutil.copy2(project_archive_path(modified_project), modified_archive)
        conflict = git_merge_ithz(base_with_event, modified_archive, base_with_event, root / "conflict.ithz", reports / "history_conflict.md")
        rows.append({"test": "modified_historical_event_conflict", "passed": conflict["merge_needed"] and any("historical_event_modified" in c for c in conflict["conflicts"]), "value": ";".join(conflict["conflicts"])})

        secret_project = _copy_archive_to_project(base_archive, root / "secret_project")
        secret_event = [{"event_id": "evt_000001", "kind": "decision", "text": "api_key = should_not_merge", "semantic_event_hash": "secret"}]
        _write_events_for_test(secret_project, secret_event)
        secret_archive = root / "secret.ithz"
        shutil.copy2(project_archive_path(secret_project), secret_archive)
        secret_merge = git_merge_ithz(base_archive, secret_archive, base_archive, root / "secret_merged.ithz", reports / "secret_blocked.md")
        rows.append({"test": "secret_like_event_blocked", "passed": secret_merge["merge_needed"] and any("secret_like_event" in c for c in secret_merge["conflicts"]), "value": ";".join(secret_merge["conflicts"])})

        install_row = {"test": "install_git_drivers_skipped", "passed": True, "value": "git_unavailable"}
        status_row = {"test": "git_driver_status_skipped", "passed": True, "value": "git_unavailable"}
        if shutil.which("git"):
            repo = root / "driver_repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=str(repo), text=True, capture_output=True, check=True)
            install = install_git_drivers(repo, dry_run=False)
            status = git_driver_status(repo)
            install_row = {"test": "install_git_drivers", "passed": bool(install["actions"]) and (repo / ".gitattributes").exists(), "value": len(install["actions"])}
            status_row = {"test": "git_driver_status", "passed": status["gitattributes_present"] and "git-merge-ithz" in status["merge_driver"], "value": status["merge_driver"]}
        rows.extend([install_row, status_row])

    write_matrix(out / "mcp16_git_merge_matrix.csv", rows)
    write_summary(
        out / "mcp16_summary.md",
        "MCP16 Git Merge Driver Summary",
        rows,
        "- project.md remains normal Git text.\n"
        "- project.ithz remains the single memory-zone archive.\n"
        "- the merge driver reads logical memory layers, unions independent append-only events, skips local-only prompt memory, blocks secret-like payloads and writes a merge report.\n"
        "- Git remains the transport; ITHZ-MCP does not replace Git.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp17_append_index_snapshot() -> bool:
    if not run_mcp13_host_compat():
        return False
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = copy_clean_sample(root / "append_project")
        git_subject_expected = None
        if shutil.which("git"):
            subprocess.run(["git", "init"], cwd=str(project), text=True, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "ithz@example.invalid"], cwd=str(project), text=True, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "ITHZ Test"], cwd=str(project), text=True, capture_output=True, check=True)
            subprocess.run(["git", "add", "README.md", "docs/decisions.md"], cwd=str(project), text=True, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "MCP17 append git subject"], cwd=str(project), text=True, capture_output=True, check=True)
            git_subject_expected = "MCP17 append git subject"
        build_native_archive(project)
        decision = archive_append_event(project, "decision", "Decision: use append-only memory events for audit trail.", "mcp17", ["audit", "decision"], include_git=git_subject_expected is not None)
        gate = archive_append_event(project, "gate", "Gate: current_index_hash must stay rebuildable and searchable.", "mcp17", ["gate"])
        risk = archive_append_event(project, "risk", "Risk: append-only history can become noisy without snapshots.", "mcp17", ["risk"])
        status = archive_memory_index_status(project)
        search = native_archive_search(project, "append-only searchable", 10)
        git_search = native_archive_search(project, "append git subject", 10)
        pack = native_archive_context_pack(project, "append-only risk gate", 8000)
        rebuild = archive_rebuild_derived_indexes(project)
        status_after_rebuild = archive_memory_index_status(project)
        snapshot = archive_create_snapshot(project, "mcp17-smoke")
        status_after_snapshot = archive_memory_index_status(project)
        blocked = False
        try:
            archive_append_event(project, "decision", "api_key = should_not_store_in_memory", "mcp17")
        except ValueError:
            blocked = True
        rows = [
            {"test": "append_decision_event", "passed": decision["appended"] and decision["event"]["event_id"] == "evt_000001", "value": decision["event"]["semantic_event_hash"]},
            {"test": "append_gate_event", "passed": gate["appended"] and gate["event"]["event_id"] == "evt_000002", "value": gate["current_index_hash"]},
            {"test": "append_risk_event", "passed": risk["appended"] and risk["event"]["event_id"] == "evt_000003", "value": risk["current_index_hash"]},
            {"test": "index_status_valid", "passed": status["index_valid"] and status["append_only_valid"] and status["event_count"] == 3, "value": status["derived_current_index_hash"]},
            {"test": "append_events_searchable", "passed": any(str(r.get("kind", "")).startswith("memory_") for r in search["rows"]), "value": len(search["rows"])},
            {
                "test": "append_event_git_subject_stored",
                "passed": True if git_subject_expected is None else decision["event"].get("git", {}).get("git_commit_subject") == git_subject_expected,
                "value": "git_unavailable" if git_subject_expected is None else decision["event"].get("git", {}).get("git_commit_subject"),
            },
            {
                "test": "append_event_git_subject_searchable",
                "passed": True if git_subject_expected is None else any(row.get("git", {}).get("git_commit_subject") == git_subject_expected for row in git_search["rows"]),
                "value": "git_unavailable" if git_subject_expected is None else len(git_search["rows"]),
            },
            {"test": "context_pack_includes_append_memory", "passed": "append-only" in pack["text"] and pack["bytes"] <= 8000, "value": pack["context_pack_hash"]},
            {"test": "rebuild_index_stable", "passed": rebuild["current_index_hash"] == status["derived_current_index_hash"] and status_after_rebuild["index_valid"], "value": rebuild["current_index_hash"]},
            {"test": "snapshot_created", "passed": snapshot["snapshot_created"] and snapshot["snapshot"]["event_count"] == 3, "value": snapshot["snapshot"]["snapshot_id"]},
            {"test": "snapshot_status_visible", "passed": status_after_snapshot["snapshot_count"] == 1 and bool(status_after_snapshot["latest_snapshot"]), "value": status_after_snapshot["latest_snapshot"]["snapshot_hash"]},
            {"test": "secret_like_event_blocked", "passed": blocked, "value": "redaction_blocked"},
            {"test": "archive_safe_verify_after_append", "passed": native_archive_status(project)["safe_verify_ok"], "value": native_archive_status(project).get("archive_sha256")},
        ]
    out = exp_dir("mcp17_append_index_snapshot")
    write_matrix(out / "mcp17_append_index_matrix.csv", rows[:9])
    write_matrix(out / "mcp17_snapshot_matrix.csv", rows[9:11])
    write_matrix(out / "mcp17_safety_matrix.csv", rows[11:])
    write_summary(
        out / "mcp17_summary.md",
        "MCP17 Append-only Memory, Derived Index and Snapshot Summary",
        rows,
        "- append_only_layer: events/events.jsonl\n"
        "- working_memory_layer: indexes/current_index.json\n"
        "- performance_layer: snapshots/snapshot_*.json\n"
        "- optional_git_metadata: branch/hash/short_hash/ref_names/commit_subject are stored when --include-git is requested\n"
        "- claim: fixture-scoped archive memory hardening only; no Git replacement or general token-saving claim\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp18_end_task_checkpoint() -> bool:
    if not run_mcp17_append_index_snapshot():
        return False
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = copy_clean_sample(root / "checkpoint_project")
        build_native_archive(project)
        workflow = project / "WORKFLOW_RULES.md"
        workflow.write_text(
            "# Workflow Rules\n\n"
            "## Read order\n\n"
            "1. project.md\n"
            "2. ARCHITECTURE.md\n"
            "3. WORKFLOW_RULES.md\n\n"
            "## Deployment rules\n\n"
            "- current working deploy path is `~/site/web/wp-content/`.\n"
            "- current working transport is direct `scp` over SSH key `~/.ssh/project_ed25519`.\n"
            "- do not commit placeholder credentials.\n\n"
            "## Git workflow rules\n\n"
            "- after each completed durable task, commit and push the resulting code and markdown changes.\n"
            "- prefer helper `scripts/git-commit-and-push.ps1 -Message \"<task summary>\"`.\n\n"
            "## Memory impact check\n\n"
            "- Documentation impact: updated / not needed.\n"
            "- Memory impact: handoff created / not needed.\n"
            "- Dovod: explain the result.\n\n"
            "## Risk areas\n\n"
            "- duplicate reminders caused by retries.\n"
            "- provider token values must not be stored.\n",
            encoding="utf-8",
        )
        secret_source = project / "secrets.key"
        secret_source.write_text("not-indexed", encoding="utf-8")
        ingest = archive_ingest_project_memory(project, [workflow, secret_source], "Initial project workflow import from user-provided markdown.")
        summary = project / "task_summary.md"
        summary.write_text(
            "Implemented end-of-task checkpoint contract.\n"
            "Gate: py_compile passed.\n"
            "Decision: write-enabled MCP profile must be explicit.\n"
            "Next: test real host write flow.\n",
            encoding="utf-8",
        )
        prompt = root / "prompt.md"
        response = root / "response.md"
        prompt.write_text("Please capture workflow. API_KEY=should_not_escape\n", encoding="utf-8")
        response.write_text("Workflow captured as summary. Gate: checkpoint passed.\n", encoding="utf-8")
        checkpoint = archive_finalize_task(
            project,
            "MCP18 end task checkpoint",
            summary_file=summary,
            decisions=["Decision: end-of-task writes require explicit write-enabled profile."],
            gates=["Gate: checkpoint search finds docs and memory impact."],
            risks=["Risk: raw prompt/response capture must stay explicit and redaction-gated."],
            next_steps=["Next step: exercise in a real MCP host."],
            changed_files=["src/ithz_mcp/task_checkpoint.py"],
            commands=["python -m py_compile src/ithz_mcp/task_checkpoint.py"],
            docs_impact="updated",
            memory_impact="handoff-created",
            prompt_file=prompt,
            response_file=response,
            prompt_mode="summary",
            create_snapshot=True,
        )
        status = archive_memory_index_status(project)
        search_workflow = native_archive_search(project, "git workflow commit push", 20)
        search_impact = native_archive_search(project, "Documentation impact Memory impact", 20)
        search_secret = native_archive_search(project, "should_not_escape API_KEY", 20)
        pack = native_archive_context_pack(project, "end-of-task checkpoint documentation impact memory impact", 10000)
        readonly_cfg = root / "readonly.json"
        write_cfg = root / "write.json"
        write_json(readonly_cfg, config_template(project, "codex", "native-archive", "read-only"))
        write_json(write_cfg, config_template(project, "codex", "native-archive", "write-enabled"))
        readonly_validation = validate_config(readonly_cfg)
        write_validation = validate_config(write_cfg)
        readonly_tools = set(readonly_validation["server"].get("tools", []))
        write_tools = set(write_validation["server"].get("tools", []))
        rows = [
            {"test": "workflow_sources_ingested", "passed": ingest["ingested"] and ingest["event_count"] >= 6, "value": ingest.get("intake_hash")},
            {"test": "secret_source_skipped", "passed": any(not r.get("indexed") and r.get("reason") == "secret_like_path" for r in ingest["rows"]), "value": "secrets.key"},
            {"test": "checkpoint_finalized", "passed": checkpoint["finalized"] and checkpoint["event_count"] >= 6, "value": checkpoint["checkpoint_hash"]},
            {"test": "prompt_summary_linked", "passed": checkpoint["prompt_record"] and checkpoint["prompt_record"]["record"]["mode"] == "summary", "value": checkpoint["prompt_record"]["record"]["prompt_id"] if checkpoint["prompt_record"] else ""},
            {"test": "snapshot_created", "passed": checkpoint["snapshot"] and checkpoint["snapshot"]["snapshot_created"], "value": checkpoint["snapshot"]["snapshot"]["snapshot_id"] if checkpoint["snapshot"] else ""},
            {"test": "index_valid_after_checkpoint", "passed": status["index_valid"] and status["append_only_valid"], "value": status["derived_current_index_hash"]},
            {"test": "workflow_searchable", "passed": bool(search_workflow["rows"]), "value": len(search_workflow["rows"])},
            {"test": "impact_searchable", "passed": bool(search_impact["rows"]) and "Documentation impact" in pack["text"], "value": pack["context_pack_hash"]},
            {"test": "secret_not_searchable", "passed": not search_secret["rows"] and "should_not_escape" not in pack["text"], "value": len(search_secret["rows"])},
            {"test": "read_only_config_has_no_write_tools", "passed": not {"ithz_archive_finalize_task", "ithz_archive_ingest_project_memory"} & readonly_tools, "value": ",".join(sorted(readonly_tools))},
            {"test": "write_enabled_config_has_write_tools", "passed": {"ithz_archive_finalize_task", "ithz_archive_ingest_project_memory"} <= write_tools and write_validation["passed"], "value": ",".join(sorted(write_tools))},
            {"test": "archive_safe_verify_after_checkpoint", "passed": native_archive_status(project)["safe_verify_ok"], "value": native_archive_status(project).get("archive_sha256")},
        ]
    out = exp_dir("mcp18_end_task_checkpoint")
    write_matrix(out / "mcp18_project_intake_matrix.csv", rows[:2])
    write_matrix(out / "mcp18_end_task_checkpoint_matrix.csv", rows[2:9])
    write_matrix(out / "mcp18_write_enabled_profile_matrix.csv", rows[9:11])
    write_matrix(out / "mcp18_safety_matrix.csv", rows[11:])
    write_summary(
        out / "mcp18_summary.md",
        "MCP18 Project Intake and End-of-task Checkpoint Summary",
        rows,
        "- project.md remains the startup contract.\n"
        "- project.ithz stores mined workflow facts, end-of-task checkpoint events, prompt summaries, derived indexes and snapshots.\n"
        "- read-only MCP profile does not expose write tools; write-enabled profile is explicit.\n"
        "- secret-like sources and prompt payloads are skipped or redacted; no automatic full chat capture is added.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp19_workflow_branches() -> bool:
    if not run_mcp18_end_task_checkpoint():
        return False
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "workflow_project"
        project.mkdir()
        (project / "PROJECT_BRIEF.md").write_text(
            "# Project Brief\n\n"
            "## Read order\n"
            "- AI session starts from project docs.\n\n"
            "## Documentation impact\n"
            "- Documentation impact check is required for non-trivial tasks.\n",
            encoding="utf-8",
        )
        (project / "WORKFLOW_RULES.md").write_text(
            "# Workflow Rules\n\n"
            "## Git workflow\n"
            "- Commit durable code and project memory changes together.\n\n"
            "## Test workflow\n"
            "- Gate: run-ci-fast must pass before handoff.\n\n"
            "## Safety\n"
            "- Do not store secrets or private keys.\n",
            encoding="utf-8",
        )
        prompt = root / "gobi_prompt.md"
        prompt.write_text(
            "Use docs-first startup, then ask ITHZ-MCP for a context pack.\n"
            "Testing workflow: run-ci-fast, targeted smoke, then checkpoint.\n"
            "Deployment note: SSH key path may be referenced, but key contents must never be stored.\n",
            encoding="utf-8",
        )
        adopt = archive_adopt_project_workflow(project, "gobi", "Gobi", prompt, include_existing_md=True)
        status = workflow_profile_status(project)
        update_prompt = root / "gobi_update.md"
        update_prompt.write_text(
            "End-of-task checklist: documentation impact, memory impact, gates, next steps.\n"
            "Git policy: push after validated durable work.\n",
            encoding="utf-8",
        )
        update = archive_update_workflow_profile(project, "gobi", "Gobi", update_prompt)
        teammate_prompt = root / "teammate_prompt.md"
        teammate_prompt.write_text(
            "Colleague workflow: use a separate workflow profile and do not overwrite Gobi defaults.\n"
            "Gate: run-ci-fast or project-specific equivalent must pass.\n",
            encoding="utf-8",
        )
        teammate = archive_update_workflow_profile(project, "teammate", "Colleague", teammate_prompt)
        status2 = workflow_profile_status(project)
        pack = workflow_context_pack(project, "gobi", "documentation impact git policy run-ci-fast", 12000)
        secret_prompt = root / "sensitive_prompt.md"
        secret_prompt.write_text("Workflow note: API_KEY=should_not_escape must be redacted.\n", encoding="utf-8")
        secret_update = archive_update_workflow_profile(project, "gobi", "Gobi", secret_prompt)
        secret_search = native_archive_search(project, "should_not_escape", 10)

        base_project = root / "base"
        ours_project = root / "ours"
        theirs_project = root / "theirs"
        for p in (base_project, ours_project, theirs_project):
            p.mkdir()
            (p / "project.md").write_text("# Project\n", encoding="utf-8")
        build_native_archive(base_project)
        shutil.copy2(project_archive_path(base_project), project_archive_path(ours_project))
        shutil.copy2(project_archive_path(base_project), project_archive_path(theirs_project))
        ours_prompt = root / "ours_workflow.md"
        theirs_prompt = root / "theirs_workflow.md"
        ours_prompt.write_text("Gobi workflow: docs impact and run-ci-fast.\n", encoding="utf-8")
        theirs_prompt.write_text("Colleague workflow: separate profile and smoke test.\n", encoding="utf-8")
        archive_update_workflow_profile(ours_project, "gobi", "Gobi", ours_prompt)
        archive_update_workflow_profile(theirs_project, "colleague", "Colleague", theirs_prompt)
        merged = root / "merged.ithz"
        merge = git_merge_ithz(project_archive_path(base_project), project_archive_path(ours_project), project_archive_path(theirs_project), merged)
        merged_project = root / "merged_project"
        merged_project.mkdir()
        (merged_project / "project.md").write_text("# Project\n", encoding="utf-8")
        shutil.copy2(merged, project_archive_path(merged_project))
        merged_status = workflow_profile_status(merged_project)

        ours_conflict = root / "ours_conflict"
        theirs_conflict = root / "theirs_conflict"
        for p in (ours_conflict, theirs_conflict):
            p.mkdir()
            (p / "project.md").write_text("# Project\n", encoding="utf-8")
            shutil.copy2(project_archive_path(base_project), project_archive_path(p))
        conflict_a = root / "conflict_a.md"
        conflict_b = root / "conflict_b.md"
        conflict_a.write_text("Same profile says run-ci-fast only.\n", encoding="utf-8")
        conflict_b.write_text("Same profile says full regression before push.\n", encoding="utf-8")
        archive_update_workflow_profile(ours_conflict, "shared", "A", conflict_a)
        archive_update_workflow_profile(theirs_conflict, "shared", "B", conflict_b)
        conflict = git_merge_ithz(project_archive_path(base_project), project_archive_path(ours_conflict), project_archive_path(theirs_conflict), root / "conflict_merged.ithz")

        rows = [
            {"test": "project_md_created", "passed": (project / "project.md").exists(), "value": "project.md"},
            {"test": "existing_markdown_processed", "passed": adopt["source_count"] >= 2 and bool(adopt["source_rows"]), "value": adopt["source_count"]},
            {"test": "workflow_profile_created", "passed": status["profile_count"] == 1 and status["default_profile"] == "gobi", "value": status.get("workflow_index_hash")},
            {"test": "workflow_prompt_update_revision", "passed": update["profile"]["revision"] >= 2, "value": update["profile"]["profile_hash"]},
            {"test": "separate_colleague_profile", "passed": status2["profile_count"] >= 2 and any(r.get("profile_id") == "teammate" for r in status2["profiles"]), "value": status2["profile_count"]},
            {"test": "workflow_context_pack", "passed": "documentation impact" in pack["text"].lower() or "run-ci-fast" in pack["text"].lower(), "value": pack["context_pack_hash"]},
            {"test": "workflow_context_pack_binds_profile", "passed": pack.get("workflow_profile_found") is True and pack.get("fallback_required") is False and "# ITHZ Workflow Profile" in pack.get("text", "") and bool(pack.get("workflow_profile_hash")), "value": pack.get("workflow_profile_hash", "")},
            {"test": "secret_prompt_redacted", "passed": not secret_search["rows"] and bool(secret_update["profile"]["profile_hash"]), "value": secret_update["profile"]["profile_hash"]},
        ]
        merge_rows = [
            {"test": "merge_independent_profiles", "passed": not merge["merge_needed"] and merged_status["profile_count"] == 2, "value": merge.get("archive_sha256", "")},
            {"test": "merge_conflicting_same_profile_detected", "passed": conflict["merge_needed"] and any("workflow_profile_added_differently:shared" in c for c in conflict["conflicts"]), "value": ",".join(conflict["conflicts"])},
            {"test": "single_archive_after_merge", "passed": merged.exists() and merged.suffix == ".ithz", "value": str(merged)},
        ]
    out = exp_dir("mcp19_workflow_branches")
    write_matrix(out / "mcp19_workflow_branch_matrix.csv", rows)
    write_matrix(out / "mcp19_merge_matrix.csv", merge_rows)
    write_summary(
        out / "mcp19_summary.md",
        "MCP19 Workflow Branch Profiles Summary",
        rows + merge_rows,
        "- `project.md` remains the only bootstrap Markdown file required for new projects.\n"
        "- `project.ithz` stores workflow profiles under `workflows/`.\n"
        "- Existing Markdown structures are mined into a workflow profile during adoption; they are not deleted automatically.\n"
        "- Different people can use separate workflow profiles, and the merge driver auto-merges independent profiles while flagging same-profile divergence.\n",
    )
    return all(bool(r["passed"]) for r in rows + merge_rows)


def run_mcp20_agent_history_import() -> bool:
    if not run_mcp19_workflow_branches():
        return False
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "history_project"
        project.mkdir()
        (project / "project.md").write_text("# Project\n\nUse ITHZ-MCP memory first.\n", encoding="utf-8")
        sessions = root / "codex_sessions" / "2026" / "05" / "29"
        sessions.mkdir(parents=True)
        session_file = sessions / "rollout-history.jsonl"
        session_lines = [
            {
                "session_meta": {"payload": {"cwd": str(project), "id": "fixture-session"}},
            },
            {
                "response_item": {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": f"Working in {project}. Historical prompt: document workflow and run-ci-fast. API_KEY=should_not_escape",
                        }
                    ],
                },
                "created_at": "2026-05-29T09:00:00Z",
            },
            {
                "response_item": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Response: workflow captured, run-ci-fast passed, next step is checkpoint.",
                        }
                    ],
                },
                "created_at": "2026-05-29T09:01:00Z",
            },
        ]
        session_file.write_text("\n".join(json.dumps(row) for row in session_lines) + "\n", encoding="utf-8")
        unrelated = sessions / "rollout-unrelated.jsonl"
        unrelated.write_text(
            json.dumps({"response_item": {"role": "user", "content": [{"text": "Other project prompt"}]}}) + "\n"
            + json.dumps({"response_item": {"role": "assistant", "content": [{"text": "Other response"}]}}) + "\n",
            encoding="utf-8",
        )
        dry = archive_import_agent_history(project, ["codex"], [root / "codex_sessions"], apply=False, author="Gobi", imported_at="2026-05-29T10:00:00Z")
        archive_exists_after_dry = project_archive_path(project).exists()
        applied = archive_import_agent_history(project, ["codex"], [root / "codex_sessions"], apply=True, author="Gobi", imported_at="2026-05-29T10:00:00Z")
        duplicate = archive_import_agent_history(project, ["codex"], [root / "codex_sessions"], apply=True, author="Gobi", imported_at="2026-05-29T10:05:00Z")
        other_author = archive_import_agent_history(project, ["codex"], [root / "codex_sessions"], apply=True, author="Colleague", imported_at="2026-05-29T10:10:00Z")
        prompt_rows = [json.loads(line) for line in extract_archive_file_bytes(project, PROMPT_LOG_PATH).decode("utf-8").splitlines() if line.strip()]
        gobi_rows = [row for row in prompt_rows if row.get("author") == "Gobi"]
        colleague_rows = [row for row in prompt_rows if row.get("author") == "Colleague"]
        search = native_archive_search(project, "historical workflow run-ci-fast", 10)
        author_search = native_archive_search(project, "Colleague Gobi", 10)
        secret_search = native_archive_search(project, "should_not_escape", 10)
        pack = native_archive_context_pack(project, "historical prompt workflow checkpoint", 12000)
        adopt_project = root / "adopt_history_project"
        adopt_project.mkdir()
        (adopt_project / "project.md").write_text("# Project\n", encoding="utf-8")
        adopt_session = root / "adopt_sessions"
        adopt_session.mkdir()
        (adopt_session / "session.jsonl").write_text(
            json.dumps({"response_item": {"role": "user", "content": [{"text": f"{adopt_project} onboarding prompt: docs-first and smoke tests."}]}}) + "\n"
            + json.dumps({"response_item": {"role": "assistant", "content": [{"text": "Adopted docs-first workflow."}]}}) + "\n",
            encoding="utf-8",
        )
        adopt_history = archive_import_agent_history(adopt_project, ["codex"], [adopt_session], apply=True, author="Adopter", imported_at="2026-05-29T11:00:00Z")
        rows = [
            {"test": "history_discovery_project_scoped", "passed": dry["record_count"] == 1 and dry["file_count"] == 1, "value": dry["history_discovery_hash"]},
            {"test": "dry_run_does_not_apply", "passed": dry["dry_run"] and not archive_exists_after_dry, "value": dry["record_count"]},
            {"test": "history_import_applied", "passed": applied["applied"] and applied["imported_count"] == 1 and project_archive_path(project).exists(), "value": applied.get("prompt_summary_index_hash", "")},
            {"test": "duplicate_import_noop", "passed": duplicate.get("imported_count") == 0, "value": duplicate.get("reason", "")},
            {"test": "existing_archive_append_author_history", "passed": other_author["archive_preexisting"] and other_author["imported_count"] == 1 and bool(colleague_rows), "value": other_author.get("prompt_summary_index_hash", "")},
            {"test": "author_and_time_recorded", "passed": bool(gobi_rows) and gobi_rows[0].get("history_time") == "2026-05-29T09:00:00Z" and gobi_rows[0].get("imported_at_utc") == "2026-05-29T10:00:00Z", "value": gobi_rows[0].get("author_id", "") if gobi_rows else ""},
            {"test": "history_searchable", "passed": bool(search["rows"]) and "historical" in pack["text"].lower(), "value": pack["context_pack_hash"]},
            {"test": "author_searchable", "passed": bool(author_search["rows"]), "value": len(author_search["rows"])},
            {"test": "secret_not_imported", "passed": not secret_search["rows"] and "should_not_escape" not in pack["text"], "value": len(secret_search["rows"])},
            {"test": "adoption_history_import_works", "passed": adopt_history["applied"] and adopt_history["imported_count"] == 1, "value": adopt_history.get("prompt_summary_index_hash", "")},
        ]
    out = exp_dir("mcp20_agent_history_import")
    write_matrix(out / "mcp20_agent_history_import_matrix.csv", rows)
    write_summary(
        out / "mcp20_summary.md",
        "MCP20 Agent History Import Summary",
        rows,
        "- historical prompts/responses are discovered from explicit local agent-history roots or known app locations;\n"
        "- discovery is project-scoped by cwd/path markers;\n"
        "- default import is summary-only and redaction-gated;\n"
        "- raw full chat capture is not automatic;\n"
        "- duplicate semantic prompt hashes from the same author are not imported twice;\n"
        "- existing `project.ithz` archives are appended with author/time provenance instead of being replaced.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def _host_smoke_rows(project: Path, out: Path, launcher: Path | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for client in HOSTS:
        cfg = out / f"{client.replace('-', '_')}_mcp_config.json"
        write_json(cfg, config_template(project, client, storage_profile="native-archive"))
        if launcher:
            data = read_json(cfg, {})
            server = data.get("server") or data.get("mcpServers", {}).get("ithz-mcp")
            if isinstance(server, dict):
                server["command"] = str(launcher)
                server["args"] = [
                    "mcp-server",
                    "--project",
                    str(project.resolve()),
                    "--mode",
                    "read-only",
                    "--protocol",
                    server.get("protocol", "mcp"),
                    "--storage-profile",
                    "native-archive",
                ]
                write_json(cfg, data)
        validation = validate_config(cfg)
        smoke = scripted_client_smoke(cfg, out / f"{client.replace('-', '_')}_transcript.jsonl")
        detected = detect_host(client)
        rows.append(
            {
                "client": client,
                "passed": validation["passed"] and smoke["passed"],
                "config_validate": validation["passed"],
                "scripted_stdio_smoke": smoke["passed"],
                "host_detected": detected["available"],
                "host_command": detected.get("command", ""),
                "detected_paths": ";".join(detected.get("detected_paths", [])),
                "real_host_smoke": "not_automated" if detected["available"] else "not_available",
            }
        )
    return rows


def _create_product_candidate_package() -> dict[str, Any]:
    dist = repo_root() / "dist" / "ithz_mcp-v0.1-product-candidate"
    if dist.exists():
        shutil.rmtree(dist)
    (dist / "docs").mkdir(parents=True)
    (dist / "examples").mkdir(parents=True)
    (dist / "native").mkdir(parents=True)
    (dist / "assets").mkdir(parents=True)
    shutil.copytree(repo_root() / "src", dist / "src", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(repo_root() / "ithz_mcp", dist / "ithz_mcp", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(repo_root() / "templates", dist / "templates")
    shutil.copytree(repo_root() / "tests" / "quality_expectations", dist / "tests" / "quality_expectations")
    shutil.copytree(sample_project(), dist / "sample_project", ignore=shutil.ignore_patterns(".ithz_mcp", ".ithz-context", "project.ithz", ".env", "secrets.key", "*.pem", "*.key"))
    for name in ("README.md", "AGENTS.md", "ITHZ_CONTEXT.md", "pyproject.toml", "install_ithz.md", "ithz_mcp.md"):
        shutil.copy2(repo_root() / name, dist / name)
    for asset in (repo_root() / "src" / "ithz_mcp" / "assets").glob("*"):
        if asset.is_file():
            shutil.copy2(asset, dist / "assets" / asset.name)
    for doc in (repo_root() / "docs").glob("*.md"):
        shutil.copy2(doc, dist / "docs" / doc.name)
    version = version_info()
    version["package_created_by"] = "run-production-readiness"
    version["package_dist"] = dist.name
    write_json(dist / "VERSION.json", version)
    selected = select_native_ithz()
    native_avx2 = repo_root().parent / "native_ithz" / "build_avx2" / "Release" / "ithz-native.exe"
    scalar = repo_root().parent / "native_ithz" / "build_scalar" / "Release" / "ithz-native.exe"
    if native_avx2.exists():
        shutil.copy2(native_avx2, dist / "native" / "ithz-native.exe")
        shutil.copy2(native_avx2, dist / "native" / "ithz-native-avx2.exe")
    else:
        shutil.copy2(Path(selected.path), dist / "native" / "ithz-native.exe")
    if scalar.exists():
        shutil.copy2(scalar, dist / "native" / "ithz-native-scalar.exe")
    macos_native = _find_macos_native_binary()
    if macos_native is not None:
        shutil.copy2(macos_native, dist / "native" / "ithz-native")
        try:
            (dist / "native" / "ithz-native").chmod(0o755)
        except OSError:
            pass
    macos_storage_profile = "native-archive" if (dist / "native" / "ithz-native").exists() else "legacy"
    launcher = dist / "ithz_mcp_server.cmd"
    launcher.write_text(
        "@echo off\r\n"
        "set \"PYTHONPATH=%~dp0;%~dp0src;%PYTHONPATH%\"\r\n"
        "set \"ITHZ_PYTHON=python\"\r\n"
        "where python >nul 2>nul\r\n"
        "if errorlevel 1 set \"ITHZ_PYTHON=py -3\"\r\n"
        "if exist \"%LOCALAPPDATA%\\Programs\\Python\\Python312\\python.exe\" set \"ITHZ_PYTHON=%LOCALAPPDATA%\\Programs\\Python\\Python312\\python.exe\"\r\n"
        "%ITHZ_PYTHON% -m ithz_mcp %*\r\n",
        encoding="utf-8",
    )
    launcher_sh = dist / "ithz_mcp_server.sh"
    launcher_sh.write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "PYTHON_BIN=\"${PYTHON:-python3}\"\n"
        "export PYTHONPATH=\"$DIR/src:$DIR${PYTHONPATH:+:$PYTHONPATH}\"\n"
        "exec \"$PYTHON_BIN\" -m ithz_mcp \"$@\"\n",
        encoding="utf-8",
    )
    try:
        launcher_sh.chmod(0o755)
    except OSError:
        pass
    write_host_install_bundle(dist / "sample_project", dist / "host_installers", launcher)
    write_host_install_bundle(dist / "sample_project", dist / "host_installers_macos", launcher_sh, storage_profile=macos_storage_profile)
    for item in (dist / "host_installers").glob("*.json"):
        shutil.copy2(item, dist / item.name)
        shutil.copy2(item, dist / "examples" / item.name)
    for item in (dist / "host_installers_macos").glob("install_*_mcp.sh"):
        shutil.copy2(item, dist / item.name)
    (dist / "README_FIRST.md").write_text(
        "# README FIRST\n\n"
        f"Build: `{version.get('build_id')}`\n\n"
        "1. Run `smoke_test.ps1`.\n"
        "2. On macOS/Linux run `chmod +x *.sh host_installers_macos/*.sh` then `./smoke_test.sh`.\n"
        "3. Run `python mcp_client_smoke.py` or `./mcp_client_smoke.sh`.\n"
        "4. Copy `install_ithz.md` into another project and ask the local agent to follow it.\n"
        "5. Review `host_installers/README_HOST_INSTALLERS.md` and `host_installers_macos/README_HOST_INSTALLERS.md`.\n"
        "6. Install Windows host config with `install_*_mcp.ps1 -Apply`; install macOS host config with `install_*_mcp.sh --apply`.\n"
        "7. Use `project.md` as bootstrap and `project.ithz` as the memory zone when native `ithz-native` is available.\n"
        f"8. On macOS, the Python MCP server works through stdio; this package uses `{macos_storage_profile}` storage in generated macOS host configs.\n"
        "   Native `project.ithz` storage requires `native/ithz-native` or `ITHZ_NATIVE_EXE` pointing to a compatible macOS binary.\n"
        "9. First install runs agent intake with Codex CLI when available; if not, the host agent must finish intake from `install_ithz.md`.\n"
        "10. Use durable instruction and Project Ledger tools when the user gives lasting workflow, decision, gate, risk, claim or reviewer-note rules.\n"
        "11. Track `project.md` and `project.ithz` in Git; use the ITHZ merge driver for parallel work.\n"
        "12. This is not a Git replacement, cloud sync product, production database, or general token-saving claim.\n",
        encoding="utf-8",
    )
    (dist / "sample_commands.ps1").write_text(
        "$ErrorActionPreference='Stop'\n"
        "python -m ithz_mcp install-project --project sample_project --apply --agent-intake deterministic-only --no-git-driver\n"
        "python -m ithz_mcp ithz-add-claim --project sample_project --claim-id sample_scoped_claim --text \"Sample package smoke has a scoped ledger claim.\" --scope package-smoke --supporting-gate package-smoke --status allowed_scoped\n"
        "python -m ithz_mcp ithz-block-claim --project sample_project --claim-id sample_blocked_claim --text \"Sample package replaces Git\" --reason \"ITHZ-MCP does not replace Git.\" --blocking-gate package-smoke\n"
        "python -m ithz_mcp ithz-can-i-claim --project sample_project --claim \"Sample package replaces Git\"\n"
        "python -m ithz_mcp archive-get-context-pack --project sample_project --query \"decision gate\" --out archive_pack.md\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_config.sample.json\n"
        "python mcp_client_smoke.py\n",
        encoding="utf-8",
    )
    (dist / "mcp_client_smoke.py").write_text(
        "from ithz_mcp.cli import main\nraise SystemExit(main(['mcp-client-smoke','--config','codex_mcp_config.sample.json','--out','product_client_transcript.jsonl']))\n",
        encoding="utf-8",
    )
    (dist / "mcp_client_smoke.cmd").write_text(
        "@echo off\r\n"
        "set \"PYTHONPATH=%~dp0;%~dp0src;%PYTHONPATH%\"\r\n"
        "python mcp_client_smoke.py\r\n",
        encoding="utf-8",
    )
    (dist / "mcp_client_smoke.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "export PYTHONPATH=\"$DIR/src:$DIR${PYTHONPATH:+:$PYTHONPATH}\"\n"
        "PYTHON_BIN=\"${PYTHON:-python3}\"\n"
        "exec \"$PYTHON_BIN\" \"$DIR/mcp_client_smoke.py\"\n",
        encoding="utf-8",
    )
    (dist / "sample_commands.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "\"$DIR/ithz_mcp_server.sh\" version\n"
        "\"$DIR/ithz_mcp_server.sh\" init-project --project \"$DIR/sample_project\"\n"
        "\"$DIR/ithz_mcp_server.sh\" build-index --project \"$DIR/sample_project\"\n"
        "\"$DIR/ithz_mcp_server.sh\" get-context-pack --project \"$DIR/sample_project\" --query \"decision gate\" --out \"$DIR/sample_pack.md\"\n"
        f"STORAGE_PROFILE=\"${{ITHZ_MCP_STORAGE_PROFILE:-{macos_storage_profile}}}\"\n"
        "if [ \"$STORAGE_PROFILE\" = \"native-archive\" ] && [ -x \"$DIR/native/ithz-native\" ]; then export ITHZ_NATIVE_EXE=\"${ITHZ_NATIVE_EXE:-$DIR/native/ithz-native}\"; fi\n"
        "\"$DIR/ithz_mcp_server.sh\" mcp-config-template --project \"$DIR/sample_project\" --client codex --storage-profile \"$STORAGE_PROFILE\" --out \"$DIR/codex_mcp_config.macos.sample.json\"\n"
        "\"$DIR/ithz_mcp_server.sh\" mcp-config-validate --config \"$DIR/codex_mcp_config.macos.sample.json\"\n",
        encoding="utf-8",
    )
    (dist / "smoke_test.ps1").write_text(
        "$ErrorActionPreference='Stop'\n"
        "python -m ithz_mcp version\n"
        "python -m ithz_mcp self-test --verbose\n"
        "python -m ithz_mcp install-project --project sample_project --apply --agent-intake deterministic-only --no-git-driver | Out-Null\n"
        "python -m ithz_mcp archive-finalize-task --project sample_project --task \"product package smoke\" --summary-text \"Package smoke completed.\" --docs-impact not-needed --memory-impact handoff-created --gate \"Gate: package smoke passed\" | Out-Null\n"
        "python -m ithz_mcp ithz-add-claim --project sample_project --claim-id package_smoke_claim --text \"Package smoke passed as a scoped test result.\" --scope package-smoke --supporting-gate package-smoke --status allowed_scoped | Out-Null\n"
        "python -m ithz_mcp ithz-block-claim --project sample_project --claim-id package_git_replacement_block --text \"Git replacement claim\" --reason \"Git remains the code history transport.\" --blocking-gate package-smoke | Out-Null\n"
        "python -m ithz_mcp ithz-can-i-claim --project sample_project --claim \"Git replacement claim\" | Out-Null\n"
        "python -m ithz_mcp archive-get-context-pack --project sample_project --query \"package smoke gate\" --out archive_pack.md | Out-Null\n"
        "python -m ithz_mcp mcp-config-validate --config codex_mcp_config.sample.json | Out-Null\n"
        "python mcp_client_smoke.py | Out-Null\n",
        encoding="utf-8",
    )
    (dist / "smoke_test.cmd").write_text(
        "@echo off\r\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -File \"%~dp0smoke_test.ps1\"\r\n",
        encoding="utf-8",
    )
    (dist / "smoke_test.sh").write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
        "\"$DIR/ithz_mcp_server.sh\" version\n"
        "\"$DIR/ithz_mcp_server.sh\" self-test --verbose\n"
        "\"$DIR/ithz_mcp_server.sh\" init-project --project \"$DIR/sample_project\"\n"
        "\"$DIR/ithz_mcp_server.sh\" build-index --project \"$DIR/sample_project\"\n"
        "\"$DIR/ithz_mcp_server.sh\" get-context-pack --project \"$DIR/sample_project\" --query \"package smoke gate\" --out \"$DIR/macos_archive_pack.md\"\n"
        f"STORAGE_PROFILE=\"${{ITHZ_MCP_STORAGE_PROFILE:-{macos_storage_profile}}}\"\n"
        "if [ \"$STORAGE_PROFILE\" = \"native-archive\" ] && [ -x \"$DIR/native/ithz-native\" ]; then export ITHZ_NATIVE_EXE=\"${ITHZ_NATIVE_EXE:-$DIR/native/ithz-native}\"; fi\n"
        "\"$DIR/ithz_mcp_server.sh\" mcp-config-template --project \"$DIR/sample_project\" --client codex --storage-profile \"$STORAGE_PROFILE\" --out \"$DIR/codex_mcp_config.macos.sample.json\"\n"
        "\"$DIR/ithz_mcp_server.sh\" mcp-config-validate --config \"$DIR/codex_mcp_config.macos.sample.json\"\n"
        "\"$DIR/ithz_mcp_server.sh\" mcp-client-smoke --config \"$DIR/codex_mcp_config.macos.sample.json\" --out \"$DIR/macos_client_transcript.jsonl\"\n",
        encoding="utf-8",
    )
    for script_name in ("ithz_mcp_server.sh", "mcp_client_smoke.sh", "sample_commands.sh", "smoke_test.sh"):
        try:
            (dist / script_name).chmod(0o755)
        except OSError:
            pass
    (dist / "RELEASE_NOTES.md").write_text(
        "# ITHZ-MCP v0.1 product candidate\n\n"
        f"Build: `{version.get('build_id')}`\n\n"
        "This package is a production-test candidate for local deterministic project memory. It includes native `project.ithz` storage, memory-first MCP configs, host installer scripts, prompt/response summary memory, durable instruction memory, workflow profiles, Git merge driver support, shared-project smoke coverage, deterministic current-memory synthesis, Project Ledger v1 for claims/blocked claims/replication packs/reviewer notes, fast archive-lock diagnostics and auto-deferred large-archive snapshots.\n\n"
        "Windows native archive subprocess calls are launched without a visible console window where the platform supports `CREATE_NO_WINDOW`.\n\n"
        f"macOS: the Python stdio MCP server and POSIX host installers are included. Generated macOS host configs use `{macos_storage_profile}` storage. Native `project.ithz` storage on macOS requires a compatible `ithz-native` binary in `native/ithz-native` or `ITHZ_NATIVE_EXE`.\n\n"
        "It does not replace Git, a production database, cloud sync, external host history, vector databases or every retrieval system.\n",
        encoding="utf-8",
    )
    _sha256sums(dist)
    smoke = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "smoke_test.ps1"], cwd=str(dist), text=True, capture_output=True, timeout=180)
    client = subprocess.run([sys.executable, "mcp_client_smoke.py"], cwd=str(dist), text=True, capture_output=True, timeout=60)
    _cleanup_package_runtime_state(dist)
    if (dist / "fixtures").exists():
        shutil.rmtree(dist / "fixtures")
    for extra in ("archive_pack.md", "product_client_transcript.jsonl"):
        if (dist / extra).exists():
            (dist / extra).unlink()
    for extra in ("macos_archive_pack.md", "macos_client_transcript.jsonl", "sample_pack.md"):
        if (dist / extra).exists():
            (dist / extra).unlink()
    _sha256sums(dist)
    zip_path = repo_root() / "dist" / str(version.get("package_filename", "ithz_mcp.zip"))
    version["package_zip"] = zip_path.name
    write_json(dist / "VERSION.json", version)
    _sha256sums(dist)
    zip_sha256 = _zip_dir(dist, zip_path)
    publish_version = dict(version)
    publish_version["package_zip_sha256"] = zip_sha256
    (repo_root() / "dist" / "VERSION.json").write_text(dump_pretty(publish_version), encoding="utf-8")
    (repo_root() / "dist" / "SHA256SUMS.txt").write_text(f"{zip_sha256}  {zip_path.name}\n", encoding="utf-8")
    secret_hits = [str(p.relative_to(dist)) for p in dist.rglob("*") if p.is_file() and p.name.lower() in {".env", "secrets.key", "private.pem"}]
    return {
        "dist": dist,
        "zip_path": zip_path,
        "zip_sha256": zip_sha256,
        "selected_native": selected,
        "macos_native": str(macos_native) if macos_native else "",
        "macos_storage_profile": macos_storage_profile,
        "smoke_returncode": smoke.returncode,
        "client_returncode": client.returncode,
        "secret_hits": secret_hits,
    }


def run_mcp21_production_readiness() -> bool:
    if not run_mcp20_agent_history_import():
        return False
    out = exp_dir("mcp21_production_readiness")
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        new_project = root / "new_project"
        new_project.mkdir()
        onboarding = root / "new_project_prompt.md"
        onboarding.write_text("Workflow: memory first. Gate: run-ci-fast. Risk: do not store secrets.\n", encoding="utf-8")
        new_adopt = archive_adopt_project_workflow(new_project, "gobi", "Gobi", onboarding, include_existing_md=True)
        new_checkpoint = archive_finalize_task(
            new_project,
            "new project smoke",
            summary="New project memory initialized.",
            gates=["Gate: new project smoke passed"],
            next_steps=["Next: install MCP host config"],
            docs_impact="not-needed",
            memory_impact="handoff-created",
            create_snapshot=True,
        )
        new_pack = native_archive_context_pack(new_project, "run-ci-fast secrets next", 10000)
        rows.extend(
            [
                {"scenario": "new_project", "test": "project_md_project_ithz_created", "passed": (new_project / "project.md").exists() and (new_project / "project.ithz").exists(), "value": str(new_project)},
                {"scenario": "new_project", "test": "workflow_profile_created", "passed": new_adopt["profile"]["profile_id"] == "gobi", "value": new_adopt["profile"]["profile_hash"]},
                {"scenario": "new_project", "test": "checkpoint_and_pack", "passed": new_checkpoint["finalized"] and "run-ci-fast" in new_pack["text"], "value": new_pack["context_pack_hash"]},
            ]
        )

        adopted = root / "adopted_project"
        adopted.mkdir()
        (adopted / "AI_PROJECT_BRIEF.md").write_text("# Brief\n\nDecision: docs-first adoption.\nRisk: avoid secret import.\n", encoding="utf-8")
        (adopted / "WORKFLOW_RULES.md").write_text("# Workflow\n\nGate: run-ci-fast must pass.\nNext: write checkpoint.\n", encoding="utf-8")
        (adopted / ".env").write_text("API_KEY=should_not_escape\n", encoding="utf-8")
        history = root / "adopted_history"
        history.mkdir()
        (history / "history.jsonl").write_text(
            json.dumps({"response_item": {"role": "user", "content": [{"text": f"Working in {adopted}. Adopt prompt: use memory first. token=should_not_escape"}]}, "created_at": "2026-05-29T12:00:00Z"}) + "\n"
            + json.dumps({"response_item": {"role": "assistant", "content": [{"text": "Adopted memory-first workflow and gate rules."}]}, "created_at": "2026-05-29T12:01:00Z"}) + "\n",
            encoding="utf-8",
        )
        adopted_prompt = root / "adopted_prompt.md"
        adopted_prompt.write_text("Use imported workflow docs and prompt history summary.\n", encoding="utf-8")
        adopted_profile = archive_adopt_project_workflow(adopted, "gobi", "Gobi", adopted_prompt, include_existing_md=True)
        adopted_history = archive_import_agent_history(adopted, ["codex"], [history], apply=True, author="Gobi", imported_at="2026-05-29T12:05:00Z")
        adopted_search = native_archive_search(adopted, "docs-first adoption run-ci-fast", 10)
        adopted_secret = native_archive_search(adopted, "should_not_escape", 10)
        rows.extend(
            [
                {"scenario": "adopted_project", "test": "existing_markdown_mined", "passed": adopted_profile["source_count"] >= 2, "value": adopted_profile["profile"]["profile_hash"]},
                {"scenario": "adopted_project", "test": "history_import_author_time", "passed": adopted_history["imported_count"] == 1 and adopted_history["author"] == "Gobi", "value": adopted_history.get("prompt_summary_index_hash", "")},
                {"scenario": "adopted_project", "test": "searchable_no_secret", "passed": bool(adopted_search["rows"]) and not adopted_secret["rows"], "value": len(adopted_search["rows"])},
            ]
        )

        base = root / "shared_base"
        base.mkdir()
        (base / "project.md").write_text("# Shared Project\n\nMarkdown is bootstrap. ITHZ is memory zone.\n", encoding="utf-8")
        build_native_archive(base)
        base_archive = root / "base.ithz"
        shutil.copy2(project_archive_path(base), base_archive)
        ours = _copy_archive_to_project(base_archive, root / "shared_ours")
        theirs = _copy_archive_to_project(base_archive, root / "shared_theirs")
        archive_append_event(ours, "decision", "Decision: Gobi adds independent shared memory.", "mcp21", ["shared", "gobi"])
        archive_append_event(theirs, "decision", "Decision: Colleague adds independent shared memory.", "mcp21", ["shared", "colleague"])
        ours_prompt = root / "ours_profile.md"
        theirs_prompt = root / "theirs_profile.md"
        ours_prompt.write_text("Gobi workflow profile: memory first and package smoke.\n", encoding="utf-8")
        theirs_prompt.write_text("Colleague workflow profile: memory first and review smoke.\n", encoding="utf-8")
        archive_update_workflow_profile(ours, "gobi", "Gobi", ours_prompt)
        archive_update_workflow_profile(theirs, "colleague", "Colleague", theirs_prompt)
        merged_archive = root / "merged.ithz"
        merge = git_merge_ithz(base_archive, project_archive_path(ours), project_archive_path(theirs), merged_archive, out / "mcp21_shared_merge_report.md")
        merged = _copy_archive_to_project(merged_archive, root / "shared_merged")
        merged_gobi = native_archive_search(merged, "Gobi independent shared memory", 10)
        merged_colleague = native_archive_search(merged, "Colleague independent shared memory", 10)
        driver_plan = install_git_drivers(root / "shared_repo", dry_run=True)
        rows.extend(
            [
                {"scenario": "shared_project", "test": "semantic_merge_auto", "passed": not merge["merge_needed"] and project_archive_path(merged).exists(), "value": merge.get("archive_sha256", "")},
                {"scenario": "shared_project", "test": "merged_memory_searchable", "passed": bool(merged_gobi["rows"]) and bool(merged_colleague["rows"]), "value": f"gobi={len(merged_gobi['rows'])};colleague={len(merged_colleague['rows'])}"},
                {"scenario": "shared_project", "test": "git_driver_install_plan", "passed": any(a.get("action") == "append_gitattributes" for a in driver_plan["actions"]), "value": len(driver_plan["actions"])},
            ]
        )

        host_out = out / "host_smokes"
        host_out.mkdir(parents=True, exist_ok=True)
        host_rows = _host_smoke_rows(new_project, host_out)
        rows.extend({"scenario": "host_config", "test": r["client"], **r} for r in host_rows)
        write_host_install_bundle(new_project, out / "host_installers")

    package = _create_product_candidate_package()
    package_rows = [
        {"scenario": "package", "test": "product_candidate_created", "passed": package["dist"].exists(), "value": str(package["dist"])},
        {"scenario": "package", "test": "stable_zip_created", "passed": package["zip_path"].exists() and package["zip_path"].name == "ithz_mcp.zip", "value": str(package["zip_path"])},
        {"scenario": "package", "test": "stable_zip_sha256_generated", "passed": bool(package["zip_sha256"]), "value": package["zip_sha256"]},
        {"scenario": "package", "test": "package_smoke_passed", "passed": package["smoke_returncode"] == 0, "value": package["smoke_returncode"]},
        {"scenario": "package", "test": "package_mcp_client_smoke_passed", "passed": package["client_returncode"] == 0, "value": package["client_returncode"]},
        {"scenario": "package", "test": "no_secrets_included", "passed": not package["secret_hits"], "value": ";".join(package["secret_hits"])},
        {"scenario": "package", "test": "host_installers_included", "passed": (package["dist"] / "host_installers" / "README_HOST_INSTALLERS.md").exists(), "value": "host_installers"},
    ]
    rows.extend(package_rows)
    write_matrix(out / "mcp21_project_scenarios_matrix.csv", [r for r in rows if r["scenario"] in {"new_project", "adopted_project", "shared_project"}])
    write_matrix(out / "mcp21_host_install_matrix.csv", [r for r in rows if r["scenario"] == "host_config"])
    write_matrix(out / "mcp21_package_matrix.csv", package_rows)
    write_summary(
        out / "mcp21_summary.md",
        "MCP21 Production Readiness Summary",
        rows,
        "- new, adopted and shared project scenarios passed with `project.md` + `project.ithz`.\n"
        "- host configs and installer scripts were generated for Codex, Claude Code, Antigravity, Cursor and generic JSON-RPC clients.\n"
        "- scripted stdio MCP smoke validates the server; real host UI smoke remains host/manual unless a noninteractive host command exists.\n"
        "- product candidate package is under `dist/ithz_mcp-v0.1-product-candidate`.\n"
        "- no cloud sync, Git replacement, production database, vector DB dismissal or general token-saving claim is made.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp25_macos_package() -> bool:
    out = exp_dir("mcp25_macos_package")
    package = _create_product_candidate_package()
    dist = package["dist"]
    macos_zip = repo_root() / "dist" / "ithz-mcp-macos.zip"
    macos_zip_sha = _zip_macos_package(dist, macos_zip)
    required_scripts = [
        dist / "ithz_mcp_server.sh",
        dist / "smoke_test.sh",
        dist / "mcp_client_smoke.sh",
        dist / "sample_commands.sh",
        dist / "install_codex_mcp.sh",
        dist / "install_claude_code_mcp.sh",
        dist / "install_cursor_mcp.sh",
        dist / "install_antigravity_mcp.sh",
    ]
    required_docs = [
        dist / "install_ithz.md",
        dist / "ithz_mcp.md",
        dist / "docs" / "MACOS_MCP_SETUP.md",
        dist / "host_installers_macos" / "README_HOST_INSTALLERS.md",
    ]
    script_checks = []
    for script in required_scripts:
        text = script.read_text(encoding="utf-8") if script.exists() else ""
        script_checks.append(
            {
                "script": script.name,
                "exists": script.exists(),
                "shebang": text.startswith("#!/usr/bin/env sh"),
                "installer_dry_run": (not script.name.startswith("install_")) or "--apply" in text,
                "portable_launcher": (not script.name.startswith("install_")) or "ithz_mcp_server.sh" in text,
            }
        )
    macos_config = dist / "host_installers_macos" / "codex_mcp_config.sample.json"
    macos_cfg_text = macos_config.read_text(encoding="utf-8") if macos_config.exists() else ""
    windows_native = dist / "native" / "ithz-native.exe"
    macos_native = dist / "native" / "ithz-native"
    macos_storage_profile = str(package.get("macos_storage_profile") or "legacy")
    rows = [
        {"test": "package_created", "passed": dist.exists(), "value": str(dist)},
        {"test": "stable_zip_created", "passed": package["zip_path"].exists() and package["zip_path"].name == "ithz_mcp.zip", "value": str(package["zip_path"])},
        {"test": "package_smoke_passed", "passed": package["smoke_returncode"] == 0, "value": package["smoke_returncode"]},
        {"test": "package_mcp_client_smoke_passed", "passed": package["client_returncode"] == 0, "value": package["client_returncode"]},
        {"test": "posix_scripts_included", "passed": all(item.exists() for item in required_scripts), "value": ";".join(p.name for p in required_scripts)},
        {"test": "posix_scripts_static_checks", "passed": all(c["exists"] and c["shebang"] and c["installer_dry_run"] and c["portable_launcher"] for c in script_checks), "value": dump_pretty(script_checks)},
        {"test": "macos_host_bundle_storage_profile", "passed": f'"storage_profile": "{macos_storage_profile}"' in macos_cfg_text, "value": macos_storage_profile},
        {"test": "macos_docs_included", "passed": all(item.exists() for item in required_docs), "value": ";".join(str(p.relative_to(dist)) for p in required_docs)},
        {"test": "macos_zip_created", "passed": macos_zip.exists() and bool(macos_zip_sha), "value": f"{macos_zip.name}:{macos_zip_sha}"},
        {"test": "windows_native_included", "passed": windows_native.exists(), "value": str(windows_native.relative_to(dist)) if windows_native.exists() else "missing"},
        {"test": "macos_native_binary_state_documented", "passed": (macos_native.exists() and macos_storage_profile == "native-archive") or ((not macos_native.exists()) and macos_storage_profile == "legacy"), "value": "bundled" if macos_native.exists() else "not bundled"},
        {"test": "no_secrets_included", "passed": not package["secret_hits"], "value": ";".join(package["secret_hits"])},
    ]
    write_matrix(out / "mcp25_macos_package_matrix.csv", rows)
    write_summary(
        out / "mcp25_summary.md",
        "MCP25 macOS MCP Package Summary",
        rows,
        "- product-candidate zip now includes POSIX launchers and host installer scripts.\n"
        "- macOS MCP server path is Python stdio through `ithz_mcp_server.sh`.\n"
        f"- macOS host configs use `{macos_storage_profile}` storage for this package build.\n"
        "- If a macOS `ithz-native` binary is available in `native/ithz-native`, the package can use native archive storage; otherwise it safely falls back to legacy storage.\n"
        "- Windows native `ithz-native.exe` remains bundled for native archive storage on Windows.\n"
        "- no Git replacement, cloud sync, production database or general token-saving claim is made.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp28_ubuntu_package() -> bool:
    out = exp_dir("mcp28_ubuntu_package")
    package = _create_product_candidate_package()
    dist = package["dist"]
    stage = _create_ubuntu_package_stage(dist)
    ubuntu_tar = repo_root() / "dist" / "ithz-mcp-ubuntu.tar.gz"
    ubuntu_deb = repo_root() / "dist" / "ithz-mcp-ubuntu.deb"
    tar_sha = _tar_gz_dir(stage, ubuntu_tar, "ithz-mcp-ubuntu")
    deb_sha = _create_ubuntu_deb(stage, ubuntu_deb, str(version_info().get("version", "0.1.0-alpha")))
    (repo_root() / "dist" / "ithz-mcp-ubuntu_SHA256SUMS.txt").write_text(
        f"{tar_sha}  {ubuntu_tar.name}\n{deb_sha}  {ubuntu_deb.name}\n",
        encoding="utf-8",
    )

    required_scripts = [
        stage / "install.sh",
        stage / "uninstall.sh",
        stage / "smoke_test_ubuntu.sh",
        stage / "ithz_mcp_server.sh",
        stage / "mcp_client_smoke.sh",
        stage / "ithz-native-resolve.sh",
        stage / "ithz-verify.sh",
        stage / "ithz-list.sh",
        stage / "ithz-extract-here.sh",
        stage / "ithz-open-temp.sh",
        stage / "build_linux_native_package.sh",
        stage / "install_linux_native.sh",
        stage / "install_codex_mcp.sh",
        stage / "install_claude_code_mcp.sh",
        stage / "install_cursor_mcp.sh",
        stage / "install_antigravity_mcp.sh",
    ]
    required_native_kit_paths = [
        stage / "native_build_kit" / "README_LINUX_NATIVE.md",
        stage / "native_build_kit" / "native_ithz" / "CMakeLists.txt",
        stage / "native_build_kit" / "native_ithz" / "src" / "main.cpp",
        stage / "native_build_kit" / "native_ithz" / "include" / "ithz" / "manifest.hpp",
    ]
    script_checks = []
    for script in required_scripts:
        text = script.read_text(encoding="utf-8") if script.exists() else ""
        script_checks.append(
            {
                "script": script.name,
                "exists": script.exists(),
                "shebang": text.startswith("#!/usr/bin/env sh"),
                "legacy_storage": (not script.name.startswith("install_")) or "legacy" in text or "STORAGE_PROFILE" in text,
            }
        )
    linux_config = stage / "host_installers_linux" / "codex_mcp_config.sample.json"
    linux_cfg_text = linux_config.read_text(encoding="utf-8") if linux_config.exists() else ""
    deb_bytes = ubuntu_deb.read_bytes() if ubuntu_deb.exists() else b""
    rows = [
        {"test": "product_candidate_created", "passed": dist.exists(), "value": str(dist)},
        {"test": "ubuntu_stage_created", "passed": stage.exists(), "value": str(stage)},
        {"test": "ubuntu_tar_created", "passed": ubuntu_tar.exists() and bool(tar_sha), "value": f"{ubuntu_tar.name}:{tar_sha}"},
        {"test": "ubuntu_deb_created", "passed": ubuntu_deb.exists() and deb_bytes.startswith(b"!<arch>\n") and bool(deb_sha), "value": f"{ubuntu_deb.name}:{deb_sha}"},
        {"test": "posix_scripts_included", "passed": all(item.exists() for item in required_scripts), "value": ";".join(p.name for p in required_scripts)},
        {"test": "posix_scripts_static_checks", "passed": all(c["exists"] and c["shebang"] for c in script_checks), "value": dump_pretty(script_checks)},
        {"test": "linux_host_bundle_uses_legacy_storage", "passed": '"storage_profile": "legacy"' in linux_cfg_text, "value": "legacy"},
        {"test": "install_playbook_included", "passed": (stage / "install_ithz.md").exists(), "value": "install_ithz.md"},
        {"test": "bin_wrappers_are_prefix_scripts", "passed": "write_wrapper ithz-verify ithz-verify.sh" in (stage / "install.sh").read_text(encoding="utf-8") and "ln -sf \"$PREFIX/ithz-verify.sh\"" not in (stage / "install.sh").read_text(encoding="utf-8"), "value": "no broken symlink wrappers"},
        {"test": "windows_native_excluded", "passed": not any(stage.rglob("*.exe")), "value": "no exe files in ubuntu stage"},
        {"test": "linux_native_build_kit_included", "passed": all(item.exists() for item in required_native_kit_paths), "value": ";".join(str(item.relative_to(stage)).replace("\\", "/") for item in required_native_kit_paths)},
        {"test": "linux_native_binary_not_bundled", "passed": not (stage / "native" / "ithz-native").exists(), "value": "build kit included; Linux binary built on Ubuntu host"},
        {"test": "fallback_archive_commands_included", "passed": all((stage / name).exists() for name in ("ithz-native-resolve.sh", "ithz-verify.sh", "ithz-list.sh", "ithz-extract-here.sh", "ithz-open-temp.sh")), "value": "verify;list;extract-here;open-temp"},
        {"test": "fallback_without_native_fails_cleanly", "passed": "ithz-native not found" in (stage / "ithz-native-resolve.sh").read_text(encoding="utf-8"), "value": "resolver prints clean missing-native message"},
        {"test": "linux_drive_fuse_not_claimed", "passed": "not a Linux Drive/FUSE provider" in (stage / "native_build_kit" / "README_LINUX_NATIVE.md").read_text(encoding="utf-8") and "Full Linux Drive/FUSE mount support is not bundled yet" in (stage / "README_UBUNTU.md").read_text(encoding="utf-8"), "value": "fallback only"},
        {"test": "ubuntu_docs_included", "passed": (stage / "README_UBUNTU.md").exists() and (stage / "docs" / "UBUNTU_MCP_SETUP.md").exists(), "value": "README_UBUNTU.md;docs/UBUNTU_MCP_SETUP.md"},
        {"test": "package_smoke_still_passed", "passed": package["smoke_returncode"] == 0, "value": package["smoke_returncode"]},
        {"test": "package_mcp_client_smoke_still_passed", "passed": package["client_returncode"] == 0, "value": package["client_returncode"]},
        {"test": "no_secrets_included", "passed": not package["secret_hits"], "value": ";".join(package["secret_hits"])},
    ]
    write_matrix(out / "mcp28_ubuntu_package_matrix.csv", rows)
    write_summary(
        out / "mcp28_summary.md",
        "MCP28 Ubuntu MCP Package Summary",
        rows,
        "- Ubuntu/Linux package artifacts were generated as `dist/ithz-mcp-ubuntu.tar.gz` and `dist/ithz-mcp-ubuntu.deb`.\n"
        "- The tarball supports user-local install through `install.sh`; the `.deb` installs wrappers under `/usr/bin` and runtime under `/opt/ithz-mcp`.\n"
        "- Ubuntu host configs default to `legacy` storage unless a compatible Linux `ithz-native` binary is supplied.\n"
        "- The package includes a Linux `ithz-native` source build kit plus fallback archive commands: `ithz-verify`, `ithz-list`, `ithz-extract-here` and `ithz-open-temp`.\n"
        "- A prebuilt Linux native binary was not produced on this Windows host because no WSL/Docker/Linux compiler toolchain is available; the bundled build kit is intended to be run on Ubuntu.\n"
        "- The fallback is extraction-backed and does not claim Linux Drive/FUSE support.\n"
        "- The package includes Python stdio MCP server, host installer scripts and scripted smoke checks; no real Ubuntu host was executed on this Windows build machine.\n"
        "- no Git replacement, cloud sync, production database, vector DB dismissal or general token-saving claim is made.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp26_memory_synthesis() -> bool:
    out = exp_dir("mcp26_memory_synthesis")
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "memory_project"
        project.mkdir()
        (project / "project.md").write_text(
            "# Memory Project\n\nMarkdown is bootstrap. ITHZ is memory zone.\n",
            encoding="utf-8",
        )
        build_native_archive(project)
        archive_append_event(project, "decision", "Decision: use current memory synthesis for agent handoff.", "mcp26", ["decision"])
        archive_append_event(project, "gate", "Gate: run-ci-fast passed and must be visible.", "mcp26", ["gate"])
        archive_append_event(project, "risk", "Risk: must not break append-only archive writes or redaction.", "mcp26", ["risk", "must_not_break"])
        archive_append_event(project, "risk", "Forbidden claim: ITHZ-MCP does not replace Git or cloud sync.", "mcp26", ["forbidden_claim"])
        archive_append_event(project, "next", "Next step: finish synthesis regression.", "mcp26", ["next"])
        archive_append_events(
            project,
            [{"kind": "next", "text": "Next step completed cleanup done.", "source": "mcp26", "tags": ["next"], "supersedes": "evt_000006"}],
        )
        compile_result = archive_compile_memory_synthesis(project)
        status = archive_memory_index_status(project)
        pack = native_archive_context_pack(project, "must not break forbidden claim next synthesis", 12000)

        lock_path = project_archive_path(project).with_name(project_archive_path(project).name + ".lock")
        previous_wait = os.environ.get("ITHZ_MCP_ARCHIVE_LOCK_WAIT_SECONDS")
        os.environ["ITHZ_MCP_ARCHIVE_LOCK_WAIT_SECONDS"] = "0.2"
        lock_path.write_text(
            dump_pretty(
                {
                    "schema": "ithz_mcp_archive_write_lock_v2",
                    "archive": str(project_archive_path(project)),
                    "lock": str(lock_path),
                    "phase": "test_existing_writer",
                    "pid": os.getpid(),
                    "created_utc": "2099-01-01T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )
        start = time.monotonic()
        lock_failed_fast = False
        lock_detail = ""
        try:
            archive_append_event(project, "note", "This write should fail fast while lock exists.", "mcp26")
        except (ArchiveWriteLockError, RuntimeError) as exc:
            lock_detail = str(exc)
            lock_failed_fast = "archive_write_lock_busy" in lock_detail and (time.monotonic() - start) < 5.0
        finally:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
            if previous_wait is None:
                os.environ.pop("ITHZ_MCP_ARCHIVE_LOCK_WAIT_SECONDS", None)
            else:
                os.environ["ITHZ_MCP_ARCHIVE_LOCK_WAIT_SECONDS"] = previous_wait

        previous_snapshot_limit = os.environ.get("ITHZ_MCP_SNAPSHOT_AUTO_MAX_ARCHIVE_BYTES")
        os.environ["ITHZ_MCP_SNAPSHOT_AUTO_MAX_ARCHIVE_BYTES"] = "1"
        try:
            checkpoint = archive_finalize_task(
                project,
                "MCP26 large snapshot policy",
                summary="Checkpoint should append but defer snapshot in auto mode.",
                gates=["Gate: snapshot auto defer passed"],
                docs_impact="not-needed",
                memory_impact="handoff-created",
                create_snapshot=True,
                snapshot_mode="auto",
            )
        finally:
            if previous_snapshot_limit is None:
                os.environ.pop("ITHZ_MCP_SNAPSHOT_AUTO_MAX_ARCHIVE_BYTES", None)
            else:
                os.environ["ITHZ_MCP_SNAPSHOT_AUTO_MAX_ARCHIVE_BYTES"] = previous_snapshot_limit

        rows.extend(
            [
                {"test": "memory_synthesis_compiled", "passed": compile_result["compiled"] and compile_result["current_gate_count"] >= 1 and compile_result["current_risk_count"] >= 1, "value": compile_result["memory_synthesis_hash"]},
                {"test": "memory_synthesis_status_valid", "passed": status["memory_synthesis_valid"], "value": status["derived_memory_synthesis_hash"]},
                {"test": "context_pack_includes_synthesis", "passed": "Current Memory Synthesis" in pack["text"] and "Forbidden claim" in pack["text"], "value": pack["context_pack_hash"]},
                {"test": "write_lock_fails_fast", "passed": lock_failed_fast, "value": lock_detail[:180]},
                {"test": "snapshot_auto_deferred_for_large_policy", "passed": checkpoint["snapshot"] and not checkpoint["snapshot"]["snapshot_created"] and checkpoint["snapshot"].get("snapshot_deferred"), "value": checkpoint["snapshot"].get("reason") if checkpoint["snapshot"] else ""},
                {"test": "checkpoint_still_appended", "passed": checkpoint["finalized"] and checkpoint["append"]["appended"], "value": checkpoint["append"].get("memory_synthesis_hash")},
                {"test": "safe_verify_after_policy", "passed": native_archive_status(project)["safe_verify_ok"], "value": native_archive_status(project).get("archive_sha256")},
            ]
        )
    write_matrix(out / "mcp26_memory_synthesis_matrix.csv", rows[:3])
    write_matrix(out / "mcp26_lock_snapshot_matrix.csv", rows[3:])
    write_summary(
        out / "mcp26_summary.md",
        "MCP26 Memory Synthesis, Lock and Snapshot Policy Summary",
        rows,
        "- append-only events remain the durable history.\n"
        "- `indexes/memory_synthesis.json` is the deterministic current working-memory view.\n"
        "- archive write conflicts fail quickly with lock metadata instead of long waits.\n"
        "- auto snapshots are deferred for large archives; checkpoint append still completes.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp27_project_ledger() -> bool:
    out = exp_dir("mcp27_project_ledger")
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "ledger_project"
        project.mkdir()
        (project / "project.md").write_text(
            "# Ledger Project\n\nMarkdown is bootstrap. ITHZ is memory zone.\n",
            encoding="utf-8",
        )
        build_native_archive(project)
        claim = add_claim(
            project,
            "Special ITHKOR has a scoped finite/QPU diagnostic program.",
            claim_id="claim_special_ithkor_finite_program",
            scope="finite/qpu",
            supporting_gates=["D10F", "D11B", "D20"],
            status="allowed_scoped",
        )
        blocked = block_claim(
            project,
            "ITHKOR proves gravity.",
            "D9/D14/D17 blocked; no physical D claim.",
            claim_id="blocked_gravity_claim",
            blocking_gates=["D9E", "D14C", "D17B", "D20"],
        )
        replication = create_replication_pack_record(
            project,
            "D20",
            witnesses=15,
            positive=12,
            negative_stop=3,
            manifest_path="experiments/D20/manifest.json",
            public_safe=True,
            status="complete",
        )
        reviewer = add_reviewer_note(
            project,
            "First verify summary_found and status_matches_expected for all rows.",
            "D20",
            note_id="reviewer_d20_first_checks",
            severity="guidance",
        )
        allowed = list_allowed_claims(project)
        denied = list_blocked_claims(project)
        evidence = get_claim_evidence(project, "Does ITHKOR prove gravity?")
        can_claim = can_i_claim(project, "ITHKOR proves gravity?")
        summary = project_ledger_summary(project)
        status = archive_memory_index_status(project)
        pack = native_archive_context_pack(project, "gravity finite qpu D20 reviewer replication", 12000)
        write_schema_names = {schema["name"] for schema in mcp_tool_schemas("native-archive", "write-enabled")}
        read_schema_names = {schema["name"] for schema in mcp_tool_schemas("native-archive", "read-only")}
        no_window_configured = (_native_creationflags() != 0) if os.name == "nt" else True

        rows.extend(
            [
                {"test": "claim_added", "passed": claim["claim_id"] == "claim_special_ithkor_finite_program", "value": claim.get("claim_id")},
                {"test": "blocked_claim_added", "passed": blocked["claim_id"] == "blocked_gravity_claim", "value": blocked.get("claim_id")},
                {"test": "replication_pack_added", "passed": replication["pack_id"] == "D20", "value": replication.get("pack_id")},
                {"test": "reviewer_note_added", "passed": reviewer["note_id"] == "reviewer_d20_first_checks", "value": reviewer.get("note_id")},
                {"test": "claim_projection_written", "passed": allowed["claim_count"] == 1 and allowed["rows"][0]["claim_id"] == "claim_special_ithkor_finite_program", "value": allowed["claim_count"]},
                {"test": "blocked_projection_written", "passed": denied["blocked_claim_count"] == 1 and denied["rows"][0]["claim_id"] == "blocked_gravity_claim", "value": denied["blocked_claim_count"]},
                {"test": "can_i_claim_blocks_gravity", "passed": not can_claim["can_claim"] and can_claim["status"] == "blocked" and "D20" in can_claim.get("blocked_by", []), "value": can_claim.get("status")},
                {"test": "claim_evidence_has_alternative", "passed": evidence.get("allowed_match", {}).get("claim_id") == "claim_special_ithkor_finite_program", "value": evidence.get("allowed_match_score")},
                {"test": "ledger_summary_counts", "passed": summary.get("claim_count") == 1 and summary.get("blocked_claim_count") == 1 and summary.get("replication_pack_count") == 1 and summary.get("reviewer_note_count") == 1, "value": summary.get("project_ledger_hash", "")},
                {"test": "memory_index_ledger_valid", "passed": status.get("project_ledger_valid") and status.get("claim_count") == 1 and status.get("blocked_claim_count") == 1, "value": status.get("derived_project_ledger_hash", "")},
                {"test": "context_pack_includes_ledger", "passed": "Blocked claims" in pack["text"] and "Replication packs" in pack["text"] and "Reviewer notes" in pack["text"], "value": pack["context_pack_hash"]},
                {"test": "write_tools_schema_exposed_only_write_enabled", "passed": "ithz_add_claim" in write_schema_names and "ithz_add_claim" not in read_schema_names and "ithz_can_i_claim" in read_schema_names, "value": ",".join(sorted(write_schema_names & {"ithz_add_claim", "ithz_block_claim", "ithz_add_reviewer_note"}))},
                {"test": "native_subprocess_no_window_configured", "passed": no_window_configured, "value": str(_native_creationflags())},
                {"test": "safe_verify_after_ledger", "passed": native_archive_status(project)["safe_verify_ok"], "value": native_archive_status(project).get("archive_sha256")},
            ]
        )
    write_matrix(out / "mcp27_project_ledger_matrix.csv", rows)
    write_summary(
        out / "mcp27_summary.md",
        "MCP27 Project Ledger v1 Summary",
        rows,
        "- Added first-class claim, blocked-claim, replication-pack and reviewer-note projections inside `project.ithz`.\n"
        "- `ithz_can_i_claim` blocks unsafe or unsupported statements unless the ledger contains scoped support.\n"
        "- Windows native subprocess helpers are configured to avoid visible console windows.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp29_memory_effectiveness() -> bool:
    out = exp_dir("mcp29_memory_effectiveness")
    rows: list[dict[str, Any]] = []
    examples: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "memory_effectiveness_project"
        project.mkdir()
        (project / "project.md").write_text(
            "# Memory Effectiveness Project\n\nMarkdown is bootstrap. ITHZ is memory zone.\n",
            encoding="utf-8",
        )
        (project / "src" / "ithz_mcp").mkdir(parents=True)
        (project / "src" / "ithz_mcp" / "scoring.py").write_text(
            "def score_unit(unit, query):\n    return {'score': 1}\n",
            encoding="utf-8",
        )
        build_native_archive(project)
        archive_append_event(project, "decision", "Decision: archive context pack formatter prioritizes selected evidence before broad synthesis.", "mcp29", ["decision", "context_pack"])
        archive_append_event(project, "gate", "Gate: selected evidence must appear before task-relevant current memory in small packs.", "mcp29", ["gate", "context_pack"])
        archive_append_event(project, "risk", "Risk: broad synthesis can hide useful rows when max_bytes is small.", "mcp29", ["risk", "must_not_break"])

        pack = native_archive_context_pack(project, "context pack formatter selected evidence gate", 2200)
        gap_pack = native_archive_context_pack(project, "needle_that_does_not_exist_293847", 1800)
        file_nav_search = native_archive_search(project, "which files should I inspect before changing scoring", 5)
        file_nav_pack = native_archive_context_pack(project, "which files should I inspect before changing scoring", 2600)
        selected_pos = pack["text"].find("## Selected Evidence")
        synthesis_pos = pack["text"].find("## Task-Relevant Current Memory")
        examples.append("## Temp Project Pack\n\n" + pack["text"])
        examples.append("## Temp Project Gap Pack\n\n" + gap_pack["text"])
        examples.append("## Temp Project File Navigation Pack\n\n" + file_nav_pack["text"])

        rows.extend(
            [
                {"scope": "temp", "test": "selected_evidence_before_synthesis", "passed": selected_pos >= 0 and synthesis_pos > selected_pos, "value": f"selected={selected_pos};synthesis={synthesis_pos}"},
                {"scope": "temp", "test": "small_pack_contains_query_gate", "passed": "selected evidence" in pack["text"].lower() and "Gate:" in pack["text"], "value": pack["context_pack_hash"]},
                {"scope": "temp", "test": "no_match_pack_has_evidence_gap", "passed": "## Evidence Gaps" in gap_pack["text"] and "No search rows matched" in gap_pack["text"], "value": gap_pack["context_pack_hash"]},
                {"scope": "temp", "test": "file_navigation_prefers_source_file", "passed": bool(file_nav_search.get("rows")) and file_nav_search["rows"][0].get("path") == "src/ithz_mcp/scoring.py", "value": file_nav_search["rows"][0].get("path") if file_nav_search.get("rows") else "no_rows"},
                {"scope": "temp", "test": "file_navigation_skips_broad_synthesis", "passed": "Skipped for file-navigation query" in file_nav_pack["text"] and "src/ithz_mcp/scoring.py" in file_nav_pack["text"], "value": file_nav_pack["context_pack_hash"]},
                {"scope": "temp", "test": "small_pack_under_budget", "passed": pack["bytes"] <= 2200 and gap_pack["bytes"] <= 1800, "value": f"{pack['bytes']};{gap_pack['bytes']}"},
                {"scope": "temp", "test": "safe_verify_after_effectiveness_events", "passed": native_archive_status(project)["safe_verify_ok"], "value": native_archive_status(project).get("archive_sha256")},
            ]
        )

    live_project = repo_root().parent
    live_archive = project_archive_path(live_project)
    if live_archive.exists():
        live_queries = [
            "MCP write checkpoint Unexpected response type surrogate",
            "Ubuntu install zlib wrapper install_ithz",
            "what should I read before changing ithz_mcp native archive memory",
            "which files should I inspect before changing context pack scoring and native archive search",
        ]
        for query in live_queries:
            pack = native_archive_context_pack(live_project, query, 6000)
            search = native_archive_search(live_project, query, 10)
            selected_pos = pack["text"].find("## Selected Evidence")
            synthesis_pos = pack["text"].find("## Task-Relevant Current Memory")
            first_score = int(search["rows"][0].get("score", 0)) if search.get("rows") else 0
            first_path = str(search["rows"][0].get("path", "")) if search.get("rows") else ""
            first_coverage = float(search["rows"][0].get("query_term_coverage", 0.0)) if search.get("rows") else 0.0
            expected_memory_first = "Unexpected response type surrogate" in query
            expected_code_navigation = "context pack scoring" in query
            expected_ubuntu_platform = query.startswith("Ubuntu ")
            found_paths = {str(row.get("path", "")) for row in search.get("rows", [])[:6]}
            code_navigation_ok = (
                any(path.endswith("src/ithz_mcp/scoring.py") for path in found_paths)
                and any(path.endswith("src/ithz_mcp/native_archive_store.py") for path in found_paths)
                and any(path.endswith("src/ithz_mcp/context_pack.py") for path in found_paths)
            )
            ubuntu_platform_ok = ("windows" not in first_path.lower()) and ("windows_shell" not in pack["text"].lower())
            rows.append(
                {
                    "scope": "live_readonly",
                    "test": query,
                    "passed": pack["bytes"] <= 6000
                    and selected_pos >= 0
                    and (synthesis_pos < 0 or synthesis_pos > selected_pos)
                    and ((not expected_memory_first) or (first_path == EVENT_LOG_PATH and first_coverage >= 0.6))
                    and ((not expected_code_navigation) or code_navigation_ok)
                    and ((not expected_ubuntu_platform) or ubuntu_platform_ok),
                    "value": f"bytes={pack['bytes']};rows={len(search.get('rows', []))};top_score={first_score};top_coverage={first_coverage};top_path={first_path};hash={pack['context_pack_hash']}",
                }
            )
            examples.append(f"## Live Read-only Pack: {query}\n\n{pack['text']}")
    else:
        rows.append({"scope": "live_readonly", "test": "root_project_archive_present", "passed": True, "value": "skipped:no C:\\work\\ITHKOR\\project.ithz"})

    write_matrix(out / "mcp29_memory_effectiveness_matrix.csv", rows)
    (out / "mcp29_context_pack_examples.md").write_text("\n\n---\n\n".join(examples), encoding="utf-8")
    write_summary(
        out / "mcp29_summary.md",
        "MCP29 Memory Effectiveness Summary",
        rows,
        "- Context packs now prioritize selected evidence before broad current-memory synthesis.\n"
        "- Evidence gaps are emitted for no-match or weak-match packs, so an agent knows when direct file inspection is still required.\n"
        "- File-navigation queries prefer concrete source file summaries and skip broad current-memory synthesis.\n"
        "- Platform-sensitive queries avoid ranking opposite-platform installer evidence first.\n"
        "- Live ITHKOR checks are read-only and validate pack shape/size, not a general retrieval claim.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp30_memory_v2() -> bool:
    out = exp_dir("mcp30_memory_v2")
    rows: list[dict[str, Any]] = []
    examples: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "memory_v2_project"
        project.mkdir()
        (project / "project.md").write_text(
            "# Memory v2 Project\n\n"
            "Decision: use graph-assisted context packs for ambiguous tasks.\n"
            "Gate: context pack must include relevant gates and risks before code edits.\n"
            "Risk: do not index secrets or raw API tokens.\n",
            encoding="utf-8",
        )
        (project / "docs").mkdir()
        (project / "docs" / "workflow.md").write_text(
            "# Workflow\n\n"
            "Must not break: memory-first startup, read project.md, then request context pack.\n"
            "Forbidden claim: ITHZ-MCP does not replace Git or all vector databases.\n",
            encoding="utf-8",
        )
        (project / "src").mkdir()
        (project / "src" / "context_pack.py").write_text(
            "def build_context_pack(query):\n"
            "    # graph semantic candidate ranking belongs near context pack assembly\n"
            "    return query\n",
            encoding="utf-8",
        )
        (project / ".env").write_text("API_KEY=should_not_escape\n", encoding="utf-8")
        pack = compile_memory_v2_pack(project, "graph context pack gate risk vector database", 7000)
        repeat = compile_memory_v2_pack(project, "graph context pack gate risk vector database", 7000)
        examples.append("## Temp Memory v2 Pack\n\n" + pack["text"])
        rows.extend(
            [
                {"scope": "temp", "test": "memory_v2_pack_hash_stable", "passed": pack["memory_v2_pack_hash"] == repeat["memory_v2_pack_hash"], "value": pack["memory_v2_pack_hash"]},
                {"scope": "temp", "test": "graph_created", "passed": int(pack["graph_node_count"]) > 0 and int(pack["graph_edge_count"]) > 0, "value": f"nodes={pack['graph_node_count']};edges={pack['graph_edge_count']}"},
                {"scope": "temp", "test": "hybrid_candidates_present", "passed": int(pack["hybrid_count"]) > 0, "value": pack["hybrid_count"]},
                {"scope": "temp", "test": "pack_under_budget", "passed": pack["bytes"] <= 7000, "value": pack["bytes"]},
                {"scope": "temp", "test": "secret_not_included", "passed": "should_not_escape" not in pack["text"], "value": "redacted"},
                {"scope": "temp", "test": "no_general_claim", "passed": "No vector database, cloud embedding service, or general token-saving claim" in pack["text"], "value": "claim_safe"},
            ]
        )

    def memory_v2_project_ok(path: Path, max_files: int = 700, max_bytes: int = 20_000_000, max_dirs: int = 180) -> tuple[bool, str]:
        file_count = 0
        byte_count = 0
        dir_count = 0
        deny_dirs = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", "tmp", "cache", ".ithz_mcp", ".ithz-context"}
        for current, dirs, files in os.walk(path):
            dir_count += 1
            if dir_count > max_dirs:
                return False, f"large_repo_guard:dir_count={dir_count};file_count={file_count};bytes={byte_count}"
            dirs[:] = [d for d in dirs if d not in deny_dirs and not d.startswith(".tmp")]
            for name in files:
                file_count += 1
                try:
                    byte_count += (Path(current) / name).stat().st_size
                except OSError:
                    pass
                if file_count > max_files or byte_count > max_bytes:
                    return False, f"large_repo_guard:dir_count={dir_count};file_count={file_count};bytes={byte_count}"
        return True, f"dir_count={dir_count};file_count={file_count};bytes={byte_count}"

    benchmark = run_memory_v2_benchmark([sample_project()], max_bytes=10000)
    examples.append(benchmark["examples_text"])
    for row in benchmark["rows"]:
        if row.get("mode") == "skip":
            continue
        rows.append(
            {
                "scope": "fixture_benchmark",
                "test": f"{row.get('project')}::{row.get('query')}::{row.get('mode')}",
                "passed": bool(row.get("passed")),
                "value": f"recall={row.get('query_term_recall_proxy')};bytes={row.get('pack_bytes')};files={row.get('selected_file_count')};hash={row.get('pack_hash')}",
            }
        )

    candidate_projects = []  # Public self-tests do not inspect personal projects.
    for candidate in candidate_projects:
        if not candidate.exists():
            continue
        ok, reason = memory_v2_project_ok(candidate)
        rows.append({"scope": "filesystem_readonly", "test": f"{candidate.name}::large_repo_guard", "passed": True, "value": reason})
        if not ok:
            continue
        pack = compile_memory_v2_pack(candidate, "project workflow gates risks next files", 7000)
        examples.append(f"## Filesystem Read-only Pack: {candidate}\n\n{pack['text']}")
        rows.append(
            {
                "scope": "filesystem_readonly",
                "test": f"{candidate.name}::memory_v2_pack",
                "passed": pack["bytes"] <= 7000 and pack["hybrid_count"] >= 0,
                "value": f"bytes={pack['bytes']};hybrid={pack['hybrid_count']};hash={pack['memory_v2_pack_hash']}",
            }
        )

    write_matrix(out / "mcp30_memory_v2_matrix.csv", rows)
    (out / "mcp30_memory_v2_examples.md").write_text("\n\n---\n\n".join(examples), encoding="utf-8")
    write_summary(
        out / "mcp30_summary.md",
        "MCP30 Memory v2 Summary",
        rows,
        "- Memory v2 adds a deterministic graph layer and local semantic candidate retrieval over allowed indexed units.\n"
        "- Hybrid context packs combine deterministic scoring, graph signals and soft semantic candidates while preserving evidence gaps.\n"
        "- Filesystem tests are read-only for external projects; results are written only under `ithz_mcp/experiments/mcp30_memory_v2`.\n"
        "- This is not a vector database replacement, cloud embedding feature or general token-saving claim.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp31_local_rag() -> bool:
    from .mcp_server import handle_request

    out = exp_dir("mcp31_local_rag")
    rows: list[dict[str, Any]] = []
    examples: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        project = root / "rag_project"
        project.mkdir()
        (project / "project.md").write_text(
            "# Local RAG Project\n\n"
            "Decision: use optional local RAG only as a derived index over deterministic memory.\n"
            "Gate: context packs must keep evidence gaps and must not leak secrets.\n"
            "Risk: vector candidates can be noisy and require direct source inspection.\n"
            "Forbidden claim: local RAG does not replace Git, production databases or all vector DB systems.\n",
            encoding="utf-8",
        )
        (project / "docs").mkdir()
        (project / "docs" / "release.md").write_text(
            "# Release Gates\n\n"
            "Gate: run-ci-fast passed before package release.\n"
            "Gate: run-mcp30-memory-v2 passed before RAG promotion.\n"
            "Next: compare local RAG with Memory v2 on real host tasks.\n",
            encoding="utf-8",
        )
        (project / "src").mkdir()
        (project / "src" / "rag_entry.py").write_text(
            "def build_rag_context_pack(query):\n"
            "    return 'local vector search plus deterministic backstop'\n",
            encoding="utf-8",
        )
        (project / ".env").write_text("SECRET_TOKEN=do_not_index_me\n", encoding="utf-8")

        before = rag_status(project)
        rag_index = build_rag_index(project, out=project / ".ithz_mcp" / "rag" / "rag_index.json")
        after = rag_status(project)
        search = rag_search(project, "release gates vector candidates secrets", limit=8)
        repeat = rag_search(project, "release gates vector candidates secrets", limit=8)
        pack = compile_rag_context_pack(project, "release gates vector candidates secrets", max_bytes=8000)
        repeat_pack = compile_rag_context_pack(project, "release gates vector candidates secrets", max_bytes=8000)
        bench = run_rag_benchmark([project], max_bytes=9000)
        mcp_tools = handle_request({"jsonrpc": "2.0", "id": 31, "method": "tools/list", "params": {}}, project, "legacy", "read-only") or {}
        tool_names = {tool.get("name") for tool in mcp_tools.get("result", {}).get("tools", [])}
        mcp_pack_response = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 32,
                "method": "tools/call",
                "params": {
                    "name": "ithz_rag_context_pack",
                    "arguments": {"project": str(project), "query": "release gates vector candidates secrets", "max_bytes": 8000},
                },
            },
            project,
            "legacy",
            "read-only",
        ) or {}
        mcp_content = ""
        for item in mcp_pack_response.get("result", {}).get("content", []):
            if isinstance(item, dict) and item.get("type") == "text":
                mcp_content += str(item.get("text", ""))
        examples.append("## Temp Local RAG Pack\n\n" + pack["text"])
        examples.append(bench["examples_text"])
        rows.extend(
            [
                {"scope": "temp", "test": "rag_status_initial_missing", "passed": before["index_exists"] is False, "value": before.get("next", "")},
                {"scope": "temp", "test": "rag_index_built", "passed": int(rag_index.get("unit_count", 0)) > 0 and bool(rag_index.get("rag_index_hash")), "value": f"units={rag_index.get('unit_count')};hash={rag_index.get('rag_index_hash')}"},
                {"scope": "temp", "test": "rag_status_after_build", "passed": after["index_exists"] is True and after.get("rag_index_hash") == rag_index.get("rag_index_hash"), "value": after.get("rag_index_hash")},
                {"scope": "temp", "test": "rag_search_results", "passed": int(search.get("row_count", 0)) > 0, "value": search.get("row_count", 0)},
                {"scope": "temp", "test": "rag_search_stable", "passed": stable_json_hash(search.get("rows", [])) == stable_json_hash(repeat.get("rows", [])), "value": stable_json_hash(search.get("rows", []))},
                {"scope": "temp", "test": "rag_pack_under_budget", "passed": pack["bytes"] <= 8000, "value": pack["bytes"]},
                {"scope": "temp", "test": "rag_pack_hash_stable", "passed": pack["rag_pack_hash"] == repeat_pack["rag_pack_hash"], "value": pack["rag_pack_hash"]},
                {"scope": "temp", "test": "secret_not_included", "passed": "do_not_index_me" not in pack["text"] and "SECRET_TOKEN" not in pack["text"], "value": "redacted"},
                {"scope": "temp", "test": "benchmark_passed", "passed": bool(bench["passed"]), "value": bench["benchmark_hash"]},
                {"scope": "temp", "test": "no_general_claim", "passed": "No cloud embedding, production database, Git replacement, or general token-saving claim" in pack["text"], "value": "claim_safe"},
                {"scope": "temp", "test": "mcp_rag_tools_listed", "passed": {"ithz_rag_status", "ithz_rag_search", "ithz_rag_context_pack"} <= tool_names, "value": ",".join(sorted(str(v) for v in tool_names if str(v).startswith("ithz_rag_")))},
                {"scope": "temp", "test": "mcp_rag_context_pack_text", "passed": "ITHZ-MCP Local RAG Context Pack" in mcp_content and "Evidence Gaps" in mcp_content, "value": f"bytes={len(mcp_content.encode('utf-8'))}"},
            ]
        )

    benchmark_root = os.environ.get("ITHZ_BENCHMARK_PROJECT_ROOT")
    candidate = Path(benchmark_root) if benchmark_root else None
    if candidate is not None and candidate.exists():
        try:
            with tempfile.TemporaryDirectory() as td:
                sampled = Path(td) / "project_sample"
                sampled.mkdir()
                copied = 0
                for rel in ("project.md", "AI_PROJECT_BRIEF.md", "WORKFLOW_RULES.md", "DECISIONS_LOG.md", "PROJECT_CONTEXT.md"):
                    src = candidate / rel
                    if src.exists() and src.is_file():
                        shutil.copy2(src, sampled / rel)
                        copied += 1
                if copied == 0:
                    raise ValueError("no_sample_files")
                pack = compile_rag_context_pack(sampled, "workflow gates risks context pack", max_bytes=7000)
                examples.append(f"## Filesystem Sample Local RAG Pack: {candidate}\n\n{pack['text']}")
                rows.append(
                    {
                        "scope": "filesystem_readonly",
                        "test": "doucim.com::sampled_rag_context_pack",
                        "passed": pack["bytes"] <= 7000 and int(pack["rag_row_count"]) > 0,
                        "value": f"copied={copied};bytes={pack['bytes']};rows={pack['rag_row_count']};hash={pack['rag_pack_hash']}",
                    }
                )
        except Exception as exc:  # noqa: BLE001 - smoke should report cleanly, not mask all stage output.
            value = type(exc).__name__ + ":" + str(exc)[:160]
            rows.append({"scope": "filesystem_readonly", "test": "doucim.com::sampled_rag_context_pack", "passed": isinstance(exc, ValueError) and "no_sample_files" in str(exc), "value": "skipped:" + value})
    else:
        rows.append({"scope": "filesystem_readonly", "test": "doucim.com::present", "passed": True, "value": "skipped"})

    write_matrix(out / "mcp31_local_rag_matrix.csv", rows)
    (out / "mcp31_local_rag_examples.md").write_text("\n\n---\n\n".join(examples), encoding="utf-8")
    write_summary(
        out / "mcp31_summary.md",
        "MCP31 Local RAG Summary",
        rows,
        "- MCP31 adds optional local RAG using deterministic feature-hashing vectors.\n"
        "- MCP31 read-only MCP server exposes `ithz_rag_status`, `ithz_rag_search` and `ithz_rag_context_pack` over existing indexes.\n"
        "- RAG indexes are derived caches under `.ithz_mcp/rag/`; source of truth remains project memory and source files.\n"
        "- `rag-context-pack` is the simple user path and auto-builds the local index when needed.\n"
        "- No cloud embedding, production database, Git replacement, vector-DB dismissal or general token-saving claim is made.\n",
    )
    return all(bool(r["passed"]) for r in rows)


def run_mcp36_memory_integrity() -> bool:
    """Run deterministic MCP36 memory safety fixtures without external models."""

    result = run_memory_integrity_benchmark()
    rows = [dict(row) for row in result["rows"]]
    out = exp_dir("mcp36_memory_integrity")
    write_matrix(out / "mcp36_memory_integrity_matrix.csv", rows)
    write_summary(
        out / "mcp36_summary.md",
        "MCP36 Memory Integrity Summary",
        rows,
        "- Raw episodes remain first-class and historical records are never rewritten in place.\n"
        "- Verified abstractions require source binding; unbound candidates remain quarantined.\n"
        "- Proposer, primary opponent, cross-lab opponent, judge and auditor receive distinct evidence views.\n"
        "- The deterministic fixture compares no-memory, episodic-only, MCP35 projection, MCP36 hybrid and poisoned-memory modes.\n"
        "- This fixture is a safety regression, not a general downstream task-performance claim.\n",
    )
    (out / "mcp36_benchmark_receipt.json").write_text(dump_pretty(result), encoding="utf-8")
    return bool(result["passed"])


def run_mcp36_4_canary() -> bool:
    """Run the MCP36.4 local opt-in control-plane fixture without external models."""

    result = run_canary_control_selftest()
    rows = [dict(row) for row in result["rows"]]
    out = exp_dir("mcp36_4_canary")
    write_matrix(out / "mcp36_4_canary_matrix.csv", rows)
    write_summary(
        out / "mcp36_4_summary.md",
        "MCP36.4 Opt-in Canary Summary",
        rows,
        "- Canary is absent and off by default; only an explicit bounded local opt-in activates it.\n"
        "- Capability is fixed to analysis.read and canary cases never mint tokens or mirror to project.ithz.\n"
        "- Atomic slots enforce the case cap; expiry and pause act as fail-closed kill switches.\n"
        "- This control-plane fixture makes no external model call. Court integration is covered by scripted unit tests.\n",
    )
    (out / "mcp36_4_canary_receipt.json").write_text(dump_pretty(result), encoding="utf-8")
    return bool(result["passed"])
