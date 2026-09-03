from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import version_info
from .agent_history_import import archive_import_agent_history, discover_agent_history
from .agent_intake import first_project_agent_intake
from .canonical_json import dump_pretty, dumps
from .context_index import build_index, search_context, why_file, load_or_build_index
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
)
from .host_install import write_host_install_bundle
from .git_merge_driver import git_diff_ithz, git_driver_status, git_merge_ithz, install_git_drivers
from .bootstrap_contract import bootstrap_dry_run, ensure_project_bootstrap_file, write_templates
from .context_compiler import run_context_compiler_benchmark
from .instruction_memory import durable_instruction_status, ingest_user_instruction, record_durable_instruction
from .invariant_diff import run_invariant_diff, terminal_summary, write_html_report, write_json_report
from .markdown_audit import audit_markdown_memory, markdown_reduction_plan, migration_plan
from .memory_v2 import compile_memory_v2_pack, run_memory_v2_benchmark
from .memory_integrity import memory_integrity_status
from .mcp_server import client_smoke, serve_stdio
from .mcp_config import config_template, scripted_client_smoke, validate_config
from .native_ithz_adapter import import_native_ithz, native_context_pack, native_status
from .native_archive_store import (
    archive_cross_zone_context_pack,
    archive_append_event,
    archive_append_memory_record,
    archive_compile_memory_synthesis,
    archive_create_snapshot,
    archive_link_zone,
    archive_memory_index_status,
    archive_record_cross_zone_event,
    archive_rebuild_derived_indexes,
    archive_zone_status,
    build_native_archive,
    native_archive_context_pack,
    native_archive_current_projection,
    native_archive_record_prompt_response,
    native_archive_search,
    native_archive_status,
)
from .prompt_memory import prompt_context_pack, prompt_log, prompt_memory_status, prompt_search, record_prompt_response
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
from .focus_context import DEFAULT_MAX_BYTES as FOCUS_MAX_BYTES, DEFAULT_TARGET_BYTES as FOCUS_TARGET_BYTES, compile_focus_context_pack
from .quality_regression import run_quality_regression
from .rag import build_rag_index, compile_rag_context_pack, rag_search, rag_status, run_rag_benchmark
from .project_scan import scan_project
from .project_installer import install_project, uninstall_project
from .task_checkpoint import archive_finalize_task, archive_ingest_project_memory, run_archive_finalize_task_worker
from .workflow_profiles import (
    archive_adopt_project_workflow,
    archive_update_workflow_profile,
    workflow_context_pack,
    workflow_profile_status,
)
from .selftest import (
    run_ci_fast,
    run_ci_full,
    run_mcp10_markdown_minimal,
    run_mcp11_external_client,
    run_mcp12_prompt_memory,
    run_mcp13_host_compat,
    run_mcp14_rc5_package,
    run_mcp16_git_merge_driver,
    run_mcp17_append_index_snapshot,
    run_mcp18_end_task_checkpoint,
    run_mcp19_workflow_branches,
    run_mcp20_agent_history_import,
    run_mcp21_production_readiness,
    run_mcp22_auto_checkpoint,
    run_mcp23_install_project,
    run_mcp24_durable_instructions,
    run_mcp25_macos_package,
    run_mcp26_memory_synthesis,
    run_mcp27_project_ledger,
    run_mcp28_ubuntu_package,
    run_mcp29_memory_effectiveness,
    run_mcp30_memory_v2,
    run_mcp31_local_rag,
    run_mcp36_memory_integrity,
    run_mcp36_4_canary,
    run_mcp8_hardening,
    run_mcp9f_native_ithz,
    run_mcp0,
    run_mcp1,
    run_mcp2,
    run_mcp3,
    run_mcp4,
    run_mcp5,
    run_mcp6,
    run_mcp7,
)
from .store_layout import context_store_status, ensure_context_store, migration_dry_run
from .storage import init_project, state_dir, write_json


def emit(value: Any) -> None:
    if isinstance(value, str):
        print(value)
    else:
        print(dump_pretty(value), end="")


def require_project(path: str | None) -> Path:
    return Path(path or ".").resolve()


def command_version(args: argparse.Namespace) -> int:
    emit(version_info())
    return 0


def command_init(args: argparse.Namespace) -> int:
    emit(init_project(require_project(args.project)))
    return 0


def command_scan(args: argparse.Namespace) -> int:
    result = scan_project(require_project(args.project))
    if args.out:
        write_json(Path(args.out), result)
    else:
        emit(result)
    return 0


def command_build_index(args: argparse.Namespace) -> int:
    init_project(require_project(args.project))
    emit(build_index(require_project(args.project)))
    return 0


def command_search(args: argparse.Namespace) -> int:
    rows = search_context(require_project(args.project), args.query, args.limit)
    if args.json:
        emit(rows)
    else:
        for r in rows:
            print(f"{r['score']:>4} {r['path']}:{r['line']} {r['kind']} {r['text']}")
    return 0


def command_pack(args: argparse.Namespace) -> int:
    pack = build_context_pack(require_project(args.project), args.query, args.max_bytes)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
    else:
        print(pack["text"])
    print(f"semantic_context_pack_hash={pack['semantic_context_pack_hash']}")
    return 0


def command_status(args: argparse.Namespace) -> int:
    project = require_project(args.project)
    index = load_or_build_index(project) if (state_dir(project) / "index" / "index.json").exists() else None
    commits = context_log(project) if state_dir(project).exists() else []
    emit(
        {
            "project": str(project),
            "state_exists": state_dir(project).exists(),
            "readonly_mode": True,
            "index_hash": index.get("index_hash") if index else None,
            "project_semantic_hash": index.get("project_semantic_hash") if index else None,
            "context_commit_count": len(commits),
        }
    )
    return 0


def command_why(args: argparse.Namespace) -> int:
    emit(why_file(require_project(args.project), args.path))
    return 0


def command_self_test(args: argparse.Namespace) -> int:
    ok = run_mcp0()
    if args.verbose:
        print("MCP0 self-test passed" if ok else "MCP0 self-test failed")
    return 0 if ok else 5


def command_mcp_server(args: argparse.Namespace) -> int:
    project = require_project(args.project)
    if args.smoke:
        transcript = client_smoke(project)
        emit({"server": "stdio-json-rpc-shim", "mode": args.mode, "smoke": True, "passed": all(t["response"] is None or "result" in t["response"] or "error" in t["response"] for t in transcript)})
        return 0
    serve_stdio(project, sys.stdin, sys.stdout, args.protocol, args.storage_profile, args.mode)
    return 0


def command_ccg_mcp_server(args: argparse.Namespace) -> int:
    from .ccg.mcp_server import serve_stdio as serve_ccg_stdio

    serve_ccg_stdio(require_project(args.project), sys.stdin, sys.stdout)
    return 0


def command_ccg_settings(args: argparse.Namespace) -> int:
    from .ccg.settings_server import run_settings_server

    return run_settings_server(args.port, not args.no_open)


def command_mcp_client_smoke(args: argparse.Namespace) -> int:
    if args.config:
        result = scripted_client_smoke(Path(args.config), Path(args.out) if args.out else None)
        emit({k: v for k, v in result.items() if k != "transcript"})
        return 0 if result["passed"] else 5
    project = require_project(args.project)
    transcript = client_smoke(project)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        with Path(args.out).open("w", encoding="utf-8", newline="\n") as f:
            for row in transcript:
                f.write(dumps(row) + "\n")
    emit({"passed": True, "requests": len(transcript), "project": str(project)})
    return 0


def command_mcp_config_template(args: argparse.Namespace) -> int:
    config = config_template(require_project(args.project), args.client, args.storage_profile, args.mode)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(dump_pretty(config), encoding="utf-8")
    emit({"out": args.out, "client": args.client, "project": str(require_project(args.project)), "storage_profile": args.storage_profile, "mode": args.mode})
    return 0


def command_init_native_archive_memory(args: argparse.Namespace) -> int:
    emit(build_native_archive(require_project(args.project), args.native_exe, args.verify, args.include_child_zones, args.index_mode, args.include_source_snapshot))
    return 0


def command_install_project(args: argparse.Namespace) -> int:
    emit(
        install_project(
            require_project(args.project),
            apply=args.apply,
            profile=args.profile,
            owner=args.owner,
            native_exe=args.native_exe,
            include_child_zones=args.include_child_zones,
            import_agent_history=args.import_agent_history,
            history_sources=args.history_source,
            history_roots=[Path(p) for p in (args.history_root or [])],
            install_codex_config=args.install_codex_config,
            install_git_driver=not args.no_git_driver,
            index_mode=args.index_mode,
            keep_install_artifacts=args.keep_install_artifacts,
            agent_intake=args.agent_intake,
        )
    )
    return 0


def command_agent_intake_project(args: argparse.Namespace) -> int:
    emit(
        first_project_agent_intake(
            require_project(args.project),
            args.owner or "",
            args.profile,
            args.mode,
            args.native_exe,
        )
    )
    return 0


def command_uninstall_project(args: argparse.Namespace) -> int:
    emit(
        uninstall_project(
            require_project(args.project),
            apply=args.apply,
            keep_project_md=args.keep_project_md,
            keep_host_configs=args.keep_host_configs,
        )
    )
    return 0


def command_archive_memory_status(args: argparse.Namespace) -> int:
    emit(native_archive_status(require_project(args.project), args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_archive_search_context(args: argparse.Namespace) -> int:
    emit(native_archive_search(require_project(args.project), args.query, args.limit, args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_archive_get_context_pack(args: argparse.Namespace) -> int:
    pack = native_archive_context_pack(require_project(args.project), args.query, args.max_bytes, args.native_exe, args.memory_zone, args.memory_zone_path)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
    else:
        print(pack["text"])
    print(f"archive_context_pack_hash={pack['context_pack_hash']}")
    return 0


def command_archive_record_prompt_response(args: argparse.Namespace) -> int:
    emit(native_archive_record_prompt_response(require_project(args.project), Path(args.prompt), Path(args.response), args.task, args.mode, args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_archive_ingest_project_memory(args: argparse.Namespace) -> int:
    emit(
        archive_ingest_project_memory(
            require_project(args.project),
            [Path(p) for p in args.source],
            args.note or "",
            args.native_exe,
            args.memory_zone,
            args.memory_zone_path,
            args.include_git,
        )
    )
    return 0


def command_archive_finalize_task(args: argparse.Namespace) -> int:
    emit(
        archive_finalize_task(
            require_project(args.project),
            args.task,
            args.summary_text or "",
            Path(args.summary) if args.summary else None,
            args.decision or [],
            args.gate or [],
            args.risk or [],
            args.next or [],
            args.changed_file or [],
            args.command or [],
            args.docs_impact,
            args.memory_impact,
            Path(args.prompt) if args.prompt else None,
            Path(args.response) if args.response else None,
            args.prompt_mode,
            args.snapshot,
            args.snapshot_mode,
            args.native_exe,
            args.memory_zone,
            args.memory_zone_path,
            args.include_git,
        )
    )
    return 0


def command_archive_finalize_task_worker(args: argparse.Namespace) -> int:
    emit(run_archive_finalize_task_worker(Path(args.input)))
    return 0


def command_workflow_profile_status(args: argparse.Namespace) -> int:
    emit(workflow_profile_status(require_project(args.project), args.native_exe))
    return 0


def command_archive_adopt_project_workflow(args: argparse.Namespace) -> int:
    project = require_project(args.project)
    result = archive_adopt_project_workflow(
            project,
            args.profile,
            args.owner or "",
            Path(args.prompt) if args.prompt else None,
            not args.no_existing_md,
            args.native_exe,
        )
    if args.import_agent_history:
        result["agent_history_import"] = archive_import_agent_history(
            project,
            args.history_source or None,
            [Path(p) for p in (args.history_root or [])],
            args.max_history_records,
            True,
            args.native_exe,
            args.history_author or args.owner,
            args.history_imported_at,
        )
    emit(result)
    return 0


def command_workflow_ingest_prompt(args: argparse.Namespace) -> int:
    emit(
        archive_update_workflow_profile(
            require_project(args.project),
            args.profile,
            args.owner or "",
            Path(args.prompt) if args.prompt else None,
            [Path(p) for p in (args.source or [])],
            args.note or "",
            args.native_exe,
            args.set_default,
        )
    )
    return 0


def command_workflow_context_pack(args: argparse.Namespace) -> int:
    pack = workflow_context_pack(require_project(args.project), args.profile, args.query, args.max_bytes, args.native_exe)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
    else:
        print(pack["text"])
    print(f"workflow_context_pack_hash={pack['context_pack_hash']}")
    return 0


def command_agent_history_discover(args: argparse.Namespace) -> int:
    emit(discover_agent_history(require_project(args.project), args.source or None, [Path(p) for p in (args.root or [])], args.max_records, args.author))
    return 0


def command_archive_import_agent_history(args: argparse.Namespace) -> int:
    emit(
        archive_import_agent_history(
            require_project(args.project),
            args.source or None,
            [Path(p) for p in (args.root or [])],
            args.max_records,
            args.apply,
            args.native_exe,
            args.author,
            args.imported_at,
        )
    )
    return 0


def command_archive_link_zone(args: argparse.Namespace) -> int:
    emit(archive_link_zone(require_project(args.project), args.zone, Path(args.path), args.native_exe, args.memory_zone, args.memory_zone_path, args.relationship))
    return 0


def command_archive_zone_status(args: argparse.Namespace) -> int:
    emit(archive_zone_status(require_project(args.project), args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_archive_cross_zone_context_pack(args: argparse.Namespace) -> int:
    pack = archive_cross_zone_context_pack(require_project(args.project), args.query, args.max_bytes, args.native_exe, args.memory_zone, args.memory_zone_path)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
    else:
        print(pack["text"])
    print(f"cross_zone_context_pack_hash={pack['context_pack_hash']}")
    return 0


def command_archive_record_cross_zone_event(args: argparse.Namespace) -> int:
    emit(archive_record_cross_zone_event(require_project(args.project), args.target_zone, args.event, args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_archive_append_event(args: argparse.Namespace) -> int:
    emit(archive_append_event(require_project(args.project), args.kind, args.text, args.source, args.tag or [], args.native_exe, args.memory_zone, args.memory_zone_path, args.include_git))
    return 0


def command_durable_instruction_status(args: argparse.Namespace) -> int:
    emit(durable_instruction_status(require_project(args.project), args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_record_durable_instruction(args: argparse.Namespace) -> int:
    text = args.text
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    emit(
        record_durable_instruction(
            require_project(args.project),
            args.instruction_type,
            text,
            args.profile,
            args.scope,
            args.source,
            args.tag or [],
            {},
            args.native_exe,
            args.memory_zone,
            args.memory_zone_path,
            args.include_git,
        )
    )
    return 0


def command_ingest_user_instruction(args: argparse.Namespace) -> int:
    text = args.text
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    emit(
        ingest_user_instruction(
            require_project(args.project),
            text,
            args.profile,
            args.scope,
            args.source,
            args.native_exe,
            args.memory_zone,
            args.memory_zone_path,
            args.include_git,
        )
    )
    return 0


def command_archive_memory_index_status(args: argparse.Namespace) -> int:
    emit(archive_memory_index_status(require_project(args.project), args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_archive_rebuild_derived_indexes(args: argparse.Namespace) -> int:
    emit(archive_rebuild_derived_indexes(require_project(args.project), args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_archive_compile_memory_synthesis(args: argparse.Namespace) -> int:
    emit(archive_compile_memory_synthesis(require_project(args.project), args.native_exe, args.memory_zone, args.memory_zone_path))
    return 0


def command_archive_create_snapshot(args: argparse.Namespace) -> int:
    emit(archive_create_snapshot(require_project(args.project), args.label, args.native_exe, args.memory_zone, args.memory_zone_path, args.mode))
    return 0


def command_ledger_add_claim(args: argparse.Namespace) -> int:
    emit(add_claim(require_project(args.project), args.text, args.claim_id, args.scope, args.supporting_gate or [], args.status, args.source, args.native_exe, args.memory_zone, args.memory_zone_path, args.include_git))
    return 0


def command_ledger_block_claim(args: argparse.Namespace) -> int:
    emit(block_claim(require_project(args.project), args.text, args.reason, args.claim_id, args.blocking_gate or [], args.status, args.source, args.native_exe, args.memory_zone, args.memory_zone_path, args.include_git))
    return 0


def command_ledger_list_allowed_claims(args: argparse.Namespace) -> int:
    emit(list_allowed_claims(require_project(args.project), args.native_exe))
    return 0


def command_ledger_list_blocked_claims(args: argparse.Namespace) -> int:
    emit(list_blocked_claims(require_project(args.project), args.native_exe))
    return 0


def command_ledger_get_claim_evidence(args: argparse.Namespace) -> int:
    emit(get_claim_evidence(require_project(args.project), args.query, args.native_exe))
    return 0


def command_ledger_can_i_claim(args: argparse.Namespace) -> int:
    claim = getattr(args, "claim", None) or getattr(args, "query", None)
    if not claim:
        raise SystemExit("ithz-can-i-claim requires --claim")
    emit(can_i_claim(require_project(args.project), claim, args.native_exe))
    return 0


def command_ledger_add_reviewer_note(args: argparse.Namespace) -> int:
    emit(add_reviewer_note(require_project(args.project), args.text, args.target, args.note_id, args.severity, args.source, args.native_exe, args.memory_zone, args.memory_zone_path, args.include_git))
    return 0


def command_ledger_create_replication_pack(args: argparse.Namespace) -> int:
    emit(create_replication_pack_record(require_project(args.project), args.pack_id, args.witnesses, args.positive, args.negative_stop, args.manifest_path, args.public_safe, args.status, args.source, args.native_exe, args.memory_zone, args.memory_zone_path, args.include_git))
    return 0


def command_ledger_summary(args: argparse.Namespace) -> int:
    emit(project_ledger_summary(require_project(args.project), args.native_exe))
    return 0


def command_mcp_config_validate(args: argparse.Namespace) -> int:
    result = validate_config(Path(args.config))
    emit({k: v for k, v in result.items() if k != "server"})
    return 0 if result["passed"] else 5


def command_write_host_installers(args: argparse.Namespace) -> int:
    emit(
        write_host_install_bundle(
            require_project(args.project),
            Path(args.out),
            Path(args.launcher) if args.launcher else None,
            args.storage_profile,
        )
    )
    return 0


def command_import_native_ithz(args: argparse.Namespace) -> int:
    if args.mode != "read-only":
        raise ValueError("only read-only native import is supported")
    emit(import_native_ithz(Path(args.workspace), Path(args.project)))
    return 0


def command_native_status(args: argparse.Namespace) -> int:
    emit(native_status(Path(args.workspace)))
    return 0


def command_native_pack(args: argparse.Namespace) -> int:
    project = require_project(args.project)
    pack = native_context_pack(project, args.query, args.max_bytes)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
    else:
        print(pack["text"])
    print(f"native_context_pack_hash={pack['context_pack_hash']}")
    return 0


def command_init_minimal_memory(args: argparse.Namespace) -> int:
    project = require_project(args.project)
    result = ensure_context_store(project)
    project_bootstrap = ensure_project_bootstrap_file(project)
    dry = bootstrap_dry_run(project, "minimal", force=False, apply=False)
    emit({"store": result, "project_bootstrap": project_bootstrap, "bootstrap": dry})
    return 0


def command_audit_markdown(args: argparse.Namespace) -> int:
    emit(audit_markdown_memory(require_project(args.project)))
    return 0


def command_suggest_markdown_reduction(args: argparse.Namespace) -> int:
    text = markdown_reduction_plan(require_project(args.project))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(text, encoding="utf-8")
    print(args.out)
    return 0


def command_context_store_status(args: argparse.Namespace) -> int:
    emit(context_store_status(require_project(args.project)))
    return 0


def command_migrate_store_name(args: argparse.Namespace) -> int:
    emit(migration_dry_run(require_project(args.project), args.from_name, args.to_name, args.apply))
    return 0


def command_context_compiler_benchmark(args: argparse.Namespace) -> int:
    rows = run_context_compiler_benchmark([require_project(args.project)])
    emit({"rows": rows, "row_count": len(rows)})
    return 0


def command_memory_v2_context_pack(args: argparse.Namespace) -> int:
    pack = compile_memory_v2_pack(require_project(args.project), args.query, args.max_bytes)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
        print(args.out)
    else:
        print(pack["text"], end="")
    return 0


def command_memory_v2_benchmark(args: argparse.Namespace) -> int:
    result = run_memory_v2_benchmark([require_project(args.project)], max_bytes=args.max_bytes)
    emit({"passed": result["passed"], "benchmark_hash": result["benchmark_hash"], "row_count": len(result["rows"]), "rows": result["rows"]})
    return 0 if result["passed"] else 5


def command_rag_status(args: argparse.Namespace) -> int:
    emit(rag_status(require_project(args.project)))
    return 0


def command_rag_index_build(args: argparse.Namespace) -> int:
    project = require_project(args.project)
    out_path = None
    if not args.no_write:
        from .rag import rag_index_path

        out_path = rag_index_path(project)
    result = build_rag_index(project, args.dimensions, out=out_path)
    if out_path is not None:
        result["index_path"] = str(out_path)
    emit(
        {
            "schema": result.get("schema"),
            "project": result.get("project"),
            "unit_count": result.get("unit_count"),
            "dimensions": result.get("dimensions"),
            "embedding_backend": result.get("embedding_backend"),
            "rag_index_hash": result.get("rag_index_hash"),
            "index_path": result.get("index_path"),
            "build_ms": result.get("build_ms"),
        }
    )
    return 0


def command_rag_search(args: argparse.Namespace) -> int:
    emit(rag_search(require_project(args.project), args.query, args.limit, args.rebuild, write_cache=not args.no_cache, write_index=not args.read_only_index))
    return 0


def command_rag_context_pack(args: argparse.Namespace) -> int:
    pack = compile_rag_context_pack(require_project(args.project), args.query, args.max_bytes, args.rebuild, write_cache=not args.no_cache, write_index=not args.read_only_index)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
        print(args.out)
    else:
        print(pack["text"], end="")
    return 0


def command_focus_context_pack(args: argparse.Namespace) -> int:
    pack = compile_focus_context_pack(require_project(args.project), args.query, args.target_bytes, args.max_bytes)
    if args.json_output:
        emit(pack)
    elif args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
        emit(
            {
                "out": args.out,
                "bytes": pack["bytes"],
                "source_pack_bytes": pack["source_pack_bytes"],
                "bytes_saved_vs_source": pack["bytes_saved_vs_source"],
                "estimated_tokens_saved_vs_source": pack["estimated_tokens_saved_vs_source"],
                "escalated": pack["escalated"],
                "fallback_required": pack["fallback_required"],
                "focus_pack_hash": pack["focus_pack_hash"],
            }
        )
    else:
        print(pack["text"], end="")
    return 0


def command_rag_benchmark(args: argparse.Namespace) -> int:
    result = run_rag_benchmark([require_project(args.project)], max_bytes=args.max_bytes)
    emit({"passed": result["passed"], "benchmark_hash": result["benchmark_hash"], "row_count": len(result["rows"]), "rows": result["rows"]})
    return 0 if result["passed"] else 5


def command_git_diff_ithz(args: argparse.Namespace) -> int:
    print(git_diff_ithz(Path(args.archive)), end="")
    return 0


def command_ithz_diff(args: argparse.Namespace) -> int:
    report = run_invariant_diff(Path(args.left), Path(args.right), args.mode, args.ignore_order)
    if args.json:
        write_json_report(report, Path(args.json))
    if args.report:
        write_html_report(report, Path(args.report))
    if args.canonical_hashes:
        write_json_report({"canonical_hashes": report.get("canonical_hashes", {})}, Path(args.canonical_hashes))
    if args.json_output:
        emit(report)
    else:
        print(terminal_summary(report), end="")
    return 0


def command_git_merge_ithz(args: argparse.Namespace) -> int:
    result = git_merge_ithz(Path(args.base), Path(args.ours), Path(args.theirs), Path(args.out), Path(args.report) if args.report else None)
    emit(result)
    return 1 if result.get("merge_needed") else 0


def command_install_git_drivers(args: argparse.Namespace) -> int:
    emit(install_git_drivers(require_project(args.repo), args.dry_run))
    return 0


def command_git_driver_status(args: argparse.Namespace) -> int:
    emit(git_driver_status(require_project(args.repo)))
    return 0


def command_context_quality_regression(args: argparse.Namespace) -> int:
    result = run_quality_regression(require_project(args.project))
    emit({"passed": result["passed"], "row_count": len(result["rows"]), "rows": result["rows"]})
    return 0 if result["passed"] else 5


def command_prompt_memory_status(args: argparse.Namespace) -> int:
    emit(prompt_memory_status(require_project(args.project)))
    return 0


def command_record_prompt_response(args: argparse.Namespace) -> int:
    emit(record_prompt_response(require_project(args.project), Path(args.prompt), Path(args.response), args.task, args.mode))
    return 0


def command_prompt_log(args: argparse.Namespace) -> int:
    emit(prompt_log(require_project(args.project)))
    return 0


def command_prompt_search(args: argparse.Namespace) -> int:
    emit(prompt_search(require_project(args.project), args.query, args.limit))
    return 0


def command_prompt_context_pack(args: argparse.Namespace) -> int:
    pack = prompt_context_pack(require_project(args.project), args.query, args.max_bytes)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(pack["text"], encoding="utf-8")
    else:
        print(pack["text"])
    print(f"prompt_context_pack_hash={pack['context_pack_hash']}")
    return 0


def command_plan_markdown_migration(args: argparse.Namespace) -> int:
    rows, text = migration_plan(require_project(args.project))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(text, encoding="utf-8")
    emit({"out": args.out, "rows": rows})
    return 0


def command_apply_markdown_migration(args: argparse.Namespace) -> int:
    emit({"project": str(require_project(args.project)), "plan": args.plan, "dry_run": args.dry_run, "applied": False, "files_moved_or_deleted": 0})
    return 0


def command_write_bootstrap_files(args: argparse.Namespace) -> int:
    emit(bootstrap_dry_run(require_project(args.project), args.mode, args.force, apply=not args.dry_run))
    return 0


def command_record_summary(args: argparse.Namespace) -> int:
    from .events import record_task_summary

    emit(record_task_summary(require_project(args.project), Path(args.summary)))
    return 0


def command_context_commit(args: argparse.Namespace) -> int:
    emit(
        context_commit(
            require_project(args.project),
            args.task,
            Path(args.summary) if args.summary else None,
            args.include_git,
            args.private,
            args.prompt_id,
            args.response_id,
        )
    )
    return 0


def command_context_log(args: argparse.Namespace) -> int:
    emit(context_log(require_project(args.project)))
    return 0


def command_context_diff(args: argparse.Namespace) -> int:
    emit(context_diff(require_project(args.project), args.from_ref, args.to_ref))
    return 0


def command_context_branch(args: argparse.Namespace) -> int:
    emit(context_branch(require_project(args.project), args.name))
    return 0


def command_context_checkout(args: argparse.Namespace) -> int:
    emit({"ref": args.ref, "read_only": args.read_only, "working_tree_changed": False})
    return 0


def command_context_tag(args: argparse.Namespace) -> int:
    emit(context_tag(require_project(args.project), args.name, args.force))
    return 0


def command_git_status(args: argparse.Namespace) -> int:
    emit(git_status(require_project(args.project)))
    return 0


def command_context_for_git_diff(args: argparse.Namespace) -> int:
    status = git_status(require_project(args.project))
    pack = build_context_pack(require_project(args.project), " ".join(status.get("git_dirty_files", [])) or "git diff", 12000)
    emit({"git": status, "context_pack_hash": pack["semantic_context_pack_hash"], "context_pack_bytes": pack["bytes"]})
    return 0


def command_decisions_between_git(args: argparse.Namespace) -> int:
    emit(decisions_between_git(require_project(args.project), args.from_hash, args.to_hash))
    return 0


def command_context_remote(args: argparse.Namespace) -> int:
    if args.remote_command == "add":
        emit(add_remote(require_project(args.project), args.name, Path(args.path)))
    elif args.remote_command == "list":
        from .storage import read_json

        emit(read_json(state_dir(require_project(args.project)) / "remotes.json", {"remotes": {}}))
    return 0


def command_context_push(args: argparse.Namespace) -> int:
    emit(push_context(require_project(args.project), args.remote))
    return 0


def command_context_pull(args: argparse.Namespace) -> int:
    emit(pull_context(require_project(args.project), args.remote))
    return 0


def command_context_merge(args: argparse.Namespace) -> int:
    emit({"branch": args.branch, "merge_commit": "plan_only_mvp", "source_tree_changed": False})
    return 0


def command_benchmark(args: argparse.Namespace) -> int:
    ok = run_mcp3()
    return 0 if ok else 5


def command_adopt(args: argparse.Namespace) -> int:
    project = require_project(args.project)
    init_project(project)
    build_index(project)
    emit({"project": str(project), "mode": args.mode, "app_code_changed": False})
    return 0


def command_memory_integrity_status(args: argparse.Namespace) -> int:
    project = require_project(args.project)
    projection = native_archive_current_projection(project, args.query, 8)
    emit(memory_integrity_status(projection))
    return 0


def command_archive_append_memory_record(args: argparse.Namespace) -> int:
    record_path = Path(args.record).resolve()
    record = json.loads(record_path.read_text(encoding="utf-8-sig"))
    if not isinstance(record, dict):
        raise ValueError("memory_record_file_must_contain_json_object")
    emit(
        archive_append_memory_record(
            require_project(args.project),
            record,
            None,
            args.memory_zone,
            args.memory_zone_path,
            bool(args.include_git),
        )
    )
    return 0


def run_stage(stage: str) -> int:
    runners = {
        "run-mcp0": run_mcp0,
        "run-mcp1": run_mcp1,
        "run-mcp2": run_mcp2,
        "run-mcp3": run_mcp3,
        "run-mcp4": run_mcp4,
        "run-mcp5": run_mcp5,
        "run-mcp6": run_mcp6,
        "run-mcp7": run_mcp7,
        "run-mcp8-hardening": run_mcp8_hardening,
        "run-mcp9f-native-ithz": run_mcp9f_native_ithz,
        "run-mcp10-markdown-minimal": run_mcp10_markdown_minimal,
        "run-mcp11-external-client": run_mcp11_external_client,
        "run-mcp12-prompt-memory": run_mcp12_prompt_memory,
        "run-mcp13-host-compat": run_mcp13_host_compat,
        "run-mcp14-rc5-package": run_mcp14_rc5_package,
        "run-mcp16-git-merge-driver": run_mcp16_git_merge_driver,
        "run-mcp17-append-index-snapshot": run_mcp17_append_index_snapshot,
        "run-mcp18-end-task-checkpoint": run_mcp18_end_task_checkpoint,
        "run-mcp19-workflow-branches": run_mcp19_workflow_branches,
        "run-mcp20-agent-history-import": run_mcp20_agent_history_import,
        "run-mcp21-production-readiness": run_mcp21_production_readiness,
        "run-mcp22-auto-checkpoint": run_mcp22_auto_checkpoint,
        "run-mcp23-install-project": run_mcp23_install_project,
        "run-mcp24-durable-instructions": run_mcp24_durable_instructions,
        "run-mcp25-macos-package": run_mcp25_macos_package,
        "run-mcp26-memory-synthesis": run_mcp26_memory_synthesis,
        "run-mcp27-project-ledger": run_mcp27_project_ledger,
        "run-mcp28-ubuntu-package": run_mcp28_ubuntu_package,
        "run-mcp29-memory-effectiveness": run_mcp29_memory_effectiveness,
        "run-mcp30-memory-v2": run_mcp30_memory_v2,
        "run-mcp31-local-rag": run_mcp31_local_rag,
        "run-mcp36-memory-integrity": run_mcp36_memory_integrity,
        "run-mcp36-4-canary": run_mcp36_4_canary,
        "run-production-readiness": run_mcp21_production_readiness,
        "run-ci-fast": run_ci_fast,
        "run-ci-full": run_ci_full,
        "run-all": run_ci_full,
    }
    ok = runners[stage]()
    print(f"{stage}: {'passed' if ok else 'failed'}")
    return 0 if ok else 5


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ithz-mcp", description="Local deterministic agent work memory CLI.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version").set_defaults(func=command_version)

    p = sub.add_parser("init-project")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_init)

    p = sub.add_parser("scan-project")
    p.add_argument("--project", default=".")
    p.add_argument("--out")
    p.set_defaults(func=command_scan)

    p = sub.add_parser("build-index")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_build_index)

    p = sub.add_parser("search-context")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=command_search)

    p = sub.add_parser("get-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--max-bytes", type=int, default=20000)
    p.add_argument("--out")
    p.set_defaults(func=command_pack)

    p = sub.add_parser("context-status")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_status)

    p = sub.add_parser("why-file")
    p.add_argument("--project", default=".")
    p.add_argument("path")
    p.set_defaults(func=command_why)

    p = sub.add_parser("self-test")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=command_self_test)

    p = sub.add_parser("mcp-server")
    p.add_argument("--project", default=".")
    p.add_argument("--mode", default="read-only", choices=["read-only", "write-enabled"])
    p.add_argument("--protocol", default="mcp", choices=["mcp", "direct"])
    p.add_argument("--storage-profile", default="legacy", choices=["legacy", "native-archive"])
    p.add_argument("--smoke", action="store_true")
    p.set_defaults(func=command_mcp_server)

    p = sub.add_parser("mcp-client-smoke")
    p.add_argument("--project", default=".")
    p.add_argument("--config")
    p.add_argument("--out")
    p.set_defaults(func=command_mcp_client_smoke)

    p = sub.add_parser("ccg-mcp-server")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_ccg_mcp_server)

    p = sub.add_parser("ccg-settings")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--no-open", action="store_true")
    p.set_defaults(func=command_ccg_settings)

    p = sub.add_parser("mcp-config-template")
    p.add_argument("--project", default=".")
    p.add_argument("--out", required=True)
    p.add_argument("--client", choices=["codex", "claude-code", "antigravity", "cursor", "generic-jsonrpc"], default="codex")
    p.add_argument("--storage-profile", choices=["legacy", "native-archive"], default="legacy")
    p.add_argument("--mode", choices=["read-only", "write-enabled"], default="read-only")
    p.set_defaults(func=command_mcp_config_template)

    p = sub.add_parser("mcp-config-validate")
    p.add_argument("--config", required=True)
    p.set_defaults(func=command_mcp_config_validate)

    p = sub.add_parser("write-host-installers")
    p.add_argument("--project", default=".")
    p.add_argument("--out", required=True)
    p.add_argument("--launcher", help="Optional portable launcher command path, such as ithz_mcp_server.cmd.")
    p.add_argument("--storage-profile", choices=["legacy", "native-archive"], default="native-archive")
    p.set_defaults(func=command_write_host_installers)

    p = sub.add_parser("import-native-ithz")
    p.add_argument("--workspace", required=True)
    p.add_argument("--project", default=".")
    p.add_argument("--mode", choices=["read-only"], default="read-only")
    p.set_defaults(func=command_import_native_ithz)

    p = sub.add_parser("native-ithz-status")
    p.add_argument("--workspace", required=True)
    p.set_defaults(func=command_native_status)

    p = sub.add_parser("native-ithz-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--max-bytes", type=int, default=20000)
    p.add_argument("--out")
    p.set_defaults(func=command_native_pack)

    p = sub.add_parser("init-minimal-memory")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_init_minimal_memory)

    p = sub.add_parser("audit-markdown-memory")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_audit_markdown)

    p = sub.add_parser("suggest-markdown-reduction")
    p.add_argument("--project", default=".")
    p.add_argument("--out", required=True)
    p.set_defaults(func=command_suggest_markdown_reduction)

    p = sub.add_parser("context-store-status")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_context_store_status)

    p = sub.add_parser("migrate-store-name")
    p.add_argument("--project", default=".")
    p.add_argument("--from", dest="from_name", default=".ithz_mcp")
    p.add_argument("--to", dest="to_name", default=".ithz-context")
    p.add_argument("--dry-run", action="store_true", default=True)
    p.add_argument("--apply", action="store_true")
    p.set_defaults(func=command_migrate_store_name)

    p = sub.add_parser("run-context-compiler-benchmark")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_context_compiler_benchmark)

    p = sub.add_parser("memory-v2-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--max-bytes", type=int, default=16000)
    p.add_argument("--out")
    p.set_defaults(func=command_memory_v2_context_pack)

    p = sub.add_parser("run-memory-v2-benchmark")
    p.add_argument("--project", default=".")
    p.add_argument("--max-bytes", type=int, default=12000)
    p.set_defaults(func=command_memory_v2_benchmark)

    p = sub.add_parser("rag-status")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_rag_status)

    p = sub.add_parser("rag-index-build")
    p.add_argument("--project", default=".")
    p.add_argument("--dimensions", type=int, default=256)
    p.add_argument("--no-write", action="store_true", help="Build in memory and report hash without writing the derived cache.")
    p.set_defaults(func=command_rag_index_build)

    p = sub.add_parser("rag-search")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--limit", type=int, default=12)
    p.add_argument("--rebuild", action="store_true")
    p.add_argument("--no-cache", action="store_true", help="Build the derived RAG index in memory without writing .ithz_mcp/rag.")
    p.add_argument("--read-only-index", action="store_true", help="Use existing .ithz_mcp/index only; fail instead of building/writing a base index.")
    p.set_defaults(func=command_rag_search)

    p = sub.add_parser("rag-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--max-bytes", type=int, default=16000)
    p.add_argument("--out")
    p.add_argument("--rebuild", action="store_true")
    p.add_argument("--no-cache", action="store_true", help="Build the derived RAG index in memory without writing .ithz_mcp/rag.")
    p.add_argument("--read-only-index", action="store_true", help="Use existing .ithz_mcp/index only; fail instead of building/writing a base index.")
    p.set_defaults(func=command_rag_context_pack)

    p = sub.add_parser("run-rag-benchmark")
    p.add_argument("--project", default=".")
    p.add_argument("--max-bytes", type=int, default=12000)
    p.set_defaults(func=command_rag_benchmark)

    p = sub.add_parser("focus-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--target-bytes", type=int, default=FOCUS_TARGET_BYTES)
    p.add_argument("--max-bytes", type=int, default=FOCUS_MAX_BYTES)
    p.add_argument("--out")
    p.add_argument("--json-output", action="store_true")
    p.set_defaults(func=command_focus_context_pack)

    p = sub.add_parser("run-context-quality-regression")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_context_quality_regression)

    p = sub.add_parser("prompt-memory-status")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_prompt_memory_status)

    p = sub.add_parser("record-prompt-response")
    p.add_argument("--project", default=".")
    p.add_argument("--prompt", required=True)
    p.add_argument("--response", required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--mode", choices=["summary", "full-redacted", "full-local-only", "off"], default="summary")
    p.set_defaults(func=command_record_prompt_response)

    p = sub.add_parser("prompt-log")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_prompt_log)

    p = sub.add_parser("prompt-search")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=command_prompt_search)

    p = sub.add_parser("prompt-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--max-bytes", type=int, default=20000)
    p.add_argument("--out")
    p.set_defaults(func=command_prompt_context_pack)

    p = sub.add_parser("init-native-archive-memory")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.add_argument("--verify", choices=["safe", "full-no-write", "checksums-only"], default="safe")
    p.add_argument("--include-child-zones", action="store_true", help="Explicitly include nested project.ithz zones in this archive snapshot.")
    p.add_argument("--index-mode", choices=["compact-v2", "full"], default="compact-v2")
    p.add_argument("--include-source-snapshot", action="store_true", help="Diagnostic mode: include copies of project source files inside project.ithz. Default stores indexes and memory layers only.")
    p.set_defaults(func=command_init_native_archive_memory)

    p = sub.add_parser("install-project")
    p.add_argument("--project", default=".", help="Project root. Defaults to the current directory; this intentionally does not climb to the Git root.")
    p.add_argument("--apply", action="store_true", help="Actually initialize project.md/project.ithz and installers. Without this, prints a dry-run plan.")
    p.add_argument("--profile", default="default")
    p.add_argument("--owner")
    p.add_argument("--native-exe")
    p.add_argument("--include-child-zones", action="store_true")
    p.add_argument("--index-mode", choices=["compact-v2", "full"], default="compact-v2")
    p.add_argument("--import-agent-history", action="store_true")
    p.add_argument("--history-source", action="append", choices=["codex", "claude", "cursor", "antigravity", "generic"])
    p.add_argument("--history-root", action="append")
    p.add_argument("--install-codex-config", action="store_true", help="Also add Codex read-only/write-enabled MCP profiles if they are not already present.")
    p.add_argument("--no-git-driver", action="store_true", help="Do not install the local ITHZ-aware Git diff/merge driver even if this directory is inside Git.")
    p.add_argument("--keep-install-artifacts", action="store_true", help="Keep generated host installer files under .ithz-install/host_installers. By default install-project cleans temporary installer artifacts after use.")
    p.add_argument("--agent-intake", choices=["auto", "codex-cli", "deterministic-only", "off"], default="auto", help="First-install project intake. auto uses Codex CLI when available, otherwise records deterministic fallback and asks the host agent to finish intake.")
    p.set_defaults(func=command_install_project)

    p = sub.add_parser("agent-intake-project")
    p.add_argument("--project", default=".")
    p.add_argument("--owner")
    p.add_argument("--profile", default="default")
    p.add_argument("--mode", choices=["auto", "codex-cli", "deterministic-only", "off"], default="auto")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_agent_intake_project)

    p = sub.add_parser("uninstall-project")
    p.add_argument("--project", default=".", help="Project root. Defaults to the current directory.")
    p.add_argument("--apply", action="store_true", help="Actually remove project.md/project.ithz and ITHZ Git driver metadata. Without this, prints a dry-run plan.")
    p.add_argument("--keep-project-md", action="store_true", help="Keep project.md and remove only project.ithz plus local ITHZ integration metadata.")
    p.add_argument("--keep-host-configs", action="store_true", help="Keep project-local MCP host config files. By default, uninstall removes ITHZ-marked .mcp.json, .antigravity/mcp.json, .cursor/mcp.json and .claude/mcp.json.")
    p.add_argument("--remove-host-configs", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(func=command_uninstall_project)

    p = sub.add_parser("archive-memory-status")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path, for parent/sibling/manual zone access.")
    p.set_defaults(func=command_archive_memory_status)

    p = sub.add_parser("archive-search-context")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path, for parent/sibling/manual zone search.")
    p.set_defaults(func=command_archive_search_context)

    p = sub.add_parser("archive-get-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--max-bytes", type=int, default=20000)
    p.add_argument("--out")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path, for parent/sibling/manual zone packs.")
    p.set_defaults(func=command_archive_get_context_pack)

    p = sub.add_parser("archive-record-prompt-response")
    p.add_argument("--project", default=".")
    p.add_argument("--prompt", required=True)
    p.add_argument("--response", required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--mode", choices=["summary", "full-redacted", "full-local-only", "off"], default="summary")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path, for parent/sibling/manual zone writes.")
    p.set_defaults(func=command_archive_record_prompt_response)

    p = sub.add_parser("archive-ingest-project-memory")
    p.add_argument("--project", default=".")
    p.add_argument("--source", action="append", required=True, help="Markdown/text source file to mine into project.ithz memory.")
    p.add_argument("--note")
    p.add_argument("--include-git", action="store_true")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_ingest_project_memory)

    p = sub.add_parser("archive-finalize-task")
    p.add_argument("--project", default=".")
    p.add_argument("--task", required=True)
    p.add_argument("--summary")
    p.add_argument("--summary-text")
    p.add_argument("--decision", action="append")
    p.add_argument("--gate", action="append")
    p.add_argument("--risk", action="append")
    p.add_argument("--next", action="append")
    p.add_argument("--changed-file", action="append")
    p.add_argument("--command", action="append")
    p.add_argument("--docs-impact", choices=["updated", "not-needed", "unknown"], default="unknown")
    p.add_argument("--memory-impact", choices=["handoff-created", "not-needed", "unknown"], default="unknown")
    p.add_argument("--prompt")
    p.add_argument("--response")
    p.add_argument("--prompt-mode", choices=["summary", "full-redacted", "full-local-only", "off"], default="summary")
    p.add_argument("--snapshot", action="store_true")
    p.add_argument("--snapshot-mode", choices=["off", "auto", "full", "defer"], default="auto", help="Snapshot policy used only when --snapshot is set. Auto defers on large archives.")
    p.add_argument("--include-git", action="store_true")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_finalize_task)

    p = sub.add_parser("archive-finalize-task-worker")
    p.add_argument("--input", required=True)
    p.set_defaults(func=command_archive_finalize_task_worker)

    p = sub.add_parser("workflow-profile-status")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_workflow_profile_status)

    p = sub.add_parser("archive-adopt-project-workflow")
    p.add_argument("--project", default=".")
    p.add_argument("--profile", default="default")
    p.add_argument("--owner")
    p.add_argument("--prompt", help="Optional onboarding prompt to mine into the workflow profile.")
    p.add_argument("--no-existing-md", action="store_true", help="Do not mine existing Markdown docs during adoption.")
    p.add_argument("--import-agent-history", action="store_true", help="Explicitly import project-related historical prompts/responses from local agent logs into project.ithz.")
    p.add_argument("--history-source", action="append", choices=["codex", "claude", "cursor", "antigravity", "generic"], help="Agent history source to scan.")
    p.add_argument("--history-root", action="append", help="Additional local history root to scan.")
    p.add_argument("--history-author", help="Author to attach to imported prompt/response history. Defaults to --owner, Git config, or OS user.")
    p.add_argument("--history-imported-at", help="Optional UTC import timestamp override for deterministic audits.")
    p.add_argument("--max-history-records", type=int, default=100)
    p.add_argument("--native-exe")
    p.set_defaults(func=command_archive_adopt_project_workflow)

    p = sub.add_parser("workflow-ingest-prompt")
    p.add_argument("--project", default=".")
    p.add_argument("--profile", default="default")
    p.add_argument("--owner")
    p.add_argument("--prompt", help="Prompt file containing workflow rules to merge into this profile.")
    p.add_argument("--source", action="append", help="Additional Markdown/text source file to mine into this profile.")
    p.add_argument("--note")
    p.add_argument("--set-default", action="store_true")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_workflow_ingest_prompt)

    p = sub.add_parser("workflow-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--profile", default="default")
    p.add_argument("--query", required=True)
    p.add_argument("--max-bytes", type=int, default=20000)
    p.add_argument("--out")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_workflow_context_pack)

    p = sub.add_parser("agent-history-discover")
    p.add_argument("--project", default=".")
    p.add_argument("--source", action="append", choices=["codex", "claude", "cursor", "antigravity", "generic"])
    p.add_argument("--root", action="append", help="Additional local history root/file to scan.")
    p.add_argument("--author", help="Author to attach to discovered prompt/response history.")
    p.add_argument("--max-records", type=int, default=100)
    p.set_defaults(func=command_agent_history_discover)

    p = sub.add_parser("archive-import-agent-history")
    p.add_argument("--project", default=".")
    p.add_argument("--source", action="append", choices=["codex", "claude", "cursor", "antigravity", "generic"])
    p.add_argument("--root", action="append", help="Additional local history root/file to scan.")
    p.add_argument("--author", help="Author to attach to imported prompt/response history. Defaults to Git config or OS user.")
    p.add_argument("--imported-at", help="Optional UTC import timestamp override for deterministic audits.")
    p.add_argument("--max-records", type=int, default=100)
    p.add_argument("--apply", action="store_true", help="Actually write imported summaries into project.ithz. Without this, discovery is dry-run only.")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_archive_import_agent_history)

    p = sub.add_parser("archive-link-zone")
    p.add_argument("--project", default=".")
    p.add_argument("--zone", required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--relationship", default="auto", choices=["auto", "parent", "child", "sibling", "external"])
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit active project directory or project.ithz path.")
    p.set_defaults(func=command_archive_link_zone)

    p = sub.add_parser("archive-zone-status")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_zone_status)

    p = sub.add_parser("archive-cross-zone-context-pack")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--max-bytes", type=int, default=20000)
    p.add_argument("--out")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_cross_zone_context_pack)

    p = sub.add_parser("archive-record-cross-zone-event")
    p.add_argument("--project", default=".")
    p.add_argument("--target-zone", required=True)
    p.add_argument("--event", required=True)
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_record_cross_zone_event)

    p = sub.add_parser("archive-append-event")
    p.add_argument("--project", default=".")
    p.add_argument("--kind", required=True, choices=["decision", "gate", "risk", "must_not_break", "next", "note", "cross_zone"])
    p.add_argument("--text", required=True)
    p.add_argument("--source", default="manual")
    p.add_argument("--tag", action="append")
    p.add_argument("--include-git", action="store_true", help="Capture current Git branch, hash and commit subject as event metadata.")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_append_event)

    p = sub.add_parser("durable-instruction-status")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_durable_instruction_status)

    def add_instruction_args(parser_obj: argparse.ArgumentParser, instruction_type: str | None = None) -> None:
        parser_obj.add_argument("--project", default=".")
        if instruction_type is None:
            parser_obj.add_argument("--instruction-type", choices=["workflow_rule", "project_decision", "gate_rule", "risk_rule"], required=True)
        else:
            parser_obj.set_defaults(instruction_type=instruction_type)
        group = parser_obj.add_mutually_exclusive_group(required=True)
        group.add_argument("--text")
        group.add_argument("--file")
        parser_obj.add_argument("--profile", default="default")
        parser_obj.add_argument("--scope", default="project")
        parser_obj.add_argument("--source", default="user_instruction")
        parser_obj.add_argument("--tag", action="append")
        parser_obj.add_argument("--include-git", action="store_true")
        parser_obj.add_argument("--native-exe")
        parser_obj.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
        parser_obj.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")

    p = sub.add_parser("record-durable-instruction")
    add_instruction_args(p)
    p.set_defaults(func=command_record_durable_instruction)

    p = sub.add_parser("record-workflow-rule")
    add_instruction_args(p, "workflow_rule")
    p.set_defaults(func=command_record_durable_instruction)

    p = sub.add_parser("record-project-decision")
    add_instruction_args(p, "project_decision")
    p.set_defaults(func=command_record_durable_instruction)

    p = sub.add_parser("record-gate-rule")
    add_instruction_args(p, "gate_rule")
    p.set_defaults(func=command_record_durable_instruction)

    p = sub.add_parser("record-risk-rule")
    add_instruction_args(p, "risk_rule")
    p.set_defaults(func=command_record_durable_instruction)

    p = sub.add_parser("ingest-user-instruction")
    p.add_argument("--project", default=".")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--text")
    group.add_argument("--file")
    p.add_argument("--profile", default="default")
    p.add_argument("--scope", default="project")
    p.add_argument("--source", default="user_instruction")
    p.add_argument("--include-git", action="store_true")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_ingest_user_instruction)

    p = sub.add_parser("archive-memory-index-status")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_memory_index_status)

    p = sub.add_parser("archive-rebuild-derived-indexes")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_rebuild_derived_indexes)

    p = sub.add_parser("archive-compile-memory-synthesis")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.set_defaults(func=command_archive_compile_memory_synthesis)

    p = sub.add_parser("archive-create-snapshot")
    p.add_argument("--project", default=".")
    p.add_argument("--label", default="manual")
    p.add_argument("--native-exe")
    p.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
    p.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")
    p.add_argument("--mode", choices=["off", "auto", "full", "defer"], default="full")
    p.set_defaults(func=command_archive_create_snapshot)

    def add_ledger_zone_args(parser_obj: argparse.ArgumentParser) -> None:
        parser_obj.add_argument("--project", default=".")
        parser_obj.add_argument("--source", default="project_ledger")
        parser_obj.add_argument("--include-git", action="store_true")
        parser_obj.add_argument("--native-exe")
        parser_obj.add_argument("--memory-zone", choices=["nearest", "current", "parent"], default="nearest")
        parser_obj.add_argument("--memory-zone-path", help="Explicit project directory or project.ithz path.")

    p = sub.add_parser("ithz-add-claim")
    add_ledger_zone_args(p)
    p.add_argument("--claim-id")
    p.add_argument("--text", required=True)
    p.add_argument("--scope", default="project")
    p.add_argument("--supporting-gate", action="append")
    p.add_argument("--status", default="allowed_scoped")
    p.set_defaults(func=command_ledger_add_claim)

    p = sub.add_parser("ithz-block-claim")
    add_ledger_zone_args(p)
    p.add_argument("--claim-id")
    p.add_argument("--text", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--blocking-gate", action="append")
    p.add_argument("--status", default="blocked")
    p.set_defaults(func=command_ledger_block_claim)

    p = sub.add_parser("ithz-list-allowed-claims")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_ledger_list_allowed_claims)

    p = sub.add_parser("ithz-list-blocked-claims")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_ledger_list_blocked_claims)

    p = sub.add_parser("ithz-get-claim-evidence")
    p.add_argument("--project", default=".")
    p.add_argument("--query", required=True)
    p.add_argument("--native-exe")
    p.set_defaults(func=command_ledger_get_claim_evidence)

    p = sub.add_parser("ithz-can-i-claim")
    p.add_argument("--project", default=".")
    p.add_argument("--claim")
    p.add_argument("--query", help="Compatibility alias for --claim.")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_ledger_can_i_claim)

    p = sub.add_parser("ithz-add-reviewer-note")
    add_ledger_zone_args(p)
    p.add_argument("--note-id")
    p.add_argument("--target", required=True)
    p.add_argument("--text", required=True)
    p.add_argument("--severity", default="guidance")
    p.set_defaults(func=command_ledger_add_reviewer_note)

    p = sub.add_parser("ithz-create-replication-pack-record")
    add_ledger_zone_args(p)
    p.add_argument("--pack-id", required=True)
    p.add_argument("--witnesses", type=int, default=0)
    p.add_argument("--positive", type=int, default=0)
    p.add_argument("--negative-stop", type=int, default=0)
    p.add_argument("--manifest-path", default="")
    p.add_argument("--public-safe", action="store_true")
    p.add_argument("--status", default="recorded")
    p.set_defaults(func=command_ledger_create_replication_pack)

    p = sub.add_parser("ithz-get-project-ledger-summary")
    p.add_argument("--project", default=".")
    p.add_argument("--native-exe")
    p.set_defaults(func=command_ledger_summary)

    p = sub.add_parser("plan-markdown-migration")
    p.add_argument("--project", default=".")
    p.add_argument("--out", required=True)
    p.set_defaults(func=command_plan_markdown_migration)

    p = sub.add_parser("apply-markdown-migration")
    p.add_argument("--project", default=".")
    p.add_argument("--plan", required=True)
    p.add_argument("--dry-run", action="store_true", default=True)
    p.set_defaults(func=command_apply_markdown_migration)

    p = sub.add_parser("write-bootstrap-files")
    p.add_argument("--project", default=".")
    p.add_argument("--mode", choices=["minimal"], default="minimal")
    p.add_argument("--dry-run", action="store_true", default=True)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=command_write_bootstrap_files)

    p = sub.add_parser("record-task-summary")
    p.add_argument("--project", default=".")
    p.add_argument("--summary", required=True)
    p.set_defaults(func=command_record_summary)

    p = sub.add_parser("context-commit")
    p.add_argument("--project", default=".")
    p.add_argument("--task", required=True)
    p.add_argument("--summary")
    p.add_argument("--include-git", action="store_true")
    p.add_argument("--private", action="store_true")
    p.add_argument("--prompt-id", action="append")
    p.add_argument("--response-id", action="append")
    p.set_defaults(func=command_context_commit)

    p = sub.add_parser("context-log")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_context_log)

    p = sub.add_parser("context-diff")
    p.add_argument("--project", default=".")
    p.add_argument("--from", dest="from_ref", required=True)
    p.add_argument("--to", dest="to_ref", required=True)
    p.set_defaults(func=command_context_diff)

    p = sub.add_parser("context-branch")
    p.add_argument("--project", default=".")
    p.add_argument("name")
    p.set_defaults(func=command_context_branch)

    p = sub.add_parser("context-checkout")
    p.add_argument("--project", default=".")
    p.add_argument("ref")
    p.add_argument("--read-only", action="store_true")
    p.set_defaults(func=command_context_checkout)

    p = sub.add_parser("context-tag")
    p.add_argument("--project", default=".")
    p.add_argument("name")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=command_context_tag)

    p = sub.add_parser("git-status")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_git_status)

    p = sub.add_parser("git-diff-ithz")
    p.add_argument("--archive", required=True)
    p.set_defaults(func=command_git_diff_ithz)

    p = sub.add_parser("ithz-diff")
    p.add_argument("left")
    p.add_argument("right")
    p.add_argument("--mode", choices=["auto", "project", "folder", "data", "ithz"], default="auto")
    p.add_argument("--ignore-order", action="store_true", help="Treat order-insensitive rows/lines as canonical for data-heavy inputs.")
    p.add_argument("--json", help="Write the full machine-readable report to this path.")
    p.add_argument("--json-output", action="store_true", help="Print the full machine-readable report to stdout.")
    p.add_argument("--report", help="Write an HTML review report to this path.")
    p.add_argument("--canonical-hashes", help="Write only canonical hash fields to this path.")
    p.set_defaults(func=command_ithz_diff)

    p = sub.add_parser("git-merge-ithz")
    p.add_argument("--base", required=True)
    p.add_argument("--ours", required=True)
    p.add_argument("--theirs", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--report")
    p.set_defaults(func=command_git_merge_ithz)

    p = sub.add_parser("install-git-drivers")
    p.add_argument("--repo", default=".")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=command_install_git_drivers)

    p = sub.add_parser("git-driver-status")
    p.add_argument("--repo", default=".")
    p.set_defaults(func=command_git_driver_status)

    p = sub.add_parser("context-for-git-diff")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_context_for_git_diff)

    p = sub.add_parser("decisions-between-git")
    p.add_argument("--project", default=".")
    p.add_argument("--from", dest="from_hash", required=True)
    p.add_argument("--to", dest="to_hash", required=True)
    p.set_defaults(func=command_decisions_between_git)

    p = sub.add_parser("context-remote")
    rp = p.add_subparsers(dest="remote_command", required=True)
    add = rp.add_parser("add")
    add.add_argument("--project", default=".")
    add.add_argument("name")
    add.add_argument("path")
    add.set_defaults(func=command_context_remote)
    ls = rp.add_parser("list")
    ls.add_argument("--project", default=".")
    ls.set_defaults(func=command_context_remote)

    p = sub.add_parser("context-push")
    p.add_argument("--project", default=".")
    p.add_argument("--remote", required=True)
    p.set_defaults(func=command_context_push)

    p = sub.add_parser("context-pull")
    p.add_argument("--project", default=".")
    p.add_argument("--remote", required=True)
    p.set_defaults(func=command_context_pull)

    p = sub.add_parser("context-merge")
    p.add_argument("--project", default=".")
    p.add_argument("branch")
    p.set_defaults(func=command_context_merge)

    p = sub.add_parser("run-memory-benchmark")
    p.add_argument("--project", default=".")
    p.set_defaults(func=command_benchmark)

    p = sub.add_parser("adopt-project")
    p.add_argument("--project", default=".")
    p.add_argument("--mode", choices=["docs-only", "minimal", "full"], default="minimal")
    p.set_defaults(func=command_adopt)

    p = sub.add_parser("memory-integrity-status")
    p.add_argument("--project", default=".")
    p.add_argument("--query", default="current memory integrity and review gates")
    p.set_defaults(func=command_memory_integrity_status)

    p = sub.add_parser("archive-append-memory-record")
    p.add_argument("--project", default=".")
    p.add_argument("--record", required=True)
    p.add_argument("--memory-zone", default="nearest", choices=["nearest", "current", "parent"])
    p.add_argument("--memory-zone-path")
    p.add_argument("--include-git", action="store_true")
    p.set_defaults(func=command_archive_append_memory_record)

    for name in ("run-mcp0", "run-mcp1", "run-mcp2", "run-mcp3", "run-mcp4", "run-mcp5", "run-mcp6", "run-mcp7", "run-mcp8-hardening", "run-mcp9f-native-ithz", "run-mcp10-markdown-minimal", "run-mcp11-external-client", "run-mcp12-prompt-memory", "run-mcp13-host-compat", "run-mcp14-rc5-package", "run-mcp16-git-merge-driver", "run-mcp17-append-index-snapshot", "run-mcp18-end-task-checkpoint", "run-mcp19-workflow-branches", "run-mcp20-agent-history-import", "run-mcp21-production-readiness", "run-mcp22-auto-checkpoint", "run-mcp23-install-project", "run-mcp24-durable-instructions", "run-mcp25-macos-package", "run-mcp26-memory-synthesis", "run-mcp27-project-ledger", "run-mcp28-ubuntu-package", "run-mcp29-memory-effectiveness", "run-mcp30-memory-v2", "run-mcp31-local-rag", "run-mcp36-memory-integrity", "run-mcp36-4-canary", "run-production-readiness", "run-ci-fast", "run-ci-full", "run-all"):
        sub.add_parser(name).set_defaults(func=lambda _args, stage=name: run_stage(stage))

    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

