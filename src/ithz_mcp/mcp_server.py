from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import VERSION
from .branding import MCP_BRAND_NAME, MCP_BRAND_TITLE, mcp_icon_metadata
from .canonical_json import dumps, sanitize_json_value
from .context_index import load_index_readonly, search_index
from .context_pack import build_context_pack
from .events import context_log
from .focus_context import DEFAULT_MAX_BYTES as FOCUS_MAX_BYTES, DEFAULT_TARGET_BYTES as FOCUS_TARGET_BYTES, FOCUS_PACK_SCHEMA, focus_context_pack_from_source
from .instruction_memory import durable_instruction_status, ingest_user_instruction, record_durable_instruction
from .memory_integrity import memory_integrity_status
from .native_archive_store import archive_append_event, archive_append_memory_record, archive_cross_zone_context_pack, archive_memory_index_status, archive_zone_status, native_archive_context_pack, native_archive_current_projection, native_archive_record_prompt_response, native_archive_search, native_archive_status
from .project_ledger import add_claim, add_reviewer_note, block_claim, can_i_claim, create_replication_pack_record, get_claim_evidence, list_allowed_claims, list_blocked_claims, project_ledger_summary
from .rag import RAG_PACK_SCHEMA, compile_rag_context_pack, rag_search, rag_status
from .storage import state_dir
from .task_checkpoint import archive_finalize_task, archive_ingest_project_memory, queue_archive_finalize_task, should_queue_checkpoint
from .workflow_profiles import archive_adopt_project_workflow, archive_update_workflow_profile, workflow_context_pack, workflow_profile_status

MAX_RESPONSE_BYTES = 65536
MAX_CONTEXT_PACK_BYTES = 12000
MEMORY_FIRST_INSTRUCTIONS = (
    "This project uses ITHZ-MCP as deterministic project memory. Read project.md as the bootstrap manifest when "
    "the host makes project bootstrap files available. Before broad codebase reads, call ithz_context_status and "
    "ithz_workflow_profile_status, then ithz_focus_context_pack for the task. Use its working set first; request "
    "ithz_archive_get_context_pack or ithz_get_context_pack only when fallback_required is true or direct evidence is still missing. "
    "Do not treat ITHZ-MCP as a Git replacement, production database, cloud sync product, or universal token-saving system."
)

LEGACY_TOOLS = {
    "ithz_context_status",
    "ithz_search_context",
    "ithz_get_context_pack",
    "ithz_focus_context_pack",
    "ithz_why_file",
    "ithz_get_decision_log",
    "ithz_get_gate_history",
    "ithz_archive_status",
    "ithz_archive_zone_status",
    "ithz_archive_memory_index_status",
    "ithz_archive_search_context",
    "ithz_archive_get_context_pack",
    "ithz_archive_cross_zone_context_pack",
    "ithz_durable_instruction_status",
    "ithz_workflow_profile_status",
    "ithz_workflow_context_pack",
    "ithz_list_allowed_claims",
    "ithz_list_blocked_claims",
    "ithz_get_claim_evidence",
    "ithz_can_i_claim",
    "ithz_get_project_ledger_summary",
    "ithz_rag_status",
    "ithz_rag_search",
    "ithz_rag_context_pack",
    "ithz_memory_integrity_status",
}

ARCHIVE_ONLY_TOOLS = {
    "ithz_context_status",
    "ithz_search_context",
    "ithz_get_context_pack",
    "ithz_focus_context_pack",
    "ithz_archive_status",
    "ithz_archive_zone_status",
    "ithz_archive_memory_index_status",
    "ithz_archive_search_context",
    "ithz_archive_get_context_pack",
    "ithz_archive_cross_zone_context_pack",
    "ithz_durable_instruction_status",
    "ithz_workflow_profile_status",
    "ithz_workflow_context_pack",
    "ithz_list_allowed_claims",
    "ithz_list_blocked_claims",
    "ithz_get_claim_evidence",
    "ithz_can_i_claim",
    "ithz_get_project_ledger_summary",
    "ithz_rag_status",
    "ithz_rag_search",
    "ithz_rag_context_pack",
    "ithz_memory_integrity_status",
}

WRITE_TOOLS = {
    "ithz_archive_append_event",
    "ithz_archive_append_memory_record",
    "ithz_archive_auto_checkpoint",
    "ithz_archive_finalize_task",
    "ithz_archive_ingest_project_memory",
    "ithz_archive_record_prompt_response",
    "ithz_archive_adopt_project_workflow",
    "ithz_workflow_ingest_prompt",
    "ithz_record_workflow_rule",
    "ithz_record_project_decision",
    "ithz_record_gate_rule",
    "ithz_record_risk_rule",
    "ithz_ingest_user_instruction",
    "ithz_add_claim",
    "ithz_block_claim",
    "ithz_add_reviewer_note",
    "ithz_create_replication_pack_record",
}

TOOLS = LEGACY_TOOLS


def active_tools(storage_profile: str = "legacy", server_mode: str = "read-only") -> set[str]:
    tools = set(ARCHIVE_ONLY_TOOLS if storage_profile == "native-archive" else LEGACY_TOOLS)
    if server_mode == "write-enabled":
        tools |= WRITE_TOOLS
    return tools


def memory_instructions(storage_profile: str = "legacy", server_mode: str = "read-only") -> str:
    if server_mode == "write-enabled":
        return (
            MEMORY_FIRST_INSTRUCTIONS
            + " This write-enabled profile is explicit and native: at the end of every completed task, before the final answer, "
            "call ithz_archive_auto_checkpoint with a concise task name, summary_text, decisions, gates, risks, next steps, changed files and commands when known. "
            "If the user gives a durable project workflow rule, decision, gate, risk, must-not-break rule, allowed claim, blocked claim, reviewer note or replication-pack record, call the matching typed durable or project-ledger tool before finishing. Use ithz_archive_append_memory_record for a source-bound MCP36 abstraction; unverified free-text events must not be promoted as typed memory. "
            "Use this tool unless the user explicitly says not to write memory or the task produced no durable project memory. "
            "The tool writes to project.ithz, applies redaction, uses the native archive path, and is the preferred end-of-task checkpoint mechanism."
        )
    return (
        MEMORY_FIRST_INSTRUCTIONS
        + " This read-only profile must not write memory. For end-of-task memory, use the separate write-enabled profile and its ithz_archive_auto_checkpoint tool."
    )


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _error(req_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _result(req_id: Any, value: Any) -> dict[str, Any]:
    response = {"jsonrpc": "2.0", "id": req_id, "result": sanitize_json_value(value)}
    encoded = dumps(response).encode("utf-8")
    if len(encoded) <= MAX_RESPONSE_BYTES:
        return response
    truncated = {
        "truncated": True,
        "truncation_reason": "max_response_bytes",
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "original_response_bytes": len(encoded),
        "summary": "Response exceeded deterministic read-only MCP shim limit.",
    }
    return {"jsonrpc": "2.0", "id": req_id, "result": truncated}


def _params(req: dict[str, Any]) -> dict[str, Any]:
    params = req.get("params", {})
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise RpcError(-32602, "invalid_params", {"reason": "params_must_be_object"})
    return params


def _project(default_project: Path, params: dict[str, Any]) -> Path:
    return Path(params.get("project") or default_project).resolve()


def _checkpoint_payload(project: Path, task: str, summary: str, params: dict[str, Any], default_memory_impact: str, include_git_default: bool) -> dict[str, Any]:
    return {
        "project": str(project),
        "task": task,
        "summary": summary,
        "decisions": [str(v) for v in params.get("decision", [])],
        "gates": [str(v) for v in params.get("gate", [])],
        "risks": [str(v) for v in params.get("risk", [])],
        "next_steps": [str(v) for v in params.get("next", [])],
        "changed_files": [str(v) for v in params.get("changed_file", [])],
        "commands": [str(v) for v in params.get("command", [])],
        "docs_impact": str(params.get("docs_impact", "unknown")),
        "memory_impact": str(params.get("memory_impact", default_memory_impact)),
        "prompt_mode": "summary",
        "create_snapshot": bool(params.get("snapshot", False)),
        "snapshot_mode": str(params.get("snapshot_mode", "auto")),
        "memory_zone": str(params.get("memory_zone", "nearest")),
        "memory_zone_path": params.get("memory_zone_path"),
        "include_git": bool(params.get("include_git", include_git_default)),
    }


def _maybe_queue_or_finalize_checkpoint(payload: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    project = Path(str(payload["project"]))
    async_mode = str(params.get("async_mode", params.get("checkpoint_mode", "auto")))
    queued, reason, signal = should_queue_checkpoint(project, str(payload["native_exe"]) if payload.get("native_exe") else None, async_mode)
    if queued:
        return queue_archive_finalize_task(payload, reason, signal)
    return archive_finalize_task(
        project=project,
        task=str(payload["task"]),
        summary=str(payload.get("summary", "")),
        decisions=[str(v) for v in payload.get("decisions", [])],
        gates=[str(v) for v in payload.get("gates", [])],
        risks=[str(v) for v in payload.get("risks", [])],
        next_steps=[str(v) for v in payload.get("next_steps", [])],
        changed_files=[str(v) for v in payload.get("changed_files", [])],
        commands=[str(v) for v in payload.get("commands", [])],
        docs_impact=str(payload.get("docs_impact", "unknown")),
        memory_impact=str(payload.get("memory_impact", "unknown")),
        prompt_mode=str(payload.get("prompt_mode", "summary")),
        create_snapshot=bool(payload.get("create_snapshot", False)),
        snapshot_mode=str(payload.get("snapshot_mode", "auto")),
        memory_zone=str(payload.get("memory_zone", "nearest")),
        memory_zone_path=payload.get("memory_zone_path"),
        include_git=bool(payload.get("include_git", False)),
    )


def _status(project: Path, storage_profile: str = "legacy", server_mode: str = "read-only") -> dict[str, Any]:
    index_path = state_dir(project) / "index" / "index.json"
    status = {
        "readonly_mode": server_mode == "read-only",
        "server_mode": server_mode,
        "project": str(project),
        "storage_profile": storage_profile,
        "state_exists": state_dir(project).exists(),
        "index_exists": index_path.exists(),
        "tools": sorted(active_tools(storage_profile, server_mode)),
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "max_context_pack_bytes": MAX_CONTEXT_PACK_BYTES,
        "agent_policy": {
            "memory_first": True,
            "bootstrap_file": "project.md",
            "first_tools": ["ithz_context_status", "ithz_focus_context_pack"],
            "broad_codebase_read_after_context_pack": True,
            "hard_enforcement_depends_on_host_tool_permissions": True,
            "auto_checkpoint": {
                "enabled": server_mode == "write-enabled",
                "tool": "ithz_archive_auto_checkpoint",
                "when": "end_of_task_before_final_answer",
                "native_archive": storage_profile == "native-archive",
                "requires_explicit_write_enabled_profile": True,
            },
        },
    }
    if storage_profile == "native-archive":
        try:
            archive_status = native_archive_status(project)
            status.update(
                {
                    "archive_exists": bool(archive_status.get("exists")),
                    "archive": archive_status.get("archive"),
                    "active_memory_zone": archive_status.get("active_memory_zone"),
                    "memory_zone": archive_status.get("memory_zone"),
                    "archive_semantic_hash": archive_status.get("archive_semantic_hash"),
                    "safe_verify_ok": archive_status.get("safe_verify_ok"),
                }
            )
        except Exception as exc:
            status["archive_error"] = str(exc)
    return status


def _tool_schema(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required or [],
            "additionalProperties": False,
        },
    }


def mcp_tool_schemas(storage_profile: str = "legacy", server_mode: str = "read-only") -> list[dict[str, Any]]:
    project_prop = {"type": "string", "description": "Project root path. Defaults to server project."}
    query_prop = {"type": "string", "description": "Deterministic query string."}
    memory_zone_prop = {"type": "string", "enum": ["nearest", "current", "parent"], "description": "Native archive zone discovery. Defaults to nearest project.ithz."}
    memory_zone_path_prop = {"type": "string", "description": "Explicit project directory or project.ithz path for parent/sibling/manual zone access."}
    archive_props = {"project": project_prop, "memory_zone": memory_zone_prop, "memory_zone_path": memory_zone_path_prop}
    schemas = [
        _tool_schema("ithz_context_status", "Return read-only context status.", {"project": project_prop}),
        _tool_schema(
            "ithz_search_context",
            "Search the deterministic sidecar context index.",
            {"project": project_prop, "memory_zone": memory_zone_prop, "memory_zone_path": memory_zone_path_prop, "query": query_prop, "limit": {"type": "integer", "minimum": 1, "maximum": 50}},
            ["query"],
        ),
        _tool_schema(
            "ithz_get_context_pack",
            "Build a deterministic context pack from the sidecar index.",
            {"project": project_prop, "memory_zone": memory_zone_prop, "memory_zone_path": memory_zone_path_prop, "query": query_prop, "max_bytes": {"type": "integer", "minimum": 1000, "maximum": MAX_CONTEXT_PACK_BYTES}},
            ["query"],
        ),
        _tool_schema("ithz_why_file", "Explain why a file is represented in the context index.", {"project": project_prop, "path": {"type": "string"}}, ["path"]),
        _tool_schema("ithz_get_decision_log", "Return matching decision entries.", {"project": project_prop, "query": query_prop}),
        _tool_schema("ithz_get_gate_history", "Return matching gate entries.", {"project": project_prop, "query": query_prop}),
        _tool_schema("ithz_archive_status", "Return status for the native project.ithz memory archive.", archive_props),
        _tool_schema("ithz_archive_zone_status", "Return active, parent, child, sibling and linked native memory zones.", archive_props),
        _tool_schema("ithz_archive_memory_index_status", "Return append-only event, derived index and snapshot status for the native archive.", archive_props),
        _tool_schema(
            "ithz_archive_search_context",
            "Search the native project.ithz memory archive after safe native extraction.",
            {**archive_props, "query": query_prop, "limit": {"type": "integer", "minimum": 1, "maximum": 50}},
            ["query"],
        ),
        _tool_schema(
            "ithz_archive_get_context_pack",
            "Build a deterministic context pack from the native project.ithz archive. Use this before broad codebase reads in memory-first host profiles.",
            {**archive_props, "query": query_prop, "max_bytes": {"type": "integer", "minimum": 1000, "maximum": MAX_CONTEXT_PACK_BYTES}},
            ["query"],
        ),
        _tool_schema(
            "ithz_archive_cross_zone_context_pack",
            "Build a read-only context pack across the active archive and explicitly linked memory zones.",
            {**archive_props, "query": query_prop, "max_bytes": {"type": "integer", "minimum": 1000, "maximum": MAX_CONTEXT_PACK_BYTES}},
            ["query"],
        ),
        _tool_schema(
            "ithz_workflow_profile_status",
            "Return workflow profiles stored in project.ithz.",
            {**archive_props},
        ),
        _tool_schema(
            "ithz_workflow_context_pack",
            "Build a deterministic context pack scoped to a workflow profile.",
            {**archive_props, "profile": {"type": "string"}, "query": query_prop, "max_bytes": {"type": "integer", "minimum": 1000, "maximum": MAX_CONTEXT_PACK_BYTES}},
            ["profile", "query"],
        ),
        _tool_schema(
            "ithz_durable_instruction_status",
            "Return typed durable workflow/decision/gate/risk instruction status stored in project.ithz.",
            {**archive_props},
        ),
        _tool_schema(
            "ithz_list_allowed_claims",
            "Return allowed/scoped project claims from the project ledger.",
            {**archive_props},
        ),
        _tool_schema(
            "ithz_list_blocked_claims",
            "Return blocked project claims from the project ledger.",
            {**archive_props},
        ),
        _tool_schema(
            "ithz_get_claim_evidence",
            "Return deterministic allowed/blocked claim evidence for a proposed statement.",
            {**archive_props, "query": query_prop},
            ["query"],
        ),
        _tool_schema(
            "ithz_focus_context_pack",
            "Build a smaller deterministic working set from the normal context pack. It preserves guardrails and expands its byte budget when evidence coverage is insufficient.",
            {
                "project": project_prop,
                "memory_zone": memory_zone_prop,
                "memory_zone_path": memory_zone_path_prop,
                "query": query_prop,
                "target_bytes": {"type": "integer", "minimum": 1000, "maximum": MAX_CONTEXT_PACK_BYTES},
                "max_bytes": {"type": "integer", "minimum": 1000, "maximum": MAX_CONTEXT_PACK_BYTES},
            },
            ["query"],
        ),
        _tool_schema(
            "ithz_can_i_claim",
            "Answer whether a proposed project claim is allowed by the ledger, blocked, or missing evidence.",
            {**archive_props, "query": query_prop, "claim": {"type": "string"}},
            [],
        ),
        _tool_schema(
            "ithz_get_project_ledger_summary",
            "Return counts and hashes for first-class ledger layers: claims, blocked claims, replication packs and reviewer notes.",
            {**archive_props},
        ),
        _tool_schema(
            "ithz_rag_status",
            "Return local deterministic RAG index status. This is read-only and does not build the index.",
            {"project": project_prop},
        ),
        _tool_schema(
            "ithz_rag_search",
            "Search the local deterministic RAG index. Read-only MCP calls use an existing index and do not write cache files.",
            {"project": project_prop, "query": query_prop, "limit": {"type": "integer", "minimum": 1, "maximum": 50}},
            ["query"],
        ),
        _tool_schema(
            "ithz_rag_context_pack",
            "Build a deterministic local RAG context pack from an existing project index. Use as a richer read-only retrieval layer before broad codebase reads.",
            {"project": project_prop, "query": query_prop, "max_bytes": {"type": "integer", "minimum": 1000, "maximum": MAX_CONTEXT_PACK_BYTES}},
            ["query"],
        ),
        _tool_schema(
            "ithz_memory_integrity_status",
            "Compile the MCP36 read-only memory influence and evidence-diversity receipt for the current projection.",
            {**archive_props, "query": query_prop},
            ["query"],
        ),
        _tool_schema(
            "ithz_archive_append_event",
            "Explicit write-enabled profile only: append one sanitized memory event to project.ithz.",
            {**archive_props, "kind": {"type": "string", "enum": ["decision", "gate", "risk", "must_not_break", "next", "note", "cross_zone"]}, "text": {"type": "string"}, "source": {"type": "string"}, "tag": {"type": "array", "items": {"type": "string"}}, "include_git": {"type": "boolean"}},
            ["kind", "text"],
        ),
        _tool_schema(
            "ithz_archive_append_memory_record",
            "Explicit write-enabled profile only: validate and append a source-bound MCP36 typed abstraction. Invalid supersession is quarantined and cannot deactivate history.",
            {**archive_props, "record": {"type": "object", "additionalProperties": True}, "include_git": {"type": "boolean"}},
            ["record"],
        ),
        _tool_schema(
            "ithz_archive_finalize_task",
            "Explicit write-enabled profile only: append an end-of-task checkpoint with docs/memory impact, gates, decisions and next steps.",
            {**archive_props, "task": {"type": "string"}, "summary_text": {"type": "string"}, "decision": {"type": "array", "items": {"type": "string"}}, "gate": {"type": "array", "items": {"type": "string"}}, "risk": {"type": "array", "items": {"type": "string"}}, "next": {"type": "array", "items": {"type": "string"}}, "changed_file": {"type": "array", "items": {"type": "string"}}, "command": {"type": "array", "items": {"type": "string"}}, "docs_impact": {"type": "string", "enum": ["updated", "not-needed", "unknown"]}, "memory_impact": {"type": "string", "enum": ["handoff-created", "not-needed", "unknown"]}, "snapshot": {"type": "boolean"}, "snapshot_mode": {"type": "string", "enum": ["off", "auto", "full", "defer"]}, "include_git": {"type": "boolean"}, "async_mode": {"type": "string", "enum": ["auto", "sync", "async", "never", "always"]}},
            ["task"],
        ),
        _tool_schema(
            "ithz_archive_auto_checkpoint",
            "Explicit write-enabled native end-of-task checkpoint. Hosts should call this automatically before the final answer when durable project memory was produced.",
            {**archive_props, "task": {"type": "string"}, "summary_text": {"type": "string"}, "decision": {"type": "array", "items": {"type": "string"}}, "gate": {"type": "array", "items": {"type": "string"}}, "risk": {"type": "array", "items": {"type": "string"}}, "next": {"type": "array", "items": {"type": "string"}}, "changed_file": {"type": "array", "items": {"type": "string"}}, "command": {"type": "array", "items": {"type": "string"}}, "docs_impact": {"type": "string", "enum": ["updated", "not-needed", "unknown"]}, "memory_impact": {"type": "string", "enum": ["handoff-created", "not-needed", "unknown"]}, "snapshot": {"type": "boolean"}, "snapshot_mode": {"type": "string", "enum": ["off", "auto", "full", "defer"]}, "include_git": {"type": "boolean"}, "async_mode": {"type": "string", "enum": ["auto", "sync", "async", "never", "always"]}},
            ["task", "summary_text"],
        ),
        _tool_schema(
            "ithz_archive_ingest_project_memory",
            "Explicit write-enabled profile only: mine workflow/decision/gate/risk facts from source docs into project.ithz without storing secrets.",
            {**archive_props, "source": {"type": "array", "items": {"type": "string"}}, "note": {"type": "string"}, "include_git": {"type": "boolean"}},
            ["source"],
        ),
        _tool_schema(
            "ithz_archive_record_prompt_response",
            "Explicit write-enabled profile only: record prompt/response summary memory into project.ithz.",
            {**archive_props, "prompt": {"type": "string"}, "response": {"type": "string"}, "task": {"type": "string"}, "mode": {"type": "string", "enum": ["summary", "full-redacted", "full-local-only", "off"]}},
            ["prompt", "response", "task"],
        ),
        _tool_schema(
            "ithz_archive_adopt_project_workflow",
            "Explicit write-enabled profile only: create project.md/project.ithz if needed and mine existing Markdown plus an onboarding prompt into a workflow profile.",
            {**archive_props, "profile": {"type": "string"}, "owner": {"type": "string"}, "prompt": {"type": "string"}, "include_existing_md": {"type": "boolean"}},
            ["profile"],
        ),
        _tool_schema(
            "ithz_workflow_ingest_prompt",
            "Explicit write-enabled profile only: update one workflow profile from a prompt and optional source docs.",
            {**archive_props, "profile": {"type": "string"}, "owner": {"type": "string"}, "prompt": {"type": "string"}, "source": {"type": "array", "items": {"type": "string"}}, "note": {"type": "string"}, "set_default": {"type": "boolean"}},
            ["profile"],
        ),
        _tool_schema(
            "ithz_record_workflow_rule",
            "Explicit write-enabled profile only: store a durable project workflow rule in project.ithz.",
            {**archive_props, "text": {"type": "string"}, "profile": {"type": "string"}, "scope": {"type": "string"}, "source": {"type": "string"}, "tag": {"type": "array", "items": {"type": "string"}}, "include_git": {"type": "boolean"}},
            ["text"],
        ),
        _tool_schema(
            "ithz_record_project_decision",
            "Explicit write-enabled profile only: store a durable project decision in project.ithz.",
            {**archive_props, "text": {"type": "string"}, "profile": {"type": "string"}, "scope": {"type": "string"}, "source": {"type": "string"}, "tag": {"type": "array", "items": {"type": "string"}}, "include_git": {"type": "boolean"}},
            ["text"],
        ),
        _tool_schema(
            "ithz_record_gate_rule",
            "Explicit write-enabled profile only: store a durable gate/test rule in project.ithz.",
            {**archive_props, "text": {"type": "string"}, "profile": {"type": "string"}, "scope": {"type": "string"}, "source": {"type": "string"}, "tag": {"type": "array", "items": {"type": "string"}}, "include_git": {"type": "boolean"}},
            ["text"],
        ),
        _tool_schema(
            "ithz_record_risk_rule",
            "Explicit write-enabled profile only: store a durable risk/must-not-break rule in project.ithz.",
            {**archive_props, "text": {"type": "string"}, "profile": {"type": "string"}, "scope": {"type": "string"}, "source": {"type": "string"}, "tag": {"type": "array", "items": {"type": "string"}}, "include_git": {"type": "boolean"}},
            ["text"],
        ),
        _tool_schema(
            "ithz_ingest_user_instruction",
            "Explicit write-enabled profile only: deterministically classify and store durable user instructions as workflow/decision/gate/risk records.",
            {**archive_props, "text": {"type": "string"}, "profile": {"type": "string"}, "scope": {"type": "string"}, "source": {"type": "string"}, "include_git": {"type": "boolean"}},
            ["text"],
        ),
        _tool_schema(
            "ithz_add_claim",
            "Explicit write-enabled profile only: store an allowed/scoped project claim in the project ledger.",
            {**archive_props, "claim_id": {"type": "string"}, "text": {"type": "string"}, "scope": {"type": "string"}, "supporting_gate": {"type": "array", "items": {"type": "string"}}, "status": {"type": "string"}, "source": {"type": "string"}, "include_git": {"type": "boolean"}},
            ["text"],
        ),
        _tool_schema(
            "ithz_block_claim",
            "Explicit write-enabled profile only: store a blocked project claim with deterministic reason and blocking gates.",
            {**archive_props, "claim_id": {"type": "string"}, "text": {"type": "string"}, "reason": {"type": "string"}, "blocking_gate": {"type": "array", "items": {"type": "string"}}, "status": {"type": "string"}, "source": {"type": "string"}, "include_git": {"type": "boolean"}},
            ["text", "reason"],
        ),
        _tool_schema(
            "ithz_add_reviewer_note",
            "Explicit write-enabled profile only: store a reviewer note linked to a target phase/file/claim.",
            {**archive_props, "note_id": {"type": "string"}, "target": {"type": "string"}, "text": {"type": "string"}, "severity": {"type": "string"}, "source": {"type": "string"}, "include_git": {"type": "boolean"}},
            ["target", "text"],
        ),
        _tool_schema(
            "ithz_create_replication_pack_record",
            "Explicit write-enabled profile only: store a replication pack ledger record.",
            {**archive_props, "pack_id": {"type": "string"}, "witnesses": {"type": "integer"}, "positive": {"type": "integer"}, "negative_stop": {"type": "integer"}, "manifest_path": {"type": "string"}, "public_safe": {"type": "boolean"}, "status": {"type": "string"}, "source": {"type": "string"}, "include_git": {"type": "boolean"}},
            ["pack_id"],
        ),
    ]
    allowed = active_tools(storage_profile, server_mode)
    return [schema for schema in schemas if schema["name"] in allowed]


def _decision_or_gate_history(project: Path, query: str, kind: str) -> dict[str, Any]:
    index = load_index_readonly(project)
    terms = query.lower().split()
    rows = []
    for unit in index["units"]:
        if unit["kind"] != kind:
            continue
        hay = (unit["path"] + " " + unit["text"]).lower()
        if not terms or any(t in hay for t in terms):
            rows.append({k: unit[k] for k in ("path", "line", "kind", "text")})
    rows.sort(key=lambda r: (r["path"], r["line"], r["text"]))
    if kind == "decision":
        for commit in context_log(project):
            for decision in commit.get("decisions", []):
                if not terms or any(t in decision.lower() for t in terms):
                    rows.append({"path": f".ithz_mcp/commits/{commit['context_commit_id']}.json", "line": 0, "kind": "decision", "text": decision})
    return {"kind": kind, "query": query, "rows": rows[:50], "truncated": len(rows) > 50}


def _why_file_readonly(project: Path, rel_path: str) -> dict[str, Any]:
    index = load_index_readonly(project)
    file_entry = next((f for f in index["files"] if f["path"] == rel_path), None)
    units = [
        u for u in index["units"]
        if u["path"] == rel_path and u["kind"] in {"heading", "decision", "gate", "risk_or_next", "symbol"}
    ]
    return {"path": rel_path, "known": file_entry is not None, "file": file_entry, "reasons": units[:20], "index_hash": index["index_hash"]}


def call_tool(method: str, params: dict[str, Any], default_project: Path, storage_profile: str = "legacy", server_mode: str = "read-only") -> Any:
    if method not in active_tools(storage_profile, server_mode) and method not in {"ithz_record_task_summary", "ithz_context_commit", "ithz_update_after_task"}:
        raise RpcError(-32601, "unknown_method", {"method": method})
    project = _project(default_project, params)
    if method == "ithz_context_status":
        return _status(project, storage_profile, server_mode)
    if method == "ithz_search_context":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        limit = int(params.get("limit", 10))
        if storage_profile == "native-archive":
            return native_archive_search(project, query, limit, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))["rows"]
        return search_index(load_index_readonly(project), query, limit)
    if method == "ithz_get_context_pack":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        max_bytes = min(int(params.get("max_bytes", MAX_CONTEXT_PACK_BYTES)), MAX_CONTEXT_PACK_BYTES)
        if storage_profile == "native-archive":
            pack = native_archive_context_pack(project, query, max_bytes, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
            pack["semantic_context_pack_hash"] = pack["context_pack_hash"]
            return pack
        return build_context_pack(project, query, max_bytes)
    if method == "ithz_focus_context_pack":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        target_bytes = min(int(params.get("target_bytes", FOCUS_TARGET_BYTES)), MAX_CONTEXT_PACK_BYTES)
        max_bytes = min(int(params.get("max_bytes", FOCUS_MAX_BYTES)), MAX_CONTEXT_PACK_BYTES)
        try:
            if storage_profile == "native-archive":
                source_pack = native_archive_context_pack(project, query, max_bytes, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
            else:
                source_pack = build_context_pack(project, query, max_bytes)
            return focus_context_pack_from_source(source_pack, query, target_bytes, max_bytes)
        except ValueError as exc:
            raise RpcError(-32602, "invalid_params", {"detail": str(exc)}) from exc
    if method == "ithz_why_file":
        rel = params.get("path")
        if not isinstance(rel, str) or not rel:
            raise RpcError(-32602, "invalid_params", {"missing": "path"})
        return _why_file_readonly(project, rel.replace("\\", "/"))
    if method == "ithz_get_decision_log":
        return _decision_or_gate_history(project, str(params.get("query", "")), "decision")
    if method == "ithz_get_gate_history":
        return _decision_or_gate_history(project, str(params.get("query", "")), "gate")
    if method == "ithz_archive_status":
        return native_archive_status(project, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
    if method == "ithz_archive_zone_status":
        return archive_zone_status(project, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
    if method == "ithz_archive_memory_index_status":
        return archive_memory_index_status(project, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
    if method == "ithz_archive_search_context":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        limit = int(params.get("limit", 10))
        return native_archive_search(project, query, limit, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
    if method == "ithz_archive_get_context_pack":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        max_bytes = min(int(params.get("max_bytes", MAX_CONTEXT_PACK_BYTES)), MAX_CONTEXT_PACK_BYTES)
        return native_archive_context_pack(project, query, max_bytes, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
    if method == "ithz_archive_cross_zone_context_pack":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        max_bytes = min(int(params.get("max_bytes", MAX_CONTEXT_PACK_BYTES)), MAX_CONTEXT_PACK_BYTES)
        return archive_cross_zone_context_pack(project, query, max_bytes, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
    if method == "ithz_workflow_profile_status":
        return workflow_profile_status(project)
    if method == "ithz_workflow_context_pack":
        query = params.get("query")
        profile = params.get("profile")
        if not isinstance(query, str) or not isinstance(profile, str):
            raise RpcError(-32602, "invalid_params", {"missing": "profile_or_query"})
        max_bytes = min(int(params.get("max_bytes", MAX_CONTEXT_PACK_BYTES)), MAX_CONTEXT_PACK_BYTES)
        return workflow_context_pack(project, profile, query, max_bytes)
    if method == "ithz_durable_instruction_status":
        return durable_instruction_status(project, None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
    if method == "ithz_list_allowed_claims":
        return list_allowed_claims(project)
    if method == "ithz_list_blocked_claims":
        return list_blocked_claims(project)
    if method == "ithz_get_claim_evidence":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        return get_claim_evidence(project, query)
    if method == "ithz_can_i_claim":
        query = params.get("query") or params.get("claim")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query_or_claim"})
        return can_i_claim(project, query)
    if method == "ithz_get_project_ledger_summary":
        return project_ledger_summary(project)
    if method == "ithz_rag_status":
        return rag_status(project)
    if method == "ithz_rag_search":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        limit = min(max(int(params.get("limit", 12)), 1), 50)
        try:
            return rag_search(project, query, limit=limit, write_cache=False, write_index=False)
        except Exception as exc:
            raise RpcError(-32010, "rag_index_unavailable", {"detail": str(exc), "next": "run rag-index-build or rag-context-pack outside the read-only MCP server"}) from exc
    if method == "ithz_rag_context_pack":
        query = params.get("query")
        if not isinstance(query, str):
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        max_bytes = min(int(params.get("max_bytes", MAX_CONTEXT_PACK_BYTES)), MAX_CONTEXT_PACK_BYTES)
        try:
            return compile_rag_context_pack(project, query, max_bytes=max_bytes, write_cache=False, write_index=False)
        except Exception as exc:
            raise RpcError(-32010, "rag_index_unavailable", {"detail": str(exc), "next": "run rag-index-build or rag-context-pack outside the read-only MCP server"}) from exc
    if method == "ithz_memory_integrity_status":
        query = params.get("query")
        if not isinstance(query, str) or not query.strip():
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        projection = native_archive_current_projection(project, query[:1200], 8)
        return memory_integrity_status(projection)
    if method == "ithz_archive_append_event":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        kind = params.get("kind")
        text = params.get("text")
        if not isinstance(kind, str) or not isinstance(text, str):
            raise RpcError(-32602, "invalid_params", {"missing": "kind_or_text"})
        return archive_append_event(project, kind, text, str(params.get("source", "mcp_write_enabled")), [str(t) for t in params.get("tag", [])], None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"), bool(params.get("include_git", False)))
    if method == "ithz_archive_append_memory_record":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        record = params.get("record")
        if not isinstance(record, dict):
            raise RpcError(-32602, "invalid_params", {"missing": "record"})
        return archive_append_memory_record(
            project,
            record,
            None,
            str(params.get("memory_zone", "nearest")),
            params.get("memory_zone_path"),
            bool(params.get("include_git", False)),
        )
    if method == "ithz_archive_finalize_task":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        task = params.get("task")
        if not isinstance(task, str):
            raise RpcError(-32602, "invalid_params", {"missing": "task"})
        payload = _checkpoint_payload(project, task, str(params.get("summary_text", "")), params, "unknown", False)
        return _maybe_queue_or_finalize_checkpoint(payload, params)
    if method == "ithz_archive_auto_checkpoint":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        task = params.get("task")
        summary_text = params.get("summary_text")
        if not isinstance(task, str) or not isinstance(summary_text, str):
            raise RpcError(-32602, "invalid_params", {"missing": "task_or_summary_text"})
        payload = _checkpoint_payload(project, task, summary_text, params, "handoff-created", True)
        return _maybe_queue_or_finalize_checkpoint(payload, params)
    if method == "ithz_archive_ingest_project_memory":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        sources = params.get("source")
        if not isinstance(sources, list):
            raise RpcError(-32602, "invalid_params", {"missing": "source"})
        return archive_ingest_project_memory(project, [Path(str(s)) for s in sources], str(params.get("note", "")), None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"), bool(params.get("include_git", False)))
    if method == "ithz_archive_record_prompt_response":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        prompt = params.get("prompt")
        response = params.get("response")
        task = params.get("task")
        if not all(isinstance(v, str) for v in (prompt, response, task)):
            raise RpcError(-32602, "invalid_params", {"missing": "prompt_response_or_task"})
        return native_archive_record_prompt_response(project, Path(str(prompt)), Path(str(response)), str(task), str(params.get("mode", "summary")), None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"))
    if method == "ithz_archive_adopt_project_workflow":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        profile = params.get("profile")
        if not isinstance(profile, str):
            raise RpcError(-32602, "invalid_params", {"missing": "profile"})
        prompt = params.get("prompt")
        return archive_adopt_project_workflow(project, profile, str(params.get("owner", "")), Path(str(prompt)) if isinstance(prompt, str) and prompt else None, bool(params.get("include_existing_md", True)))
    if method == "ithz_workflow_ingest_prompt":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        profile = params.get("profile")
        if not isinstance(profile, str):
            raise RpcError(-32602, "invalid_params", {"missing": "profile"})
        prompt = params.get("prompt")
        return archive_update_workflow_profile(project, profile, str(params.get("owner", "")), Path(str(prompt)) if isinstance(prompt, str) and prompt else None, [Path(str(s)) for s in params.get("source", [])], str(params.get("note", "")), None, bool(params.get("set_default", False)))
    if method in {"ithz_record_workflow_rule", "ithz_record_project_decision", "ithz_record_gate_rule", "ithz_record_risk_rule"}:
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        text = params.get("text")
        if not isinstance(text, str) or not text.strip():
            raise RpcError(-32602, "invalid_params", {"missing": "text"})
        instruction_type = {
            "ithz_record_workflow_rule": "workflow_rule",
            "ithz_record_project_decision": "project_decision",
            "ithz_record_gate_rule": "gate_rule",
            "ithz_record_risk_rule": "risk_rule",
        }[method]
        return record_durable_instruction(
            project,
            instruction_type,
            text,
            str(params.get("profile", "default")),
            str(params.get("scope", "project")),
            str(params.get("source", "mcp_write_enabled")),
            [str(t) for t in params.get("tag", [])],
            {},
            None,
            str(params.get("memory_zone", "nearest")),
            params.get("memory_zone_path"),
            bool(params.get("include_git", False)),
        )
    if method == "ithz_add_claim":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        text = params.get("text")
        if not isinstance(text, str):
            raise RpcError(-32602, "invalid_params", {"missing": "text"})
        return add_claim(project, text, params.get("claim_id") if isinstance(params.get("claim_id"), str) else None, str(params.get("scope", "project")), [str(v) for v in params.get("supporting_gate", [])], str(params.get("status", "allowed_scoped")), str(params.get("source", "mcp_write_enabled")), None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"), bool(params.get("include_git", False)))
    if method == "ithz_block_claim":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        text = params.get("text")
        reason = params.get("reason")
        if not isinstance(text, str) or not isinstance(reason, str):
            raise RpcError(-32602, "invalid_params", {"missing": "text_or_reason"})
        return block_claim(project, text, reason, params.get("claim_id") if isinstance(params.get("claim_id"), str) else None, [str(v) for v in params.get("blocking_gate", [])], str(params.get("status", "blocked")), str(params.get("source", "mcp_write_enabled")), None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"), bool(params.get("include_git", False)))
    if method == "ithz_add_reviewer_note":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        text = params.get("text")
        target = params.get("target")
        if not isinstance(text, str) or not isinstance(target, str):
            raise RpcError(-32602, "invalid_params", {"missing": "target_or_text"})
        return add_reviewer_note(project, text, target, params.get("note_id") if isinstance(params.get("note_id"), str) else None, str(params.get("severity", "guidance")), str(params.get("source", "mcp_write_enabled")), None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"), bool(params.get("include_git", False)))
    if method == "ithz_create_replication_pack_record":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        pack_id = params.get("pack_id")
        if not isinstance(pack_id, str):
            raise RpcError(-32602, "invalid_params", {"missing": "pack_id"})
        return create_replication_pack_record(project, pack_id, int(params.get("witnesses", 0)), int(params.get("positive", 0)), int(params.get("negative_stop", 0)), str(params.get("manifest_path", "")), bool(params.get("public_safe", False)), str(params.get("status", "recorded")), str(params.get("source", "mcp_write_enabled")), None, str(params.get("memory_zone", "nearest")), params.get("memory_zone_path"), bool(params.get("include_git", False)))
    if method == "ithz_ingest_user_instruction":
        if server_mode != "write-enabled":
            raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
        text = params.get("text")
        if not isinstance(text, str) or not text.strip():
            raise RpcError(-32602, "invalid_params", {"missing": "text"})
        return ingest_user_instruction(
            project,
            text,
            str(params.get("profile", "default")),
            str(params.get("scope", "project")),
            str(params.get("source", "mcp_write_enabled")),
            None,
            str(params.get("memory_zone", "nearest")),
            params.get("memory_zone_path"),
            bool(params.get("include_git", False)),
        )
    if method in {"ithz_record_task_summary", "ithz_context_commit", "ithz_update_after_task"}:
        raise RpcError(-32001, "write_back_disabled_in_read_only_phase")
    raise RpcError(-32601, "unknown_method", {"method": method})

def _mcp_initialize(req: dict[str, Any], storage_profile: str = "legacy", server_mode: str = "read-only") -> dict[str, Any]:
    params = _params(req)
    protocol = params.get("protocolVersion") or "2024-11-05"
    return {
        "protocolVersion": protocol,
        "capabilities": {"tools": {}},
        "serverInfo": {
            "name": MCP_BRAND_NAME,
            "title": MCP_BRAND_TITLE,
            "version": VERSION,
            "_meta": {"ithz": mcp_icon_metadata()},
        },
        "instructions": memory_instructions(storage_profile, server_mode),
    }


def _compact_tool_structured_content(value: Any) -> dict[str, Any]:
    clean = sanitize_json_value(value)
    if not isinstance(clean, dict):
        return {"value": clean}
    update = clean.get("update") if isinstance(clean.get("update"), dict) else {}
    append = clean.get("append") if isinstance(clean.get("append"), dict) else {}
    snapshot = clean.get("snapshot") if isinstance(clean.get("snapshot"), dict) else clean.get("snapshot")
    structured: dict[str, Any] = {
        key: clean[key]
        for key in (
            "finalized",
            "queued",
            "queue_reason",
            "appended",
            "recorded",
            "ingested",
            "project",
            "active_memory_zone",
            "task",
            "request_hash",
            "pid",
            "job_log",
            "event_count",
            "appended_count",
            "checkpoint_hash",
            "context_pack_hash",
            "current_index_hash",
            "memory_synthesis_hash",
            "rag_index_hash",
            "rag_pack_hash",
            "focus_pack_hash",
            "source_pack_hash",
            "source_index_hash",
            "embedding_backend",
            "row_count",
            "rag_row_count",
            "selected_files",
            "bytes",
            "source_pack_bytes",
            "source_pack_truncated",
            "bytes_saved_vs_source",
            "estimated_tokens",
            "estimated_tokens_saved_vs_source",
            "budget_tier",
            "escalated",
            "escalation_reason",
            "fallback_required",
            "query_term_coverage",
            "cache_status",
        )
        if key in clean
    }
    if isinstance(append, dict):
        structured["append"] = {
            key: append.get(key)
            for key in ("appended", "appended_count", "event_count", "current_index_hash", "memory_synthesis_hash")
            if key in append
        }
    if isinstance(update, dict):
        structured["update"] = {
            key: update.get(key)
            for key in ("updated", "archive_sha256_before", "archive_sha256_after", "manifest_bytes", "archive_bytes")
            if key in update
        }
    if isinstance(snapshot, dict):
        structured["snapshot"] = {
            key: snapshot.get(key)
            for key in ("snapshot_created", "snapshot_deferred", "reason", "snapshot_id", "snapshot_hash")
            if key in snapshot
        }
    return structured or {"ok": True}


def _compact_tool_text(value: Any) -> str:
    clean = sanitize_json_value(value)
    if (
        isinstance(clean, dict)
        and isinstance(clean.get("text"), str)
        and (
            clean.get("schema") == RAG_PACK_SCHEMA
            or clean.get("schema") == FOCUS_PACK_SCHEMA
            or "context_pack_hash" in clean
            or "rag_pack_hash" in clean
            or "focus_pack_hash" in clean
        )
    ):
        return clean["text"]
    compact = _compact_tool_structured_content(value)
    return dumps(compact)


def _mcp_tool_result(value: Any) -> dict[str, Any]:
    clean = sanitize_json_value(value)
    return {
        "content": [{"type": "text", "text": _compact_tool_text(clean)}],
        "structuredContent": _compact_tool_structured_content(clean),
        "isError": False,
    }


def handle_request(req: Any, default_project: Path, storage_profile: str = "legacy", server_mode: str = "read-only") -> dict[str, Any] | None:
    if not isinstance(req, dict):
        raise RpcError(-32600, "invalid_request", {"reason": "request_must_be_object"})
    req_id = req.get("id")
    method = req.get("method")
    if method is None:
        raise RpcError(-32600, "missing_method")
    if not isinstance(method, str):
        raise RpcError(-32600, "invalid_method")
    params = _params(req)
    if method == "initialize":
        result = _mcp_initialize(req, storage_profile, server_mode)
    elif method == "tools/list":
        result = {"tools": mcp_tool_schemas(storage_profile, server_mode)}
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str):
            raise RpcError(-32602, "invalid_params", {"missing": "name"})
        if not isinstance(arguments, dict):
            raise RpcError(-32602, "invalid_params", {"reason": "arguments_must_be_object"})
        result = _mcp_tool_result(call_tool(name, arguments, default_project, storage_profile, server_mode))
    else:
        result = call_tool(method, params, default_project, storage_profile, server_mode)
    if "id" not in req:
        return None
    return _result(req_id, result)


def handle_line(line: str, default_project: Path, storage_profile: str = "legacy", server_mode: str = "read-only") -> dict[str, Any] | None:
    try:
        req = json.loads(line)
    except json.JSONDecodeError as exc:
        return _error(None, -32700, "parse_error", {"detail": str(exc)})
    req_id = req.get("id") if isinstance(req, dict) else None
    try:
        return handle_request(req, default_project, storage_profile, server_mode)
    except RpcError as exc:
        if "id" not in req if isinstance(req, dict) else True:
            return None
        return _error(req_id, exc.code, exc.message, exc.data)
    except Exception as exc:
        if "id" not in req if isinstance(req, dict) else True:
            return None
        return _error(req_id, -32603, "internal_error", {"detail": str(exc)})


def _write_jsonrpc_line(stdout: Any, value: dict[str, Any]) -> None:
    line = dumps(value) + "\n"
    buffer = getattr(stdout, "buffer", None)
    if buffer is not None:
        buffer.write(line.encode("utf-8"))
        buffer.flush()
        return
    print(line, file=stdout, end="", flush=True)


def serve_stdio(default_project: Path, stdin: Any, stdout: Any, protocol: str = "mcp", storage_profile: str = "legacy", server_mode: str = "read-only") -> None:
    if protocol == "direct":
        _write_jsonrpc_line(stdout, _status(default_project, storage_profile, server_mode))
    for line in stdin:
        response = handle_line(line, default_project, storage_profile, server_mode)
        if response is not None:
            _write_jsonrpc_line(stdout, response)


def client_smoke(project: Path) -> list[dict[str, Any]]:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"project": str(project)}},
        {"jsonrpc": "2.0", "id": 2, "method": "ithz_context_status", "params": {"project": str(project)}},
        {"jsonrpc": "2.0", "id": 3, "method": "ithz_search_context", "params": {"project": str(project), "query": "decision", "limit": 3}},
        {"jsonrpc": "2.0", "id": 4, "method": "ithz_get_context_pack", "params": {"project": str(project), "query": "decision", "max_bytes": 4000}},
        {"jsonrpc": "2.0", "id": 5, "method": "ithz_why_file", "params": {"project": str(project), "path": "docs/decisions.md"}},
        {"jsonrpc": "2.0", "id": 8, "method": "ithz_get_decision_log", "params": {"project": str(project), "query": "MCP0"}},
        {"jsonrpc": "2.0", "id": 9, "method": "ithz_get_gate_history", "params": {"project": str(project), "query": "gate"}},
        "{not-json",
        {"jsonrpc": "2.0", "id": 6, "method": "unknown_tool", "params": {}},
        {"jsonrpc": "2.0", "id": 7, "method": "ithz_search_context", "params": {"project": str(project)}},
        {"jsonrpc": "2.0", "method": "ithz_context_status", "params": {"project": str(project)}},
    ]
    transcript: list[dict[str, Any]] = []
    for req in requests:
        if isinstance(req, str):
            response = handle_line(req, project)
            transcript.append({"request": req, "response": response})
        else:
            response = handle_line(dumps(req), project)
            transcript.append({"request": req, "response": response})
    return transcript
