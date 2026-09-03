from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .canonical_json import dumps
from . import version_info
from .branding import MCP_BRAND_TITLE, mcp_icon_metadata
from .mcp_server import MAX_CONTEXT_PACK_BYTES, MAX_RESPONSE_BYTES, TOOLS, active_tools, _result

WRITE_TOOL_NAMES = {
    "ithz_update_after_task",
    "ithz_record_task_summary",
    "ithz_context_commit",
    "context_push",
    "context_pull",
    "ithz_archive_append_event",
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


def config_template(project: Path, client: str = "codex", storage_profile: str = "legacy", mode: str = "read-only") -> dict[str, Any]:
    return config_template_with_mode(project, client, storage_profile, mode)


def config_template_with_mode(project: Path, client: str = "codex", storage_profile: str = "legacy", mode: str = "read-only") -> dict[str, Any]:
    project = project.resolve()
    if mode not in {"read-only", "write-enabled"}:
        raise ValueError("unsupported_mcp_mode")
    protocol = "mcp" if client in {"codex", "claude-code", "antigravity", "cursor"} else "direct"
    version = version_info()
    server = {
        "command": sys.executable,
        "args": [
            "-m",
            "ithz_mcp",
            "mcp-server",
            "--project",
            str(project),
            "--mode",
            mode,
            "--protocol",
            protocol,
            "--storage-profile",
            storage_profile,
        ],
        "env": {},
        "read_only": mode == "read-only",
        "mode": mode,
        "protocol": protocol,
        "display_name": MCP_BRAND_TITLE,
        "icon": mcp_icon_metadata(),
        "storage_profile": storage_profile,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "max_context_pack_bytes": MAX_CONTEXT_PACK_BYTES,
        "ithz_mcp_version": version.get("version"),
        "ithz_mcp_build_id": version.get("build_id"),
        "ithz_mcp_package_filename": version.get("package_filename"),
        "tools": sorted(active_tools(storage_profile, mode)),
        "agent_policy": {
            "memory_first": True,
            "bootstrap_file": "project.md",
            "bootstrap_statement": "Markdown is the bootstrap. ITHZ is the memory zone.",
            "startup_sequence": [
                "read_project_bootstrap",
                "ithz_context_status",
                "ithz_workflow_profile_status",
                "ithz_focus_context_pack",
            ],
            "end_of_task_sequence": [
                "summarize_task",
                "evaluate_documentation_impact",
                "evaluate_memory_impact",
                "ithz_archive_auto_checkpoint" if mode == "write-enabled" else "ithz_archive_finalize_task",
            ],
            "broad_codebase_read_after_context_pack": True,
            "hard_enforcement_depends_on_host_tool_permissions": True,
            "write_tools_require_explicit_write_enabled_profile": True,
            "workflow_profile_updates_use": "ithz_workflow_ingest_prompt",
            "durable_instruction_capture": {
                "enabled": mode == "write-enabled",
                "workflow_rule_tool": "ithz_record_workflow_rule",
                "decision_tool": "ithz_record_project_decision",
                "gate_tool": "ithz_record_gate_rule",
                "risk_tool": "ithz_record_risk_rule",
                "ingest_tool": "ithz_ingest_user_instruction",
                "when": "when_user_gives_lasting_project_instruction",
            },
            "auto_checkpoint": {
                "enabled": mode == "write-enabled",
                "tool": "ithz_archive_auto_checkpoint",
                "when": "end_of_task_before_final_answer",
                "native_archive": storage_profile == "native-archive",
                "requires_summary_text": True,
                "requires_explicit_write_enabled_profile": True,
            },
            "project_ledger": {
                "enabled": True,
                "read_tools": ["ithz_can_i_claim", "ithz_list_allowed_claims", "ithz_list_blocked_claims", "ithz_get_project_ledger_summary"],
                "write_tools_enabled": mode == "write-enabled",
                "write_tools": ["ithz_add_claim", "ithz_block_claim", "ithz_add_reviewer_note", "ithz_create_replication_pack_record"],
            },
        },
    }
    if client == "codex":
        return {"client": "codex", "mcpServers": {"ithz-mcp": server}}
    if client == "claude-code":
        return {"client": "claude-code", "mcpServers": {"ithz-mcp": server}}
    if client == "antigravity":
        return {"client": "antigravity", "mcpServers": {"ithz-mcp": server}}
    if client == "cursor":
        return {"client": "cursor", "mcpServers": {"ithz-mcp": server}}
    if client == "generic-jsonrpc":
        return {"client": "generic-jsonrpc", "server": server, "framing": "line-delimited-json-rpc-2.0"}
    raise ValueError("unsupported_client")


def _server_from_config(config: dict[str, Any]) -> dict[str, Any]:
    if "mcpServers" in config:
        servers = config.get("mcpServers")
        if not isinstance(servers, dict) or "ithz-mcp" not in servers:
            raise ValueError("missing_ithz_mcp_server")
        server = servers["ithz-mcp"]
    else:
        server = config.get("server")
    if not isinstance(server, dict):
        raise ValueError("server_config_must_be_object")
    return server


def validate_config(config_path: Path) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    server = _server_from_config(config)
    command = server.get("command")
    args = server.get("args", [])
    tools = set(server.get("tools", []))
    rows: list[dict[str, Any]] = []
    command_ok = isinstance(command, str) and (Path(command).exists() or shutil.which(command) is not None)
    rows.append({"check": "command_exists", "passed": command_ok, "value": command})
    args_ok = isinstance(args, list) and "mcp-server" in args and "--mode" in args and ("read-only" in args or "write-enabled" in args)
    rows.append({"check": "args_server_invocation_valid", "passed": args_ok, "value": " ".join(str(a) for a in args) if isinstance(args, list) else ""})
    protocol = "mcp" if isinstance(args, list) and "--protocol" in args and "mcp" in args else server.get("protocol", "direct")
    project = extract_project_from_server(server)
    rows.append({"check": "project_path_exists", "passed": project.exists(), "value": str(project)})
    server_mode = str(server.get("mode") or ("read-only" if server.get("read_only") is True else "write-enabled"))
    rows.append({"check": "mode_valid", "passed": server_mode in {"read-only", "write-enabled"}, "value": server_mode})
    rows.append({"check": "protocol_valid", "passed": protocol in {"mcp", "direct"}, "value": protocol})
    rows.append({"check": "max_response_bytes_present", "passed": isinstance(server.get("max_response_bytes"), int), "value": server.get("max_response_bytes")})
    rows.append({"check": "max_context_pack_bytes_present", "passed": isinstance(server.get("max_context_pack_bytes"), int), "value": server.get("max_context_pack_bytes")})
    policy = server.get("agent_policy", {})
    rows.append({"check": "memory_first_policy_present", "passed": isinstance(policy, dict) and policy.get("memory_first") is True, "value": policy.get("startup_sequence") if isinstance(policy, dict) else ""})
    bootstrap_file = policy.get("bootstrap_file") if isinstance(policy, dict) else None
    rows.append({"check": "memory_first_bootstrap_file_declared", "passed": bootstrap_file == "project.md", "value": bootstrap_file})
    rows.append({"check": "memory_first_bootstrap_file_exists", "passed": (project / "project.md").exists(), "value": str(project / "project.md")})
    rows.append({"check": "ithz_mcp_build_id_present", "passed": isinstance(server.get("ithz_mcp_build_id"), str) and bool(server.get("ithz_mcp_build_id")), "value": server.get("ithz_mcp_build_id")})
    rows.append({"check": "no_write_tools_exposed", "passed": server_mode == "write-enabled" or not (tools & WRITE_TOOL_NAMES), "value": ",".join(sorted(tools & WRITE_TOOL_NAMES))})
    rows.append({"check": "write_enabled_explicit", "passed": server_mode == "read-only" or ("write-enabled" in args and server.get("read_only") is False), "value": server_mode})
    return {"config": str(config_path), "project": str(project), "passed": all(bool(r["passed"]) for r in rows), "rows": rows, "server": server}


def extract_project_from_server(server: dict[str, Any]) -> Path:
    args = server.get("args", [])
    if not isinstance(args, list):
        raise ValueError("args_must_be_list")
    if "--project" in args:
        idx = args.index("--project")
        if idx + 1 < len(args):
            return Path(str(args[idx + 1])).resolve()
    return Path(".").resolve()


def scripted_client_smoke(config_path: Path, transcript_path: Path | None = None) -> dict[str, Any]:
    validation = validate_config(config_path)
    if not validation["passed"]:
        return {"passed": False, "validation": validation, "transcript": []}
    server = validation["server"]
    command = str(server["command"])
    args = [str(a) for a in server["args"]]
    project = validation["project"]
    requests: list[Any] = [
        {"jsonrpc": "2.0", "id": "initialize", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "ithz-mcp-scripted-smoke", "version": "0"}}},
        {"jsonrpc": "2.0", "id": "tools_list", "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": "tools_call_status", "method": "tools/call", "params": {"name": "ithz_context_status", "arguments": {"project": project}}},
        {"jsonrpc": "2.0", "id": "archive_status", "method": "ithz_archive_status", "params": {"project": project}},
        {"jsonrpc": "2.0", "id": "status", "method": "ithz_context_status", "params": {"project": project}},
        {"jsonrpc": "2.0", "id": "search", "method": "ithz_search_context", "params": {"project": project, "query": "decision gate risk", "limit": 5}},
        {"jsonrpc": "2.0", "id": "archive_search", "method": "ithz_archive_search_context", "params": {"project": project, "query": "decision gate risk", "limit": 5}},
        {"jsonrpc": "2.0", "id": "pack", "method": "ithz_get_context_pack", "params": {"project": project, "query": "decision gate risk", "max_bytes": 4000}},
        {"jsonrpc": "2.0", "id": "focus_pack", "method": "ithz_focus_context_pack", "params": {"project": project, "query": "decision gate risk", "target_bytes": 1000, "max_bytes": 4000}},
        {"jsonrpc": "2.0", "id": "archive_pack", "method": "ithz_archive_get_context_pack", "params": {"project": project, "query": "decision gate risk", "max_bytes": 4000}},
        {"jsonrpc": "2.0", "id": "why", "method": "ithz_why_file", "params": {"project": project, "path": "docs/decisions.md"}},
        {"jsonrpc": "2.0", "id": "decisions", "method": "ithz_get_decision_log", "params": {"project": project, "query": "decision"}},
        {"jsonrpc": "2.0", "id": "gates", "method": "ithz_get_gate_history", "params": {"project": project, "query": "gate"}},
        "{not-json",
        {"jsonrpc": "2.0", "id": "unknown", "method": "unknown_method", "params": {}},
        {"jsonrpc": "2.0", "id": "invalid", "method": "ithz_search_context", "params": {"project": project}},
    ]
    transcript: list[dict[str, Any]] = []
    proc = subprocess.Popen([command, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        protocol = "mcp" if "--protocol" in args and "mcp" in args else str(server.get("protocol", "direct"))
        if protocol == "direct":
            initial = proc.stdout.readline().strip() if proc.stdout else ""
            transcript.append({"event": "server_initial_status", "line": initial})
        for req in requests:
            line = req if isinstance(req, str) else dumps(req)
            assert proc.stdin is not None and proc.stdout is not None
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            response_line = proc.stdout.readline().strip()
            try:
                response = json.loads(response_line)
            except json.JSONDecodeError:
                response = {"decode_error": response_line}
            transcript.append({"request": req, "response": response})
    finally:
        if proc.stdin:
            proc.stdin.close()
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    limit_response = _result("limit", {"blob": "x" * (MAX_RESPONSE_BYTES + 1000)})
    transcript.append({"request": "response_limit_direct", "response": limit_response})
    if transcript_path:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with transcript_path.open("w", encoding="utf-8", newline="\n") as f:
            for row in transcript:
                f.write(dumps(row) + "\n")
    by_id = {}
    for row in transcript:
        response = row.get("response")
        if isinstance(response, dict) and response.get("id") is not None:
            by_id[response["id"]] = response
    exposed_tools = set(server.get("tools", []))
    expects_archive = bool(exposed_tools & {"ithz_archive_status", "ithz_archive_search_context", "ithz_archive_get_context_pack"})
    initialize_result = by_id.get("initialize", {}).get("result", {})
    server_info = initialize_result.get("serverInfo", {}) if isinstance(initialize_result, dict) else {}
    rows = [
        {"check": "initialize", "passed": "serverInfo" in by_id.get("initialize", {}).get("result", {})},
        {"check": "initialize_brand_title", "passed": server_info.get("title") == "ITHZ-MCP", "value": server_info.get("title")},
        {"check": "initialize_icon_metadata", "passed": isinstance(server_info.get("_meta", {}).get("ithz", {}).get("icon_data_uri"), str), "value": server_info.get("_meta", {}).get("ithz", {}).get("icon_type")},
        {"check": "tools_list", "passed": isinstance(by_id.get("tools_list", {}).get("result", {}).get("tools"), list)},
        {"check": "tools_call_status", "passed": "content" in by_id.get("tools_call_status", {}).get("result", {})},
        {"check": "status", "passed": "result" in by_id.get("status", {})},
        {"check": "archive_status", "passed": (not expects_archive) or "exists" in by_id.get("archive_status", {}).get("result", {})},
        {"check": "search", "passed": isinstance(by_id.get("search", {}).get("result"), list) or isinstance(by_id.get("archive_search", {}).get("result", {}).get("rows"), list)},
        {"check": "archive_search", "passed": (not expects_archive) or isinstance(by_id.get("archive_search", {}).get("result", {}).get("rows"), list)},
        {"check": "context_pack", "passed": "semantic_context_pack_hash" in by_id.get("pack", {}).get("result", {}) or "context_pack_hash" in by_id.get("archive_pack", {}).get("result", {})},
        {"check": "focus_context_pack", "passed": "focus_pack_hash" in by_id.get("focus_pack", {}).get("result", {})},
        {"check": "archive_context_pack", "passed": (not expects_archive) or "context_pack_hash" in by_id.get("archive_pack", {}).get("result", {})},
        {"check": "why_file", "passed": ("ithz_why_file" not in exposed_tools) or "result" in by_id.get("why", {})},
        {"check": "decision_log", "passed": ("ithz_get_decision_log" not in exposed_tools) or "rows" in by_id.get("decisions", {}).get("result", {})},
        {"check": "gate_history", "passed": ("ithz_get_gate_history" not in exposed_tools) or "rows" in by_id.get("gates", {}).get("result", {})},
        {"check": "invalid_json", "passed": any(row.get("response", {}).get("error", {}).get("message") == "parse_error" for row in transcript if isinstance(row.get("response"), dict))},
        {"check": "unknown_method", "passed": by_id.get("unknown", {}).get("error", {}).get("message") == "unknown_method"},
        {"check": "invalid_params", "passed": by_id.get("invalid", {}).get("error", {}).get("message") == "invalid_params"},
        {"check": "request_ids_preserved", "passed": all(k == by_id[k].get("id") for k in by_id)},
        {"check": "response_limit_behavior", "passed": limit_response.get("result", {}).get("truncated") is True},
    ]
    return {
        "passed": validation["passed"] and all(bool(r["passed"]) for r in rows),
        "validation": validation,
        "rows": rows,
        "transcript": transcript,
        "external_client_available": False,
        "scripted_stdio_client_passed": all(bool(r["passed"]) for r in rows),
    }
