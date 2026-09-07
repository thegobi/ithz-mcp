from __future__ import annotations

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Any

from .. import VERSION
from ..canonical_json import dumps, sanitize_json_value
from .court import CCG_VERSION, CourtRunner, initialize_project
from .ledger import EvidenceLedger
from .models import CodexAppServerBackend, ScriptedBackend
from .settings_store import effective_preferences


MAX_RESPONSE_BYTES = 262144


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _result(request_id: Any, value: Any) -> dict[str, Any]:
    response = {"jsonrpc": "2.0", "id": request_id, "result": sanitize_json_value(value)}
    if len(dumps(response).encode("utf-8")) > MAX_RESPONSE_BYTES:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "truncated": True,
                "reason": "ccg_mcp_max_response_bytes",
                "max_response_bytes": MAX_RESPONSE_BYTES,
            },
        }
    return response


def _error(request_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = sanitize_json_value(data)
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _schema(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
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


def tool_schemas() -> list[dict[str, Any]]:
    project = {"type": "string", "description": "Absolute or relative project root. Defaults to server project."}
    case_id = {"type": "string", "description": "CCG case identifier."}
    return [
        _schema("ccg_status", "Show CCG, model fallback, constitution and ITHZ evidence status.", {"project": project}),
        _schema(
            "ccg_memory_integrity_status",
            "Compile the MCP36 read-only memory influence receipt and role-specific evidence-view hashes for a query.",
            {"project": project, "query": {"type": "string", "maxLength": 1200}},
        ),
        _schema(
            "ccg_memory_integrity_selftest",
            "Run deterministic no-memory, episodic, MCP35 baseline, MCP36 hybrid and poisoned-memory safety fixtures without an external model.",
            {},
        ),
        _schema(
            "ccg_mcp36_canary_status",
            "Read the local MCP36.4 opt-in canary state. Canary is absent and off by default; status never enables it.",
            {"project": project},
        ),
        _schema(
            "ccg_mcp36_canary_enable",
            "Explicitly enable one bounded local MCP36.4 shadow rollout. It permits only analysis.read, requires independent cross-lab metering, never issues a capability token and never mirrors cases to project.ithz.",
            {
                "project": project,
                "max_cases": {"type": "integer", "minimum": 1, "maximum": 25, "default": 5},
                "expires_hours": {"type": "integer", "minimum": 1, "maximum": 168, "default": 24},
            },
        ),
        _schema(
            "ccg_mcp36_canary_pause",
            "Activate the local MCP36.4 canary kill switch. Existing receipts remain immutable and no new canary case is admitted.",
            {"project": project},
        ),
        _schema(
            "ccg_run_mcp36_canary_case",
            "Run one fresh five-role MCP36.4 shadow case after explicit opt-in. Capability is fixed to analysis.read; independent Gemini or Grok opposition and complete metering are mandatory.",
            {
                "project": project,
                "task": {"type": "string", "maxLength": 12000},
                "risk": {"type": "string", "enum": ["low", "medium", "high", "critical"], "default": "high"},
                "cross_lab_provider": {"type": "string", "enum": ["gemini", "grok"], "default": "gemini"},
            },
            ["task"],
        ),
        _schema(
            "ccg_initialize_project",
            "Create the universal baseline constitution and local ignored CCG/ITHZ evidence directories without overwriting an existing constitution.",
            {"project": project, "overwrite": {"type": "boolean", "default": False}},
        ),
        _schema(
            "ccg_run_case",
            "Run or safely reuse a five-role review with Daybreak security opposition and Gemini-first cross-lab opposition.",
            {
                "project": project,
                "task": {"type": "string", "maxLength": 12000},
                "risk": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "capability": {"type": "string"},
                "use_grok": {"type": "string", "enum": ["auto", "required", "off"], "default": "auto"},
                "opponent_2": {
                    "type": "string",
                    "enum": ["auto", "gemini", "grok", "off"],
                    "default": "auto",
                },
                "use_daybreak": {"type": "string", "enum": ["auto", "required", "off"], "default": "auto"},
                "reuse_decision": {"type": "string", "enum": ["auto", "off"], "default": "auto"},
                "blind_first_pass": {"type": "boolean", "default": False, "description": "Optional six-run raw-first pass sealed before the proposal."},
            },
            ["task", "risk", "capability"],
        ),
        _schema(
            "ccg_run_final_case",
            "Run at most one fully metered high-risk final review for an exact completed ITHZ checkpoint. MCP36 requires a checkpoint-bound v2 manifest, runtime-verifiable command output artifacts and role-specific evidence views before model calls. Capability is fixed to analysis.read, decision reuse is automatic, and an independent Gemini or Grok raw-first opponent is required.",
            {
                "project": project,
                "task": {"type": "string", "maxLength": 12000},
                "expected_memory_synthesis_hash": {
                    "type": "string",
                    "pattern": "^[a-f0-9]{64}$",
                    "description": "Exact append.memory_synthesis_hash returned by the immediately preceding ithz_archive_auto_checkpoint call.",
                },
                "cross_lab_provider": {
                    "type": "string",
                    "enum": ["gemini", "grok"],
                    "default": "gemini",
                },
                "review_manifest_path": {
                    "type": "string",
                    "description": "Project-relative ccg_final_review_manifest_v2 JSON bound to the checkpoint. Changed artifacts and command output artifacts are runtime verified before model calls.",
                },
            },
            ["task", "expected_memory_synthesis_hash", "review_manifest_path"],
        ),
        _schema(
            "ccg_execute_demo",
            "Execute only the registered sandboxed text-write demo action using an exact, expiring, single-use capability token.",
            {"project": project, "case_id": case_id, "token": {"type": "string"}},
            ["case_id", "token"],
        ),
        _schema("ccg_get_case", "Read a case dossier without returning the raw capability token.", {"project": project, "case_id": case_id, "include_events": {"type": "boolean", "default": True}}, ["case_id"]),
        _schema("ccg_verify_case", "Verify the complete ITHZ-style event hash chain and role evidence hashes.", {"project": project, "case_id": case_id}, ["case_id"]),
        _schema("ccg_list_cases", "List newest CCG cases.", {"project": project, "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}}),
    ]


def _backend_from_environment() -> Any:
    if os.getenv("CCG_BACKEND", "codex").lower() == "scripted":
        return ScriptedBackend()
    preferences = effective_preferences()
    return CodexAppServerBackend(
        model=preferences["codex_model"],
        effort=preferences["codex_effort"],
        timeout_seconds=preferences["codex_timeout"],
        service_tier=os.getenv("CCG_CODEX_SERVICE_TIER", "fast"),
    )


def _runner(default_project: Path, arguments: dict[str, Any]) -> CourtRunner:
    project = Path(str(arguments.get("project") or default_project)).resolve()
    backend = _backend_from_environment()
    if isinstance(backend, ScriptedBackend):
        gemini = ScriptedBackend("scripted-gemini-canary")
        gemini.provider = "google"
        return CourtRunner(project, codex_backend=backend, gemini_backend=gemini)
    return CourtRunner(project, codex_backend=backend)


def call_tool(name: str, arguments: dict[str, Any], default_project: Path) -> Any:
    project = Path(str(arguments.get("project") or default_project)).resolve()
    if name == "ccg_initialize_project":
        return initialize_project(project, bool(arguments.get("overwrite", False)))
    if name == "ccg_status":
        return _runner(default_project, arguments).status()
    if name == "ccg_memory_integrity_status":
        query = arguments.get("query", "current memory integrity and review gates")
        if not isinstance(query, str) or not query.strip():
            raise RpcError(-32602, "invalid_params", {"missing": "query"})
        return _runner(default_project, arguments).integrity_status(query)
    if name == "ccg_memory_integrity_selftest":
        return CourtRunner.integrity_selftest()
    if name == "ccg_mcp36_canary_status":
        return _runner(default_project, arguments).canary_status()
    if name == "ccg_mcp36_canary_enable":
        return _runner(default_project, arguments).enable_canary(
            int(arguments.get("max_cases", 5)),
            int(arguments.get("expires_hours", 24)),
        )
    if name == "ccg_mcp36_canary_pause":
        return _runner(default_project, arguments).pause_canary()
    if name == "ccg_run_mcp36_canary_case":
        task = arguments.get("task")
        if not isinstance(task, str) or not task.strip():
            raise RpcError(-32602, "invalid_params", {"missing": "task"})
        return _runner(default_project, arguments).run_canary_case(
            task,
            str(arguments.get("risk", "high")),
            str(arguments.get("cross_lab_provider", "gemini")),
        )
    if name == "ccg_run_case":
        task = arguments.get("task")
        risk = arguments.get("risk")
        capability = arguments.get("capability")
        if not all(isinstance(item, str) and item for item in (task, risk, capability)):
            raise RpcError(-32602, "invalid_params", {"missing": "task_risk_or_capability"})
        return _runner(default_project, arguments).run_case(
            task,
            risk,
            capability,
            str(arguments.get("use_grok", "auto")),
            str(arguments.get("use_daybreak", "auto")),
            str(arguments.get("reuse_decision", "auto")),
            str(arguments.get("opponent_2", "auto")),
            blind_first_pass=bool(arguments.get("blind_first_pass", False)),
        )
    if name == "ccg_run_final_case":
        task = arguments.get("task")
        expected_hash = arguments.get("expected_memory_synthesis_hash")
        review_manifest_path = arguments.get("review_manifest_path")
        if not isinstance(task, str) or not task.strip() or not isinstance(expected_hash, str) or not isinstance(review_manifest_path, str) or not review_manifest_path:
            raise RpcError(-32602, "invalid_params", {"missing": "task_expected_memory_synthesis_hash_or_review_manifest_path"})
        return _runner(default_project, arguments).run_final_case(
            task,
            expected_hash,
            str(arguments.get("cross_lab_provider", "gemini")),
            review_manifest_path,
        )
    if name == "ccg_execute_demo":
        case_id = arguments.get("case_id")
        token = arguments.get("token")
        if not isinstance(case_id, str) or not isinstance(token, str):
            raise RpcError(-32602, "invalid_params", {"missing": "case_id_or_token"})
        return _runner(default_project, arguments).execute_demo(case_id, token)
    ledger = EvidenceLedger(project)
    if name == "ccg_get_case":
        case_id = arguments.get("case_id")
        if not isinstance(case_id, str):
            raise RpcError(-32602, "invalid_params", {"missing": "case_id"})
        return ledger.read_case(case_id, bool(arguments.get("include_events", True)))
    if name == "ccg_verify_case":
        case_id = arguments.get("case_id")
        if not isinstance(case_id, str):
            raise RpcError(-32602, "invalid_params", {"missing": "case_id"})
        return ledger.verify(case_id)
    if name == "ccg_list_cases":
        return ledger.list_cases(min(max(int(arguments.get("limit", 20)), 1), 100))
    raise RpcError(-32601, "unknown_tool", {"name": name})


def _tool_result(value: Any) -> dict[str, Any]:
    clean = sanitize_json_value(value)
    return {
        "content": [{"type": "text", "text": dumps(clean)}],
        "structuredContent": clean if isinstance(clean, dict) else {"value": clean},
        "isError": False,
    }


def handle_request(request: Any, default_project: Path) -> dict[str, Any] | None:
    if not isinstance(request, dict):
        raise RpcError(-32600, "invalid_request")
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    if not isinstance(method, str) or not isinstance(params, dict):
        raise RpcError(-32600, "invalid_request")
    if method == "initialize":
        result: Any = {
            "protocolVersion": params.get("protocolVersion") or "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "dev.ithz/ccg-ithz-mcp", "title": "CCG & ITHZ Court", "version": VERSION},
            "instructions": (
                "Use ccg_run_case before consequential actions. For end-of-task review, first call the write-enabled "
                "ITHZ ithz_archive_auto_checkpoint tool, create a checkpoint-bound ccg_final_review_manifest_v2 with "
                "runtime-verifiable command output artifacts, then "
                "call ccg_run_final_case with its exact append.memory_synthesis_hash and review_manifest_path. The "
                "final-case tool verifies changed-file and command-output hashes before model calls, compiles distinct "
                "proposer, counterevidence, raw-first cross-lab, blind-judge and audit evidence views, fixes capability to analysis.read, requires an "
                "independent cross-lab opponent before model calls, requires complete provider usage telemetry, and "
                "permits only one full five-role run per checkpoint. The semantic judge is blind to provider identity. "
                "MCP36.4 canary is absent and off by default. Only ccg_mcp36_canary_enable explicitly opts a project "
                "into a bounded, expiring analysis.read shadow rollout; canary cases require fresh independent cross-lab "
                "metering, issue no token, and are never mirrored into project.ithz. ccg_mcp36_canary_pause is the kill switch. "
                "The formal core knows whether cross-lab quorum exists. Gemini 3.7 Flash is the default second "
                "opponent, Grok is the alternate, and a new blind Codex B2 thread is the recorded fallback. "
                "Daybreak Blue is an adaptive primary security opponent for high/critical cases. Verified decision "
                "material may be reused, but capability tokens never are. Only ccg_execute_demo can consume the bundled "
                "demonstration capability; this server is not a general shell broker. Project-specific policies and "
                "private organizational profiles are intentionally not bundled in this public core."
            ),
        }
    elif method == "tools/list":
        result = {"tools": tool_schemas()}
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise RpcError(-32602, "invalid_params")
        result = _tool_result(call_tool(name, arguments, default_project))
    else:
        result = call_tool(method, params, default_project)
    if "id" not in request:
        return None
    return _result(request_id, result)


def handle_line(line: str, default_project: Path) -> dict[str, Any] | None:
    try:
        request = json.loads(line)
    except json.JSONDecodeError as exc:
        return _error(None, -32700, "parse_error", {"detail": str(exc)})
    request_id = request.get("id") if isinstance(request, dict) else None
    try:
        return handle_request(request, default_project)
    except RpcError as exc:
        return _error(request_id, exc.code, exc.message, exc.data) if isinstance(request, dict) and "id" in request else None
    except Exception as exc:
        return _error(request_id, -32603, "internal_error", {"type": type(exc).__name__, "detail": str(exc)}) if isinstance(request, dict) and "id" in request else None


def serve_stdio(default_project: Path, stdin: Any = sys.stdin, stdout: Any = sys.stdout) -> None:
    for line in stdin:
        response = handle_line(line, default_project)
        if response is not None:
            encoded = dumps(response) + "\n"
            buffer = getattr(stdout, "buffer", None)
            if buffer is not None:
                buffer.write(encoded.encode("utf-8"))
                buffer.flush()
            else:
                stdout.write(encoded)
                stdout.flush()


def mcp_status(default_project: Path) -> dict[str, Any]:
    return {
        "schema": "ccg_ithz_mcp_server_v1",
        "version": CCG_VERSION,
        "project": str(default_project.resolve()),
        "tools": [schema["name"] for schema in tool_schemas()],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCG & ITHZ Court stdio MCP server.")
    parser.add_argument("--project", default=".")
    args = parser.parse_args(argv)
    serve_stdio(Path(args.project).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
