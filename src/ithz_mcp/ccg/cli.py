from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from ..canonical_json import dump_pretty
from ..mcp36_canary import canary_status, enable_canary, pause_canary
from .court import CourtRunner, initialize_project
from .ledger import EvidenceLedger
from .mcp_server import serve_stdio
from .models import CodexAppServerBackend, ScriptedBackend
from .settings_store import effective_preferences


DEMO_TASK = (
    "Create one Slovak Markdown maintenance notice in the isolated CCG demo sandbox. "
    "Use capability file.write.sandboxed. The exact relative path must be maintenance_notice.md. "
    "The content must have a short heading and exactly three factual sentences, no external links, "
    "no credentials and no claim that the system is certified."
)


def _backend(args: argparse.Namespace) -> Any:
    if args.backend == "scripted":
        return ScriptedBackend()
    return CodexAppServerBackend(
        model=args.model,
        effort=args.effort,
        timeout_seconds=args.timeout,
        service_tier=os.getenv("CCG_CODEX_SERVICE_TIER", "fast"),
    )


def _print(value: Any) -> None:
    sys.stdout.write(dump_pretty(value))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CCG & ITHZ constitutional court MCP and demo runner.")
    sub = parser.add_subparsers(dest="command", required=True)
    preferences = effective_preferences()

    settings = sub.add_parser("settings", help="Open the protected local settings page.")
    settings.add_argument("--port", type=int, default=0)
    settings.add_argument("--no-open", action="store_true")

    init = sub.add_parser("init", help="Initialize a project constitution and evidence area.")
    init.add_argument("--project", default=".")
    init.add_argument("--overwrite", action="store_true")

    status = sub.add_parser("status", help="Show court configuration.")
    status.add_argument("--project", default=".")
    status.add_argument("--backend", choices=["codex", "scripted"], default="codex")
    status.add_argument("--model", default=preferences["codex_model"])
    status.add_argument("--effort", default=preferences["codex_effort"])
    status.add_argument("--timeout", type=int, default=preferences["codex_timeout"])

    canary_status_parser = sub.add_parser("canary-status", help="Show the default-off local MCP36.4 canary state.")
    canary_status_parser.add_argument("--project", default=".")

    canary_enable = sub.add_parser("canary-enable", help="Explicitly enable one bounded read-only MCP36.4 shadow rollout.")
    canary_enable.add_argument("--project", default=".")
    canary_enable.add_argument("--max-cases", type=int, default=5)
    canary_enable.add_argument("--expires-hours", type=int, default=24)

    canary_pause = sub.add_parser("canary-pause", help="Activate the MCP36.4 local kill switch.")
    canary_pause.add_argument("--project", default=".")

    canary_run = sub.add_parser("canary-run", help="Run one explicitly enabled analysis.read MCP36.4 shadow case.")
    canary_run.add_argument("--project", default=".")
    canary_run.add_argument("--task", required=True)
    canary_run.add_argument("--risk", choices=["low", "medium", "high", "critical"], default="high")
    canary_run.add_argument("--cross-lab-provider", choices=["gemini", "grok"], default="gemini")
    canary_run.add_argument("--backend", choices=["codex", "scripted"], default="codex")
    canary_run.add_argument("--model", default=preferences["codex_model"])
    canary_run.add_argument("--effort", default=preferences["codex_effort"])
    canary_run.add_argument("--timeout", type=int, default=preferences["codex_timeout"])

    run = sub.add_parser("run", help="Run a constitutional case.")
    run.add_argument("--project", default=".")
    run.add_argument("--task", required=True)
    run.add_argument("--risk", choices=["low", "medium", "high", "critical"], required=True)
    run.add_argument("--capability", required=True)
    run.add_argument("--use-grok", choices=["auto", "required", "off"], default="auto")
    run.add_argument("--opponent-2", choices=["auto", "gemini", "grok", "off"], default="auto")
    run.add_argument("--use-daybreak", choices=["auto", "required", "off"], default="auto")
    run.add_argument("--reuse-decision", choices=["auto", "off"], default="auto")
    run.add_argument("--backend", choices=["codex", "scripted"], default="codex")
    run.add_argument("--model", default=preferences["codex_model"])
    run.add_argument("--effort", default=preferences["codex_effort"])
    run.add_argument("--timeout", type=int, default=preferences["codex_timeout"])
    run.add_argument("--execute-demo", action="store_true")

    demo = sub.add_parser("demo", help="Run the bounded maintenance-notice demonstration.")
    demo.add_argument("--project", default=".")
    demo.add_argument("--backend", choices=["codex", "scripted"], default="codex")
    demo.add_argument("--model", default=preferences["codex_model"])
    demo.add_argument("--effort", default=preferences["codex_effort"])
    demo.add_argument("--timeout", type=int, default=preferences["codex_timeout"])
    demo.add_argument("--use-grok", choices=["auto", "required", "off"], default="auto")
    demo.add_argument("--opponent-2", choices=["auto", "gemini", "grok", "off"], default="auto")
    demo.add_argument("--use-daybreak", choices=["auto", "required", "off"], default="auto")
    demo.add_argument("--reuse-decision", choices=["auto", "off"], default="auto")
    demo.add_argument("--no-execute", action="store_true")

    verify = sub.add_parser("verify", help="Verify one CCG evidence chain.")
    verify.add_argument("--project", default=".")
    verify.add_argument("--case-id", required=True)

    serve = sub.add_parser("mcp-server", help="Run the stdio MCP server.")
    serve.add_argument("--project", default=".")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "settings":
        from .settings_server import run_settings_server

        return run_settings_server(args.port, not args.no_open)
    project = Path(args.project).resolve()
    if args.command == "canary-status":
        _print(canary_status(project))
        return 0
    if args.command == "canary-enable":
        _print(enable_canary(project, max_cases=args.max_cases, expires_hours=args.expires_hours))
        return 0
    if args.command == "canary-pause":
        _print(pause_canary(project))
        return 0
    if args.command == "init":
        _print(initialize_project(project, args.overwrite))
        return 0
    if args.command == "verify":
        result = EvidenceLedger(project).verify(args.case_id)
        _print(result)
        return 0 if result["valid"] else 2
    if args.command == "mcp-server":
        serve_stdio(project)
        return 0
    backend = _backend(args)
    if args.command == "canary-run" and isinstance(backend, ScriptedBackend):
        gemini = ScriptedBackend("scripted-gemini-canary")
        gemini.provider = "google"
        runner = CourtRunner(project, codex_backend=backend, gemini_backend=gemini)
    else:
        runner = CourtRunner(project, codex_backend=backend)
    if args.command == "canary-run":
        _print(runner.run_canary_case(args.task, args.risk, args.cross_lab_provider))
        return 0
    if args.command == "status":
        _print(runner.status())
        return 0
    if args.command == "demo":
        result = runner.run_case(
            DEMO_TASK,
            "low",
            "file.write.sandboxed",
            args.use_grok,
            args.use_daybreak,
            args.reuse_decision,
            args.opponent_2,
        )
        token = result.pop("capability_token", None)
        if token and not args.no_execute:
            result["demo_execution"] = runner.execute_demo(result["case_id"], token)
            result["post_execution_verification"] = runner.ledger.verify(result["case_id"])
        _print(result)
        return 0 if result["final_verdict"] in {"ALLOW", "ALLOW_WITH_LIMITS"} else 3
    result = runner.run_case(
        args.task,
        args.risk,
        args.capability,
        args.use_grok,
        args.use_daybreak,
        args.reuse_decision,
        args.opponent_2,
    )
    token = result.pop("capability_token", None)
    if token and args.execute_demo:
        result["demo_execution"] = runner.execute_demo(result["case_id"], token)
    elif token:
        result["capability_token"] = token
    _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
