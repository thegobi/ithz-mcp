from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty, dumps


def state_dir(project: Path) -> Path:
    return project / ".ithz_mcp"


def ensure_state(project: Path) -> Path:
    base = state_dir(project)
    for rel in ("index", "packs", "logs", "events", "commits", "refs", "branches", "tags"):
        (base / rel).mkdir(parents=True, exist_ok=True)
    return base


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_pretty(value), encoding="utf-8")


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(dumps(value) + "\n")


def read_jsonl(path: Path) -> list[Any]:
    if not path.exists():
        return []
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"corrupt jsonl at line {i}: {exc}") from exc
    return rows


def init_project(project: Path) -> dict[str, Any]:
    project = project.resolve()
    base = ensure_state(project)
    config = {
        "schema": "ithz_mcp_config_v1",
        "project_root": str(project),
        "storage_version": 1,
        "default_mode": "local",
    }
    write_json(base / "config.json", config)
    agents = project / "AGENTS.md"
    context = project / "ITHZ_CONTEXT.md"
    warnings = []
    if not agents.exists():
        agents.write_text(
            "# Agent Instructions\n\n"
            "- Load a focused ITHZ-MCP context pack before non-trivial edits.\n"
            "- Do not skip stage gates.\n"
            "- Do not index secrets or private keys.\n"
            "- ITHZ-MCP complements Git; it does not replace Git.\n",
            encoding="utf-8",
        )
    else:
        warnings.append("AGENTS.md exists; left unchanged")
    if not context.exists():
        context.write_text(
            "# ITHZ Context\n\nLocal agent work memory context for decisions, gates and next steps.\n",
            encoding="utf-8",
        )
    else:
        warnings.append("ITHZ_CONTEXT.md exists; left unchanged")
    return {"project": str(project), "state_dir": str(base), "warnings": warnings}

