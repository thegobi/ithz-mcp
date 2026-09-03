from __future__ import annotations

from pathlib import Path
from typing import Any

PROJECT_BOOTSTRAP = """# Project Memory Bootstrap

This repository uses ITHZ-MCP for deterministic project memory.

Markdown is the bootstrap. ITHZ is the memory zone.

## Memory-first startup

When a new agent thread opens in this project, start here before broad codebase reading:

1. Read this `project.md` bootstrap.
2. Call `ithz_context_status`.
3. Call `ithz_archive_get_context_pack` for the current task.
4. Inspect only candidate files and evidence gaps returned by the context pack unless the task clearly requires more.
5. After meaningful work, append a decision, gate, prompt summary or context event through ITHZ-MCP.
6. For non-trivial work, finish with `archive-finalize-task` so documentation impact, memory impact, gates and next steps are preserved in `project.ithz`.

CLI fallback:

```powershell
python -m ithz_mcp archive-memory-status --project .
python -m ithz_mcp archive-get-context-pack --project . --query "<task>" --out context_pack.md
python -m ithz_mcp archive-finalize-task --project . --task "<task>" --summary task_summary.md --docs-impact updated --memory-impact handoff-created
```

## Memory zone

- Human bootstrap: `project.md`
- Agent memory archive: `project.ithz`
- Active memory zone discovery: nearest `project.ithz`
- Parent or sibling memory zones require explicit selection.

Do not full-scan repository Markdown as long-term memory when `project.ithz` exists.
Do not index secrets, `.env`, private keys or credential-like data.
ITHZ-MCP complements Git; it does not replace Git.
ITHZ-MCP is not a production database or cloud sync product.
"""

AGENTS_MINIMAL = """# Agent Bootstrap Contract

This repository uses ITHZ-MCP for long-term agent memory.

- If `project.md` exists, read it first as the project bootstrap manifest.
- Do not read all Markdown files by default.
- Start with `python -m ithz_mcp context-status --project .`.
- Request a focused context pack before broad edits.
- Check decisions, gates, risks and next steps.
- After a task, write a context commit or checkpoint summary.
- Do not index secrets.
- Do not duplicate long-term agent memory in repo Markdown unless it is human-facing.
- ITHZ-MCP complements Git; it does not replace Git.
"""

ITHZ_CONTEXT_MINIMAL = """# ITHZ Context Bootstrap

Long-term agent memory lives in `.ithz-context/`.

Use ITHZ-MCP context packs for task context. Markdown files are bootstrap and human-readable documentation, not the authoritative agent memory store when `.ithz-context/` exists.
"""


def write_templates(root: Path) -> None:
    (root / "templates").mkdir(parents=True, exist_ok=True)
    (root / "templates" / "PROJECT_BOOTSTRAP.md").write_text(PROJECT_BOOTSTRAP, encoding="utf-8")
    (root / "templates" / "AGENTS_MINIMAL.md").write_text(AGENTS_MINIMAL, encoding="utf-8")
    (root / "templates" / "ITHZ_CONTEXT_MINIMAL.md").write_text(ITHZ_CONTEXT_MINIMAL, encoding="utf-8")


def ensure_project_bootstrap_file(project: Path) -> dict[str, Any]:
    path = project.resolve() / "project.md"
    created = False
    if not path.exists():
        path.write_text(PROJECT_BOOTSTRAP, encoding="utf-8", newline="\n")
        created = True
    return {"path": str(path), "created": created}


def bootstrap_dry_run(project: Path, mode: str = "minimal", force: bool = False, apply: bool = False) -> dict[str, Any]:
    files = {
        "project.md": PROJECT_BOOTSTRAP,
        "AGENTS.md": AGENTS_MINIMAL,
        "ITHZ_CONTEXT.md": ITHZ_CONTEXT_MINIMAL,
    }
    rows = []
    for name, text in files.items():
        path = project / name
        exists = path.exists()
        action = "would_create" if not exists else ("would_overwrite" if force else "skip_exists")
        rows.append({"path": name, "exists": exists, "action": action, "bytes": len(text.encode("utf-8"))})
        if apply and (not exists or force):
            path.write_text(text, encoding="utf-8")
    return {"project": str(project.resolve()), "mode": mode, "apply": apply, "force": force, "files": rows}
