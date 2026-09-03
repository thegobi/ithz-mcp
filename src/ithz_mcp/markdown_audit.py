from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .safety import normalize_rel

BOOTSTRAP_FILES = {"README.md", "AGENTS.md", "ITHZ_CONTEXT.md", "main.md", "CONTRIBUTING.md", "SECURITY.md"}
HUMAN_DOC_HINTS = ("quickstart", "usage", "api", "user", "guide", "manual")
MEMORY_HINTS = ("summary", "result", "phase", "gate", "decision", "next", "status", "experiment", "handoff", "worklog")


def audit_markdown_memory(project: Path) -> dict[str, Any]:
    project = project.resolve()
    rows = []
    total = 0
    for p in sorted(project.rglob("*.md"), key=lambda x: normalize_rel(x.relative_to(project))):
        rel = normalize_rel(p.relative_to(project))
        if (
            ".git/" in rel
            or ".ithz-install/" in rel
            or ".ithz_mcp/" in rel
            or ".ithz-context/" in rel
            or ".antigravity/" in rel
            or ".claude/" in rel
            or ".cursor/" in rel
            or ".mempalace-capture/" in rel
            or ".mempalace-pilot/" in rel
            or ".mempalace-seed/" in rel
            or "dist/" in rel
            or "build/" in rel
        ):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        total += p.stat().st_size
        lower = rel.lower()
        category = "docs_that_should_remain_human_readable"
        reason = "human_doc"
        if p.name in BOOTSTRAP_FILES:
            category, reason = "candidate_bootstrap_files", "bootstrap_manifest"
        elif any(h in lower for h in MEMORY_HINTS) or re.search(r"\b(decision|gate|next|risk|passed|failed)\b", text, re.I):
            category, reason = "docs_that_should_move_to_ithz_context", "agent_memory_like"
        elif any(h in lower for h in HUMAN_DOC_HINTS):
            category, reason = "docs_that_should_remain_human_readable", "human_usage_doc"
        rows.append({"path": rel, "bytes": p.stat().st_size, "category": category, "reason": reason})
    return {
        "project": str(project),
        "md_file_count": len(rows),
        "md_total_bytes": total,
        "candidate_bootstrap_files": [r["path"] for r in rows if r["category"] == "candidate_bootstrap_files"],
        "candidate_memory_files": [r["path"] for r in rows if r["category"] == "docs_that_should_move_to_ithz_context"],
        "docs_that_should_remain_human_readable": [r["path"] for r in rows if r["category"] == "docs_that_should_remain_human_readable"],
        "rows": rows,
    }


def markdown_reduction_plan(project: Path) -> str:
    audit = audit_markdown_memory(project)
    lines = [
        "# Markdown Reduction Plan",
        "",
        "This is a dry-run plan. No Markdown files are deleted or moved automatically.",
        "",
        f"- markdown_files: {audit['md_file_count']}",
        f"- markdown_bytes: {audit['md_total_bytes']}",
        "",
        "## Keep As Bootstrap",
    ]
    for path in audit["candidate_bootstrap_files"]:
        lines.append(f"- `{path}`")
    lines += ["", "## Move To Context Archive Candidates"]
    for path in audit["candidate_memory_files"]:
        lines.append(f"- `{path}`")
    lines += ["", "## Keep Human-readable"]
    for path in audit["docs_that_should_remain_human_readable"]:
        lines.append(f"- `{path}`")
    lines += ["", "Human review is required for any destructive change."]
    return "\n".join(lines) + "\n"


def migration_plan(project: Path) -> tuple[list[dict[str, Any]], str]:
    audit = audit_markdown_memory(project)
    rows = []
    for row in audit["rows"]:
        category = row["category"]
        if category == "candidate_bootstrap_files":
            action = "keep_in_repo_bootstrap"
        elif category == "docs_that_should_move_to_ithz_context":
            action = "move_to_context_archive_candidate"
        else:
            action = "keep_in_repo_human_docs"
        rows.append(
            {
                "file": row["path"],
                "category": action,
                "reason": row["reason"],
                "suggested_action": action,
                "risk": "requires_human_review" if action == "move_to_context_archive_candidate" else "low",
                "requires_human_review": action == "move_to_context_archive_candidate",
            }
        )
    text = ["# Markdown Migration Plan", "", "Dry-run only. No files are moved or deleted.", ""]
    for row in rows:
        text.append(f"- `{row['file']}`: {row['category']} ({row['reason']})")
    return rows, "\n".join(text) + "\n"
