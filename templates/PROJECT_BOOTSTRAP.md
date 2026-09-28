# Project Memory Bootstrap

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

## Task workflow intake

For every new task, first propose its concrete workflow with `ithz_workflow_plan` (CLI: `workflow-plan --goal "<task>"`). Include steps, advisory agent roles, dependencies, acceptance checks, bounded repair loops, and approval boundaries. Present the plan and execute within existing authorization; routine authorized work needs no separate plan approval.

The host performs implementation and agent dispatch. MCP38 offers an optional durable sequential coordinator (`workflow-prepare`, `workflow-status`, `workflow-resume`, `workflow-cancel`) with an immutable contract. Its local check runner is opt-in and requires actual host permission. It does not start background agents, grant model/export permission, or execute publication, merge or deployment. A prepared handoff is not an executed final action. Keep live state outside tracked code; append only sanitized checkpoint summaries to `project.ithz`.

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
