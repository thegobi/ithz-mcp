# Agent Bootstrap Contract

This repository uses ITHZ-MCP for long-term agent memory.

- If `project.md` exists, read it first as the project bootstrap manifest.
- Do not read all Markdown files by default.
- Start with `python -m ithz_mcp context-status --project .`.
- Request a focused context pack before broad edits.
- Check decisions, gates, risks and next steps.
- First propose each new task's workflow: steps, advisory agent roles, dependencies, acceptance checks, bounded repair loops and approval boundaries. Use `ithz_workflow_plan` or `workflow-plan --goal "<task>"`.
- Execute within existing host/user authorization without a separate approval for routine authorized planning. Role recommendations do not authorize agent spawning. MCP38 coordinates evidence; the host executes work.
- After a task, write a context commit or checkpoint summary.
- Do not index secrets.
- Do not duplicate long-term agent memory in repo Markdown unless it is human-facing.
- ITHZ-MCP complements Git; it does not replace Git.
