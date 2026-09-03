# ITHZ-MCP 36.4 public core

ITHZ-MCP is a local-first project-memory server for AI coding agents. MCP36 adds source-bound memory influence receipts, typed evidence views and deterministic safety checks. MCP36.4 adds an explicitly enabled, bounded shadow canary for evaluating those controls before they are trusted on consequential work.

This repository contains the generic public core. It intentionally excludes organization-specific constitutions and profiles, customer or participant data, private project archives, case ledgers, provider settings, credentials, logs and internal operating documents.

## What MCP36.4 changes

- Memory is treated as evidence, not truth. Retrieved records keep provenance, status and contradiction signals.
- The system can compile role-specific evidence views and hashes instead of silently feeding the same memory to every reviewer.
- Poisoned-memory and no-memory controls are deterministic and local.
- The canary is absent/off by default. It must be explicitly enabled, expires automatically and has a case limit.
- Canary cases are fixed to `analysis.read`, require an independent cross-lab opponent and complete usage telemetry, mint no capability token and are not mirrored into `project.ithz`.
- A local kill switch pauses new canary cases while preserving existing receipts.

MCP36.4 remains alpha software. A passing canary is review evidence, not permission to deploy, publish, send messages, change payments or perform another external action.

## Install from the GitHub release

Download the wheel and `SHA256SUMS.txt` from the release, verify the checksum, then install into an isolated Python environment:

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install .\ithz_mcp-0.1.0a14-py3-none-any.whl
.\.venv\Scripts\ithz-mcp version
```

Linux/macOS:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install ./ithz_mcp-0.1.0a14-py3-none-any.whl
./.venv/bin/ithz-mcp version
```

## Quick local verification

These checks do not call an external model:

```bash
ithz-mcp run-mcp36-memory-integrity
ithz-mcp run-mcp36-4-canary
```

The second command exercises the deterministic canary fixtures. To inspect or enable the bounded project canary through the CCG CLI:

```bash
ccg-ithz canary-status --project .
ccg-ithz canary-enable --project . --max-cases 5 --expires-hours 24
ccg-ithz canary-pause --project .
```

Running a live multi-model court additionally depends on model-provider configuration. Do not put provider secrets in a repository or project-memory archive.

## Upgrade

Install the new wheel into a fresh virtual environment first. Existing `project.ithz` archives are not rewritten merely by installing the package. Back up the project, run the two deterministic checks above, inspect `ithz-mcp version`, then opt a low-risk project into the bounded canary. Keep the old environment available for rollback until the pilot is accepted.

The package is not a Git replacement, cloud-sync service or production database. No general token-saving claim is made.

## Development

```bash
python -m venv .venv
./.venv/bin/python -m pip install -e .
./.venv/bin/python -m unittest discover -s tests -p "test_*.py"
```

On Windows use `.venv\Scripts\python` instead.

## License and security

See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md). Do not report a vulnerability by opening an issue that contains secrets or private data.
