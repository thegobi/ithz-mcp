# ITHZ-MCP 38 (`0.1.0a21`)

MCP38 adds task-intake workflow planning and an opt-in bounded local coordinator. A host can propose the steps, roles, dependencies, checks and repair paths before implementation, then hand off evidence tied to the actual checkout.

- Lightweight read-only planning works without Git; durable execution requires the exact Git root and a concrete immutable task contract.
- Registered local checks have frozen verifier paths, selected commands, minimum test counts and finite time/repair budgets. Changed source invalidates downstream evidence; failures remain recorded.
- Existing MCP37 exact-diff review is revalidated, including missing receipts and source changes during review. The coordinator makes no model-provider calls.
- Fresh MCP initialization and bootstrap templates expose plan-first guidance. Read-only profiles expose planning/status/summary; mutations require the write profile.
- State is kept outside the checkout. Locks, interrupted-attempt checks and snapshot validation prevent blind continuation. The host can save a sanitized summary in project memory.

This is alpha software. Roles are advisory and execution is sequential: MCP38 does not launch coding agents, provide an OS sandbox, guarantee descendant-process termination or execute final external actions. Checks use the host's permissions and a trusted, preselected acceptance harness. `ready_for_approval` does not establish release, merge or deployment. Existing MCP37 provider/export authorization remains separate.

Validation counts and installed checks are recorded in `VERSION.json`. Synthetic engineering tests do not establish general model quality, cost savings or provider availability. Install in a fresh isolated environment and retain the previous configuration/runtime for rollback. The public distribution excludes native binaries, organization-specific profiles, private archives and operating records.

See [workflow usage and limits](docs/MCP38_DEVELOPMENT_WORKFLOW.md) and [retained MCP37.1 review](docs/MCP37_1_CODE_REVIEW.md).
