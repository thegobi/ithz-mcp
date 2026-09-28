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

---

# Changelog

## 0.1.0a20 - 2026-09-22

- Add opt-in exact-diff independent code review and freshness gates.
- Add lossless multipart review with mandatory integration.
- Add explicit one-use recovery preserving prior attempts and sanitized provider diagnostics.

## 0.1.0a16 - 2026-09-08

- Bind typed event display/routing to verified signed content and reject duplicate identities.
- Deliver bounded artifact and command content to role prompts with separate integrity/delivery receipts.
- Preserve signed source IDs and digest bindings through native projection into judge evidence.

## 0.1.0a15 - 2026-09-08

- Memory activation separates source binding, independently signed support and independently signed authorization. Receipts bind the exact candidate, evidence contents, scope and policy. Missing trust configuration leaves new typed claims quarantined.
- Native archive reads revalidate typed records. Invalid activation or supersession cannot silently erase an existing conclusion or a legacy safety rule. Historical bytes remain intact.
- CCG reports structure, isolation, evidence sufficiency and policy coverage separately. The economical five-run default remains; optional blind-first review seals an additional opponent run before the proposal, for six metered runs.
- Retrieval keeps the lexical/graph baseline and compatible APIs, adds explicit optional provider identity and stable reciprocal-rank fusion, and keeps mandatory policy and warning/history lanes visible.
- New timestamp validation compares timezone-aware instants and preserves historical timestamp text and hashes.

## 0.1.0a14 - 2026-09-03

- Published the generic MCP36.4 public core.
- Added source-bound memory integrity receipts and role-specific evidence-view hashes.
- Added deterministic no-memory, episodic, MCP35, MCP36 and poisoned-memory comparison fixtures.
- Added an opt-in, bounded and expiring `analysis.read` canary with a kill switch.
- Required fresh independent cross-lab evidence and complete metering for canary cases.
- Ensured canary cases issue no capability token and do not mirror into `project.ithz`.
- Removed all organization-specific constitutions, profiles and preflight logic from the public distribution.
