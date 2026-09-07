# ITHZ-MCP 36.5 (`0.1.0a15`)

A source link can show where a claim came from without showing that the claim is true. MCP36.5 makes that distinction explicit throughout memory activation, review and retrieval.

- Memory activation separates source binding, independently signed support and independently signed authorization. Receipts bind the exact candidate, evidence contents, scope and policy. Missing trust configuration leaves new typed claims quarantined.
- Native archive reads revalidate typed records. Invalid activation or supersession cannot silently erase an existing conclusion or a legacy safety rule. Historical bytes remain intact.
- CCG reports structure, isolation, evidence sufficiency and policy coverage separately. The economical five-run default remains; optional blind-first review seals an additional opponent run before the proposal, for six metered runs.
- Retrieval keeps the lexical/graph baseline and compatible APIs, adds explicit optional provider identity and stable reciprocal-rank fusion, and keeps mandatory policy and warning/history lanes visible.
- New timestamp validation compares timezone-aware instants and preserves historical timestamp text and hashes.

The trust policy and signing keys must be administered outside the proposing agent's write authority. Install the optional verifier with `pip install 'ithz-mcp[trust]'`; installation does not create trusted signers or enable the canary. The built-in native path verifies archive-event content; an external artifact hash alone is insufficient for activation.

Validation includes unit regressions, a real Windows native MCP write/read/context roundtrip, deterministic stage gates, isolated package installation and public artifact inspection. The small author-labeled SK/EN retrieval fixture is diagnostic: it shows failures as well as successes and establishes no general retrieval improvement, multilingual uplift, model-quality gain or token savings. No new embedding model is enabled by default; matched-budget live-agent evaluation remains unmeasured.

Upgrade through a new virtual environment, retain the old environment and project configuration for rollback, and check the reported version and MCP handshake before switching projects. Existing `project.ithz` archives are not rewritten by installation.

This is an alpha release of the generic public core. It excludes organization-specific profiles, private archives, provider settings and operational records. See [the trust protocol](docs/MCP36_5_EVIDENCE_TRUST.md) and [retrieval limitations](docs/LOCAL_RAG.md).
