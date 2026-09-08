# MCP36.6: integrity through the final model context

MCP36.6 / `0.1.0a16` repairs three gaps identified in the MCP36.5 public core. A valid signature is useful only when the verified content is the content subsequently displayed and reviewed.

## Signed record and event envelope

The native append and read paths reject conflicting typed event text, kind, source, tags, supersession targets and authority metadata. Active views derive their statement, kind, scope, applicability and provenance from the verified typed record. Unsigned Git metadata remains historical context and is not carried as typed authority. Quarantined records retain their deterministic quarantine display envelope and cannot enter active views. Duplicate event identities and references to ambiguous source identities cannot activate a typed claim.

Historical events are not rewritten. A malformed envelope is excluded from the active read projection and fails append-only validation. Legacy untyped notes retain their existing historical status; they are not converted to signed records by installing this release.

## Artifact integrity and delivery to roles

Runtime artifact validation and actual content delivery are distinct receipts. A role packet includes the exact UTF-8 artifact/command output bytes, their digest and delivery status. Native source events use the exact canonical JSON object whose digest was bound by the support signature. Paths, hashes or summaries alone do not satisfy content delivery.

Content is bounded to 16 KiB per item and 128 KiB across the compiled evidence packet. Missing, unreadable, modified, redaction-blocked or oversized content is withheld with an explicit reason. There is no silent partial excerpt or whole-file support claim for truncated content. A correctly hashed oversized artifact can pass integrity verification while failing content delivery and evidence sufficiency.

The internal project root used to resolve manifest paths is excluded from sealed role packets. Existing role isolation remains: the raw-first opponent does not receive the shared current projection, and the judge receives a claim matrix with the corresponding raw content.

## Source bindings survive projection

The path is signed record → current synthesis → native projection → evidence views → judge packet. It retains source event IDs, artifact hashes, signed source bindings, candidate/record identity, scope and the full signed statement. The projection also supplies the bounded matching source objects, independent of whether a source happens to be selected in a short current-memory section.

Claim completeness requires the exact referenced identity, matching signed digest and verified content that is actually present in the packet. Changing both source text and its newly computed hash does not satisfy an older signed binding. An active gate/abstraction cannot substitute for its own missing raw source.

## Validation scope and rollout

The regression suite includes valid independently signed records, envelope tampering, duplicate identities, missing/changed/rehashed/oversized source payloads, runtime manifest content delivery into role prompts, and portable plus real Windows native projection-to-judge roundtrips. Exact release counts and installed-artifact hashes belong in the delivery receipt.

These tests exercise synthetic records and temporary artifacts. They do not establish live model-quality improvements, multilingual retrieval gains, token savings or multi-day task performance. No new embedding model is enabled. The economical five-run review remains the default, optional blind-first review uses six metered runs, and the canary remains off by default.

Install into a new isolated runtime and retain the previous runtime/configuration for rollback. Signing policy and keys still require an operator-controlled boundary outside the proposing agent's write authority. Installation does not create trusted signers, rewrite existing project archives or confer action authority.
