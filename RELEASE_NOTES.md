# ITHZ-MCP 36.6 (`0.1.0a16`)

This corrective release closes three gaps between signed project memory and the evidence actually shown to a model.

- Active typed text, kind and routing come from the verified signed record. Conflicting event envelopes, unsigned authority overrides and duplicate identities cannot enter active views. Historical bytes are preserved.
- Opponent and judge packets contain bounded, hash-verified source/artifact/command content. Artifact integrity is reported separately from content delivery; a path, digest or summary alone is insufficient.
- Signed source IDs, digest bindings and full claims survive synthesis and native projection into the judge's evidence matrix. Changed content with a newly computed hash does not satisfy an existing signed binding.

Delivery is capped at 16 KiB per item and 128 KiB per packet. Missing, changed, unreadable, redaction-blocked or oversized content is explicitly withheld. A correctly hashed oversized artifact may pass integrity while failing delivery and evidence sufficiency. No silent excerpt represents the whole artifact.

The public source suite passed 119 tests with no skips on Windows; the internal source suite passed 133. Regression validation includes real Windows native archive roundtrips, portable signed projection-to-judge cases, manifest-to-role prompt delivery, negative tampering controls, stage gates and isolated installation. These are synthetic engineering tests, not measurements of live model quality, multilingual retrieval improvement, token savings or multi-day task performance.

Operator-controlled trust policy and signing keys are still required. Install the optional Ed25519 verifier with `pip install 'ithz-mcp[trust]'`. The five-run economical review remains the default, optional blind-first review uses six metered runs, and the canary stays off by default. Installation grants no new action authority and does not rewrite existing archives.

Use a new isolated runtime and keep the previous runtime/configuration for rollback. This generic public alpha core excludes organization-specific modules, private archives, provider settings and operational records. See [the repaired delivery boundary](docs/MCP36_6_END_TO_END_INTEGRITY.md) and [operator trust setup](docs/MCP36_5_EVIDENCE_TRUST.md).
