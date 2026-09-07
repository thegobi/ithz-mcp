# MCP36.5: evidence, support and authority

Release candidate: `0.1.0a15`. This maintenance release closes the four reviewed MCP36.4 gaps while retaining legacy entry points and append-only archives.

## Memory activation

An existing event ID is provenance, not proof of a statement. The consolidation receipt separately reports `source_binding_valid`, `support_verdict`, and `activation_authorized`. A candidate cannot become active merely by supplying event IDs, a confidence value, an old `active` label or a nonempty human approval ID.

Activation requires two Ed25519 attestations, embedded as `support_receipt` and `activation_authorization`. The runtime supplies an operator-pinned policy through `ITHZ_MEMORY_TRUST_POLICY`; no MCP method installs a trust policy, supplies a trusted key, or issues a signature. Install the optional verifier with `pip install 'ithz-mcp[trust]'`. Missing policy, missing cryptography, unavailable content, malformed signatures and ambiguous validity fail closed.

The policy schema is `ithz_memory_trust_policy_v1`. It contains a nonempty `rules_version`, an authenticated runtime `proposer_principal` and a `keys` map. Each key entry contains its base64 raw Ed25519 public key, principal, authorized roles (`support` or `activation`), exact scopes, policy classes and optional revocation flag. Human reviewers use `authority: human`. Runtime identity must match the candidate creator; support and activation principals must differ from that identity and from each other. Hard policy activation also needs a human activation signer and a bound approval ID.

**Operational trust boundary:** the process environment, policy file and signing keys must be administered outside the proposing agent's write authority. A signature does not enforce this separation if the same agent can replace the runtime or policy. Installation does not create trusted signers automatically. The default quarantine behavior is intentional.

`candidate_content_hash()` binds every candidate field except its record hash, lifecycle state and the two receipt envelopes. Both receipts bind this hash, exact scope, rules version, issuance and expiry. Support also binds exact source IDs and canonical content hashes, the verifier method and `supports` / `contradicts` / `insufficient`. Activation binds the complete signed support receipt hash. Sign the canonical JSON body (the signature field omitted) as UTF-8; receipt schemas and executable examples are in `tests/test_memory_trust.py`.

The built-in native path resolves archive event content. An external artifact digest alone remains insufficient: external artifact-only activation needs a separate trusted content resolver and is not enabled by this release. Store a bounded, sanitized, independently reviewed event with the relevant evidence when using the built-in path. Human and model support receipts are identified attestations, not mathematical proofs. The deterministic test-run method checks the exact run/suite/revision/output digest and success fields; it accepts only the narrowly templated test-run statement and never infers deployment safety.

Typed memory is rechecked against current content, policy and validity on read. Historical legacy records are retained without retroactive promotion. Invalid or expired typed records are omitted from active conclusions and retained as history/warnings. Failed supersession cannot deactivate a target; a typed record cannot silently replace an untyped legacy safety rule. Activation append is bound to the archive hash checked during review, so concurrent changes require fresh validation.

## Validity and history

New timestamps require an explicit timezone. Comparisons use UTC instants, accept supported fractional seconds and offsets, reject an equal instant as a newer replacement and require `valid_until > valid_from`. The stored historical timestamp text and hashes are not rewritten. Legacy ambiguous timestamps remain history and cannot silently gain current authority.

## CCG review modes

Evidence reports distinguish structural schema, role isolation, sufficient contents, required policy coverage and independent first pass. Content identity ignores role names, purpose, ordering and duplicates. Claims bind their declared evidence instead of inheriting every artifact in the manifest. Manifest-bound excerpts are content-checked; file paths and hashes alone do not pretend the reviewer received the contents.

The default `proposal_then_critique_economical` workflow retains five roles and makes no blind-first independence claim. The optional `blind_first_pass` mode runs the cross-lab opponent before the proposer, persists and hashes its first result, then conducts the normal critique; all six runs are metered. Use `ccg-ithz run --blind-first-pass` or `ccg_run_case` with `blind_first_pass: true`. The bounded canary retains its fixed five-run contract and rejects blind-first admission; installation does not enable canary mode.

## Retrieval and evidence limits

The former semantic candidate API remains as a compatibility alias for `lexical_graph_candidates`. Optional embedding providers have explicit model/revision/tokenizer/normalization/dimension identities, derived cache invalidation, deterministic fusion and offline fallback. Matching relevance never grants a memory record authority.

The local SK/EN retrieval fixture is small, synthetic and author-labeled. Its receipt reports successes and failures; it does not establish multilingual quality gains, general token savings or improved real-agent outcomes. No new embedding model is enabled by default. Multi-day, matched-budget live-agent trials and independently labeled retrieval evaluation remain unmeasured.

## Deployment and rollback

Install the built wheel into a new versioned runtime, retain the previous environment and exact project configuration, and run stdio initialize/tools-list plus native archive verification before changing the project target. Existing `project.ithz` bytes are preserved during installation. Project constitutions, private organization extensions, custom CCG wrappers and default-off canary state are retained. Public source packages exclude private organization modules.

Rollback restores the previous configuration/runtime; installing or rolling back the package does not rewrite archive history. Final release and project rollout receipts are separate from local unit-test evidence.
