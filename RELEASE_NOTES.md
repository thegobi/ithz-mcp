# ITHZ-MCP 37.1 (`0.1.0a20`)

This alpha release adds opt-in independent review of an exact Git diff through `ccg_prepare_code_review`, `ccg_run_code_review` and `ccg_check_pr_review` on the CCG MCP server.

- Review receipts bind source/target commits, full changed files, policy and context. Missing coverage, stale evidence and P0-P2 findings block readiness.
- Large reviews use lossless parts with individual receipts and mandatory integration. No silently truncated packet receives a PASS.
- Explicit operator-authorized recovery consumes one permission before one provider call, retains original failures and rejects rerolling accepted results.
- Provider diagnostics retain controlled categories/status values without raw response bodies, headers or exception text.

Review remains disabled until configured per project. Model calls send the selected source packet to Google and require appropriate authorization. Existing project-memory APIs and the default-off canary remain available. This local gate does not enforce remote GitHub/Bitbucket APIs or grant merge/deployment authority.

Validation results are recorded in the release manifest. Synthetic engineering tests do not demonstrate live model quality, token savings or provider availability. Install in an isolated environment and retain the previous runtime/configuration for rollback. Native binaries, organization profiles, private archives and operational records are excluded.

See [setup, recovery and limitations](docs/MCP37_1_CODE_REVIEW.md).
