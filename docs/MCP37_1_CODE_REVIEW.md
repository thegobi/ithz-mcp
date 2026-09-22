# MCP37.1 independent code review

Version `0.1.0a20` adds opt-in exact-Git-diff review, lossless multipart review and operator-authorized one-use recovery. Existing memory tools remain available. Installation does not enable review or grant deployment, merge or publication authority.

## Enable and review

Create `.ccg/code-review.json` in the Git root:

```json
{"schema":"ccg_code_review_policy_v1","enabled":true,"author_provider":"openai","reviewer_provider":"google","block_severities":["P0","P1","P2"]}
```

Ignore `.ithz-ccg/`, commit the implementation, and fetch the actual target branch. Configure the Gemini provider through the existing settings mechanism. Call `ccg_prepare_code_review`, then `ccg_run_code_review` with `base_ref`, checked-out `head_ref` and optional tracked `context_paths`. These tools are served by `ccg-ithz-mcp`; clients with an explicit tool allowlist must add them and restart their MCP session.

Preparation makes no model call. Review sends the complete selected source packet to the configured Google provider. Do not include private operational data; the credential scanner is not a general personal-data classifier. Only enable this workflow where that external source-code processing is authorized.

The packet binds the current target tip, merge base, HEAD, policy, complete changed files and explicit context. P0-P2 findings, incomplete coverage, invalid file/line locations, missing usage or stale evidence block readiness. An identical packet reuses its first accepted result, including a negative result. Fetch the target again and call `ccg_check_pr_review` immediately before a PR operation.

## Large packets

The default packet limit is 1,500,000 bytes. `max_packet_bytes` is an explicit integer policy setting from 1,024 to 10,000,000 bytes. `max_part_bytes` enables the bounded multipart path; preparation validates the configured limits. Parts preserve original file identities and locations, have immutable individual receipts, and require a final integration review. There is no silent truncation or partial PASS.

## Recovery and limits

The Python operator API `ithz_mcp.ccg.code_review_recovery.authorize_recovery` binds an explicit authorization to the exact packet, partition manifest, failed request and original evidence. This is deliberately not an automatic MCP retry tool. The permission is durably consumed before one recovery call; an ambiguous response, crash or repeated failure does not replenish it. Accepted results cannot be rerolled. Original attempts, failures and prior accepted parts remain preserved, and execution returns after the recovery call.

Diagnostics use a closed vocabulary of error categories and status values. They do not retain raw provider responses, headers, prompts or exception messages. A later diagnostic does not establish the cause of an older failure.

This is a local workflow gate, not a broker enforcing remote PR APIs or cryptographic proof of human authorization. Local hashes detect corruption, not a malicious local operator rewriting both evidence and hashes. Model findings remain fallible. Synthetic regression tests do not establish live review quality or guaranteed provider availability.

Install into a new environment, verify the reported version and MCP handshake, and retain the previous environment and configuration for rollback. Existing archives are not rewritten by installation. The public package excludes organization-specific profiles, private archives, provider settings and operational receipts.
