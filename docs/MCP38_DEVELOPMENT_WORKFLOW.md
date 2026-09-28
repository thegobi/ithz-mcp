# MCP38: task planning and bounded local development workflow

Version: `0.1.0a21`, build `public-mcp38-development-workflow.20260928.1`.

At each new task, the host first proposes a concrete workflow: steps, agent roles,
dependencies, acceptance checks, bounded repair loops and approval boundaries.
The host then performs work within existing user authorization. Routine authorized
work does not need an extra plan approval. A recommended role does not authorize
spawning an agent or exporting source to a provider.

The planning tool is available through both read-only and write-enabled memory
profiles. Initialization instructions and newly generated `project.md`/`AGENTS.md`
bootstrap templates teach this intake behavior. Existing project bootstrap files
are preserved; updated MCP initialization instructions also reach those projects.
The host must follow these instructions; an MCP server cannot compel every host.

## Lightweight intake

```powershell
python -m ithz_mcp workflow-plan --project . --goal "Fix duplicate checkout reservations" --allowed-path src/checkout --check "Sequential duplicate request acceptance test" --check "Cancellation and persistence check" --final-action "handoff for authorized deployment"
```

Equivalent MCP call: `ithz_workflow_plan` with `goal`, `allowed_paths`, `checks` and
`final_action`. The result contains task-specific steps, dependencies, advisory
roles, a maximum-three-repairs proposal and permission boundaries. It is read-only
and works in non-Git directories and monorepo subdirectories. Unspecified checks
remain an explicit verification gap to fill from focused project context.

For durable execution, provide a full immutable `contract` to the same planning
tool and to `ithz_workflow_prepare`. The concrete contract supplies scope, frozen
verifiers, acceptance conditions, exact commands and finite limits. MCP38 does
not infer execution permission from a generated plan or from repository memory.

## Contract

Example `ithz_workflow_contract_v1` for a project with an independently selected
acceptance harness under `tests/acceptance`. Select real paths and commands before
preparing; missing verifier paths and executables are rejected.

```json
{
  "schema": "ithz_workflow_contract_v1",
  "goal": "Fix duplicate checkout reservations",
  "allowed_paths": ["src/checkout", "tests/supplementary"],
  "protected_paths": ["docs/acceptance-policy.md"],
  "invariants": ["A reservation is recorded at most once per request identity"],
  "acceptance": ["Duplicate and cancellation acceptance tests pass"],
  "checks": [{
    "id": "acceptance",
    "argv": ["python", "-B", "-m", "unittest", "discover", "-s", "tests/acceptance", "-v"],
    "timeout_seconds": 60,
    "min_tests": 1,
    "parser": "unittest",
    "verifier_paths": ["tests/acceptance"]
  }],
  "review": {"required": true, "base_ref": "origin/main", "context_paths": ["docs/acceptance-policy.md"]},
  "limits": {"max_repairs": 3, "max_seconds": 1800, "max_check_runs": 4, "model_calls": 0, "cost_microunits": 0, "concurrency": 1},
  "allowed_actions": ["local_implementation", "local_checks"],
  "final_action": {"kind": "create_pr", "target": "the selected repository and branch", "authorized": false}
}
```

All fields are required; unknown fields fail closed. Paths are literal relative
files or directory prefixes, without globs, traversal, `.git`, or ambiguous Windows
trailing dots/spaces. Windows comparisons respect filesystem case insensitivity.
Protected paths, every check's `verifier_paths`, and `.ccg/code-review.json` are
frozen against both working-tree and staged changes. Supplementary tests can be
changed outside those frozen paths when their locations are in `allowed_paths`.

At least one registered check must require a nonzero test count. Parsers are
`unittest`, `pytest` and `exit`; `exit` proves only the process exit and cannot
claim tests. Commands and interpreter hashes are bound to receipts. The host must
select a meaningful, trusted baseline acceptance harness. A count and an exit
code do not prove that a malicious or inadequate harness tests the desired goal.

Limits are immutable: zero to three repairs, one to 86,400 seconds, one to 100
check invocations, concurrency one, and zero coordinator model calls/cost. Existing
MCP37 provider calls use their own separately authorized controls and metering;
MCP38 does not claim to meter or enforce all host/provider activity. Contract
changes require a newly authorized workflow; no limit-escalation API exists.

## Sequential execution

The durable coordinator requires an exact Git checkout root with a resolvable
HEAD and base. Monorepo subdirectories and non-Git projects can use intake planning,
but cannot claim this v1 execution/review evidence. Existing MCP37 additionally
requires a clean checkout, its policy and complete supported source coverage.

```powershell
python -m ithz_mcp workflow-prepare --project . --contract C:/task-inputs/contract.json
python -m ithz_mcp workflow-begin-step --project . --workflow-id wf_<identity>
# Host implements within the contract; preserve the returned attempt identity.
# If review is required, commit the authorized implementation now so MCP37 has a clean checkout.
# Record/check the committed final snapshot; committing later invalidates existing check evidence.
python -m ithz_mcp workflow-record-result --project . --workflow-id wf_<identity> --attempt-id attempt_<identity>
python -m ithz_mcp workflow-run-check --project . --workflow-id wf_<identity> --check-id acceptance --execution-authorized
# Host obtains the existing MCP37 review under its separate provider/export authority.
python -m ithz_mcp workflow-record-review --project . --workflow-id wf_<identity>
python -m ithz_mcp workflow-status --project . --workflow-id wf_<identity>
```

The runner is opt-in: `execution_authorized=true` asserts actual existing host/user
permission, and `allowed_actions` must include `local_checks`. That boolean grants
no permission by itself. Commands are the exact registered argv with `shell=False`,
the checkout cwd, a fixed timeout, a monitored output limit and a persisted attempt
before launch. MCP38 exposes no unrestricted shell command endpoint.

`record_result` accepts an implementation attempt identity, never a caller's
claimed test PASS. Checks capture actual process exit, test count, time, command,
interpreter, snapshot and redacted evidence hashes. All check dependencies run in
the declared order. Acceptance tests cannot be rewritten by the repair step.

State progression is `planned -> implementing -> checking -> reviewing ->
ready_for_approval`. When review is explicitly optional, checks can produce
`ready_for_approval` with that limitation visible in the contract. A failed check
or verified blocking P0/P1/P2 review can enter `correcting`; the host begins a
bounded repair, provides a relevant content change, and reruns dependent checks
and review. An empty commit or altered staging alone cannot reopen an unchanged
failed content snapshot. Negative receipts are retained in history.

The conservative repeated-failure rule stops on the same check identity plus
exit/test/error class, even if incidental output timing changes. This may stop
distinct failures with the same class; the host then inspects evidence instead of
extending the loop. Transport errors, missing/incomplete review evidence, corrupt
receipts and provider recovery conditions are not source-repair invitations.
MCP38 revalidates existing MCP37 receipts and never invokes/retries a provider.
Existing MCP37.1 recovery authorization remains unchanged.

`ready_for_approval` is a bound handoff, not completed execution. `completed` remains
false. Already granted final authority need not be requested again, but the host
must execute and verify any external step using its separately authorized adapter.
V1 has no merge, release, deployment, PR publication or approval-token adapter.

## Durable state, resume and cancellation

Live state defaults to `%LOCALAPPDATA%/ITHZ-MCP/workflows` on Windows and
`~/.local/state/ithz-mcp/workflows` elsewhere, with a checkout-identity directory.
`--store-root`/`store_root` can select an external store. A store inside the project
or its containing Git root is rejected. No live state is placed in tracked source
or silently appended to `project.ithz`.

State uses atomic replacement, fsync, an integrity envelope and an event hash
chain. Both checkout-wide and workflow-specific mutation locks prevent overlapping
coordinator mutations/checks. Existing locks are never stolen using an age guess.
Investigate their owner and preserve evidence before operator recovery. The local
hash chain detects accidental corruption; it does not defend against a person
who can rewrite/roll back the entire local store.

```powershell
python -m ithz_mcp workflow-resume --project . --workflow-id wf_<identity>
python -m ithz_mcp workflow-cancel --project . --workflow-id wf_<identity>
python -m ithz_mcp workflow-memory-summary --project . --workflow-id wf_<identity>
```

Resume verifies current checkout, contract, budgets, interpreter and evidence.
An interrupted implementation retains its attempt and may be completed only after
scope validation. An interrupted check with an unknown outcome blocks, preserving
the attempt; no automatic retry occurs. Cancellation preserves history and rejects
future work. An active check holds its lock until direct-process exit or timeout;
cancellation does not interrupt that active process or guarantee descendant death.

The read-only memory summary contains the task, state, limits/evidence references,
hashes, blockers and next step. The host can pass that sanitized payload to the
existing write-enabled `ithz_archive_auto_checkpoint`. Raw prompts, test stdout,
and the live state are not placed in project memory. Durable stdout evidence is
bounded and redacted, with recognized remaining secrets blocking the output.

## Security and evidence limits

The check runner is not an OS sandbox. An authorized command may execute arbitrary
code, spawn descendants, access the network or change Gitignored files. The source
snapshot covers Git-visible tracked/untracked files, their modes, HEAD/base and
index entries; it does not make the environment hermetic or capture ignored side
effects. The host must choose appropriately isolated checks and checkout permissions.

The output-size monitor kills the direct process after observing excess output;
there can be scheduling overshoot. Temporary raw output uses a delete-on-close
temporary handle, and only bounded redacted output becomes durable evidence.
Timeout/output enforcement does not provide a process-tree sandbox or disk quota.
External concurrent writers do not honor MCP38 advisory locks; snapshots are
rechecked after checks/review and on status/resume, but final external actions need
their own immediate authority/evidence validation.

The v1 plan is sequential and deterministic. Agent roles and dependencies are
visible for host coordination, but there is no parallel DAG executor, background
agent service, model planner, or remote enforcement guarantee.

## MCP routing and validation

Read-only: `ithz_workflow_plan`, `ithz_workflow_status`,
`ithz_workflow_memory_summary`.

Write-enabled only: `ithz_workflow_prepare`, `ithz_workflow_begin_step`,
`ithz_workflow_record_result`, `ithz_workflow_run_check`,
`ithz_workflow_record_review`, `ithz_workflow_resume`, `ithz_workflow_cancel`.

The existing context, archive, workflow-profile and MCP37 tools remain available
with their original routing. Workflow results survive the actual MCP `tools/call`
structured/text wrappers with state, plan, remaining budgets and next step intact.

Validation uses real temporary Git fixtures, real local acceptance subprocesses,
positive and failed repair histories, corruption/staleness/lock/zero-test tests,
CLI lifecycle and JSON-RPC initialize/list/call lifecycle. No paid provider call
is required or claimed for MCP38's deterministic gates.
