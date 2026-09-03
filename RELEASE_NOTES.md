# ITHZ-MCP 36.4 public core (`0.1.0a14`)

Long-lived agent memory is useful, but an old or poisoned record can become a quiet source of confident error. MCP36.4 makes that influence inspectable and introduces a deliberately conservative path from local tests to real-project evaluation.

The canary is off by default. Once explicitly enabled, it is read-only, time-bounded and case-bounded. Every canary case requires independent cross-lab opposition and complete usage telemetry, produces no executable capability token and never writes its case into the project archive. A kill switch stops further admission without changing existing evidence.

This release is the generic public core. Organization-specific constitutions and profiles, project archives, model-provider settings, internal case records, logs and private operational documents are not included.

Validation for this release includes the public unit suite, deterministic MCP36 memory-integrity checks, the MCP36.4 canary fixture, isolated wheel installation and a forbidden-content scan of both source and built artifacts.

Status: alpha and suitable for controlled pilots. It is not an autonomous deployment authority.
