"""MCP38 bounded local workflow coordination, without a background agent.

The host supplies an authorized contract and performs implementation. This module
executes only explicitly requested, registered local checks. It never invokes a
model, recovers a provider call, or performs a final external action. Its hashes
detect accidental corruption, not malicious rewriting of the whole local store.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

SCHEMA = "ithz_development_workflow_v1"
CONTRACT_SCHEMA = "ithz_workflow_contract_v1"
MAX_STATE_BYTES = 16_000_000
MAX_FILES = 10_000
MAX_LOG_BYTES = 1_000_000
TERMINAL = {"cancelled", "blocked", "ready_for_approval"}


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("invalid_workflow_" + name)
    return value


def _text(value: Any, name: str, limit: int = 2000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError("invalid_workflow_" + name)
    from .ccg.code_review import safe_text
    safe_text("workflow.txt", value.encode())
    return value


def _paths(value: Any, name: str, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > 200 or (nonempty and not value):
        raise ValueError("invalid_workflow_" + name)
    paths = []
    for raw in value:
        item = _text(raw, name, 400).replace("\\", "/")
        parts = PurePosixPath(item).parts
        if item.startswith("/") or ":" in item or any(p.casefold() in {"..", ".", ".git"} or p.endswith((".", " ")) for p in parts) or not parts or any(c in item for c in "*?[]"):
            raise ValueError("invalid_workflow_" + name)
        if str(PurePosixPath(item)) != item.rstrip("/"):
            raise ValueError("invalid_workflow_" + name)
        paths.append(item.rstrip("/"))
    if len(paths) != len(set(p.casefold() if os.name == "nt" else p for p in paths)):
        raise ValueError("duplicate_workflow_" + name)
    return paths


def validate_contract(contract: Any) -> dict[str, Any]:
    """No inferred authority, budget escalation, or acceptance weakening."""
    value = copy.deepcopy(_object(contract, {"schema", "goal", "allowed_paths", "protected_paths", "invariants", "acceptance", "checks", "review", "limits", "allowed_actions", "final_action"}, "contract"))
    if value["schema"] != CONTRACT_SCHEMA:
        raise ValueError("unsupported_workflow_contract_schema")
    _text(value["goal"], "goal")
    for name in ("allowed_paths", "protected_paths"):
        value[name] = _paths(value[name], name, name == "allowed_paths")
    for name in ("invariants", "acceptance"):
        if not isinstance(value[name], list) or not 1 <= len(value[name]) <= 50:
            raise ValueError("invalid_workflow_" + name)
        for item in value[name]:
            _text(item, name)
    actions = value["allowed_actions"]
    if not isinstance(actions, list) or len(actions) != len(set(actions)) or not set(actions) <= {"local_implementation", "local_checks"}:
        raise ValueError("invalid_workflow_allowed_actions")
    limits = _object(value["limits"], {"max_repairs", "max_seconds", "max_check_runs", "model_calls", "cost_microunits", "concurrency"}, "limits")
    for key, low, high in (("max_repairs", 0, 3), ("max_seconds", 1, 86400), ("max_check_runs", 1, 100), ("model_calls", 0, 0), ("cost_microunits", 0, 0), ("concurrency", 1, 1)):
        if type(limits[key]) is not int or not low <= limits[key] <= high:
            raise ValueError("invalid_workflow_limit:" + key)
    checks = value["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= 20:
        raise ValueError("invalid_workflow_checks")
    ids = set()
    for check in checks:
        _object(check, {"id", "argv", "timeout_seconds", "min_tests", "parser", "verifier_paths"}, "check")
        if not isinstance(check["id"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,59}", check["id"]) or check["id"] in ids:
            raise ValueError("invalid_workflow_check_id")
        ids.add(check["id"])
        if not isinstance(check["argv"], list) or not 1 <= len(check["argv"]) <= 60:
            raise ValueError("invalid_workflow_check_argv")
        for arg in check["argv"]:
            _text(arg, "check_argv", 4000)
        if type(check["timeout_seconds"]) is not int or not 1 <= check["timeout_seconds"] <= min(3600, limits["max_seconds"]):
            raise ValueError("invalid_workflow_check_timeout")
        if type(check["min_tests"]) is not int or not 0 <= check["min_tests"] <= 1_000_000 or check["parser"] not in {"unittest", "pytest", "exit"}:
            raise ValueError("invalid_workflow_test_count")
        if check["parser"] == "exit" and check["min_tests"] != 0:
            raise ValueError("exit_parser_cannot_prove_tests")
        check["verifier_paths"] = _paths(check["verifier_paths"], "verifier_paths", True)
    if not any(check["min_tests"] > 0 for check in checks):
        raise ValueError("workflow_requires_nonzero_acceptance_tests")
    review = _object(value["review"], {"required", "base_ref", "context_paths"}, "review")
    if type(review["required"]) is not bool:
        raise ValueError("invalid_workflow_review_required")
    ref = _text(review["base_ref"], "base_ref", 240)
    if ref.startswith("-"):
        raise ValueError("invalid_workflow_base_ref")
    review["context_paths"] = _paths(review["context_paths"], "context_paths")
    final = _object(value["final_action"], {"kind", "target", "authorized"}, "final_action")
    if final["kind"] not in {"handoff", "create_pr", "merge", "deploy", "release"} or type(final["authorized"]) is not bool:
        raise ValueError("invalid_workflow_final_action")
    _text(final["target"], "final_target", 500)
    if len(json.dumps(value)) > 100_000:
        raise ValueError("workflow_contract_too_large")
    return value


def _git(project: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(project), *args], capture_output=True, timeout=30, shell=False)
    if result.returncode:
        raise ValueError("workflow_git_unavailable:" + args[0])
    return result.stdout


def capabilities(project: Path) -> dict[str, Any]:
    project = project.resolve()
    root = None
    try:
        root = Path(_git(project, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    except (ValueError, OSError, subprocess.TimeoutExpired):
        pass
    return {"planning_available": True, "git_root": str(root) if root else None,
            "execution_available": root == project, "review_requires_clean_git_root": True,
            "background_agents": False, "external_action_adapter": False,
            "limitation": None if root == project else "execution_v1_requires_exact_git_root"}


def plan(project: Path, contract: dict[str, Any]) -> dict[str, Any]:
    """Read-only concrete intake plan; role suggestions do not authorize spawning."""
    contract = validate_contract(contract)
    steps = [{"id": "context", "role": "host_agent", "depends_on": [], "action": "Read focused ITHZ context and verify scope/invariants.", "inputs": contract["invariants"]},
             {"id": "implement", "role": "host_implementer", "depends_on": ["context"], "action": contract["goal"], "allowed_paths": contract["allowed_paths"]}]
    previous = "implement"
    for check in contract["checks"]:
        steps.append({"id": "check:" + check["id"], "role": "deterministic_local_verifier", "depends_on": [previous], "argv": check["argv"], "acceptance": contract["acceptance"], "min_tests": check["min_tests"], "frozen_verifier_paths": check["verifier_paths"]})
        previous = "check:" + check["id"]
    if contract["review"]["required"]:
        steps.append({"id": "review", "role": "independent_mcp37_reviewer", "depends_on": [previous], "action": "Host obtains existing MCP37 exact-diff review within its separate export/provider authority; coordinator revalidates the gate.", "base_ref": contract["review"]["base_ref"]})
        previous = "review"
    steps.append({"id": "handoff", "role": "host_supervisor", "depends_on": [previous], "action": "Present bound evidence, limitations, and proposed final action.", "final_action": contract["final_action"]})
    result = {"schema": SCHEMA, "project": str(project.resolve()), "goal": contract["goal"], "contract_hash": digest(contract), "steps": steps,
            "roles_advisory_only": True, "capabilities": capabilities(project), "limits": contract["limits"],
            "repair_loop": {"from": "failed_check_or_actionable_review", "to": "implement", "max_repairs": contract["limits"]["max_repairs"], "requires_changed_snapshot": True, "repeat_finding_stops": True, "invalidate": "all dependent checks and review"},
            "approval_boundaries": {"plan_confirmation_required": False, "host_authorization_required": True, "local_checks": "Explicit invocation with execution_authorized=true AND allowed_actions includes local_checks; not a security sandbox.", "external_models": "Separate MCP37 export/provider authority; no model invocation by this coordinator.", "final_action": "No execution adapter in v1; ready_for_approval never proves publication, merge or deployment."},
            "next_step": "Host presents this workflow, then prepares only within existing authorization."}
    if len(json.dumps(result).encode()) > 40_000:
        raise ValueError("workflow_plan_too_large_no_truncation")
    return result


def propose(project: Path, goal: str, allowed_paths: list[str] | None = None, checks: list[str] | None = None, final_action: str = "handoff") -> dict[str, Any]:
    """Lightweight intake even before an execution contract or Git is available."""
    _text(goal, "goal")
    paths = _paths(allowed_paths or [], "allowed_paths")
    checks = checks or []
    if not isinstance(checks, list) or len(checks) > 20:
        raise ValueError("invalid_workflow_checks")
    for check in checks:
        _text(check, "check")
    _text(final_action, "final_action", 500)
    check_actions = checks or ["Select task-specific acceptance checks from current project context; disclose missing verification evidence."]
    steps = [
        {"id": "context", "role": "host_agent", "depends_on": [], "action": "Retrieve focused ITHZ context, identify current evidence and authorization for: " + goal},
        {"id": "work", "role": "host_implementer_or_analyst", "depends_on": ["context"], "action": goal, "allowed_paths": paths, "authorization": "Existing host/user scope; paths are proposed scope, not new permission."},
        {"id": "checks", "role": "local_verifier", "depends_on": ["work"], "actions": check_actions},
        {"id": "review", "role": "independent_reviewer_when_required", "depends_on": ["checks"], "action": "Inspect final combined evidence; for code changes use existing MCP37 within separate provider/export authorization."},
        {"id": "handoff", "role": "host_supervisor", "depends_on": ["review"], "action": "Present outcome, evidence, limitations and concrete proposed final action: " + final_action},
    ]
    return {"schema": SCHEMA, "project": str(project.resolve()), "goal": goal, "steps": steps, "roles_advisory_only": True,
            "capabilities": capabilities(project), "execution_contract_prepared": False,
            "repair_loop": {"max_repairs": 3, "requires_changed_snapshot": True, "repeat_finding_stops": True, "invalidate": "checks and review dependent on changed inputs"},
            "limits": {"concurrency": 1, "model_calls_by_coordinator": 0, "cost_microunits_by_coordinator": 0, "execution_limits_required_before_prepare": ["max_seconds", "max_check_runs", "max_repairs"]},
            "approval_boundaries": {"plan_confirmation_required": False, "execute_only_existing_authorization": True, "roles_do_not_authorize_spawning": True, "external_model_export_requires_separate_authority": True, "final_action": final_action, "external_action_adapter": False},
            "next_step": "Host presents and specializes this plan, then performs authorized work; durable runner is optional."}


def _file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def snapshot(project: Path, contract: dict[str, Any]) -> dict[str, Any]:
    if not capabilities(project)["execution_available"]:
        raise ValueError("workflow_execution_requires_exact_git_root")
    files = {}
    names = _git(project, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\x00")
    if len(names) > MAX_FILES:
        raise ValueError("workflow_snapshot_too_many_files")
    for name in sorted(set(names)):
        if not name:
            continue
        rel = name.decode("utf-8")
        path = project / rel
        if path.is_symlink() or not path.resolve().is_relative_to(project):
            raise ValueError("workflow_snapshot_symlink_unsupported")
        if path.exists() and not path.is_file():
            raise ValueError("workflow_snapshot_submodule_unsupported")
        files[rel] = {"sha256": _file_hash(path), "mode": stat.S_IMODE(path.stat().st_mode)} if path.is_file() else None
    index_raw = _git(project, "ls-files", "--stage", "-z")
    index_entries = {}
    for entry in index_raw.split(b"\x00"):
        if entry:
            metadata, name = entry.split(b"\t", 1)
            index_entries[name.decode("utf-8")] = metadata.decode("ascii")
    result = {"project": str(project), "head_sha": _git(project, "rev-parse", "--verify", "HEAD^{commit}").decode().strip(),
              "base_sha": _git(project, "rev-parse", "--verify", contract["review"]["base_ref"] + "^{commit}").decode().strip(), "files": files,
              "git_directory": _git(project, "rev-parse", "--absolute-git-dir").decode().strip(),
              "index_sha256": hashlib.sha256(index_raw).hexdigest(), "index_entries": index_entries}
    result["input_hash"] = digest({"base_sha": result["base_sha"], "files": files})
    result["snapshot_hash"] = digest(result)
    return result


def _under(name: str, paths: list[str]) -> bool:
    if os.name == "nt":
        name = name.casefold()
        paths = [p.casefold() for p in paths]
    return any(name == p or name.startswith(p + "/") for p in paths)


def _changed(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return sorted(name for name in set(before["files"]) | set(after["files"]) if before["files"].get(name) != after["files"].get(name))


def _scope_errors(state: dict[str, Any], current: dict[str, Any]) -> list[str]:
    contract = state["contract"]
    baseline = state["baseline"]
    changed = set(_changed(baseline, current)) | {p for p in set(baseline["index_entries"]) | set(current["index_entries"]) if baseline["index_entries"].get(p) != current["index_entries"].get(p)}
    frozen = contract["protected_paths"] + [p for c in contract["checks"] for p in c["verifier_paths"]] + [".ccg/code-review.json"]
    errors = []
    if current["base_sha"] != state["baseline"]["base_sha"]:
        errors.append("workflow_base_changed")
    if any(not _under(p, contract["allowed_paths"]) for p in changed):
        errors.append("workflow_out_of_scope_change")
    if any(_under(p, frozen) for p in changed):
        errors.append("workflow_protected_verifier_or_policy_changed")
    return errors


def _root(project: Path, store_root: Path | None) -> Path:
    if store_root is None:
        local = os.environ.get("LOCALAPPDATA")
        store_root = Path(local) / "ITHZ-MCP" / "workflows" if local else Path.home() / ".local" / "state" / "ithz-mcp" / "workflows"
    root = store_root.resolve()
    git_root = capabilities(project)["git_root"]
    if root.is_relative_to(project) or (git_root and root.is_relative_to(Path(git_root))):
        raise ValueError("workflow_runtime_store_must_be_outside_checkout")
    return root / hashlib.sha256(str(project).encode()).hexdigest()[:24]


def _location(project: Path, workflow_id: str, store_root: Path | None) -> Path:
    if not isinstance(workflow_id, str) or not re.fullmatch(r"wf_[0-9a-f]{32}", workflow_id):
        raise ValueError("invalid_workflow_id")
    return _root(project, store_root) / workflow_id


@contextmanager
def _lock(location: Path) -> Iterator[None]:
    """Exclusive process lock; never steals an existing lock based on age."""
    acquired = []
    try:
        for lock in (location.parent / "mutation.lock", location / "mutation.lock"):
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as exc:
                raise ValueError("workflow_locked_or_interrupted") from exc
            acquired.append(lock)
            with os.fdopen(fd, "w") as handle:
                handle.write(json.dumps({"pid": os.getpid(), "created_at": time.time()}))
                handle.flush()
                os.fsync(handle.fileno())
        yield
    finally:
        for lock in reversed(acquired):
            lock.unlink(missing_ok=True)


def _read(location: Path, project: Path) -> dict[str, Any]:
    path = location / "state.json"
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            raise ValueError("workflow_state_too_large")
        envelope = json.loads(path.read_text(encoding="utf-8"))
        state = envelope["state"]
        if envelope["state_hash"] != digest(state) or state["schema"] != SCHEMA or state["project"] != str(project) or state["workflow_id"] != location.name:
            raise ValueError("workflow_state_integrity_invalid")
        if digest(validate_contract(state["contract"])) != state["contract_hash"]:
            raise ValueError("workflow_contract_integrity_invalid")
        previous = "0" * 64
        for index, event in enumerate(state["events"]):
            body = {k: v for k, v in event.items() if k != "event_hash"}
            if event["sequence"] != index or event["previous_hash"] != previous or event["event_hash"] != digest(body):
                raise ValueError("workflow_event_integrity_invalid")
            previous = event["event_hash"]
        for receipt in state["receipt_history"]:
            body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
            if receipt["receipt_hash"] != digest(body) or receipt["contract_hash"] != state["contract_hash"]:
                raise ValueError("workflow_receipt_integrity_invalid")
            artifact = location / "evidence" / receipt["attempt_id"] / "output.txt"
            if not artifact.is_file() or _file_hash(artifact) != receipt["output_sha256"]:
                raise ValueError("workflow_check_evidence_missing_or_corrupt")
            persisted = json.loads((artifact.parent / "receipt.json").read_text(encoding="utf-8"))
            if persisted != receipt:
                raise ValueError("workflow_receipt_evidence_missing_or_corrupt")
        for check_id, receipt in state["check_receipts"].items():
            if receipt not in state["receipt_history"] or receipt["check_id"] != check_id:
                raise ValueError("workflow_current_receipt_not_in_audit_history")
        return state
    except (OSError, KeyError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("workflow_state_missing_or_corrupt") from exc


def _write(location: Path, state: dict[str, Any], kind: str, detail: Any = None) -> None:
    events = state["events"]
    event = {"sequence": len(events), "previous_hash": events[-1]["event_hash"] if events else "0" * 64,
             "kind": kind, "at": time.time(), "state": state["state"], "detail": detail}
    event["event_hash"] = digest(event)
    events.append(event)
    data = json.dumps({"state": state, "state_hash": digest(state)}, ensure_ascii=True, indent=2)
    if len(data.encode()) > MAX_STATE_BYTES:
        raise ValueError("workflow_state_too_large")
    fd, name = tempfile.mkstemp(prefix=".state-", suffix=".tmp", dir=location)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, location / "state.json")
    finally:
        Path(name).unlink(missing_ok=True)


def _budget_errors(state: dict[str, Any]) -> list[str]:
    limits = state["contract"]["limits"]
    if time.time() >= state["created_at"] + limits["max_seconds"]:
        return ["workflow_time_budget_exhausted"]
    return []


def _review_current_errors(project: Path, state: dict[str, Any]) -> list[str]:
    if state["state"] != "ready_for_approval" or not state["contract"]["review"]["required"]:
        return []
    from .ccg.code_review import gate
    review = state["contract"]["review"]
    try:
        current = gate(project, review["base_ref"], "HEAD", review["context_paths"])
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return ["workflow_review_evidence_no_longer_valid:" + str(exc)]
    if current.get("ready_for_pr") is not True or current != state["review_receipt"]:
        return ["workflow_review_evidence_missing_changed_or_invalid"]
    return []


def _checks_current_errors(state: dict[str, Any]) -> list[str]:
    errors = []
    for check in state["contract"]["checks"]:
        identity = state["check_executables"][check["id"]]
        executable = shutil.which(check["argv"][0])
        if not executable or executable != identity["path"] or _file_hash(Path(executable)) != identity["sha256"]:
            errors.append("workflow_check_executable_changed")
        receipt = state["check_receipts"].get(check["id"])
        if receipt and (receipt["command_hash"] != digest(check) or receipt["snapshot_hash"] != state["snapshot"]["snapshot_hash"]):
            errors.append("workflow_check_receipt_inputs_changed")
        if state["state"] in {"reviewing", "ready_for_approval"} and (not receipt or receipt["passed"] is not True or receipt["exit_code"] != 0 or receipt["tests_run"] < check["min_tests"]):
            errors.append("workflow_successful_check_receipt_required")
    return sorted(set(errors))


def _block(location: Path, state: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    state["state"] = "blocked"
    state["blockers"] = sorted(set(errors))
    _write(location, state, "blocked", state["blockers"])
    return _view(state, location)


def _view(state: dict[str, Any], location: Path) -> dict[str, Any]:
    limits = state["contract"]["limits"]
    names = {"planned": "begin_step", "implementing": "record_result", "correcting": "begin_step", "checking": "run_check", "reviewing": "host_MCP37_review_then_record_review", "ready_for_approval": "host_handoff_no_external_execution", "blocked": "inspect_blockers_new_authorization_or_manual_recovery", "cancelled": "no_further_work"}
    return {"schema": SCHEMA, "workflow_id": state["workflow_id"], "project": state["project"], "state": state["state"],
            "contract_hash": state["contract_hash"], "snapshot_hash": state["snapshot"]["snapshot_hash"], "next_step": names[state["state"]],
            "pending_attempt": state["pending_attempt"], "blockers": state["blockers"], "limits": limits,
            "remaining": {"repairs": max(0, limits["max_repairs"] - state["repairs"]), "check_runs": max(0, limits["max_check_runs"] - state["check_runs"]), "seconds": max(0, int(state["created_at"] + limits["max_seconds"] - time.time())), "model_calls": 0, "cost_microunits": 0},
            "check_receipts": state["check_receipts"], "review": state["review_receipt"], "event_count": len(state["events"]), "audit_head": state["events"][-1]["event_hash"],
            "evidence_directory": str(location), "final_action": state["contract"]["final_action"],
            "ready_for_approval": state["state"] == "ready_for_approval", "completed": False,
            "execution": "host_agent_only_no_background_agent_or_external_action_adapter"}


def prepare(project: Path, contract: dict[str, Any], store_root: Path | None = None) -> dict[str, Any]:
    project = project.resolve()
    contract = validate_contract(contract)
    prepared_plan = plan(project, contract)
    baseline = snapshot(project, contract)
    for check in contract["checks"]:
        if any(not any(_under(name, [p]) and baseline["files"][name] is not None for name in baseline["files"]) for p in check["verifier_paths"]):
            raise ValueError("workflow_verifier_path_missing")
    executables = {}
    for check in contract["checks"]:
        executable = shutil.which(check["argv"][0])
        if not executable:
            raise ValueError("workflow_check_executable_missing")
        executables[check["id"]] = {"path": executable, "sha256": _file_hash(Path(executable))}
    workflow_id = "wf_" + uuid.uuid4().hex
    location = _location(project, workflow_id, store_root)
    location.mkdir(parents=True, exist_ok=False)
    state = {"schema": SCHEMA, "workflow_id": workflow_id, "project": str(project), "contract": contract, "contract_hash": digest(contract),
             "created_at": time.time(), "state": "planned", "baseline": baseline, "snapshot": baseline, "pending_attempt": None,
             "repairs": 0, "check_runs": 0, "check_receipts": {}, "receipt_history": [], "check_executables": executables, "review_receipt": None, "failed_snapshots": [], "failure_fingerprints": [], "blockers": [], "events": []}
    with _lock(location):
        _write(location, state, "prepared", {"plan_hash": digest(prepared_plan)})
    result = _view(state, location)
    result["plan"] = prepared_plan
    return result


def status(project: Path, workflow_id: str, store_root: Path | None = None) -> dict[str, Any]:
    project = project.resolve()
    location = _location(project, workflow_id, store_root)
    state = _read(location, project)
    result = _view(state, location)
    stale = []
    try:
        current = snapshot(project, state["contract"])
        stale = _scope_errors(state, current)
        if state["state"] not in {"planned", "implementing", "correcting", "cancelled"} and current != state["snapshot"]:
            stale.append("workflow_snapshot_changed")
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        stale.append(str(exc))
    stale += _review_current_errors(project, state) + _checks_current_errors(state)
    if state["state"] == "ready_for_approval":
        try:
            if snapshot(project, state["contract"]) != state["snapshot"]:
                stale.append("workflow_snapshot_changed_during_readiness_check")
        except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
            stale.append(str(exc))
    result["blockers"] = sorted(set(result["blockers"] + stale + _budget_errors(state)))
    result["evidence_current"] = not stale
    if result["blockers"]:
        result["ready_for_approval"] = False
    result["mutation_locked"] = (location / "mutation.lock").exists() or (location.parent / "mutation.lock").exists()
    if result["mutation_locked"]:
        result["next_step"] = "inspect_lock_owner_never_steal_lock"
        result["ready_for_approval"] = False
    return result


def begin_step(project: Path, workflow_id: str, store_root: Path | None = None) -> dict[str, Any]:
    project = project.resolve()
    location = _location(project, workflow_id, store_root)
    with _lock(location):
        state = _read(location, project)
        if state["state"] not in {"planned", "correcting"} or state["pending_attempt"]:
            raise ValueError("workflow_implementation_not_allowed_in_current_state")
        if "local_implementation" not in state["contract"]["allowed_actions"]:
            raise ValueError("workflow_implementation_not_authorized")
        errors = _budget_errors(state) + _scope_errors(state, snapshot(project, state["contract"]))
        if errors:
            return _block(location, state, errors)
        if state["state"] == "correcting":
            if state["repairs"] >= state["contract"]["limits"]["max_repairs"]:
                return _block(location, state, ["workflow_repair_budget_exhausted"])
            state["repairs"] += 1
        state["state"] = "implementing"
        state["pending_attempt"] = {"id": "attempt_" + uuid.uuid4().hex, "kind": "implementation", "snapshot_hash": state["snapshot"]["snapshot_hash"]}
        _write(location, state, "implementation_started", state["pending_attempt"])
        return _view(state, location)


def record_result(project: Path, workflow_id: str, attempt_id: str, store_root: Path | None = None) -> dict[str, Any]:
    """Complete host implementation; never accept a caller's claimed test success."""
    project = project.resolve()
    location = _location(project, workflow_id, store_root)
    with _lock(location):
        state = _read(location, project)
        pending = state["pending_attempt"]
        if state["state"] != "implementing" or not pending or pending["id"] != attempt_id or pending["kind"] != "implementation":
            raise ValueError("workflow_attempt_mismatch")
        current = snapshot(project, state["contract"])
        errors = _budget_errors(state) + _scope_errors(state, current)
        if current["input_hash"] in state["failed_snapshots"]:
            errors.append("workflow_unchanged_failed_snapshot")
        if errors:
            return _block(location, state, errors)
        state["pending_attempt"] = None
        state["snapshot"] = current
        state["check_receipts"] = {}
        state["review_receipt"] = None
        state["state"] = "checking"
        _write(location, state, "implementation_recorded", {"attempt_id": attempt_id, "changed_paths": _changed(state["baseline"], current)})
        return _view(state, location)


def _test_count(text: str, parser: str) -> int:
    if parser == "unittest":
        found = re.findall(r"^Ran (\d+) tests? in [0-9.]+s", text, re.MULTILINE)
    elif parser == "pytest":
        found = re.findall(r"\b(\d+) passed\b", text)
    else:
        return 0
    return int(found[-1]) if found else 0


def _failed(location: Path, state: dict[str, Any], fingerprint: str, errors: list[str]) -> dict[str, Any]:
    repeated = fingerprint in state["failure_fingerprints"]
    state["failure_fingerprints"].append(fingerprint)
    state["failed_snapshots"].append(state["snapshot"]["input_hash"])
    state["pending_attempt"] = None
    state["blockers"] = errors
    if repeated:
        return _block(location, state, errors + ["workflow_repeated_finding_no_progress"])
    if state["repairs"] >= state["contract"]["limits"]["max_repairs"]:
        return _block(location, state, errors + ["workflow_repair_budget_exhausted"])
    state["state"] = "correcting"
    _write(location, state, "repair_required", {"fingerprint": fingerprint, "errors": errors})
    return _view(state, location)


def run_check(project: Path, workflow_id: str, check_id: str, execution_authorized: bool = False, store_root: Path | None = None) -> dict[str, Any]:
    """Opt-in registered argv runner, NOT a sandbox or independent authorization."""
    if execution_authorized is not True:
        raise ValueError("workflow_local_check_execution_requires_host_authorization")
    project = project.resolve()
    location = _location(project, workflow_id, store_root)
    # Keep the mutation lock for the actual check. Cancel cannot race this receipt;
    # the check finishes within its timeout, after which cancel stops future work.
    with _lock(location):
        state = _read(location, project)
        if state["state"] != "checking" or state["pending_attempt"]:
            raise ValueError("workflow_check_not_allowed_in_current_state")
        if "local_checks" not in state["contract"]["allowed_actions"]:
            raise ValueError("workflow_local_checks_not_authorized")
        checks = state["contract"]["checks"]
        check = next((c for c in checks if c["id"] == check_id), None)
        if check is None:
            raise ValueError("workflow_unknown_check")
        next_check = next((c["id"] for c in checks if c["id"] not in state["check_receipts"]), None)
        if check_id != next_check:
            raise ValueError("workflow_check_dependency_or_duplicate")
        current = snapshot(project, state["contract"])
        errors = _budget_errors(state) + _scope_errors(state, current)
        if current != state["snapshot"]:
            errors.append("workflow_snapshot_changed_before_check")
        if state["check_runs"] >= state["contract"]["limits"]["max_check_runs"]:
            errors.append("workflow_check_budget_exhausted")
        if errors:
            return _block(location, state, errors)
        executable = shutil.which(check["argv"][0])
        if not executable:
            return _block(location, state, ["workflow_check_executable_missing"])
        identity = state["check_executables"][check_id]
        if executable != identity["path"] or _file_hash(Path(executable)) != identity["sha256"]:
            return _block(location, state, ["workflow_check_executable_changed"])
        attempt_id = "attempt_" + uuid.uuid4().hex
        state["pending_attempt"] = {"id": attempt_id, "kind": "local_check", "check_id": check_id, "snapshot_hash": current["snapshot_hash"]}
        state["check_runs"] += 1
        _write(location, state, "check_started", state["pending_attempt"])
        evidence = location / "evidence" / attempt_id
        evidence.mkdir(parents=True)
        started = time.time()
        timeout = min(check["timeout_seconds"], max(0.01, state["created_at"] + state["contract"]["limits"]["max_seconds"] - started))
        exit_code = -1
        errors = []
        # TemporaryFile is deleted on close, including exceptional exits. It is
        # not an enduring named raw log in the workflow evidence directory.
        with tempfile.TemporaryFile(mode="w+b", dir=evidence) as handle:
            try:
                process = subprocess.Popen([executable, *check["argv"][1:]], cwd=project, stdout=handle, stderr=subprocess.STDOUT, shell=False)
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if os.fstat(handle.fileno()).st_size > MAX_LOG_BYTES or time.monotonic() >= deadline:
                        errors.append("workflow_check_output_limit_exceeded" if os.fstat(handle.fileno()).st_size > MAX_LOG_BYTES else "workflow_check_timeout")
                        process.kill()
                        break
                    time.sleep(0.02)
                exit_code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                errors.append("workflow_check_termination_unverified")
            except OSError:
                errors.append("workflow_check_launch_failed")
            if os.fstat(handle.fileno()).st_size > MAX_LOG_BYTES:
                errors.append("workflow_check_output_limit_exceeded")
            handle.seek(0)
            raw_text = handle.read(MAX_LOG_BYTES).decode("utf-8", errors="replace")
        # Store only bounded redacted evidence, never raw stdout in durable memory.
        from .prompt_memory import redact_text
        sanitized = redact_text(raw_text)["text"]
        from .ccg.code_review import safe_text
        try:
            safe_text("check-output.txt", sanitized.encode())
        except ValueError:
            sanitized = "[WORKFLOW OUTPUT BLOCKED: redaction incomplete]"
            errors.append("workflow_check_output_redaction_failed")
        sanitized_bytes = sanitized.encode("utf-8")
        if len(sanitized_bytes) > MAX_LOG_BYTES:
            sanitized = sanitized_bytes[:MAX_LOG_BYTES].decode("utf-8", errors="ignore")
            errors.append("workflow_check_redacted_output_limit_exceeded")
        output = evidence / "output.txt"
        output.write_text(str(sanitized), encoding="utf-8", newline="\n")
        tests = _test_count(raw_text, check["parser"])
        if exit_code != 0:
            errors.append("workflow_check_nonzero_exit")
        if tests < check["min_tests"]:
            errors.append("workflow_check_insufficient_tests")
        after = snapshot(project, state["contract"])
        if after != current:
            errors.append("workflow_check_changed_snapshot")
        if _file_hash(Path(executable)) != identity["sha256"]:
            errors.append("workflow_check_executable_changed_during_check")
        errors += _budget_errors(state)
        receipt = {"schema": SCHEMA, "attempt_id": attempt_id, "check_id": check_id, "contract_hash": state["contract_hash"], "snapshot_hash": current["snapshot_hash"],
                   "command_hash": digest(check), "executable_sha256": _file_hash(Path(executable)), "exit_code": exit_code, "tests_run": tests,
                   "started_at": started, "duration_seconds": time.time() - started, "output_sha256": _file_hash(output), "errors": sorted(set(errors)), "passed": not errors}
        receipt["receipt_hash"] = digest(receipt)
        (evidence / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, ensure_ascii=True, indent=2), encoding="utf-8")
        state["receipt_history"].append(receipt)
        state["check_receipts"][check_id] = receipt
        state["pending_attempt"] = None
        if errors:
            fingerprint = digest({"check_id": check_id, "errors": sorted(set(errors)), "exit_code": exit_code, "tests_run": tests})
            return _failed(location, state, fingerprint, sorted(set(errors)))
        state["blockers"] = []
        if len(state["check_receipts"]) == len(checks):
            state["state"] = "reviewing" if state["contract"]["review"]["required"] else "ready_for_approval"
        _write(location, state, "check_recorded", {"check_id": check_id, "receipt_hash": receipt["receipt_hash"]})
        return _view(state, location)


def record_review(project: Path, workflow_id: str, store_root: Path | None = None) -> dict[str, Any]:
    """Revalidate MCP37's own receipt; do not call, retry, or bypass its provider."""
    project = project.resolve()
    location = _location(project, workflow_id, store_root)
    with _lock(location):
        state = _read(location, project)
        if state["state"] != "reviewing" or state["pending_attempt"]:
            raise ValueError("workflow_review_not_allowed_in_current_state")
        current = snapshot(project, state["contract"])
        errors = _budget_errors(state) + _scope_errors(state, current) + _review_current_errors(project, state) + _checks_current_errors(state)
        if current != state["snapshot"]:
            errors.append("workflow_snapshot_changed_before_review")
        if errors:
            return _block(location, state, errors)
        from .ccg.code_review import gate
        review = state["contract"]["review"]
        try:
            result = gate(project, review["base_ref"], "HEAD", review["context_paths"])
        except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
            return _block(location, state, ["workflow_review_gate_blocked:" + str(exc)])
        after = snapshot(project, state["contract"])
        errors = _budget_errors(state) + _scope_errors(state, after) + _checks_current_errors(state)
        if after != current:
            errors.append("workflow_snapshot_changed_during_review_gate")
        if errors:
            return _block(location, state, errors)
        if result.get("ready_for_pr") is not True:
            review_errors = result.get("errors", [])
            if "review_missing_or_stale" in review_errors and not any(e.startswith("unresolved_") for e in review_errors):
                state["blockers"] = ["workflow_mcp37_review_required"]
                _write(location, state, "review_evidence_missing", result)
                return _view(state, location)
            state["review_receipt"] = result
            # Invalid usage, missing evidence, interrupted transport and corrupt
            # receipts are not code repair invitations or provider retry authority.
            actionable = {"unresolved_P0", "unresolved_P1", "unresolved_P2"}
            if not set(review_errors) & actionable or set(review_errors) - actionable - {"review_not_passed"}:
                return _block(location, state, ["workflow_mcp37_recovery_or_evidence_required", *review_errors])
            return _failed(location, state, digest({"review_errors": review_errors}), ["workflow_mcp37_review_failed", *review_errors])
        state["review_receipt"] = result
        state["blockers"] = []
        state["state"] = "ready_for_approval"
        _write(location, state, "review_verified", result)
        return _view(state, location)


def resume(project: Path, workflow_id: str, store_root: Path | None = None) -> dict[str, Any]:
    project = project.resolve()
    location = _location(project, workflow_id, store_root)
    with _lock(location):
        state = _read(location, project)
        if state["state"] in {"cancelled", "blocked"}:
            return _view(state, location)
        if state["pending_attempt"] and state["pending_attempt"]["kind"] != "implementation":
            return _block(location, state, ["workflow_interrupted_check_outcome_unknown_no_automatic_retry"])
        current = snapshot(project, state["contract"])
        errors = _budget_errors(state) + _scope_errors(state, current) + _review_current_errors(project, state) + _checks_current_errors(state)
        if state["state"] not in {"planned", "implementing", "correcting"} and current != state["snapshot"]:
            errors.append("workflow_snapshot_changed_on_resume")
        if errors:
            return _block(location, state, errors)
        _write(location, state, "resumed", {"implementation_attempt_preserved": bool(state["pending_attempt"])})
        return _view(state, location)


def cancel(project: Path, workflow_id: str, store_root: Path | None = None) -> dict[str, Any]:
    project = project.resolve()
    location = _location(project, workflow_id, store_root)
    with _lock(location):
        state = _read(location, project)
        if state["state"] != "cancelled":
            state["state"] = "cancelled"
            _write(location, state, "cancelled", {"pending_attempt_preserved": state["pending_attempt"]})
        return _view(state, location)


def memory_summary(project: Path, workflow_id: str, store_root: Path | None = None) -> dict[str, Any]:
    """Safe checkpoint payload; does not append live state, logs, or prompts."""
    project = project.resolve()
    location = _location(project, workflow_id, store_root)
    state = _read(location, project)
    view = status(project, workflow_id, store_root)
    return {"schema": SCHEMA, "workflow_id": workflow_id, "project": str(project), "task": state["contract"]["goal"],
            "summary_text": f"Workflow {workflow_id}: {state['state']}; {len(state['check_receipts'])} check receipts; repairs {state['repairs']}. Final external action is not executed by MCP38.",
            "limits": view["limits"], "remaining": view["remaining"],
            "gates": [f"contract={state['contract_hash']}", f"snapshot={state['snapshot']['snapshot_hash']}", f"audit={view['audit_head']}", f"evidence_current={view['evidence_current']}"],
            "risks": view["blockers"], "next": [view["next_step"]], "evidence_directory": str(location), "memory_written": False}


def dispatch(action: str, project: Path, params: dict[str, Any]) -> dict[str, Any]:
    """Shared MCP/CLI routing; unexpected fields cannot smuggle a claimed PASS."""
    action = action.replace("-", "_")
    specific = {"plan": {"contract", "goal", "allowed_paths", "checks", "final_action"}, "prepare": {"contract"}, "status": set(), "begin_step": set(), "record_result": {"attempt_id"}, "run_check": {"check_id", "execution_authorized"}, "record_review": set(), "resume": set(), "cancel": set(), "memory_summary": set()}
    if action not in specific or set(params) - (specific[action] | {"project", "workflow_id", "store_root"}):
        raise ValueError("invalid_workflow_dispatch_parameters")
    if action == "plan":
        if "contract" in params:
            if set(params) & {"goal", "allowed_paths", "checks", "final_action"}:
                raise ValueError("workflow_plan_use_contract_or_goal")
            return plan(project, params["contract"])
        return propose(project, params.get("goal"), params.get("allowed_paths"), params.get("checks"), params.get("final_action", "handoff"))
    root = Path(params["store_root"]) if params.get("store_root") else None
    if action == "prepare":
        return prepare(project, params.get("contract"), root)
    workflow_id = params.get("workflow_id")
    if action == "record_result":
        return record_result(project, workflow_id, params.get("attempt_id"), root)
    if action == "run_check":
        return run_check(project, workflow_id, params.get("check_id"), params.get("execution_authorized", False), root)
    functions = {"status": status, "begin_step": begin_step, "record_review": record_review, "resume": resume, "cancel": cancel, "memory_summary": memory_summary}
    return functions[action](project, workflow_id, root)
