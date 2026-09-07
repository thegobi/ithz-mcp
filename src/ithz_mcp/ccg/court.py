from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..canonical_json import dump_pretty, dumps
from ..context_pack import build_context_pack
from ..focus_context import focus_context_pack_from_source
from ..hashing import sha256_file, stable_json_hash
from ..memory_integrity import (
    build_evidence_views,
    memory_integrity_status,
    run_memory_integrity_benchmark,
    sealed_evidence_for_role,
)
from ..mcp36_canary import (
    CANARY_VERSION,
    CanaryGateError,
    canary_admission,
    canary_status,
    enable_canary,
    pause_canary,
    record_canary_receipt,
    reserve_canary_slot,
)
from ..native_archive_store import archive_append_event, native_archive_current_projection
from ..safety import redaction_block_reason
from .broker import CapabilityBroker
from .ledger import EvidenceLedger
from .models import BackendError, CodexAppServerBackend, GeminiBackend, GrokBackend, RoleResult
from .settings_store import effective_preferences, resolve_gemini_key, resolve_xai_key


CCG_VERSION = "mcp36.5-evidence-trust-v2"
ROLE_TEMPLATE_VERSION = "ccg_role_template_v3"
RISK_LEVELS = ("low", "medium", "high", "critical")
VERDICTS = ("ALLOW", "ALLOW_WITH_LIMITS", "SIMULATE_ONLY", "REQUEST_EVIDENCE", "HUMAN_REQUIRED", "STOP")


def default_constitution() -> dict[str, Any]:
    constitution: dict[str, Any] = {
        "schema": "ccg_constitution_v1",
        "constitution_id": "ccg-universal-baseline",
        "version": "1.0.0",
        "title": "Universal CCG baseline constitution",
        "principles": [
            "Models may propose and contest actions but never mint their own capabilities.",
            "Every role works from one sealed evidence hash and submits before seeing peer identity.",
            "The semantic judge is blind to model provider and fallback identity.",
            "The formal core knows the real role manifest and fails closed on missing quorum.",
            "A case cannot weaken or amend the constitution that governs that same case.",
            "Unknown capability scope or unverifiable evidence cannot become an authorization.",
            "Model diversity is not evidence diversity; high-risk review needs a raw-first independent evidence view.",
            "Summaries and derived memory are navigation aids, never the sole source of a consequential claim.",
        ],
        "risk_policy": {
            "low": {"opponents": 2, "cross_lab_required": False, "human_required": False, "fallback_limit": False},
            "medium": {"opponents": 2, "cross_lab_required": False, "human_required": False, "fallback_limit": True},
            "high": {"opponents": 2, "cross_lab_required": True, "human_required": True, "fallback_limit": True},
            "critical": {"opponents": 2, "cross_lab_required": True, "human_required": True, "fallback_limit": True},
        },
        "allowed_capabilities": [
            "analysis.read",
            "file.write.sandboxed",
            "test.run.sandboxed",
            "git.patch.reviewed",
            "external.action.scoped",
        ],
        "forbidden_capabilities": [
            "credential.read",
            "payment.unbounded",
            "production.delete.unbounded",
            "constitution.modify_in_case",
            "broker.bypass",
        ],
        "verdicts": list(VERDICTS),
        "authorization": {"default_ttl_seconds": 600, "max_uses": 1, "exact_action_hash": True},
    }
    constitution["constitution_hash"] = stable_json_hash(constitution)
    return constitution


def _constitution_markdown(constitution: dict[str, Any]) -> str:
    lines = [
        "# CCG Constitution",
        "",
        f"Version: `{constitution['version']}`",
        f"Hash: `{constitution['constitution_hash']}`",
        "",
        "## Principles",
        "",
    ]
    lines.extend(f"- {item}" for item in constitution["principles"])
    lines += ["", "## Risk quorum", ""]
    for risk, policy in constitution["risk_policy"].items():
        lines.append(
            f"- **{risk}**: {policy['opponents']} opponents; cross-lab={str(policy['cross_lab_required']).lower()}; "
            f"human={str(policy['human_required']).lower()}"
        )
    lines += ["", "## Forbidden capabilities", ""]
    lines.extend(f"- `{item}`" for item in constitution["forbidden_capabilities"])
    return "\n".join(lines).rstrip() + "\n"


def initialize_project(project: Path, overwrite: bool = False) -> dict[str, Any]:
    root = project.resolve()
    root.mkdir(parents=True, exist_ok=True)
    config_dir = root / ".ccg"
    config_dir.mkdir(parents=True, exist_ok=True)
    constitution_path = config_dir / "constitution.json"
    markdown_path = config_dir / "CONSTITUTION.md"
    if constitution_path.exists() and not overwrite:
        constitution = json.loads(constitution_path.read_text(encoding="utf-8"))
        created = False
    else:
        constitution = default_constitution()
        constitution_path.write_text(dump_pretty(constitution), encoding="utf-8")
        markdown_path.write_text(_constitution_markdown(constitution), encoding="utf-8")
        created = True
    ledger = EvidenceLedger(root)
    ledger.initialize()
    for local_dir in (ledger.root, root / ".ccg-sandbox"):
        local_dir.mkdir(parents=True, exist_ok=True)
        ignore = local_dir / ".gitignore"
        if not ignore.exists():
            ignore.write_text("*\n!.gitignore\n", encoding="utf-8")
    return {
        "project": str(root),
        "created": created,
        "constitution": str(constitution_path),
        "constitution_hash": constitution["constitution_hash"],
        "evidence_root": str(ledger.root),
    }


def load_constitution(project: Path) -> dict[str, Any]:
    path = project.resolve() / ".ccg" / "constitution.json"
    if not path.exists():
        initialize_project(project)
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "ccg_constitution_v1":
        raise ValueError("unsupported_ccg_constitution")
    stored_hash = value.get("constitution_hash")
    body = {key: item for key, item in value.items() if key != "constitution_hash"}
    if stored_hash != stable_json_hash(body):
        raise ValueError("constitution_hash_mismatch")
    return value


def _object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or list(properties),
        "additionalProperties": False,
    }


HASH_SCHEMA = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
STRING_ARRAY = {"type": "array", "items": {"type": "string"}}

ACTION_SCHEMA = _object_schema(
    {
        "capability": {"type": "string"},
        "description": {"type": "string"},
        "parameters_json": {"type": "string", "description": "Canonical JSON object encoded as text."},
        "expected_effect": {"type": "string"},
        "rollback": {"type": "string"},
        "irreversible": {"type": "boolean"},
    }
)

PROPOSER_SCHEMA = _object_schema(
    {
        "evidence_hash": HASH_SCHEMA,
        "summary": {"type": "string"},
        "actions": {"type": "array", "minItems": 1, "maxItems": 8, "items": ACTION_SCHEMA},
        "risk_assessment": {"type": "string", "enum": list(RISK_LEVELS)},
        "assumptions": STRING_ARRAY,
        "evidence_references": STRING_ARRAY,
    }
)

OBJECTION_SCHEMA = _object_schema(
    {
        "id": {"type": "string"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "claim": {"type": "string"},
        "constitution_clauses": STRING_ARRAY,
        "evidence": STRING_ARRAY,
        "safer_alternative": {"type": "string"},
        "veto": {"type": "boolean"},
    }
)

OPPONENT_SCHEMA = _object_schema(
    {
        "evidence_hash": HASH_SCHEMA,
        "recommendation": {"type": "string", "enum": list(VERDICTS)},
        "objections": {"type": "array", "maxItems": 12, "items": OBJECTION_SCHEMA},
        "missing_evidence": STRING_ARRAY,
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    }
)

JUDGE_SCHEMA = _object_schema(
    {
        "evidence_hash": HASH_SCHEMA,
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "scope_limits": STRING_ARRAY,
        "resolved_objections": STRING_ARRAY,
        "unresolved_objections": STRING_ARRAY,
        "rationale": {"type": "string"},
        "human_approval_required": {"type": "boolean"},
    }
)

AUDITOR_SCHEMA = _object_schema(
    {
        "evidence_hash": HASH_SCHEMA,
        "process_valid": {"type": "boolean"},
        "checks": STRING_ARRAY,
        "defects": STRING_ARRAY,
        "final_disposition": {"type": "string", "enum": ["VALID", "INVALID", "INCOMPLETE"]},
    }
)


def _safe_json_string(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)


def _role_template(
    role: str,
    constitution: dict[str, Any],
    output_schema: dict[str, Any],
) -> tuple[str, str]:
    contracts = {
        "proposer": (
            "Prepare the smallest sufficient plan. Every action needs a capability and parameters_json containing "
            "a JSON object. Prefer reversible, bounded actions. Use the assigned verified-current evidence view, cite "
            "raw artifacts when available, and never request credentials or bypass the broker."
        ),
        "opponent_primary": (
            "Attack assumptions, scope, reversibility, evidence and trajectory risks. Give stable objection ids. "
            "Prioritize the assigned conflict and counterevidence view. A veto is reserved for credible unsafe or "
            "constitution-breaking paths."
        ),
        "opponent_cross": (
            "Work as the raw-first memory-disabled control. Do not infer support from a withheld shared synthesis. "
            "Search for composed multi-step failures, indirect effects, hidden state changes and apparently harmless "
            "operations that combine into a forbidden result. Give stable objection ids."
        ),
        "opponent_blind_first": (
            "Perform an independent raw-first pass before any proposal exists. Do not infer a plan, shared synthesis, "
            "or another role's position. Record only evidence-grounded risks and missing evidence with stable objection ids."
        ),
        "opponent_fallback": (
            "Work as the raw-first fallback control. Do not infer support from a withheld shared synthesis. Search for "
            "composed multi-step failures, indirect effects and apparently harmless operations that combine into a "
            "forbidden result. Give stable objection ids."
        ),
        "judge": (
            "Act as the blind semantic governor. Evaluate arguments without guessing model identity. Mark every veto "
            "objection as resolved or unresolved. Do not issue a token."
        ),
        "auditor": (
            "Audit procedure rather than policy merits: isolation, evidence binding, quorum, judge blindness and "
            "declared model and evidence-view diversity. Verify that the cross-lab view was raw-first and that the "
            "shared synthesized projection was withheld from it. A missing substantive fact, a restrictive semantic verdict, or pending human "
            "approval is not by itself a process defect; the judge and formal core handle those gates. Mark the "
            "process invalid only for protocol defects such as hash mismatch, missing role, non-isolation, false "
            "diversity, judge identity leakage, or malformed role output."
        ),
    }
    if role not in contracts:
        raise ValueError(f"unknown_ccg_role:{role}")
    template = (
        f"CCG ROLE TEMPLATE: {ROLE_TEMPLATE_VERSION}\n"
        f"ROLE: {role}\n\n"
        f"GOVERNING CONSTITUTION:\n{_safe_json_string(constitution)}\n\n"
        f"ROLE CONTRACT:\n{contracts[role]}\n\n"
        f"REQUIRED OUTPUT SCHEMA:\n{_safe_json_string(output_schema)}\n\n"
        "Use only the following case packet. Copy its evidence_hash exactly. Return the schema object only. "
        "Do not reveal hidden reasoning or identify provider, model, laboratory or fallback origin.\n\n"
        "--- CASE-SPECIFIC PACKET FOLLOWS ---\n"
    )
    return template, stable_json_hash({"schema": ROLE_TEMPLATE_VERSION, "template": template})


def _role_prompt(
    role: str,
    evidence: dict[str, Any],
    payload: dict[str, Any],
    output_schema: dict[str, Any],
    constitution: dict[str, Any],
) -> tuple[str, str]:
    template, template_hash = _role_template(role, constitution, output_schema)
    sealed_packet = sealed_evidence_for_role(evidence, role)
    if role == "judge":
        material = sealed_packet.get("decision_material")
        if isinstance(material, dict) and isinstance(material.get("review_profile"), dict):
            material["review_profile"] = {
                "routing_profile_hash": stable_json_hash(material["review_profile"]),
                "provider_identity_withheld_from_judge": True,
            }
    review_profile = evidence.get("decision_material", {}).get("review_profile", {})
    final_case_note = ""
    if isinstance(review_profile, dict) and isinstance(review_profile.get("final_case_contract"), dict):
        final_case_note = (
            "CURRENT FINAL CASE POSTFLIGHT CONTRACT:\n"
            "The current case's five-run count, cross-lab quorum, per-provider usage, ledger verification and "
            "latest_final_case record are outputs created only after all five roles finish. Their absence from this "
            "preflight packet is not missing evidence and must not be raised as an objection or veto. The deterministic "
            "runtime validates them fail-closed after role completion. Review the supplied preflight manifest and "
            "substantive task evidence instead.\n\n"
        )
    base = (
        template
        + f"SEALED EVIDENCE HASH: {evidence['evidence_hash']}\n\n"
        + f"SEALED PACKET:\n{_safe_json_string(sealed_packet)}\n\n"
        + final_case_note
    )
    if role == "proposer":
        return base + "Prepare the proposal now.", template_hash
    if role == "opponent_primary":
        return base + (
            f"PROPOSAL:\n{_safe_json_string(payload['proposal'])}\n\n"
            "Submit the primary objection report now."
        ), template_hash
    if role == "opponent_blind_first":
        return base + "Submit the sealed independent first-pass objection report now.", template_hash
    if role in {"opponent_cross", "opponent_fallback"}:
        return base + (
            f"PROPOSAL:\n{_safe_json_string(payload['proposal'])}\n\n"
            "Submit the second objection report now."
        ), template_hash
    if role == "judge":
        # Deliberately contains no provider, model, fallback or thread metadata.
        blind_first = payload.get("opponent_blind_first")
        blind_first_block = f"INDEPENDENT FIRST PASS:\n{_safe_json_string(blind_first)}\n\n" if isinstance(blind_first, dict) else ""
        return base + (
            f"PROPOSAL:\n{_safe_json_string(payload['proposal'])}\n\n"
            f"OPPONENT 1:\n{_safe_json_string(payload['opponent_1'])}\n\n"
            f"OPPONENT 2:\n{_safe_json_string(payload['opponent_2'])}\n\n"
            f"{blind_first_block}"
            "Return only the blind semantic verdict."
        ), template_hash
    if role == "auditor":
        return base + (
            f"ROLE MANIFEST:\n{_safe_json_string(payload['role_manifest'])}\n\n"
            f"FORMAL PROCEDURE EVIDENCE:\n{_safe_json_string(payload['procedure_evidence'])}\n\n"
            f"PROPOSAL:\n{_safe_json_string(payload['proposal'])}\n\n"
            f"OPPONENT REPORTS:\n{_safe_json_string(payload['opponents'])}\n\n"
            f"BLIND JUDGE VERDICT:\n{_safe_json_string(payload['judge'])}\n\n"
            "The manifest contains the four completed upstream roles; your current isolated submission is role five. "
            "Verify the five-role protocol only. Do not reject the process merely because direct implementation "
            "evidence or human approval is absent; preserve those as semantic/formal gates. Return only the process audit."
        ), template_hash
    raise ValueError(f"unknown_ccg_role:{role}")


def _decode_parameters(action: dict[str, Any]) -> dict[str, Any]:
    raw = action.get("parameters_json", "{}")
    if not isinstance(raw, str):
        raise ValueError("action_parameters_json_must_be_string")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("action_parameters_json_must_encode_object")
    return value


def _action_with_parameters(action: dict[str, Any]) -> dict[str, Any]:
    parameters = _decode_parameters(action)
    if action.get("capability") == "file.write.sandboxed":
        relative_path = parameters.get("relative_path", parameters.get("path", ""))
        content = parameters.get("content", "")
        if not isinstance(relative_path, str) or not isinstance(content, str):
            raise ValueError("sandbox_write_path_and_content_must_be_strings")
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("unsafe_sandbox_write_path")
        if len(content.encode("utf-8")) > 100_000:
            raise ValueError("sandbox_write_content_too_large")
        parameters = {
            "relative_path": relative.as_posix(),
            "content": content,
            "allow_overwrite": bool(parameters.get("allow_overwrite", False)),
        }
    return {**action, "parameters": parameters}


def _provider_usage(results: list[RoleResult]) -> dict[str, Any]:
    missing_roles: list[str] = []
    summary: dict[str, Any] = {
        "model_calls": len(results),
        "metered_model_calls": 0,
        "complete": True,
        "missing_roles": missing_roles,
        "providers": {},
    }
    for result in results:
        row = summary["providers"].setdefault(
            result.provider,
            {
                "calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cached_input_tokens": 0,
                "thinking_tokens": 0,
                "total_tokens": 0,
            },
        )
        row["calls"] += 1
        for key in ("input_tokens", "output_tokens", "cached_input_tokens", "thinking_tokens", "total_tokens"):
            row[key] += int(result.usage.get(key, 0))
        if result.usage.get("total_tokens", 0) > 0 and result.usage_source:
            summary["metered_model_calls"] += 1
        else:
            missing_roles.append(result.role)
    summary["complete"] = not missing_roles
    return summary


def _load_final_review_manifest(
    project: Path,
    manifest_path: str,
    expected_memory_synthesis_hash: str,
) -> dict[str, Any]:
    path = Path(manifest_path)
    path = path.resolve() if path.is_absolute() else (project / path).resolve()
    if project != path and project not in path.parents:
        raise BackendError("final_review_manifest_outside_project")
    if not path.is_file():
        raise BackendError("final_review_manifest_missing")
    raw = path.read_bytes()
    if len(raw) > 65_536:
        raise BackendError("final_review_manifest_too_large")
    text = raw.decode("utf-8-sig")
    if redaction_block_reason(text):
        raise BackendError("final_review_manifest_secret_like_content")
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BackendError("final_review_manifest_invalid_json") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") not in {
        "ccg_final_review_manifest_v1",
        "ccg_final_review_manifest_v2",
    }:
        raise BackendError("final_review_manifest_schema_invalid")
    schema = str(manifest["schema"])
    if manifest.get("memory_synthesis_hash") != expected_memory_synthesis_hash:
        raise BackendError("final_review_manifest_checkpoint_mismatch")
    artifacts = manifest.get("artifacts")
    receipts = manifest.get("command_receipts")
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 40:
        raise BackendError("final_review_manifest_artifacts_invalid")
    if not isinstance(receipts, list) or not receipts or len(receipts) > 20:
        raise BackendError("final_review_manifest_command_receipts_invalid")
    verified_artifacts: list[dict[str, Any]] = []
    for row in artifacts:
        if not isinstance(row, dict):
            raise BackendError("final_review_manifest_artifact_invalid")
        relative = Path(str(row.get("path", "")))
        expected_hash = str(row.get("sha256", ""))
        target = (project / relative).resolve()
        if relative.is_absolute() or project not in target.parents or not target.is_file():
            raise BackendError("final_review_manifest_artifact_path_invalid")
        actual_hash = sha256_file(target)
        if actual_hash != expected_hash:
            raise BackendError("final_review_manifest_artifact_hash_mismatch")
        verified_artifacts.append({"path": relative.as_posix(), "sha256": actual_hash})
    verified_receipts: list[dict[str, Any]] = []
    for row in receipts:
        if not isinstance(row, dict):
            raise BackendError("final_review_manifest_command_receipt_invalid")
        command = str(row.get("command", "")).strip()
        output_hash = str(row.get("output_sha256", ""))
        exit_code = row.get("exit_code")
        summary = str(row.get("result_summary", "")).strip()
        if (
            not command
            or not isinstance(exit_code, int)
            or len(output_hash) != 64
            or any(char not in "0123456789abcdef" for char in output_hash)
            or not summary
            or len(summary) > 500
        ):
            raise BackendError("final_review_manifest_command_receipt_invalid")
        verified: dict[str, Any] = {
            "command": command[:500],
            "exit_code": exit_code,
            "output_sha256": output_hash,
            "result_summary": summary,
            "output_runtime_verified": False,
        }
        if schema == "ccg_final_review_manifest_v2":
            output_relative = Path(str(row.get("output_artifact_path", "")))
            output_target = (project / output_relative).resolve()
            started_at = str(row.get("started_at", "")).strip()
            finished_at = str(row.get("finished_at", "")).strip()
            working_directory = str(row.get("working_directory", "")).strip()
            tool_version = str(row.get("tool_version", "")).strip()
            environment_fingerprint = str(row.get("environment_fingerprint", ""))
            if (
                output_relative.is_absolute()
                or project not in output_target.parents
                or not output_target.is_file()
                or not started_at
                or not finished_at
                or not working_directory
                or not tool_version
                or len(environment_fingerprint) != 64
                or any(char not in "0123456789abcdef" for char in environment_fingerprint)
            ):
                raise BackendError("final_review_manifest_command_output_artifact_invalid")
            actual_output_hash = sha256_file(output_target)
            if actual_output_hash != output_hash:
                raise BackendError("final_review_manifest_command_output_hash_mismatch")
            verified.update(
                {
                    "output_artifact_path": output_relative.as_posix(),
                    "output_sha256": actual_output_hash,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "working_directory": working_directory[:500],
                    "tool_version": tool_version[:200],
                    "environment_fingerprint": environment_fingerprint,
                    "output_runtime_verified": True,
                }
            )
        verified_receipts.append(verified)
    known_risks = manifest.get("known_risks")
    if not isinstance(known_risks, list):
        known_risks = []
    return {
        "schema": "ccg_final_review_manifest_receipt_v2" if schema.endswith("_v2") else "ccg_final_review_manifest_receipt_v1",
        "source_schema": schema,
        "path": path.relative_to(project).as_posix(),
        "manifest_sha256": sha256_file(path),
        "memory_synthesis_hash": expected_memory_synthesis_hash,
        "scope": str(manifest.get("scope", ""))[:1000],
        "artifacts": verified_artifacts,
        "command_receipts": verified_receipts,
        "git": manifest.get("git", {}) if isinstance(manifest.get("git"), dict) else {},
        "known_risks": [str(item)[:500] for item in known_risks[:20]],
        "artifact_hashes_runtime_verified": True,
        "command_outputs_reported_hash_bound": True,
        "command_outputs_runtime_verified": schema.endswith("_v2") and all(
            bool(row.get("output_runtime_verified")) for row in verified_receipts
        ),
    }


class CourtRunner:
    def __init__(
        self,
        project: Path,
        codex_backend: Any | None = None,
        grok_backend: Any | None = None,
        gemini_backend: Any | None = None,
        daybreak_backend: Any | None = None,
    ) -> None:
        self.project = project.resolve()
        initialize_project(self.project)
        self.constitution = load_constitution(self.project)
        self.ledger = EvidenceLedger(self.project)
        self.broker = CapabilityBroker(self.project, self.ledger)
        preferences = effective_preferences()
        self.preferences = preferences
        self.codex = codex_backend or CodexAppServerBackend(
            model=preferences["codex_model"],
            effort=preferences["codex_effort"],
            timeout_seconds=preferences["codex_timeout"],
            service_tier=os.getenv("CCG_CODEX_SERVICE_TIER", "fast"),
        )
        scripted = getattr(self.codex, "provider", "") == "scripted"
        self.daybreak = daybreak_backend
        if self.daybreak is None and not scripted and preferences["daybreak_policy"] != "off":
            self.daybreak = CodexAppServerBackend(
                model=preferences["daybreak_model"],
                effort=preferences["daybreak_effort"],
                timeout_seconds=preferences["codex_timeout"],
                service_tier=os.getenv("CCG_CODEX_SERVICE_TIER", "fast"),
            )
        if grok_backend is not None:
            self.grok = grok_backend
            self.grok_secret_source = "injected_backend"
        else:
            secret = resolve_xai_key()
            self.grok_secret_source = str(secret["source"])
            self.grok = (
                GrokBackend(
                    secret["value"],
                    preferences["grok_model"],
                    reasoning_effort=preferences["grok_effort"],
                )
                if secret["configured"]
                else None
            )
        if gemini_backend is not None:
            self.gemini = gemini_backend
            self.gemini_secret_source = "injected_backend"
        else:
            gemini_secret = resolve_gemini_key()
            self.gemini_secret_source = str(gemini_secret["source"])
            self.gemini = (
                GeminiBackend(
                    gemini_secret["value"],
                    preferences["gemini_model"],
                    thinking_level=preferences["gemini_thinking_level"],
                )
                if gemini_secret["configured"]
                else None
            )
        role_schemas = {
            "proposer": PROPOSER_SCHEMA,
            "opponent_primary": OPPONENT_SCHEMA,
            "opponent_cross": OPPONENT_SCHEMA,
            "opponent_fallback": OPPONENT_SCHEMA,
            "judge": JUDGE_SCHEMA,
            "auditor": AUDITOR_SCHEMA,
        }
        self.template_hashes = {
            role: _role_template(role, self.constitution, schema)[1]
            for role, schema in role_schemas.items()
        }
        self.template_set_hash = stable_json_hash(self.template_hashes)

    def _focus_context(self, task: str) -> dict[str, Any]:
        query = task[:1200]
        try:
            if (self.project / "project.ithz").exists():
                return native_archive_current_projection(self.project, query, 4)
            source = build_context_pack(self.project, query, 12000)
            source_kind = "ithz_sidecar_v32"
            focus = focus_context_pack_from_source(source, query, 3500, 12000)
            focus_text = str(focus.get("text", ""))[:12000]
            focus_redaction = redaction_block_reason(focus_text)
            if focus_redaction:
                focus_text = "ITHZ focus text withheld by the CCG redaction gate; direct task evidence only."
            return {
                "source": source_kind,
                "schema": focus.get("schema"),
                "focus_pack_hash": focus.get("focus_pack_hash"),
                "fallback_required": bool(focus.get("fallback_required", False) or focus_redaction),
                "selected_files": focus.get("selected_files", []),
                "text": focus_text,
                "redaction_status": "withheld" if focus_redaction else "safe",
            }
        except Exception as exc:
            return {
                "source": "ithz_context_gap",
                "focus_pack_hash": stable_json_hash({"error_type": type(exc).__name__}),
                "fallback_required": True,
                "selected_files": [],
                "text": "ITHZ context was unavailable; direct task evidence only.",
                "evidence_gap": type(exc).__name__,
            }

    @staticmethod
    def _projection_item_ids(projection: dict[str, Any]) -> set[str]:
        sections = projection.get("sections", {})
        if not isinstance(sections, dict):
            return set()
        return {
            str(item.get("event_id") or item.get("semantic_event_hash") or stable_json_hash(item))
            for items in sections.values()
            if isinstance(items, list)
            for item in items
            if isinstance(item, dict)
        }

    def _projection_delta(self, family_hash: str, projection: dict[str, Any]) -> dict[str, Any]:
        for manifest in self.ledger.list_cases(200):
            case_id = str(manifest.get("case_id", ""))
            try:
                prior = self.ledger.read_case(case_id, include_events=False).get("evidence", {})
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if prior.get("case_family_hash") != family_hash:
                continue
            previous = prior.get("ithz_current_projection", {})
            if not isinstance(previous, dict):
                continue
            current_ids = self._projection_item_ids(projection)
            previous_ids = self._projection_item_ids(previous)
            return {
                "schema": "ithz_projection_delta_v1",
                "from_case_id": case_id,
                "from_projection_hash": previous.get("projection_hash"),
                "to_projection_hash": projection.get("projection_hash"),
                "added_item_ids": sorted(current_ids - previous_ids),
                "removed_item_ids": sorted(previous_ids - current_ids),
            }
        return {
            "schema": "ithz_projection_delta_v1",
            "from_case_id": None,
            "from_projection_hash": None,
            "to_projection_hash": projection.get("projection_hash"),
            "added_item_ids": sorted(self._projection_item_ids(projection)),
            "removed_item_ids": [],
        }

    def _evidence(
        self,
        task: str,
        risk: str,
        capability: str,
        run_profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if risk not in RISK_LEVELS:
            raise ValueError(f"invalid_risk_level:{risk}")
        if not task.strip() or len(task) > 12000:
            raise ValueError("task_must_be_between_1_and_12000_characters")
        reason = redaction_block_reason(task)
        if reason:
            raise ValueError(f"task_redaction_blocked:{reason}")
        family_hash = stable_json_hash(
            {
                "task": task.strip(),
                "risk": risk,
                "capability": capability,
                "constitution_hash": self.constitution["constitution_hash"],
            }
        )
        current_projection = self._focus_context(task)
        review_profile = {
            "codex_model": self.codex.model,
            "daybreak_policy": self.preferences["daybreak_policy"],
            "daybreak_model": self.preferences["daybreak_model"],
            "opponent_2_provider": self.preferences["opponent_2_provider"],
            "gemini_model": self.preferences["gemini_model"],
            "grok_model": self.preferences["grok_model"],
        }
        review_profile.update(run_profile or {})
        final_case_contract = review_profile.get("final_case_contract", {})
        review_manifest = (
            final_case_contract.get("review_evidence_manifest")
            if isinstance(final_case_contract, dict)
            else None
        )
        evidence_views = build_evidence_views(
            current_projection,
            review_manifest if isinstance(review_manifest, dict) else None,
        )
        decision_material = {
            "schema": "ccg_decision_material_v2",
            "ccg_version": CCG_VERSION,
            "case_family_hash": family_hash,
            "constitution_hash": self.constitution["constitution_hash"],
            "current_projection_hash": current_projection.get("projection_hash")
            or current_projection.get("focus_pack_hash"),
            "template_set_hash": self.template_set_hash,
            "evidence_view_set_hash": evidence_views["view_set_hash"],
            "memory_influence_receipt_hash": evidence_views["memory_influence_receipt"]["receipt_hash"],
            "review_profile": review_profile,
        }
        body: dict[str, Any] = {
            "schema": "ccg_sealed_evidence_pack_v3",
            "ccg_version": CCG_VERSION,
            "task_charter": {
                "objective": task.strip(),
                "risk_level": risk,
                "requested_capability": capability,
                "done_condition": "A reviewed decision and, when allowed, an exact scoped capability certificate.",
                "non_goals": ["credential access", "broker bypass", "self-amendment of the governing constitution"],
            },
            "constitution_hash": self.constitution["constitution_hash"],
            "constitution": self.constitution,
            "case_family_hash": family_hash,
            "decision_material_hash": stable_json_hash(decision_material),
            "decision_material": decision_material,
            "template_set_hash": self.template_set_hash,
            "template_hashes": self.template_hashes,
            "ithz_current_projection": current_projection,
            "ithz_projection_delta": self._projection_delta(family_hash, current_projection),
            "evidence_views": evidence_views,
        }
        body["evidence_hash"] = stable_json_hash(body)
        return body

    def _run_role(
        self,
        backend: Any,
        role: str,
        evidence: dict[str, Any],
        payload: dict[str, Any],
        schema: dict[str, Any],
        case_id: str,
    ) -> RoleResult:
        chamber = self.ledger.root / "chambers" / case_id / role
        prompt, template_hash = _role_prompt(role, evidence, payload, schema, self.constitution)
        result = backend.run(
            role,
            prompt,
            schema,
            evidence["evidence_hash"],
            chamber,
            template_hash=template_hash,
        )
        self.ledger.store_role_result(case_id, result.as_dict())
        return result

    def _formal_verdict(
        self,
        evidence: dict[str, Any],
        proposal: RoleResult,
        opponents: list[RoleResult],
        judge: RoleResult,
        auditor: RoleResult,
        cross_lab_quorum: bool,
    ) -> tuple[str, list[str], dict[str, Any] | None]:
        reasons: list[str] = []
        requested = evidence["task_charter"]["requested_capability"]
        risk = evidence["task_charter"]["risk_level"]
        policy = self.constitution["risk_policy"][risk]
        expected_hash = evidence["evidence_hash"]
        all_results = [proposal, *opponents, judge, auditor]
        if any(result.data.get("evidence_hash") != expected_hash for result in all_results):
            return "STOP", ["role_evidence_hash_mismatch"], None
        if requested in self.constitution["forbidden_capabilities"]:
            return "STOP", ["requested_capability_forbidden"], None
        if requested not in self.constitution["allowed_capabilities"]:
            return "REQUEST_EVIDENCE", ["requested_capability_not_in_allowlist"], None
        if len(opponents) < int(policy["opponents"]):
            return "STOP", ["opponent_quorum_missing"], None
        if not auditor.data.get("process_valid") or auditor.data.get("final_disposition") != "VALID":
            return "STOP", ["process_auditor_rejected_case"], None
        diversity = evidence.get("evidence_views", {}).get("diversity_receipt", {})
        if risk in {"high", "critical"} and not diversity.get("valid"):
            return "REQUEST_EVIDENCE", ["evidence_view_diversity_missing"], None
        final_contract = evidence.get("decision_material", {}).get("review_profile", {}).get("final_case_contract")
        if isinstance(final_contract, dict):
            manifest = final_contract.get("review_evidence_manifest", {})
            if not isinstance(manifest, dict) or not manifest.get("command_outputs_runtime_verified"):
                return "REQUEST_EVIDENCE", ["command_outputs_not_runtime_verified"], None
        veto_ids = {
            str(objection.get("id"))
            for opponent in opponents
            for objection in opponent.data.get("objections", [])
            if objection.get("veto")
        }
        resolved = {str(item) for item in judge.data.get("resolved_objections", [])}
        unresolved_vetoes = sorted(veto_ids - resolved)
        if unresolved_vetoes:
            return "STOP", [f"unresolved_veto:{item}" for item in unresolved_vetoes], None
        semantic = str(judge.data.get("verdict", "STOP"))
        if semantic not in VERDICTS:
            return "STOP", ["judge_verdict_invalid"], None
        if policy["cross_lab_required"] and not cross_lab_quorum:
            return "HUMAN_REQUIRED", ["cross_lab_quorum_missing"], None
        if policy["human_required"] or judge.data.get("human_approval_required"):
            return "HUMAN_REQUIRED", ["human_approval_required"], None
        if semantic not in {"ALLOW", "ALLOW_WITH_LIMITS"}:
            return semantic, ["semantic_judge_did_not_authorize"], None
        if not cross_lab_quorum and policy.get("fallback_limit") and semantic == "ALLOW":
            semantic = "ALLOW_WITH_LIMITS"
            reasons.append("same_lab_fallback_scope_reduction")
        actions = proposal.data.get("actions", [])
        matching = [action for action in actions if action.get("capability") == requested]
        if len(matching) != 1:
            return "STOP", ["proposal_must_contain_exactly_one_requested_capability_action"], None
        try:
            action = _action_with_parameters(matching[0])
        except (ValueError, json.JSONDecodeError) as exc:
            return "STOP", [f"invalid_action_parameters:{type(exc).__name__}"], None
        if action.get("irreversible") and risk in {"low", "medium"}:
            return "STOP", ["irreversible_action_understated_risk"], None
        return semantic, reasons or ["formal_protocol_satisfied"], action

    def _mirror_summary_to_ithz(self, case_id: str, verdict: str, evidence_hash: str) -> dict[str, Any]:
        if not (self.project / "project.ithz").exists():
            return {"mirrored": False, "reason": "project_ithz_not_present"}
        try:
            result = archive_append_event(
                self.project,
                "ccg_case",
                f"CCG case {case_id} finished with {verdict}; evidence {evidence_hash[:16]}.",
                "ccg_ithz_mcp33",
                ["ccg", "constitutional-review", verdict.lower()],
            )
            event = result.get("event", {})
            return {
                "mirrored": True,
                "event_id": event.get("event_id"),
                "event_hash": event.get("semantic_event_hash"),
                "active_memory_zone": result.get("active_memory_zone"),
                "event_count": result.get("event_count"),
                "current_index_hash": result.get("current_index_hash"),
            }
        except Exception as exc:
            return {"mirrored": False, "reason": f"ithz_mirror_failed:{type(exc).__name__}"}

    def _opponent_2_selection(self, use_grok: str, opponent_2: str) -> tuple[str, bool]:
        if use_grok not in {"auto", "required", "off"}:
            raise ValueError("use_grok_must_be_auto_required_or_off")
        if opponent_2 not in {"auto", "gemini", "grok", "off"}:
            raise ValueError("opponent_2_must_be_auto_gemini_grok_or_off")
        if opponent_2 != "auto":
            return opponent_2, opponent_2 in {"gemini", "grok"}
        if use_grok == "required":
            return "grok", True
        if use_grok == "off":
            return "off", False
        return self.preferences["opponent_2_provider"], False

    def _daybreak_selected(self, risk: str, use_daybreak: str) -> tuple[bool, bool]:
        if use_daybreak not in {"auto", "required", "off"}:
            raise ValueError("use_daybreak_must_be_auto_required_or_off")
        if use_daybreak == "required":
            return True, True
        if use_daybreak == "off":
            return False, False
        policy = self.preferences["daybreak_policy"]
        return policy == "always" or (policy == "high_and_critical" and risk in {"high", "critical"}), False

    def _backend_for_cross_provider(self, provider: str) -> Any | None:
        return self.gemini if provider == "gemini" else self.grok if provider == "grok" else None

    def _existing_final_case(self, memory_synthesis_hash: str) -> dict[str, Any] | None:
        for manifest in self.ledger.list_cases(500):
            case_id = str(manifest.get("case_id", ""))
            try:
                case = self.ledger.read_case(case_id, include_events=False)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            contract = (
                case.get("evidence", {})
                .get("decision_material", {})
                .get("review_profile", {})
                .get("final_case_contract", {})
            )
            if contract.get("memory_synthesis_hash") != memory_synthesis_hash:
                continue
            verification = self.ledger.verify(case_id)
            if not verification.get("valid"):
                raise BackendError("existing_final_case_ledger_invalid")
            return {
                "case_id": case_id,
                "final": case.get("final", {}),
                "verification": verification,
                "contract": contract,
            }
        return None

    def run_final_case(
        self,
        task: str,
        expected_memory_synthesis_hash: str,
        cross_lab_provider: str = "gemini",
        review_manifest_path: str = "",
    ) -> dict[str, Any]:
        """Run at most one fully metered, cross-lab final review per ITHZ checkpoint."""

        if len(expected_memory_synthesis_hash) != 64 or any(
            char not in "0123456789abcdef" for char in expected_memory_synthesis_hash
        ):
            raise ValueError("expected_memory_synthesis_hash_must_be_sha256")
        existing = self._existing_final_case(expected_memory_synthesis_hash)
        if existing is not None:
            return {
                **existing["final"],
                "capability_token": None,
                "existing_final_case_reused": True,
                "source_case_id": existing["case_id"],
                "model_runs": 0,
                "provider_usage": {
                    "model_calls": 0,
                    "metered_model_calls": 0,
                    "complete": True,
                    "missing_roles": [],
                    "providers": {},
                    "reused_from_case": existing["case_id"],
                },
                "ledger_verification": existing["verification"],
                "final_case_contract": existing["contract"],
            }

        projection = native_archive_current_projection(self.project, task[:1200], 4)
        current_hash = str(projection.get("memory_synthesis_hash", ""))
        if current_hash != expected_memory_synthesis_hash:
            raise BackendError("final_case_checkpoint_hash_mismatch")
        if "analysis.read" not in self.constitution.get("allowed_capabilities", []):
            raise BackendError("final_case_analysis_read_not_allowed")
        if cross_lab_provider not in {"gemini", "grok"}:
            raise ValueError("final_case_cross_lab_provider_must_be_gemini_or_grok")
        cross_backend = self._backend_for_cross_provider(cross_lab_provider)
        if cross_backend is None:
            raise BackendError(f"final_case_{cross_lab_provider}_not_configured")
        if getattr(cross_backend, "provider", "") == getattr(self.codex, "provider", ""):
            raise BackendError("final_case_cross_lab_provider_not_independent")
        if not review_manifest_path:
            raise BackendError("final_review_manifest_required")
        review_manifest = _load_final_review_manifest(
            self.project,
            review_manifest_path,
            expected_memory_synthesis_hash,
        )
        if not review_manifest.get("command_outputs_runtime_verified"):
            raise BackendError("final_review_manifest_v2_required")

        contract = {
            "schema": "ccg_final_case_contract_v2",
            "memory_synthesis_hash": expected_memory_synthesis_hash,
            "capability": "analysis.read",
            "risk": "high",
            "cross_lab_provider": cross_lab_provider,
            "reuse_decision": "auto",
            "single_full_case_per_checkpoint": True,
            "provider_usage_required": True,
            "review_evidence_manifest": review_manifest,
            "evidence_diversity_required": True,
            "raw_first_cross_lab_required": True,
            "command_outputs_runtime_verified": True,
            "postflight_receipt_enforced_by_runtime": True,
        }
        result = self.run_case(
            task,
            "high",
            "analysis.read",
            "auto",
            "auto",
            "auto",
            cross_lab_provider,
            final_case_contract=contract,
        )
        return {**result, "existing_final_case_reused": False, "final_case_contract": contract}

    def canary_status(self) -> dict[str, Any]:
        return canary_status(self.project)

    def enable_canary(self, max_cases: int = 5, expires_hours: int = 24) -> dict[str, Any]:
        return enable_canary(self.project, max_cases=max_cases, expires_hours=expires_hours)

    def pause_canary(self) -> dict[str, Any]:
        return pause_canary(self.project)

    def run_canary_case(
        self,
        task: str,
        risk: str = "high",
        cross_lab_provider: str = "gemini",
    ) -> dict[str, Any]:
        """Run one fresh, metered, read-only MCP36.4 shadow case after explicit opt-in."""

        try:
            admission = canary_admission(
                self.project,
                risk=risk,
                capability="analysis.read",
                cross_lab_provider=cross_lab_provider,
            )
        except CanaryGateError as exc:
            raise BackendError(str(exc)) from exc
        cross_backend = self._backend_for_cross_provider(cross_lab_provider)
        if cross_backend is None:
            raise BackendError(f"canary_{cross_lab_provider}_not_configured")
        if getattr(cross_backend, "provider", "") == getattr(self.codex, "provider", ""):
            raise BackendError("canary_cross_lab_provider_not_independent")
        try:
            reservation = reserve_canary_slot(self.project, admission)
        except CanaryGateError as exc:
            raise BackendError(str(exc)) from exc
        contract = {
            "schema": "mcp36_canary_case_contract_v1",
            "version": CANARY_VERSION,
            "rollout_id": admission["rollout_id"],
            "config_hash": admission["config_hash"],
            "rollout_hash": admission["rollout_hash"],
            "reservation_hash": reservation["reservation_hash"],
            "slot": reservation["slot"],
            "mode": "shadow-read-only",
            "capability": "analysis.read",
            "risk": risk,
            "cross_lab_provider": cross_lab_provider,
            "cross_lab_required": True,
            "provider_usage_required": True,
            "fresh_case_required": True,
            "reuse_decision": "off",
            "capability_tokens_forbidden": True,
            "ithz_mirror": False,
            "external_writes": False,
        }
        result = self.run_case(
            task,
            risk,
            "analysis.read",
            "auto",
            "off",
            "off",
            cross_lab_provider,
            canary_contract=contract,
        )
        try:
            receipt = record_canary_receipt(self.project, reservation, result)
        except CanaryGateError as exc:
            raise BackendError(str(exc)) from exc
        return {
            **result,
            "canary_contract": contract,
            "canary_receipt": receipt,
            "canary_status": canary_status(self.project),
        }

    def _reuse_acceptable(
        self,
        candidate: dict[str, Any],
        risk: str,
        selected_cross: str,
        daybreak_selected: bool,
    ) -> bool:
        final = candidate["final"]
        manifest = final.get("role_manifest", {})
        if final.get("model_runs") not in {None, 5}:
            return False
        if risk in {"high", "critical"} and not final.get("cross_lab_quorum"):
            return False
        expected_provider = {"gemini": "google", "grok": "xai"}.get(selected_cross)
        selected_backend = self._backend_for_cross_provider(selected_cross)
        opponent_2 = manifest.get("opponent_2", {}) if isinstance(manifest, dict) else {}
        if expected_provider and selected_backend is not None and opponent_2.get("provider") != expected_provider:
            return False
        opponent_1 = manifest.get("opponent_1", {}) if isinstance(manifest, dict) else {}
        if daybreak_selected and self.daybreak is not None and opponent_1.get("model") != self.daybreak.model:
            return False
        return True

    def _reuse_case(self, evidence: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
        source_final = candidate["final"]
        role_plan = {
            "mode": "verified_decision_reuse",
            "source_case_id": candidate["case_id"],
            "model_runs": 0,
            "authorization_reuse_forbidden": True,
        }
        case_id = self.ledger.create_case(evidence, self.constitution, role_plan)
        self.ledger.append(
            case_id,
            "decision_reuse_validated",
            {
                "source_case_id": candidate["case_id"],
                "source_final_hash": stable_json_hash(source_final),
                "source_ledger_head_hash": candidate["verification"]["head_hash"],
                "decision_material_hash": evidence["decision_material_hash"],
                "authorization_reused": False,
            },
        )
        final = {
            "schema": "ccg_case_result_v2",
            "case_id": case_id,
            "evidence_hash": evidence["evidence_hash"],
            "decision_material_hash": evidence["decision_material_hash"],
            "constitution_hash": evidence["constitution_hash"],
            "semantic_verdict": source_final["semantic_verdict"],
            "final_verdict": source_final["final_verdict"],
            "formal_reasons": list(source_final.get("formal_reasons", [])) + ["verified_decision_reuse"],
            "cross_lab_quorum": bool(source_final.get("cross_lab_quorum")),
            "fallback_used": bool(source_final.get("fallback_used")),
            "role_manifest": {
                "reused_from_case": candidate["case_id"],
                "source_role_manifest_hash": stable_json_hash(source_final.get("role_manifest", {})),
                "model_runs": 0,
            },
            "approved_action": None,
            "authorization": None,
            "advisory_only": True,
            "judge_blind_to_provider": True,
            "reused_decision": True,
            "source_case_id": candidate["case_id"],
            "source_final_hash": stable_json_hash(source_final),
            "source_ledger_head_hash": candidate["verification"]["head_hash"],
            "model_runs": 0,
            "provider_usage": {
                "model_calls": 0,
                "metered_model_calls": 0,
                "complete": True,
                "missing_roles": [],
                "providers": {},
                "reused_from_case": candidate["case_id"],
            },
            "audit_checkpoints_preserved": ["case_opened", "decision_reuse_validated", "case_finalized"],
        }
        self.ledger.finalize(case_id, final)
        mirror = self._mirror_summary_to_ithz(case_id, final["final_verdict"], evidence["evidence_hash"])
        self.ledger.append(case_id, "ithz_mirror_status", mirror)
        verification = self.ledger.verify(case_id)
        return {
            **final,
            "capability_token": None,
            "ithz_mirror": mirror,
            "ledger_verification": verification,
        }

    def run_case(
        self,
        task: str,
        risk: str,
        capability: str,
        use_grok: str = "auto",
        use_daybreak: str = "auto",
        reuse_decision: str = "auto",
        opponent_2: str = "auto",
        final_case_contract: dict[str, Any] | None = None,
        canary_contract: dict[str, Any] | None = None,
        blind_first_pass: bool = False,
    ) -> dict[str, Any]:
        if reuse_decision not in {"auto", "off"}:
            raise ValueError("reuse_decision_must_be_auto_or_off")
        if canary_contract is not None:
            if final_case_contract is not None:
                raise ValueError("final_case_and_canary_contracts_are_mutually_exclusive")
            if (
                canary_contract.get("schema") != "mcp36_canary_case_contract_v1"
                or canary_contract.get("mode") != "shadow-read-only"
                or canary_contract.get("capability") != "analysis.read"
                or canary_contract.get("ithz_mirror") is not False
                or canary_contract.get("capability_tokens_forbidden") is not True
            ):
                raise ValueError("canary_contract_invalid")
            if capability != "analysis.read" or reuse_decision != "off":
                raise ValueError("canary_runtime_scope_invalid")
            if blind_first_pass:
                raise ValueError("canary_blind_first_pass_not_enabled")
        selected_cross, cross_required = self._opponent_2_selection(use_grok, opponent_2)
        if canary_contract is not None:
            cross_backend = self._backend_for_cross_provider(selected_cross)
            if selected_cross not in {"gemini", "grok"} or not cross_required or cross_backend is None:
                raise BackendError("canary_runtime_cross_lab_required")
            if getattr(cross_backend, "provider", "") == getattr(self.codex, "provider", ""):
                raise BackendError("canary_cross_lab_provider_not_independent")
        daybreak_selected, daybreak_required = self._daybreak_selected(risk, use_daybreak)
        review_profile = {
            "opponent_2_selection": selected_cross,
            "opponent_2_required": cross_required,
            "daybreak_selected": daybreak_selected,
            "daybreak_required": daybreak_required,
            "reuse_contract": "verified_material_only_no_authorization_copy",
            "deliberation_mode": "blind_first_then_critique" if blind_first_pass else "proposal_then_critique_economical",
        }
        if final_case_contract is not None:
            review_profile["final_case_contract"] = final_case_contract
        if canary_contract is not None:
            review_profile["canary_contract"] = canary_contract
        evidence = self._evidence(
            task,
            risk,
            capability,
            review_profile,
        )
        if reuse_decision == "auto":
            candidate = self.ledger.find_reusable_case(evidence["decision_material_hash"])
            if candidate and self._reuse_acceptable(candidate, risk, selected_cross, daybreak_selected):
                return self._reuse_case(evidence, candidate)

        if daybreak_required and self.daybreak is None:
            raise BackendError("daybreak_required_but_model_unavailable")
        intended_cross = selected_cross != "off" and self._backend_for_cross_provider(selected_cross) is not None
        role_plan = {
            "mode": "fresh_isolated_deliberation",
            "proposer": "codex_new_thread",
            "opponent_1": "daybreak_when_selected_else_codex_new_thread",
            "opponent_2": f"{selected_cross}_cross_lab_with_recorded_fallback",
            "independent_first_pass": "sealed_before_proposal" if blind_first_pass else "not_requested",
            "judge": "codex_blind_new_thread",
            "auditor": "codex_process_new_thread",
            "cross_lab_intended": intended_cross,
            "template_set_hash": self.template_set_hash,
            "stable_prefix_cache": True,
            "evidence_views": "proposer_verified_primary_counter_cross_raw_first_judge_matrix_auditor_receipts",
            "evidence_view_set_hash": evidence["evidence_views"]["view_set_hash"],
        }
        case_id = self.ledger.create_case(evidence, self.constitution, role_plan)
        self.ledger.append(case_id, "deliberation_started", {"risk": risk, "capability": capability})

        blind_first: RoleResult | None = None
        if blind_first_pass:
            blind_backend = self._backend_for_cross_provider(selected_cross)
            if selected_cross not in {"gemini", "grok"} or blind_backend is None:
                raise BackendError("blind_first_cross_lab_required")
            blind_first = self._run_role(blind_backend, "opponent_blind_first", evidence, {}, OPPONENT_SCHEMA, case_id)
            self.ledger.append(case_id, "blind_first_pass_sealed", {"thread_id": blind_first.thread_id, "evidence_hash": evidence["evidence_hash"]})
        proposal = self._run_role(self.codex, "proposer", evidence, {}, PROPOSER_SCHEMA, case_id)
        cross_fallbacks: list[str] = []
        daybreak_fallback_reason = ""

        def primary_job() -> RoleResult:
            nonlocal daybreak_fallback_reason
            if daybreak_selected and self.daybreak is not None:
                try:
                    return self._run_role(
                        self.daybreak,
                        "opponent_primary",
                        evidence,
                        {"proposal": proposal.data},
                        OPPONENT_SCHEMA,
                        case_id,
                    )
                except BackendError as exc:
                    if daybreak_required:
                        raise
                    daybreak_fallback_reason = f"daybreak_failed:{type(exc).__name__}"
            elif daybreak_selected:
                daybreak_fallback_reason = "daybreak_not_available"
            return self._run_role(
                self.codex,
                "opponent_primary",
                evidence,
                {"proposal": proposal.data},
                OPPONENT_SCHEMA,
                case_id,
            )

        def second_job() -> RoleResult:
            if selected_cross == "off":
                cross_fallbacks.append("cross_lab_disabled")
                candidates: list[str] = []
            elif cross_required:
                candidates = [selected_cross]
            else:
                alternate = "grok" if selected_cross == "gemini" else "gemini"
                candidates = [selected_cross, alternate]
            last_error: BackendError | None = None
            for provider in candidates:
                backend = self._backend_for_cross_provider(provider)
                if backend is None:
                    cross_fallbacks.append(f"{provider}_not_configured")
                    continue
                try:
                    return self._run_role(
                        backend,
                        "opponent_cross",
                        evidence,
                        {"proposal": proposal.data},
                        OPPONENT_SCHEMA,
                        case_id,
                    )
                except BackendError as exc:
                    last_error = exc
                    cross_fallbacks.append(f"{provider}_failed:{type(exc).__name__}")
                    if cross_required:
                        raise
            if cross_required:
                if last_error:
                    raise last_error
                raise BackendError(f"{selected_cross}_required_but_api_key_missing")
            return self._run_role(
                self.codex,
                "opponent_fallback",
                evidence,
                {"proposal": proposal.data},
                OPPONENT_SCHEMA,
                case_id,
            )

        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="ccg-opponent") as executor:
            primary_future = executor.submit(primary_job)
            second_future = executor.submit(second_job)
            opponent_1 = primary_future.result()
            opponent_2_result = second_future.result()

        cross_lab_quorum = opponent_2_result.provider != opponent_1.provider
        cross_fallback_reason = ";".join(cross_fallbacks)
        role_manifest = {
            "proposer": {"provider": proposal.provider, "model": proposal.model, "thread_id": proposal.thread_id},
            "opponent_1": {"provider": opponent_1.provider, "model": opponent_1.model, "thread_id": opponent_1.thread_id},
            "opponent_2": {
                "provider": opponent_2_result.provider,
                "model": opponent_2_result.model,
                "thread_id": opponent_2_result.thread_id,
            },
            "cross_lab_quorum": cross_lab_quorum,
            "fallback_reason": cross_fallback_reason,
            "daybreak_fallback_reason": daybreak_fallback_reason,
        }
        if blind_first is not None:
            role_manifest["opponent_blind_first"] = {"provider": blind_first.provider, "model": blind_first.model, "thread_id": blind_first.thread_id}
        self.ledger.append(case_id, "role_manifest_sealed", role_manifest)

        judge_payload = {"proposal": proposal.data, "opponent_1": opponent_1.data, "opponent_2": opponent_2_result.data}
        if blind_first is not None:
            judge_payload["opponent_blind_first"] = blind_first.data
        judge = self._run_role(
            self.codex,
            "judge",
            evidence,
            judge_payload,
            JUDGE_SCHEMA,
            case_id,
        )
        role_manifest["judge"] = {"provider": judge.provider, "model": judge.model, "thread_id": judge.thread_id}
        upstream_thread_ids = [
            str(role_manifest[name]["thread_id"])
            for name in ("proposer", "opponent_1", "opponent_2", "judge")
        ]
        if blind_first is not None:
            upstream_thread_ids.append(str(role_manifest["opponent_blind_first"]["thread_id"]))
        procedure_evidence = {
            "schema": "ccg_formal_procedure_evidence_v2",
            "case_id": case_id,
            "expected_role_count": 6 if blind_first is not None else 5,
            "completed_upstream_role_count": 5 if blind_first is not None else 4,
            "current_role": "auditor",
            "upstream_thread_ids_distinct": len(set(upstream_thread_ids)) == len(upstream_thread_ids),
            "all_upstream_evidence_hashes_match": all(
                result.data.get("evidence_hash") == evidence["evidence_hash"]
                for result in ([proposal, opponent_1, opponent_2_result] + ([blind_first] if blind_first is not None else []) + [judge])
            ),
            "judge_packet_provider_identity_withheld": True,
            "opponents_completed_before_judge": True,
            "judge_completed_before_auditor": True,
            "role_plan_hash": stable_json_hash(role_plan),
            "role_evidence_view_hashes": evidence["evidence_views"]["view_hashes"],
            "evidence_view_set_hash": evidence["evidence_views"]["view_set_hash"],
            "evidence_view_diversity_valid": evidence["evidence_views"]["diversity_receipt"]["valid"],
            "cross_lab_raw_first": evidence["evidence_views"]["diversity_receipt"]["cross_lab_raw_first"],
            "shared_projection_withheld_from_cross_lab": evidence["evidence_views"]["diversity_receipt"][
                "shared_projection_withheld_from_cross_lab"
            ],
        }
        auditor = self._run_role(
            self.codex,
            "auditor",
            evidence,
            {
                "role_manifest": role_manifest,
                "procedure_evidence": procedure_evidence,
                "proposal": proposal.data,
                "opponents": [opponent_1.data, opponent_2_result.data] + ([blind_first.data] if blind_first is not None else []),
                "judge": judge.data,
            },
            AUDITOR_SCHEMA,
            case_id,
        )
        role_manifest["auditor"] = {"provider": auditor.provider, "model": auditor.model, "thread_id": auditor.thread_id}
        self.ledger.append(
            case_id,
            "role_manifest_completed",
            {"role_count": 6 if blind_first is not None else 5, "role_manifest_hash": stable_json_hash(role_manifest)},
        )

        all_opponents = [opponent_1, opponent_2_result] + ([blind_first] if blind_first is not None else [])
        verdict, formal_reasons, approved_action = self._formal_verdict(
            evidence,
            proposal,
            all_opponents,
            judge,
            auditor,
            cross_lab_quorum,
        )
        authorization_for_return: dict[str, Any] | None = None
        authorization_for_ledger: dict[str, Any] | None = None
        if (
            verdict in {"ALLOW", "ALLOW_WITH_LIMITS"}
            and approved_action is not None
            and capability != "analysis.read"
        ):
            authorization_for_return = self.broker.issue(
                case_id,
                evidence["evidence_hash"],
                approved_action,
                int(self.constitution["authorization"]["default_ttl_seconds"]),
            )
            authorization_for_ledger = {
                "token_hash": authorization_for_return["token_hash"],
                "claims": authorization_for_return["claims"],
            }

        provider_usage = _provider_usage([proposal, *all_opponents, judge, auditor])
        if (final_case_contract is not None or canary_contract is not None) and not provider_usage["complete"]:
            verdict = "REQUEST_EVIDENCE"
            approved_action = None
            formal_reasons = [*formal_reasons, "provider_usage_incomplete"]
        final = {
            "schema": "ccg_case_result_v2",
            "case_id": case_id,
            "evidence_hash": evidence["evidence_hash"],
            "decision_material_hash": evidence["decision_material_hash"],
            "constitution_hash": evidence["constitution_hash"],
            "semantic_verdict": judge.data["verdict"],
            "final_verdict": verdict,
            "formal_reasons": formal_reasons,
            "cross_lab_quorum": cross_lab_quorum,
            "fallback_used": bool(cross_fallback_reason or daybreak_fallback_reason),
            "role_manifest": role_manifest,
            "approved_action": approved_action,
            "authorization": authorization_for_ledger,
            "advisory_only": capability == "analysis.read" or authorization_for_ledger is None,
            "judge_blind_to_provider": True,
            "reused_decision": False,
            "model_runs": 6 if blind_first is not None else 5,
            "independent_first_pass": blind_first is not None,
            "provider_usage": provider_usage,
            "final_case_contract": final_case_contract,
            "canary_contract": canary_contract,
            "evidence_diversity_receipt": evidence["evidence_views"]["diversity_receipt"],
            "template_set_hash": self.template_set_hash,
        }
        self.ledger.finalize(case_id, final)
        mirror = (
            {"mirrored": False, "reason": "mcp36_canary_read_only"}
            if canary_contract is not None
            else self._mirror_summary_to_ithz(case_id, verdict, evidence["evidence_hash"])
        )
        self.ledger.append(case_id, "ithz_mirror_status", mirror)
        verification = self.ledger.verify(case_id)
        return {
            **final,
            "capability_token": authorization_for_return["token"] if authorization_for_return else None,
            "ithz_mirror": mirror,
            "ledger_verification": verification,
        }

    def execute_demo(self, case_id: str, token: str) -> dict[str, Any]:
        case = self.ledger.read_case(case_id, include_events=False)
        final = case.get("final") or {}
        action = final.get("approved_action")
        if not isinstance(action, dict):
            raise ValueError("case_has_no_approved_action")
        parameters = action.get("parameters")
        if not isinstance(parameters, dict):
            parameters = _decode_parameters(action)
        relative_path = str(parameters.get("relative_path", ""))
        content = str(parameters.get("content", ""))
        return self.broker.execute_demo_write(case_id, token, relative_path, content)

    def integrity_status(self, query: str = "current memory integrity and review gates") -> dict[str, Any]:
        return memory_integrity_status(self._focus_context(query[:1200]))

    @staticmethod
    def integrity_selftest() -> dict[str, Any]:
        return run_memory_integrity_benchmark()

    def status(self) -> dict[str, Any]:
        cases = self.ledger.list_cases(10000)
        historical_results: list[RoleResult] = []
        reused_cases = 0
        roles_without_usage = 0
        latest_final_case: dict[str, Any] | None = None
        for manifest in cases:
            case_id = str(manifest.get("case_id", ""))
            directory = self.ledger.case_dir(case_id)
            final_path = directory / "final.json"
            if final_path.exists():
                try:
                    final = json.loads(final_path.read_text(encoding="utf-8"))
                    reused_cases += int(bool(final.get("reused_decision")))
                    contract = final.get("final_case_contract")
                    if latest_final_case is None and isinstance(contract, dict):
                        final_usage = final.get("provider_usage")
                        latest_final_case = {
                            "case_id": case_id,
                            "memory_synthesis_hash": contract.get("memory_synthesis_hash"),
                            "capability": contract.get("capability"),
                            "cross_lab_provider": contract.get("cross_lab_provider"),
                            "cross_lab_quorum": bool(final.get("cross_lab_quorum")),
                            "model_runs": int(final.get("model_runs", 0)),
                            "provider_usage": final_usage if isinstance(final_usage, dict) else {},
                        }
                except (OSError, json.JSONDecodeError):
                    pass
            roles_dir = directory / "roles"
            if not roles_dir.exists():
                continue
            for path in roles_dir.glob("*.json"):
                try:
                    role = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                historical_results.append(
                    RoleResult(
                        role=str(role.get("role", "unknown")),
                        provider=str(role.get("provider", "unknown")),
                        model=str(role.get("model", "unknown")),
                        thread_id="",
                        data={},
                        duration_ms=int(role.get("duration_ms", 0)),
                        template_hash=str(role.get("template_hash", "")),
                        usage=role.get("usage", {}) if isinstance(role.get("usage"), dict) else {},
                        usage_source=str(role.get("usage_source", "")),
                    )
                )
                roles_without_usage += int(
                    not isinstance(role.get("usage"), dict)
                    or int(role.get("usage", {}).get("total_tokens", 0)) <= 0
                    or not role.get("usage_source")
                )
        usage = _provider_usage(historical_results)
        historical_missing_roles = usage.pop("missing_roles")
        missing_role_counts: dict[str, int] = {}
        for role in historical_missing_roles:
            missing_role_counts[role] = missing_role_counts.get(role, 0) + 1
        usage.update(
            {
                "scope": "historical_all_cases",
                "missing_role_count": len(historical_missing_roles),
                "missing_role_counts": dict(sorted(missing_role_counts.items())),
            }
        )
        applied_layers = self.constitution.get("applied_layers", [])
        active_task = next(
            (item.get("id") for item in reversed(applied_layers) if isinstance(item, dict) and item.get("layer") == "task"),
            None,
        )
        active_topic = next(
            (item.get("id") for item in reversed(applied_layers) if isinstance(item, dict) and item.get("layer") == "topic"),
            None,
        )
        try:
            integrity = self.integrity_status()
        except Exception as exc:
            integrity = {
                "schema": "ithz_memory_integrity_status_v1",
                "version": "mcp36-memory-integrity-v1",
                "available": False,
                "evidence_gap": type(exc).__name__,
            }
        return {
            "schema": "ccg_ithz_status_v2",
            "ccg_version": CCG_VERSION,
            "project": str(self.project),
            "constitution_hash": self.constitution["constitution_hash"],
            "codex_backend": {"provider": self.codex.provider, "model": self.codex.model},
            "daybreak": {
                "configured": self.daybreak is not None,
                "model": self.preferences["daybreak_model"],
                "policy": self.preferences["daybreak_policy"],
                "role": "opponent_primary",
            },
            "gemini_configured": self.gemini is not None,
            "gemini_model": self.preferences["gemini_model"],
            "gemini_secret_source": self.gemini_secret_source,
            "grok_configured": self.grok is not None,
            "grok_model": self.preferences["grok_model"],
            "grok_secret_source": self.grok_secret_source,
            "opponent_2_policy": "gemini_default_then_grok_then_blind_codex_b2",
            "opponent_2_default": self.preferences["opponent_2_provider"],
            "stable_role_prefix_cache": True,
            "template_set_hash": self.template_set_hash,
            "decision_reuse": "verified_material_hash_only_no_authorization_copy",
            "cache_diagnostics": {
                "stable_prefix_enabled": True,
                "template_hash_count": len(self.template_hashes),
                "case_count": len(cases),
                "reused_case_count": reused_cases,
                "cached_input_tokens_observed": sum(
                    int(row.get("cached_input_tokens", 0)) for row in usage["providers"].values()
                ),
            },
            "provider_usage": usage,
            "provider_usage_coverage": {
                "scope": "historical_all_cases",
                "metering_version": "mcp36",
                "roles_with_complete_usage": len(historical_results) - roles_without_usage,
                "roles_without_complete_usage": roles_without_usage,
                "legacy_unmetered_history_present": roles_without_usage > 0,
                "guidance": "Use latest_final_case.provider_usage for the current final review; historical gaps are not current-run counters.",
            },
            "latest_final_case": latest_final_case,
            "mcp36_4_canary": self.canary_status(),
            "final_case_workflow": {
                "tool": "ccg_run_final_case",
                "checkpoint_binding": "expected_memory_synthesis_hash",
                "capability": "analysis.read",
                "risk": "high",
                "cross_lab_required": True,
                "reuse_decision": "auto",
                "single_full_case_per_checkpoint": True,
                "provider_usage_required": True,
                "review_manifest_schema": "ccg_final_review_manifest_v2",
                "command_outputs_runtime_verified": True,
                "evidence_diversity_required": True,
                "raw_first_cross_lab_required": True,
            },
            "memory_integrity": integrity,
            "project_profile": {
                "active_topic": active_topic,
                "active_task": active_task,
                "frontend_visual_gate_required": any(
                    str(gate).startswith("frontend_") for gate in self.constitution.get("required_gates", [])
                ),
                "auto_task_preflight": False,
            },
            "judge_blind_to_provider": True,
            "ithz_native_archive_present": (self.project / "project.ithz").exists(),
            "case_count": len(cases),
        }
