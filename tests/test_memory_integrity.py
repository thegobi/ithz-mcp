import tempfile
import unittest
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ithz_mcp.memory_integrity import (
    MEMORY_RECORD_SCHEMA,
    build_evidence_views,
    evaluate_consolidation_candidate,
    run_memory_integrity_benchmark,
    sealed_evidence_for_role,
    validate_memory_record,
    validate_supersession,
    _manifest_raw_evidence,
)
from ithz_mcp.native_archive_store import archive_append_memory_record
from ithz_mcp.mcp_server import RpcError, call_tool, mcp_tool_schemas
from ithz_mcp.ccg.court import _load_final_review_manifest, _role_prompt


class MemoryIntegrityTests(unittest.TestCase):
    def record(self, **updates):
        value = {
            "schema": MEMORY_RECORD_SCHEMA,
            "memory_id": "mem-1",
            "kind": "decision",
            "scope": "mcp36",
            "statement": "Raw evidence remains first class.",
            "applies_when": "Reviewing a completed task.",
            "does_not_apply_when": "No evidence exists.",
            "valid_from": "2026-09-02T00:00:00+00:00",
            "valid_until": "",
            "source_event_ids": ["event-1"],
            "source_artifact_hashes": [],
            "counterexample_ids": [],
            "confidence": 1.0,
            "verification_state": "candidate",
            "policy_class": "verified",
            "created_by": "test",
            "created_at": "2026-09-02T00:00:00+00:00",
            "supersedes": [],
            "supersession_reason": "",
            "human_approval_ids": [],
        }
        value.update(updates)
        return value

    def projection(self):
        return {
            "projection_hash": "1" * 64,
            "memory_synthesis_hash": "2" * 64,
            "sections": {
                "must_not_break": [{"event_id": "hard", "text": "Never bypass the broker."}],
                "current_decisions": [{"event_id": "decision", "text": "Use verified evidence."}],
                "current_gates": [{"event_id": "gate", "text": "Tests passed."}],
                "current_risks": [{"event_id": "risk", "text": "Summaries may be stale."}],
                "current_blocked_claims": [],
                "forbidden_claims": [],
                "current_claims": [],
                "current_next_steps": [],
            },
        }

    def test_verified_records_require_source_binding(self):
        with self.assertRaisesRegex(ValueError, "verified_state_requires_sources"):
            validate_memory_record(
                self.record(verification_state="active", source_event_ids=[], source_artifact_hashes=[])
            )

    def test_hard_policy_cannot_receive_dynamic_utility_weight(self):
        with self.assertRaisesRegex(ValueError, "hard_policy_utility_weight_forbidden"):
            validate_memory_record(self.record(policy_class="hard", utility_weight=0.3))

    def test_consolidation_quarantines_missing_sources(self):
        receipt = evaluate_consolidation_candidate(self.record(), set(), set())
        self.assertFalse(receipt["accepted"])
        self.assertEqual(receipt["next_state"], "quarantined")
        self.assertIn("source_events_missing:event-1", receipt["reasons"])

    def test_supersession_requires_same_scope_kind_and_newer_validity(self):
        old = self.record(
            memory_id="old",
            verification_state="active",
            valid_from="2026-09-01T00:00:00+00:00",
        )
        new = self.record(
            memory_id="new",
            verification_state="active",
            valid_from="2026-09-03T00:00:00+00:00",
            supersedes=["old"],
            supersession_reason="New source-bound evidence.",
        )
        self.assertTrue(validate_supersession(new, old)["valid"])
        self.assertFalse(validate_supersession({**new, "scope": "other"}, old)["valid"])

    def test_role_views_are_distinct_and_cross_lab_is_raw_first(self):
        compiled = build_evidence_views(self.projection())
        self.assertTrue(compiled["diversity_receipt"]["structurally_valid"])
        self.assertFalse(compiled["diversity_receipt"]["valid"])
        self.assertFalse(compiled["diversity_receipt"]["claim_bindings_complete"])
        cross = compiled["views"]["opponent_cross"]
        self.assertEqual(cross["verified_abstractions"], [])
        self.assertTrue(cross["shared_current_projection_withheld"])
        self.assertEqual(len({compiled["view_hashes"][name] for name in ("proposer", "opponent_primary", "opponent_cross")}), 3)

    def test_sealed_role_packet_does_not_leak_shared_projection(self):
        compiled = build_evidence_views(self.projection())
        evidence = {
            "evidence_hash": "a" * 64,
            "constitution": {},
            "ithz_current_projection": self.projection(),
            "ithz_projection_delta": {"added": ["decision"]},
            "evidence_views": compiled,
        }
        cross = sealed_evidence_for_role(evidence, "opponent_cross")
        self.assertNotIn("ithz_current_projection", cross)
        self.assertNotIn("ithz_projection_delta", cross)
        self.assertEqual(cross["role_evidence_view"]["purpose"], "raw_first_memory_disabled_control")

    def test_cross_packet_removes_nested_projection_and_routing_profile(self):
        compiled = build_evidence_views(self.projection())
        evidence = {
            "evidence_hash": "a" * 64,
            "decision_material": {"review_profile": {"ithz_current_projection": self.projection(), "codex_model": "hidden"}},
            "evidence_views": compiled,
        }
        cross = sealed_evidence_for_role(evidence, "opponent_cross")
        self.assertNotIn("decision_material", cross)
        self.assertNotIn("ithz_current_projection", str(cross))

    def test_empty_views_are_structurally_honest_but_not_sufficient(self):
        compiled = build_evidence_views({"sections": {}})
        receipt = compiled["diversity_receipt"]
        self.assertTrue(receipt["structurally_valid"])
        self.assertFalse(receipt["evidence_sufficient"])
        self.assertFalse(receipt["required_policy_coverage"])
        self.assertFalse(receipt["valid"])

    def test_claims_bind_only_their_named_raw_sources_and_content_hash_ignores_order(self):
        projection = self.projection()
        projection["sections"]["current_decisions"] = [{
            "event_id": "decision",
            "text": "Use verified evidence.",
            "source_event_ids": ["gate"],
        }]
        first = build_evidence_views(projection)
        projection["sections"]["current_risks"].reverse()
        second = build_evidence_views(projection)
        row = first["views"]["judge"]["claim_evidence_matrix"][0]
        self.assertEqual(row["raw_evidence_ids"], ["gate"])
        self.assertTrue(row["binding_complete"])
        self.assertEqual(first["evidence_content_hashes"], second["evidence_content_hashes"])

    def test_signed_source_evidence_delivers_exact_content_to_judge(self):
        projection = self.projection()
        payload = '{"event_id":"gate","outcome":"passed"}'
        projection["source_evidence"] = [{
            "id": "event:gate", "kind": "archive_event", "content_text": payload,
            "content_bytes": len(payload.encode("utf-8")),
            "content_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "runtime_verified": True, "verification_basis": "signed_memory_source_binding",
            "claim_ids": ["decision"],
        }]
        projection["sections"]["current_decisions"] = [{"event_id": "decision", "text": "Use verified evidence.", "source_event_ids": ["gate"], "source_bindings": {"event:gate": {"sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest()}}}]
        compiled = build_evidence_views(projection)
        raw = compiled["views"]["judge"]["raw_evidence"][0]
        self.assertTrue(raw["content_verified"])
        self.assertTrue(raw["content_delivered_to_role"])
        self.assertEqual(raw["content_text"], payload)
        self.assertEqual(compiled["views"]["judge"]["claim_evidence_matrix"][0]["raw_evidence_ids"], ["event:gate"])

    def test_changed_or_oversize_signed_payload_fails_closed(self):
        projection = self.projection()
        projection["source_evidence"] = [{
            "id": "event:gate", "kind": "archive_event", "content_text": "changed",
            "content_sha256": "0" * 64, "content_bytes": 7, "runtime_verified": True,
        }, {
            "id": "event:risk", "kind": "archive_event", "content_text": "x" * (16 * 1024 + 1),
            "content_bytes": 16 * 1024 + 1, "content_sha256": hashlib.sha256(("x" * (16 * 1024 + 1)).encode()).hexdigest(), "runtime_verified": True,
        }]
        raw = build_evidence_views(projection)["views"]["proposer"]["raw_evidence"]
        self.assertEqual([row["delivery_failure_reason"] for row in raw], ["content_hash_mismatch", "content_oversize"])
        self.assertFalse(any(row["content_verified"] for row in raw))

    def test_signed_source_requires_declared_byte_count_and_claim_binding(self):
        projection = self.projection()
        payload = "event bytes"
        projection["source_evidence"] = [{
            "id": "event:gate", "kind": "archive_event", "content_text": payload,
            "content_bytes": 1, "content_sha256": hashlib.sha256(payload.encode()).hexdigest(),
            "runtime_verified": True, "claim_ids": ["another-claim"],
        }]
        projection["sections"]["current_decisions"] = [{"event_id": "decision", "text": "Claim", "source_event_ids": ["gate"]}]
        compiled = build_evidence_views(projection)
        raw = compiled["views"]["judge"]["raw_evidence"][0]
        self.assertEqual(raw["delivery_failure_reason"], "content_bytes_mismatch")
        self.assertFalse(compiled["views"]["judge"]["claim_evidence_matrix"][0]["binding_complete"])

    def test_oversize_integrity_checks_hash_before_withholding(self):
        content = "x" * (16 * 1024 + 1)
        good = hashlib.sha256(content.encode()).hexdigest()
        projection = {"source_evidence": [{"id": "event:oversize", "kind": "archive_event", "content_text": content, "content_bytes": len(content.encode()), "content_sha256": good, "runtime_verified": True}]}
        row = build_evidence_views(projection)["views"]["proposer"]["raw_evidence"][0]
        self.assertEqual(row["delivery_failure_reason"], "content_oversize")
        self.assertTrue(row["source_integrity_verified"])
        projection["source_evidence"][0]["content_sha256"] = "0" * 64
        row = build_evidence_views(projection)["views"]["proposer"]["raw_evidence"][0]
        self.assertEqual(row["delivery_failure_reason"], "content_hash_mismatch")
        self.assertFalse(row["source_integrity_verified"])

    def test_oversize_manifest_artifact_hash_is_checked_before_withholding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); artifact = root / "big.txt"; artifact.write_text("z" * (16 * 1024 + 1), encoding="utf-8")
            good = hashlib.sha256(artifact.read_bytes()).hexdigest()
            manifest = {"command_outputs_runtime_verified": True, "_content_root": str(root), "artifacts": [{"path": "big.txt", "sha256": good}], "command_receipts": []}
            row = _manifest_raw_evidence(manifest)[0]
            self.assertEqual(row["delivery_failure_reason"], "content_oversize")
            self.assertTrue(row["artifact_integrity_verified"])
            manifest["artifacts"][0]["sha256"] = "0" * 64
            row = _manifest_raw_evidence(manifest)[0]
            self.assertEqual(row["delivery_failure_reason"], "content_hash_mismatch")
            self.assertFalse(row["artifact_integrity_verified"])

    def test_same_payload_with_distinct_evidence_ids_keeps_both_bindings(self):
        payload = "same payload"; digest = hashlib.sha256(payload.encode()).hexdigest()
        projection = self.projection()
        projection["source_evidence"] = [
            {"id": "event:one", "kind": "archive_event", "content_text": payload, "content_bytes": len(payload), "content_sha256": digest, "runtime_verified": True, "claim_ids": ["decision"]},
            {"id": "event:two", "kind": "archive_event", "content_text": payload, "content_bytes": len(payload), "content_sha256": digest, "runtime_verified": True, "claim_ids": ["decision"]},
        ]
        projection["sections"]["current_decisions"] = [{"event_id": "decision", "text": "Claim", "source_event_ids": ["one", "two"], "source_bindings": [{"id": "event:one", "sha256": digest}, {"id": "event:two", "sha256": digest}]}]
        matrix = build_evidence_views(projection)["views"]["judge"]["claim_evidence_matrix"][0]
        self.assertEqual(matrix["raw_evidence_ids"], ["event:one", "event:two"])
        self.assertTrue(matrix["binding_complete"])

    def test_runtime_validated_manifest_rereads_artifact_before_role_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "receipt.txt"; artifact.write_text("bounded test receipt", encoding="utf-8")
            output = root / "output.txt"; output.write_text("bounded command output", encoding="utf-8")
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            manifest = {
                "schema": "ccg_final_review_manifest_v2", "memory_synthesis_hash": "a" * 64,
                "artifacts": [{"path": "receipt.txt", "sha256": digest(artifact)}],
                "command_receipts": [{"command": "test", "exit_code": 0, "output_sha256": digest(output), "result_summary": "passed", "output_artifact_path": "output.txt", "started_at": "now", "finished_at": "now", "working_directory": str(root), "tool_version": "1", "environment_fingerprint": "b" * 64}],
            }
            manifest_path = root / "manifest.json"; manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            validated = _load_final_review_manifest(root, "manifest.json", "a" * 64)
            compiled = build_evidence_views(self.projection(), validated)
            evidence = {"evidence_hash": "e" * 64, "evidence_views": compiled, "decision_material": {}, "final_review_manifest": validated}
            judge_prompt, _ = _role_prompt("judge", evidence, {"proposal": {}, "opponent_1": {}, "opponent_2": {}}, {}, {})
            primary_prompt, _ = _role_prompt("opponent_primary", evidence, {"proposal": {}}, {}, {})
            cross_prompt, _ = _role_prompt("opponent_cross", evidence, {"proposal": {}}, {}, {})
            for prompt in (judge_prompt, primary_prompt, cross_prompt):
                self.assertIn("bounded test receipt", prompt)
                self.assertIn("bounded command output", prompt)
                self.assertNotIn("_content_root", prompt)
            artifact.write_text("changed after validation", encoding="utf-8")
            changed = build_evidence_views(self.projection(), validated)
            self.assertFalse(changed["views"]["judge"]["raw_evidence"][0]["content_verified"])

    def test_benchmark_covers_all_memory_modes(self):
        result = run_memory_integrity_benchmark()
        self.assertTrue(result["passed"])
        modes = {row["mode"] for row in result["rows"]}
        self.assertEqual(
            modes,
            {"no_memory", "episodic_only", "mcp35_projection", "mcp36_hybrid", "mcp36_poisoned"},
        )

    def test_append_memory_record_does_not_activate_merely_bound_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "project.ithz"
            archive.write_bytes(b"fixture")
            appended = {
                "events": [{"event_id": "evt_000002"}],
                "active_memory_zone": str(root),
                "memory_synthesis_hash": "f" * 64,
                "update": {"updated": True},
            }
            with patch(
                "ithz_mcp.native_archive_store.resolve_memory_zone",
                return_value=SimpleNamespace(active_root=root),
            ), patch(
                "ithz_mcp.native_archive_store.project_archive_path",
                return_value=archive,
            ), patch(
                "ithz_mcp.native_archive_store.locate_native_ithz",
                return_value=root / "ithz-native.exe",
            ), patch(
                "ithz_mcp.native_archive_store._memory_events",
                return_value=[{"event_id": "event-1", "metadata": {}}],
            ), patch(
                "ithz_mcp.native_archive_store.archive_append_events",
                return_value=appended,
            ) as write:
                receipt = archive_append_memory_record(root, self.record())
            self.assertFalse(receipt["accepted"])
            event_spec = write.call_args.args[1][0]
            self.assertEqual(write.call_args.args[3], "current")
            self.assertEqual(event_spec["kind"], "memory_candidate_quarantined")
            self.assertEqual(event_spec["metadata"]["memory_record"]["verification_state"], "quarantined")

    def test_append_memory_record_quarantines_invalid_supersession_without_deactivating_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "project.ithz"
            archive.write_bytes(b"fixture")
            appended = {
                "events": [{"event_id": "evt_000003"}],
                "active_memory_zone": str(root),
                "memory_synthesis_hash": "f" * 64,
                "update": {"updated": True},
            }
            candidate = self.record(
                supersedes=["legacy-event"],
                supersession_reason="Attempted replacement.",
            )
            with patch(
                "ithz_mcp.native_archive_store.resolve_memory_zone",
                return_value=SimpleNamespace(active_root=root),
            ), patch(
                "ithz_mcp.native_archive_store.project_archive_path",
                return_value=archive,
            ), patch(
                "ithz_mcp.native_archive_store.locate_native_ithz",
                return_value=root / "ithz-native.exe",
            ), patch(
                "ithz_mcp.native_archive_store._memory_events",
                return_value=[{"event_id": "event-1"}, {"event_id": "legacy-event"}],
            ), patch(
                "ithz_mcp.native_archive_store.archive_append_events",
                return_value=appended,
            ) as write:
                receipt = archive_append_memory_record(root, candidate)
            self.assertFalse(receipt["accepted"])
            event_spec = write.call_args.args[1][0]
            self.assertEqual(event_spec["kind"], "memory_candidate_quarantined")
            self.assertNotIn("supersedes", event_spec)

    def test_main_mcp_exposes_read_status_and_gates_typed_write_by_profile(self):
        read_names = {row["name"] for row in mcp_tool_schemas("native-archive", "read-only")}
        write_names = {row["name"] for row in mcp_tool_schemas("native-archive", "write-enabled")}
        self.assertIn("ithz_memory_integrity_status", read_names)
        self.assertNotIn("ithz_archive_append_memory_record", read_names)
        self.assertIn("ithz_archive_append_memory_record", write_names)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RpcError, "unknown_method|write_back_disabled"):
                call_tool(
                    "ithz_archive_append_memory_record",
                    {"record": self.record()},
                    Path(directory),
                    "native-archive",
                    "read-only",
                )


if __name__ == "__main__":
    unittest.main()
