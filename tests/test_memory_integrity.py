import tempfile
import unittest
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
)
from ithz_mcp.native_archive_store import archive_append_memory_record
from ithz_mcp.mcp_server import RpcError, call_tool, mcp_tool_schemas


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
