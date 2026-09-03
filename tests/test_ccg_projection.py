import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ithz_mcp.native_archive_store import _active_events, native_archive_current_projection


class CCGCurrentProjectionTests(unittest.TestCase):
    def test_supersedes_accepts_multiple_event_ids(self):
        events = [
            {"event_id": "old-a", "sequence": 1},
            {"event_id": "old-b", "sequence": 2},
            {"event_id": "new", "sequence": 3, "supersedes": ["old-a", "old-b"]},
        ]
        active, superseded = _active_events(events)
        self.assertEqual(superseded, {"old-a", "old-b"})
        self.assertEqual([event["event_id"] for event in active], ["new"])

    def test_typed_memory_cannot_be_superseded_without_valid_receipt(self):
        typed = {
            "event_id": "typed",
            "sequence": 1,
            "metadata": {"memory_record": {"schema": "ithz_memory_record_v2"}},
        }
        invalid = {"event_id": "invalid", "sequence": 2, "supersedes": ["typed"]}
        active, superseded = _active_events([typed, invalid])
        self.assertEqual(superseded, set())
        self.assertEqual({event["event_id"] for event in active}, {"typed", "invalid"})

        valid = {
            "event_id": "valid",
            "sequence": 3,
            "supersedes": ["typed"],
            "metadata": {
                "supersession_receipts": [
                    {"target_id": "typed", "valid": True},
                ]
            },
        }
        active, superseded = _active_events([typed, valid])
        self.assertEqual(superseded, {"typed"})
        self.assertEqual([event["event_id"] for event in active], ["valid"])

    def test_projection_is_compact_current_only_and_carries_safety_boundaries(self):
        synthesis = {
            "schema": "ithz_mcp_memory_synthesis_v1",
            "memory_synthesis_hash": "1" * 64,
            "current_decisions": [
                {"event_id": "d1", "kind": "decision", "text": "Gemini opponent is the current decision."},
                {"event_id": "d2", "kind": "decision", "text": "Unrelated historical topic."},
            ],
            "current_claims": [],
            "current_blocked_claims": [],
            "current_gates": [],
            "current_risks": [],
            "must_not_break": [
                {"event_id": "s1", "kind": "must_not_break", "text": "Never copy capability tokens."}
            ],
            "forbidden_claims": [],
            "current_next_steps": [],
            "stale_items": [{"event_id": "stale", "text": "Gemini stale decision."}],
        }
        with tempfile.TemporaryDirectory() as directory, patch(
            "ithz_mcp.native_archive_store.resolve_memory_zone",
            return_value=SimpleNamespace(
                active_root=directory,
                active_memory_zone=directory,
                requested_project=directory,
            ),
        ), patch(
            "ithz_mcp.native_archive_store._load_archive_json_optional",
            return_value=synthesis,
        ):
            projection = native_archive_current_projection(Path(directory), "Gemini opponent", 4)
        decisions = projection["sections"]["current_decisions"]
        safety = projection["sections"]["must_not_break"]
        self.assertEqual([item["event_id"] for item in decisions], ["d1"])
        self.assertEqual([item["event_id"] for item in safety], ["s1"])
        projected_ids = {
            item.get("event_id")
            for items in projection["sections"].values()
            for item in items
        }
        self.assertNotIn("stale", projected_ids)
        self.assertTrue(projection["supersession_applied"])
        self.assertRegex(projection["projection_hash"], "^[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
