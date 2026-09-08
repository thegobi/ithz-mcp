"""MCP36.6 delivery-path regression: signed memory through native projection/views."""
import json
import copy
import os
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from ithz_mcp.memory_integrity import build_evidence_views
from ithz_mcp.hashing import stable_json_hash, sha256_text
from ithz_mcp.mcp_server import call_tool
from ithz_mcp.native_archive_store import (
    build_native_archive,
    locate_native_ithz,
    native_archive_current_projection,
)
from tests import test_memory_trust as trust_fixtures
from tests.test_memory_trust import signed_candidate, candidate


@unittest.skipIf(trust_fixtures.Ed25519PrivateKey is None, "optional Ed25519 verifier not installed")
class MemoryDeliveryEndToEndTests(unittest.TestCase):
    def test_signed_record_reaches_projection_and_judge_binding_with_raw_content(self):
        try:
            native = locate_native_ithz()
        except (FileNotFoundError, RuntimeError):
            self.skipTest("native archive executable not available")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "project.md").write_text("Synthetic delivery fixture.\n", encoding="utf-8")
            policy_file = Path(directory) / "operator-policy.json"
            with patch.dict(os.environ, {"ITHZ_NATIVE_EXE": str(native), "ITHZ_MEMORY_TRUST_POLICY": str(policy_file)}):
                build_native_archive(root, str(native))
                source = call_tool("ithz_archive_append_event", {"kind": "note", "text": "Exact raw delivery evidence."}, root, "native-archive", "write-enabled")["event"]
                record, policy, sources = signed_candidate(candidate(source_event_ids=[source["event_id"]]), {"event:" + source["event_id"]: source})
                policy_file.write_text(json.dumps(policy), encoding="utf-8")
                receipt = call_tool("ithz_archive_append_memory_record", {"record": record}, root, "native-archive", "write-enabled")
                self.assertTrue(receipt.get("active"), receipt)
                projection = native_archive_current_projection(root, native_exe=str(native))
                active = [row for row in projection["sections"]["current_decisions"] if row.get("event_id") == receipt["event"]["event_id"]]
                self.assertTrue(active, projection)
                row = active[0]
                self.assertEqual(row.get("source_event_ids"), [source["event_id"]], "projection must preserve exact source binding")
                self.assertEqual(row.get("text"), record["statement"])
                source_evidence = [item for item in projection.get("source_evidence", []) if item.get("id") == "event:" + source["event_id"]]
                self.assertTrue(source_evidence, "projection must expose canonical source evidence")
                self.assertEqual(source_evidence[0]["content_sha256"], stable_json_hash(source))
                self.assertTrue(source_evidence[0]["runtime_verified"])
                compiled = build_evidence_views(projection)
                judge_rows = compiled["views"]["judge"]["claim_evidence_matrix"]
                claim = next(item for item in judge_rows if item["item_id"] == row["event_id"])
                self.assertTrue(claim["binding_complete"], claim)
                self.assertIn("event:" + source["event_id"], claim["raw_evidence_ids"])
                self.assertIn("Exact raw delivery evidence.", json.dumps(compiled["views"]["judge"]))

    def test_portable_projection_delivery_path_uses_real_event_payload(self):
        from ithz_mcp import native_archive_store
        typed, policy, sources = trust_fixtures.SignedMemoryTrustTests().active_event()
        source = sources[0]
        with patch("ithz_mcp.memory_trust.load_runtime_trust_policy", return_value=policy), patch.object(native_archive_store, "_memory_events", return_value=[*sources, typed]), patch.object(native_archive_store, "resolve_memory_zone", return_value=SimpleNamespace(active_root=Path("."), active_memory_zone="nearest")):
            projection = native_archive_store.native_archive_current_projection(Path("."), native_exe="unused")
        self.assertEqual(projection["source_evidence"][0]["content_sha256"], stable_json_hash(source))
        compiled = build_evidence_views(projection)
        claim = compiled["views"]["judge"]["claim_evidence_matrix"][0]
        self.assertTrue(claim["binding_complete"], claim)
        self.assertEqual(claim["raw_evidence_ids"], ["event:" + source["event_id"]])
        self.assertIn(source["text"], json.dumps(compiled["views"]["judge"]))

    def test_source_payload_missing_or_tampered_fails_binding(self):
        from ithz_mcp import native_archive_store
        typed, policy, sources = trust_fixtures.SignedMemoryTrustTests().active_event()
        with patch("ithz_mcp.memory_trust.load_runtime_trust_policy", return_value=policy), patch.object(native_archive_store, "_memory_events", return_value=[*sources, typed]), patch.object(native_archive_store, "resolve_memory_zone", return_value=SimpleNamespace(active_root=Path("."), active_memory_zone="nearest")):
            base = native_archive_store.native_archive_current_projection(Path("."), native_exe="unused")
        for mode in ("missing", "changed", "changed_and_rehashed"):
            projection = copy.deepcopy(base)
            evidence = projection["source_evidence"][0]
            if mode == "missing":
                evidence.pop("content_text")
            else:
                evidence["content_text"] = '"Forged replacement content"'
                evidence["content_bytes"] = len(evidence["content_text"].encode("utf-8"))
                if mode == "changed_and_rehashed":
                    evidence["content_sha256"] = sha256_text(evidence["content_text"])
            compiled = build_evidence_views(projection)
            claim = compiled["views"]["judge"]["claim_evidence_matrix"][0]
            with self.subTest(mode=mode):
                self.assertFalse(claim["binding_complete"], claim)

    def test_oversized_source_payload_is_not_delivered_as_evidence(self):
        from ithz_mcp.memory_integrity import build_evidence_views
        huge = "x" * (16 * 1024 + 1)
        projection = {"schema": "ithz_current_projection_v1", "source_evidence": [{"id": "event:event-real", "kind": "archive_event", "content_text": huge, "content_sha256": sha256_text(huge), "content_bytes": len(huge), "runtime_verified": True}], "sections": {"current_decisions": [] , "current_gates": []}}
        evidence = build_evidence_views(projection)["views"]["judge"]["raw_evidence"]
        self.assertFalse(evidence[0]["content_delivered_to_role"])
        self.assertEqual(evidence[0]["delivery_failure_reason"], "content_oversize")

    def test_projection_tamper_does_not_create_judge_binding(self):
        projection = {"sections": {"current_decisions": [{"event_id": "mem-1", "text": "claimed", "source_event_ids": ["missing"]}], "current_gates": [{"event_id": "real", "text": "real raw"}]}}
        compiled = build_evidence_views(projection)
        claim = compiled["views"]["judge"]["claim_evidence_matrix"][0]
        self.assertFalse(claim["binding_complete"])
        self.assertEqual(claim["raw_evidence_ids"], [])


if __name__ == "__main__":
    unittest.main()
