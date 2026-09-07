import base64
import copy
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ithz_mcp.canonical_json import dumps
from ithz_mcp.hashing import stable_json_hash
from ithz_mcp.memory_integrity import evaluate_consolidation_candidate, validate_memory_record, validate_supersession
from ithz_mcp.memory_trust import candidate_content_hash, TRUST_SCHEMA, SUPPORT_SCHEMA, AUTHORIZATION_SCHEMA

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None


def candidate(**updates):
    record = dict(schema="ithz_memory_record_v2", memory_id="mem-1", kind="decision", scope="tests",
        statement="The fixture records a scoped outcome.", applies_when="Review this fixture.",
        does_not_apply_when="Outside the fixture.", valid_from="2026-09-01T00:00:00Z", valid_until="",
        source_event_ids=["event-1"], source_artifact_hashes=[], counterexample_ids=[], confidence=1.0,
        verification_state="candidate", policy_class="verified", created_by="proposer",
        created_at="2026-09-01T00:00:00Z", supersedes=[], supersession_reason="", human_approval_ids=[])
    record.update(updates)
    return record


def signed_candidate(record=None, sources=None, relation="supports"):
    record = validate_memory_record(record or candidate())
    sources = sources or {"event:event-1": {"event_id": "event-1", "text": "The fixture records a scoped outcome."}}
    support_key, activation_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    policy = dict(schema=TRUST_SCHEMA, rules_version="test-policy-1", proposer_principal="proposer", keys={})
    for role, private in (("support", support_key), ("activation", activation_key)):
        policy["keys"][role] = dict(principal=role + "-reviewer", roles=[role], scopes=["tests"],
            policy_classes=["verified", "hard"], authority="human",
            public_key=base64.b64encode(private.public_key().public_bytes_raw()).decode())
    common = dict(candidate_hash=candidate_content_hash(record), scope=record["scope"],
        rules_version="test-policy-1", issued_at="2026-09-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z")
    support = dict(common, schema=SUPPORT_SCHEMA, key_id="support", relation=relation,
        verification_method="human_evidence_review", evidence=[dict(id=key, sha256=stable_json_hash(value)) for key, value in sorted(sources.items())])
    support["signature"] = base64.b64encode(support_key.sign(dumps(support).encode())).decode()
    auth = dict(common, schema=AUTHORIZATION_SCHEMA, key_id="activation", decision="activate",
        support_receipt_hash=stable_json_hash(support), approval_id="approval-1")
    auth["signature"] = base64.b64encode(activation_key.sign(dumps(auth).encode())).decode()
    record.update(support_receipt=support, activation_authorization=auth)
    return record, policy, sources


class TemporalIntegrityTests(unittest.TestCase):
    def test_offsets_equal_and_older_are_rejected_without_mutation(self):
        old = candidate(memory_id="old")
        before = copy.deepcopy(old)
        for stamp in ("2026-09-01T00:00:00+00:00", "2026-09-01T02:00:00+02:00", "2026-09-01T01:00:00+02:00"):
            new = candidate(memory_id="new", valid_from=stamp, supersedes=["old"], supersession_reason="Replacement")
            self.assertFalse(validate_supersession(new, old)["valid"])
        self.assertEqual(old, before)
        self.assertEqual(stable_json_hash(old), stable_json_hash(before))

    def test_midnight_and_fraction_are_newer(self):
        old = candidate(memory_id="old")
        for stamp in ("2026-08-31T23:30:00-01:00", "2026-09-01T00:00:00.000001Z"):
            self.assertTrue(validate_supersession(candidate(valid_from=stamp, supersedes=["old"], supersession_reason="New"), old)["valid"])

    def test_bad_types_naive_and_interval_raise_value_error(self):
        for stamp in ([], {}, 42, "2026-09-01", "2026-09-01T00:00:00", "invalid", "2026-13-01T00:00:00Z"):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                validate_memory_record(candidate(valid_from=stamp))
        with self.assertRaises(ValueError):
            validate_memory_record(candidate(valid_until="2026-09-01T00:00:00Z"))

    def test_existing_source_or_claimed_approval_alone_never_activates(self):
        for record in (candidate(), candidate(source_event_ids=[]), candidate(human_approval_ids=["invented"])):
            result = evaluate_consolidation_candidate(record, {"event-1"}, set())
            self.assertFalse(result["accepted"])
            self.assertFalse(result["activation_authorized"])


@unittest.skipIf(Ed25519PrivateKey is None, "optional Ed25519 verifier not installed")
class SignedMemoryTrustTests(unittest.TestCase):
    def gate(self, record, policy, sources):
        return evaluate_consolidation_candidate(record, {key.removeprefix("event:") for key in sources}, set(),
            source_contents=sources, trust_policy=policy, now=datetime(2026, 9, 7, tzinfo=timezone.utc))

    def test_independent_bound_receipts_activate_and_do_not_rewrite_candidate(self):
        record, policy, sources = signed_candidate()
        before = copy.deepcopy(record)
        result = self.gate(record, policy, sources)
        self.assertTrue(result["accepted"], result)
        self.assertTrue(result["source_binding_valid"])
        self.assertEqual(result["support_verdict"], "supports")
        self.assertTrue(result["activation_authorized"])
        self.assertEqual(record, before)

    def test_mutated_candidate_evidence_wrong_scope_and_self_approval_fail(self):
        record, policy, sources = signed_candidate()
        for field, value in (("statement", "Deployment is safe."), ("scope", "production"), ("valid_from", "2026-09-02T00:00:00Z")):
            self.assertFalse(self.gate({**record, field: value}, policy, sources)["accepted"])
        self.assertFalse(self.gate(record, policy, {"event:event-1": {"event_id": "event-1", "text": "All tests FAILED"}})["accepted"])
        self.assertFalse(self.gate(record, policy, {})["accepted"])
        policy["keys"]["activation"]["principal"] = "proposer"
        self.assertFalse(self.gate(record, policy, sources)["accepted"])

    def test_contradiction_insufficient_replay_forged_signature_and_revocation(self):
        for relation in ("contradicts", "insufficient"):
            args = signed_candidate(relation=relation)
            self.assertFalse(self.gate(*args)["accepted"])
        record, policy, sources = signed_candidate()
        other, _, _ = signed_candidate(candidate(memory_id="other"))
        record["activation_authorization"] = other["activation_authorization"]
        self.assertFalse(self.gate(record, policy, sources)["accepted"])
        record, policy, sources = signed_candidate()
        record["support_receipt"]["signature"] = "forged"
        self.assertFalse(self.gate(record, policy, sources)["accepted"])
        record, policy, sources = signed_candidate()
        policy["keys"]["support"]["revoked"] = True
        self.assertFalse(self.gate(record, policy, sources)["accepted"])

    def test_receipt_same_principal_and_current_validity(self):
        record, policy, sources = signed_candidate()
        policy["keys"]["activation"]["principal"] = policy["keys"]["support"]["principal"]
        self.assertFalse(self.gate(record, policy, sources)["accepted"])

    def test_creator_cannot_be_relabelled_to_evade_runtime_identity(self):
        record, policy, sources = signed_candidate(candidate(created_by="someone-else"))
        self.assertFalse(self.gate(record, policy, sources)["accepted"])
        record, policy, sources = signed_candidate(candidate(valid_until="2026-09-06T00:00:00Z"))
        self.assertFalse(self.gate(record, policy, sources)["accepted"])

    def test_malformed_attestations_fail_closed(self):
        for value in ([], "fake", {"key_id": []}, {"schema": SUPPORT_SCHEMA, "key_id": []}):
            record, policy, sources = signed_candidate()
            record["support_receipt"] = value
            self.assertFalse(self.gate(record, policy, sources)["accepted"])

    def test_read_does_not_promote_legacy_or_expired_typed_memory(self):
        from ithz_mcp.native_archive_store import _active_events
        record = candidate(verification_state="active")
        events = [{"event_id": "event-1", "text": "Evidence"},
                  {"event_id": "event-2", "kind": "decision", "metadata": {"memory_record": record}}]
        with patch.dict(os.environ, {"ITHZ_MEMORY_TRUST_POLICY": ""}):
            active, _ = _active_events(events)
        self.assertEqual([event["event_id"] for event in active], ["event-1"])

    def test_public_mcp_native_roundtrip_and_failed_supersession_preserve_history(self):
        from ithz_mcp.mcp_server import call_tool
        from ithz_mcp.native_archive_store import build_native_archive, locate_native_ithz, _memory_events, native_archive_current_projection, native_archive_context_pack
        try:
            native = locate_native_ithz()
        except (FileNotFoundError, RuntimeError):
            self.skipTest("native archive executable not available")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "project.md").write_text("Synthetic memory trust roundtrip.\n", encoding="utf-8")
            policy_file = Path(directory) / "operator-policy.json"
            with patch.dict(os.environ, {"ITHZ_NATIVE_EXE": str(native), "ITHZ_MEMORY_TRUST_POLICY": str(policy_file)}):
                build_native_archive(root, str(native))
                source = call_tool("ithz_archive_append_event", {"kind": "note", "text": "The fixture records a scoped outcome."}, root, "native-archive", "write-enabled")["event"]
                record, policy, sources = signed_candidate(candidate(source_event_ids=[source["event_id"]]), {"event:" + source["event_id"]: source})
                policy_file.write_text(json.dumps(policy), encoding="utf-8")
                receipt = call_tool("ithz_archive_append_memory_record", {"record": record}, root, "native-archive", "write-enabled")
                self.assertTrue(receipt["active"], receipt)
                history = _memory_events(root, str(native))
                projection = native_archive_current_projection(root, native_exe=str(native))
                self.assertTrue(any(row.get("verification_state") == "active" for row in projection["sections"]["current_decisions"]))
                forged = copy.deepcopy(record)
                forged.update(memory_id="forged", statement="Production deployment is safe.",
                    supersedes=[receipt["event"]["event_id"]], supersession_reason="Forged replacement")
                denied = call_tool("ithz_archive_append_memory_record", {"record": forged}, root, "native-archive", "write-enabled")
                self.assertFalse(denied["active"])
                after = _memory_events(root, str(native))
                self.assertEqual(after[:len(history)], history)
                projection = native_archive_current_projection(root, native_exe=str(native))
                self.assertTrue(any(row.get("event_id") == receipt["event"]["event_id"] for row in projection["sections"]["current_decisions"]))
                self.assertFalse(any("Production deployment is safe." in row.get("text", "") for row in projection["sections"]["current_decisions"]))
                pack = native_archive_context_pack(root, "current decisions fixture", native_exe=str(native))
                self.assertIn("decision; active", pack["text"])
                self.assertIn("retrieved_evidence_not_authorization", pack["text"])


if __name__ == "__main__":
    unittest.main()
