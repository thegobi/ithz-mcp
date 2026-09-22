import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from ithz_mcp.ccg import code_review as cr
from ithz_mcp.ccg import code_review_parts as parts
from ithz_mcp.ccg import code_review_recovery as recovery
from ithz_mcp.ccg.models import BackendError, GeminiBackend, PreResponseTransportError, RoleResult, safe_backend_diagnostic


class Backend:
    provider = "google"
    def __init__(self, fail_at=None, callback=None, malformed=False):
        self.calls = 0
        self.fail_at = fail_at
        self.callback = callback
        self.malformed = malformed

    def run(self, role, prompt, schema, evidence_hash, directory):
        self.calls += 1
        if self.callback:
            self.callback(directory)
        if self.calls == self.fail_at:
            raise BackendError("SECRET raw message", diagnostic={"category": "http_error", "http_status": 400, "provider_status": "INVALID_ARGUMENT"})
        request = json.loads(prompt.split("SEALED PACKET:\n")[1])
        segments = request["segments"] if request["kind"] == "part" else request["manifest"]["segments"]
        data = {"evidence_hash": evidence_hash, "coverage_complete": True, "reviewed_segments": [s["id"] for s in segments],
                "reviewed_files": sorted({s["path"] for s in segments if s["side"] != "diff"}), "missing_context": [], "summary": "Synthetic", "findings": []}
        return RoleResult(role, "google", "synthetic", "fixture", None if self.malformed else data, 1,
                          usage={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}, usage_source="gemini.response.usageMetadata")


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.packet = {"schema": cr.VERSION, "project": str(self.root), "base_sha": "a" * 40, "head_sha": "b" * 40,
                       "max_packet_bytes": 1_500_000, "max_part_bytes": 30_000, "diff": "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a=1\n+a=2\n",
                       "files": [{"path": "app.py", "before": "a=1\n", "after": "a=2\n", "changed": True},
                                 {"path": "large.txt", "before": "a=1\n" * 4000, "after": "a=1\n" * 4000, "changed": False}]}
        self.plan = parts.plan(self.packet)
        self.directory = parts.directory_for(self.root, self.plan)

    def run_backend(self, backend):
        return parts.run_parts(self.root, self.packet, lambda: self.packet, backend=backend)

    def authorize(self, index=0, **kwargs):
        return recovery.authorize_recovery(self.root, self.packet, lambda: self.packet,
            expected_manifest_hash=self.plan["manifest_hash"], request_hash=cr.digest(self.plan["parts"][index]),
            authorization_id="user-approved-one-attempt", reason="Inspect sanitized provider failure", **kwargs)

    def test_exact_one_use_preserves_original_and_prior_receipts(self):
        self.assertFalse(self.run_backend(Backend(fail_at=2))["ready_for_pr"])
        original = {p.name: p.read_bytes() for p in self.directory.iterdir() if p.is_file()}
        self.assertTrue(self.authorize(1)["authorized"])
        def consumed_before_call(directory):
            self.assertTrue((directory / recovery.USED).exists())
            self.assertTrue((directory / recovery.CONSUMED).exists())
            self.assertEqual(recovery.chain(directory, self.packet, self.plan)["maximum_additional_attempts"], 1)
        backend = Backend(callback=consumed_before_call)
        result = self.run_backend(backend)
        self.assertTrue(result["recovery_attempt_completed"])
        self.assertEqual(backend.calls, 1)
        for name, data in original.items():
            self.assertEqual((self.directory / name).read_bytes(), data)
        with self.assertRaisesRegex(ValueError, "already_authorized"):
            self.authorize(1)
        # Root-approved original workflow may now review previously unattempted parts.
        continuation = Backend()
        self.assertTrue(self.run_backend(continuation)["ready_for_pr"])
        self.assertTrue(parts.gate_parts(self.root, self.packet)["ready_for_pr"])
        self.assertEqual(self.run_backend(Backend())["model_runs"], 0)

    def test_failure_consumes_even_preconnection_and_blocks_reroll(self):
        self.run_backend(Backend(fail_at=1)); self.authorize()
        class Dns(Backend):
            def run(self, *args):
                self.calls += 1
                raise PreResponseTransportError("DNS", diagnostic={"category": "connection_not_established"})
        backend = Dns()
        self.assertFalse(self.run_backend(backend)["ready_for_pr"])
        self.assertTrue((self.directory / recovery.FAILED).exists())
        self.assertEqual(self.run_backend(backend)["model_runs"], 0)
        self.assertEqual(backend.calls, 1)
        original = (self.directory / recovery.USED).read_bytes()
        (self.directory / recovery.USED).unlink()
        with self.assertRaisesRegex(ValueError, "consumption_missing"):
            self.run_backend(Backend())
        (self.directory / recovery.USED).write_bytes(original)
        self.assertFalse(parts.gate_parts(self.root, self.packet)["ready_for_pr"])

    def test_accepted_malformed_response_cannot_be_recovered(self):
        self.run_backend(Backend(malformed=True))
        with self.assertRaisesRegex(ValueError, "accepted_response"):
            self.authorize()

    def test_accepted_p2_receipt_cannot_be_recovered_or_hidden(self):
        class Blocking(Backend):
            def run(self, *args):
                role = super().run(*args)
                role.data["findings"] = [{"severity": "P2", "file": "app.py", "side": "after", "line": 1,
                                          "title": "Broken", "scenario": "Broken result", "suggested_fix": "Fix"}]
                return role
        self.assertIn("unresolved_P2", self.run_backend(Blocking())["errors"])
        original = (self.directory / "part-0000.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "accepted_response"):
            self.authorize()
        self.assertEqual((self.directory / "part-0000.json").read_bytes(), original)
        self.assertEqual(len(parts.gate_parts(self.root, self.packet)["findings"]), 1)

    def test_corrupt_consumption_bytes_and_resealed_wrong_schema_block(self):
        self.run_backend(Backend(fail_at=1)); self.authorize(); self.run_backend(Backend(fail_at=1))
        consumed = self.directory / recovery.CONSUMED
        original = consumed.read_bytes(); consumed.write_bytes(b"\xff")
        self.assertFalse(parts.gate_parts(self.root, self.packet)["ready_for_pr"])
        consumed.write_bytes(original)
        for name in [recovery.USED, recovery.FAILED]:
            path = self.directory / name; saved = path.read_bytes(); record = json.loads(saved)
            record["schema"] = "wrong"
            record["receipt_hash"] = cr.digest({key: item for key, item in record.items() if key != "receipt_hash"})
            path.write_text(json.dumps(record))
            self.assertFalse(parts.gate_parts(self.root, self.packet)["ready_for_pr"])
            with self.assertRaises(ValueError):
                self.run_backend(Backend())
            path.write_bytes(saved)

    def test_simultaneous_recovery_success_and_failure_always_blocks(self):
        self.run_backend(Backend(fail_at=1)); self.authorize(); self.run_backend(Backend())
        authorization = recovery.read_sealed(self.directory / recovery.AUTH)
        parts.atomic_write(self.directory / recovery.FAILED, {"schema": cr.VERSION, "packet_hash": cr.digest(self.packet),
            "manifest_hash": self.plan["manifest_hash"], "request_hash": authorization["request_hash"],
            "authorization_hash": authorization["receipt_hash"], "diagnostic": {"category": "backend_error"}})
        gate = parts.gate_parts(self.root, self.packet)
        self.assertFalse(gate["ready_for_pr"])
        self.assertIn("recovery_multiple_outcomes", gate["errors"])
        backend = Backend()
        with self.assertRaisesRegex(ValueError, "multiple_outcomes"):
            self.run_backend(backend)
        self.assertEqual(backend.calls, 0)

    def test_legacy_marker_recovery_and_chain_tamper_fail_closed(self):
        self.run_backend(Backend(fail_at=1))
        (self.directory / "part-0000.failure.json").unlink()  # Simulate actual a19 legacy marker with no diagnostic file.
        self.assertEqual(self.authorize()["diagnostic"], {"category": "legacy_failure_diagnostic_unavailable"})
        original = (self.directory / recovery.AUTH).read_bytes()
        for field, value in [("prior_receipts", []), ("maximum_additional_attempts", True), ("target", "part-9999.json")]:
            auth = json.loads(original); auth[field] = value
            auth["receipt_hash"] = cr.digest({key: item for key, item in auth.items() if key != "receipt_hash"})
            (self.directory / recovery.AUTH).write_text(json.dumps(auth))
            self.assertFalse(parts.gate_parts(self.root, self.packet)["ready_for_pr"])
            with self.assertRaises(ValueError):
                self.run_backend(Backend())
        (self.directory / recovery.AUTH).write_bytes(original)
        self.run_backend(Backend())
        for name in [recovery.AUTH, recovery.USED, recovery.CONSUMED, "part-0000.attempt"]:
            file = self.directory / name; saved = file.read_bytes(); file.unlink()
            self.assertFalse(parts.gate_parts(self.root, self.packet)["ready_for_pr"])
            file.write_bytes(saved)

    def test_stale_or_concurrent_authorization_never_writes(self):
        self.run_backend(Backend(fail_at=1))
        with self.assertRaisesRegex(ValueError, "evidence_changed"):
            recovery.authorize_recovery(self.root, self.packet, lambda: {}, expected_manifest_hash=self.plan["manifest_hash"],
                request_hash=cr.digest(self.plan["parts"][0]), authorization_id="approved", reason="reason")
        lock = self.directory / "review.lock"; lock.touch()
        with self.assertRaisesRegex(ValueError, "in_progress"):
            self.authorize()
        self.assertTrue(lock.exists())
        self.assertFalse((self.directory / recovery.AUTH).exists())

    def test_actual_http_diagnostic_is_sanitized_and_sealed(self):
        error = urllib.error.HTTPError("https://example.invalid/SECRET", 400, "SECRET", {"SECRET": "token"},
                io.BytesIO(json.dumps({"error": {"status": "INVALID_ARGUMENT", "message": "SECRET PROMPT TOKEN"}}).encode()))
        backend = GeminiBackend("SECRET", "synthetic")
        with patch("urllib.request.urlopen", side_effect=error):
            result = self.run_backend(backend)
        self.assertEqual(result["diagnostic"], {"category": "http_error", "http_status": 400, "provider_status": "INVALID_ARGUMENT"})
        self.assertNotIn("SECRET", json.dumps(result))
        failure = (self.directory / "part-0000.failure.json").read_text()
        self.assertNotIn("SECRET", failure)
        self.assertEqual(self.authorize()["diagnostic"], result["diagnostic"])

    def test_dns_then_http_preserves_both_and_recovery_uses_current_failure(self):
        class Dns(Backend):
            def run(self, *args):
                raise PreResponseTransportError("DNS", diagnostic={"category": "connection_not_established"})
        self.run_backend(Dns())
        self.run_backend(Backend(fail_at=1))
        self.assertTrue((self.directory / "part-0000.transport-0000.json").exists())
        self.assertEqual(self.authorize()["diagnostic"]["category"], "http_error")


class DiagnosticTests(unittest.TestCase):
    def test_hostile_diagnostic_types_do_not_throw(self):
        for malformed in [[], {}, 42, None]:
            diagnostic = safe_backend_diagnostic(BackendError("SECRET", diagnostic={"category": malformed, "provider_status": malformed, "http_status": True}))
            self.assertEqual(diagnostic, {"category": "backend_error"})
            body = io.BytesIO(json.dumps({"error": {"status": malformed, "message": "SECRET"}}).encode())
            with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError("u", 500, "SECRET", {}, body)):
                with self.assertRaises(BackendError) as caught:
                    GeminiBackend("SECRET", "synthetic").run("test", "SECRET", {}, "hash", Path("."))
            self.assertEqual(safe_backend_diagnostic(caught.exception), {"category": "http_error", "http_status": 500})


if __name__ == "__main__":
    unittest.main()
