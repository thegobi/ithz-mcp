import json
import socket
import urllib.error
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

from ithz_mcp.ccg import code_review as cr
from ithz_mcp.ccg import code_review_parts as parts
from ithz_mcp.ccg.models import RoleResult, GeminiBackend, PreResponseTransportError, BackendError


class PartsBackend:
    provider = "google"

    def __init__(self):
        self.calls = []
        self.fail_at = None
        self.mutate = None
        self.after_call = None
        self.usage = True

    def run(self, role, prompt, schema, evidence_hash, directory):
        request = json.loads(prompt.split("SEALED PACKET:\n", 1)[1])
        self.calls.append(request)
        if len(self.calls) == self.fail_at:
            raise PreResponseTransportError("private transport data")
        segments = request["segments"] if request["kind"] == "part" else request["manifest"]["segments"]
        data = {"evidence_hash": evidence_hash, "coverage_complete": True,
                "reviewed_files": sorted({segment["path"] for segment in segments if segment["side"] != "diff"}),
                "reviewed_segments": [segment["id"] for segment in segments],
                "missing_context": [], "summary": "Synthetic exact review", "findings": []}
        if self.mutate:
            replacement = self.mutate(data, request)
            if isinstance(replacement, tuple):
                data = replacement[0]
        if self.after_call:
            self.after_call()
        return RoleResult(role, "google", "synthetic-model", "fixture", data, 1,
                          usage={"input_tokens": 100, "output_tokens": 20, "total_tokens": 120} if self.usage else {},
                          usage_source="gemini.response.usageMetadata")


class TransportBoundaryTests(unittest.TestCase):
    def test_actual_gemini_http_envelope_is_bounded(self):
        request = {"schema": cr.VERSION, "kind": "part", "segments": [{"text": 'quote " slash \\ Unicode Ž 😀\r\n' * 200}],
                   "scope": {"paths": ["long/path/name.py"]}}
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({
            "candidates": [{"content": {"parts": [{"text": json.dumps({"evidence_hash": cr.digest(request)})}]}}]
        }).encode()
        with patch("urllib.request.urlopen", return_value=response) as send:
            GeminiBackend("synthetic", "synthetic").run("test", parts.review_prompt(request), parts.result_schema(), cr.digest(request), Path("."))
        self.assertLessEqual(len(send.call_args.args[0].data), parts.request_bytes(request))

    def test_only_proven_preconnection_errors_are_retryable(self):
        backend = GeminiBackend("synthetic", "synthetic")
        for error, retryable in [(urllib.error.URLError(socket.gaierror("dns")), True),
                                 (urllib.error.URLError(ConnectionRefusedError()), True), (TimeoutError(), False)]:
            with patch("urllib.request.urlopen", side_effect=error):
                with self.assertRaises(BackendError) as caught:
                    backend.run("test", "x", {}, "hash", Path("."))
                self.assertEqual(isinstance(caught.exception, PreResponseTransportError), retryable)
        response = MagicMock()
        response.__enter__.return_value.read.side_effect = urllib.error.URLError(socket.gaierror("after-response"))
        with patch("urllib.request.urlopen", return_value=response):
            with self.assertRaises(BackendError) as caught:
                backend.run("test", "x", {}, "hash", Path("."))
            self.assertNotIsInstance(caught.exception, PreResponseTransportError)


class MultipartReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.autocrlf", "false")
        (self.root / ".ccg").mkdir()
        self.config = {"schema": "ccg_code_review_policy_v1", "enabled": True, "author_provider": "openai",
                       "reviewer_provider": "google", "block_severities": ["P0", "P1", "P2"],
                       "max_packet_bytes": 1_500_000, "max_part_bytes": 35_000}
        self.write_policy()
        (self.root / ".gitignore").write_text(".ithz-ccg/\n", encoding="utf-8")
        (self.root / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
        # Large unchanged context must still have both complete versions reviewed.
        (self.root / "artifact.txt").write_bytes(("Žltý 😀 záver\r\n" * 1_200 + "bez konca").encode("utf-8"))
        (self.root / "empty.txt").write_bytes(b"")
        (self.root / "deleted.txt").write_bytes("prvý\r\ndruhý".encode("utf-8"))
        self.commit()
        self.git("branch", "base")
        (self.root / "app.py").write_text("def value():\n    return 2\n", encoding="utf-8")
        (self.root / "deleted.txt").unlink()
        (self.root / "new-empty.txt").write_bytes(b"")
        self.commit()
        self.context = ["artifact.txt", "empty.txt"]

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.STDOUT)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def write_policy(self):
        (self.root / cr.POLICY).write_text(json.dumps(self.config), encoding="utf-8")

    def packet(self):
        return cr.snapshot(self.root, "base", context_paths=self.context)

    def run_review(self, backend):
        return cr.run_review(self.root, "base", context_paths=self.context, backend=backend)

    def gate(self):
        return cr.gate(self.root, "base", context_paths=self.context)

    def directory(self):
        return parts.directory_for(self.root, parts.plan(self.packet()))

    def test_exact_lossless_segments_all_versions_diff_unicode_newlines(self):
        packet = self.packet()
        plan = parts.plan(packet)
        all_segments = [segment for part in plan["parts"] for segment in part["segments"]]
        for document in plan["manifest"]["documents"]:
            matching = [segment for segment in all_segments if (segment["path"], segment["side"]) == (document["path"], document["side"])]
            if not document["exists"]:
                self.assertEqual(matching, [])
                continue
            original = packet["diff"] if document["side"] == "diff" else next(file for file in packet["files"] if file["path"] == document["path"])[document["side"]]
            self.assertEqual("".join(segment["text"] for segment in matching), original)
            offset, line = 0, 1
            for segment in matching:
                self.assertEqual(segment["start_byte"], offset)
                self.assertEqual(segment["start_line"], line)
                offset += len(segment["text"].encode("utf-8"))
                line += len(cr.source_lines(segment["text"]))
                self.assertEqual(segment["end_byte"], offset)
                self.assertEqual(segment["end_line"], line - 1)
            self.assertEqual(offset, document["bytes"])
            self.assertEqual(parts.sha(original), document["sha256"])
        self.assertEqual(parts.plan(packet), plan)
        self.assertIn("artifact.txt", plan["manifest"]["oversized_files"])
        self.assertTrue(all(parts.request_bytes(part) <= self.config["max_part_bytes"] for part in plan["parts"]))

    def test_prepare_runs_no_model_and_reports_all_parts(self):
        prepared = cr.prepare(self.root, "base", context_paths=self.context)
        self.assertEqual(prepared["model_runs"], 0)
        self.assertGreater(len(prepared["parts"]), 1)

    def test_success_requires_parts_and_integration_and_reuses_all(self):
        backend = PartsBackend()
        self.assertFalse(self.gate()["ready_for_pr"])
        result = self.run_review(backend)
        self.assertTrue(result["ready_for_pr"], result)
        count = len(backend.calls)
        self.assertEqual(backend.calls[-1]["kind"], "integration")
        self.assertEqual(backend.calls[-1]["diff"], self.packet()["diff"])
        self.assertNotIn("artifact.txt", [file["path"] for file in backend.calls[-1]["files"]])
        self.assertTrue(backend.calls[-1]["part_reports"])
        self.assertTrue(self.gate()["ready_for_pr"])
        self.assertEqual(self.run_review(backend)["model_runs"], 0)
        self.assertEqual(len(backend.calls), count)

    def test_transport_resume_does_not_reroll_accepted_parts(self):
        backend = PartsBackend()
        backend.fail_at = 2
        first = self.run_review(backend)
        self.assertFalse(first["ready_for_pr"])
        self.assertNotIn("private", json.dumps(first))
        first_hash = cr.digest(backend.calls[0])
        backend.fail_at = None
        self.assertTrue(self.run_review(backend)["ready_for_pr"])
        self.assertEqual(sum(cr.digest(call) == first_hash for call in backend.calls), 1)

    def test_bad_coverage_hash_usage_and_missing_context_are_immutable(self):
        scenarios = [lambda data, request: data.update(evidence_hash="wrong"),
                     lambda data, request: data.update(reviewed_segments=[]),
                     lambda data, request: data.update(reviewed_segments=list(reversed(data["reviewed_segments"]))),
                     lambda data, request: data.update(missing_context=["missing necessary module"])]
        for mutate in scenarios:
            # Each failed policy hash is a distinct authorized evidence packet, not a reroll.
            self.config["max_part_bytes"] += 1
            self.write_policy(); self.commit()
            backend = PartsBackend(); backend.mutate = mutate
            result = self.run_review(backend)
            self.assertFalse(result["ready_for_pr"])
            backend.mutate = None
            self.assertFalse(self.run_review(backend)["ready_for_pr"])
            self.assertEqual(len(backend.calls), 1)

    def test_bad_usage_is_sealed(self):
        backend = PartsBackend(); backend.usage = False
        self.assertIn("unverified_provider_usage", self.run_review(backend)["errors"])
        backend.usage = True
        self.assertFalse(self.run_review(backend)["ready_for_pr"])
        self.assertEqual(len(backend.calls), 1)

    def test_blocking_finding_cannot_be_overruled_or_rerolled(self):
        backend = PartsBackend()
        def mutate(data, request):
            source = next(segment for segment in request["segments"] if segment["path"] == "app.py" and segment["side"] == "after")
            data["findings"] = [{"severity": "P1", "file": "app.py", "side": "after", "line": source["start_line"],
                                 "title": "Synthetic issue", "scenario": "Synthetic failing value", "suggested_fix": "Fix value"}]
        backend.mutate = mutate
        self.assertIn("unresolved_P1", self.run_review(backend)["errors"])
        backend.mutate = None
        self.assertFalse(self.run_review(backend)["ready_for_pr"])
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(len(self.gate()["findings"]), 1)

    def test_missing_corrupt_duplicated_manifest_receipts_block(self):
        backend = PartsBackend()
        self.assertTrue(self.run_review(backend)["ready_for_pr"])
        directory = self.directory()
        receipt = directory / "part-0000.json"
        original = receipt.read_text()
        receipt.write_text("{")
        self.assertFalse(self.gate()["ready_for_pr"])
        self.assertFalse(self.run_review(backend)["ready_for_pr"])
        receipt.write_text(original)
        (directory / "unexpected.json").write_text(original)
        self.assertIn("unexpected_review_receipt", self.gate()["errors"])
        (directory / "unexpected.json").unlink()
        receipt.unlink()
        self.assertFalse(self.gate()["ready_for_pr"])
        count = len(backend.calls)
        self.assertIn("accepted_receipt_missing_or_attempt_interrupted", self.run_review(backend)["errors"])
        self.assertEqual(len(backend.calls), count)

    def test_malformed_accepted_data_blocks_cleanly_without_reroll(self):
        for malformed in [None, []]:
            self.config["max_part_bytes"] += 1
            self.write_policy(); self.commit()
            backend = PartsBackend(); backend.mutate = lambda data, request: (malformed,)
            self.assertFalse(self.run_review(backend)["ready_for_pr"])
            self.assertFalse(self.run_review(backend)["ready_for_pr"])
            self.assertFalse(self.gate()["ready_for_pr"])
            self.assertEqual(len(backend.calls), 1)

    def test_real_gemini_malformed_response_never_rerolls(self):
        bodies = [b"not JSON", b'{"candidates": []}',
                  json.dumps({"candidates": [{"content": {"parts": [{"text": "not model JSON"}]}}]}).encode(),
                  json.dumps({"candidates": [{"content": {"parts": [{"text": "[]"}]}}]}).encode()]
        for body in bodies:
            self.config["max_part_bytes"] += 1
            self.write_policy(); self.commit()
            response = MagicMock()
            response.__enter__.return_value.read.return_value = body
            with patch("urllib.request.urlopen", return_value=response) as request:
                backend = GeminiBackend("synthetic-not-real", "synthetic-model")
                self.assertFalse(self.run_review(backend)["ready_for_pr"])
                self.assertIn("accepted_receipt_missing_or_attempt_interrupted", self.run_review(backend)["errors"])
                self.assertEqual(request.call_count, 1)

    def test_integration_blocking_findings_are_reported_and_sealed(self):
        backend = PartsBackend()
        def mutate(data, request):
            if request["kind"] == "integration":
                data["findings"] = [{"severity": "P1", "file": "app.py", "side": "after", "line": 2,
                                     "title": "Integration issue", "scenario": "Broken contract", "suggested_fix": "Fix contract"}]
        backend.mutate = mutate
        self.assertIn("unresolved_P1", self.run_review(backend)["errors"])
        self.assertEqual(len(self.gate()["findings"]), 1)
        count = len(backend.calls)
        self.assertFalse(self.run_review(backend)["ready_for_pr"])
        self.assertEqual(len(backend.calls), count)

    def test_diff_only_locations_and_unicode_separators_are_original_lines(self):
        packet = self.packet()
        packet["diff"] = 'diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n value = "a\u2028b"\n-return 1\n+return 2\n'
        source = next(file for file in packet["files"] if file["path"] == "app.py")
        source["before"] = 'value = "a\u2028b"\nreturn 1\n'
        source["after"] = 'value = "a\u2028b"\nreturn 2\n'
        planned = parts.plan(packet)
        diff = [segment for request in planned["parts"] for segment in request["segments"] if segment["side"] == "diff"]
        request = {"kind": "part", "segments": diff}
        data = {"evidence_hash": cr.digest(request), "coverage_complete": True, "reviewed_files": [],
                "reviewed_segments": [segment["id"] for segment in diff], "missing_context": [], "summary": "Exact hunk review",
                "findings": [{"severity": "P3", "file": "app.py", "side": "after", "line": 2,
                              "title": "Issue", "scenario": "Scenario", "suggested_fix": "Fix"}]}
        self.assertEqual(parts.validate(data, packet, request, planned), [])
        data["findings"][0]["line"] = 3
        self.assertTrue(parts.validate(data, packet, request, planned))
        self.assertEqual(len(cr.source_lines(source["after"])), 2)

    def test_policy_head_dirty_and_manifest_tampering_block(self):
        self.assertTrue(self.run_review(PartsBackend())["ready_for_pr"])
        manifest = self.directory() / "manifest.json"
        data = json.loads(manifest.read_text()); data["parts"].reverse(); manifest.write_text(json.dumps(data))
        self.assertIn("manifest_integrity_invalid", self.gate()["errors"])
        (self.root / "app.py").write_text("changed")
        with self.assertRaisesRegex(ValueError, "clean_worktree"):
            self.gate()
        self.commit()
        self.assertFalse(self.gate()["ready_for_pr"])
        self.config["max_part_bytes"] += 1; self.write_policy(); self.commit()
        self.assertFalse(self.gate()["ready_for_pr"])

    def test_same_provider_forbidden_and_stale_during_call_sealed(self):
        backend = PartsBackend(); backend.provider = "openai"
        with self.assertRaisesRegex(ValueError, "independent_google"):
            self.run_review(backend)
        self.assertEqual(backend.calls, [])
        backend.provider = "google"
        backend.after_call = lambda: (self.root / "app.py").write_text("dirty")
        self.assertIn("git_changed_during_review", self.run_review(backend)["errors"])

    def test_secret_in_late_context_blocks_before_any_export(self):
        with (self.root / "artifact.txt").open("a", encoding="utf-8") as handle:
            handle.write("\n" + "ghp_" + "a" * 30)
        self.commit()
        backend = PartsBackend()
        with self.assertRaisesRegex(ValueError, "secret_like_content_blocked"):
            self.run_review(backend)
        self.assertEqual(backend.calls, [])

    def test_limits_strict_and_huge_line_fails_closed(self):
        for value in [True, None, "600000", 1.5, 0, 10_000_001]:
            with self.assertRaises(ValueError):
                parts.part_byte_limit({"max_part_bytes": value})
        with self.assertRaisesRegex(ValueError, "single_line_too_large"):
            parts.segments("app.py", "after", "😀" * 1_000, 100)

    def test_integration_growth_blocks_without_truncation(self):
        packet = self.packet(); planned = parts.plan(packet)
        with self.assertRaisesRegex(ValueError, "integration_too_large"):
            parts.integration_request(packet, planned, [{"summary": "report" * 10_000}])

    def test_lock_prevents_second_model_and_is_not_removed_by_nonowner(self):
        directory = self.directory(); directory.mkdir(parents=True)
        lock = directory / "review.lock"; lock.touch()
        backend = PartsBackend()
        self.assertIn("review_in_progress_or_interrupted", self.run_review(backend)["errors"])
        self.assertTrue(lock.exists()); self.assertEqual(backend.calls, [])


if __name__ == "__main__":
    unittest.main()
