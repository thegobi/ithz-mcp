import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ithz_mcp.ccg.code_review import prepare, run_review, gate, snapshot, digest, safe_text, packet_byte_limit
from ithz_mcp.ccg.models import RoleResult
from ithz_mcp.ccg.mcp_server import tool_schemas, call_tool


class Backend:
    provider = "google"
    calls = 0
    mutate = None
    finding = False
    usage = True
    def run(self, role, prompt, schema, evidence_hash, chamber):
        self.calls += 1
        packet = json.loads(prompt.split("SEALED PACKET:\n")[1])
        data = dict(evidence_hash=evidence_hash, coverage_complete=True,
                    reviewed_files=[f["path"] for f in packet["files"]], missing_context=[], summary="Reviewed exact code.", findings=[])
        if self.finding:
            data["findings"] = [dict(severity="P1", file="app.py", side="after", line=1, title="Bug", scenario="Returns wrong value", suggested_fix="Correct the return value")]
        if self.mutate:
            self.mutate(data)
        return RoleResult(role, "google", "test-fixture", "fixture", data, 1,
                          usage={"input_tokens": 100, "output_tokens": 20, "total_tokens": 120} if self.usage else {},
                          usage_source="gemini.response.usageMetadata")


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.root / ".ccg").mkdir()
        (self.root / ".ccg/code-review.json").write_text(json.dumps({"schema":"ccg_code_review_policy_v1","enabled":True,"author_provider":"openai","reviewer_provider":"google","block_severities":["P0","P1","P2"]}))
        (self.root / ".gitignore").write_text(".ithz-ccg/\n")
        (self.root / "app.py").write_text("def value():\n    return 1\n")
        self.commit()
        self.git("branch", "base")
        (self.root / "app.py").write_text("def value():\n    return 2\n")
        self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.STDOUT)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def test_pass_and_idempotency(self):
        backend = Backend()
        self.assertFalse(gate(self.root, "base")["ready_for_pr"])
        self.assertTrue(run_review(self.root, "base", backend=backend)["ready_for_pr"])
        self.assertTrue(gate(self.root, "base")["ready_for_pr"])
        self.assertEqual(run_review(self.root, "base", backend=backend)["model_runs"], 0)
        self.assertEqual(backend.calls, 1)

    def test_findings_cannot_be_rerolled(self):
        backend = Backend(); backend.finding = True
        self.assertFalse(run_review(self.root, "base", backend=backend)["ready_for_pr"])
        backend.finding = False
        self.assertFalse(run_review(self.root, "base", backend=backend)["ready_for_pr"])
        self.assertEqual(backend.calls, 1)

    def test_dirty_and_untracked_block(self):
        (self.root / "new.txt").write_text("new")
        with self.assertRaisesRegex(ValueError, "clean_worktree"):
            prepare(self.root, "base")

    def test_head_and_base_drift(self):
        run_review(self.root, "base", backend=Backend())
        (self.root / "app.py").write_text("def value():\n    return 3\n")
        self.commit()
        self.assertFalse(gate(self.root, "base")["ready_for_pr"])
        self.git("branch", "-f", "base", "HEAD~1")
        self.assertFalse(gate(self.root, "base")["ready_for_pr"])

    def test_tamper_blocks(self):
        result = run_review(self.root, "base", backend=Backend())
        path = Path(result["receipt_path"])
        data = json.loads(path.read_text()); data["review"]["data"]["summary"] = "tampered"
        path.write_text(json.dumps(data))
        self.assertIn("receipt_integrity_invalid", gate(self.root, "base")["errors"])

    def test_missing_usage_blocks(self):
        backend = Backend(); backend.usage = False
        self.assertFalse(run_review(self.root, "base", backend=backend)["ready_for_pr"])

    def test_incomplete_coverage_blocks(self):
        backend = Backend(); backend.mutate = lambda d: d.update(reviewed_files=[])
        self.assertFalse(run_review(self.root, "base", backend=backend)["ready_for_pr"])

    def test_wrong_hash_blocks(self):
        backend = Backend(); backend.mutate = lambda d: d.update(evidence_hash="0" * 64)
        self.assertFalse(run_review(self.root, "base", backend=backend)["ready_for_pr"])

    def test_same_lab_blocks(self):
        backend = Backend(); backend.provider = "openai"
        with self.assertRaisesRegex(ValueError, "independent_google"):
            run_review(self.root, "base", backend=backend)
        self.assertEqual(backend.calls, 0)

    def test_binary_and_oversize_fail_before_provider(self):
        with patch("ithz_mcp.ccg.code_review.MAX_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "too_large"):
                prepare(self.root, "base")
        (self.root / "image.bin").write_bytes(b"\x00\xff")
        self.commit()
        with self.assertRaisesRegex(ValueError, "binary"):
            prepare(self.root, "base")

    def test_secret_block(self):
        with self.assertRaisesRegex(ValueError, "sensitive_path"):
            safe_text(".env", b"x")
        with self.assertRaisesRegex(ValueError, "secret_like"):
            safe_text("app.py", ("ghp_" + "a" * 30).encode())

    def test_tool_dispatch(self):
        names = {s["name"] for s in tool_schemas()}
        self.assertTrue({"ccg_prepare_code_review", "ccg_run_code_review", "ccg_check_pr_review"} <= names)
        result = call_tool("ccg_prepare_code_review", {"base_ref":"base"}, self.root)
        self.assertEqual(result["model_runs"], 0)

    def test_context_bound(self):
        first = prepare(self.root, "base")["evidence_hash"]
        second = prepare(self.root, "base", context_paths=[".gitignore"])["evidence_hash"]
        self.assertNotEqual(first, second)

    def test_policy_opt_in(self):
        (self.root / ".ccg/code-review.json").unlink()
        with self.assertRaisesRegex(ValueError, "not_enabled"):
            prepare(self.root, "base")

    def test_concurrent_review_returns_block_without_second_call(self):
        evidence_hash = prepare(self.root, "base")["evidence_hash"]
        directory = self.root / ".ithz-ccg/code-reviews"
        directory.mkdir(parents=True)
        (directory / (evidence_hash + ".lock")).touch()
        backend = Backend()
        result = run_review(self.root, "base", backend=backend)
        self.assertEqual(result["errors"], ["review_in_progress_or_interrupted"])
        self.assertEqual(backend.calls, 0)
        self.assertTrue((directory / (evidence_hash + ".lock")).is_file())

    def test_mutation_during_review_persists_block(self):
        backend = Backend()
        backend.mutate = lambda d: (self.root / "app.py").write_text("changed during request")
        result = run_review(self.root, "base", backend=backend)
        self.assertIn("git_changed_during_review", result["errors"])

    def test_deleted_sensitive_file_blocks_before_model(self):
        (self.root / '.env').write_text('fixture')
        self.commit()
        self.git('branch', '-f', 'base', 'HEAD')
        (self.root / '.env').unlink()
        self.commit()
        with self.assertRaisesRegex(ValueError, 'sensitive_path'):
            prepare(self.root, 'base')

    def test_corrupt_receipt_blocks_cleanly(self):
        result = run_review(self.root, 'base', backend=Backend())
        Path(result['receipt_path']).write_text('{')
        self.assertFalse(gate(self.root, 'base')['ready_for_pr'])

    def test_provider_failure_is_safe_and_retryable(self):
        backend = Backend()
        with patch.object(backend, 'run', side_effect=RuntimeError('private diagnostic')):
            result = run_review(self.root, 'base', backend=backend)
        self.assertFalse(result['ready_for_pr'])
        self.assertNotIn('private diagnostic', json.dumps(result))
        self.assertTrue(run_review(self.root, 'base', backend=backend)['ready_for_pr'])

    def set_limit(self, value):
        path = self.root / '.ccg/code-review.json'
        config = json.loads(path.read_text())
        config['max_packet_bytes'] = value
        path.write_text(json.dumps(config))
        self.commit()

    def test_default_limit_is_decimal_1500kb(self):
        result = prepare(self.root, 'base')
        self.assertEqual(result['max_packet_bytes'], 1_500_000)
        self.assertEqual(snapshot(self.root, 'base')['schema'], 'mcp37.1-pre-pr-review-v2')

    def test_configured_limit_is_bound_to_packet(self):
        first = prepare(self.root, 'base')['evidence_hash']
        self.set_limit(3_000_000)
        result = prepare(self.root, 'base')
        self.assertEqual(result['max_packet_bytes'], 3_000_000)
        self.assertNotEqual(first, result['evidence_hash'])

    def test_invalid_limits_fail_closed(self):
        for value in [None, True, False, '3000000', 3000000.0, 0, -1, 1023, 10_000_001]:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'invalid_code_review_max_packet_bytes'):
                    packet_byte_limit({'max_packet_bytes': value})

    def test_limit_boundaries_are_accepted(self):
        self.assertEqual(packet_byte_limit({'max_packet_bytes': 1024}), 1024)
        self.assertEqual(packet_byte_limit({'max_packet_bytes': 10_000_000}), 10_000_000)

    def test_small_project_limit_stops_before_model(self):
        self.set_limit(1024)
        backend = Backend()
        with self.assertRaisesRegex(ValueError, 'too_large_no_truncation'):
            run_review(self.root, 'base', backend=backend)
        self.assertEqual(backend.calls, 0)

    def test_larger_limit_preserves_complete_content(self):
        content = 'bounded complete review fixture\n' * 24_000
        (self.root / 'large.txt').write_text(content, encoding='utf-8')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'too_large_no_truncation'):
            prepare(self.root, 'base')
        self.set_limit(4_000_000)
        packet = snapshot(self.root, 'base')
        large = next(item for item in packet['files'] if item['path'] == 'large.txt')
        self.assertEqual(large['after'], content)
        self.assertIn(content.splitlines()[-1], packet['diff'])

    def test_limit_change_invalidates_existing_receipt(self):
        self.set_limit(3_000_000)
        self.assertTrue(run_review(self.root, 'base', backend=Backend())['ready_for_pr'])
        self.set_limit(4_000_000)
        self.assertFalse(gate(self.root, 'base')['ready_for_pr'])

    def test_large_limit_does_not_relax_security_or_findings(self):
        self.set_limit(10_000_000)
        backend = Backend(); backend.finding = True
        self.assertFalse(run_review(self.root, 'base', backend=backend)['ready_for_pr'])
        (self.root / '.env').write_text('fixture')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'sensitive_path'):
            prepare(self.root, 'base')


if __name__ == "__main__":
    unittest.main()
