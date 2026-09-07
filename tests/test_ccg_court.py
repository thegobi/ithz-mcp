import json
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ithz_mcp.ccg.court import CourtRunner, initialize_project
from ithz_mcp.ccg.ledger import _exclusive_lock
from ithz_mcp.ccg.models import (
    BackendError,
    ScriptedBackend,
    _normalized_usage,
    _resolve_codex_app_server_executable,
    _usage_from_app_server_notification,
)


class CCGCourtTests(unittest.TestCase):
    @staticmethod
    def _final_review_manifest(root: Path, checkpoint_hash: str) -> Path:
        artifact = root / "reviewed-artifact.txt"
        artifact.write_text("reviewed evidence\n", encoding="utf-8")
        artifact_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
        command_output = root / "unittest-output.txt"
        command_output.write_text("Ran deterministic fixture: OK\n", encoding="utf-8")
        command_output_hash = hashlib.sha256(command_output.read_bytes()).hexdigest()
        manifest = root / "final-review-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "ccg_final_review_manifest_v2",
                    "memory_synthesis_hash": checkpoint_hash,
                    "scope": "Deterministic final-case fixture.",
                    "artifacts": [{"path": artifact.name, "sha256": artifact_hash}],
                    "command_receipts": [
                        {
                            "command": "python -m unittest",
                            "exit_code": 0,
                            "output_artifact_path": command_output.name,
                            "output_sha256": command_output_hash,
                            "started_at": "2026-09-02T10:00:00+00:00",
                            "finished_at": "2026-09-02T10:00:01+00:00",
                            "working_directory": ".",
                            "tool_version": "python-test-runtime",
                            "environment_fingerprint": "b" * 64,
                            "result_summary": "Fixture command passed.",
                        }
                    ],
                    "git": {"dirty": False},
                    "known_risks": [],
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def test_app_server_token_usage_notification_uses_last_turn_without_reasoning_double_count(self):
        notification = {
            "method": "thread/tokenUsage/updated",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "tokenUsage": {
                    "last": {
                        "inputTokens": 100,
                        "cachedInputTokens": 40,
                        "outputTokens": 25,
                        "reasoningOutputTokens": 10,
                        "totalTokens": 125,
                    },
                    "total": {
                        "inputTokens": 999,
                        "cachedInputTokens": 0,
                        "outputTokens": 999,
                        "reasoningOutputTokens": 999,
                        "totalTokens": 1998,
                    },
                },
            },
        }
        usage = _usage_from_app_server_notification(notification, "thread-1", "turn-1")
        self.assertEqual(usage["total_tokens"], 125)
        self.assertEqual(usage["cached_input_tokens"], 40)
        self.assertEqual(usage["thinking_tokens"], 10)
        self.assertEqual(_normalized_usage({"inputTokens": 100, "outputTokens": 25, "reasoningOutputTokens": 10})["total_tokens"], 125)
        self.assertEqual(_usage_from_app_server_notification(notification, "other-thread", "turn-1"), {})

    @unittest.skipUnless(os.name == "nt", "Windows lock contention behavior")
    def test_windows_transient_permission_error_is_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "event.lock"
            real_open = os.open
            first = True

            def contested(path, flags, mode=0o777):
                nonlocal first
                if first:
                    first = False
                    raise PermissionError(13, "simulated Windows EACCES", str(path))
                return real_open(path, flags, mode)

            with patch("ithz_mcp.ccg.ledger.os.open", side_effect=contested):
                with _exclusive_lock(lock, timeout_seconds=1):
                    self.assertTrue(lock.exists())

    @unittest.skipUnless(__import__("os").name == "nt", "Windows launcher behavior")
    def test_windows_codex_launcher_resolves_tracked_runtime_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "codex.exe"
            runtime = root / "runtime-version" / "codex.exe"
            runtime.parent.mkdir()
            launcher.write_bytes(b"launcher")
            runtime.write_bytes(b"runtime")
            with patch("ithz_mcp.ccg.models.shutil.which", return_value=str(launcher)):
                self.assertEqual(_resolve_codex_app_server_executable("codex"), str(runtime.resolve()))

    def test_five_role_fallback_is_blind_and_token_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "README.md").write_text("# Demo\n\nRisk: writes must stay in the sandbox.\n", encoding="utf-8")
            backend = ScriptedBackend()
            runner = CourtRunner(project, codex_backend=backend)
            result = runner.run_case(
                "Create the bounded Slovak maintenance notice described by the demo contract.",
                "low",
                "file.write.sandboxed",
                "off",
            )

            self.assertEqual(result["final_verdict"], "ALLOW_WITH_LIMITS")
            self.assertFalse(result["cross_lab_quorum"])
            self.assertEqual(result["role_manifest"]["fallback_reason"], "cross_lab_disabled")
            self.assertTrue(result["ledger_verification"]["valid"])
            self.assertEqual(len({item["thread_id"] for item in result["role_manifest"].values() if isinstance(item, dict)}), 5)

            judge_prompt = next(call["prompt"] for call in backend.calls if call["role"] == "judge")
            self.assertNotIn("grok_disabled", judge_prompt)
            self.assertNotIn("scripted-court-v1", judge_prompt)
            self.assertNotIn("scripted-opponent", judge_prompt)

            token = result["capability_token"]
            execution = runner.execute_demo(result["case_id"], token)
            self.assertTrue(execution["executed"])
            target = project / ".ccg-sandbox" / "maintenance_notice.md"
            self.assertTrue(target.exists())
            self.assertIn("Plánovaná údržba", target.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "already_spent"):
                runner.execute_demo(result["case_id"], token)
            self.assertTrue(runner.ledger.verify(result["case_id"])["valid"])

    def test_high_risk_without_cross_lab_quorum_requires_human(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ScriptedBackend()
            runner = CourtRunner(Path(directory), codex_backend=backend)
            result = runner.run_case(
                "Prepare a bounded sandbox maintenance notice, classified high for this policy test.",
                "high",
                "file.write.sandboxed",
                "off",
            )
            self.assertEqual(result["semantic_verdict"], "ALLOW_WITH_LIMITS")
            self.assertEqual(result["final_verdict"], "REQUEST_EVIDENCE")
            self.assertIn("evidence_view_diversity_missing", result["formal_reasons"])
            self.assertIsNone(result["capability_token"])
            auditor_prompt = next(call["prompt"] for call in backend.calls if call["role"] == "auditor")
            self.assertIn("pending human approval is not by itself a process defect", auditor_prompt)
            self.assertIn('"completed_upstream_role_count": 4', auditor_prompt)
            self.assertIn('"judge_completed_before_auditor": true', auditor_prompt)

    def test_optional_blind_first_pass_is_sealed_before_proposal_and_metered_as_six_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            codex = ScriptedBackend("codex-blind-first")
            gemini = ScriptedBackend("gemini-blind-first")
            gemini.provider = "google"
            runner = CourtRunner(Path(directory), codex_backend=codex, gemini_backend=gemini)
            result = runner.run_case(
                "Review a bounded read-only task with an independent first pass.",
                "low",
                "analysis.read",
                opponent_2="gemini",
                blind_first_pass=True,
            )
            self.assertTrue(result["independent_first_pass"])
            self.assertEqual(result["model_runs"], 6)
            self.assertIn("opponent_blind_first", result["role_manifest"])
            calls = codex.calls + gemini.calls
            first = next(item for item in calls if item["role"] == "opponent_blind_first")
            self.assertNotIn("PROPOSAL:", first["prompt"])
            events = runner.ledger.read_case(result["case_id"], include_events=True)["events"]
            self.assertIn("blind_first_pass_sealed", [event["event_type"] for event in events])

    def test_preexisting_demo_target_is_not_overwritten_and_spends_token(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            target = project / ".ccg-sandbox" / "maintenance_notice.md"
            target.parent.mkdir(parents=True)
            target.write_text("original\n", encoding="utf-8")
            runner = CourtRunner(project, codex_backend=ScriptedBackend())
            result = runner.run_case("Create the bounded demo notice.", "low", "file.write.sandboxed", "off")
            token = result["capability_token"]
            with self.assertRaisesRegex(ValueError, "overwrite_not_authorized"):
                runner.execute_demo(result["case_id"], token)
            self.assertEqual(target.read_text(encoding="utf-8"), "original\n")
            with self.assertRaisesRegex(ValueError, "already_spent"):
                runner.execute_demo(result["case_id"], token)

    def test_unknown_capability_never_receives_token(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = CourtRunner(Path(directory), codex_backend=ScriptedBackend())
            result = runner.run_case("Review an unknown bounded operation.", "low", "unknown.operation", "off")
            self.assertEqual(result["final_verdict"], "REQUEST_EVIDENCE")
            self.assertIsNone(result["capability_token"])

    def test_event_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = CourtRunner(Path(directory), codex_backend=ScriptedBackend())
            result = runner.run_case("Create the bounded demo notice.", "low", "file.write.sandboxed", "off")
            path = runner.ledger.case_dir(result["case_id"]) / "events.jsonl"
            rows = path.read_text(encoding="utf-8").splitlines()
            event = json.loads(rows[2])
            event["payload"]["tampered"] = True
            rows[2] = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            path.write_text("\n".join(rows) + "\n", encoding="utf-8")
            verification = runner.ledger.verify(result["case_id"])
            self.assertFalse(verification["valid"])
            self.assertTrue(any("event_hash_mismatch" in error for error in verification["errors"]))

    def test_initialize_does_not_overwrite_existing_constitution(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            first = initialize_project(project)
            path = project / ".ccg" / "constitution.json"
            before = path.read_bytes()
            second = initialize_project(project)
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertEqual(path.read_bytes(), before)

    def test_stable_role_prefix_is_reused_but_case_packet_stays_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ScriptedBackend()
            runner = CourtRunner(Path(directory), codex_backend=backend)
            first = runner.run_case("Review bounded case alpha.", "low", "unknown.operation", "off", reuse_decision="off")
            second = runner.run_case("Review bounded case beta.", "low", "unknown.operation", "off", reuse_decision="off")
            prompts = [call for call in backend.calls if call["role"] == "proposer"]
            self.assertEqual(len(prompts), 2)
            marker = "--- CASE-SPECIFIC PACKET FOLLOWS ---"
            self.assertEqual(prompts[0]["prompt"].split(marker)[0], prompts[1]["prompt"].split(marker)[0])
            self.assertEqual(prompts[0]["template_hash"], prompts[1]["template_hash"])
            self.assertNotEqual(first["evidence_hash"], second["evidence_hash"])
            self.assertEqual(len({item["thread_id"] for item in first["role_manifest"].values() if isinstance(item, dict)}), 5)

    def test_unchanged_non_authorizing_material_reuses_verified_decision_without_model_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ScriptedBackend()
            runner = CourtRunner(Path(directory), codex_backend=backend)
            first = runner.run_case("Review the same unknown operation.", "low", "unknown.operation", "off")
            calls_after_first = len(backend.calls)
            second = runner.run_case("Review the same unknown operation.", "low", "unknown.operation", "off")
            self.assertEqual(calls_after_first, 5)
            self.assertEqual(len(backend.calls), calls_after_first)
            self.assertTrue(second["reused_decision"])
            self.assertEqual(second["source_case_id"], first["case_id"])
            self.assertEqual(second["decision_material_hash"], first["decision_material_hash"])
            self.assertNotEqual(second["evidence_hash"], first["evidence_hash"])
            self.assertIsNone(second["capability_token"])
            self.assertTrue(second["ledger_verification"]["valid"])

    def test_authorization_is_never_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ScriptedBackend()
            runner = CourtRunner(Path(directory), codex_backend=backend)
            first = runner.run_case("Create the bounded demo notice.", "low", "file.write.sandboxed", "off")
            second = runner.run_case("Create the bounded demo notice.", "low", "file.write.sandboxed", "off")
            self.assertFalse(first["reused_decision"])
            self.assertFalse(second["reused_decision"])
            self.assertEqual(len(backend.calls), 10)
            self.assertNotEqual(first["capability_token"], second["capability_token"])

    def test_gemini_is_cross_lab_opponent_and_daybreak_can_take_primary_security_role(self):
        with tempfile.TemporaryDirectory() as directory:
            codex = ScriptedBackend("codex-test")
            gemini = ScriptedBackend("gemini-3.7-flash")
            gemini.provider = "google"
            daybreak = ScriptedBackend("gpt-daybreak-blue-latest")
            daybreak.provider = "openai"
            runner = CourtRunner(
                Path(directory),
                codex_backend=codex,
                gemini_backend=gemini,
                daybreak_backend=daybreak,
            )
            result = runner.run_case(
                "Review a high-risk security boundary.",
                "high",
                "unknown.operation",
                "auto",
                "required",
                "off",
                "gemini",
            )
            self.assertTrue(result["cross_lab_quorum"])
            self.assertEqual(result["role_manifest"]["opponent_1"]["model"], "gpt-daybreak-blue-latest")
            self.assertEqual(result["role_manifest"]["opponent_2"]["provider"], "google")
            self.assertEqual(result["role_manifest"]["opponent_2"]["model"], "gemini-3.7-flash")

    def test_final_case_is_checkpoint_bound_cross_lab_metered_and_single_run(self):
        with tempfile.TemporaryDirectory() as directory:
            codex = ScriptedBackend("codex-test")
            gemini = ScriptedBackend("gemini-test")
            gemini.provider = "google"
            runner = CourtRunner(Path(directory), codex_backend=codex, gemini_backend=gemini)
            checkpoint_hash = "a" * 64
            review_manifest = self._final_review_manifest(Path(directory), checkpoint_hash)
            projection = {"memory_synthesis_hash": checkpoint_hash}
            with patch("ithz_mcp.ccg.court.native_archive_current_projection", return_value=projection) as current:
                first = runner.run_final_case("Review the completed task.", checkpoint_hash, "gemini", str(review_manifest))
                calls_after_first = len(codex.calls) + len(gemini.calls)
                second = runner.run_final_case("Do not run this checkpoint twice.", checkpoint_hash, "gemini")

            self.assertEqual(calls_after_first, 5)
            self.assertEqual(len(codex.calls) + len(gemini.calls), 5)
            self.assertTrue(first["cross_lab_quorum"])
            self.assertTrue(first["provider_usage"]["complete"])
            self.assertEqual(first["provider_usage"]["metered_model_calls"], 5)
            self.assertEqual(first["final_case_contract"]["capability"], "analysis.read")
            self.assertTrue(first["final_case_contract"]["review_evidence_manifest"]["artifact_hashes_runtime_verified"])
            self.assertTrue(first["final_case_contract"]["review_evidence_manifest"]["command_outputs_runtime_verified"])
            self.assertTrue(any("CURRENT FINAL CASE POSTFLIGHT CONTRACT" in call["prompt"] for call in codex.calls))
            cross_prompt = next(call["prompt"] for call in gemini.calls if call["role"] == "opponent_cross")
            self.assertIn("raw_first_memory_disabled_control", cross_prompt)
            self.assertNotIn('"ithz_current_projection"', cross_prompt)
            self.assertFalse(first["existing_final_case_reused"])
            self.assertTrue(second["existing_final_case_reused"])
            self.assertEqual(second["model_runs"], 0)
            self.assertEqual(second["source_case_id"], first["case_id"])
            self.assertEqual(current.call_count, 1)

            status = runner.status()
            self.assertEqual(status["schema"], "ccg_ithz_status_v2")
            self.assertEqual(status["latest_final_case"]["case_id"], first["case_id"])
            self.assertEqual(status["latest_final_case"]["model_runs"], 5)
            self.assertTrue(status["latest_final_case"]["provider_usage"]["complete"])
            self.assertEqual(status["latest_final_case"]["provider_usage"]["metered_model_calls"], 5)
            self.assertEqual(status["provider_usage"]["scope"], "historical_all_cases")
            self.assertNotIn("missing_roles", status["provider_usage"])
            self.assertEqual(status["provider_usage"]["missing_role_count"], 0)

    def test_final_case_preflight_blocks_stale_checkpoint_or_missing_cross_lab_before_models(self):
        with tempfile.TemporaryDirectory() as directory:
            codex = ScriptedBackend("codex-test")
            runner = CourtRunner(Path(directory), codex_backend=codex)
            runner.gemini = None
            with patch(
                "ithz_mcp.ccg.court.native_archive_current_projection",
                return_value={"memory_synthesis_hash": "b" * 64},
            ):
                with self.assertRaisesRegex(BackendError, "checkpoint_hash_mismatch"):
                    runner.run_final_case("Review stale evidence.", "a" * 64, "gemini")
                with self.assertRaisesRegex(BackendError, "gemini_not_configured"):
                    runner.run_final_case("Review current evidence.", "b" * 64, "gemini")
            self.assertEqual(codex.calls, [])

    def test_final_case_preflight_blocks_missing_or_changed_review_manifest_before_models(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex = ScriptedBackend("codex-test")
            gemini = ScriptedBackend("gemini-test")
            gemini.provider = "google"
            runner = CourtRunner(root, codex_backend=codex, gemini_backend=gemini)
            checkpoint_hash = "c" * 64
            with patch(
                "ithz_mcp.ccg.court.native_archive_current_projection",
                return_value={"memory_synthesis_hash": checkpoint_hash},
            ):
                with self.assertRaisesRegex(BackendError, "final_review_manifest_required"):
                    runner.run_final_case("Review missing evidence.", checkpoint_hash, "gemini")
                manifest = self._final_review_manifest(root, checkpoint_hash)
                (root / "reviewed-artifact.txt").write_text("changed after manifest\n", encoding="utf-8")
                with self.assertRaisesRegex(BackendError, "final_review_manifest_artifact_hash_mismatch"):
                    runner.run_final_case("Review stale evidence.", checkpoint_hash, "gemini", str(manifest))
            self.assertEqual(codex.calls, [])
            self.assertEqual(gemini.calls, [])

    def test_final_case_requires_v2_and_runtime_verifies_command_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex = ScriptedBackend("codex-test")
            gemini = ScriptedBackend("gemini-test")
            gemini.provider = "google"
            runner = CourtRunner(root, codex_backend=codex, gemini_backend=gemini)
            checkpoint_hash = "d" * 64
            manifest = self._final_review_manifest(root, checkpoint_hash)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["schema"] = "ccg_final_review_manifest_v1"
            for receipt in payload["command_receipts"]:
                for field in (
                    "output_artifact_path",
                    "started_at",
                    "finished_at",
                    "working_directory",
                    "tool_version",
                    "environment_fingerprint",
                ):
                    receipt.pop(field, None)
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with patch(
                "ithz_mcp.ccg.court.native_archive_current_projection",
                return_value={"memory_synthesis_hash": checkpoint_hash},
            ):
                with self.assertRaisesRegex(BackendError, "final_review_manifest_v2_required"):
                    runner.run_final_case("Review legacy manifest.", checkpoint_hash, "gemini", str(manifest))

                manifest = self._final_review_manifest(root, checkpoint_hash)
                (root / "unittest-output.txt").write_text("tampered\n", encoding="utf-8")
                with self.assertRaisesRegex(BackendError, "command_output_hash_mismatch"):
                    runner.run_final_case("Review tampered output.", checkpoint_hash, "gemini", str(manifest))
            self.assertEqual(codex.calls, [])
            self.assertEqual(gemini.calls, [])

    def test_daybreak_auto_failure_is_recorded_before_codex_fallback(self):
        class FailingBackend:
            provider = "openai"
            model = "gpt-daybreak-blue-latest"

            def run(self, *args, **kwargs):
                raise BackendError("daybreak_unavailable")

        with tempfile.TemporaryDirectory() as directory:
            runner = CourtRunner(
                Path(directory),
                codex_backend=ScriptedBackend(),
                daybreak_backend=FailingBackend(),
            )
            result = runner.run_case(
                "Review a high-risk fallback boundary.",
                "high",
                "unknown.operation",
                "off",
                "auto",
                "off",
                "off",
            )
            self.assertEqual(result["role_manifest"]["daybreak_fallback_reason"], "daybreak_failed:BackendError")
            self.assertEqual(result["role_manifest"]["opponent_1"]["model"], "scripted-court-v1")


if __name__ == "__main__":
    unittest.main()
