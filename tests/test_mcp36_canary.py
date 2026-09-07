import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ithz_mcp.ccg.court import CourtRunner
from ithz_mcp.ccg.models import BackendError, ScriptedBackend
from ithz_mcp.mcp36_canary import (
    CanaryGateError,
    canary_admission,
    canary_status,
    enable_canary,
    pause_canary,
    reserve_canary_slot,
    run_canary_control_selftest,
)


class MCP364CanaryTests(unittest.TestCase):
    def test_default_off_enable_limit_pause_and_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            now = datetime(2026, 9, 2, 10, 0, tzinfo=timezone.utc)
            default = canary_status(project, now=now)
            self.assertFalse(default["configured"])
            self.assertFalse(default["active"])
            self.assertEqual(default["reason"], "canary_not_configured")

            enabled = enable_canary(project, max_cases=1, expires_hours=1, now=now)
            self.assertTrue(enabled["active"])
            self.assertEqual(enabled["allowed_capabilities"], ["analysis.read"])
            admission = canary_admission(
                project,
                risk="high",
                capability="analysis.read",
                cross_lab_provider="gemini",
                now=now,
            )
            reserve_canary_slot(project, admission, now=now)
            limited = canary_status(project, now=now)
            self.assertEqual(limited["reason"], "canary_case_limit_reached")
            with self.assertRaisesRegex(CanaryGateError, "case_limit_reached"):
                reserve_canary_slot(project, admission, now=now)

            paused = pause_canary(project, now=now + timedelta(minutes=1))
            self.assertEqual(paused["state"], "paused")
            self.assertTrue(paused["telemetry_valid"])
            self.assertFalse(paused["active"])

            expired_project = project / "expired"
            enable_canary(expired_project, max_cases=1, expires_hours=1, now=now)
            expired = canary_status(expired_project, now=now + timedelta(hours=2))
            self.assertEqual(expired["reason"], "canary_expired")

    def test_capability_provider_and_tamper_fail_before_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            enable_canary(project, max_cases=2, expires_hours=1)
            with self.assertRaisesRegex(CanaryGateError, "capability_must_be_analysis_read"):
                canary_admission(
                    project,
                    risk="low",
                    capability="file.write.sandboxed",
                    cross_lab_provider="gemini",
                )
            with self.assertRaisesRegex(CanaryGateError, "provider_must_be_gemini_or_grok"):
                canary_admission(
                    project,
                    risk="low",
                    capability="analysis.read",
                    cross_lab_provider="off",
                )
            config_path = project / ".ccg" / "mcp36-canary" / "config.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["max_cases"] = 25
            config_path.write_text(json.dumps(config), encoding="utf-8")
            status = canary_status(project)
            self.assertFalse(status["telemetry_valid"])
            self.assertEqual(status["reason"], "canary_config_hash_mismatch")

    def test_scripted_court_canary_is_fresh_metered_and_never_mirrored(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            codex = ScriptedBackend("codex-canary-test")
            gemini = ScriptedBackend("gemini-canary-test")
            gemini.provider = "google"
            runner = CourtRunner(project, codex_backend=codex, gemini_backend=gemini)

            with self.assertRaisesRegex(BackendError, "canary_not_configured"):
                runner.run_canary_case("Review the bounded read-only architecture.")
            self.assertEqual(len(codex.calls) + len(gemini.calls), 0)

            runner.enable_canary(max_cases=1, expires_hours=1)
            with patch.object(runner, "_mirror_summary_to_ithz", side_effect=AssertionError("mirror must not run")):
                result = runner.run_canary_case("Review the bounded read-only architecture.")

            self.assertEqual(len(codex.calls) + len(gemini.calls), 5)
            self.assertEqual(result["model_runs"], 5)
            self.assertTrue(result["cross_lab_quorum"])
            self.assertTrue(result["provider_usage"]["complete"])
            self.assertTrue(result["evidence_diversity_receipt"]["structurally_valid"])
            self.assertFalse(result["evidence_diversity_receipt"]["evidence_sufficient"])
            self.assertEqual(result["final_verdict"], "REQUEST_EVIDENCE")
            self.assertTrue(result["advisory_only"])
            self.assertIsNone(result["capability_token"])
            self.assertIsNone(result["authorization"])
            self.assertEqual(result["ithz_mirror"], {"mirrored": False, "reason": "mcp36_canary_read_only"})
            self.assertFalse(result["canary_receipt"]["ithz_mirrored"])
            self.assertEqual(result["canary_status"]["completed_cases"], 1)
            self.assertEqual(result["canary_status"]["reason"], "canary_case_limit_reached")

            calls = len(codex.calls) + len(gemini.calls)
            with self.assertRaisesRegex(BackendError, "case_limit_reached"):
                runner.run_canary_case("This second case must be blocked before models.")
            self.assertEqual(len(codex.calls) + len(gemini.calls), calls)

    def test_same_provider_is_rejected_before_slot_or_models(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            codex = ScriptedBackend("codex")
            gemini = ScriptedBackend("not-independent")
            runner = CourtRunner(project, codex_backend=codex, gemini_backend=gemini)
            runner.enable_canary(max_cases=1, expires_hours=1)
            with self.assertRaisesRegex(BackendError, "not_independent"):
                runner.run_canary_case("Reject a false cross-lab quorum.")
            self.assertEqual(len(codex.calls) + len(gemini.calls), 0)
            self.assertEqual(runner.canary_status()["remaining_slots"], 1)

    def test_internal_canary_contract_cannot_widen_runtime_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ScriptedBackend("codex")
            runner = CourtRunner(Path(directory), codex_backend=backend)
            forged = {
                "schema": "mcp36_canary_case_contract_v1",
                "mode": "shadow-read-only",
                "capability": "analysis.read",
                "ithz_mirror": False,
                "capability_tokens_forbidden": True,
            }
            with self.assertRaisesRegex(ValueError, "runtime_scope_invalid"):
                runner.run_case(
                    "Attempt to widen a forged canary.",
                    "low",
                    "file.write.sandboxed",
                    "off",
                    reuse_decision="off",
                    opponent_2="off",
                    canary_contract=forged,
                )
            self.assertEqual(backend.calls, [])

    def test_control_selftest_is_local(self):
        result = run_canary_control_selftest()
        self.assertTrue(result["passed"])
        self.assertEqual(result["external_model_calls"], 0)
        self.assertEqual(result["external_writes"], 0)


if __name__ == "__main__":
    unittest.main()
