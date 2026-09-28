"""Independent MCP38 adversarial acceptance tests, with no external providers."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ithz_mcp import development_workflow as workflow
from ithz_mcp import mcp_server


class WorkflowAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        self.store = Path(self.temp.name) / "external-state"
        self.git("init", "-q")
        self.git("config", "user.name", "Workflow fixture")
        self.git("config", "user.email", "workflow@example.invalid")
        self.git("config", "core.autocrlf", "false")
        (self.root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (self.root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.root / "acceptance.py").write_text(
            "import unittest\nimport app\n"
            "class Acceptance(unittest.TestCase):\n"
            "    def test_value(self): self.assertEqual(app.VALUE, 2)\n"
            "if __name__ == '__main__': unittest.main()\n", encoding="utf-8")
        (self.root / "unrelated.txt").write_text("original\n", encoding="utf-8")
        self.commit()
        self.git("branch", "base")
        self.contract = {
            "schema": "ithz_workflow_contract_v1",
            "goal": "Make VALUE equal 2 and prove it with an independent acceptance check.",
            "allowed_paths": ["app.py", "tests"],
            "protected_paths": ["unrelated.txt"],
            "invariants": ["Do not change unrelated behavior or acceptance criteria."],
            "acceptance": ["VALUE equals 2."],
            "checks": [{"id": "acceptance", "argv": [sys.executable, "acceptance.py"],
                        "timeout_seconds": 10, "min_tests": 1, "parser": "unittest",
                        "verifier_paths": ["acceptance.py"]}],
            "review": {"required": False, "base_ref": "base", "context_paths": []},
            "limits": {"max_repairs": 2, "max_seconds": 120, "max_check_runs": 3,
                       "model_calls": 0, "cost_microunits": 0, "concurrency": 1},
            "allowed_actions": ["local_implementation", "local_checks"],
            "final_action": {"kind": "handoff", "target": "local diff", "authorized": True},
        }

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.STDOUT)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def prepare(self, contract=None):
        return workflow.prepare(self.root, contract or self.contract, store_root=self.store)

    def implement(self, workflow_id, content="VALUE = 2\n"):
        started = workflow.begin_step(self.root, workflow_id, store_root=self.store)
        (self.root / "app.py").write_text(content, encoding="utf-8")
        return workflow.record_result(self.root, workflow_id, started["pending_attempt"]["id"], store_root=self.store)

    def test_plan_does_not_write_project_or_state(self):
        before = {str(p.relative_to(self.root)): p.read_bytes()
                  for p in self.root.rglob("*") if p.is_file() and ".git" not in p.parts}
        result = workflow.plan(self.root, self.contract)
        self.assertTrue(result)
        self.assertFalse(self.store.exists())
        after = {str(p.relative_to(self.root)): p.read_bytes()
                 for p in self.root.rglob("*") if p.is_file() and ".git" not in p.parts}
        self.assertEqual(before, after)
        self.assertEqual(self.git("status", "--porcelain"), b"")

    def test_model_calls_and_parallelism_cannot_be_authorized_by_contract(self):
        for field, value in [("model_calls", 1), ("concurrency", 2), ("max_repairs", 4),
                             ("max_seconds", 0), ("max_check_runs", 0), ("cost_microunits", 1)]:
            with self.subTest(field=field):
                contract = copy.deepcopy(self.contract)
                contract["limits"][field] = value
                with self.assertRaises(ValueError):
                    workflow.plan(self.root, contract)

    def test_relative_path_traversal_and_git_storage_never_become_scope(self):
        for path in ["../outside.py", ".git/config", ".GIT/config", "C:/outside.py", "/outside.py", "app.py/../acceptance.py"]:
            with self.subTest(path=path):
                contract = copy.deepcopy(self.contract)
                contract["allowed_paths"] = [path]
                with self.assertRaises(ValueError):
                    workflow.plan(self.root, contract)

    def test_shell_operators_are_arguments_and_execution_requires_authorization(self):
        result = self.prepare()
        workflow_id = result["workflow_id"]
        with patch.object(workflow.subprocess, "run", side_effect=AssertionError("check must not execute")):
            with self.assertRaises(ValueError):
                workflow.run_check(self.root, workflow_id, "acceptance", store_root=self.store)

    def test_preparation_requires_isolated_git_root_but_planning_still_works(self):
        child = self.root / "nested"
        child.mkdir()
        self.assertTrue(workflow.plan(child, self.contract))
        with self.assertRaises(ValueError):
            workflow.prepare(child, self.contract, store_root=self.store)

    def test_state_store_inside_project_is_rejected(self):
        with self.assertRaises(ValueError):
            workflow.prepare(self.root, self.contract, store_root=self.root / ".workflow-state")

    def test_no_independent_test_check_cannot_make_an_executable_contract(self):
        contract = copy.deepcopy(self.contract)
        contract["checks"][0].update(parser="exit", min_tests=0)
        with self.assertRaises(ValueError):
            workflow.prepare(self.root, contract, store_root=self.store)

    def test_unknown_contract_keys_do_not_silently_expand_authority(self):
        contract = copy.deepcopy(self.contract)
        contract["auto_deploy"] = True
        with self.assertRaises(ValueError):
            workflow.prepare(self.root, contract, store_root=self.store)

    def test_non_git_intake_can_still_describe_a_plan(self):
        project = Path(self.temp.name) / "plain-project"
        project.mkdir()
        result = workflow.plan(project, self.contract)
        self.assertTrue(result)
        self.assertFalse(self.store.exists())

    def test_frozen_verifier_cannot_be_changed_even_with_tests_in_allowed_scope(self):
        contract = copy.deepcopy(self.contract)
        contract["allowed_paths"].append("acceptance.py")
        prepared = self.prepare(contract)
        workflow_id = prepared["workflow_id"]
        started = workflow.begin_step(self.root, workflow_id, store_root=self.store)
        (self.root / "acceptance.py").write_text(
            "import unittest\nclass Fake(unittest.TestCase):\n"
            "    def test_anything(self): pass\nunittest.main()\n", encoding="utf-8")
        try:
            result = workflow.record_result(self.root, workflow_id, started["pending_attempt"]["id"], store_root=self.store)
        except ValueError:
            return
        self.assertEqual(result["state"], "blocked")

    def test_out_of_scope_untracked_file_blocks_result(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        started = workflow.begin_step(self.root, workflow_id, store_root=self.store)
        (self.root / "outside.py").write_text("unauthorized = True\n", encoding="utf-8")
        try:
            result = workflow.record_result(self.root, workflow_id, started["pending_attempt"]["id"], store_root=self.store)
        except ValueError:
            return
        self.assertEqual(result["state"], "blocked")

    def test_attempt_identity_cannot_be_replayed(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        started = workflow.begin_step(self.root, workflow_id, store_root=self.store)
        (self.root / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        workflow.record_result(self.root, workflow_id, started["pending_attempt"]["id"], store_root=self.store)
        with self.assertRaises(ValueError):
            workflow.record_result(self.root, workflow_id, started["pending_attempt"]["id"], store_root=self.store)

    def test_workflow_identity_is_bound_to_project_and_cannot_cross_contexts(self):
        prepared = self.prepare()
        sibling = Path(self.temp.name) / "sibling"
        sibling.mkdir()
        with self.assertRaises(ValueError):
            workflow.status(sibling, prepared["workflow_id"], store_root=self.store)

    def test_cancel_is_terminal_for_check_execution(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        workflow.cancel(self.root, workflow_id, store_root=self.store)
        with self.assertRaises(ValueError):
            workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)

    def test_corrupt_state_fails_closed(self):
        prepared = self.prepare()
        states = list(self.store.rglob("state.json"))
        self.assertEqual(len(states), 1)
        states[0].write_text('{"state":"ready_for_approval"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            workflow.status(self.root, prepared["workflow_id"], store_root=self.store)

    def test_zero_tests_never_prove_acceptance(self):
        (self.root / "acceptance.py").write_text("import unittest\nunittest.main()\n", encoding="utf-8")
        self.commit()
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id)
        result = workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        self.assertFalse(result["ready_for_approval"])
        self.assertEqual(result["check_receipts"]["acceptance"]["tests_run"], 0)
        self.assertIn("workflow_check_insufficient_tests", result["blockers"])

    def test_unchanged_failed_input_cannot_be_rerolled_by_new_commit(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id, "VALUE = 3\n")
        failure = workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        self.assertEqual(failure["state"], "correcting")
        started = workflow.begin_step(self.root, workflow_id, store_root=self.store)
        self.git("commit", "--allow-empty", "-qm", "metadata change is not a repair")
        result = workflow.record_result(self.root, workflow_id, started["pending_attempt"]["id"], store_root=self.store)
        self.assertEqual(result["state"], "blocked")
        self.assertIn("workflow_unchanged_failed_snapshot", result["blockers"])

    def test_staged_diff_change_invalidates_passing_content_snapshot(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id)
        passed = workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        self.assertTrue(passed["ready_for_approval"])
        (self.root / "app.py").write_text("VALUE = 999\n", encoding="utf-8")
        self.git("add", "app.py")
        (self.root / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        result = workflow.status(self.root, workflow_id, store_root=self.store)
        self.assertFalse(result["ready_for_approval"], "Changed staged Git diff must invalidate handoff evidence")
        self.assertFalse(result["evidence_current"])

    def test_prior_review_is_revalidated_when_readiness_is_requested(self):
        contract = copy.deepcopy(self.contract)
        contract["review"]["required"] = True
        prepared = self.prepare(contract)
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id)
        checked = workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        self.assertEqual(checked["state"], "reviewing")
        with patch("ithz_mcp.ccg.code_review.gate", return_value={"ready_for_pr": True, "errors": [], "evidence_hash": "accepted-review"}):
            reviewed = workflow.record_review(self.root, workflow_id, store_root=self.store)
        self.assertTrue(reviewed["ready_for_approval"])
        with patch("ithz_mcp.ccg.code_review.gate", return_value={"ready_for_pr": False, "errors": ["review_missing_or_stale"]}):
            result = workflow.status(self.root, workflow_id, store_root=self.store)
        self.assertFalse(result["ready_for_approval"], "Lost MCP37 receipt cannot preserve readiness")

    def test_interrupted_check_cannot_execute_twice_on_resume(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id)
        actual_popen = subprocess.Popen
        executions = []

        def interrupted(args, *positional, **kwargs):
            if args[0] == sys.executable:
                executions.append(args)
                raise RuntimeError("simulated process death after durable check reservation")
            return actual_popen(args, *positional, **kwargs)

        with patch.object(workflow.subprocess, "Popen", side_effect=interrupted):
            with self.assertRaises(RuntimeError):
                workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        result = workflow.resume(self.root, workflow_id, store_root=self.store)
        self.assertEqual(result["state"], "blocked")
        self.assertIn("workflow_interrupted_check_outcome_unknown_no_automatic_retry", result["blockers"])
        with self.assertRaises(ValueError):
            workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        self.assertEqual(len(executions), 1)

    def test_existing_project_lock_blocks_another_workflow_and_is_preserved(self):
        first = self.prepare()
        second = self.prepare()
        lock = Path(first["evidence_directory"]).parent / "mutation.lock"
        lock.write_text("external owner", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "locked_or_interrupted"):
            workflow.begin_step(self.root, second["workflow_id"], store_root=self.store)
        self.assertEqual(lock.read_text(encoding="utf-8"), "external owner")

    def test_staged_protected_verifier_change_cannot_hide_behind_original_worktree(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        started = workflow.begin_step(self.root, workflow_id, store_root=self.store)
        verifier = self.root / "acceptance.py"
        original = verifier.read_bytes()
        verifier.write_text("print('unverified staged harness')\n", encoding="utf-8")
        self.git("add", "acceptance.py")
        verifier.write_bytes(original)
        (self.root / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        result = workflow.record_result(self.root, workflow_id, started["pending_attempt"]["id"], store_root=self.store)
        self.assertEqual(result["state"], "blocked", "Frozen verifier protection also applies to Git index")

    def test_mcp_stdio_exposes_plan_and_enforces_read_only_mutation_boundary(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "ithz_workflow_plan", "arguments": {"goal": "Repair VALUE", "allowed_paths": ["app.py"], "checks": ["Independent VALUE acceptance test"]}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "ithz_workflow_prepare", "arguments": {"contract": self.contract, "store_root": str(self.store)}}},
        ]
        result = subprocess.run([sys.executable, "-m", "ithz_mcp", "mcp-server", "--project", str(self.root), "--storage-profile", "native-archive"],
                                input="".join(json.dumps(request) + "\n" for request in requests), text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = {reply["id"]: reply for reply in map(json.loads, result.stdout.splitlines())}
        self.assertIn("ithz_workflow_plan", replies[1]["result"]["instructions"])
        names = {tool["name"] for tool in replies[2]["result"]["tools"]}
        self.assertIn("ithz_workflow_plan", names)
        self.assertNotIn("ithz_workflow_prepare", names)
        plan = replies[3]["result"]["structuredContent"]
        self.assertTrue(plan["steps"])
        self.assertTrue(plan["approval_boundaries"]["roles_do_not_authorize_spawning"])
        self.assertEqual(plan["steps"][1]["allowed_paths"], ["app.py"])
        self.assertIn("error", replies[4])
        self.assertFalse(self.store.exists())

    def test_cli_lightweight_intake_outputs_concrete_plan(self):
        result = subprocess.run([sys.executable, "-m", "ithz_mcp", "workflow-plan", "--project", str(self.root), "--goal", "Repair VALUE", "--allowed-path", "app.py", "--check", "Run VALUE acceptance"], text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["goal"], "Repair VALUE")
        self.assertTrue(plan["steps"])
        self.assertFalse(plan["execution_contract_prepared"])
        self.assertFalse(self.store.exists())

    def test_mcp_claimed_success_is_rejected_without_advancing_state(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        started = workflow.begin_step(self.root, workflow_id, store_root=self.store)
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "ithz_workflow_record_result", "arguments": {"workflow_id": workflow_id, "store_root": str(self.store), "attempt_id": started["pending_attempt"]["id"], "passed": True}}}
        reply = mcp_server.handle_line(json.dumps(request), self.root, "native-archive", "write-enabled")
        self.assertIn("error", reply)
        self.assertEqual(workflow.status(self.root, workflow_id, store_root=self.store)["state"], "implementing")

    @unittest.skipUnless(os.name == "nt", "Windows path identity")
    def test_protected_path_alias_case_cannot_bypass_windows_identity(self):
        contract = copy.deepcopy(self.contract)
        contract["protected_paths"].append("APP.PY")
        prepared = self.prepare(contract)
        result = self.implement(prepared["workflow_id"])
        self.assertEqual(result["state"], "blocked")

    def test_same_failing_check_stops_despite_variable_diagnostic_output(self):
        verifier = self.root / "acceptance.py"
        verifier.write_text(verifier.read_text(encoding="utf-8").replace("import unittest", "import time\nprint(time.time())\nimport unittest"), encoding="utf-8")
        self.commit()
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id, "VALUE = 3\n")
        first = workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        self.assertEqual(first["state"], "correcting")
        self.implement(workflow_id, "VALUE = 3\n# A comment does not repair the assertion.\n")
        second = workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        self.assertEqual(second["state"], "blocked")
        self.assertIn("workflow_repeated_finding_no_progress", second["blockers"])

    def test_missing_multipart_review_evidence_does_not_request_source_repair(self):
        contract = copy.deepcopy(self.contract)
        contract["review"]["required"] = True
        prepared = self.prepare(contract)
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id)
        workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        with patch("ithz_mcp.ccg.code_review.gate", return_value={"ready_for_pr": False, "errors": ["manifest_missing_or_invalid", "review_missing_or_stale"]}):
            result = workflow.record_review(self.root, workflow_id, store_root=self.store)
        self.assertNotEqual(result["state"], "correcting", "Unavailable review evidence cannot be repaired by changing code")
        self.assertEqual(result["remaining"]["repairs"], contract["limits"]["max_repairs"])
        self.assertFalse(result["ready_for_approval"])

    def test_review_gate_snapshot_change_during_validation_cannot_return_ready(self):
        contract = copy.deepcopy(self.contract)
        contract["review"]["required"] = True
        prepared = self.prepare(contract)
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id)
        workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)

        def changed_during_gate(*args, **kwargs):
            (self.root / "app.py").write_text("VALUE = 3\n", encoding="utf-8")
            return {"ready_for_pr": True, "errors": [], "evidence_hash": "old-review"}

        with patch("ithz_mcp.ccg.code_review.gate", side_effect=changed_during_gate):
            result = workflow.record_review(self.root, workflow_id, store_root=self.store)
        self.assertFalse(result["ready_for_approval"], "Concurrent source change must invalidate returned review readiness")

    def test_output_overflow_cannot_create_a_passing_receipt_or_leave_raw_log(self):
        verifier = self.root / "acceptance.py"
        verifier.write_text("print('x' * 4096)\n" + verifier.read_text(encoding="utf-8"), encoding="utf-8")
        self.commit()
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        self.implement(workflow_id)
        with patch.object(workflow, "MAX_LOG_BYTES", 128):
            result = workflow.run_check(self.root, workflow_id, "acceptance", execution_authorized=True, store_root=self.store)
        self.assertFalse(result["ready_for_approval"])
        self.assertIn("workflow_check_output_limit_exceeded", result["blockers"])
        evidence = Path(prepared["evidence_directory"]) / "evidence"
        self.assertFalse(list(evidence.rglob("*.raw")))
        self.assertTrue(all(path.stat().st_size <= 128 for path in evidence.rglob("output.txt")))

    def test_atomic_write_failure_preserves_last_complete_state(self):
        prepared = self.prepare()
        workflow_id = prepared["workflow_id"]
        location = Path(prepared["evidence_directory"])
        before = (location / "state.json").read_bytes()
        with patch.object(workflow.os, "replace", side_effect=OSError("simulated atomic replacement failure")):
            with self.assertRaises(OSError):
                workflow.begin_step(self.root, workflow_id, store_root=self.store)
        self.assertEqual((location / "state.json").read_bytes(), before)
        self.assertFalse(list(location.glob(".state-*.tmp")))
        state = workflow.status(self.root, workflow_id, store_root=self.store)
        self.assertEqual(state["state"], "planned")
        self.assertFalse(state["mutation_locked"])


if __name__ == "__main__":
    unittest.main()
