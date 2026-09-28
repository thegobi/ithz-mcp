"""MCP38 real local checks and transport compatibility; no provider calls."""
import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ithz_mcp import development_workflow as wf
from ithz_mcp.cli import main
from ithz_mcp.mcp_server import handle_line, serve_stdio


class DevelopmentWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "checkout"
        self.root.mkdir()
        self.store = self.base / "runtime"
        self.git("init", "-q")
        self.git("config", "user.name", "Workflow Fixture")
        self.git("config", "user.email", "workflow@example.invalid")
        (self.root / ".gitignore").write_text("__pycache__/\n.ithz-ccg/\n", encoding="utf-8")
        (self.root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.root / "acceptance.py").write_text("import unittest\nfrom app import VALUE\nclass Acceptance(unittest.TestCase):\n    def test_value(self):\n        self.assertEqual(VALUE, 2)\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.git("branch", "base")
        self.contract = {"schema": wf.CONTRACT_SCHEMA, "goal": "Set the fixture value to 2", "allowed_paths": ["app.py"], "protected_paths": [],
                         "invariants": ["Keep acceptance verifier unchanged"], "acceptance": ["VALUE equals 2"],
                         "checks": [{"id": "acceptance", "argv": [sys.executable, "-B", "-m", "unittest", "acceptance", "-v"], "timeout_seconds": 10, "min_tests": 1, "parser": "unittest", "verifier_paths": ["acceptance.py"]}],
                         "review": {"required": False, "base_ref": "base", "context_paths": []},
                         "limits": {"max_repairs": 3, "max_seconds": 300, "max_check_runs": 5, "model_calls": 0, "cost_microunits": 0, "concurrency": 1},
                         "allowed_actions": ["local_implementation", "local_checks"], "final_action": {"kind": "handoff", "target": "local fixture evidence", "authorized": True}}

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.STDOUT)

    def implementation(self, workflow_id, value):
        attempt = wf.begin_step(self.root, workflow_id, self.store)
        (self.root / "app.py").write_text(f"VALUE = {value}\n", encoding="utf-8")
        return wf.record_result(self.root, workflow_id, attempt["pending_attempt"]["id"], self.store)

    def test_positive_real_check_and_sanitized_checkpoint(self):
        prepared = wf.prepare(self.root, self.contract, self.store)
        workflow_id = prepared["workflow_id"]
        self.implementation(workflow_id, 2)
        result = wf.run_check(self.root, workflow_id, "acceptance", True, self.store)
        self.assertEqual(result["state"], "ready_for_approval")
        self.assertFalse(result["completed"])
        self.assertEqual(result["check_receipts"]["acceptance"]["tests_run"], 1)
        self.assertTrue(wf.resume(self.root, workflow_id, self.store)["ready_for_approval"])
        checkpoint = wf.memory_summary(self.root, workflow_id, self.store)
        self.assertFalse(checkpoint["memory_written"])
        self.assertNotIn("Traceback", json.dumps(checkpoint))
        self.assertFalse((self.root / "project.ithz").exists())

    def test_one_repair_keeps_negative_receipt_then_passes(self):
        prepared = wf.prepare(self.root, self.contract, self.store)
        workflow_id = prepared["workflow_id"]
        self.implementation(workflow_id, 3)
        failure = wf.run_check(self.root, workflow_id, "acceptance", True, self.store)
        self.assertEqual(failure["state"], "correcting")
        self.implementation(workflow_id, 2)
        result = wf.run_check(self.root, workflow_id, "acceptance", True, self.store)
        self.assertEqual(result["state"], "ready_for_approval")
        state = json.loads((Path(result["evidence_directory"]) / "state.json").read_text())["state"]
        self.assertEqual(len(state["receipt_history"]), 2)
        self.assertFalse(state["receipt_history"][0]["passed"])
        self.assertTrue(state["receipt_history"][1]["passed"])
        self.assertEqual(state["repairs"], 1)

    def test_jsonrpc_lifecycle_readonly_and_write_routes(self):
        def rpc(method, arguments, mode="write-enabled"):
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": method, "arguments": arguments}}
            result = json.loads(json.dumps(handle_line(json.dumps(request), self.root, "native-archive", mode)))
            return result

        plan_result = rpc("ithz_workflow_plan", {"goal": "Set fixture to 2", "checks": ["VALUE equals 2"]}, "read-only")
        self.assertIn("steps", plan_result["result"]["structuredContent"])
        denied = rpc("ithz_workflow_prepare", {"contract": self.contract, "store_root": str(self.store)}, "read-only")
        self.assertEqual(denied["error"]["code"], -32601)
        prepared = rpc("ithz_workflow_prepare", {"contract": self.contract, "store_root": str(self.store)})["result"]["structuredContent"]
        args = {"workflow_id": prepared["workflow_id"], "store_root": str(self.store)}
        started = rpc("ithz_workflow_begin_step", args)["result"]["structuredContent"]
        (self.root / "app.py").write_text("VALUE = 2\n")
        recorded = rpc("ithz_workflow_record_result", {**args, "attempt_id": started["pending_attempt"]["id"]})["result"]["structuredContent"]
        self.assertEqual(recorded["state"], "checking")
        checked = rpc("ithz_workflow_run_check", {**args, "check_id": "acceptance", "execution_authorized": True})["result"]["structuredContent"]
        self.assertTrue(checked["ready_for_approval"])
        final = rpc("ithz_workflow_status", args, "read-only")["result"]["structuredContent"]
        self.assertEqual(final["state"], "ready_for_approval")
        cancelled = rpc("ithz_workflow_cancel", args)["result"]["structuredContent"]
        self.assertEqual(cancelled["state"], "cancelled")

    def test_stdio_initialization_discovery_and_plan_visible(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "ithz_workflow_plan", "arguments": {"goal": "Fix value", "checks": ["one fixture test"]}}},
        ]
        output = io.StringIO()
        serve_stdio(self.root, io.StringIO("\n".join(json.dumps(r) for r in requests)), output, storage_profile="native-archive", server_mode="read-only")
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertIn("first propose", replies[0]["result"]["instructions"])
        names = {tool["name"] for tool in replies[1]["result"]["tools"]}
        self.assertIn("ithz_workflow_plan", names)
        self.assertNotIn("ithz_workflow_prepare", names)
        self.assertEqual(replies[2]["result"]["structuredContent"]["goal"], "Fix value")

    def test_cli_prepare_implementation_check_status_cancel(self):
        contract_path = self.base / "contract.json"
        contract_path.write_text(json.dumps(self.contract), encoding="utf-8")
        def command(action, *extra):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["workflow-" + action, "--project", str(self.root), "--store-root", str(self.store), *extra])
            self.assertEqual(code, 0, output.getvalue())
            return json.loads(output.getvalue())

        self.assertIn("steps", command("plan", "--contract", str(contract_path)))
        prepared = command("prepare", "--contract", str(contract_path))
        args = ("--workflow-id", prepared["workflow_id"])
        started = command("begin-step", *args)
        (self.root / "app.py").write_text("VALUE = 2\n")
        command("record-result", *args, "--attempt-id", started["pending_attempt"]["id"])
        checked = command("run-check", *args, "--check-id", "acceptance", "--execution-authorized")
        self.assertTrue(checked["ready_for_approval"])
        self.assertEqual(command("status", *args)["state"], "ready_for_approval")
        self.assertEqual(command("cancel", *args)["state"], "cancelled")

    def test_contract_limits_no_models_and_fixed_checks(self):
        self.assertEqual(wf.plan(self.root, self.contract), wf.plan(self.root, self.contract))
        bad = copy.deepcopy(self.contract)
        bad["limits"]["model_calls"] = 1
        with self.assertRaisesRegex(ValueError, "invalid_workflow_limit"):
            wf.prepare(self.root, bad, self.store)
        bad = copy.deepcopy(self.contract)
        bad["checks"][0]["min_tests"] = 0
        with self.assertRaisesRegex(ValueError, "nonzero_acceptance_tests"):
            wf.prepare(self.root, bad, self.store)


if __name__ == "__main__":
    unittest.main()
