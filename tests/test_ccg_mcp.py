import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ithz_mcp.ccg.mcp_server import handle_line, tool_schemas


class CCGMCPTests(unittest.TestCase):
    def test_tool_catalog_contains_full_case_lifecycle(self):
        catalog = tool_schemas()
        names = {item["name"] for item in catalog}
        self.assertEqual(
            names,
            {
                "ccg_status",
                "ccg_memory_integrity_status",
                "ccg_memory_integrity_selftest",
                "ccg_mcp36_canary_status",
                "ccg_mcp36_canary_enable",
                "ccg_mcp36_canary_pause",
                "ccg_run_mcp36_canary_case",
                "ccg_initialize_project",
                "ccg_run_case",
                "ccg_run_final_case",
                "ccg_execute_demo",
                "ccg_get_case",
                "ccg_verify_case",
                "ccg_list_cases",
            },
        )
        run_schema = next(item for item in catalog if item["name"] == "ccg_run_case")["inputSchema"]["properties"]
        self.assertEqual(run_schema["opponent_2"]["default"], "auto")
        self.assertEqual(run_schema["use_daybreak"]["default"], "auto")
        self.assertEqual(run_schema["reuse_decision"]["default"], "auto")
        final_schema = next(item for item in catalog if item["name"] == "ccg_run_final_case")["inputSchema"]
        self.assertEqual(final_schema["properties"]["cross_lab_provider"]["default"], "gemini")
        self.assertEqual(final_schema["required"], ["task", "expected_memory_synthesis_hash", "review_manifest_path"])
        self.assertNotIn("capability", final_schema["properties"])
        self.assertNotIn("reuse_decision", final_schema["properties"])
        canary_schema = next(item for item in catalog if item["name"] == "ccg_run_mcp36_canary_case")["inputSchema"]
        self.assertEqual(canary_schema["required"], ["task"])
        self.assertNotIn("capability", canary_schema["properties"])

    def test_memory_integrity_selftest_is_local_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            response = handle_line(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 36,
                        "method": "tools/call",
                        "params": {"name": "ccg_memory_integrity_selftest", "arguments": {}},
                    }
                ),
                project,
            )
            result = response["result"]["structuredContent"]
            self.assertTrue(result["passed"])
            self.assertEqual(result["schema"], "ithz_mcp36_memory_integrity_benchmark_v1")

    def test_mcp36_canary_tool_flow_is_explicit_read_only_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"CCG_BACKEND": "scripted"}):
            project = Path(directory)

            def call(request_id, name, arguments):
                response = handle_line(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": "tools/call",
                            "params": {"name": name, "arguments": arguments},
                        }
                    ),
                    project,
                )
                return response["result"]["structuredContent"]

            initial = call(40, "ccg_mcp36_canary_status", {})
            self.assertFalse(initial["configured"])
            enabled = call(41, "ccg_mcp36_canary_enable", {"max_cases": 1, "expires_hours": 1})
            self.assertTrue(enabled["active"])
            result = call(
                42,
                "ccg_run_mcp36_canary_case",
                {"task": "Review one bounded MCP36.4 architecture decision.", "risk": "high"},
            )
            self.assertEqual(result["model_runs"], 5)
            self.assertTrue(result["cross_lab_quorum"])
            self.assertTrue(result["provider_usage"]["complete"])
            self.assertIsNone(result["capability_token"])
            self.assertFalse(result["ithz_mirror"]["mirrored"])
            self.assertEqual(result["canary_status"]["reason"], "canary_case_limit_reached")
            paused = call(43, "ccg_mcp36_canary_pause", {})
            self.assertEqual(paused["state"], "paused")

    def test_stdio_style_scripted_case_and_verify(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"CCG_BACKEND": "scripted"}):
            project = Path(directory)
            initialize = handle_line(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}), project)
            self.assertEqual(initialize["result"]["serverInfo"]["name"], "dev.ithz/ccg-ithz-mcp")
            request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "ccg_run_case",
                    "arguments": {
                        "task": "Create the bounded demo notice.",
                        "risk": "low",
                        "capability": "file.write.sandboxed",
                        "use_grok": "off",
                    },
                },
            }
            response = handle_line(json.dumps(request), project)
            structured = response["result"]["structuredContent"]
            self.assertEqual(structured["final_verdict"], "ALLOW_WITH_LIMITS")
            case_id = structured["case_id"]
            verify = handle_line(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "ccg_verify_case", "arguments": {"case_id": case_id}},
                    }
                ),
                project,
            )
            self.assertTrue(verify["result"]["structuredContent"]["valid"])

    def test_parse_error_is_jsonrpc_error(self):
        with tempfile.TemporaryDirectory() as directory:
            response = handle_line("not-json", Path(directory))
            self.assertEqual(response["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
