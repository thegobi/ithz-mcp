import tempfile
import unittest
from pathlib import Path

from ithz_mcp.prompt_memory import prompt_context_pack, prompt_search, record_prompt_response
from ithz_mcp.storage import init_project


class PromptMemoryTests(unittest.TestCase):
    def test_summary_mode_is_deterministic_and_no_raw_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            init_project(root)
            prompt = root / "prompt.md"
            response = root / "response.md"
            prompt.write_text("Decision: keep prompt memory summary-first.\n", encoding="utf-8")
            response.write_text("Gate: prompt memory test passed.\n", encoding="utf-8")
            a = record_prompt_response(root, prompt, response, "summary task", "summary")
            b = record_prompt_response(root, prompt, response, "summary task", "summary")
            self.assertEqual(a["semantic_prompt_hash"], b["semantic_prompt_hash"])
            self.assertIsNone(a["prompt_path"])
            self.assertTrue(prompt_search(root, "summary"))
            self.assertIn("Prompt / Response Summaries", prompt_context_pack(root, "summary")["text"])

    def test_full_redacted_removes_secret_value(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            init_project(root)
            prompt = root / "prompt.md"
            response = root / "response.md"
            secret = "sk-testsecretvalue12345678901234567890"
            prompt.write_text(f"API_KEY={secret}\n", encoding="utf-8")
            response.write_text("password: topsecret12345\n", encoding="utf-8")
            record = record_prompt_response(root, prompt, response, "redaction task", "full-redacted")
            stored = (root / ".ithz-context" / record["prompt_path"]).read_text(encoding="utf-8")
            self.assertNotIn(secret, stored)
            self.assertEqual(record["redaction_status"], "redacted")


if __name__ == "__main__":
    unittest.main()
