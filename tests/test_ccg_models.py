import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ithz_mcp.ccg.models import GeminiBackend, GrokBackend


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class CCGModelBackendTests(unittest.TestCase):
    def test_grok_sends_reasoning_and_privacy_safe_cache_affinity(self):
        captured = {}
        role = {"evidence_hash": "a" * 64, "recommendation": "STOP", "objections": [], "missing_evidence": [], "confidence": 1}

        def open_request(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return _Response({"id": "xai-test", "choices": [{"message": {"content": json.dumps(role)}}]})

        backend = GrokBackend("xai-" + "A" * 40, reasoning_effort="low")
        with tempfile.TemporaryDirectory() as directory, patch(
            "ithz_mcp.ccg.models.urllib.request.urlopen", side_effect=open_request
        ):
            result = backend.run("opponent_cross", "stable-prefix\ncase", {}, "a" * 64, Path(directory), "b" * 64)
        payload = json.loads(captured["request"].data.decode("utf-8"))
        self.assertEqual(payload["reasoning_effort"], "low")
        self.assertEqual(captured["request"].get_header("X-grok-conv-id"), "ccg-template-" + "b" * 40)
        self.assertEqual(result.template_hash, "b" * 64)

    def test_gemini_37_flash_uses_low_thinking_and_json_schema(self):
        captured = {}
        role = {"evidence_hash": "c" * 64, "recommendation": "STOP", "objections": [], "missing_evidence": [], "confidence": 1}

        def open_request(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return _Response(
                {
                    "responseId": "gemini-test",
                    "candidates": [{"content": {"parts": [{"text": json.dumps(role)}]}}],
                }
            )

        schema = {"type": "object", "properties": {"evidence_hash": {"type": "string"}}}
        backend = GeminiBackend("AIza" + "B" * 35, model="gemini-3.7-flash", thinking_level="low")
        with tempfile.TemporaryDirectory() as directory, patch(
            "ithz_mcp.ccg.models.urllib.request.urlopen", side_effect=open_request
        ):
            result = backend.run("opponent_cross", "stable-prefix\ncase", schema, "c" * 64, Path(directory), "d" * 64)
        request = captured["request"]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertIn("gemini-3.7-flash:generateContent", request.full_url)
        self.assertEqual(payload["generationConfig"]["thinkingConfig"]["thinkingLevel"], "low")
        self.assertEqual(payload["generationConfig"]["responseJsonSchema"], schema)
        self.assertEqual(result.provider, "google")
        self.assertEqual(result.template_hash, "d" * 64)


if __name__ == "__main__":
    unittest.main()
