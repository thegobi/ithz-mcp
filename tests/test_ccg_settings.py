import http.cookiejar
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from ithz_mcp.ccg.court import CourtRunner
from ithz_mcp.ccg.models import ScriptedBackend
from ithz_mcp.ccg.settings_server import create_settings_server
from ithz_mcp.ccg.settings_store import (
    delete_gemini_key,
    delete_xai_key,
    effective_preferences,
    resolve_gemini_key,
    resolve_xai_key,
    save_gemini_key,
    save_preferences,
    save_xai_key,
    secrets_path,
)


DUMMY_KEY = "xai-" + "A" * 40
DUMMY_GEMINI_KEY = "AIza" + "B" * 35


class CCGSettingsTests(unittest.TestCase):
    def _environment(self, directory: str):
        return patch.dict(
            os.environ,
            {
                "CCG_SETTINGS_DIR": directory,
                "XAI_API_KEY": "",
                "GEMINI_API_KEY": "",
                "CCG_CODEX_MODEL": "",
                "CCG_CODEX_EFFORT": "",
                "CCG_CODEX_TIMEOUT": "",
                "CCG_GROK_MODEL": "",
                "CCG_GEMINI_MODEL": "",
                "CCG_GEMINI_THINKING_LEVEL": "",
                "CCG_OPPONENT_2_PROVIDER": "",
                "CCG_DAYBREAK_MODEL": "",
                "CCG_DAYBREAK_EFFORT": "",
                "CCG_DAYBREAK_POLICY": "",
                "CCG_GROK_EFFORT": "",
            },
        )

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI storage")
    def test_dpapi_roundtrip_never_persists_plaintext(self):
        with tempfile.TemporaryDirectory() as directory, self._environment(directory):
            save_xai_key(DUMMY_KEY)
            save_gemini_key(DUMMY_GEMINI_KEY)
            self.assertEqual(resolve_xai_key()["value"], DUMMY_KEY)
            self.assertEqual(resolve_gemini_key()["value"], DUMMY_GEMINI_KEY)
            self.assertNotIn(DUMMY_KEY, secrets_path().read_text(encoding="utf-8"))
            self.assertNotIn(DUMMY_GEMINI_KEY, secrets_path().read_text(encoding="utf-8"))
            delete_xai_key()
            self.assertFalse(resolve_xai_key()["configured"])
            self.assertTrue(resolve_gemini_key()["configured"])
            delete_gemini_key()
            self.assertFalse(resolve_gemini_key()["configured"])

    def test_preferences_are_validated_and_environment_can_override(self):
        with tempfile.TemporaryDirectory() as directory, self._environment(directory):
            saved = save_preferences(
                {
                    "codex_model": "gpt-5.6-luna",
                    "codex_effort": "medium",
                    "codex_timeout": 300,
                    "grok_model": "grok-4.3",
                    "gemini_model": "gemini-3.7-flash",
                    "opponent_2_provider": "gemini",
                    "daybreak_model": "gpt-daybreak-blue-latest",
                    "daybreak_policy": "high_and_critical",
                }
            )
            self.assertEqual(saved["codex_effort"], "medium")
            with patch.dict(os.environ, {"CCG_CODEX_MODEL": "gpt-5.6-sol"}):
                self.assertEqual(effective_preferences()["codex_model"], "gpt-5.6-sol")
            with self.assertRaisesRegex(ValueError, "invalid_grok_model"):
                save_preferences({"grok_model": "model with spaces"})
            self.assertEqual(saved["gemini_model"], "gemini-3.7-flash")
            self.assertEqual(saved["opponent_2_provider"], "gemini")

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI storage")
    def test_court_detects_dpapi_key_without_receiving_secret(self):
        with tempfile.TemporaryDirectory() as directory, self._environment(directory):
            save_xai_key(DUMMY_KEY)
            runner = CourtRunner(Path(directory), codex_backend=ScriptedBackend())
            status = runner.status()
            self.assertTrue(status["grok_configured"])
            self.assertEqual(status["grok_secret_source"], "windows_dpapi")
            self.assertNotIn(DUMMY_KEY, json.dumps(status))

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI storage")
    def test_loopback_page_requires_session_and_csrf_and_never_returns_key(self):
        with tempfile.TemporaryDirectory() as directory, self._environment(directory):
            server = create_settings_server(0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            try:
                origin = server.origin
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(origin + "/api/status", timeout=5)
                self.assertEqual(denied.exception.code, 403)
                denied.exception.close()

                with opener.open(server.bootstrap_url, timeout=5) as response:
                    page = response.read().decode("utf-8")
                self.assertIn("CCG &amp; ITHZ MCP", page)

                payload = json.dumps(
                    {
                        "xai_key": DUMMY_KEY,
                        "gemini_key": DUMMY_GEMINI_KEY,
                        "preferences": {
                            "codex_model": "gpt-5.6-luna",
                            "codex_effort": "low",
                            "codex_timeout": 240,
                            "grok_model": "grok-4.3",
                            "gemini_model": "gemini-3.7-flash",
                            "opponent_2_provider": "gemini",
                            "daybreak_model": "gpt-daybreak-blue-latest",
                            "daybreak_policy": "high_and_critical",
                        },
                    }
                ).encode("utf-8")
                request = urllib.request.Request(
                    origin + "/api/settings",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Origin": origin,
                        "X-CCG-CSRF": server.csrf_token,
                    },
                    method="POST",
                )
                with opener.open(request, timeout=5) as opened:
                    response = opened.read().decode("utf-8")
                self.assertNotIn(DUMMY_KEY, response)
                self.assertNotIn(DUMMY_GEMINI_KEY, response)
                status = json.loads(response)
                self.assertTrue(status["xai"]["configured"])
                self.assertTrue(status["gemini"]["configured"])

                with opener.open(origin + "/", timeout=5) as opened:
                    rendered = opened.read().decode("utf-8")
                self.assertNotIn(DUMMY_KEY, rendered)
                self.assertNotIn(DUMMY_GEMINI_KEY, rendered)

                missing_csrf = urllib.request.Request(
                    origin + "/api/delete-key",
                    data=b"{}",
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as forbidden:
                    opener.open(missing_csrf, timeout=5)
                self.assertEqual(forbidden.exception.code, 403)
                forbidden.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
