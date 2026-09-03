from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from ithz_mcp.rag import build_rag_index, compile_rag_context_pack, rag_search


class RagTests(unittest.TestCase):
    def make_project(self, root: Path) -> Path:
        project = root / "project"
        project.mkdir()
        (project / "project.md").write_text(
            "# Test Project\n\n"
            "Decision: use local RAG as a derived context index.\n"
            "Gate: run tests before release.\n"
            "Risk: never index secrets.\n",
            encoding="utf-8",
        )
        (project / "src").mkdir()
        (project / "src" / "app.py").write_text("def context_pack():\n    return 'gate risk decision'\n", encoding="utf-8")
        (project / ".env").write_text("API_KEY=do_not_leak\n", encoding="utf-8")
        return project

    def test_rag_index_hash_stable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            project = self.make_project(Path(td))
            first = build_rag_index(project)
            second = build_rag_index(project)
            self.assertEqual(first["rag_index_hash"], second["rag_index_hash"])
            self.assertGreater(first["unit_count"], 0)

    def test_rag_pack_is_bounded_and_secret_safe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            project = self.make_project(Path(td))
            pack = compile_rag_context_pack(project, "decision gate risk", max_bytes=5000)
            self.assertLessEqual(pack["bytes"], 5000)
            self.assertNotIn("do_not_leak", pack["text"])
            self.assertIn("Local RAG", pack["text"])

    def test_rag_search_returns_relevant_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            project = self.make_project(Path(td))
            result = rag_search(project, "release gate tests", limit=5, rebuild=True)
            self.assertGreater(result["row_count"], 0)
            self.assertTrue(any("Gate:" in row["text"] or "gate" in row["text"].lower() for row in result["rows"]))


if __name__ == "__main__":
    unittest.main()
