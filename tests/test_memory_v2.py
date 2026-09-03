import tempfile
import unittest
from pathlib import Path

from ithz_mcp.memory_v2 import build_memory_graph, compile_memory_v2_pack, load_project_units, run_memory_v2_benchmark


class MemoryV2Tests(unittest.TestCase):
    def _project(self) -> tempfile.TemporaryDirectory:
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        (root / "project.md").write_text(
            "# Test Project\n\n"
            "Decision: keep memory-first workflow.\n"
            "Gate: run-ci-fast passed.\n"
            "Risk: do not index secrets.\n",
            encoding="utf-8",
        )
        (root / "src").mkdir()
        (root / "src" / "context_pack.py").write_text(
            "def build_context_pack():\n"
            "    return 'graph semantic context pack'\n",
            encoding="utf-8",
        )
        (root / ".env").write_text("API_KEY=should_not_escape\n", encoding="utf-8")
        return td

    def test_graph_hash_stable(self):
        with self._project() as td:
            project = Path(td)
            units = load_project_units(project)["units"]
            a = build_memory_graph(units)
            b = build_memory_graph(units)
            self.assertEqual(a["graph_hash"], b["graph_hash"])
            self.assertGreater(a["node_count"], 0)

    def test_pack_is_bounded_and_secret_safe(self):
        with self._project() as td:
            project = Path(td)
            pack = compile_memory_v2_pack(project, "context pack gate risk", 6000)
            self.assertLessEqual(pack["bytes"], 6000)
            self.assertNotIn("should_not_escape", pack["text"])
            self.assertGreater(pack["hybrid_count"], 0)

    def test_benchmark_passes_fixture(self):
        with self._project() as td:
            project = Path(td)
            result = run_memory_v2_benchmark([project], ["context pack gate risk"], 8000)
            self.assertTrue(result["passed"])
            self.assertTrue(result["benchmark_hash"])


if __name__ == "__main__":
    unittest.main()
