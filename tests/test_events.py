import tempfile
import unittest
from pathlib import Path

from ithz_mcp.events import context_commit, validate_dag
from ithz_mcp.storage import init_project


class EventsTests(unittest.TestCase):
    def test_context_commit_dag(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("# Demo\n\nDecision: keep it local.\n", encoding="utf-8")
            init_project(root)
            context_commit(root, "first")
            context_commit(root, "second")
            self.assertTrue(validate_dag(root)["valid"])


if __name__ == "__main__":
    unittest.main()

