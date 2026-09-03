import unittest
from pathlib import Path

from ithz_mcp.context_index import build_index
from ithz_mcp.context_pack import build_context_pack
from ithz_mcp.storage import init_project


class ContextPackTests(unittest.TestCase):
    def test_pack_hash_is_stable(self):
        root = Path(__file__).resolve().parents[1] / "fixtures" / "sample_project"
        init_project(root)
        build_index(root)
        a = build_context_pack(root, "decision", 12000)
        b = build_context_pack(root, "decision", 12000)
        self.assertEqual(a["semantic_context_pack_hash"], b["semantic_context_pack_hash"])


if __name__ == "__main__":
    unittest.main()

