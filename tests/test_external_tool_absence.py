import unittest
from pathlib import Path
from unittest.mock import patch

import ithz_mcp
from ithz_mcp.project_installer import detect_git


class ExternalToolAbsenceTests(unittest.TestCase):
    def test_version_info_without_git(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("git")):
            info = ithz_mcp.version_info()
        self.assertEqual(info["product"], "ITHZ-MCP / ITHZ ContextDB")
        self.assertNotIn("source_tree_dirty", info)

    def test_detect_git_without_git(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("git")):
            status = detect_git(Path("."))
        self.assertFalse(status["inside_git"])
        self.assertEqual(status["git_root"], "")
        self.assertEqual(status["branch"], "")


if __name__ == "__main__":
    unittest.main()
