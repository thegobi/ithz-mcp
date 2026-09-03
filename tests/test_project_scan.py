import unittest
import tempfile
from pathlib import Path

from ithz_mcp.project_scan import scan_project


class ProjectScanTests(unittest.TestCase):
    def test_secrets_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# Synthetic project\n", encoding="utf-8")
            (root / ".env").write_text("EXAMPLE_ONLY=not-a-real-secret\n", encoding="utf-8")
            (root / "secrets.key").write_text("synthetic-test-value\n", encoding="utf-8")
            scan = scan_project(root)
            ignored = {row["path"] for row in scan["ignored"]}
            self.assertIn(".env", ignored)
            self.assertIn("secrets.key", ignored)


if __name__ == "__main__":
    unittest.main()

