import unittest

from ithz_mcp.safety import ignore_reason, validate_archive_path


class SafetyTests(unittest.TestCase):
    def test_secret_ignore(self):
        self.assertEqual(ignore_reason(".env", 1), "secret_like_path")

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            validate_archive_path("../bad")


if __name__ == "__main__":
    unittest.main()

