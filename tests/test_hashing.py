import unittest

from ithz_mcp.hashing import sha256_text, stable_json_hash


class HashingTests(unittest.TestCase):
    def test_sha256_text_is_stable(self):
        self.assertEqual(sha256_text("abc"), sha256_text("abc"))

    def test_stable_json_hash_sorts_keys(self):
        self.assertEqual(stable_json_hash({"b": 2, "a": 1}), stable_json_hash({"a": 1, "b": 2}))


if __name__ == "__main__":
    unittest.main()

