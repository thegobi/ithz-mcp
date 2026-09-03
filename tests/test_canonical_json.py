import unittest

from ithz_mcp.canonical_json import dumps, sanitize_json_value, sanitize_text


class CanonicalJsonTests(unittest.TestCase):
    def test_dumps_is_sorted(self):
        self.assertEqual(dumps({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_lone_surrogate_is_sanitized_before_utf8_encoding(self):
        payload = {"bad": "before\udcffafter", "nested": [{"\ud800key": "value\udfff"}]}
        dumped = dumps(payload)
        dumped.encode("utf-8")
        self.assertNotIn("\udcff", dumped)
        self.assertNotIn("\ud800", dumped)
        self.assertIn("\ufffd", dumped)

    def test_sanitize_text_is_deterministic(self):
        self.assertEqual(sanitize_text("a\udcffb"), "a\ufffdb")
        self.assertEqual(sanitize_json_value({"x": ("a\udcff",)})["x"], ["a\ufffd"])


if __name__ == "__main__":
    unittest.main()

