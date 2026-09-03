import unittest

from ithz_mcp.selftest import run_mcp0


class SelfTestTests(unittest.TestCase):
    def test_mcp0_runner(self):
        self.assertTrue(run_mcp0())


if __name__ == "__main__":
    unittest.main()

