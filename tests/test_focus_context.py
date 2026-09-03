import unittest
from pathlib import Path

from ithz_mcp.context_index import build_index
from ithz_mcp.focus_context import FOCUS_PACK_SCHEMA, focus_context_pack_from_source
from ithz_mcp.mcp_server import call_tool, mcp_tool_schemas
from ithz_mcp.storage import init_project


def source_pack(repetitions: int = 16):
    rows = []
    for index in range(repetitions):
        rows.extend(
            [
                f"- `src/payment.py:{10 + index}` (decision, score=40): Stripe webhook grants credits only after verified payment event {index}.",
                "  - why_selected: decision, payment",
                f"- `tests/test_payment.py:{20 + index}` (gate, score=35): webhook idempotency regression test {index} passed.",
                "  - why_selected: gate, test",
            ]
        )
    text = "\n".join(
        [
            "# ITHZ-MCP Context Pack",
            "",
            "- query: Stripe webhook idempotency risk",
            "",
            "## Relevant Decisions",
            *rows,
            "",
            "## Known Risks / Must Not Break",
            "- `docs/PAYMENTS.md:42` (risk, score=50): Never grant credits from the browser redirect.",
            "",
            "## Evidence Gaps",
            "- Production Stripe secrets are intentionally unavailable in fixtures.",
        ]
    ) + "\n"
    return {"text": text, "semantic_context_pack_hash": "source-hash"}


class FocusContextPackTests(unittest.TestCase):
    def test_pack_is_deterministic_and_smaller(self):
        source = source_pack()
        first = focus_context_pack_from_source(source, "Stripe webhook idempotency risk", 1800, 6000)
        second = focus_context_pack_from_source(source, "Stripe webhook idempotency risk", 1800, 6000)
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], FOCUS_PACK_SCHEMA)
        self.assertLess(first["bytes"], first["source_pack_bytes"])
        self.assertEqual(first["bytes_saved_vs_source"], first["source_pack_bytes"] - first["bytes"])
        self.assertIn("Never grant credits", first["text"])
        self.assertIn("Evidence Gaps", first["text"])
        self.assertGreaterEqual(first["query_term_coverage"], 0.8)

    def test_small_source_is_not_expanded(self):
        source = {"text": "# Context\n\n- one useful row\n", "context_pack_hash": "small"}
        result = focus_context_pack_from_source(source, "useful", 1000, 2000)
        self.assertEqual(result["text"], source["text"])
        self.assertEqual(result["budget_tier"], "source_already_compact")
        self.assertEqual(result["bytes_saved_vs_source"], 0)

    def test_invalid_budget_fails_closed(self):
        with self.assertRaises(ValueError):
            focus_context_pack_from_source(source_pack(), "query", 999, 2000)
        with self.assertRaises(ValueError):
            focus_context_pack_from_source(source_pack(), "query", 2000, 1500)

    def test_missing_query_evidence_requires_fallback(self):
        source = {"text": "# Context\n\n## Evidence Gaps\n- No matching evidence.\n", "context_pack_hash": "empty"}
        result = focus_context_pack_from_source(source, "payment webhook", 1000, 2000)
        self.assertTrue(result["fallback_required"])
        self.assertEqual(result["query_term_coverage"], 0.0)

    def test_mcp_tool_is_listed_and_returns_focus_metrics(self):
        root = Path(__file__).resolve().parents[1] / "fixtures" / "sample_project"
        init_project(root)
        build_index(root)
        names = {tool["name"] for tool in mcp_tool_schemas()}
        self.assertIn("ithz_focus_context_pack", names)
        self.assertIn("ithz_get_context_pack", names)
        self.assertIn("ithz_archive_get_context_pack", names)
        self.assertIn("ithz_rag_context_pack", names)
        result = call_tool(
            "ithz_focus_context_pack",
            {"project": str(root), "query": "decision risk", "target_bytes": 1000, "max_bytes": 4000},
            root,
        )
        self.assertEqual(result["schema"], FOCUS_PACK_SCHEMA)
        self.assertIn("focus_pack_hash", result)
        self.assertLessEqual(result["bytes"], result["source_pack_bytes"])


if __name__ == "__main__":
    unittest.main()
