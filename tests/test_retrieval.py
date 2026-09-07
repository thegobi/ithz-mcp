import tempfile
import unittest
from pathlib import Path

from ithz_mcp.memory_v2 import build_memory_graph, lexical_graph_candidates, load_project_units, semantic_candidates
from ithz_mcp.rag import build_rag_index, ensure_rag_index, rag_search
from ithz_mcp.retrieval import ProviderIdentity, annotate_policy_lanes, retrieval_metrics, rrf_fuse


class RetrievalTests(unittest.TestCase):
    class Provider:
        identity = {"backend": "synthetic", "model": "test", "model_revision": "test-1", "tokenizer": "none", "normalization": "none", "dimension": 3}
        def embed(self, texts):
            return [[1.0, 0.0, 0.0] for _ in texts]

    class BadProvider(Provider):
        def embed(self, texts):
            return [[float("nan")] for _ in texts]

    class TrackingProvider(Provider):
        def __init__(self): self.calls = []
        def embed(self, texts):
            self.calls.append(list(texts))
            return [[3.0, 4.0, 0.0] for _ in texts]

    class BuildFailsThenQueryWorks(Provider):
        def __init__(self): self.calls = 0
        def embed(self, texts):
            self.calls += 1
            return [[float("nan")] for _ in texts] if self.calls == 1 else [[1.0, 0.0, 0.0] for _ in texts]

    def test_lexical_name_and_compatibility_alias(self):
        units = [{"path": "a.md", "line": 1, "kind": "line", "text": "mandatory gate"}]
        graph = build_memory_graph(units)
        self.assertEqual([r["path"] for r in lexical_graph_candidates(units, "gate", graph)], ["a.md"])
        self.assertEqual(semantic_candidates, lexical_graph_candidates)

    def test_rrf_is_stable_and_policy_lanes_are_separate(self):
        rows = [{"id": "a", "path": "a", "line": 1}, {"id": "b", "path": "b", "line": 1}]
        self.assertEqual([r["id"] for r in rrf_fuse({"z": rows, "a": list(reversed(rows))})], ["a", "b"])
        tagged = annotate_policy_lanes([
            {"id": "p", "text": "must not edit", "categories": []},
            {"id": "h", "text": "old", "status": "revoked"},
        ])
        self.assertEqual(tagged[0]["policy_lane"], "mandatory_hard_policy")
        self.assertEqual(tagged[1]["policy_lane"], "warning_history")

    def test_candidate_stale_and_future_policy_rows_are_never_active_lanes(self):
        tagged = annotate_policy_lanes([
            {"id": "candidate", "text": "must not deploy", "verification_state": "candidate"},
            {"id": "stale", "text": "must not deploy", "verification_state": "legacy_unverified_abstraction"},
            {"id": "future", "text": "must not deploy", "verification_state": "active", "valid_from": "2999-01-01T00:00:00+00:00"},
        ])
        self.assertEqual([row["policy_lane"] for row in tagged], ["warning_history"] * 3)

    def test_metrics_and_provider_identity_are_explicit(self):
        result = retrieval_metrics([[{"id": "a"}, {"id": "b"}], [{"id": "x"}]], [{"a"}, {"z"}], k=2)
        self.assertEqual(result["recall_at_k"], 0.5)
        identity = ProviderIdentity("local", "model", "rev", "tok", "norm", 3).as_dict()
        self.assertEqual(identity["model_revision"], "rev")

    def test_cache_dimension_invalidation(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "project.md").write_text("Gate: run tests", encoding="utf-8")
            first = ensure_rag_index(project, dimensions=16)
            second = ensure_rag_index(project, dimensions=32)
            self.assertEqual(first["cache_status"], "rebuilt")
            self.assertEqual(second["cache_status"], "rebuilt")
            self.assertEqual(second["dimensions"], 32)

    def test_optional_provider_route_and_malformed_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "project.md").write_text("Gate: run tests", encoding="utf-8")
            synthetic = build_rag_index(project, dimensions=3, provider=self.Provider())
            self.assertEqual(synthetic["embedding_backend"], "synthetic")
            self.assertNotIn("provider_fallback", synthetic)
            fallback = build_rag_index(project, dimensions=3, provider=self.BadProvider())
            self.assertTrue(fallback["provider_fallback"])
            self.assertEqual(fallback["embedding_backend"], "local_feature_hashing_v1")

    def test_provider_revision_change_invalidates_same_backend_cache(self):
        class V2(self.Provider):
            identity = {**self.Provider.identity, "model_revision": "test-2"}
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "project.md").write_text("Gate: run tests", encoding="utf-8")
            first = ensure_rag_index(project, dimensions=3, provider=self.Provider())
            hit = ensure_rag_index(project, dimensions=3, provider=self.Provider())
            rebuilt = ensure_rag_index(project, dimensions=3, provider=V2())
            self.assertEqual(hit["cache_status"], "hit")
            self.assertEqual(rebuilt["cache_status"], "rebuilt")

    def test_provider_receives_only_safe_units_and_vectors_are_normalized(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            provider = self.TrackingProvider()
            loaded = {"index_hash": "a" * 64, "project_semantic_hash": "b" * 64, "units": [
                {"path": "safe.md", "line": 1, "kind": "line", "text": "release gate evidence"},
                {"path": ".env", "line": 1, "kind": "line", "text": "API_KEY=never-send"},
            ]}
            index = build_rag_index(project, dimensions=3, loaded=loaded, provider=provider)
            self.assertEqual(len(provider.calls), 1)
            self.assertNotIn("never-send", " ".join(provider.calls[0]))
            self.assertAlmostEqual(sum(value * value for value in index["units"][0]["vector"].values()), 1.0, places=6)

    def test_fallback_index_never_uses_later_provider_query_vector(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "project.md").write_text("release gate evidence", encoding="utf-8")
            provider = self.BuildFailsThenQueryWorks()
            result = rag_search(project, "release gate", dimensions=3, rebuild=True, write_cache=False, provider=provider)
            self.assertEqual(result["embedding_backend"], "local_feature_hashing_v1")
            self.assertEqual(provider.calls, 1)

    def test_no_answer_does_not_fill_from_irrelevant_policy_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            loaded = {"index_hash": "c" * 64, "project_semantic_hash": "d" * 64, "units": [
                {"path": "policy.md", "line": 1, "kind": "line", "text": "must not publish secrets", "scope": "prod", "verification_state": "active"},
                {"path": "old.md", "line": 1, "kind": "line", "text": "old gate", "status": "revoked"},
            ]}
            result = rag_search(project, "unrelated quasiparticle", rebuild=True, write_cache=False, loaded=loaded)
            self.assertEqual(result["rows"], [])
            self.assertTrue(result["no_answer"])
            mandatory = result["policy_rows"]["mandatory_hard_policy"]
            self.assertTrue(mandatory and mandatory[0]["scope_requires_check"])
            self.assertEqual(result["policy_rows"]["warning_history"][0]["policy_lane"], "warning_history")


if __name__ == "__main__":
    unittest.main()
