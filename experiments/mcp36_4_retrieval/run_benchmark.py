"""Run the small MCP36.4 retrieval fixture without external models."""
from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from ithz_mcp.memory_v2 import build_memory_graph, deterministic_candidates, lexical_graph_candidates, hybrid_candidates
from ithz_mcp.rag import rag_search
from ithz_mcp.retrieval import retrieval_metrics


def _ids(rows):
    return [str(r.get("id") or f"{r.get('path', '')}:{r.get('line', 0)}:{r.get('kind', '')}") for r in rows]


def run(fixture: Path) -> dict:
    spec = json.loads(fixture.read_text(encoding="utf-8"))
    records = []
    with tempfile.TemporaryDirectory(prefix="ithz_mcp364_retrieval_") as td:
        project = Path(td)
        for item in spec["corpus"]:
            (project / item["path"]).write_text(item["text"], encoding="utf-8")
        units = []
        # The fixture is intentionally transparent: source lines become units.
        from ithz_mcp.memory_v2 import load_project_units
        units = load_project_units(project)["units"]
        graph = build_memory_graph(units)
        for split in ("dev", "test"):
            for case in spec["split"][split]:
                query, gold = case["query"], set(case["relevant_ids"])
                modes = {
                    "deterministic": lambda: deterministic_candidates(units, query, 5),
                    "lexical_graph": lambda: lexical_graph_candidates(units, query, graph, 5),
                    "hybrid": lambda: hybrid_candidates(units, query, graph, 5),
                    "rag_baseline": lambda: rag_search(project, query, limit=5, rebuild=True, write_cache=False, write_index=False)["rows"],
                }
                for mode, fn in modes.items():
                    started = time.perf_counter()
                    rows = fn()
                    elapsed = round((time.perf_counter() - started) * 1000, 3)
                    ranked = _ids(rows)
                    first = next((i + 1 for i, value in enumerate(ranked) if value in gold), None)
                    records.append({"split": split, "query": query, "mode": mode, "gold_ids": sorted(gold), "ranked_ids": ranked, "first_relevant_rank": first, "latency_ms": elapsed})
    metrics = {}
    for split in ("dev", "test"):
        for mode in sorted({r["mode"] for r in records}):
            selected = [r for r in records if r["split"] == split and r["mode"] == mode]
            metrics[f"{split}:{mode}"] = retrieval_metrics([[{"id": x} for x in r["ranked_ids"]] for r in selected], [set(r["gold_ids"]) for r in selected], 5)
            metrics[f"{split}:{mode}"]["mean_latency_ms"] = round(sum(r["latency_ms"] for r in selected) / max(1, len(selected)), 3)
    return {"schema": "ithz_mcp364_retrieval_benchmark_receipt_v1", "fixture": str(fixture), "external_models": False, "labels": "synthetic fixture labels; not independent annotation", "records": records, "metrics": metrics}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=Path(__file__).parents[2] / "fixtures/mcp36_4_retrieval_labels.json")
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("mcp36_4_retrieval_receipt.json"))
    args = parser.parse_args()
    args.out.write_text(json.dumps(run(args.fixture), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.out)
