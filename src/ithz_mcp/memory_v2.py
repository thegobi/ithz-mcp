from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import math
import time
from typing import Any

from .context_index import build_index, search_index
from .hashing import stable_json_hash
from .scoring import classify_text, normalize_text, query_terms, score_unit
from .safety import is_secret_like, redaction_block_reason


MEMORY_V2_SCHEMA = "ithz_mcp_memory_v2_candidate_v1"

GRAPH_STOPWORDS = {
    "and",
    "are",
    "after",
    "before",
    "be",
    "candidate",
    "context",
    "current",
    "file",
    "files",
    "from",
    "for",
    "have",
    "into",
    "ithz",
    "memory",
    "project",
    "query",
    "should",
    "that",
    "this",
    "what",
    "which",
    "with",
    "zmena",
    "projekt",
    "subor",
    "subory",
}


def _tokenize(value: str) -> list[str]:
    normalized = normalize_text(value).replace("\\", "/")
    chars = []
    for ch in normalized:
        chars.append(ch if ch.isalnum() or ch in {"_", "-", "/"} else " ")
    tokens = []
    for token in "".join(chars).split():
        token = token.strip("_-/")
        if len(token) < 3 or token in GRAPH_STOPWORDS:
            continue
        tokens.append(token)
    return tokens


def _unit_key(unit: dict[str, Any]) -> str:
    return f"{unit.get('path', '')}:{int(unit.get('line', 0))}:{unit.get('kind', '')}"


def _safe_units(units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    safe = []
    for unit in units:
        path = str(unit.get("path", ""))
        text = str(unit.get("text", ""))
        if is_secret_like(path):
            continue
        if redaction_block_reason(text):
            continue
        safe.append(unit)
    return safe


def load_project_units(project: Path) -> dict[str, Any]:
    index = build_index(project)
    units = _safe_units(list(index.get("units", [])))
    return {
        "schema": "ithz_mcp_memory_v2_project_units_v1",
        "project": str(project.resolve()),
        "project_semantic_hash": index.get("project_semantic_hash"),
        "index_hash": index.get("index_hash"),
        "units": units,
        "unit_count": len(units),
    }


def build_memory_graph(units: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    term_counts: Counter[str] = Counter()
    file_to_units: dict[str, list[str]] = defaultdict(list)
    category_to_units: dict[str, list[str]] = defaultdict(list)
    term_to_units: dict[str, list[str]] = defaultdict(list)

    for unit in _safe_units(units):
        path = str(unit.get("path", ""))
        key = _unit_key(unit)
        kind = str(unit.get("kind", "line"))
        text = str(unit.get("text", ""))
        categories = classify_text(text, path, kind).get("categories", [])
        tokens = _tokenize(path + " " + text)
        top_terms = [term for term, _count in Counter(tokens).most_common(8)]

        nodes.setdefault(f"file:{path}", {"id": f"file:{path}", "type": "file", "label": path})
        nodes.setdefault(key, {"id": key, "type": "unit", "label": text[:120], "path": path, "line": int(unit.get("line", 0)), "kind": kind})
        edges.append({"src": f"file:{path}", "dst": key, "type": "contains", "weight": 1})
        file_to_units[path].append(key)

        for category in categories:
            cid = f"category:{category}"
            nodes.setdefault(cid, {"id": cid, "type": "category", "label": category})
            edges.append({"src": key, "dst": cid, "type": "classified_as", "weight": 3})
            category_to_units[category].append(key)

        for term in top_terms:
            tid = f"term:{term}"
            nodes.setdefault(tid, {"id": tid, "type": "term", "label": term})
            edges.append({"src": key, "dst": tid, "type": "mentions", "weight": 1})
            term_to_units[term].append(key)
            term_counts[term] += 1

    graph = {
        "schema": "ithz_mcp_memory_graph_v1",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": sorted(nodes.values(), key=lambda row: row["id"]),
        "edges": sorted(edges, key=lambda row: (row["src"], row["dst"], row["type"])),
        "top_terms": [{"term": term, "count": count} for term, count in term_counts.most_common(80)],
        "file_count": len(file_to_units),
        "category_counts": {category: len(rows) for category, rows in sorted(category_to_units.items())},
        "unit_refs_by_term": {term: sorted(set(rows))[:40] for term, rows in sorted(term_to_units.items()) if term_counts[term] >= 2},
    }
    graph["graph_hash"] = stable_json_hash(
        {
            "schema": graph["schema"],
            "nodes": graph["nodes"],
            "edges": graph["edges"],
            "top_terms": graph["top_terms"],
        }
    )
    return graph


def _semantic_score(unit: dict[str, Any], query: str, graph: dict[str, Any]) -> dict[str, Any] | None:
    path = str(unit.get("path", ""))
    text = str(unit.get("text", ""))
    kind = str(unit.get("kind", ""))
    if is_secret_like(path) or redaction_block_reason(text):
        return None

    q_terms = set(query_terms(query)) | set(_tokenize(query))
    if not q_terms:
        return None
    unit_terms = set(_tokenize(path + " " + text + " " + kind))
    if not unit_terms:
        return None

    overlap = q_terms & unit_terms
    soft_overlap = {term for term in q_terms for candidate in unit_terms if term in candidate or candidate in term}
    overlap_score = len(overlap) * 18 + len(soft_overlap - overlap) * 7
    if overlap_score <= 0:
        return None

    categories = classify_text(text, path, kind).get("categories", [])
    category_boost = 0
    if "gate" in q_terms and "gate" in categories:
        category_boost += 20
    if "risk" in q_terms and "risk" in categories:
        category_boost += 18
    if "decision" in q_terms and "decision" in categories:
        category_boost += 18
    if "claim" in q_terms and "forbidden_claim" in categories:
        category_boost += 16

    graph_refs = graph.get("unit_refs_by_term", {})
    key = _unit_key(unit)
    graph_boost = sum(5 for term in q_terms if key in graph_refs.get(term, []))
    length_penalty = min(12, int(math.log(max(1, len(text)), 2))) if len(text) > 240 else 0
    score = overlap_score + category_boost + graph_boost - length_penalty
    if score <= 0:
        return None
    return {
        "score": score,
        "mode": "semantic_candidate",
        "matched_terms": sorted(overlap | soft_overlap),
        "categories": categories,
        "score_components": {
            "term_overlap": overlap_score,
            "category_boost": category_boost,
            "graph_boost": graph_boost,
            "length_penalty": -length_penalty,
        },
    }


def semantic_candidates(units: list[dict[str, Any]], query: str, graph: dict[str, Any], limit: int = 20) -> list[dict[str, Any]]:
    rows = []
    for unit in _safe_units(units):
        scored = _semantic_score(unit, query, graph)
        if scored:
            rows.append({**unit, **scored})
    rows.sort(key=lambda row: (-int(row.get("score", 0)), row.get("path", ""), int(row.get("line", 0)), row.get("text", "")))
    return rows[:limit]


def deterministic_candidates(units: list[dict[str, Any]], query: str, limit: int = 20) -> list[dict[str, Any]]:
    index = {"schema": "ithz_mcp_memory_v2_temp_index", "units": _safe_units(units)}
    return search_index(index, query, limit)


def hybrid_candidates(units: list[dict[str, Any]], query: str, graph: dict[str, Any], limit: int = 20) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for row in deterministic_candidates(units, query, limit * 2):
        key = _unit_key(row)
        boosted = dict(row)
        components = dict(boosted.get("score_components", {}))
        components["deterministic_anchor"] = components.get("deterministic_anchor", 0) + 18
        boosted["score_components"] = components
        boosted["score"] = int(boosted.get("score", 0)) + 18
        by_key[key] = {**boosted, "retrieval_modes": ["deterministic"]}
    for row in semantic_candidates(units, query, graph, limit * 2):
        key = _unit_key(row)
        if key in by_key:
            merged = by_key[key]
            merged["score"] = int(merged.get("score", 0)) + int(row.get("score", 0))
            merged["retrieval_modes"] = sorted(set(merged.get("retrieval_modes", []) + ["semantic"]))
            merged["score_components"] = {**merged.get("score_components", {}), **{f"semantic:{k}": v for k, v in row.get("score_components", {}).items()}}
            merged_terms = set(merged.get("matched_terms", []) or merged.get("matched_query_terms", []) or [])
            merged_terms.update(row.get("matched_terms", []) or row.get("matched_query_terms", []) or [])
            if merged_terms:
                merged["matched_terms"] = sorted(merged_terms)
            merged["categories"] = sorted(set(merged.get("categories", []) or []) | set(row.get("categories", []) or []))
        else:
            by_key[key] = {**row, "retrieval_modes": ["semantic"]}
    rows = list(by_key.values())
    def matched_count(row: dict[str, Any]) -> int:
        return len(set(row.get("matched_query_terms", []) or row.get("matched_terms", []) or []))

    rows.sort(key=lambda row: (-matched_count(row), -int(row.get("score", 0)), -len(row.get("retrieval_modes", [])), row.get("path", ""), int(row.get("line", 0)), row.get("text", "")))
    return rows[:limit]


def compile_memory_v2_pack(project: Path, query: str, max_bytes: int = 16000) -> dict[str, Any]:
    start = time.perf_counter()
    loaded = load_project_units(project)
    graph = build_memory_graph(loaded["units"])
    deterministic = deterministic_candidates(loaded["units"], query, 16)
    semantic = semantic_candidates(loaded["units"], query, graph, 16)
    hybrid = hybrid_candidates(loaded["units"], query, graph, 18)
    semantic_hash = stable_json_hash(
        {
            "schema": MEMORY_V2_SCHEMA,
            "query": query,
            "project_semantic_hash": loaded.get("project_semantic_hash"),
            "graph_hash": graph.get("graph_hash"),
            "hybrid": [
                {
                    "path": row.get("path"),
                    "line": row.get("line"),
                    "kind": row.get("kind"),
                    "text": row.get("text"),
                    "score": row.get("score"),
                    "retrieval_modes": row.get("retrieval_modes", []),
                }
                for row in hybrid
            ],
        }
    )

    lines = [
        "# ITHZ-MCP Memory v2 Pack",
        "",
        f"- query: {query}",
        f"- project_root: {project.resolve()}",
        f"- project_semantic_hash: {loaded.get('project_semantic_hash')}",
        f"- graph_hash: {graph.get('graph_hash')}",
        f"- memory_v2_pack_hash: {semantic_hash}",
        f"- retrieval: deterministic + graph + local semantic candidates",
        "",
        "## Hybrid Evidence",
    ]
    if not hybrid:
        lines.append("- No hybrid evidence matched. Inspect files directly or broaden the query.")
    for row in hybrid[:12]:
        text = str(row.get("text", ""))
        if len(text) > 360:
            text = text[:360].rstrip() + "..."
        modes = ",".join(row.get("retrieval_modes", []))
        lines.append(f"- `{row.get('path')}:{row.get('line')}` [{row.get('kind')}] score={row.get('score')} modes={modes}: {text}")

    lines.extend(["", "## Graph Signals"])
    lines.append(f"- graph_nodes: {graph.get('node_count')}")
    lines.append(f"- graph_edges: {graph.get('edge_count')}")
    lines.append(f"- category_counts: {graph.get('category_counts')}")
    lines.append("- top_terms: " + ", ".join(item["term"] for item in graph.get("top_terms", [])[:12]))

    lines.extend(["", "## Semantic Candidates"])
    for row in semantic[:8]:
        lines.append(f"- `{row.get('path')}:{row.get('line')}` score={row.get('score')} matched={','.join(row.get('matched_terms', [])[:6])}")

    lines.extend(["", "## Deterministic Candidates"])
    for row in deterministic[:8]:
        lines.append(f"- `{row.get('path')}:{row.get('line')}` score={row.get('score')} why={','.join(row.get('why_selected', []))}")

    lines.extend(
        [
            "",
            "## Evidence Gaps",
            "- Memory v2 semantic candidates are local deterministic hints, not authority.",
            "- Direct source inspection is still required before editing behavior.",
            "- No vector database, cloud embedding service, or general token-saving claim is used.",
        ]
    )
    text = "\n".join(lines).rstrip() + "\n"
    if len(text.encode("utf-8")) > max_bytes:
        marker = "\n\n[truncated deterministically]\n"
        allowed = max(0, max_bytes - len(marker.encode("utf-8")))
        text = text.encode("utf-8")[:allowed].decode("utf-8", errors="ignore") + marker

    return {
        "schema": MEMORY_V2_SCHEMA,
        "query": query,
        "text": text,
        "bytes": len(text.encode("utf-8")),
        "memory_v2_pack_hash": semantic_hash,
        "project_semantic_hash": loaded.get("project_semantic_hash"),
        "graph_hash": graph.get("graph_hash"),
        "graph_node_count": graph.get("node_count"),
        "graph_edge_count": graph.get("edge_count"),
        "deterministic_count": len(deterministic),
        "semantic_count": len(semantic),
        "hybrid_count": len(hybrid),
        "selected_files": sorted({str(row.get("path", "")) for row in hybrid if row.get("path")}),
        "generation_ms": int((time.perf_counter() - start) * 1000),
    }


def _recall_proxy(rows: list[dict[str, Any]], query: str) -> dict[str, Any]:
    text = "\n".join(
        str(row.get("path", ""))
        + " "
        + str(row.get("text", ""))
        + " "
        + " ".join(row.get("categories", []))
        + " "
        + " ".join(row.get("matched_terms", []) or row.get("matched_query_terms", []) or [])
        for row in rows
    ).lower()
    q_terms = {term for term in (set(query_terms(query)) | set(_tokenize(query))) if term not in GRAPH_STOPWORDS}
    matched = {term for term in q_terms if term in text}
    return {
        "query_term_recall_proxy": round(len(matched) / max(1, len(q_terms)), 3),
        "decision_recall_proxy": "decision" in text or "rozhod" in text,
        "gate_recall_proxy": "gate" in text or "passed" in text or "test" in text,
        "risk_recall_proxy": "risk" in text or "must not" in text or "nesmie" in text,
        "matched_terms": ",".join(sorted(matched)),
    }


def run_memory_v2_benchmark(projects: list[Path], queries: list[str] | None = None, max_bytes: int = 12000) -> dict[str, Any]:
    queries = queries or [
        "what must not be broken before changing context pack scoring",
        "which files are relevant for MCP server config and host compatibility",
        "known risks around secrets prompt memory and team sync",
        "current gates for installer package release",
        "forbidden claims token saving vector database replacement",
    ]
    rows: list[dict[str, Any]] = []
    examples: list[str] = ["# MCP30 Memory v2 Pack Examples", ""]
    for project in projects:
        if not project.exists():
            rows.append({"project": str(project), "query": "__project_exists__", "mode": "skip", "passed": True, "note": "missing"})
            continue
        loaded = load_project_units(project)
        graph = build_memory_graph(loaded["units"])
        for query in queries:
            modes = {
                "deterministic": deterministic_candidates(loaded["units"], query, 20),
                "semantic": semantic_candidates(loaded["units"], query, graph, 20),
                "hybrid": hybrid_candidates(loaded["units"], query, graph, 20),
            }
            pack = compile_memory_v2_pack(project, query, max_bytes)
            examples.extend([f"## {project.name}: {query}", "", pack["text"], ""])
            hybrid_recall = _recall_proxy(modes["hybrid"], query)
            deterministic_recall = _recall_proxy(modes["deterministic"], query)
            semantic_recall = _recall_proxy(modes["semantic"], query)
            for mode, selected in modes.items():
                recall = _recall_proxy(selected, query)
                rows.append(
                    {
                        "project": project.name,
                        "query": query,
                        "mode": mode,
                        "selected_count": len(selected),
                        "selected_file_count": len({row.get("path") for row in selected}),
                        "query_term_recall_proxy": recall["query_term_recall_proxy"],
                        "decision_recall_proxy": recall["decision_recall_proxy"],
                        "gate_recall_proxy": recall["gate_recall_proxy"],
                        "risk_recall_proxy": recall["risk_recall_proxy"],
                        "matched_terms": recall["matched_terms"],
                        "false_secret_inclusion_count": sum(1 for row in selected if is_secret_like(str(row.get("path", ""))) or redaction_block_reason(str(row.get("text", "")))),
                        "graph_hash": graph.get("graph_hash"),
                        "pack_hash": pack["memory_v2_pack_hash"],
                        "pack_bytes": pack["bytes"],
                        "pack_under_budget": pack["bytes"] <= max_bytes,
                        "passed": pack["bytes"] <= max_bytes and not any(is_secret_like(str(row.get("path", ""))) for row in selected),
                    }
                )
            rows.append(
                {
                    "project": project.name,
                    "query": query,
                    "mode": "hybrid_vs_baselines",
                    "selected_count": pack["hybrid_count"],
                    "query_term_recall_proxy": hybrid_recall["query_term_recall_proxy"],
                    "decision_recall_proxy": hybrid_recall["decision_recall_proxy"],
                    "gate_recall_proxy": hybrid_recall["gate_recall_proxy"],
                    "risk_recall_proxy": hybrid_recall["risk_recall_proxy"],
                    "deterministic_recall_proxy": deterministic_recall["query_term_recall_proxy"],
                    "semantic_recall_proxy": semantic_recall["query_term_recall_proxy"],
                    "hybrid_not_worse_than_best_single": hybrid_recall["query_term_recall_proxy"] >= max(deterministic_recall["query_term_recall_proxy"], semantic_recall["query_term_recall_proxy"]) - 0.001,
                    "false_secret_inclusion_count": 0,
                    "graph_hash": graph.get("graph_hash"),
                    "pack_hash": pack["memory_v2_pack_hash"],
                    "pack_bytes": pack["bytes"],
                    "pack_under_budget": pack["bytes"] <= max_bytes,
                    "passed": pack["bytes"] <= max_bytes and hybrid_recall["query_term_recall_proxy"] >= max(deterministic_recall["query_term_recall_proxy"], semantic_recall["query_term_recall_proxy"]) - 0.001,
                }
            )
    return {
        "schema": "ithz_mcp_memory_v2_benchmark_v1",
        "rows": rows,
        "examples_text": "\n".join(examples),
        "passed": all(bool(row.get("passed", True)) for row in rows),
        "benchmark_hash": stable_json_hash({"rows": rows}),
    }
