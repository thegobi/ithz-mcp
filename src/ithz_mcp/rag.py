from __future__ import annotations

from collections import Counter
from pathlib import Path
import math
import time
from typing import Any

from .canonical_json import dump_pretty
from .context_index import build_index, load_index_readonly
from .hashing import stable_json_hash
from .memory_v2 import (
    GRAPH_STOPWORDS,
    _safe_units,
    _tokenize,
    build_memory_graph,
    deterministic_candidates,
    hybrid_candidates,
)
from .safety import is_secret_like, redaction_block_reason
from .scoring import classify_text, query_terms
from .retrieval import EmbeddingProvider, ProviderIdentity, annotate_policy_lanes, rrf_fuse, validate_vectors


RAG_SCHEMA = "ithz_mcp_local_rag_index_v1"
RAG_PACK_SCHEMA = "ithz_mcp_local_rag_pack_v1"
DEFAULT_DIMENSIONS = 256
DEFAULT_PROVIDER_IDENTITY = ProviderIdentity(
    backend="local_feature_hashing_v1",
    model="feature_hashing",
    model_revision="builtin",
    tokenizer="ithz_mcp_tokenize_v1",
    normalization="scoring.normalize_text_v1",
    dimension=DEFAULT_DIMENSIONS,
)


def rag_index_path(project: Path) -> Path:
    return project.resolve() / ".ithz_mcp" / "rag" / "rag_index.json"


def _unit_id(unit: dict[str, Any]) -> str:
    return f"{unit.get('path', '')}:{int(unit.get('line', 0))}:{unit.get('kind', '')}"


def _feature_terms(value: str) -> list[str]:
    tokens = _tokenize(value)
    features = list(tokens)
    for a, b in zip(tokens, tokens[1:]):
        if a not in GRAPH_STOPWORDS and b not in GRAPH_STOPWORDS:
            features.append(f"{a}_{b}")
    return features


def _vectorize(features: list[str], dimensions: int) -> dict[str, float]:
    counts: Counter[int] = Counter()
    for feature in features:
        idx = int(stable_json_hash({"f": feature})[:8], 16) % dimensions
        counts[idx] += 1
    norm = math.sqrt(sum(v * v for v in counts.values()))
    if norm <= 0:
        return {}
    return {str(idx): round(value / norm, 6) for idx, value in sorted(counts.items())}


def _cosine_sparse(left: dict[str, float], right: dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    if len(left) > len(right):
        left, right = right, left
    return sum(value * right.get(key, 0.0) for key, value in left.items())


def _provider_identity(value: Any, dimensions: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("provider identity must be an object")
    required = ("backend", "model", "model_revision", "tokenizer", "normalization")
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in required):
        raise ValueError("provider identity fields must be nonempty strings")
    if isinstance(value.get("dimension"), bool) or not isinstance(value.get("dimension"), int) or value["dimension"] <= 0 or value["dimension"] != dimensions:
        raise ValueError("provider identity dimension mismatch")
    return {key: value[key] for key in (*required, "dimension")}


def _normalized_provider_vector(vector: Any, dimensions: int) -> dict[str, float]:
    if not isinstance(vector, (list, tuple)) or len(vector) != dimensions:
        raise ValueError("provider vector shape invalid")
    values = [float(value) for value in vector]
    if not all(math.isfinite(value) for value in values):
        raise ValueError("provider vector nonfinite")
    norm = math.sqrt(sum(value * value for value in values))
    if norm <= 0:
        raise ValueError("provider vector zero norm")
    return {str(index): round(value / norm, 8) for index, value in enumerate(values) if value != 0.0}


def _safe_index_units(project: Path, write_index: bool = True) -> dict[str, Any]:
    index = build_index(project) if write_index else load_index_readonly(project)
    units = _safe_units(list(index.get("units", [])))
    return {
        "index_hash": index.get("index_hash"),
        "project_semantic_hash": index.get("project_semantic_hash"),
        "units": units,
    }


def build_rag_index(project: Path, dimensions: int = DEFAULT_DIMENSIONS, out: Path | None = None, loaded: dict[str, Any] | None = None, write_index: bool = True, provider: EmbeddingProvider | None = None) -> dict[str, Any]:
    project = project.resolve()
    start = time.perf_counter()
    loaded = loaded or _safe_index_units(project, write_index=write_index)
    safe_units = _safe_units(list(loaded.get("units", [])))
    graph = build_memory_graph(safe_units)
    rows: list[dict[str, Any]] = []
    provider_error = None
    provider_vectors = None
    provider_identity = {**DEFAULT_PROVIDER_IDENTITY.as_dict(), "dimension": dimensions}
    if provider is not None:
        try:
            provider_identity = _provider_identity(provider.identity, dimensions)
            candidate_vectors = provider.embed([str(u.get("path", "")) + " " + str(u.get("kind", "")) + " " + str(u.get("text", "")) for u in safe_units])
            if not validate_vectors(candidate_vectors, len(safe_units), dimensions):
                raise ValueError("provider returned malformed vectors")
            provider_vectors = candidate_vectors
        except Exception as exc:  # optional providers must fail closed to deterministic fallback
            provider_error = type(exc).__name__ + ": " + str(exc)
            provider_identity = {**DEFAULT_PROVIDER_IDENTITY.as_dict(), "dimension": dimensions}
    for unit_index, unit in enumerate(safe_units):
        path = str(unit.get("path", ""))
        text = str(unit.get("text", ""))
        if is_secret_like(path) or redaction_block_reason(text):
            continue
        kind = str(unit.get("kind", "line"))
        features = _feature_terms(path + " " + kind + " " + text)
        vector = (_normalized_provider_vector(provider_vectors[unit_index], dimensions) if provider_vectors is not None else _vectorize(features, dimensions))
        if not vector:
            continue
        categories = classify_text(text, path, kind).get("categories", [])
        rows.append(
            {
                "id": _unit_id(unit),
                "path": path,
                "line": int(unit.get("line", 0)),
                "kind": kind,
                "text": text[:500],
                "categories": categories,
                **{key: unit[key] for key in ("status", "verification_state", "valid_from", "valid_until", "scope") if key in unit},
                "features": sorted(set(features))[:32],
                "vector": vector,
            }
        )
    rag = {
        "schema": RAG_SCHEMA,
        "project": str(project),
        "dimensions": dimensions,
        "embedding_backend": provider_identity["backend"],
        "embedding_identity": provider_identity,
        "source_index_hash": loaded.get("index_hash"),
        "project_semantic_hash": loaded.get("project_semantic_hash"),
        "graph_hash": graph.get("graph_hash"),
        "unit_count": len(rows),
        "units": sorted(rows, key=lambda row: (row["path"], row["line"], row["kind"], row["text"])),
    }
    rag["rag_index_hash"] = stable_json_hash(
        {
            "schema": rag["schema"],
            "dimensions": rag["dimensions"],
            "embedding_backend": rag["embedding_backend"],
            "embedding_identity": rag["embedding_identity"],
            "source_index_hash": rag["source_index_hash"],
            "units": rag["units"],
        }
    )
    rag["build_ms"] = int((time.perf_counter() - start) * 1000)
    if provider_error:
        rag["provider_fallback"] = True
        rag["provider_error"] = provider_error
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(dump_pretty(rag), encoding="utf-8")
    return rag


def load_rag_index(project: Path) -> dict[str, Any] | None:
    path = rag_index_path(project)
    if not path.exists():
        return None
    try:
        import json

        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) and loaded.get("schema") == RAG_SCHEMA else None


def ensure_rag_index(project: Path, dimensions: int = DEFAULT_DIMENSIONS, rebuild: bool = False, write_cache: bool = True, loaded: dict[str, Any] | None = None, write_index: bool = True, provider: EmbeddingProvider | None = None) -> dict[str, Any]:
    project = project.resolve()
    if loaded is None:
        loaded = _safe_index_units(project, write_index=write_index)
    cached = None if rebuild else load_rag_index(project)
    expected_source = loaded.get("index_hash") if loaded else None
    cache_identity = cached.get("embedding_identity", {}) if cached else {}
    expected_identity = {**DEFAULT_PROVIDER_IDENTITY.as_dict(), "dimension": dimensions}
    if provider is not None:
        try:
            expected_identity = dict(provider.identity)
        except Exception:
            expected_identity = {"backend": "__invalid_provider__"}
    if cached and int(cached.get("dimensions", 0)) == int(dimensions) and cache_identity == expected_identity and expected_source and cached.get("source_index_hash") == expected_source:
        return {**cached, "cache_status": "hit"}
    built = build_rag_index(project, dimensions, rag_index_path(project) if write_cache else None, loaded=loaded, write_index=write_index, provider=provider)
    return {**built, "cache_status": "rebuilt"}


def rag_status(project: Path) -> dict[str, Any]:
    project = project.resolve()
    cached = load_rag_index(project)
    if not cached:
        return {
            "schema": "ithz_mcp_rag_status_v1",
            "project": str(project),
            "index_exists": False,
            "index_path": str(rag_index_path(project)),
            "next": "run rag-index-build or rag-context-pack",
        }
    return {
        "schema": "ithz_mcp_rag_status_v1",
        "project": str(project),
        "index_exists": True,
        "index_path": str(rag_index_path(project)),
        "rag_index_hash": cached.get("rag_index_hash"),
        "source_index_hash": cached.get("source_index_hash"),
        "unit_count": cached.get("unit_count"),
        "dimensions": cached.get("dimensions"),
        "embedding_backend": cached.get("embedding_backend"),
        "embedding_identity": cached.get("embedding_identity"),
    }


def rag_search(project: Path, query: str, limit: int = 12, rebuild: bool = False, dimensions: int = DEFAULT_DIMENSIONS, write_cache: bool = True, loaded: dict[str, Any] | None = None, write_index: bool = True, provider: EmbeddingProvider | None = None) -> dict[str, Any]:
    start = time.perf_counter()
    index = ensure_rag_index(project, dimensions, rebuild, write_cache, loaded=loaded, write_index=write_index, provider=provider)
    # Never query an optional provider against a deterministic fallback index:
    # the vectors occupy incompatible spaces even if the provider is available now.
    if provider is not None and index.get("embedding_backend") != "local_feature_hashing_v1":
        try:
            query_vectors = provider.embed([query])
            if not validate_vectors(query_vectors, 1, int(index.get("dimensions", dimensions))):
                raise ValueError("provider returned malformed query vector")
            query_vec = _normalized_provider_vector(query_vectors[0], int(index.get("dimensions", dimensions)))
        except Exception:
            # A provider failure cannot rank across incompatible spaces.
            if index.get("embedding_backend") != "local_feature_hashing_v1":
                return rag_search(project, query, limit, rebuild=True, dimensions=dimensions, write_cache=write_cache, loaded=loaded, write_index=write_index, provider=None)
            query_vec = _vectorize(_feature_terms(query), int(index.get("dimensions", dimensions)))
    else:
        query_vec = _vectorize(_feature_terms(query), int(index.get("dimensions", dimensions)))
    q_terms = set(query_terms(query)) | set(_tokenize(query))
    rows = []
    for unit in index.get("units", []):
        path = str(unit.get("path", ""))
        text = str(unit.get("text", ""))
        if is_secret_like(path) or redaction_block_reason(text):
            continue
        vector_score = _cosine_sparse(query_vec, unit.get("vector", {}))
        if vector_score <= 0:
            continue
        categories = list(unit.get("categories", []))
        category_boost = 0.0
        if "gate" in q_terms and "gate" in categories:
            category_boost += 0.12
        if "risk" in q_terms and "risk" in categories:
            category_boost += 0.10
        if "decision" in q_terms and "decision" in categories:
            category_boost += 0.10
        if "claim" in q_terms and "forbidden_claim" in categories:
            category_boost += 0.08
        matched = sorted(q_terms & set(unit.get("features", [])))
        score = vector_score + category_boost
        rows.append(
            {
                "id": unit.get("id"),
                "path": path,
                "line": int(unit.get("line", 0)),
                "kind": unit.get("kind", "line"),
                "text": text,
                "categories": categories,
                "score": round(score, 6),
                "vector_score": round(vector_score, 6),
                "category_boost": round(category_boost, 6),
                "matched_terms": matched,
                "why_selected": ["local_vector_similarity"] + (["category_boost"] if category_boost else []),
                **{key: unit[key] for key in ("status", "verification_state", "valid_from", "valid_until", "scope") if key in unit},
            }
        )
    rows.sort(key=lambda row: (-float(row["score"]), row["path"], row["line"], row["text"]))
    selected = annotate_policy_lanes(rows)[:limit]
    # Policy lanes are intentionally evaluated independently of similarity;
    # they must never become ordinary zero-score "matches".
    # Policy extraction uses source units rather than vector rows. A policy
    # with no lexical features or a rejected optional embedding is still a
    # policy row, never a fabricated similarity match.
    policy_source = _safe_units(list(loaded.get("units", []))) if isinstance(loaded, dict) else _safe_index_units(project, write_index=write_index)["units"]
    all_tagged = annotate_policy_lanes(policy_source)
    lane_rows = {
        "warning_history": [row for row in all_tagged if row.get("policy_lane") == "warning_history"][:limit],
        "mandatory_hard_policy": [row for row in all_tagged if row.get("policy_lane") == "mandatory_hard_policy"][:limit],
        "blocking_conflict": [row for row in all_tagged if row.get("policy_lane") == "blocking_conflict"][:limit],
    }
    return {
        "schema": "ithz_mcp_rag_search_v1",
        "project": str(project.resolve()),
        "query": query,
        "rag_index_hash": index.get("rag_index_hash"),
        "source_index_hash": index.get("source_index_hash"),
        "embedding_backend": index.get("embedding_backend"),
        "cache_status": index.get("cache_status", "unknown"),
        "rows": selected,
        "policy_rows": lane_rows,
        "row_count": len(selected),
        "no_answer": not selected,
        "search_ms": int((time.perf_counter() - start) * 1000),
    }


def compile_rag_context_pack(project: Path, query: str, max_bytes: int = 16000, rebuild: bool = False, write_cache: bool = True, write_index: bool = True) -> dict[str, Any]:
    start = time.perf_counter()
    project = project.resolve()
    loaded = _safe_index_units(project, write_index=write_index)
    search = rag_search(project, query, limit=16, rebuild=rebuild, write_cache=write_cache, loaded=loaded, write_index=write_index)
    graph = build_memory_graph(loaded["units"])
    deterministic = deterministic_candidates(loaded["units"], query, 12)
    hybrid = hybrid_candidates(loaded["units"], query, graph, 12)
    policy_rows = search.get("policy_rows", {})
    pack_hash = stable_json_hash(
        {
            "schema": RAG_PACK_SCHEMA,
            "query": query,
            "rag_index_hash": search.get("rag_index_hash"),
            "rag_rows": [
                {"path": row.get("path"), "line": row.get("line"), "text": row.get("text"), "score": row.get("score")}
                for row in search.get("rows", [])
            ],
            "hybrid_rows": [
                {"path": row.get("path"), "line": row.get("line"), "text": row.get("text"), "score": row.get("score")}
                for row in hybrid
            ],
            "policy_rows": policy_rows,
        }
    )
    lines = [
        "# ITHZ-MCP Local RAG Context Pack",
        "",
        f"- query: {query}",
        f"- project_root: {project}",
        f"- rag_pack_hash: {pack_hash}",
        f"- rag_index_hash: {search.get('rag_index_hash')}",
        f"- embedding_backend: {search.get('embedding_backend')}",
        f"- cache_status: {search.get('cache_status')}",
        "",
        "## Mandatory and Conflict Context",
    ]
    policy_lines: list[str] = []
    for lane, label in (("mandatory_hard_policy", "MANDATORY POLICY"), ("blocking_conflict", "BLOCKING CONFLICT"), ("warning_history", "HISTORICAL WARNING - NOT ACTIVE")):
        for row in policy_rows.get(lane, [])[:8]:
            scope_note = " scope_requires_check=true" if row.get("scope_requires_check") else ""
            policy_lines.append(f"- [{label}]{scope_note} `{row.get('path')}:{row.get('line')}`: {str(row.get('text', ''))[:340]}")
    if not policy_lines:
        policy_lines.append("- No mandatory, conflict, or historical-policy rows were identified.")
    lines.extend(policy_lines)
    lines.extend(["", "## Hybrid RAG Evidence"])
    ranked = rrf_fuse({"rag_vector": search.get("rows", []), "memory_v2": hybrid}, limit=24)
    if not ranked:
        lines.append("- No RAG evidence matched. Use direct source inspection or broaden the query.")
    for row in ranked[:12]:
        text = str(row.get("text", ""))
        if len(text) > 340:
            text = text[:340].rstrip() + "..."
        modes = ",".join(row.get("retrieval_modes", []))
        lines.append(
            f"- `{row.get('path')}:{row.get('line')}` [{row.get('kind')}] "
            f"rrf_score={row.get('rrf_score')} modes={modes}: {text}"
        )
    lines.extend(["", "## Deterministic Backstop"])
    for row in deterministic[:8]:
        lines.append(f"- `{row.get('path')}:{row.get('line')}` score={row.get('score')} why={','.join(row.get('why_selected', []))}")
    lines.extend(
        [
            "",
            "## Evidence Gaps",
            "- Local RAG is a derived index, not the source of truth.",
            "- Direct source inspection is still required before edits.",
            "- No cloud embedding, production database, Git replacement, or general token-saving claim is used.",
        ]
    )
    text = "\n".join(lines).rstrip() + "\n"
    policy_bytes = len("\n".join(lines[:lines.index("## Hybrid RAG Evidence")]).encode("utf-8")) if "## Hybrid RAG Evidence" in lines else 0
    fallback_required = policy_bytes > max_bytes
    if len(text.encode("utf-8")) > max_bytes:
        marker = "\n\n[truncated deterministically]\n"
        allowed = max(0, max_bytes - len(marker.encode("utf-8")))
        text = text.encode("utf-8")[:allowed].decode("utf-8", errors="ignore") + marker
    return {
        "schema": RAG_PACK_SCHEMA,
        "project": str(project),
        "query": query,
        "text": text,
        "bytes": len(text.encode("utf-8")),
        "rag_pack_hash": pack_hash,
        "rag_index_hash": search.get("rag_index_hash"),
        "embedding_backend": search.get("embedding_backend"),
        "rag_row_count": search.get("row_count", 0),
        "policy_rows": policy_rows,
        "fallback_required": fallback_required,
        "selected_files": sorted({str(row.get("path", "")) for row in ranked if row.get("path")}),
        "generation_ms": int((time.perf_counter() - start) * 1000),
    }


def run_rag_benchmark(projects: list[Path], queries: list[str] | None = None, max_bytes: int = 12000) -> dict[str, Any]:
    queries = queries or [
        "decision gate risk forbidden claim",
        "which files are relevant for MCP server config",
        "prompt memory secrets team sync",
        "installer package release gates",
    ]
    rows: list[dict[str, Any]] = []
    examples = ["# MCP31 Local RAG Examples", ""]
    for project in projects:
        if not project.exists():
            rows.append({"project": str(project), "query": "__project_exists__", "mode": "skip", "passed": True, "note": "missing"})
            continue
        status_before = rag_status(project)
        index = ensure_rag_index(project, rebuild=True)
        rows.append(
            {
                "project": project.name,
                "query": "__index_build__",
                "mode": "rag",
                "unit_count": index.get("unit_count"),
                "rag_index_hash": index.get("rag_index_hash"),
                "passed": int(index.get("unit_count", 0)) > 0 and bool(index.get("rag_index_hash")),
                "note": "rebuilt" if not status_before.get("index_exists") else "refreshed",
            }
        )
        for query in queries:
            search = rag_search(project, query, limit=12)
            pack = compile_rag_context_pack(project, query, max_bytes=max_bytes)
            text = "\n".join(str(row.get("path", "")) + " " + str(row.get("text", "")) for row in search.get("rows", [])).lower()
            q_terms = {term for term in (set(query_terms(query)) | set(_tokenize(query))) if term not in GRAPH_STOPWORDS}
            matched = {term for term in q_terms if term in text}
            false_secret_count = sum(1 for row in search.get("rows", []) if is_secret_like(str(row.get("path", ""))) or redaction_block_reason(str(row.get("text", ""))))
            rows.append(
                {
                    "project": project.name,
                    "query": query,
                    "mode": "rag_context_pack",
                    "selected_count": search.get("row_count", 0),
                    "query_term_recall_proxy": round(len(matched) / max(1, len(q_terms)), 3),
                    "false_secret_inclusion_count": false_secret_count,
                    "pack_bytes": pack["bytes"],
                    "pack_hash": pack["rag_pack_hash"],
                    "rag_index_hash": pack["rag_index_hash"],
                    "passed": pack["bytes"] <= max_bytes and false_secret_count == 0 and search.get("row_count", 0) > 0,
                }
            )
            examples.extend([f"## {project.name}: {query}", "", pack["text"], ""])
    return {
        "schema": "ithz_mcp_local_rag_benchmark_v1",
        "rows": rows,
        "examples_text": "\n".join(examples),
        "passed": all(bool(row.get("passed", True)) for row in rows),
        "benchmark_hash": stable_json_hash({"rows": rows}),
    }
