"""Small deterministic retrieval building blocks.

Providers are deliberately optional: this module defines the contract and
fusion rules without selecting or downloading a model.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence
import math
from datetime import datetime, timezone
from .hashing import stable_json_hash


class EmbeddingProvider(Protocol):
    """Optional local provider contract; implementations own model loading."""

    @property
    def identity(self) -> dict[str, Any]: ...

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...


@dataclass(frozen=True)
class ProviderIdentity:
    backend: str
    model: str
    model_revision: str
    tokenizer: str
    normalization: str
    dimension: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "model": self.model,
            "model_revision": self.model_revision,
            "tokenizer": self.tokenizer,
            "normalization": self.normalization,
            "dimension": self.dimension,
        }


def rrf_fuse(rankings: dict[str, Sequence[dict[str, Any]]], limit: int = 20, k: int = 60) -> list[dict[str, Any]]:
    """Fuse ranked result lists with stable reciprocal-rank scores.

    The first appearance supplies the row payload; ties use the canonical row
    identity so results remain reproducible across providers and runs.
    """
    merged: dict[str, dict[str, Any]] = {}
    if k < 1 or limit < 1:
        raise ValueError("rrf_limit_and_k_must_be_positive")
    for source in sorted(rankings):
        seen: set[str] = set()
        for row in rankings[source]:
            key = retrieval_row_id(row)
            if key in seen:
                continue
            seen.add(key)
            item = merged.setdefault(key, {**row, "retrieval_modes": [], "rrf_score": 0.0})
            item["rrf_score"] += 1.0 / (k + len(seen))
            item["retrieval_modes"] = sorted(set(item["retrieval_modes"]) | {source})
    rows = list(merged.values())
    rows.sort(key=lambda row: (-float(row.get("rrf_score", 0.0)), str(row.get("path", "")), int(row.get("line", 0)), str(row.get("kind", "")), str(row.get("text", ""))))
    return rows[:limit]


def retrieval_row_id(row: dict[str, Any]) -> str:
    return str(row.get("id") or row.get("event_id") or (
        f"{row['path']}:{row.get('line', 0)}:{row.get('kind', '')}" if row.get("path") else stable_json_hash(row)))


def policy_lane(row: dict[str, Any]) -> str:
    """Label retrieval context without granting it authority."""
    status = str(row.get("status", "")).lower()
    verification = str(row.get("verification_state", "")).lower()
    from .memory_integrity import timestamp_instant
    current = datetime.now(timezone.utc)
    invalid_time = False
    try:
        invalid_time = bool((row.get("valid_from") and timestamp_instant(row["valid_from"]) > current)
            or (row.get("valid_until") and timestamp_instant(row["valid_until"]) <= current))
    except (ValueError, TypeError):
        invalid_time = True
    excluded = {"expired", "revoked", "quarantined", "superseded", "challenged", "invalid", "unverified", "unverified_history", "legacy_unverified_abstraction", "candidate"}
    if status in excluded or verification in excluded or invalid_time:
        return "warning_history"
    categories = {str(value).lower() for value in row.get("categories", [])}
    text = str(row.get("text", "")).lower()
    if "mandatory" in categories or "hard_policy" in categories or "must not" in text or "nesmie" in text:
        return "mandatory_hard_policy"
    if "conflict" in categories or "conflict" in text or "konflikt" in text:
        return "blocking_conflict"
    return "context"


def annotate_policy_lanes(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    annotated = []
    for row in rows:
        scope = str(row.get("scope", "")).strip().lower()
        annotated.append({
            **row,
            "policy_lane": policy_lane(row),
            # Search has no asserted execution scope. A scoped policy remains
            # visible but cannot be represented as active for this query.
            "scope_requires_check": bool(scope and scope not in {"global", "all", "*"}),
        })
    return annotated


def validate_vectors(vectors: Sequence[Sequence[float]], count: int, dimension: int) -> bool:
    return len(vectors) == count and all(len(vector) == dimension and all(math.isfinite(float(value)) for value in vector) for vector in vectors)


def retrieval_metrics(results: Sequence[Sequence[dict[str, Any]]], relevant: Sequence[set[str]], k: int = 5) -> dict[str, Any]:
    """Report labeled retrieval quality; no-answer queries have a separate metric."""
    if len(results) != len(relevant) or k < 1:
        raise ValueError("metric_query_count_or_k_invalid")
    recalls: list[float] = []
    reciprocal: list[float] = []
    for rows, gold in zip(results, relevant):
        ids = [retrieval_row_id(row) for row in rows[:k]]
        if not gold:
            continue
        else:
            recalls.append(len(set(ids) & gold) / len(gold))
        reciprocal.append(next((1.0 / (i + 1) for i, item in enumerate(ids) if item in gold), 0.0))
    no_answer = [not gold for gold in relevant]
    no_answer_correct = sum(1 for rows, gold in zip(results, relevant) if not gold and not rows)
    return {"recall_at_k": round(sum(recalls) / len(recalls), 6) if recalls else None,
            "mrr": round(sum(reciprocal) / len(reciprocal), 6) if reciprocal else None,
            "no_answer_accuracy": round(no_answer_correct / sum(no_answer), 6) if any(no_answer) else None,
            "queries": len(results), "answerable_queries": len(recalls), "k": k}
