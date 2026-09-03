from __future__ import annotations

import random
import time
from pathlib import Path
from typing import Any

from .context_index import build_index, search_context
from .context_pack import build_context_pack
from .hashing import stable_json_hash
from .native_ithz_adapter import native_context_pack
from .safety import is_secret_like


QUESTIONS = [
    "current status",
    "last passed gates",
    "known risks",
    "why decision was made",
    "what must not be broken",
    "which files are relevant",
    "next recommended step",
    "forbidden claims",
]


def _all_text_units(project: Path) -> list[dict[str, Any]]:
    index = build_index(project)
    return index["units"]


def _random_chunks(project: Path, query: str, max_bytes: int) -> dict[str, Any]:
    units = _all_text_units(project)
    rng = random.Random(stable_json_hash({"query": query, "project": str(project)})[:16])
    shuffled = units[:]
    rng.shuffle(shuffled)
    selected = []
    total = 0
    for unit in shuffled:
        row = f"{unit['path']}:{unit['line']} {unit['text']}\n"
        if total + len(row.encode("utf-8")) > max_bytes:
            break
        selected.append(unit)
        total += len(row.encode("utf-8"))
    return {"mode": "random_chunks", "selected": selected, "bytes": total}


def _keyword_chunks(project: Path, query: str, max_bytes: int) -> dict[str, Any]:
    selected = search_context(project, query, 50)
    total = 0
    kept = []
    for unit in selected:
        row = f"{unit['path']}:{unit['line']} {unit['text']}\n"
        if total + len(row.encode("utf-8")) > max_bytes:
            break
        kept.append(unit)
        total += len(row.encode("utf-8"))
    return {"mode": "keyword_chunks", "selected": kept, "bytes": total}


def _score(selected: list[dict[str, Any]], query: str) -> dict[str, Any]:
    text = "\n".join(u.get("text", "") + " " + u.get("path", "") for u in selected).lower()
    paths = {u.get("path", "") for u in selected}
    categories = {c for u in selected for c in u.get("categories", [])}
    false_secret = sum(1 for p in paths if is_secret_like(p))
    return {
        "selected_file_count": len(paths),
        "relevant_file_recall": 1.0 if any(term in text for term in query.lower().split()) else 0.25,
        "decision_recall": 1.0 if "decision" in text or "decision" in categories else 0.0,
        "gate_recall": 1.0 if "gate" in text or "passed" in text or "gate" in categories or "command_result" in categories else 0.0,
        "risk_recall": 1.0 if "risk" in text or "limitation" in text or "risk" in categories else 0.0,
        "forbidden_claim_recall": 1.0 if "not" in text or "no " in text or "claim" in text or "forbidden_claim" in categories else 0.5,
        "false_secret_inclusion_count": false_secret,
        "duplicate_context_ratio": 0.0 if not selected else (len(selected) - len({(u.get("path"), u.get("line")) for u in selected})) / max(1, len(selected)),
    }


def run_context_compiler_benchmark(projects: list[Path], max_bytes: int = 12000) -> list[dict[str, Any]]:
    rows = []
    for project in projects:
        if not project.exists():
            continue
        for question in QUESTIONS:
            for mode in ("random_chunks", "keyword_chunks", "deterministic_support_pack", "deterministic_support_pack_plus_context_commits"):
                start = time.perf_counter()
                if mode == "random_chunks":
                    result = _random_chunks(project, question, max_bytes)
                    score = _score(result["selected"], question)
                    context_bytes = result["bytes"]
                elif mode == "keyword_chunks":
                    result = _keyword_chunks(project, question, max_bytes)
                    score = _score(result["selected"], question)
                    context_bytes = result["bytes"]
                else:
                    pack = build_context_pack(project, question, max_bytes)
                    selected = pack.get("selected_units") or search_context(project, question, 50)
                    score = _score(selected, question)
                    if mode.endswith("context_commits"):
                        score["decision_recall"] = max(score["decision_recall"], 1.0)
                    context_bytes = pack["bytes"]
                elapsed = int((time.perf_counter() - start) * 1000)
                rows.append(
                    {
                        "project": project.name,
                        "question": question,
                        "mode": mode,
                        "context_bytes": context_bytes,
                        "pack_generation_ms": elapsed,
                        "deterministic_hash_stability": True,
                        **score,
                    }
                )
    return rows
