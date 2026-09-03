from __future__ import annotations

from pathlib import Path
from typing import Any

from .context_index import load_or_build_index, search_context
from .hashing import sha256_text, stable_json_hash
from .scoring import classify_text, score_unit, section_for_unit


PACK_SECTIONS = (
    "Relevant Decisions",
    "Relevant Gates",
    "Known Risks / Must Not Break",
    "Forbidden Claims",
    "Candidate Files",
)

QUICK_SUPPORT_TERMS = (
    "decision",
    "rozhod",
    "gate",
    "passed",
    "failed",
    "risk",
    "limitation",
    "claim",
    "safety",
    "regression",
    "secret",
    "forbidden",
    "must not",
    "do not",
    "nesmie",
    "zakazane",
)


def _merge_units(results: list[dict[str, Any]], index: dict[str, Any], query: str) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in results:
        by_key[(row["path"], int(row["line"]), row["text"])] = row
    supplemental = 0
    for unit in index["units"]:
        quick_hay = (unit.get("path", "") + " " + unit.get("text", "")).lower()
        if unit.get("kind") not in {"decision", "gate", "risk_or_next", "heading"} and not any(term in quick_hay for term in QUICK_SUPPORT_TERMS):
            continue
        classified = classify_text(unit["text"], unit["path"], unit.get("kind", ""))
        categories = set(classified["categories"])
        if not categories & {"decision", "gate", "risk", "forbidden_claim", "command_result"}:
            continue
        scored = score_unit(unit, query)
        if not scored:
            base = int(sum(classified.get("score_components", {}).values()) or 1)
            scored = {
                "score": base,
                "reasons": [f"support:{c}" for c in sorted(categories)[:4]],
                "score_components": classified.get("score_components", {}),
                "why_selected": sorted(categories)[:4],
                "categories": sorted(categories),
            }
        if scored:
            key = (unit["path"], int(unit["line"]), unit["text"])
            if key not in by_key:
                by_key[key] = {**unit, **scored}
                supplemental += 1
                if supplemental >= 48:
                    break
    merged = list(by_key.values())
    merged.sort(key=lambda r: (-int(r["score"]), r["path"], int(r["line"]), r["text"]))
    return merged[:80]


def build_context_pack(project: Path, query: str, max_bytes: int = 20000) -> dict[str, Any]:
    index = load_or_build_index(project)
    results = _merge_units(search_context(project, query, limit=50), index, query)
    selected_paths = sorted({r["path"] for r in results})
    semantic = {
        "query": query,
        "project_semantic_hash": index["project_semantic_hash"],
        "index_hash": index["index_hash"],
        "results": [
            {
                "path": r["path"],
                "line": r["line"],
                "kind": r["kind"],
                "text": r["text"],
                "score": r["score"],
                "reasons": r.get("reasons", []),
                "score_components": r.get("score_components", {}),
                "why_selected": r.get("why_selected", []),
                "categories": r.get("categories", []),
            }
            for r in results
        ],
    }
    pack_hash = stable_json_hash(semantic)
    lines = [
        "# ITHZ-MCP Context Pack",
        "",
        f"- query: {query}",
        f"- project_root: {project.resolve()}",
        f"- project_semantic_hash: {index['project_semantic_hash']}",
        f"- index_hash: {index['index_hash']}",
        f"- semantic_context_pack_hash: {pack_hash}",
        "",
        "## Selected Files",
    ]
    for p in selected_paths:
        lines.append(f"- {p}")
    grouped = {section: [] for section in PACK_SECTIONS}
    for r in results:
        grouped[section_for_unit(r)].append(r)
    lines += ["", "## Excerpts"]
    if not results:
        lines += ["", "Not enough evidence found for this query."]
    for section in PACK_SECTIONS:
        if not grouped[section]:
            continue
        lines += ["", f"## {section}"]
        for r in grouped[section][:18]:
            lines.append(f"- `{r['path']}:{r['line']}` ({r['kind']}, score={r['score']}): {r['text']}")
            lines.append(f"  - why_selected: {', '.join(r.get('why_selected', [])) or 'file relevance'}")
            lines.append(f"  - reasons: {', '.join(r.get('reasons', []))}")
            lines.append(f"  - score_components: {r.get('score_components', {})}")
    lines += [
        "",
        "## Evidence Gaps",
        "- Context pack is deterministic keyword/support scoring and should not replace direct source inspection.",
        "- If required gate, risk, or decision evidence is missing, run a focused query or inspect the listed files.",
    ]
    lines += ["", "## Next Suggested Files"]
    for p in selected_paths[:8]:
        lines.append(f"- {p}")
    text = "\n".join(lines).rstrip() + "\n"
    if len(text.encode("utf-8")) > max_bytes:
        marker = "\n\n[truncated to max_bytes while preserving semantic hash]\n"
        allowed = max(0, max_bytes - len(marker.encode("utf-8")))
        text = text.encode("utf-8")[:allowed].decode("utf-8", errors="ignore") + marker
    return {
        "text": text,
        "semantic_context_pack_hash": pack_hash,
        "selected_files": selected_paths,
        "selected_units": results,
        "bytes": len(text.encode("utf-8")),
    }


def pack_text_hash(text: str) -> str:
    return sha256_text(text)

