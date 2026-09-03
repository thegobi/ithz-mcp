from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Callable

from .context_pack import build_context_pack
from .hashing import stable_json_hash


FOCUS_PACK_SCHEMA = "ithz_mcp_focus_context_pack_v1"
DEFAULT_TARGET_BYTES = 3500
DEFAULT_MAX_BYTES = 12000

_WORD_RE = re.compile(r"[a-z0-9_.\-/]+")
_PATH_RE = re.compile(r"`([^`]+?)(?::\d+)?`")
_STOPWORDS = {
    "a",
    "aj",
    "ako",
    "and",
    "are",
    "do",
    "for",
    "from",
    "how",
    "in",
    "is",
    "je",
    "k",
    "na",
    "of",
    "or",
    "pre",
    "sa",
    "s",
    "the",
    "to",
    "v",
    "what",
    "with",
    "z",
}
_GUARDRAIL_SECTIONS = ("risk", "must not", "forbidden", "gate", "evidence gap", "limitation")


def _terms(text: str) -> list[str]:
    return sorted({term for term in _WORD_RE.findall(text.lower()) if len(term) > 1 and term not in _STOPWORDS})


def _byte_len(text: str) -> int:
    return len(text.encode("utf-8"))


def _source_hash(source_pack: dict[str, Any]) -> str:
    for key in ("focus_pack_hash", "rag_pack_hash", "context_pack_hash", "semantic_context_pack_hash"):
        value = source_pack.get(key)
        if isinstance(value, str) and value:
            return value
    return stable_json_hash({"text": str(source_pack.get("text", ""))})


def _pack_rows(text: str, query: str) -> list[dict[str, Any]]:
    query_terms = set(_terms(query))
    section = "Evidence"
    rows: list[dict[str, Any]] = []
    for order, raw_line in enumerate(text.splitlines()):
        if raw_line.startswith((" ", "\t")):
            continue
        line = raw_line.strip()
        if line.startswith("##"):
            section = line.lstrip("# ") or "Evidence"
            continue
        if not line.startswith("-"):
            continue
        if section.lower() in {"selected files", "next suggested files"}:
            continue
        lower = f"{section} {line}".lower()
        if line.startswith(
            (
                "- query:",
                "- project_root:",
                "- project_semantic_hash:",
                "- archive_semantic_hash:",
                "- memory_synthesis_hash:",
                "- index_hash:",
                "- semantic_context_pack_hash:",
            )
        ):
            continue
        overlaps = sorted(term for term in query_terms if term in lower)
        guardrail = any(signal in lower for signal in _GUARDRAIL_SECTIONS)
        path_match = _PATH_RE.search(line)
        path = path_match.group(1) if path_match else None
        score = len(overlaps) * 20 + (12 if guardrail else 0) + (5 if path else 0)
        if path:
            normalized_path = path.replace("\\", "/").lower()
            if normalized_path.startswith(("dist/", "dist_", "build/")) or ".egg-info/" in normalized_path:
                score -= 20
            elif normalized_path.startswith("experiments/") or "quality_expectations/" in normalized_path:
                score -= 10
            elif normalized_path.startswith("src/"):
                score += 7
            elif normalized_path.startswith("docs/") or "/" not in normalized_path:
                score += 5
        evidence_text = line.split("): ", 1)[-1] if "): " in line else line
        signature = " ".join(evidence_text.lower().split())
        rows.append(
            {
                "line": line,
                "section": section,
                "order": order,
                "overlaps": overlaps,
                "guardrail": guardrail,
                "path": path,
                "score": score,
                "signature": signature,
            }
        )
    rows.sort(key=lambda row: (-int(row["score"]), int(row["order"]), str(row["line"])))
    deduplicated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        signature = str(row["signature"])
        if signature in seen:
            continue
        seen.add(signature)
        deduplicated.append(row)
    return deduplicated


def _render(query: str, source_hash: str, rows: list[dict[str, Any]], budget: int, source_bytes: int, source_truncated: bool) -> tuple[str, list[dict[str, Any]]]:
    header = [
        "# ITHZ Focus Context Pack",
        "",
        f"- objective: {query}",
        "- done: enough evidence to choose the next source files or action",
        "- non_goals: exhaustive project summary or broad source dump",
        "- route: use this working set first; broaden only when the evidence gap says so",
        "- next_signal: inspect selected files, or request the full source pack when fallback_required is true",
        f"- source_pack_hash: {source_hash}",
        f"- source_pack_bytes: {source_bytes}",
        f"- budget_bytes: {budget}",
        "",
        "## Working Set",
    ]
    footer = [
        "",
        "## Evidence Gaps",
        "- This is a compact orientation layer, not a replacement for direct source inspection.",
    ]
    if source_truncated:
        footer.append("- The source pack reached its byte cap; coverage is relative only to evidence emitted by that source pack.")
    selected: list[dict[str, Any]] = []
    body: list[str] = []
    current_section: str | None = None
    reserved: list[dict[str, Any]] = []
    reserved_sections: set[str] = set()
    for row in rows:
        section = str(row["section"])
        if row["guardrail"] and section not in reserved_sections:
            reserved.append(row)
            reserved_sections.add(section)
    ordered_rows = reserved + [row for row in rows if row not in reserved]
    for row in ordered_rows:
        section = str(row["section"])
        candidate = list(header)
        candidate.extend(body)
        if section != current_section:
            candidate.extend(["", f"### {section}"])
        candidate.append(str(row["line"]))
        candidate.extend(footer)
        if _byte_len("\n".join(candidate).rstrip() + "\n") > budget:
            continue
        if section != current_section:
            body.extend(["", f"### {section}"])
            current_section = section
        body.append(str(row["line"]))
        selected.append(row)
    if not selected:
        body.append("- No evidence row fits the requested budget.")
    text = "\n".join(header + body + footer).rstrip() + "\n"
    return text, selected


def focus_context_pack_from_source(
    source_pack: dict[str, Any],
    query: str,
    target_bytes: int = DEFAULT_TARGET_BYTES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    if target_bytes < 1000:
        raise ValueError("target_bytes must be at least 1000")
    if max_bytes < target_bytes:
        raise ValueError("max_bytes must be greater than or equal to target_bytes")
    source_text = str(source_pack.get("text", ""))
    source_bytes = _byte_len(source_text)
    source_truncated = "[truncated" in source_text.lower()
    source_hash = _source_hash(source_pack)
    query_terms = set(_terms(query))
    rows = _pack_rows(source_text, query)
    source_covered_terms = {term for row in rows for term in row["overlaps"]}
    source_guardrail_sections = {str(row["section"]) for row in rows if row["guardrail"]}
    source_fact_rows = [row for row in rows if "evidence gap" not in str(row["section"]).lower()]
    source_evidence_count = len(source_fact_rows)
    source_has_no_query_evidence = bool(query_terms) and not source_covered_terms

    if source_bytes <= target_bytes:
        result = {
            "schema": FOCUS_PACK_SCHEMA,
            "text": source_text,
            "bytes": source_bytes,
            "source_pack_bytes": source_bytes,
            "source_pack_truncated": source_truncated,
            "bytes_saved_vs_source": 0,
            "estimated_tokens": math.ceil(source_bytes / 4),
            "estimated_tokens_saved_vs_source": 0,
            "target_bytes": target_bytes,
            "budget_used": source_bytes,
            "budget_tier": "source_already_compact",
            "escalated": False,
            "escalation_reason": None,
            "fallback_required": source_evidence_count == 0 or source_has_no_query_evidence,
            "query_term_coverage": 0.0 if source_has_no_query_evidence else 1.0,
            "selected_files": list(source_pack.get("selected_files", [])),
            "source_pack_hash": source_hash,
        }
        result["focus_pack_hash"] = stable_json_hash({key: value for key, value in result.items() if key != "focus_pack_hash"})
        return result

    tiers = []
    for tier in (target_bytes, min(max_bytes, target_bytes * 2), max_bytes):
        if tier not in tiers:
            tiers.append(tier)
    selected_text = ""
    selected_rows: list[dict[str, Any]] = []
    coverage = 1.0
    escalation_reason: str | None = None
    fallback_required = False
    selected_tier = tiers[-1]
    for index, tier in enumerate(tiers):
        text, chosen = _render(query, source_hash, rows, tier, source_bytes, source_truncated)
        covered_terms = {term for row in chosen for term in row["overlaps"]}
        coverage = len(covered_terms) / len(source_covered_terms) if source_covered_terms else (0.0 if query_terms else 1.0)
        selected_guardrails = {str(row["section"]) for row in chosen if row["guardrail"]}
        minimum_rows = min(3, source_evidence_count)
        enough_rows = len(chosen) >= minimum_rows
        guardrails_preserved = source_guardrail_sections.issubset(selected_guardrails)
        selected_text, selected_rows, selected_tier = text, chosen, tier
        if coverage >= 0.8 and enough_rows and guardrails_preserved:
            break
        reasons = []
        if coverage < 0.8:
            reasons.append("query_term_coverage")
        if not enough_rows:
            reasons.append("too_few_evidence_rows")
        if not guardrails_preserved:
            reasons.append("guardrail_section_missing")
        escalation_reason = ",".join(reasons)
        if index == len(tiers) - 1:
            fallback_required = True

    if _byte_len(selected_text) >= source_bytes:
        selected_text = source_text
        selected_rows = rows
        selected_tier = source_bytes
        coverage = 1.0
        fallback_required = False
        escalation_reason = "source_pack_was_smaller"

    if source_evidence_count == 0 or source_has_no_query_evidence:
        fallback_required = True
        escalation_reason = "source_pack_has_no_query_evidence" if source_has_no_query_evidence else "source_pack_has_no_evidence_rows"

    selected_files = sorted({str(row["path"]) for row in selected_rows if row.get("path")})
    output_bytes = _byte_len(selected_text)
    result = {
        "schema": FOCUS_PACK_SCHEMA,
        "text": selected_text,
        "bytes": output_bytes,
        "source_pack_bytes": source_bytes,
        "source_pack_truncated": source_truncated,
        "bytes_saved_vs_source": max(0, source_bytes - output_bytes),
        "estimated_tokens": math.ceil(output_bytes / 4),
        "estimated_tokens_saved_vs_source": max(0, math.ceil(source_bytes / 4) - math.ceil(output_bytes / 4)),
        "target_bytes": target_bytes,
        "budget_used": selected_tier,
        "budget_tier": "target" if selected_tier == target_bytes else "expanded" if selected_tier < max_bytes else "maximum",
        "escalated": selected_tier > target_bytes,
        "escalation_reason": escalation_reason,
        "fallback_required": fallback_required,
        "query_term_coverage": round(coverage, 4),
        "query_terms": sorted(query_terms),
        "source_covered_terms": sorted(source_covered_terms),
        "selected_files": selected_files,
        "source_pack_hash": source_hash,
    }
    result["focus_pack_hash"] = stable_json_hash({key: value for key, value in result.items() if key != "focus_pack_hash"})
    return result


def compile_focus_context_pack(
    project: Path,
    query: str,
    target_bytes: int = DEFAULT_TARGET_BYTES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    source_builder: Callable[[Path, str, int], dict[str, Any]] = build_context_pack,
) -> dict[str, Any]:
    source_pack = source_builder(project, query, max_bytes)
    return focus_context_pack_from_source(source_pack, query, target_bytes, max_bytes)
