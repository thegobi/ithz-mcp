from __future__ import annotations

from functools import lru_cache
import re
import unicodedata
from typing import Any


GATE_PATTERNS = (
    "gate",
    "gates",
    "acceptance",
    "safety",
    "regression",
    "hard rules",
    "stop conditions",
    "must not break",
    "test",
    "tests",
    "passed",
    "failed",
    "prejst",
    "preslo",
    "zlyhalo",
    "brany",
    "tvrde pravidla",
    "bezpecnostne pravidla",
    "nesmie sa rozbit",
)

RISK_PATTERNS = (
    "risk",
    "risks",
    "known risks",
    "limitation",
    "limitations",
    "unsafe",
    "corrupt",
    "redaction",
    "secret",
    "stale",
    "rizika",
    "limity",
)

DECISION_PATTERNS = (
    "decision",
    "decisions",
    "decided",
    "reason",
    "because",
    "rozhodnutie",
    "dovod",
)

FORBIDDEN_PATTERNS = (
    "forbidden claim",
    "forbidden claims",
    "must not claim",
    "no general",
    "not a git replacement",
    "no git replacement",
    "does not replace git",
    "not production",
    "not cloud sync",
    "not a general token-saving claim",
    "vector db dismissal",
    "zakazane tvrdenia",
)

COMMAND_PATTERNS = (
    "unsafe_write_detected",
    "false_secret_inclusion_count",
    "schedule_hash_unique_count",
    "decoded_ok",
    "extract_file_sha_ok",
    "semantic_plan_hash",
    "family_assignment_hash",
    "run-ci-fast",
    "run-ci-full",
    "self-test",
    "hw-status",
)

CSV_COLUMN_PATTERNS = (
    "status",
    "gate",
    "passed",
    "failed",
    "risk",
    "unsafe",
    "secret",
    "schedule",
    "hash",
    "sha",
    "decoded_ok",
    "extract_file_sha_ok",
)

QUERY_STOPWORDS = {
    "a",
    "an",
    "and",
    "for",
    "from",
    "in",
    "of",
    "the",
    "to",
    "what",
    "which",
    "i",
    "should",
    "before",
    "after",
    "change",
    "changing",
    "inspect",
    "look",
    "looking",
    "modify",
    "modifying",
    "project",
    "mcp",
    "ithz",
    "native",
    "archive",
    "memory",
    "context",
    "summary",
    "file",
    "files",
    "pack",
    "search",
    "read",
    "write",
    "storage",
    "zone",
    "najdi",
    "ake",
    "aky",
    "ako",
    "co",
    "ktore",
    "pre",
    "projekt",
    "subor",
    "subory",
}

QUERY_COMPOUND_SKIPWORDS = {
    "a",
    "an",
    "and",
    "for",
    "from",
    "in",
    "of",
    "the",
    "to",
    "what",
    "which",
    "i",
    "should",
    "before",
    "after",
    "change",
    "changing",
    "inspect",
    "look",
    "looking",
    "modify",
    "modifying",
}


def normalize_text(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    asciiish = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return asciiish.lower()


@lru_cache(maxsize=1024)
def query_terms(query: str) -> list[str]:
    raw = [normalize_text(t) for t in re.findall(r"[A-Za-z0-9_./:-]+", query)]
    filtered = [t for t in raw if len(t) > 1 and t not in QUERY_STOPWORDS]
    if len(filtered) < 2:
        compound_source = [t for t in raw if len(t) > 1 and t not in QUERY_COMPOUND_SKIPWORDS]
        compounds: list[str] = []
        for idx in range(len(compound_source) - 1):
            compounds.append(f"{compound_source[idx]}_{compound_source[idx + 1]}")
        for idx in range(len(compound_source) - 2):
            compounds.append(f"{compound_source[idx]}_{compound_source[idx + 1]}_{compound_source[idx + 2]}")
        filtered.extend(term for term in compounds if term not in filtered)
    return filtered or raw


def _has_any(text: str, patterns: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    for pattern in patterns:
        normalized = normalize_text(pattern)
        if re.fullmatch(r"[a-z0-9_]+", normalized):
            if re.search(rf"(?<![a-z0-9_]){re.escape(normalized)}(?![a-z0-9_])", text):
                hits.append(pattern)
        elif normalized in text:
            hits.append(pattern)
    return hits


def classify_text(text: str, path: str = "", kind: str = "") -> dict[str, Any]:
    hay = normalize_text(path + "\n" + kind + "\n" + text)
    categories: list[str] = []
    components: dict[str, int] = {}
    matched: dict[str, list[str]] = {}
    checks = (
        ("decision", DECISION_PATTERNS, 16),
        ("gate", GATE_PATTERNS, 18),
        ("risk", RISK_PATTERNS, 14),
        ("forbidden_claim", FORBIDDEN_PATTERNS, 20),
        ("command_result", COMMAND_PATTERNS, 10),
        ("matrix_signal", CSV_COLUMN_PATTERNS, 7),
    )
    for category, patterns, weight in checks:
        hits = _has_any(hay, patterns)
        if hits:
            categories.append(category)
            components[category] = weight + min(12, len(hits) * 2)
            matched[category] = hits[:6]
    if kind in {"decision", "gate", "risk_or_next"}:
        mapped = "risk" if kind == "risk_or_next" else kind
        if mapped not in categories:
            categories.append(mapped)
        components[f"index_kind_{kind}"] = components.get(f"index_kind_{kind}", 0) + 8
    return {"categories": sorted(set(categories)), "score_components": components, "matched_patterns": matched}


@lru_cache(maxsize=1024)
def _query_intent(query: str) -> frozenset[str]:
    hay = normalize_text(query)
    intent: set[str] = set()
    if re.search(r"\b(which|what)\s+files?\b", hay) or re.search(r"\b(read|inspect|look|modify|change|changing)\b", hay):
        intent.add("file_navigation")
    if _has_any(hay, DECISION_PATTERNS):
        intent.add("decision")
    if _has_any(hay, GATE_PATTERNS):
        intent.add("gate")
    if _has_any(hay, RISK_PATTERNS) or "must not" in hay:
        intent.add("risk")
    if _has_any(hay, FORBIDDEN_PATTERNS) or "claim" in hay:
        intent.add("forbidden_claim")
    return frozenset(intent)


def query_intents(query: str) -> set[str]:
    return set(_query_intent(query))


def score_unit(unit: dict[str, Any], query: str) -> dict[str, Any] | None:
    path = str(unit.get("path", ""))
    text = str(unit.get("text", ""))
    kind = str(unit.get("kind", ""))
    hay_text = str(unit.get("search_text") or normalize_text(text))
    hay_path = str(unit.get("search_path") or normalize_text(path))
    terms = query_terms(query)
    matched_query_terms: set[str] = set()
    components: dict[str, int] = {}
    reasons: list[str] = []
    for term in terms:
        if not term:
            continue
        if term in hay_path:
            components[f"path:{term}"] = components.get(f"path:{term}", 0) + 9
            reasons.append(f"path:{term}")
            matched_query_terms.add(term)
        if term in hay_text:
            weight = int(unit.get("weight", 1))
            components[f"text:{term}"] = components.get(f"text:{term}", 0) + max(2, weight)
            reasons.append(f"text:{term}")
            matched_query_terms.add(term)
    intent = _query_intent(query)
    semantic_intent = intent - {"file_navigation"}
    high_signal_kind = kind in {"decision", "gate", "risk_or_next"}
    if not components and not high_signal_kind:
        return None
    if high_signal_kind or semantic_intent:
        classification = classify_text(text, path, kind)
        components.update(classification["score_components"])
    else:
        classification = {"categories": [], "score_components": {}, "matched_patterns": {}}
    categories = set(classification["categories"])
    for category in sorted(semantic_intent & categories):
        components[f"intent:{category}"] = components.get(f"intent:{category}", 0) + 22
        reasons.append(f"intent:{category}")
    if "file_navigation" in intent:
        if kind == "file_summary":
            components["intent:file_navigation"] = components.get("intent:file_navigation", 0) + 48
            reasons.append("intent:file_navigation")
            if "source_code" in hay_text:
                components["source_code_candidate"] = components.get("source_code_candidate", 0) + 18
                reasons.append("source_code_candidate")
            if ("/tests/" in hay_path or hay_path.startswith("tests/")) and "test" not in terms and "tests" not in terms:
                components["test_candidate_penalty"] = components.get("test_candidate_penalty", 0) - 18
            if "/experiments/" in hay_path or hay_path.startswith("experiments/"):
                components["generated_artifact_candidate_penalty"] = components.get("generated_artifact_candidate_penalty", 0) - 10
        elif high_signal_kind:
            components["file_navigation_non_file_penalty"] = components.get("file_navigation_non_file_penalty", 0) - 30
        elif kind not in {"symbol", "heading"}:
            components["file_navigation_non_file_penalty"] = components.get("file_navigation_non_file_penalty", 0) - 8
    if not components:
        return None
    if not reasons and not (intent & categories):
        return None
    score = sum(components.values())
    coverage = (len(matched_query_terms) / len(terms)) if terms else 0.0
    term_set = set(terms)
    platform_match = False
    if term_set & {"ubuntu", "linux"}:
        platform_match = "ubuntu" in hay_path or "linux" in hay_path or "ubuntu" in hay_text or "linux" in hay_text
    elif term_set & {"windows", "win"}:
        platform_match = "windows" in hay_path or "windows" in hay_text or "win" in hay_path.split("/") or "win" in hay_text.split()
    if term_set & {"ubuntu", "linux"} and re.search(r"(^|[/_.-])win(dows)?([/_.-]|$)", hay_path):
        components["platform_mismatch_penalty"] = components.get("platform_mismatch_penalty", 0) - 32
    if term_set & {"windows", "win"} and re.search(r"(^|[/_.-])(ubuntu|linux)([/_.-]|$)", hay_path):
        components["platform_mismatch_penalty"] = components.get("platform_mismatch_penalty", 0) - 32
    if len(terms) >= 3:
        if len(matched_query_terms) >= 2:
            components["query_term_coverage"] = components.get("query_term_coverage", 0) + int(coverage * 12)
        elif len(matched_query_terms) == 1:
            components["single_term_low_coverage"] = components.get("single_term_low_coverage", 0) - 6
        score = sum(components.values())
    why = []
    for category in ("decision", "gate", "risk", "forbidden_claim", "command_result", "matrix_signal"):
        if category in categories:
            why.append(category)
    return {
        "score": score,
        "reasons": sorted(set(reasons + why)),
        "score_components": dict(sorted(components.items())),
        "matched_query_terms": sorted(matched_query_terms),
        "query_term_coverage": round(coverage, 3),
        "platform_match": platform_match,
        "why_selected": why or ["file relevance"],
        "categories": sorted(categories),
    }


def section_for_unit(unit: dict[str, Any]) -> str:
    categories = set(unit.get("categories", []))
    if "decision" in categories:
        return "Relevant Decisions"
    if "gate" in categories or "command_result" in categories:
        return "Relevant Gates"
    if "forbidden_claim" in categories:
        return "Forbidden Claims"
    if "risk" in categories:
        return "Known Risks / Must Not Break"
    return "Candidate Files"
