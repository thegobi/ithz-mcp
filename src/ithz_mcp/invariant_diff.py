from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import csv
import hashlib
import html
import io
import json
import re
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty, dumps, sanitize_json_value, sanitize_text
from .git_merge_driver import _archive_layers
from .hashing import stable_json_hash
from .safety import ignore_reason, looks_binary, normalize_rel


VOLATILE_JSON_KEYS = {
    "created_at",
    "generated_at",
    "mtime",
    "timestamp",
    "updated_at",
}

TEXT_EXTS = {
    ".c",
    ".cc",
    ".cfg",
    ".cmake",
    ".cpp",
    ".css",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".php",
    ".py",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

RISK_PATH_RE = re.compile(
    r"(^|/)(auth|security|secrets?|permissions?|policy|config|settings|mcp_server|native_archive_store|project_ledger)\b|"
    r"(\.env|secret|token|credential|safety|limits|gate|risk)",
    re.IGNORECASE,
)

CLAIM_TEXT_RE = re.compile(
    r"\b(blocked claim|claim boundary|allowed claim|qpu|continuum|gravity|lorentz|spacetime|"
    r"zip superiority|production database|cloud sync|replaces git|proof)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FileEntity:
    path: str
    size: int
    raw_hash: str
    canonical_hash: str
    unit_hash: str
    kind: str
    binary: bool
    claim_terms: list[str]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _normalize_newlines(text: str) -> str:
    return sanitize_text(text).replace("\r\n", "\n").replace("\r", "\n")


def _strip_volatile_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_volatile_json(item)
            for key, item in sorted(value.items(), key=lambda row: str(row[0]))
            if str(key).lower() not in VOLATILE_JSON_KEYS
        }
    if isinstance(value, list):
        return [_strip_volatile_json(item) for item in value]
    return value


def _canonical_json_bytes(data: bytes) -> tuple[str, str]:
    loaded = json.loads(data.decode("utf-8-sig"))
    canonical = dumps(_strip_volatile_json(loaded))
    unit = canonical
    return canonical, unit


def _canonical_csv_text(text: str, ignore_order: bool) -> tuple[str, str]:
    rows = list(csv.reader(io.StringIO(text)))
    canonical_rows = rows if not ignore_order else sorted(rows)
    canonical = "\n".join(",".join(row) for row in canonical_rows)
    unit = "\n".join(",".join(row) for row in sorted(rows))
    return canonical, unit


def _markdown_section_units(text: str) -> str:
    sections: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith("#") and current:
            sections.append("\n".join(current).strip())
            current = []
        current.append(line.strip())
    if current:
        sections.append("\n".join(current).strip())
    return "\n\n".join(sorted(section for section in sections if section))


def _canonical_text_units(text: str, ext: str, ignore_order: bool) -> tuple[str, str]:
    normalized = _normalize_newlines(text)
    lines = [line.rstrip() for line in normalized.splitlines()]
    while lines and not lines[-1]:
        lines.pop()
    canonical = "\n".join(lines) + ("\n" if lines else "")
    collapsed = re.sub(r"\n{3,}", "\n\n", canonical)
    if ext == ".md":
        return collapsed, _markdown_section_units(collapsed)
    if ignore_order:
        non_empty = sorted(line for line in collapsed.splitlines() if line.strip())
        return "\n".join(non_empty) + ("\n" if non_empty else ""), "\n".join(non_empty)
    return collapsed, collapsed


def _claim_terms(text: str, path: str) -> list[str]:
    hay = f"{path}\n{text[:20000]}"
    return sorted({match.group(0).lower() for match in CLAIM_TEXT_RE.finditer(hay)})


def canonicalize_file(path: Path, rel: str, ignore_order: bool = False) -> FileEntity:
    data = path.read_bytes()
    raw_hash = _sha256_bytes(data)
    ext = path.suffix.lower()
    sample = data[:8192]
    binary = ext not in TEXT_EXTS and looks_binary(sample)
    if binary:
        return FileEntity(rel, len(data), raw_hash, raw_hash, raw_hash, "binary", True, [])
    try:
        if ext == ".json":
            canonical, unit = _canonical_json_bytes(data)
            kind = "json"
        elif ext == ".csv":
            text = data.decode("utf-8-sig", errors="replace")
            canonical, unit = _canonical_csv_text(_normalize_newlines(text), ignore_order)
            kind = "csv"
        else:
            text = data.decode("utf-8-sig", errors="replace")
            canonical, unit = _canonical_text_units(text, ext, ignore_order)
            kind = "markdown" if ext == ".md" else "text"
        claim_terms = _claim_terms(canonical, rel)
        return FileEntity(rel, len(data), raw_hash, _sha256_text(canonical), _sha256_text(unit), kind, False, claim_terms)
    except Exception:
        text = data.decode("utf-8-sig", errors="replace")
        canonical, unit = _canonical_text_units(text, ext, ignore_order)
        return FileEntity(rel, len(data), raw_hash, _sha256_text(canonical), _sha256_text(unit), "text-fallback", False, _claim_terms(canonical, rel))


def _should_include(root: Path, path: Path) -> tuple[bool, str]:
    rel = normalize_rel(path.relative_to(root))
    if rel == "project.ithz" or rel.endswith(".ithz"):
        return False, "ithz_archive_compare_with_ithz_mode"
    if rel.startswith((".git/", ".ithz-install/", ".ithz-context/", ".ithz_mcp/", "__pycache__/", "dist/", "build/")):
        return False, "generated_or_tool_state"
    try:
        reason = ignore_reason(rel, path.stat().st_size)
    except OSError:
        return False, "stat_error"
    if reason:
        return False, reason
    return True, ""


def scan_folder(root: Path, ignore_order: bool = False) -> tuple[dict[str, FileEntity], list[dict[str, Any]]]:
    root = root.resolve()
    entities: dict[str, FileEntity] = {}
    ignored: list[dict[str, Any]] = []
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: normalize_rel(p.relative_to(root)).lower()):
        include, reason = _should_include(root, path)
        rel = normalize_rel(path.relative_to(root))
        if not include:
            ignored.append({"path": rel, "reason": reason})
            continue
        entities[rel] = canonicalize_file(path, rel, ignore_order)
    return entities, ignored


def _path_risk(path: str) -> bool:
    return bool(RISK_PATH_RE.search(path.replace("\\", "/")))


def _record_change(kind: str, path: str, details: dict[str, Any]) -> dict[str, Any]:
    row = {"kind": kind, "path": path}
    row.update(details)
    return sanitize_json_value(row)


def _verdict(counts: dict[str, int]) -> str:
    if counts.get("claim_boundary_change", 0):
        return "CLAIM_BOUNDARY_CHANGE"
    if counts.get("risk_relevant_change", 0):
        return "RISK_RELEVANT_CHANGE"
    if counts.get("unknown", 0):
        return "UNKNOWN_NEEDS_REVIEW"
    if counts.get("material", 0) or counts.get("added", 0) or counts.get("deleted", 0):
        return "MATERIAL_CHANGE"
    if counts.get("structural", 0):
        return "STRUCTURAL_ONLY_CHANGED"
    if counts.get("moved_renamed", 0) or counts.get("representation_only", 0):
        return "REPRESENTATION_ONLY_CHANGED"
    return "EQUIVALENT"


def diff_folders(left: Path, right: Path, mode: str, ignore_order: bool = False) -> dict[str, Any]:
    left_entities, left_ignored = scan_folder(left, ignore_order)
    right_entities, right_ignored = scan_folder(right, ignore_order)
    changes: list[dict[str, Any]] = []
    counts: dict[str, int] = defaultdict(int)

    left_only = set(left_entities) - set(right_entities)
    right_only = set(right_entities) - set(left_entities)
    left_by_canonical: dict[str, list[str]] = defaultdict(list)
    right_by_canonical: dict[str, list[str]] = defaultdict(list)
    for path in left_only:
        left_by_canonical[left_entities[path].canonical_hash].append(path)
    for path in right_only:
        right_by_canonical[right_entities[path].canonical_hash].append(path)

    moved_left: set[str] = set()
    moved_right: set[str] = set()
    for digest, lpaths in sorted(left_by_canonical.items()):
        rpaths = right_by_canonical.get(digest, [])
        for old, new in zip(sorted(lpaths), sorted(rpaths)):
            moved_left.add(old)
            moved_right.add(new)
            counts["moved_renamed"] += 1
            changes.append(_record_change("moved_renamed", new, {"from_path": old, "canonical_hash": digest}))

    for path in sorted(set(left_entities) & set(right_entities)):
        old = left_entities[path]
        new = right_entities[path]
        if old.raw_hash == new.raw_hash:
            continue
        if old.canonical_hash == new.canonical_hash:
            counts["representation_only"] += 1
            changes.append(_record_change("representation_only", path, {"reason": "raw bytes changed but canonical hash is stable"}))
        elif old.unit_hash == new.unit_hash and old.kind == "json" and new.kind == "json":
            counts["representation_only"] += 1
            changes.append(_record_change("representation_only", path, {"reason": "JSON differs only by timestamp-like volatile metadata"}))
        elif old.unit_hash == new.unit_hash:
            counts["structural"] += 1
            changes.append(_record_change("structural", path, {"reason": "same normalized units, different order or section layout"}))
        elif old.binary or new.binary:
            counts["unknown"] += 1
            changes.append(_record_change("unknown", path, {"reason": "binary content changed"}))
        else:
            counts["material"] += 1
            details = {
                "old_canonical_hash": old.canonical_hash,
                "new_canonical_hash": new.canonical_hash,
                "old_kind": old.kind,
                "new_kind": new.kind,
            }
            if _path_risk(path):
                counts["risk_relevant_change"] += 1
                details["risk_relevant"] = True
            terms = sorted(set(old.claim_terms) | set(new.claim_terms))
            if terms:
                counts["claim_boundary_change"] += 1
                details["claim_terms"] = terms
            changes.append(_record_change("material", path, details))

    for path in sorted(left_only - moved_left):
        ent = left_entities[path]
        counts["deleted"] += 1
        details: dict[str, Any] = {"canonical_hash": ent.canonical_hash, "kind": ent.kind}
        if ent.binary:
            counts["unknown"] += 1
            details["unknown"] = True
        if _path_risk(path):
            counts["risk_relevant_change"] += 1
            details["risk_relevant"] = True
        if ent.claim_terms:
            counts["claim_boundary_change"] += 1
            details["claim_terms"] = ent.claim_terms
        changes.append(_record_change("deleted", path, details))

    for path in sorted(right_only - moved_right):
        ent = right_entities[path]
        counts["added"] += 1
        details = {"canonical_hash": ent.canonical_hash, "kind": ent.kind}
        if ent.binary:
            counts["unknown"] += 1
            details["unknown"] = True
        if _path_risk(path):
            counts["risk_relevant_change"] += 1
            details["risk_relevant"] = True
        if ent.claim_terms:
            counts["claim_boundary_change"] += 1
            details["claim_terms"] = ent.claim_terms
        changes.append(_record_change("added", path, details))

    canonical_tree_a = stable_json_hash({path: ent.canonical_hash for path, ent in sorted(left_entities.items())})
    canonical_tree_b = stable_json_hash({path: ent.canonical_hash for path, ent in sorted(right_entities.items())})
    unit_tree_a = stable_json_hash(Counter(ent.unit_hash for ent in left_entities.values()))
    unit_tree_b = stable_json_hash(Counter(ent.unit_hash for ent in right_entities.values()))
    review_priority = [
        row["path"]
        for row in changes
        if row["kind"] in {"material", "unknown", "added", "deleted"} or row.get("risk_relevant") or row.get("claim_terms")
    ][:25]
    count_dict = {key: int(value) for key, value in sorted(counts.items())}
    return sanitize_json_value(
        {
            "schema": "ithz_invariant_diff_report_v1",
            "mode": mode,
            "input_type": "folder",
            "left": str(left.resolve()),
            "right": str(right.resolve()),
            "verdict": _verdict(count_dict),
            "canonical_equal": canonical_tree_a == canonical_tree_b,
            "unit_multiset_equal": unit_tree_a == unit_tree_b,
            "canonical_hashes": {"left": canonical_tree_a, "right": canonical_tree_b, "left_units": unit_tree_a, "right_units": unit_tree_b},
            "counts": count_dict,
            "raw_file_count": {"left": len(left_entities), "right": len(right_entities)},
            "ignored": {"left_count": len(left_ignored), "right_count": len(right_ignored), "left_sample": left_ignored[:20], "right_sample": right_ignored[:20]},
            "review_priority": review_priority,
            "changes": changes,
            "normalization_rules": [
                "file order ignored in folder scan",
                "line endings and trailing whitespace normalized for text",
                "JSON key order canonicalized",
                "JSON volatile timestamp-like keys ignored by the explicit JSON canonicalizer",
                "Markdown section moves classified as structural when section units are unchanged",
                "Binary changes are UNKNOWN_NEEDS_REVIEW",
                ".ithz files are excluded from folder mode; use mode=ithz",
            ],
        }
    )


def _event_key(row: dict[str, Any]) -> str:
    existing = row.get("semantic_event_hash")
    if isinstance(existing, str) and existing:
        return existing
    return stable_json_hash({k: v for k, v in row.items() if k not in {"event_id", "merged_from_event_id"}})


def _prompt_key(row: dict[str, Any]) -> str:
    existing = row.get("semantic_prompt_hash")
    if isinstance(existing, str) and existing:
        return existing
    return stable_json_hash({k: v for k, v in row.items() if k not in {"record_id", "prompt_id", "response_id"}})


def _counter_delta(left: Counter[str], right: Counter[str]) -> tuple[list[str], list[str]]:
    added: list[str] = []
    removed: list[str] = []
    for key, count in (right - left).items():
        added.extend([key] * count)
    for key, count in (left - right).items():
        removed.extend([key] * count)
    return sorted(added), sorted(removed)


def diff_ithz_archives(left: Path, right: Path) -> dict[str, Any]:
    left_layers = _archive_layers(left.resolve())
    right_layers = _archive_layers(right.resolve())
    left_manifest = left_layers.get("manifest", {})
    right_manifest = right_layers.get("manifest", {})
    changes: list[dict[str, Any]] = []
    counts: dict[str, int] = defaultdict(int)

    left_event_counts = Counter(_event_key(row) for row in left_layers["events"])
    right_event_counts = Counter(_event_key(row) for row in right_layers["events"])
    event_added, event_removed = _counter_delta(left_event_counts, right_event_counts)
    event_by_key = {_event_key(row): row for row in [*left_layers["events"], *right_layers["events"]]}
    for key in event_added:
        row = event_by_key.get(key, {})
        kind = str(row.get("kind", "event"))
        counts["material"] += 1
        details = {"event_hash": key, "event_kind": kind, "text": str(row.get("text", ""))[:240]}
        if kind in {"claim", "blocked_claim", "replication_pack", "reviewer_note"}:
            counts["claim_boundary_change"] += 1
            details["claim_boundary"] = True
        if kind in {"risk", "must_not_break", "gate"}:
            counts["risk_relevant_change"] += 1
            details["risk_relevant"] = True
        changes.append(_record_change("archive_event_added", f"events/{kind}", details))
    for key in event_removed:
        row = event_by_key.get(key, {})
        kind = str(row.get("kind", "event"))
        counts["material"] += 1
        details = {"event_hash": key, "event_kind": kind, "text": str(row.get("text", ""))[:240]}
        if kind in {"claim", "blocked_claim", "replication_pack", "reviewer_note"}:
            counts["claim_boundary_change"] += 1
            details["claim_boundary"] = True
        changes.append(_record_change("archive_event_removed", f"events/{kind}", details))

    left_prompt_counts = Counter(_prompt_key(row) for row in left_layers["prompts"] if not row.get("local_only"))
    right_prompt_counts = Counter(_prompt_key(row) for row in right_layers["prompts"] if not row.get("local_only"))
    prompt_added, prompt_removed = _counter_delta(left_prompt_counts, right_prompt_counts)
    if prompt_added or prompt_removed:
        counts["material"] += len(prompt_added) + len(prompt_removed)
        changes.append(
            _record_change(
                "archive_prompt_summary_delta",
                "prompts/prompt_log.jsonl",
                {"added": len(prompt_added), "removed": len(prompt_removed)},
            )
        )

    same_archive_semantic = left_manifest.get("archive_semantic_hash") == right_manifest.get("archive_semantic_hash")
    same_project_semantic = left_manifest.get("project_semantic_hash") == right_manifest.get("project_semantic_hash")
    same_bytes = left_layers.get("archive_sha256") == right_layers.get("archive_sha256")
    if same_archive_semantic and not same_bytes:
        counts["representation_only"] += 1
        changes.append(_record_change("archive_representation_only", "project.ithz", {"reason": "archive bytes differ but archive_semantic_hash is stable"}))
    elif not same_archive_semantic and not changes:
        counts["material"] += 1
        changes.append(_record_change("archive_semantic_hash_changed", "project.ithz", {"reason": "archive_semantic_hash differs but no event projection delta was found"}))

    count_dict = {key: int(value) for key, value in sorted(counts.items())}
    return sanitize_json_value(
        {
            "schema": "ithz_invariant_diff_report_v1",
            "mode": "ithz",
            "input_type": "ithz_archive",
            "left": str(left.resolve()),
            "right": str(right.resolve()),
            "verdict": _verdict(count_dict),
            "canonical_equal": same_archive_semantic,
            "project_semantic_equal": same_project_semantic,
            "byte_equal": same_bytes,
            "canonical_hashes": {
                "left_archive_semantic_hash": left_manifest.get("archive_semantic_hash"),
                "right_archive_semantic_hash": right_manifest.get("archive_semantic_hash"),
                "left_project_semantic_hash": left_manifest.get("project_semantic_hash"),
                "right_project_semantic_hash": right_manifest.get("project_semantic_hash"),
                "left_project_ledger_hash": left_manifest.get("project_ledger_hash"),
                "right_project_ledger_hash": right_manifest.get("project_ledger_hash"),
            },
            "counts": count_dict,
            "archive_counts": {
                "left_events": len(left_layers["events"]),
                "right_events": len(right_layers["events"]),
                "left_prompt_summaries": len([p for p in left_layers["prompts"] if not p.get("local_only")]),
                "right_prompt_summaries": len([p for p in right_layers["prompts"] if not p.get("local_only")]),
            },
            "review_priority": [row["path"] for row in changes if row.get("claim_boundary") or row.get("risk_relevant") or row["kind"] != "archive_representation_only"][:25],
            "changes": changes,
            "normalization_rules": [
                "native safe verification is used before archive layer extraction",
                "archive_semantic_hash is the primary canonical archive identity",
                "project_semantic_hash is reported separately from memory-event changes",
                "local-only prompt memory is excluded from prompt summary comparison",
                "claim, blocked-claim, replication-pack and reviewer-note events are claim-boundary changes",
            ],
        }
    )


def infer_mode(left: Path, right: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    if left.suffix.lower() == ".ithz" and right.suffix.lower() == ".ithz":
        return "ithz"
    if left.is_dir() and right.is_dir():
        return "project"
    return "data"


def run_invariant_diff(left: Path, right: Path, mode: str = "auto", ignore_order: bool = False) -> dict[str, Any]:
    left = left.resolve()
    right = right.resolve()
    if not left.exists():
        raise FileNotFoundError(f"left input not found: {left}")
    if not right.exists():
        raise FileNotFoundError(f"right input not found: {right}")
    resolved_mode = infer_mode(left, right, mode)
    if resolved_mode == "ithz":
        return diff_ithz_archives(left, right)
    if left.is_dir() and right.is_dir():
        return diff_folders(left, right, resolved_mode, ignore_order or resolved_mode == "data")
    raise ValueError("current MVP supports folder-vs-folder and .ithz-vs-.ithz inputs")


def terminal_summary(report: dict[str, Any]) -> str:
    counts = report.get("counts", {})
    lines = [
        f"Invariant verdict: {report.get('verdict')}",
        f"Canonical equal: {str(report.get('canonical_equal')).lower()}",
        f"Input type: {report.get('input_type')}",
    ]
    for key in (
        "material",
        "representation_only",
        "structural",
        "moved_renamed",
        "added",
        "deleted",
        "risk_relevant_change",
        "claim_boundary_change",
        "unknown",
    ):
        if counts.get(key):
            lines.append(f"{key}: {counts[key]}")
    review = report.get("review_priority") or []
    if review:
        lines.append("Review priority:")
        lines.extend(f"- {item}" for item in review[:10])
    return "\n".join(lines) + "\n"


def write_json_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_pretty(report), encoding="utf-8", newline="\n")


def write_html_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = report.get("counts", {})
    changes = report.get("changes", [])
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(str(row.get('kind', '')))}</td>"
        f"<td>{html.escape(str(row.get('path', '')))}</td>"
        f"<td><pre>{html.escape(dumps({k: v for k, v in row.items() if k not in {'kind', 'path'}}))}</pre></td>"
        "</tr>"
        for row in changes[:500]
    )
    count_items = "\n".join(f"<li><strong>{html.escape(str(k))}</strong>: {html.escape(str(v))}</li>" for k, v in sorted(counts.items()))
    rules = "\n".join(f"<li>{html.escape(str(rule))}</li>" for rule in report.get("normalization_rules", []))
    doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ITHZ Invariant Diff Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #172033; }}
    h1 {{ font-size: 24px; margin-bottom: 4px; }}
    .verdict {{ display: inline-block; padding: 8px 12px; border: 1px solid #9aa7bd; border-radius: 6px; background: #f5f7fb; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin: 24px 0; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #d7dde8; padding: 8px; text-align: left; vertical-align: top; }}
    pre {{ white-space: pre-wrap; margin: 0; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>ITHZ Invariant Diff</h1>
  <div class="verdict">{html.escape(str(report.get("verdict")))}</div>
  <p>Canonical equal: {html.escape(str(report.get("canonical_equal")).lower())}</p>
  <div class="grid">
    <section>
      <h2>Inputs</h2>
      <p><strong>Left:</strong> {html.escape(str(report.get("left")))}</p>
      <p><strong>Right:</strong> {html.escape(str(report.get("right")))}</p>
      <p><strong>Mode:</strong> {html.escape(str(report.get("mode")))}</p>
    </section>
    <section>
      <h2>Counts</h2>
      <ul>{count_items}</ul>
    </section>
  </div>
  <section>
    <h2>Normalization Rules</h2>
    <ul>{rules}</ul>
  </section>
  <section>
    <h2>Changes</h2>
    <table>
      <thead><tr><th>Kind</th><th>Path</th><th>Details</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
</body>
</html>
"""
    path.write_text(doc, encoding="utf-8", newline="\n")
