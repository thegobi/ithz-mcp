from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .hashing import stable_json_hash
from .project_scan import scan_project
from .scoring import score_unit
from .safety import normalize_rel
from .storage import state_dir, write_json, read_json


def _read_lines(project: Path, rel: str) -> list[str]:
    try:
        return (project / rel).read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return (project / rel).read_text(encoding="utf-8", errors="replace").splitlines()


def build_index(project: Path) -> dict[str, Any]:
    project = project.resolve()
    scan = scan_project(project)
    units: list[dict[str, Any]] = []
    for f in scan["files"]:
        if not f["text"]:
            continue
        lines = _read_lines(project, f["path"])
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            kind = "line"
            weight = 1
            if re.match(r"^#{1,6}\s+", stripped):
                kind, weight = "heading", 5
            elif re.search(r"\b(decision|rozhodnutie)\b", stripped, re.I):
                kind, weight = "decision", 6
            elif re.search(r"\b(gate|test|passed|failed|verify)\b", stripped, re.I):
                kind, weight = "gate", 4
            elif re.search(r"\b(todo|next|risk|limitation)\b", stripped, re.I):
                kind, weight = "risk_or_next", 3
            elif re.match(r"\s*(def|class|function|const|let|var|public|private)\b", line):
                kind, weight = "symbol", 4
            if stripped:
                units.append(
                    {
                        "path": f["path"],
                        "line": lineno,
                        "kind": kind,
                        "text": stripped[:500],
                        "weight": weight,
                    }
                )
    index = {
        "schema": "ithz_mcp_index_v1",
        "project": str(project),
        "scan_hash": scan["scan_hash"],
        "files": scan["files"],
        "ignored": scan["ignored"],
        "units": units,
    }
    index["project_semantic_hash"] = stable_json_hash(
        {"scan_hash": scan["scan_hash"], "units": [{k: u[k] for k in ("path", "line", "kind", "text")} for u in units]}
    )
    index["index_hash"] = stable_json_hash(
        {
            "schema": index["schema"],
            "scan_hash": index["scan_hash"],
            "files": [{k: f[k] for k in ("path", "size", "sha256", "extension", "family_guess", "text", "line_count")} for f in scan["files"]],
            "units": index["units"],
            "project_semantic_hash": index["project_semantic_hash"],
        }
    )
    base = state_dir(project) / "index"
    write_json(base / "index.json", index)
    (base / "index_hash.txt").write_text(index["index_hash"] + "\n", encoding="utf-8")
    (base / "scan_hash.txt").write_text(scan["scan_hash"] + "\n", encoding="utf-8")
    return index


def load_or_build_index(project: Path) -> dict[str, Any]:
    existing = read_json(state_dir(project) / "index" / "index.json")
    return existing if existing else build_index(project)


def load_index_readonly(project: Path) -> dict[str, Any]:
    existing = read_json(state_dir(project) / "index" / "index.json")
    if not existing:
        raise ValueError("index_missing_build_index_first")
    return existing


def search_index(index: dict[str, Any], query: str, limit: int = 10) -> list[dict[str, Any]]:
    results = []
    for u in index["units"]:
        scored = score_unit(u, query)
        if scored:
            results.append({**u, **scored})
    results.sort(key=lambda r: (-r["score"], r["path"], r["line"], r["text"]))
    return results[:limit]


def search_context(project: Path, query: str, limit: int = 10) -> list[dict[str, Any]]:
    index = load_or_build_index(project)
    return search_index(index, query, limit)


def why_file(project: Path, rel_path: str) -> dict[str, Any]:
    rel = normalize_rel(rel_path)
    index = load_or_build_index(project)
    file_entry = next((f for f in index["files"] if f["path"] == rel), None)
    units = [u for u in index["units"] if u["path"] == rel and u["kind"] in {"heading", "decision", "gate", "risk_or_next", "symbol"}]
    return {
        "path": rel,
        "known": file_entry is not None,
        "file": file_entry,
        "reasons": units[:20],
        "index_hash": index["index_hash"],
    }

