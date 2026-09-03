from __future__ import annotations

from pathlib import Path
from typing import Any

from .hashing import sha256_file, stable_json_hash
from .safety import ignore_reason, looks_binary, normalize_rel

TEXT_EXTS = {".md", ".txt", ".py", ".js", ".ts", ".php", ".cpp", ".hpp", ".h", ".json", ".yaml", ".yml", ".toml", ".ini", ".css", ".html", ".xml"}


def family_guess(path: str, binary: bool) -> str:
    ext = Path(path).suffix.lower()
    if binary:
        return "binary_or_media"
    if ext in {".md", ".txt"}:
        return "docs_text"
    if ext in {".py", ".js", ".ts", ".php", ".cpp", ".hpp", ".h"}:
        return "source_code"
    if ext in {".json", ".yaml", ".yml", ".toml", ".ini"}:
        return "config"
    return "text_other"


def scan_project(project: Path) -> dict[str, Any]:
    project = project.resolve()
    files = []
    ignored = []
    for path in sorted((p for p in project.rglob("*") if p.is_file()), key=lambda p: normalize_rel(p.relative_to(project))):
        rel = normalize_rel(path.relative_to(project))
        size = path.stat().st_size
        reason = ignore_reason(rel, size)
        if reason:
            ignored.append({"path": rel, "size": size, "ignored_reason": reason})
            continue
        sample = path.read_bytes()[:8192]
        binary = looks_binary(sample)
        if binary and path.suffix.lower() not in TEXT_EXTS:
            ignored.append({"path": rel, "size": size, "ignored_reason": "binary_default_ignore"})
            continue
        text = ""
        line_count = 0
        if not binary:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = path.read_text(encoding="utf-8", errors="replace")
            line_count = 0 if not text else text.count("\n") + (0 if text.endswith("\n") else 1)
        files.append(
            {
                "path": rel,
                "normalized_path": rel,
                "size": size,
                "sha256": sha256_file(path),
                "extension": path.suffix.lower(),
                "family_guess": family_guess(rel, binary),
                "text": not binary,
                "line_count": line_count,
                "mtime_ns_metadata": path.stat().st_mtime_ns,
            }
        )
    semantic = [
        {k: f[k] for k in ("path", "size", "sha256", "extension", "family_guess", "text", "line_count")}
        for f in files
    ]
    scan_hash = stable_json_hash({"files": semantic})
    return {"schema": "ithz_mcp_scan_v1", "project": str(project), "files": files, "ignored": ignored, "scan_hash": scan_hash}

