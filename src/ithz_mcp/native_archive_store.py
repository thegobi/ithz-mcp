from __future__ import annotations

import base64
import csv
import ctypes
import hashlib
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .bootstrap_contract import PROJECT_BOOTSTRAP
from .canonical_json import dump_pretty, dumps, sanitize_json_value, sanitize_text
from .context_index import search_index
from .events import git_status
from .hashing import sha256_file, stable_json_hash
from .prompt_memory import _summarize_text, redact_text, redaction_status
from .project_scan import scan_project
from .safety import IGNORED_DIRS, ignore_reason, looks_binary, normalize_rel, redaction_block_reason, validate_archive_path
from .scoring import query_intents, query_terms
from .storage import read_json, write_json

ARCHIVE_NAME = "project.ithz"
BOOTSTRAP_NAME = "project.md"
ARCHIVE_SCHEMA = "ithz_mcp_native_archive_v1"
INDEX_MODE_FULL = "full"
INDEX_MODE_COMPACT = "compact-v2"
PF_AVX2_INSTRUCTIONS_AVAILABLE = 40
EVENT_LOG_PATH = "events/events.jsonl"
CONTEXT_COMMIT_INDEX_PATH = "context-commits/commit_index.json"
DECISION_LOG_PATH = "decisions/decision_log.jsonl"
PROMPT_LOG_PATH = "prompts/prompt_log.jsonl"
REF_HEAD_PATH = "refs/HEAD"
REF_MAIN_PATH = "refs/main"
REF_INDEX_PATH = "refs/ref_index.json"
BRANCH_MAIN_PATH = "branches/main.json"
CURRENT_INDEX_PATH = "indexes/current_index.json"
SEARCH_INDEX_PATH = "indexes/search_index.json"
SOURCE_SEARCH_INDEX_PATH = "indexes/source_search_index.json"
GATE_INDEX_PATH = "indexes/gate_index.json"
RISK_INDEX_PATH = "indexes/risk_index.json"
PROMPT_SUMMARY_INDEX_PATH = "indexes/prompt_summary_index.json"
MEMORY_SYNTHESIS_PATH = "indexes/memory_synthesis.json"
SNAPSHOT_INDEX_PATH = "snapshots/snapshot_index.json"
WORKFLOW_INDEX_PATH = "workflows/workflow_index.json"
WORKFLOW_PROMPT_LOG_PATH = "workflows/workflow_prompt_log.jsonl"
CLAIM_LOG_PATH = "claims/claim_log.jsonl"
BLOCKED_CLAIM_LOG_PATH = "claims/blocked_claim_log.jsonl"
REPLICATION_PACK_LOG_PATH = "replication/replication_pack_log.jsonl"
REVIEWER_NOTE_LOG_PATH = "review/reviewer_notes.jsonl"
PROJECT_LEDGER_SUMMARY_PATH = "ledger/project_ledger_summary.json"
CLAIM_INDEX_PATH = "indexes/claim_index.json"

COMMON_TOKEN_STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "have", "will", "not", "are", "was", "were", "you", "your",
    "ako", "pre", "ale", "toto", "tento", "tieto", "som", "sme", "bude", "bolo", "nie", "tam", "este", "ktor", "ktore",
    "function", "return", "const", "class", "public", "private", "static", "array", "string", "null", "true", "false",
}
MAX_INDEX_TEXT_SAMPLE_BYTES = 64 * 1024
MAX_SOURCE_SEARCH_UNITS = 60_000
MAX_SOURCE_SEARCH_TEXT_BYTES = 320
MAX_SOURCE_SEARCH_DOC_TEXT_BYTES = 700
MAX_SOURCE_SEARCH_DOC_FILES = 120
MAX_SOURCE_SEARCH_DOC_SAMPLE_BYTES = 64 * 1024
ARCHIVE_TEXT_EXTS = {".md", ".txt", ".py", ".js", ".ts", ".php", ".cpp", ".hpp", ".h", ".json", ".yaml", ".yml", ".toml", ".ini", ".css", ".html", ".xml"}
ARCHIVE_BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svgz", ".zip", ".gz", ".7z", ".rar", ".pdf", ".docx", ".xlsx", ".pptx", ".mp4", ".mov", ".avi", ".dll", ".exe", ".so", ".bin"}
DEFAULT_ARCHIVE_LOCK_WAIT_SECONDS = 2.0
DEFAULT_SNAPSHOT_AUTO_MAX_ARCHIVE_BYTES = 1_000_000
DEFAULT_NATIVE_UPDATE_TIMEOUT_SECONDS = 60.0
DEFAULT_NATIVE_UPDATE_DIRECT_REPACK_BYTES = 8_000_000


class ArchiveWriteLockError(RuntimeError):
    pass


@dataclass(frozen=True)
class NativeSelection:
    path: str
    selected_build: str
    reason: str
    cpu_avx2_supported: bool
    explicit: bool = False


@dataclass(frozen=True)
class MemoryZone:
    requested_project: str
    active_root: str
    active_archive: str
    discovery_mode: str
    active_memory_zone: str
    explicit_zone_path: str | None
    parent_zones: list[str]
    child_zones: list[str]
    sibling_zones: list[str]
    child_zones_included_by_default: bool = False


def _repo_roots() -> list[Path]:
    here = Path(__file__).resolve()
    roots: list[Path] = []
    for idx in (2, 3):
        try:
            candidate = here.parents[idx]
        except IndexError:
            continue
        if candidate not in roots:
            roots.append(candidate)
    return roots


def cpu_supports_avx2() -> bool:
    override = os.environ.get("ITHZ_MCP_ASSUME_AVX2")
    if override is not None:
        return override.strip().lower() in {"1", "true", "yes", "on"}
    if os.name == "nt":
        try:
            return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE))
        except Exception:
            return False
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        try:
            return " avx2 " in (" " + cpuinfo.read_text(encoding="utf-8", errors="ignore").lower() + " ")
        except OSError:
            return False
    return False


def _first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path.resolve()
    return None


def _selection_for_explicit(path: Path, reason: str) -> NativeSelection:
    if not path.exists():
        raise FileNotFoundError(f"ithz-native.exe not found at {path}")
    return NativeSelection(str(path.resolve()), "explicit", reason, cpu_supports_avx2(), True)


def select_native_ithz(explicit: str | None = None) -> NativeSelection:
    if explicit:
        return _selection_for_explicit(Path(explicit), "explicit_cli")
    env = os.environ.get("ITHZ_NATIVE_EXE")
    if env:
        return _selection_for_explicit(Path(env), "explicit_env_ITHZ_NATIVE_EXE")

    avx2_supported = cpu_supports_avx2()
    scalar_candidates: list[Path] = []
    avx2_candidates: list[Path] = []
    generic_candidates: list[Path] = []
    for root in _repo_roots():
        native_dir = root / "native"
        avx2_candidates.extend(
            [
                native_dir / "ithz-native-avx2.exe",
                root / "native_ithz" / "build_avx2" / "Release" / "ithz-native.exe",
                root / "dist" / "ithz-native-v0.1-alpha-rc1-win64-avx2" / "ithz-native.exe",
            ]
        )
        scalar_candidates.extend(
            [
                native_dir / "ithz-native-scalar.exe",
                root / "native_ithz" / "build_scalar" / "Release" / "ithz-native.exe",
                root / "dist" / "ithz-native-v0.1-alpha-rc1-win64-scalar" / "ithz-native.exe",
            ]
        )
        generic_candidates.append(native_dir / "ithz-native.exe")

    if avx2_supported:
        path = _first_existing(generic_candidates + avx2_candidates + scalar_candidates)
        if path:
            selected_build = "scalar" if "scalar" in str(path).lower() else "avx2"
            return NativeSelection(str(path), selected_build, "auto_avx2_supported", avx2_supported)
    else:
        path = _first_existing(scalar_candidates)
        if path:
            return NativeSelection(str(path), "scalar", "auto_scalar_cpu_no_avx2", avx2_supported)

    path = _first_existing(generic_candidates)
    if path and avx2_supported:
        return NativeSelection(str(path), "avx2", "auto_generic_avx2_supported", avx2_supported)
    raise FileNotFoundError("ithz-native.exe not found; set ITHZ_NATIVE_EXE or build native_ithz scalar/AVX2")


def locate_native_ithz(explicit: str | None = None) -> Path:
    return Path(select_native_ithz(explicit).path)


def project_archive_path(project: Path) -> Path:
    return project.resolve() / ARCHIVE_NAME


def cleanup_native_plan_artifacts(project: Path) -> list[str]:
    project = project.resolve()
    removed: list[str] = []
    for rel in (
        f"{ARCHIVE_NAME}.lock",
        f"{ARCHIVE_NAME}.auto_mixed_plan.json",
        "auto_mixed_plan_summary.md",
        "native_ithz_p9_auto_mixed_plan_matrix.csv",
    ):
        target = project / rel
        if target.exists() and target.is_file():
            try:
                target.unlink()
                removed.append(str(target))
            except FileNotFoundError:
                pass
    return removed


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _zone_root_from_path(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.name.lower() == ARCHIVE_NAME.lower():
        return resolved.parent
    return resolved


def _nearest_archive_root(project: Path) -> Path | None:
    cur = project.resolve()
    candidates = [cur, *cur.parents]
    for candidate in candidates:
        if (candidate / ARCHIVE_NAME).exists():
            return candidate
    return None


def _parent_zone_roots(active_root: Path) -> list[Path]:
    return [p for p in active_root.resolve().parents if (p / ARCHIVE_NAME).exists()]


def _sibling_zone_roots(active_root: Path) -> list[Path]:
    parent = active_root.resolve().parent
    if not parent.exists():
        return []
    roots = []
    for child in sorted((p for p in parent.iterdir() if p.is_dir()), key=lambda p: str(p).lower()):
        if child.resolve() == active_root.resolve():
            continue
        if (child / ARCHIVE_NAME).exists():
            roots.append(child.resolve())
    return roots


def _discover_child_zone_roots(project: Path) -> list[Path]:
    project = project.resolve()
    roots: list[Path] = []
    skip_dir_names = {
        ".git", ".ithz-install", ".ithz-context", ".ithz_mcp", ".antigravity", ".claude", ".cursor",
        ".mempalace-capture", ".mempalace-pilot", ".mempalace-seed", "node_modules", "vendor", "dist",
        "build", "__pycache__", "tmp",
    }
    try:
        max_dirs = max(1, int(os.environ.get("ITHZ_MCP_CHILD_ZONE_SCAN_MAX_DIRS", "1500")))
    except ValueError:
        max_dirs = 1500
    scanned_dirs = 0
    for root, dirs, names in os.walk(project):
        scanned_dirs += 1
        if scanned_dirs > max_dirs:
            dirs[:] = []
            break
        root_path = Path(root)
        try:
            rel = normalize_rel(root_path.relative_to(project))
        except ValueError:
            rel = ""
        if root_path != project and any(name.lower() == ARCHIVE_NAME.lower() for name in names):
            roots.append(root_path.resolve())
            dirs[:] = []
            continue
        kept_dirs = []
        for name in sorted(dirs, key=str.lower):
            child_rel = normalize_rel((root_path / name).relative_to(project))
            if name.lower() in skip_dir_names or ignore_reason(child_rel + "/", 0):
                continue
            parts = {part.lower() for part in Path(child_rel).parts}
            if parts.intersection(skip_dir_names):
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs
        if rel:
            parts = tuple(Path(rel).parts)
            if parts and parts[0].lower() in {"plugins", "themes"} and len(parts) >= 2:
                dirs[:] = []
            if parts and parts[0].lower() == "assets" and len(parts) >= 1:
                dirs[:] = []
    return roots


def _zone_path_list(paths: list[Path]) -> list[str]:
    return [str((p / ARCHIVE_NAME).resolve()) for p in paths]


def resolve_memory_zone(project: Path, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> MemoryZone:
    requested = project.resolve()
    if memory_zone_path:
        active_root = _zone_root_from_path(Path(memory_zone_path))
        mode = "explicit_path"
        explicit = str(Path(memory_zone_path).resolve())
    elif memory_zone == "current":
        active_root = requested
        mode = "current_project"
        explicit = None
    elif memory_zone == "parent":
        nearest = _nearest_archive_root(requested)
        base = nearest or requested
        parents = _parent_zone_roots(base)
        if not parents:
            raise FileNotFoundError(f"no parent {ARCHIVE_NAME} found above {base}")
        active_root = parents[0]
        mode = "parent"
        explicit = None
    elif memory_zone == "nearest":
        active_root = _nearest_archive_root(requested) or requested
        mode = "nearest"
        explicit = None
    else:
        raise ValueError("memory_zone must be nearest, current, or parent")
    active_root = active_root.resolve()
    archive = active_root / ARCHIVE_NAME
    return MemoryZone(
        requested_project=str(requested),
        active_root=str(active_root),
        active_archive=str(archive),
        discovery_mode=mode,
        active_memory_zone=str(archive),
        explicit_zone_path=explicit,
        parent_zones=_zone_path_list(_parent_zone_roots(active_root)),
        child_zones=_zone_path_list(_discover_child_zone_roots(active_root)),
        sibling_zones=_zone_path_list(_sibling_zone_roots(active_root)),
    )


def project_bootstrap_path(project: Path) -> Path:
    return project.resolve() / BOOTSTRAP_NAME


def ensure_project_bootstrap(project: Path) -> dict[str, Any]:
    project = project.resolve()
    path = project_bootstrap_path(project)
    created = False
    if not path.exists():
        path.write_text(PROJECT_BOOTSTRAP, encoding="utf-8", newline="\n")
        created = True
    return {"path": str(path), "created": created}


def _include_source_file(rel: str, size: int) -> bool:
    if rel in {ARCHIVE_NAME}:
        return False
    if rel in {ARCHIVE_NAME + ".lock"}:
        return False
    if rel.startswith((".git/", ".ithz-install/", ".ithz-context/", ".ithz_mcp/", ".antigravity/", ".claude/", ".cursor/", ".mempalace-capture/", ".mempalace-pilot/", ".mempalace-seed/", "tmp/")):
        return False
    if rel in {
        "auto_mixed_plan_summary.md",
        "native_ithz_p9_auto_mixed_plan_matrix.csv",
        f"{ARCHIVE_NAME}.auto_mixed_plan.json",
    }:
        return False
    if rel.startswith("dist/") or rel.startswith("build/") or rel.startswith("__pycache__/"):
        return False
    if rel.endswith(".ithz") or rel.endswith(".exe") or rel.endswith(".pyc"):
        return False
    return ignore_reason(rel, size) is None


def _rel_under_child_zone(rel: str, child_rel_roots: list[str]) -> bool:
    return any(rel == root or rel.startswith(root + "/") for root in child_rel_roots)


def _filter_scan_child_zones(scan: dict[str, Any], child_roots: list[Path], project: Path) -> dict[str, Any]:
    if not child_roots:
        return scan
    child_rel_roots = [normalize_rel(root.relative_to(project)) for root in child_roots]
    kept = []
    ignored = list(scan.get("ignored", []))
    for entry in scan.get("files", []):
        rel = entry["path"]
        if _rel_under_child_zone(rel, child_rel_roots):
            ignored.append({"path": rel, "size": entry.get("size"), "ignored_reason": "nested_child_memory_zone"})
        else:
            kept.append(entry)
    semantic = [
        {k: f[k] for k in ("path", "size", "sha256", "extension", "family_guess", "text", "line_count")}
        for f in kept
    ]
    filtered = dict(scan)
    filtered["files"] = kept
    filtered["ignored"] = ignored
    filtered["scan_hash"] = stable_json_hash({"files": semantic})
    return filtered


def _scan_ignored_summary(ignored: list[dict[str, Any]]) -> dict[str, Any]:
    by_reason: dict[str, int] = {}
    total_bytes = 0
    for row in ignored:
        reason = str(row.get("ignored_reason", "unknown"))
        by_reason[reason] = by_reason.get(reason, 0) + 1
        try:
            total_bytes += int(row.get("size", 0) or 0)
        except (TypeError, ValueError):
            pass
    return {
        "ignored_count": len(ignored),
        "ignored_bytes": total_bytes,
        "ignored_by_reason": dict(sorted(by_reason.items())),
        "ignored_sample": sorted(
            (
                {"path": str(row.get("path", "")), "ignored_reason": str(row.get("ignored_reason", "unknown"))}
                for row in ignored
            ),
            key=lambda r: (r["ignored_reason"], r["path"]),
        )[:100],
    }


def compact_scan_for_archive(scan: dict[str, Any]) -> dict[str, Any]:
    files = list(scan.get("files", []))
    by_extension: dict[str, int] = {}
    by_family: dict[str, int] = {}
    indexed_bytes = 0
    for f in files:
        ext = str(f.get("extension", "") or "[none]")
        fam = str(f.get("family_guess", "unknown"))
        by_extension[ext] = by_extension.get(ext, 0) + 1
        by_family[fam] = by_family.get(fam, 0) + 1
        try:
            indexed_bytes += int(f.get("size", 0) or 0)
        except (TypeError, ValueError):
            pass
    return {
        "schema": "ithz_mcp_scan_v1_compact",
        "project": scan.get("project", ""),
        "file_count": len(files),
        "indexed_bytes": indexed_bytes,
        "by_extension": dict(sorted(by_extension.items())),
        "by_family": dict(sorted(by_family.items())),
        "file_sample": [
            {k: f.get(k) for k in ("path", "size", "extension", "family_guess", "text", "line_count", "sha256_mode")}
            for f in sorted(files, key=lambda row: str(row.get("path", "")).lower())[:500]
        ],
        "scan_hash": scan.get("scan_hash", ""),
        **_scan_ignored_summary(list(scan.get("ignored", []))),
    }


def compact_index_for_archive(index: dict[str, Any], source_search_index: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "ithz_mcp_index_v1_compact",
        "index_mode": index.get("index_mode", ""),
        "project": index.get("project", ""),
        "scan_hash": index.get("scan_hash", ""),
        "index_hash": index.get("index_hash", ""),
        "project_semantic_hash": index.get("project_semantic_hash", ""),
        "file_count": len(index.get("files", [])),
        "unit_count": len(index.get("units", [])),
        "files": [],
        "ignored": [],
        "units": [],
        "source_search_index_path": SOURCE_SEARCH_INDEX_PATH,
        "source_search_index_hash": source_search_index.get("source_search_index_hash", ""),
        "source_search_unit_count": len(source_search_index.get("units", [])),
    }


def _fast_scan_text_guess(path: Path, size: int) -> tuple[bool, bool, int, str, str]:
    ext = path.suffix.lower()
    if ext in ARCHIVE_TEXT_EXTS:
        return True, False, -1, "", ""
    if ext in ARCHIVE_BINARY_EXTS:
        return False, True, 0, "binary_default_ignore", ""
    try:
        sample = path.read_bytes()[:8192]
    except OSError:
        return False, True, 0, "read_error", ""
    sample_hash = hashlib.sha256(sample).hexdigest()
    binary = looks_binary(sample)
    text = not binary
    if binary:
        return False, True, 0, "binary_default_ignore", sample_hash
    sample_text = sample.decode("utf-8", errors="replace") if text else ""
    line_count_estimate = 0 if not text else sample_text.count("\n") + (0 if sample_text.endswith("\n") else 1)
    if size > len(sample) and text:
        line_count_estimate = -line_count_estimate
    return text, False, line_count_estimate, "", sample_hash


def _iter_project_files_pruned(project: Path) -> list[Path]:
    project = project.resolve()
    files: list[Path] = []
    for root, dirs, names in os.walk(project):
        root_path = Path(root)
        try:
            root_rel_parts = tuple(Path(normalize_rel(root_path.relative_to(project))).parts)
        except ValueError:
            root_rel_parts = ()
        if root_rel_parts and root_rel_parts[0].lower() in {"plugins", "themes"} and len(root_rel_parts) >= 3:
            dirs[:] = []
        if root_rel_parts and root_rel_parts[0].lower() in {"assets"} and len(root_rel_parts) >= 2:
            dirs[:] = []
        kept_dirs = []
        for name in sorted(dirs, key=str.lower):
            rel = normalize_rel((root_path / name).relative_to(project))
            if name.lower() in IGNORED_DIRS or ignore_reason(rel + "/", 0):
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(names, key=str.lower):
            files.append(root_path / name)
    return files


def scan_project_for_archive_fast(project: Path, include_child_zones: bool = False) -> dict[str, Any]:
    project = project.resolve()
    files: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for path in sorted(_iter_project_files_pruned(project), key=lambda p: normalize_rel(p.relative_to(project))):
        rel = normalize_rel(path.relative_to(project))
        try:
            size = path.stat().st_size
        except OSError:
            ignored.append({"path": rel, "size": 0, "ignored_reason": "stat_error"})
            continue
        reason = ignore_reason(rel, size)
        if reason:
            ignored.append({"path": rel, "size": size, "ignored_reason": reason})
            continue
        if not _include_source_file(rel, size):
            ignored.append({"path": rel, "size": size, "ignored_reason": "native_archive_source_excluded"})
            continue
        text, ignored_binary, line_count, binary_reason, sample_hash = _fast_scan_text_guess(path, size)
        if ignored_binary:
            ignored.append({"path": rel, "size": size, "ignored_reason": binary_reason})
            continue
        # Archive install uses sampled content fingerprints for speed. Full SHA scans remain available via scan-project.
        fingerprint = stable_json_hash({"path": rel, "size": size, "extension": path.suffix.lower(), "text": text, "sample_sha256": sample_hash})
        files.append(
            {
                "path": rel,
                "normalized_path": rel,
                "size": size,
                "sha256": fingerprint,
                "sha256_mode": "sampled_inventory",
                "extension": path.suffix.lower(),
                "family_guess": "source_code" if path.suffix.lower() in {".py", ".js", ".ts", ".php", ".cpp", ".hpp", ".h"} else ("docs_text" if path.suffix.lower() in {".md", ".txt"} else ("config" if path.suffix.lower() in {".json", ".yaml", ".yml", ".toml", ".ini"} else "text_other")),
                "text": text,
                "line_count": line_count,
                "mtime_ns_metadata": path.stat().st_mtime_ns,
            }
        )
    semantic = [
        {k: f[k] for k in ("path", "size", "sha256", "extension", "family_guess", "text", "line_count")}
        for f in files
    ]
    scan = {"schema": "ithz_mcp_scan_v1_fast_archive", "project": str(project), "files": files, "ignored": ignored, "scan_hash": stable_json_hash({"files": semantic})}
    if include_child_zones:
        return scan
    return _filter_scan_child_zones(scan, _discover_child_zone_roots(project), project)


def scan_project_for_archive(project: Path, include_child_zones: bool = False) -> dict[str, Any]:
    return scan_project_for_archive_fast(project, include_child_zones)


def _copy_source_snapshot(project: Path, dataset: Path, scan: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    source_root = dataset / "source"
    for entry in sorted(scan.get("files", []), key=lambda f: f["path"]):
        rel = entry["path"]
        path = project / rel
        if not path.exists() or not path.is_file():
            continue
        size = path.stat().st_size
        if not _include_source_file(rel, size):
            continue
        dst = source_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dst)
        rows.append({"path": rel, "size": size, "sha256": sha256_file(path)})
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
                handle.write(dumps(row) + "\n")


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return "".join(dumps(row) + "\n" for row in rows).encode("utf-8")


def _text_bytes(value: str) -> bytes:
    return (sanitize_text(value).rstrip("\n") + "\n").encode("utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(sanitize_json_value(json.loads(line)))
    return rows


def _read_project_prompt_rows(project: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for store_name in (".ithz-context", ".ithz_mcp"):
        conversations = project / store_name / "conversations"
        if not conversations.exists():
            continue
        for path in sorted(conversations.glob("pr_*.json")):
            value = read_json(path, {})
            if isinstance(value, dict) and value:
                rows.append(value)
    return rows


def _line_kind_weight(stripped: str, raw_line: str) -> tuple[str, int]:
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
    elif re.match(r"\s*(def|class|function|const|let|var|public|private)\b", raw_line):
        kind, weight = "symbol", 4
    return kind, weight


def _token_summary(text: str, limit: int = 60) -> str:
    counts: dict[str, int] = {}
    for token in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{2,}", text.lower()):
        if token in COMMON_TOKEN_STOPWORDS or token.isdigit():
            continue
        counts[token] = counts.get(token, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return " ".join(token for token, _count in ranked)


def _source_search_unit_priority(unit: dict[str, Any]) -> int:
    rel = normalize_rel(str(unit.get("path", ""))).lower()
    kind = str(unit.get("kind", ""))
    name = Path(rel).name.lower()
    ext = Path(rel).suffix.lower()
    bootstrap_docs = {
        "project.md",
        "readme.md",
        "agents.md",
        "ithz_context.md",
        "architecture.md",
        "workflow_rules.md",
        "decisions_log.md",
        "project_context.md",
        "repo.md",
    }
    if rel in bootstrap_docs or name in bootstrap_docs:
        return 0
    if kind == "file_summary":
        return 1
    if ext in {".md", ".txt", ".rst"} or rel.startswith("docs/"):
        if kind in {"heading", "decision", "gate", "risk_or_next"}:
            return 2
        return 5
    if kind in {"decision", "gate", "risk_or_next"}:
        return 3
    if kind == "heading":
        return 4
    if kind == "symbol":
        return 6
    return 9


def build_source_search_index(index: dict[str, Any]) -> dict[str, Any]:
    ranked: list[tuple[int, str, int, str, dict[str, Any]]] = []
    for unit in index.get("units", []):
        if not isinstance(unit, dict):
            continue
        priority = _source_search_unit_priority(unit)
        if priority >= 9:
            continue
        text_limit = MAX_SOURCE_SEARCH_DOC_TEXT_BYTES if priority in {0, 2} else MAX_SOURCE_SEARCH_TEXT_BYTES
        slim = {
            "path": str(unit.get("path", "")),
            "line": int(unit.get("line", 0) or 0),
            "kind": str(unit.get("kind", "")),
            "text": str(unit.get("text", ""))[:text_limit],
            "weight": int(unit.get("weight", 1) or 1),
        }
        ranked.append((priority, slim["path"].lower(), slim["line"], slim["text"], slim))
    ranked.sort(key=lambda row: (row[0], row[1], row[2], row[3]))
    selected = [row[4] for row in ranked[:MAX_SOURCE_SEARCH_UNITS]]
    doc = {
        "schema": "ithz_mcp_source_search_index_v1",
        "index_hash": index.get("index_hash", ""),
        "project_semantic_hash": index.get("project_semantic_hash", ""),
        "scan_hash": index.get("scan_hash", ""),
        "index_mode": index.get("index_mode", ""),
        "source_unit_count": len(selected),
        "source_unit_limit": MAX_SOURCE_SEARCH_UNITS,
        "source_units_truncated": len(ranked) > len(selected),
        "units": selected,
    }
    doc["source_search_index_hash"] = stable_json_hash(
        {
            "schema": doc["schema"],
            "index_hash": doc["index_hash"],
            "project_semantic_hash": doc["project_semantic_hash"],
            "units": selected,
        }
    )
    return doc


def _is_source_search_doc(rel: str) -> bool:
    rel_l = normalize_rel(rel).lower()
    name = Path(rel_l).name
    if name in {
        "project.md",
        "readme.md",
        "agents.md",
        "ithz_context.md",
        "architecture.md",
        "workflow_rules.md",
        "decisions_log.md",
        "project_context.md",
        "repo.md",
    }:
        return True
    return rel_l.startswith("docs/") and Path(rel_l).suffix in {".md", ".txt", ".rst"}


def _read_source_search_doc_lines(project: Path, rel: str) -> list[str]:
    path = project / rel
    try:
        data = path.read_bytes()[:MAX_SOURCE_SEARCH_DOC_SAMPLE_BYTES]
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()


def build_source_search_index_from_scan(
    project: Path,
    scan: dict[str, Any],
    index_hash: str = "",
    project_semantic_hash: str = "",
    index_mode: str = "",
) -> dict[str, Any]:
    project = project.resolve()
    units: list[dict[str, Any]] = []
    files = sorted(scan.get("files", []), key=lambda f: str(f.get("path", "")).lower())
    for f in files:
        rel = normalize_rel(str(f.get("path", "")))
        text = " ".join(
            str(part)
            for part in (
                rel,
                f.get("extension", ""),
                f.get("family_guess", ""),
                f"size:{f.get('size', 0)}",
                "text" if f.get("text") else "binary",
            )
            if part is not None
        )
        units.append({"path": rel, "line": 0, "kind": "file_summary", "text": text[:MAX_SOURCE_SEARCH_TEXT_BYTES], "weight": 2})
    doc_paths = [normalize_rel(str(f.get("path", ""))) for f in files if f.get("text") and _is_source_search_doc(str(f.get("path", "")))]
    for rel in doc_paths[:MAX_SOURCE_SEARCH_DOC_FILES]:
        kept = 0
        for lineno, line in enumerate(_read_source_search_doc_lines(project, rel), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            kind, weight = _line_kind_weight(stripped, line)
            is_bootstrap = Path(rel.lower()).name in {"project.md", "agents.md", "ithz_context.md", "readme.md"}
            if kind == "line" and not is_bootstrap:
                continue
            kept += 1
            if kept > 120:
                break
            units.append(
                {
                    "path": rel,
                    "line": lineno,
                    "kind": kind,
                    "text": stripped[:MAX_SOURCE_SEARCH_DOC_TEXT_BYTES],
                    "weight": weight,
                }
            )
    doc = {
        "schema": "ithz_mcp_source_search_index_v1",
        "index_hash": index_hash,
        "project_semantic_hash": project_semantic_hash,
        "scan_hash": scan.get("scan_hash", ""),
        "index_mode": index_mode,
        "source_unit_count": len(units),
        "source_unit_limit": MAX_SOURCE_SEARCH_UNITS,
        "source_units_truncated": len(units) > MAX_SOURCE_SEARCH_UNITS,
        "units": units[:MAX_SOURCE_SEARCH_UNITS],
    }
    doc["source_search_index_hash"] = stable_json_hash(
        {
            "schema": doc["schema"],
            "index_hash": doc["index_hash"],
            "project_semantic_hash": doc["project_semantic_hash"],
            "scan_hash": doc["scan_hash"],
            "units": doc["units"],
        }
    )
    return doc


def _read_index_text_sample(path: Path) -> list[str]:
    data = path.read_bytes()[:MAX_INDEX_TEXT_SAMPLE_BYTES]
    text = data.decode("utf-8", errors="replace")
    return text.splitlines()


def _event_semantic_key(event: dict[str, Any]) -> str:
    existing = event.get("semantic_event_hash")
    if isinstance(existing, str) and existing:
        return existing
    return stable_json_hash({k: v for k, v in event.items() if k not in {"event_id", "merged_from_event_id"}})


def _prompt_semantic_key(row: dict[str, Any]) -> str:
    existing = row.get("semantic_prompt_hash")
    if isinstance(existing, str) and existing:
        return existing
    return stable_json_hash({k: v for k, v in row.items() if k not in {"record_id", "prompt_id", "response_id"}})


def _derive_prompt_summary_index(prompt_rows: list[dict[str, Any]]) -> dict[str, Any]:
    units = []
    for idx, row in enumerate(prompt_rows, start=1):
        if row.get("local_only"):
            continue
        text = " ".join(
            str(row.get(k, ""))
            for k in ("task", "prompt_summary", "response_summary", "redaction_status")
            if row.get(k)
        )
        units.append(
            {
                "record_id": row.get("record_id"),
                "prompt_id": row.get("prompt_id"),
                "response_id": row.get("response_id"),
                "line": idx,
                "task": row.get("task", ""),
                "text": text[:1000],
                "semantic_prompt_hash": _prompt_semantic_key(row),
            }
        )
    doc = {"schema": "ithz_mcp_prompt_summary_index_v1", "units": units, "prompt_count": len(units)}
    doc["prompt_summary_index_hash"] = stable_json_hash({"units": units})
    return doc


def _derive_context_commits(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any], str]:
    commits: list[dict[str, Any]] = []
    parent: str | None = None
    for idx, event in enumerate(events, start=1):
        cid = f"ctx_{idx:06d}"
        commit = {
            "schema": "ithz_mcp_archive_context_commit_v1",
            "context_commit_id": cid,
            "parent": parent,
            "parents": [parent] if parent else [],
            "event_id": event.get("event_id"),
            "kind": event.get("kind", "event"),
            "source": event.get("source", ""),
            "tags": event.get("tags", []),
            "text": str(event.get("text", ""))[:1000],
            "git": event.get("git", {}),
            "semantic_event_hash": _event_semantic_key(event),
        }
        commit["semantic_context_hash"] = stable_json_hash({k: v for k, v in commit.items() if k != "context_commit_id"})
        commits.append(commit)
        parent = cid
    head = commits[-1]["context_commit_id"] if commits else ""
    commit_index = {
        "schema": "ithz_mcp_archive_context_commit_index_v1",
        "commit_count": len(commits),
        "head": head,
        "commits": [
            {
                "context_commit_id": c["context_commit_id"],
                "parent": c["parent"],
                "semantic_context_hash": c["semantic_context_hash"],
                "event_id": c.get("event_id"),
                "kind": c.get("kind"),
            }
            for c in commits
        ],
    }
    commit_index["commit_index_hash"] = stable_json_hash({"commits": commit_index["commits"], "head": head})
    ref_index = {
        "schema": "ithz_mcp_archive_refs_v1",
        "HEAD": head,
        "refs": {"main": head},
        "branches": {"main": head},
        "tags": {},
    }
    ref_index["refs_hash"] = stable_json_hash({"HEAD": head, "refs": ref_index["refs"], "branches": ref_index["branches"], "tags": ref_index["tags"]})
    return commits, commit_index, ref_index, head


def build_ephemeral_index(project: Path, include_child_zones: bool = False, scan: dict[str, Any] | None = None, index_mode: str = INDEX_MODE_COMPACT) -> dict[str, Any]:
    scan = scan or scan_project_for_archive(project, include_child_zones)
    compact = index_mode != INDEX_MODE_FULL
    units: list[dict[str, Any]] = []
    if compact:
        units = build_source_search_index_from_scan(project, scan, index_mode=index_mode)["units"]
    else:
        for f in scan["files"]:
            if not f["text"]:
                continue
            path = project / f["path"]
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                kind, weight = _line_kind_weight(stripped, line)
                units.append({"path": f["path"], "line": lineno, "kind": kind, "text": stripped[:500], "weight": weight})
    index = {
        "schema": "ithz_mcp_index_v1",
        "index_mode": index_mode,
        "project": str(project.resolve()),
        "scan_hash": scan["scan_hash"],
        "files": [
            {k: f.get(k) for k in ("path", "size", "sha256", "extension", "family_guess", "text", "line_count")}
            for f in scan["files"]
        ],
        "ignored": [] if compact else scan["ignored"],
        "ignored_summary": _scan_ignored_summary(list(scan.get("ignored", []))) if compact else {},
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
    return index


def _prepare_dataset(
    project: Path,
    work: Path,
    include_child_zones: bool = False,
    index_mode: str = INDEX_MODE_COMPACT,
    include_source_snapshot: bool = False,
) -> dict[str, Any]:
    project = project.resolve()
    dataset = work / "dataset"
    dataset.mkdir(parents=True, exist_ok=True)
    bootstrap = ensure_project_bootstrap(project)
    scan = scan_project_for_archive(project, include_child_zones)
    source_rows = _copy_source_snapshot(project, dataset, scan) if include_source_snapshot else []
    index = build_ephemeral_index(project, include_child_zones, scan, index_mode)
    source_search_index = build_source_search_index_from_scan(
        project,
        scan,
        str(index.get("index_hash", "")),
        str(index.get("project_semantic_hash", "")),
        index_mode,
    )
    prompt_rows = _read_project_prompt_rows(project)
    zone = resolve_memory_zone(project, "current")
    scan_to_store = compact_scan_for_archive(scan) if index_mode != INDEX_MODE_FULL else scan
    index_to_store = compact_index_for_archive(index, source_search_index) if index_mode != INDEX_MODE_FULL else index
    context_units_to_store = [] if index_mode != INDEX_MODE_FULL else index["units"]
    manifest = {
        "schema": ARCHIVE_SCHEMA,
        "project_root": str(project),
        "bootstrap_file": BOOTSTRAP_NAME,
        "archive_file": ARCHIVE_NAME,
        "index_mode": index_mode,
        "scan_storage_mode": "compact" if index_mode != INDEX_MODE_FULL else "full",
        "context_units_storage_mode": "compact" if index_mode != INDEX_MODE_FULL else "full",
        "source_file_count": len(source_rows),
        "source_bytes": sum(int(r["size"]) for r in source_rows),
        "source_snapshot_included": bool(include_source_snapshot),
        "scan_hash": scan["scan_hash"],
        "index_hash": index["index_hash"],
        "source_search_index_hash": source_search_index["source_search_index_hash"],
        "project_semantic_hash": index["project_semantic_hash"],
        "prompt_record_count": len(prompt_rows),
        "bootstrap": bootstrap,
        "active_memory_zone": zone.active_memory_zone,
        "child_zones": zone.child_zones,
        "child_zones_included": bool(include_child_zones),
        "memory_layers": {
            "events": EVENT_LOG_PATH,
            "context_commits": "context-commits/",
            "decisions": DECISION_LOG_PATH,
            "prompts": PROMPT_LOG_PATH,
            "refs": "refs/",
            "branches": "branches/",
            "indexes": "indexes/",
            "memory_synthesis": MEMORY_SYNTHESIS_PATH,
            "claims": "claims/",
            "claim_index": CLAIM_INDEX_PATH,
            "project_ledger": PROJECT_LEDGER_SUMMARY_PATH,
            "replication": "replication/",
            "review": "review/",
            "snapshots": "snapshots/",
            "workflows": "workflows/",
            "instructions": "instructions/",
        },
    }
    manifest["archive_semantic_hash"] = stable_json_hash(
        {
            "schema": ARCHIVE_SCHEMA,
            "source": source_rows,
            "index_hash": index["index_hash"],
            "prompt_rows": [
                {k: r.get(k) for k in ("prompt_id", "response_id", "task", "mode", "semantic_prompt_hash", "semantic_response_hash")}
                for r in prompt_rows
            ],
        }
    )
    write_json(dataset / "manifest.json", manifest)
    write_json(dataset / "index.json", index_to_store)
    write_json(dataset / SOURCE_SEARCH_INDEX_PATH, source_search_index)
    write_json(dataset / "scan.json", scan_to_store)
    _write_jsonl(dataset / "context_units.jsonl", context_units_to_store)
    _write_jsonl(dataset / PROMPT_LOG_PATH, prompt_rows)
    for rel, data in _layer_update_bytes([], prompt_rows).items():
        target = dataset / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (dataset / BOOTSTRAP_NAME).write_text(project_bootstrap_path(project).read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    return manifest


def _native_creationflags() -> int:
    if os.name != "nt":
        return 0
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _native_subprocess_kwargs() -> dict[str, int]:
    flags = _native_creationflags()
    return {"creationflags": flags} if flags else {}


def _run_native(args: list[str], native_exe: Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run([str(native_exe), *args], text=True, capture_output=True, check=False, cwd=str(cwd) if cwd else None, **_native_subprocess_kwargs())
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return subprocess.CompletedProcess(
            [str(native_exe), *args],
            127,
            "",
            f"native_transport_unavailable: {type(exc).__name__}: {exc}",
        )


def _run_native_bytes(args: list[str], native_exe: Path, cwd: Path | None = None, timeout: float | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run([str(native_exe), *args], capture_output=True, check=False, cwd=str(cwd) if cwd else None, timeout=timeout, **_native_subprocess_kwargs())
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            [str(native_exe), *args],
            124,
            exc.stdout or b"",
            (exc.stderr or b"") + f"\nnative_transport_timeout_seconds={timeout}".encode("utf-8"),
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return subprocess.CompletedProcess(
            [str(native_exe), *args],
            127,
            b"",
            f"native_transport_unavailable: {type(exc).__name__}: {exc}".encode("utf-8", errors="replace"),
        )


def _run_native_stdin(args: list[str], native_exe: Path, data: bytes, cwd: Path | None = None, timeout: float | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run([str(native_exe), *args], input=data, capture_output=True, check=False, cwd=str(cwd) if cwd else None, timeout=timeout, **_native_subprocess_kwargs())
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            [str(native_exe), *args],
            124,
            exc.stdout or b"",
            (exc.stderr or b"") + f"\nnative_transport_timeout_seconds={timeout}".encode("utf-8"),
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return subprocess.CompletedProcess(
            [str(native_exe), *args],
            127,
            b"",
            f"native_transport_unavailable: {type(exc).__name__}: {exc}".encode("utf-8", errors="replace"),
        )


def _parse_native_kv(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _write_update_bytes_to_extracted_tree(extracted: Path, updates: dict[str, bytes]) -> None:
    root = extracted.resolve()
    for rel_path, data in updates.items():
        validate_archive_path(rel_path)
        target = (root / Path(rel_path.replace("/", os.sep))).resolve()
        if root != target and root not in target.parents:
            raise ValueError(f"update path escapes archive root: {rel_path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _update_archive_files_by_repack(
    archive: Path,
    updates: dict[str, bytes],
    native_exe: Path,
    verify: str,
    archive_sha256_before: str,
    fallback_reason: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ithz_mcp_update_repack_") as tmp:
        tmp_root = Path(tmp)
        extracted = tmp_root / "extracted"
        new_archive = tmp_root / ARCHIVE_NAME
        extract_result = _run_native_bytes(
            ["--extract", str(archive), "--output", str(extracted), "--verify=safe"],
            native_exe,
            cwd=tmp_root,
            timeout=DEFAULT_NATIVE_UPDATE_TIMEOUT_SECONDS,
        )
        if extract_result.returncode != 0:
            stdout = extract_result.stdout.decode("utf-8", errors="replace")
            stderr = extract_result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(stderr.strip() or stdout.strip() or "ithz-native extract fallback failed")
        _write_update_bytes_to_extracted_tree(extracted, updates)
        pack_result = _run_native_bytes(
            ["--pack-folder", str(extracted), "--archive", str(new_archive), "--verify=" + verify],
            native_exe,
            cwd=tmp_root,
            timeout=DEFAULT_NATIVE_UPDATE_TIMEOUT_SECONDS,
        )
        stdout = pack_result.stdout.decode("utf-8", errors="replace")
        stderr = pack_result.stderr.decode("utf-8", errors="replace")
        if pack_result.returncode != 0:
            raise RuntimeError(stderr.strip() or stdout.strip() or "ithz-native repack fallback failed")
        os.replace(new_archive, archive)
    values = _parse_native_kv(stdout)
    return {
        "paths": sorted(updates),
        "update_count": len(updates),
        "replaced_existing_count": len(updates),
        "input_bytes": sum(len(data) for data in updates.values()),
        "archive_sha256_before": archive_sha256_before,
        "archive_sha256_after": sha256_file(archive),
        "lock_acquired": True,
        "precondition_checked": True,
        "semantic_plan_hash": values.get("semantic_plan_hash"),
        "container_bytes_hash": values.get("container_bytes_hash"),
        "archive_bytes": int(values.get("archive_bytes", "0") or "0"),
        "verify_mode": values.get("verify_mode"),
        "update_mode": "extract_repack_fallback",
        "fallback_reason": fallback_reason,
        "raw_stdout": stdout,
    }


@contextmanager
def _archive_write_lock(archive: Path, phase: str = "archive_write", wait_seconds: float | None = None):
    lock = archive.with_name(archive.name + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    if wait_seconds is None:
        wait_seconds = _archive_lock_wait_seconds()
    deadline = time.monotonic() + max(0.0, wait_seconds)
    metadata = _archive_lock_metadata(archive, lock, phase, wait_seconds)
    fd: int | None = None
    try:
        while True:
            try:
                fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, dump_pretty(metadata).encode("utf-8"))
                os.close(fd)
                fd = None
                yield lock
                break
            except FileExistsError as exc:
                existing = _read_archive_lock(lock)
                if _remove_stale_lock_if_safe(lock, existing):
                    continue
                if time.monotonic() >= deadline:
                    detail = {
                        "reason": "archive_write_lock_busy",
                        "archive": str(archive),
                        "lock": str(lock),
                        "phase": phase,
                        "wait_seconds": wait_seconds,
                        "existing_lock": existing,
                    }
                    raise ArchiveWriteLockError("archive_write_lock_busy:" + dump_pretty(detail)) from exc
                time.sleep(0.1)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def _archive_lock_wait_seconds() -> float:
    raw = os.environ.get("ITHZ_MCP_ARCHIVE_LOCK_WAIT_SECONDS")
    if not raw:
        return DEFAULT_ARCHIVE_LOCK_WAIT_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_ARCHIVE_LOCK_WAIT_SECONDS


def _archive_lock_metadata(archive: Path, lock: Path, phase: str, wait_seconds: float) -> dict[str, Any]:
    argv = " ".join(sys.argv[:6])
    if redaction_block_reason(argv):
        argv = "[redacted_command]"
    return {
        "schema": "ithz_mcp_archive_write_lock_v2",
        "archive": str(archive),
        "lock": str(lock),
        "phase": phase,
        "pid": os.getpid(),
        "created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "wait_seconds": wait_seconds,
        "command": argv[:500],
    }


def _read_archive_lock(lock: Path) -> dict[str, Any]:
    try:
        text = lock.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"schema": "ithz_mcp_archive_write_lock_unknown", "lock": str(lock), "read_error": str(exc)}
    try:
        loaded = json.loads(text)
        if isinstance(loaded, dict):
            return loaded
    except json.JSONDecodeError:
        pass
    legacy: dict[str, Any] = {"schema": "ithz_mcp_archive_write_lock_legacy", "lock": str(lock), "raw": text[:1000]}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            legacy[key.strip()] = value.strip()
    return legacy


def _pid_is_running(pid: Any) -> bool | None:
    try:
        numeric = int(pid)
    except (TypeError, ValueError):
        return None
    if numeric <= 0:
        return None
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {numeric}", "/FO", "CSV", "/NH"],
                text=True,
                capture_output=True,
                check=False,
                timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return str(numeric) in result.stdout
    try:
        os.kill(numeric, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None


def _lock_age_seconds(lock_info: dict[str, Any]) -> float | None:
    created = lock_info.get("created_utc")
    if not isinstance(created, str):
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds())


def _remove_stale_lock_if_safe(lock: Path, lock_info: dict[str, Any]) -> bool:
    raw = os.environ.get("ITHZ_MCP_ARCHIVE_LOCK_STALE_SECONDS", "1800")
    try:
        stale_after = max(0.0, float(raw))
    except ValueError:
        stale_after = 1800.0
    age = _lock_age_seconds(lock_info)
    if age is None or age < stale_after:
        return False
    running = _pid_is_running(lock_info.get("pid"))
    if running is True:
        return False
    try:
        lock.unlink()
        return True
    except OSError:
        return False


def native_version_info(native_exe: Path) -> dict[str, Any]:
    result = _run_native(["--version"], native_exe)
    if result.returncode != 0:
        return {"version_ok": False, "error": result.stderr.strip() or result.stdout.strip()}
    values = _parse_native_kv(result.stdout)
    return {
        "version_ok": True,
        "ithz_native_version": values.get("ithz_native_version"),
        "build_profile": values.get("build_profile"),
        "avx2_build": values.get("avx2_build"),
        "manifest_support_versions": values.get("manifest_support_versions"),
    }


def build_native_archive(
    project: Path,
    native_exe: str | None = None,
    verify: str = "safe",
    include_child_zones: bool = False,
    index_mode: str = INDEX_MODE_COMPACT,
    include_source_snapshot: bool = False,
) -> dict[str, Any]:
    project = project.resolve()
    if index_mode not in {INDEX_MODE_FULL, INDEX_MODE_COMPACT}:
        raise ValueError("unsupported_index_mode")
    exe = locate_native_ithz(native_exe)
    archive = project_archive_path(project)
    with _archive_write_lock(archive, "build_native_archive"):
        with tempfile.TemporaryDirectory(prefix="ithz_mcp_archive_") as tmp:
            work = Path(tmp)
            manifest = _prepare_dataset(project, work, include_child_zones, index_mode, include_source_snapshot)
            result = _run_native(["--pack-folder", str(work / "dataset"), "--archive", str(archive), "--verify=" + verify], exe, cwd=work)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "ithz-native pack failed")
    cleanup_native_plan_artifacts(project)
    verify_result = _run_native(["--verify", str(archive), "--verify=safe"], exe)
    if verify_result.returncode != 0:
        raise RuntimeError(verify_result.stderr.strip() or verify_result.stdout.strip() or "ithz-native verify failed")
    return {
        "archive": str(archive),
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": sha256_file(archive),
        "native_exe": str(exe),
        "verified_safe": True,
        "active_memory_zone": str(archive.resolve()),
        "child_zones_included": bool(include_child_zones),
        **manifest,
    }


def extract_native_archive(project: Path, native_exe: str | None = None) -> tuple[Path, tempfile.TemporaryDirectory[str]]:
    project = project.resolve()
    archive = project_archive_path(project)
    if not archive.exists():
        raise FileNotFoundError(f"{archive} does not exist; run init-native-archive-memory first")
    exe = locate_native_ithz(native_exe)
    tmp = tempfile.TemporaryDirectory(prefix="ithz_mcp_read_")
    out = Path(tmp.name) / "extract"
    result = _run_native(["--extract", str(archive), "--output", str(out)], exe)
    if result.returncode != 0:
        tmp.cleanup()
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "ithz-native extract failed")
    return out, tmp


def extract_archive_file_bytes(project: Path, archive_inner_path: str, native_exe: str | None = None) -> bytes:
    project = project.resolve()
    archive = project_archive_path(project)
    if not archive.exists():
        raise FileNotFoundError(f"{archive} does not exist; run init-native-archive-memory first")
    exe = locate_native_ithz(native_exe)
    result = _run_native_bytes(["--extract-file", str(archive), "--path", archive_inner_path, "--output", "-"], exe)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(detail.strip() or f"ithz-native extract-file stdout failed for {archive_inner_path}")
    return result.stdout


def update_archive_file_bytes(project: Path, archive_inner_path: str, data: bytes, native_exe: str | None = None, verify: str = "safe", expected_archive_sha256: str | None = None) -> dict[str, Any]:
    project = project.resolve()
    archive = project_archive_path(project)
    if not archive.exists():
        raise FileNotFoundError(f"{archive} does not exist; run init-native-archive-memory first")
    exe = locate_native_ithz(native_exe)
    with _archive_write_lock(archive, f"update_archive_file:{archive_inner_path}"):
        archive_sha256_before = sha256_file(archive)
        if expected_archive_sha256 is not None and archive_sha256_before != expected_archive_sha256:
            raise RuntimeError("archive hash precondition failed")
        with tempfile.TemporaryDirectory(prefix="ithz_mcp_update_") as tmp:
            result = _run_native_stdin(
                ["--update-file", str(archive), "--path", archive_inner_path, "--input", "-", "--verify=" + verify],
                exe,
                data,
                cwd=Path(tmp),
            )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(stderr.strip() or stdout.strip() or f"ithz-native update-file failed for {archive_inner_path}")
    cleanup_native_plan_artifacts(project)
    values = _parse_native_kv(stdout)
    return {
        "path": archive_inner_path,
        "input_bytes": len(data),
        "archive_sha256_before": archive_sha256_before,
        "archive_sha256_after": sha256_file(archive),
        "lock_acquired": True,
        "precondition_checked": expected_archive_sha256 is not None,
        "input_sha256": values.get("input_sha256"),
        "semantic_plan_hash": values.get("semantic_plan_hash"),
        "container_bytes_hash": values.get("container_bytes_hash"),
        "archive_bytes": int(values.get("archive_bytes", "0") or "0"),
        "verify_mode": values.get("verify_mode"),
        "update_mode": values.get("update_mode"),
        "raw_stdout": stdout,
    }


def update_archive_files_bytes(project: Path, updates: dict[str, bytes], native_exe: str | None = None, verify: str = "safe", expected_archive_sha256: str | None = None) -> dict[str, Any]:
    project = project.resolve()
    archive = project_archive_path(project)
    if not archive.exists():
        raise FileNotFoundError(f"{archive} does not exist; run init-native-archive-memory first")
    exe = locate_native_ithz(native_exe)
    payload = {
        "updates": [
            {"path": path, "data_base64": base64.b64encode(data).decode("ascii")}
            for path, data in sorted(updates.items())
        ]
    }
    with _archive_write_lock(archive, "update_archive_files_bytes"):
        archive_sha256_before = sha256_file(archive)
        if expected_archive_sha256 is not None and archive_sha256_before != expected_archive_sha256:
            raise RuntimeError("archive hash precondition failed")
        input_bytes = sum(len(data) for data in updates.values())
        if input_bytes >= DEFAULT_NATIVE_UPDATE_DIRECT_REPACK_BYTES:
            return _update_archive_files_by_repack(
                archive,
                updates,
                exe,
                verify,
                archive_sha256_before,
                "large_update_payload",
            )
        with tempfile.TemporaryDirectory(prefix="ithz_mcp_update_") as tmp:
            payload_path = Path(tmp) / "updates.json"
            payload_path.write_bytes(dump_pretty(payload).encode("utf-8"))
            result = _run_native_bytes(
                ["--update-files", str(archive), "--input", str(payload_path), "--verify=" + verify],
                exe,
                cwd=Path(tmp),
                timeout=DEFAULT_NATIVE_UPDATE_TIMEOUT_SECONDS,
            )
            if result.returncode == 124:
                return _update_archive_files_by_repack(
                    archive,
                    updates,
                exe,
                verify,
                archive_sha256_before,
                "native_update_files_timeout",
            )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(stderr.strip() or stdout.strip() or "ithz-native update-files failed")
    cleanup_native_plan_artifacts(project)
    values = _parse_native_kv(stdout)
    return {
        "paths": sorted(updates),
        "update_count": int(values.get("update_count", "0") or "0"),
        "replaced_existing_count": int(values.get("replaced_existing_count", "0") or "0"),
        "input_bytes": sum(len(data) for data in updates.values()),
        "archive_sha256_before": archive_sha256_before,
        "archive_sha256_after": sha256_file(archive),
        "lock_acquired": True,
        "precondition_checked": expected_archive_sha256 is not None,
        "semantic_plan_hash": values.get("semantic_plan_hash"),
        "container_bytes_hash": values.get("container_bytes_hash"),
        "archive_bytes": int(values.get("archive_bytes", "0") or "0"),
        "verify_mode": values.get("verify_mode"),
        "update_mode": values.get("update_mode"),
        "raw_stdout": stdout,
    }


def _load_archive_json_optional(project: Path, archive_inner_path: str, default: Any, native_exe: str | None = None) -> Any:
    try:
        return _load_archive_json(project, archive_inner_path, native_exe)
    except RuntimeError as exc:
        if "path not found" in str(exc):
            return default
        raise


def _load_archive_jsonl_optional(project: Path, archive_inner_path: str, native_exe: str | None = None) -> list[dict[str, Any]]:
    try:
        data = extract_archive_file_bytes(project, archive_inner_path, native_exe)
    except RuntimeError as exc:
        if "path not found" in str(exc):
            return []
        raise
    return [sanitize_json_value(json.loads(line)) for line in data.decode("utf-8-sig").splitlines() if line.strip()]


def _relationship_between(active_root: Path, target_root: Path) -> str:
    active = active_root.resolve()
    target = target_root.resolve()
    if active == target:
        return "self"
    if target in active.parents:
        return "parent"
    if active in target.parents:
        return "child"
    if active.parent == target.parent:
        return "sibling"
    return "external"


def _linked_zones_document(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    zone = resolve_memory_zone(project, "current")
    default = {
        "schema": "ithz_mcp_linked_zones_v1",
        "owner_active_memory_zone": zone.active_memory_zone,
        "zones": [],
    }
    doc = _load_archive_json_optional(project, "zones/linked_zones.json", default, native_exe)
    if not isinstance(doc, dict):
        return default
    doc.setdefault("schema", "ithz_mcp_linked_zones_v1")
    doc.setdefault("owner_active_memory_zone", zone.active_memory_zone)
    doc.setdefault("zones", [])
    return doc


def archive_link_zone(
    project: Path,
    name: str,
    target_path: Path,
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    relationship: str = "auto",
) -> dict[str, Any]:
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    if not project_archive_path(active_root).exists():
        build_native_archive(active_root, native_exe)
    target_root = _zone_root_from_path(target_path)
    target_archive = project_archive_path(target_root)
    if not target_archive.exists():
        raise FileNotFoundError(f"target memory zone archive does not exist: {target_archive}")
    rel = _relationship_between(active_root, target_root) if relationship == "auto" else relationship
    exe = locate_native_ithz(native_exe)
    current_hash = sha256_file(project_archive_path(active_root))
    doc = _linked_zones_document(active_root, str(exe))
    zones = [z for z in doc.get("zones", []) if z.get("name") != name]
    target_status = native_archive_status(target_root, str(exe), "current")
    entry = {
        "name": name,
        "root": str(target_root.resolve()),
        "archive": str(target_archive.resolve()),
        "relationship": rel,
        "read_allowed": True,
        "write_requires_explicit_target": True,
        "archive_exists": True,
        "archive_sha256": target_status.get("archive_sha256"),
        "archive_semantic_hash": target_status.get("archive_semantic_hash"),
    }
    zones.append(entry)
    zones.sort(key=lambda z: z["name"])
    doc["zones"] = zones
    doc["linked_zone_hash"] = stable_json_hash({"zones": zones})
    update = update_archive_files_bytes(
        active_root,
        {"zones/linked_zones.json": dump_pretty(doc).encode("utf-8")},
        str(exe),
        "safe",
        current_hash,
    )
    return {"linked": True, "active_memory_zone": active_zone.active_memory_zone, "zone": entry, "linked_zone_hash": doc["linked_zone_hash"], "update": update}


def archive_zone_status(project: Path, native_exe: str | None = None, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> dict[str, Any]:
    status = native_archive_status(project, native_exe, memory_zone, memory_zone_path)
    if not status.get("exists"):
        status["linked_zones"] = []
        status["cross_zone_event_count"] = 0
        return status
    active_root = Path(status["project"])
    exe = locate_native_ithz(native_exe)
    linked = _linked_zones_document(active_root, str(exe))
    events = _load_archive_jsonl_optional(active_root, "zones/cross_zone_events.jsonl", str(exe))
    status["linked_zones"] = linked.get("zones", [])
    status["linked_zone_hash"] = linked.get("linked_zone_hash")
    status["cross_zone_event_count"] = len(events)
    return status


def archive_cross_zone_context_pack(
    project: Path,
    query: str,
    max_bytes: int = 20000,
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_active: bool = True,
) -> dict[str, Any]:
    status = archive_zone_status(project, native_exe, memory_zone, memory_zone_path)
    active_root = Path(status["project"])
    exe = locate_native_ithz(native_exe)
    zone_entries: list[dict[str, Any]] = []
    if include_active:
        zone_entries.append({"name": "active", "root": str(active_root), "archive": status["active_memory_zone"], "relationship": "self"})
    for zone in status.get("linked_zones", []):
        if zone.get("read_allowed", True):
            zone_entries.append(zone)
    lines = [
        "# ITHZ Cross-Zone Context Pack",
        "",
        f"- query: {query}",
        f"- active_memory_zone: {status.get('active_memory_zone')}",
        f"- zone_count: {len(zone_entries)}",
        "",
    ]
    all_rows: list[dict[str, Any]] = []
    for zone in zone_entries:
        root = Path(zone["root"])
        try:
            result = native_archive_search(root, query, 10, str(exe), "current")
            rows = result["rows"]
            zone_hash = result.get("archive_semantic_hash")
            zone_error = None
        except Exception as exc:
            rows = []
            zone_hash = None
            zone_error = str(exc)
        lines.append(f"## Zone: {zone.get('name')}")
        lines.append(f"- relationship: {zone.get('relationship')}")
        lines.append(f"- archive: {zone.get('archive')}")
        if zone_hash:
            lines.append(f"- archive_semantic_hash: {zone_hash}")
        if zone_error:
            lines.append(f"- error: {zone_error}")
        if not rows:
            lines.append("- no matching evidence")
        for row in rows:
            all_rows.append({"zone": zone.get("name"), **row})
            lines.append(f"- `{row['path']}:{row['line']}` [{row['kind']}] score={row.get('score')} reason={row.get('why_selected')}: {row['text']}")
        lines.append("")
    text = sanitize_text("\n".join(lines))
    if len(text.encode("utf-8")) > max_bytes:
        text = text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore") + "\n\n[truncated deterministically]\n"
    return {
        "text": text,
        "bytes": len(text.encode("utf-8")),
        "query": query,
        "active_memory_zone": status.get("active_memory_zone"),
        "zones": zone_entries,
        "rows": all_rows,
        "context_pack_hash": stable_json_hash({"query": query, "text": text, "active_memory_zone": status.get("active_memory_zone")}),
    }


def archive_record_cross_zone_event(
    project: Path,
    target_zone: str,
    event: str,
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
) -> dict[str, Any]:
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    if not project_archive_path(active_root).exists():
        build_native_archive(active_root, native_exe)
    exe = locate_native_ithz(native_exe)
    current_hash = sha256_file(project_archive_path(active_root))
    linked = _linked_zones_document(active_root, str(exe))
    target = next((z for z in linked.get("zones", []) if z.get("name") == target_zone), None)
    rows = _load_archive_jsonl_optional(active_root, "zones/cross_zone_events.jsonl", str(exe))
    event_id = f"xz_{len(rows) + 1:06d}"
    record = {
        "schema": "ithz_mcp_cross_zone_event_v1",
        "event_id": event_id,
        "active_memory_zone": active_zone.active_memory_zone,
        "target_zone": target_zone,
        "target_archive": target.get("archive") if target else None,
        "relationship": target.get("relationship") if target else "unlinked",
        "event": event,
        "semantic_event_hash": stable_json_hash({"target_zone": target_zone, "event": event, "target_archive": target.get("archive") if target else None}),
    }
    rows.append(record)
    update = update_archive_files_bytes(
        active_root,
        {"zones/cross_zone_events.jsonl": _jsonl_bytes(rows)},
        str(exe),
        "safe",
        current_hash,
    )
    return {"recorded": True, "active_memory_zone": active_zone.active_memory_zone, "record": record, "update": update}


def _memory_events(project: Path, native_exe: str | None = None) -> list[dict[str, Any]]:
    return _load_archive_jsonl_optional(project, EVENT_LOG_PATH, native_exe)


def _snapshot_index(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    default = {"schema": "ithz_mcp_snapshot_index_v1", "snapshots": []}
    doc = _load_archive_json_optional(project, SNAPSHOT_INDEX_PATH, default, native_exe)
    if not isinstance(doc, dict):
        return default
    doc.setdefault("schema", "ithz_mcp_snapshot_index_v1")
    doc.setdefault("snapshots", [])
    return doc


def _derive_current_index(events: list[dict[str, Any]]) -> dict[str, Any]:
    current, _ = _active_events(events)
    active_typed = {event.get("event_id") for event in current if event.get("_memory_read_state") == "active"}
    normalized = []
    counts_by_kind: dict[str, int] = {}
    latest_by_kind: dict[str, str] = {}
    searchable_units = []
    for event in sorted(events, key=lambda e: e.get("event_id", "")):
        event_id = str(event.get("event_id", ""))
        kind = str(event.get("kind", "event"))
        text = str(event.get("text", ""))
        git = event.get("git") if isinstance(event.get("git"), dict) else {}
        git_text = " ".join(str(git.get(k, "")) for k in ("git_branch", "git_commit_short_hash", "git_commit_subject", "git_commit_ref_names"))
        source = str(event.get("source", ""))
        tags = [str(t) for t in event.get("tags", [])]
        semantic_hash = str(event.get("semantic_event_hash", ""))
        record = event.get("metadata", {}).get("memory_record", {}) if isinstance(event.get("metadata"), dict) else {}
        verification_state = ("active" if event_id in active_typed else "unverified_history") if record else "legacy_unverified_abstraction"
        normalized.append(
            {
                "event_id": event_id,
                "kind": kind,
                "source": source,
                "tags": tags,
                "text": text,
                "git": {k: git.get(k) for k in ("available", "git_branch", "git_commit_hash", "git_commit_short_hash", "git_commit_subject", "git_commit_ref_names") if k in git},
                "semantic_event_hash": semantic_hash,
                "verification_state": verification_state,
            }
        )
        counts_by_kind[kind] = counts_by_kind.get(kind, 0) + 1
        latest_by_kind[kind] = event_id
        searchable_units.append(
            {
                "event_id": event_id,
                "kind": kind,
                "source": source,
                "tags": tags,
                "text": text[:1000],
                "git": {k: git.get(k) for k in ("git_branch", "git_commit_short_hash", "git_commit_subject") if k in git},
                "git_text": git_text[:500],
                "verification_state": verification_state,
                "status": "active" if event_id in active_typed else "history" if record else "observed",
                "valid_from": record.get("valid_from", ""),
                "valid_until": record.get("valid_until", ""),
                "weight": {
                    "decision": 6,
                    "workflow_rule": 6,
                    "claim": 6,
                    "blocked_claim": 7,
                    "gate": 5,
                    "risk": 5,
                    "must_not_break": 6,
                    "replication_pack": 5,
                    "reviewer_note": 4,
                    "next": 4,
                }.get(kind, 3),
            }
        )
    index = {
        "schema": "ithz_mcp_current_index_v1",
        "event_count": len(normalized),
        "counts_by_kind": dict(sorted(counts_by_kind.items())),
        "latest_by_kind": dict(sorted(latest_by_kind.items())),
        "searchable_units": searchable_units,
    }
    index["current_index_hash"] = stable_json_hash({"events": normalized, "schema": index["schema"]})
    return index


def _event_order(event: dict[str, Any]) -> tuple[int, str]:
    event_id = str(event.get("event_id", ""))
    match = re.search(r"(\d+)$", event_id)
    return (int(match.group(1)) if match else -1, event_id)


def _compact_event_view(event: dict[str, Any], why: str) -> dict[str, Any]:
    git = event.get("git") if isinstance(event.get("git"), dict) else {}
    return {
        "event_id": str(event.get("event_id", "")),
        "kind": str(event.get("kind", "event")),
        "source": str(event.get("source", "")),
        "tags": [str(t) for t in event.get("tags", [])],
        "text": str(event.get("text", ""))[:1000],
        "git": {k: git.get(k) for k in ("git_branch", "git_commit_short_hash", "git_commit_subject") if k in git},
        "why_current": why,
        "semantic_event_hash": str(event.get("semantic_event_hash", "")),
        "verification_state": event.get("_memory_read_state", "legacy_unverified_abstraction"),
    }


def _event_matches(event: dict[str, Any], patterns: list[str]) -> bool:
    hay = " ".join(
        [
            str(event.get("kind", "")),
            str(event.get("source", "")),
            " ".join(str(t) for t in event.get("tags", [])),
            str(event.get("text", "")),
        ]
    ).lower()
    return any(re.search(pattern, hay, re.I) for pattern in patterns)


def _active_events(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[str]]:
    from .memory_integrity import evaluate_consolidation_candidate, validate_supersession
    from .memory_trust import load_runtime_trust_policy

    superseded: set[str] = set()
    by_id = {str(event.get("event_id", "")): event for event in events}
    source_contents = {"event:" + key: value for key, value in by_id.items()}
    policy = load_runtime_trust_policy()
    eligible = []
    for original in events:
        event = dict(original)
        metadata = event.get("metadata")
        record = metadata.get("memory_record") if isinstance(metadata, dict) else None
        if isinstance(record, dict):
            # Recheck signatures/content/time on read. Old active labels and
            # archived gate booleans never acquire new trust automatically.
            if record.get("verification_state") != "active":
                continue
            gate = evaluate_consolidation_candidate(record, set(by_id), set(),
                source_contents=source_contents, trust_policy=policy)
            if not gate["accepted"]:
                continue
            event["_memory_read_state"] = "active"
        eligible.append(event)
    for event in eligible:
        value = event.get("supersedes")
        targets: list[str] = []
        if isinstance(value, str) and value.strip():
            targets = [value.strip()]
        elif isinstance(value, list):
            targets = [str(item).strip() for item in value if isinstance(item, str) and item.strip()]
        metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
        receipts = metadata.get("supersession_receipts", [])
        for target_id in targets:
            target = by_id.get(target_id, {})
            target_metadata = target.get("metadata", {}) if isinstance(target, dict) and isinstance(target.get("metadata"), dict) else {}
            target_is_typed = isinstance(target_metadata.get("memory_record"), dict)
            source_record = metadata.get("memory_record")
            source_is_typed = isinstance(source_record, dict)
            if source_is_typed and not target_is_typed:
                # A typed abstraction cannot replace an untyped hard boundary.
                continue
            if target_is_typed:
                receipt_valid = source_is_typed and bool(validate_supersession(
                    source_record, target_metadata["memory_record"], target_id)["valid"])
                if not receipt_valid:
                    continue
            superseded.add(target_id)
    ordered = sorted(eligible, key=_event_order)
    active = [event for event in ordered if str(event.get("event_id", "")) not in superseded]
    return active, superseded


def _latest_events(events: list[dict[str, Any]], kinds: set[str], limit: int, why: str) -> list[dict[str, Any]]:
    selected = [event for event in reversed(events) if str(event.get("kind", "")) in kinds]
    return [_compact_event_view(event, why) for event in selected[:limit]]


def _derive_memory_synthesis(events: list[dict[str, Any]], prompt_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    prompt_rows = prompt_rows or []
    active, superseded = _active_events(events)
    next_events = [event for event in active if str(event.get("kind", "")) == "next"]
    completed_next_patterns = [r"\b(done|completed|closed|resolved|fixed|passed|hotove|ukoncene|vyriesene)\b"]
    expired_next = [
        _compact_event_view(event, "next_step_marked_completed_or_resolved")
        for event in next_events
        if _event_matches(event, completed_next_patterns)
    ]
    current_next = [
        _compact_event_view(event, "latest_open_next_step")
        for event in reversed(next_events)
        if not _event_matches(event, completed_next_patterns)
    ][:12]
    stale_items = [
        _compact_event_view(event, "superseded_by_later_event")
        for event in sorted(events, key=_event_order)
        if str(event.get("event_id", "")) in superseded
    ][:20]
    active_ids = {event.get("event_id") for event in active}
    stale_items.extend(
        {**_compact_event_view(event, "typed_memory_not_currently_authorized"), "verification_state": "unverified_history"}
        for event in events if event.get("event_id") not in active_ids
        and isinstance(event.get("metadata"), dict) and isinstance(event["metadata"].get("memory_record"), dict)
        and event.get("event_id") not in superseded
    )
    if len(next_events) > 24:
        stale_items.extend(
            _compact_event_view(event, "older_next_step_outside_current_window")
            for event in next_events[:-24]
            if str(event.get("event_id", "")) not in superseded
        )
        stale_items = stale_items[:40]
    forbidden_patterns = [r"forbidden", r"claim", r"zip", r"tar\.gz", r"git replacement", r"cloud sync", r"token-saving", r"nahradza", r"zakazane"]
    must_not_break_patterns = [r"must not", r"must-not-break", r"nesmie", r"hard rule", r"safety", r"bezpec", r"extract", r"secret", r"redaction"]
    forbidden_claims = [
        _compact_event_view(event, "forbidden_claim_or_boundary")
        for event in reversed(active)
        if _event_matches(event, forbidden_patterns)
    ][:10]
    must_not_break = [
        _compact_event_view(event, "must_not_break_or_safety_boundary")
        for event in reversed(active)
        if _event_matches(event, must_not_break_patterns)
    ][:12]
    latest_git = next((event.get("git") for event in reversed(active) if isinstance(event.get("git"), dict)), {})
    prompt_summaries = [
        {
            "record_id": row.get("record_id"),
            "task": row.get("task"),
            "mode": row.get("mode"),
            "local_only": row.get("local_only"),
            "prompt_summary": row.get("prompt_summary"),
            "response_summary": row.get("response_summary"),
            "semantic_prompt_hash": row.get("semantic_prompt_hash"),
        }
        for row in list(reversed(prompt_rows))[:8]
    ]
    synthesis = {
        "schema": "ithz_mcp_memory_synthesis_v1",
        "synthesis_rules": {
            "history_model": "append_only_events",
            "current_view": "latest_non_superseded_events_by_kind",
            "stale_policy": "superseded_events_and_old_next_steps_are_kept_in_history_but_downranked",
            "no_llm": True,
        },
        "event_count": len(events),
        "active_event_count": len(active),
        "superseded_event_count": len(superseded),
        "current_decisions": _latest_events(active, {"decision"}, 12, "latest_non_superseded_decision"),
        "current_claims": _latest_events(active, {"claim"}, 12, "latest_non_superseded_claim"),
        "current_blocked_claims": _latest_events(active, {"blocked_claim"}, 12, "latest_non_superseded_blocked_claim"),
        "current_gates": _latest_events(active, {"gate"}, 14, "latest_non_superseded_gate"),
        "current_risks": _latest_events(active, {"risk", "must_not_break"}, 14, "latest_non_superseded_risk"),
        "current_replication_packs": _latest_events(active, {"replication_pack"}, 10, "latest_replication_pack_record"),
        "latest_reviewer_notes": _latest_events(active, {"reviewer_note"}, 10, "latest_reviewer_note"),
        "must_not_break": must_not_break,
        "forbidden_claims": forbidden_claims,
        "current_next_steps": current_next,
        "expired_next_steps": expired_next,
        "stale_items": stale_items,
        "latest_prompt_summaries": prompt_summaries,
        "latest_git": latest_git if isinstance(latest_git, dict) else {},
    }
    synthesis["memory_synthesis_hash"] = stable_json_hash(
        {
            "schema": synthesis["schema"],
            "event_count": synthesis["event_count"],
            "active_event_count": synthesis["active_event_count"],
            "current_decisions": synthesis["current_decisions"],
            "current_claims": synthesis["current_claims"],
            "current_blocked_claims": synthesis["current_blocked_claims"],
            "current_gates": synthesis["current_gates"],
            "current_risks": synthesis["current_risks"],
            "current_replication_packs": synthesis["current_replication_packs"],
            "latest_reviewer_notes": synthesis["latest_reviewer_notes"],
            "current_next_steps": synthesis["current_next_steps"],
            "stale_items": synthesis["stale_items"],
            "latest_prompt_summaries": synthesis["latest_prompt_summaries"],
        }
    )
    return synthesis


def _event_metadata(event: dict[str, Any]) -> dict[str, Any]:
    metadata = event.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _ledger_record_from_event(event: dict[str, Any], record_type: str) -> dict[str, Any]:
    metadata = _event_metadata(event)
    record = {
        "schema": f"ithz_mcp_{record_type}_v1",
        "type": record_type,
        "event_id": event.get("event_id"),
        "text": metadata.get("text") or event.get("text", ""),
        "source": event.get("source", ""),
        "tags": event.get("tags", []),
        "semantic_event_hash": event.get("semantic_event_hash", ""),
    }
    for key, value in sorted(metadata.items()):
        if key not in {"type"}:
            record[key] = value
    git = event.get("git")
    if isinstance(git, dict) and git:
        record["git"] = {
            k: git.get(k)
            for k in ("available", "git_branch", "git_commit_hash", "git_commit_short_hash", "git_commit_subject", "git_commit_ref_names")
            if k in git
        }
    return sanitize_json_value(record)


def _derive_project_ledger(events: list[dict[str, Any]]) -> dict[str, Any]:
    claims = [_ledger_record_from_event(event, "claim") for event in events if event.get("kind") == "claim"]
    blocked_claims = [_ledger_record_from_event(event, "blocked_claim") for event in events if event.get("kind") == "blocked_claim"]
    replication_packs = [_ledger_record_from_event(event, "replication_pack") for event in events if event.get("kind") == "replication_pack"]
    reviewer_notes = [_ledger_record_from_event(event, "reviewer_note") for event in events if event.get("kind") == "reviewer_note"]
    claim_units = []
    for record in [*claims, *blocked_claims]:
        claim_units.append(
            {
                "type": record.get("type"),
                "claim_id": record.get("claim_id"),
                "status": record.get("status"),
                "scope": record.get("scope"),
                "text": str(record.get("text", ""))[:1000],
                "event_id": record.get("event_id"),
                "supporting_gates": record.get("supporting_gates", []),
                "blocking_gates": record.get("blocking_gates", []),
                "reason": record.get("reason", ""),
            }
        )
    claim_index = {
        "schema": "ithz_mcp_claim_index_v1",
        "claim_count": len(claims),
        "blocked_claim_count": len(blocked_claims),
        "units": claim_units,
    }
    claim_index["claim_index_hash"] = stable_json_hash({"units": claim_units})
    summary = {
        "schema": "ithz_mcp_project_ledger_summary_v1",
        "claim_count": len(claims),
        "blocked_claim_count": len(blocked_claims),
        "replication_pack_count": len(replication_packs),
        "reviewer_note_count": len(reviewer_notes),
        "latest_claim_id": claims[-1].get("claim_id") if claims else None,
        "latest_blocked_claim_id": blocked_claims[-1].get("claim_id") if blocked_claims else None,
        "latest_replication_pack_id": replication_packs[-1].get("pack_id") if replication_packs else None,
        "latest_reviewer_note_id": reviewer_notes[-1].get("note_id") if reviewer_notes else None,
        "claim_index_hash": claim_index["claim_index_hash"],
    }
    summary["project_ledger_hash"] = stable_json_hash(
        {
            "claims": claims,
            "blocked_claims": blocked_claims,
            "replication_packs": replication_packs,
            "reviewer_notes": reviewer_notes,
            "schema": summary["schema"],
        }
    )
    return {
        "claims": claims,
        "blocked_claims": blocked_claims,
        "replication_packs": replication_packs,
        "reviewer_notes": reviewer_notes,
        "claim_index": claim_index,
        "summary": summary,
    }


def _derive_layered_indexes(events: list[dict[str, Any]], prompt_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    prompt_rows = prompt_rows or []
    current = _derive_current_index(events)
    synthesis = _derive_memory_synthesis(events, prompt_rows)
    search_units = list(current.get("searchable_units", []))
    search_index = {"schema": "ithz_mcp_search_index_v1", "units": search_units}
    search_index["search_index_hash"] = stable_json_hash({"units": search_units})
    gate_units = [unit for unit in search_units if unit.get("kind") == "gate"]
    gate_index = {"schema": "ithz_mcp_gate_index_v1", "units": gate_units, "gate_count": len(gate_units)}
    gate_index["gate_index_hash"] = stable_json_hash({"units": gate_units})
    risk_units = [unit for unit in search_units if unit.get("kind") in {"risk", "must_not_break"}]
    risk_index = {"schema": "ithz_mcp_risk_index_v1", "units": risk_units, "risk_count": len(risk_units)}
    risk_index["risk_index_hash"] = stable_json_hash({"units": risk_units})
    prompt_index = _derive_prompt_summary_index(prompt_rows)
    ledger = _derive_project_ledger(events)
    decisions = [
        {
            "schema": "ithz_mcp_decision_record_v1",
            "event_id": event.get("event_id"),
            "decision": event.get("text", ""),
            "source": event.get("source", ""),
            "tags": event.get("tags", []),
            "semantic_event_hash": _event_semantic_key(event),
        }
        for event in events
        if event.get("kind") == "decision"
    ]
    commits, commit_index, ref_index, head = _derive_context_commits(events)
    branch_main = {"schema": "ithz_mcp_archive_branch_v1", "name": "main", "head": head}
    return {
        "current_index": current,
        "search_index": search_index,
        "gate_index": gate_index,
        "risk_index": risk_index,
        "prompt_summary_index": prompt_index,
        "memory_synthesis": synthesis,
        "project_ledger": ledger,
        "decisions": decisions,
        "context_commits": commits,
        "commit_index": commit_index,
        "ref_index": ref_index,
        "branch_main": branch_main,
        "head": head,
    }


def _layer_update_bytes(
    events: list[dict[str, Any]],
    prompt_rows: list[dict[str, Any]] | None = None,
    commit_start_index: int | None = None,
) -> dict[str, bytes]:
    layers = _derive_layered_indexes(events, prompt_rows)
    updates: dict[str, bytes] = {
        EVENT_LOG_PATH: _jsonl_bytes(events),
        DECISION_LOG_PATH: _jsonl_bytes(layers["decisions"]),
        CONTEXT_COMMIT_INDEX_PATH: dump_pretty(layers["commit_index"]).encode("utf-8"),
        REF_HEAD_PATH: _text_bytes(layers["head"]),
        REF_MAIN_PATH: _text_bytes(layers["head"]),
        REF_INDEX_PATH: dump_pretty(layers["ref_index"]).encode("utf-8"),
        BRANCH_MAIN_PATH: dump_pretty(layers["branch_main"]).encode("utf-8"),
        CURRENT_INDEX_PATH: dump_pretty(layers["current_index"]).encode("utf-8"),
        SEARCH_INDEX_PATH: dump_pretty(layers["search_index"]).encode("utf-8"),
        GATE_INDEX_PATH: dump_pretty(layers["gate_index"]).encode("utf-8"),
        RISK_INDEX_PATH: dump_pretty(layers["risk_index"]).encode("utf-8"),
        PROMPT_SUMMARY_INDEX_PATH: dump_pretty(layers["prompt_summary_index"]).encode("utf-8"),
        MEMORY_SYNTHESIS_PATH: dump_pretty(layers["memory_synthesis"]).encode("utf-8"),
        CLAIM_LOG_PATH: _jsonl_bytes(layers["project_ledger"]["claims"]),
        BLOCKED_CLAIM_LOG_PATH: _jsonl_bytes(layers["project_ledger"]["blocked_claims"]),
        REPLICATION_PACK_LOG_PATH: _jsonl_bytes(layers["project_ledger"]["replication_packs"]),
        REVIEWER_NOTE_LOG_PATH: _jsonl_bytes(layers["project_ledger"]["reviewer_notes"]),
        CLAIM_INDEX_PATH: dump_pretty(layers["project_ledger"]["claim_index"]).encode("utf-8"),
        PROJECT_LEDGER_SUMMARY_PATH: dump_pretty(layers["project_ledger"]["summary"]).encode("utf-8"),
    }
    commit_start_index = max(1, int(commit_start_index or 1))
    for commit in layers["context_commits"]:
        try:
            commit_index = int(str(commit["context_commit_id"]).rsplit("_", 1)[-1])
        except (KeyError, ValueError):
            commit_index = 0
        if commit_index < commit_start_index:
            continue
        updates[f"context-commits/{commit['context_commit_id']}.json"] = dump_pretty(commit).encode("utf-8")
    return updates


def _archive_safe_git_metadata(git: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "available",
        "git_branch",
        "git_commit_hash",
        "git_commit_short_hash",
        "git_commit_subject",
        "git_commit_subject_hash",
        "git_commit_ref_names",
        "git_status_porcelain_hash",
    )
    return {key: git.get(key) for key in allowed if key in git}


def _validate_append_only_events(events: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen: dict[str, str] = {}
    for event in events:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            errors.append("missing_event_id")
            continue
        semantic_hash = event.get("semantic_event_hash")
        if event_id in seen and seen[event_id] != semantic_hash:
            errors.append(f"duplicate_event_id_conflict:{event_id}")
        seen[event_id] = str(semantic_hash)
        text = event.get("text")
        if isinstance(text, str) and redaction_block_reason(text):
            errors.append(f"secret_like_event_text:{event_id}")
    return errors


def _secret_like_payload_paths(value: Any, path: str = "$") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if isinstance(item, (str, int, float, bool)) and redaction_block_reason(f"{key}={item}"):
                paths.append(child_path)
            paths.extend(_secret_like_payload_paths(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(_secret_like_payload_paths(item, f"{path}[{index}]"))
    elif isinstance(value, str) and redaction_block_reason(value):
        paths.append(path)
    return paths


def _validate_new_event_payload(event: dict[str, Any]) -> None:
    paths = _secret_like_payload_paths(
        {
            "kind": event.get("kind"),
            "source": event.get("source"),
            "tags": event.get("tags", []),
            "text": event.get("text", ""),
            "metadata": event.get("metadata", {}),
            "git": event.get("git", {}),
        }
    )
    if paths:
        raise ValueError("secret_like_event_payload_blocked:" + ",".join(sorted(paths)[:8]))


def archive_append_event(
    project: Path,
    kind: str,
    text: str,
    source: str = "manual",
    tags: list[str] | None = None,
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {"kind": kind, "text": text, "source": source, "tags": sorted(tags or [])}
    if metadata:
        spec["metadata"] = metadata
    result = archive_append_events(
        project,
        [spec],
        native_exe,
        memory_zone,
        memory_zone_path,
        include_git,
    )
    return {
        "appended": True,
        "active_memory_zone": result["active_memory_zone"],
        "event": result["events"][-1],
        "event_count": result["event_count"],
        "current_index_hash": result["current_index_hash"],
        "memory_synthesis_hash": result.get("memory_synthesis_hash"),
        "project_ledger_hash": result.get("project_ledger_hash"),
        "update": result["update"],
    }


def archive_append_memory_record(
    project: Path,
    record: dict[str, Any],
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
) -> dict[str, Any]:
    """Append an active typed abstraction or a harmless quarantine receipt."""

    from .memory_integrity import (
        evaluate_consolidation_candidate,
        validate_memory_record,
        validate_supersession,
    )

    normalized = validate_memory_record(record)
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    if not project_archive_path(active_root).exists():
        build_native_archive(active_root, native_exe)
    exe = locate_native_ithz(native_exe)
    evidence_archive_hash = sha256_file(project_archive_path(active_root))
    events = _memory_events(active_root, str(exe))
    available_event_ids = {
        str(event.get("event_id")) for event in events if isinstance(event.get("event_id"), str)
    }

    def payload_hashes(value: Any, key: str = "") -> set[str]:
        found: set[str] = set()
        if isinstance(value, dict):
            for child_key, child in value.items():
                found.update(payload_hashes(child, str(child_key)))
        elif isinstance(value, list):
            for child in value:
                found.update(payload_hashes(child, key))
        elif (
            isinstance(value, str)
            and len(value) == 64
            and all(char in "0123456789abcdef" for char in value)
            and ("hash" in key.lower() or "sha256" in key.lower())
        ):
            found.add(value)
        return found

    from .memory_trust import load_runtime_trust_policy
    gate = evaluate_consolidation_candidate(normalized, available_event_ids, payload_hashes(events),
        source_contents={"event:" + str(event.get("event_id")): event for event in events},
        trust_policy=load_runtime_trust_policy())
    supersession_receipts: list[dict[str, Any]] = []
    by_id = {str(event.get("event_id")): event for event in events}
    for event in events:
        metadata = event.get("metadata")
        prior = metadata.get("memory_record") if isinstance(metadata, dict) else None
        if isinstance(prior, dict):
            by_id.setdefault(str(prior.get("memory_id")), event)
    for target_id in normalized.get("supersedes", []):
        target = by_id.get(str(target_id))
        target_record = target.get("metadata", {}).get("memory_record") if isinstance(target, dict) else None
        if not isinstance(target_record, dict):
            receipt = {
                "schema": "ithz_supersession_receipt_v1",
                "candidate_id": normalized["memory_id"],
                "target_id": str(target_id),
                "valid": False,
                "reasons": ["typed_target_record_missing"],
                "historical_target_preserved": True,
            }
            receipt["receipt_hash"] = stable_json_hash(receipt)
            supersession_receipts.append(receipt)
        else:
            supersession_receipts.append(validate_supersession(normalized, target_record, str(target.get("event_id"))))
    supersession_valid = all(bool(receipt.get("valid")) for receipt in supersession_receipts)
    accepted = bool(gate.get("accepted")) and supersession_valid

    stored_record = dict(normalized)
    stored_record.pop("record_hash", None)
    stored_record["verification_state"] = "active" if accepted else "quarantined"
    if not accepted:
        stored_record["supersedes"] = []
        stored_record["supersession_reason"] = ""
    stored_record = validate_memory_record(stored_record)
    metadata = {
        "memory_record": stored_record,
        "consolidation_receipt": gate,
        "supersession_receipts": supersession_receipts,
        "active_abstraction": accepted,
        "historical_events_rewritten": False,
    }
    event_spec: dict[str, Any] = {
        "kind": stored_record["kind"] if accepted else "memory_candidate_quarantined",
        "text": stored_record["statement"] if accepted else f"Quarantined memory candidate: {stored_record['statement']}",
        "source": "mcp36_consolidation_gate",
        "tags": sorted({"mcp36", "typed_memory", stored_record["policy_class"], stored_record["scope"]}),
        "metadata": metadata,
    }
    if accepted and stored_record.get("supersedes"):
        event_spec["supersedes"] = [receipt["target_id"] for receipt in supersession_receipts]
    result = archive_append_events(
        active_root,
        [event_spec],
        str(exe),
        "current",
        None,
        include_git,
        expected_archive_sha256=evidence_archive_hash,
    )
    return {
        "schema": "ithz_append_memory_record_receipt_v1",
        "appended": True,
        "accepted": accepted,
        "active": accepted,
        "event": result["events"][-1],
        "consolidation_receipt": gate,
        "supersession_receipts": supersession_receipts,
        "active_memory_zone": result["active_memory_zone"],
        "memory_synthesis_hash": result.get("memory_synthesis_hash"),
        "update": result["update"],
    }


def archive_append_events(
    project: Path,
    event_specs: list[dict[str, Any]],
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    include_git: bool = False,
    extra_updates: dict[str, bytes] | None = None,
    manifest_extra: dict[str, Any] | None = None,
    expected_archive_sha256: str | None = None,
) -> dict[str, Any]:
    if not event_specs:
        raise ValueError("at_least_one_event_required")
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    if not project_archive_path(active_root).exists():
        build_native_archive(active_root, native_exe)
    exe = locate_native_ithz(native_exe)
    git = _archive_safe_git_metadata(git_status(active_root)) if include_git else None
    last_error: RuntimeError | None = None
    for attempt in range(2):
        current_hash = sha256_file(project_archive_path(active_root))
        if expected_archive_sha256 is not None and current_hash != expected_archive_sha256:
            raise RuntimeError("archive evidence precondition failed; candidate must be revalidated")
        events = _memory_events(active_root, str(exe))
        before_errors = _validate_append_only_events(events)
        if before_errors:
            raise ValueError("append_only_event_log_invalid:" + ",".join(before_errors))
        event_count_before = len(events)
        appended: list[dict[str, Any]] = []
        for spec in event_specs:
            spec = sanitize_json_value(spec)
            kind = sanitize_text(str(spec.get("kind", "note")))
            text = sanitize_text(str(spec.get("text", "")))
            source = sanitize_text(str(spec.get("source", "manual")))
            tags = sorted(sanitize_text(str(t)) for t in spec.get("tags", []) if str(t))
            if not text.strip():
                raise ValueError("event text is required")
            if redaction_block_reason(text):
                raise ValueError("secret_like_event_text_blocked")
            event_id = f"evt_{len(events) + 1:06d}"
            event = {
                "schema": "ithz_mcp_memory_event_v1",
                "event_id": event_id,
                "kind": kind,
                "source": source,
                "tags": tags,
                "text": text,
                "supersedes": spec.get("supersedes"),
            }
            metadata = spec.get("metadata")
            if isinstance(metadata, dict) and metadata:
                event["metadata"] = sanitize_json_value(metadata)
            if git is not None:
                event["git"] = git
            _validate_new_event_payload(event)
            event["semantic_event_hash"] = stable_json_hash(
                {
                    "kind": kind,
                    "source": source,
                    "tags": tags,
                    "text": text,
                        "metadata": sanitize_json_value(metadata) if isinstance(metadata, dict) else None,
                    "git": {
                        k: git.get(k) for k in ("available", "git_branch", "git_commit_hash", "git_commit_subject")
                    } if isinstance(git, dict) else None,
                }
            )
            events.append(event)
            appended.append(event)
        prompt_rows = _load_archive_jsonl_optional(active_root, PROMPT_LOG_PATH, str(exe))
        layers = _derive_layered_indexes(events, prompt_rows)
        index = layers["current_index"]
        synthesis = layers["memory_synthesis"]
        ledger_summary = layers["project_ledger"]["summary"]
        manifest = _load_archive_json(active_root, "manifest.json", str(exe))
        manifest["memory_event_count"] = len(events)
        manifest["current_index_hash"] = index["current_index_hash"]
        manifest["memory_synthesis_hash"] = synthesis["memory_synthesis_hash"]
        manifest["project_ledger_hash"] = ledger_summary["project_ledger_hash"]
        manifest["memory_layers"] = {
            "events": EVENT_LOG_PATH,
            "context_commits": "context-commits/",
            "decisions": DECISION_LOG_PATH,
            "prompts": PROMPT_LOG_PATH,
            "refs": "refs/",
            "branches": "branches/",
            "indexes": "indexes/",
            "memory_synthesis": MEMORY_SYNTHESIS_PATH,
            "claims": "claims/",
            "claim_index": CLAIM_INDEX_PATH,
            "project_ledger": PROJECT_LEDGER_SUMMARY_PATH,
            "replication": "replication/",
            "review": "review/",
            "snapshots": "snapshots/",
            "workflows": "workflows/",
            "instructions": "instructions/",
        }
        if manifest_extra:
            manifest.update(manifest_extra)
        extra_updates_hash = (
            stable_json_hash({path: base64.b64encode(data).decode("ascii") for path, data in sorted(extra_updates.items())})
            if extra_updates
            else None
        )
        manifest["archive_semantic_hash"] = stable_json_hash(
            {
                "previous": manifest.get("archive_semantic_hash"),
                "memory_event_count": len(events),
                "current_index_hash": index["current_index_hash"],
                "memory_synthesis_hash": synthesis["memory_synthesis_hash"],
                "project_ledger_hash": ledger_summary["project_ledger_hash"],
                "extra_updates_hash": extra_updates_hash,
                "manifest_extra": manifest_extra or {},
            }
        )
        updates = _layer_update_bytes(events, prompt_rows, commit_start_index=event_count_before + 1)
        if extra_updates:
            updates.update(extra_updates)
        updates["manifest.json"] = dump_pretty(manifest).encode("utf-8")
        try:
            update = update_archive_files_bytes(active_root, updates, str(exe), "safe", current_hash)
        except RuntimeError as exc:
            last_error = exc
            if "archive hash precondition failed" in str(exc) and attempt == 0 and expected_archive_sha256 is None:
                continue
            raise
        return sanitize_json_value({
            "appended": True,
            "active_memory_zone": active_zone.active_memory_zone,
            "events": appended,
            "appended_count": len(appended),
            "event_count": len(events),
            "current_index_hash": index["current_index_hash"],
            "memory_synthesis_hash": synthesis["memory_synthesis_hash"],
            "project_ledger_hash": ledger_summary["project_ledger_hash"],
            "update": update,
        })
    raise last_error or RuntimeError("archive append failed")


def archive_memory_index_status(project: Path, native_exe: str | None = None, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> dict[str, Any]:
    status = archive_zone_status(project, native_exe, memory_zone, memory_zone_path)
    if not status.get("exists"):
        return {**status, "event_count": 0, "index_valid": False, "snapshot_count": 0}
    active_root = Path(status["project"])
    exe = locate_native_ithz(native_exe)
    events = _memory_events(active_root, str(exe))
    derived = _derive_current_index(events)
    prompt_rows = _load_archive_jsonl_optional(active_root, PROMPT_LOG_PATH, str(exe))
    derived_synthesis = _derive_memory_synthesis(events, prompt_rows)
    derived_ledger = _derive_project_ledger(events)
    stored = _load_archive_json_optional(active_root, CURRENT_INDEX_PATH, {}, str(exe))
    stored_synthesis = _load_archive_json_optional(active_root, MEMORY_SYNTHESIS_PATH, {}, str(exe))
    stored_ledger = _load_archive_json_optional(active_root, PROJECT_LEDGER_SUMMARY_PATH, {}, str(exe))
    snapshots = _snapshot_index(active_root, str(exe)).get("snapshots", [])
    errors = _validate_append_only_events(events)
    ledger_event_kinds = {"claim", "blocked_claim", "replication_pack", "reviewer_note"}
    has_ledger_events = any(str(event.get("kind", "")) in ledger_event_kinds for event in events)
    project_ledger_layer_present = isinstance(stored_ledger, dict) and bool(stored_ledger.get("project_ledger_hash"))
    project_ledger_valid = (
        bool(project_ledger_layer_present)
        and stored_ledger.get("project_ledger_hash") == derived_ledger["summary"]["project_ledger_hash"]
    ) or (not project_ledger_layer_present and not has_ledger_events)
    return {
        **status,
        "event_count": len(events),
        "counts_by_kind": derived["counts_by_kind"],
        "latest_by_kind": derived["latest_by_kind"],
        "derived_current_index_hash": derived["current_index_hash"],
        "stored_current_index_hash": stored.get("current_index_hash") if isinstance(stored, dict) else None,
        "index_valid": isinstance(stored, dict) and stored.get("current_index_hash") == derived["current_index_hash"],
        "derived_memory_synthesis_hash": derived_synthesis["memory_synthesis_hash"],
        "stored_memory_synthesis_hash": stored_synthesis.get("memory_synthesis_hash") if isinstance(stored_synthesis, dict) else None,
        "memory_synthesis_valid": isinstance(stored_synthesis, dict) and stored_synthesis.get("memory_synthesis_hash") == derived_synthesis["memory_synthesis_hash"],
        "derived_project_ledger_hash": derived_ledger["summary"]["project_ledger_hash"],
        "stored_project_ledger_hash": stored_ledger.get("project_ledger_hash") if isinstance(stored_ledger, dict) else None,
        "project_ledger_layer_present": project_ledger_layer_present,
        "project_ledger_valid": project_ledger_valid,
        "claim_count": derived_ledger["summary"]["claim_count"],
        "blocked_claim_count": derived_ledger["summary"]["blocked_claim_count"],
        "replication_pack_count": derived_ledger["summary"]["replication_pack_count"],
        "reviewer_note_count": derived_ledger["summary"]["reviewer_note_count"],
        "current_decision_count": len(derived_synthesis["current_decisions"]),
        "current_claim_count": len(derived_synthesis["current_claims"]),
        "current_blocked_claim_count": len(derived_synthesis["current_blocked_claims"]),
        "current_gate_count": len(derived_synthesis["current_gates"]),
        "current_risk_count": len(derived_synthesis["current_risks"]),
        "current_replication_pack_count": len(derived_synthesis["current_replication_packs"]),
        "latest_reviewer_note_count": len(derived_synthesis["latest_reviewer_notes"]),
        "current_next_step_count": len(derived_synthesis["current_next_steps"]),
        "stale_item_count": len(derived_synthesis["stale_items"]),
        "append_only_valid": not errors,
        "append_only_errors": errors,
        "snapshot_count": len(snapshots),
        "latest_snapshot": snapshots[-1] if snapshots else None,
    }


def archive_rebuild_derived_indexes(project: Path, native_exe: str | None = None, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> dict[str, Any]:
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    if not project_archive_path(active_root).exists():
        raise FileNotFoundError(f"{project_archive_path(active_root)} does not exist")
    exe = locate_native_ithz(native_exe)
    current_hash = sha256_file(project_archive_path(active_root))
    events = _memory_events(active_root, str(exe))
    errors = _validate_append_only_events(events)
    if errors:
        raise ValueError("append_only_event_log_invalid:" + ",".join(errors))
    prompt_rows = _load_archive_jsonl_optional(active_root, PROMPT_LOG_PATH, str(exe))
    layers = _derive_layered_indexes(events, prompt_rows)
    index = layers["current_index"]
    synthesis = layers["memory_synthesis"]
    ledger_summary = layers["project_ledger"]["summary"]
    manifest = _load_archive_json(active_root, "manifest.json", str(exe))
    manifest["memory_event_count"] = len(events)
    manifest["current_index_hash"] = index["current_index_hash"]
    manifest["memory_synthesis_hash"] = synthesis["memory_synthesis_hash"]
    manifest["project_ledger_hash"] = ledger_summary["project_ledger_hash"]
    manifest.setdefault("memory_layers", {})["memory_synthesis"] = MEMORY_SYNTHESIS_PATH
    manifest.setdefault("memory_layers", {})["claims"] = "claims/"
    manifest.setdefault("memory_layers", {})["claim_index"] = CLAIM_INDEX_PATH
    manifest.setdefault("memory_layers", {})["project_ledger"] = PROJECT_LEDGER_SUMMARY_PATH
    manifest.setdefault("memory_layers", {})["replication"] = "replication/"
    manifest.setdefault("memory_layers", {})["review"] = "review/"
    updates = _layer_update_bytes(events, prompt_rows)
    updates["manifest.json"] = dump_pretty(manifest).encode("utf-8")
    update = update_archive_files_bytes(
        active_root,
        updates,
        str(exe),
        "safe",
        current_hash,
    )
    return {
        "rebuilt": True,
        "active_memory_zone": active_zone.active_memory_zone,
        "event_count": len(events),
        "current_index_hash": index["current_index_hash"],
        "memory_synthesis_hash": synthesis["memory_synthesis_hash"],
        "update": update,
    }


def archive_compile_memory_synthesis(project: Path, native_exe: str | None = None, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> dict[str, Any]:
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    if not project_archive_path(active_root).exists():
        raise FileNotFoundError(f"{project_archive_path(active_root)} does not exist")
    exe = locate_native_ithz(native_exe)
    current_hash = sha256_file(project_archive_path(active_root))
    events = _memory_events(active_root, str(exe))
    errors = _validate_append_only_events(events)
    if errors:
        raise ValueError("append_only_event_log_invalid:" + ",".join(errors))
    prompt_rows = _load_archive_jsonl_optional(active_root, PROMPT_LOG_PATH, str(exe))
    synthesis = _derive_memory_synthesis(events, prompt_rows)
    manifest = _load_archive_json(active_root, "manifest.json", str(exe))
    manifest["memory_synthesis_hash"] = synthesis["memory_synthesis_hash"]
    manifest.setdefault("memory_layers", {})["memory_synthesis"] = MEMORY_SYNTHESIS_PATH
    manifest.setdefault("memory_layers", {})["claims"] = "claims/"
    manifest.setdefault("memory_layers", {})["claim_index"] = CLAIM_INDEX_PATH
    manifest.setdefault("memory_layers", {})["project_ledger"] = PROJECT_LEDGER_SUMMARY_PATH
    manifest.setdefault("memory_layers", {})["replication"] = "replication/"
    manifest.setdefault("memory_layers", {})["review"] = "review/"
    manifest["archive_semantic_hash"] = stable_json_hash(
        {"previous": manifest.get("archive_semantic_hash"), "memory_synthesis_hash": synthesis["memory_synthesis_hash"]}
    )
    update = update_archive_files_bytes(
        active_root,
        {
            MEMORY_SYNTHESIS_PATH: dump_pretty(synthesis).encode("utf-8"),
            "manifest.json": dump_pretty(manifest).encode("utf-8"),
        },
        str(exe),
        "safe",
        current_hash,
    )
    return {
        "compiled": True,
        "active_memory_zone": active_zone.active_memory_zone,
        "event_count": len(events),
        "memory_synthesis_hash": synthesis["memory_synthesis_hash"],
        "current_decision_count": len(synthesis["current_decisions"]),
        "current_gate_count": len(synthesis["current_gates"]),
        "current_risk_count": len(synthesis["current_risks"]),
        "current_next_step_count": len(synthesis["current_next_steps"]),
        "stale_item_count": len(synthesis["stale_items"]),
        "update": update,
    }


def _snapshot_auto_max_archive_bytes() -> int:
    raw = os.environ.get("ITHZ_MCP_SNAPSHOT_AUTO_MAX_ARCHIVE_BYTES")
    if not raw:
        return DEFAULT_SNAPSHOT_AUTO_MAX_ARCHIVE_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_SNAPSHOT_AUTO_MAX_ARCHIVE_BYTES


def archive_create_snapshot(
    project: Path,
    label: str = "manual",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
    mode: str = "full",
) -> dict[str, Any]:
    active_zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(active_zone.active_root)
    archive = project_archive_path(active_root)
    if not archive.exists():
        raise FileNotFoundError(f"{archive} does not exist")
    mode = (mode or "full").lower()
    if mode in {"off", "none", "defer"}:
        return {
            "snapshot_created": False,
            "snapshot_deferred": mode == "defer",
            "active_memory_zone": active_zone.active_memory_zone,
            "reason": "snapshot_mode_" + mode,
        }
    if mode == "auto":
        archive_bytes = archive.stat().st_size
        max_bytes = _snapshot_auto_max_archive_bytes()
        if max_bytes and archive_bytes > max_bytes:
            return {
                "snapshot_created": False,
                "snapshot_deferred": True,
                "active_memory_zone": active_zone.active_memory_zone,
                "reason": "large_archive_snapshot_deferred",
                "archive_bytes": archive_bytes,
                "auto_max_archive_bytes": max_bytes,
            }
    elif mode != "full":
        raise ValueError("unsupported_snapshot_mode")
    exe = locate_native_ithz(native_exe)
    current_hash = sha256_file(archive)
    events = _memory_events(active_root, str(exe))
    prompt_rows = _load_archive_jsonl_optional(active_root, PROMPT_LOG_PATH, str(exe))
    layers = _derive_layered_indexes(events, prompt_rows)
    index = layers["current_index"]
    synthesis = layers["memory_synthesis"]
    snapshot_index = _snapshot_index(active_root, str(exe))
    snapshot_id = f"snapshot_{len(snapshot_index.get('snapshots', [])) + 1:06d}"
    snapshot = {
        "schema": "ithz_mcp_memory_snapshot_v1",
        "snapshot_id": snapshot_id,
        "label": label,
        "event_count": len(events),
        "current_index_hash": index["current_index_hash"],
        "memory_synthesis_hash": synthesis["memory_synthesis_hash"],
        "counts_by_kind": index["counts_by_kind"],
        "latest_by_kind": index["latest_by_kind"],
        "snapshot_hash": stable_json_hash({"event_count": len(events), "current_index_hash": index["current_index_hash"], "memory_synthesis_hash": synthesis["memory_synthesis_hash"], "label": label}),
    }
    snapshots = list(snapshot_index.get("snapshots", []))
    snapshots.append({k: snapshot[k] for k in ("snapshot_id", "label", "event_count", "current_index_hash", "memory_synthesis_hash", "snapshot_hash")})
    snapshot_index["snapshots"] = snapshots
    snapshot_index["snapshot_index_hash"] = stable_json_hash({"snapshots": snapshots})
    manifest = _load_archive_json(active_root, "manifest.json", str(exe))
    manifest["snapshot_count"] = len(snapshots)
    manifest["latest_snapshot_id"] = snapshot_id
    manifest["current_index_hash"] = index["current_index_hash"]
    manifest["memory_synthesis_hash"] = synthesis["memory_synthesis_hash"]
    updates = _layer_update_bytes(events, prompt_rows)
    updates.update(
        {
            f"snapshots/{snapshot_id}.json": dump_pretty(snapshot).encode("utf-8"),
            SNAPSHOT_INDEX_PATH: dump_pretty(snapshot_index).encode("utf-8"),
            "manifest.json": dump_pretty(manifest).encode("utf-8"),
        }
    )
    update = update_archive_files_bytes(
        active_root,
        updates,
        str(exe),
        "safe",
        current_hash,
    )
    return {"snapshot_created": True, "active_memory_zone": active_zone.active_memory_zone, "snapshot": snapshot, "snapshot_count": len(snapshots), "update": update}


def _search_memory_index(project: Path, query: str, limit: int, native_exe: str | None = None) -> list[dict[str, Any]]:
    current = _load_archive_json_optional(project, CURRENT_INDEX_PATH, {}, native_exe)
    if not isinstance(current, dict):
        return []
    terms = query_terms(query)
    term_set = set(terms)
    rows = []
    for idx, unit in enumerate(current.get("searchable_units", []), start=1):
        hay = " ".join(
            [
                str(unit.get("kind", "")),
                str(unit.get("source", "")),
                " ".join(str(t) for t in unit.get("tags", [])),
                str(unit.get("git_text", "")),
                str(unit.get("text", "")),
            ]
        ).lower()
        matched_terms = sorted({term for term in terms if term in hay})
        if terms and not matched_terms:
            continue
        score = int(unit.get("weight", 1))
        score += sum(3 for term in matched_terms if term in str(unit.get("text", "")).lower())
        score += sum(2 for term in matched_terms if term in str(unit.get("kind", "")).lower())
        score += sum(1 for term in matched_terms if term in " ".join(str(t).lower() for t in unit.get("tags", [])))
        coverage = (len(matched_terms) / len(terms)) if terms else 0.0
        if len(terms) >= 3 and len(matched_terms) == 1:
            score -= 3
        elif len(terms) >= 3 and len(matched_terms) >= 2:
            score += int(coverage * 8)
        platform_match = False
        if term_set & {"ubuntu", "linux"}:
            platform_match = "ubuntu" in hay or "linux" in hay
        elif term_set & {"windows", "win"}:
            platform_match = "windows" in hay or " win " in f" {hay} "
        if term_set & {"ubuntu", "linux"} and ("windows" in hay or " win " in f" {hay} "):
            score -= 8
        if term_set & {"windows", "win"} and ("ubuntu" in hay or "linux" in hay):
            score -= 8
        rows.append(
            {
                "score": score,
                "path": EVENT_LOG_PATH,
                "line": idx,
                "kind": "memory_" + str(unit.get("kind", "event")),
                "text": str(unit.get("text", "")),
                "event_id": unit.get("event_id"),
                "git": unit.get("git", {}),
                "why_selected": "append_only_memory_index",
                "matched_query_terms": matched_terms,
                "query_term_coverage": round(coverage, 3),
                "platform_match": platform_match,
            }
        )
    rows.sort(key=lambda r: (-int(r["score"]), r["path"], int(r["line"]), str(r.get("event_id", ""))))
    return rows[:limit]


def _load_archive_json(project: Path, archive_inner_path: str, native_exe: str | None = None) -> Any:
    data = extract_archive_file_bytes(project, archive_inner_path, native_exe)
    return sanitize_json_value(json.loads(data.decode("utf-8-sig")))


def load_archive_payload(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    manifest = _load_archive_json(project, "manifest.json", native_exe)
    index = _load_archive_json(project, "index.json", native_exe)
    scan = _load_archive_json(project, "scan.json", native_exe)
    return {"manifest": manifest, "index": index, "scan": scan, "extract_mode": "stdout_memory"}


def load_archive_manifest(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    return _load_archive_json(project, "manifest.json", native_exe)


def load_archive_source_search_index(project: Path, native_exe: str | None = None) -> dict[str, Any]:
    try:
        return _load_archive_json(project, SOURCE_SEARCH_INDEX_PATH, native_exe)
    except RuntimeError as exc:
        if "path not found" in str(exc):
            return _load_archive_json(project, "index.json", native_exe)
        raise


def native_archive_status(project: Path, native_exe: str | None = None, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> dict[str, Any]:
    zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    project = Path(zone.active_root)
    archive = project_archive_path(project)
    selection = select_native_ithz(native_exe)
    exe = Path(selection.path)
    version = native_version_info(exe)
    if not archive.exists():
        return {
            "project": str(project),
            "requested_project": zone.requested_project,
            "active_memory_zone": zone.active_memory_zone,
            "memory_zone": asdict(zone),
            "archive": str(archive),
            "exists": False,
            "native_exe": str(exe),
            "native_selection": asdict(selection),
            "native_selected_build": selection.selected_build,
            "native_selection_reason": selection.reason,
            "native_cpu_avx2_supported": selection.cpu_avx2_supported,
            "native_version": version,
        }
    result = _run_native(["--verify", str(archive), "--verify=safe"], exe)
    manifest = load_archive_manifest(project, str(exe))
    return {
        "project": str(project),
        "requested_project": zone.requested_project,
        "active_memory_zone": zone.active_memory_zone,
        "memory_zone": asdict(zone),
        "archive": str(archive),
        "exists": True,
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": sha256_file(archive),
        "native_exe": str(exe),
        "native_selection": asdict(selection),
        "native_selected_build": selection.selected_build,
        "native_selection_reason": selection.reason,
        "native_cpu_avx2_supported": selection.cpu_avx2_supported,
        "native_version": version,
        "safe_verify_ok": result.returncode == 0,
        "schema": manifest.get("schema"),
        "index_mode": manifest.get("index_mode", "legacy-full"),
        "project_semantic_hash": manifest.get("project_semantic_hash"),
        "archive_semantic_hash": manifest.get("archive_semantic_hash"),
        "memory_synthesis_hash": manifest.get("memory_synthesis_hash"),
        "source_file_count": manifest.get("source_file_count"),
        "source_snapshot_included": manifest.get("source_snapshot_included", False),
        "prompt_record_count": manifest.get("prompt_record_count"),
    }


def native_archive_search(project: Path, query: str, limit: int = 10, native_exe: str | None = None, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> dict[str, Any]:
    zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    project = Path(zone.active_root)
    manifest = load_archive_manifest(project, native_exe)
    source_index = load_archive_source_search_index(project, native_exe)
    candidate_limit = max(limit, 40)
    rows = search_index(source_index, query, candidate_limit)
    rows.extend(_search_memory_index(project, query, candidate_limit, native_exe))
    platform_query = bool(set(query_terms(query)) & {"ubuntu", "linux", "windows", "win"})

    def platform_rank(row: dict[str, Any]) -> int:
        return 0 if (not platform_query or row.get("platform_match")) else 1

    if "file_navigation" in query_intents(query):
        rows.sort(
            key=lambda r: (
                platform_rank(r),
                -int(r.get("score", 0)),
                -float(r.get("query_term_coverage", 0.0)),
                r.get("path", ""),
                int(r.get("line", 0)),
                r.get("text", ""),
            )
        )
    else:
        rows.sort(
            key=lambda r: (
                platform_rank(r),
                -float(r.get("query_term_coverage", 0.0)),
                -int(r.get("score", 0)),
                r.get("path", ""),
                int(r.get("line", 0)),
                r.get("text", ""),
            )
        )
    rows = rows[:limit]
    return {
        "requested_project": zone.requested_project,
        "active_memory_zone": zone.active_memory_zone,
        "query": query,
        "rows": rows,
        "index_hash": source_index.get("index_hash") or source_index.get("source_search_index_hash"),
        "archive_semantic_hash": manifest.get("archive_semantic_hash"),
    }


CURRENT_PROJECTION_SECTIONS = (
    "current_decisions",
    "current_claims",
    "current_blocked_claims",
    "current_gates",
    "current_risks",
    "must_not_break",
    "forbidden_claims",
    "current_next_steps",
)


def native_archive_current_projection(
    project: Path,
    query: str = "",
    max_items_per_section: int = 4,
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
) -> dict[str, Any]:
    """Return a compact current-state view that excludes stale and superseded history."""
    if not 1 <= int(max_items_per_section) <= 20:
        raise ValueError("max_items_per_section_out_of_range")
    zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    active_root = Path(zone.active_root)
    # A persisted projection cannot decide current validity or signer revocation.
    synthesis = _derive_memory_synthesis(_memory_events(active_root, native_exe))
    terms = [term for term in query_terms(query) if term not in {"checkpoint", "type"}]

    def compact(item: dict[str, Any]) -> dict[str, Any]:
        text = str(item.get("text", ""))
        return {
            key: value
            for key, value in {
                "event_id": item.get("event_id"),
                "kind": item.get("kind"),
                "source": item.get("source"),
                "tags": item.get("tags", []),
                "text": text[:600],
                "why_current": item.get("why_current"),
                "semantic_event_hash": item.get("semantic_event_hash"),
                "verification_state": item.get("verification_state", "legacy_unverified_abstraction"),
            }.items()
            if value not in (None, "", [])
        }

    def relevant(item: dict[str, Any]) -> bool:
        if not terms:
            return True
        blob = " ".join(
            [
                str(item.get("kind", "")),
                str(item.get("source", "")),
                " ".join(str(tag) for tag in item.get("tags", [])),
                str(item.get("text", "")),
            ]
        ).lower()
        return any(term in blob for term in terms)

    sections: dict[str, list[dict[str, Any]]] = {}
    for name in CURRENT_PROJECTION_SECTIONS:
        raw = synthesis.get(name, [])
        items = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
        matched = [item for item in items if relevant(item)]
        # Safety boundaries are always carried even when the task vocabulary differs.
        selected = matched or (items if name in {"must_not_break", "forbidden_claims", "current_gates", "current_risks"} else [])
        sections[name] = [compact(item) for item in selected[: int(max_items_per_section)]]
    body = {
        "schema": "ithz_current_projection_v1",
        "active_memory_zone": zone.active_memory_zone,
        "query_terms": terms[:24],
        "memory_synthesis_hash": synthesis.get("memory_synthesis_hash"),
        "sections": sections,
        "stale_history_excluded": True,
        "supersession_applied": True,
    }
    body["projection_hash"] = stable_json_hash(body)
    return body


def native_archive_context_pack(project: Path, query: str, max_bytes: int = 20000, native_exe: str | None = None, memory_zone: str = "nearest", memory_zone_path: str | None = None) -> dict[str, Any]:
    zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    project = Path(zone.active_root)
    manifest = load_archive_manifest(project, native_exe)
    source_index = load_archive_source_search_index(project, native_exe)
    synthesis = _derive_memory_synthesis(_memory_events(project, native_exe))
    rows = native_archive_search(project, query, 30, native_exe, "current")["rows"]
    context_pack_query_stopwords = {"checkpoint", "type"}
    terms = [term for term in query_terms(query) if term not in context_pack_query_stopwords]
    intents = query_intents(query)
    file_navigation_query = "file_navigation" in intents
    broad_query_terms = {"current", "status", "task", "handoff", "next", "workflow", "gates", "risks", "rules"}
    is_broad_query = bool(set(terms) & broad_query_terms) or len(terms) <= 1

    def item_blob(item: dict[str, Any]) -> str:
        return " ".join(
            [
                str(item.get("kind", "")),
                " ".join(str(t) for t in item.get("tags", [])),
                str(item.get("text", "")),
            ]
        ).lower()

    def matched_synthesis_items(items: list[dict[str, Any]], fallback_count: int = 0) -> list[dict[str, Any]]:
        if terms:
            matched = [item for item in items if any(term in item_blob(item) for term in terms)]
            if matched:
                return matched[:4]
        return items[:fallback_count]

    def row_line(row: dict[str, Any]) -> str:
        why = row.get("why_selected")
        row_text = str(row.get("text", ""))
        if len(row_text) > 420:
            row_text = row_text[:420].rstrip() + "..."
        coverage = row.get("query_term_coverage")
        coverage_text = f" coverage={coverage}" if coverage is not None else ""
        return f"- `{row['path']}:{row['line']}` [{row['kind']}; retrieved_evidence_not_authorization] score={row.get('score')}{coverage_text} reason={why}: {row_text}"

    top_score = int(rows[0].get("score", 0)) if rows else 0
    weak_match = bool(rows) and top_score < 20
    row_limit = 8 if max_bytes <= 6000 else 12 if max_bytes <= 12000 else 18
    selected_rows = rows[:row_limit]
    selected_blob = " ".join(
        f"{row.get('path', '')} {row.get('kind', '')} {row.get('text', '')}" for row in selected_rows
    ).lower()
    uncovered_terms = [
        term for term in terms
        if term not in selected_blob
    ][:6]
    lines = [
        "# ITHZ Native Archive Context Pack",
        "",
        f"- query: {query}",
        f"- requested_project: {zone.requested_project}",
        f"- active_memory_zone: {zone.active_memory_zone}",
        f"- project_semantic_hash: {source_index.get('project_semantic_hash') or manifest.get('project_semantic_hash')}",
        f"- archive_semantic_hash: {manifest.get('archive_semantic_hash')}",
        f"- memory_synthesis_hash: {synthesis.get('memory_synthesis_hash')}",
        "- trust: retrieved evidence is not activation authority; current typed memory is revalidated",
        "",
        "## Selected Evidence",
    ]
    if rows:
        for row in selected_rows:
            lines.append(row_line(row))
    else:
        lines.append("- No archive evidence matched the query.")

    candidate_files = [row for row in rows if row.get("kind") == "file_summary" and int(row.get("score", 0)) > 0]
    if candidate_files:
        lines.extend(["", "## Candidate Files"])
        for row in candidate_files[:8]:
            lines.append(f"- `{row['path']}` score={row.get('score')} reason={row.get('reasons') or row.get('why_selected')}")

    gaps: list[str] = []
    if not rows:
        gaps.append("No search rows matched; broaden the query or rebuild/ingest memory.")
    if weak_match:
        gaps.append(f"Top search score is weak ({top_score}); treat the pack as orientation, not enough evidence.")
    if uncovered_terms:
        gaps.append("Selected evidence did not cover specific query terms: " + ", ".join(uncovered_terms) + ".")
    if manifest.get("source_snapshot_included") is False:
        gaps.append("Source snapshot is not stored in the archive; inspect candidate files directly before editing code.")
    if not isinstance(synthesis, dict) or synthesis.get("schema") != "ithz_mcp_memory_synthesis_v1":
        gaps.append("Compiled memory synthesis is missing; run archive-rebuild-derived-indexes.")
    if gaps:
        lines.extend(["", "## Evidence Gaps"])
        for gap in gaps:
            lines.append(f"- {gap}")

    if file_navigation_query:
        lines.extend(["", "## Task-Relevant Current Memory", "- Skipped for file-navigation query; selected evidence and candidate files are the primary signal."])
    elif isinstance(synthesis, dict) and synthesis.get("schema") == "ithz_mcp_memory_synthesis_v1":
        lines.extend(["", "## Task-Relevant Current Memory"])
        synthesis_sections = [
            ("Current next steps", "current_next_steps"),
            ("Relevant decisions", "current_decisions"),
            ("Relevant gates", "current_gates"),
            ("Known risks / must not break", "current_risks"),
            ("Forbidden claims", "forbidden_claims"),
            ("Blocked claims", "current_blocked_claims"),
            ("Allowed / scoped claims", "current_claims"),
            ("Replication packs", "current_replication_packs"),
            ("Reviewer notes", "latest_reviewer_notes"),
            ("Stale / superseded memory", "stale_items"),
        ]
        any_synthesis = False
        for title, key in synthesis_sections:
            items = list(synthesis.get(key, []) or [])
            fallback = 2 if is_broad_query and key in {"current_next_steps", "current_decisions", "current_gates", "current_risks", "forbidden_claims"} else 0
            items = matched_synthesis_items(items, fallback)
            if not items:
                continue
            any_synthesis = True
            lines.append(f"### {title}")
            for item in items:
                lines.append(f"- `{item.get('event_id')}` [{item.get('kind')}; {item.get('verification_state', 'legacy_unverified_abstraction')}] {item.get('text')} ({item.get('why_current')})")
        if not any_synthesis:
            lines.append("- No query-matched current-memory items. Selected evidence above is the primary signal.")
    else:
        lines.extend(["", "## Task-Relevant Current Memory"])
        lines.append("- No compiled memory synthesis layer found; run `archive-rebuild-derived-indexes` or `archive-compile-memory-synthesis`.")
    text = sanitize_text("\n".join(lines) + "\n")
    if len(text.encode("utf-8")) > max_bytes:
        marker = "\n\n[truncated deterministically]\n"
        marker_bytes = marker.encode("utf-8")
        budget = max(0, max_bytes - len(marker_bytes))
        encoded = text.encode("utf-8")[:budget]
        text = encoded.decode("utf-8", errors="ignore") + marker
    return {
        "text": text,
        "bytes": len(text.encode("utf-8")),
        "active_memory_zone": zone.active_memory_zone,
        "context_pack_hash": stable_json_hash({"query": query, "text": text, "archive_semantic_hash": manifest.get("archive_semantic_hash")}),
    }


def native_archive_record_prompt_response(
    project: Path,
    prompt_file: Path,
    response_file: Path,
    task: str,
    mode: str = "summary",
    native_exe: str | None = None,
    memory_zone: str = "nearest",
    memory_zone_path: str | None = None,
) -> dict[str, Any]:
    if mode == "off":
        return {"recorded": False, "mode": mode, "reason": "prompt_memory_off"}
    if mode not in {"summary", "full-redacted", "full-local-only"}:
        raise ValueError("unsupported_prompt_memory_mode")
    zone = resolve_memory_zone(project, memory_zone, memory_zone_path)
    project = Path(zone.active_root)
    exe = locate_native_ithz(native_exe)
    if not project_archive_path(project).exists():
        build_native_archive(project, str(exe))
    prompt_text = sanitize_text(prompt_file.read_text(encoding="utf-8", errors="replace"))
    response_text = sanitize_text(response_file.read_text(encoding="utf-8", errors="replace"))
    task = sanitize_text(task)
    prompt_redaction = redact_text(prompt_text)
    response_redaction = redact_text(response_text)
    local_only = mode == "full-local-only"
    if local_only and (prompt_redaction["redacted"] or response_redaction["redacted"]):
        raise ValueError("local_only_prompt_memory_secret_like_content_blocked")
    archive_sha256_before = sha256_file(project_archive_path(project))
    try:
        prompt_log_bytes = extract_archive_file_bytes(project, PROMPT_LOG_PATH, str(exe))
        rows = [sanitize_json_value(json.loads(line)) for line in prompt_log_bytes.decode("utf-8-sig").splitlines() if line.strip()]
    except RuntimeError as exc:
        if "path not found" not in str(exc):
            raise
        rows = []
    record_id = f"pr_{len(rows) + 1:06d}"
    prompt_id = f"prompt_{record_id[3:]}"
    response_id = f"response_{record_id[3:]}"
    prompt_summary = _summarize_text(prompt_redaction["text"], "prompt")
    response_summary = _summarize_text(response_redaction["text"], "response")
    record = {
        "schema": "ithz_prompt_memory_record_v1",
        "record_id": record_id,
        "prompt_id": prompt_id,
        "response_id": response_id,
        "task": task,
        "mode": mode,
        "local_only": local_only,
        "prompt_hash": stable_json_hash({"prompt": prompt_text}),
        "response_hash": stable_json_hash({"response": response_text}),
        "semantic_prompt_hash": stable_json_hash({"task": task, "mode": mode, "prompt_summary": prompt_summary, "response_summary": response_summary}),
        "prompt_summary": prompt_summary,
        "response_summary": response_summary,
        "redaction_status": redaction_status(prompt_redaction, response_redaction),
        "redaction_hits": sorted(set(prompt_redaction["hits"] + response_redaction["hits"])),
        "team_sync_allowed": not local_only,
    }
    rows.append(record)
    events = _memory_events(project, str(exe))
    layer_updates = _layer_update_bytes(events, rows)
    synthesis = _derive_memory_synthesis(events, rows)
    manifest = _load_archive_json(project, "manifest.json", str(exe))
    manifest["prompt_record_count"] = len(rows)
    manifest["prompt_summary_index_hash"] = _derive_prompt_summary_index(rows)["prompt_summary_index_hash"]
    manifest["memory_synthesis_hash"] = synthesis["memory_synthesis_hash"]
    manifest["project_ledger_hash"] = layer_updates.get(PROJECT_LEDGER_SUMMARY_PATH) and json.loads(layer_updates[PROJECT_LEDGER_SUMMARY_PATH].decode("utf-8")).get("project_ledger_hash")
    manifest.setdefault("memory_layers", {})["memory_synthesis"] = MEMORY_SYNTHESIS_PATH
    manifest.setdefault("memory_layers", {})["claims"] = "claims/"
    manifest.setdefault("memory_layers", {})["claim_index"] = CLAIM_INDEX_PATH
    manifest.setdefault("memory_layers", {})["project_ledger"] = PROJECT_LEDGER_SUMMARY_PATH
    manifest.setdefault("memory_layers", {})["replication"] = "replication/"
    manifest.setdefault("memory_layers", {})["review"] = "review/"
    manifest["archive_semantic_hash"] = stable_json_hash({"previous": manifest.get("archive_semantic_hash"), "prompt_rows": rows, "memory_synthesis_hash": synthesis["memory_synthesis_hash"]})
    layer_updates["manifest.json"] = dump_pretty(manifest).encode("utf-8")
    layer_updates[PROMPT_LOG_PATH] = _jsonl_bytes(rows)
    batch_update = update_archive_files_bytes(
        project,
        layer_updates,
        str(exe),
        "safe",
        archive_sha256_before,
    )
    archive = native_archive_status(project, str(exe))
    return {"record": record, "archive": archive, "updates": [batch_update], "update_mode": "native_memory_update_files_batch", "active_memory_zone": zone.active_memory_zone}


def write_mcp13_outputs(project: Path, rows: list[dict[str, Any]], summary: str) -> None:
    out = project / "experiments" / "mcp13_native_archive"
    out.mkdir(parents=True, exist_ok=True)
    matrix = out / "mcp13_native_archive_matrix.csv"
    if rows:
        with matrix.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=sorted({k for row in rows for k in row}))
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
    (out / "mcp13_summary.md").write_text(summary, encoding="utf-8", newline="\n")
