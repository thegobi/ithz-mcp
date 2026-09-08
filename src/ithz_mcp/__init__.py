from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


VERSION = "0.1.0a16"
BUILD_ID = "public-mcp36.6-end-to-end-integrity.20260908.1"
PACKAGE_NAME = "ithz-mcp"
PACKAGE_FILENAME = "ithz_mcp-0.1.0a16-py3-none-any.whl"
PRODUCT = "ITHZ-MCP / ITHZ ContextDB"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git_commit(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short=12", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _git_dirty(root: Path) -> bool | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--", str(root)],
            text=True,
            capture_output=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())


def version_info() -> dict[str, Any]:
    root = _repo_root()
    info: dict[str, Any] = {
        "product": PRODUCT,
        "version": VERSION,
        "build_id": BUILD_ID,
        "package_name": PACKAGE_NAME,
        "package_filename": PACKAGE_FILENAME,
        "mode": "local-first",
        "claims": ["not_git_replacement", "not_production_database", "not_cloud_sync"],
    }
    manifest = root / "VERSION.json"
    if manifest.exists():
        try:
            loaded = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                info.update(loaded)
        except json.JSONDecodeError:
            info["version_manifest_error"] = "invalid_json"
    commit = info.get("source_git_commit") or _git_commit(root)
    if commit:
        info["source_git_commit"] = commit
    dirty = _git_dirty(root)
    if dirty is not None:
        info["source_tree_dirty"] = dirty
    return info
