from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

SECRET_NAME_PATTERNS = (
    ".env",
    "*.key",
    "*.pem",
    "secrets*",
    "secret*",
    "credentials*",
    "credential*",
    "token*",
)

IGNORED_DIRS = {
    ".git",
    ".ithz-install",
    ".ithz_mcp",
    ".ithz-context",
    ".antigravity",
    ".claude",
    ".cursor",
    ".mempalace-capture",
    ".mempalace-pilot",
    ".mempalace-seed",
    ".vscode",
    ".idea",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".cache",
    "cache",
    "tmp",
    "backup",
    "backups",
    "zaloha",
}

IGNORED_PREFIXES = (".ithz/cache", ".ithz/tmp")
IGNORED_FILE_NAMES = {".mcp.json", "mcp.json"}
MAX_DEFAULT_FILE_BYTES = 2 * 1024 * 1024
WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def normalize_rel(path: Path | str) -> str:
    rel = str(PurePosixPath(str(path).replace("\\", "/")))
    while rel.startswith("./"):
        rel = rel[2:]
    return rel


def is_secret_like(rel_path: str) -> bool:
    rel = normalize_rel(rel_path)
    name = PurePosixPath(rel).name.lower()
    lowered = rel.lower()
    if name in {".env"}:
        return True
    for suffix in (".key", ".pem"):
        if name.endswith(suffix):
            return True
    return any(token in lowered for token in ("secret", "credential", "private_key", "api_key", "token"))


def ignore_reason(rel_path: str, size: int | None = None) -> str | None:
    rel = normalize_rel(rel_path)
    parts = [p.lower() for p in PurePosixPath(rel).parts]
    if PurePosixPath(rel).name.lower() in IGNORED_FILE_NAMES:
        return "ignored_local_host_config"
    if any(part in IGNORED_DIRS for part in parts):
        return "ignored_directory"
    if any(rel.lower().startswith(prefix) for prefix in IGNORED_PREFIXES):
        return "ignored_ithz_cache"
    if is_secret_like(rel):
        return "secret_like_path"
    if size is not None and size > MAX_DEFAULT_FILE_BYTES:
        return "large_file_default_ignore"
    return None


def looks_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    if not data:
        return False
    non_text = sum(1 for b in data if b < 9 or (13 < b < 32))
    return non_text / max(1, len(data)) > 0.20


def safe_output_path(root: Path, rel_path: str) -> Path:
    validate_archive_path(rel_path)
    root_resolved = root.resolve()
    out = (root_resolved / Path(rel_path.replace("/", "\\"))).resolve()
    if root_resolved != out and root_resolved not in out.parents:
        raise ValueError("path escapes output root")
    return out


def validate_archive_path(rel_path: str) -> None:
    if "\\" in rel_path:
        raise ValueError("backslash paths are not allowed")
    if rel_path.startswith("/") or re.match(r"^[A-Za-z]:", rel_path):
        raise ValueError("absolute paths are not allowed")
    pp = PurePosixPath(rel_path)
    if any(part in ("..", "") for part in pp.parts):
        raise ValueError("path traversal is not allowed")
    if len(rel_path) > 240:
        raise ValueError("path is too long")
    for part in pp.parts:
        lowered = part.lower().rstrip(" .")
        if lowered in WINDOWS_RESERVED:
            raise ValueError("windows reserved path segment")
        if part.endswith(".") or part.endswith(" "):
            raise ValueError("trailing dot or space is not allowed")


def redaction_block_reason(text: str) -> str | None:
    lowered = text.lower()
    if any(token in lowered for token in (".env", "-----begin", "api_key", "private_key")):
        return "secret_like_content"
    if re.search(r"\b(?!secret_like[_-])[a-z0-9_-]*(?:secret|credential)[a-z0-9_-]*\s*[:=]\s*\S+", lowered):
        return "secret_like_content"
    if re.search(r"(password|passwd|pwd|token|access_token|refresh_token|bearer)\s*[:=]\s*\S+", lowered):
        return "secret_like_content"
    if re.search(r"\b[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b", text):
        return "secret_like_content"
    if re.search(r"\b(?:sk|pk|ghp|github_pat|xox[baprs])-?[A-Za-z0-9_=-]{20,}\b", text, re.I):
        return "secret_like_content"
    return None
