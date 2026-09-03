import hashlib
from pathlib import Path
from typing import Any, Iterable

from .canonical_json import dumps, sanitize_text


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(sanitize_text(text).encode("utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stable_json_hash(value: Any) -> str:
    return sha256_text(dumps(value))


def hash_lines(lines: Iterable[str]) -> str:
    h = hashlib.sha256()
    for line in lines:
        h.update(sanitize_text(line).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()

