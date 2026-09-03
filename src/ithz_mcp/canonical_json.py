import json
import re
from typing import Any

_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


def sanitize_text(value: str) -> str:
    """Return text that can always be encoded as valid UTF-8."""
    if not isinstance(value, str):
        return value
    if not _SURROGATE_RE.search(value):
        return value
    return _SURROGATE_RE.sub("\uFFFD", value)


def sanitize_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_json_value(item) for item in value]
    if isinstance(value, dict):
        clean: dict[Any, Any] = {}
        for key, item in value.items():
            clean_key = sanitize_text(key) if isinstance(key, str) else key
            clean[clean_key] = sanitize_json_value(item)
        return clean
    return value


def dumps(value: Any) -> str:
    return json.dumps(sanitize_json_value(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def dump_pretty(value: Any) -> str:
    return json.dumps(sanitize_json_value(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def load_text(text: str) -> Any:
    return json.loads(text)

