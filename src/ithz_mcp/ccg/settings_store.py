from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import urllib.error
import urllib.request
from ctypes import wintypes
from pathlib import Path
from time import monotonic
from typing import Any

from ..canonical_json import dump_pretty


SETTINGS_SCHEMA = "ccg_ithz_user_settings_v2"
LEGACY_SETTINGS_SCHEMA = "ccg_ithz_user_settings_v1"
SECRETS_SCHEMA = "ccg_ithz_user_secrets_v2"
LEGACY_SECRETS_SCHEMA = "ccg_ithz_user_secrets_v1"
DEFAULTS: dict[str, Any] = {
    "codex_model": "gpt-5.6-luna",
    "codex_effort": "low",
    "codex_timeout": 240,
    "grok_model": "grok-4.20-reasoning-latest",
    "grok_effort": "low",
    "gemini_model": "gemini-3.7-flash",
    "gemini_thinking_level": "low",
    "opponent_2_provider": "gemini",
    "daybreak_model": "gpt-daybreak-blue-latest",
    "daybreak_effort": "low",
    "daybreak_policy": "high_and_critical",
}
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,99}$")
XAI_KEY_RE = re.compile(r"^xai-[A-Za-z0-9_-]{20,}$")
GEMINI_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{20,256}$")
DPAPI_ENTROPY = b"ITHZ-CCG-MCP-user-secret-v1"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def settings_root() -> Path:
    override = os.getenv("CCG_SETTINGS_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        base = Path(os.getenv("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config")
    return (base / "ITHZ" / "ccg-mcp").resolve()


def preferences_path() -> Path:
    return settings_root() / "settings.json"


def secrets_path() -> Path:
    return settings_root() / "secrets.dpapi.json"


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(dump_pretty(value), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, path)


def _validated_preferences(value: dict[str, Any]) -> dict[str, Any]:
    model = str(value.get("codex_model", DEFAULTS["codex_model"])).strip()
    grok_model = str(value.get("grok_model", DEFAULTS["grok_model"])).strip()
    gemini_model = str(value.get("gemini_model", DEFAULTS["gemini_model"])).strip()
    daybreak_model = str(value.get("daybreak_model", DEFAULTS["daybreak_model"])).strip()
    effort = str(value.get("codex_effort", DEFAULTS["codex_effort"])).strip().lower()
    grok_effort = str(value.get("grok_effort", DEFAULTS["grok_effort"])).strip().lower()
    gemini_thinking_level = str(
        value.get("gemini_thinking_level", DEFAULTS["gemini_thinking_level"])
    ).strip().lower()
    opponent_2_provider = str(
        value.get("opponent_2_provider", DEFAULTS["opponent_2_provider"])
    ).strip().lower()
    daybreak_effort = str(value.get("daybreak_effort", DEFAULTS["daybreak_effort"])).strip().lower()
    daybreak_policy = str(value.get("daybreak_policy", DEFAULTS["daybreak_policy"])).strip().lower()
    try:
        timeout = int(value.get("codex_timeout", DEFAULTS["codex_timeout"]))
    except (TypeError, ValueError) as exc:
        raise ValueError("codex_timeout_must_be_integer") from exc
    if not MODEL_RE.fullmatch(model):
        raise ValueError("invalid_codex_model")
    if not MODEL_RE.fullmatch(grok_model):
        raise ValueError("invalid_grok_model")
    if not MODEL_RE.fullmatch(gemini_model):
        raise ValueError("invalid_gemini_model")
    if not MODEL_RE.fullmatch(daybreak_model):
        raise ValueError("invalid_daybreak_model")
    if effort not in {"low", "medium", "high", "xhigh"}:
        raise ValueError("invalid_codex_effort")
    if grok_effort not in {"none", "low", "medium", "high"}:
        raise ValueError("invalid_grok_effort")
    if gemini_thinking_level not in {"low", "medium", "high"}:
        raise ValueError("invalid_gemini_thinking_level")
    if opponent_2_provider not in {"gemini", "grok"}:
        raise ValueError("invalid_opponent_2_provider")
    if daybreak_effort not in {"low", "medium", "high", "xhigh"}:
        raise ValueError("invalid_daybreak_effort")
    if daybreak_policy not in {"off", "high_and_critical", "always"}:
        raise ValueError("invalid_daybreak_policy")
    if not 30 <= timeout <= 1800:
        raise ValueError("codex_timeout_out_of_range")
    return {
        "codex_model": model,
        "codex_effort": effort,
        "codex_timeout": timeout,
        "grok_model": grok_model,
        "grok_effort": grok_effort,
        "gemini_model": gemini_model,
        "gemini_thinking_level": gemini_thinking_level,
        "opponent_2_provider": opponent_2_provider,
        "daybreak_model": daybreak_model,
        "daybreak_effort": daybreak_effort,
        "daybreak_policy": daybreak_policy,
    }


def stored_preferences() -> dict[str, Any]:
    path = preferences_path()
    if not path.exists():
        return dict(DEFAULTS)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") not in {SETTINGS_SCHEMA, LEGACY_SETTINGS_SCHEMA}:
            raise ValueError("unsupported_settings_schema")
        return _validated_preferences(value)
    except (OSError, json.JSONDecodeError, ValueError):
        return dict(DEFAULTS)


def save_preferences(value: dict[str, Any]) -> dict[str, Any]:
    merged = {**stored_preferences(), **value}
    clean = _validated_preferences(merged)
    _atomic_json(preferences_path(), {"schema": SETTINGS_SCHEMA, **clean})
    return clean


def effective_preferences() -> dict[str, Any]:
    stored = stored_preferences()
    overrides = {
        "codex_model": os.getenv("CCG_CODEX_MODEL", "").strip() or stored["codex_model"],
        "codex_effort": os.getenv("CCG_CODEX_EFFORT", "").strip() or stored["codex_effort"],
        "codex_timeout": os.getenv("CCG_CODEX_TIMEOUT", "").strip() or stored["codex_timeout"],
        "grok_model": os.getenv("CCG_GROK_MODEL", "").strip() or stored["grok_model"],
        "grok_effort": os.getenv("CCG_GROK_EFFORT", "").strip() or stored["grok_effort"],
        "gemini_model": os.getenv("CCG_GEMINI_MODEL", "").strip() or stored["gemini_model"],
        "gemini_thinking_level": os.getenv("CCG_GEMINI_THINKING_LEVEL", "").strip()
        or stored["gemini_thinking_level"],
        "opponent_2_provider": os.getenv("CCG_OPPONENT_2_PROVIDER", "").strip()
        or stored["opponent_2_provider"],
        "daybreak_model": os.getenv("CCG_DAYBREAK_MODEL", "").strip() or stored["daybreak_model"],
        "daybreak_effort": os.getenv("CCG_DAYBREAK_EFFORT", "").strip() or stored["daybreak_effort"],
        "daybreak_policy": os.getenv("CCG_DAYBREAK_POLICY", "").strip() or stored["daybreak_policy"],
    }
    return _validated_preferences(overrides)


def _blob(value: bytes) -> tuple[_DataBlob, Any]:
    buffer = ctypes.create_string_buffer(value)
    pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    return _DataBlob(len(value), pointer), buffer


def _dpapi_protect(value: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("secure_persistence_unavailable_on_this_platform")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    source, source_buffer = _blob(value)
    entropy, entropy_buffer = _blob(DPAPI_ENTROPY)
    protected = _DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(source),
        "ITHZ CCG xAI API key",
        ctypes.byref(entropy),
        None,
        None,
        0x1,
        ctypes.byref(protected),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(protected.pbData, protected.cbData)
    finally:
        kernel32.LocalFree(protected.pbData)


def _dpapi_unprotect(value: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("secure_persistence_unavailable_on_this_platform")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    source, source_buffer = _blob(value)
    entropy, entropy_buffer = _blob(DPAPI_ENTROPY)
    plain = _DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        ctypes.byref(entropy),
        None,
        None,
        0x1,
        ctypes.byref(plain),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(plain.pbData, plain.cbData)
    finally:
        kernel32.LocalFree(plain.pbData)


def _read_persisted_secrets() -> tuple[dict[str, str], str]:
    path = secrets_path()
    if not path.exists():
        return {}, ""
    if os.name != "nt":
        return {}, "unsupported_platform"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") not in {SECRETS_SCHEMA, LEGACY_SECRETS_SCHEMA}:
            raise ValueError("unsupported_secrets_schema")
        result: dict[str, str] = {}
        for field, pattern in (("xai_key", XAI_KEY_RE), ("gemini_key", GEMINI_KEY_RE)):
            encoded = value.get(field)
            if not isinstance(encoded, str) or not encoded:
                continue
            protected = base64.b64decode(encoded, validate=True)
            plain = _dpapi_unprotect(protected).decode("utf-8")
            if not pattern.fullmatch(plain):
                raise ValueError(f"invalid_decrypted_{field}")
            result[field] = plain
        return result, ""
    except (OSError, KeyError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return {}, f"secret_read_failed:{type(exc).__name__}"


def _write_persisted_secrets(values: dict[str, str]) -> None:
    if not values:
        try:
            secrets_path().unlink()
        except FileNotFoundError:
            pass
        return
    payload: dict[str, Any] = {
        "schema": SECRETS_SCHEMA,
        "protection": "windows-dpapi-current-user",
    }
    for field, value in values.items():
        payload[field] = base64.b64encode(_dpapi_protect(value.encode("utf-8"))).decode("ascii")
    _atomic_json(secrets_path(), payload)


def save_xai_key(key: str) -> dict[str, Any]:
    clean = key.strip()
    if not XAI_KEY_RE.fullmatch(clean):
        raise ValueError("invalid_xai_api_key_format")
    values, error = _read_persisted_secrets()
    if error:
        raise RuntimeError(error)
    values["xai_key"] = clean
    _write_persisted_secrets(values)
    return secret_status()


def save_gemini_key(key: str) -> dict[str, Any]:
    clean = key.strip()
    if not GEMINI_KEY_RE.fullmatch(clean):
        raise ValueError("invalid_gemini_api_key_format")
    values, error = _read_persisted_secrets()
    if error:
        raise RuntimeError(error)
    values["gemini_key"] = clean
    _write_persisted_secrets(values)
    return gemini_secret_status()


def _delete_persisted_key(field: str) -> None:
    values, error = _read_persisted_secrets()
    if error:
        raise RuntimeError(error)
    values.pop(field, None)
    _write_persisted_secrets(values)


def delete_xai_key() -> dict[str, Any]:
    _delete_persisted_key("xai_key")
    return secret_status()


def delete_gemini_key() -> dict[str, Any]:
    _delete_persisted_key("gemini_key")
    return gemini_secret_status()


def resolve_xai_key() -> dict[str, Any]:
    environment = os.getenv("XAI_API_KEY", "").strip()
    if environment:
        if XAI_KEY_RE.fullmatch(environment):
            return {"value": environment, "configured": True, "source": "environment", "error": ""}
        return {"value": "", "configured": False, "source": "environment", "error": "invalid_environment_key"}
    values, error = _read_persisted_secrets()
    if error:
        return {"value": "", "configured": False, "source": "windows_dpapi", "error": error}
    key = values.get("xai_key", "")
    return {
        "value": key,
        "configured": bool(key),
        "source": "windows_dpapi" if key else "none",
        "error": "",
    }


def resolve_gemini_key() -> dict[str, Any]:
    environment = os.getenv("GEMINI_API_KEY", "").strip()
    if environment:
        if GEMINI_KEY_RE.fullmatch(environment):
            return {"value": environment, "configured": True, "source": "environment", "error": ""}
        return {"value": "", "configured": False, "source": "environment", "error": "invalid_environment_key"}
    values, error = _read_persisted_secrets()
    if error:
        return {"value": "", "configured": False, "source": "windows_dpapi", "error": error}
    key = values.get("gemini_key", "")
    return {
        "value": key,
        "configured": bool(key),
        "source": "windows_dpapi" if key else "none",
        "error": "",
    }


def secret_status() -> dict[str, Any]:
    resolved = resolve_xai_key()
    return {
        "configured": bool(resolved["configured"]),
        "source": resolved["source"],
        "error": resolved["error"],
        "secure_persistence_supported": os.name == "nt",
        "storage": "Windows DPAPI, current user" if os.name == "nt" else "environment variable only",
    }


def gemini_secret_status() -> dict[str, Any]:
    resolved = resolve_gemini_key()
    return {
        "configured": bool(resolved["configured"]),
        "source": resolved["source"],
        "error": resolved["error"],
        "secure_persistence_supported": os.name == "nt",
        "storage": "Windows DPAPI, current user" if os.name == "nt" else "environment variable only",
    }


def settings_status() -> dict[str, Any]:
    return {
        "schema": SETTINGS_SCHEMA,
        "preferences": effective_preferences(),
        "stored_preferences": stored_preferences(),
        "xai": secret_status(),
        "gemini": gemini_secret_status(),
        "settings_directory": str(settings_root()),
    }


def test_xai_connection(timeout_seconds: int = 15) -> dict[str, Any]:
    resolved = resolve_xai_key()
    model = effective_preferences()["grok_model"]
    if not resolved["configured"]:
        return {"ok": False, "model": model, "message": "xAI API key is not configured.", "duration_ms": 0}
    started = monotonic()
    request = urllib.request.Request(
        "https://api.x.ai/v1/models",
        headers={"Authorization": f"Bearer {resolved['value']}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
        names = {
            str(item.get("id") or item.get("name") or "")
            for item in payload.get("data", [])
            if isinstance(item, dict)
        } if isinstance(payload, dict) else set()
        return {
            "ok": True,
            "model": model,
            "model_visible": model in names or f"{model}-latest" in names,
            "message": "xAI connection succeeded.",
            "duration_ms": int((monotonic() - started) * 1000),
        }
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "model": model,
            "message": f"xAI connection failed: {type(exc).__name__}",
            "duration_ms": int((monotonic() - started) * 1000),
        }


def test_gemini_connection(timeout_seconds: int = 15) -> dict[str, Any]:
    resolved = resolve_gemini_key()
    model = effective_preferences()["gemini_model"]
    if not resolved["configured"]:
        return {"ok": False, "model": model, "message": "Gemini API key is not configured.", "duration_ms": 0}
    started = monotonic()
    request = urllib.request.Request(
        "https://generativelanguage.googleapis.com/v1beta/models",
        headers={"x-goog-api-key": resolved["value"], "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
        names = {
            str(item.get("baseModelId") or item.get("name") or "").removeprefix("models/")
            for item in payload.get("models", [])
            if isinstance(item, dict)
        } if isinstance(payload, dict) else set()
        return {
            "ok": True,
            "model": model,
            "model_visible": model in names,
            "message": "Gemini connection succeeded.",
            "duration_ms": int((monotonic() - started) * 1000),
        }
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "model": model,
            "message": f"Gemini connection failed: {type(exc).__name__}",
            "duration_ms": int((monotonic() - started) * 1000),
        }
