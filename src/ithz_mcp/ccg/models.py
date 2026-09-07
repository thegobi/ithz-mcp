from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import VERSION
from ..canonical_json import dumps


class BackendError(RuntimeError):
    """A model backend failed before producing a schema-valid role result."""


def _resolve_codex_app_server_executable(executable: str) -> str:
    """Avoid the Codex Desktop Windows launcher leaving its app-server child detached."""
    if os.name != "nt" or executable.lower() != "codex":
        return executable
    launcher = shutil.which(executable)
    if not launcher:
        return executable
    launcher_path = Path(launcher).resolve()
    candidates = [
        path
        for path in launcher_path.parent.glob("*/codex.exe")
        if path.is_file() and path.resolve() != launcher_path
    ]
    if not candidates:
        return executable
    return str(max(candidates, key=lambda path: path.stat().st_mtime_ns).resolve())


@dataclass(frozen=True)
class RoleResult:
    role: str
    provider: str
    model: str
    thread_id: str
    data: dict[str, Any]
    duration_ms: int
    template_hash: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    usage_source: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "provider": self.provider,
            "model": self.model,
            "thread_id": self.thread_id,
            "data": self.data,
            "duration_ms": self.duration_ms,
            "template_hash": self.template_hash,
            "usage": self.usage,
            "usage_source": self.usage_source,
        }


def _usage_count(value: Any, *keys: str) -> int:
    if not isinstance(value, dict):
        return 0
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate >= 0:
            return candidate
    return 0


def _normalized_usage(value: Any) -> dict[str, int]:
    """Normalize provider usage without retaining prompts, credentials or response text."""

    if not isinstance(value, dict):
        return {}
    input_tokens = _usage_count(value, "input_tokens", "inputTokens", "prompt_tokens", "promptTokenCount")
    output_tokens = _usage_count(value, "output_tokens", "outputTokens", "completion_tokens", "candidatesTokenCount")
    cached_tokens = _usage_count(
        value,
        "cached_input_tokens",
        "cachedInputTokens",
        "cached_tokens",
        "cachedContentTokenCount",
    )
    thinking_tokens = _usage_count(
        value,
        "reasoning_output_tokens",
        "reasoningOutputTokens",
        "reasoning_tokens",
        "thoughtsTokenCount",
    )
    total_tokens = _usage_count(value, "total_tokens", "totalTokens", "totalTokenCount")
    if not total_tokens:
        # Reasoning output is already included in output_tokens by the
        # supported providers and must not be counted twice.
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_input_tokens": cached_tokens,
        "thinking_tokens": thinking_tokens,
        "total_tokens": total_tokens,
    }


def _usage_from_app_server_notification(
    message: Any,
    thread_id: str,
    turn_id: str = "",
) -> dict[str, int]:
    """Read per-turn usage from the App Server v2 token-usage notification."""

    if not isinstance(message, dict) or message.get("method") != "thread/tokenUsage/updated":
        return {}
    params = message.get("params", {})
    if not isinstance(params, dict) or params.get("threadId") != thread_id:
        return {}
    message_turn_id = str(params.get("turnId", ""))
    if turn_id and message_turn_id and message_turn_id != turn_id:
        return {}
    token_usage = params.get("tokenUsage", {})
    if not isinstance(token_usage, dict):
        return {}
    return _normalized_usage(token_usage.get("last", {}))


def _parse_json_message(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        candidate = "\n".join(lines).strip()
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError as exc:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start < 0 or end <= start:
            raise BackendError(f"model_output_not_json:{exc}") from exc
        try:
            value = json.loads(candidate[start : end + 1])
        except json.JSONDecodeError as inner:
            raise BackendError(f"model_output_not_json:{inner}") from inner
    if not isinstance(value, dict):
        raise BackendError("model_output_must_be_object")
    return value


class CodexAppServerBackend:
    """Run one isolated, read-only Codex App Server thread per court role."""

    provider = "openai"

    def __init__(
        self,
        model: str = "gpt-5.6-luna",
        effort: str = "medium",
        timeout_seconds: int = 240,
        codex_executable: str = "codex",
        service_tier: str = "fast",
    ) -> None:
        self.model = model
        self.effort = effort
        self.timeout_seconds = timeout_seconds
        self.codex_executable = codex_executable
        self.service_tier = service_tier

    def run(
        self,
        role: str,
        prompt: str,
        output_schema: dict[str, Any],
        evidence_hash: str,
        chamber: Path,
        template_hash: str = "",
    ) -> RoleResult:
        started = time.monotonic()
        chamber.mkdir(parents=True, exist_ok=True)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        app_server_executable = _resolve_codex_app_server_executable(self.codex_executable)
        try:
            proc = subprocess.Popen(
                [
                    app_server_executable,
                    "app-server",
                    "-c",
                    f'service_tier="{self.service_tier}"',
                    "-c",
                    "mcp_servers={}",
                    "--listen",
                    "stdio://",
                ],
                cwd=str(chamber),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
            )
        except (FileNotFoundError, OSError) as exc:
            raise BackendError(f"codex_app_server_unavailable:{exc}") from exc

        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            proc.kill()
            raise BackendError("codex_app_server_pipe_setup_failed")

        out_queue: queue.Queue[str | None] = queue.Queue()
        stderr_lines: list[str] = []

        def read_stdout() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                out_queue.put(line)
            out_queue.put(None)

        def read_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                if len(stderr_lines) < 80:
                    stderr_lines.append(line.rstrip())

        threading.Thread(target=read_stdout, daemon=True).start()
        threading.Thread(target=read_stderr, daemon=True).start()

        deadline = time.monotonic() + self.timeout_seconds
        pending: list[dict[str, Any]] = []

        def send(message: dict[str, Any]) -> None:
            assert proc.stdin is not None
            proc.stdin.write(dumps(message) + "\n")
            proc.stdin.flush()

        def next_message() -> dict[str, Any]:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BackendError(f"codex_app_server_timeout:{role}")
                try:
                    line = out_queue.get(timeout=min(remaining, 1.0))
                except queue.Empty:
                    if proc.poll() is not None:
                        detail = " | ".join(stderr_lines[-8:])
                        raise BackendError(f"codex_app_server_exited:{proc.returncode}:{detail}")
                    continue
                if line is None:
                    detail = " | ".join(stderr_lines[-8:])
                    raise BackendError(f"codex_app_server_closed:{proc.returncode}:{detail}")
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    return value

        def wait_for_response(request_id: int) -> dict[str, Any]:
            for index, message in enumerate(list(pending)):
                if message.get("id") == request_id:
                    pending.pop(index)
                    return message
            while True:
                message = next_message()
                if message.get("id") == request_id:
                    return message
                pending.append(message)

        try:
            send(
                {
                    "method": "initialize",
                    "id": 1,
                    "params": {
                        "clientInfo": {
                            "name": "ccg-ithz-court",
                            "title": "CCG & ITHZ Court",
                            "version": VERSION,
                        }
                    },
                }
            )
            initialized = wait_for_response(1)
            if "error" in initialized:
                raise BackendError(f"codex_initialize_failed:{initialized['error']}")
            send({"method": "initialized", "params": {}})

            send(
                {
                    "method": "thread/start",
                    "id": 2,
                    "params": {
                        "model": self.model,
                        "cwd": str(chamber.resolve()),
                        "approvalPolicy": "never",
                        "sandbox": "read-only",
                        "ephemeral": False,
                        "serviceName": "ccg-ithz-court",
                        "developerInstructions": (
                            "You are one isolated role in a constitutional review. Do not call tools, "
                            "inspect files, browse, delegate, or communicate with other roles. Reason only "
                            "over the sealed packet in the user message. Return the requested JSON object. "
                            "Do not reveal private chain-of-thought; provide concise conclusions and evidence references."
                        ),
                    },
                }
            )
            thread_response = wait_for_response(2)
            if "error" in thread_response:
                raise BackendError(f"codex_thread_start_failed:{thread_response['error']}")
            thread = thread_response.get("result", {}).get("thread", {})
            thread_id = str(thread.get("id", ""))
            if not thread_id:
                raise BackendError("codex_thread_id_missing")

            send(
                {
                    "method": "turn/start",
                    "id": 3,
                    "params": {
                        "threadId": thread_id,
                        "input": [{"type": "text", "text": prompt}],
                        "model": self.model,
                        "effort": self.effort,
                        "summary": "none",
                        "approvalPolicy": "never",
                        "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
                        "outputSchema": output_schema,
                    },
                }
            )
            turn_response = wait_for_response(3)
            if "error" in turn_response:
                raise BackendError(f"codex_turn_start_failed:{turn_response['error']}")
            turn_id = str(turn_response.get("result", {}).get("turn", {}).get("id", ""))

            final_messages: list[str] = []
            usage: dict[str, int] = {}
            usage_source = ""
            for message in list(pending):
                observed_usage = _usage_from_app_server_notification(message, thread_id, turn_id)
                if observed_usage:
                    usage = observed_usage
                    usage_source = "app_server.thread_token_usage.last"
                item = message.get("params", {}).get("item", {})
                if message.get("method") == "item/completed" and item.get("type") == "agentMessage":
                    final_messages.append(str(item.get("text", "")))
            while True:
                message = next_message()
                method = message.get("method")
                params = message.get("params", {})
                observed_usage = _usage_from_app_server_notification(message, thread_id, turn_id)
                if observed_usage:
                    usage = observed_usage
                    usage_source = "app_server.thread_token_usage.last"
                if method == "item/completed":
                    item = params.get("item", {})
                    if item.get("type") == "agentMessage":
                        final_messages.append(str(item.get("text", "")))
                if method == "turn/completed" and params.get("threadId") == thread_id:
                    turn = params.get("turn", {})
                    if turn.get("status") != "completed":
                        raise BackendError(f"codex_turn_failed:{turn.get('error') or turn.get('status')}")
                    for item in turn.get("items", []):
                        if item.get("type") == "agentMessage" and item.get("text"):
                            if item.get("phase") == "final_answer":
                                final_messages.append(str(item["text"]))
                    if not usage:
                        usage = _normalized_usage(turn.get("usage", {}))
                        if usage and usage.get("total_tokens", 0) > 0:
                            usage_source = "app_server.turn_completed.legacy"
                    break
            # App Server v2 publishes metering as a separate notification.
            # Usually it precedes turn/completed, but tolerate a short delivery
            # tail so a successfully completed role cannot silently report zero.
            if usage.get("total_tokens", 0) <= 0:
                usage_deadline = min(deadline, time.monotonic() + 2.0)
                while time.monotonic() < usage_deadline:
                    remaining = usage_deadline - time.monotonic()
                    try:
                        line = out_queue.get(timeout=min(remaining, 0.25))
                    except queue.Empty:
                        if proc.poll() is not None:
                            break
                        continue
                    if line is None:
                        break
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    observed_usage = _usage_from_app_server_notification(message, thread_id, turn_id)
                    if observed_usage.get("total_tokens", 0) > 0:
                        usage = observed_usage
                        usage_source = "app_server.thread_token_usage.last"
                        break
            if not final_messages:
                raise BackendError("codex_final_message_missing")
            data = _parse_json_message(final_messages[-1])
            if data.get("evidence_hash") != evidence_hash:
                data["_evidence_hash_mismatch"] = True
            return RoleResult(
                role=role,
                provider=self.provider,
                model=self.model,
                thread_id=thread_id,
                data=data,
                duration_ms=int((time.monotonic() - started) * 1000),
                template_hash=template_hash,
                usage=usage,
                usage_source=usage_source,
            )
        finally:
            try:
                if proc.stdin is not None:
                    proc.stdin.close()
            except OSError:
                pass
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


class GrokBackend:
    """Cross-laboratory opponent using xAI structured outputs."""

    provider = "xai"

    def __init__(
        self,
        api_key: str,
        model: str = "grok-4.20-reasoning-latest",
        timeout_seconds: int = 180,
        reasoning_effort: str = "low",
    ) -> None:
        if not api_key.strip():
            raise ValueError("xai_api_key_required")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.reasoning_effort = reasoning_effort

    def run(
        self,
        role: str,
        prompt: str,
        output_schema: dict[str, Any],
        evidence_hash: str,
        chamber: Path,
        template_hash: str = "",
    ) -> RoleResult:
        del chamber
        started = time.monotonic()
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an isolated cross-laboratory constitutional opponent. Use only the sealed "
                        "packet. Do not request or call tools. Do not mention or imply your provider, model, "
                        "laboratory or role origin in the report. Return concise JSON, not private chain-of-thought."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": f"ccg_{role}", "strict": True, "schema": output_schema},
            },
        }
        if self.reasoning_effort != "none":
            payload["reasoning_effort"] = self.reasoning_effort
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        if template_hash:
            # xAI documents this opaque conversation id as the cache-affinity key for Chat Completions.
            headers["x-grok-conv-id"] = f"ccg-template-{template_hash[:40]}"
        request = urllib.request.Request(
            "https://api.x.ai/v1/chat/completions",
            data=dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
            raise BackendError(f"grok_request_failed:{type(exc).__name__}:{exc}") from exc
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendError("grok_response_shape_invalid") from exc
        data = _parse_json_message(str(content))
        if data.get("evidence_hash") != evidence_hash:
            data["_evidence_hash_mismatch"] = True
        return RoleResult(
            role=role,
            provider=self.provider,
            model=self.model,
            thread_id=str(body.get("id", "xai-response")),
            data=data,
            duration_ms=int((time.monotonic() - started) * 1000),
            template_hash=template_hash,
            usage=_normalized_usage(body.get("usage", {})),
            usage_source="xai.response.usage",
        )


class GeminiBackend:
    """Cross-laboratory opponent using Gemini structured outputs without tools."""

    provider = "google"

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-3.7-flash",
        timeout_seconds: int = 180,
        thinking_level: str = "low",
    ) -> None:
        if not api_key.strip():
            raise ValueError("gemini_api_key_required")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.thinking_level = thinking_level

    def run(
        self,
        role: str,
        prompt: str,
        output_schema: dict[str, Any],
        evidence_hash: str,
        chamber: Path,
        template_hash: str = "",
    ) -> RoleResult:
        del chamber
        started = time.monotonic()
        payload = {
            "systemInstruction": {
                "parts": [
                    {
                        "text": (
                            "You are an isolated cross-laboratory constitutional opponent. Use only the sealed "
                            "packet. Do not call tools or identify your provider or model. Return concise JSON only."
                        )
                    }
                ]
            },
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "thinkingConfig": {"thinkingLevel": self.thinking_level},
                "responseMimeType": "application/json",
                "responseJsonSchema": output_schema,
            },
        }
        model = urllib.parse.quote(self.model, safe="")
        request = urllib.request.Request(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            data=dumps(payload).encode("utf-8"),
            headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
            raise BackendError(f"gemini_request_failed:{type(exc).__name__}") from exc
        try:
            parts = body["candidates"][0]["content"]["parts"]
            content = "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendError("gemini_response_shape_invalid") from exc
        data = _parse_json_message(content)
        if data.get("evidence_hash") != evidence_hash:
            data["_evidence_hash_mismatch"] = True
        return RoleResult(
            role=role,
            provider=self.provider,
            model=self.model,
            thread_id=str(body.get("responseId", "gemini-response")),
            data=data,
            duration_ms=int((time.monotonic() - started) * 1000),
            template_hash=template_hash,
            usage=_normalized_usage(body.get("usageMetadata", {})),
            usage_source="gemini.response.usageMetadata",
        )


class ScriptedBackend:
    """Deterministic backend used only by unit tests and offline protocol smoke tests."""

    provider = "scripted"

    def __init__(self, model: str = "scripted-court-v1") -> None:
        self.model = model
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        role: str,
        prompt: str,
        output_schema: dict[str, Any],
        evidence_hash: str,
        chamber: Path,
        template_hash: str = "",
    ) -> RoleResult:
        del output_schema, chamber
        self.calls.append({"role": role, "prompt": prompt, "template_hash": template_hash})
        if role == "proposer":
            data = {
                "evidence_hash": evidence_hash,
                "summary": "Create one bounded demonstration artifact.",
                "actions": [
                    {
                        "capability": "file.write.sandboxed",
                        "description": "Write the approved maintenance notice.",
                        "parameters_json": dumps(
                            {
                                "relative_path": "maintenance_notice.md",
                                "content": "# Plánovaná údržba\n\nSlužba bude krátko nedostupná. Dáta zostávajú v bezpečí. Ďakujeme za pochopenie.\n",
                            }
                        ),
                        "expected_effect": "One Markdown file in the CCG sandbox.",
                        "rollback": "Delete the generated sandbox file.",
                        "irreversible": False,
                    }
                ],
                "risk_assessment": "low",
                "assumptions": ["The target is the isolated demonstration sandbox."],
                "evidence_references": ["constitution", "task charter"],
            }
        elif role in {"opponent_primary", "opponent_cross", "opponent_fallback", "opponent_blind_first"}:
            data = {
                "evidence_hash": evidence_hash,
                "recommendation": "ALLOW_WITH_LIMITS",
                "objections": [],
                "missing_evidence": [],
                "confidence": 0.91,
            }
        elif role == "judge":
            data = {
                "evidence_hash": evidence_hash,
                "verdict": "ALLOW_WITH_LIMITS",
                "scope_limits": ["Only maintenance_notice.md inside the demonstration sandbox."],
                "resolved_objections": [],
                "unresolved_objections": [],
                "rationale": "The action is bounded, reversible and matches the requested capability.",
                "human_approval_required": False,
            }
        elif role == "auditor":
            data = {
                "evidence_hash": evidence_hash,
                "process_valid": True,
                "checks": ["sealed evidence hash matched", "two opponents submitted", "judge packet was blind"],
                "defects": [],
                "final_disposition": "VALID",
            }
        else:
            raise BackendError(f"unsupported_scripted_role:{role}")
        return RoleResult(
            role=role,
            provider=self.provider,
            model=self.model,
            thread_id=f"scripted-{role}-{len(self.calls):02d}",
            data=data,
            duration_ms=1,
            template_hash=template_hash,
            usage={
                "input_tokens": 100,
                "output_tokens": 20,
                "cached_input_tokens": 0,
                "thinking_tokens": 5,
                "total_tokens": 120,
            },
            usage_source="scripted.fixture",
        )
