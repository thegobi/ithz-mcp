from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from ..canonical_json import dump_pretty, dumps
from ..hashing import stable_json_hash
from .ledger import EvidenceLedger


TOKEN_SCHEMA = "ccg_capability_token_v1"


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(dump_pretty(value), encoding="utf-8")
    os.replace(temporary, path)


class CapabilityBroker:
    """Small capability core with exact-scope, expiring, single-use tokens."""

    def __init__(self, project: Path, ledger: EvidenceLedger) -> None:
        self.project = project.resolve()
        self.ledger = ledger
        self.private_dir = ledger.root / "private"
        self.key_path = self.private_dir / "signing.key"

    def _key(self) -> bytes:
        env_key = os.getenv("CCG_SIGNING_KEY", "")
        if env_key:
            return hashlib.sha256(env_key.encode("utf-8")).digest()
        self.private_dir.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            encoded = base64.b64encode(secrets.token_bytes(32))
            descriptor = os.open(self.key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(descriptor, encoded)
            finally:
                os.close(descriptor)
        return base64.b64decode(self.key_path.read_bytes())

    def issue(self, case_id: str, evidence_hash: str, action: dict[str, Any], ttl_seconds: int = 600) -> dict[str, Any]:
        now = int(time.time())
        parameters = action.get("parameters", {})
        if not isinstance(parameters, dict):
            parameters = {}
        claims = {
            "schema": TOKEN_SCHEMA,
            "case_id": case_id,
            "evidence_hash": evidence_hash,
            "capability": action["capability"],
            "action_hash": stable_json_hash(action),
            "relative_path": str(parameters.get("relative_path", "")),
            "content_hash": hashlib.sha256(str(parameters.get("content", "")).encode("utf-8")).hexdigest(),
            "allow_overwrite": bool(parameters.get("allow_overwrite", False)),
            "issued_at": now,
            "expires_at": now + max(30, min(int(ttl_seconds), 3600)),
            "max_uses": 1,
            "nonce": secrets.token_hex(12),
        }
        body = _b64url_encode(dumps(claims).encode("utf-8"))
        signature = _b64url_encode(hmac.new(self._key(), body.encode("ascii"), hashlib.sha256).digest())
        token = f"{body}.{signature}"
        state = {
            "schema": TOKEN_SCHEMA,
            "token_hash": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "claims_hash": stable_json_hash(claims),
            "spent": False,
            "execution_status": "not_started",
        }
        _atomic_json(self.ledger.case_dir(case_id) / "token_state.json", state)
        self.ledger.append(
            case_id,
            "capability_issued",
            {
                "token_hash": state["token_hash"],
                "claims_hash": state["claims_hash"],
                "capability": claims["capability"],
                "expires_at": claims["expires_at"],
                "max_uses": 1,
            },
        )
        return {"token": token, "claims": claims, "token_hash": state["token_hash"]}

    def decode_and_verify(self, token: str) -> dict[str, Any]:
        try:
            body, signature = token.split(".", 1)
        except ValueError as exc:
            raise ValueError("invalid_capability_token_format") from exc
        expected = hmac.new(self._key(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(signature), expected):
            raise ValueError("invalid_capability_token_signature")
        try:
            claims = json.loads(_b64url_decode(body).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid_capability_token_payload") from exc
        if claims.get("schema") != TOKEN_SCHEMA:
            raise ValueError("unsupported_capability_token_schema")
        if int(claims.get("expires_at", 0)) < int(time.time()):
            raise ValueError("capability_token_expired")
        return claims

    def execute_demo_write(self, case_id: str, token: str, relative_path: str, content: str) -> dict[str, Any]:
        claims = self.decode_and_verify(token)
        if claims.get("case_id") != case_id:
            raise ValueError("capability_case_mismatch")
        if claims.get("capability") != "file.write.sandboxed":
            raise ValueError("unsupported_demo_capability")
        if claims.get("relative_path") != relative_path:
            raise ValueError("capability_path_mismatch")
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if claims.get("content_hash") != content_hash:
            raise ValueError("capability_content_mismatch")
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("unsafe_demo_relative_path")
        sandbox = (self.project / ".ccg-sandbox").resolve()
        target = (sandbox / relative).resolve()
        try:
            target.relative_to(sandbox)
        except ValueError as exc:
            raise ValueError("demo_target_outside_sandbox") from exc
        state_path = self.ledger.case_dir(case_id) / "token_state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        if state.get("token_hash") != token_hash:
            raise ValueError("capability_token_not_registered")
        if state.get("spent"):
            raise ValueError("capability_token_already_spent")

        # Spend before the side effect. A crash can deny the action, never make the token reusable.
        state["spent"] = True
        state["spent_at"] = int(time.time())
        state["execution_status"] = "started"
        _atomic_json(state_path, state)
        if target.exists() and not claims.get("allow_overwrite", False):
            state["execution_status"] = "denied_precondition"
            state["denial_reason"] = "target_exists_and_overwrite_not_authorized"
            _atomic_json(state_path, state)
            self.ledger.append(
                case_id,
                "capability_denied",
                {
                    "reason": state["denial_reason"],
                    "relative_path": relative.as_posix(),
                    "token_hash": token_hash,
                    "token_spent": True,
                },
            )
            raise ValueError("target_exists_and_overwrite_not_authorized")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".ccg-tmp")
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, target)
        state["execution_status"] = "completed"
        state["output_hash"] = hashlib.sha256(target.read_bytes()).hexdigest()
        _atomic_json(state_path, state)
        self.ledger.append(
            case_id,
            "capability_executed",
            {
                "adapter": "demo.write_text",
                "relative_path": relative.as_posix(),
                "output_hash": state["output_hash"],
                "token_hash": token_hash,
            },
        )
        return {
            "executed": True,
            "adapter": "demo.write_text",
            "target": str(target),
            "output_hash": state["output_hash"],
            "token_spent": True,
        }
