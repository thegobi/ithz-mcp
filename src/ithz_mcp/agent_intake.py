from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .hashing import stable_json_hash
from .instruction_memory import record_durable_instructions
from .native_archive_store import archive_append_events, build_native_archive, native_archive_context_pack, project_archive_path, scan_project_for_archive
from .prompt_memory import redact_text
from .safety import ignore_reason, normalize_rel, redaction_block_reason


INTAKE_SCHEMA = "ithz_mcp_agent_intake_v2"
DEFAULT_QUERY = "project workflow decisions gates risks architecture deployment testing next steps"
MAX_CONTEXT_BYTES = 24000
MAX_DOC_EXCERPT_BYTES = 14000
MAX_REPO_DOSSIER_BYTES = 52000
MAX_SOURCE_EXCERPT_BYTES = 30000
MAX_SOURCE_EXCERPT_FILES = 24
MAX_SOURCE_EXCERPT_PER_FILE = 1700
MAX_CANDIDATE_FILES = 80
MAX_FACTS_PER_CATEGORY = 12
DEFAULT_CODEX_INTAKE_TIMEOUT_SECONDS = 90

SOURCE_EXTS = {
    ".php",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".css",
    ".scss",
    ".html",
    ".vue",
    ".cpp",
    ".hpp",
    ".h",
    ".cs",
    ".java",
    ".go",
    ".rs",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
}

CONFIG_NAMES = {
    "package.json",
    "composer.json",
    "pyproject.toml",
    "requirements.txt",
    "vite.config.js",
    "vite.config.ts",
    "next.config.js",
    "webpack.config.js",
    "tsconfig.json",
    "phpunit.xml",
    "pytest.ini",
    "docker-compose.yml",
    "dockerfile",
    ".gitignore",
}

HIGH_SIGNAL_PATH_TOKENS = (
    "readme",
    "agent",
    "context",
    "workflow",
    "decision",
    "architecture",
    "deploy",
    "release",
    "test",
    "gate",
    "risk",
    "plugin",
    "theme",
    "src",
    "app",
    "api",
    "routes",
    "controllers",
    "services",
)

SIGNAL_LINE_RE = re.compile(
    r"(?i)("
    r"^#{1,6}\s+|"
    r"\b(class|def|function|interface|trait|namespace|export\s+default|export\s+function|const\s+\w+|let\s+\w+|var\s+\w+)\b|"
    r"\b(add_action|add_filter|register_post_type|register_rest_route|Route::|router\.|app\.|describe\(|it\(|test\()\b|"
    r"\b(decision|gate|risk|workflow|deploy|ssh|cron|cache|security|auth|payment|woocommerce|wordpress|plugin|theme|todo|fixme|must not|nesmie|pozor|rizik)"
    r")"
)


def codex_cli_path() -> str | None:
    return shutil.which("codex")


def _safe_text(text: str) -> dict[str, Any]:
    redacted = redact_text(text)
    safe = redacted.get("text", "")
    if redaction_block_reason(safe):
        safe = re.sub(
            r"(?i)(secret|credential|password|passwd|pwd|token|access_token|refresh_token|bearer|api_key|private_key)\s*[:=]\s*\S+",
            r"\1=[REDACTED]",
            safe,
        )
        safe = safe.replace(".env", "[DOTENV_FILE]")
        safe = safe.replace("-----BEGIN", "[PRIVATE_KEY_BEGIN]")
        safe = safe.replace("-----END", "[PRIVATE_KEY_END]")
    return {
        "text": safe,
        "redaction_status": "redacted" if redacted.get("redacted") or safe != text else "clean",
        "blocked_after_redaction": redaction_block_reason(safe),
        "redaction_hits": sorted(set(redacted.get("hits", []))),
    }


def _scan_summary_from_scan(scan: dict[str, Any]) -> dict[str, Any]:
    files = scan.get("files", [])
    ignored = scan.get("ignored", [])
    by_extension: dict[str, int] = {}
    families: dict[str, int] = {}
    indexed_bytes = 0
    for row in files:
        ext = str(row.get("extension", "") or "[none]")
        by_extension[ext] = by_extension.get(ext, 0) + 1
        family = str(row.get("family_guess", "unknown"))
        families[family] = families.get(family, 0) + 1
        indexed_bytes += int(row.get("size", 0) or 0)
    return {
        "scan_hash": scan.get("scan_hash"),
        "file_count": len(files),
        "ignored_count": len(ignored),
        "indexed_bytes": indexed_bytes,
        "by_extension": dict(sorted(by_extension.items())),
        "families": dict(sorted(families.items())),
        "top_files": [
            {
                "path": row.get("path"),
                "size": row.get("size"),
                "family_guess": row.get("family_guess"),
                "line_count": row.get("line_count"),
            }
            for row in sorted(files, key=lambda r: (str(r.get("family_guess")), str(r.get("path"))))[:80]
        ],
        "ignored_sample": [
            {"path": row.get("path"), "ignored_reason": row.get("ignored_reason")}
            for row in sorted(ignored, key=lambda r: (str(r.get("ignored_reason")), str(r.get("path"))))[:40]
        ],
    }


def _scan_summary(project: Path) -> dict[str, Any]:
    return _scan_summary_from_scan(scan_project_for_archive(project))


def _repo_scale(summary: dict[str, Any]) -> str:
    file_count = int(summary.get("file_count", 0) or 0)
    indexed_bytes = int(summary.get("indexed_bytes", 0) or 0)
    if file_count <= 120 and indexed_bytes <= 2_000_000:
        return "small"
    if file_count <= 1500 and indexed_bytes <= 25_000_000:
        return "medium"
    if file_count <= 12_000 and indexed_bytes <= 180_000_000:
        return "large"
    return "huge"


def _candidate_doc_paths(project: Path, scan: dict[str, Any] | None = None) -> list[Path]:
    names = {
        "project.md",
        "readme.md",
        "agents.md",
        "ithz_context.md",
        "ai_project_brief.md",
        "project_context.md",
        "workflow_rules.md",
        "decisions_log.md",
        "architecture.md",
        "repo.md",
    }
    scan = scan or scan_project_for_archive(project)
    rows = []
    for row in scan.get("files", []):
        rel = str(row.get("path", ""))
        name = Path(rel).name.lower()
        ext = Path(rel).suffix.lower()
        size = int(row.get("size", 0) or 0)
        if ignore_reason(rel, size):
            continue
        score = 0
        if name in names:
            score += 100
        if ext in {".md", ".txt"}:
            score += 20
        if any(token in rel.lower() for token in ("decision", "workflow", "architecture", "context", "agent", "readme", "deploy", "test", "gate", "risk")):
            score += 30
        if score:
            rows.append((score, rel, size))
    selected = []
    total = 0
    for _, rel, size in sorted(rows, key=lambda r: (-r[0], r[1])):
        if total + size > MAX_DOC_EXCERPT_BYTES:
            continue
        selected.append(project / rel)
        total += size
        if len(selected) >= 16:
            break
    return selected


def _read_doc_excerpts(project: Path, scan: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    excerpts = []
    for path in _candidate_doc_paths(project, scan):
        try:
            rel = normalize_rel(path.relative_to(project))
        except ValueError:
            rel = path.name
        text = path.read_text(encoding="utf-8", errors="replace")
        safe = _safe_text(text[:5000])
        if safe["blocked_after_redaction"]:
            excerpts.append({"path": rel, "included": False, "reason": "blocked_after_redaction"})
            continue
        excerpts.append({"path": rel, "included": True, "text": safe["text"][:4000], "redaction_status": safe["redaction_status"]})
    return excerpts


def _directory_summary(scan: dict[str, Any]) -> list[dict[str, Any]]:
    dirs: dict[str, dict[str, Any]] = {}
    for row in scan.get("files", []):
        rel = str(row.get("path", ""))
        parts = Path(rel).parts
        key = "/".join(parts[:2]) if len(parts) >= 2 else "[root]"
        item = dirs.setdefault(key, {"path": key, "file_count": 0, "bytes": 0, "extensions": {}})
        item["file_count"] += 1
        item["bytes"] += int(row.get("size", 0) or 0)
        ext = str(row.get("extension", "") or "[none]")
        item["extensions"][ext] = item["extensions"].get(ext, 0) + 1
    rows = []
    for item in dirs.values():
        item["extensions"] = dict(sorted(item["extensions"].items(), key=lambda kv: (-kv[1], kv[0]))[:8])
        rows.append(item)
    return sorted(rows, key=lambda r: (-int(r["file_count"]), str(r["path"])))[:60]


def _score_file_candidate(rel: str, size: int, family: str) -> tuple[int, list[str]]:
    lower = rel.lower().replace("\\", "/")
    name = Path(lower).name
    ext = Path(lower).suffix
    parts = tuple(Path(lower).parts)
    score = 0
    reasons: list[str] = []
    if name in CONFIG_NAMES:
        score += 45
        reasons.append("config")
    if len(parts) >= 3 and parts[0] == "plugins" and ext == ".php":
        plugin_slug = parts[1]
        if name in {f"{plugin_slug}.php", "plugin.php"}:
            score += 70
            reasons.append("wordpress_plugin_entry")
    if len(parts) >= 3 and parts[0] == "themes" and name in {"functions.php", "style.css", "theme.json"}:
        score += 70
        reasons.append("wordpress_theme_entry")
    if name in {"project.md", "agents.md", "ithz_context.md", "ai_project_brief.md", "project_context.md", "workflow_rules.md", "decisions_log.md", "architecture.md", "repo.md"} or (name == "readme.md" and len(parts) <= 2):
        score += 100
        reasons.append("bootstrap_doc")
    elif name == "readme.md":
        score += 20
        reasons.append("local_readme")
    matched_tokens = [token for token in HIGH_SIGNAL_PATH_TOKENS if token in lower]
    if matched_tokens:
        score += min(65, 8 * len(matched_tokens))
        reasons.extend(f"path:{token}" for token in matched_tokens[:6])
    if ext in SOURCE_EXTS:
        score += 20
        reasons.append("source_or_config")
    if "/tests/" in lower or lower.startswith("tests/") or "/test/" in lower:
        score += 20
        reasons.append("test_area")
    if lower.startswith(("plugins/", "themes/", "src/", "app/", "includes/")):
        score += 18
        reasons.append("primary_area")
    if family in {"markdown", "source_code", "config"}:
        score += 10
    if size > 180_000:
        score -= 25
        reasons.append("large_sample_only")
    if size == 0:
        score -= 10
    return score, reasons


def _signal_excerpt(path: Path, max_bytes: int = MAX_SOURCE_EXCERPT_PER_FILE) -> dict[str, Any]:
    rel = path.name
    try:
        raw = path.read_bytes()[:64 * 1024]
    except OSError as exc:
        return {"included": False, "reason": f"read_failed:{exc}"}
    text = raw.decode("utf-8", errors="replace")
    safe = _safe_text(text)
    if safe["blocked_after_redaction"]:
        return {"included": False, "reason": "blocked_after_redaction", "redaction_hits": safe["redaction_hits"]}
    lines: list[str] = []
    for idx, line in enumerate(safe["text"].splitlines(), start=1):
        stripped = re.sub(r"\s+", " ", line.strip())
        if not stripped:
            continue
        if len(lines) < 8 or SIGNAL_LINE_RE.search(stripped):
            lines.append(f"L{idx}: {stripped[:240]}")
        if len("\n".join(lines).encode("utf-8")) >= max_bytes:
            break
        if len(lines) >= 38:
            break
    excerpt = "\n".join(lines)[:max_bytes]
    return {
        "included": bool(excerpt),
        "text": excerpt,
        "redaction_status": safe["redaction_status"],
        "redaction_hits": safe["redaction_hits"],
    }


def _build_repo_dossier(project: Path, scan: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    scale = _repo_scale(summary)
    rows: list[dict[str, Any]] = []
    for row in scan.get("files", []):
        rel = str(row.get("path", ""))
        size = int(row.get("size", 0) or 0)
        if ignore_reason(rel, size):
            continue
        score, reasons = _score_file_candidate(rel, size, str(row.get("family_guess", "")))
        if score <= 0:
            continue
        rows.append(
            {
                "path": rel,
                "size": size,
                "extension": row.get("extension", ""),
                "family_guess": row.get("family_guess", ""),
                "score": score,
                "reasons": reasons,
            }
        )
    ranked = sorted(rows, key=lambda r: (-int(r["score"]), str(r["path"])))
    candidates: list[dict[str, Any]] = []
    by_top_dir: dict[str, int] = {}
    by_name: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for row in ranked:
        rel = str(row["path"])
        parts = Path(rel).parts
        top_dir = "/".join(parts[:2]) if len(parts) >= 2 else "[root]"
        name = Path(rel).name.lower()
        category = "other"
        if parts and parts[0].lower() == "plugins" and "wordpress_plugin_entry" in row.get("reasons", []):
            category = "wordpress_plugin_entry"
        elif parts and parts[0].lower() == "themes":
            category = "wordpress_theme"
        elif name in CONFIG_NAMES:
            category = "config"
        elif Path(rel).suffix.lower() in {".md", ".txt"}:
            category = "docs"
        category_cap = {
            "wordpress_plugin_entry": 18,
            "wordpress_theme": 12,
            "config": 12,
            "docs": 14,
        }.get(category, 30)
        if by_category.get(category, 0) >= category_cap:
            continue
        if by_top_dir.get(top_dir, 0) >= 12:
            continue
        if name in {"composer.json", "package.json", "index.php"} and by_name.get(name, 0) >= 8:
            continue
        candidates.append(row)
        by_category[category] = by_category.get(category, 0) + 1
        by_top_dir[top_dir] = by_top_dir.get(top_dir, 0) + 1
        by_name[name] = by_name.get(name, 0) + 1
        if len(candidates) >= MAX_CANDIDATE_FILES:
            break
    excerpt_budget = MAX_SOURCE_EXCERPT_BYTES
    if scale == "huge":
        excerpt_budget = 18_000
    elif scale == "large":
        excerpt_budget = 24_000
    excerpts: list[dict[str, Any]] = []
    used = 0
    excerpt_category_counts: dict[str, int] = {}
    for row in candidates:
        if len(excerpts) >= MAX_SOURCE_EXCERPT_FILES or used >= excerpt_budget:
            break
        rel = str(row["path"])
        ext = Path(rel).suffix.lower()
        parts = Path(rel).parts
        name = Path(rel).name.lower()
        category = "source"
        if parts and parts[0].lower() == "plugins" and "wordpress_plugin_entry" in row.get("reasons", []):
            category = "wordpress_plugin_entry"
        elif parts and parts[0].lower() == "themes":
            category = "wordpress_theme"
        elif name in CONFIG_NAMES:
            category = "config"
        elif ext in {".md", ".txt"}:
            category = "docs"
        excerpt_cap = {
            "wordpress_plugin_entry": 8,
            "wordpress_theme": 6,
            "config": 4,
            "docs": 5,
        }.get(category, 10)
        if excerpt_category_counts.get(category, 0) >= excerpt_cap:
            continue
        if ext not in SOURCE_EXTS and Path(rel).name.lower() not in CONFIG_NAMES:
            continue
        item = _signal_excerpt(project / rel)
        if not item.get("included"):
            continue
        text = str(item.get("text", ""))
        encoded = len(text.encode("utf-8"))
        if used + encoded > excerpt_budget:
            remaining = max(0, excerpt_budget - used)
            text = text.encode("utf-8")[:remaining].decode("utf-8", errors="ignore")
            encoded = len(text.encode("utf-8"))
        if not text.strip():
            continue
        used += encoded
        excerpt_category_counts[category] = excerpt_category_counts.get(category, 0) + 1
        excerpts.append(
            {
                "path": rel,
                "score": row["score"],
                "reasons": row["reasons"],
                "text": text,
                "redaction_status": item.get("redaction_status", ""),
            }
        )
    dossier = {
        "schema": "ithz_mcp_repo_intake_dossier_v1",
        "project_scale": scale,
        "intake_strategy": {
            "small": "docs_plus_source_excerpts",
            "medium": "ranked_docs_configs_and_primary_source_excerpts",
            "large": "ranked_map_and_sampled_high_signal_excerpts",
            "huge": "map_first_minimal_excerpts_require_evidence_gaps",
        }[scale],
        "budgets": {
            "max_repo_dossier_bytes": MAX_REPO_DOSSIER_BYTES,
            "max_source_excerpt_bytes": excerpt_budget,
            "max_source_excerpt_files": MAX_SOURCE_EXCERPT_FILES,
            "max_facts_per_category": MAX_FACTS_PER_CATEGORY,
        },
        "directory_summary": _directory_summary(scan),
        "candidate_files": candidates,
        "source_excerpts": excerpts,
    }
    dossier["dossier_hash"] = stable_json_hash(dossier)
    raw = json.dumps(dossier, ensure_ascii=False, sort_keys=True)
    if len(raw.encode("utf-8")) > MAX_REPO_DOSSIER_BYTES:
        dossier["directory_summary"] = dossier["directory_summary"][:30]
        dossier["candidate_files"] = dossier["candidate_files"][:45]
        while len(json.dumps(dossier, ensure_ascii=False, sort_keys=True).encode("utf-8")) > MAX_REPO_DOSSIER_BYTES and dossier["source_excerpts"]:
            dossier["source_excerpts"].pop()
        dossier["truncated"] = True
        dossier["truncation_reason"] = "repo_dossier_byte_budget"
        dossier["dossier_hash"] = stable_json_hash(dossier)
    return dossier


def _intake_prompt(project: Path, owner: str, profile: str, context_pack_text: str, summary: dict[str, Any], excerpts: list[dict[str, Any]], repo_dossier: dict[str, Any]) -> str:
    payload = {
        "project": str(project),
        "owner": owner,
        "profile": profile,
        "scan_summary": summary,
        "doc_excerpts": excerpts,
        "repo_intake_dossier": repo_dossier,
        "context_pack": context_pack_text[:MAX_CONTEXT_BYTES],
    }
    return (
        "You are performing a read-only ITHZ-MCP first project intake.\n"
        "Do not write files. Do not run commands that mutate the project.\n"
        "Do not inspect or include secrets, .env files, private keys, tokens, build artifacts, vendor folders, node_modules, or .git objects.\n"
        "Use the supplied sanitized project context and repo intake dossier first.\n"
        "Select the important project files or file sections from the dossier. If you need more evidence and the project is not huge, you may inspect only those selected files read-only.\n"
        "For large/huge projects, prefer the supplied map and excerpts; do not broad-scan the tree.\n"
        "Do not quote long source code. Store durable project memory only: workflow, decisions, gates, risks, candidate files, next steps and evidence gaps.\n"
        f"Return at most {MAX_FACTS_PER_CATEGORY} short items per list. If evidence is weak, say so in evidence_gaps.\n"
        "Return only one JSON object matching this shape:\n"
        "{\n"
        '  "project_summary": ["short factual project summary"],\n'
        '  "workflow_rules": ["durable workflow rule"],\n'
        '  "project_decisions": ["durable decision or architecture fact"],\n'
        '  "gate_rules": ["test or validation gate"],\n'
        '  "risk_rules": ["must-not-break, safety or limitation rule"],\n'
        '  "candidate_files": ["path or area likely relevant for future work"],\n'
        '  "next_steps": ["short next useful step"],\n'
        '  "evidence_gaps": ["missing evidence or uncertainty"],\n'
        '  "confidence": "low|medium|high"\n'
        "}\n\n"
        "Sanitized context payload:\n"
        + json.dumps(payload, ensure_ascii=False, sort_keys=True)
    )


def _output_schema(path: Path) -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "project_summary": {"type": "array", "items": {"type": "string"}},
            "workflow_rules": {"type": "array", "items": {"type": "string"}},
            "project_decisions": {"type": "array", "items": {"type": "string"}},
            "gate_rules": {"type": "array", "items": {"type": "string"}},
            "risk_rules": {"type": "array", "items": {"type": "string"}},
            "candidate_files": {"type": "array", "items": {"type": "string"}},
            "next_steps": {"type": "array", "items": {"type": "string"}},
            "evidence_gaps": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        },
        "required": [
            "project_summary",
            "workflow_rules",
            "project_decisions",
            "gate_rules",
            "risk_rules",
            "candidate_files",
            "next_steps",
            "evidence_gaps",
            "confidence",
        ],
    }
    path.write_text(json.dumps(schema, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")


def _parse_codex_output(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.I)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            return json.loads(stripped[start : end + 1])
        raise


def _run_codex_intake(project: Path, prompt: str, work_dir: Path, timeout_seconds: int | None = None) -> dict[str, Any]:
    codex = codex_cli_path()
    if not codex:
        return {"available": False, "reason": "codex_cli_not_found"}
    if timeout_seconds is None:
        try:
            timeout_seconds = max(30, int(os.environ.get("ITHZ_MCP_AGENT_INTAKE_TIMEOUT_SECONDS", str(DEFAULT_CODEX_INTAKE_TIMEOUT_SECONDS))))
        except ValueError:
            timeout_seconds = DEFAULT_CODEX_INTAKE_TIMEOUT_SECONDS
    work_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = work_dir / "agent_intake_prompt.txt"
    output_path = work_dir / "agent_intake_output.json"
    schema_path = work_dir / "agent_intake_schema.json"
    prompt_path.write_text(prompt, encoding="utf-8")
    _output_schema(schema_path)
    command = [
        codex,
        "exec",
        "--cd",
        str(project),
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--output-schema",
        str(schema_path),
        "--output-last-message",
        str(output_path),
        "-",
    ]
    try:
        result = subprocess.run(
            command,
            input=prompt,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "passed": False, "reason": "codex_cli_timeout", "timeout_seconds": timeout_seconds}
    output_text = output_path.read_text(encoding="utf-8", errors="replace") if output_path.exists() else ""
    if result.returncode != 0:
        return {
            "available": True,
            "passed": False,
            "reason": "codex_cli_failed",
            "returncode": result.returncode,
            "stderr_tail": result.stderr[-1200:],
            "stdout_tail": result.stdout[-1200:],
        }
    try:
        parsed = _parse_codex_output(output_text)
    except Exception as exc:
        return {
            "available": True,
            "passed": False,
            "reason": "codex_cli_output_parse_failed",
            "error": str(exc),
            "output_tail": output_text[-1200:],
        }
    return {
        "available": True,
        "passed": True,
        "returncode": result.returncode,
        "analysis": parsed,
        "prompt_hash": stable_json_hash({"prompt": prompt}),
        "output_hash": stable_json_hash(parsed),
    }


def _cleanup_intake_work_dir(work_dir: Path) -> None:
    keep = os.environ.get("ITHZ_MCP_KEEP_INTAKE_ARTIFACTS", "").strip().lower() in {"1", "true", "yes", "on"}
    if keep:
        return
    shutil.rmtree(work_dir, ignore_errors=True)


def _deterministic_analysis(project: Path, summary: dict[str, Any], excerpts: list[dict[str, Any]]) -> dict[str, Any]:
    workflow_rules: list[str] = []
    project_decisions: list[str] = []
    gate_rules: list[str] = []
    risk_rules: list[str] = []
    project_summary: list[str] = [
        f"Project has {summary.get('file_count', 0)} indexable files and {summary.get('ignored_count', 0)} ignored files under ITHZ-MCP safety rules.",
        "First intake used deterministic fallback because host model intake was not available or was disabled.",
    ]
    for excerpt in excerpts:
        if not excerpt.get("included"):
            continue
        path = excerpt.get("path", "")
        for raw in str(excerpt.get("text", "")).splitlines():
            line = re.sub(r"\s+", " ", raw.strip(" -*#\t"))
            if not line:
                continue
            lower = line.lower()
            tagged = f"{path}: {line[:700]}"
            if any(token in lower for token in ("decision", "rozhodnutie", "architecture", "accepted")):
                project_decisions.append(tagged)
            elif any(token in lower for token in ("gate", "test", "deploy", "validation", "prejde", "failed", "passed")):
                gate_rules.append(tagged)
            elif any(token in lower for token in ("risk", "nesmie", "must not", "secret", "limitation", "do not")):
                risk_rules.append(tagged)
            elif any(token in lower for token in ("workflow", "commit", "ssh", "agent", "codex", "install", "next")):
                workflow_rules.append(tagged)
    return {
        "project_summary": project_summary[:8],
        "workflow_rules": workflow_rules[:12],
        "project_decisions": project_decisions[:12],
        "gate_rules": gate_rules[:12],
        "risk_rules": risk_rules[:12],
        "candidate_files": [str(row.get("path")) for row in summary.get("top_files", [])[:20]],
        "next_steps": ["Ask ITHZ-MCP for a task-specific context pack before broad source reading."],
        "evidence_gaps": ["No host LLM analysis was recorded in this intake."],
        "confidence": "medium" if (workflow_rules or project_decisions or gate_rules or risk_rules) else "low",
    }


def _clean_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    cleaned = []
    for value in values:
        safe = _safe_text(str(value).strip())
        if not safe["text"] or safe["blocked_after_redaction"]:
            continue
        cleaned.append(safe["text"][:900])
        if len(cleaned) >= MAX_FACTS_PER_CATEGORY:
            break
    return cleaned


def _analysis_to_memory(
    project: Path,
    analysis: dict[str, Any],
    profile: str,
    source: str,
    native_exe: str | None,
) -> dict[str, Any]:
    instruction_specs: list[dict[str, Any]] = []
    mapping = (
        ("workflow_rules", "workflow_rule"),
        ("project_decisions", "project_decision"),
        ("gate_rules", "gate_rule"),
        ("risk_rules", "risk_rule"),
    )
    for key, instruction_type in mapping:
        for text in _clean_list(analysis.get(key)):
            instruction_specs.append(
                {
                    "instruction_type": instruction_type,
                    "text": text,
                    "profile": profile,
                    "scope": "project",
                    "source": source,
                    "tags": ["first_install", "agent_intake", key],
                    "metadata": {"agent_intake_schema": INTAKE_SCHEMA, "confidence": analysis.get("confidence", "")},
                }
            )
    instruction_result = None
    if instruction_specs:
        instruction_result = record_durable_instructions(project, instruction_specs, native_exe=native_exe, memory_zone="current")

    events: list[dict[str, Any]] = []
    for key, kind in (
        ("project_summary", "note"),
        ("candidate_files", "note"),
        ("next_steps", "next"),
        ("evidence_gaps", "risk"),
    ):
        for text in _clean_list(analysis.get(key)):
            events.append(
                {
                    "kind": kind,
                    "text": f"Agent intake {key}: {text}",
                    "source": source,
                    "tags": ["first_install", "agent_intake", key],
                    "metadata": {"agent_intake_schema": INTAKE_SCHEMA, "confidence": analysis.get("confidence", "")},
                }
            )
    event_result = None
    if events:
        event_result = archive_append_events(project, events, native_exe=native_exe, memory_zone="current")
    return {
        "instruction_count": len(instruction_specs),
        "event_count": len(events),
        "instruction_result": {
            "new_record_count": instruction_result.get("new_record_count"),
            "deduplicated_count": instruction_result.get("deduplicated_count"),
            "instruction_index_hash": instruction_result.get("instruction_index_hash"),
        } if isinstance(instruction_result, dict) else None,
        "event_result": {
            "appended_count": event_result.get("appended_count"),
            "event_count": event_result.get("event_count"),
            "current_index_hash": event_result.get("current_index_hash"),
        } if isinstance(event_result, dict) else None,
    }


def first_project_agent_intake(
    project: Path,
    owner: str = "",
    profile: str = "default",
    mode: str = "auto",
    native_exe: str | None = None,
) -> dict[str, Any]:
    project = project.resolve()
    if mode not in {"auto", "codex-cli", "deterministic-only", "off"}:
        raise ValueError("agent_intake mode must be auto, codex-cli, deterministic-only, or off")
    if mode == "off":
        return {"schema": INTAKE_SCHEMA, "project": str(project), "ran": False, "mode": "off", "reason": "disabled"}
    if not project_archive_path(project).exists():
        build_native_archive(project, native_exe)
    scan = scan_project_for_archive(project)
    summary = _scan_summary_from_scan(scan)
    excerpts = _read_doc_excerpts(project, scan)
    repo_dossier = _build_repo_dossier(project, scan, summary)
    context_pack = native_archive_context_pack(project, DEFAULT_QUERY, MAX_CONTEXT_BYTES, native_exe, "current")
    prompt = _intake_prompt(project, owner, profile, context_pack["text"], summary, excerpts, repo_dossier)
    work_dir = project / ".ithz-install" / "tmp" / "agent_intake"
    codex_result = {"available": bool(codex_cli_path()), "passed": False, "reason": "not_requested"}
    analysis_source = "agent_intake_deterministic"
    fallback_reason = ""
    if mode in {"auto", "codex-cli"}:
        codex_result = _run_codex_intake(project, prompt, work_dir)
        _cleanup_intake_work_dir(work_dir)
        if codex_result.get("passed"):
            analysis = codex_result["analysis"]
            analysis_source = "agent_intake_codex_cli"
        elif mode == "codex-cli":
            return {
                "schema": INTAKE_SCHEMA,
                "project": str(project),
                "ran": False,
                "mode": mode,
                "codex_cli_available": codex_result.get("available", False),
                "codex_cli_result": {k: v for k, v in codex_result.items() if k != "analysis"},
                "reason": codex_result.get("reason", "codex_cli_failed"),
                "manual_host_intake_required": True,
            }
        else:
            fallback_reason = str(codex_result.get("reason", "codex_cli_unavailable_or_failed"))
            analysis = _deterministic_analysis(project, summary, excerpts)
    else:
        fallback_reason = "deterministic_only_requested"
        analysis = _deterministic_analysis(project, summary, excerpts)
    memory = _analysis_to_memory(project, analysis, profile, analysis_source, native_exe)
    return {
        "schema": INTAKE_SCHEMA,
        "project": str(project),
        "ran": True,
        "mode": mode,
        "analysis_source": analysis_source,
        "codex_cli_available": codex_result.get("available", False),
        "codex_cli_passed": codex_result.get("passed", False),
        "codex_cli_reason": codex_result.get("reason", ""),
        "fallback_reason": fallback_reason,
        "manual_host_intake_required": analysis_source != "agent_intake_codex_cli",
        "confidence": analysis.get("confidence", ""),
        "summary_item_count": len(_clean_list(analysis.get("project_summary"))),
        "workflow_rule_count": len(_clean_list(analysis.get("workflow_rules"))),
        "decision_count": len(_clean_list(analysis.get("project_decisions"))),
        "gate_rule_count": len(_clean_list(analysis.get("gate_rules"))),
        "risk_rule_count": len(_clean_list(analysis.get("risk_rules"))),
        "candidate_file_count": len(_clean_list(analysis.get("candidate_files"))),
        "evidence_gap_count": len(_clean_list(analysis.get("evidence_gaps"))),
        "repo_scale": repo_dossier.get("project_scale"),
        "repo_intake_strategy": repo_dossier.get("intake_strategy"),
        "repo_intake_dossier_hash": repo_dossier.get("dossier_hash"),
        "repo_intake_candidate_count": len(repo_dossier.get("candidate_files", [])),
        "repo_intake_excerpt_count": len(repo_dossier.get("source_excerpts", [])),
        "repo_intake_prompt_bytes": len(prompt.encode("utf-8")),
        "intake_hash": stable_json_hash({"source": analysis_source, "analysis": analysis}),
        "memory": memory,
    }
