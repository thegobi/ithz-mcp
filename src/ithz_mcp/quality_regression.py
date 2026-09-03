from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .context_pack import build_context_pack
from .hashing import stable_json_hash
from .native_ithz_adapter import import_native_ithz, native_context_pack


def load_expectations(repo: Path) -> list[dict[str, Any]]:
    base = repo / "tests" / "quality_expectations"
    rows: list[dict[str, Any]] = []
    for path in sorted(base.glob("*.json")):
        rows.append(json.loads(path.read_text(encoding="utf-8")))
    return rows


def _contains_all(text: str, terms: list[str]) -> tuple[bool, list[str]]:
    lower = text.lower()
    missing = [term for term in terms if term.lower() not in lower]
    return not missing, missing


def _contains_none(text: str, terms: list[str]) -> tuple[bool, list[str]]:
    lower = text.lower()
    present = [term for term in terms if term.lower() in lower]
    return not present, present


def run_quality_regression(repo: Path, workspace: Path | None = None) -> dict[str, Any]:
    repo = repo.resolve()
    workspace = workspace.resolve() if workspace else repo.parent.resolve()
    expectations = load_expectations(repo)
    if not expectations:
        raise ValueError("quality_expectations_missing")
    rows: list[dict[str, Any]] = []
    examples: list[str] = ["# Context Quality Regression Examples", ""]
    import_native = any(exp.get("native") for exp in expectations)
    if import_native:
        import_native_ithz(workspace, repo)
    for exp in expectations:
        if exp.get("native"):
            pack = native_context_pack(repo, exp["query"], int(exp.get("max_bytes", 12000)))
            text = pack["text"]
            pack_hash = pack["context_pack_hash"]
            selected_files = pack.get("selected_files", [])
        else:
            project = (repo / exp["project"]).resolve()
            pack = build_context_pack(project, exp["query"], int(exp.get("max_bytes", 12000)))
            repeat = build_context_pack(project, exp["query"], int(exp.get("max_bytes", 12000)))
            text = pack["text"]
            pack_hash = pack["semantic_context_pack_hash"]
            selected_files = pack.get("selected_files", [])
            if repeat["semantic_context_pack_hash"] != pack_hash:
                text += "\n[determinism regression]\n"
        checks = {}
        missing_terms: list[str] = []
        for key in ("expected_decision_terms", "expected_gate_terms", "expected_risk_terms", "expected_forbidden_claim_terms"):
            ok, missing = _contains_all(text, list(exp.get(key, [])))
            checks[key] = ok
            missing_terms.extend(missing)
        no_secret, secret_hits = _contains_none(text, list(exp.get("forbidden_secret_terms_absent", [])))
        checks["forbidden_secret_terms_absent"] = no_secret
        max_bytes_ok = len(text.encode("utf-8")) <= int(exp.get("max_bytes", 12000))
        checks["max_bytes"] = max_bytes_ok
        row = {
            "name": exp["name"],
            "project": exp.get("project", "native_ithz"),
            "query": exp["query"],
            "passed": all(checks.values()),
            "context_bytes": len(text.encode("utf-8")),
            "context_pack_hash": pack_hash,
            "selected_file_count": len(selected_files),
            "missing_terms": ";".join(missing_terms),
            "secret_hits": ";".join(secret_hits),
            "checks_hash": stable_json_hash(checks),
        }
        rows.append(row)
        examples += [f"## {exp['name']}", "", text[:3000], ""]
    return {"rows": rows, "examples_text": "\n".join(examples), "passed": all(bool(r["passed"]) for r in rows)}
