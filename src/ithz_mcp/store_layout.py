from __future__ import annotations

from pathlib import Path
from typing import Any

from .context_index import build_index, load_or_build_index
from .storage import read_json, state_dir, write_json

PREFERRED_STORE = ".ithz-context"
LEGACY_STORE = ".ithz_mcp"

STORE_DIRS = (
    "checkpoints",
    "decisions",
    "prompts",
    "responses",
    "conversations",
    "prompt-summaries",
    "experiment-results",
    "context-commits",
    "refs",
    "branches",
    "packs",
    "logs",
    "tmp",
)


def preferred_state_dir(project: Path) -> Path:
    return project / PREFERRED_STORE


def ensure_context_store(project: Path) -> dict[str, Any]:
    project = project.resolve()
    store = preferred_state_dir(project)
    store.mkdir(parents=True, exist_ok=True)
    for rel in STORE_DIRS:
        (store / rel).mkdir(parents=True, exist_ok=True)
    index_hash = None
    project_hash = None
    legacy = state_dir(project)
    if legacy.exists() and (legacy / "index" / "index.json").exists():
        try:
            index = load_or_build_index(project)
            index_hash = index.get("index_hash")
            project_hash = index.get("project_semantic_hash")
        except Exception:
            pass
    config = {
        "schema": "ithz_context_store_config_v1",
        "storage_version": 1,
        "preferred_store_dir": PREFERRED_STORE,
        "legacy_store_dir": LEGACY_STORE,
        "compatibility_mode": legacy.exists(),
        "project_semantic_hash": project_hash,
        "index_hash": index_hash,
        "last_context_commit": None,
        "prompt_memory": "summary",
    }
    write_json(store / "config.json", config)
    (store / "project_context.jsonl").touch(exist_ok=True)
    (store / "index.json").write_text("{}\n", encoding="utf-8")
    return {"project": str(project), "store": str(store), "config": config}


def context_store_status(project: Path) -> dict[str, Any]:
    project = project.resolve()
    preferred = preferred_state_dir(project)
    legacy = state_dir(project)
    config = read_json(preferred / "config.json", None)
    return {
        "project": str(project),
        "preferred_store_dir": str(preferred),
        "preferred_exists": preferred.exists(),
        "legacy_store_dir": str(legacy),
        "legacy_exists": legacy.exists(),
        "config": config,
        "context_status_compatible": preferred.exists() or legacy.exists(),
    }


def migration_dry_run(project: Path, from_name: str = LEGACY_STORE, to_name: str = PREFERRED_STORE, apply: bool = False) -> dict[str, Any]:
    project = project.resolve()
    src = project / from_name
    dst = project / to_name
    plan = {
        "project": str(project),
        "from": from_name,
        "to": to_name,
        "source_exists": src.exists(),
        "destination_exists": dst.exists(),
        "apply": apply,
        "would_copy_files": [],
        "requires_backup": True,
        "destructive": False,
    }
    if src.exists():
        plan["would_copy_files"] = [str(p.relative_to(src)).replace("\\", "/") for p in sorted(src.rglob("*")) if p.is_file()][:200]
    if apply:
        raise ValueError("apply_migration_not_enabled_in_mcp10")
    return plan
