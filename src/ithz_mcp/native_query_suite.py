from __future__ import annotations

from pathlib import Path
from typing import Any

from .native_ithz_adapter import import_native_ithz, native_context_pack


NATIVE_QUERY_SUITE_V2 = [
    "What is the current native_ithz status?",
    "What did P15A find?",
    "What did P16A estimate?",
    "What did P17A physically confirm?",
    "Why was P17B not promoted?",
    "What is the default verify mode?",
    "What must not be broken in extraction safety?",
    "Which claims are forbidden?",
    "What are the next likely native_ithz candidates?",
    "Which files should Codex inspect before changing native_ithz?",
    "What gates protect old golden archives?",
    "What is the difference between p9-v3 and p9-v4 experimental?",
    "What does P10 safety protect?",
    "What does P14.5 package contain?",
    "Why should p9-v4 remain experimental?",
]


def run_native_query_suite(workspace: Path, project: Path, max_bytes: int = 20000) -> dict[str, Any]:
    imported = import_native_ithz(workspace, project)
    rows: list[dict[str, Any]] = []
    packs: list[str] = ["# MCP11C Native ITHZ Query Suite v2", ""]
    for query in NATIVE_QUERY_SUITE_V2:
        pack = native_context_pack(project, query, max_bytes)
        rows.append(
            {
                "query": query,
                "passed": pack["bytes"] <= max_bytes and ".ithz" not in pack["text"].lower(),
                "bytes": pack["bytes"],
                "match_count": pack["match_count"],
                "selected_phases": ";".join(pack.get("selected_phases", [])),
                "selected_files": ";".join(pack.get("selected_files", [])[:10]),
                "selected_decisions_count": len(pack.get("selected_decisions", [])),
                "selected_gates_count": len(pack.get("selected_gates", [])),
                "selected_risks_count": len(pack.get("selected_risks", [])),
                "selected_forbidden_claims_count": len(pack.get("selected_forbidden_claims", [])),
                "evidence_gaps": ";".join(pack.get("evidence_gaps", [])),
                "context_pack_hash": pack["context_pack_hash"],
            }
        )
        packs += [f"## {query}", "", pack["text"][:5000], ""]
    return {"import": imported, "rows": rows, "packs_text": "\n".join(packs)}
