from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty
from .context_pack import build_context_pack
from .hashing import stable_json_hash
from .safety import normalize_rel
from .storage import write_json

NATIVE_DOC_NAMES = {
    "README_NATIVE_ITHZ.md",
    "ITHZ_CFC_RESULTS.md",
    "RESULTS_INDEX.md",
    "EXPERIMENTS.md",
    "ITHZ_QUICKSTART.md",
    "ITHZ_LIMITATIONS.md",
    "native_ithz_refactor_file_map.md",
}

NATIVE_IGNORE_EXTS = {".ithz", ".exe", ".dll", ".pdb", ".obj", ".lib", ".zip"}
NATIVE_IGNORE_PARTS = {"build", "build_avx2", "dist", ".git", "node_modules", "decoded_cpp_archive", "python_decoded_cpp_archive", "smoke_work", "tmp"}


def _is_ignored(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if any(p in parts for p in NATIVE_IGNORE_PARTS):
        return True
    return path.suffix.lower() in NATIVE_IGNORE_EXTS


def _phase_id(path: Path, text: str = "") -> str:
    blob = path.name + "\n" + text[:1000]
    m = re.search(r"\b(P\d+[A-Z]?(?:\.\d+)?|MCP\d+[A-Z]?|P\d+R\d*|P\d+R)\b", blob, re.I)
    if m:
        return m.group(1).upper()
    m = re.search(r"native_ithz_(p\d+[a-z]?)", path.name, re.I)
    return m.group(1).upper() if m else "GENERAL"


def _category(phase_id: str, path: Path, text: str) -> str:
    hay = (phase_id + " " + path.name + " " + text[:2000]).lower()
    if "safety" in hay or "corruption" in hay or "extract" in hay:
        return "safety"
    if "perf" in hay or "throughput" in hay or "decode" in hay:
        return "performance"
    if "package" in hay or "release" in hay or "rc" in hay:
        return "packaging"
    if "metadata" in hay or "attribution" in hay:
        return "metadata"
    if "beta" in hay or "real" in hay:
        return "beta"
    if "refactor" in hay:
        return "refactor"
    if "auto" in hay or "mixed" in hay:
        return "auto_mixed"
    if "diagnostic" in hay or "gap" in hay:
        return "diagnostics"
    return "archive_core"


def _extract_key_numbers(text: str) -> list[str]:
    rows = []
    for line in text.splitlines():
        if re.search(r"\b(passed|ok|bytes|hash|decoded|unique|archive|payload|input|safe|gate)\b", line, re.I) and re.search(r"\d", line):
            rows.append(line.strip()[:240])
    return rows[:12]


def _csv_summary(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, [])
            rows = sum(1 for _ in reader)
        return {"path": str(path), "header": header, "row_count": rows}
    except Exception as exc:
        return {"path": str(path), "error": str(exc), "row_count": 0, "header": []}


def discover_native_artifacts(workspace: Path) -> list[Path]:
    candidates: list[Path] = []
    for name in NATIVE_DOC_NAMES:
        for path in (workspace / name, workspace / "docs" / name):
            if path.exists() and path.is_file() and not _is_ignored(path):
                candidates.append(path)
    for rel in ("docs",):
        base = workspace / rel
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or _is_ignored(p):
                continue
            if p.suffix.lower() in {".md", ".csv", ".json"} and (p.name in NATIVE_DOC_NAMES or "native_ithz" in normalize_rel(p.relative_to(workspace)).lower() or "ITHZ" in p.name or p.suffix.lower() == ".csv"):
                if p.stat().st_size <= 2_000_000:
                    candidates.append(p)
    raw = workspace / "experiments" / "06_ithz_archive" / "raw" / "native_ithz"
    if raw.exists():
        for p in raw.iterdir():
            if p.is_file() and not _is_ignored(p) and p.suffix.lower() in {".md", ".csv", ".json"} and p.stat().st_size <= 2_000_000:
                candidates.append(p)
    return sorted(set(candidates), key=lambda p: normalize_rel(p.relative_to(workspace)))


def import_native_ithz(workspace: Path, project: Path) -> dict[str, Any]:
    workspace = workspace.resolve()
    project = project.resolve()
    artifacts = discover_native_artifacts(workspace)
    store = project / ".ithz-context" / "native_ithz"
    store.mkdir(parents=True, exist_ok=True)
    phase_map: dict[str, dict[str, Any]] = {}
    artifact_rows = []
    matrix_count = 0
    summary_count = 0
    for path in artifacts:
        rel = normalize_rel(path.relative_to(workspace))
        if path.suffix.lower() == ".csv":
            matrix_count += 1
            csv_meta = _csv_summary(path)
            phase_id = _phase_id(path)
            artifact_rows.append({"path": rel, "type": "matrix", "phase_id": phase_id, "bytes": path.stat().st_size, "csv": csv_meta})
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
            phase_id = _phase_id(path, text)
            if "summary" in path.name.lower() or path.suffix.lower() == ".md":
                summary_count += 1
            artifact_rows.append({"path": rel, "type": path.suffix.lower().lstrip("."), "phase_id": phase_id, "bytes": path.stat().st_size})
            phase = phase_map.setdefault(
                phase_id,
                {
                    "phase_id": phase_id,
                    "title": phase_id,
                    "category": _category(phase_id, path, text),
                    "status": "indexed",
                    "summary_file": rel,
                    "matrix_files": [],
                    "key_numbers": [],
                    "cautious_interpretation": [],
                    "forbidden_claims": ["no general ZIP/tar.gz superiority claim", "no production replacement claim"],
                    "next_candidates": [],
                    "gates_passed": [],
                    "known_risks": [],
                },
            )
            phase["key_numbers"].extend(_extract_key_numbers(text))
            for line in text.splitlines():
                lower = line.lower()
                if "claim" in lower or "interpret" in lower:
                    phase["cautious_interpretation"].append(line.strip()[:240])
                if "next" in lower or "candidate" in lower:
                    phase["next_candidates"].append(line.strip()[:240])
                if "gate" in lower or "passed" in lower:
                    phase["gates_passed"].append(line.strip()[:240])
                if "risk" in lower or "limitation" in lower:
                    phase["known_risks"].append(line.strip()[:240])
        if path.suffix.lower() == ".csv":
            phase_map.setdefault(
                artifact_rows[-1]["phase_id"],
                {
                    "phase_id": artifact_rows[-1]["phase_id"],
                    "title": artifact_rows[-1]["phase_id"],
                    "category": _category(artifact_rows[-1]["phase_id"], path, ""),
                    "status": "indexed",
                    "summary_file": "",
                    "matrix_files": [],
                    "key_numbers": [],
                    "cautious_interpretation": [],
                    "forbidden_claims": ["no general ZIP/tar.gz superiority claim"],
                    "next_candidates": [],
                    "gates_passed": [],
                    "known_risks": [],
                },
            )["matrix_files"].append(rel)
    phases = sorted(phase_map.values(), key=lambda p: p["phase_id"])
    for phase in phases:
        for key in ("key_numbers", "cautious_interpretation", "next_candidates", "gates_passed", "known_risks"):
            phase[key] = phase[key][:12]
    index_hash = stable_json_hash({"phases": phases, "artifacts": artifact_rows})
    write_json(store / "phase_index.json", {"schema": "native_ithz_phase_index_v1", "workspace": str(workspace), "index_hash": index_hash, "phases": phases})
    write_json(store / "artifact_index.json", {"schema": "native_ithz_artifact_index_v1", "workspace": str(workspace), "index_hash": index_hash, "artifacts": artifact_rows})
    return {
        "workspace": str(workspace),
        "project": str(project),
        "phase_count": len(phases),
        "summary_count": summary_count,
        "matrix_count": matrix_count,
        "artifact_count": len(artifact_rows),
        "index_hash": index_hash,
        "store": str(store),
        "phases": phases,
        "artifacts": artifact_rows,
    }


def native_status(workspace: Path) -> dict[str, Any]:
    artifacts = discover_native_artifacts(workspace.resolve())
    return {
        "workspace": str(workspace.resolve()),
        "artifact_count": len(artifacts),
        "summary_like_count": sum(1 for p in artifacts if p.suffix.lower() == ".md"),
        "matrix_count": sum(1 for p in artifacts if p.suffix.lower() == ".csv"),
        "binary_included": any(p.suffix.lower() == ".ithz" for p in artifacts),
    }


def native_context_pack(project: Path, query: str, max_bytes: int = 20000) -> dict[str, Any]:
    store = project.resolve() / ".ithz-context" / "native_ithz"
    phase_index = {}
    artifact_index = {}
    if (store / "phase_index.json").exists():
        import json
        phase_index = json.loads((store / "phase_index.json").read_text(encoding="utf-8"))
    if (store / "artifact_index.json").exists():
        import json
        artifact_index = json.loads((store / "artifact_index.json").read_text(encoding="utf-8"))
    terms = [t.lower() for t in re.findall(r"[A-Za-z0-9_.:-]+", query)]
    matches = []
    for phase in phase_index.get("phases", []):
        hay = dump_pretty(phase).lower()
        score = sum(1 for t in terms if t in hay)
        if score:
            matches.append((score, phase["phase_id"], phase))
    matches.sort(key=lambda x: (-x[0], x[1]))
    selected_phases = [m[2] for m in matches[:12]]
    selected_files = sorted(
        {
            p
            for phase in selected_phases
            for p in ([phase.get("summary_file", "")] + list(phase.get("matrix_files", [])))
            if p
        }
    )
    selected_decisions = []
    selected_gates = []
    selected_risks = []
    selected_forbidden = []
    for phase in selected_phases:
        selected_decisions.extend(phase.get("cautious_interpretation", [])[:4])
        selected_gates.extend(phase.get("gates_passed", [])[:6])
        selected_risks.extend(phase.get("known_risks", [])[:5])
        selected_forbidden.extend(phase.get("forbidden_claims", [])[:4])
    lines = [
        "# Native ITHZ Context Pack",
        "",
        f"- query: {query}",
        f"- phase_index_hash: {phase_index.get('index_hash')}",
        f"- artifact_count: {len(artifact_index.get('artifacts', []))}",
        "",
        "## Matching Phases",
    ]
    if not matches:
        lines.append("- Not enough evidence found.")
    for _, _, phase in matches[:12]:
        lines.append(f"### {phase['phase_id']} - {phase.get('category')}")
        lines.append(f"- summary_file: {phase.get('summary_file')}")
        lines.append(f"- matrix_files: {', '.join(phase.get('matrix_files', [])[:5])}")
        for number in phase.get("key_numbers", [])[:5]:
            lines.append(f"- key: {number}")
        for interp in phase.get("cautious_interpretation", [])[:3]:
            lines.append(f"- interpretation: {interp}")
        for nxt in phase.get("next_candidates", [])[:3]:
            lines.append(f"- next: {nxt}")
    lines += ["", "## Selected Files"]
    for path in selected_files[:24]:
        lines.append(f"- {path}")
    lines += ["", "## Selected Gates"]
    for gate in selected_gates[:18]:
        lines.append(f"- {gate}")
    lines += ["", "## Selected Risks / Must Not Break"]
    for risk in selected_risks[:18]:
        lines.append(f"- {risk}")
    lines += ["", "## Forbidden Claims"]
    for claim in sorted(set(selected_forbidden))[:12]:
        lines.append(f"- {claim}")
    if not selected_gates and not selected_risks:
        lines += ["", "## Evidence Gaps", "- No focused gate or risk evidence matched; run a narrower query."]
    text = "\n".join(lines).strip() + "\n"
    if len(text.encode("utf-8")) > max_bytes:
        text = text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore") + "\n[truncated]\n"
    return {
        "text": text,
        "context_pack_hash": stable_json_hash({"query": query, "matches": selected_phases}),
        "bytes": len(text.encode("utf-8")),
        "match_count": len(matches),
        "selected_phases": [p["phase_id"] for p in selected_phases],
        "selected_files": selected_files,
        "selected_decisions": selected_decisions[:24],
        "selected_gates": selected_gates[:24],
        "selected_risks": selected_risks[:24],
        "selected_forbidden_claims": sorted(set(selected_forbidden))[:24],
        "evidence_gaps": [] if selected_phases else ["no_matching_phase"],
    }
