from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any

from .canonical_json import dump_pretty
from .mcp_config import config_template
from .storage import write_json

HOSTS = ("codex", "claude-code", "antigravity", "cursor", "generic-jsonrpc")


def _known_host_paths(client: str) -> list[Path]:
    appdata = Path(os.environ.get("APPDATA", ""))
    localappdata = Path(os.environ.get("LOCALAPPDATA", ""))
    home = Path.home()
    if client == "codex":
        return [home / ".codex" / "config.toml"]
    if client == "claude-code":
        return [home / ".claude", appdata / "Claude"]
    if client == "antigravity":
        return [appdata / "Antigravity", localappdata / "Antigravity", home / ".antigravity"]
    if client == "cursor":
        return [appdata / "Cursor", localappdata / "Programs" / "Cursor", home / ".cursor"]
    return []


def detect_host(client: str) -> dict[str, Any]:
    commands = {
        "codex": ["codex"],
        "claude-code": ["claude"],
        "antigravity": ["antigravity", "antigravity.cmd"],
        "cursor": ["cursor", "cursor.cmd"],
        "generic-jsonrpc": [],
    }.get(client, [])
    command_path = next((shutil.which(cmd) for cmd in commands if shutil.which(cmd)), None)
    paths = [p for p in _known_host_paths(client) if p.exists()]
    return {
        "client": client,
        "available": bool(command_path or paths or client == "generic-jsonrpc"),
        "command": command_path or "",
        "detected_paths": [str(p) for p in paths],
        "real_host_smoke_supported": bool(command_path and client in {"codex"}),
        "real_host_smoke_note": "scripted stdio smoke is authoritative unless host-specific noninteractive MCP smoke is available",
    }


def _server_command(launcher: Path | None) -> str:
    return str(launcher.resolve()) if launcher else sys.executable


def _server_args(
    project: Path,
    mode: str = "read-only",
    protocol: str = "mcp",
    portable_launcher: bool = False,
    storage_profile: str = "native-archive",
) -> list[str]:
    args = [] if portable_launcher else ["-m", "ithz_mcp"]
    args.extend(
        [
            "mcp-server",
            "--project",
            str(project.resolve()),
            "--mode",
            mode,
            "--protocol",
            protocol,
            "--storage-profile",
            storage_profile,
        ]
    )
    return args


def host_config(
    project: Path,
    client: str,
    launcher: Path | None = None,
    mode: str = "read-only",
    storage_profile: str = "native-archive",
) -> dict[str, Any]:
    cfg = config_template(project, client, storage_profile=storage_profile, mode=mode)
    server = cfg.get("server") or cfg.get("mcpServers", {}).get("ithz-mcp")
    if isinstance(server, dict):
        server["command"] = _server_command(launcher)
        protocol = server.get("protocol", "mcp")
        server["args"] = _server_args(
            project,
            mode,
            protocol,
            portable_launcher=launcher is not None,
            storage_profile=storage_profile,
        )
    return cfg


def _codex_server_block(
    name: str,
    project: Path,
    launcher: Path | None = None,
    mode: str = "read-only",
    storage_profile: str = "native-archive",
) -> str:
    command = _server_command(launcher)
    args = _server_args(project, mode, "mcp", portable_launcher=launcher is not None, storage_profile=storage_profile)
    rendered_args = ", ".join('"' + str(a).replace("\\", "\\\\").replace('"', '\\"') + '"' for a in args)
    rendered_command = command.replace("\\", "\\\\").replace('"', '\\"')
    return (
        f"[mcp_servers.{name}]\n"
        f'command = "{rendered_command}"\n'
        f"args = [{rendered_args}]\n"
        'startup_timeout_sec = 60\n'
    )


def codex_toml_snippet(
    project: Path,
    launcher: Path | None = None,
    mode: str = "read-only",
    storage_profile: str = "native-archive",
) -> str:
    if mode == "write-enabled":
        return _codex_server_block("ithz_mcp_write", project, launcher, "write-enabled", storage_profile)
    return (
        _codex_server_block("ithz_mcp", project, launcher, "read-only", storage_profile)
        + "\n"
        + _codex_server_block("ithz_mcp_write", project, launcher, "write-enabled", storage_profile)
    )


def _write_posix_installers(out_dir: Path, storage_profile: str) -> None:
    common = f"""#!/usr/bin/env sh
set -eu
PROJECT=""
APPLY=0
CONFIG_PATH=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --config-path) CONFIG_PATH="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --help|-h) echo "Usage: $0 [--project PATH] [--config-path PATH] [--apply]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$PROJECT" ]; then PROJECT="$(pwd)"; fi
PROJECT="$(cd "$PROJECT" && pwd)"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PACKAGE_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
LAUNCHER="${{ITHZ_MCP_LAUNCHER:-$PACKAGE_ROOT/ithz_mcp_server.sh}}"
PYTHON="${{PYTHON:-python3}}"
STORAGE_PROFILE="${{ITHZ_MCP_STORAGE_PROFILE:-{storage_profile}}}"
export PYTHONPATH="$PACKAGE_ROOT/src:$PACKAGE_ROOT${{PYTHONPATH:+:$PYTHONPATH}}"
"""
    codex = common + """if [ -z "$CONFIG_PATH" ]; then CONFIG_PATH="$HOME/.codex/config.toml"; fi
if [ "$APPLY" -ne 1 ]; then
  echo "DRY RUN: would append ITHZ-MCP Codex config to $CONFIG_PATH"
  echo "Project: $PROJECT"
  echo "Launcher: $LAUNCHER"
  echo "Storage profile: $STORAGE_PROFILE"
  exit 0
fi
mkdir -p "$(dirname "$CONFIG_PATH")"
if [ -f "$CONFIG_PATH" ]; then cp "$CONFIG_PATH" "$CONFIG_PATH.bak"; fi
ITHZ_PROJECT="$PROJECT" ITHZ_LAUNCHER="$LAUNCHER" ITHZ_STORAGE_PROFILE="$STORAGE_PROFILE" "$PYTHON" - <<'PY' >> "$CONFIG_PATH"
import os
from pathlib import Path
from ithz_mcp.host_install import codex_toml_snippet
project = Path(os.environ["ITHZ_PROJECT"])
launcher = Path(os.environ["ITHZ_LAUNCHER"])
storage_profile = os.environ["ITHZ_STORAGE_PROFILE"]
print()
print(codex_toml_snippet(project, launcher if launcher.exists() else None, storage_profile=storage_profile))
PY
echo "Installed ITHZ-MCP Codex config: $CONFIG_PATH"
"""
    (out_dir / "install_codex_mcp.sh").write_text(codex, encoding="utf-8")

    installers = {
        "claude_code": ("claude-code", ".mcp.json"),
        "cursor": ("cursor", ".cursor/mcp.json"),
        "antigravity": ("antigravity", ".antigravity/mcp.json"),
        "generic_jsonrpc": ("generic-jsonrpc", "ithz_mcp_config.json"),
    }
    for script_name, (client, target_rel) in installers.items():
        body = common + f"""CLIENT="{client}"
if [ -z "$CONFIG_PATH" ]; then CONFIG_PATH="$PROJECT/{target_rel}"; fi
if [ "$APPLY" -ne 1 ]; then
  echo "DRY RUN: would write $CLIENT config to $CONFIG_PATH"
  echo "Project: $PROJECT"
  echo "Launcher: $LAUNCHER"
  echo "Storage profile: $STORAGE_PROFILE"
  exit 0
fi
mkdir -p "$(dirname "$CONFIG_PATH")"
ITHZ_PROJECT="$PROJECT" ITHZ_LAUNCHER="$LAUNCHER" ITHZ_STORAGE_PROFILE="$STORAGE_PROFILE" ITHZ_CLIENT="$CLIENT" ITHZ_CONFIG_PATH="$CONFIG_PATH" "$PYTHON" - <<'PY'
import os
from pathlib import Path
from ithz_mcp.canonical_json import dump_pretty
from ithz_mcp.host_install import host_config
project = Path(os.environ["ITHZ_PROJECT"])
launcher = Path(os.environ["ITHZ_LAUNCHER"])
client = os.environ["ITHZ_CLIENT"]
storage_profile = os.environ["ITHZ_STORAGE_PROFILE"]
config_path = Path(os.environ["ITHZ_CONFIG_PATH"])
cfg = host_config(project, client, launcher if launcher.exists() else None, storage_profile=storage_profile)
config_path.write_text(dump_pretty(cfg), encoding="utf-8")
PY
echo "Installed ITHZ-MCP $CLIENT config: $CONFIG_PATH"
"""
        path = out_dir / f"install_{script_name}_mcp.sh"
        path.write_text(body, encoding="utf-8")
        try:
            path.chmod(0o755)
        except OSError:
            pass
    for script in out_dir.glob("install_*_mcp.sh"):
        try:
            script.chmod(0o755)
        except OSError:
            pass


def write_host_install_bundle(
    project: Path,
    out_dir: Path,
    launcher: Path | None = None,
    storage_profile: str = "native-archive",
) -> dict[str, Any]:
    project = project.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for client in HOSTS:
        if client == "generic-jsonrpc":
            cfg_name = "generic_mcp_config.sample.json"
        else:
            cfg_name = f"{client.replace('-', '_')}_mcp_config.sample.json"
        cfg = host_config(project, client, launcher, storage_profile=storage_profile)
        write_json(out_dir / cfg_name, cfg)
        rows.append({**detect_host(client), "config": cfg_name, "config_written": True})

    (out_dir / "codex_config_snippet.toml").write_text(codex_toml_snippet(project, launcher, storage_profile=storage_profile), encoding="utf-8")
    (out_dir / "install_codex_mcp.ps1").write_text(
        "param([string]$Project='',[string]$ConfigPath=\"$HOME\\.codex\\config.toml\",[switch]$Apply)\n"
        "$ErrorActionPreference='Stop'\n"
        "if ([string]::IsNullOrWhiteSpace($Project)) { $Project = (Get-Location).ProviderPath }\n"
        "$snippet = Get-Content -Raw -Path (Join-Path $PSScriptRoot 'codex_config_snippet.toml')\n"
        "if (-not $Apply) { Write-Host 'DRY RUN: would append/update [mcp_servers.ithz_mcp] and [mcp_servers.ithz_mcp_write] in' $ConfigPath; Write-Host $snippet; exit 0 }\n"
        "if (Test-Path $ConfigPath) { Copy-Item $ConfigPath \"$ConfigPath.bak\" -Force }\n"
        "Add-Content -Path $ConfigPath -Value \"`n$snippet\"\n"
        "Write-Host 'Installed ITHZ-MCP Codex read-only and write-enabled config. Backup:' \"$ConfigPath.bak\"\n",
        encoding="utf-8",
    )
    for client, target in (
        ("claude_code", ".mcp.json"),
        ("cursor", ".cursor\\mcp.json"),
        ("antigravity", ".antigravity\\mcp.json"),
    ):
        script = out_dir / f"install_{client}_mcp.ps1"
        cfg_file = out_dir / f"{client}_mcp_config.sample.json"
        script.write_text(
            "param([string]$Project='',[switch]$Apply)\n"
            "$ErrorActionPreference='Stop'\n"
            "if ([string]::IsNullOrWhiteSpace($Project)) { $Project = (Get-Location).ProviderPath }\n"
            f"$target = Join-Path $Project '{target}'\n"
            f"$source = Join-Path $PSScriptRoot '{cfg_file.name}'\n"
            "if (-not $Apply) { Write-Host 'DRY RUN: would copy' $source 'to' $target; exit 0 }\n"
            "New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null\n"
            "Copy-Item $source $target -Force\n"
            "Write-Host 'Installed ITHZ-MCP MCP config:' $target\n",
            encoding="utf-8",
        )
    _write_posix_installers(out_dir, storage_profile)
    (out_dir / "README_HOST_INSTALLERS.md").write_text(
        "# ITHZ-MCP Host Installers\n\n"
        "These scripts prepare local MCP config files for Codex, Claude Code, Cursor, Antigravity and generic JSON-RPC clients.\n\n"
        "- Windows PowerShell scripts default to dry-run. Pass `-Apply` to write config files.\n"
        "- macOS/Linux POSIX scripts default to dry-run. Pass `--apply` to write config files.\n"
        "- Codex config includes `ithz_mcp` for read-only startup and `ithz_mcp_write` for explicit native auto-checkpoint writes.\n"
        "- Read-only config is the default. The write-enabled profile exposes `ithz_archive_auto_checkpoint` for end-of-task memory writes.\n"
        f"- Generated configs use storage profile `{storage_profile}`. On macOS, use `legacy` unless a macOS `ithz-native` binary is available.\n"
        "- External host UIs and config formats may change; validate with `python -m ithz_mcp mcp-config-validate --config <file>` and `python -m ithz_mcp mcp-client-smoke --config <file>`.\n"
        "- ITHZ-MCP does not replace Git, a production database, cloud sync or every retrieval system.\n",
        encoding="utf-8",
    )
    return {"project": str(project), "out_dir": str(out_dir), "rows": rows, "install_bundle_hash": dump_pretty(rows)}
