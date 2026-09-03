from __future__ import annotations

from urllib.parse import quote

MCP_BRAND_NAME = "ithz-mcp"
MCP_BRAND_TITLE = "ITHZ-MCP"
MCP_BRAND_DESCRIPTION = "Deterministic project memory for AI agents."
MCP_ICON_RELATIVE_PATH = "src/ithz_mcp/assets/ithz-mcp.svg"

MCP_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 32 32" fill="none">
  <rect width="32" height="32" rx="7" fill="#071015"/>
  <path d="M16 3 27 9.5v13L16 29 5 22.5v-13L16 3Z" stroke="#18E1D1" stroke-width="2" stroke-linejoin="round"/>
  <path d="M10 12.5 16 9l6 3.5v7L16 23l-6-3.5v-7Z" stroke="#D8F6F1" stroke-width="1.7" stroke-linejoin="round"/>
  <path d="M16 9v14M10 12.5l12 7M22 12.5l-12 7" stroke="#18E1D1" stroke-width="1.4" stroke-linecap="round"/>
</svg>"""

MCP_ICON_DATA_URI = "data:image/svg+xml;utf8," + quote(MCP_ICON_SVG, safe=":/#?&=,;+-._~%")


def mcp_icon_metadata() -> dict[str, str]:
    return {
        "display_name": MCP_BRAND_TITLE,
        "description": MCP_BRAND_DESCRIPTION,
        "icon_type": "image/svg+xml",
        "icon_path": MCP_ICON_RELATIVE_PATH,
        "icon_data_uri": MCP_ICON_DATA_URI,
    }
