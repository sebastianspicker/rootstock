"""
report_diagrams.py — Mermaid diagram generation for Rootstock security reports.

All functions are pure (no Neo4j dependency) — they take query result dicts
and return formatted diagram strings suitable for embedding in Markdown.
"""

from __future__ import annotations

import re


# ── Helpers ───────────────────────────────────────────────────────────────────

def sanitize_mermaid_id(text: str) -> str:
    """Convert arbitrary strings to safe Mermaid node IDs (alphanumeric + underscore)."""
    if not text:
        return "node"
    return re.sub(r"[^a-zA-Z0-9_]", "_", text)


def _truncate(text: str, max_len: int = 30) -> str:
    """Truncate long labels for diagram readability."""
    return text if len(text) <= max_len else text[:max_len - 1] + "…"


# ── TCC Node Detection ────────────────────────────────────────────────────────

_TCC_KEYWORDS = {
    "full disk access", "accessibility", "screen recording",
    "microphone", "camera", "location", "contacts", "calendar",
    "reminders", "photos", "bluetooth", "homekit", "health",
    "appleevents", "developer tools",
}


def _is_tcc_node(name: str) -> bool:
    """Heuristic: is this node a TCC permission node?"""
    lower = name.lower()
    return any(kw in lower for kw in _TCC_KEYWORDS) or name.startswith("kTCC")


# ── Mermaid Attack Path Flowchart ─────────────────────────────────────────────

def mermaid_attack_path(path_result: dict) -> str:
    """
    Generate a Mermaid LR flowchart for a single attack path.

    Args:
        path_result: dict with keys:
            - node_names: list[str] — display names of nodes in path
            - rel_types:  list[str] — relationship types between nodes
            - path_length: int

    Returns:
        Mermaid flowchart string (fenced code block), or "" if path is empty.
    """
    nodes: list[str] = path_result.get("node_names") or []
    rels: list[str] = path_result.get("rel_types") or []

    if not nodes or len(nodes) < 2:
        return ""

    # Ensure nodes and rels are consistent lengths
    edge_count = min(len(nodes) - 1, len(rels))
    nodes = nodes[: edge_count + 1]
    rels = rels[:edge_count]

    lines = ["```mermaid", "graph LR"]

    # Unique node IDs: sanitize name + index suffix to avoid collisions
    ids = [sanitize_mermaid_id(n) + str(i) for i, n in enumerate(nodes)]

    for name, node_id in zip(nodes, ids):
        label = _truncate(name)
        lines.append(f'  {node_id}["{label}"]')

    for i in range(edge_count):
        src = ids[i]
        dst = ids[i + 1]
        rel = rels[i]
        lines.append(f"  {src} -->|{rel}| {dst}")

    # Style: TCC permission nodes red, attacker node orange
    for name, node_id in zip(nodes, ids):
        if _is_tcc_node(name):
            lines.append(f"  style {node_id} fill:#ff6666,color:#fff")
        elif "attacker" in name.lower():
            lines.append(f"  style {node_id} fill:#ff9933,color:#fff")

    lines.append("```")
    return "\n".join(lines)


def mermaid_attack_paths_block(path_rows: list[dict], max_paths: int = 3) -> str:
    """
    Generate Mermaid diagrams for the top N attack paths.
    Falls back to text representation when diagram generation fails.
    """
    if not path_rows:
        return "_No attack paths found._"

    parts = []
    for i, row in enumerate(path_rows[:max_paths]):
        hops = row.get("path_length", "?")
        parts.append(f"**Path {i + 1}** ({hops} hop{'s' if hops != 1 else ''})")
        diagram = mermaid_attack_path(row)
        if diagram:
            parts.append(diagram)
        else:
            # Text fallback for paths that can't be diagrammed
            names = row.get("node_names") or []
            rel_types = row.get("rel_types") or []
            steps: list[str] = []
            for j, name in enumerate(names):
                steps.append(f"`{name}`")
                if j < len(rel_types):
                    steps.append(f"→ _{rel_types[j]}_ →")
            parts.append(" ".join(steps))
        parts.append("")

    return "\n".join(parts)


# ── Mermaid Pie Chart ─────────────────────────────────────────────────────────

def mermaid_tcc_pie(rows: list[dict], top_n: int = 10) -> str:
    """
    Generate a Mermaid pie chart of TCC grant distribution.

    Args:
        rows: list of dicts with keys 'permission' (str) and 'total_grants' (int)
        top_n: include only the top N permissions by grant count

    Returns:
        Mermaid pie chart string (fenced code block), or a "no data" message.
    """
    if not rows:
        return "_No TCC grant data available._"

    sorted_rows = sorted(rows, key=lambda r: r.get("total_grants", 0), reverse=True)
    top = sorted_rows[:top_n]

    lines = ["```mermaid", "pie title TCC Permission Distribution"]
    for row in top:
        label = row.get("permission", "Unknown")
        count = row.get("total_grants", 0)
        safe_label = label.replace('"', "'")
        lines.append(f'  "{safe_label}" : {count}')
    lines.append("```")
    return "\n".join(lines)
