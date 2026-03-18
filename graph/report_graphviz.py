"""
report_graphviz.py — Graphviz DOT format export for Rootstock graphs.

CLI: python3 report_graphviz.py --neo4j bolt://localhost:7687 --output graph.dot
     python3 report_graphviz.py --neo4j bolt://localhost:7687 --output graph.dot --render png

Color coding (ROADMAP spec):
  Application    = lightblue
  TCC_Permission = #ff6666  (red)
  Entitlement    = #ffff99  (yellow)
  XPC_Service    = #99ff99  (green)
  LaunchItem     = #ffcc99  (orange)
  MDM_Profile    = #cc99ff  (purple)
  User           = #e0e0e0  (grey)
  Keychain_Item  = #ffe0b2  (peach)

Edge styles:
  solid  = explicit relationships (imported directly from scan data)
  dashed = inferred relationships (CAN_INJECT_INTO, CHILD_INHERITS_TCC, etc.)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from neo4j import GraphDatabase


# ── Color / Style Tables ──────────────────────────────────────────────────────

NODE_COLORS: dict[str, str] = {
    "Application": "lightblue",
    "TCC_Permission": "#ff6666",
    "Entitlement": "#ffff99",
    "XPC_Service": "#99ff99",
    "LaunchItem": "#ffcc99",
    "MDM_Profile": "#cc99ff",
    "User": "#e0e0e0",
    "Keychain_Item": "#ffe0b2",
}

# Relationships inferred at import time (always rendered dashed)
INFERRED_RELS = {"CAN_INJECT_INTO", "CHILD_INHERITS_TCC", "CAN_SEND_APPLE_EVENT"}

MAX_LABEL_LEN = 35


def _safe_dot_id(text: str) -> str:
    """Convert arbitrary text to a safe DOT identifier."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", str(text))


def _truncate(text: str, max_len: int = MAX_LABEL_LEN) -> str:
    return text if len(text) <= max_len else text[:max_len - 1] + "…"


# ── Neo4j Fetch ───────────────────────────────────────────────────────────────

def fetch_graph_data(driver) -> tuple[list[dict], list[dict]]:
    """
    Fetch nodes and relationships from Neo4j.

    Returns:
        (nodes, edges) — each a list of property dicts.
    """
    with driver.session() as session:
        node_result = session.run("""
            MATCH (n)
            WHERE n:Application OR n:TCC_Permission OR n:Entitlement
               OR n:XPC_Service OR n:LaunchItem OR n:MDM_Profile
               OR n:User OR n:Keychain_Item
            RETURN elementId(n) AS id,
                   labels(n)[0]  AS label,
                   coalesce(n.name, n.display_name, n.label, n.identifier, '?') AS display,
                   n.bundle_id   AS bundle_id
            LIMIT 500
        """)
        nodes = [dict(r) for r in node_result]

        edge_result = session.run("""
            MATCH (a)-[r]->(b)
            WHERE (a:Application OR a:TCC_Permission OR a:Entitlement OR a:LaunchItem
                   OR a:XPC_Service OR a:MDM_Profile OR a:User OR a:Keychain_Item)
              AND (b:Application OR b:TCC_Permission OR b:Entitlement OR b:LaunchItem
                   OR b:XPC_Service OR b:MDM_Profile OR b:User OR b:Keychain_Item)
            RETURN elementId(a) AS src_id,
                   elementId(b) AS dst_id,
                   type(r) AS rel_type,
                   coalesce(r.inferred, false) AS inferred
            LIMIT 2000
        """)
        edges = [dict(r) for r in edge_result]

    return nodes, edges


# ── DOT Generation ────────────────────────────────────────────────────────────

def generate_dot(nodes: list[dict], edges: list[dict]) -> str:
    """
    Generate a Graphviz DOT string from node and edge lists.

    Args:
        nodes: list of dicts with keys: id, label (node type), display, bundle_id
        edges: list of dicts with keys: src_id, dst_id, rel_type, inferred

    Returns:
        DOT format string.
    """
    lines = [
        "digraph rootstock {",
        "  graph [rankdir=LR fontname=Helvetica bgcolor=white]",
        '  node  [fontname=Helvetica fontsize=11 style=filled]',
        '  edge  [fontname=Helvetica fontsize=9]',
        "",
    ]

    # elementId → dot identifier mapping
    id_map: dict[str, str] = {}
    seen_dot_ids: set[str] = set()

    for node in nodes:
        raw_id = str(node["id"])
        display = node.get("display") or "?"
        node_type = node.get("label") or "Unknown"
        bundle = node.get("bundle_id") or ""

        # Build unique dot id
        base_id = _safe_dot_id(bundle if bundle else display)
        dot_id = base_id
        counter = 0
        while dot_id in seen_dot_ids:
            counter += 1
            dot_id = f"{base_id}_{counter}"
        seen_dot_ids.add(dot_id)
        id_map[raw_id] = dot_id

        color = NODE_COLORS.get(node_type, "white")
        label = _truncate(display)
        shape = "box" if node_type == "Application" else "ellipse"
        lines.append(
            f'  {dot_id} [label="{label}" fillcolor="{color}" shape={shape}]'
        )

    lines.append("")

    for edge in edges:
        src_raw = str(edge["src_id"])
        dst_raw = str(edge["dst_id"])
        rel = edge.get("rel_type", "REL")
        is_inferred = edge.get("inferred", False) or rel in INFERRED_RELS

        src_dot = id_map.get(src_raw)
        dst_dot = id_map.get(dst_raw)
        if src_dot is None or dst_dot is None:
            continue  # skip orphan edges (node may have been excluded by LIMIT)

        style = "dashed" if is_inferred else "solid"
        lines.append(f'  {src_dot} -> {dst_dot} [label="{rel}" style={style}]')

    lines.append("}")
    return "\n".join(lines)


# ── Rendering ─────────────────────────────────────────────────────────────────

def render_dot(dot_path: Path, output_format: str = "png") -> Path:
    """Render a DOT file to PNG/SVG using the `dot` command (requires Graphviz)."""
    out_path = dot_path.with_suffix(f".{output_format}")
    try:
        subprocess.run(
            ["dot", f"-T{output_format}", str(dot_path), "-o", str(out_path)],
            check=True,
            capture_output=True,
        )
        return out_path
    except FileNotFoundError:
        print(
            "Warning: `dot` command not found. Install Graphviz to render DOT files.",
            file=sys.stderr,
        )
        raise
    except subprocess.CalledProcessError as e:
        print(f"Error rendering DOT file: {e.stderr.decode()}", file=sys.stderr)
        raise


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export Rootstock graph to Graphviz DOT format"
    )
    parser.add_argument("--neo4j", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--username", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="rootstock", help="Neo4j password")
    parser.add_argument("--output", required=True, help="Output .dot file path")
    parser.add_argument(
        "--render",
        choices=["png", "svg"],
        help="Auto-render to image using `dot` command (requires Graphviz)",
    )
    args = parser.parse_args()

    driver = GraphDatabase.driver(args.neo4j, auth=(args.username, args.password))
    try:
        driver.verify_connectivity()
    except Exception as e:
        print(f"Cannot connect to Neo4j at {args.neo4j}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching graph data from {args.neo4j}…", file=sys.stderr)
    nodes, edges = fetch_graph_data(driver)
    driver.close()

    print(f"  {len(nodes)} nodes, {len(edges)} edges", file=sys.stderr)

    dot_content = generate_dot(nodes, edges)
    out_path = Path(args.output)
    out_path.write_text(dot_content, encoding="utf-8")
    print(f"DOT file written to {out_path}", file=sys.stderr)

    if args.render:
        rendered = render_dot(out_path, args.render)
        print(f"Rendered to {rendered}", file=sys.stderr)


if __name__ == "__main__":
    main()
