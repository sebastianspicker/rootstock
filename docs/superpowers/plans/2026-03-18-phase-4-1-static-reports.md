# Phase 4.1 — Static Reports (Mermaid/Graphviz) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python report generator that runs all Killer Queries against Neo4j and produces a comprehensive Markdown security report with Mermaid diagrams and Graphviz DOT export.

**Architecture:** Three modules: `report_diagrams.py` (pure Mermaid/DOT formatting functions, no Neo4j dependency), `report_graphviz.py` (DOT export with optional neo4j fetch), and `report.py` (main CLI: connects to Neo4j, executes all queries, assembles all sections). The report engine reads `.cypher` files from `graph/queries/` at runtime — new queries are picked up automatically.

**Tech Stack:** Python 3.10+, neo4j>=5.0, pydantic>=2.0, tabulate (new dep for table rendering)

---

## File Structure

| File | Create/Modify | Responsibility |
|------|--------------|----------------|
| `graph/report_diagrams.py` | Create | Pure functions: Mermaid flowchart + pie chart generation from query result dicts |
| `graph/report_graphviz.py` | Create | DOT format export of graph nodes/edges with color coding |
| `graph/report.py` | Create | Main CLI: Neo4j connection, query execution, section assembly, Markdown output |
| `graph/requirements.txt` | Modify | Add `tabulate>=0.9` |
| `graph/tests/test_report_diagrams.py` | Create | Unit tests for all diagram generation functions (no Neo4j needed) |
| `graph/tests/test_report.py` | Create | Unit tests for query result formatting functions |

---

## Task 1: Add `tabulate` Dependency

**Files:**
- Modify: `graph/requirements.txt`

- [ ] **Step 1: Add tabulate to requirements.txt**

```
neo4j>=5.0
pydantic>=2.0
tabulate>=0.9
```

- [ ] **Step 2: Install and verify**

Run: `cd graph && pip install tabulate`
Expected: `Successfully installed tabulate-...`

- [ ] **Step 3: Commit**

```bash
git add graph/requirements.txt
git commit -m "[graph] add tabulate dependency for report table rendering"
```

---

## Task 2: Mermaid Diagram Module (`report_diagrams.py`)

**Files:**
- Create: `graph/report_diagrams.py`
- Create: `graph/tests/test_report_diagrams.py`

### Step 2a: Write the failing tests first

- [ ] **Step 1: Write failing tests**

Create `graph/tests/test_report_diagrams.py`:

```python
"""Tests for report_diagrams.py — all pure functions, no Neo4j required."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report_diagrams import (
    mermaid_attack_path,
    mermaid_tcc_pie,
    sanitize_mermaid_id,
)


class TestSanitizeMermaidId:
    def test_strips_dots_and_spaces(self):
        assert "com_apple_foo" == sanitize_mermaid_id("com.apple.foo")

    def test_handles_slashes(self):
        result = sanitize_mermaid_id("/Applications/Foo.app")
        assert "/" not in result
        assert "." not in result

    def test_empty_string(self):
        result = sanitize_mermaid_id("")
        assert isinstance(result, str)


class TestMermaidAttackPath:
    def test_two_node_path(self):
        path_result = {
            "node_names": ["attacker_payload", "iTerm2"],
            "rel_types": ["CAN_INJECT_INTO"],
            "path_length": 1,
        }
        diagram = mermaid_attack_path(path_result)
        assert "graph LR" in diagram
        assert "CAN_INJECT_INTO" in diagram
        assert "attacker_payload" in diagram
        assert "iTerm2" in diagram

    def test_three_node_path(self):
        path_result = {
            "node_names": ["attacker_payload", "Slack", "Full Disk Access"],
            "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
            "path_length": 2,
        }
        diagram = mermaid_attack_path(path_result)
        assert "graph LR" in diagram
        assert "CAN_INJECT_INTO" in diagram
        assert "HAS_TCC_GRANT" in diagram

    def test_highlights_tcc_node(self):
        path_result = {
            "node_names": ["attacker_payload", "iTerm2", "Full Disk Access"],
            "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
            "path_length": 2,
        }
        diagram = mermaid_attack_path(path_result)
        # TCC nodes should be styled red
        assert "fill:#ff6666" in diagram

    def test_empty_path_returns_empty(self):
        result = mermaid_attack_path({"node_names": [], "rel_types": [], "path_length": 0})
        assert result == ""

    def test_mismatched_nodes_rels_is_safe(self):
        # Should not raise, even if len(nodes) != len(rels) + 1
        path_result = {
            "node_names": ["A"],
            "rel_types": [],
            "path_length": 0,
        }
        result = mermaid_attack_path(path_result)
        assert isinstance(result, str)


class TestMermaidTccPie:
    def test_basic_pie_chart(self):
        rows = [
            {"permission": "Full Disk Access", "total_grants": 5},
            {"permission": "Camera", "total_grants": 3},
            {"permission": "Microphone", "total_grants": 2},
        ]
        diagram = mermaid_tcc_pie(rows)
        assert "pie" in diagram
        assert "Full Disk Access" in diagram
        assert "5" in diagram

    def test_empty_rows(self):
        diagram = mermaid_tcc_pie([])
        assert isinstance(diagram, str)

    def test_top_n_limiting(self):
        rows = [{"permission": f"Perm{i}", "total_grants": i} for i in range(1, 20)]
        diagram = mermaid_tcc_pie(rows, top_n=10)
        # Should not include all 19 entries
        assert diagram.count('"') <= 22  # 10 entries × 2 quotes + some extra
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd graph && python -m pytest tests/test_report_diagrams.py -v 2>&1 | head -30`
Expected: `ModuleNotFoundError: No module named 'report_diagrams'`

### Step 2b: Implement `report_diagrams.py`

- [ ] **Step 3: Implement `graph/report_diagrams.py`**

```python
"""
report_diagrams.py — Mermaid and Graphviz diagram generation for Rootstock reports.

All functions are pure (no Neo4j dependency) — they take query result dicts
and return formatted diagram strings suitable for embedding in Markdown.
"""

from __future__ import annotations

import re


# ── Helpers ──────────────────────────────────────────────────────────────────

def sanitize_mermaid_id(text: str) -> str:
    """Convert arbitrary strings to safe Mermaid node IDs (alphanumeric + underscore)."""
    if not text:
        return "node"
    return re.sub(r"[^a-zA-Z0-9_]", "_", text)


def _truncate(text: str, max_len: int = 30) -> str:
    """Truncate long labels for diagram readability."""
    return text if len(text) <= max_len else text[:max_len - 1] + "…"


# ── Mermaid Attack Path Flowchart ─────────────────────────────────────────────

TCC_PERM_KEYWORDS = {
    "Full Disk Access", "Accessibility", "Screen Recording",
    "Microphone", "Camera", "Location", "Contacts", "Calendar",
    "Reminders", "Photos", "Bluetooth", "HomeKit", "Health",
    "AppleEvents", "Developer Tools", "kTCC",
}


def _is_tcc_node(name: str) -> bool:
    """Heuristic: is this node a TCC permission?"""
    return any(kw.lower() in name.lower() for kw in TCC_PERM_KEYWORDS) or name.startswith("kTCC")


def mermaid_attack_path(path_result: dict) -> str:
    """
    Generate a Mermaid LR flowchart for a single attack path.

    Args:
        path_result: dict with keys:
            - node_names: list[str] — display names of nodes in path
            - rel_types:  list[str] — relationship types between nodes
            - path_length: int

    Returns:
        Mermaid flowchart string, or "" if path is empty.
    """
    nodes: list[str] = path_result.get("node_names") or []
    rels: list[str] = path_result.get("rel_types") or []

    if not nodes or len(nodes) < 2:
        return ""

    # Ensure nodes and rels are consistent
    edge_count = min(len(nodes) - 1, len(rels))
    nodes = nodes[: edge_count + 1]
    rels = rels[:edge_count]

    lines = ["```mermaid", "graph LR"]

    ids = [sanitize_mermaid_id(n) + str(i) for i, n in enumerate(nodes)]

    for i, (name, node_id) in enumerate(zip(nodes, ids)):
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
    Each path is preceded by a subheading showing hop count.
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
            # Fallback: render as text
            names = row.get("node_names") or []
            rel_types = row.get("rel_types") or []
            steps = []
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
        top_n: include only the top N permissions by count

    Returns:
        Mermaid pie chart string.
    """
    if not rows:
        return "_No TCC grant data available._"

    # Sort descending by count, take top N
    sorted_rows = sorted(rows, key=lambda r: r.get("total_grants", 0), reverse=True)
    top = sorted_rows[:top_n]

    lines = ["```mermaid", 'pie title TCC Permission Distribution']
    for row in top:
        label = row.get("permission", "Unknown")
        count = row.get("total_grants", 0)
        # Escape quotes in label
        safe_label = label.replace('"', "'")
        lines.append(f'  "{safe_label}" : {count}')
    lines.append("```")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd graph && python -m pytest tests/test_report_diagrams.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add graph/report_diagrams.py graph/tests/test_report_diagrams.py
git commit -m "[graph] add Mermaid diagram generation module with tests"
```

---

## Task 3: Graphviz DOT Export Module (`report_graphviz.py`)

**Files:**
- Create: `graph/report_graphviz.py`

No unit tests for this module (DOT generation is straightforward string formatting; integration tested by running `dot -Tpng`).

- [ ] **Step 1: Implement `graph/report_graphviz.py`**

```python
"""
report_graphviz.py — Graphviz DOT format export for Rootstock graphs.

CLI: python3 report_graphviz.py --neo4j bolt://localhost:7687 --output graph.dot
     python3 report_graphviz.py --neo4j bolt://localhost:7687 --output graph.dot --render png

Color coding (matches ROADMAP spec):
  Applications  = lightblue
  TCC_Permission = #ff6666 (red)
  Entitlement    = #ffff99 (yellow)
  XPC_Service    = #99ff99 (green)
  LaunchItem     = #ffcc99 (orange)
  MDM_Profile    = #cc99ff (purple)

Edge styles:
  Solid   = explicit relationships (imported directly from scan)
  Dashed  = inferred relationships (CAN_INJECT_INTO, CHILD_INHERITS_TCC, etc.)
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

INFERRED_RELS = {"CAN_INJECT_INTO", "CHILD_INHERITS_TCC", "CAN_SEND_APPLE_EVENT"}

MAX_LABEL_LEN = 35


def _safe_dot_id(text: str) -> str:
    """Make a safe DOT node identifier."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", str(text))


def _truncate(text: str, max_len: int = MAX_LABEL_LEN) -> str:
    return text if len(text) <= max_len else text[:max_len - 1] + "…"


# ── DOT Generation ────────────────────────────────────────────────────────────

def _fetch_graph_data(driver, subgraph_filter: str | None = None) -> tuple[list[dict], list[dict]]:
    """
    Fetch nodes and relationships from Neo4j.

    Returns:
        (nodes, edges) where each is a list of property dicts.
    """
    with driver.session() as session:
        # Nodes: fetch all primary node types
        node_query = """
        MATCH (n)
        WHERE n:Application OR n:TCC_Permission OR n:Entitlement
           OR n:XPC_Service OR n:LaunchItem OR n:MDM_Profile
           OR n:User OR n:Keychain_Item
        RETURN elementId(n) AS id,
               labels(n)[0]  AS label,
               coalesce(n.name, n.display_name, n.label, n.identifier, '?') AS display,
               n.bundle_id   AS bundle_id
        LIMIT 500
        """
        node_result = session.run(node_query)
        nodes = [dict(r) for r in node_result]

        # Edges: fetch all relationships
        edge_query = """
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
        """
        edge_result = session.run(edge_query)
        edges = [dict(r) for r in edge_result]

    return nodes, edges


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

    # Node ID mapping: elementId → dot id
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
            continue  # orphan edge, skip

        style = "dashed" if is_inferred else "solid"
        lines.append(f'  {src_dot} -> {dst_dot} [label="{rel}" style={style}]')

    lines.append("}")
    return "\n".join(lines)


def render_dot(dot_path: Path, output_format: str = "png") -> Path:
    """Render a DOT file to PNG/SVG using the `dot` command."""
    out_path = dot_path.with_suffix(f".{output_format}")
    try:
        subprocess.run(
            ["dot", f"-T{output_format}", str(dot_path), "-o", str(out_path)],
            check=True,
            capture_output=True,
        )
        return out_path
    except FileNotFoundError:
        print("Warning: `dot` command not found. Install Graphviz to render DOT files.", file=sys.stderr)
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
        help="Auto-render to PNG or SVG using `dot` command (requires Graphviz)",
    )
    args = parser.parse_args()

    driver = GraphDatabase.driver(args.neo4j, auth=(args.username, args.password))
    try:
        driver.verify_connectivity()
    except Exception as e:
        print(f"Cannot connect to Neo4j at {args.neo4j}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching graph data from {args.neo4j}…", file=sys.stderr)
    nodes, edges = _fetch_graph_data(driver)
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
```

- [ ] **Step 2: Validate DOT syntax is parseable (no live Neo4j needed)**

```python
# Quick smoke test — run inline
python3 -c "
from graph.report_graphviz import generate_dot
dot = generate_dot(
    nodes=[
        {'id': '1', 'label': 'Application', 'display': 'iTerm2', 'bundle_id': 'com.googlecode.iterm2'},
        {'id': '2', 'label': 'TCC_Permission', 'display': 'Full Disk Access', 'bundle_id': None},
    ],
    edges=[
        {'src_id': '1', 'dst_id': '2', 'rel_type': 'HAS_TCC_GRANT', 'inferred': False},
    ]
)
assert 'digraph rootstock' in dot
assert 'HAS_TCC_GRANT' in dot
assert 'lightblue' in dot
print('DOT smoke test passed')
"
```

Run from repo root: `cd /path/to/rootstock && python3 -c "..."` (adjust path).

- [ ] **Step 3: Commit**

```bash
git add graph/report_graphviz.py
git commit -m "[graph] add Graphviz DOT export module"
```

---

## Task 4: Query Runner + Section Formatters (test-first)

**Files:**
- Create: `graph/tests/test_report.py`
- Create: `graph/report.py` (partial — formatting functions first, CLI last)

### Step 4a: Tests for formatting functions

- [ ] **Step 1: Write failing tests for table/section formatters**

Create `graph/tests/test_report.py`:

```python
"""
Tests for report.py formatting functions — no Neo4j required.
All tested functions take query result dicts and return Markdown strings.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report import (
    format_injectable_fda_table,
    format_electron_table,
    format_apple_event_table,
    format_tcc_overview_table,
    format_private_entitlement_table,
    format_executive_summary,
    format_no_findings,
)


class TestFormatNoFindings:
    def test_returns_markdown_string(self):
        result = format_no_findings()
        assert isinstance(result, str)
        assert "No findings" in result


class TestFormatInjectableFdaTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "iTerm2",
                "bundle_id": "com.googlecode.iterm2",
                "team_id": "H7V7XYVQ7D",
                "injection_methods": ["missing_library_validation"],
                "method_count": 1,
                "path": "/Applications/iTerm.app",
            }
        ]
        result = format_injectable_fda_table(rows)
        assert "iTerm2" in result
        assert "missing_library_validation" in result
        assert "H7V7XYVQ7D" in result

    def test_empty_returns_no_findings(self):
        result = format_injectable_fda_table([])
        assert "No findings" in result

    def test_multiple_injection_methods_joined(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "team_id": "BQR82RBBHL",
                "injection_methods": ["missing_library_validation", "electron_env_var"],
                "method_count": 2,
                "path": "/Applications/Slack.app",
            }
        ]
        result = format_injectable_fda_table(rows)
        assert "missing_library_validation" in result
        assert "electron_env_var" in result


class TestFormatElectronTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "inherited_permissions": ["Full Disk Access", "Microphone"],
                "permission_count": 2,
            }
        ]
        result = format_electron_table(rows)
        assert "Slack" in result
        assert "Full Disk Access" in result

    def test_empty_returns_no_findings(self):
        result = format_electron_table([])
        assert "No findings" in result


class TestFormatAppleEventTable:
    def test_basic_table(self):
        rows = [
            {
                "source_app": "Terminal",
                "target_app": "Finder",
                "permission_gained": "Full Disk Access",
            }
        ]
        result = format_apple_event_table(rows)
        assert "Terminal" in result
        assert "Finder" in result
        assert "Full Disk Access" in result

    def test_empty_returns_no_findings(self):
        result = format_apple_event_table([])
        assert "No findings" in result


class TestFormatTccOverviewTable:
    def test_basic_table(self):
        rows = [
            {"permission": "Full Disk Access", "service": "kTCCServiceSystemPolicyAllFiles",
             "allowed_count": 3, "denied_count": 0, "total_grants": 3},
            {"permission": "Camera", "service": "kTCCServiceCamera",
             "allowed_count": 5, "denied_count": 1, "total_grants": 6},
        ]
        result = format_tcc_overview_table(rows)
        assert "Full Disk Access" in result
        assert "Camera" in result

    def test_empty_returns_no_findings(self):
        result = format_tcc_overview_table([])
        assert "No findings" in result


class TestFormatPrivateEntitlementTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "private_entitlements": ["com.apple.private.tcc.allow"],
                "is_injectable": True,
            }
        ]
        result = format_private_entitlement_table(rows)
        assert "Slack" in result
        assert "com.apple.private.tcc.allow" in result

    def test_empty_returns_no_findings(self):
        result = format_private_entitlement_table([])
        assert "No findings" in result


class TestFormatExecutiveSummary:
    def test_counts_reflected(self):
        result = format_executive_summary(
            critical_count=3,
            high_count=7,
            top_paths=[
                "iTerm2 has Full Disk Access and is injectable via missing library validation",
                "Slack inherits Full Disk Access via ELECTRON_RUN_AS_NODE",
            ],
        )
        assert "3" in result
        assert "7" in result
        assert "iTerm2" in result

    def test_zero_findings(self):
        result = format_executive_summary(critical_count=0, high_count=0, top_paths=[])
        assert "0" in result
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd graph && python -m pytest tests/test_report.py -v 2>&1 | head -20`
Expected: `ModuleNotFoundError: No module named 'report'`

### Step 4b: Implement formatting functions in `report.py`

- [ ] **Step 3: Create `graph/report.py` with formatting functions (no CLI yet)**

```python
"""
report.py — Rootstock Security Assessment Report Generator.

CLI: python3 report.py --neo4j bolt://localhost:7687 --output report.md
     python3 report.py --neo4j bolt://localhost:7687 --output report.html --format html
     python3 report.py --neo4j bolt://localhost:7687 --output report.md --scan-json scan.json

Architecture:
  1. Connect to Neo4j, run all queries from graph/queries/*.cypher
  2. Format each result set into a Markdown section
  3. Generate Mermaid diagrams for critical findings
  4. Assemble full report document and write to output file
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from neo4j import GraphDatabase
from tabulate import tabulate

from report_diagrams import mermaid_attack_paths_block, mermaid_tcc_pie


# ── Formatting Helpers ────────────────────────────────────────────────────────

def format_no_findings() -> str:
    return "_No findings in this category._"


def _list_or_str(value) -> str:
    """Convert list values from Neo4j to a comma-separated string."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value) if value is not None else "—"


# ── Section Formatters ────────────────────────────────────────────────────────

def format_injectable_fda_table(rows: list[dict]) -> str:
    """Format Query 1 results: injectable apps with Full Disk Access."""
    if not rows:
        return format_no_findings()

    table_rows = []
    for r in rows:
        methods = _list_or_str(r.get("injection_methods", []))
        table_rows.append([
            r.get("app_name", "?"),
            r.get("team_id") or "—",
            methods,
            r.get("bundle_id", "?"),
        ])

    headers = ["App Name", "Team ID", "Injection Method(s)", "Bundle ID"]
    table = tabulate(table_rows, headers=headers, tablefmt="github")

    # Risk descriptions per finding
    risk_lines = []
    for r in rows:
        app = r.get("app_name", "?")
        methods = _list_or_str(r.get("injection_methods", []))
        risk_lines.append(
            f"- **{app}**: Attacker can inject via `{methods}` to inherit Full Disk Access."
        )

    return table + "\n\n" + "\n".join(risk_lines)


def format_electron_table(rows: list[dict]) -> str:
    """Format Query 3 results: Electron apps with TCC inheritance."""
    if not rows:
        return format_no_findings()

    table_rows = []
    for r in rows:
        perms = _list_or_str(r.get("inherited_permissions", []))
        table_rows.append([
            r.get("app_name", "?"),
            r.get("bundle_id", "?"),
            perms,
            str(r.get("permission_count", 0)),
        ])

    headers = ["Electron App", "Bundle ID", "Inherited Permissions", "Count"]
    return tabulate(table_rows, headers=headers, tablefmt="github")


def format_apple_event_table(rows: list[dict]) -> str:
    """Format Query 5 results: Apple Event TCC cascade."""
    if not rows:
        return format_no_findings()

    table_rows = []
    for r in rows:
        table_rows.append([
            r.get("source_app", "?"),
            r.get("target_app", "?"),
            r.get("permission_gained", "?"),
        ])

    headers = ["Source App", "Target App", "Gained Permission"]
    return tabulate(table_rows, headers=headers, tablefmt="github")


def format_tcc_overview_table(rows: list[dict]) -> str:
    """Format Query 7 section 1 results: TCC grant distribution."""
    if not rows:
        return format_no_findings()

    table_rows = []
    for r in rows:
        table_rows.append([
            r.get("permission", "?"),
            r.get("service", "?"),
            str(r.get("allowed_count", 0)),
            str(r.get("denied_count", 0)),
            str(r.get("total_grants", 0)),
        ])

    headers = ["Permission", "TCC Service", "Allowed", "Denied", "Total"]
    return tabulate(table_rows, headers=headers, tablefmt="github")


def format_private_entitlement_table(rows: list[dict]) -> str:
    """Format Query 4 results: private entitlement audit."""
    if not rows:
        return format_no_findings()

    table_rows = []
    for r in rows:
        ents = _list_or_str(r.get("private_entitlements", []))
        injectable = "Yes" if r.get("is_injectable") else "No"
        table_rows.append([
            r.get("app_name", "?"),
            ents,
            injectable,
        ])

    headers = ["App", "Private Entitlements", "Injectable?"]
    return tabulate(table_rows, headers=headers, tablefmt="github")


def format_executive_summary(
    critical_count: int,
    high_count: int,
    top_paths: list[str],
) -> str:
    """Format the Executive Summary section."""
    lines = [
        f"- **Critical findings:** {critical_count}",
        f"- **High-risk findings:** {high_count}",
        "",
        "**Top Attack Paths:**",
    ]

    if top_paths:
        for i, path in enumerate(top_paths[:3], 1):
            lines.append(f"{i}. {path}")
    else:
        lines.append("_No attack paths discovered._")

    return "\n".join(lines)


# ── Query Execution ───────────────────────────────────────────────────────────

QUERY_FILES = [
    "01-injectable-fda-apps.cypher",
    "02-shortest-path-to-fda.cypher",
    "03-electron-tcc-inheritance.cypher",
    "04-private-entitlement-audit.cypher",
    "05-appleevent-tcc-cascade.cypher",
    "06-injection-chain.cypher",
    "07-tcc-grant-overview.cypher",
    "08-persistence-audit.cypher",
    "09-keychain-acl-audit.cypher",
    "10-mdm-managed-tcc.cypher",
]


def _load_query(queries_dir: Path, filename: str) -> str | None:
    """Load a .cypher file, returning None if not found."""
    path = queries_dir / filename
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _split_cypher_statements(cypher: str) -> list[str]:
    """
    Split a .cypher file into individual statements (separated by ';' or double newline).
    Returns only the first statement for multi-statement files unless overridden.
    """
    # Split on semicolons to handle files like 07-tcc-grant-overview.cypher
    # that contain multiple queries
    statements = [s.strip() for s in cypher.split(";") if s.strip()]
    return statements if statements else [cypher.strip()]


def run_query(session, cypher: str, params: dict | None = None) -> list[dict]:
    """Run a single Cypher statement, return list of record dicts."""
    result = session.run(cypher, params or {})
    return [dict(r) for r in result]


def run_all_queries(driver, queries_dir: Path) -> dict[str, list[dict] | str]:
    """
    Run all queries from queries_dir, returning results keyed by filename.
    On failure, returns an error string instead of a list.
    """
    results: dict[str, list[dict] | str] = {}

    with driver.session() as session:
        for filename in QUERY_FILES:
            cypher = _load_query(queries_dir, filename)
            if cypher is None:
                results[filename] = f"Query file not found: {filename}"
                continue

            try:
                statements = _split_cypher_statements(cypher)
                # Use the first statement for report sections (additional sections
                # for multi-query files like 07 are handled separately)
                first_stmt = statements[0]
                rows = run_query(session, first_stmt)
                results[filename] = rows
                print(f"  ✓ {filename}: {len(rows)} rows", file=sys.stderr)
            except Exception as e:
                results[filename] = f"Query failed: {e}"
                print(f"  ✗ {filename}: {e}", file=sys.stderr)

    return results


# ── Scan Metadata ─────────────────────────────────────────────────────────────

def get_scan_metadata_from_neo4j(driver) -> dict:
    """Query Neo4j for node counts and available scan metadata."""
    with driver.session() as session:
        try:
            counts_result = session.run("""
                MATCH (a:Application) WITH count(a) AS app_count
                MATCH (t:TCC_Permission) WITH app_count, count(t) AS tcc_perm_count
                OPTIONAL MATCH (g:Application)-[:HAS_TCC_GRANT]->(p:TCC_Permission)
                WITH app_count, tcc_perm_count, count(g) AS tcc_grant_count
                OPTIONAL MATCH (e:Application)-[:HAS_ENTITLEMENT]->(en:Entitlement)
                WITH app_count, tcc_perm_count, tcc_grant_count, count(en) AS entitlement_count
                RETURN app_count, tcc_perm_count, tcc_grant_count, entitlement_count
            """)
            row = dict(counts_result.single() or {})
        except Exception:
            row = {}

        try:
            meta_result = session.run("""
                MATCH (a:Application) WHERE a.scan_id IS NOT NULL
                RETURN a.scan_id AS scan_id, a.hostname AS hostname,
                       a.macos_version AS macos_version
                LIMIT 1
            """)
            meta_row = dict(meta_result.single() or {})
        except Exception:
            meta_row = {}

    return {**row, **meta_row}


def get_scan_metadata_from_json(json_path: Path) -> dict:
    """Read scan metadata from the original collector JSON file."""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        return {
            "scan_id": data.get("scan_id", "unknown"),
            "hostname": data.get("hostname", socket.gethostname()),
            "macos_version": data.get("macos_version", "unknown"),
            "collector_version": data.get("collector_version", "unknown"),
            "is_root": data.get("elevation", {}).get("is_root", False),
            "has_fda": data.get("elevation", {}).get("has_fda", False),
            "app_count": len(data.get("applications", [])),
            "tcc_grant_count": len(data.get("tcc_grants", [])),
        }
    except Exception as e:
        return {"error": str(e)}


# ── Report Assembly ───────────────────────────────────────────────────────────

RECOMMENDATIONS = {
    "injectable_fda": [
        "Enable Hardened Runtime for all first-party and in-house applications.",
        "Enable Library Validation to prevent unsigned dylib injection.",
        "Audit all applications with Full Disk Access — revoke unnecessary grants via System Settings → Privacy & Security.",
        "Use `codesign --verify --deep --strict` in CI/CD pipelines to catch regressions.",
    ],
    "electron_inheritance": [
        "Disable `ELECTRON_RUN_AS_NODE` support in production Electron apps via `--disable-node-options` flag.",
        "Sandbox Electron apps using macOS App Sandbox where possible.",
        "Apply principle of least privilege: Electron apps should not hold TCC permissions they don't actively need.",
    ],
    "apple_events": [
        "Audit Apple Event permissions granted in TCC — revoke automation grants to low-trust apps.",
        "Implement AppleScript permission review as part of quarterly access reviews.",
    ],
    "general": [
        "Enable System Integrity Protection (SIP) on all endpoints.",
        "Enforce Full Disk Access via MDM allow-list — only approved apps should hold FDA.",
        "Review all LaunchDaemons and LaunchAgents with `launchctl list` regularly.",
        "Implement application allow-listing via PPPC profiles.",
        "Run Rootstock periodically (monthly) to detect new attack paths introduced by software installs.",
    ],
}


def assemble_report(
    query_results: dict[str, list[dict] | str],
    metadata: dict,
    queries_dir: Path,
) -> str:
    """Assemble the full Markdown report from query results and metadata."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Extract result sets (with fallback for failed queries)
    def get_rows(filename: str) -> list[dict]:
        result = query_results.get(filename, [])
        return result if isinstance(result, list) else []

    injectable_rows = get_rows("01-injectable-fda-apps.cypher")
    path_rows = get_rows("02-shortest-path-to-fda.cypher")
    electron_rows = get_rows("03-electron-tcc-inheritance.cypher")
    private_ent_rows = get_rows("04-private-entitlement-audit.cypher")
    apple_event_rows = get_rows("05-appleevent-tcc-cascade.cypher")
    tcc_overview_rows = get_rows("07-tcc-grant-overview.cypher")

    critical_count = len(injectable_rows) + len(path_rows)
    high_count = len(electron_rows) + len(apple_event_rows)

    # Build top 3 attack path descriptions
    top_paths: list[str] = []
    for row in injectable_rows[:3]:
        app = row.get("app_name", "?")
        methods = _list_or_str(row.get("injection_methods", []))
        top_paths.append(f"{app} has Full Disk Access and is injectable via {methods}.")
    for row in electron_rows[:1]:
        app = row.get("app_name", "?")
        perms = _list_or_str(row.get("inherited_permissions", []))
        top_paths.append(f"{app} (Electron) inherits {perms} via ELECTRON_RUN_AS_NODE abuse.")

    sections: list[str] = []

    # ── Header ──
    sections.append("# Rootstock Security Assessment Report")
    sections.append(f"_Generated: {now}_")
    sections.append("")

    # ── Scan Metadata ──
    sections.append("## Scan Metadata")
    meta_rows = [
        ["Hostname", metadata.get("hostname", socket.gethostname())],
        ["macOS Version", metadata.get("macos_version", "unknown")],
        ["Scan Timestamp", metadata.get("timestamp", now)],
        ["Scan ID", metadata.get("scan_id", "unknown")],
        ["Collector Version", metadata.get("collector_version", "unknown")],
        ["Elevation", "root" if metadata.get("is_root") else "user"],
        ["Full Disk Access", "Yes" if metadata.get("has_fda") else "No"],
        ["Total Apps Scanned", str(metadata.get("app_count", "unknown"))],
        ["TCC Grants Found", str(metadata.get("tcc_grant_count", "unknown"))],
        ["Entitlements Extracted", str(metadata.get("entitlement_count", "unknown"))],
    ]
    sections.append(tabulate(meta_rows, tablefmt="github"))
    sections.append("")

    # ── Executive Summary ──
    sections.append("## Executive Summary")
    sections.append(format_executive_summary(critical_count, high_count, top_paths))
    sections.append("")

    # ── Critical: Injectable FDA Apps ──
    sections.append("## Critical Findings: Injectable Apps with Privileged TCC Grants")
    sections.append(
        "> **Risk:** An attacker who controls a dylib can inject it into these apps "
        "and inherit their Full Disk Access grant — enabling read/write of TCC.db, "
        "Mail, SSH keys, and all user files."
    )
    sections.append("")
    sections.append(format_injectable_fda_table(injectable_rows))
    sections.append("")

    if injectable_rows or path_rows:
        sections.append("### Attack Path Diagrams")
        sections.append(mermaid_attack_paths_block(path_rows, max_paths=3))
    sections.append("")

    # ── High: Electron TCC Inheritance ──
    sections.append("## High Findings: Electron TCC Inheritance")
    sections.append(
        "> **Risk:** Electron apps can be abused via the `ELECTRON_RUN_AS_NODE` environment variable "
        "to spawn a Node.js interpreter that inherits the parent process's TCC permissions. "
        "An attacker with code execution can exploit this to access protected resources silently."
    )
    sections.append("")
    sections.append(format_electron_table(electron_rows))
    sections.append("")

    # ── High: Apple Event TCC Cascade ──
    sections.append("## High Findings: Apple Event TCC Cascade")
    sections.append(
        "> **Risk:** An app with Apple Event automation permission over a privileged app "
        "can invoke that app's capabilities transactively, gaining effective access to the "
        "target's TCC grants without holding those grants directly."
    )
    sections.append("")
    sections.append(format_apple_event_table(apple_event_rows))
    sections.append("")

    # ── Informational: TCC Grant Overview ──
    sections.append("## Informational: TCC Grant Overview")
    sections.append(format_tcc_overview_table(tcc_overview_rows))
    sections.append("")

    if tcc_overview_rows:
        sections.append("### TCC Permission Distribution")
        sections.append(mermaid_tcc_pie(tcc_overview_rows))
        sections.append("")

    # ── Informational: Private Entitlement Audit ──
    sections.append("## Informational: Private Entitlement Audit")
    sections.append(
        "> Private Apple entitlements (`com.apple.private.*`) grant capabilities "
        "not available to App Store apps. Third-party apps holding these entitlements "
        "are high-value targets: compromising them may yield privileged capabilities."
    )
    sections.append("")
    sections.append(format_private_entitlement_table(private_ent_rows))
    sections.append("")

    # ── Recommendations ──
    sections.append("## Recommendations")

    if injectable_rows:
        sections.append("### Injectable Applications with Privileged TCC Grants")
        for rec in RECOMMENDATIONS["injectable_fda"]:
            sections.append(f"- {rec}")
        sections.append("")

    if electron_rows:
        sections.append("### Electron Application Hardening")
        for rec in RECOMMENDATIONS["electron_inheritance"]:
            sections.append(f"- {rec}")
        sections.append("")

    if apple_event_rows:
        sections.append("### Apple Event Automation Hygiene")
        for rec in RECOMMENDATIONS["apple_events"]:
            sections.append(f"- {rec}")
        sections.append("")

    sections.append("### General macOS Hardening")
    for rec in RECOMMENDATIONS["general"]:
        sections.append(f"- {rec}")
    sections.append("")

    # ── Appendix: Raw Query Results ──
    sections.append("## Appendix: Raw Query Results")
    sections.append(
        "Full output of each query. Use these for detailed analysis or to import "
        "into other reporting tools."
    )
    sections.append("")

    for filename in QUERY_FILES:
        result = query_results.get(filename)
        sections.append(f"### {filename}")

        if result is None:
            sections.append("_Not executed._")
        elif isinstance(result, str):
            sections.append(f"> **Error:** {result}")
        elif not result:
            sections.append("_No results._")
        else:
            if result:
                headers = list(result[0].keys())
                table_rows = [[_list_or_str(r.get(h)) for h in headers] for r in result]
                sections.append(tabulate(table_rows, headers=headers, tablefmt="github"))
        sections.append("")

    return "\n".join(sections)


# ── HTML Output ───────────────────────────────────────────────────────────────

def markdown_to_html(md: str) -> str:
    """
    Minimal Markdown-to-HTML conversion.
    For production use, install `markdown` package. This fallback handles basics.
    """
    try:
        import markdown
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Rootstock Security Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        max-width: 1200px; margin: 40px auto; padding: 0 20px; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #f4f4f4; }}
blockquote {{ background: #fff8e1; border-left: 4px solid #ffc107;
              padding: 10px 15px; margin: 1em 0; }}
code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
h1 {{ color: #c62828; }} h2 {{ color: #333; border-bottom: 2px solid #eee; }}
</style></head><body>
{markdown.markdown(md, extensions=['tables', 'fenced_code'])}
</body></html>"""
    except ImportError:
        # Basic fallback
        lines = []
        for line in md.split("\n"):
            if line.startswith("# "):
                lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                lines.append(f"<h3>{line[4:]}</h3>")
            else:
                lines.append(f"<p>{line}</p>")
        return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rootstock Security Assessment Report Generator"
    )
    parser.add_argument("--neo4j", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--username", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="rootstock", help="Neo4j password")
    parser.add_argument("--output", required=True, help="Output report file path")
    parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--scan-json",
        help="Optional: path to original scan.json for richer metadata",
    )
    args = parser.parse_args()

    # Determine queries directory relative to this script
    queries_dir = Path(__file__).parent / "queries"
    if not queries_dir.exists():
        print(f"Queries directory not found: {queries_dir}", file=sys.stderr)
        sys.exit(1)

    # Connect to Neo4j
    print(f"Connecting to Neo4j at {args.neo4j}…", file=sys.stderr)
    driver = GraphDatabase.driver(args.neo4j, auth=(args.username, args.password))
    try:
        driver.verify_connectivity()
    except Exception as e:
        print(f"Cannot connect to Neo4j: {e}", file=sys.stderr)
        sys.exit(1)
    print("  Connected.", file=sys.stderr)

    # Gather metadata
    if args.scan_json:
        metadata = get_scan_metadata_from_json(Path(args.scan_json))
    else:
        metadata = get_scan_metadata_from_neo4j(driver)

    # Run queries
    print("Running queries…", file=sys.stderr)
    query_results = run_all_queries(driver, queries_dir)
    driver.close()

    # Assemble report
    print("Assembling report…", file=sys.stderr)
    md = assemble_report(query_results, metadata, queries_dir)

    # Write output
    out_path = Path(args.output)
    if args.format == "html":
        content = markdown_to_html(md)
    else:
        content = md

    out_path.write_text(content, encoding="utf-8")
    print(f"Report written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run formatting tests — verify they pass**

Run: `cd graph && python -m pytest tests/test_report.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add graph/report.py graph/tests/test_report.py
git commit -m "[graph] add report generator with formatting functions and tests"
```

---

## Task 5: Integration Smoke Test

**Files:**
- No new files — runs against a live (or mock) Neo4j instance

- [ ] **Step 1: Run unit test suite to confirm all tests pass**

Run: `cd graph && python -m pytest tests/ -v`
Expected: All tests PASS (test_report_diagrams.py + test_report.py at minimum)

- [ ] **Step 2: Validate DOT generation inline (no Neo4j)**

Run:
```bash
cd graph && python3 -c "
from report_graphviz import generate_dot
dot = generate_dot(
    nodes=[
        {'id': '1', 'label': 'Application', 'display': 'iTerm2', 'bundle_id': 'com.googlecode.iterm2'},
        {'id': '2', 'label': 'TCC_Permission', 'display': 'Full Disk Access', 'bundle_id': None},
        {'id': '3', 'label': 'Application', 'display': 'Slack', 'bundle_id': 'com.tinyspeck.slackmacgap'},
    ],
    edges=[
        {'src_id': '1', 'dst_id': '2', 'rel_type': 'HAS_TCC_GRANT', 'inferred': False},
        {'src_id': '3', 'dst_id': '2', 'rel_type': 'HAS_TCC_GRANT', 'inferred': False},
        {'src_id': '4', 'dst_id': '1', 'rel_type': 'CAN_INJECT_INTO', 'inferred': True},  # orphan src
    ]
)
assert 'digraph rootstock' in dot
assert 'HAS_TCC_GRANT' in dot
assert 'lightblue' in dot
assert 'ff6666' in dot
print('DOT smoke test PASSED')
print(dot[:200])
"
```

Expected: `DOT smoke test PASSED` and DOT header printed.

- [ ] **Step 3: Test against live Neo4j (if available)**

If Neo4j is running with data from `import.py + infer.py`:

```bash
cd graph && python3 report.py \
  --neo4j bolt://localhost:7687 \
  --output /tmp/rootstock-report.md

# Spot-check the output
head -60 /tmp/rootstock-report.md
grep -c "^|" /tmp/rootstock-report.md   # Count table rows
```

Expected:
- File exists with all required sections
- Tables visible in output (lines starting with `|`)
- Mermaid blocks visible (` ```mermaid ` markers)

If Neo4j has no data yet, verify the report handles empty results gracefully:
```bash
grep -c "No findings" /tmp/rootstock-report.md  # Should be > 0
```

- [ ] **Step 4: Test DOT export against live Neo4j (if available)**

```bash
cd graph && python3 report_graphviz.py \
  --neo4j bolt://localhost:7687 \
  --output /tmp/rootstock.dot

# Validate DOT syntax
head -5 /tmp/rootstock.dot  # Should start with "digraph rootstock {"

# Render to PNG if Graphviz installed
which dot && dot -Tpng /tmp/rootstock.dot -o /tmp/rootstock.png && echo "PNG rendered"
```

- [ ] **Step 5: Test HTML output format**

```bash
cd graph && python3 report.py \
  --neo4j bolt://localhost:7687 \
  --output /tmp/rootstock-report.html \
  --format html

head -5 /tmp/rootstock-report.html  # Should start with <!DOCTYPE html>
```

- [ ] **Step 6: Final commit**

```bash
git add graph/report.py graph/report_diagrams.py graph/report_graphviz.py \
        graph/tests/test_report_diagrams.py graph/tests/test_report.py \
        graph/requirements.txt
git commit -m "[graph] Phase 4.1 complete — static report generator with Mermaid and Graphviz"
```

---

## Acceptance Criteria Checklist

- [ ] `python3 graph/report.py --neo4j bolt://... --output report.md` produces a Markdown file
- [ ] Report has all sections: Metadata, Executive Summary, Critical/High/Informational findings, Recommendations
- [ ] At least one Mermaid attack path diagram generated for critical findings
- [ ] Mermaid pie chart shows TCC grant distribution
- [ ] Tables are properly formatted Markdown (GitHub-flavored)
- [ ] Graphviz DOT export produces valid syntax
- [ ] Report runs without error on a graph with real scan data
- [ ] Report handles empty query results gracefully ("No findings in this category")
- [ ] Recommendations are actionable (not generic placeholder text)
- [ ] Executive summary counts reflect actual query results
- [ ] All unit tests pass (`pytest tests/`)
