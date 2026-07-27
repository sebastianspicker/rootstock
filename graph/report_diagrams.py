"""
report_diagrams.py - Mermaid diagram generation for Rootstock security reports.

All functions are pure (no Neo4j dependency) - they take query result dicts
and return formatted diagram strings suitable for embedding in Markdown.
"""

from __future__ import annotations

import html as html_mod

from utils import sanitize_id as sanitize_mermaid_id, truncate as _truncate


# ── TCC Node Detection ────────────────────────────────────────────────────────

_TCC_KEYWORDS = {
    "full disk access",
    "accessibility",
    "screen recording",
    "microphone",
    "camera",
    "location",
    "contacts",
    "calendar",
    "reminders",
    "photos",
    "bluetooth",
    "homekit",
    "health",
    "appleevents",
    "developer tools",
}


def _safe_label(value: object, max_len: int = 30) -> str:
    label = _truncate(str(value), max_len).replace('"', "'")
    return html_mod.escape(label, quote=True)


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
            - node_names: list[str] - display names of nodes in path
            - rel_types:  list[str] - relationship types between nodes
            - path_length: int

    Returns:
        Mermaid flowchart string (fenced code block), or "" if path is empty.
    """
    nodes: list[str] = path_result.get("node_names") or []
    rels: list[str] = path_result.get("rel_types") or []

    if not nodes or len(nodes) < 2:
        return ""

    nodes, rels = _normalise_attack_path(nodes, rels)
    edge_count = len(rels)

    lines = ["```mermaid", "graph LR"]

    # Unique node IDs: sanitize name + index suffix to avoid collisions
    ids = [sanitize_mermaid_id(n) + str(i) for i, n in enumerate(nodes)]

    _append_attack_path_nodes(lines, nodes, ids)
    _append_attack_path_edges(lines, rels, ids, edge_count)
    _append_attack_path_styles(lines, nodes, ids)
    lines.append("```")
    return "\n".join(lines)


def _normalise_attack_path(
    nodes: list[str], rels: list[str]
) -> tuple[list[str], list[str]]:
    edge_count = min(len(nodes) - 1, len(rels))
    return nodes[: edge_count + 1], rels[:edge_count]


def _append_attack_path_nodes(
    lines: list[str], nodes: list[str], ids: list[str]
) -> None:
    for name, node_id in zip(nodes, ids, strict=True):
        label = _safe_label(name)
        lines.append(f'  {node_id}["{label}"]')


def _append_attack_path_edges(
    lines: list[str],
    rels: list[str],
    ids: list[str],
    edge_count: int,
) -> None:
    for i in range(edge_count):
        src = ids[i]
        dst = ids[i + 1]
        rel = _safe_label(rels[i])
        lines.append(f"  {src} -->|{rel}| {dst}")


def _append_attack_path_styles(
    lines: list[str], nodes: list[str], ids: list[str]
) -> None:
    for name, node_id in zip(nodes, ids, strict=True):
        if _is_tcc_node(name):
            lines.append(f"  style {node_id} fill:#ff6666,color:#fff")
        elif "attacker" in name.lower():
            lines.append(f"  style {node_id} fill:#ff9933,color:#fff")


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
                steps.append(f"`{_safe_label(name)}`")
                if j < len(rel_types):
                    steps.append(f"→ _{_safe_label(rel_types[j])}_ →")
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
        safe_label = _safe_label(label)
        lines.append(f'  "{safe_label}" : {count}')
    lines.append("```")
    return "\n".join(lines)


# ── Tier Classification Pie Chart ─────────────────────────────────────────────


def mermaid_tier_pie(tier_counts: dict[str, int]) -> str:
    """
    Generate a Mermaid pie chart of Tier 0 / Tier 1 / Tier 2 / Unclassified counts.

    Args:
        tier_counts: pre-aggregated counts keyed by tier label (e.g. {"Tier 0": 5, ...}).

    Returns:
        Mermaid pie chart string (fenced code block).
    """
    if not tier_counts:
        return "_No tier classification data available._"

    # Sort tiers in a natural order
    tier_order = ["Tier 0", "Tier 1", "Tier 2", "Unclassified"]
    sorted_tiers = sorted(
        tier_counts.keys(), key=lambda t: tier_order.index(t) if t in tier_order else 99
    )

    lines = ["```mermaid", "pie title Application Tier Classification"]
    for tier in sorted_tiers:
        safe_label = _safe_label(tier)
        lines.append(f'  "{safe_label}" : {tier_counts[tier]}')
    lines.append("```")
    return "\n".join(lines)


# ── Physical Security Posture Summary ─────────────────────────────────────────


def _posture_checks(row: dict) -> list[tuple[str, str, object]]:
    return [
        ("lockdown_mode", "Lockdown Mode", row.get("lockdown_mode")),
        ("screen_lock", "Screen Lock", row.get("screen_lock")),
        ("filevault", "FileVault", row.get("filevault")),
        ("sip", "SIP", row.get("sip")),
        ("bt_discoverable", "BT Discoverable", row.get("bluetooth_discoverable")),
        ("secure_boot", "Secure Boot", row.get("secure_boot")),
        ("external_boot", "External Boot", row.get("external_boot")),
        ("thunderbolt", "Thunderbolt Security", row.get("thunderbolt_security")),
    ]


def _posture_bool_colour(check_id: str, value: bool) -> str:
    if check_id in ("bt_discoverable", "external_boot"):
        # Discoverable / external boot allowed = bad
        return "#ff6666" if value else "#66bb6a"
    return "#66bb6a" if value else "#ff6666"


def _posture_text_colour(check_id: str, value: object) -> str:
    if check_id in ("thunderbolt", "secure_boot"):
        return "#66bb6a" if str(value).lower() == "full" else "#ff9933"
    return "#42a5f5"


def _append_posture_check(
    lines: list[str], host_id: str, check_id: str, label: str, value: object
) -> None:
    node_id = f"{host_id}_{check_id}"
    if isinstance(value, bool):
        display = "Enabled" if value else "Disabled"
        lines.append(f'  {node_id}["{label}: {display}"]')
        lines.append(f"  {host_id} --> {node_id}")
        colour = _posture_bool_colour(check_id, value)
        lines.append(f"  style {node_id} fill:{colour},color:#fff")
    elif value is not None:
        safe_value = _safe_label(value)
        lines.append(f'  {node_id}["{label}: {safe_value}"]')
        lines.append(f"  {host_id} --> {node_id}")
        colour = _posture_text_colour(check_id, value)
        lines.append(f"  style {node_id} fill:{colour},color:#fff")


def mermaid_posture_summary(posture_rows: list[dict]) -> str:
    """
    Generate a Mermaid graph showing physical security posture per host.

    Args:
        posture_rows: query 67 results - each row has host posture properties.

    Returns:
        Mermaid graph string (fenced code block).
    """
    if not posture_rows:
        return "_No physical security posture data available._"

    row = posture_rows[0]  # First host
    hostname = str(row.get("hostname", row.get("computer", "Host")))
    host_id = sanitize_mermaid_id(hostname)

    lines = ["```mermaid", "graph TD"]
    safe_hostname = _safe_label(hostname, 25)
    lines.append(f'  {host_id}["{safe_hostname}"]')

    for check_id, label, value in _posture_checks(row):
        _append_posture_check(lines, host_id, check_id, label, value)

    lines.append("```")
    return "\n".join(lines)


# ── iCloud Risk Flow Diagram ─────────────────────────────────────────────────


def mermaid_icloud_risk_flow(icloud_rows: list[dict]) -> str:
    """
    Generate a Mermaid LR flowchart showing injectable app → iCloud entitlement → synced data.

    Args:
        icloud_rows: query 68 results - top injectable apps with iCloud entitlements.

    Returns:
        Mermaid flowchart string (fenced code block).
    """
    if not icloud_rows:
        return "_No iCloud risk data available._"

    lines = ["```mermaid", "graph LR"]
    lines.append('  attacker["Attacker Code"]')
    lines.append("  style attacker fill:#ff9933,color:#fff")

    seen_apps: set[str] = set()
    emitted: list[str] = []  # track ent_ids for the sync edges

    for row in icloud_rows:
        app_name = str(row.get("app_name", row.get("name", "?")))
        if app_name in seen_apps:
            continue
        seen_apps.add(app_name)
        if len(seen_apps) > 3:
            break

        idx = len(emitted)
        app_id = sanitize_mermaid_id(app_name) + str(idx)
        ent_label = str(
            row.get("icloud_entitlement", row.get("entitlement", "iCloud Container"))
        )
        ent_id = f"ent_{idx}"
        emitted.append(ent_id)

        lines.append(f'  {app_id}["{_safe_label(app_name)}"]')
        lines.append(f"  style {app_id} fill:#ff6666,color:#fff")
        lines.append(f'  {ent_id}["{_safe_label(ent_label)}"]')
        lines.append(f"  style {ent_id} fill:#42a5f5,color:#fff")

        lines.append(f"  attacker -->|CAN_INJECT_INTO| {app_id}")
        lines.append(f"  {app_id} -->|HAS_ENTITLEMENT| {ent_id}")

    lines.append('  icloud_sync["iCloud Sync (All Devices)"]')
    lines.append("  style icloud_sync fill:#7e57c2,color:#fff")
    for ent_id in emitted:
        lines.append(f"  {ent_id} -->|syncs to| icloud_sync")

    lines.append("```")
    return "\n".join(lines)


# ── Family red/blue findings (open-export / multi-plane narrative) ─────────────


def mermaid_family_findings_block(
    findings: list[dict],
    *,
    source: str | None = None,
    max_findings: int = 8,
) -> str:
    """Render a Mermaid flowchart of family open-export findings.

    Distinguishes red vs blue via source / kind so operators can map
    red path-to-impact findings to blue harden/detect controls.

    Each finding dict may include: id, name/title, severity, source/kind,
    finding_id, category.
    """
    if not findings:
        return "_No family findings to diagram._"

    lines = ["```mermaid", "flowchart TB"]
    lines.append("  subgraph FamilyFindings[\"Family findings (red / blue)\"]")
    red_ids: list[str] = []
    blue_ids: list[str] = []

    for i, f in enumerate(findings[:max_findings]):
        fid = str(
            f.get("finding_id")
            or f.get("id")
            or f.get("name")
            or f"finding_{i}"
        )
        title = str(f.get("name") or f.get("title") or fid)
        sev = str(f.get("severity") or "info").lower()
        src = str(
            f.get("source")
            or f.get("family_source")
            or source
            or f.get("kind")
            or ""
        ).lower()
        is_red = "red" in src or src.endswith("rootstock-red") or "rs_red" in src
        is_blue = "blue" in src or src.endswith("rootstock-blue") or "rs_blue" in src
        if not is_red and not is_blue:
            # Heuristic: rootstock.vector / rootstock.check → red; harden/sample → blue
            lower_id = fid.lower()
            if lower_id.startswith("rootstock.") or "vector" in lower_id:
                is_red = True
            elif lower_id.startswith("harden.") or lower_id.startswith("sample.") or "control" in lower_id:
                is_blue = True
            else:
                is_red = True

        node_id = sanitize_mermaid_id(f"f{i}_{fid}")[:48]
        label = _safe_label(f"{'[R] ' if is_red else '[B] '}{title} ({sev})", max_len=42)
        lines.append(f"    {node_id}[\"{label}\"]")
        if is_red:
            red_ids.append(node_id)
        else:
            blue_ids.append(node_id)

    lines.append("  end")
    for nid in red_ids:
        lines.append(f"  style {nid} fill:#c0392b,color:#fff,stroke:#7b241c")
    for nid in blue_ids:
        lines.append(f"  style {nid} fill:#2471a3,color:#fff,stroke:#1a5276")
    lines.append("```")
    return "\n".join(lines)


def format_family_findings_section(
    findings: list[dict],
    *,
    source: str | None = None,
    max_findings: int = 12,
) -> str:
    """Markdown section: family findings table + mermaid diagram."""
    if not findings:
        return (
            "## Family Red/Blue Findings\n\n"
            "_No family open-export findings provided._\n"
        )
    parts = [
        "## Family Red/Blue Findings",
        "",
        "> **Purple narrative:** Red findings are path-to-impact / assess surfaces; "
        "blue findings are offline harden/detect/forensic controls. Distinct OpenGraph "
        "kinds (`rs_RedFinding` / `rs_BlueFinding`) keep them legible in the viewer.",
        "",
        "| Side | Finding ID | Severity | Title |",
        "|------|------------|----------|-------|",
    ]
    for f in findings[:max_findings]:
        fid = str(f.get("finding_id") or f.get("id") or "?")
        title = str(f.get("name") or f.get("title") or fid).replace("|", "/")
        sev = str(f.get("severity") or "info")
        src = str(f.get("source") or source or "").lower()
        side = "red" if "red" in src or fid.startswith("rootstock.") else "blue"
        if fid.startswith("harden.") or fid.startswith("sample."):
            side = "blue"
        parts.append(f"| {side} | `{fid}` | {sev} | {title} |")
    parts.append("")
    parts.append("### Family findings diagram")
    parts.append(mermaid_family_findings_block(findings, source=source, max_findings=max_findings))
    parts.append("")
    return "\n".join(parts)


def format_multi_plane_campaign_section(
    planes: list[dict],
    *,
    campaign: str = "Wave multi-plane",
    max_planes: int = 12,
) -> str:
    """Markdown section summarizing multi-plane red/blue campaign themes.

    Each plane dict may include: id, title, red_ids (list), blue_ids (list),
    stage (delivery|persist|visibility|lateral|collection).
    """
    if not planes:
        return (
            f"## {campaign} campaign\n\n"
            "_No multi-plane themes provided._\n"
        )
    parts = [
        f"## {campaign} campaign",
        "",
        "> **Path-to-impact narrative:** each plane pairs red assess findings with blue "
        "harden/detect controls. Diagrams below are engagement ranking aids - not auto-exploit chains.",
        "",
        "| Plane | Stage | Red findings | Blue controls |",
        "|-------|-------|--------------|---------------|",
    ]
    mermaid_nodes: list[dict] = []
    for p in planes[:max_planes]:
        pid = str(p.get("id") or p.get("title") or "?")
        title = str(p.get("title") or pid).replace("|", "/")
        stage = str(p.get("stage") or "posture")
        reds = p.get("red_ids") or []
        blues = p.get("blue_ids") or []
        red_s = ", ".join(f"`{r}`" for r in reds[:3]) or " - "
        blue_s = ", ".join(f"`{b}`" for b in blues[:3]) or " - "
        parts.append(f"| {title} | {stage} | {red_s} | {blue_s} |")
        for r in reds[:2]:
            mermaid_nodes.append(
                {
                    "finding_id": r,
                    "name": r.split(".")[-1],
                    "severity": "medium",
                    "source": "rootstock-red",
                }
            )
        for b in blues[:2]:
            mermaid_nodes.append(
                {
                    "finding_id": b,
                    "name": b,
                    "severity": "medium",
                    "source": "rootstock-blue",
                }
            )
    parts.append("")
    parts.append("### Multi-plane family diagram")
    parts.append(mermaid_family_findings_block(mermaid_nodes, max_findings=max_planes * 2))
    parts.append("")
    return "\n".join(parts)


def format_multi_plane_severity_board(
    findings: list[dict],
    *,
    title: str = "Multi-plane severity board",
    max_items: int = 16,
) -> str:
    """Compact severity board for red/blue multi-plane findings in reports."""
    if not findings:
        return f"## {title}\n\n_No findings._\n"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(
        findings,
        key=lambda f: order.get(str(f.get("severity", "info")).lower(), 9),
    )
    parts = [
        f"## {title}",
        "",
        "> Ranked for purple operators: red path-to-impact first within severity bands; "
        "blue harden/detect second. Not an auto-exploit queue.",
        "",
        "| Sev | Side | ID | Title |",
        "|-----|------|----|-------|",
    ]
    for f in sorted_f[:max_items]:
        fid = str(f.get("finding_id") or f.get("id") or "?")
        name = str(f.get("name") or f.get("title") or fid).replace("|", "/")
        sev = str(f.get("severity") or "info")
        src = str(f.get("source") or "").lower()
        side = "red" if "red" in src or fid.startswith("rootstock.") else "blue"
        if fid.startswith("harden.") or fid.startswith("sample."):
            side = "blue"
        parts.append(f"| {sev} | {side} | `{fid}` | {name} |")
    parts.append("")
    parts.append(mermaid_family_findings_block(sorted_f[:max_items]))
    parts.append("")
    return "\n".join(parts)


def format_purple_engagement_matrix(
    pairs: list[dict],
    *,
    title: str = "Purple engagement matrix",
    max_pairs: int = 20,
) -> str:
    """Red finding → blue control matrix for multi-plane purple ops reports.

    Each pair dict: red_id, blue_id, plane, stage (optional).
    """
    if not pairs:
        return f"## {title}\n\n_No red↔blue pairs provided._\n"
    parts = [
        f"## {title}",
        "",
        "> **Purple operator view:** map red path-to-impact findings to blue "
        "offline parse/harden/detect controls. Assess-first - not auto-exploit.",
        "",
        "| Plane | Stage | Red assess ID | Blue defend ID |",
        "|-------|-------|---------------|----------------|",
    ]
    findings = []
    for p in pairs[:max_pairs]:
        plane = str(p.get("plane") or p.get("title") or "?").replace("|", "/")
        stage = str(p.get("stage") or "posture")
        red = str(p.get("red_id") or "")
        blue = str(p.get("blue_id") or "")
        parts.append(f"| {plane} | {stage} | `{red}` | `{blue}` |")
        if red:
            findings.append({"finding_id": red, "name": red.split(".")[-1], "severity": "medium", "source": "rootstock-red"})
        if blue:
            findings.append({"finding_id": blue if blue.startswith("harden.") else f"harden.{blue}", "name": blue, "severity": "medium", "source": "rootstock-blue"})
    parts.append("")
    parts.append("### Engagement matrix diagram")
    parts.append(mermaid_family_findings_block(findings, max_findings=max_pairs * 2))
    parts.append("")
    return "\n".join(parts)


def format_kill_chain_stage_timeline(
    stages: list[dict],
    *,
    title: str = "Kill-chain stage timeline",
    max_stages: int = 12,
) -> str:
    """Mermaid timeline of multi-plane engagement stages for purple reports.

    Each stage dict: stage, label, red_count (optional), blue_count (optional).
    """
    if not stages:
        return f"## {title}\n\n_No stages provided._\n"
    parts = [
        f"## {title}",
        "",
        "> **Path-to-impact narrative only** - stage labels rank operator attention, "
        "not automated exploit orchestration.",
        "",
        "```mermaid",
        "timeline",
        f"    title {title}",
    ]
    for s in stages[:max_stages]:
        stage = str(s.get("stage") or s.get("name") or "stage")
        label = str(s.get("label") or stage)
        red_n = s.get("red_count", "")
        blue_n = s.get("blue_count", "")
        detail = label
        if red_n != "" or blue_n != "":
            detail = f"{label} (R:{red_n} B:{blue_n})"
        parts.append(f"    {stage} : {detail}")
    parts.append("```")
    parts.append("")
    parts.append("| Stage | Red findings | Blue controls | Notes |")
    parts.append("|-------|--------------|---------------|-------|")
    for s in stages[:max_stages]:
        stage = str(s.get("stage") or "?")
        red_n = s.get("red_count", " - ")
        blue_n = s.get("blue_count", " - ")
        notes = str(s.get("label") or s.get("notes") or "").replace("|", "/")
        parts.append(f"| {stage} | {red_n} | {blue_n} | {notes} |")
    parts.append("")
    return "\n".join(parts)


def format_fleet_campaign_dashboard(
    campaigns: list[dict],
    *,
    title: str = "Fleet multi-plane campaign dashboard",
) -> str:
    """Aggregate dashboard for multi-wave red|blue half-pair campaigns.

    Each campaign dict: name, theme_count, half_pairs, stages (list[str]), highlight (optional).
    """
    if not campaigns:
        return f"## {title}\n\n_No campaigns provided._\n"
    total_themes = sum(int(c.get("theme_count") or 0) for c in campaigns)
    total_half = sum(int(c.get("half_pairs") or 0) for c in campaigns)
    parts = [
        f"## {title}",
        "",
        f"> **Campaign fleet:** {len(campaigns)} waves · {total_themes} multi-plane themes · "
        f"{total_half} red|blue half-pairs. Assess-first path-to-impact - not auto-exploit.",
        "",
        "| Campaign | Themes | Half-pairs | Stages | Highlight |",
        "|----------|--------|------------|--------|-----------|",
    ]
    findings = []
    for c in campaigns:
        name = str(c.get("name") or "?")
        themes = c.get("theme_count", " - ")
        half = c.get("half_pairs", " - ")
        stages = ", ".join(c.get("stages") or []) or " - "
        highlight = str(c.get("highlight") or "").replace("|", "/")
        parts.append(f"| {name} | {themes} | {half} | {stages} | {highlight} |")
        findings.append({
            "finding_id": f"campaign.{name}",
            "name": name,
            "severity": "high" if int(c.get("theme_count") or 0) >= 20 else "medium",
            "source": "rootstock-red" if "Wave" in name else "rootstock-blue",
        })
    parts.append("")
    parts.append("### Fleet diagram")
    parts.append(mermaid_family_findings_block(findings, max_findings=max(len(campaigns) * 2, 8)))
    parts.append("")
    return "\n".join(parts)
