"""
report.py — Rootstock Security Assessment Report Generator.

CLI: python3 report.py --neo4j bolt://localhost:7687 --output report.md
     python3 report.py --neo4j bolt://localhost:7687 --output report.html --format html
     python3 report.py --neo4j bolt://localhost:7687 --output report.md --scan-json scan.json

Architecture:
  1. Connect to Neo4j, run all queries from graph/queries/*.cypher
  2. Format each result set into a Markdown section with tabulate
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


# ── No-findings Placeholder ───────────────────────────────────────────────────

def format_no_findings() -> str:
    return "_No findings in this category._"


# ── Value Coercion ────────────────────────────────────────────────────────────

def _list_or_str(value) -> str:
    """Convert list values from Neo4j to a comma-separated string."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value) if value is not None else "—"


# ── Section Formatters ────────────────────────────────────────────────────────

def format_injectable_fda_table(rows: list[dict]) -> str:
    """Format Query 01 results: injectable apps with Full Disk Access."""
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

    risk_lines = []
    for r in rows:
        app = r.get("app_name", "?")
        methods = _list_or_str(r.get("injection_methods", []))
        risk_lines.append(
            f"- **{app}**: Attacker can inject via `{methods}` to inherit Full Disk Access."
        )

    return table + "\n\n" + "\n".join(risk_lines)


def format_electron_table(rows: list[dict]) -> str:
    """Format Query 03 results: Electron apps with TCC inheritance."""
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
    """Format Query 05 results: Apple Event TCC cascade."""
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
    """Format Query 07 section-1 results: TCC grant distribution."""
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
    """Format Query 04 results: private entitlement audit."""
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


def _first_cypher_statement(cypher: str) -> str:
    """
    Extract the first Cypher statement from a multi-statement file.
    Statements are delimited by semicolons. Comment-only content is skipped.
    """
    for stmt in cypher.split(";"):
        stripped = stmt.strip()
        # Skip if the statement is only comments
        non_comment = "\n".join(
            line for line in stripped.splitlines() if not line.strip().startswith("//")
        ).strip()
        if non_comment:
            return stripped
    return cypher.strip()


def run_query(session, cypher: str, params: dict | None = None) -> list[dict]:
    """Run a single Cypher statement, return list of record dicts."""
    result = session.run(cypher, params or {})
    return [dict(r) for r in result]


def run_all_queries(driver, queries_dir: Path) -> dict[str, list[dict] | str]:
    """
    Run all queries from queries_dir, returning results keyed by filename.
    On failure, stores an error string instead of a list.
    """
    results: dict[str, list[dict] | str] = {}

    with driver.session() as session:
        for filename in QUERY_FILES:
            cypher = _load_query(queries_dir, filename)
            if cypher is None:
                results[filename] = f"Query file not found: {filename}"
                continue

            try:
                stmt = _first_cypher_statement(cypher)
                rows = run_query(session, stmt)
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
            row = dict(session.run("""
                MATCH (a:Application)
                WITH count(a) AS app_count
                OPTIONAL MATCH (g:Application)-[:HAS_TCC_GRANT]->(p:TCC_Permission)
                WITH app_count, count(g) AS tcc_grant_count
                OPTIONAL MATCH (e:Application)-[:HAS_ENTITLEMENT]->(en:Entitlement)
                RETURN app_count, tcc_grant_count, count(en) AS entitlement_count
            """).single() or {})
        except Exception:
            row = {}

        try:
            meta_row = dict(session.run("""
                MATCH (a:Application) WHERE a.scan_id IS NOT NULL
                RETURN a.scan_id AS scan_id, a.hostname AS hostname,
                       a.macos_version AS macos_version
                LIMIT 1
            """).single() or {})
        except Exception:
            meta_row = {}

    return {**row, **meta_row}


def get_scan_metadata_from_json(json_path: Path) -> dict:
    """Read scan metadata from the original collector JSON file."""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        elev = data.get("elevation", {})
        return {
            "scan_id": data.get("scan_id", "unknown"),
            "hostname": data.get("hostname", socket.gethostname()),
            "macos_version": data.get("macos_version", "unknown"),
            "collector_version": data.get("collector_version", "unknown"),
            "timestamp": data.get("timestamp", "unknown"),
            "is_root": elev.get("is_root", False),
            "has_fda": elev.get("has_fda", False),
            "app_count": len(data.get("applications", [])),
            "tcc_grant_count": len(data.get("tcc_grants", [])),
            "entitlement_count": sum(
                len(a.get("entitlements", [])) for a in data.get("applications", [])
            ),
        }
    except Exception as e:
        return {"error": str(e)}


# ── Recommendations ───────────────────────────────────────────────────────────

RECOMMENDATIONS = {
    "injectable_fda": [
        "Enable Hardened Runtime for all first-party and in-house applications via the entitlements editor in Xcode.",
        "Enable Library Validation (`com.apple.security.cs.require-library-validation`) to prevent unsigned dylib injection.",
        "Audit all applications with Full Disk Access — revoke unnecessary grants via System Settings → Privacy & Security → Full Disk Access.",
        "Use `codesign --verify --deep --strict` in CI/CD pipelines to catch hardened-runtime regressions before release.",
    ],
    "electron_inheritance": [
        "Disable `ELECTRON_RUN_AS_NODE` support in production Electron builds by passing `--disable-node-options` or using `app.commandLine.appendSwitch`.",
        "Sandbox Electron apps using macOS App Sandbox where feasible to limit the blast radius of ELECTRON_RUN_AS_NODE abuse.",
        "Apply least privilege: Electron apps should not hold TCC permissions they don't actively need; request only what is strictly required.",
    ],
    "apple_events": [
        "Audit Apple Event automation grants in TCC — revoke `kTCCServiceAppleEvents` grants to low-trust or injectable apps.",
        "Implement Apple Event permission review as part of quarterly access reviews alongside FDA and Accessibility grants.",
    ],
    "general": [
        "Ensure System Integrity Protection (SIP) is enabled on all managed endpoints (`csrutil status`).",
        "Enforce Full Disk Access via MDM Privacy Preferences Policy Control (PPPC) profiles — maintain an allow-list of approved applications.",
        "Review all LaunchDaemons and LaunchAgents with `launchctl list` and remove any unrecognised or unnecessary persistence items.",
        "Deploy application allow-listing via PPPC profiles through your MDM solution.",
        "Run Rootstock periodically (e.g., monthly or after major software installs) to detect new attack paths introduced by vendor updates.",
    ],
}


# ── Report Assembly ───────────────────────────────────────────────────────────

def assemble_report(
    query_results: dict[str, list[dict] | str],
    metadata: dict,
) -> str:
    """Assemble the full Markdown report from query results and metadata."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

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

    # Build top 3 attack path descriptions for the executive summary
    top_paths: list[str] = []
    for row in injectable_rows[:2]:
        app = row.get("app_name", "?")
        methods = _list_or_str(row.get("injection_methods", []))
        top_paths.append(
            f"{app} has Full Disk Access and is injectable via `{methods}`."
        )
    for row in electron_rows[:1]:
        app = row.get("app_name", "?")
        perms = _list_or_str(row.get("inherited_permissions", []))
        top_paths.append(
            f"{app} (Electron) inherits TCC permissions ({perms}) via ELECTRON_RUN_AS_NODE abuse."
        )

    sections: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    sections.append("# Rootstock Security Assessment Report")
    sections.append(f"_Generated: {now}_")
    sections.append("")

    # ── Scan Metadata ─────────────────────────────────────────────────────────
    sections.append("## Scan Metadata")
    meta_table = [
        ["Hostname", metadata.get("hostname") or socket.gethostname()],
        ["macOS Version", metadata.get("macos_version") or "unknown"],
        ["Scan Timestamp", metadata.get("timestamp") or now],
        ["Scan ID", metadata.get("scan_id") or "unknown"],
        ["Collector Version", metadata.get("collector_version") or "unknown"],
        ["Elevation", "root" if metadata.get("is_root") else "user"],
        ["Full Disk Access (collector)", "Yes" if metadata.get("has_fda") else "No"],
        ["Total Apps Scanned", str(metadata.get("app_count") or "unknown")],
        ["TCC Grants Found", str(metadata.get("tcc_grant_count") or "unknown")],
        ["Entitlements Extracted", str(metadata.get("entitlement_count") or "unknown")],
    ]
    sections.append(tabulate(meta_table, tablefmt="github"))
    sections.append("")

    # ── Executive Summary ─────────────────────────────────────────────────────
    sections.append("## Executive Summary")
    sections.append(format_executive_summary(critical_count, high_count, top_paths))
    sections.append("")

    # ── Critical: Injectable FDA Apps ─────────────────────────────────────────
    sections.append("## Critical Findings: Injectable Apps with Privileged TCC Grants")
    sections.append(
        "> **Risk:** An attacker who controls a dylib can inject it into these apps "
        "and inherit their Full Disk Access grant — enabling read/write of TCC.db, "
        "Mail, SSH keys, and all user files without prompting the user."
    )
    sections.append("")
    sections.append(format_injectable_fda_table(injectable_rows))
    sections.append("")

    if path_rows:
        sections.append("### Attack Path Diagrams (Shortest Paths to Full Disk Access)")
        sections.append(mermaid_attack_paths_block(path_rows, max_paths=3))
    elif injectable_rows:
        sections.append("### Attack Path Diagrams")
        # Synthesise path rows from injectable results when query 02 returned nothing
        synthetic = [
            {
                "node_names": ["attacker_payload", r.get("app_name", "?"), "Full Disk Access"],
                "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
                "path_length": 2,
            }
            for r in injectable_rows[:3]
        ]
        sections.append(mermaid_attack_paths_block(synthetic, max_paths=3))
    sections.append("")

    # ── High: Electron TCC Inheritance ────────────────────────────────────────
    sections.append("## High Findings: Electron TCC Inheritance")
    sections.append(
        "> **Risk:** Electron apps can be abused via the `ELECTRON_RUN_AS_NODE` environment "
        "variable to spawn a Node.js interpreter that inherits the parent process's TCC "
        "permissions. An attacker with local code execution can exploit this silently."
    )
    sections.append("")
    sections.append(format_electron_table(electron_rows))
    sections.append("")

    # ── High: Apple Event TCC Cascade ─────────────────────────────────────────
    sections.append("## High Findings: Apple Event TCC Cascade")
    sections.append(
        "> **Risk:** An app with Apple Event automation permission over a privileged app "
        "can invoke that app's capabilities transitively, gaining effective access to the "
        "target's TCC grants without holding those grants directly."
    )
    sections.append("")
    sections.append(format_apple_event_table(apple_event_rows))
    sections.append("")

    # ── Informational: TCC Grant Overview ─────────────────────────────────────
    sections.append("## Informational: TCC Grant Overview")
    sections.append(format_tcc_overview_table(tcc_overview_rows))
    sections.append("")

    if tcc_overview_rows:
        sections.append("### TCC Permission Distribution")
        sections.append(mermaid_tcc_pie(tcc_overview_rows))
        sections.append("")

    # ── Informational: Private Entitlement Audit ──────────────────────────────
    sections.append("## Informational: Private Entitlement Audit")
    sections.append(
        "> Private Apple entitlements (`com.apple.private.*`) grant capabilities not "
        "available to App Store apps. Third-party apps holding these are high-value "
        "targets: compromising them may yield elevated privileges."
    )
    sections.append("")
    sections.append(format_private_entitlement_table(private_ent_rows))
    sections.append("")

    # ── Recommendations ───────────────────────────────────────────────────────
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

    # ── Appendix: Raw Query Results ───────────────────────────────────────────
    sections.append("## Appendix: Raw Query Results")
    sections.append(
        "Full output of each query for detailed analysis or import into other tools."
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
            # Collect all keys across all rows to handle inconsistent key sets safely
            all_keys: list[str] = []
            seen_keys: set[str] = set()
            for row in result:
                for k in row.keys():
                    if k not in seen_keys:
                        all_keys.append(k)
                        seen_keys.add(k)
            table_rows = [[_list_or_str(row.get(h)) for h in all_keys] for row in result]
            sections.append(tabulate(table_rows, headers=all_keys, tablefmt="github"))

        sections.append("")

    return "\n".join(sections)


# ── HTML Conversion ───────────────────────────────────────────────────────────

def markdown_to_html(md: str) -> str:
    """Convert Markdown report to HTML. Uses `markdown` package if available."""
    try:
        import markdown as md_lib
        body = md_lib.markdown(md, extensions=["tables", "fenced_code"])
    except ImportError:
        # Minimal fallback — preserves readability without the markdown package
        lines = []
        for line in md.split("\n"):
            if line.startswith("# "):
                lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                lines.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("- "):
                lines.append(f"<li>{line[2:]}</li>")
            elif line.strip():
                lines.append(f"<p>{line}</p>")
        body = "\n".join(lines)

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Rootstock Security Assessment Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            max-width: 1200px; margin: 40px auto; padding: 0 20px; color: #333; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 0.9em; }}
    th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
    th {{ background: #f4f4f4; font-weight: 600; }}
    tr:nth-child(even) {{ background: #fafafa; }}
    blockquote {{ background: #fff8e1; border-left: 4px solid #ffc107;
                  padding: 10px 15px; margin: 1em 0; border-radius: 0 4px 4px 0; }}
    code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }}
    pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    h1 {{ color: #c62828; border-bottom: 3px solid #c62828; padding-bottom: 8px; }}
    h2 {{ color: #333; border-bottom: 2px solid #eee; padding-bottom: 4px; margin-top: 2em; }}
    h3 {{ color: #555; margin-top: 1.5em; }}
  </style>
</head>
<body>
{body}
</body>
</html>"""


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
    md = assemble_report(query_results, metadata)

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
