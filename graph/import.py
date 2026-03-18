#!/usr/bin/env python3
"""
import.py — Import a Rootstock collector scan JSON into Neo4j.

Usage:
    python3 graph/import.py --input scan.json [--neo4j bolt://localhost:7687] [--user neo4j] [--password rootstock]

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable, AuthError
except ImportError:
    print("ERROR: neo4j driver not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)

try:
    from pydantic import ValidationError
except ImportError:
    print("ERROR: pydantic not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)

from models import ScanResult
from import_nodes import (
    import_applications,
    import_tcc_grants,
    import_entitlements,
    import_signed_by_team,
)

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def load_scan(path: Path) -> ScanResult | None:
    """Load and validate a scan JSON file. Returns None on fatal error."""
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {path}: {e}", file=sys.stderr)
        return None

    try:
        return ScanResult.model_validate(data)
    except ValidationError as e:
        print(f"ERROR: Scan JSON failed schema validation:\n{e}", file=sys.stderr)
        return None


def query_stats(session) -> dict:
    """Query post-import node and relationship counts for reporting."""
    result = session.run(
        """
        MATCH (a:Application) WITH count(a) AS apps
        OPTIONAL MATCH ()-[tcc:HAS_TCC_GRANT]->() WITH apps, count(tcc) AS tcc_rels
        OPTIONAL MATCH ()-[ent:HAS_ENTITLEMENT]->() WITH apps, tcc_rels, count(ent) AS ent_rels
        OPTIONAL MATCH ()-[team:SIGNED_BY_SAME_TEAM]->() WITH apps, tcc_rels, ent_rels, count(team) AS team_rels
        OPTIONAL MATCH (e:Entitlement) WITH apps, tcc_rels, ent_rels, team_rels, count(e) AS entitlements
        RETURN apps, tcc_rels, ent_rels, team_rels, entitlements
        """
    )
    row = result.single()
    return dict(row)


def query_security_summary(session) -> dict:
    """Query security-relevant aggregate stats as smoke-test output."""
    fda = session.run(
        """
        MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        RETURN count(a) AS n
        """
    ).single()["n"]

    injectable = session.run(
        """
        MATCH (a:Application)
        WHERE size(a.injection_methods) > 0
        RETURN count(a) AS n
        """
    ).single()["n"]

    electron = session.run(
        "MATCH (a:Application {is_electron: true}) RETURN count(a) AS n"
    ).single()["n"]

    return {"fda_apps": fda, "injectable_apps": injectable, "electron_apps": electron}


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a Rootstock scan JSON into Neo4j")
    parser.add_argument("--input", required=True, help="Path to scan JSON file")
    parser.add_argument("--neo4j", default="bolt://localhost:7687", dest="uri")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default="rootstock")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        return 1

    print(f"Loading {input_path}...")
    scan = load_scan(input_path)
    if scan is None:
        return 1

    print(f"  scan_id:  {scan.scan_id}")
    print(f"  hostname: {scan.hostname}")
    print(f"  apps:     {len(scan.applications)}")
    print(f"  grants:   {len(scan.tcc_grants)}")
    print(f"  errors:   {len(scan.errors)}")

    print(f"\nConnecting to Neo4j at {args.uri}...")
    try:
        driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
        driver.verify_connectivity()
    except ServiceUnavailable:
        print(f"ERROR: Cannot connect to Neo4j at {args.uri}", file=sys.stderr)
        return 1
    except AuthError:
        print("ERROR: Authentication failed. Check --user / --password.", file=sys.stderr)
        return 1

    print("Importing...")
    with driver.session() as session:
        n_apps = import_applications(session, scan.applications, scan.scan_id)
        print(f"  Applications:  {n_apps}")

        grants_linked, grants_skipped = import_tcc_grants(session, scan.tcc_grants, scan.scan_id)
        print(f"  TCC grants:    {grants_linked} linked, {grants_skipped} skipped (path-only clients)")

        n_ents, n_ent_rels = import_entitlements(session, scan.applications)
        print(f"  Entitlements:  {n_ents} nodes, {n_ent_rels} relationships")

        n_team_rels = import_signed_by_team(session)
        print(f"  Team edges:    {n_team_rels}")

        stats = query_stats(session)
        security = query_security_summary(session)

    driver.close()

    total_rels = stats["tcc_rels"] + stats["ent_rels"] + stats["team_rels"]
    print(
        f"\nImported {n_apps} applications, {grants_linked} TCC grants, "
        f"{n_ents} entitlements, {total_rels} relationships"
    )
    print(
        f"Applications with FDA: {security['fda_apps']}  |  "
        f"Injectable apps: {security['injectable_apps']}  |  "
        f"Electron apps: {security['electron_apps']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
