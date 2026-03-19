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
    from neo4j import GraphDatabase  # noqa: F401 — used by import_nodes
    from neo4j.exceptions import ServiceUnavailable, AuthError  # noqa: F401
except ImportError:
    print("ERROR: neo4j driver not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)

try:
    from pydantic import ValidationError
except ImportError:
    print("ERROR: pydantic not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)

from neo4j_connection import add_neo4j_args, connect_from_args
from models import ScanResult
from import_nodes import (
    import_applications,
    import_tcc_grants,
    import_entitlements,
    import_signed_by_team,
    import_xpc_services,
    import_keychain_items,
    import_mdm_profiles,
    import_launch_items,
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
    counts = {}
    for label in ["Application", "Entitlement", "TCC_Permission", "XPC_Service",
                   "LaunchItem", "Keychain_Item", "MDM_Profile", "User"]:
        row = session.run(f"MATCH (n:{label}) RETURN count(n) AS n").single()
        counts[label] = row["n"]
    for rel_type in ["HAS_TCC_GRANT", "HAS_ENTITLEMENT", "SIGNED_BY_SAME_TEAM",
                     "COMMUNICATES_WITH", "PERSISTS_VIA", "RUNS_AS",
                     "CAN_READ_KEYCHAIN", "CONFIGURES"]:
        row = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS n").single()
        counts[rel_type] = row["n"]
    return counts


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
    add_neo4j_args(parser)
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
    print(f"  xpc:      {len(scan.xpc_services)}")
    print(f"  keychain: {len(scan.keychain_acls)}")
    print(f"  mdm:      {len(scan.mdm_profiles)}")
    print(f"  items:    {len(scan.launch_items)}")
    print(f"  errors:   {len(scan.errors)}")

    driver = connect_from_args(args)

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

        n_xpc, n_comm = import_xpc_services(session, scan.xpc_services)
        print(f"  XPC services:  {n_xpc} nodes, {n_comm} COMMUNICATES_WITH edges")

        n_kc, n_kc_edges = import_keychain_items(session, scan.keychain_acls)
        print(f"  Keychain ACLs: {n_kc} nodes, {n_kc_edges} CAN_READ_KEYCHAIN edges")

        n_mdm, n_cfg = import_mdm_profiles(session, scan.mdm_profiles)
        print(f"  MDM profiles:  {n_mdm} nodes, {n_cfg} CONFIGURES edges")

        n_items, n_persists, n_runs = import_launch_items(session, scan.launch_items)
        print(f"  Launch items:  {n_items} nodes, {n_persists} PERSISTS_VIA, {n_runs} RUNS_AS edges")

        stats = query_stats(session)
        security = query_security_summary(session)

    driver.close()

    total_rels = sum(v for k, v in stats.items() if k.isupper() and "_" in k)
    total_nodes = sum(v for k, v in stats.items() if not (k.isupper() and "_" in k))
    print(f"\nGraph totals: {total_nodes} nodes, {total_rels} relationships")
    print(
        f"  Nodes:  {stats['Application']} apps, {stats['Entitlement']} entitlements, "
        f"{stats['XPC_Service']} XPC, {stats['LaunchItem']} launch items, "
        f"{stats['Keychain_Item']} keychain, {stats['MDM_Profile']} MDM"
    )
    print(
        f"Applications with FDA: {security['fda_apps']}  |  "
        f"Injectable apps: {security['injectable_apps']}  |  "
        f"Electron apps: {security['electron_apps']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
