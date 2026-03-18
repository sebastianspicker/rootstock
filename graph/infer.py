#!/usr/bin/env python3
"""
infer.py — Run all Rootstock inference modules to derive attack-path relationships.

Usage:
    python3 graph/infer.py [--neo4j bolt://localhost:7687] [--user neo4j] [--password rootstock]

All inferred edges carry {inferred: true} to distinguish them from explicit collector data.
Idempotent: safe to re-run on the same graph.

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable, AuthError
except ImportError:
    print("ERROR: neo4j driver not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)

import infer_injection
import infer_electron
import infer_automation


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Rootstock graph inference")
    parser.add_argument("--neo4j", default="bolt://localhost:7687", dest="uri")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default="rootstock")
    args = parser.parse_args()

    print(f"Connecting to Neo4j at {args.uri}...")
    try:
        driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
        driver.verify_connectivity()
    except ServiceUnavailable:
        print(f"ERROR: Cannot connect to Neo4j at {args.uri}", file=sys.stderr)
        return 1
    except AuthError:
        print("ERROR: Authentication failed.", file=sys.stderr)
        return 1

    print("Running inference...")
    with driver.session() as session:
        n_inject = infer_injection.infer(session)
        print(f"  CAN_INJECT_INTO:      {n_inject}")

        n_inherit = infer_electron.infer(session)
        print(f"  CHILD_INHERITS_TCC:   {n_inherit}")

        n_apple_events = infer_automation.infer(session)
        print(f"  CAN_SEND_APPLE_EVENT: {n_apple_events}")

    driver.close()

    total = n_inject + n_inherit + n_apple_events
    print(
        f"\nInferred {n_inject} CAN_INJECT_INTO, "
        f"{n_inherit} CHILD_INHERITS_TCC, "
        f"{n_apple_events} CAN_SEND_APPLE_EVENT edges"
    )
    if total == 0:
        print("Note: No inferred edges created. Import scan data first with: python3 graph/import.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
