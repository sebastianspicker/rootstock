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
    from neo4j import GraphDatabase  # noqa: F401
    from neo4j.exceptions import ServiceUnavailable, AuthError  # noqa: F401
except ImportError:
    print("ERROR: neo4j driver not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)

from neo4j_connection import add_neo4j_args, connect_from_args
import infer_injection
import infer_electron
import infer_automation


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Rootstock graph inference")
    add_neo4j_args(parser)
    args = parser.parse_args()

    driver = connect_from_args(args)

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
