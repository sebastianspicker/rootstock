#!/usr/bin/env python3
"""
setup_schema.py — Create Neo4j indexes and constraints for the Rootstock graph.

Run once before the first import, or re-run safely (all statements use IF NOT EXISTS).

Usage:
    python3 graph/setup_schema.py [--neo4j bolt://localhost:7687] [--username neo4j] [--password rootstock]
"""

from __future__ import annotations

import argparse
import sys

try:
    from neo4j import GraphDatabase  # noqa: F401
except ImportError:
    print("ERROR: neo4j driver not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)

from neo4j_connection import add_neo4j_args, connect_from_args

# ── Schema definitions ───────────────────────────────────────────────────────

# Uniqueness constraints (also create implicit indexes)
CONSTRAINTS = [
    ("app_bundle_unique",     "Application",    "a.bundle_id"),
    ("tcc_service_unique",    "TCC_Permission",  "t.service"),
    ("ent_name_unique",       "Entitlement",     "e.name"),
    ("xpc_label_unique",      "XPC_Service",     "x.label"),
    ("launch_label_unique",   "LaunchItem",      "l.label"),
    ("mdm_id_unique",         "MDM_Profile",     "m.identifier"),
    ("user_name_unique",      "User",            "u.name"),
]

# Composite uniqueness constraint (Keychain items keyed by label + kind)
COMPOSITE_CONSTRAINTS = [
    ("keychain_label_kind_unique", "Keychain_Item", "k.label", "k.kind"),
]

# Additional indexes for query performance (beyond what constraints provide)
INDEXES = [
    ("app_team_id",  "Application", "a.team_id"),
    ("app_scan_id",  "Application", "a.scan_id"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Create Neo4j schema (indexes + constraints) for Rootstock")
    add_neo4j_args(parser)
    args = parser.parse_args()

    driver = connect_from_args(args)

    print("Creating schema...")
    with driver.session() as session:
        for name, label, prop in CONSTRAINTS:
            var = prop.split(".")[0]
            prop_name = prop.split(".")[1]
            stmt = (
                f"CREATE CONSTRAINT {name} IF NOT EXISTS "
                f"FOR ({var}:{label}) REQUIRE {var}.{prop_name} IS UNIQUE"
            )
            session.run(stmt)
            print(f"  ✓ UNIQUE {label}.{prop_name}")

        for name, label, *props in COMPOSITE_CONSTRAINTS:
            var = props[0].split(".")[0]
            prop_list = ", ".join(props)
            stmt = (
                f"CREATE CONSTRAINT {name} IF NOT EXISTS "
                f"FOR ({var}:{label}) REQUIRE ({prop_list}) IS UNIQUE"
            )
            session.run(stmt)
            prop_names = ", ".join(p.split(".")[1] for p in props)
            print(f"  ✓ UNIQUE {label}.({prop_names})")

        for name, label, prop in INDEXES:
            var = prop.split(".")[0]
            prop_name = prop.split(".")[1]
            stmt = (
                f"CREATE INDEX {name} IF NOT EXISTS "
                f"FOR ({var}:{label}) ON ({var}.{prop_name})"
            )
            session.run(stmt)
            print(f"  ✓ INDEX  {label}.{prop_name}")

    driver.close()
    print("Schema setup complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
