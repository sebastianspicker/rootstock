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

from neo4j_connection import add_neo4j_args, connect_from_args

# ── Schema definitions ───────────────────────────────────────────────────────

# Uniqueness constraints (also create implicit indexes)
CONSTRAINTS = [
    ("app_bundle_unique",     "Application",         "a.bundle_id"),
    ("tcc_service_unique",    "TCC_Permission",       "t.service"),
    ("ent_name_unique",       "Entitlement",          "e.name"),
    ("xpc_label_unique",      "XPC_Service",          "x.label"),
    ("launch_label_unique",   "LaunchItem",           "l.label"),
    ("mdm_id_unique",         "MDM_Profile",          "m.identifier"),
    ("user_name_unique",      "User",                 "u.name"),
    ("group_name_unique",     "LocalGroup",           "g.name"),
    ("remote_svc_unique",     "RemoteAccessService",  "r.service"),
    ("firewall_name_unique",  "FirewallPolicy",       "f.name"),
    ("session_terminal_unique", "LoginSession",       "s.terminal"),
    ("auth_right_unique",      "AuthorizationRight", "ar.name"),
    ("auth_plugin_unique",     "AuthorizationPlugin","ap.name"),
    ("sysext_id_unique",       "SystemExtension",    "se.identifier"),
    ("sudoers_key_unique",     "SudoersRule",        "sr.key"),
    ("critfile_path_unique",   "CriticalFile",       "cf.path"),
    ("computer_hostname_unique", "Computer",         "c.hostname"),
    ("ca_sha256_unique",         "CertificateAuthority", "ca.sha256"),
    ("bt_device_addr_unique",    "BluetoothDevice",      "bt.address"),
    ("kerberos_path_unique",     "KerberosArtifact",     "ka.path"),
    ("adgroup_name_unique",      "ADGroup",              "ag.name"),
    ("vuln_cve_unique",          "Vulnerability",        "v.cve_id"),
    ("technique_id_unique",      "AttackTechnique",      "t.technique_id"),
    ("sandbox_bundle_unique",    "SandboxProfile",       "sp.bundle_id"),
    ("ad_user_sid_unique",       "ADUser",               "u.object_id"),
]

# Composite uniqueness constraint (Keychain items keyed by label + kind)
COMPOSITE_CONSTRAINTS = [
    ("keychain_label_kind_unique", "Keychain_Item", "k.label", "k.kind"),
]

# Additional indexes for query performance (beyond what constraints provide)
INDEXES = [
    ("app_team_id",  "Application", "a.team_id"),
    ("app_scan_id",  "Application", "a.scan_id"),
    ("app_owned",    "Application", "a.owned"),
    ("app_tier",     "Application", "a.tier"),
    ("vuln_cvss",    "Vulnerability",   "v.cvss_score"),
    ("vuln_epss",    "Vulnerability",   "v.epss_score"),
    ("vuln_kev",     "Vulnerability",   "v.in_kev"),
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
