"""
conftest.py — Shared pytest fixtures for Rootstock graph tests.

Provides:
  - Neo4j connection env vars (NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
  - neo4j_driver: session-scoped driver that skips if Neo4j is unavailable
  - cleanup_test_nodes(): utility to remove test data by scan_id
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure graph/ is on the import path
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Shared constants ─────────────────────────────────────────────────────────

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "rootstock")


# ── Neo4j driver fixture (session-scoped) ────────────────────────────────────

@pytest.fixture(scope="session")
def neo4j_driver():
    """
    Session-scoped Neo4j driver. Skips all tests if Neo4j is unavailable.
    """
    try:
        from neo4j import GraphDatabase
        from neo4j.exceptions import ServiceUnavailable, AuthError
    except ImportError:
        pytest.skip("neo4j driver not installed")

    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
    except (ServiceUnavailable, ConnectionRefusedError):
        pytest.skip(f"Neo4j not available at {NEO4J_URI}")
    except AuthError:
        pytest.skip("Neo4j auth failed — check NEO4J_USER / NEO4J_PASSWORD")

    yield driver
    driver.close()


# ── Cleanup utility ──────────────────────────────────────────────────────────

ALL_NODE_LABELS = [
    "Application", "Entitlement", "TCC_Permission", "XPC_Service",
    "LaunchItem", "Keychain_Item", "MDM_Profile", "User",
    "LocalGroup", "RemoteAccessService", "FirewallPolicy",
    "LoginSession", "AuthorizationRight", "AuthorizationPlugin",
    "SystemExtension", "SudoersRule", "CriticalFile", "Computer",
    "CertificateAuthority", "BluetoothDevice",
    "KerberosArtifact", "ADGroup",
    "Vulnerability", "AttackTechnique",
    "SandboxProfile", "ADUser", "ThreatGroup",
    "CWE", "Recommendation",
]


def cleanup_test_nodes(session, scan_id: str) -> None:
    """Remove test nodes by scan_id, then clean up orphans.

    1. DETACH DELETE all Application nodes matching the test's scan_id
       (removes the apps and every edge touching them).
    2. Sweep non-Application nodes that have no remaining relationships.
       This removes test-created nodes while preserving any nodes still
       referenced by other (non-test) data.
    """
    session.run(
        "MATCH (a:Application {scan_id: $scan_id}) DETACH DELETE a",
        scan_id=scan_id,
    )
    for label in ALL_NODE_LABELS:
        if label != "Application":
            session.run(f"MATCH (n:{label}) WHERE NOT (n)--() DELETE n")
