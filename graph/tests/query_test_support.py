"""
test_queries.py - Tests for the Rootstock Cypher query library.

Two layers:
  1. File validation (no Neo4j): all .cypher files have correct headers.
  2. Syntax validation (Neo4j required): EXPLAIN each query to catch parse errors.
  3. Seeded execution (Neo4j required): representative queries return expected results.

Usage:
    pytest graph/tests/test_queries.py -v
    # With custom connection:
    NEO4J_URI=bolt://localhost:7687 pytest graph/tests/test_queries.py -v
"""

from __future__ import annotations

from unittest import TestCase

import re
from pathlib import Path

import pytest

from conftest import cleanup_test_nodes

QUERIES_DIR = Path(__file__).parent.parent / "queries"
_REACHABILITY_QUERY_FILES = [
    "41-owned-to-fda.cypher",
    "42-owned-reachable.cypher",
    "44-paths-to-target.cypher",
    "45-owned-blast-radius.cypher",
    "47-owned-to-tier0.cypher",
    "57-tier0-inbound-control.cypher",
]
_REQUIRED_ATTACK_EDGES = {
    "CAN_CHANGE_PASSWORD",
    "CAN_READ_KERBEROS",
    "SHARES_KEYCHAIN_GROUP",
}
_REQUIRED_QUERY_FILES = {
    "01": "01-injectable-fda-apps.cypher",
    "07": "07-tcc-grant-overview.cypher",
    "16": "16-tcc-grant-audit.cypher",
    "45": "45-owned-blast-radius.cypher",
    "57": "57-tier0-inbound-control.cypher",
    "79": "79-stale-keytab-detection.cypher",
    "80": "80-cve-affected-apps.cypher",
    "99": "99-esf-monitoring-gaps.cypher",
    "100": "100-top-recommendations.cypher",
    "103": "103-cve-scan-remediation-queue.cypher",
}
_REQUIRED_QUERY_METADATA = {
    "01": {"category": "Red Team", "severity": "Critical"},
    "45": {"category": "Red Team", "severity": "Critical"},
    "57": {"category": "Blue Team", "severity": "Critical"},
    "79": {"category": "Blue Team", "severity": "Informational"},
    "99": {"category": "Blue Team", "severity": "High"},
    "100": {"category": "Blue Team", "severity": "High"},
    "103": {"category": "Blue Team", "severity": "High"},
}

_HEADER_RE = re.compile(
    r"^//\s*(?P<key>Name|Purpose|Category|Severity|Parameters|CVE|ATT&CK):\s*(?P<value>.+)$",
    re.IGNORECASE,
)
_VALID_CATEGORIES = {"Red Team", "Blue Team", "Forensic"}
_VALID_SEVERITIES = {"Critical", "High", "Informational"}

TEST_SCAN_ID = "test-queries-00000000-0000-0000-0000-000000000003"


# ── Helpers ─────────────────────────────────────────────────────────────────


def _parse_header(path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("//"):
            if stripped:
                break
        m = _HEADER_RE.match(stripped)
        if m:
            meta[m.group("key").lower()] = m.group("value").strip()
    return meta


def _all_cypher_files() -> list[Path]:
    return sorted(QUERIES_DIR.glob("*.cypher"))


def _query_text(filename: str) -> str:
    return (QUERIES_DIR / filename).read_text(encoding="utf-8")


def _first_statement(cypher: str) -> str:
    """Extract the first non-comment Cypher statement."""
    non_comment_lines = [
        line for line in cypher.splitlines() if not line.strip().startswith("//")
    ]
    cleaned = "\n".join(non_comment_lines)
    for stmt in cleaned.split(";"):
        stripped = stmt.strip()
        if stripped:
            return stripped
    return cleaned.strip()


# ── Neo4j fixture ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def neo4j_session(neo4j_driver):
    """Module-scoped Neo4j session with cleanup."""
    with neo4j_driver.session() as session:
        yield session
    with neo4j_driver.session() as session:
        cleanup_test_nodes(session, TEST_SCAN_ID)


def _seed_minimal_graph(session) -> None:
    """
    Seed a minimal graph with known properties for query execution tests.
    Includes: 1 injectable FDA app, 1 Electron app, TCC grants, entitlements.
    """
    _seed_query_permissions(session)
    _seed_query_apps(session)
    _seed_query_relationships(session)


def _seed_query_permissions(session) -> None:
    session.run(
        """
        MERGE (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        ON CREATE SET fda.display_name = 'Full Disk Access'

        MERGE (mic:TCC_Permission {service: 'kTCCServiceMicrophone'})
        ON CREATE SET mic.display_name = 'Microphone'

        MERGE (cam:TCC_Permission {service: 'kTCCServiceCamera'})
        ON CREATE SET cam.display_name = 'Camera'
        """
    )


def _seed_query_apps(session) -> None:
    session.run(
        """
        MERGE (appA:Application {bundle_id: 'com.rootstock.query.test.iterm'})
        SET appA.name = 'TestITerm',
            appA.path = '/Applications/TestITerm.app',
            appA.hardened_runtime = false,
            appA.library_validation = false,
            appA.is_electron = false,
            appA.is_system = false,
            appA.signed = true,
            appA.team_id = 'TESTTEAM01',
            appA.injection_methods = ['missing_library_validation', 'dyld_insert_via_entitlement'],
            appA.is_sip_protected = false,
            appA.scan_id = $scan_id

        MERGE (appB:Application {bundle_id: 'com.rootstock.query.test.electron'})
        SET appB.name = 'TestElectron',
            appB.path = '/Applications/TestElectron.app',
            appB.hardened_runtime = false,
            appB.library_validation = false,
            appB.is_electron = true,
            appB.is_system = false,
            appB.signed = true,
            appB.team_id = 'TESTTEAM02',
            appB.injection_methods = ['missing_library_validation', 'electron_env_var'],
            appB.is_sip_protected = false,
            appB.scan_id = $scan_id
        """,
        scan_id=TEST_SCAN_ID,
    )


def _seed_query_relationships(session) -> None:
    session.run(
        """
        MATCH (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        MATCH (mic:TCC_Permission {service: 'kTCCServiceMicrophone'})
        MATCH (cam:TCC_Permission {service: 'kTCCServiceCamera'})
        MATCH (appA:Application {bundle_id: 'com.rootstock.query.test.iterm'})
        MATCH (appB:Application {bundle_id: 'com.rootstock.query.test.electron'})
        MERGE (appA)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(fda)
        MERGE (appB)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(mic)
        MERGE (appB)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(cam)

        MERGE (ent1:Entitlement {name: 'com.apple.security.cs.allow-dyld-environment-variables'})
        ON CREATE SET ent1.is_private = false, ent1.category = 'injection',
                      ent1.is_security_critical = true
        MERGE (ent2:Entitlement {name: 'com.apple.security.cs.disable-library-validation'})
        ON CREATE SET ent2.is_private = false, ent2.category = 'injection',
                      ent2.is_security_critical = true
        MERGE (ent3:Entitlement {name: 'com.apple.private.tcc.allow'})
        ON CREATE SET ent3.is_private = true, ent3.category = 'tcc',
                      ent3.is_security_critical = true

        MERGE (appA)-[:HAS_ENTITLEMENT]->(ent1)
        MERGE (appA)-[:HAS_ENTITLEMENT]->(ent2)
        MERGE (appB)-[:HAS_ENTITLEMENT]->(ent3)
        """,
        scan_id=TEST_SCAN_ID,
    )


# ── Layer 1: File validation (no Neo4j) ──────────────────────────────────────

checks = TestCase()


