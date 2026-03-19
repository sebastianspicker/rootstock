"""
test_queries.py — Tests for the Rootstock Cypher query library.

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

import re
from pathlib import Path

import pytest

from conftest import cleanup_test_nodes

QUERIES_DIR = Path(__file__).parent.parent / "queries"
EXPECTED_QUERY_COUNT = 23

_HEADER_RE = re.compile(
    r"^//\s*(?P<key>Name|Purpose|Category|Severity|Parameters):\s*(?P<value>.+)$",
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


def _first_statement(cypher: str) -> str:
    """Extract the first non-comment Cypher statement."""
    for stmt in cypher.split(";"):
        stripped = stmt.strip()
        non_comment = "\n".join(
            ln for ln in stripped.splitlines() if not ln.strip().startswith("//")
        ).strip()
        if non_comment:
            return stripped
    return cypher.strip()


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
    session.run(
        """
        MERGE (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        ON CREATE SET fda.display_name = 'Full Disk Access'

        MERGE (mic:TCC_Permission {service: 'kTCCServiceMicrophone'})
        ON CREATE SET mic.display_name = 'Microphone'

        MERGE (cam:TCC_Permission {service: 'kTCCServiceCamera'})
        ON CREATE SET cam.display_name = 'Camera'

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
            appB.scan_id = $scan_id

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

class TestQueryFileStructure:
    def test_query_directory_exists(self):
        assert QUERIES_DIR.is_dir(), f"queries/ directory not found at {QUERIES_DIR}"

    def test_expected_query_count(self):
        files = _all_cypher_files()
        assert len(files) == EXPECTED_QUERY_COUNT, (
            f"Expected {EXPECTED_QUERY_COUNT} .cypher files, found {len(files)}"
        )

    def test_all_files_have_name_header(self):
        missing = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            if "name" not in meta or not meta["name"]:
                missing.append(path.name)
        assert not missing, f"Missing 'Name' header in: {missing}"

    def test_all_files_have_valid_category(self):
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            cat = meta.get("category", "")
            if cat not in _VALID_CATEGORIES:
                bad.append(f"{path.name}: '{cat}'")
        assert not bad, f"Invalid or missing 'Category' in: {bad}"

    def test_all_files_have_valid_severity(self):
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            sev = meta.get("severity", "")
            if sev not in _VALID_SEVERITIES:
                bad.append(f"{path.name}: '{sev}'")
        assert not bad, f"Invalid or missing 'Severity' in: {bad}"

    def test_all_files_non_empty(self):
        empty = []
        for path in _all_cypher_files():
            stmt = _first_statement(path.read_text(encoding="utf-8"))
            if not stmt:
                empty.append(path.name)
        assert not empty, f"Empty (no Cypher body) in: {empty}"

    def test_sequential_ids(self):
        """Query IDs should be consecutive from 01 to EXPECTED_QUERY_COUNT."""
        ids = []
        for path in _all_cypher_files():
            stem = path.stem
            qid = stem.split("-")[0]
            try:
                ids.append(int(qid))
            except ValueError:
                pytest.fail(f"Non-numeric query ID in filename: {path.name}")
        ids.sort()
        expected = list(range(1, EXPECTED_QUERY_COUNT + 1))
        assert ids == expected, f"Non-sequential IDs: got {ids}, expected {expected}"


# ── Layer 2: Syntax validation (Neo4j EXPLAIN) ────────────────────────────────

class TestQuerySyntax:
    def test_all_queries_parse(self, neo4j_session):
        """EXPLAIN each query to verify Cypher syntax is valid."""
        failures = []
        for path in _all_cypher_files():
            cypher = path.read_text(encoding="utf-8")
            stmt = _first_statement(cypher)
            if not stmt:
                continue
            # Strip parameter references for EXPLAIN — use empty params
            try:
                neo4j_session.run(f"EXPLAIN {stmt}", {
                    "target_service": "kTCCServiceMicrophone",
                    "min_permissions": 3,
                    "team_id": "TEST",
                    "bundle_id": "com.example.test",
                    "days_old": 365,
                    "min_methods": 1,
                })
            except Exception as e:
                failures.append(f"{path.name}: {e}")
        assert not failures, "Cypher syntax errors:\n" + "\n".join(failures)


# ── Layer 3: Seeded execution tests ──────────────────────────────────────────

class TestQueryExecution:
    @pytest.fixture(autouse=True)
    def seed(self, neo4j_session):
        _seed_minimal_graph(neo4j_session)

    def test_query_01_injectable_fda_apps(self, neo4j_session):
        """Query 01 should find our injectable FDA app."""
        from infer_injection import infer
        infer(neo4j_session)

        cypher = (QUERIES_DIR / "01-injectable-fda-apps.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected at least 1 injectable FDA app in seeded graph"

    def test_query_07_tcc_overview(self, neo4j_session):
        """Query 07 should return at least 1 TCC permission row."""
        cypher = (QUERIES_DIR / "07-tcc-grant-overview.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected TCC grants in seeded graph"

    def test_query_16_tcc_grant_audit(self, neo4j_session):
        """Query 16 should return TCC grant detail rows."""
        cypher = (QUERIES_DIR / "16-tcc-grant-audit.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected TCC grant audit rows in seeded graph"

    def test_query_04_private_entitlements(self, neo4j_session):
        """Query 04 should find our app with com.apple.private.tcc.allow."""
        cypher = (QUERIES_DIR / "04-private-entitlement-audit.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected at least 1 private entitlement in seeded graph"
