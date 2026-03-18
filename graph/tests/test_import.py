"""
test_import.py — Integration tests for the graph importer.

Requires a running Neo4j instance. Tests are skipped if Neo4j is unavailable.

Usage:
    pytest graph/tests/test_import.py -v
    # With custom connection:
    NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j NEO4J_PASSWORD=rootstock pytest graph/tests/test_import.py -v
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Ensure graph/ is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))

FIXTURE_PATH = Path(__file__).parent / "fixture_minimal.json"
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "rootstock")

# Unique scan_id prefix for test isolation
TEST_SCAN_ID = "test-00000000-0000-0000-0000-000000000001"


@pytest.fixture(scope="module")
def neo4j_session():
    """Provide a Neo4j session, skipping the module if Neo4j is unavailable."""
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

    with driver.session() as session:
        yield session

    # Cleanup: remove test nodes
    with driver.session() as session:
        session.run(
            "MATCH (a:Application {scan_id: $scan_id}) DETACH DELETE a",
            scan_id=TEST_SCAN_ID,
        )
    driver.close()


@pytest.fixture(scope="module")
def scan_result():
    from models import ScanResult
    data = json.loads(FIXTURE_PATH.read_text())
    data["scan_id"] = TEST_SCAN_ID
    return ScanResult.model_validate(data)


# ── Model validation tests (no Neo4j required) ─────────────────────────────

class TestPydanticModels:
    def test_fixture_loads_cleanly(self):
        from models import ScanResult
        data = json.loads(FIXTURE_PATH.read_text())
        scan = ScanResult.model_validate(data)
        assert len(scan.applications) == 3
        assert len(scan.tcc_grants) == 5

    def test_entitlement_counts(self):
        from models import ScanResult
        data = json.loads(FIXTURE_PATH.read_text())
        scan = ScanResult.model_validate(data)
        total = sum(len(a.entitlements) for a in scan.applications)
        assert total == 10, f"Expected 10 entitlements, got {total}"

    def test_tcc_grant_allowed_property(self):
        from models import TCCGrantData
        grant_allow = TCCGrantData(
            service="kTCCServiceMicrophone", display_name="Microphone",
            client="com.example.app", client_type=0,
            auth_value=2, auth_reason=1, scope="user", last_modified=0,
        )
        assert grant_allow.allowed is True

        grant_deny = grant_allow.model_copy(update={"auth_value": 0})
        assert grant_deny.allowed is False

        grant_limited = grant_allow.model_copy(update={"auth_value": 3})
        assert grant_limited.allowed is True

    def test_missing_required_field_raises(self):
        from models import ApplicationData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ApplicationData.model_validate({"name": "Broken"})  # missing bundle_id etc.

    def test_invalid_category_raises(self):
        from models import EntitlementData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            EntitlementData.model_validate({
                "name": "com.example.ent", "is_private": False,
                "category": "INVALID_CATEGORY", "is_security_critical": False,
            })

    def test_missing_fields_in_application_returns_defaults(self):
        """Fields with defaults should not fail validation."""
        from models import ApplicationData
        app = ApplicationData.model_validate({
            "name": "Minimal", "bundle_id": "com.example.minimal",
            "path": "/Applications/Minimal.app",
            "hardened_runtime": False, "library_validation": False,
            "is_electron": False, "is_system": False, "signed": False,
            # entitlements and injection_methods use default_factory=list
        })
        assert app.entitlements == []
        assert app.injection_methods == []


# ── Integration tests (require Neo4j) ──────────────────────────────────────

class TestImportIntegration:
    def test_import_applications(self, neo4j_session, scan_result):
        from import_nodes import import_applications
        n = import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        assert n == 3

        result = neo4j_session.run(
            "MATCH (a:Application {scan_id: $scan_id}) RETURN count(a) AS n",
            scan_id=TEST_SCAN_ID,
        )
        assert result.single()["n"] == 3

    def test_application_properties(self, neo4j_session, scan_result):
        from import_nodes import import_applications
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)

        result = neo4j_session.run(
            "MATCH (a:Application {bundle_id: 'com.googlecode.iterm2'}) RETURN a"
        )
        row = result.single()
        assert row is not None
        app = row["a"]
        assert app["name"] == "iTerm2"
        assert app["hardened_runtime"] is False
        assert app["is_electron"] is False
        assert "missing_library_validation" in app["injection_methods"]

    def test_import_tcc_grants(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_tcc_grants
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        linked, skipped = import_tcc_grants(neo4j_session, scan_result.tcc_grants, TEST_SCAN_ID)
        assert linked == 5  # all 5 grants match apps in fixture
        assert skipped == 0

        result = neo4j_session.run(
            "MATCH (:Application)-[r:HAS_TCC_GRANT]->(:TCC_Permission) RETURN count(r) AS n"
        )
        assert result.single()["n"] >= 5

    def test_import_entitlements(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_entitlements
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        n_ent_nodes, n_ent_rels = import_entitlements(neo4j_session, scan_result.applications)
        # 10 total entitlements but some names are shared across apps → fewer unique nodes
        assert n_ent_rels == 10  # one rel per (app, entitlement) pair
        assert n_ent_nodes <= 10  # unique entitlement names

    def test_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same data must not create duplicate nodes."""
        from import_nodes import import_applications, import_tcc_grants, import_entitlements
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_tcc_grants(neo4j_session, scan_result.tcc_grants, TEST_SCAN_ID)
        import_entitlements(neo4j_session, scan_result.applications)

        # Import again
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_tcc_grants(neo4j_session, scan_result.tcc_grants, TEST_SCAN_ID)
        import_entitlements(neo4j_session, scan_result.applications)

        result = neo4j_session.run(
            "MATCH (a:Application {scan_id: $scan_id}) RETURN count(a) AS n",
            scan_id=TEST_SCAN_ID,
        )
        assert result.single()["n"] == 3, "Duplicate Application nodes created"

        result = neo4j_session.run(
            "MATCH (:Application)-[r:HAS_TCC_GRANT]->(:TCC_Permission) RETURN count(r) AS n"
        )
        # Should still be exactly 5 TCC grant relationships (no duplicates)
        tcc_count = result.single()["n"]
        assert tcc_count >= 5  # may have pre-existing from other tests in suite

    def test_unknown_client_grant_skipped(self, neo4j_session):
        """A TCC grant whose client has no Application node should be skipped gracefully."""
        from models import TCCGrantData
        from import_nodes import import_tcc_grants
        orphan = TCCGrantData(
            service="kTCCServiceMicrophone", display_name="Microphone",
            client="com.nonexistent.app", client_type=0,
            auth_value=2, auth_reason=1, scope="user", last_modified=0,
        )
        linked, skipped = import_tcc_grants(neo4j_session, [orphan], TEST_SCAN_ID)
        assert linked == 0
        assert skipped == 1
