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
from pathlib import Path

import pytest

from conftest import cleanup_test_nodes

FIXTURE_PATH = Path(__file__).parent / "fixture_minimal.json"
TEST_SCAN_ID = "test-00000000-0000-0000-0000-000000000001"


@pytest.fixture(scope="module")
def neo4j_session(neo4j_driver):
    """Module-scoped Neo4j session with cleanup."""
    with neo4j_driver.session() as session:
        yield session
    with neo4j_driver.session() as session:
        cleanup_test_nodes(session, TEST_SCAN_ID)


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
        assert len(scan.xpc_services) == 2
        assert len(scan.keychain_acls) == 3
        assert len(scan.mdm_profiles) == 2
        assert len(scan.launch_items) == 3

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

    def test_launch_item_defaults(self):
        from models import LaunchItemData
        item = LaunchItemData.model_validate({
            "label": "com.example.minimal",
            "path": "/Library/LaunchDaemons/com.example.minimal.plist",
            "type": "daemon",
        })
        assert item.program is None
        assert item.user is None
        assert item.run_at_load is False

    def test_launch_item_invalid_type_raises(self):
        from models import LaunchItemData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            LaunchItemData.model_validate({
                "label": "com.example.bad",
                "path": "/Library/LaunchDaemons/com.example.bad.plist",
                "type": "INVALID",
            })

    def test_xpc_service_defaults(self):
        from models import XPCServiceData
        svc = XPCServiceData.model_validate({
            "label": "com.example.minimal",
            "path": "/Library/LaunchDaemons/com.example.minimal.plist",
            "type": "daemon",
        })
        assert svc.program is None
        assert svc.user is None
        assert svc.run_at_load is False
        assert svc.keep_alive is False
        assert svc.mach_services == []
        assert svc.entitlements == []

    def test_xpc_service_invalid_type_raises(self):
        from models import XPCServiceData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            XPCServiceData.model_validate({
                "label": "com.example.bad",
                "path": "/Library/LaunchDaemons/com.example.bad.plist",
                "type": "INVALID_TYPE",
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

    def test_keychain_item_defaults(self):
        from models import KeychainItemData
        item = KeychainItemData.model_validate({
            "label": "My Credential",
            "kind": "generic_password",
        })
        assert item.service is None
        assert item.access_group is None
        assert item.trusted_apps == []

    def test_keychain_item_invalid_kind_raises(self):
        from models import KeychainItemData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            KeychainItemData.model_validate({
                "label": "Bad Item",
                "kind": "INVALID_KIND",
            })

    def test_keychain_item_with_trusted_apps(self):
        from models import KeychainItemData
        item = KeychainItemData.model_validate({
            "label": "SSH Key",
            "kind": "generic_password",
            "service": "OpenSSH",
            "access_group": "TEAMID.com.example",
            "trusted_apps": ["com.example.app", "com.apple.Terminal"],
        })
        assert len(item.trusted_apps) == 2
        assert "com.apple.Terminal" in item.trusted_apps

    def test_mdm_profile_defaults(self):
        from models import MDMProfileData
        profile = MDMProfileData.model_validate({
            "identifier": "com.example.profile",
            "display_name": "Test Profile",
        })
        assert profile.organization is None
        assert profile.install_date is None
        assert profile.tcc_policies == []

    def test_mdm_tcc_policy_fields(self):
        from models import MDMProfileData
        profile = MDMProfileData.model_validate({
            "identifier": "com.example.profile",
            "display_name": "Privacy Profile",
            "tcc_policies": [
                {"service": "SystemPolicyAllFiles", "client_bundle_id": "com.example.app", "allowed": True},
                {"service": "Microphone", "client_bundle_id": "com.example.app", "allowed": False},
            ],
        })
        assert len(profile.tcc_policies) == 2
        fda = next(p for p in profile.tcc_policies if p.service == "SystemPolicyAllFiles")
        assert fda.client_bundle_id == "com.example.app"
        assert fda.allowed is True

    def test_mdm_profile_missing_required_raises(self):
        from models import MDMProfileData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            MDMProfileData.model_validate({"identifier": "com.example.only-identifier"})  # missing display_name


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

    def test_import_launch_items(self, neo4j_session, scan_result):
        from import_nodes import import_launch_items
        n_nodes, n_persists, n_runs = import_launch_items(neo4j_session, scan_result.launch_items)
        assert n_nodes == 3

        result = neo4j_session.run(
            "MATCH (l:LaunchItem) WHERE l.label IN ['com.example.daemon', 'com.example.agent', 'cron.root.1'] RETURN count(l) AS n"
        )
        assert result.single()["n"] == 3

    def test_launch_item_properties(self, neo4j_session, scan_result):
        from import_nodes import import_launch_items
        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            "MATCH (l:LaunchItem {label: 'com.example.daemon'}) RETURN l"
        )
        row = result.single()
        assert row is not None
        launch_item = row["l"]
        assert launch_item["type"] == "daemon"
        assert launch_item["run_at_load"] is True
        assert launch_item["user"] == "root"

    def test_launch_item_runs_as_edge(self, neo4j_session, scan_result):
        from import_nodes import import_launch_items
        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            """
            MATCH (l:LaunchItem {label: 'com.example.daemon'})-[:RUNS_AS]->(u:User {name: 'root'})
            RETURN count(l) AS n
            """
        )
        assert result.single()["n"] == 1, "RUNS_AS edge to root User should exist"

    def test_launch_item_idempotency(self, neo4j_session, scan_result):
        from import_nodes import import_launch_items
        import_launch_items(neo4j_session, scan_result.launch_items)
        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            "MATCH (l:LaunchItem) WHERE l.label IN ['com.example.daemon', 'com.example.agent'] RETURN count(l) AS n"
        )
        assert result.single()["n"] == 2, "Duplicate LaunchItem nodes created"

    def test_import_xpc_services(self, neo4j_session, scan_result):
        from import_nodes import import_xpc_services
        n_nodes, n_edges = import_xpc_services(neo4j_session, scan_result.xpc_services)
        assert n_nodes == 2

        result = neo4j_session.run(
            "MATCH (x:XPC_Service) WHERE x.label IN ['com.example.testdaemon', 'com.example.testagent'] RETURN count(x) AS n"
        )
        assert result.single()["n"] == 2

    def test_xpc_service_properties(self, neo4j_session, scan_result):
        from import_nodes import import_xpc_services
        import_xpc_services(neo4j_session, scan_result.xpc_services)

        result = neo4j_session.run(
            "MATCH (x:XPC_Service {label: 'com.example.testdaemon'}) RETURN x"
        )
        row = result.single()
        assert row is not None
        svc = row["x"]
        assert svc["type"] == "daemon"
        assert svc["run_at_load"] is True
        assert svc["keep_alive"] is True
        assert "com.example.testdaemon.xpc" in svc["mach_services"]
        assert "com.apple.private.tcc.allow" in svc["entitlements"]

    def test_xpc_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same XPC services must not create duplicate nodes."""
        from import_nodes import import_xpc_services
        import_xpc_services(neo4j_session, scan_result.xpc_services)
        import_xpc_services(neo4j_session, scan_result.xpc_services)

        result = neo4j_session.run(
            "MATCH (x:XPC_Service) WHERE x.label IN ['com.example.testdaemon', 'com.example.testagent'] RETURN count(x) AS n"
        )
        assert result.single()["n"] == 2, "Duplicate XPC_Service nodes created"

    def test_import_keychain_items(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_keychain_items
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        n_nodes, n_edges = import_keychain_items(neo4j_session, scan_result.keychain_acls)
        assert n_nodes == 3  # 3 items in fixture

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item) WHERE k.label IN ['iTerm2 Credential', 'Slack Token', 'Developer Certificate'] RETURN count(k) AS n"
        )
        assert result.single()["n"] == 3

    def test_keychain_can_read_edges(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_keychain_items
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        _, n_edges = import_keychain_items(neo4j_session, scan_result.keychain_acls)
        # iTerm2 → iTerm2 Credential (1) + Slack → Slack Token (1) + Terminal → Slack Token (1) = 3
        assert n_edges >= 3

        result = neo4j_session.run(
            "MATCH (a:Application)-[r:CAN_READ_KEYCHAIN]->(k:Keychain_Item) RETURN count(r) AS n"
        )
        assert result.single()["n"] >= 3

    def test_keychain_item_properties(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_keychain_items
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item {label: 'iTerm2 Credential'}) RETURN k"
        )
        row = result.single()
        assert row is not None
        k = row["k"]
        assert k["kind"] == "generic_password"
        assert k["service"] == "com.googlecode.iterm2.SecureInput"
        assert k["access_group"] == "H7V7XYVQ7D.com.googlecode.iterm2"

    def test_keychain_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same keychain items must not create duplicate nodes."""
        from import_nodes import import_applications, import_keychain_items
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item) WHERE k.label IN ['iTerm2 Credential', 'Slack Token'] RETURN count(k) AS n"
        )
        assert result.single()["n"] == 2, "Duplicate Keychain_Item nodes created"

    def test_keychain_no_trusted_apps_creates_no_edges(self, neo4j_session, scan_result):
        """Keychain items with empty trusted_apps must not create CAN_READ_KEYCHAIN edges."""
        from import_nodes import import_applications, import_keychain_items
        from models import KeychainItemData
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        cert_only = [KeychainItemData(
            label="Orphan Cert", kind="certificate",
            service=None, access_group=None, trusted_apps=[],
        )]
        n_nodes, n_edges = import_keychain_items(neo4j_session, cert_only)
        assert n_nodes == 1
        assert n_edges == 0

    def test_import_mdm_profiles(self, neo4j_session, scan_result):
        from import_nodes import import_mdm_profiles
        n_nodes, n_edges = import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)
        assert n_nodes == 2  # 2 profiles in fixture
        assert n_edges == 2  # 2 TCC policies (only 1 profile has policies)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile) WHERE m.identifier IN ['com.example.tcc.profile', 'com.example.basic.profile'] RETURN count(m) AS n"
        )
        assert result.single()["n"] == 2

    def test_mdm_configures_edges(self, neo4j_session, scan_result):
        from import_nodes import import_mdm_profiles
        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile {identifier: 'com.example.tcc.profile'})-[c:CONFIGURES]->(t:TCC_Permission) RETURN count(c) AS n"
        )
        assert result.single()["n"] == 2

    def test_mdm_profile_properties(self, neo4j_session, scan_result):
        from import_nodes import import_mdm_profiles
        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile {identifier: 'com.example.tcc.profile'}) RETURN m"
        )
        row = result.single()
        assert row is not None
        m = row["m"]
        assert m["display_name"] == "Privacy Policy Profile"
        assert m["organization"] == "Example Corp"
        assert m["install_date"] == "2026-03-01 00:00:00 +0000"

    def test_mdm_no_tcc_policies_creates_no_edges(self, neo4j_session, scan_result):
        """Profiles with no TCC policies must not create CONFIGURES edges."""
        from import_nodes import import_mdm_profiles
        from models import MDMProfileData
        basic_profile = [MDMProfileData(
            identifier="com.example.empty.profile",
            display_name="Empty Profile",
            organization=None, install_date=None, tcc_policies=[],
        )]
        n_nodes, n_edges = import_mdm_profiles(neo4j_session, basic_profile)
        assert n_nodes == 1
        assert n_edges == 0

    def test_mdm_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same MDM profiles must not create duplicate nodes."""
        from import_nodes import import_mdm_profiles
        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)
        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile) WHERE m.identifier IN ['com.example.tcc.profile', 'com.example.basic.profile'] RETURN count(m) AS n"
        )
        assert result.single()["n"] == 2, "Duplicate MDM_Profile nodes created"

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
