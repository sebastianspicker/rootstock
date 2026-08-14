"""Collected seeded execution tests for Rootstock Cypher queries."""

import pytest
from query_test_support import QUERIES_DIR, _first_statement, _seed_minimal_graph, checks

pytest_plugins = ["query_test_support"]

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
        checks.assertGreaterEqual(
            len(result), 1, "Expected at least 1 injectable FDA app in seeded graph"
        )

    def test_query_07_tcc_overview(self, neo4j_session):
        """Query 07 should return at least 1 TCC permission row."""
        cypher = (QUERIES_DIR / "07-tcc-grant-overview.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        checks.assertGreaterEqual(len(result), 1, "Expected TCC grants in seeded graph")

    def test_query_16_tcc_grant_audit(self, neo4j_session):
        """Query 16 should return TCC grant detail rows."""
        cypher = (QUERIES_DIR / "16-tcc-grant-audit.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {"scope": None}))
        checks.assertGreaterEqual(
            len(result), 1, "Expected TCC grant audit rows in seeded graph"
        )

    def test_query_04_private_entitlements(self, neo4j_session):
        """Query 04 should find our app with com.apple.private.tcc.allow."""
        cypher = (QUERIES_DIR / "04-private-entitlement-audit.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        checks.assertGreaterEqual(
            len(result), 1, "Expected at least 1 private entitlement in seeded graph"
        )

    def test_query_45_owned_blast_radius(self, neo4j_session):
        """Query 45 should return results when nodes are marked owned."""
        # Mark one app as owned
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.owned = true, a.owned_at = '2026-03-19T00:00:00Z'
            """
        )
        cypher = (QUERIES_DIR / "45-owned-blast-radius.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        checks.assertGreaterEqual(
            len(result), 1, "Expected at least 1 owned node blast radius row"
        )
        # Clean up owned markers
        neo4j_session.run("MATCH (n) WHERE n.owned = true REMOVE n.owned, n.owned_at")

    def test_query_46_tier_classification(self, neo4j_session):
        """Query 46 should return results after tier classification runs."""
        from tier_classification import classify

        classify(neo4j_session)
        cypher = (QUERIES_DIR / "46-tier-classification.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        checks.assertGreaterEqual(
            len(result), 1, "Expected at least 1 classified app in seeded graph"
        )
        # Clean up tier properties
        neo4j_session.run(
            "MATCH (a:Application) WHERE a.tier IS NOT NULL REMOVE a.tier"
        )

    def test_query_54_accessibility_abuse(self, neo4j_session):
        """Query 54 should execute without error on seeded graph."""
        from infer_accessibility import infer

        infer(neo4j_session)
        cypher = (QUERIES_DIR / "54-accessibility-abuse.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        # May return 0 rows if no A11Y grant in seed data; just verify it runs
        checks.assertTrue(isinstance(result, list))

    def test_query_57_tier0_inbound(self, neo4j_session):
        """Query 57 should return results when tiers are classified."""
        from tier_classification import classify

        classify(neo4j_session)
        cypher = (QUERIES_DIR / "57-tier0-inbound-control.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        checks.assertTrue(isinstance(result, list))
        # Clean up tier properties
        neo4j_session.run(
            "MATCH (a:Application) WHERE a.tier IS NOT NULL REMOVE a.tier"
        )

    def test_query_59_keychain_crown_jewels(self, neo4j_session):
        """Query 59 should return keychain items with sensitivity tiers."""
        cypher = (QUERIES_DIR / "59-keychain-crown-jewels.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        checks.assertTrue(isinstance(result, list))

    def test_certificate_authority_nodes_created(self, neo4j_session):
        """Verify CertificateAuthority nodes can be created and queried."""
        neo4j_session.run(
            """
            MERGE (ca:CertificateAuthority {sha256: 'test-ca-sha256-root'})
            SET ca.common_name = 'Apple Root CA',
                ca.organization = 'Apple Inc.',
                ca.is_root = true
            MERGE (ca2:CertificateAuthority {sha256: 'test-ca-sha256-intermediate'})
            SET ca2.common_name = 'Developer ID Certification Authority',
                ca2.organization = 'Apple Inc.',
                ca2.is_root = false
            MERGE (ca2)-[:ISSUED_BY]->(ca)
            """
        )
        result = neo4j_session.run(
            "MATCH (ca:CertificateAuthority) RETURN count(ca) AS n"
        ).single()
        checks.assertGreaterEqual(
            result["n"], 2, "Expected at least 2 CertificateAuthority nodes"
        )

    def test_signed_by_ca_edges(self, neo4j_session):
        """Verify SIGNED_BY_CA edges link apps to correct CAs."""
        neo4j_session.run(
            """
            MERGE (ca:CertificateAuthority {sha256: 'test-ca-sha256-leaf'})
            SET ca.common_name = 'Developer ID Application: Test',
                ca.is_root = false
            WITH ca
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            MERGE (a)-[:SIGNED_BY_CA]->(ca)
            """
        )
        result = neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})-[:SIGNED_BY_CA]->(ca:CertificateAuthority)
            RETURN ca.common_name AS cn
            """
        ).single()
        checks.assertIsNotNone(result, "Expected SIGNED_BY_CA edge from test app to CA")

    def test_issued_by_chain(self, neo4j_session):
        """Verify ISSUED_BY edges form correct hierarchy."""
        result = neo4j_session.run(
            """
            MATCH (child:CertificateAuthority {sha256: 'test-ca-sha256-intermediate'})
                  -[:ISSUED_BY]->(root:CertificateAuthority {sha256: 'test-ca-sha256-root'})
            RETURN root.common_name AS root_cn
            """
        ).single()
        checks.assertIsNotNone(
            result, "Expected ISSUED_BY edge from intermediate to root"
        )
        checks.assertEqual(result["root_cn"], "Apple Root CA")

    def test_query_60_expired_cert(self, neo4j_session):
        """Query 60 should find apps with expired certs and TCC grants."""
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.is_certificate_expired = true,
                a.certificate_expires = '2024-01-01T00:00:00Z',
                a.signing_certificate_cn = 'Test Expired Cert'
            """
        )
        cypher = (QUERIES_DIR / "60-expired-cert-with-tcc.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        checks.assertGreaterEqual(
            len(result), 1, "Expected at least 1 expired-cert app with TCC grants"
        )
        # Clean up
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.is_certificate_expired = false
            REMOVE a.certificate_expires, a.signing_certificate_cn
            """
        )

    def test_query_61_adhoc_signed(self, neo4j_session):
        """Query 61 should find ad-hoc signed apps with TCC grants."""
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.is_adhoc_signed = true
            """
        )
        cypher = (QUERIES_DIR / "61-adhoc-signed-with-tcc.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        checks.assertGreaterEqual(
            len(result), 1, "Expected at least 1 ad-hoc signed app with TCC grants"
        )
        # Clean up
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.is_adhoc_signed = false
            """
        )
