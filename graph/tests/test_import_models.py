"""
test_import_models.py - Importer-record integration tests (no Neo4j required).

Usage:
    pytest graph/tests/test_import_models.py -v
"""

from __future__ import annotations

from unittest import TestCase
from unittest.mock import MagicMock

TEST_SCAN_ID = "test-00000000-0000-0000-0000-000000000001"


checks = TestCase()


class TestImporterModelRecords:
    def test_code_signing_analysis_error_keeps_signing_posture_unknown(self):
        from import_nodes_core import import_applications
        from models import ApplicationData

        app = ApplicationData.model_validate(
            {
                "name": "Unanalyzable",
                "bundle_id": "com.example.unknown",
                "path": "/Applications/Unknown.app",
                "is_electron": False,
                "is_system": False,
                "code_signing_analysis_error": True,
                "injection_methods": [],
            }
        )

        checks.assertIsNone(app.signed)
        checks.assertIsNone(app.hardened_runtime)
        checks.assertIsNone(app.library_validation)
        checks.assertIs(app.code_signing_analysis_error, True)
        checks.assertEqual(app.injection_methods, [])

        session = MagicMock()
        imported = import_applications(session, [app], TEST_SCAN_ID)
        record = session.run.call_args.kwargs["records"][0]

        checks.assertEqual(imported, 1)
        checks.assertIsNone(record["signed"])
        checks.assertIsNone(record["hardened_runtime"])
        checks.assertIsNone(record["library_validation"])
        checks.assertIs(record["code_signing_analysis_error"], True)
        checks.assertEqual(record["injection_methods"], [])

    def test_entitlement_extraction_error_survives_model_and_import_record(self):
        from import_nodes_core import import_applications
        from models import ApplicationData

        app = ApplicationData.model_validate(
            {
                "name": "Unreadable Entitlements",
                "bundle_id": "com.example.entitlements.unknown",
                "path": "/Applications/EntitlementsUnknown.app",
                "is_electron": False,
                "is_system": False,
                "entitlements_available": False,
                "entitlement_extraction_error": "codesign failed",
                "entitlements": [],
            }
        )

        checks.assertIs(app.entitlements_available, False)
        checks.assertEqual(app.entitlement_extraction_error, "codesign failed")
        checks.assertEqual(app.entitlements, [])

        session = MagicMock()
        imported = import_applications(session, [app], TEST_SCAN_ID)
        record = session.run.call_args.kwargs["records"][0]

        checks.assertEqual(imported, 1)
        checks.assertIs(record["entitlements_available"], False)
        checks.assertEqual(record["entitlement_extraction_error"], "codesign failed")

    def test_firewall_rule_unknown_state_survives_model_and_import_record(self):
        from import_nodes_security import import_firewall_status
        from models import FirewallStatusData

        status = FirewallStatusData.model_validate(
            {
                "enabled": None,
                "stealth_mode": None,
                "allow_signed": None,
                "allow_built_in": None,
                "app_rules": [
                    {"bundle_id": "com.example.firewall", "allow_incoming": None},
                ],
            }
        )

        checks.assertIsNone(status.app_rules[0].allow_incoming)

        result = MagicMock()
        result.single.return_value = {"n": 1}
        session = MagicMock()
        session.run.return_value = result

        imported = import_firewall_status(session, [status], TEST_SCAN_ID)
        rule_record = session.run.call_args_list[1].kwargs["records"][0]

        checks.assertEqual(imported, (1, 1))
        checks.assertIsNone(rule_record["allow_incoming"])
