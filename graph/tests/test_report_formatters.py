"""Tests for report formatting functions - no Neo4j required."""

from unittest import TestCase

from report_formatters import (
    format_apple_event_table,
    format_electron_table,
    format_executive_summary,
    format_injectable_fda_table,
    format_no_findings,
    format_private_entitlement_table,
    format_tcc_overview_table,
)


checks = TestCase()


class TestFormatNoFindings:
    def test_returns_markdown_string(self):
        result = format_no_findings()
        checks.assertTrue(isinstance(result, str))
        checks.assertIn("No findings", result)


class TestFormatInjectableFdaTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "iTerm2",
                "bundle_id": "com.googlecode.iterm2",
                "team_id": "H7V7XYVQ7D",
                "injection_methods": ["missing_library_validation"],
                "method_count": 1,
                "path": "/Applications/iTerm.app",
            }
        ]
        result = format_injectable_fda_table(rows)
        checks.assertIn("iTerm2", result)
        checks.assertIn("missing_library_validation", result)
        checks.assertIn("H7V7XYVQ7D", result)

    def test_empty_returns_no_findings(self):
        result = format_injectable_fda_table([])
        checks.assertIn("No findings", result)

    def test_multiple_injection_methods_joined(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "team_id": "BQR82RBBHL",
                "injection_methods": ["missing_library_validation", "electron_env_var"],
                "method_count": 2,
                "path": "/Applications/Slack.app",
            }
        ]
        result = format_injectable_fda_table(rows)
        checks.assertIn("missing_library_validation", result)
        checks.assertIn("electron_env_var", result)


class TestFormatElectronTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "inherited_permissions": ["Full Disk Access", "Microphone"],
                "permission_count": 2,
            }
        ]
        result = format_electron_table(rows)
        checks.assertIn("Slack", result)
        checks.assertIn("Full Disk Access", result)

    def test_empty_returns_no_findings(self):
        result = format_electron_table([])
        checks.assertIn("No findings", result)


class TestFormatAppleEventTable:
    def test_basic_table(self):
        rows = [
            {
                "source_app": "Terminal",
                "target_app": "Finder",
                "permission_gained": "Full Disk Access",
            }
        ]
        result = format_apple_event_table(rows)
        checks.assertIn("Terminal", result)
        checks.assertIn("Finder", result)
        checks.assertIn("Full Disk Access", result)

    def test_empty_returns_no_findings(self):
        result = format_apple_event_table([])
        checks.assertIn("No findings", result)


class TestFormatTccOverviewTable:
    def test_basic_table(self):
        rows = [
            {
                "permission": "Full Disk Access",
                "service": "kTCCServiceSystemPolicyAllFiles",
                "allowed_count": 3,
                "denied_count": 0,
                "total_grants": 3,
            },
            {
                "permission": "Camera",
                "service": "kTCCServiceCamera",
                "allowed_count": 5,
                "denied_count": 1,
                "total_grants": 6,
            },
        ]
        result = format_tcc_overview_table(rows)
        checks.assertIn("Full Disk Access", result)
        checks.assertIn("Camera", result)

    def test_empty_returns_no_findings(self):
        result = format_tcc_overview_table([])
        checks.assertIn("No findings", result)


class TestFormatPrivateEntitlementTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "private_entitlements": ["com.apple.private.tcc.allow"],
                "is_injectable": True,
            }
        ]
        result = format_private_entitlement_table(rows)
        checks.assertIn("Slack", result)
        checks.assertIn("com.apple.private.tcc.allow", result)
        checks.assertIn("Yes", result)

    def test_empty_returns_no_findings(self):
        result = format_private_entitlement_table([])
        checks.assertIn("No findings", result)


class TestFormatExecutiveSummary:
    def test_counts_reflected(self):
        result = format_executive_summary(
            critical_count=3,
            high_count=7,
            top_paths=[
                "iTerm2 has Full Disk Access and is injectable via missing library validation",
                "Slack inherits Full Disk Access via ELECTRON_RUN_AS_NODE",
            ],
        )
        checks.assertIn("3", result)
        checks.assertIn("7", result)
        checks.assertIn("iTerm2", result)

    def test_zero_findings(self):
        result = format_executive_summary(critical_count=0, high_count=0, top_paths=[])
        checks.assertIn("0", result)
