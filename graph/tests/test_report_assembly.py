"""Tests for report assembly behavior - no Neo4j required."""

import sys
from types import SimpleNamespace
from unittest import TestCase

from report_assembly import assemble_report


checks = TestCase()


def assert_report_line_contains(lines, label, value):
    matches = [line for line in lines if label in line and value in line]
    checks.assertTrue(matches)


def assert_report_line_missing(lines, label, value):
    matches = [line for line in lines if label in line and value in line]
    checks.assertFalse(matches)


def injectable_fda_query_results():
    return {
        "01-injectable-fda-apps.cypher": [
            {
                "app_name": "München <Agent>",
                "bundle_id": "com.example.agent",
                "team_id": "TEAMID",
                "injection_methods": ["missing_library_validation"],
                "method_count": 1,
                "path": "/Applications/Agent.app",
            }
        ],
        "07-tcc-grant-overview.cypher": [
            {
                "permission": "Full Disk Access",
                "service": "kTCCServiceSystemPolicyAllFiles",
                "allowed_count": 1,
                "denied_count": 0,
                "total_grants": 1,
            }
        ],
    }


def assert_injectable_report_order(report):
    critical_heading = (
        "## Critical Findings: Injectable Apps with Privileged TCC Grants"
    )
    electron_heading = "## High Findings: Electron TCC Inheritance"

    checks.assertLess(
        report.index("## Executive Summary"), report.index(critical_heading)
    )
    checks.assertLess(report.index(critical_heading), report.index(electron_heading))


def injectable_report_sections(report):
    critical_heading = (
        "## Critical Findings: Injectable Apps with Privileged TCC Grants"
    )
    electron_heading = "## High Findings: Electron TCC Inheritance"
    apple_event_heading = "## High Findings: Apple Event TCC Cascade"

    return (
        report[report.index(critical_heading) : report.index(electron_heading)],
        report[report.index(electron_heading) : report.index(apple_event_heading)],
    )


class TestReportAssemblyFailuresAndUnknowns:
    def test_enrichment_failure_is_reported(self, monkeypatch):
        def fail_enrichment():
            raise RuntimeError("fixture enrichment failure")

        monkeypatch.setitem(
            sys.modules,
            "cve_enrichment",
            SimpleNamespace(enrich_registry=fail_enrichment),
        )
        monkeypatch.setattr("report_assembly.discover_queries", lambda: [])

        report = assemble_report({}, {"hostname": "fixture-host"})

        checks.assertIn("### Vulnerability Intelligence", report)
        checks.assertIn("CVE enrichment unavailable", report)
        checks.assertIn("fixture enrichment failure", report)

    def test_missing_posture_metadata_renders_unknown_not_false(self, monkeypatch):
        monkeypatch.setattr("report_assembly.discover_queries", lambda: [])

        report = assemble_report(
            {}, {"hostname": "fixture-host", "icloud_signed_in": True}
        )
        lines = report.splitlines()

        assert_report_line_contains(lines, "Elevation", "unknown")
        assert_report_line_missing(lines, "Elevation", "user")
        assert_report_line_contains(lines, "Full Disk Access (collector)", "unknown")
        assert_report_line_contains(lines, "iCloud Drive", "unknown")
        assert_report_line_contains(lines, "iCloud Keychain", "unknown")


class TestReportAssemblyFindings:
    def _metadata(self):
        return {
            "hostname": "fixture-host",
            "macos_version": "14.5",
            "timestamp": "2026-04-17T00:00:00Z",
            "scan_id": "fixture-scan",
            "collector_version": "0.2.0",
            "is_root": False,
            "has_fda": True,
            "app_count": 1,
            "tcc_grant_count": 1,
            "entitlement_count": 1,
        }

    def test_injectable_fda_finding_reaches_summary_detail_and_recommendations(
        self, monkeypatch
    ):
        monkeypatch.setitem(
            sys.modules,
            "cve_enrichment",
            SimpleNamespace(enrich_registry=lambda: {}),
        )

        report = assemble_report(injectable_fda_query_results(), self._metadata())
        assert_injectable_report_order(report)
        critical_section, electron_section = injectable_report_sections(report)

        checks.assertIn("**Overall Risk: CRITICAL**", report)
        checks.assertIn("München &lt;Agent&gt;", critical_section)
        checks.assertIn("missing_library_validation", critical_section)
        checks.assertNotIn("München &lt;Agent&gt;", electron_section)
        checks.assertNotIn("München <Agent>", report)
        checks.assertIn("Full Disk Access and is injectable", report)
        checks.assertIn(
            "### Injectable Applications with Privileged TCC Grants", report
        )
        checks.assertIn("01-injectable-fda-apps.cypher", report)

    def test_empty_report_keeps_low_risk_and_no_injectable_recommendation(
        self, monkeypatch
    ):
        monkeypatch.setitem(
            sys.modules,
            "cve_enrichment",
            SimpleNamespace(enrich_registry=lambda: {}),
        )

        report = assemble_report({}, self._metadata())

        checks.assertIn("**Overall Risk: LOW**", report)
        checks.assertIn("_No attack paths discovered._", report)
        checks.assertIn(
            "## Critical Findings: Injectable Apps with Privileged TCC Grants", report
        )
        checks.assertIn("_No findings in this category._", report)
        checks.assertNotIn(
            "### Injectable Applications with Privileged TCC Grants", report
        )

    def test_file_acl_query_drives_vulnerability_context_and_recommendation(
        self, monkeypatch
    ):
        monkeypatch.setitem(
            sys.modules,
            "cve_enrichment",
            SimpleNamespace(enrich_registry=lambda: {}),
        )
        query_results = {
            "48-file-acl-write-paths.cypher": [
                {
                    "path": "/Library/Application Support/com.example/TCC.db",
                    "principal": "staff",
                    "access": "write",
                }
            ],
        }

        report = assemble_report(query_results, self._metadata())

        checks.assertIn("## Top Vulnerabilities & ATT&CK Mapping", report)
        checks.assertIn("file_acl_escalation", report)
        checks.assertIn("### File ACL Escalation Mitigation", report)
