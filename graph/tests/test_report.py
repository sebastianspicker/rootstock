"""
Tests for report.py formatting functions - no Neo4j required.
All tested functions take query result dicts and return Markdown strings.
"""

import json

import pytest

from report import (
    ScanMetadataError,
    get_scan_metadata_from_neo4j,
    get_scan_metadata_from_json,
    main,
    run_all_queries,
)
from unittest import TestCase
from unittest.mock import ANY, MagicMock, patch


checks = TestCase()


def assert_failed_report(output, driver, *uninvoked_mocks):
    checks.assertEqual(1, main())
    driver.close.assert_called_once()
    for mock in uninvoked_mocks:
        mock.assert_not_called()
    checks.assertFalse(output.exists())


def report_cli_setup(tmp_path, monkeypatch):
    output = tmp_path / "report.md"
    fake_driver = MagicMock()
    monkeypatch.setattr("sys.argv", ["report.py", "--output", str(output)])
    return output, fake_driver


class TestReportMetadata:
    def test_metadata_prefers_computer_node(self):
        driver = MagicMock()
        session_cm = driver.session.return_value.__enter__.return_value
        session_cm.run.side_effect = [
            MagicMock(
                single=lambda: {
                    "app_count": 2,
                    "tcc_grant_count": 3,
                    "entitlement_count": 4,
                }
            ),
            MagicMock(
                single=lambda: {
                    "scan_id": "scan-1",
                    "hostname": "host-a",
                    "macos_version": "14.5",
                    "collector_version": "0.2.0",
                    "timestamp": "2026-04-17T00:00:00Z",
                    "is_root": True,
                    "has_fda": True,
                }
            ),
        ]

        metadata = get_scan_metadata_from_neo4j(driver)

        checks.assertEqual(metadata["scan_id"], "scan-1")
        checks.assertEqual(metadata["hostname"], "host-a")
        checks.assertEqual(metadata["collector_version"], "0.2.0")
        checks.assertIs(metadata["has_fda"], True)

    def test_json_metadata_preserves_missing_elevation_as_unknown(self, tmp_path):
        scan_json = tmp_path / "scan.json"
        scan_json.write_text(
            json.dumps(
                {
                    "scan_id": "scan-unknown",
                    "hostname": "host-a",
                    "macos_version": "14.5",
                    "collector_version": "0.2.0",
                    "timestamp": "2026-04-17T00:00:00Z",
                    "elevation": {},
                }
            ),
            encoding="utf-8",
        )

        metadata = get_scan_metadata_from_json(scan_json)

        checks.assertIsNone(metadata["is_root"])
        checks.assertIsNone(metadata["has_fda"])

    def test_json_metadata_read_error_raises_typed_exception(self, tmp_path):
        missing_scan = tmp_path / "missing-scan.json"

        with pytest.raises(ScanMetadataError, match="Cannot read scan metadata"):
            get_scan_metadata_from_json(missing_scan)


class TestReportQueries:
    def test_parameterized_queries_receive_app_name_default(self, monkeypatch):
        session = MagicMock()
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        monkeypatch.setattr(
            "report.discover_queries",
            lambda: [
                {
                    "filename": "22-trust-boundary-map.cypher",
                    "cypher": "MATCH (a) WHERE $app_name IS NULL RETURN a",
                    "parameters": "$app_name",
                }
            ],
        )

        with patch("report.run_query", return_value=[]) as run_query_mock:
            results = run_all_queries(driver)

        checks.assertEqual(results["22-trust-boundary-map.cypher"], [])
        run_query_mock.assert_called_once_with(
            session,
            "MATCH (a) WHERE $app_name IS NULL RETURN a",
            ANY,
        )
        params = run_query_mock.call_args.args[2]
        checks.assertIn("app_name", params)
        checks.assertIsNone(params["app_name"])


class TestReportCli:
    def test_main_uses_shared_connection_helper(self, tmp_path, monkeypatch):
        output, fake_driver = report_cli_setup(tmp_path, monkeypatch)

        with (
            patch("report.connect_from_args", return_value=fake_driver) as connect_mock,
            patch(
                "report.get_scan_metadata_from_neo4j", return_value={"hostname": "host"}
            ),
            patch("report.run_all_queries", return_value={}),
            patch("report.assemble_report", return_value="# report"),
        ):
            exit_code = main()

        checks.assertEqual(exit_code, 0)
        connect_mock.assert_called_once()
        checks.assertEqual(output.read_text(), "# report")

    def test_main_fails_when_scan_metadata_cannot_be_read(self, tmp_path, monkeypatch):
        output = tmp_path / "report.md"
        missing_scan = tmp_path / "missing-scan.json"
        fake_driver = MagicMock()
        monkeypatch.setattr(
            "sys.argv",
            ["report.py", "--output", str(output), "--scan-json", str(missing_scan)],
        )

        with (
            patch("report.connect_from_args", return_value=fake_driver),
            patch("report.run_all_queries") as run_queries_mock,
            patch("report.assemble_report") as assemble_mock,
        ):
            assert_failed_report(output, fake_driver, run_queries_mock, assemble_mock)

    def test_main_fails_when_neo4j_metadata_query_reports_uncertainty(
        self, tmp_path, monkeypatch
    ):
        output, fake_driver = report_cli_setup(tmp_path, monkeypatch)

        with (
            patch("report.connect_from_args", return_value=fake_driver),
            patch(
                "report.get_scan_metadata_from_neo4j",
                return_value={"_metadata_errors": ["metadata counts: boom"]},
            ),
            patch("report.run_all_queries") as run_queries_mock,
            patch("report.assemble_report") as assemble_mock,
        ):
            assert_failed_report(output, fake_driver, run_queries_mock, assemble_mock)

    def test_main_fails_when_any_query_fails(self, tmp_path, monkeypatch):
        output = tmp_path / "report.md"
        fake_driver = MagicMock()
        monkeypatch.setattr("sys.argv", ["report.py", "--output", str(output)])

        with (
            patch("report.connect_from_args", return_value=fake_driver),
            patch(
                "report.get_scan_metadata_from_neo4j", return_value={"hostname": "host"}
            ),
            patch(
                "report.run_all_queries",
                return_value={"01-injectable-fda-apps.cypher": "Query failed: boom"},
            ),
            patch("report.assemble_report") as assemble_mock,
        ):
            assert_failed_report(output, fake_driver, assemble_mock)
