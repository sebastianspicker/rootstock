"""Focused unit tests for precise vulnerability-to-application edges."""

from unittest import TestCase
from unittest.mock import MagicMock, patch

from cve_reference import CveEntry
from import_vulnerabilities import import_precise_affected_by_edges

checks = TestCase()

class TestPreciseAffectedByEdgesEmptyInput:
    def test_import_precise_edges_empty_input_skips_session(self):
        """No precise candidates means no Neo4j work."""
        mock_session = MagicMock()

        with patch("import_vulnerabilities._collect_precise_cves", return_value=[]):
            count, warning_count = import_precise_affected_by_edges(mock_session)

        checks.assertEqual((count, warning_count), (0, 0))
        mock_session.run.assert_not_called()


class TestPreciseAffectedByEdges:
    def test_import_precise_edges_match_failure_then_later_success(self, capsys):
        """A failed CVE match warns and does not block a later CVE."""
        failed_cve = self._precise_cve("CVE-2099-77770")
        successful_cve = self._precise_cve("CVE-2099-77771")
        mock_session = MagicMock()
        mock_session.run.side_effect = [
            RuntimeError("fixture match failed"),
            [
                {
                    "bundle_id": "com.example.precise",
                    "app_version": "1.0.0",
                    "macos_version": None,
                    "app_id": "app-1",
                }
            ],
            MagicMock(single=MagicMock(return_value={"n": 1})),
        ]

        with (
            patch(
                "import_vulnerabilities._collect_precise_cves",
                return_value=[failed_cve, successful_cve],
            ),
            patch(
                "import_vulnerabilities._precise_record_is_affected", return_value=True
            ),
        ):
            count, warning_count = import_precise_affected_by_edges(mock_session)

        self._assert_warning(
            capsys,
            (count, warning_count),
            "  Warning: Precise match for CVE-2099-77770 failed: fixture match failed\n",
        )

    def test_import_precise_edges_failure_continues_and_counts(self, capsys):
        """A failed edge write warns while later records still import."""
        test_cve = self._precise_cve("CVE-2099-77772")
        mock_session = MagicMock()
        mock_session.run.side_effect = [
            [
                {
                    "bundle_id": "com.example.precise",
                    "app_version": "1.0.0",
                    "macos_version": None,
                    "app_id": "app-1",
                },
                {
                    "bundle_id": "com.example.precise",
                    "app_version": "1.0.0",
                    "macos_version": None,
                    "app_id": "app-2",
                },
            ],
            RuntimeError("fixture write failed"),
            MagicMock(single=MagicMock(return_value={"n": 1})),
        ]

        with (
            patch(
                "import_vulnerabilities._collect_precise_cves", return_value=[test_cve]
            ),
            patch(
                "import_vulnerabilities._precise_record_is_affected", return_value=True
            ),
        ):
            count, warning_count = import_precise_affected_by_edges(mock_session)

        self._assert_warning(
            capsys,
            (count, warning_count),
            "  Warning: Edge creation for CVE-2099-77772 failed: fixture write failed\n",
        )
        checks.assertEqual(mock_session.run.call_count, 3)

    def test_import_precise_edges_unaffected_records_do_not_write(self):
        """Version-mismatched records remain unmatched without an edge write."""
        test_cve = self._precise_cve("CVE-2099-77773")
        mock_session = MagicMock()
        mock_session.run.return_value = [
            {
                "bundle_id": "com.example.precise",
                "app_version": "1.4.0",
                "macos_version": None,
                "app_id": "app-1",
            }
        ]

        with patch(
            "import_vulnerabilities._collect_precise_cves", return_value=[test_cve]
        ):
            count, warning_count = import_precise_affected_by_edges(mock_session)

        checks.assertEqual((count, warning_count), (0, 0))
        checks.assertEqual(mock_session.run.call_count, 1)

    @staticmethod
    def _precise_cve(cve_id: str) -> CveEntry:
        return CveEntry(
            cve_id=cve_id,
            title="Precise edge fixture CVE",
            cvss_score=7.0,
            affected_versions="FixtureApp 1.2.0 and earlier",
            patched_version="FixtureApp 1.3.0",
            description="fixture",
            reference_url="https://example.com",
            affected_bundle_ids=("com.example.precise",),
            max_affected_version="1.2.0",
        )

    @staticmethod
    def _assert_warning(capsys, result: tuple[int, int], expected: str) -> None:
        checks.assertEqual(result, (1, 1))
        checks.assertEqual(capsys.readouterr().out, expected)


