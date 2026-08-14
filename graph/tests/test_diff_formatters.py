"""test_diff_formatters.py - Tests for diff_formatters.py (summarize, format_text)."""

from __future__ import annotations

from unittest import TestCase

import json
from pathlib import Path

from conftest import clone_clean_application
from diff_formatters import (
    _application_lines,
    _persistence_lines,
    _physical_posture_lines,
    format_text,
    summarize,
)
from diff_models import AppDiff, PersistenceDiff, PhysicalPostureDiff, PostureDiff
from diff_scans import diff_scans
from models import ScanResult

FIXTURE = Path(__file__).parent / "fixtures" / "minimal_scan.json"


def _load_fixture() -> ScanResult:
    return ScanResult.model_validate(json.loads(FIXTURE.read_text()))


# ── summarize ────────────────────────────────────────────────────────────────

checks = TestCase()


def test_summarize_keys():
    """All expected metric keys are present in summary dict."""
    scan = _load_fixture()
    diff = diff_scans(scan, scan)
    s = summarize(diff, scan, scan)

    expected_keys = {
        "apps_before",
        "apps_after",
        "apps_delta",
        "injectable_before",
        "injectable_after",
        "injectable_delta",
        "tcc_grants_before",
        "tcc_grants_after",
        "tcc_grants_delta",
        "persistence_before",
        "persistence_after",
        "persistence_delta",
        "new_tcc_grants",
        "removed_tcc_grants",
        "changed_tcc_grants",
        "new_injectable_apps",
        "fixed_injectable_apps",
        "physical_posture_changes",
        "remote_access_changes",
        "icloud_posture_changes",
    }
    checks.assertEqual(expected_keys, set(s.keys()))


def test_summarize_identical_scans_zero_deltas():
    """Identical scans produce zero deltas."""
    scan = _load_fixture()
    diff = diff_scans(scan, scan)
    s = summarize(diff, scan, scan)

    checks.assertEqual(s["apps_delta"], 0)
    checks.assertEqual(s["injectable_delta"], 0)
    checks.assertEqual(s["tcc_grants_delta"], 0)
    checks.assertEqual(s["persistence_delta"], 0)
    checks.assertEqual(s["new_tcc_grants"], 0)
    checks.assertEqual(s["removed_tcc_grants"], 0)


# ── format_text ──────────────────────────────────────────────────────────────


def test_format_text_header():
    """Output contains hostname."""
    scan = _load_fixture()
    diff = diff_scans(scan, scan)
    s = summarize(diff, scan, scan)
    output = format_text(diff, s)

    checks.assertIn("test-mac", output)


def test_format_text_no_changes():
    """Identical scans produce 'No security-relevant changes detected.'"""
    scan = _load_fixture()
    diff = diff_scans(scan, scan)
    s = summarize(diff, scan, scan)
    output = format_text(diff, s)

    checks.assertIn("No security-relevant changes detected.", output)


def test_format_text_app_changes():
    """Diff with added app shows [+] marker."""
    before = _load_fixture()
    after_data = json.loads(FIXTURE.read_text())
    added_app = clone_clean_application(
        after_data["applications"][0],
        name="NewApp",
        bundle_id="com.example.newapp",
        path="/Applications/NewApp.app",
        team_id="TEAM123",
    )
    after_data["applications"].append(added_app)
    after = ScanResult.model_validate(after_data)

    diff = diff_scans(before, after)
    s = summarize(diff, before, after)
    output = format_text(diff, s)

    checks.assertIn("[+]", output)
    checks.assertIn("com.example.newapp", output)


def test_application_lines_render_added_and_removed_entries_exactly():
    """Application sections retain marker order and trailing blank line."""
    diff = PostureDiff(
        apps=AppDiff(
            added=["com.example.add (Added App)"],
            removed=["com.example.remove (Removed App)"],
        )
    )

    checks.assertEqual(
        _application_lines(diff),
        [
            "=== Application Changes ===",
            "  [+] com.example.add (Added App)",
            "  [-] com.example.remove (Removed App)",
            "",
        ],
    )


def test_application_lines_render_removed_only_entry_exactly():
    """Application sections remain present when only removals are reported."""
    diff = PostureDiff(apps=AppDiff(removed=["com.example.remove (Removed App)"]))

    checks.assertEqual(
        _application_lines(diff),
        [
            "=== Application Changes ===",
            "  [-] com.example.remove (Removed App)",
            "",
        ],
    )


def test_persistence_lines_render_added_and_removed_entries_exactly():
    """Persistence sections retain marker order and trailing blank line."""
    diff = PostureDiff(
        persistence=PersistenceDiff(
            added=["com.example.add"],
            removed=["com.example.remove"],
        )
    )

    checks.assertEqual(
        _persistence_lines(diff),
        [
            "=== Persistence Changes ===",
            "  [+] com.example.add",
            "  [-] com.example.remove",
            "",
        ],
    )


def test_persistence_lines_render_added_only_entry_exactly():
    """Persistence sections remain present when only additions are reported."""
    diff = PostureDiff(persistence=PersistenceDiff(added=["com.example.add"]))

    checks.assertEqual(
        _persistence_lines(diff),
        [
            "=== Persistence Changes ===",
            "  [+] com.example.add",
            "",
        ],
    )


def test_persistence_lines_render_removed_only_entry_exactly():
    """Persistence sections remain present when only removals are reported."""
    diff = PostureDiff(persistence=PersistenceDiff(removed=["com.example.remove"]))

    checks.assertEqual(
        _persistence_lines(diff),
        [
            "=== Persistence Changes ===",
            "  [-] com.example.remove",
            "",
        ],
    )


def test_physical_posture_lines_normalize_keys_and_render_changes_exactly():
    """Physical posture sections retain normalized labels and trailing blank line."""
    diff = PostureDiff(
        physical_posture=PhysicalPostureDiff(
            changes={
                "screen_lock_delay": {"before": 5, "after": 0},
                "external_boot_allowed": {"before": True, "after": False},
            }
        )
    )

    checks.assertEqual(
        _physical_posture_lines(diff),
        [
            "=== Physical Security Posture Changes ===",
            "  [!] Screen Lock Delay: 5 → 0",
            "  [!] External Boot Allowed: True → False",
            "",
        ],
    )


def test_added_removed_sections_omit_empty_output():
    """Empty application, persistence, and physical posture sections are omitted."""
    diff = PostureDiff()

    checks.assertEqual(_application_lines(diff), [])
    checks.assertEqual(_persistence_lines(diff), [])
    checks.assertEqual(_physical_posture_lines(diff), [])
