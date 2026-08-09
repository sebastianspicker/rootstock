"""Tests for HTML report rendering - no Neo4j required."""

import builtins
from unittest import TestCase
from unittest.mock import patch

import pytest

from report_formatters import format_generic_table
from report_html import markdown_to_html


checks = TestCase()


class TestHtmlReportEscaping:
    def test_query_values_are_escaped_before_html_conversion(self):
        table = format_generic_table([{"app": '<script>alert("x")</script>'}])
        html = markdown_to_html(table)

        checks.assertNotIn("<script>", html)
        checks.assertTrue("&lt;script&gt;" in html or "&amp;lt;script&amp;gt;" in html)

    def test_html_report_uses_landmarks_language_and_accessible_tables(self):
        html = markdown_to_html(
            "# Report\n\n> Risk: review this finding.\n\n"
            "| Name | Value |\n| --- | --- |\n| `item` | [details](https://example.test) |\n\n"
            "```text\ncommand\n```"
        )

        checks.assertIn('<html lang="en">', html)
        checks.assertIn('<main id="report-content">', html)
        checks.assertIn("<blockquote>", html)
        checks.assertIn(
            '<div class="table-scroll" role="region" aria-label="Scrollable report data table" '
            'tabindex="0"><figure><figcaption>Report data table</figcaption>',
            html,
        )
        checks.assertIn("<pre><code", html)
        checks.assertIn('href="https://example.test"', html)

    def test_html_report_fails_clearly_without_the_required_markdown_dependency(self):
        original_import = builtins.__import__

        def unavailable_markdown(name, *args, **kwargs):
            if name == "markdown":
                raise ImportError("fixture dependency unavailable")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=unavailable_markdown):
            with pytest.raises(RuntimeError, match=r"requires Markdown>=3\.8\.1,<4"):
                markdown_to_html("# Report")
