"""test_utils.py — Tests for graph/utils.py helper functions."""

from __future__ import annotations

from unittest.mock import MagicMock

from utils import first_cypher_statement, list_or_str, run_query, sanitize_id, truncate


# ── list_or_str ──────────────────────────────────────────────────────────────

def test_list_or_str_with_list():
    assert list_or_str(["a", "b", "c"]) == "a, b, c"


def test_list_or_str_with_none():
    assert list_or_str(None) == "—"


def test_list_or_str_with_custom_placeholder():
    assert list_or_str(None, none_placeholder="N/A") == "N/A"


def test_list_or_str_with_string():
    assert list_or_str("hello") == "hello"


def test_list_or_str_with_int():
    assert list_or_str(42) == "42"


# ── truncate ─────────────────────────────────────────────────────────────────

def test_truncate_short_unchanged():
    assert truncate("short", max_len=30) == "short"


def test_truncate_exact_length():
    text = "x" * 30
    assert truncate(text, max_len=30) == text


def test_truncate_over_length():
    text = "a" * 40
    result = truncate(text, max_len=30)
    assert len(result) == 30
    assert result.endswith("…")


# ── sanitize_id ──────────────────────────────────────────────────────────────

def test_sanitize_id_alphanums_unchanged():
    assert sanitize_id("abc_123") == "abc_123"


def test_sanitize_id_special_chars():
    assert sanitize_id("com.apple.Terminal") == "com_apple_Terminal"


def test_sanitize_id_empty_returns_fallback():
    assert sanitize_id("") == "node"
    assert sanitize_id("", fallback="unknown") == "unknown"


# ── first_cypher_statement ───────────────────────────────────────────────────

def test_first_cypher_strips_comments():
    cypher = "// comment\nMATCH (n) RETURN n;\nMATCH (m) RETURN m;"
    assert first_cypher_statement(cypher) == "MATCH (n) RETURN n"


def test_first_cypher_returns_first_nonempty():
    cypher = "  ;  ; MATCH (n) RETURN n"
    assert first_cypher_statement(cypher) == "MATCH (n) RETURN n"


def test_first_cypher_no_semicolons():
    cypher = "MATCH (n) RETURN n"
    assert first_cypher_statement(cypher) == "MATCH (n) RETURN n"


# ── run_query ────────────────────────────────────────────────────────────────

def test_run_query_returns_dicts():
    record1 = {"name": "iTerm2", "count": 1}
    record2 = {"name": "Slack", "count": 2}
    mock_session = MagicMock()
    mock_session.run.return_value = [record1, record2]

    result = run_query(mock_session, "MATCH (n) RETURN n.name AS name")
    assert result == [record1, record2]
    mock_session.run.assert_called_once_with("MATCH (n) RETURN n.name AS name", {})
