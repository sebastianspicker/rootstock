"""
utils.py — Shared utilities for Rootstock graph tools.

Common helpers used by report.py, query_runner.py, report_diagrams.py,
and report_graphviz.py to avoid duplication.
"""

from __future__ import annotations

import re
from typing import Any


def list_or_str(value: Any, none_placeholder: str = "—") -> str:
    """Convert list values from Neo4j to a comma-separated string."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if value is None:
        return none_placeholder
    return str(value)


def first_cypher_statement(cypher: str) -> str:
    """
    Extract the first executable Cypher statement from a multi-statement file.
    Strips comment lines first, then splits on semicolons.
    """
    non_comment_lines = [
        line for line in cypher.splitlines()
        if not line.strip().startswith("//")
    ]
    cleaned = "\n".join(non_comment_lines)
    for stmt in cleaned.split(";"):
        stripped = stmt.strip()
        if stripped:
            return stripped
    return cleaned.strip()


def run_query(session, cypher: str, params: dict | None = None) -> list[dict]:
    """Run a single Cypher statement, return list of record dicts."""
    result = session.run(cypher, params or {})
    return [dict(r) for r in result]


def sanitize_id(text: str, fallback: str = "node") -> str:
    """Convert arbitrary strings to safe identifiers (alphanumeric + underscore)."""
    if not text:
        return fallback
    return re.sub(r"[^a-zA-Z0-9_]", "_", str(text))


def truncate(text: str, max_len: int = 30) -> str:
    """Truncate long labels for diagram readability."""
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


# ── Read-only Cypher validation ─────────────────────────────────────────────

_WRITE_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DROP|DETACH|CALL\s*\{)\b",
    re.IGNORECASE,
)


def validate_read_only_cypher(cypher: str) -> str | None:
    """
    Check that a Cypher query is read-only.

    Returns None if the query is safe, or an error message string
    describing the rejected keyword if a write operation is detected.

    Strips comments before checking.
    """
    # Strip // comments
    lines = [
        line for line in cypher.splitlines()
        if not line.strip().startswith("//")
    ]
    cleaned = " ".join(lines)

    # Strip string literals to avoid false positives
    # (e.g., "SET something" as a string value)
    no_strings = re.sub(r"'[^']*'", "''", cleaned)
    no_strings = re.sub(r'"[^"]*"', '""', no_strings)

    match = _WRITE_KEYWORDS.search(no_strings)
    if match:
        return f"Write operation not allowed: {match.group(0).strip()}"
    return None
