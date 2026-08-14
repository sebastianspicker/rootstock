"""Collected query catalog and syntax validation tests."""

import re
from query_test_support import (
    QUERIES_DIR,
    _REACHABILITY_QUERY_FILES,
    _REQUIRED_ATTACK_EDGES,
    _REQUIRED_QUERY_FILES,
    _REQUIRED_QUERY_METADATA,
    _VALID_CATEGORIES,
    _VALID_SEVERITIES,
    _all_cypher_files,
    _first_statement,
    _parse_header,
    _query_text,
    checks,
)

pytest_plugins = ["query_test_support"]


class TestQueryFileStructure:
    def test_query_directory_exists(self):
        checks.assertTrue(
            QUERIES_DIR.is_dir(), f"queries/ directory not found at {QUERIES_DIR}"
        )

    def test_required_query_files_present(self):
        files_by_id = {
            path.stem.split("-")[0]: path.name for path in _all_cypher_files()
        }

        missing = {
            qid: filename
            for qid, filename in _REQUIRED_QUERY_FILES.items()
            if files_by_id.get(qid) != filename
        }
        checks.assertFalse(missing, f"Missing or renamed required queries: {missing}")

    def test_required_query_metadata_is_stable(self):
        files_by_id = {path.stem.split("-")[0]: path for path in _all_cypher_files()}
        mismatches = []
        for qid, expected in _REQUIRED_QUERY_METADATA.items():
            path = files_by_id.get(qid)
            if path is None:
                mismatches.append(f"{qid}: missing")
                continue
            meta = _parse_header(path)
            for key, value in expected.items():
                if meta.get(key) != value:
                    mismatches.append(f"{path.name}: {key}={meta.get(key)!r}")
        checks.assertFalse(mismatches, f"Required query metadata drifted: {mismatches}")

    def test_all_files_have_name_header(self):
        missing = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            if "name" not in meta or not meta["name"]:
                missing.append(path.name)
        checks.assertFalse(missing, f"Missing 'Name' header in: {missing}")

    def test_all_files_have_valid_category(self):
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            cat = meta.get("category", "")
            if cat not in _VALID_CATEGORIES:
                bad.append(f"{path.name}: '{cat}'")
        checks.assertFalse(bad, f"Invalid or missing 'Category' in: {bad}")

    def test_all_files_have_valid_severity(self):
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            sev = meta.get("severity", "")
            if sev not in _VALID_SEVERITIES:
                bad.append(f"{path.name}: '{sev}'")
        checks.assertFalse(bad, f"Invalid or missing 'Severity' in: {bad}")

    def test_all_files_non_empty(self):
        empty = []
        for path in _all_cypher_files():
            stmt = _first_statement(path.read_text(encoding="utf-8"))
            if not stmt:
                empty.append(path.name)
        checks.assertFalse(empty, f"Empty (no Cypher body) in: {empty}")

    def test_query_ids_are_unique_numeric_prefixes(self):
        """Query IDs should be unique numeric filename prefixes."""
        ids = []
        non_numeric = []
        for path in _all_cypher_files():
            stem = path.stem
            qid = stem.split("-")[0]
            try:
                ids.append(int(qid))
            except ValueError:
                non_numeric.append(path.name)
        checks.assertFalse(non_numeric, f"Non-numeric query IDs: {non_numeric}")
        duplicates = sorted({qid for qid in ids if ids.count(qid) > 1})
        checks.assertFalse(duplicates, f"Duplicate query IDs: {duplicates}")

    def test_all_queries_are_read_only(self):
        """Every .cypher file should pass the read-only Cypher validator."""
        from utils import validate_read_only_cypher

        failures = []
        for path in _all_cypher_files():
            cypher = path.read_text(encoding="utf-8")
            stmt = _first_statement(cypher)
            error = validate_read_only_cypher(stmt)
            if error:
                failures.append(f"{path.name}: {error}")
        checks.assertFalse(
            failures,
            "Queries that failed read-only validation:\n" + "\n".join(failures),
        )

    def test_all_queries_parseable(self):
        """Every .cypher file should produce a non-empty first statement."""
        failures = []
        for path in _all_cypher_files():
            cypher = path.read_text(encoding="utf-8")
            stmt = _first_statement(cypher)
            if not stmt:
                failures.append(path.name)
        checks.assertFalse(failures, f"Queries with no parseable statement: {failures}")

    def test_cve_header_format_when_present(self):
        """CVE headers (when present) must contain valid CVE IDs."""
        cve_id_re = re.compile(r"CVE-\d{4}-\d+")
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            cve_val = meta.get("cve", "")
            if not cve_val:
                continue
            ids = cve_id_re.findall(cve_val)
            if not ids:
                bad.append(f"{path.name}: '{cve_val}' has no valid CVE IDs")
        checks.assertFalse(bad, f"Invalid CVE header format: {bad}")

    def test_attack_header_format_when_present(self):
        """ATT&CK headers (when present) must contain valid technique IDs."""
        tech_re = re.compile(r"T\d{4}(?:\.\d{3})?")
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            attack_val = meta.get("att&ck", "")
            if not attack_val:
                continue
            ids = tech_re.findall(attack_val)
            if not ids:
                bad.append(f"{path.name}: '{attack_val}' has no valid technique IDs")
        checks.assertFalse(bad, f"Invalid ATT&CK header format: {bad}")

    def test_reachability_queries_include_all_attack_edges(self):
        for filename in _REACHABILITY_QUERY_FILES:
            text = _query_text(filename)
            for edge in _REQUIRED_ATTACK_EDGES:
                checks.assertIn(edge, text, f"{filename} is missing {edge}")

    def test_query_62_bounds_certificate_chain_depth(self):
        text = _query_text("62-non-apple-ca-chain.cypher")
        checks.assertIn("[:ISSUED_BY*0..10]", text)
        checks.assertNotIn("[:ISSUED_BY*0..]", text)


# ── Layer 2: Syntax validation (Neo4j EXPLAIN) ────────────────────────────────


class TestQuerySyntax:
    def test_all_queries_parse(self, neo4j_session):
        """EXPLAIN each query to verify Cypher syntax is valid."""
        failures = []
        for path in _all_cypher_files():
            cypher = path.read_text(encoding="utf-8")
            stmt = _first_statement(cypher)
            if not stmt:
                continue
            # Strip parameter references for EXPLAIN - use empty params
            try:
                neo4j_session.run(
                    f"EXPLAIN {stmt}",
                    {
                        "target_service": "kTCCServiceMicrophone",
                        "min_permissions": 3,
                        "team_id": "TEST",
                        "bundle_id": "com.example.test",
                        "days_old": 365,
                        "min_methods": 1,
                        "username": "testuser",
                        "scope": None,
                    },
                )
            except Exception as e:
                failures.append(f"{path.name}: {e}")
        checks.assertFalse(failures, "Cypher syntax errors:\n" + "\n".join(failures))


# ── Layer 3: Seeded execution tests ──────────────────────────────────────────
