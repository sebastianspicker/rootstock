#!/usr/bin/env python3
"""
validate-scan.py — Validate a Rootstock scan JSON output.

Usage:
    python3 scripts/validate-scan.py <scan-file.json>

Exit code 0 on success, 1 on validation failure.
"""

import json
import sys
import uuid
from pathlib import Path
from datetime import datetime

try:
    import jsonschema
except ImportError:
    print("ERROR: jsonschema not installed. Run: pip3 install jsonschema", file=sys.stderr)
    sys.exit(1)

SCHEMA_PATH = Path(__file__).parent.parent / "collector" / "schema" / "scan-result.schema.json"


def load_schema():
    if not SCHEMA_PATH.exists():
        print(f"ERROR: Schema not found at {SCHEMA_PATH}", file=sys.stderr)
        sys.exit(1)
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def validate_schema(data, schema):
    """Validate data against JSON Schema. Returns list of error strings."""
    errors = []
    validator = jsonschema.Draft202012Validator(schema)
    for err in validator.iter_errors(data):
        path = " → ".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"  Schema: [{path}] {err.message}")
    return errors


def validate_semantics(data):
    """Perform semantic checks beyond JSON Schema. Returns list of error strings."""
    errors = []

    # scan_id must be a valid UUID
    try:
        uuid.UUID(data.get("scan_id", ""))
    except ValueError:
        errors.append(f"  Semantic: scan_id is not a valid UUID: {data.get('scan_id')!r}")

    # timestamp must be parseable ISO 8601
    ts = data.get("timestamp", "")
    try:
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        errors.append(f"  Semantic: timestamp is not valid ISO 8601 UTC: {ts!r}")

    # No empty strings in required string fields
    for field in ("hostname", "macos_version", "collector_version"):
        if not data.get(field, "").strip():
            errors.append(f"  Semantic: required field '{field}' is empty")

    # No duplicate bundle_ids in applications
    bundle_ids = [a["bundle_id"] for a in data.get("applications", [])]
    seen = set()
    for bid in bundle_ids:
        if bid in seen:
            errors.append(f"  Semantic: duplicate bundle_id: {bid!r}")
        seen.add(bid)

    # No empty strings in application required string fields
    for app in data.get("applications", []):
        for field in ("name", "bundle_id", "path"):
            if not app.get(field, "").strip():
                errors.append(
                    f"  Semantic: application {app.get('bundle_id', '?')!r} has empty '{field}'"
                )

    # Entitlement categories must be from known set
    known_categories = {"tcc", "injection", "privilege", "sandbox", "keychain", "network", "other"}
    for app in data.get("applications", []):
        for ent in app.get("entitlements", []):
            if ent.get("category") not in known_categories:
                errors.append(
                    f"  Semantic: unknown entitlement category {ent.get('category')!r} "
                    f"in {app.get('bundle_id')!r}"
                )

    return errors


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <scan-file.json>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    # Load JSON
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)

    schema = load_schema()

    schema_errors = validate_schema(data, schema)
    semantic_errors = validate_semantics(data)
    all_errors = schema_errors + semantic_errors

    if all_errors:
        print(f"✗ Invalid: {path}")
        for err in all_errors:
            print(err)
        sys.exit(1)
    else:
        apps = len(data.get("applications", []))
        grants = len(data.get("tcc_grants", []))
        errors = len(data.get("errors", []))
        print(
            f"✓ Valid: {path} "
            f"({apps} apps, {grants} TCC grants, {errors} collection errors)"
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
