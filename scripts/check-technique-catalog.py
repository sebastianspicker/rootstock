#!/usr/bin/env python3
"""Validate docs/references/technique-catalog.yaml reference integrity.

Checks:
  - YAML parses and has >= 15 techniques
  - graph_queries basenames exist under graph/queries/
  - blue_detections basenames exist under rootstock-blue/Content/detections/samples/
  - red_findings IDs appear as string literals under rootstock-red/Sources/

Entries with status ``planned`` skip missing-reference failures for empty mappings
but still require an id/title.

Usage:
    python3 scripts/check-technique-catalog.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "docs" / "references" / "technique-catalog.yaml"
QUERIES = ROOT / "graph" / "queries"
BLUE_DET = ROOT / "rootstock-blue" / "Content" / "detections" / "samples"
RED_SRC = ROOT / "rootstock-red" / "Sources"
MIN_TECHNIQUES = 15


def load_yaml(path: Path) -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:
        # Minimal subset parser for our catalog shape (no PyYAML required).
        return _load_yaml_minimal(path.read_text(encoding="utf-8"))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("catalog root must be a mapping")
    return data


def _load_yaml_minimal(text: str) -> dict:
    """Parse the technique catalog without PyYAML (indent-based, list of maps)."""
    # Strip comments
    lines = []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        # drop inline comments carefully only for full-line already handled
        lines.append(line)

    techniques: list[dict] = []
    version = 1
    current: dict | None = None
    section: str | None = None  # mappings key
    list_key: str | None = None
    depth_lines: list[str] = []
    in_depth = False

    def flush_depth():
        nonlocal in_depth, depth_lines, current
        if current is not None and in_depth:
            current["depth_notes"] = "\n".join(depth_lines).strip()
        depth_lines = []
        in_depth = False

    for raw in lines:
        if not raw.strip():
            if in_depth:
                depth_lines.append("")
            continue
        # version
        m = re.match(r"^version:\s*(\d+)\s*$", raw)
        if m:
            version = int(m.group(1))
            continue
        if raw.startswith("techniques:"):
            continue
        # new technique
        m = re.match(r"^\s*-\s*id:\s*(.+)\s*$", raw)
        if m:
            flush_depth()
            if current is not None:
                techniques.append(current)
            current = {
                "id": m.group(1).strip().strip("'\""),
                "mappings": {
                    "graph_queries": [],
                    "red_findings": [],
                    "blue_detections": [],
                },
            }
            section = None
            list_key = None
            continue
        if current is None:
            continue
        if re.match(r"^\s+depth_notes:\s*\|", raw):
            flush_depth()
            in_depth = True
            depth_lines = []
            list_key = None
            section = None
            continue
        if in_depth:
            # End block scalar when a peer field of the technique starts (4-space key)
            if re.match(
                r"^\s{4}(title|attack_techniques|surfaces|mappings|status|id):",
                raw,
            ):
                flush_depth()
            elif re.match(r"^\s*-\s*id:", raw):
                flush_depth()
            else:
                depth_lines.append(raw.strip())
                continue
        m = re.match(r"^\s+title:\s*(.+)\s*$", raw)
        if m:
            current["title"] = m.group(1).strip().strip("'\"")
            continue
        m = re.match(r"^\s+status:\s*(\S+)\s*$", raw)
        if m:
            current["status"] = m.group(1).strip()
            continue
        if re.match(r"^\s+mappings:\s*$", raw):
            section = "mappings"
            list_key = None
            continue
        m = re.match(r"^\s+(graph_queries|red_findings|blue_detections):\s*$", raw)
        if m:
            list_key = m.group(1)
            continue
        m = re.match(r"^\s+-\s+(.+)\s*$", raw)
        if m and list_key and section == "mappings":
            val = m.group(1).strip().strip("'\"")
            current["mappings"][list_key].append(val)
            continue
        # ignore other keys (attack_techniques, surfaces) for validation
    flush_depth()
    if current is not None:
        techniques.append(current)
    return {"version": version, "techniques": techniques}


def collect_red_ids() -> set[str]:
    ids: set[str] = set()
    if not RED_SRC.is_dir():
        return ids
    pat = re.compile(
        r'["\'](rootstock\.(?:vector|check)\.[a-zA-Z0-9_.]+)["\']'
    )
    for path in RED_SRC.rglob("*.swift"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        ids.update(pat.findall(text))
    return ids


def main() -> int:
    if not CATALOG.is_file():
        print(f"ERROR: catalog not found: {CATALOG}", file=sys.stderr)
        return 1

    try:
        data = load_yaml(CATALOG)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: failed to parse catalog: {exc}", file=sys.stderr)
        return 1

    techniques = data.get("techniques") or []
    if len(techniques) < MIN_TECHNIQUES:
        print(
            f"ERROR: expected >= {MIN_TECHNIQUES} techniques, found {len(techniques)}",
            file=sys.stderr,
        )
        return 1

    red_ids = collect_red_ids()
    errors: list[str] = []
    seen_ids: set[str] = set()

    for tech in techniques:
        tid = tech.get("id")
        if not tid:
            errors.append("technique missing id")
            continue
        if tid in seen_ids:
            errors.append(f"duplicate id: {tid}")
        seen_ids.add(tid)
        if not tech.get("title"):
            errors.append(f"{tid}: missing title")
        status = tech.get("status") or "mapped"
        mappings = tech.get("mappings") or {}
        planned = status == "planned"

        for q in mappings.get("graph_queries") or []:
            path = QUERIES / q
            if not path.is_file() and not planned:
                errors.append(f"{tid}: missing graph query {q}")

        for det in mappings.get("blue_detections") or []:
            path = BLUE_DET / f"{det}.yaml"
            if not path.is_file() and not planned:
                errors.append(f"{tid}: missing blue detection {det}.yaml")

        for fid in mappings.get("red_findings") or []:
            if fid not in red_ids and not planned:
                errors.append(f"{tid}: red finding id not found in Sources: {fid}")

    if errors:
        print("Technique catalog check FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(
        f"OK: {len(techniques)} techniques; "
        f"graph/red/blue references resolve (status≠planned enforced)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
