# Examples

Demo data and scripts for Rootstock.

## Files

### `demo-scan.json`
Synthetic scan data representing a typical corporate MacBook. Contains 15 applications,
15 TCC grants, 5 XPC services, and representative entitlements. Use this to test the
graph pipeline without running the collector.

### `generate_demo_scan.py`
Python script that generates `demo-scan.json`. Edit this to add or modify demo data.

```bash
python3 examples/generate_demo_scan.py
```

### `regenerate.sh`
End-to-end script that regenerates all demo outputs from `demo-scan.json`.
Requires a running Neo4j instance.

```bash
# Ensure Neo4j is running, then:
bash examples/regenerate.sh
```

This runs the full pipeline (schema, import, infer, classify, report) and produces:
- `demo-report.md` — Full attack path report
- `demo-viewer.html` — Interactive graph viewer (open in browser)

## Using Demo Data

```bash
# Import into Neo4j
cd graph && bash pipeline.sh ../examples/demo-scan.json

# Or step by step:
python3 graph/setup_schema.py
python3 graph/import.py --input examples/demo-scan.json
python3 graph/infer.py
python3 graph/import_vulnerabilities.py
```
