You are a senior graph database engineer performing a systematic review of the Rootstock graph schema, Pydantic models, and Neo4j import pipeline — the bridge between raw JSON scan data and the property graph used for attack path discovery.

## Context

Read: CLAUDE.md, ARCHITECTURE.md, docs/QUALITY.md,
graph/models.py, graph/setup_schema.py, graph/scan_loader.py,
graph/import.py, graph/import_nodes.py, graph/import_nodes_core.py,
graph/import_nodes_services.py, graph/import_nodes_security.py,
graph/import_nodes_security_enterprise.py, graph/import_nodes_enrichment.py,
graph/constants.py, graph/neo4j_connection.py,
graph/tests/conftest.py, graph/tests/fixture_minimal.json,
graph/tests/test_import.py, graph/tests/test_import_models.py

Also read a recent scan JSON output to understand the collector's actual format:
scan.json or graph.json (whichever exists at the repo root)

## Priority Definitions

- **P0 — Critical:** Import produces wrong graph data, MERGE creates duplicates instead of updating, data loss during import, security vulnerability
- **P1 — High:** Missing node types not imported, incorrect edge direction, property mapping errors, schema doesn't match model definitions
- **P2 — Medium:** Missing indexes causing slow queries, poor error messages on malformed input, unhelpful failure modes
- **P3 — Low:** Style inconsistencies, naming convention violations, documentation gaps

## Task: Review Phase B — Graph Schema & Import Pipeline

Perform an iterative, priority-ordered review. Fix P0 immediately, P1 in the same pass, collect P2/P3 for a later pass.

### B.1 Pydantic Model Definitions

Review `graph/models.py`:
- [ ] Does every model field match a corresponding field in the collector's JSON output?
- [ ] Are validators correct (field constraints, type coercions, default values)?
- [ ] Are there fields in the scan JSON that are not captured by any Pydantic model?
- [ ] Are there Pydantic model fields that never appear in actual scan data?
- [ ] Do model names match the Neo4j node labels defined in `constants.py`?
- [ ] Are `Optional` annotations correct — does the collector actually omit these fields?

### B.2 Schema Setup

Review `graph/setup_schema.py`:
- [ ] Do UNIQUENESS constraints cover the merge key for every node type?
- [ ] Do indexes exist for properties frequently used in WHERE clauses by queries and inference?
- [ ] Are there node types in models.py without a corresponding constraint?
- [ ] Does the schema setup handle "constraint already exists" gracefully (idempotent)?
- [ ] Are relationship types in the schema setup consistent with those created by import and inference?

### B.3 Import Modules

For each import module (`import_nodes_core.py`, `_services.py`, `_security.py`, `_security_enterprise.py`, `_enrichment.py`):
- [ ] Does every MERGE statement use the correct merge key (matching the uniqueness constraint)?
- [ ] Is every MERGE idempotent — re-importing the same data produces identical results?
- [ ] Are SET properties correct — no property mapped to the wrong field?
- [ ] Are edge directions correct (`:A)-[:REL]->(:B)` matches the actual semantic relationship)?
- [ ] Are there collector data fields that are collected but never imported into the graph?
- [ ] Does each function handle missing/null fields in the scan data without crashing?

### B.4 Import Facade

Review `graph/import_nodes.py`:
- [ ] Does it re-export all public functions from the sub-modules?
- [ ] Are there any import functions in sub-modules NOT exposed through the facade?
- [ ] Can external code (`import.py`) import everything it needs from the facade?

### B.5 Scan Loader

Review `graph/scan_loader.py`:
- [ ] Does it handle malformed JSON (truncated, invalid syntax)?
- [ ] Does it handle missing top-level fields gracefully?
- [ ] Does it handle version differences between old and new scan formats?
- [ ] Does it validate the scan data against Pydantic models with useful error messages?

### B.6 Import Orchestrator

Review `graph/import.py`:
- [ ] Does it import nodes before edges that reference them (correct ordering)?
- [ ] Does it call all import functions (cross-reference with import_nodes.py facade)?
- [ ] Does it handle partial failures (one import function fails, others continue)?
- [ ] Does it report import statistics (nodes created, relationships created)?
- [ ] Does it clear stale data or handle incremental imports correctly?

### B.7 Import Tests

Review all import-related tests:
- [ ] Is there test coverage for all node types?
- [ ] Do tests verify idempotency (import twice, same result)?
- [ ] Do tests verify edge creation with correct direction?
- [ ] Do tests cover error cases (missing fields, malformed data)?
- [ ] Does `fixture_minimal.json` contain representative data for all node types that the import handles?

## Output

For each iteration, state:
1. What you reviewed
2. Issues found (with priority)
3. Fixes applied
4. What remains

After all issues are resolved, produce a summary:

```
## Review B Summary — Graph Schema & Import
- Files reviewed: [count]
- P0 issues found/fixed: [N]
- P1 issues found/fixed: [N]
- P2 issues found/fixed: [N]
- P3 issues deferred: [N]
- Tests: [pass count] / [total count]
- Node types with import coverage: [N] / [total]
- Schema constraints verified: [N]
```

## Acceptance Criteria

- [ ] All import-related tests pass (run `cd graph && python3 -m pytest tests/test_import.py tests/test_import_models.py -q`)
- [ ] No import function produces incorrect graph data (wrong labels, wrong properties, wrong edge direction)
- [ ] Schema constraints match all node types in models.py
- [ ] MERGE operations are idempotent
- [ ] fixture_minimal.json covers all imported node types
- [ ] No P0 or P1 issues remain open
- [ ] P2/P3 issues documented in tech-debt-tracker.md

## If Stuck

After 20 iterations:
- If a schema mismatch requires collector changes: document in tech-debt-tracker.md as a cross-subsystem issue for the final consistency loop
- If Neo4j is not available for testing: verify logic by code review, flag tests as needing live validation
- If fixture_minimal.json is missing node types: add them incrementally, prioritizing types used by inference and queries

When ALL acceptance criteria are met, output:
<promise>REVIEW_B_COMPLETE</promise>
