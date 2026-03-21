You are a senior DevOps and testing infrastructure engineer performing a systematic review of the Rootstock test harness, shared utilities, and pipeline orchestration — the foundation that everything else depends on.

## Context

Read: CLAUDE.md, ARCHITECTURE.md, docs/QUALITY.md,
graph/tests/conftest.py, graph/tests/fixture_minimal.json,
graph/utils.py, graph/constants.py, graph/neo4j_connection.py,
graph/pipeline.sh, graph/test_connection.py, graph/setup.py,
graph/requirements.txt,
graph/tests/test_utils.py, graph/tests/test_scan_loader.py

Also run: `cd graph && python3 -m pytest tests/ -q --co` (collect tests without running) to see the full test inventory.

## Priority Definitions

- **P0 — Critical:** Test infrastructure silently passes when it should fail, fixture data causes tests to produce wrong assertions, pipeline script can corrupt data
- **P1 — High:** Missing fixture data for node types (tests can't cover them), broken imports between modules, incorrect Neo4j connection handling (leaks, no cleanup)
- **P2 — Medium:** Slow test execution, missing test helpers, pipeline error handling gaps, stale constants
- **P3 — Low:** Style inconsistencies, missing docstrings, redundant utilities

## Task: Review Phase F — Test Harness & Utilities

Perform an iterative, priority-ordered review of the infrastructure layer.

### F.1 Test Configuration

Review `graph/tests/conftest.py`:
- [ ] Are pytest fixtures correctly scoped (session vs function vs module)?
- [ ] Does the Neo4j test fixture properly set up and tear down test data?
- [ ] Is there a risk of test pollution (one test's data affecting another)?
- [ ] Does the fixture handle "Neo4j not available" gracefully (skip, not crash)?
- [ ] Are fixture cleanup hooks reliable (no orphaned test data)?
- [ ] Is the test database isolated from production data?

### F.2 Test Fixture Data

Review `graph/tests/fixture_minimal.json`:
- [ ] Does the fixture contain representative data for ALL node types handled by the import pipeline?
- [ ] Cross-reference with `graph/models.py` — are there models without fixture data?
- [ ] Cross-reference with `graph/import_nodes*.py` — are there import functions without matching fixture data?
- [ ] Is the fixture data internally consistent (e.g., entitlements reference apps that exist)?
- [ ] Is the fixture realistic enough that inference modules produce meaningful results?
- [ ] Are edge cases represented (empty arrays, null optional fields, maximum-length strings)?

### F.3 Utilities

Review `graph/utils.py`:
- [ ] Is every function in utils.py actually used somewhere in the codebase?
- [ ] Are there utility functions duplicated elsewhere that should be consolidated?
- [ ] Do utility functions handle edge cases (empty input, None, unexpected types)?
- [ ] Are there any utility functions that have side effects they shouldn't?

### F.4 Constants

Review `graph/constants.py`:
- [ ] Does every Neo4j node label constant match what `setup_schema.py` creates?
- [ ] Does every relationship type constant match what `import_nodes*.py` and `infer_*.py` create?
- [ ] Are there constants defined but never used?
- [ ] Are there hardcoded strings in other files that should be constants?
- [ ] Do constant names follow the project's UPPER_SNAKE_CASE convention?

### F.5 Neo4j Connection

Review `graph/neo4j_connection.py`:
- [ ] Is connection pooling configured correctly?
- [ ] Does it handle connection failures with retry logic?
- [ ] Is there proper timeout configuration?
- [ ] Are sessions/transactions properly closed (no resource leaks)?
- [ ] Does it read connection parameters from environment variables (not hardcoded)?
- [ ] Is there a health check or ping method?

### F.6 Pipeline Script

Review `graph/pipeline.sh`:
- [ ] Does it chain all steps correctly (schema → import → infer → classify → report)?
- [ ] Does it check for prerequisites (Neo4j running, Python available, scan file exists)?
- [ ] Does error handling between steps work (step fails → pipeline stops with clear message)?
- [ ] Does it support `--help` with usage information?
- [ ] Are file paths relative/configurable (not hardcoded absolute paths)?
- [ ] Does `set -e` or equivalent prevent silent failures?

### F.7 Connection Test & Setup

Review `graph/test_connection.py` and `graph/setup.py`:
- [ ] Does the connection test correctly validate Neo4j connectivity?
- [ ] Does it report the Neo4j version and status?
- [ ] Is `setup.py` package metadata correct (name, version, dependencies)?
- [ ] Are entry points (if any) correctly defined?
- [ ] Does `requirements.txt` match actual imports across the codebase?

### F.8 Cross-File Import Consistency

Verify that all inter-module imports work after the codebase splits:
- [ ] Run `cd graph && python3 -c "from import_nodes import *"` — does the facade work?
- [ ] Run `cd graph && python3 -c "from infer import *"` — does the inference facade work?
- [ ] Are there any circular imports?
- [ ] Are there any imports of modules that don't exist or were renamed?

### F.9 Full Test Suite

- [ ] Run `cd graph && python3 -m pytest tests/ -q` — do ALL tests pass?
- [ ] Are there any tests that are skipped? Why?
- [ ] Are there any tests that pass but have wrong assertions (testing the wrong thing)?
- [ ] What is the total test count? Is it reasonable for the codebase size?

## Output

For each iteration, state:
1. What you reviewed
2. Issues found (with priority)
3. Fixes applied
4. What remains

After all issues are resolved, produce a summary:

```
## Review F Summary — Test Harness & Utilities
- Files reviewed: [count]
- P0 issues found/fixed: [N]
- P1 issues found/fixed: [N]
- P2 issues found/fixed: [N]
- P3 issues deferred: [N]
- Total test count: [N]
- Tests passing: [N] / [N]
- Fixture coverage: [N] node types / [total]
- Constants verified: [N] / [total]
- Pipeline steps verified: [N] / [total]
```

## Acceptance Criteria

- [ ] Full test suite passes: `cd graph && python3 -m pytest tests/ -q`
- [ ] `pipeline.sh` runs without errors (or `--help` works if Neo4j unavailable)
- [ ] No orphaned imports or missing dependencies
- [ ] fixture_minimal.json covers all node types
- [ ] constants.py matches actual usage across the codebase
- [ ] No P0 or P1 issues remain open
- [ ] P2/P3 issues documented in tech-debt-tracker.md

## If Stuck

After 12 iterations:
- If Neo4j is unavailable for pipeline testing: verify `pipeline.sh` logic by reading, test individual Python steps
- If circular import issues are deep: document the dependency graph, propose a fix plan in tech-debt-tracker.md
- If fixture_minimal.json grows too large: keep it minimal but representative, add comments for why each entry exists
- Priority: test infrastructure correctness > fixture completeness > utility cleanup > pipeline polish

When ALL acceptance criteria are met, output:
<promise>REVIEW_F_COMPLETE</promise>
