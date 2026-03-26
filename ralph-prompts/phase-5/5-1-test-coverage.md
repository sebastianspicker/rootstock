You are the Collector Engineer agent for the Rootstock project.

## Context

Read: CLAUDE.md §Security Principles, docs/QUALITY.md, ARCHITECTURE.md,
all collector modules in collector/Sources/, graph/import.py, graph/infer.py

## Task: Phase 5.1 — Testabdeckung & Fixtures

Build comprehensive test fixtures and achieve solid test coverage across both the collector and the graph pipeline.

### Step 1: Synthetic TCC.db Fixtures
Create `tests/fixtures/tcc/`:
- `basic.db` — 10 TCC grants: mix of allowed/denied, FDA, Camera, Mic, Accessibility
- `empty.db` — valid TCC schema but zero rows
- `system-scope.db` — entries with system scope and MDM auth_reason
- `malformed.db` — SQLite file with wrong schema (missing columns) → tests graceful failure
- Python helper script `tests/fixtures/tcc/create_fixtures.py` that generates these

### Step 2: Fixture App Bundles
Create `tests/fixtures/apps/`:
- `HardenedApp.app/` — minimal app bundle with hardened runtime + library validation
  - Create with: `mkdir -p`, Info.plist, dummy binary, sign with `codesign --sign - --options runtime`
- `UnhardenedApp.app/` — app bundle WITHOUT hardened runtime
  - Sign with: `codesign --sign -` (no --options runtime)
- `ElectronApp.app/` — app bundle with `Frameworks/Electron Framework.framework/` directory
- `UnsignedApp.app/` — app bundle with no code signature at all
- `WithEntitlements.app/` — app with specific entitlements via entitlements plist
- Shell script `tests/fixtures/apps/create_fixtures.sh` that builds all fixture apps
  (NOTE: this script must run on macOS with Xcode tools)

### Step 3: Collector Unit Tests
Create/expand `collector/Tests/`:
- `TCCTests/TCCDataSourceTests.swift`:
  - Parse basic.db → verify 10 grants with correct fields
  - Parse empty.db → verify empty array, no errors
  - Parse malformed.db → verify graceful error, no crash
  - Parse nonexistent path → verify error in result, no crash
  - Verify service display name mapping for all known services

- `EntitlementTests/EntitlementDataSourceTests.swift`:
  - Discover apps in fixtures/apps/ → correct count
  - Extract entitlements from WithEntitlements.app → correct entitlement names
  - Classify entitlements → correct categories and is_private flags
  - Detect ElectronApp.app as Electron → is_electron: true
  - Handle UnsignedApp.app → signed: false, no crash

- `CodeSigningTests/CodeSigningAnalyzerTests.swift`:
  - HardenedApp.app → hardened_runtime: true, library_validation: true
  - UnhardenedApp.app → hardened_runtime: false
  - Injection assessment for unhardened app → dyld_insert in injection_methods
  - Injection assessment for electron app → electron_env_var in injection_methods

- `ExportTests/JSONExportTests.swift`:
  - ScanResult with sample data → valid JSON output
  - Re-parse exported JSON → matches original data
  - Verify snake_case keys in output

### Step 4: Graph Pipeline Tests
Create `graph/tests/`:
- `test_import.py`:
  - Import minimal fixture JSON (3 apps, 5 grants) → verify node counts in Neo4j
  - Re-import same fixture → no duplicate nodes
  - Import with missing fields → graceful handling

- `test_infer.py`:
  - Seed graph with known apps (injectable + FDA) → verify CAN_INJECT_INTO edge created
  - Seed graph with Electron app + TCC → verify CHILD_INHERITS_TCC edge
  - Run inference twice → same edge count (idempotent)

- `test_queries.py`:
  - For each Killer Query: seed a minimal graph that should produce results → verify non-empty
  - For each query: verify it parses without syntax error

- Test fixture JSON: `tests/fixtures/graph/minimal-scan.json`
  - 5 applications (2 injectable, 1 Electron, 2 hardened)
  - 8 TCC grants (FDA, Camera, Mic, Automation, etc.)
  - 15 entitlements (mix of categories)

### Step 5: Integration Test
Create `tests/integration/test_full_pipeline.sh`:
- End-to-end: run collector on fixture data → import JSON → run inference → run queries
- Verify: queries return expected results for known fixture data
- This is a smoke test, not exhaustive — confirm the pipeline works end-to-end

### Step 6: CI Configuration
Create `.github/workflows/test.yml`:
- **Swift tests:** runs on macOS runner, `swift test` in collector/
- **Python tests:** runs on ubuntu (or macOS), pytest in graph/tests/
- **Integration test:** runs on macOS, full pipeline
- **Lint:** swift-format check, ruff check for Python
- Trigger: on push and PR to main

## Acceptance Criteria

- [ ] TCC fixture databases exist (basic, empty, system-scope, malformed)
- [ ] Fixture app bundles exist with creation script
- [ ] Collector has unit tests for all 3 data source modules (TCC, Entitlements, CodeSigning)
- [ ] JSON export has serialization/deserialization round-trip test
- [ ] Graph pipeline has tests for import, inference, and query syntax
- [ ] Minimal fixture JSON exists for graph testing
- [ ] Integration test script runs the full pipeline end-to-end
- [ ] GitHub Actions workflow exists for CI
- [ ] `swift test` passes in collector/
- [ ] `pytest` passes in graph/tests/
- [ ] No test depends on real system state (all use fixtures)

## If Stuck

After 15 iterations:
- If building signed fixture apps is impossible without a developer cert: create unsigned
  fixtures only and mock the code signing analysis in tests
- If Neo4j is unavailable in CI: skip graph tests in CI, run them locally
- If swift test infrastructure is complex: use XCTest directly, skip any test framework
- Priority: collector unit tests > graph tests > integration test > CI

When ALL acceptance criteria are met, output:
<promise>PHASE_5_1_COMPLETE</promise>
