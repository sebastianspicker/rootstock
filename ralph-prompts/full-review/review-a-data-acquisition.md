You are a senior macOS security engineer performing a systematic review of the Rootstock data acquisition layer — the Swift collector that extracts TCC grants, entitlements, code signing metadata, XPC services, persistence mechanisms, and 15+ additional security data sources from macOS endpoints.

## Context

Read: CLAUDE.md, ARCHITECTURE.md, docs/QUALITY.md,
collector/Package.swift, collector/Sources/** (all modules), collector/Tests/** (all tests)

## Priority Definitions

- **P0 — Critical:** Crashes, data loss, security vulnerabilities (secret leakage, injection), broken core functionality that produces wrong scan data
- **P1 — High:** Incorrect results, missing critical edge cases, protocol contract violations, silent data corruption
- **P2 — Medium:** Performance issues, poor error messages, missing input validation at system boundaries, unhelpful failure modes
- **P3 — Low:** Style inconsistencies, naming convention violations, documentation gaps, minor code quality issues

## Task: Review Phase A — Data Acquisition

Perform an iterative, priority-ordered review of the entire Swift collector. Fix P0 issues immediately. Fix P1 issues in the same iteration you find them. Collect P2/P3 issues and fix them in a dedicated pass after all P0/P1 issues are resolved.

### A.1 DataSource Protocol Conformance

For every `*DataSource.swift` file in `collector/Sources/`:
- [ ] Does each data source conform to its protocol correctly?
- [ ] Does it handle errors gracefully (no force-unwraps on external data, no unhandled throws)?
- [ ] Does it degrade when SIP blocks access (e.g., system TCC.db, protected directories)?
- [ ] Does it return meaningful error information when a data source is unavailable?
- [ ] Does it avoid shelling out to external commands where a framework API exists?
- [ ] Are there any data sources that silently return empty data when they should report an error?

### A.2 Model Correctness

For every model in `collector/Sources/Models/`:
- [ ] Are all fields properly typed (no `String` for things that should be enums or booleans)?
- [ ] Do defaults make sense (not hiding missing data behind false positives)?
- [ ] Are optional vs required fields correct (can any non-optional field actually be nil in practice)?
- [ ] Does `Codable` conformance produce correct JSON with snake_case keys?
- [ ] Are there any models that are defined but never populated by any data source?
- [ ] Do model relationships match the graph schema in `graph/models.py`?

### A.3 ScanOrchestrator

Review `collector/Sources/RootstockCLI/ScanOrchestrator.swift`:
- [ ] Does it call ALL data sources? Cross-reference with the list of `*DataSource.swift` files
- [ ] Is the aggregation into `ScanResult` correct — no fields left nil that should be populated?
- [ ] Does it handle individual data source failures without aborting the entire scan?
- [ ] Is the module execution order correct (any dependencies between data sources)?
- [ ] Does the final JSON output contain all collected data?

### A.4 Security Principle Compliance

Across the entire collector:
- [ ] **No secret extraction:** Verify no module reads passwords, keys, token values, or credential data
- [ ] **No network calls:** Verify no module makes HTTP requests, DNS lookups, or any network I/O
- [ ] **Minimal privilege:** Document which modules require elevation and verify it's justified
- [ ] **No command injection:** Verify any Process() calls properly escape arguments
- [ ] **No temp file leakage:** Verify any temporary files are cleaned up

### A.5 Test Coverage

For all tests in `collector/Tests/`:
- [ ] Do tests cover the happy path for each data source?
- [ ] Do tests cover error paths (missing files, permission denied, malformed input)?
- [ ] Are there missing test cases for edge conditions (empty databases, huge inputs, corrupt data)?
- [ ] Do tests use fixtures/mocks rather than real system state?
- [ ] Run `swift test` — do all tests pass?

### A.6 Package.swift Hygiene

- [ ] Do all target declarations match actual source directories?
- [ ] Are there any declared dependencies that are unused?
- [ ] Are there any source files not included in any target?
- [ ] Is the minimum Swift version specified?

## Output

For each iteration, state:
1. What you reviewed
2. Issues found (with priority)
3. Fixes applied
4. What remains

After all issues are resolved, produce a summary in this format:

```
## Review A Summary — Data Acquisition
- Files reviewed: [count]
- P0 issues found/fixed: [N]
- P1 issues found/fixed: [N]
- P2 issues found/fixed: [N]
- P3 issues deferred: [N] (tracked in tech-debt-tracker.md)
- Tests: [pass count] / [total count]
- Build: [clean/warnings]
```

## Acceptance Criteria

- [ ] `cd collector && swift build` completes without errors
- [ ] `cd collector && swift test` — all tests pass
- [ ] No P0 or P1 issues remain open
- [ ] P2/P3 issues are either fixed or documented in `docs/exec-plans/tech-debt-tracker.md`
- [ ] Every data source handles its error paths gracefully
- [ ] No security principle violations

## If Stuck

After 20 iterations:
- If a P1 issue requires architectural changes: document it in tech-debt-tracker.md with a concrete fix plan, mark as deferred, and move on
- If `swift test` has flaky tests: isolate the flaky test, document the cause, and `XCTSkip` it with a TODO
- If a data source module has deep issues: fix what you can, document the rest, prioritize the modules that feed the most graph data

When ALL acceptance criteria are met, output:
<promise>REVIEW_A_COMPLETE</promise>
