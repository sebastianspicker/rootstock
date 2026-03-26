You are a senior security engineer and Swift developer performing a thorough review of Phase 1 of the Rootstock project.

## Context

Read these files first to understand the project goals and standards:
- CLAUDE.md (project overview, conventions, security principles)
- ARCHITECTURE.md (component design, DataSource protocol, output schema, graph model)
- ROADMAP.md §Phase 1 (all 6 sub-phases and their acceptance criteria)
- docs/QUALITY.md (quality standards)
- docs/design-docs/core-beliefs.md (design principles)

## Your Task

Perform a comprehensive review of Phase 1 — Collector MVP. Check every acceptance criterion from every sub-phase (1.1 through 1.6). Report findings honestly — do not skip checks, do not assume things work without verifying.

## Review Checklist

### 1.1 Scaffolding
- [ ] `cd collector && swift build` succeeds with zero warnings
- [ ] `swift build -c release` succeeds
- [ ] Binary responds to `--help`, `--version`, `--output`, `--verbose`, `--modules`
- [ ] `DataSource` protocol exists with `name`, `requiresElevation`, `collect()` 
- [ ] All model structs are Codable: `Application`, `TCCGrant`, `EntitlementInfo`, `ScanResult`
- [ ] JSON output uses snake_case keys
- [ ] No external dependencies except swift-argument-parser
- [ ] Package.swift has separate library targets for TCC, Entitlements, CodeSigning, Models, Export

### 1.2 TCC Parser
- [ ] `TCCDataSource` conforms to `DataSource`
- [ ] SQLite wrapper uses system SQLite3 (no external dependency), read-only mode
- [ ] User TCC.db path is correct: `~/Library/Application Support/com.apple.TCC/TCC.db`
- [ ] System TCC.db failure is caught gracefully — verify by checking error handling code
- [ ] `auth_value` mapping is correct: 0=denied, 2=allowed, 3=limited
- [ ] `auth_reason` mapping exists: 1=user_prompt, 2=user_settings, 3=entitlement, 4=mdm, 5=system
- [ ] Service display name registry has ≥15 TCC services
- [ ] Unknown services get a fallback display name
- [ ] Unit tests exist for fixture DB parsing and missing DB path

### 1.3 Entitlement Scanner
- [ ] `EntitlementDataSource` conforms to `DataSource`
- [ ] App discovery scans at least `/Applications/` and `/System/Applications/`
- [ ] Entitlements extracted via Security.framework or codesign CLI fallback
- [ ] Entitlement classification exists with categories: tcc, injection, privilege, sandbox, keychain, network, other
- [ ] `is_private` correctly identifies `com.apple.private.*` entitlements
- [ ] `isSecurityCritical` flags tcc, injection, and privilege categories
- [ ] Electron detection checks for `Electron Framework.framework`
- [ ] Per-app failures are caught — verify error handling, no crash on bad bundles

### 1.4 Code Signing
- [ ] Every Application in output has: team_id, hardened_runtime, library_validation, signed
- [ ] `injection_methods` array is populated per app
- [ ] Injection logic is correct:
  - No hardened runtime → `dyld_insert`
  - Hardened runtime + allow-dyld-environment-variables → `dyld_insert_via_entitlement`
  - No library validation → `missing_library_validation`
  - Electron → `electron_env_var`
- [ ] `is_system` correctly identifies apps under /System/ or /usr/
- [ ] Code signing failures set `signed: false` with error, no crash

### 1.5 JSON Export & CLI
- [ ] `rootstock-collector --output /tmp/test.json` produces valid JSON
- [ ] JSON has all top-level fields: scan_id, timestamp, hostname, macos_version, collector_version, elevation, applications, tcc_grants, errors
- [ ] `scan_id` is a UUID
- [ ] `timestamp` is ISO 8601
- [ ] `elevation.is_root` and `elevation.has_fda` are populated
- [ ] `--modules tcc` limits collection to TCC only
- [ ] `--verbose` produces additional stderr output
- [ ] Progress/summary output appears on stderr
- [ ] Errors array collects per-module failures

### 1.6 Validation
- [ ] JSON Schema exists at `collector/schema/scan-result.schema.json`
- [ ] Validation script exists at `scripts/validate-scan.py`
- [ ] At least one real scan output has been validated
- [ ] Performance documented (scan time)
- [ ] No secrets or sensitive data in any output or fixture

### Cross-Cutting Concerns
- [ ] **Security:** Collector never extracts passwords, keys, or tokens
- [ ] **Security:** Collector makes zero network connections
- [ ] **No force-unwraps** in production Swift code (only in tests)
- [ ] **Error handling:** Every module degrades gracefully
- [ ] **Documentation:** Code has doc comments on public APIs
- [ ] **Conventions:** Commit messages follow `[component] description` format
- [ ] **Tech debt:** Known issues documented in `docs/exec-plans/tech-debt-tracker.md`

## Execution

For each checklist item:
1. **Verify by reading the actual source code** — don't just check if a file exists
2. **Run builds and tests** where possible: `swift build`, `swift test`
3. **Try running the collector** if on macOS: `swift run rootstock-collector --output /tmp/review.json`
4. **Validate the output** if a scan JSON exists

## Output Format

Produce a review report in `docs/reviews/phase-1-review.md`:

```markdown
# Phase 1 Review — Collector MVP

**Reviewer:** Claude Opus (automated review)
**Date:** [today]
**Overall Status:** ✅ PASS | ⚠️ PASS WITH ISSUES | ❌ FAIL

## Summary
[2-3 sentences: overall assessment]

## Results by Sub-Phase

### 1.1 Scaffolding: [✅|⚠️|❌]
- [findings per criterion]

### 1.2 TCC Parser: [✅|⚠️|❌]
- [findings per criterion]

[... etc for all sub-phases]

## Critical Issues (must fix before Phase 2)
1. [issue description + file + suggested fix]

## Warnings (should fix, not blocking)
1. [issue description]

## Recommendations
1. [improvement suggestion]

## Meilenstein M1 Status
**"Wir haben Daten":** [MET | NOT MET]
- Collector produces valid JSON: [yes/no]
- JSON contains TCC grants: [yes/no, count]
- JSON contains entitlements: [yes/no, count]
- JSON contains code signing metadata: [yes/no]
```

After writing the review, output your assessment of whether Milestone M1 is met.
