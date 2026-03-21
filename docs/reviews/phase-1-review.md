# Phase 1 Review — Collector MVP

**Reviewer:** Claude Opus 4.6 (automated review)
**Date:** 2026-03-18
**Overall Status:** ⚠️ PASS WITH ISSUES

## Summary

Phase 1 delivers a functional, well-structured collector that scans 184 apps in under 1 second, extracts entitlements and code signing metadata, and produces valid JSON. The architecture is clean with proper graceful degradation, zero force-unwraps, and no security violations. Two issues warrant attention before Phase 2: the `is_system` flag does not cover `/usr/` (as specified in the roadmap), and model structs lack doc comments (counter to QUALITY.md standards). TCC collection is blocked by macOS 15+ kernel restrictions (documented as TD-004) but the collector handles this gracefully.

## Results by Sub-Phase

### 1.1 Scaffolding: ✅

- ✅ `swift build` and `swift build -c release` succeed with zero warnings
- ✅ Binary responds to `--help`, `--version`, `--output`, `--verbose`, `--modules`
- ✅ `DataSource` protocol exists with `name: String`, `requiresElevation: Bool`, `collect() async -> DataSourceResult`
- ✅ All model structs are `Codable`: `Application`, `TCCGrant`, `EntitlementInfo`, `ScanResult`
- ✅ JSON output uses snake_case keys (via explicit `CodingKeys` enums)
- ✅ Only external dependency is `swift-argument-parser` — verified in Package.swift
- ✅ Package.swift has separate library targets: Models, TCC, Entitlements, CodeSigning, Export (plus RootstockCLI executable)

### 1.2 TCC Parser: ✅

- ✅ `TCCDataSource` conforms to `DataSource` with `name = "TCC Database"`, `requiresElevation = false`
- ✅ SQLite wrapper uses system `SQLite3` C API (no external dependency), `SQLITE_OPEN_READONLY`
- ✅ User TCC.db path is correct: `~/Library/Application Support/com.apple.TCC/TCC.db`
- ✅ System TCC.db failure caught gracefully — returns `CollectionError` with `recoverable: true`
- ✅ `auth_value` mapping documented in `docs/research/tcc-internals.md`: 0=denied, 2=allowed, 3=limited; query filters `auth_value != 1` (skips unknown)
- ✅ `auth_reason` mapping exists in `docs/research/tcc-internals.md`
- ✅ `TCCServiceRegistry` has 23 TCC services (exceeds ≥15 requirement)
- ✅ Unknown services fall back to raw identifier via `names[service] ?? service`
- ✅ 8 unit tests: fixture DB parsing (6 grants from 7 rows), missing DB path, column types, system DB error handling, display names, unknown service fallback

### 1.3 Entitlement Scanner: ✅

- ✅ `EntitlementDataSource` conforms to `DataSource`
- ✅ App discovery scans `/Applications/`, `~/Applications/`, `/System/Applications/`, `/System/Applications/Utilities/`
- ✅ Entitlements extracted via `SecStaticCodeCreateWithPath` / `SecCodeCopySigningInformation` (primary) with `codesign -d --entitlements :-` CLI fallback
- ✅ Classification categories: tcc, injection, privilege, sandbox, keychain, network, other (all 7 present)
- ✅ `is_private` identifies `com.apple.private.*` via `.contains("com.apple.private.")`
- ✅ `isSecurityCritical` flags tcc, injection, privilege categories
- ✅ Electron detection checks for `Electron Framework.framework` and `Squirrel.framework`
- ✅ Per-app failures handled: `makeDiscoveredApp` returns nil for bad bundles; `extract()` returns `[:]` on failure; no crash
- ⚠️ **Warning:** `EntitlementDataSource.collect()` declares `let errors: [CollectionError] = []` — never mutated, so per-app entitlement extraction failures are silently swallowed rather than recorded

### 1.4 Code Signing: ⚠️

- ✅ Every Application has `team_id`, `hardened_runtime`, `library_validation`, `signed` fields (with proper snake_case CodingKeys)
- ✅ `injection_methods: [InjectionMethod]` array populated per app (89/184 apps have entries on test machine)
- ✅ Injection logic correct:
  - No hardened runtime → `.dyldInsert` ✅
  - Hardened runtime + `allow-dyld-environment-variables` → `.dyldInsertViaEntitlement` ✅
  - No effective library validation → `.missingLibraryValidation` ✅
  - Electron → `.electronEnvVar` ✅
- ⚠️ **Issue:** `is_system` only checks `url.path.hasPrefix("/System/")` — does NOT cover `/usr/` as specified in the Phase 1.4 prompt and ARCHITECTURE.md. Apps or binaries under `/usr/` would not be flagged as system.
- ✅ Code signing failures set `signed: false` with `CollectionError(recoverable: true)` — no crash. `CodeSigningAnalyzer.analyze()` returns `analysisError: true` on any Security.framework failure.

### 1.5 JSON Export & CLI: ✅

- ✅ `rootstock-collector --output /tmp/test.json` produces valid JSON (confirmed via `python3 -m json.tool`)
- ✅ JSON has all 9 top-level fields: `scan_id`, `timestamp`, `hostname`, `macos_version`, `collector_version`, `elevation`, `applications`, `tcc_grants`, `errors`
- ✅ `scan_id` is UUID (e.g., `5B60FF68-4162-4EF5-A82C-E2B7A02CE991`)
- ✅ `timestamp` is ISO 8601 (e.g., `2026-03-18T07:19:16Z`)
- ✅ `elevation.is_root` and `elevation.has_fda` populated correctly
- ✅ `--modules tcc` limits collection to TCC only (0 apps, 0 entitlements)
- ✅ `--verbose` produces per-module counts on stderr
- ✅ Progress appears on stderr via `FileHandle.standardError.write()`; summary on stdout via `print()`
- ✅ JSONExporter uses `.prettyPrinted` and `.sortedKeys`; includes sanity re-parse check
- ✅ Errors array collects per-module failures (e.g., 2 TCC database access errors)

### 1.6 Validation: ✅

- ✅ JSON Schema exists at `collector/schema/scan-result.schema.json` — draft 2020-12, uses `$defs`, `additionalProperties: false`, UUID pattern, ISO 8601 pattern, enum constraints for categories/injection methods/scope
- ✅ `scripts/validate-scan.py` validates against schema AND performs semantic checks: UUID format, ISO 8601 parsing, duplicate `bundle_id` detection, empty string checks, unknown category detection
- ✅ Real scan output validated successfully: `✓ Valid: scan.json (184 apps, 0 TCC grants, 2 collection errors)`
- ✅ Performance documented in README.md: ~0.7s total, 184 apps, 3841 entitlements
- ✅ No secrets in output — all "password"/"token"/"key"/"secret" matches are entitlement key names (metadata)

### Cross-Cutting Concerns: ⚠️

- ✅ **Security:** Collector never extracts passwords, keys, or tokens — grep confirms zero hits in code logic
- ✅ **Security:** Collector makes zero network connections — no URLSession, URLRequest, socket, or connect calls found
- ✅ **No force-unwraps** in production Swift code (0 instances found across all 20 files in `Sources/`)
- ✅ **Error handling:** Every module degrades gracefully — TCC returns CollectionErrors, Entitlements returns empty dicts, CodeSigning returns `analysisError: true` defaults
- ⚠️ **Documentation:** 5 of 14 public types lack `///` doc comments (Application, TCCGrant, ScanResult, ElevationInfo, CollectionError). QUALITY.md requires "All public APIs have doc comments."
- ⚠️ **Conventions:** Only 1 commit in history (`Initial commit`) — does not follow `[component] description` format
- ✅ **Tech debt:** `docs/exec-plans/tech-debt-tracker.md` exists with 7 items (TD-001 through TD-007)

## Critical Issues (must fix before Phase 2)

None. All sub-phases pass functionally. The issues below are recommended but not blocking.

## Warnings (should fix, not blocking)

1. **`is_system` does not check `/usr/` path prefix** (`AppDiscovery.swift:121`). The 1.4 prompt specifies `is_system` for apps "under /System/ or /usr/" but only `/System/` is checked. In practice this is low-impact — no `.app` bundles live under `/usr/` — but the flag description in the schema and docs should be updated to match the implementation, or the check should be expanded.

2. **Model structs lack doc comments** (`Application.swift`, `TCCGrant.swift`, `ScanResult.swift`, `ElevationInfo.swift`, `DataSource.swift:CollectionError`). QUALITY.md states "All public APIs have doc comments." These are self-documenting Codable structs, but for an academic project, complete documentation is expected.

3. **`EntitlementDataSource.collect()` line 23** — `let errors: [CollectionError] = []` is never mutated. Entitlement extraction failures produce empty arrays silently rather than being recorded. Should be `var` with error recording when an app is signed but yields no entitlements.

4. **`EntitlementDataSource.collect()` line 39** — `signed: !entitlementDict.isEmpty` is a weak proxy for signing status. A signed app with zero entitlements is incorrectly marked unsigned. This is later corrected by `CodeSigningDataSource.enrich()`, but the two-phase coupling is implicit and fragile.

5. **TD-001 appears in both Active and Resolved tables** in `tech-debt-tracker.md`. The active entry is stale.

6. **`is_private` detection uses `.contains()` not `.hasPrefix()`** (`EntitlementClassifier.swift`). Works correctly in practice but is semantically imprecise.

## Recommendations

1. Add `///` doc comments to the 5 model structs before Phase 2, per QUALITY.md standards.
2. Change `EntitlementDataSource.collect()` to use `var errors` and record per-app extraction failures.
3. Clean up the tech-debt-tracker by removing the stale TD-001 from the Active table.
4. Consider making `ScanOrchestrator` enforce that `CodeSigningDataSource.enrich()` always runs after `EntitlementDataSource.collect()` — the current architecture has an implicit ordering dependency that could produce incorrect output if modules are run individually.

## Meilenstein M1 Status

**"Wir haben Daten":** MET ✅

- Collector produces valid JSON: **yes** — validated by JSON Schema and semantic checks
- JSON contains TCC grants: **partially** — 0 grants due to macOS 15+ kernel restrictions (TD-004); module correctly reports authorization errors and would populate grants if run with FDA
- JSON contains entitlements: **yes** — 3,841 entitlements across 184 apps, categorized into 7 categories
- JSON contains code signing metadata: **yes** — hardened_runtime, library_validation, team_id, signed, injection_methods all populated; 123 apps with hardened runtime, 89 apps with injection methods, 10 Electron apps detected

The collector is a functional, well-engineered MVP. It runs in under 1 second, handles all failure modes gracefully, makes zero network calls, and extracts only metadata. The architecture cleanly separates concerns through the `DataSource` protocol, and the codebase has zero force-unwraps and zero build warnings. The primary limitation is TCC data collection on modern macOS, which is a platform restriction rather than a collector defect.
