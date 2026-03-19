# Phase 5 Review — Hardening & Quality

**Reviewer:** Claude Opus (automated review)
**Date:** 2026-03-19
**Overall Status:** ⚠️ PASS WITH ISSUES

## Summary

Phases 5.1–5.3 (test coverage, macOS compatibility, performance) are **excellent** — engineering quality is high, edge cases are thoroughly handled, and the codebase is well-tested. Phase 5.4 (documentation & academic preparation) was **not executed** — THREAT_MODEL.md, paper skeleton, and references.bib do not exist. The project is engineering-complete but not yet publication-ready.

## Test Coverage Assessment

- Collector modules with unit tests: **8/8** (TCC, Entitlements, CodeSigning, Export, Keychain, Persistence, XPC, MDM)
- Graph pipeline with tests: **5/5** (import, infer, queries, report, report_diagrams)
- Integration test: **exists** (`tests/integration/test_full_pipeline.sh`)
- CI: **configured** (`.github/workflows/test.yml` — Swift on macOS-14, pytest on Ubuntu, ruff lint)
- Total tests: **100 Swift + 87 Python = 187 tests**
- Estimated line coverage: ~70–80% (strong model/parser coverage; real-system tests optional via graceful degradation)

## Results by Sub-Phase

### 5.1 Test Coverage: ✅ PASS

| Criterion | Status | Evidence |
|---|---|---|
| TCC fixtures (basic, empty, system-scope, malformed) | ✅ | 5 SQLite databases in `tests/fixtures/tcc/` |
| App fixtures (≥3 signing states) | ✅ | 5 bundles: Hardened, Unhardened, Electron, Unsigned, WithEntitlements |
| Fixture creation scripts documented | ✅ | `create_fixtures.py` (TCC), `create_fixtures.sh` (apps) |
| Collector unit tests for core modules | ✅ | 8 modules tested: TCC(24), Entitlements(13), CodeSigning(13), Export(8), Keychain(9), Persistence(10), XPC(12), MDM(11) |
| JSON round-trip test | ✅ | `testRoundTripPreservesApplicationData`, `testRoundTripPreservesTCCGrant`, `testRoundTripPreservesElevationInfo`, `testRoundTripEmptyScanResult` |
| Graph import tests + idempotency | ✅ | 39 import tests including `test_idempotency` for all node types |
| Inference tests | ✅ | 11 tests: `test_can_inject_into_*`, `test_child_inherits_tcc_*`, `test_can_send_apple_event` |
| Query syntax tests | ✅ | `test_all_queries_parse` validates all 23 .cypher files via EXPLAIN |
| Integration test (pipeline) | ✅ | `test_full_pipeline.sh`: import → infer → query, with cleanup |
| No test uses real TCC.db | ✅ | All TCC tests use synthetic fixture databases in `/tmp/` |
| CI configuration | ✅ | `.github/workflows/test.yml` with 3 jobs: swift-tests, python-tests, python-lint |
| Test pass rate 100% | ✅ | 100/100 Swift, Python tests pass (Neo4j-dependent tests auto-skip in CI) |

**Note:** Some tests (CodeSigning, Keychain, Persistence) _do_ touch real system state (Safari.app, Terminal.app, real keychain) but degrade gracefully when those targets are missing. This is a pragmatic choice — the core assertion logic uses fixtures, while the real-system tests act as integration-level smoke tests.

### 5.2 macOS Compat: ✅ PASS

| Criterion | Status | Evidence |
|---|---|---|
| Version detection identifies macOS version | ✅ | `MacOSVersion.detect()` → `.tahoe` on macOS 26.3; `testMacOSVersionDetectReturnsValidValue` |
| Schema adapter pattern (not hardcoded) | ✅ | `TCCSchemaAdapter` protocol with `SonomaTCCSchemaAdapter`, `SequoiaTCCSchemaAdapter`, `TahoeTCCSchemaAdapter` |
| PRAGMA table_info for dynamic detection | ✅ | `SQLiteDatabase.columnNames(table:)` → `PRAGMA table_info(access)` |
| `tcc-version-diffs.md` documents differences | ✅ | Comprehensive: schema DDL, access restrictions, new services, testing notes |
| macOS 15+ services in registry | ✅ | `kTCCServiceGameCenterFriends`, `kTCCServiceWebBrowserPublicKeyCredential` with `minimumMajorVersion` annotations |
| Compatibility matrix in README | ✅ | Table covers macOS 14/15/26/<14 with notes |
| Tested on ≥2 versions (or documented) | ⚠️ | Tested on macOS 26.3 only; macOS 14/15 testing is via fixture databases replicating Sonoma schema. Single-version testing is clearly documented in tcc-version-diffs.md |
| Unknown schema columns don't crash | ✅ | PRAGMA-based detection ignores extra columns; `testSchemaAdapterFactoryReturnsNilForMalformedDB` |

### 5.3 Performance: ✅ PASS

| Criterion | Status | Evidence |
|---|---|---|
| Benchmark script exists | ✅ | `scripts/benchmark.sh` — 3 runs + memory + per-module timing |
| Benchmark results documented | ✅ | `docs/benchmarks/baseline.md` — comprehensive with bottleneck analysis |
| Collector < 60s (target < 30s) | ✅ | **5.64s average** on 184 apps (11× under target) |
| Per-module timing via `--verbose` | ✅ | `[TCC] 0.00s [Entitlements] 0.15s [CodeSigning] 0.21s [XPC] 4.83s ... Total: 5.28s` |
| Edge cases — App without Info.plist | ✅ | `fileManager.fileExists(atPath: plistURL.path)` guard → skip |
| Edge cases — Missing CFBundleIdentifier | ✅ | Fallback to `path.<AppName>` pseudo-ID |
| Edge cases — Corrupted code signature | ✅ | `analysisError: true`, `signed: false`, recoverable error |
| Edge cases — Symlinked apps | ✅ | `url.resolvingSymlinksInPath()` before file I/O; original path retained for reporting |
| Edge cases — Locked TCC.db | ✅ | 1× retry after 500ms for `SQLITE_BUSY` / `SQLITE_LOCKED` |
| Edge cases — Empty Keychain | ✅ | `errSecItemNotFound` → `([], [])` with no error |
| Neo4j import handles 200+ apps | ✅ | `UNWIND` batching throughout `import_nodes.py` — no per-row round-trips |
| No memory leaks | ✅ | ~45 MB peak memory measured; no leaks reported by `time -l` |

**Performance highlight:** `EntitlementDataSource` was parallelized with `TaskGroup` (max 8 concurrent), reducing entitlement scanning from ~1.2s to 0.15s for 184 apps — an 8× speedup for that module.

### 5.4 Documentation: ❌ FAIL — NOT EXECUTED

| Criterion | Status | Evidence |
|---|---|---|
| README has Quick Start, example output, compat matrix | ✅ | All present and tested |
| README is testable end-to-end | ✅ | `swift build`, run, `validate-scan.py` commands all work |
| ARCHITECTURE.md includes real-world example with stats | ⚠️ | Has architecture diagram and component descriptions but no actual scan statistics |
| THREAT_MODEL.md exists | ❌ | **File does not exist** |
| Paper skeleton in `docs/paper/` | ❌ | **Directory does not exist** |
| references.bib with ≥15 references | ❌ | **File does not exist** |
| Target venues documented | ❌ | **Not documented** |
| BibTeX entry in README | ❌ | **Not present** |

## Academic Readiness

- Paper skeleton quality: **missing** — `docs/paper/` directory does not exist
- Reproducibility: **partially reproducible** — the software pipeline is fully reproducible from the repository (collector → graph → queries), but there is no paper or methodology description formalizing this
- Ethical framework: **missing** — no THREAT_MODEL.md, no responsible disclosure guidance, no authorized-use-only statement beyond CLAUDE.md's security principles

## Critical Issues

1. **THREAT_MODEL.md does not exist.** This is essential for a security research tool. It must document: what Rootstock can and cannot discover, what an attacker with Rootstock output could do, assumptions about the threat model, and limitations (e.g., SIP-protected apps, cross-platform blindness, temporal scope).

2. **Paper skeleton does not exist.** The Meilenstein M5 criterion "Publikationsreif" requires a paper skeleton with abstract, 7 sections, and structured outline. `docs/paper/` is empty.

3. **references.bib does not exist.** No bibliography of related work (BloodHound, Bifrost, Chainbreaker, macOS security research).

## Warnings

1. **Some tests touch real system state** (Safari.app, Terminal.app, system keychain). While they degrade gracefully, this creates CI environment sensitivity. Consider adding explicit fixture-only test targets for CI and marking real-system tests as integration tests.

2. **ARCHITECTURE.md lacks scan statistics.** Adding a "Real-World Example" section with actual scan output (e.g., "On a developer Mac with 184 apps: 3841 entitlements extracted, 440 XPC services enumerated, 234 keychain items read, 5.3s total") would strengthen the document.

3. **Single macOS version tested.** All live testing was on macOS 26.3 Tahoe. macOS 14 Sonoma and 15 Sequoia compatibility is validated only via fixture databases. This is documented and acceptable for a research project, but a CI matrix with multiple macOS versions would increase confidence.

4. **Tech debt TD-006** (SIP-protected apps reporting false injection positives for Terminal.app/Safari.app) is still open. This could affect academic claims about injection surface area.

## Recommendations

1. **Execute Phase 5.4** — create THREAT_MODEL.md, paper skeleton, references.bib, and update ARCHITECTURE.md with real-world statistics. This is the only remaining gap to M5.

2. **Add `is_sip_protected` to injection assessment** (TD-006) before publication — false positives in the injection analysis undermine credibility.

3. **Consider a CI macOS matrix** (macOS-14 + macOS-15 runners) for cross-version regression testing. GitHub Actions supports `macos-14` and `macos-15` runners.

## Meilenstein M5 Status

**"Publikationsreif":** **NOT MET**

| Criterion | Status |
|---|---|
| Tests pass | ✅ yes — 100/100 Swift, 87 Python |
| Multi-version tested | ⚠️ yes (Tahoe live, Sonoma/Sequoia via fixtures) |
| Performance documented | ✅ yes — 5.64s average, 45 MB peak, benchmarks documented |
| Academic paper skeleton exists | ❌ no — `docs/paper/` does not exist |
| Threat model exists | ❌ no — `docs/THREAT_MODEL.md` does not exist |
| README enables first-time use | ✅ yes — Quick Start is complete and tested |

**Blocking items for M5:** Phase 5.4 (documentation & academic preparation) must be completed. Engineering quality (5.1–5.3) is excellent.
