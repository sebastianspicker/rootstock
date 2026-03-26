You are a senior security engineer and academic reviewer performing a thorough review of Phase 5 of the Rootstock project.

## Context

Read: CLAUDE.md, ROADMAP.md §Phase 5, docs/QUALITY.md, tests/ (all test code and fixtures),
docs/THREAT_MODEL.md, docs/paper/, docs/benchmarks/, README.md, ARCHITECTURE.md

## Your Task

Review Phase 5 — Hardening & Quality. Verify test coverage, cross-version compatibility, performance, and documentation quality. This phase determines whether the project is publication-ready.

## Review Checklist

### 5.1 Test Coverage & Fixtures
- [ ] **TCC fixtures:** basic.db, empty.db, system-scope.db, malformed.db exist and are valid SQLite
- [ ] **App fixtures:** at least 3 fixture app bundles with different signing states
- [ ] **Fixture creation scripts** exist and are documented
- [ ] **Collector unit tests** exist for all 3 core modules (TCC, Entitlements, CodeSigning)
- [ ] **JSON round-trip test:** serialize ScanResult → deserialize → matches original
- [ ] **Graph tests:** import fixture → verify node counts, re-import → no duplicates
- [ ] **Inference tests:** seed known graph → verify expected edges
- [ ] **Query syntax tests:** all .cypher files parse without error
- [ ] **Integration test:** full pipeline (collect → import → infer → query) in one script
- [ ] **No test uses real system state** — all use fixtures
- [ ] **CI configuration** (.github/workflows/) exists with macOS and Python jobs
- [ ] **Test pass rate:** `swift test` and `pytest` both pass 100%

### 5.2 macOS Version Compatibility
- [ ] Version detection code correctly identifies macOS version
- [ ] TCC schema adapter pattern exists (not hardcoded column assumptions)
- [ ] `PRAGMA table_info(access)` or equivalent is used for dynamic schema detection
- [ ] `docs/research/tcc-version-diffs.md` documents known differences across versions
- [ ] New TCC services from macOS 15+ are in the registry
- [ ] Compatibility matrix in README covers macOS 14 and 15
- [ ] Collector tested on at least 2 macOS versions (or documents single-version testing)
- [ ] Unknown schema columns don't cause crashes (forward-compatible)

### 5.3 Performance & Edge Cases
- [ ] Benchmark script exists at `scripts/benchmark.sh`
- [ ] Benchmark results documented in `docs/benchmarks/`
- [ ] Collector completes in <60 seconds on typical Mac (target: <30s)
- [ ] Per-module timing available via `--verbose`
- [ ] **Edge cases handled** (verify by reading code):
  - App without Info.plist → skip
  - App without CFBundleIdentifier → fallback ID
  - Corrupted code signature → signed=false, continue
  - Symlinked apps → resolved
  - Locked TCC.db → retry or skip with error
  - Empty Keychain → empty array
- [ ] Neo4j import handles 200+ app scans without timeout
- [ ] No memory leaks documented (or noted as untested)

### 5.4 Documentation & Academic Preparation
- [ ] **README** has: working Quick Start, example output, compatibility matrix, installation
- [ ] **README** is testable: a new user on a clean Mac can follow it end-to-end
- [ ] **ARCHITECTURE.md** includes real-world example with actual statistics
- [ ] **THREAT_MODEL.md** exists with: assumptions, limitations, what Rootstock does NOT do, BloodHound comparison
- [ ] **Paper skeleton** exists in `docs/paper/` with: abstract, 7 sections, structured outline
- [ ] **references.bib** has ≥15 relevant references (BloodHound, Bifrost, macOS security research)
- [ ] **Target venues** documented with at least 3 conferences
- [ ] **BibTeX entry** complete in README
- [ ] No placeholder text remaining (except [Author]/[University])

### Academic Rigor
- [ ] Methodology is reproducible from the repository alone
- [ ] Threat model is honest about limitations
- [ ] Related work section acknowledges prior art fairly (BloodHound, Bifrost, Chainbreaker, etc.)
- [ ] Results claims are supported by data (scan statistics, query results)
- [ ] Ethical considerations addressed (responsible disclosure, authorized use only)

## Output Format

Produce `docs/reviews/phase-5-review.md`:

```markdown
# Phase 5 Review — Hardening & Quality

**Reviewer:** Claude Opus (automated review)
**Date:** [today]
**Overall Status:** ✅ PASS | ⚠️ PASS WITH ISSUES | ❌ FAIL

## Summary

## Test Coverage Assessment
- Collector modules with unit tests: [N/3]
- Graph pipeline with tests: [import/infer/queries — which have tests?]
- Integration test: [exists/missing]
- CI: [configured/missing]
- Estimated line coverage: [rough assessment]

## Results by Sub-Phase
### 5.1 Test Coverage: [✅|⚠️|❌]
### 5.2 macOS Compat: [✅|⚠️|❌]
### 5.3 Performance: [✅|⚠️|❌]
### 5.4 Documentation: [✅|⚠️|❌]

## Academic Readiness
- Paper skeleton quality: [ready for writing / needs work / missing]
- Reproducibility: [fully reproducible / partially / not reproducible]
- Ethical framework: [adequate / needs improvement / missing]

## Critical Issues
## Warnings
## Recommendations

## Meilenstein M5 Status
**"Publikationsreif":** [MET | NOT MET]
- Tests pass: [yes/no]
- Multi-version tested: [yes/no]
- Performance documented: [yes/no]
- Academic paper skeleton exists: [yes/no]
- Threat model exists: [yes/no]
- README enables first-time use: [yes/no]
```
