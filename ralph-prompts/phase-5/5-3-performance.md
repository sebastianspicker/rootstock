You are the Collector Engineer agent for the Rootstock project.

## Context

Read: CLAUDE.md, collector/Sources/ (all modules), graph/import.py,
docs/exec-plans/tech-debt-tracker.md (known issues)

## Task: Phase 5.3 — Performance & Edge Cases

Optimize collector performance and harden against edge cases discovered during earlier phases.

### Step 1: Performance Benchmark
Create `scripts/benchmark.sh`:
- Run the collector 3 times, measure wall-clock time with `time`
- Record: total time, apps scanned, TCC grants found, JSON file size
- Save results to `docs/benchmarks/baseline.md`:
  ```markdown
  | Metric | Run 1 | Run 2 | Run 3 | Average |
  |---|---|---|---|---|
  | Total time (s) | | | | |
  | Apps scanned | | | | |
  | TCC grants | | | | |
  | JSON size (KB) | | | | |
  | Peak memory (MB) | | | | |
  ```
- Use `leaks --atExit -- rootstock-collector --output /tmp/bench.json` for memory check
- Target: < 30 seconds for ~150 apps, < 50 MB memory

### Step 2: Identify Bottlenecks
Profile the collector:
- Time each DataSource module separately (add internal timing to ScanOrchestrator)
- Expected bottleneck: `codesign` / Security.framework calls per app (I/O bound)
- Print per-module timing when `--verbose` is set:
  ```
  [TCC]          completed in 0.3s  (42 grants)
  [Entitlements] completed in 12.7s (187 apps)
  [CodeSigning]  completed in 8.2s  (187 apps)
  Total: 21.2s
  ```

### Step 3: Parallelization
If entitlement/code signing scanning is slow (>10s):
- Use Swift structured concurrency: `TaskGroup` to scan apps in parallel
- Limit concurrency to avoid overwhelming the system: max 8 concurrent tasks
- Ensure thread-safe result collection
- Measure improvement: before/after timing in benchmark

### Step 4: Edge Case Hardening
Fix or handle these known edge cases:
- [ ] App without Info.plist → skip with warning
- [ ] App without CFBundleIdentifier → use path-based fallback ID
- [ ] App with corrupted/invalid code signature → set signed=false, continue
- [ ] Binary that is a universal fat binary → handle correctly in Security.framework calls
- [ ] Symlinked apps (Homebrew Cask) → resolve symlinks before processing
- [ ] Very long file paths → ensure no buffer overflows or truncation
- [ ] App bundle that is actually a directory without real content → skip
- [ ] TCC.db that is locked by tccd → retry once after 500ms, then skip with error
- [ ] Empty Keychain (no items at all) → return empty array, no error
- [ ] Non-UTF8 strings in plist files → handle encoding gracefully

### Step 5: Neo4j Import Performance
Test and optimize graph import:
- Time `python3 import.py` with large scan JSON (200+ apps)
- If slow (>30s): batch MERGE operations using UNWIND:
  ```cypher
  UNWIND $apps AS app
  MERGE (a:Application {bundle_id: app.bundle_id})
  SET a += app
  ```
- Measure: import time before and after optimization

### Step 6: Large-Scale Test
If possible, test on a "heavy" Mac (developer machine with many tools):
- Homebrew, multiple IDEs, Docker, many Electron apps
- Target: 200+ apps, 50+ TCC grants
- Document any failures or unexpected results
- Update edge case list in tech-debt-tracker.md

## Acceptance Criteria

- [ ] Benchmark script exists and produces documented results
- [ ] Per-module timing is printed with --verbose
- [ ] Collector completes in < 30 seconds on a typical Mac (~150 apps)
- [ ] If parallelization implemented: measurable speedup documented
- [ ] All 10 listed edge cases are handled without crash
- [ ] Neo4j import handles 200+ app scans in < 30 seconds
- [ ] No memory leaks detected (leaks tool or Instruments)
- [ ] Benchmark results documented in docs/benchmarks/
- [ ] Tech-debt-tracker updated with any remaining known issues

## If Stuck

After 12 iterations:
- If parallelization causes thread safety issues: keep sequential, it's fine for MVP
  if total time is < 60 seconds
- If leaks tool is not available: skip memory profiling, focus on functional edge cases
- If some edge cases are rare/impossible to reproduce: add a comment noting the handling
  logic but mark the test as theoretical
- Priority: edge case hardening > performance optimization > Neo4j optimization

When ALL acceptance criteria are met, output:
<promise>PHASE_5_3_COMPLETE</promise>
