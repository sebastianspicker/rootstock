You are the review orchestrator for a full-codebase review of the Rootstock project. Your job is to execute each review phase in sequence, track cross-cutting issues, and ensure the codebase is consistent after all phases complete.

## Context

Read: CLAUDE.md, ARCHITECTURE.md,
ralph-prompts/full-review/review-a-data-acquisition.md,
ralph-prompts/full-review/review-b-graph-import.md,
ralph-prompts/full-review/review-c-inference-engine.md,
ralph-prompts/full-review/review-d-query-library.md,
ralph-prompts/full-review/review-e-reporting-viz-api.md,
ralph-prompts/full-review/review-f-test-harness-utils.md

## Priority Definitions

- **P0 — Critical:** Crashes, data loss, security vulnerabilities, broken core functionality
- **P1 — High:** Incorrect results, missing critical edge cases, contract violations
- **P2 — Medium:** Performance issues, poor error messages, missing validation
- **P3 — Low:** Style inconsistencies, naming violations, documentation gaps

## Task: Orchestrate Full Review

Execute the review phases in order. After each phase, verify the codebase is still buildable and testable before proceeding.

### Execution Sequence

```
Phase A (Data Acquisition) → Phase B (Graph Import) → Phase C (Inference Engine)
→ Phase D (Query Library) → Phase E (Reporting/Viz/API) → Phase F (Test Harness)
```

### For Each Phase

1. **Execute the phase review** by following the corresponding prompt file
2. **After the phase completes**, run verification:
   - Phase A: `cd collector && swift build && swift test`
   - Phase B: `cd graph && python3 -m pytest tests/test_import.py tests/test_import_models.py -q`
   - Phase C: `cd graph && python3 -m pytest tests/ -k "infer" -q`
   - Phase D: `cd graph && python3 -m pytest tests/test_queries.py -q`
   - Phase E: `cd graph && python3 -m pytest tests/test_server.py tests/test_diff_scans.py tests/test_diff_formatters.py tests/test_opengraph.py -q`
   - Phase F: `cd graph && python3 -m pytest tests/ -q`
3. **Commit changes** with message format: `[review] Phase X — brief description of changes`
4. **Track cross-cutting issues** — if a phase fix reveals an issue in a previously-reviewed phase, note it for the final consistency loop
5. **Check for regressions** — if a phase fix breaks something from an earlier phase, fix it before moving on

### Cross-Cutting Issue Tracker

Maintain a running list of issues that span multiple phases:
- Schema mismatches between collector output and graph models
- Constants that need updating across multiple files
- Naming inconsistencies between subsystems
- Missing test fixture data discovered during later phases

Pass this list to the final consistency loop.

### Abort Conditions

- If a phase introduces a P0 regression in a previously-passing phase, STOP and fix before continuing
- If `swift build` or `python3 -m pytest tests/ -q` fails after a phase, STOP and fix before continuing
- If you've spent 5 iterations on a single phase without progress, document the blocker and move to the next phase

## Output

After each phase, report:
```
## Phase [X] Complete
- Issues found: P0=[N] P1=[N] P2=[N] P3=[N]
- Issues fixed: [N]
- Issues deferred: [N]
- Cross-cutting issues discovered: [list]
- Regression check: [PASS/FAIL]
- Commit: [hash]
```

After all phases, report:
```
## Orchestrator Summary
- Total issues found: P0=[N] P1=[N] P2=[N] P3=[N]
- Total issues fixed: [N]
- Total issues deferred: [N]
- Cross-cutting issues for final loop: [list]
- All tests passing: [yes/no]
- Commits created: [list of hashes]
```

## Acceptance Criteria

- [ ] All 6 phase reviews completed
- [ ] `cd collector && swift build && swift test` passes
- [ ] `cd graph && python3 -m pytest tests/ -q` passes
- [ ] All phase commits created with `[review]` prefix
- [ ] Cross-cutting issues documented for the final consistency loop
- [ ] No P0 regressions introduced

## If Stuck

After 8 iterations total:
- If a phase is completely blocked: skip it, document why, continue with the next phase
- If regressions cascade: revert the last phase's changes, re-assess the approach
- If tests require infrastructure not available: run what you can, document what needs manual verification

When ALL acceptance criteria are met, output:
<promise>REVIEW_ORCHESTRATOR_COMPLETE</promise>
