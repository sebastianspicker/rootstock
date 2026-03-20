You are a senior systems architect performing the final cross-cutting consistency review of the Rootstock project. All 6 subsystem reviews have completed. Your job is to verify that the subsystems work together correctly and that documentation reflects the current state of the code.

## Context

Read: CLAUDE.md, ARCHITECTURE.md, docs/QUALITY.md, docs/exec-plans/tech-debt-tracker.md,
docs/benchmarks/baseline.md

Also read the git log for review commits:
`git log --oneline --grep="[review]" | head -20`

And the cross-cutting issues documented by the orchestrator (if any).

## Priority Definitions

- **P0 — Critical:** Cross-subsystem data flow broken (collector output can't be imported, inference references missing nodes, queries reference missing relationships)
- **P1 — High:** Documentation doesn't match code, tests pass but validate wrong behavior, security boundary violation
- **P2 — Medium:** Stale documentation sections, incomplete fixture coverage, naming inconsistencies across subsystems
- **P3 — Low:** Minor documentation wording, formatting, version numbers

## Task: Final Consistency Review

### F.1 End-to-End Schema Consistency

Trace 3 representative data paths from collector JSON → Pydantic model → Neo4j MERGE → inference → Cypher query → report output:

**Path 1: Application with TCC grant**
- [ ] Collector JSON field names for an app match Pydantic model field names
- [ ] Pydantic model fields map to correct Neo4j node properties in import MERGE
- [ ] Inference modules reference these properties correctly
- [ ] Queries reference these labels and properties correctly
- [ ] Report output includes the relevant data

**Path 2: XPC service with entitlements**
- [ ] XPC service JSON fields → Pydantic → Neo4j → query coverage

**Path 3: Code signing + injection assessment**
- [ ] Code signing JSON fields → Pydantic → Neo4j → injection inference → query → report

For each path, note any field name mismatches, missing mappings, or broken links.

### F.2 Import ↔ Inference Alignment

- [ ] List every node label created by import modules
- [ ] List every node label referenced by inference modules
- [ ] List every relationship type created by inference
- [ ] List every relationship type referenced by queries
- [ ] Identify: node types created but never used by inference or queries (orphaned)
- [ ] Identify: node types referenced by inference/queries but not created by import (broken references)

### F.3 Logical Attack Path Validation

Sample 5 complex multi-hop attack paths and validate the security logic:

1. **Injection → FDA escalation:** Injectable app → DYLD_INSERT → FDA-granted app → Full Disk Access
2. **Electron + Accessibility chain:** Electron app with TCC → parent injection → Accessibility → UI control
3. **Kerberos → lateral movement:** Injectable with Kerberos → ticket theft → cross-host access
4. **Shell hook → persistence:** Writable shell config → code execution → persistence → TCC inheritance
5. **File ACL → privilege escalation:** Writable system file → modify privileged binary → execution as root

For each path:
- [ ] Are all edges in the path created by inference?
- [ ] Is each hop a real, documented macOS attack technique?
- [ ] Could a real attacker execute this chain?
- [ ] Does at least one Cypher query surface this path or a component of it?

### F.4 Test Coverage Gaps

Run the full test suites and assess coverage:
- [ ] `cd collector && swift test` — passes? Module coverage?
- [ ] `cd graph && python3 -m pytest tests/ -q` — passes? Total test count?
- [ ] Are there collector modules with zero test coverage?
- [ ] Are there graph modules with zero test coverage?
- [ ] Are there inference modules with zero test coverage?
- [ ] Is the test fixture data sufficient for meaningful testing?

### F.5 Documentation Updates

Verify and update documentation to match the current codebase:

**ARCHITECTURE.md:**
- [ ] Does the module list match actual files in `collector/Sources/` and `graph/`?
- [ ] Are recently added modules (splits, new features) reflected?
- [ ] Is the data flow diagram accurate?

**docs/exec-plans/tech-debt-tracker.md:**
- [ ] Add any P3 items deferred during the phase reviews
- [ ] Remove items that were fixed during the review
- [ ] Ensure each item has: description, priority, affected files, suggested fix

**docs/benchmarks/baseline.md:**
- [ ] Do benchmarks reflect current performance?
- [ ] Are there new modules not covered by benchmarks?

**CLAUDE.md:**
- [ ] Does the "Repository Layout" section match the actual file structure?
- [ ] Are newly added directories listed?
- [ ] Are the key conventions still accurate?

### F.6 Naming Convention Audit

Spot-check naming across all subsystems:
- [ ] Python files: `snake_case` filenames, `snake_case` functions/variables, `UpperCamelCase` classes
- [ ] Swift files: `UpperCamelCase` types, `lowerCamelCase` functions/variables
- [ ] Neo4j labels: `UpperCamelCase` (e.g., `Application`, `TCC_Permission`)
- [ ] Neo4j relationships: `UPPER_SNAKE_CASE` (e.g., `HAS_TCC_GRANT`)
- [ ] Constants: `UPPER_SNAKE_CASE` in Python, following Swift conventions in Swift
- [ ] JSON keys: `snake_case` in collector output

### F.7 Security Audit

Final pass across the entire codebase:
- [ ] **No secrets in code:** grep for password, secret, token, key patterns — verify none contain actual values
- [ ] **No network calls in collector:** grep for URL, HTTP, network, socket patterns in Swift code
- [ ] **No Cypher injection:** verify all user-provided values go through parameterized queries, not string interpolation
- [ ] **No XSS in viewer:** verify all graph data inserted into HTML is properly escaped
- [ ] **No command injection:** verify any subprocess calls properly escape arguments
- [ ] **API security:** verify server.py doesn't expose sensitive data in error messages

## Output

For each iteration, state:
1. What you verified
2. Inconsistencies found (with priority)
3. Fixes applied
4. What remains

After all checks complete, produce the final report:

```
## Final Consistency Review

### Schema Consistency
- Data paths traced: 3/3
- Field mismatches found/fixed: [N]
- Broken references found/fixed: [N]

### Import ↔ Inference Alignment
- Node types created by import: [N]
- Node types used by inference/queries: [N]
- Orphaned node types: [list or "none"]
- Broken references: [list or "none"]

### Attack Path Validation
- Paths validated: 5/5
- Logically correct: [N]/5
- Issues found: [list or "none"]

### Test Coverage
- Collector tests: [pass/fail] ([N] tests)
- Graph tests: [pass/fail] ([N] tests)
- Modules with zero coverage: [list or "none"]

### Documentation
- ARCHITECTURE.md: [current/updated]
- tech-debt-tracker.md: [current/updated]
- CLAUDE.md: [current/updated]
- benchmarks: [current/updated]

### Naming Conventions
- Violations found/fixed: [N]

### Security
- Issues found/fixed: [N]
- Remaining concerns: [list or "none"]

### Final Status
- All P0 issues: RESOLVED
- All P1 issues: RESOLVED
- P2 issues: [N] resolved, [N] tracked
- P3 issues: [N] tracked in tech-debt-tracker.md
```

## Acceptance Criteria

- [ ] All tests pass: `swift test` and `python3 -m pytest tests/ -q`
- [ ] Documentation matches code reality
- [ ] No cross-subsystem inconsistencies (schema, naming, imports)
- [ ] All P0–P2 issues resolved
- [ ] P3 items tracked in tech-debt-tracker.md
- [ ] Security audit clean (no injection vectors, no secret leakage)
- [ ] 3 data paths traced end-to-end with no broken links
- [ ] 5 attack paths validated as logically sound

## If Stuck

After 15 iterations:
- If documentation updates are extensive: focus on accuracy over completeness, defer formatting to tech-debt
- If a cross-subsystem schema mismatch requires significant refactoring: document in tech-debt-tracker.md with a concrete fix plan, don't attempt the refactor in this loop
- If attack path validation reveals fundamental design issues: document them clearly, these are valuable findings even if not fixed immediately
- Priority: schema consistency > security audit > test coverage > documentation > naming

When ALL acceptance criteria are met, output:
<promise>REVIEW_FINAL_COMPLETE</promise>
