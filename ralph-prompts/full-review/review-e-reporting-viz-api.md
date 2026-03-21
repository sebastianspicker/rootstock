You are a senior full-stack engineer performing a systematic review of the Rootstock reporting, visualization, and API layer — the components that transform graph query results into human-readable reports, interactive visualizations, and a REST API.

## Context

Read: CLAUDE.md, ARCHITECTURE.md, docs/QUALITY.md,
graph/report.py, graph/report_assembly.py, graph/report_formatters.py,
graph/report_diagrams.py, graph/report_graphviz.py,
graph/viewer.py, graph/viewer_layout.py, graph/viewer_template.html,
graph/server.py,
graph/opengraph_export.py,
graph/diff_scans.py, graph/diff_models.py, graph/diff_formatters.py,
graph/merge_scans.py,
graph/tests/test_server.py, graph/tests/test_diff_scans.py,
graph/tests/test_diff_formatters.py, graph/tests/test_opengraph.py

## Priority Definitions

- **P0 — Critical:** Security vulnerability in the API (injection, unauthorized access), report generates incorrect security findings, viewer executes arbitrary scripts
- **P1 — High:** Report sections missing data they should contain, API returns wrong data, viewer doesn't render graph correctly, diff logic produces wrong results
- **P2 — Medium:** Poor formatting, missing error handling in API endpoints, viewer performance issues, incomplete diff output
- **P3 — Low:** Style inconsistencies, cosmetic issues, missing docstrings

## Task: Review Phase E — Reporting, Visualization & API

Perform an iterative, priority-ordered review of all output-facing components.

### E.1 Report Generation

Review `graph/report.py`, `graph/report_assembly.py`, `graph/report_formatters.py`:
- [ ] Does the report include all security finding categories?
- [ ] Is the report structure logical (executive summary → detailed findings → recommendations)?
- [ ] Are severity ratings in findings consistent with the query/inference priorities?
- [ ] Does the report handle empty result sets gracefully (no broken sections)?
- [ ] Is the markdown output valid and well-formatted?
- [ ] Are there any hardcoded values that should come from query results?

### E.2 Diagram Generation

Review `graph/report_diagrams.py`, `graph/report_graphviz.py`:
- [ ] Does Mermaid syntax output parse correctly?
- [ ] Does Graphviz DOT syntax output parse correctly?
- [ ] Do diagrams accurately represent the graph data (correct nodes, edges, labels)?
- [ ] Is there proper escaping of special characters in node/edge labels?
- [ ] Do diagrams handle edge cases (single node, no edges, very large graphs)?

### E.3 Interactive Viewer

Review `graph/viewer.py`, `graph/viewer_layout.py`, `graph/viewer_template.html`:
- [ ] Is the HTML self-contained (no external dependencies that would break offline)?
- [ ] Does the layout algorithm produce readable graphs (no overlapping nodes)?
- [ ] Is user interaction correct (click, drag, zoom, search)?
- [ ] Are there any XSS vulnerabilities (graph data injected into HTML without escaping)?
- [ ] Does the viewer handle large graphs (100+ nodes) without freezing?
- [ ] Are node colors/shapes consistent with the tier classification?

### E.4 FastAPI Server

Review `graph/server.py`:
- [ ] Are all endpoints correctly defined (HTTP method, path, request/response schema)?
- [ ] Is there input validation on all user-provided parameters?
- [ ] Are there Cypher injection vulnerabilities via query parameters?
- [ ] Does error handling return appropriate HTTP status codes?
- [ ] Is CORS configured appropriately (not wide-open unless intentional)?
- [ ] Are there endpoints that should require authentication but don't?
- [ ] Does the server handle Neo4j connection failures gracefully?
- [ ] Are response schemas consistent with what the viewer/client expects?

### E.5 OpenGraph Export

Review `graph/opengraph_export.py`:
- [ ] Is the export format correct and complete?
- [ ] Does it include all node types and relationships?
- [ ] Does it handle special characters in property values?
- [ ] Is the output deterministic (same graph → same export)?

### E.6 Scan Diffing

Review `graph/diff_scans.py`, `graph/diff_models.py`, `graph/diff_formatters.py`:
- [ ] Does the diff correctly identify added, removed, and changed nodes?
- [ ] Does the diff correctly identify added, removed, and changed edges?
- [ ] Does the diff handle schema evolution (new fields in newer scans)?
- [ ] Is the diff output human-readable and actionable?
- [ ] Does it handle edge cases (comparing identical scans, comparing empty scans)?

### E.7 Scan Merging

Review `graph/merge_scans.py`:
- [ ] Does the merge correctly combine data from multiple scans?
- [ ] How does it handle conflicts (same app, different data)?
- [ ] Does it preserve data provenance (which scan contributed what)?
- [ ] Does it handle merging scans with different schema versions?

### E.8 Tests

Review all tests for this phase:
- [ ] Do report tests verify output structure and content?
- [ ] Do server tests cover all endpoints?
- [ ] Do diff tests verify correct detection of changes?
- [ ] Do tests cover error cases?
- [ ] Run the tests — do they pass?

## Output

For each iteration, state:
1. What you reviewed
2. Issues found (with priority)
3. Fixes applied
4. What remains

After all issues are resolved, produce a summary:

```
## Review E Summary — Reporting, Viz & API
- Files reviewed: [count]
- P0 issues found/fixed: [N]
- P1 issues found/fixed: [N]
- P2 issues found/fixed: [N]
- P3 issues deferred: [N]
- API endpoints reviewed: [N]
- Security issues found: [N]
- Tests: [pass count] / [total count]
```

## Acceptance Criteria

- [ ] Report generation produces valid, complete markdown
- [ ] Diagram syntax is valid (Mermaid and Graphviz)
- [ ] Viewer HTML is self-contained and functional
- [ ] No XSS or injection vulnerabilities in viewer or API
- [ ] API endpoints return correct responses with proper error handling
- [ ] Diff logic correctly identifies changes between scans
- [ ] All related tests pass
- [ ] No P0 or P1 issues remain open
- [ ] P2/P3 issues documented in tech-debt-tracker.md

## If Stuck

After 15 iterations:
- If viewer layout issues require complex algorithm work: document the issue, ensure basic rendering works, defer optimization
- If API testing requires a running Neo4j instance: validate request/response schemas statically, flag as needing integration testing
- If Mermaid/Graphviz syntax validation is uncertain: test with a small example, document assumptions
- Priority: security (injection/XSS) > correctness > completeness > style

When ALL acceptance criteria are met, output:
<promise>REVIEW_E_COMPLETE</promise>
