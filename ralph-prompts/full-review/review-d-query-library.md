You are a senior graph database engineer and security analyst performing a systematic review of the Rootstock Cypher query library — 79 pre-built queries that surface attack paths, misconfigurations, and security findings from the property graph.

## Context

Read: CLAUDE.md, ARCHITECTURE.md, docs/QUALITY.md,
graph/queries/*.cypher (all 79 files),
graph/query_runner.py,
graph/constants.py (node labels, relationship types),
graph/models.py (node properties),
graph/setup_schema.py (indexes),
graph/tests/test_queries.py

## Priority Definitions

- **P0 — Critical:** Query has Cypher syntax error, references non-existent labels/relationships (will always return empty), or has a Cypher injection vulnerability via parameter substitution
- **P1 — High:** Query returns incorrect results (wrong logic), misses critical cases its description claims to find, uses wrong relationship direction
- **P2 — Medium:** Unbounded variable-length paths that could hang on large graphs, missing ORDER BY/LIMIT on potentially huge result sets, misleading header comments
- **P3 — Low:** Inconsistent formatting, missing comments, suboptimal query patterns that don't affect correctness

## Task: Review Phase D — Cypher Query Library

Perform a systematic review of all 79 queries. This is the user-facing output of Rootstock — query correctness directly determines the tool's value.

### D.1 Syntax & Schema Validation

For EVERY `.cypher` file in `graph/queries/`:
- [ ] Does the query parse as valid Cypher? (No syntax errors)
- [ ] Does every node label referenced (`:Application`, `:TCC_Permission`, etc.) exist in the schema?
- [ ] Does every relationship type referenced (`:HAS_TCC_GRANT`, `:CAN_INJECT_INTO`, etc.) exist — either created by import or by inference?
- [ ] Does every property referenced (`.bundle_id`, `.hardened_runtime`, etc.) get set by import or inference?
- [ ] Are parameter placeholders (if any) correctly named and typed?

### D.2 Query Logic Correctness

For each query:
- [ ] Does the header comment accurately describe what the query finds?
- [ ] Does the WHERE clause correctly filter for the described scenario?
- [ ] Is the relationship direction correct in MATCH patterns?
- [ ] Does the RETURN clause include all fields needed to understand the finding?
- [ ] For queries with variable-length paths `[:REL*]`: is there a bound on path length?
- [ ] For queries with OPTIONAL MATCH: is the null handling correct?

### D.3 Query Runner

Review `graph/query_runner.py`:
- [ ] Does it correctly load all `.cypher` files from the queries directory?
- [ ] Does it handle parameterized queries correctly?
- [ ] Is there protection against Cypher injection in query parameters?
- [ ] Does it handle query execution errors gracefully (connection issues, syntax errors, timeouts)?
- [ ] Does it format results consistently?

### D.4 Coverage Analysis

Cross-reference queries against inference modules:
- [ ] For each inferred relationship type: is there at least one query that uses it?
- [ ] Are there attack patterns the inference engine can discover that no query surfaces?
- [ ] Are there any "dead" queries that reference removed/renamed labels or relationships?
- [ ] Group queries by category — are there gaps in coverage (e.g., no queries for a specific security domain)?

### D.5 Performance Review

For queries that could be expensive:
- [ ] Any `MATCH path = (a)-[*]-(b)` without length bounds? → Flag as P2
- [ ] Any Cartesian products (multiple disconnected MATCH patterns)? → Flag as P2
- [ ] Any queries missing LIMIT that could return thousands of rows? → Flag as P3
- [ ] Are the indexes in `setup_schema.py` sufficient for the WHERE clauses in these queries?

### D.6 Query Tests

Review `graph/tests/test_queries.py`:
- [ ] Does the test suite validate that all 79 queries parse without syntax errors?
- [ ] Are there semantic tests (seed graph → run query → verify expected results)?
- [ ] Do tests cover parameterized queries?
- [ ] Run the tests — do they pass?

## Output

For each iteration, state:
1. Queries reviewed (by number range or category)
2. Issues found (with priority)
3. Fixes applied
4. What remains

After all issues are resolved, produce a summary:

```
## Review D Summary — Cypher Query Library
- Queries reviewed: [count] / 79
- P0 issues found/fixed: [N] (syntax errors, broken references)
- P1 issues found/fixed: [N] (logic errors)
- P2 issues found/fixed: [N] (performance, misleading comments)
- P3 issues deferred: [N]
- Queries referencing valid schema: [N] / 79
- Inference relationships with query coverage: [N] / [total]
- Query tests: [pass count] / [total count]
```

## Acceptance Criteria

- [ ] All 79 queries parse without Cypher syntax errors
- [ ] All queries reference node labels and relationship types that exist in the schema
- [ ] Query header comments accurately describe query behavior
- [ ] No unbounded variable-length paths without explicit limits
- [ ] query_runner.py has no Cypher injection vulnerabilities
- [ ] Query tests pass
- [ ] No P0 or P1 issues remain open
- [ ] P2/P3 issues documented in tech-debt-tracker.md

## If Stuck

After 15 iterations:
- If a query references a node type from a planned-but-unimplemented collector module: add a comment noting the dependency, don't delete the query
- If you can't validate query logic without a live Neo4j database: validate syntax and schema references statically, flag semantic validation as needing live testing
- If query count changes during review (files added/removed): update the count and re-verify
- Priority: syntax correctness > schema reference validity > logic correctness > performance > style

When ALL acceptance criteria are met, output:
<promise>REVIEW_D_COMPLETE</promise>
