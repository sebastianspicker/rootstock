You are a senior security engineer and UX reviewer performing a thorough review of Phase 4 of the Rootstock project.

## Context

Read: CLAUDE.md, ROADMAP.md §Phase 4, graph/report.py, graph/browser/, graph/queries/,
docs/guides/

## Your Task

Review Phase 4 — Visualization & UX. Verify that the tool produces usable, accurate output for Red Teams, Blue Teams, and researchers.

## Review Checklist

### 4.1 Static Reports
- [ ] `python3 graph/report.py --neo4j bolt://... --output report.md` runs successfully
- [ ] Report contains ALL required sections:
  - Scan Metadata (hostname, version, counts)
  - Executive Summary (critical/high finding counts, top 3 attack paths)
  - Critical Findings: Injectable FDA apps (table)
  - High Findings: Electron inheritance (table)
  - High Findings: Apple Event cascade (table)
  - Informational: TCC grant overview
  - Informational: Private entitlement audit
  - Recommendations (actionable, not generic)
- [ ] At least one Mermaid attack path diagram generated
- [ ] Mermaid syntax is valid (renders in GitHub/VS Code preview)
- [ ] Tables are properly formatted Markdown
- [ ] Empty sections show "No findings" instead of crashing
- [ ] Recommendations are specific to the findings (not boilerplate)
- [ ] Graphviz DOT export exists and produces valid syntax (optional — note if missing)

### 4.2 Neo4j Browser Integration
- [ ] GraSS style sheet assigns distinct colors to ALL 8 node types
- [ ] Attack edges (CAN_INJECT_INTO, CHILD_INHERITS_TCC) are visually distinct (dashed, red)
- [ ] Data edges (HAS_ENTITLEMENT, COMMUNICATES_WITH) use different styles
- [ ] Node captions show the `name` property
- [ ] Neo4j Browser Guide exists with ≥5 slides and runnable queries
- [ ] Saved queries file contains all Killer Queries + exploratory queries
- [ ] Setup script/instructions exist for loading styles into Neo4j
- [ ] Quickstart documentation exists in docs/guides/

### 4.3 Query Library
- [ ] **Count:** ≥20 `.cypher` files in `graph/queries/`
- [ ] **Coverage:** Red Team (≥5), Blue Team (≥5), Forensic (≥3) queries
- [ ] **Headers:** Every query has Name, Purpose, Category, Severity in comment block
- [ ] **Correctness:** Spot-check 5 random queries — is the Cypher syntactically valid?
- [ ] **Phase 3 data:** ≥3 queries use XPC, Persistence, or Keychain data
- [ ] **Query runner CLI:** `query_runner.py --list` works, `--run <id>` executes a query
- [ ] **Parameterized queries:** At least 2 queries accept `$target_service` or `$app_name`
- [ ] **README:** Documents all queries with purpose, category, example invocation

### Usability Assessment
- [ ] A new user could follow the documentation and produce a report within 30 minutes
- [ ] Neo4j Browser with loaded styles makes the graph immediately understandable
- [ ] Query names are descriptive enough to find the right query without reading the code
- [ ] Report is suitable for inclusion in a pentest report or academic paper
- [ ] Error messages from tools are helpful (not stack traces)

## Output Format

Produce `docs/reviews/phase-4-review.md`:

```markdown
# Phase 4 Review — Visualization & UX

**Reviewer:** Claude Opus (automated review)
**Date:** [today]
**Overall Status:** ✅ PASS | ⚠️ PASS WITH ISSUES | ❌ FAIL

## Summary

## Results by Sub-Phase
### 4.1 Static Reports: [✅|⚠️|❌]
### 4.2 Neo4j Browser: [✅|⚠️|❌]
### 4.3 Query Library: [✅|⚠️|❌]

## Query Library Inventory
| ID | Name | Category | Valid Cypher? | Returns Results? |
|---|---|---|---|---|
[table of all queries]

## Usability Score (1-5)
- First-use experience: [score] — [justification]
- Report quality: [score] — [justification]
- Graph visualization: [score] — [justification]

## Critical Issues
## Warnings
## Recommendations

## Meilenstein M4 Status
**"Benutzbar für Dritte":** [MET | NOT MET]
- Report generator produces actionable output: [yes/no]
- Neo4j Browser integration is functional: [yes/no]
- Query library has ≥20 documented queries: [yes/no, count]
```
