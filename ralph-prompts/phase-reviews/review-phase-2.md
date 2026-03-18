You are a senior security engineer and graph database specialist performing a thorough review of Phase 2 of the Rootstock project.

## Context

Read these files first:
- CLAUDE.md, ARCHITECTURE.md §Graph Model (full node/edge definitions, inferred relationships)
- ROADMAP.md §Phase 2 (all 4 sub-phases and their acceptance criteria)
- docs/QUALITY.md, docs/design-docs/core-beliefs.md
- graph/ (all Python source code)
- graph/queries/ (all Cypher queries)

## Your Task

Perform a comprehensive review of Phase 2 — Graph Pipeline. Verify that collector data flows correctly into Neo4j, relationships are inferred properly, and queries find real attack paths.

## Review Checklist

### 2.1 Neo4j Setup
- [ ] `docker-compose.yml` exists in `graph/` and starts Neo4j successfully
- [ ] Schema init script creates all unique constraints listed in ARCHITECTURE.md:
  - Application(bundle_id), TCC_Permission(service), Entitlement(name), XPC_Service(label), User(name), LaunchItem(label)
- [ ] Indexes exist for: Application.hardened_runtime, Application.library_validation, Application.is_electron, Entitlement.is_private
- [ ] TCC_Permission seed data contains ≥15 services with correct display names
- [ ] `python3 graph/setup.py` is idempotent (run twice, no errors)
- [ ] `requirements.txt` lists neo4j and pydantic

### 2.2 Graph Importer
- [ ] `python3 graph/import.py --input scan.json --neo4j bolt://localhost:7687` runs successfully
- [ ] Pydantic models validate collector JSON strictly — test with a malformed JSON
- [ ] Application nodes have ALL properties from ARCHITECTURE.md: name, bundle_id, path, version, team_id, hardened_runtime, library_validation, is_electron, is_system, signed, scan_id
- [ ] HAS_TCC_GRANT edges link Application → TCC_Permission with properties: allowed, auth_reason, scope
- [ ] HAS_ENTITLEMENT edges link Application → Entitlement
- [ ] MERGE semantics verified: import same scan twice → `MATCH (n) RETURN count(n)` stays the same
- [ ] scan_id and imported_at tags on all nodes
- [ ] Import statistics printed (node counts, relationship counts)
- [ ] Per-item errors don't abort the entire import

### 2.3 Inferred Relationships
- [ ] `python3 graph/infer.py` runs without error
- [ ] **CAN_INJECT_INTO edges are correct** — verify logic:
  - Apps with TCC grants + library_validation=false → edge exists
  - Apps with TCC grants + hardened_runtime=false → edge exists
  - Apps with allow-dyld-environment-variables entitlement → edge exists
  - Apps that are fully hardened with no injection entitlements → NO edge
- [ ] **CHILD_INHERITS_TCC edges** exist for Electron apps with TCC grants
- [ ] **CAN_SEND_APPLE_EVENT edges** exist for apps with Automation TCC grant
- [ ] All inferred edges have `{inferred: true}` property
- [ ] Attacker_payload synthetic node exists
- [ ] Inference is idempotent: run twice → same edge count
- [ ] Statistics printed per edge type

### 2.4 Killer Queries
- [ ] At least 5 `.cypher` files exist in `graph/queries/`
- [ ] Each query has a comment header with: Name, Purpose, Severity
- [ ] **Query 1 (Injectable FDA):** syntactically valid, returns results on test data or documents why not
- [ ] **Query 2 (Shortest Path):** uses shortestPath with depth limit, returns paths
- [ ] **Query 3 (Electron Inheritance):** correctly identifies Electron apps with TCC grants
- [ ] **Query 4 (Private Entitlements):** filters non-system apps, groups by private entitlement count
- [ ] **Query 5 (Apple Event Cascade):** finds transitive TCC access via automation
- [ ] `graph/queries/README.md` documents all queries
- [ ] At least one query produces a non-trivial finding on real scan data

### Cross-Cutting Concerns
- [ ] **Data integrity:** Node counts in Neo4j match item counts in source JSON
- [ ] **No data loss:** Every application, TCC grant, and entitlement from JSON has a corresponding node
- [ ] **Edge correctness:** Spot-check 3 random HAS_TCC_GRANT edges — do they match the JSON source?
- [ ] **Python quality:** Type hints on function signatures, docstrings on public functions
- [ ] **No hardcoded credentials:** Neo4j password configurable via CLI args or env vars

## Execution

1. **Read all Python source code** in `graph/` — check logic, not just file existence
2. **If Neo4j is running:** execute queries and verify results
3. **If a scan.json exists:** import it and verify node/edge counts
4. **Check Cypher syntax:** paste each query into Neo4j Browser or verify with `EXPLAIN`
5. **Verify inferred relationship logic** by tracing the code against ARCHITECTURE.md §Inferred Relationships

## Output Format

Produce a review report in `docs/reviews/phase-2-review.md`:

```markdown
# Phase 2 Review — Graph Pipeline

**Reviewer:** Claude Opus (automated review)
**Date:** [today]
**Overall Status:** ✅ PASS | ⚠️ PASS WITH ISSUES | ❌ FAIL

## Summary
[2-3 sentences]

## Results by Sub-Phase

### 2.1 Neo4j Setup: [✅|⚠️|❌]
### 2.2 Graph Importer: [✅|⚠️|❌]
### 2.3 Inferred Relationships: [✅|⚠️|❌]
### 2.4 Killer Queries: [✅|⚠️|❌]

## Data Integrity Check
- Applications in JSON: N → Applications in Neo4j: M [match/mismatch]
- TCC grants in JSON: N → HAS_TCC_GRANT edges: M [match/mismatch]
- Inferred edges: N CAN_INJECT_INTO, M CHILD_INHERITS_TCC, K CAN_SEND_APPLE_EVENT

## Critical Issues
## Warnings
## Recommendations

## Meilenstein M2 Status
**"Wir finden Angriffspfade":** [MET | NOT MET]
- 5 Killer Queries exist: [yes/no]
- At least 1 query finds a real attack path: [yes/no, describe the path]
- Graph correctly represents macOS trust boundaries: [yes/no]
```
