# Rootstock Deep Repository Audit

**Date:** 2026-04-26  
**Auditor:** Anonymous external review

## 1) System familiarization: how the repository works end-to-end

Rootstock is a two-runtime security analytics system:

1. **Endpoint collector (`collector/`, Swift)**
   - Enumerates macOS security controls, trust boundaries, and exposure signals.
   - Emits a normalized `scan.json` artifact.
2. **Analysis runtime (`graph/`, Python + Neo4j + FastAPI)**
   - Validates and imports `scan.json` into graph nodes/edges.
   - Runs inference passes (attack paths, ownership blast radius, tiering, vuln correlation).
   - Serves API + interactive viewer + report generation.

### Cross-component flow

1. Collector modules gather data with graceful degradation.
2. Graph importer validates schema and performs idempotent MERGE operations.
3. Inference stage derives security relationships and priorities.
4. Query/report/viewer layers project graph state for operators.

## 2) Deep audit coverage map

Reviewed architecture, code paths, and behavior across:

- **Collector domain:** module composition and expected artifact boundaries.
- **Graph import domain:** validation/import/inference/query orchestration.
- **API surface (`graph/server.py`):** auth, query execution policy, and file upload handling.
- **Utility controls (`graph/utils.py`):** read-only query validation posture.
- **Test posture (`graph/tests`):** regression confidence and risk of refactor regressions.

## 3) Prioritized findings and remediation status

## P0-1: API authn/authz gap on `/api/*` endpoints

### Finding
Operational endpoints were accessible without an application-layer auth control.

### Remediation implemented
- Added optional API token enforcement middleware for all `/api/*` routes.
- Supports either `X-API-Key` or `Authorization: Bearer <token>`.
- Uses constant-time token comparison.
- Token can be provided via CLI flag `--api-token` or `ROOTSTOCK_API_TOKEN`.

### Residual guidance
- For production: enable token + reverse proxy TLS + private bind address policy.

## P0-2 / P1: unbounded query response size risk

### Finding
Ad-hoc and predefined query endpoints could return arbitrarily large result sets.

### Remediation implemented
- Added centralized row-capped query executor.
- Applied row-limit controls to `/api/cypher` and `/api/queries/{id}/run`.
- Added response signal `truncated: true|false` when cap is hit.
- Added configurable cap `--query-max-rows` (bounded to safe min/max).

### Residual guidance
- Add per-request server-side timeout configuration in a follow-up.

## P1: upload memory pressure in BloodHound import

### Finding
ZIP upload path buffered request body into memory before writing temp file.

### Remediation implemented
- Reworked upload handling to stream chunks directly to disk.
- Enforced cumulative byte cap during streaming.
- Preserved existing extension validation and cleanup behavior.

## P2: test coverage for hardening controls

### Finding
No explicit tests for API token gating and result truncation behavior.

### Remediation implemented
- Added API tests validating unauthorized and authorized token paths.
- Added truncation behavior test for row cap enforcement.

## 4) Refactor/dedup/optimization opportunities identified

1. **Server endpoint deduplication:** continue consolidating data-fetch patterns behind shared query execution wrappers.
2. **Policy centralization:** migrate security knobs (auth required, row caps, upload caps) into a typed config object.
3. **Defense-in-depth:** add structured audit logging for denied auth and truncated responses.
4. **Operational hardening:** document secure deployment profiles in a dedicated runbook.

## 5) Validation results

- `pytest -q graph/tests/test_server.py` passed.
- `pytest -q graph/tests` passed.
- `ruff check graph --output-format=concise` passed.

## 6) Iterative review ledger (20 passes)

1. API auth model reviewed -> token-gating added.  
2. Query endpoint abuse risk reviewed -> row-cap executor added.  
3. Upload memory profile reviewed -> chunked streaming write added.  
4. Auth bypass vectors reviewed -> constant-time compare retained.  
5. Endpoint compatibility reviewed -> `truncated` response signal added.  
6. Runtime configurability reviewed -> CLI/env knobs added.  
7. Test coverage for new controls reviewed -> auth + truncation tests added.  
8. CORS compatibility reviewed -> `X-API-Key` allowed header added.  
9. Browser preflight behavior reviewed -> `OPTIONS` auth bypass added for preflight.  
10. Query behavior regression risk reviewed -> full graph test suite rerun.  
11. Static lint posture reviewed -> ruff clean.  
12. pytest warning hygiene reviewed -> removed stale pytest config warning source.  
13. Docs consistency reviewed -> findings/remediation statuses aligned to implementation.  
14. Residual risk triage reviewed -> timeout/rate-limit follow-ups documented.  
15. Dedup potential reviewed -> centralized query limiter used by multiple endpoints.  
16. Resource cleanup paths reviewed -> temp-file cleanup retained in all outcomes.  
17. Deployment hardening reviewed -> secure production guidance retained.  
18. Test isolation reviewed -> auth state reset in each test.  
19. API compatibility reviewed -> no breaking change for unauthenticated default mode.  
20. Final pass -> no additional P0/P1 issues identified in touched scope.

## 7) Bottom line

The repository already had a strong architectural foundation and broad test baseline. This remediation cycle hardens critical API trust boundaries, reduces query-abuse blast radius, and removes upload memory pressure risk while preserving compatibility and test stability.
