You are the Graph Engineer agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §Graph Model (all node/edge types), §Collector Output Schema,
graph/schema/ (existing constraints), collector output from Phase 1

## Task: Phase 2.2 — JSON → Graph Importer

Build the Python importer that reads collector JSON and creates nodes and relationships in Neo4j.

### Step 1: Pydantic Models
Create `graph/models.py`:
- Pydantic v2 models mirroring the collector JSON schema:
  - `ScanResult`, `ApplicationData`, `TCCGrantData`, `EntitlementData`, `ElevationInfo`
- Strict validation: reject malformed input early
- Parse the scan JSON file into these models

### Step 2: Node Importer
Create `graph/import_nodes.py`:
- Function `import_applications(tx, apps: list[ApplicationData], scan_id: str)`
  - MERGE on bundle_id, SET all properties
  - Tag with scan_id and imported_at timestamp
- Function `import_tcc_grants(tx, grants: list[TCCGrantData], scan_id: str)`
  - TCC_Permission nodes already exist from seed → MERGE
  - Create HAS_TCC_GRANT relationship: match Application by client bundle_id → TCC_Permission by service
  - Edge properties: allowed, auth_reason, scope
- Function `import_entitlements(tx, apps: list[ApplicationData], scan_id: str)`
  - MERGE Entitlement nodes by name
  - Create HAS_ENTITLEMENT relationships: Application → Entitlement
- All operations use MERGE (not CREATE) for idempotency

### Step 3: Main Import Script
Create `graph/import.py`:
- CLI: `python3 import.py --input scan.json --neo4j bolt://localhost:7687 [--user neo4j --password rootstock]`
- Flow:
  1. Read and validate JSON with Pydantic
  2. Connect to Neo4j
  3. Import nodes in order: Applications → TCC grants (with relationships) → Entitlements (with relationships)
  4. Print statistics: "Imported N applications, M TCC grants, K entitlements, J relationships"
- Transaction management: batch MERGE operations (not one tx per node)
- Error handling: log failures per-item, continue importing

### Step 4: Relationship Building
Within the import, create these explicit relationships:
- `(Application)-[:HAS_TCC_GRANT {allowed, auth_reason, scope}]->(TCC_Permission)`
  Match application by client field in TCC grant → match TCC_Permission by service field
- `(Application)-[:HAS_ENTITLEMENT]->(Entitlement)`
  For each app's entitlements list
- `(Application)-[:SIGNED_BY_SAME_TEAM]->(Application)`
  Group apps by team_id, create edges between apps signed by the same team

### Step 5: Import Verification
After import completes:
- Query and print: number of Application nodes, TCC_Permission nodes with grants, Entitlement nodes
- Sanity check: "Applications with FDA: N", "Injectable apps: N", "Electron apps: N"
- These serve as smoke tests for the data quality

### Step 6: Testing
- Create a minimal test JSON fixture (3 apps, 5 TCC grants, 10 entitlements)
- Test: import fixture → verify correct node counts in Neo4j
- Test: re-import same fixture → no duplicate nodes (MERGE works)
- Test: import with missing fields → graceful handling

## Acceptance Criteria

- [ ] `python3 graph/import.py --input scan.json --neo4j bolt://localhost:7687` runs successfully
- [ ] Application nodes exist in Neo4j with all properties from JSON
- [ ] TCC_Permission nodes are linked to Applications via HAS_TCC_GRANT
- [ ] Entitlement nodes are linked to Applications via HAS_ENTITLEMENT
- [ ] Re-importing the same JSON does not create duplicates
- [ ] Import statistics are printed (node counts, relationship counts)
- [ ] Malformed JSON entries are skipped with warning, not crash
- [ ] Pydantic validation catches schema violations early
- [ ] On real scan data: at least 20+ Application nodes, 5+ TCC relationships visible in Neo4j Browser

## If Stuck

After 15 iterations:
- If Pydantic validation is too strict for edge cases: relax to Optional fields and warn
- If batch MERGE is slow: reduce batch size or use UNWIND for bulk operations
- If Neo4j auth issues: try `--no-auth` mode in docker-compose for development

When ALL acceptance criteria are met, output:
<promise>PHASE_2_2_COMPLETE</promise>
