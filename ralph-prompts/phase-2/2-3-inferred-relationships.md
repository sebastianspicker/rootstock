You are the Graph Engineer agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §Inferred Relationships, §Injection-Enabling Entitlements,
docs/research/entitlements-reference.md, existing graph/import.py

## Task: Phase 2.3 — Inferred Relationships Engine

Compute derived relationships that don't exist in the raw JSON but emerge from combining multiple data points.

### Step 1: CAN_INJECT_INTO Relationships
Create `graph/infer_injection.py`:
- Query all Applications that have TCC grants or security-critical entitlements (they are valuable targets)
- For each such target app, check:
  - `library_validation == false` → create `CAN_INJECT_INTO {method: "missing_library_validation"}`
  - `hardened_runtime == false` → create `CAN_INJECT_INTO {method: "dyld_insert"}`
  - Has entitlement `com.apple.security.cs.allow-dyld-environment-variables` → create `CAN_INJECT_INTO {method: "dyld_insert_via_entitlement"}`
- The edge goes FROM any unprivileged app (or an attacker placeholder node) TO the injectable target
- Create a synthetic `(:Application {name: "attacker_payload", bundle_id: "attacker.payload"})` node
  as the source for all injection edges (represents arbitrary code execution)
- Cypher pattern:
  ```cypher
  MATCH (target:Application)-[:HAS_TCC_GRANT]->(t:TCC_Permission)
  WHERE target.library_validation = false
  MERGE (attacker:Application {bundle_id: 'attacker.payload'})
  ON CREATE SET attacker.name = 'Attacker Payload', attacker.is_system = false
  MERGE (attacker)-[:CAN_INJECT_INTO {method: 'missing_library_validation', inferred: true}]->(target)
  ```

### Step 2: CHILD_INHERITS_TCC Relationships
Create `graph/infer_electron.py`:
- Query all Electron apps (is_electron == true) that have TCC grants
- For each: create CHILD_INHERITS_TCC edge from app to itself (semantically: child processes inherit)
- Or better: create a synthetic `(:Process {name: "<app>_child"})` node representing the child
  that inherits permissions — BUT for simplicity in MVP, just mark the edge:
  ```cypher
  MATCH (e:Application {is_electron: true})-[:HAS_TCC_GRANT]->(t:TCC_Permission)
  MERGE (attacker:Application {bundle_id: 'attacker.payload'})
  MERGE (attacker)-[:CHILD_INHERITS_TCC {inferred: true, via: 'ELECTRON_RUN_AS_NODE'}]->(e)
  ```

### Step 3: CAN_SEND_APPLE_EVENT Relationships
Create `graph/infer_automation.py`:
- Apps with TCC grant for kTCCServiceAppleEvents can automate other apps
- Apps with `com.apple.private.tcc.allow` containing AppleEvents can automate ALL apps
- Query:
  ```cypher
  MATCH (a:Application)-[:HAS_TCC_GRANT]->(t:TCC_Permission {service: 'kTCCServiceAppleEvents'})
  MATCH (target:Application)-[:HAS_TCC_GRANT]->(valuable:TCC_Permission)
  WHERE a <> target
  MERGE (a)-[:CAN_SEND_APPLE_EVENT {inferred: true}]->(target)
  ```

### Step 4: Orchestrator
Create `graph/infer.py`:
- Runs all inference modules in sequence
- `python3 infer.py --neo4j bolt://localhost:7687`
- Prints statistics: "Inferred N CAN_INJECT_INTO, M CHILD_INHERITS_TCC, K CAN_SEND_APPLE_EVENT edges"
- All inferred edges have `{inferred: true}` property to distinguish from explicit data
- Idempotent: uses MERGE, safe to re-run

### Step 5: Testing
- Seed a test graph with 3 known apps:
  - App A: has FDA, library_validation=false
  - App B: is Electron, has Screen Recording
  - App C: has AppleEvents TCC grant
- Run inference → verify expected edges exist
- Test idempotency: run twice → same edge count

## Acceptance Criteria

- [ ] `python3 graph/infer.py` runs successfully on a populated graph
- [ ] CAN_INJECT_INTO edges exist for apps with TCC grants AND missing library validation or hardened runtime
- [ ] CHILD_INHERITS_TCC edges exist for Electron apps with TCC grants
- [ ] CAN_SEND_APPLE_EVENT edges exist for apps with Automation TCC grants
- [ ] All inferred edges have `{inferred: true}` property
- [ ] Attacker_payload synthetic node exists as injection source
- [ ] Statistics printed: count per edge type
- [ ] Re-running inference doesn't create duplicate edges
- [ ] On real scan data: at least some inferred edges are created

## If Stuck

After 12 iterations:
- If the inference queries are too slow on large graphs: add WHERE clauses to limit scope
- If the Electron detection missed apps: broaden heuristic or add manual override list
- Simplify: start with CAN_INJECT_INTO only, add the others incrementally

When ALL acceptance criteria are met, output:
<promise>PHASE_2_3_COMPLETE</promise>
