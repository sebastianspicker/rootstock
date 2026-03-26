You are the Security Researcher agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §Graph Model, graph/schema/ (constraints), ROADMAP.md §Phase 2.4,
docs/research/tcc-internals.md, docs/research/entitlements-reference.md

## Task: Phase 2.4 — Killer Queries

Create the five core Cypher queries that demonstrate Rootstock's value by finding real attack paths.

### Query 1: Injectable FDA Apps
Create `graph/queries/01-injectable-fda-apps.cypher`:
```
// Name: Injectable Full Disk Access Apps
// Purpose: Find apps with Full Disk Access that can be injected with attacker code
// Attack: Inject dylib into FDA app → inherit Full Disk Access → read/modify TCC.db
// Severity: Critical
```
- Find Applications with HAS_TCC_GRANT → kTCCServiceSystemPolicyAllFiles
- That also have CAN_INJECT_INTO edges pointing to them
- Return: app name, path, injection method, team_id
- Order by number of injection methods (most injectable first)

### Query 2: Shortest Path to FDA
Create `graph/queries/02-shortest-path-to-fda.cypher`:
```
// Name: Shortest Attack Path to Full Disk Access
// Purpose: From the attacker_payload node, find the shortest chain to FDA
// Attack: Multi-hop privilege escalation through injection + TCC inheritance
// Severity: Critical
```
- Start from attacker_payload Application node
- Find shortest path (max depth 5) to TCC_Permission kTCCServiceSystemPolicyAllFiles
- Return the full path with all intermediate nodes and relationship types
- Limit to top 10 shortest paths

### Query 3: Electron TCC Inheritance Map
Create `graph/queries/03-electron-tcc-inheritance.cypher`:
```
// Name: Electron App TCC Permission Inheritance
// Purpose: Map which Electron apps pass TCC permissions to child processes
// Attack: ELECTRON_RUN_AS_NODE → child inherits parent's TCC grants
// Severity: High
```
- Find all Electron apps with TCC grants
- Return: app name, list of inherited permissions, injection methods available
- Order by number of permissions inherited (most permissive first)

### Query 4: Private Entitlement Audit
Create `graph/queries/04-private-entitlement-audit.cypher`:
```
// Name: Private Apple Entitlement Audit
// Purpose: Find third-party apps with private Apple entitlements (high-value targets)
// Attack: Private entitlements grant elevated privileges not available to normal apps
// Severity: High
```
- Find non-system Applications with private Entitlements (is_private: true)
- Return: app name, bundle_id, list of private entitlements, whether injectable
- Exclude Apple system apps (is_system: true) — they're expected to have private entitlements

### Query 5: Apple Event TCC Cascade
Create `graph/queries/05-appleevent-tcc-cascade.cypher`:
```
// Name: Apple Event TCC Permission Cascade
// Purpose: Find apps that gain TCC access transitively via Apple Event automation
// Attack: App A automates App B → App A gains App B's TCC permissions
// Severity: High
```
- Find chains: App A → CAN_SEND_APPLE_EVENT → App B → HAS_TCC_GRANT → Permission
- Where App A does NOT have direct HAS_TCC_GRANT to that Permission
- Return: source app, target app, permission gained, whether source is injectable

### Additional Queries (bonus, if time permits)

Create `graph/queries/06-injection-chain.cypher`:
```
// Name: Multi-hop Injection Chain
// Purpose: Find chains of injectable apps leading to high-value permissions
```

Create `graph/queries/07-tcc-grant-overview.cypher`:
```
// Name: TCC Grant Overview (Blue Team)
// Purpose: Summary of all TCC grants — useful for security audits
```
- Count grants per permission type
- List apps with the most TCC permissions
- Identify MDM-managed vs user-granted permissions

### Documentation
Create `graph/queries/README.md`:
- Table of all queries with: name, purpose, severity, prerequisites
- Instructions for running queries in Neo4j Browser
- Example output for each query (can be placeholder until tested on real data)

### Validation
- Run each query on the graph populated from real scan data
- Document actual results: "On my Mac, Query 1 finds N injectable FDA apps: ..."
- If a query returns zero results: that's useful info too — document why
- Save example outputs to `graph/queries/examples/`

## Acceptance Criteria

- [ ] 5 `.cypher` files exist in `graph/queries/` with proper comment headers
- [ ] Each query is syntactically valid Cypher (no parse errors in Neo4j Browser)
- [ ] Each query returns results on real scan data (or documents why not)
- [ ] `graph/queries/README.md` documents all queries with purpose and severity
- [ ] At least one query finds a real, non-trivial attack path
- [ ] Queries use parameterized patterns where applicable
- [ ] Blue team query (07) provides an audit-style overview
- [ ] Example outputs documented in `graph/queries/examples/`

## If Stuck

After 10 iterations:
- If queries return no results: the graph may be missing data. Check import worked correctly.
  Verify node counts: `MATCH (n) RETURN labels(n), count(n)`
- If shortestPath is slow: add explicit depth limit `[*..4]`
- If no injectable apps found: that's actually a good security posture — document it as a finding

When ALL acceptance criteria are met, output:
<promise>PHASE_2_4_COMPLETE</promise>
