You are the Security Researcher agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §Graph Model, graph/queries/ (existing queries from Phase 2.4),
docs/research/tcc-internals.md, docs/research/entitlements-reference.md

## Task: Phase 4.3 — Interaktive Query-Bibliothek

Expand the query library to 20+ queries covering Red Team, Blue Team, and Forensic use cases,
with full documentation and a CLI query runner.

### Step 1: Red Team Queries (Attack Paths)
Add to `graph/queries/`:

- `10-multi-hop-injection-chain.cypher`
  Find chains: attacker → inject into App A → A can automate App B → B has FDA
  (multi-hop privilege escalation)

- `11-tcc-db-write-path.cypher`
  Find apps that can modify TCC.db itself (FDA + injectable → complete TCC takeover)

- `12-keychain-via-injection.cypher`
  Find injectable apps that can read high-value Keychain items (Phase 3.3 data)

- `13-persistence-as-root.cypher`
  Find injectable apps that persist as root via LaunchDaemons (Phase 3.2 data)

- `14-xpc-privilege-escalation.cypher`
  Find XPC services with elevated entitlements reachable from injectable apps (Phase 3.1 data)

### Step 2: Blue Team Queries (Audit & Compliance)
Add to `graph/queries/`:

- `15-tcc-grant-audit.cypher`
  Full TCC grant inventory: service, app, how granted (user/MDM/system), age

- `16-overprivileged-apps.cypher`
  Apps with more TCC permissions than typical (> 3 different services)

- `17-unsigned-or-unhardened-with-grants.cypher`
  Apps that have TCC grants but are unsigned or lack hardened runtime (immediate risk)

- `18-stale-tcc-grants.cypher`
  TCC grants for apps that are no longer installed (orphaned grants)

- `19-mdm-vs-user-grants.cypher`
  Compare MDM-managed TCC grants vs user-granted ones (enterprise compliance)

### Step 3: Forensic Queries
Add to `graph/queries/`:

- `20-high-value-targets.cypher`
  Rank all apps by "attack value": weighted score of TCC grants × injectability

- `21-trust-boundary-map.cypher`
  Visualize all trust boundaries: which apps trust which other apps (via same team, automation, etc.)

- `22-full-attack-surface.cypher`
  Return every inferred attack edge with source, target, method — the complete attack surface

### Step 4: Parameterized Queries
For queries that benefit from user input, use Cypher parameters:
- `$target_service` — e.g., 'kTCCServiceSystemPolicyAllFiles'
- `$app_name` — e.g., 'iTerm'
- `$team_id` — filter by signing team
- Document parameter usage in each query's comment header

### Step 5: Query Runner CLI
Create `graph/query_runner.py`:
- `python3 query_runner.py --neo4j bolt://... --list` → list all queries with names
- `python3 query_runner.py --neo4j bolt://... --run 01` → run query 01, print results as table
- `python3 query_runner.py --neo4j bolt://... --run all` → run all queries sequentially
- `python3 query_runner.py --neo4j bolt://... --run 02 --param target_service=kTCCServiceCamera`
- Output format: ASCII table (default), `--format json`, `--format csv`
- Parse query headers (Name, Purpose, Severity) from comment blocks in .cypher files

### Step 6: Query Library Documentation
Update `graph/queries/README.md`:
- Table of all queries: ID, Name, Category (Red/Blue/Forensic), Severity, Parameters
- For each query: purpose, example invocation, sample output
- "Getting Started" section: which queries to run first for each use case
- Cross-reference to Neo4j Browser Guide from Phase 4.2

## Acceptance Criteria

- [ ] At least 20 `.cypher` files exist in `graph/queries/`
- [ ] Queries cover all three categories: Red Team (5+), Blue Team (5+), Forensic (3+)
- [ ] Every query has a comment header with: Name, Purpose, Category, Severity, Parameters
- [ ] `query_runner.py --list` shows all queries with names and categories
- [ ] `query_runner.py --run <id>` executes a query and prints results as a table
- [ ] `query_runner.py --run all` runs all queries without error
- [ ] Parameterized queries work with `--param key=value`
- [ ] `graph/queries/README.md` documents all queries
- [ ] At least 3 queries use the Phase 3 data (XPC, Persistence, Keychain)
- [ ] JSON and CSV output formats work

## If Stuck

After 12 iterations:
- If some queries return no results: that's expected — not every graph has every attack path.
  The query should still be syntactically valid and documented.
- If the query runner CLI is complex: start with `--list` and `--run <id>` only, skip `--run all` and formats
- If Phase 3 data isn't in the graph yet: write the queries anyway with a note that they
  require Phase 3 data sources. They'll work once that data is imported.
- Focus on query quality over CLI features. The .cypher files are the real deliverable.

When ALL acceptance criteria are met, output:
<promise>PHASE_4_3_COMPLETE</promise>
