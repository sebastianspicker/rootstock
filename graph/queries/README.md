# Rootstock Cypher Queries

These queries surface attack paths in the Rootstock Neo4j graph. Run them in the
Neo4j Browser (`http://localhost:7474`) or via `cypher-shell`.

## Prerequisites

Before running queries:
```bash
cd graph
docker compose up -d          # start Neo4j
python3 setup.py              # initialize schema + seed TCC nodes
python3 import.py --input scan.json  # import collector data
python3 infer.py              # compute inferred relationships
```

---

## Query Index

| # | File | Name | Severity | Purpose |
|---|---|---|---|---|
| 01 | `01-injectable-fda-apps.cypher` | Injectable FDA Apps | **Critical** | Apps with Full Disk Access that can be injected |
| 02 | `02-shortest-path-to-fda.cypher` | Shortest Path to FDA | **Critical** | Shortest attack chain from attacker node to Full Disk Access |
| 03 | `03-electron-tcc-inheritance.cypher` | Electron TCC Inheritance | **High** | Electron apps whose TCC grants are inheritable by child processes |
| 04 | `04-private-entitlement-audit.cypher` | Private Entitlement Audit | **High** | Third-party apps with private Apple entitlements |
| 05 | `05-appleevent-tcc-cascade.cypher` | Apple Event TCC Cascade | **High** | Apps that gain transitive TCC access via Apple Event automation |
| 06 | `06-injection-chain.cypher` | Multi-hop Injection Chain | **Critical** | Multi-hop paths: inject → escalate to critical permission |
| 07 | `07-tcc-grant-overview.cypher` | TCC Grant Overview | **Info** | Blue team audit: distribution of TCC grants across the system |

---

## Query Details

### 01 — Injectable Full Disk Access Apps

**File:** `01-injectable-fda-apps.cypher`
**Severity:** Critical
**Attack chain:** Inject dylib → inherit FDA → read/modify TCC.db → escalate

**What it finds:** Applications that have been granted Full Disk Access AND can be
injected with arbitrary code via DYLD injection or missing library validation.

**Interpretation:**
- Any result here is a critical finding.
- The injection methods indicate the exact technique an attacker would use.
- Apps without a team_id are platform binaries — usually not injectable in practice.

**Example output:** See `examples/01-injectable-fda-apps.md`

---

### 02 — Shortest Path to Full Disk Access

**File:** `02-shortest-path-to-fda.cypher`
**Severity:** Critical
**Attack chain:** attacker.payload → [any path] → Full Disk Access TCC_Permission

**What it finds:** The minimum number of hops from an attacker's initial foothold
(represented as the synthetic `attacker.payload` node) to Full Disk Access.

**Interpretation:**
- path_length = 2 means: inject directly into an FDA-holding app (1-hop escalation).
- path_length = 4 means: inject App A → A automates App B → B has FDA (multi-hop).
- Shorter paths = more critical findings.

**Note:** If shortestPath returns no results, no injectable path to FDA exists in
the scanned system. This is a positive finding — document it.

**Example output:** See `examples/02-shortest-path-to-fda.md`

---

### 03 — Electron TCC Inheritance Map

**File:** `03-electron-tcc-inheritance.cypher`
**Severity:** High
**Attack:** `ELECTRON_RUN_AS_NODE=1 /path/to/Electron.app/Contents/MacOS/app node-script.js`

**What it finds:** Electron apps with TCC grants whose child processes (spawned via
`ELECTRON_RUN_AS_NODE` or `--inspect` flag) inherit the parent's TCC permissions.

**Interpretation:**
- An Electron app with Microphone + Camera + Screen Recording is a high-value target.
- Even without injecting the app binary, an attacker can run Node.js code inside it
  using environment variables, inheriting all its TCC grants.

**Example output:** See `examples/03-electron-tcc-inheritance.md`

---

### 04 — Private Entitlement Audit

**File:** `04-private-entitlement-audit.cypher`
**Severity:** High

**What it finds:** Non-system applications that possess private Apple entitlements
(prefixed `com.apple.private.*`). These entitlements are reserved for Apple internal
use and grant elevated privileges not available through normal App Store APIs.

**Interpretation:**
- Third-party apps with private entitlements have been explicitly granted special
  access by Apple (usually enterprise/developer tools) or have bypassed app review.
- Injectable apps with private entitlements are critical: injection = privilege theft.

**Example output:** See `examples/04-private-entitlement-audit.md`

---

### 05 — Apple Event TCC Cascade

**File:** `05-appleevent-tcc-cascade.cypher`
**Severity:** High
**Attack:** App A → `CAN_SEND_APPLE_EVENT` → App B → invoke B's privileged action

**What it finds:** Apps that can send Apple Events to a more-privileged app, gaining
transitive access to that app's TCC permissions without holding them directly.

**Interpretation:**
- If App A (injectable, no TCC) can automate App B (has FDA), an attacker who injects
  App A can invoke App B via Apple Events to perform FDA-level operations.
- This is a common real-world technique for TCC bypass.

**Example output:** See `examples/05-appleevent-tcc-cascade.md`

---

### 06 — Multi-hop Injection Chain

**File:** `06-injection-chain.cypher`
**Severity:** Critical

**What it finds:** Chains where the attacker injects one or more apps in sequence,
ultimately reaching an app with a high-value TCC permission. Depth limited to 3 hops
to keep queries fast; increase `[*1..N]` for deeper searches.

**Example output:** See `examples/06-injection-chain.md`

---

### 07 — TCC Grant Overview (Blue Team)

**File:** `07-tcc-grant-overview.cypher`
**Severity:** Informational
**Use case:** Security audit, baseline establishment, anomaly detection

**What it finds:** Three views of TCC grant data:
1. Permission distribution — which permissions are most commonly granted
2. Most-permissioned apps — apps with the widest TCC access
3. Authorization reason — how each grant was established (user prompt, MDM, entitlement)

**Note:** This file contains 3 separate Cypher statements separated by `;`.
Run them individually in Neo4j Browser by pressing Ctrl+Enter on each block.

**Example output:** See `examples/07-tcc-grant-overview.md`

---

## Running Queries

### Neo4j Browser (recommended for visualization)

1. Open `http://localhost:7474`
2. Log in with `neo4j` / `rootstock`
3. Paste the query into the editor (⌘K to clear, ⌘Enter to run)
4. Switch between "Graph", "Table", and "Text" views in the results panel

### cypher-shell (command line)

```bash
# Run a single query file
cat graph/queries/01-injectable-fda-apps.cypher | \
  cypher-shell -u neo4j -p rootstock --format plain

# Or pipe via docker
cat graph/queries/01-injectable-fda-apps.cypher | \
  docker exec -i rootstock-neo4j cypher-shell -u neo4j -p rootstock
```

---

## Interpreting Zero Results

| Query | Zero results means |
|---|---|
| 01 | No injectable apps have FDA — strong security posture |
| 02 | No path exists from attacker to FDA — no injectable FDA apps |
| 03 | No Electron apps with TCC grants found |
| 04 | No third-party apps with private entitlements |
| 05 | No apps with Automation TCC grants found (or no valuable targets) |
| 06 | No multi-hop injection path to critical permissions |

Zero results on queries 01–02 is a **positive finding** worth documenting.
