# Rootstock Cypher Queries

These queries surface attack paths in the Rootstock Neo4j graph. Run them with the
`query_runner.py` CLI, in the Neo4j Browser (`http://localhost:7474`), or via `cypher-shell`.

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

## Quick Start (CLI)

```bash
# List all 23 queries with category and severity
python3 query_runner.py --list

# Run a single query
python3 query_runner.py --run 01

# Run with a parameter
python3 query_runner.py --run 17 --param min_permissions=5

# Run all queries and export CSV
python3 query_runner.py --run all --format csv > results.csv
```

---

## Query Index

### Red Team — Attack Path Discovery

| # | File | Name | Severity | Parameters |
|---|------|------|----------|------------|
| 01 | `01-injectable-fda-apps.cypher` | Injectable FDA Apps | **Critical** | none |
| 02 | `02-shortest-path-to-fda.cypher` | Shortest Path to FDA | **Critical** | none |
| 03 | `03-electron-tcc-inheritance.cypher` | Electron TCC Inheritance | **High** | none |
| 04 | `04-private-entitlement-audit.cypher` | Private Entitlement Audit | **High** | none |
| 05 | `05-appleevent-tcc-cascade.cypher` | Apple Event TCC Cascade | **High** | none |
| 06 | `06-injection-chain.cypher` | Multi-hop Injection Chain | **Critical** | none |
| 11 | `11-multi-hop-injection-chain.cypher` | Multi-hop Injection + Apple Event | **Critical** | `$target_service` |
| 12 | `12-tcc-db-write-path.cypher` | TCC Database Write Path | **Critical** | none |
| 13 | `13-keychain-via-injection.cypher` | Keychain Access via Injection | **Critical** | none |
| 14 | `14-persistence-as-root.cypher` | Persistent Root Exec via Injection | **Critical** | none |
| 15 | `15-xpc-privilege-escalation.cypher` | XPC Privilege Escalation | **High** | none |

### Blue Team — Security Audit

| # | File | Name | Severity | Parameters |
|---|------|------|----------|------------|
| 07 | `07-tcc-grant-overview.cypher` | TCC Grant Overview | **Info** | none |
| 08 | `08-persistence-audit.cypher` | Persistence Audit | **High** | none |
| 09 | `09-keychain-acl-audit.cypher` | Keychain ACL Audit | **High** | none |
| 10 | `10-mdm-managed-tcc.cypher` | MDM-Managed TCC Permissions | **Info** | none |
| 16 | `16-tcc-grant-audit.cypher` | Full TCC Grant Inventory | **Info** | `$scope` |
| 17 | `17-overprivileged-apps.cypher` | Over-privileged Applications | **High** | `$min_permissions` |
| 18 | `18-unsigned-or-unhardened-with-grants.cypher` | Unsigned/Unhardened with Grants | **High** | none |
| 19 | `19-stale-tcc-grants.cypher` | Stale TCC Grants | **High** | none |
| 20 | `20-mdm-vs-user-grants.cypher` | MDM vs User Grants Comparison | **Info** | none |

### Forensic — Investigation & Mapping

| # | File | Name | Severity | Parameters |
|---|------|------|----------|------------|
| 21 | `21-high-value-targets.cypher` | High-Value Target Ranking | **Info** | none |
| 22 | `22-trust-boundary-map.cypher` | Trust Boundary Map | **Info** | `$app_name` |
| 23 | `23-full-attack-surface.cypher` | Full Attack Surface Map | **Info** | none |

---

## Query Details

### 01 — Injectable Full Disk Access Apps

**File:** `01-injectable-fda-apps.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack chain:** Inject dylib → inherit FDA → read/modify TCC.db → escalate

**What it finds:** Applications that have been granted Full Disk Access AND can be
injected with arbitrary code via DYLD injection or missing library validation.

**Interpretation:**
- Any result here is a critical finding.
- The `injection_methods` column shows the exact technique an attacker would use.
- Apps without a `team_id` are platform binaries — usually not injectable in practice.

---

### 02 — Shortest Path to Full Disk Access

**File:** `02-shortest-path-to-fda.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack chain:** `attacker.payload` → [any path] → Full Disk Access `TCC_Permission`

**What it finds:** The minimum number of hops from an attacker's initial foothold
(represented as the synthetic `attacker.payload` node) to Full Disk Access.

**Interpretation:**
- `path_length = 2` means inject directly into an FDA-holding app (1-hop escalation).
- `path_length = 4` means inject App A → A automates App B → B has FDA (multi-hop).
- Shorter paths = more critical findings.

**Note:** No results = no injectable path to FDA exists on the scanned system. This is a positive finding worth documenting.

---

### 03 — Electron TCC Inheritance Map

**File:** `03-electron-tcc-inheritance.cypher` | **Category:** Red Team | **Severity:** High

**Attack:** `ELECTRON_RUN_AS_NODE=1 /path/to/Electron.app/Contents/MacOS/app node-script.js`

**What it finds:** Electron apps with TCC grants whose child processes (spawned via
`ELECTRON_RUN_AS_NODE` or `--inspect` flag) inherit the parent's TCC permissions.

**Interpretation:** An attacker can run Node.js code inside an Electron app without
injecting the binary, inheriting all its TCC grants via `CHILD_INHERITS_TCC`.

---

### 04 — Private Entitlement Audit

**File:** `04-private-entitlement-audit.cypher` | **Category:** Red Team | **Severity:** High

**What it finds:** Non-system applications that possess private Apple entitlements
(`com.apple.private.*`). These grant elevated privileges reserved for Apple internal use.

**Interpretation:** Third-party apps with private entitlements have been explicitly granted
special access (enterprise/developer tools) or bypassed App Store review. Injectable apps
with private entitlements are critical: injection = privilege theft.

---

### 05 — Apple Event TCC Cascade

**File:** `05-appleevent-tcc-cascade.cypher` | **Category:** Red Team | **Severity:** High

**Attack:** App A → `CAN_SEND_APPLE_EVENT` → App B → invoke B's privileged action

**What it finds:** Apps that can send Apple Events to a more-privileged app, gaining
transitive access to that app's TCC permissions without holding them directly.

**Interpretation:** If App A (injectable, no TCC) can automate App B (has FDA), injecting
App A lets an attacker invoke App B via Apple Events to perform FDA-level operations.
Common real-world TCC bypass technique.

---

### 06 — Multi-hop Injection Chain

**File:** `06-injection-chain.cypher` | **Category:** Red Team | **Severity:** Critical

**What it finds:** Chains where the attacker injects one or more apps in sequence,
ultimately reaching an app with a high-value TCC permission. Depth limited to 3 hops;
increase `[*1..N]` for deeper searches.

---

### 07 — TCC Grant Overview (Blue Team)

**File:** `07-tcc-grant-overview.cypher` | **Category:** Blue Team | **Severity:** Informational

**What it finds:** Three views of TCC grant data (3 separate Cypher statements):
1. Permission distribution — which permissions are most commonly granted
2. Most-permissioned apps — apps with the widest TCC access
3. Authorization reason — how each grant was established (user, MDM, entitlement)

**Note:** Contains 3 Cypher statements separated by `;`. Run each block individually
in Neo4j Browser (Ctrl+Enter per block), or use `query_runner.py` (runs first block).

---

### 08 — Persistence Audit

**File:** `08-persistence-audit.cypher` | **Category:** Blue Team | **Severity:** High

**What it finds:** Third-party LaunchDaemons and LaunchAgents that run as root OR are
associated with an injectable application. An attacker who injects into a persistence
item's parent app gains persistent code execution as root.

**Interpretation:** `runs_as_root=true` + `app_is_injectable=true` is the worst case.

---

### 09 — Keychain ACL Audit

**File:** `09-keychain-acl-audit.cypher` | **Category:** Blue Team | **Severity:** High

**What it finds:** Applications explicitly listed in Keychain item ACLs — meaning those
apps can read the stored credential without prompting the user.

**Interpretation:** Injectable apps with `CAN_READ_KEYCHAIN` are silent credential theft
vectors. Prioritize results where `app_is_injectable = true`.

---

### 10 — MDM-Managed TCC Permissions

**File:** `10-mdm-managed-tcc.cypher` | **Category:** Blue Team | **Severity:** Informational

**What it finds:** TCC permissions enforced via MDM configuration profiles.
MDM grants cannot be revoked by the user and take precedence over manual settings.

**Interpretation:** Injectable apps with MDM-granted TCC permissions are particularly
dangerous — injecting them inherits silently-granted access without any user prompt.

---

### 11 — Multi-hop Injection + Apple Event Privilege Escalation

**File:** `11-multi-hop-injection-chain.cypher` | **Category:** Red Team | **Severity:** Critical

**Parameters:** `$target_service` (default: `kTCCServiceSystemPolicyAllFiles`)

**Attack:** Inject App A → App A automates App B (Apple Event) → App B has `$target_service`

**What it finds:** Two-step attack chains combining injection with Apple Event automation.
Broader than query 06 — finds paths where the mid-hop uses automation rather than injection.
Use `--param target_service=kTCCServiceScreenCapture` to hunt different target permissions.

---

### 12 — TCC Database Write Path (Complete TCC Takeover)

**File:** `12-tcc-db-write-path.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack:** Inject FDA app → write TCC.db → grant arbitrary permissions to any app

**What it finds:** Injectable apps with Full Disk Access. FDA means write access to
the user-level TCC.db (and with additional escalation, the system-level one).

**Interpretation:** Any result is a total TCC takeover vector. An attacker who injects
one of these apps can grant themselves any TCC permission on the system.

---

### 13 — Keychain Credential Access via Injection

**File:** `13-keychain-via-injection.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack:** Inject app → inherit `CAN_READ_KEYCHAIN` → extract credentials silently

**What it finds:** Injectable applications that hold silent Keychain read access.
Requires Phase 3.3 (Keychain ACL scanner) data.

**Interpretation:** These apps are credential theft vectors. Injecting the process
gives the attacker all secrets accessible by that app's ACL entry.

---

### 14 — Persistent Root Code Execution via Injectable Apps

**File:** `14-persistence-as-root.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack:** Inject app → LaunchDaemon runs injected code as root on every boot

**What it finds:** Apps registered as LaunchDaemons running as root where the app
itself is injectable. Requires Phase 3.2 (persistence scanner) data.

**Interpretation:** Results here are persistent root backdoor vectors — not just
one-time escalation, but code that re-executes as root on every system startup.

---

### 15 — XPC Service Privilege Escalation

**File:** `15-xpc-privilege-escalation.cypher` | **Category:** Red Team | **Severity:** High

**Attack:** Inject client app → call XPC service → XPC inherits entitlements to caller

**What it finds:** XPC services with elevated entitlements reachable via
`COMMUNICATES_WITH` from injectable applications. Requires Phase 3.1 (XPC) data.

---

### 16 — Full TCC Grant Inventory

**File:** `16-tcc-grant-audit.cypher` | **Category:** Blue Team | **Severity:** Informational

**Parameters:** `$scope` (optional: `user` or `system`, default: all)

**What it finds:** Complete audit of all TCC grants — service name, app, bundle ID,
grant type (user/MDM/entitlement), and approximate grant age.

**Use case:** Baseline establishment before a policy change, compliance reporting,
or identifying grants that predate a known security incident.

---

### 17 — Over-privileged Applications

**File:** `17-overprivileged-apps.cypher` | **Category:** Blue Team | **Severity:** High

**Parameters:** `$min_permissions` (default: `3`) — minimum distinct TCC services to flag

**What it finds:** Apps holding more TCC permissions than the specified threshold.
Results include the full permission list and injectability status.

**Interpretation:** High permission counts + injectable = priority remediation target.
Use `--param min_permissions=5` for a tighter filter in large environments.

---

### 18 — Unsigned or Unhardened Apps with TCC Grants

**File:** `18-unsigned-or-unhardened-with-grants.cypher` | **Category:** Blue Team | **Severity:** High

**What it finds:** Apps that have been granted TCC permissions but lack basic code
signing protections (unsigned, missing hardened runtime, or disabled library validation).

**Interpretation:** These apps represent grants made to principals that can be trivially
hijacked. Any TCC grant to an unsigned or unhardened app should be reviewed and revoked.

---

### 19 — Stale TCC Grants (Orphaned Permissions)

**File:** `19-stale-tcc-grants.cypher` | **Category:** Blue Team | **Severity:** High

**What it finds:** TCC grants referencing bundle IDs for which no installed Application
node exists in the graph. These are grants for uninstalled apps — leftover attack surface.

**Interpretation:** Stale grants can be exploited by an attacker who re-installs
an application using the same bundle ID, inheriting the existing TCC grants instantly.

---

### 20 — MDM-Managed vs User-Granted TCC Comparison

**File:** `20-mdm-vs-user-grants.cypher` | **Category:** Blue Team | **Severity:** Informational

**What it finds:** Side-by-side breakdown of MDM-enforced grants vs user-granted TCC
permissions. Useful for compliance validation: are production grants consistent with
what MDM policy dictates?

---

### 21 — High-Value Target Ranking (Attack Value Score)

**File:** `21-high-value-targets.cypher` | **Category:** Forensic | **Severity:** Informational

**What it finds:** All applications ranked by weighted attack value score:
- `tcc_count × 10` — base TCC surface (each allowed grant = +10)
- `+ injectability × 50` — injectable process flag (+50 if injectable)
- `+ private_ent_count × 20` — private entitlement bonus (+20 per entitlement)
- `+ keychain_count × 30` — Keychain ACL entries (+30 per item)
- `+ daemon_count × 40` — persistence bonus (+40 per LaunchDaemon)

**Use case:** Prioritize hardening effort; focus on highest-scored apps first.

---

### 22 — Trust Boundary Map

**File:** `22-trust-boundary-map.cypher` | **Category:** Forensic | **Severity:** Informational

**Parameters:** `$app_name` (optional) — filter to a single app's trust relationships

**What it finds:** All trust relationships between applications:
- Same team ID (code-signing trust chain)
- Apple Event automation targets (`CAN_SEND_APPLE_EVENT`)
- XPC communication peers (`COMMUNICATES_WITH`)
- Injection vectors (`CAN_INJECT_INTO`)

**Use case:** Blast-radius analysis — given one compromised app, what can an attacker reach?

---

### 23 — Full Attack Surface Map

**File:** `23-full-attack-surface.cypher` | **Category:** Forensic | **Severity:** Informational

**What it finds:** Every inferred attack edge in the graph using `UNION ALL` across
all relationship types (`CAN_INJECT_INTO`, `CHILD_INHERITS_TCC`, `CAN_SEND_APPLE_EVENT`,
`COMMUNICATES_WITH`, `CAN_READ_KEYCHAIN`). Complete enumeration of the attack surface.

**Use case:** Full export for offline analysis, or input to external graph tools.
Pipe to `--format csv` and load into Gephi or similar for visual exploration.

---

## Running Queries

### query_runner.py (recommended)

```bash
# List all queries with category/severity colour coding
python3 query_runner.py --list

# Run a specific query (table output)
python3 query_runner.py --run 01

# Run with parameters
python3 query_runner.py --run 17 --param min_permissions=5
python3 query_runner.py --run 11 --param target_service=kTCCServiceScreenCapture

# Output formats
python3 query_runner.py --run 21 --format json
python3 query_runner.py --run 23 --format csv > attack-surface.csv

# Run all queries
python3 query_runner.py --run all

# Custom Neo4j connection
python3 query_runner.py --neo4j bolt://host:7687 --user neo4j --password mypass --run 01
```

### Neo4j Browser (recommended for visualization)

1. Open `http://localhost:7474`
2. Log in with `neo4j` / `rootstock`
3. Load the Browser Guide: `:play http://localhost:8001/rootstock-guide.html`
4. Apply the GraSS stylesheet from `browser/rootstock-style.grass`
5. Paste a query into the editor (⌘K to clear, ⌘Enter to run)

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
| 01, 12 | No injectable apps have FDA — strong security posture |
| 02 | No attack path from attacker node to FDA exists |
| 03 | No Electron apps with TCC grants found |
| 04 | No third-party apps with private entitlements |
| 05, 11 | No Apple Event + TCC cascade found |
| 06 | No multi-hop injection path to critical permissions |
| 13 | No injectable apps hold Keychain ACL entries |
| 14 | No injectable apps linked to root LaunchDaemons |
| 15 | No injectable apps reach privileged XPC services |
| 19 | No stale grants for uninstalled apps — clean TCC state |

Zero results on queries 01, 02, 06, 12, 13, 14 are **positive findings** worth documenting
in your security report.
