# ARCHITECTURE.md — System Architecture

## Overview

Rootstock is a three-stage pipeline:

```
┌─────────────────────────────────────────────────────────────────┐
│                        macOS Endpoint                           │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              Collector (Swift CLI)                     │      │
│  │                                                       │      │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────┐           │      │
│  │  │ TCC      │ │ Entitle- │ │ CodeSign   │           │      │
│  │  │ Parser   │ │ ments    │ │ Analyzer   │           │      │
│  │  └────┬─────┘ └────┬─────┘ └─────┬──────┘           │      │
│  │       │             │             │                   │      │
│  │  ┌────┴─────┐ ┌────┴─────┐ ┌─────┴──────┐           │      │
│  │  │ XPC      │ │ Keychain │ │ Persistence│           │      │
│  │  │ Enum     │ │ ACLs     │ │ Scanner    │           │      │
│  │  └────┬─────┘ └────┬─────┘ └─────┬──────┘           │      │
│  │       │             │             │                   │      │
│  │       └─────────────┼─────────────┘                   │      │
│  │                     ▼                                 │      │
│  │              ┌──────────────┐                         │      │
│  │              │ JSON Export  │                         │      │
│  │              └──────┬───────┘                         │      │
│  └─────────────────────┼────────────────────────────────┘      │
│                        │                                        │
└────────────────────────┼────────────────────────────────────────┘
                         │  scan.json
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Analysis Workstation                          │
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐                        │
│  │ Graph Import │ ──▶  │   Neo4j      │                        │
│  │ (Python)     │      │   Database   │                        │
│  └──────────────┘      └──────┬───────┘                        │
│                               │                                 │
│                        ┌──────┴───────┐                        │
│                        │ Query Engine │                        │
│                        │ (Cypher)     │                        │
│                        └──────┬───────┘                        │
│                               │                                 │
│                        ┌──────┴───────┐                        │
│                        │ Visualizer   │                        │
│                        │ (Neo4j UI /  │                        │
│                        │  Custom)     │                        │
│                        └──────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

## Design Principle: Separation of Collection and Analysis

The collector runs on the target macOS endpoint. The analysis runs elsewhere.
This separation is intentional:

- **Security:** The collector has minimal footprint and no network dependencies.
- **Portability:** The JSON output can be analyzed on any machine with Neo4j.
- **Reproducibility:** Scan results are static artifacts that can be shared, compared,
  and version-controlled.
- **Multi-host:** Multiple scans from different endpoints can be ingested into the same
  graph to discover cross-host attack paths (future work).

---

## Component: Collector

### Responsibility
Extract security-relevant metadata from the local macOS system and serialize it as JSON.

### Language & Build
- **Language:** Swift 5.9+
- **Build system:** Swift Package Manager
- **Target:** Single static binary, no runtime dependencies beyond macOS system frameworks
- **Entry point:** `collector/Sources/CLI/main.swift`

### Module Boundaries

Each data source is an independent module behind a `DataSource` protocol:

```swift
protocol DataSource {
    /// Human-readable name for logging
    var name: String { get }

    /// Whether this source requires elevated privileges
    var requiresElevation: Bool { get }

    /// Collect data. Returns partial results on failure (graceful degradation).
    func collect() async throws -> [GraphNode]
}
```

This abstraction serves three purposes:
1. **Graceful degradation:** If the collector lacks FDA, TCC system DB collection fails
   but everything else still works. Each module reports its own success/failure.
2. **Testability:** Modules can be tested independently with fixture data.
3. **Extensibility:** New data sources (MDM profiles, ESF events, etc.) plug in without
   modifying existing code.

### Data Sources — Priority Order

| Priority | Module | Data Source | Requires Elevation? |
|----------|--------|-------------|---------------------|
| P0 | TCC | User TCC.db (`~/Library/Application Support/com.apple.TCC/TCC.db`) | No |
| P0 | TCC | System TCC.db (`/Library/Application Support/com.apple.TCC/TCC.db`) | Yes (FDA) |
| P0 | Entitlements | `codesign -d --entitlements` for all installed apps | No |
| P0 | CodeSigning | Hardened runtime, library validation, team ID per app | No |
| P1 | Persistence | LaunchDaemons, LaunchAgents, login items | Partial |
| P1 | XPC | XPC service plists and Mach port configurations | No |
| P2 | Keychain | Keychain item ACLs (metadata only, no secrets) | Partial |
| P2 | MDM | Installed configuration profiles | No |

P0 = Phase 1 (MVP), P1 = Phase 2, P2 = Phase 3

---

## Component: Graph Import

### Responsibility
Parse collector JSON, validate it, and create/update nodes and relationships in Neo4j.

### Language & Dependencies
- **Language:** Python 3.10+
- **Dependencies:** `neo4j` (official driver), `pydantic` (validation)

### Import Behavior
- **Idempotent:** Re-importing the same scan updates existing nodes (MERGE, not CREATE).
- **Scan-tagged:** Each import is tagged with a scan ID and timestamp, enabling
  comparison of before/after states.
- **Relationship inference:** Some relationships are explicit in the JSON (e.g., app → TCC
  grant). Others are inferred during import (e.g., `CAN_INJECT_INTO` is computed by
  checking whether target app lacks hardened runtime + library validation).

---

## Graph Model

### Node Types

```
Application {
    name: String            // e.g., "iTerm"
    bundle_id: String       // e.g., "com.googlecode.iterm2"
    path: String            // e.g., "/Applications/iTerm.app"
    version: String?
    team_id: String?        // Code signing team identifier
    hardened_runtime: Bool
    library_validation: Bool
    is_electron: Bool       // Heuristic: contains Electron framework
    is_system: Bool         // Located in /System/ or /usr/
    signed: Bool
    scan_id: String         // Which scan produced this node
}

User {
    name: String
    uid: Int
    is_admin: Bool
    home: String
    type: String            // "local" | "network" | "mobile"
}

TCC_Permission {
    service: String         // e.g., "kTCCServiceSystemPolicyAllFiles"
    display_name: String    // e.g., "Full Disk Access"
    scope: String           // "user" | "system"
}

Keychain_Item {
    label: String           // Metadata only
    kind: String            // "generic_password" | "internet_password" | "certificate" | "key"
    service: String?
    // NO secret values — ever
}

XPC_Service {
    label: String           // e.g., "com.apple.diskarbitrationd"
    path: String            // Path to plist
    program: String         // Executable path
    user: String?           // RunAtLoad user
    type: String            // "daemon" | "agent"
}

Entitlement {
    name: String            // e.g., "com.apple.private.tcc.allow"
    is_private: Bool        // com.apple.private.* prefix
    category: String        // "tcc" | "security" | "sandbox" | "other"
}

LaunchItem {
    label: String
    path: String
    type: String            // "daemon" | "agent" | "login_item"
    program: String
    run_at_load: Bool
}

MDM_Profile {
    identifier: String
    display_name: String
    organization: String?
    install_date: String?
}
```

### Relationship Types

```
(Application)-[:HAS_TCC_GRANT {allowed: Bool, auth_reason: String?}]->(TCC_Permission)
(Application)-[:HAS_ENTITLEMENT]->(Entitlement)
(Application)-[:SIGNED_BY {team_id: String}]->(Application)  // Same team
(Application)-[:CAN_INJECT_INTO {method: String}]->(Application)
    // method: "dylib_hijack" | "dyld_insert" | "electron_env" | "missing_library_validation"
(Application)-[:CAN_SEND_APPLE_EVENT]->(Application)
(Application)-[:CHILD_INHERITS_TCC]->(Application)
(Application)-[:CAN_READ_KEYCHAIN]->(Keychain_Item)
(Application)-[:COMMUNICATES_WITH]->(XPC_Service)
(Application)-[:PERSISTS_VIA]->(LaunchItem)
(User)-[:OWNS]->(Application)
(User)-[:HAS_KEYCHAIN]->(Keychain_Item)
(LaunchItem)-[:RUNS_AS]->(User)
(MDM_Profile)-[:CONFIGURES]->(TCC_Permission)  // MDM-managed TCC policies
```

### Inferred Relationships (computed at import time)

These relationships don't exist in the raw collector JSON but are derived:

| Relationship | Inference Rule |
|---|---|
| `CAN_INJECT_INTO` | Target app has `library_validation = false` AND (`hardened_runtime = false` OR has `com.apple.security.cs.allow-dyld-environment-variables` entitlement) |
| `CHILD_INHERITS_TCC` | Source app is Electron-based AND has TCC grants (children spawned via `ELECTRON_RUN_AS_NODE` inherit parent TCC) |
| `CAN_SEND_APPLE_EVENT` | Source app has `com.apple.private.tcc.allow` with `kTCCServiceAppleEvents` OR has explicit TCC grant for automation |

---

## Collector Output Schema (JSON)

```json
{
    "scan_id": "uuid",
    "timestamp": "ISO-8601",
    "hostname": "string",
    "macos_version": "14.5",
    "collector_version": "0.1.0",
    "elevation": {
        "is_root": false,
        "has_fda": false
    },
    "applications": [ /* Application objects */ ],
    "tcc_grants": [ /* TCC grant objects */ ],
    "xpc_services": [ /* XPC service objects */ ],
    "keychain_acls": [ /* Keychain ACL objects */ ],
    "launch_items": [ /* LaunchItem objects */ ],
    "mdm_profiles": [ /* MDM profile objects */ ],
    "users": [ /* User objects */ ],
    "errors": [ /* Per-module error reports */ ]
}
```

See `docs/design-docs/collector-output-schema.md` for the full JSON Schema definition.

---

## Real-World Example

A scan on a typical developer Mac (macOS 26.3 Tahoe, arm64) produces the following graph:

### Scan Statistics

| Metric | Value |
|---|---|
| Applications discovered | 184 |
| Signed applications | 180 (98%) |
| Hardened runtime enabled | 123 (67%) |
| Electron apps | 10 (5%) |
| Entitlements extracted | 3,841 |
| XPC services enumerated | 440 |
| Keychain items (metadata) | 234 |
| Launch items (daemons/agents) | 440 |
| MDM profiles | 1 |
| Injectable applications | 89 (48%) |
| TCC grants | 0 (no FDA — see Note) |
| JSON output size | ~1 MB |
| Scan time | 5.3 seconds |
| Peak memory | ~45 MB |

> **Note:** TCC grants require Full Disk Access on macOS 15+. Without FDA, the TCC module
> returns zero grants. With FDA or root, a typical Mac shows 10–50 TCC grants.

### Graph Size (Estimated with TCC)

A typical graph produced from a 184-app scan with TCC grants would contain:

- **~190 Application nodes** (one per discovered app)
- **~20 TCC_Permission nodes** (unique services like FDA, Camera, Microphone)
- **~200 Entitlement nodes** (unique entitlement names from 3,841 app→entitlement pairs)
- **~440 XPC_Service nodes**
- **~234 Keychain_Item nodes**
- **~440 LaunchItem nodes**
- **~3,841 HAS_ENTITLEMENT edges** (app → entitlement)
- **~30–100 CAN_INJECT_INTO edges** (inferred from missing hardened runtime / library validation)
- **~10 CHILD_INHERITS_TCC edges** (Electron apps with TCC grants)
- **~50 COMMUNICATES_WITH edges** (apps referencing XPC mach services via entitlements)

### Example Attack Path

```
(Slack.app)
  -[:HAS_ENTITLEMENT]-> (com.apple.security.cs.allow-dyld-environment-variables)
  # Slack is Electron-based, has allow-dyld entitlement

(Attacker)
  -[:CAN_INJECT_INTO {method: "dyld_insert"}]-> (Slack.app)
  # Slack lacks library validation, allowing DYLD_INSERT_LIBRARIES injection

(Slack.app)
  -[:HAS_TCC_GRANT {allowed: true}]-> (Microphone)
  # If Slack has microphone access, an injected dylib inherits it
```

This three-hop path shows how a DYLD injection into Slack could inherit its TCC microphone
grant — a real attack pattern that Rootstock surfaces automatically.

---

## Design Decisions

| Decision | Rationale | Reference |
|---|---|---|
| Swift for collector | Single static binary, no runtime deps, direct access to Security.framework and macOS APIs | `docs/design-docs/` |
| DataSource protocol | Graceful degradation (each module fails independently), testability, extensibility | §Component: Collector |
| JSON intermediate format | Portable, human-readable, version-controllable; decouples collection from analysis | §Design Principle |
| PRAGMA-based schema detection | Forward-compatible with future macOS TCC changes; avoids hardcoded column assumptions | `docs/research/tcc-version-diffs.md` |
| MERGE (not CREATE) in Neo4j | Idempotent re-imports; safe to re-scan and re-import without duplicates | §Component: Graph Import |
| Inferred relationships | Cross-boundary attack paths (injection, inheritance) can't be read from a single data source — they emerge from correlating multiple sources | §Inferred Relationships |
| Bounded parallelism (max 8) | Prevents overwhelming Security.framework with concurrent code signing queries | `collector/Sources/Entitlements/EntitlementDataSource.swift` |
