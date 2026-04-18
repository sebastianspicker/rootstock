# CLAUDE.md — Project Intelligence for Rootstock

> This file is the primary entry point for Claude Code and Claude-assisted development.
> It contains project context, conventions, and pointers to deeper documentation.

## What is Rootstock?

Rootstock is a graph-based attack path discovery tool for macOS security boundaries.
It maps TCC grants, entitlements, Keychain ACLs, code signing metadata, and XPC services
as a directed property graph — enabling automated discovery of privilege escalation paths
that would be impossible to find manually.

Think: BloodHound for macOS-native security boundaries.

## Project Phase

**Current phase:** Post-Phase 7 — Hardening & Release Alignment
**Status:** All 7 phases complete + full-repo review. Collector has 26 data source modules,
graph pipeline has 17 inference engines, 101 Cypher queries, 31 node types, and 506 Python tests.
All subsystems at A-grade quality after systematic audit and improvement pass.

## Repository Layout

```
rootstock/
├── CLAUDE.md                 # ← You are here. Start with this file.
├── AGENTS.md                 # Role definitions for Claude Code tasks
├── ARCHITECTURE.md           # System architecture and component boundaries
├── ROADMAP.md                # Full development roadmap (7 phases)
├── README.md                 # Public-facing project README
│
├── collector/                # Swift-based macOS collector (26 modules)
│   ├── Package.swift
│   └── Sources/
│       ├── RootstockCLI/     # CLI entry point + ScanOrchestrator
│       ├── Models/           # Shared data models (30+ Codable structs)
│       ├── TCC/              # TCC database parser
│       ├── Entitlements/     # codesign / entitlement extraction
│       ├── CodeSigning/      # Hardened runtime, library validation, certificates
│       ├── XPCServices/      # XPC service enumeration
│       ├── Persistence/      # LaunchDaemon/Agent/LoginItem discovery
│       ├── Keychain/         # Keychain ACL metadata reader
│       ├── MDM/              # MDM profile + PPPC policy extraction
│       ├── Groups/           # Local groups + user details
│       ├── RemoteAccess/     # SSH, VNC, ARD service detection
│       ├── Firewall/         # Application firewall policy
│       ├── LoginSession/     # Active login sessions
│       ├── AuthorizationDB/  # Authorization rights database
│       ├── AuthorizationPlugins/ # Security agent plugins
│       ├── SystemExtensions/ # System/network extensions
│       ├── Sudoers/          # Sudoers NOPASSWD rules
│       ├── ProcessSnapshot/  # Running process enumeration
│       ├── FileACLs/         # Critical file ACL auditing
│       ├── ShellHooks/       # Shell config injection points
│       ├── PhysicalSecurity/ # Bluetooth, screen lock, Thunderbolt posture
│       ├── ActiveDirectory/  # AD binding + user/group discovery
│       ├── KerberosArtifacts/ # ccache, keytab, krb5.conf
│       ├── Sandbox/          # Sandbox profile deep parsing (SBPL rules)
│       ├── Quarantine/       # Gatekeeper quarantine xattr reader
│       └── Export/           # JSON serialization
│
├── graph/                    # Python-based Neo4j import, inference, query engine & API
│   ├── import.py             # Scan JSON → Neo4j importer (orchestrator)
│   ├── import_nodes_core.py  # Core node imports (apps, TCC, entitlements, certs)
│   ├── import_nodes_services.py   # Services (XPC, persistence, keychain)
│   ├── import_nodes_security.py   # Security nodes (groups, firewall, auth, sudoers)
│   ├── import_nodes_security_enterprise.py  # Enterprise (AD, Kerberos, process, file ACL)
│   ├── import_nodes_enrichment.py # Enrichment (physical, iCloud, bluetooth)
│   ├── import_vulnerabilities.py  # CVE/ATT&CK/ThreatGroup import + version matching
│   ├── infer.py              # Inference engine orchestrator (18 modules)
│   ├── infer_esf.py          # ESF event enrichment + monitoring gap analysis
│   ├── infer_risk_score.py   # Composite risk scoring engine (0-100 scale)
│   ├── infer_recommendations.py # Automated remediation recommendations
│   ├── server.py             # FastAPI REST API server
│   ├── models.py             # Pydantic v2 graph node/edge type definitions
│   ├── queries/              # Pre-built Cypher queries (101 .cypher files)
│   ├── bloodhound_import.py  # SharpHound ZIP → ADUser/SAME_IDENTITY import
│   ├── cve_reference.py      # CVE + ATT&CK + ThreatGroup registry
│   ├── cve_enrichment.py     # Live EPSS + KEV + NVD enrichment with caching
│   ├── version_matcher.py    # Version-aware CVE matching
│   ├── opengraph_export.py   # BloodHound OpenGraph JSON export
│   ├── viewer_template.html  # Interactive Canvas-based graph viewer
│   ├── pipeline.sh           # One-command pipeline (schema → import → infer → classify → report)
│   └── requirements.txt
│
├── docs/                     # Engineering documentation
│   ├── design-docs/          # Architecture decisions and rationale
│   ├── research/             # macOS security research notes
│   └── references/           # LLM-optimized reference material
│
└── examples/                 # Demo scan data + generation scripts
```

## Key Conventions

### Language & Style
- **Collector:** Swift 5.9+, structured concurrency where appropriate, no third-party deps
  unless absolutely necessary (goal: single static binary with no runtime dependencies)
- **Graph tools:** Python 3.10+, neo4j driver, minimal dependencies
- **Cypher queries:** One query per .cypher file, with a comment header explaining purpose
- **Documentation:** English, Markdown, concise

### Naming
- Swift: `UpperCamelCase` for types, `lowerCamelCase` for functions/variables
- Python: `snake_case` throughout, PEP 8
- Neo4j labels: `UpperCamelCase` (e.g., `Application`, `TCC_Permission`)
- Neo4j relationship types: `UPPER_SNAKE_CASE` (e.g., `HAS_TCC_GRANT`)
- Files: `kebab-case` for docs, language conventions for code

### Security Principles
- **Never extract secrets.** Rootstock reads metadata (ACLs, permissions, entitlements),
  never passwords, keys, or token values.
- **Minimal privileges.** The collector should work with the lowest possible permissions.
  Document clearly what requires elevation and why.
- **No network calls.** The collector is strictly local. It never phones home, uploads data,
  or contacts any remote service.

### Commit Messages
```
[component] brief description

component = collector | graph | queries | docs | harness | tests
example:  [collector] add TCC database parser for user-level db
```

## How to Use This Harness

1. **Starting a task:** Read CLAUDE.md (this file), then AGENTS.md for the role.
2. **Architecture questions:** See ARCHITECTURE.md and `docs/design-docs/`.
3. **macOS internals:** See `docs/research/` and `docs/references/`.
4. **Running the pipeline:** `cd graph && bash pipeline.sh <scan.json>`
5. **Running tests:** Swift: `cd collector && swift test` / Python: `cd graph && python3 -m pytest tests/`

## Critical Context

- **Target macOS version:** Sonoma 14+ (primary), Sequoia 15+ (secondary)
- **SIP considerations:** System TCC.db requires Full Disk Access; user TCC.db is readable
  without elevation. Design the collector to degrade gracefully.
- **Apple changes things:** TCC, entitlements, and security mechanisms change with every
  major macOS release. The collector must abstract data sources behind protocols/interfaces
  to isolate version-specific logic.
- **Academic context:** This is a university research project. All code must be clearly
  attributable, well-documented, and reproducible.
