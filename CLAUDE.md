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

**Current phase:** Phase 1 — Collector PoC
**Focus:** Building the Swift CLI collector that extracts TCC databases, app entitlements,
and code signing metadata from a macOS endpoint and outputs structured JSON.

## Repository Layout

> Items marked *(planned)* do not exist yet. They will be created as each phase begins.

```
rootstock/
├── CLAUDE.md                 # ← You are here. Start with this file.
├── AGENTS.md                 # Role definitions for Claude Code tasks
├── ARCHITECTURE.md           # System architecture and component boundaries
├── ROADMAP.md                # Full development roadmap (6 phases, 24 weeks)
├── README.md                 # Public-facing project README (planned)
├── LICENSE                   # GPLv3 (planned)
│
├── collector/                # Swift-based macOS collector (planned — Phase 1)
│   ├── Package.swift
│   └── Sources/
│       ├── CLI/              # Command-line interface entry point
│       ├── TCC/              # TCC database parser
│       ├── Entitlements/     # codesign / entitlement extraction
│       ├── CodeSigning/      # Hardened runtime, library validation checks
│       ├── XPC/              # XPC service enumeration
│       ├── Keychain/         # Keychain ACL metadata reader
│       ├── Models/           # Shared data models (Codable structs)
│       └── Export/           # JSON serialization
│
├── graph/                    # Python-based Neo4j import, inference, query engine & API
│   ├── import.py             # Scan JSON → Neo4j importer
│   ├── infer.py              # Inference engine orchestrator (13 modules)
│   ├── server.py             # FastAPI REST API server
│   ├── models.py             # Graph node/edge type definitions
│   ├── queries/              # Pre-built Cypher queries (76 .cypher files)
│   ├── viewer_template.html  # Interactive Canvas-based graph viewer
│   ├── pipeline.sh           # One-command pipeline (schema → import → infer → classify → report)
│   └── requirements.txt
│
├── docs/                     # Harness engineering documentation
│   ├── design-docs/          # Architecture decisions and rationale
│   ├── exec-plans/           # Execution plans for phases
│   ├── research/             # macOS security research notes
│   ├── references/           # LLM-optimized reference material
│   └── product-specs/        # Feature specifications
│
├── ralph-prompts/            # Phase-based execution prompts for ralph-loop
│
└── tests/                    # (planned — Phase 1+)
    ├── fixtures/             # Sample TCC.db, entitlement plists, etc.
    └── collector/            # Swift test targets
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

1. **Starting a task:** Read CLAUDE.md (this file), then AGENTS.md for the role, then
   the relevant exec-plan in `docs/exec-plans/active/`.
2. **Architecture questions:** See ARCHITECTURE.md and `docs/design-docs/`.
3. **macOS internals:** See `docs/research/` and `docs/references/`.
4. **What to build next:** See `docs/exec-plans/active/` for current phase plans.
5. **Quality checks:** See `docs/QUALITY.md` for standards and review criteria.

## Critical Context

- **Target macOS version:** Sonoma 14+ (primary), Sequoia 15+ (secondary)
- **SIP considerations:** System TCC.db requires Full Disk Access; user TCC.db is readable
  without elevation. Design the collector to degrade gracefully.
- **Apple changes things:** TCC, entitlements, and security mechanisms change with every
  major macOS release. The collector must abstract data sources behind protocols/interfaces
  to isolate version-specific logic.
- **Academic context:** This is a university research project. All code must be clearly
  attributable, well-documented, and reproducible.
