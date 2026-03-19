# rootstock

[![Build](https://github.com/[org]/rootstock/actions/workflows/test.yml/badge.svg)](https://github.com/[org]/rootstock/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![macOS 14+](https://img.shields.io/badge/macOS-14%2B-brightgreen)](https://support.apple.com/macos)

Attack path discovery for macOS that maps TCC grants, entitlements, Keychain ACLs, and XPC trust relationships as an exploitable graph.

> **Status:** Phase 5 Complete — Collector + Graph Pipeline + Hardening. Scans macOS apps, extracts entitlements and code signing metadata, imports into Neo4j, and discovers attack paths via pre-built Cypher queries.

## What is Rootstock?

Rootstock is a graph-based attack path discovery tool for macOS security boundaries — think BloodHound for macOS-native trust relationships. It maps:

- **TCC grants** — which apps have camera, microphone, full disk access, etc.
- **Entitlements** — code-signing privileges that weaken security boundaries
- **Code signing** — hardened runtime, library validation, team identifiers
- **Injection vectors** — per-app assessment of DYLD injection viability

## Quick Start

### Requirements

- macOS 14 (Sonoma) or later
- Swift 5.9+ (Xcode 15+)

### Build

```bash
cd collector
swift build -c release
```

### Run

```bash
# Full scan (TCC + entitlements + code signing)
.build/release/rootstock-collector --output scan.json

# Verbose progress output
.build/release/rootstock-collector --output scan.json --verbose

# TCC grants only
.build/release/rootstock-collector --output scan.json --modules tcc

# Entitlements + code signing only (no TCC)
.build/release/rootstock-collector --output scan.json --modules entitlements,codesigning

# With Full Disk Access (reads system TCC.db)
sudo .build/release/rootstock-collector --output scan.json
```

### Validate Output

```bash
python3 scripts/validate-scan.py scan.json
# ✓ Valid: scan.json (184 apps, 12 TCC grants, 3841 entitlements, 0 collection errors)
```

### Example Output

```json
{
  "scan_id": "7D7DFA2B-...",
  "timestamp": "2026-03-18T08:00:00Z",
  "hostname": "my-mac.local",
  "macos_version": "Version 15.0 (Build 26A...",
  "collector_version": "0.1.0",
  "elevation": {
    "is_root": false,
    "has_fda": false
  },
  "applications": [
    {
      "name": "1Password",
      "bundle_id": "com.1password.1password",
      "path": "/Applications/1Password.app",
      "version": "8.10.56",
      "team_id": "2BUA8C4S2C",
      "hardened_runtime": true,
      "library_validation": true,
      "is_electron": true,
      "is_system": false,
      "signed": true,
      "entitlements": [
        {
          "name": "com.apple.security.cs.allow-jit",
          "is_private": false,
          "category": "injection",
          "is_security_critical": true
        }
      ],
      "injection_methods": ["electron_env_var"]
    }
  ],
  "tcc_grants": [],
  "errors": []
}
```

## Performance

Benchmarked on macOS 26.3 Tahoe (arm64), 184 apps, release build:

| Metric | Value |
|--------|-------|
| Total scan time | 5.6 seconds (average of 3 runs) |
| Apps scanned | 184 |
| Entitlements extracted | 3,841 |
| XPC services enumerated | 440 |
| Keychain items | 234 |
| Peak memory | ~45 MB |
| JSON output size | ~1 MB |

Per-module timing (via `--verbose`):

```
[TCC]          0.00s   [Entitlements] 0.15s   [CodeSigning]  0.21s
[XPC]          4.83s   [Persistence]  0.01s   [Keychain]     0.06s
[MDM]          0.02s   Total: 5.28s
```

See `docs/benchmarks/baseline.md` for full benchmark methodology and results.

## macOS Compatibility

| macOS Version | Collector | User TCC.db | System TCC.db | Notes |
|---|---|---|---|---|
| 14 Sonoma | ✅ Full | ✅ Normal read | ✅ Requires FDA | Primary development target |
| 15 Sequoia | ✅ Full | ⚠️ Requires FDA | ✅ Requires FDA | Kernel-enforced; grant FDA or use sudo |
| 26 Tahoe | ✅ Full | ⚠️ Requires FDA | ✅ Requires FDA | Year-based versioning (2025 release) — tested on 26.3 |
| < 14 | ❌ | ❌ | ❌ | Not supported |

> **Apple switched to year-based macOS versioning in 2025.** macOS 26 ("Tahoe") was formerly planned as "macOS 16". `ProcessInfo.majorVersion` returns 26 on Tahoe.

## Notes on TCC Collection

macOS 15+ requires Full Disk Access to read TCC databases. Without FDA:
- User TCC.db: blocked at kernel level (`SQLITE_AUTH`)
- System TCC.db: blocked at kernel level

Run with `sudo` or grant FDA to the binary to collect TCC grants. See `docs/research/tcc-version-diffs.md` for full details and `docs/exec-plans/tech-debt-tracker.md` TD-004 for the tech-debt entry.

## Project Structure

```
collector/                 Swift CLI collector
├── Sources/
│   ├── Models/            Shared data models + MacOSVersion detection
│   ├── TCC/               TCC database parser (version-aware schema adapters)
│   ├── Entitlements/      App discovery + entitlement extraction (parallelized)
│   ├── CodeSigning/       Code signing analysis + injection assessment
│   ├── XPCServices/       XPC service enumeration
│   ├── Keychain/          Keychain ACL metadata reader
│   ├── Persistence/       LaunchDaemons/Agents/crontab scanner
│   ├── MDM/               MDM configuration profile parser
│   ├── Export/            JSON serialization
│   └── RootstockCLI/      CLI entry point + scan orchestration
├── Tests/                 Unit tests (100 tests across 8 modules)
└── schema/                JSON Schema for output validation

graph/                     Neo4j import + Cypher queries
├── import.py              JSON → Neo4j graph importer (UNWIND-batched)
├── infer.py               Relationship inference engine
├── report.py              Markdown report generator
├── queries/               23 pre-built Cypher queries (4 severity levels)
└── tests/                 87 Python tests

scripts/
├── validate-scan.py       Output validation script
└── benchmark.sh           Performance benchmark runner

docs/
├── THREAT_MODEL.md        Assumptions, limitations, ethical framework
├── benchmarks/            Performance measurements
├── research/              macOS security research notes
└── paper/                 Academic paper skeleton + references
```

## Threat Model

Rootstock is a passive, read-only analysis tool. It does not extract secrets, make network
calls, or execute attacks. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full
threat model, including assumptions, limitations, BloodHound comparison, and ethical framework.

## Citing Rootstock

```bibtex
@software{rootstock2026,
  title   = {Rootstock: Graph-Based Attack Path Discovery for macOS Security Boundaries},
  author  = {[Author Names]},
  year    = {2026},
  url     = {https://github.com/[org]/rootstock},
  note    = {Open-source research tool, [University Name]}
}
```
