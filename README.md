# rootstock

Attack path discovery for macOS that maps TCC grants, entitlements, Keychain ACLs, and XPC trust relationships as an exploitable graph.

> **Status:** Phase 1 Complete — Collector PoC. Scans macOS apps, extracts entitlements and code signing metadata, and outputs structured JSON for graph ingestion.

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

On a typical Mac with ~180 apps:

| Metric | Value |
|--------|-------|
| Total scan time | ~0.7 seconds |
| Apps scanned | 184 |
| Entitlements extracted | 3,841 |
| Release binary size | ~2 MB |

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
collector/              Swift CLI collector
├── Sources/
│   ├── Models/         Shared data models
│   ├── TCC/            TCC database parser
│   ├── Entitlements/   App discovery + entitlement extraction
│   ├── CodeSigning/    Code signing analysis + injection assessment
│   ├── Export/         JSON serialization
│   └── RootstockCLI/   CLI entry point + scan orchestration
├── Tests/              Unit + integration tests
└── schema/             JSON Schema for output validation

scripts/
└── validate-scan.py    Output validation script

graph/                  (Phase 2) Neo4j import + Cypher queries
```
