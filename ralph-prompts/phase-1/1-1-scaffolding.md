You are the Collector Engineer agent for the Rootstock project.

## Context

Read these files first:
- CLAUDE.md (project overview and conventions)
- AGENTS.md (your role as Collector Engineer)
- ARCHITECTURE.md (component boundaries, DataSource protocol, output schema)

Rootstock is a macOS attack path discovery tool. You are building the Swift collector.

## Task: Phase 1.1 — Project Scaffolding & Toolchain

Create the Swift Package structure for the Rootstock collector.

### Step 1: Package.swift
Create `collector/Package.swift` with these targets:
- **RootstockCLI** (executable) — depends on all library targets
- **TCC** (library) — TCC database parsing
- **Entitlements** (library) — entitlement extraction
- **CodeSigning** (library) — code signing analysis
- **Models** (library) — shared data models, used by all other targets
- **Export** (library) — JSON serialization

Use swift-argument-parser (https://github.com/apple/swift-argument-parser, 1.3.0+)
as the ONLY external dependency. Everything else uses Foundation and system frameworks.
Minimum platform: macOS 14.

### Step 2: DataSource Protocol
In `collector/Sources/Models/DataSource.swift`, define:

```swift
import Foundation

/// A data source that collects security-relevant metadata from the local system.
protocol DataSource {
    /// Human-readable name for logging (e.g., "TCC Database")
    var name: String { get }

    /// Whether this source requires elevated privileges to collect fully
    var requiresElevation: Bool { get }

    /// Collect data from this source.
    /// Returns partial results on failure — never throws to abort the entire scan.
    func collect() async -> DataSourceResult
}

struct DataSourceResult {
    let nodes: [any GraphNode]
    let errors: [CollectionError]
}

struct CollectionError: Codable {
    let source: String
    let message: String
    let recoverable: Bool
}
```

### Step 3: Shared Models
In `collector/Sources/Models/`, create Codable structs matching ARCHITECTURE.md:
- `Application` (name, bundle_id, path, version, team_id, hardened_runtime, library_validation, is_electron, is_system, signed)
- `TCCGrant` (service, client, client_type, auth_value, auth_reason, scope)
- `EntitlementInfo` (name, is_private, category)
- `ScanResult` (scan_id, timestamp, hostname, macos_version, collector_version, elevation, applications, tcc_grants, errors)
- `GraphNode` protocol that all node types conform to

Make all structs Codable with CodingKeys using snake_case JSON keys.

### Step 4: CLI Entry Point
In `collector/Sources/RootstockCLI/RootstockCommand.swift`, create:
- Main command `rootstock-collector`
- `--output <path>` argument (required)
- `--verbose` flag (optional, default false)
- `--modules <tcc,entitlements,codesigning>` option (optional, default all)
- Version flag showing "rootstock-collector 0.1.0"
- On run: print "Rootstock Collector v0.1.0" and "Scanning..." then write an empty
  ScanResult to the output path as a placeholder

### Step 5: Build & Verify
- `swift build` completes with ZERO warnings
- `swift build -c release` produces a binary
- `.build/release/rootstock-collector --help` shows usage
- `.build/release/rootstock-collector --output /tmp/test.json` produces valid JSON

### Step 6: Git Setup
- `.gitignore` for Swift (`.build/`, `.swiftpm/`, `*.xcodeproj`, `DerivedData/`)
- Ensure `collector/` directory structure matches ARCHITECTURE.md

## Acceptance Criteria

Verify ALL of the following before completing:
- [ ] `cd collector && swift build` succeeds with zero warnings
- [ ] `swift build -c release` succeeds
- [ ] `.build/release/rootstock-collector --help` prints usage with --output, --verbose, --modules
- [ ] `.build/release/rootstock-collector --version` prints "rootstock-collector 0.1.0"
- [ ] `.build/release/rootstock-collector --output /tmp/test.json` creates valid JSON
- [ ] `/tmp/test.json` contains the ScanResult structure (scan_id, timestamp, empty arrays)
- [ ] `DataSource` protocol exists in Models/DataSource.swift
- [ ] All model structs (`Application`, `TCCGrant`, `EntitlementInfo`, `ScanResult`) are Codable
- [ ] No external dependencies except swift-argument-parser
- [ ] Package.swift has separate library targets for TCC, Entitlements, CodeSigning, Models, Export

## If Stuck

After 10 iterations without all criteria met:
1. Document what's blocking in `docs/exec-plans/tech-debt-tracker.md`
2. List exact compiler errors or test failures
3. If swift-argument-parser causes issues, fall back to manual CommandLine.arguments parsing
4. Emit the completion promise anyway with a note about remaining issues

When ALL acceptance criteria are met, output:
<promise>PHASE_1_1_COMPLETE</promise>
