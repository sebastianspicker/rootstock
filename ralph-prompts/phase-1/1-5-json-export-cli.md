You are the Collector Engineer agent for the Rootstock project.

## Context

Read: CLAUDE.md, ARCHITECTURE.md §Collector Output Schema, collector/Sources/ (all existing modules)

## Task: Phase 1.5 — JSON Export & CLI Integration

Wire all data source modules together into the CLI and produce the final JSON output.

### Step 1: Scan Orchestrator
Create `collector/Sources/Export/ScanOrchestrator.swift`:
- Accepts a list of `DataSource` instances and a configuration struct
- Runs each source sequentially (async), collects results and errors
- Merges application data: TCC grants are matched to applications by bundle_id/client
- Builds the final `ScanResult` with:
  - `scan_id`: UUID().uuidString
  - `timestamp`: ISO 8601 format
  - `hostname`: ProcessInfo.processInfo.hostName
  - `macos_version`: ProcessInfo.processInfo.operatingSystemVersionString
  - `collector_version`: "0.1.0"
  - `elevation.is_root`: getuid() == 0
  - `elevation.has_fda`: attempt to open system TCC.db → true if succeeds
- Stderr progress output: "[1/3] Collecting TCC grants...", "[2/3] Scanning entitlements...", etc.

### Step 2: JSON Serializer
Create `collector/Sources/Export/JSONExporter.swift`:
- Takes `ScanResult` → writes to file path
- JSONEncoder with `.prettyPrinted` and `.sortedKeys`
- Date encoding: `.iso8601`
- Key encoding: `.convertToSnakeCase`
- Validate: output is valid JSON (re-parse after writing as sanity check)

### Step 3: CLI Wiring
Update `collector/Sources/RootstockCLI/RootstockCommand.swift`:
- `--output <path>`: where to write JSON (required)
- `--verbose`: print additional detail to stderr
- `--modules <list>`: comma-separated module selection (tcc, entitlements, codesigning, all)
  Default: all
- Run flow:
  1. Print banner: "Rootstock Collector v0.1.0"
  2. Detect elevation status
  3. Initialize selected DataSources
  4. Run ScanOrchestrator
  5. Export JSON
  6. Print summary: "Scan complete. Found N apps, M TCC grants, K entitlements. Output: <path>"
  7. If errors occurred: print "⚠ N warnings — see 'errors' in output for details"

### Step 4: Error Aggregation
- Every module's errors are collected in the top-level `errors` array
- Each error has: source (module name), message, recoverable (bool)
- Non-recoverable errors (e.g., no apps found at all) should print a clear message

### Step 5: End-to-End Verification
- Run `swift build -c release`
- Run `.build/release/rootstock-collector --output /tmp/scan.json`
- Verify /tmp/scan.json is valid JSON with: scan_id, timestamp, applications, tcc_grants, errors
- Verify applications have entitlements and code signing data
- Verify tcc_grants have service names and auth status

## Acceptance Criteria

- [ ] `swift build -c release` succeeds
- [ ] `rootstock-collector --output /tmp/scan.json` runs to completion
- [ ] JSON output has all top-level fields: scan_id, timestamp, hostname, macos_version, collector_version, elevation, applications, tcc_grants, errors
- [ ] `applications` array is non-empty on a real Mac
- [ ] `tcc_grants` array is non-empty on a real Mac with any TCC grants
- [ ] Each application has entitlements array AND code signing metadata
- [ ] `--modules tcc` runs only TCC collection
- [ ] `--verbose` produces additional stderr output
- [ ] Stderr shows progress during scan
- [ ] Summary line prints counts of discovered items
- [ ] JSON is valid (parseable by `python3 -m json.tool /tmp/scan.json`)
- [ ] `errors` array exists (may be empty if no errors)

## If Stuck

After 12 iterations:
- If module wiring is complex: simplify by hardcoding the three DataSources instead
  of dynamic registration. Refactor to dynamic later.
- If async orchestration causes issues: use synchronous collection for MVP
- Document shortcuts in tech-debt-tracker.md

When ALL acceptance criteria are met, output:
<promise>PHASE_1_5_COMPLETE</promise>
