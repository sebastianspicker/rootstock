You are the Collector Engineer agent for the Rootstock project.

## Context

Read these files first:
- CLAUDE.md (conventions, security principles)
- ARCHITECTURE.md §DataSource protocol, §Collector Output Schema
- docs/research/tcc-internals.md (TCC database schema, auth_value meanings, service identifiers)
- collector/Sources/Models/ (existing model definitions from Phase 1.1)

## Task: Phase 1.2 — TCC Database Parser

Implement the TCC data source module that reads macOS TCC databases and returns structured grant data.

### Step 1: SQLite Wrapper
Create `collector/Sources/TCC/SQLiteDatabase.swift`:
- Thin wrapper around the C sqlite3 API (import `SQLite3` — it ships with macOS)
- `init(path: String) throws` — opens database in read-only mode with WAL journal
- `func query(_ sql: String) -> [[String: Any]]` — returns rows as dictionaries
- `deinit` — closes the database handle
- Handle locked databases gracefully (tccd might be writing)
- NO external SQLite dependencies — use the system library only

### Step 2: TCC Service Registry
Create `collector/Sources/TCC/TCCServiceRegistry.swift`:
- Static mapping of TCC service identifiers to display names:
  - `kTCCServiceSystemPolicyAllFiles` → "Full Disk Access"
  - `kTCCServiceAccessibility` → "Accessibility"
  - `kTCCServiceScreenCapture` → "Screen Recording"
  - `kTCCServiceMicrophone` → "Microphone"
  - `kTCCServiceCamera` → "Camera"
  - `kTCCServiceAppleEvents` → "Automation"
  - `kTCCServiceListenEvent` → "Input Monitoring"
  - `kTCCServiceSystemPolicyDesktopFolder` → "Desktop Folder"
  - `kTCCServiceSystemPolicyDocumentsFolder` → "Documents Folder"
  - `kTCCServiceSystemPolicyDownloadsFolder` → "Downloads Folder"
  - `kTCCServiceSystemPolicyRemovableVolumes` → "Removable Volumes"
  - `kTCCServiceSystemPolicyNetworkVolumes` → "Network Volumes"
  - `kTCCServiceEndpointSecurityClient` → "Endpoint Security"
  - (include at least 15 services total, handle unknown services gracefully)
- `static func displayName(for service: String) -> String`

### Step 3: TCC Data Source
Create `collector/Sources/TCC/TCCDataSource.swift`:
- Conforms to `DataSource` protocol
- `requiresElevation`: false (user DB works without elevation)
- `collect()` does:
  1. Read user-level TCC.db at `~/Library/Application Support/com.apple.TCC/TCC.db`
  2. Attempt system-level TCC.db at `/Library/Application Support/com.apple.TCC/TCC.db`
     - If access denied → log error in `errors`, continue with user DB only
  3. Parse `access` table: extract service, client, client_type, auth_value, auth_reason, last_modified
  4. Map auth_value: 0=denied, 2=allowed, 3=limited (skip auth_value=1/unknown)
  5. Map auth_reason: 1=user_prompt, 2=user_settings, 3=entitlement, 4=mdm, 5=system
  6. Create `TCCGrant` objects with scope ("user" or "system")
  7. Return `DataSourceResult` with grants and any errors

### Step 4: Integration
- Register `TCCDataSource` in the CLI runner (wherever DataSources are orchestrated)
- When the collector runs with `--modules tcc`, only this source is invoked
- TCC grants appear in the JSON output under the `tcc_grants` array

### Step 5: Testing
- Create `tests/fixtures/test-tcc.db` — a synthetic SQLite database with the TCC schema
  and 5–10 sample entries (mix of allowed, denied, different services, user vs system scope)
- Write unit test: parse the fixture DB → verify correct TCCGrant objects
- Write unit test: nonexistent DB path → returns empty results with error, no crash
- Write unit test: verify service display name mapping for all registered services

## Acceptance Criteria

- [ ] `swift build` succeeds with zero warnings
- [ ] `TCCDataSource` conforms to `DataSource` protocol
- [ ] Running collector produces JSON with `tcc_grants` array
- [ ] Each grant has: service, display_name, client, client_type, auth_value, auth_reason, scope, last_modified
- [ ] User TCC.db is successfully parsed (on a real Mac, this should return >0 grants)
- [ ] System TCC.db failure is caught gracefully → error in `errors` array, no crash
- [ ] Unknown TCC services get a fallback display name (e.g., the raw service string)
- [ ] Unit tests pass for fixture DB parsing
- [ ] Unit test passes for missing DB path (graceful failure)
- [ ] SQLite wrapper uses read-only mode and WAL journal mode

## If Stuck

After 15 iterations:
- If SQLite3 import causes issues: the module name on macOS is `SQLite3` (capital S)
- If TCC.db is not readable even as user: check if macOS version has new restrictions,
  document in tech-debt-tracker.md and use a fixture-only approach for now
- If WAL mode causes locking issues: try opening with `SQLITE_OPEN_READONLY` flag only
- Document blockers in `docs/exec-plans/tech-debt-tracker.md`

When ALL acceptance criteria are met, output:
<promise>PHASE_1_2_COMPLETE</promise>
