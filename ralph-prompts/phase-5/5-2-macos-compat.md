You are the Collector Engineer agent for the Rootstock project.

## Context

Read: CLAUDE.md §Critical Context (target macOS versions), docs/research/tcc-internals.md,
docs/exec-plans/tech-debt-tracker.md, collector/Sources/TCC/

## Task: Phase 5.2 — Multi-macOS-Version-Kompatibilität

Ensure the collector works correctly across macOS 14 Sonoma, macOS 15 Sequoia, and ideally macOS 16 Tahoe.

### Step 1: Version Detection
Create or update `collector/Sources/Models/SystemInfo.swift`:
- Detect running macOS version programmatically:
  `ProcessInfo.processInfo.operatingSystemVersion` → (major, minor, patch)
- Expose as enum or struct: `.sonoma14`, `.sequoia15`, `.tahoe16`, `.unknown`
- Include version in scan output metadata

### Step 2: TCC Schema Differences
Research and document in `docs/research/tcc-version-diffs.md`:
- macOS 14 Sonoma: baseline TCC.db schema (what we built against in Phase 1.2)
- macOS 15 Sequoia: known changes:
  - Additional access restrictions on user-level TCC.db (may require TCC grant for our own app)
  - Possible new columns in access table
  - New TCC service identifiers
- macOS 16 Tahoe (if available): any known changes
- For each version: list new TCC services added, schema changes, access restrictions

### Step 3: Version-Specific Code Paths
Update collector modules with version-aware logic:
- `TCCDataSource`: handle different column sets in access table across versions
  Use `PRAGMA table_info(access)` to detect available columns before querying
- `EntitlementExtractor`: handle any API changes in Security.framework across versions
- `CodeSigningAnalyzer`: handle new code signing flags or entitlement categories
- Pattern: use protocol/strategy pattern, not `if macOS15 { } else { }`
  ```swift
  protocol TCCSchemaAdapter {
      func parseRow(_ row: [String: Any]) -> TCCGrant?
      var supportedColumns: [String] { get }
  }
  class SonomaTCCAdapter: TCCSchemaAdapter { ... }
  class SequoiaTCCAdapter: TCCSchemaAdapter { ... }
  ```

### Step 4: New TCC Services
Update `TCCServiceRegistry.swift`:
- Add any TCC services introduced in macOS 15/16 that aren't in our current list
- Mark each service with the minimum macOS version it exists on
- Handle unknown services gracefully (return raw identifier as display name)

### Step 5: Compatibility Testing
- [ ] Run collector on macOS 14 Sonoma → document results, any warnings
- [ ] Run collector on macOS 15 Sequoia → document results, differences from Sonoma
- [ ] If macOS 16 is available: run and document
- [ ] Compare JSON outputs: same structure? different grant counts? new services?
- [ ] Document all findings in `docs/research/tcc-version-diffs.md`

### Step 6: Compatibility Matrix
Update `README.md` with a compatibility matrix:

```markdown
| macOS Version | Collector | User TCC.db | System TCC.db | Notes |
|---|---|---|---|---|
| 14 Sonoma | ✅ Full | ✅ | ✅ (with FDA) | Primary development target |
| 15 Sequoia | ✅ Full | ⚠️ See note | ✅ (with FDA) | User DB may need TCC grant |
| 16 Tahoe | 🔄 Testing | TBD | TBD | |
| < 14 | ❌ | ❌ | ❌ | Not supported |
```

## Acceptance Criteria

- [ ] Version detection works correctly on the running macOS
- [ ] TCC parser uses version-aware schema adaptation (not hardcoded column assumptions)
- [ ] `docs/research/tcc-version-diffs.md` documents known differences
- [ ] New TCC services from macOS 15+ are in the registry
- [ ] Collector runs without crash on macOS 14 AND macOS 15
- [ ] Compatibility matrix exists in README
- [ ] Version-specific code paths are behind clean abstractions (protocol/strategy)
- [ ] Unknown TCC schema columns don't cause crashes (forward-compatible)

## If Stuck

After 10 iterations:
- If you only have one macOS version to test on: implement the abstractions anyway,
  document what's theoretically needed for other versions based on research
- If Sequoia TCC.db access is completely blocked: document the restriction clearly,
  note workarounds (e.g., granting FDA to the collector), add to README caveats
- If schema research is inconclusive: use PRAGMA-based dynamic column detection as
  the primary strategy — this handles any schema version without prior knowledge

When ALL acceptance criteria are met, output:
<promise>PHASE_5_2_COMPLETE</promise>
