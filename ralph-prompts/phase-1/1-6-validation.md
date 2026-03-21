You are the Collector Engineer agent for the Rootstock project.

## Context

Read: CLAUDE.md, ARCHITECTURE.md §Collector Output Schema, the existing collector code

## Task: Phase 1.6 — Integration Testing & Validation

Validate the collector end-to-end on a real macOS system and create a JSON Schema for automated validation.

### Step 1: JSON Schema
Create `collector/schema/scan-result.schema.json`:
- Formal JSON Schema (draft 2020-12) for the ScanResult output
- All required fields marked as required
- Enum constraints for known values (auth_value, auth_reason, entitlement categories, injection methods)
- Validate: applications array items have the correct shape
- Validate: tcc_grants array items have the correct shape

### Step 2: Validation Script
Create `scripts/validate-scan.py`:
- Takes a scan JSON file path as argument
- Validates against the JSON Schema (use `jsonschema` library)
- Prints: "✓ Valid" or lists all validation errors
- Also performs semantic checks:
  - scan_id is a valid UUID
  - timestamp is valid ISO 8601
  - No duplicate bundle_ids in applications
  - All tcc_grant clients reference existing applications (where possible)
  - No empty strings in required fields
- Exit code 0 on valid, 1 on invalid

### Step 3: Real-System Test Runs
Run the collector in different configurations and document results:
- [ ] As normal user: `rootstock-collector --output /tmp/scan-user.json`
  → Document: how many apps, how many TCC grants, any errors?
- [ ] As root (sudo): `sudo rootstock-collector --output /tmp/scan-root.json`
  → Document: does system TCC.db get parsed? Additional grants visible?
- [ ] With module selection: `rootstock-collector --modules tcc --output /tmp/scan-tcc-only.json`
  → Document: only TCC grants, no entitlements or code signing
- [ ] Validate all outputs: `python3 scripts/validate-scan.py /tmp/scan-user.json`

### Step 4: Spot-Check Known Apps
Manually verify in the JSON output:
- Terminal.app: should have Full Disk Access TCC grant (if configured)
- Xcode.app: should have `com.apple.security.cs.debugger` entitlement
- Any Electron app (VS Code, Slack, Discord): should have `is_electron: true`
- System apps: should have `is_system: true`, `hardened_runtime: true`
- Document any discrepancies as issues in tech-debt-tracker.md

### Step 5: Performance Baseline
- Time the collector: `time rootstock-collector --output /tmp/scan.json`
- Document: total time, number of apps scanned, any bottlenecks
- Target: < 30 seconds for a typical Mac with ~100 apps
- If > 30 seconds: identify bottleneck (likely codesign per-app) and note in tech debt

### Step 6: Documentation Update
- Update README.md with actual example output (redacted if needed)
- Add a "Quick Start" section showing how to run the collector
- Move Phase 1 exec-plan from `active/` to `completed/` directory

## Acceptance Criteria

- [ ] JSON Schema exists at `collector/schema/scan-result.schema.json`
- [ ] `python3 scripts/validate-scan.py scan.json` validates successfully on real output
- [ ] Collector runs without crash as normal user
- [ ] Collector runs without crash as root
- [ ] `--modules` flag correctly limits collection
- [ ] At least 3 real-world scan outputs validated against schema
- [ ] Known apps spot-checked and results documented
- [ ] Performance measured and documented (total scan time)
- [ ] Scan completes in < 60 seconds (< 30 seconds preferred)
- [ ] No secrets or sensitive data in the JSON output (review manually)
- [ ] README updated with Quick Start section

## If Stuck

After 10 iterations:
- If jsonschema library install fails: write the schema file anyway, validate manually with an online tool
- If real-system tests reveal unexpected issues: document them thoroughly, they become Phase 2+ fixes
- Priority is documentation over perfection — capture what works and what doesn't

When ALL acceptance criteria are met, output:
<promise>PHASE_1_6_COMPLETE</promise>
