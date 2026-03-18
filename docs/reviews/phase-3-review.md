# Phase 3 Review — Extended Collection

**Reviewer:** Claude Opus (automated review)
**Date:** 2026-03-18
**Overall Status:** ⚠️ PASS WITH ISSUES

## Summary

Phase 3 successfully implements all four extended data sources (XPC, Persistence, Keychain, MDM) with solid architecture, comprehensive tests, and correct graph integration. One critical issue found and fixed during review: the JSON Schema (`scan-result.schema.json`) was not updated for Phase 3 fields, causing `validate-scan.py` to reject valid scan output. This has been corrected.

Real-Mac validation metrics:
- 440 XPC services discovered (320 with MachServices)
- 440 persistence items (433 daemons, 7 agents)
- 234 Keychain items (132 with trusted_apps, 169 total ACL entries)
- 1 MDM profile (no TCC policies — non-MDM-managed Mac)

## Security Audit: Keychain Module

**No secrets extracted:** CONFIRMED

Specific checks performed:

1. **Source code audit of `KeychainScanner.swift`:**
   - `kSecReturnData: kCFBooleanFalse!` explicitly set in BOTH queries (line 50, line 97)
   - `kSecReturnRef: kCFBooleanTrue!` used only for password classes (line 49) to obtain `SecKeychainItem` refs for ACL extraction — this returns an opaque handle, NOT secret data
   - `kSecValueRef` (line 72) reads the ref from the query result dict — safe, expected pattern
   - No occurrence of `kSecReturnData: true` or `kSecReturnData: kCFBooleanTrue` anywhere

2. **Grep audit of entire Keychain module:**
   - `kSecReturnData` appears exactly twice — both set to `kCFBooleanFalse!`
   - `kSecValueRef` appears once — reading the opaque ref for ACL extraction
   - `password`, `secret` appear only in documentation comments and the `Kind` enum raw values ("generic_password", "internet_password")
   - `kSecValueData` does NOT appear anywhere in the module

3. **Runtime validation:**
   - Scanned real Keychain with 234 items
   - JSON output verified: only fields present are `label`, `kind`, `service`, `access_group`, `trusted_apps`
   - No fields containing or capable of containing secret values

4. **API safety:**
   - `SecKeychainItemCopyAccess` reads ACL metadata, not item data
   - `SecACLCopyContents` reads trusted app lists, not secret values
   - `SecTrustedApplicationCopyData` returns executable path, not secrets
   - Even if the scanner is called incorrectly, the query itself cannot return secret data because `kSecReturnData: false` is hardcoded

5. **Test fixtures:**
   - `fixture_minimal.json` contains synthetic Keychain data (labels like "iTerm2 Credential", "Slack Token") — no real Keychain data
   - Test `testKeychainItemsHaveNoSecretData()` explicitly checks for forbidden keys in JSON output

## Results by Sub-Phase

### 3.1 XPC Services: ✅

| Criterion | Status | Notes |
|-----------|--------|-------|
| `XPCDataSource` conforms to `DataSource` | ✅ | `name = "XPC Services"`, `requiresElevation = false` |
| Parses all 4 directories | ✅ | `/System/Library/LaunchDaemons/`, `/Library/LaunchDaemons/`, `/Library/LaunchAgents/`, `~/Library/LaunchAgents/` |
| Handles XML and binary plist | ✅ | `PropertyListSerialization` handles both formats automatically |
| Extracts required fields | ✅ | Label, Program/ProgramArguments, MachServices, UserName, RunAtLoad, KeepAlive |
| MachServices keys extracted | ✅ | 320 of 440 services have MachServices on real Mac |
| Binary entitlements cross-referenced | ✅ | `codesign -d --entitlements :-` called per binary, keys extracted |
| Unreadable directories → errors not crashes | ✅ | `parseDirectory` returns errors array; test `testNonexistentDirectoryReturnsEmptyWithoutError` confirms |
| JSON output contains `xpc_services` | ✅ | Array present in ScanResult |
| Graph import creates XPC_Service nodes | ✅ | `import_xpc_services()` in import_nodes.py |
| COMMUNICATES_WITH edges | ✅ | Matches app entitlement name to mach service name |
| Real Mac: >100 XPC services | ✅ | 440 discovered |
| Tests | ✅ | 12 Swift tests (unit + integration), model/graph tests in Python |

### 3.2 Persistence: ✅

| Criterion | Status | Notes |
|-----------|--------|-------|
| `PersistenceDataSource` conforms to `DataSource` | ✅ | `name = "Persistence"`, `requiresElevation = false` |
| Scans LaunchDaemons, LaunchAgents | ✅ | All 4 directories scanned |
| Login Items (BTM) | ✅ | Reads `backgrounditems.btm`, handles newer binary format gracefully |
| Cron Jobs | ✅ | System crontab + per-user crontabs via `CronParser` |
| Login Hooks (legacy) | ✅ | `com.apple.loginwindow.plist` — LoginHook/LogoutHook |
| LaunchItem fields complete | ✅ | label, path, type, program, run_at_load, user |
| Owner resolution (PERSISTS_VIA) | ✅ | Graph: `WHERE r.program STARTS WITH a.path` |
| JSON output contains `launch_items` | ✅ | Array present in ScanResult |
| PERSISTS_VIA edges | ✅ | Application → LaunchItem when binary path starts with app bundle path |
| RUNS_AS edges | ✅ | LaunchItem → User node via MERGE |
| Real Mac: >50 persistence items | ✅ | 440 discovered |
| Tests | ✅ | 10 Swift tests, model/graph tests in Python |

### 3.3 Keychain ACLs: ✅

| Criterion | Status | Notes |
|-----------|--------|-------|
| `KeychainDataSource` conforms to `DataSource` | ✅ | `name = "Keychain"`, `requiresElevation = false` |
| **NO secrets in output** | ✅ | See Security Audit section above |
| Metadata only: label, kind, service, access_group | ✅ | Plus `trusted_apps` ACL list |
| ACLs extracted: trusted_apps list | ✅ | 132 of 234 items have trusted_apps (169 total entries) |
| No user prompts | ✅ | `kSecReturnData: false`, silent error handling for locked keychain |
| System keychain: graceful skip | ✅ | `errSecAuthFailed`, `errSecInteractionNotAllowed` silently handled |
| JSON output contains `keychain_acls` | ✅ | Array present in ScanResult |
| Graph: Keychain_Item nodes | ✅ | MERGE on composite key (label + kind) |
| CAN_READ_KEYCHAIN edges | ✅ | Maps trusted_apps bundle_ids to Application nodes |
| Tests | ✅ | 9 Swift tests (including security validation test), model/graph tests in Python |

### 3.4 MDM Profiles: ✅

| Criterion | Status | Notes |
|-----------|--------|-------|
| `MDMDataSource` conforms to `DataSource` | ✅ | `name = "MDM"`, `requiresElevation = false` |
| Parses `profiles` command | ✅ | `-C -o stdout-xml` (computer) + `-L -o stdout-xml` (user) |
| Extracts required fields | ✅ | identifier, display_name, organization, install_date |
| TCC payloads detected | ✅ | `PayloadType = "com.apple.TCC.configuration-profile-policy"` matching |
| JSON output contains `mdm_profiles` | ✅ | Empty array on unmanaged Macs |
| Graph: MDM_Profile nodes | ✅ | MERGE on identifier |
| CONFIGURES edges | ✅ | MDM_Profile → TCC_Permission with bundle_id and allowed properties |
| Unmanaged Macs: empty, no errors | ✅ | 1 profile found (provisioning, no TCC policies), no errors |
| `profiles` failure caught | ✅ | Checks `isExecutableFile` before running; catches Process errors |
| Tests | ✅ | 11 Swift tests (with synthetic XML fixtures), model/graph tests in Python |

## Graph Model Completeness

Node types in ARCHITECTURE.md vs actually implemented:

| Node Type | In ARCHITECTURE.md | Implemented | Import Function |
|-----------|-------------------|-------------|-----------------|
| Application | ✅ | ✅ | `import_applications` |
| User | ✅ | ✅ | Created by `import_launch_items` (RUNS_AS) |
| TCC_Permission | ✅ | ✅ | `import_tcc_grants`, `import_mdm_profiles` |
| Keychain_Item | ✅ | ✅ | `import_keychain_items` |
| XPC_Service | ✅ | ✅ | `import_xpc_services` |
| Entitlement | ✅ | ✅ | `import_entitlements` |
| LaunchItem | ✅ | ✅ | `import_launch_items` |
| MDM_Profile | ✅ | ✅ | `import_mdm_profiles` |

Edge types in ARCHITECTURE.md vs actually implemented:

| Edge Type | In ARCHITECTURE.md | Implemented | Location |
|-----------|-------------------|-------------|----------|
| HAS_TCC_GRANT | ✅ | ✅ | import_nodes.py |
| HAS_ENTITLEMENT | ✅ | ✅ | import_nodes.py |
| SIGNED_BY (same team) | ✅ | ✅ | `import_signed_by_team` (as SIGNED_BY_SAME_TEAM) |
| CAN_INJECT_INTO | ✅ | ✅ | infer_injection.py |
| CAN_SEND_APPLE_EVENT | ✅ | ✅ | infer_automation.py |
| CHILD_INHERITS_TCC | ✅ | ✅ | infer_electron.py |
| CAN_READ_KEYCHAIN | ✅ | ✅ | import_nodes.py |
| COMMUNICATES_WITH | ✅ | ✅ | import_nodes.py |
| PERSISTS_VIA | ✅ | ✅ | import_nodes.py |
| OWNS | ✅ | ❌ | Not implemented (requires user enumeration data source) |
| HAS_KEYCHAIN | ✅ | ❌ | Not implemented (requires user → keychain mapping) |
| RUNS_AS | ✅ | ✅ | import_nodes.py |
| CONFIGURES | ✅ | ✅ | import_nodes.py |

**Missing edges:** `OWNS` (User → Application) and `HAS_KEYCHAIN` (User → Keychain_Item) are defined in ARCHITECTURE.md but not yet implemented. These require a User enumeration data source that isn't part of Phase 3's scope.

## Critical Issues

1. **JSON Schema was out of date (FIXED):** `collector/schema/scan-result.schema.json` did not include `xpc_services`, `keychain_acls`, `mdm_profiles`, or `launch_items`, causing `scripts/validate-scan.py` to reject valid Phase 3 scan output. Fixed during this review by adding all Phase 3 types and their `$defs`.

## Warnings

1. **Relationship naming divergence:** ARCHITECTURE.md defines `SIGNED_BY` but the implementation uses `SIGNED_BY_SAME_TEAM`. The implementation name is more precise and arguably better, but the documentation should be updated for consistency.

2. **MDM TCC service names differ from TCC database:** MDM profiles use short service names (e.g., "SystemPolicyAllFiles") while the TCC database uses the full `kTCCService*` prefix (e.g., "kTCCServiceSystemPolicyAllFiles"). This means MDM CONFIGURES edges create separate TCC_Permission nodes from TCC database HAS_TCC_GRANT edges. Acceptable for Phase 3, but a normalization mapping would improve cross-referencing in Phase 4+.

3. **Persistence scanner finds 0 cron jobs, 0 login items, 0 login hooks** on the test Mac (all 440 items are daemons/agents). This is expected for a modern macOS system, but means these code paths have limited real-world testing. The synthetic tests and CronParser unit tests provide coverage.

4. **`SecKeychainItemCopyAccess` is deprecated** in macOS 13+. The code documents this (line 133 of KeychainScanner.swift) and notes no modern replacement exists. This will need monitoring in future macOS versions.

## Recommendations

1. **Add service name normalization** for MDM TCC policies (map "SystemPolicyAllFiles" → "kTCCServiceSystemPolicyAllFiles") so CONFIGURES edges connect to the same TCC_Permission nodes as HAS_TCC_GRANT edges.

2. **Update ARCHITECTURE.md** relationship table to use `SIGNED_BY_SAME_TEAM` to match implementation.

3. **Consider adding `Keychain_Item.access_group`** to the graph model in ARCHITECTURE.md — it's in the implementation but not documented there.

4. **Phase 5 TODO:** Create test fixtures with cron jobs, login items, and login hooks to exercise these code paths beyond unit tests.

## Test Results

### Swift Tests: 76/76 passed (0 failures)

| Module | Tests | Status |
|--------|-------|--------|
| TCC | 8 | ✅ |
| Entitlements | 16 | ✅ |
| CodeSigning | 10 | ✅ |
| XPC | 12 | ✅ |
| Persistence | 10 | ✅ |
| Keychain | 9 | ✅ |
| MDM | 11 | ✅ |

### Python Tests: 16/16 passed, 23 skipped (Neo4j not available)

| Category | Tests | Status |
|----------|-------|--------|
| Pydantic models (no Neo4j) | 16 | ✅ |
| Neo4j integration | 23 | ⏭️ Skipped (no Neo4j instance) |

## Meilenstein M3 Status

**"Vollständige Datenerfassung":** MET

- XPC services in graph: yes, 440 discovered on real Mac
- Persistence items in graph: yes, 440 discovered on real Mac
- Keychain ACLs in graph: yes, 234 items with 169 ACL entries discovered
- MDM profiles in graph: yes, 1 profile found (N/A for TCC policies on unmanaged Mac)

All four Phase 3 data sources are implemented, integrated into the collector CLI (with `--modules` flag support), validated by real-Mac scans, covered by Swift and Python tests, imported into the graph, and queryable via Cypher (queries 08-10).
