You are a senior security engineer performing a thorough review of Phase 3 of the Rootstock project.

## Context

Read: CLAUDE.md, ARCHITECTURE.md (full graph model including XPC, LaunchItem, Keychain, MDM nodes),
ROADMAP.md §Phase 3, docs/QUALITY.md, all collector modules, graph/import.py, graph/infer.py

## Your Task

Review Phase 3 — Extended Collection. Verify that all four new data sources (XPC, Persistence, Keychain, MDM) are correctly implemented, integrated into the collector JSON, and properly imported into the graph.

## Review Checklist

### 3.1 XPC Service Enumeration
- [ ] `XPCDataSource` exists and conforms to `DataSource`
- [ ] Parses plists from all 4 directories: /System/Library/LaunchDaemons/, /Library/LaunchDaemons/, /Library/LaunchAgents/, ~/Library/LaunchAgents/
- [ ] Handles both XML and binary plist formats
- [ ] Extracts: Label, Program/ProgramArguments, MachServices, UserName, RunAtLoad
- [ ] MachServices dict keys extracted as XPC endpoint names
- [ ] XPC service binary entitlements are cross-referenced (high-value if has private TCC entitlements)
- [ ] Unreadable directories produce errors, not crashes
- [ ] JSON output contains `xpc_services` array
- [ ] Graph import creates XPC_Service nodes
- [ ] COMMUNICATES_WITH edges link apps to XPC services
- [ ] On real Mac: >100 XPC services discovered

### 3.2 Persistence Scanner
- [ ] `PersistenceDataSource` exists and conforms to `DataSource`
- [ ] Scans: LaunchDaemons, LaunchAgents, Login Items, Cron Jobs
- [ ] Login Items parsed from backgrounditems.btm or SMAppService API
- [ ] Each LaunchItem has: label, path, type, program, run_at_load, user
- [ ] Owner resolution: persistence items linked to parent Application bundles where possible
- [ ] JSON output contains `launch_items` array
- [ ] Graph: PERSISTS_VIA (Application → LaunchItem) and RUNS_AS (LaunchItem → User) edges
- [ ] On real Mac: >50 persistence items discovered

### 3.3 Keychain ACL Metadata
- [ ] `KeychainDataSource` exists and conforms to `DataSource`
- [ ] **CRITICAL: NO passwords, keys, or secret data anywhere in the output** — verify by:
  - Reading the source code: no `kSecReturnData: true` calls
  - Checking JSON output: no fields that could contain secrets
  - Searching for `kSecValueData`, `kSecValueRef` in source → must NOT be used
- [ ] Enumerates items from login keychain with metadata only: label, kind, service, access_group
- [ ] ACLs extracted: trusted_apps list per item (bundle IDs or paths)
- [ ] No user prompts triggered by the scanner — verify API usage
- [ ] System keychain: graceful skip if not accessible
- [ ] JSON output contains `keychain_acls` array
- [ ] Graph: Keychain_Item nodes and CAN_READ_KEYCHAIN edges
- [ ] CAN_READ_KEYCHAIN correctly maps trusted_apps to Application nodes via team_id or bundle_id

### 3.4 MDM Profile Analysis
- [ ] `MDMDataSource` exists and conforms to `DataSource`
- [ ] Parses `profiles show -all` or equivalent command output
- [ ] Extracts: identifier, display_name, organization, install_date
- [ ] TCC-relevant payloads (Privacy Preferences Policy Control) detected
- [ ] JSON output contains `mdm_profiles` array (empty on unmanaged Macs)
- [ ] Graph: MDM_Profile nodes and CONFIGURES edges to TCC_Permission
- [ ] Unmanaged Macs: empty array, no errors, no crash

### Integration Checks
- [ ] All 4 new data sources are wired into the ScanOrchestrator
- [ ] `--modules` flag supports new module names (xpc, persistence, keychain, mdm)
- [ ] JSON Schema updated to include new arrays
- [ ] `scripts/validate-scan.py` validates scans with new data sources
- [ ] Graph import handles all new node types and edge types
- [ ] Inference engine updated if new inferred relationships were added
- [ ] New Cypher queries exist that leverage Phase 3 data

### Security Review (CRITICAL for 3.3 Keychain)
- [ ] Grep entire codebase for `kSecReturnData`, `kSecValueData`, `kSecValueRef`, `password`, `secret` in Keychain module
- [ ] Verify: KeychainDataSource CANNOT be made to return secrets even if called incorrectly
- [ ] Verify: test fixtures contain NO real Keychain data

## Output Format

Produce `docs/reviews/phase-3-review.md`:

```markdown
# Phase 3 Review — Extended Collection

**Reviewer:** Claude Opus (automated review)
**Date:** [today]
**Overall Status:** ✅ PASS | ⚠️ PASS WITH ISSUES | ❌ FAIL

## Summary

## Security Audit: Keychain Module
**No secrets extracted:** [CONFIRMED | ⚠️ CONCERN — details]
[Detail the specific checks performed]

## Results by Sub-Phase
### 3.1 XPC Services: [✅|⚠️|❌]
### 3.2 Persistence: [✅|⚠️|❌]
### 3.3 Keychain ACLs: [✅|⚠️|❌]
### 3.4 MDM Profiles: [✅|⚠️|❌]

## Graph Model Completeness
- Node types in ARCHITECTURE.md: [list] → actually created: [list]
- Edge types in ARCHITECTURE.md: [list] → actually created: [list]
- Missing: [any nodes/edges defined but not implemented]

## Critical Issues
## Warnings
## Recommendations

## Meilenstein M3 Status
**"Vollständige Datenerfassung":** [MET | NOT MET]
- XPC services in graph: [yes/no, count]
- Persistence items in graph: [yes/no, count]
- Keychain ACLs in graph: [yes/no, count]
- MDM profiles in graph: [yes/no, count or N/A if unmanaged]
```
