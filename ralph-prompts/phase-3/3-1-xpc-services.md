You are the Collector Engineer agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §XPC_Service node, AGENTS.md §Collector Engineer,
collector/Sources/Models/DataSource.swift, existing collector modules

## Task: Phase 3.1 — XPC Service Enumeration

Add a new data source module that discovers XPC services via LaunchDaemon/LaunchAgent plists.

### Steps

1. **Plist Parser** — Create `collector/Sources/XPC/LaunchdPlistParser.swift`:
   - Parse plist files in: `/System/Library/LaunchDaemons/`, `/Library/LaunchDaemons/`,
     `/Library/LaunchAgents/`, `~/Library/LaunchAgents/`
   - Extract: Label, Program/ProgramArguments, MachServices (dict keys = service names),
     UserName, RunAtLoad, KeepAlive
   - Handle both XML and binary plist formats (use PropertyListSerialization)

2. **XPC Service Model** — Extend Models/ with `XPCService` Codable struct:
   - label, path, program, user, type (daemon/agent), run_at_load, mach_services: [String]

3. **Entitlement Cross-Reference** — For each XPC service binary:
   - Extract its entitlements using the existing EntitlementExtractor from Phase 1.3
   - An XPC service with `com.apple.private.tcc.allow` is a high-value target

4. **XPCDataSource** — Create `collector/Sources/XPC/XPCDataSource.swift`:
   - Conforms to DataSource protocol
   - collect() → parse all plist directories → return XPCService nodes
   - Skip unreadable directories (system dirs may need elevation) with graceful error

5. **JSON Integration** — Add `xpc_services` array to ScanResult, wire into orchestrator

6. **Graph Import Extension** — Update `graph/import.py` to:
   - Create XPC_Service nodes
   - Create COMMUNICATES_WITH edges: match MachService names to apps that reference them

7. **Tests** — Create fixture plist files, verify parsing, verify graceful failure on unreadable dirs

## Acceptance Criteria

- [ ] XPCDataSource conforms to DataSource protocol
- [ ] JSON output contains `xpc_services` array with label, program, mach_services
- [ ] LaunchDaemons and LaunchAgents from all four directories are scanned
- [ ] XPC service entitlements are extracted for accessible binaries
- [ ] Graph import creates XPC_Service nodes and COMMUNICATES_WITH edges
- [ ] On a real Mac: > 100 XPC services discovered
- [ ] Unreadable directories produce errors, not crashes

When ALL acceptance criteria are met, output:
<promise>PHASE_3_1_COMPLETE</promise>
