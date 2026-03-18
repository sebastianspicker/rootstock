# Tech Debt Tracker

> Track known shortcuts, deferred decisions, and areas that need revisiting.
> Review this list at the start of each new phase.

## Active Debt

| ID | Component | Description | Incurred | Priority |
|---|---|---|---|---|
| TD-004 | collector/TCC | macOS 26.3 (and macOS 15+) blocks TCC.db reads via `SQLITE_OPEN_READONLY` at kernel level even for user-owned files — returns `SQLITE_AUTH`. Process requires FDA (Full Disk Access) entitlement or must be signed with `com.apple.private.tcc.allow` to read TCC.db. Currently, the collector degrades gracefully: TCC module reports a recoverable error and returns zero grants. Resolution: (a) Ship the binary with FDA entitlement for opt-in use, or (b) use macOS Security framework proxy APIs if available. Until resolved, all correctness testing uses synthetic fixture databases. | Phase 1.2 | High |
| TD-002 | collector | App discovery only scans three directories — should also check Homebrew Cask, user-specific installs | Phase 1 | Medium |
| TD-003 | graph | No schema migration strategy for Neo4j — model changes require manual DB wipe | Phase 2 | Medium |

| TD-005 | collector/CodeSigning | Platform binaries (Apple system apps with no developer team) have `team_id` omitted from JSON entirely rather than serialized as `null`. Swift's `JSONEncoder` omits nil optionals by default. Consumers must use `app.get("team_id")` not `app["team_id"]`. Fix: use a custom encoder or encode as explicit null. | Phase 1.4 | Low |
| TD-006 | collector/CodeSigning | Terminal.app, Safari.app and other Apple platform binaries report `hardened_runtime: false` and appear in `injection_methods` as `dyld_insert`. These apps have SIP (System Integrity Protection) kernel-level enforcement that prevents DYLD injection regardless of the CS_RUNTIME flag. The injection assessment should add a `is_sip_protected` check (path starts with /System/) to suppress false positives. | Phase 1.6 | Medium |
| TD-007 | collector/CodeSigning | sudo/root run could not be tested via CI pipeline (requires interactive terminal for sudo). Root run expected to show `has_fda: true` and parse system TCC.db. Verify manually. | Phase 1.6 | Low |

## Resolved Debt

| ID | Component | Description | Incurred | Resolved | Resolution |
|---|---|---|---|---|---|
| TD-001 | collector | CLI argument parsing was minimal | Phase 1 | Phase 1.1 | Added `--verbose`, `--modules`, `--output` flags with swift-argument-parser |
