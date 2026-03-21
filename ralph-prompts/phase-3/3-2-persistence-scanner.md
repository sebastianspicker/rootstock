You are the Collector Engineer agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §LaunchItem node, collector/Sources/XPC/ (reuse plist parsing from 3.1)

## Task: Phase 3.2 — Persistence Scanner

Enumerate all persistence mechanisms and model them as LaunchItem nodes in the graph.

### Steps

1. **Persistence Sources** — Scan these locations:
   - LaunchDaemons: `/System/Library/LaunchDaemons/`, `/Library/LaunchDaemons/`
   - LaunchAgents: `/Library/LaunchAgents/`, `~/Library/LaunchAgents/`
   - Login Items (modern): SMAppService registered items via
     `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`
   - Cron jobs: `/var/at/tabs/`, `/etc/crontab`, user crontabs
   - Login hooks (legacy): `/var/root/Library/Preferences/com.apple.loginwindow.plist`

2. **LaunchItem Model** — Codable struct: label, path, type (daemon/agent/login_item/cron),
   program, run_at_load, user (who it runs as)

3. **PersistenceDataSource** — Conforms to DataSource. Reuse LaunchdPlistParser from 3.1
   for daemon/agent parsing. Add parsers for login items and cron jobs.

4. **Owner Resolution** — For each persistence item, try to determine which Application
   it belongs to (match by program path → app bundle containing that binary)

5. **Graph Edges** — `PERSISTS_VIA`: Application → LaunchItem, `RUNS_AS`: LaunchItem → User

6. **New Query** — `graph/queries/08-persistence-audit.cypher`:
   Third-party persistence items running as root that are associated with injectable apps

## Acceptance Criteria

- [ ] JSON output contains `launch_items` array
- [ ] LaunchDaemons, LaunchAgents, login items, and cron jobs are discovered
- [ ] Each item has: label, path, type, program, run_at_load, user
- [ ] Graph import creates LaunchItem nodes with PERSISTS_VIA and RUNS_AS edges
- [ ] Persistence audit query identifies high-risk persistence mechanisms
- [ ] On a real Mac: > 50 persistence items discovered

When ALL acceptance criteria are met, output:
<promise>PHASE_3_2_COMPLETE</promise>
