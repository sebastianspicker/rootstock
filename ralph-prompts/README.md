# Ralph-Loop Prompts — Execution Guide

> Jede Unterphase der Roadmap hat ein eigenes Prompt-File, das mit dem
> Ralph-Loop-Plugin in Claude Code ausgeführt werden kann.
>
> Die Prompts sind so geschrieben, dass Claude Code iterativ daran arbeitet,
> bis die Acceptance Criteria erfüllt sind.

## Voraussetzungen

1. Ralph-Loop Plugin installiert:
   ```bash
   npx claudepluginhub anthropics/claude-plugins-official --plugin ralph-loop
   ```

2. Rootstock-Repository geklont mit Harness-Dokumentation vorhanden

3. Xcode + Swift Toolchain installiert (für Phase 1)

4. Neo4j via Docker verfügbar (für Phase 2)

## Ausführungsreihenfolge

### Phase 1 — Collector MVP

```bash
# 1.1 Scaffolding (Fundament, muss zuerst laufen)
/ralph-loop:ralph-loop "@ralph-prompts/phase-1/1-1-scaffolding.md" --max-iterations 15 --completion-promise "PHASE_1_1_COMPLETE"

# 1.2 TCC Parser (Kern-Datenquelle)
/ralph-loop:ralph-loop "@ralph-prompts/phase-1/1-2-tcc-parser.md" --max-iterations 25 --completion-promise "PHASE_1_2_COMPLETE"

# 1.3 Entitlement Scanner (parallel zu 1.2 möglich)
/ralph-loop:ralph-loop "@ralph-prompts/phase-1/1-3-entitlement-scanner.md" --max-iterations 25 --completion-promise "PHASE_1_3_COMPLETE"

# 1.4 Code Signing Analyse (baut auf 1.3 auf)
/ralph-loop:ralph-loop "@ralph-prompts/phase-1/1-4-codesigning.md" --max-iterations 20 --completion-promise "PHASE_1_4_COMPLETE"

# 1.5 JSON Export & CLI (integriert alles)
/ralph-loop:ralph-loop "@ralph-prompts/phase-1/1-5-json-export-cli.md" --max-iterations 20 --completion-promise "PHASE_1_5_COMPLETE"

# 1.6 Integration & Validierung
/ralph-loop:ralph-loop "@ralph-prompts/phase-1/1-6-validation.md" --max-iterations 15 --completion-promise "PHASE_1_6_COMPLETE"
```

### Phase 2 — Graph Pipeline

```bash
# 2.1 Neo4j Setup
/ralph-loop:ralph-loop "@ralph-prompts/phase-2/2-1-neo4j-setup.md" --max-iterations 15 --completion-promise "PHASE_2_1_COMPLETE"

# 2.2 JSON → Graph Importer
/ralph-loop:ralph-loop "@ralph-prompts/phase-2/2-2-graph-importer.md" --max-iterations 25 --completion-promise "PHASE_2_2_COMPLETE"

# 2.3 Inferred Relationships
/ralph-loop:ralph-loop "@ralph-prompts/phase-2/2-3-inferred-relationships.md" --max-iterations 20 --completion-promise "PHASE_2_3_COMPLETE"

# 2.4 Killer Queries
/ralph-loop:ralph-loop "@ralph-prompts/phase-2/2-4-killer-queries.md" --max-iterations 15 --completion-promise "PHASE_2_4_COMPLETE"
```

### Phase 3 — Erweiterte Collection

```bash
# 3.1 XPC Services
/ralph-loop:ralph-loop "@ralph-prompts/phase-3/3-1-xpc-services.md" --max-iterations 25 --completion-promise "PHASE_3_1_COMPLETE"

# 3.2 Persistence Scanner
/ralph-loop:ralph-loop "@ralph-prompts/phase-3/3-2-persistence-scanner.md" --max-iterations 20 --completion-promise "PHASE_3_2_COMPLETE"

# 3.3 Keychain ACLs
/ralph-loop:ralph-loop "@ralph-prompts/phase-3/3-3-keychain-acls.md" --max-iterations 25 --completion-promise "PHASE_3_3_COMPLETE"

# 3.4 MDM Profiles
/ralph-loop:ralph-loop "@ralph-prompts/phase-3/3-4-mdm-profiles.md" --max-iterations 15 --completion-promise "PHASE_3_4_COMPLETE"
```

### Phase 4 — Visualisierung & UX

```bash
# 4.1 Static Reports (Mermaid/Graphviz)
/ralph-loop:ralph-loop "@ralph-prompts/phase-4/4-1-static-reports.md" --max-iterations 20 --completion-promise "PHASE_4_1_COMPLETE"

# 4.2 Neo4j Browser Integration
/ralph-loop:ralph-loop "@ralph-prompts/phase-4/4-2-neo4j-browser.md" --max-iterations 15 --completion-promise "PHASE_4_2_COMPLETE"

# 4.3 Interactive Query Library
/ralph-loop:ralph-loop "@ralph-prompts/phase-4/4-3-query-library.md" --max-iterations 20 --completion-promise "PHASE_4_3_COMPLETE"
```

### Phase 5 — Härtung & Qualität

```bash
# 5.1 Test Coverage & Fixtures
/ralph-loop:ralph-loop "@ralph-prompts/phase-5/5-1-test-coverage.md" --max-iterations 25 --completion-promise "PHASE_5_1_COMPLETE"

# 5.2 Multi-macOS Version Compatibility
/ralph-loop:ralph-loop "@ralph-prompts/phase-5/5-2-macos-compat.md" --max-iterations 15 --completion-promise "PHASE_5_2_COMPLETE"

# 5.3 Performance & Edge Cases
/ralph-loop:ralph-loop "@ralph-prompts/phase-5/5-3-performance.md" --max-iterations 20 --completion-promise "PHASE_5_3_COMPLETE"

# 5.4 Documentation & Academic Preparation
/ralph-loop:ralph-loop "@ralph-prompts/phase-5/5-4-documentation.md" --max-iterations 15 --completion-promise "PHASE_5_4_COMPLETE"
```

### Phase 6 — Community Release

```bash
# 6.1 Repository Preparation
/ralph-loop:ralph-loop "@ralph-prompts/phase-6/6-1-repo-preparation.md" --max-iterations 15 --completion-promise "PHASE_6_1_COMPLETE"

# 6.2 First Public Release
/ralph-loop:ralph-loop "@ralph-prompts/phase-6/6-2-first-release.md" --max-iterations 15 --completion-promise "PHASE_6_2_COMPLETE"

# 6.3 Community Feedback Cycle
/ralph-loop:ralph-loop "@ralph-prompts/phase-6/6-3-community-feedback.md" --max-iterations 15 --completion-promise "PHASE_6_3_COMPLETE"
```

## Tipps

- **Vor jedem Loop:** Sicherstellen dass der vorherige Abschnitt committed ist (`git add . && git commit`)
- **Bei Stuck-Loops:** Die Prompts enthalten Anweisungen für "wenn du steckenbleibst" — Claude dokumentiert Blocker in `docs/exec-plans/tech-debt-tracker.md`
- **Iteration Limits:** Konservativ gesetzt. Erhöhe `--max-iterations` wenn ein Abschnitt komplex ist.
- **Review zwischen Phasen:** Nach jedem COMPLETE den Output reviewen, bevor der nächste Loop startet.
- **Harness-Kontext:** Jeder Prompt referenziert CLAUDE.md, AGENTS.md und ARCHITECTURE.md — diese müssen im Repo vorhanden sein, damit Claude den vollen Kontext hat.
- **Mehrere Dateien referenzieren:** Bei Bedarf können Harness-Docs als zusätzlicher Kontext mitgegeben werden:
  ```bash
  /ralph-loop:ralph-loop "@ralph-prompts/phase-1/1-2-tcc-parser.md @docs/research/tcc-internals.md" --max-iterations 25 --completion-promise "PHASE_1_2_COMPLETE"
  ```
