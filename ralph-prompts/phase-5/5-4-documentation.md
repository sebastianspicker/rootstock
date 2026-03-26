You are the Technical Writer agent for the Rootstock project.

## Context

Read: CLAUDE.md, AGENTS.md §Technical Writer, README.md, ARCHITECTURE.md,
docs/ (all existing documentation), ROADMAP.md §Meilensteine

## Task: Phase 5.4 — Dokumentation & Akademische Aufbereitung

Finalize all documentation to publication-quality standard — suitable for both the
GitHub community and an academic paper submission.

### Step 1: README Finalization
Update `README.md` to reflect the actual state of the project:
- Quick Start section with actual commands (tested, working)
- Example output: a redacted snippet of real collector JSON (no real hostnames/user data)
- Example query results: screenshot descriptions or Markdown tables showing real attack paths found
- Compatibility matrix (from Phase 5.2)
- Performance characteristics (from Phase 5.3 benchmarks)
- Installation instructions that actually work (tested on a clean system)
- Badges: build status (CI), license, macOS version support

### Step 2: ARCHITECTURE.md Enhancement
Update `ARCHITECTURE.md`:
- Add a "Real-World Example" section showing a concrete scan result and the graph it produces
- Annotate the graph model with actual statistics: "typical scan produces ~150 Application nodes,
  ~40 TCC grants, ~1200 entitlements, ~30 inferred attack edges"
- Add a section on design decisions and their rationale (link to design-docs/)

### Step 3: Threat Model Document
Create `docs/THREAT_MODEL.md`:
- **What Rootstock assumes:** local access to macOS endpoint, collector runs as user or root
- **What Rootstock does NOT do:**
  - No remote collection (requires local execution)
  - No secret extraction (metadata only)
  - No exploitation (analysis only, no active attacks)
  - No real-time monitoring (point-in-time snapshot)
- **Limitations:**
  - SIP prevents some data collection (system TCC.db)
  - Apple may change security mechanisms in future macOS versions
  - The graph model is an approximation — not all theoretical attack paths are exploitable in practice
  - Inferred relationships (CAN_INJECT_INTO) are necessary conditions, not sufficient
- **Comparison with BloodHound:**
  - Both use graph theory for attack path analysis
  - BloodHound: identity-centric (AD users, groups, GPOs)
  - Rootstock: app-centric (TCC, entitlements, code signing)
  - Complementary: Rootstock covers macOS-native boundaries BloodHound doesn't model
  - BloodHound OpenGraph could potentially ingest Rootstock data (future work)

### Step 4: Academic Paper Skeleton
Create `docs/paper/`:
- `paper-skeleton.md` — structured outline for a potential conference paper:
  ```markdown
  # Rootstock: Graph-Based Attack Path Discovery for macOS Security Boundaries

  ## Abstract (200 words)
  - Problem: macOS security boundaries create complex, invisible trust relationships
  - Approach: graph-theoretic modeling of TCC, entitlements, code signing
  - Results: automated discovery of N attack paths on M real-world systems
  - Contribution: first systematic tool for macOS-native attack path analysis

  ## 1. Introduction
  - Growing macOS enterprise adoption
  - Complexity of macOS security model (TCC, SIP, entitlements, Keychain)
  - Gap: no equivalent to BloodHound for macOS-native boundaries
  - Our contribution

  ## 2. Background
  - 2.1 macOS Security Architecture (TCC, SIP, Gatekeeper, Keychain)
  - 2.2 Attack Path Analysis (BloodHound, graph theory in security)
  - 2.3 Existing macOS Offensive Tools (Bifrost, Chainbreaker, etc.)

  ## 3. Design & Implementation
  - 3.1 Graph Model (nodes, edges, inferred relationships)
  - 3.2 Data Collection (collector architecture, data sources)
  - 3.3 Analysis Engine (Neo4j, Cypher queries)

  ## 4. Evaluation
  - 4.1 Methodology (N macOS systems scanned, version mix)
  - 4.2 Attack Paths Discovered (categories, severity)
  - 4.3 Performance (scan time, graph size, query performance)
  - 4.4 Comparison with Manual Analysis

  ## 5. Discussion
  - Limitations, ethical considerations, responsible disclosure

  ## 6. Related Work

  ## 7. Conclusion & Future Work
  - BloodHound OpenGraph integration
  - Live analysis (Process nodes)
  - Multi-host correlation
  ```

- `references.bib` — BibTeX file with key references:
  - BloodHound (SpecterOps papers)
  - Bifrost (Cody Thomas, OBTS talks)
  - macOS Security research (Wojciech Reguła, Patrick Wardle)
  - MITRE ATT&CK macOS matrix
  - Apple Platform Security Guide

### Step 5: Target Venues
Document in `docs/paper/target-venues.md`:
- **Conferences:** Objective by the Sea (macOS-specific), BSides, DEF CON (demo labs),
  Black Hat (Arsenal), USENIX Security, ACM CCS
- **Journals:** IEEE S&P, NDSS (if research is substantial enough)
- Submission deadlines and format requirements for top 3 choices
- Recommendation: Objective by the Sea as primary target (most receptive audience)

### Step 6: BibTeX Entry
Update the BibTeX entry in README.md with actual author names, year, and URL:
```bibtex
@software{rootstock2026,
  title   = {Rootstock: Graph-based Attack Path Discovery for macOS Security Boundaries},
  author  = {[Actual Author Names]},
  year    = {2026},
  url     = {https://github.com/[org]/rootstock},
  note    = {Open source research tool, [University Name]}
}
```

## Acceptance Criteria

- [ ] README.md has working Quick Start, real example output, compatibility matrix, badges
- [ ] ARCHITECTURE.md includes real-world example with actual scan statistics
- [ ] `docs/THREAT_MODEL.md` documents assumptions, limitations, and BloodHound comparison
- [ ] Paper skeleton exists with structured outline and all sections
- [ ] `references.bib` has at least 15 relevant references
- [ ] Target venues documented with deadlines
- [ ] BibTeX entry is complete (except author placeholders)
- [ ] All documentation is in English, well-formatted Markdown
- [ ] No placeholder text remaining (except author/university names)
- [ ] Someone unfamiliar with the project could set up and use Rootstock from the README alone

## If Stuck

After 12 iterations:
- If real example output isn't available yet: use the fixture data to generate a representative example
- If paper skeleton scope is unclear: focus on the outline structure, leave section content as bullet points
- If venue research is time-consuming: list 3 venues with URLs only, fill in details later
- Priority: README > Threat Model > Architecture update > Paper skeleton

When ALL acceptance criteria are met, output:
<promise>PHASE_5_4_COMPLETE</promise>
