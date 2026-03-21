You are the Planner agent for the Rootstock project.

## Context

Read: README.md, CONTRIBUTING.md, docs/product-specs/index.md,
ROADMAP.md §Entscheidungspunkte, ARCHITECTURE.md §Graph Model

## Task: Phase 6.3 — Community-Feedback-Zyklus

Establish the processes and templates for ongoing community engagement after the initial release.

### Step 1: Issue Triage Process
Create `docs/community/issue-triage.md`:
- Label taxonomy:
  - `bug` — something broken
  - `enhancement` — feature request
  - `new-data-source` — request to add a macOS data source
  - `new-query` — request for a new Cypher query
  - `documentation` — docs improvement
  - `good-first-issue` — suitable for new contributors
  - `help-wanted` — actively seeking contributions
  - `wontfix` — intentionally not addressing
  - `macos-15`, `macos-16` — version-specific issues
- Triage process:
  1. New issue → add labels within 48 hours
  2. Bug → attempt to reproduce, ask for scan JSON (redacted) if needed
  3. Feature request → evaluate against core-beliefs.md, label priority
  4. New data source → evaluate: where does the data live? what attack paths does it enable?
- Priority levels: P0 (security/crash), P1 (incorrect results), P2 (enhancement), P3 (nice-to-have)

### Step 2: Quick-Win Identification
Create `docs/community/quick-wins.md`:
- List of low-effort, high-value contributions suitable for newcomers:
  - Add display names for new TCC services (just update TCCServiceRegistry.swift)
  - Add a new Cypher query (create a .cypher file following the template)
  - Fix a typo or improve documentation
  - Test on a new macOS version and report results
  - Add entitlement classifications for newly discovered entitlements
  - Translate documentation to another language
- For each: estimated effort (1-4 hours), files to touch, skills needed
- Tag matching issues with `good-first-issue`

### Step 3: BloodHound OpenGraph Evaluation
Create `docs/community/bloodhound-opengraph-evaluation.md`:
- Research: what would it take to make Rootstock data available in BloodHound CE via OpenGraph?
- BloodHound OpenGraph requirements:
  - Custom node types and relationship definitions
  - Data ingestion format (JSON?)
  - How Rootstock nodes would map to BloodHound's graph model
  - Would Rootstock be a standalone ingestor or an OpenGraph plugin?
- Pros: massive existing user base, unified graph with AD + macOS data
- Cons: dependency on BloodHound release cycle, potential model mismatch
- Decision recommendation: build a BloodHound export adapter as an optional feature,
  keep Rootstock's own Neo4j import as the primary path
- Prototype: minimal Cypher script that creates OpenGraph-compatible nodes from Rootstock data

### Step 4: Conference Submission Preparation
Create `docs/community/conference-prep.md`:
- **Primary target: Objective by the Sea (OBTS)**
  - Why: macOS-specific audience, tool demos welcome, Cody Thomas and other macOS researchers attend
  - Format: 30-minute talk + live demo
  - Abstract draft (200 words)
  - Outline matching the paper skeleton from Phase 5.4
- **Secondary targets:**
  - BSides (various cities): 20-minute tool talk
  - DEF CON Demo Labs: hands-on demo session
  - Black Hat Arsenal: tool showcase
- **Talk structure:**
  1. "macOS has a BloodHound-shaped gap" (problem)
  2. How macOS security boundaries work (background)
  3. Rootstock architecture (solution)
  4. Live demo: scan → import → find attack paths (demo)
  5. Results from N real-world scans (evaluation)
  6. What's next / call to action (future work)
- **Demo preparation checklist:**
  - [ ] Pre-recorded backup video in case of live demo failure
  - [ ] Test Mac with interesting TCC grants pre-configured
  - [ ] Neo4j pre-loaded with sample data as fallback

### Step 5: Roadmap Update
Create `docs/community/roadmap-v0.2.md`:
- Based on anticipated community feedback, plan v0.2.0:
  - BloodHound OpenGraph adapter (if community interest is high)
  - Process node type for live analysis (running processes, their TCC inheritance)
  - Multi-host graph merging (scan multiple Macs, import into one graph)
  - Homebrew formula for easy installation (`brew install rootstock`)
  - macOS 16 Tahoe support
- Community-driven priorities: set up a GitHub Discussion or poll for feature prioritization

### Step 6: Maintainer Sustainability
Create `docs/community/maintainer-guide.md`:
- How to review PRs (checklist: tests, docs, no secrets, coding conventions)
- Release process: version bump, changelog, tag, build binary, GitHub Release
- Changelog format: Keep-a-Changelog style
- When to accept vs. reject contributions (aligned with core-beliefs.md)
- How to handle security reports (SECURITY.md process)
- Bus factor mitigation: at least 2 people with commit access, documented processes

## Acceptance Criteria

- [ ] Issue triage process documented with label taxonomy
- [ ] Quick-wins list exists with 6+ contributor-friendly tasks, each tagged `good-first-issue`
- [ ] BloodHound OpenGraph evaluation document with pros/cons and recommendation
- [ ] Conference submission materials: abstract draft, talk outline, demo checklist
- [ ] v0.2.0 roadmap exists with 5+ planned features
- [ ] Maintainer guide covers PR review, release process, and security reports
- [ ] All docs are in English, well-structured Markdown
- [ ] GitHub labels created (or documented for creation)
- [ ] At least one concrete next step identified for BloodHound OpenGraph integration

## If Stuck

After 10 iterations:
- If BloodHound OpenGraph research requires testing: write the evaluation document
  based on documentation only, mark hands-on testing as future work
- If conference abstract is hard to write without real evaluation data: write a
  draft using anticipated results from fixture data
- If maintainer guide feels premature: write a minimal version covering PR review
  and release process only
- This phase is primarily documentation — if any section is blocking, skip it
  and move to the next. All sections are independently valuable.

When ALL acceptance criteria are met, output:
<promise>PHASE_6_3_COMPLETE</promise>
