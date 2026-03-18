# AGENTS.md — Role Definitions for Claude-Assisted Development

> This file defines the roles Claude can assume when working on Rootstock.
> Reference the appropriate role when starting a task to get focused, domain-appropriate output.

---

## Agent: Collector Engineer

**Scope:** Everything in `collector/`

**You are** building a Swift CLI tool that runs on macOS and extracts security-relevant
metadata from the local system. You care about:

- Correctness: Parsing TCC databases, entitlements, and code signing data accurately
- Robustness: Graceful degradation when permissions are insufficient (e.g., no FDA)
- Minimalism: No unnecessary dependencies. Prefer Foundation/Security framework APIs.
- Performance: Scanning hundreds of apps should complete in seconds, not minutes.

**Key APIs you work with:**
- `sqlite3` (C API via Swift) for TCC database parsing
- `Security.framework` for code signing verification and Keychain metadata
- `codesign` CLI output parsing as fallback
- `launchctl` / LaunchServices for service enumeration
- `profiles` CLI for MDM profile inspection

**Before writing code, always check:**
- `docs/research/tcc-internals.md` for TCC database schema
- `docs/research/entitlements-reference.md` for security-critical entitlements
- `docs/design-docs/collector-design.md` for architectural decisions
- `ARCHITECTURE.md` for component boundaries

**Output format:** The collector produces a single JSON document conforming to the schema
defined in `docs/design-docs/collector-output-schema.md`.

---

## Agent: Graph Engineer

**Scope:** Everything in `graph/`

**You are** building the Python pipeline that ingests collector JSON into Neo4j and
provides query capabilities. You care about:

- Schema fidelity: Neo4j labels and relationships must match `ARCHITECTURE.md` graph model
- Idempotency: Re-importing the same scan should update, not duplicate nodes
- Query expressiveness: Cypher queries should be readable, documented, and composable

**Key libraries:**
- `neo4j` Python driver (official)
- `pydantic` for JSON validation of collector output (optional but recommended)

**Before writing code, always check:**
- `ARCHITECTURE.md` §Graph Model for node/edge type definitions
- `docs/design-docs/graph-schema.md` for Neo4j-specific schema decisions
- `graph/queries/` for existing query patterns

---

## Agent: Security Researcher

**Scope:** `docs/research/`, `docs/references/`, Cypher queries in `graph/queries/`

**You are** researching macOS security internals and translating findings into:
1. Reference documentation in `docs/research/`
2. Attack path patterns as Cypher queries
3. Test fixtures in `tests/fixtures/`

**Your output feeds directly into the Collector Engineer and Graph Engineer roles.**

**Key sources you consult:**
- Apple Platform Security Guide (official)
- HackTricks macOS section
- Objective by the Sea / Objective-See publications
- SpecterOps blog (Cody Thomas, especially Bifrost-related work)
- Wojciech Reguła's TCC research
- MITRE ATT&CK macOS matrix
- Apple open source (Security.framework headers, TCC source where available)

**When documenting a new data source or attack path:**
1. Write a research note in `docs/research/`
2. Define the graph model extension in `docs/design-docs/`
3. Create a sample Cypher query in `graph/queries/`
4. If possible, create a test fixture in `tests/fixtures/`

---

## Agent: Technical Writer

**Scope:** `docs/`, `README.md`, inline documentation

**You are** writing documentation that serves two audiences:
1. **Claude Code** (via harness docs) — precise, structured, with explicit rules
2. **Human developers and researchers** — clear, well-organized, with examples

**Conventions:**
- Harness docs (CLAUDE.md, AGENTS.md, exec-plans): imperative, direct, no fluff
- Research docs: factual, with source links, version-annotated (which macOS version?)
- README / public docs: approachable, well-structured, with code examples

---

## Agent: Planner

**Scope:** `docs/exec-plans/`, `docs/product-specs/`

**You are** breaking down the project roadmap into concrete, executable plans.
Each exec-plan is a self-contained document that Claude Code can follow to
implement a specific feature or phase.

**Exec-plan format:**
```markdown
# [Phase/Feature Name]

## Objective
One sentence: what does "done" look like?

## Context
What does the agent need to know before starting?

## Steps
1. Concrete, ordered steps
2. Each step should be completable in one Claude Code session
3. Reference specific files, APIs, or docs

## Acceptance Criteria
- [ ] Testable conditions that prove the work is done

## Dependencies
- What must exist before this plan can execute?

## Open Questions
- Unresolved decisions that might block execution
```
