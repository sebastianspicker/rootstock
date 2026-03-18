You are the Graph Engineer agent for the Rootstock project.

## Context

Read these files first:
- CLAUDE.md (conventions)
- ARCHITECTURE.md §Graph Model (node/edge types)
- graph/queries/ (all existing Cypher queries from Phase 2.4)
- ROADMAP.md §Phase 4.1

## Task: Phase 4.1 — Static Reports (Mermaid/Graphviz)

Build a Python report generator that runs all Killer Queries against Neo4j and produces
a comprehensive Markdown security report — suitable for pentest deliverables and academic papers.

### Step 1: Report Engine
Create `graph/report.py`:
- CLI: `python3 report.py --neo4j bolt://localhost:7687 --output report.md`
- Optional flags: `--format markdown` (default), `--format html`
- Connect to Neo4j, run all queries from `graph/queries/*.cypher`, collect results
- Handle query failures gracefully: note the failure in the report, continue with others

### Step 2: Report Structure
The generated Markdown report should have these sections:

```markdown
# Rootstock Security Assessment Report
## Scan Metadata
- Hostname, macOS version, scan timestamp, collector version
- Elevation level (root/user, FDA status)
- Total apps scanned, TCC grants found, entitlements extracted

## Executive Summary
- Number of critical findings
- Number of high-risk findings
- Top 3 most concerning attack paths (one-sentence each)

## Critical Findings: Injectable Apps with Privileged TCC Grants
- Table: App Name | TCC Permission | Injection Method | Team ID
- For each: one-sentence risk description
- Mermaid diagram of the top 3 attack paths

## High Findings: Electron TCC Inheritance
- Table: Electron App | Inherited Permissions
- Risk explanation for ELECTRON_RUN_AS_NODE abuse

## High Findings: Apple Event TCC Cascade
- Table: Source App | Target App | Gained Permission
- Explanation of transitive trust abuse

## Informational: TCC Grant Overview
- Table: TCC Service | Display Name | Granted Apps Count
- Pie chart (Mermaid) of grant distribution

## Informational: Private Entitlement Audit
- Table: App | Private Entitlements | Injectable?
- Focus on non-system apps with private entitlements

## Recommendations
- Per finding category: actionable remediation steps
- General macOS hardening recommendations

## Appendix: Raw Query Results
- Full output of each query for detailed analysis
```

### Step 3: Mermaid Diagram Generation
Create `graph/report_diagrams.py`:
- For attack paths returned by shortestPath queries: generate Mermaid flowchart syntax
- Example output:
  ```mermaid
  graph LR
    A[attacker_payload] -->|CAN_INJECT_INTO| B[iTerm2]
    B -->|HAS_TCC_GRANT| C[Full Disk Access]
    style C fill:#ff6666
  ```
- For TCC distribution: generate Mermaid pie chart
- Handle paths of varying lengths (2-hop, 3-hop, etc.)

### Step 4: Graphviz DOT Export
Create `graph/report_graphviz.py`:
- Export the full graph (or a filtered subgraph) as DOT format
- Color coding: Applications=lightblue, TCC_Permission=red, Entitlement=yellow, XPC_Service=green
- Edge styles: solid for explicit, dashed for inferred relationships
- `python3 report_graphviz.py --neo4j bolt://... --output graph.dot`
- Optional: auto-render to PNG/SVG if `dot` command is available

### Step 5: Scan Metadata Extraction
- Query Neo4j for scan metadata (scan_id, timestamp, node counts)
- Or read it from the original JSON file if provided via `--scan-json scan.json`
- Populate the Scan Metadata section of the report

### Step 6: Testing
- Run report generator on a populated graph from real scan data
- Verify: Markdown is valid, Mermaid diagrams render correctly (check in VS Code preview or GitHub)
- Verify: all sections are populated (or show "No findings" where appropriate)
- Verify: DOT export produces valid Graphviz syntax (`dot -Tpng graph.dot -o graph.png`)

## Acceptance Criteria

- [ ] `python3 graph/report.py --neo4j bolt://... --output report.md` produces a Markdown file
- [ ] Report has all sections: Metadata, Executive Summary, Critical/High/Informational findings, Recommendations
- [ ] At least one Mermaid attack path diagram is generated for critical findings
- [ ] Mermaid pie chart shows TCC grant distribution
- [ ] Tables are properly formatted Markdown
- [ ] Graphviz DOT export produces valid syntax
- [ ] Report runs without error on a graph with real scan data
- [ ] Report handles empty query results gracefully ("No findings in this category")
- [ ] Recommendations are actionable (not generic placeholder text)
- [ ] Executive summary counts reflect actual query results

## If Stuck

After 12 iterations:
- If Mermaid generation is too complex for multi-hop paths: start with simple 2-node diagrams
  and document longer paths as text instead
- If Graphviz DOT is a stretch: make it optional, focus on Markdown+Mermaid only
- If Neo4j query results are hard to format: use tabulate library for table rendering
- Minimum viable: Markdown report with tables, no diagrams. Add diagrams as enhancement.

When ALL acceptance criteria are met, output:
<promise>PHASE_4_1_COMPLETE</promise>
