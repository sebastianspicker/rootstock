You are the Graph Engineer agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §Graph Model, graph/queries/ (all existing queries),
graph/schema/ (constraints and seed data)

## Task: Phase 4.2 — Neo4j Browser Integration

Make Rootstock data visually compelling and navigable in Neo4j Browser out of the box.

### Step 1: Neo4j Browser Guide
Create `graph/browser/rootstock-guide.html`:
- A Neo4j Browser Guide (`:play rootstock`) with slides:
  - Slide 1: "Welcome to Rootstock" — what it is, what the graph contains
  - Slide 2: "Getting Started" — sample query to show all TCC grants
  - Slide 3: "Find Injectable Apps" — Killer Query 1 with explanation
  - Slide 4: "Attack Paths" — shortestPath query with explanation
  - Slide 5: "Electron Risks" — Electron inheritance query
  - Slide 6: "Blue Team Audit" — TCC overview query
  - Slide 7: "Next Steps" — link to query library, documentation
- Each slide has a runnable Cypher query embedded
- Guide format: HTML with Neo4j Browser guide conventions (`:play` compatible)

### Step 2: Graph Style Sheet (GraSS)
Create `graph/browser/rootstock-style.grass`:
- Node styling by label:
  - `Application` → blue (#4A90D9), icon: app/computer
  - `TCC_Permission` → red (#E74C3C), icon: shield/lock
  - `Entitlement` → amber (#F39C12), icon: key
  - `XPC_Service` → green (#27AE60), icon: gear/server
  - `LaunchItem` → purple (#8E44AD), icon: play/clock
  - `Keychain_Item` → teal (#1ABC9C), icon: lock
  - `MDM_Profile` → gray (#95A5A6), icon: settings
  - `User` → orange (#E67E22), icon: person
- Edge styling:
  - `HAS_TCC_GRANT` → red, thick
  - `CAN_INJECT_INTO` → red, dashed (attack path)
  - `HAS_ENTITLEMENT` → amber, thin
  - `CHILD_INHERITS_TCC` → red, dashed
  - `CAN_SEND_APPLE_EVENT` → orange, dashed
  - `PERSISTS_VIA` → purple
  - `COMMUNICATES_WITH` → green
- Node captions: show `name` property for all node types
- Size nodes by degree (more connections = bigger)

### Step 3: Saved Queries / Favorites
Create `graph/browser/saved-queries.cypher`:
- All Killer Queries from Phase 2.4 formatted as `:favorites` import format
- Additional exploratory queries:
  - "Show all nodes and relationships (limit 100)"
  - "Apps with most TCC permissions"
  - "Apps with most entitlements"
  - "All inferred attack edges"
  - "TCC grants by scope (user vs system)"
- Each query has a descriptive name/comment

### Step 4: Setup Script
Create `graph/browser/setup-browser.sh`:
- Copies the GraSS file to Neo4j's import directory
- Copies the guide HTML to Neo4j's import directory
- Prints instructions: "Open Neo4j Browser → run `:play rootstock` → import style with `:style`"
- Docker-compatible: mount the files as volumes in docker-compose.yml

### Step 5: Documentation
Create `docs/guides/neo4j-browser-quickstart.md`:
- Step-by-step: start Neo4j, import data, load style, run guide
- Screenshots placeholders (describe what each step should look like)
- Troubleshooting: common issues (empty graph, missing styles, connection errors)

## Acceptance Criteria

- [ ] Neo4j Browser Guide exists and has 7 slides with runnable queries
- [ ] GraSS style sheet assigns distinct colors to all 8 node types
- [ ] GraSS style sheet assigns distinct styles to all edge types (attack edges are dashed red)
- [ ] Saved queries file contains all Killer Queries + 5 exploratory queries
- [ ] Setup script works with Docker-based Neo4j
- [ ] Loading the style in Neo4j Browser visually distinguishes node types
- [ ] Guide queries actually return results on a populated graph
- [ ] Quickstart documentation covers the full workflow
- [ ] Inferred/attack edges are visually distinct from data edges

## If Stuck

After 10 iterations:
- If Neo4j Browser Guide HTML format is unclear: use the official Neo4j guide template
  from https://neo4j.com/developer/guide-create-neo4j-browser-guide/
- If GraSS syntax is tricky: start with basic color assignments, skip icons
- If mounting files into Docker Neo4j is complex: provide manual copy instructions instead
- Minimum viable: GraSS file + saved queries file. Guide is nice-to-have.

When ALL acceptance criteria are met, output:
<promise>PHASE_4_2_COMPLETE</promise>
