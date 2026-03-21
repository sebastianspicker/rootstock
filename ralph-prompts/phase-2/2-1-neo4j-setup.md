You are the Graph Engineer agent for the Rootstock project.

## Context

Read: CLAUDE.md, AGENTS.md §Graph Engineer, ARCHITECTURE.md §Graph Model (full node/edge type definitions)

## Task: Phase 2.1 — Neo4j Setup & Schema Definition

Set up the Neo4j graph database and define the schema for Rootstock's graph model.

### Step 1: Docker Compose
Create `graph/docker-compose.yml`:
- Neo4j 4.4 (compatible with BloodHound ecosystem) or 5.x
- Expose ports 7474 (browser) and 7687 (bolt)
- Persistent volume for data
- Default auth: neo4j/rootstock (configurable via env vars)
- Health check included
- `docker compose up -d` should start Neo4j successfully

### Step 2: Schema Initialization
Create `graph/schema/init-schema.cypher`:
- Unique constraints:
  - Application(bundle_id)
  - TCC_Permission(service)
  - Entitlement(name)
  - XPC_Service(label)
  - User(name)
  - LaunchItem(label)
- Indexes for frequently queried properties:
  - Application(hardened_runtime)
  - Application(library_validation)
  - Application(is_electron)
  - Application(is_system)
  - Entitlement(is_private)
  - Entitlement(category)

Create `graph/schema/seed-tcc-services.cypher`:
- Pre-create all known TCC_Permission nodes with service identifier and display_name
- At least 15 TCC services (from docs/research/tcc-internals.md)

### Step 3: Schema Application Script
Create `graph/setup.py`:
- Connect to Neo4j via bolt
- Execute init-schema.cypher
- Execute seed-tcc-services.cypher
- Print confirmation: "Schema initialized with N constraints, M indexes, K TCC services"
- Idempotent: safe to run multiple times

### Step 4: Python Environment
Create `graph/requirements.txt`:
- neo4j (official driver, >=5.0)
- pydantic (>=2.0)

Create `graph/pyproject.toml` or simple setup for the Python package.

### Step 5: Connection Test
Create `graph/test_connection.py`:
- Connect to Neo4j
- Run a simple query: `RETURN 1`
- Verify TCC_Permission nodes exist after setup
- Print: "Connected to Neo4j. Schema OK. Found N TCC_Permission nodes."

### Step 6: Generated Schema Docs
Create `docs/generated/db-schema.md`:
- Auto-generated (or manually written) documentation of all node labels, their properties, and relationships
- Include property types and whether required/optional
- Cross-reference to ARCHITECTURE.md

## Acceptance Criteria

- [ ] `docker compose up -d` in `graph/` starts Neo4j successfully
- [ ] Neo4j Browser accessible at http://localhost:7474
- [ ] `python3 graph/setup.py` creates all constraints and indexes without error
- [ ] `python3 graph/setup.py` is idempotent (running twice doesn't fail)
- [ ] TCC_Permission nodes are seeded (>= 15 services)
- [ ] `python3 graph/test_connection.py` prints success message
- [ ] `graph/requirements.txt` lists all Python dependencies
- [ ] `docs/generated/db-schema.md` documents the complete graph schema

## If Stuck

After 10 iterations:
- If Neo4j 4.4 Docker image is unavailable: use Neo4j 5.x (the Cypher differences are minimal)
- If bolt connection fails: check Docker port mapping, try `neo4j://localhost:7687` vs `bolt://localhost:7687`
- If constraints fail on empty DB: ensure seed script runs after constraint creation

When ALL acceptance criteria are met, output:
<promise>PHASE_2_1_COMPLETE</promise>
