#!/usr/bin/env bash
# test_full_pipeline.sh — Rootstock end-to-end smoke test.
#
# Verifies the graph pipeline (import → infer → query) works end-to-end using
# the fixture JSON from tests/fixtures/graph/minimal-scan.json.
#
# Requirements:
#   - Python 3.10+ with neo4j and pydantic installed (see graph/requirements.txt)
#   - A running Neo4j instance (defaults: bolt://localhost:7687, user: neo4j, pass: rootstock)
#
# Environment variables (all optional):
#   NEO4J_URI      default: bolt://localhost:7687
#   NEO4J_USER     default: neo4j
#   NEO4J_PASSWORD default: rootstock
#
# Usage:
#   bash tests/integration/test_full_pipeline.sh
#   NEO4J_URI=bolt://other:7687 bash tests/integration/test_full_pipeline.sh

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-rootstock}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GRAPH_DIR="$REPO_ROOT/graph"
FIXTURE_JSON="$REPO_ROOT/tests/fixtures/graph/minimal-scan.json"
TEST_SCAN_ID="integration-test-$(date +%s)"

PASS=0
FAIL=0

# ── Helpers ───────────────────────────────────────────────────────────────────

ok()   { echo "  ✓ $1"; ((PASS++)); }
fail() { echo "  ✗ $1"; ((FAIL++)); }
step() { echo ""; echo "── $1 ──"; }

run_cypher() {
    python3 - "$@" <<'PYTHON'
import sys, os
sys.path.insert(0, os.environ.get("GRAPH_DIR", "."))
from neo4j import GraphDatabase
uri  = os.environ.get("NEO4J_URI",      "bolt://localhost:7687")
user = os.environ.get("NEO4J_USER",     "neo4j")
pw   = os.environ.get("NEO4J_PASSWORD", "rootstock")
cypher = sys.argv[1]
params = {}
for arg in sys.argv[2:]:
    k, _, v = arg.partition("=")
    params[k] = v
driver = GraphDatabase.driver(uri, auth=(user, pw))
with driver.session() as s:
    result = list(s.run(cypher, params))
    print(len(result))
driver.close()
PYTHON
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────

step "Pre-flight checks"

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi
ok "python3 found: $(python3 --version)"

if ! python3 -c "import neo4j" 2>/dev/null; then
    echo "ERROR: neo4j Python driver not installed (pip install neo4j)" >&2
    exit 1
fi
ok "neo4j driver installed"

if ! python3 -c "import pydantic" 2>/dev/null; then
    echo "ERROR: pydantic not installed (pip install pydantic)" >&2
    exit 1
fi
ok "pydantic installed"

if [ ! -f "$FIXTURE_JSON" ]; then
    echo "ERROR: Fixture JSON not found at $FIXTURE_JSON" >&2
    exit 1
fi
ok "fixture JSON found"

# Test Neo4j connectivity
if ! python3 -c "
import sys, os
sys.path.insert(0, '$GRAPH_DIR')
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable
try:
    d = GraphDatabase.driver('$NEO4J_URI', auth=('$NEO4J_USER', '$NEO4J_PASSWORD'))
    d.verify_connectivity()
    d.close()
except (ServiceUnavailable, ConnectionRefusedError) as e:
    print(f'Neo4j not available: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null; then
    echo "SKIP: Neo4j not available at $NEO4J_URI — skipping integration tests"
    exit 0
fi
ok "Neo4j reachable at $NEO4J_URI"

export GRAPH_DIR NEO4J_URI NEO4J_USER NEO4J_PASSWORD

# ── Step 1: Import fixture JSON ───────────────────────────────────────────────

step "Step 1: Import fixture JSON"

python3 "$GRAPH_DIR/import.py" \
    --neo4j "$NEO4J_URI" \
    --username "$NEO4J_USER" \
    --password "$NEO4J_PASSWORD" \
    --input "$FIXTURE_JSON" \
    --scan-id "$TEST_SCAN_ID" 2>&1 | tail -5

APP_COUNT=$(run_cypher "MATCH (a:Application {scan_id: '$TEST_SCAN_ID'}) RETURN count(a) AS n" 2>/dev/null || echo 0)
if [ "$APP_COUNT" -ge 3 ]; then
    ok "Application nodes imported (count: $APP_COUNT)"
else
    fail "Expected ≥3 Application nodes, got $APP_COUNT"
fi

TCC_COUNT=$(run_cypher "MATCH (:Application {scan_id: '$TEST_SCAN_ID'})-[r:HAS_TCC_GRANT]->() RETURN count(r) AS n" 2>/dev/null || echo 0)
if [ "$TCC_COUNT" -ge 1 ]; then
    ok "TCC_GRANT edges imported (count: $TCC_COUNT)"
else
    fail "Expected TCC_GRANT edges, got $TCC_COUNT"
fi

# ── Step 2: Run inference ─────────────────────────────────────────────────────

step "Step 2: Run inference"

python3 "$GRAPH_DIR/infer.py" \
    --neo4j "$NEO4J_URI" \
    --username "$NEO4J_USER" \
    --password "$NEO4J_PASSWORD" 2>&1 | tail -5

INJECT_COUNT=$(run_cypher "MATCH ()-[r:CAN_INJECT_INTO {inferred: true}]->() RETURN count(r) AS n" 2>/dev/null || echo 0)
if [ "$INJECT_COUNT" -ge 1 ]; then
    ok "CAN_INJECT_INTO edges inferred (count: $INJECT_COUNT)"
else
    fail "Expected CAN_INJECT_INTO edges after inference"
fi

# ── Step 3: Run queries ───────────────────────────────────────────────────────

step "Step 3: Run representative queries"

Q01_COUNT=$(run_cypher "$(head -20 "$GRAPH_DIR/queries/01-injectable-fda-apps.cypher" | grep -v '//')" 2>/dev/null || echo -1)
if [ "$Q01_COUNT" -ge 0 ]; then
    ok "Query 01 executed successfully (returned $Q01_COUNT rows)"
else
    fail "Query 01 failed"
fi

Q07_COUNT=$(run_cypher "$(grep -v '//' "$GRAPH_DIR/queries/07-tcc-grant-overview.cypher" | tr -d '\n')" 2>/dev/null || echo -1)
if [ "$Q07_COUNT" -ge 0 ]; then
    ok "Query 07 executed successfully (returned $Q07_COUNT rows)"
else
    fail "Query 07 failed"
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────

step "Cleanup"

python3 -c "
import sys, os
sys.path.insert(0, '$GRAPH_DIR')
from neo4j import GraphDatabase
d = GraphDatabase.driver('$NEO4J_URI', auth=('$NEO4J_USER', '$NEO4J_PASSWORD'))
with d.session() as s:
    r = s.run('MATCH (n {scan_id: \$id}) DETACH DELETE n RETURN count(n) AS n',
              id='$TEST_SCAN_ID').single()
    print(f'  Deleted {r[\"n\"]} test nodes')
d.close()
"
ok "Test nodes cleaned up"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "────────────────────────────────────────"
echo "Integration test results: $PASS passed, $FAIL failed"
echo "────────────────────────────────────────"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
