#!/usr/bin/env python3
"""
server.py — Rootstock REST API server.

Thin HTTP wrapper over existing Rootstock functions: query execution,
owned-node marking, tier classification, and live graph data for the viewer.

Usage:
    python3 graph/server.py --port 8000
    python3 graph/server.py --port 8000 --neo4j bolt://localhost:7687

Opens at http://localhost:8000/ (viewer) and http://localhost:8000/docs (OpenAPI).

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import html as html_mod
import json
import sys
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

# ── Imports from existing Rootstock modules ─────────────────────────────────

sys.path.insert(0, str(Path(__file__).parent))

import importlib

from query_runner import discover_queries, find_query, load_cypher
from utils import first_cypher_statement, run_query

_import_mod = importlib.import_module("import")
query_stats = _import_mod.query_stats

from opengraph_export import build_opengraph
from mark_owned import mark_by_bundle_id, mark_by_username, mark_by_label_key, list_owned
from clear_owned import clear_all, clear_by_bundle_id, clear_by_username
from tier_classification import classify_tier0, classify_tier1, classify_tier2
from viewer_layout import compute_layout
from cve_enrichment import enrich_registry, fetch_and_cache, get_enrichment_status
from bloodhound_import import import_all as bloodhound_import_all


# ── Request/Response models ─────────────────────────────────────────────────

class MarkOwnedRequest(BaseModel):
    bundle_ids: list[str] | None = None
    usernames: list[str] | None = None
    label: str | None = None
    keys: list[str] | None = None


class ClearOwnedRequest(BaseModel):
    all: bool = False
    bundle_ids: list[str] | None = None
    usernames: list[str] | None = None


class QueryRunRequest(BaseModel):
    params: dict[str, Any] | None = None


# ── App lifecycle ───────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create Neo4j driver on startup, close on shutdown."""
    uri = app.state.neo4j_uri
    user = app.state.neo4j_user
    password = app.state.neo4j_password

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
    except ServiceUnavailable:
        print(f"ERROR: Cannot connect to Neo4j at {uri}", file=sys.stderr)
        sys.exit(1)
    except AuthError:
        print("ERROR: Neo4j authentication failed.", file=sys.stderr)
        sys.exit(1)

    app.state.driver = driver
    print(f"Connected to Neo4j at {uri}")
    yield
    driver.close()
    print("Neo4j connection closed.")


app = FastAPI(
    title="Rootstock API",
    description="REST API for Rootstock macOS attack graph",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:*", "http://127.0.0.1:*"],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Dependencies ────────────────────────────────────────────────────────────

def get_session(request: Request):
    """Yield a Neo4j session from the app-level driver."""
    with request.app.state.driver.session() as session:
        yield session


# ── Routes ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def serve_viewer(request: Request):
    """Serve the live interactive viewer with real-time graph data."""
    with request.app.state.driver.session() as session:
        hostname = _get_hostname(session)
        data = build_opengraph(session, hostname)

    graph = data.get("graph", {})
    node_list = graph.get("nodes", [])
    edge_list = graph.get("edges", [])

    n_nodes = len(node_list)
    iters = min(300, max(100, 500 - n_nodes // 10))
    compute_layout(node_list, edge_list, iterations=iters)

    template_path = Path(__file__).parent / "viewer_template.html"
    template = template_path.read_text()

    safe_json = json.dumps(data).replace("</", "<\\/")
    title = f"{hostname} Attack Graph"

    # Inject live mode flag and replace template placeholders
    live_inject = "const __ROOTSTOCK_LIVE__ = true;\nconst API_BASE = '';\n"
    html = template.replace("{{VIEWER_TITLE}}", html_mod.escape(title))
    html = html.replace(
        "const DATA = {{VIEWER_DATA}};",
        live_inject + "const DATA = " + safe_json + ";",
    )

    return HTMLResponse(content=html)


@app.get("/api/queries")
def list_queries():
    """List all available Cypher queries with metadata."""
    queries = discover_queries()
    return [
        {
            "id": q["id"],
            "filename": q["filename"],
            "name": q["name"],
            "purpose": q["purpose"],
            "category": q["category"],
            "severity": q["severity"],
            "parameters": q["parameters"],
        }
        for q in queries
    ]


@app.post("/api/queries/{query_id}/run")
def run_query_endpoint(
    query_id: str,
    body: QueryRunRequest | None = None,
    session=Depends(get_session),
):
    """Execute a query by ID and return results as JSON."""
    queries = discover_queries()
    q = find_query(queries, query_id)
    if not q:
        raise HTTPException(status_code=404, detail=f"Query '{query_id}' not found")

    cypher = first_cypher_statement(load_cypher(q))
    params = body.params if body else {}
    try:
        rows = run_query(session, cypher, params or {})
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "query": {
            "id": q["id"],
            "name": q["name"],
            "category": q["category"],
            "severity": q["severity"],
        },
        "rows": rows,
        "count": len(rows),
    }


@app.get("/api/stats")
def get_stats(session=Depends(get_session)):
    """Return node and relationship counts."""
    node_counts, rel_counts = query_stats(session)
    return {
        "nodes": node_counts,
        "relationships": rel_counts,
        "total_nodes": sum(node_counts.values()),
        "total_relationships": sum(rel_counts.values()),
    }


@app.get("/api/graph")
def get_graph(session=Depends(get_session)):
    """Return the full OpenGraph JSON for viewer refresh."""
    hostname = _get_hostname(session)
    data = build_opengraph(session, hostname)

    graph = data.get("graph", {})
    node_list = graph.get("nodes", [])
    edge_list = graph.get("edges", [])
    n_nodes = len(node_list)
    iters = min(300, max(100, 500 - n_nodes // 10))
    compute_layout(node_list, edge_list, iterations=iters)

    return data


@app.post("/api/mark-owned")
def mark_owned_endpoint(body: MarkOwnedRequest, session=Depends(get_session)):
    """Mark nodes as owned (compromised)."""
    timestamp = datetime.now(timezone.utc).isoformat()
    count = 0

    if body.bundle_ids:
        count += mark_by_bundle_id(session, body.bundle_ids, timestamp)
    if body.usernames:
        count += mark_by_username(session, body.usernames, timestamp)
    if body.label and body.keys:
        count += mark_by_label_key(session, body.label, body.keys, timestamp)

    if count == 0:
        raise HTTPException(status_code=404, detail="No matching nodes found")

    return {"marked": count, "timestamp": timestamp}


@app.post("/api/clear-owned")
def clear_owned_endpoint(body: ClearOwnedRequest, session=Depends(get_session)):
    """Clear owned markers from nodes."""
    count = 0

    if body.all:
        count = clear_all(session)
    elif body.bundle_ids:
        count = clear_by_bundle_id(session, body.bundle_ids)
    elif body.usernames:
        count = clear_by_username(session, body.usernames)
    else:
        raise HTTPException(status_code=400, detail="Specify 'all', 'bundle_ids', or 'usernames'")

    return {"cleared": count}


@app.get("/api/owned")
def get_owned(session=Depends(get_session)):
    """List all currently owned nodes."""
    owned = list_owned(session)
    results = []
    for item in owned:
        props = item.get("props", {})
        results.append({
            "labels": item.get("labels", []),
            "name": props.get("name", props.get("bundle_id", props.get("label", "?"))),
            "owned_at": props.get("owned_at", "?"),
            "properties": props,
        })
    return {"owned": results, "count": len(results)}


@app.post("/api/tier-classify")
def tier_classify_endpoint(session=Depends(get_session)):
    """Run tier classification on all Application nodes."""
    # Clear existing tiers first
    session.run(
        "MATCH (app:Application) WHERE app.tier IS NOT NULL REMOVE app.tier"
    )
    t0 = classify_tier0(session)
    t1 = classify_tier1(session)
    t2 = classify_tier2(session)

    return {
        "tier0": t0,
        "tier1": t1,
        "tier2": t2,
        "total": t0 + t1 + t2,
    }


# ── Vulnerability endpoints ──────────────────────────────────────────────

@app.get("/api/vulnerabilities")
def list_vulnerabilities(session=Depends(get_session)):
    """List all Vulnerability nodes with EPSS/KEV data."""
    result = session.run(
        """
        MATCH (v:Vulnerability)
        OPTIONAL MATCH (app:Application)-[:AFFECTED_BY]->(v)
        RETURN v.cve_id AS cve_id,
               v.title AS title,
               v.cvss_score AS cvss_score,
               v.epss_score AS epss_score,
               v.epss_percentile AS epss_percentile,
               v.in_kev AS in_kev,
               v.kev_date_added AS kev_date_added,
               v.exploitation_status AS exploitation_status,
               v.cwe_ids AS cwe_ids,
               collect(DISTINCT app.name) AS affected_apps
        ORDER BY v.epss_score DESC NULLS LAST, v.cvss_score DESC
        """
    )
    return [dict(record) for record in result]


@app.get("/api/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str, session=Depends(get_session)):
    """Single CVE lookup with affected apps."""
    result = session.run(
        """
        MATCH (v:Vulnerability {cve_id: $cve_id})
        OPTIONAL MATCH (app:Application)-[:AFFECTED_BY]->(v)
        OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(t:AttackTechnique)
        RETURN v,
               collect(DISTINCT {name: app.name, bundle_id: app.bundle_id, tier: app.tier}) AS affected_apps,
               collect(DISTINCT {id: t.technique_id, name: t.name, tactic: t.tactic}) AS techniques
        """,
        cve_id=cve_id,
    )
    row = result.single()
    if not row or not row["v"]:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found")

    vuln_props = dict(row["v"])
    return {
        "vulnerability": vuln_props,
        "affected_apps": [a for a in row["affected_apps"] if a.get("name")],
        "techniques": [t for t in row["techniques"] if t.get("id")],
    }


@app.post("/api/enrichment/refresh")
def refresh_enrichment():
    """Trigger EPSS/KEV re-fetch."""
    try:
        fetch_and_cache(force=True)
        status = get_enrichment_status()
        return {"status": "ok", "enrichment": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Threat Group endpoints ────────────────────────────────────────────

@app.get("/api/threat-groups")
def get_threat_groups(session=Depends(get_session)):
    """List all ThreatGroup nodes with technique counts."""
    result = session.run(
        """
        MATCH (g:ThreatGroup)
        OPTIONAL MATCH (g)-[:USES_TECHNIQUE]->(t:AttackTechnique)
        RETURN g.group_id AS group_id, g.name AS name, g.aliases AS aliases,
               count(t) AS technique_count
        ORDER BY technique_count DESC
        """
    )
    return [dict(r) for r in result]


# ── BloodHound import endpoint ──────────────────────────────────────────

@app.post("/api/import-bloodhound")
async def import_bloodhound(file: UploadFile, session=Depends(get_session)):
    """Import a SharpHound ZIP archive into the Rootstock graph.

    Creates ADUser nodes and links them to existing Rootstock User nodes
    via SAME_IDENTITY edges, enabling cross-domain attack path analysis.
    """
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a .zip archive")

    MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds 50 MB limit")

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        counts = bloodhound_import_all(session, tmp_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return counts


# ── Helpers ─────────────────────────────────────────────────────────────────

def _get_hostname(session) -> str:
    """Get hostname from graph data."""
    result = session.run(
        "MATCH (c:Computer) RETURN c.hostname AS hostname LIMIT 1"
    )
    row = result.single()
    if row and row["hostname"]:
        return row["hostname"]
    # Fallback to scan_id prefix
    result = session.run(
        "MATCH (a:Application) WHERE a.scan_id IS NOT NULL "
        "RETURN a.scan_id AS scan_id LIMIT 1"
    )
    row = result.single()
    return row["scan_id"][:8] if row else "rootstock"


# ── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Rootstock REST API server")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--neo4j", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="rootstock", help="Neo4j password")
    args = parser.parse_args()

    app.state.neo4j_uri = args.neo4j
    app.state.neo4j_user = args.neo4j_user
    app.state.neo4j_password = args.neo4j_password

    import uvicorn
    print(f"Starting Rootstock API server on {args.host}:{args.port}")
    print(f"  Viewer:  http://{args.host}:{args.port}/")
    print(f"  OpenAPI: http://{args.host}:{args.port}/docs")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
