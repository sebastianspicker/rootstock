"""
import_nodes.py — Neo4j node and relationship import functions.

All operations use MERGE (not CREATE) for idempotency: re-importing the same
scan is always safe. UNWIND is used throughout to batch operations into single
queries rather than one query per node.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from neo4j import Session

from models import ApplicationData, TCCGrantData

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def import_applications(session: Session, apps: list[ApplicationData], scan_id: str) -> int:
    """MERGE Application nodes. Returns the number of apps processed."""
    if not apps:
        return 0

    now = _now_iso()
    records = [
        {
            "bundle_id": app.bundle_id,
            "name": app.name,
            "path": app.path,
            "version": app.version,
            "team_id": app.team_id,
            "hardened_runtime": app.hardened_runtime,
            "library_validation": app.library_validation,
            "is_electron": app.is_electron,
            "is_system": app.is_system,
            "signed": app.signed,
            "injection_methods": app.injection_methods,
            "scan_id": scan_id,
            "imported_at": now,
        }
        for app in apps
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (a:Application {bundle_id: r.bundle_id})
        SET a.name             = r.name,
            a.path             = r.path,
            a.version          = r.version,
            a.team_id          = r.team_id,
            a.hardened_runtime = r.hardened_runtime,
            a.library_validation = r.library_validation,
            a.is_electron      = r.is_electron,
            a.is_system        = r.is_system,
            a.signed           = r.signed,
            a.injection_methods = r.injection_methods,
            a.scan_id          = r.scan_id,
            a.imported_at      = r.imported_at
        """,
        records=records,
    )
    return len(records)


def import_tcc_grants(
    session: Session, grants: list[TCCGrantData], scan_id: str
) -> tuple[int, int]:
    """
    MERGE TCC_Permission nodes and HAS_TCC_GRANT relationships.
    Skips grants whose client bundle_id has no matching Application node.
    Returns (grants_linked, grants_skipped).
    """
    if not grants:
        return 0, 0

    records = [
        {
            "service": g.service,
            "display_name": g.display_name,
            "client": g.client,
            "allowed": g.allowed,
            "auth_reason": g.auth_reason_label,
            "auth_value": g.auth_value,
            "scope": g.scope,
            "last_modified": g.last_modified,
            "scan_id": scan_id,
        }
        for g in grants
    ]

    # MERGE the TCC_Permission nodes (they may already exist from the seed)
    session.run(
        """
        UNWIND $records AS r
        MERGE (t:TCC_Permission {service: r.service})
        ON CREATE SET t.display_name = r.display_name
        """,
        records=records,
    )

    # Create HAS_TCC_GRANT edges only where an Application node matches the client
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {bundle_id: r.client})
        MATCH (t:TCC_Permission {service: r.service})
        MERGE (a)-[rel:HAS_TCC_GRANT {scope: r.scope}]->(t)
        SET rel.allowed       = r.allowed,
            rel.auth_reason   = r.auth_reason,
            rel.auth_value    = r.auth_value,
            rel.last_modified = r.last_modified,
            rel.scan_id       = r.scan_id
        RETURN count(rel) AS linked
        """,
        records=records,
    )
    linked = result.single()["linked"]
    skipped = len(records) - linked
    if skipped > 0:
        logger.debug("%d TCC grants had no matching Application node (path-only clients)", skipped)
    return linked, skipped


def import_entitlements(
    session: Session, apps: list[ApplicationData]
) -> tuple[int, int]:
    """
    MERGE Entitlement nodes and HAS_ENTITLEMENT relationships.
    Returns (entitlement_nodes_created_or_merged, relationships_created_or_merged).
    """
    # Flatten app → entitlement pairs, keyed by bundle_id
    records = [
        {
            "bundle_id": app.bundle_id,
            "name": ent.name,
            "is_private": ent.is_private,
            "category": ent.category,
            "is_security_critical": ent.is_security_critical,
        }
        for app in apps
        for ent in app.entitlements
    ]

    if not records:
        return 0, 0

    # MERGE Entitlement nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (e:Entitlement {name: r.name})
        SET e.is_private          = r.is_private,
            e.category            = r.category,
            e.is_security_critical = r.is_security_critical
        """,
        records=records,
    )

    # MERGE HAS_ENTITLEMENT relationships
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {bundle_id: r.bundle_id})
        MATCH (e:Entitlement {name: r.name})
        MERGE (a)-[rel:HAS_ENTITLEMENT]->(e)
        RETURN count(rel) AS rels
        """,
        records=records,
    )
    rels = result.single()["rels"]

    # Count distinct entitlement names (nodes merged)
    unique_names = len({r["name"] for r in records})
    return unique_names, rels


def import_signed_by_team(session: Session) -> int:
    """
    Create SIGNED_BY_SAME_TEAM edges between all Application pairs sharing a team_id.
    Edges go from lexicographically smaller bundle_id to larger to avoid duplicates.
    Returns number of relationships created or merged.
    """
    result = session.run(
        """
        MATCH (a:Application), (b:Application)
        WHERE a.team_id IS NOT NULL
          AND a.team_id = b.team_id
          AND a.bundle_id < b.bundle_id
        MERGE (a)-[r:SIGNED_BY_SAME_TEAM]->(b)
        SET r.team_id = a.team_id
        RETURN count(r) AS rels
        """
    )
    return result.single()["rels"]
